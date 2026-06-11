#!/usr/bin/env python3
"""apply_prose_fixes.py — deterministic post-compose touch-ups for prose-style
violations that the renderer LLM consistently misses.

Fix classes applied (each is idempotent):

1. ``inline_code_format`` — wrap path-shaped tokens in backticks when bare
   in prose. Mirrors ``qa_checks.py:check_inline_code_format``.

2. ``ai_padding_phrases`` — strip ``Additionally,`` / ``Furthermore,`` /
   ``Moreover,`` sentence-leading transitional filler (prose-style Rule 5).
   Only matches at sentence start (after ``.``/``!``/``?`` + space) to
   preserve uses inside compound predicates.

3. ``rhetorical_severity`` — rewrite the most-common rhetorical adjective
   "trivially crackable" to a mechanism+response phrasing the QA helper
   accepts (``— recoverable by GPU dictionary attack within seconds``).
   Only the safe textual replacements are applied; the broader phrasing
   class still relies on the renderer prompt.

4. ``unfounded_perimeter_claims`` — strip standalone ``No <perimeter>``
   sentences for deployment-time controls when nothing in the recon data
   confirms them. Uses the shared negative-claim patterns also used by
   ``qa_checks.py:check_unfounded_perimeter_claims``.

5. ``controls_covered_anchor_rewrite`` — for every ``**Controls covered:**``
   line under a ``### 7.x`` section, recompute the link targets from the
   ``#### ...`` subsection headings actually present in the rendered MD.
   This closes the LLM-rename slug-drift class entirely (was the source
   of all 60 §7.x ``toc_closure`` / ``control_subsection_coverage`` issues
   in the 2026-05 juice-shop run).

6. ``threat_title_path_normalization`` — rewrite the path-token tail of every
   legacy threat-register title cell into canonical parenthesised form
   (``Weakness — file:line`` → ``Weakness (file:line)``). This is a
   fallback only; compose normalises ``threats[].title`` before rendering.

7. ``relevant_findings_bullet_list`` — rewrite inline
   ``**Relevant findings:** [F-001](...) ...`` lines into the v2 canonical
   standalone label plus one bullet per finding.

What this script does NOT do:
  - It does not restructure arbitrary dense paragraphs into bullet lists
    (``paragraph_density``, ``falls_short_format``). Those changes require
    semantic awareness of which references belong together and which
    sentence breaks signal new bullets; they are addressed via renderer
    prompt guidance (see ``agents/appsec-threat-renderer.md``). The only
    exception is the narrow ``Relevant findings`` inline form above.
  - It does not touch fragments under ``.fragments/``. The fix is applied
    to ``threat-model.md`` post-compose because the renderer cleans up the
    fragments before each compose run anyway — fixing the rendered output
    is the only place the touch-up sticks.

Excluded contexts (mirrors qa_checks.py):
  - Fenced code blocks (```…```)
  - Headings (`#`/`##`/… lines)
  - Table rows (lines starting with `|`)
  - Existing backticked spans
  - Markdown-link URLs `[label](path)`
  - HTML attributes (`href="…"`, `src="…"`)
  - Tokens containing `*` or `**` (glob wildcards from YAML-derived prose)

Whole-document post-processors still touch narrowly scoped table rows for
canonical threat-title fallback normalization.

Idempotent — a second run on the same file produces no diff.

Usage:
    python3 apply_prose_fixes.py <threat-model.md>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from _slug import github_slug
from perimeter_patterns import strip_perimeter_absence_sentences

_EXTENSIONS = (
    "ts",
    "tsx",
    "js",
    "jsx",
    "json",
    "yaml",
    "yml",
    "py",
    "go",
    "rs",
    "java",
    "kt",
    "rb",
    "php",
    "cs",
    "c",
    "h",
    "cpp",
    "hpp",
    "swift",
    "scala",
    "md",
    "html",
    "css",
    "scss",
    "sql",
    "sh",
    "bash",
    "ps1",
    "toml",
    "lock",
    "env",
    # Common backup / build artefacts (2026-05): the LLM-authored prose
    # frequently mentions `package.json.bak`, `acquisitions.md`,
    # `incident-support.kdbx` etc. as bare tokens — wrap them too.
    "bak",
    "kdbx",
    "pem",
    "crt",
    "p12",
    "key",
    "pub",
)
_PATH_RE = re.compile(
    r"(?P<path>[A-Za-z][\w.-]*/[\w./-]+\.(?:"
    + "|".join(_EXTENSIONS)
    + r")(?::\d+)?)"
    # Trailing boundary (mirrors _BARE_FILENAME_RE): without it the extension
    # alternation stops at a PREFIX extension — `.h` is tried before `.html`
    # and matches `administration.component.h`, leaving a bare `tml`. The
    # `(?![\w/`])` lookahead forces backtracking to the longest extension that
    # ends at a real token boundary, so `.html` / `.ts` match in full.
    + r"(?![\w/`])"
)
# 2026-05 R-7 — additional code-token classes the LLM frequently leaves
# bare in prose. Each pattern fires INDEPENDENTLY of `_PATH_RE`; all
# share the same forbidden-zone mask (existing backticks, link URLs,
# HTML attrs).
#   - URL paths starting with `/`: `/rest/user/login`, `/etc/passwd`.
#     Conservative: requires ≥ 2 path segments AND the first segment must
#     start with a letter so accidental matches like " /etc."  or " /."
#     are excluded.  Trailing punctuation (`.`, `,`, `;`, `)`, `?`) is left
#     OUTSIDE the backticked span via a negative-character-class boundary.
_URL_PATH_RE = re.compile(
    # Lookbehind also rejects `<` so long HTML closing tags `</thead>`,
    # `</tbody>`, `</table>` are not mis-matched as `/thead`/`/tbody`/`/table`
    # URL paths and wrapped in backticks. The Top Findings table emitted
    # these tags structurally; the wrapper produced `<`/thead`>` etc. and
    # broke contract validation. Adding `<` to the negative class closes
    # this without affecting any legitimate `/path` match (prose URL paths
    # are never adjacent to `<`).
    r"(?<![\w`/<])"
    # First segment requires ≥ 3 chars after `/` so accidental tokens like
    # `and/or` (`/or` would be only 2 chars) are rejected. Additional
    # segments are optional so `/ftp` and `/etc/passwd` both match.
    r"(?P<urlpath>/[A-Za-z][\w-]{2,}(?:/[\w%:&=.-]+)*)"
    # Allow `.`, `,`, `;`, `)`, `?`, `!` as next character — those are
    # sentence punctuation that the trailing-punct stripper takes care of.
    # Symmetric tightening: also reject `>` so the closing-bracket end of
    # an HTML tag boundary is rejected, mirroring the lookbehind.
    r"(?![\w/`>])"
)
#   - Bare standalone source-filename tokens (no preceding path):
#     `login.ts`, `search.ts:23`, `package.json.bak`, `app.guard.ts:54`.
#     Excludes tokens that already contain a slash (handled by `_PATH_RE`)
#     and excludes domain-like tokens (`owasp.org`, `juice.shop`, `Node.js`)
#     by requiring the extension to be one of our recognised source
#     extensions (a TLD allowlist would be brittle — the extension list IS
#     the allowlist).
_BARE_FILENAME_RE = re.compile(
    # `-` is in the negative lookbehind so a hyphen-joined path component is
    # not re-matched mid-token: in `frontend/.../last-login-ip.component.ts`
    # the bare pattern must NOT start at `login-ip.component.ts` (preceded by
    # `-`), otherwise it wraps the tail before _PATH_RE can wrap the whole
    # path and the leading `last-` is left dangling outside the code span.
    r"(?<![\w./`-])"
    # Allow multi-dot filenames like `package.json.bak`. The
    # ``(?:\.[A-Za-z0-9-]+)*`` allows zero or more middle dot-segments
    # before the final recognised extension (was ``?`` which capped at
    # one middle segment).
    r"(?P<file>[A-Za-z][\w-]+(?:\.[A-Za-z0-9-]+)*\.(?:" + "|".join(_EXTENSIONS) + r")(?::\d+)?)"
    # Trailing punctuation (period, comma, semicolon, `)`) is allowed —
    # the trailing-punct stripper handles them.
    r"(?![\w/`])"
)
# 2026-05 — well-known product names that match _BARE_FILENAME_RE but are
# NOT files. Excluded from wrapping so `Node.js` reads as a product name
# in prose ("crashes the Node.js process") instead of as a file token.
# Keep this list narrow — adding a name suppresses wrapping for every
# context, including legitimate file references.
_BARE_FILENAME_ALLOWLIST: frozenset[str] = frozenset(
    {
        "Node.js",
        "node.js",
        "Vue.js",
        "vue.js",
        "Next.js",
        "next.js",
        "Nuxt.js",
        "nuxt.js",
        "Express.js",
        "express.js",
        "Backbone.js",
        "backbone.js",
        "Ember.js",
        "ember.js",
        "Three.js",
        "three.js",
    }
)
#   - Function-call tokens: `eval()`, `bypassSecurityTrustHtml()`,
#     `helmet.noSniff()`, `models.sequelize.query()`. Conservative:
#     requires the parens AND a leading letter so generic prose ("the
#     resulting (broken) check") doesn't false-positive.
_FUNCTION_CALL_RE = re.compile(
    r"(?<![\w`])"
    r"(?P<fn>[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*\(\s*\))"
    r"(?![\w`])"
)
#   - JWT / HTTP literal allowlist: `alg:none`, `alg:HS256`, `alg:RS256`,
#     `role:admin`, `role:user`, `role:guest`. Narrow allowlist to avoid
#     accidentally matching generic prose like "the time is now:".
_LITERAL_TOKEN_RE = re.compile(
    r"(?<![\w`])"
    r"(?P<lit>(?:alg:(?:none|HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|none)"
    r"|role:(?:admin|user|guest|root|anonymous|deluxe)"
    r"|noent:(?:true|false)"
    r"|multi:(?:true|false)"
    r"|method:(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)))"
    r"(?![\w`])"
)
#   - Package@version tokens: `express-jwt@0.1.3`, `jsonwebtoken@0.4.0`,
#     `@angular/core@15.2.0`. The `@<digit>` boundary requires the version to
#     start with a digit, so email addresses (`user@example.com` → letter
#     after `@`) and decorators (`@Component`) never match. The optional
#     `@scope/` prefix admits npm-scoped packages.
_LIB_VERSION_RE = re.compile(
    r"(?<![\w`/@])"
    r"(?P<libver>(?:@[a-z0-9][\w.-]*/)?[a-z][\w.-]*@\d[\w.\-+]*)"
    r"(?![\w`])"
)
#   - CVE identifiers: `CVE-2020-28042`. Distinctive shape, very low
#     false-positive risk. CVEs inside a markdown link label
#     (`[CVE-2020-28042](https://…)`) are protected by _MD_LINK_LABEL_RE.
_CVE_RE = re.compile(r"(?<![\w`-])(?P<cve>CVE-\d{4}-\d{4,7})(?![\w`])")
#   - Bare JWT/JWS algorithm names: `HS256`, `RS256`, `ES384`, `PS512`.
#     The `:` in the negative lookbehind keeps the `HS256` inside `alg:HS256`
#     out of this pass (that whole literal is owned by _LITERAL_TOKEN_RE);
#     this pass only catches the algorithm used bare in prose
#     ("switch to HS256"). Bare `none` is intentionally NOT matched here.
_ALG_NAME_RE = re.compile(r"(?<![\w`:])(?P<alg>(?:HS|RS|ES|PS)(?:256|384|512))(?![\w`])")
#   - Bare hash / digest algorithm names used in prose ("unsalted MD5",
#     "SHA-1 hashing"). These read as code identifiers, not English words,
#     so they get backticked like any other code token. Restricted to the
#     named MD/SHA digests so arbitrary capitalised words are never matched.
_HASH_NAME_RE = re.compile(r"(?<![\w`:/-])(?P<hash>MD[45]|SHA-?(?:1|224|256|384|512))(?![\w`])")
#   - HTTP method + URL path pairs: backtick the path portion of
#     `GET /support/logs` → `GET \`/support/logs\``.  The method stays
#     bare so the sentence reads naturally; only the route gets the code
#     span.
_HTTP_METHOD_PATH_RE = re.compile(
    r"\b(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(?P<route>/[A-Za-z][\w/.:%-]+)"
    r"(?![\w/`])"
)
#   - Dotted runtime-API tokens used BARE in prose, no parens: `vm.runInContext`,
#     `req.body`, `process.env`, `child_process.exec`, `JSON.parse`. These read
#     as code, not English, in §5 Notes / §8 descriptions / §3 Attack Steps.
#     Anchored to a known-object allowlist so generic dotted prose ("the U.S.
#     team", "Node.js") never matches; the trailing `(`-exclusion leaves the
#     `foo()` forms to `_FUNCTION_CALL_RE`. Plus a couple of standalone sandbox
#     sink identifiers (`notevil`, `vm2`) that are unambiguously code names.
_CODE_API_RE = re.compile(
    r"(?<![\w`.$@-])"
    r"(?P<api>"
    r"(?:vm|req|res|process|child_process|JSON|Object|crypto|fs|sequelize)"
    r"\.[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
    r"|notevil|vm2"
    r")"
    r"(?![\w`])"
)
#   - NoSQL / MongoDB-operator object literals used bare in prose:
#     `{id: {$gt:''}, message: 'hacked'}`, `{$where: '...'}`, `{$ne: null}`.
#     Matches a `{…}` span (≤1 level of nesting, single line) that CONTAINS a
#     known query operator. The operator may already carry the composer's
#     `\$`-escape (`_escape_dollar_operators` runs before this pass); the
#     content guard in `_wrap_line` accepts both `$op` and `\$op`, and unescapes
#     `\$`→`$` before wrapping so the code span renders the operator cleanly
#     (inside a backtick span the `$` is literal — no math-mode risk remains).
_NOSQL_OBJECT_RE = re.compile(
    r"(?<![\w`])"
    r"(?P<obj>\{(?:[^{}\n]|\{[^{}\n]*\})*\})"
    r"(?![\w`])"
)
# Detects a Mongo/NoSQL operator inside a candidate object — gates the
# _NOSQL_OBJECT_RE pass so plain `{a, b}` prose sets are never backticked.
_NOSQL_OPERATOR_RE = re.compile(
    r"\\?\$(?:gt|gte|lt|lte|ne|eq|in|nin|where|regex|exists|or|and|not|elemMatch|set|push|all)\b"
)
_BACKTICK_SPAN_RE = re.compile(r"`[^`\n]+`")
_MD_LINK_URL_RE = re.compile(r"\]\(([^)]+)\)")
_HTML_ATTR_RE = re.compile(r'(?:href|src|action|formaction)="[^"]+"')
# 2026-05 — additional forbidden zones for the §8 Findings Register cells.
# `<details>...</details>` blocks contain a `<pre><code>` snippet that
# must NEVER be rewritten; `<pre>...</pre>` and `<code>...</code>`
# (without surrounding details) likewise hold raw source code. We skip the
# entire span so the inner regex engines never see the embedded tokens.
_HTML_DETAILS_RE = re.compile(r"<details\b.*?</details>", re.DOTALL)
_HTML_PRE_RE = re.compile(r"<pre\b.*?</pre>", re.DOTALL)
_HTML_CODE_INLINE_RE = re.compile(r"<code\b.*?</code>", re.DOTALL)
# Markdown link LABEL — `[label](url)` — keep the bracketed text raw so
# multi-word link labels like `[CWE-321](https://…)` aren't broken by
# accidental backtick injection inside the label.
_MD_LINK_LABEL_RE = re.compile(r"\[[^\]]+\]\([^)]+\)")
# Linked-title TAIL — the `— <title>` that trails a finding / threat /
# mitigation anchor link, e.g. `[F-002](#f-002) — MD5 hashing`. Per the
# title-exemption rule ("code in titles and links is NOT backticked"), the
# title tail is a title context: code tokens in it (function calls, paths,
# hash names) must stay bare. Requiring the em-dash immediately after the
# link scopes this to title tails only — genuine prose that merely follows
# a link ("see [F-001](#f-001) which calls eval()") is NOT protected. The
# tail runs up to the next `<br/>`, table-cell `|`, or end of line.
# The separator may be an em-dash, en-dash, or a spaced hyphen — the
# `_bulletize_relevant_findings` post-processor normalises `- ` to `— `
# only AFTER the per-line wrap pass, so the hyphen form must match here too.
_LINKED_TITLE_TAIL_RE = re.compile(r"\]\(#(?:f|t|m|th)-\d+\)\s*[—–-]\s[^\n|]*?(?=<br/?>|\||$)")


def _wrap_line(line: str) -> tuple[str, int]:
    """Return (rewritten_line, n_changes).

    Multi-pass wrapper — applies each of the registered code-token regexes
    in order, refreshing the ``forbidden`` mask after every pass so a token
    backticked in pass N is treated as forbidden by pass N+1 (prevents
    nested-backtick artifacts like `` ``login.ts`` ``).
    """
    n_total = 0

    # Order matters: HTTP-method-path runs FIRST because its match consumes
    # both the method and the path; otherwise `_URL_PATH_RE` would
    # backtick the path while leaving the method bare on the outside.
    # Then path tokens, then bare filenames, then function calls, then
    # literal allowlist. _PATH_RE last so it doesn't shadow more-specific
    # patterns (it only matches `<word>/<file>.<ext>` shapes anyway).
    pass_order: list[tuple[re.Pattern[str], str]] = [
        (_HTTP_METHOD_PATH_RE, "_http_method_path"),
        # NoSQL operator objects run early so the whole `{…}` span is wrapped
        # before the inner tokens are exposed to later single-token passes.
        (_NOSQL_OBJECT_RE, "obj"),
        (_LIB_VERSION_RE, "libver"),
        (_URL_PATH_RE, "urlpath"),
        (_BARE_FILENAME_RE, "file"),
        (_FUNCTION_CALL_RE, "fn"),
        (_LITERAL_TOKEN_RE, "lit"),
        (_ALG_NAME_RE, "alg"),
        (_HASH_NAME_RE, "hash"),
        (_CVE_RE, "cve"),
        (_CODE_API_RE, "api"),
        (_PATH_RE, "path"),
    ]

    for pat, group_or_special in pass_order:
        forbidden: list[tuple[int, int]] = []
        for span_re in (
            _BACKTICK_SPAN_RE,
            _MD_LINK_URL_RE,
            _MD_LINK_LABEL_RE,
            _LINKED_TITLE_TAIL_RE,
            _HTML_ATTR_RE,
            _HTML_DETAILS_RE,
            _HTML_PRE_RE,
            _HTML_CODE_INLINE_RE,
        ):
            for m in span_re.finditer(line):
                forbidden.append((m.start(), m.end()))
        forbidden.sort()

        def overlaps_forbidden(s: int, e: int) -> bool:
            for fs, fe in forbidden:
                if s < fe and e > fs:
                    return True
            return False

        matches = list(pat.finditer(line))
        if not matches:
            continue

        # Special case: HTTP method + path — backtick only the path
        # portion, leave the method as bare uppercase text.
        if group_or_special == "_http_method_path":
            out: list[str] = []
            last = 0
            n_changes = 0
            for m in matches:
                # Span of the ROUTE (not the whole match).
                rs, re_ = m.start("route"), m.end("route")
                tok = m.group("route")
                if "*" in tok:
                    continue
                if overlaps_forbidden(rs, re_):
                    continue
                # Strip trailing punctuation that should sit OUTSIDE the
                # backtick span (`.`, `,`, `;`, `)`, `?`).
                trailing = ""
                while tok.endswith((".", ",", ";", ")", "?", "!")):
                    trailing = tok[-1] + trailing
                    tok = tok[:-1]
                    re_ -= 1
                if not tok:
                    continue
                out.append(line[last:rs])
                out.append(f"`{tok}`" + trailing)
                last = re_ + len(trailing)
                n_changes += 1
            out.append(line[last:])
            line = "".join(out)
            n_total += n_changes
            continue

        out2: list[str] = []
        last = 0
        n_changes = 0
        for m in matches:
            s, e = m.start(), m.end()
            tok = m.group(group_or_special)
            # NoSQL object pass: only wrap a `{…}` span that actually carries a
            # query operator (so plain prose sets like `{read, write}` are
            # left alone), and unescape the composer's `\$`→`$` so the code
            # span renders the operator cleanly.
            if group_or_special == "obj":
                if not _NOSQL_OPERATOR_RE.search(tok):
                    continue
                tok = tok.replace("\\$", "$")
            # Globs and wildcards never get backticked — they may be
            # YAML-derived prose like `routes/**`.
            if "*" in tok:
                continue
            # Well-known product names (Node.js, Vue.js, …) match the
            # bare-filename regex but are NOT files. Skip them so they
            # read as product names in prose.
            if group_or_special == "file" and tok in _BARE_FILENAME_ALLOWLIST:
                continue
            if overlaps_forbidden(s, e):
                continue
            # Adjacency guard (2026-06-02): never backtick a token that sits
            # INSIDE a larger un-backticked code expression — wrapping just the
            # inner token produces broken partial formatting like
            #   btoa(profile.email.split('').`reverse()`.join(''))
            # or  algorithm: '`RS256`'  or  execSync('cat `/etc/passwd`').
            # Signals that the match is mid-expression:
            #   • preceded by `.` / `_`  → member-access or identifier fragment
            #   • wrapped in quotes      → it is a string-literal fragment
            #   • a dotted chain immediately followed by `(`  → method call
            #     embedded in a bigger expression
            #   • followed by `.<word>`  → the member chain continues
            # Standalone tokens in real prose (space / paren-in-prose
            # boundaries) are unaffected and still get backticked.
            gs, ge = m.start(group_or_special), m.end(group_or_special)
            before = line[gs - 1] if gs > 0 else " "
            after = line[ge] if ge < len(line) else " "
            if before in "._":
                continue
            if before in "'\"" and after in "'\"":
                continue
            if after == "(" and "." in tok:
                continue
            if after == "." and ge + 1 < len(line) and (line[ge + 1].isalnum() or line[ge + 1] == "_"):
                continue
            # Strip trailing punctuation (`.`, `,`, `;`, `)`, `?`, `!`).
            trailing = ""
            while tok.endswith((".", ",", ";", ")", "?", "!")) and not tok.endswith("()"):
                # Preserve trailing `()` on function-calls; everything else
                # (period, comma, semicolon, closing paren in prose) goes
                # OUTSIDE the backtick span.
                trailing = tok[-1] + trailing
                tok = tok[:-1]
                e -= 1
            if not tok:
                continue
            out2.append(line[last:s])
            out2.append(f"`{tok}`" + trailing)
            last = e + len(trailing)
            n_changes += 1
        out2.append(line[last:])
        line = "".join(out2)
        n_total += n_changes

    return line, n_total


_AI_PADDING_SENTENCE_RE = re.compile(
    r"([\.!\?]\s+)(?:Additionally|Furthermore|Moreover),\s+",
    re.IGNORECASE,
)
_AI_PADDING_LINE_START_RE = re.compile(
    r"(\*\*[^*]+\*\*:\s+|\s*)(?:Additionally|Furthermore|Moreover),\s+",
    re.IGNORECASE,
)

_RHETORICAL_SEVERITY_RE = re.compile(
    r"\btrivially\s+crackable\b",
    re.IGNORECASE,
)

# 2026-05 R-7 — Inverse to path-wrapping: strip backticks from tokens that
# are LABELS / FIELD NAMES / bare HTTP-method nouns, not code fragments.
# Mirrors ``qa_checks.check_label_as_code`` — same curated allowlist.
_LABEL_TOKENS_TO_UNWRAP: frozenset[str] = frozenset(
    {
        # MS / threat-register / mitigation-register field labels
        "Why",
        "How",
        "Effort",
        "Priority",
        "Severity",
        "Addresses",
        "Component",
        "Components",
        "Mitigation",
        "Mitigations",
        "Notes",
        "Vektor",
        "Classification",
        "Issue",
        "Impact",
        "Fix",
        "Location",
        "Evidence",
        "Verification",
        "Steps",
        # Schema column / field names in lower case
        "notes",
        "addresses",
        "priority",
        "effort",
        "severity",
        "verify",
        # HTTP methods written as bare nouns
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    }
)
_LABEL_AS_CODE_RE = re.compile(r"`(?P<token>[A-Za-z]{3,15})`")


def _apply_label_as_code_unwrap(line: str) -> tuple[str, int]:
    """Strip backticks from single-word tokens that match the label
    allowlist. Anything outside the allowlist stays backticked (it is
    likely a legitimate code reference such as ``eval`` or ``null``)."""
    n = 0

    def _sub(m: re.Match[str]) -> str:
        nonlocal n
        tok = m.group("token")
        if tok in _LABEL_TOKENS_TO_UNWRAP:
            n += 1
            return tok
        return m.group(0)

    new_line = _LABEL_AS_CODE_RE.sub(_sub, line)
    return new_line, n


def _apply_ai_padding_fixes(line: str) -> tuple[str, int]:
    """Remove `Additionally,` / `Furthermore,` / `Moreover,` transitional
    filler at sentence boundaries."""
    line, n1 = _AI_PADDING_SENTENCE_RE.subn(lambda m: m.group(1), line)
    line, n2 = _AI_PADDING_LINE_START_RE.subn(lambda m: m.group(1), line)
    return line, n1 + n2


def _apply_rhetorical_severity(line: str) -> tuple[str, int]:
    """Rewrite the single most-common rhetorical adjective phrase."""
    new = _RHETORICAL_SEVERITY_RE.sub("recoverable by GPU dictionary attack within seconds", line)
    return new, (1 if new != line else 0)


def _apply_perimeter_claim_strip(line: str) -> tuple[str, int]:
    """Remove standalone perimeter-absence sentences. Only collapses
    interior runs of whitespace introduced by the deletion — the leading
    indentation is preserved so bullet structures are not flattened."""
    new, removed = strip_perimeter_absence_sentences(line)
    return new, len(removed)


def _rewrite_controls_covered_anchors(text: str) -> tuple[str, int]:
    """Recompute every `**Controls covered:**` link target under §7.x.
    Slugs are derived from the actual `#### ...` subsection headings
    inside the same `### 7.x` block, so any LLM rename of a subsection
    no longer breaks the link mapping."""
    lines = text.split("\n")
    # Build per-section list of (heading_text, slug).
    sections: dict[str, list[tuple[str, str]]] = {}
    current_sec: str | None = None
    sec_header_re = re.compile(r"^###\s+(7\.\d+)\s+(.+?)\s*$")
    sub_header_re = re.compile(r"^####\s+(.+?)\s*$")
    for ln in lines:
        m3 = sec_header_re.match(ln)
        if m3:
            current_sec = m3.group(1)
            sections.setdefault(current_sec, [])
            continue
        if ln.startswith("## ") or ln.startswith("### "):
            current_sec = None
            continue
        if current_sec is None:
            continue
        m4 = sub_header_re.match(ln)
        if m4:
            h = m4.group(1)
            sections[current_sec].append((h, github_slug(h)))

    n_fixes = 0
    current_sec = None
    cc_re = re.compile(r"^(\s*)\*\*Controls covered:\*\*\s*(.*)$")
    bullet_re = re.compile(r"^(\s*)-\s+\[[^\]]+\]\(#[a-z0-9-]+\)\s*$")
    for idx, ln in enumerate(lines):
        m3 = sec_header_re.match(ln)
        if m3:
            current_sec = m3.group(1)
            continue
        if ln.startswith("## ") or ln.startswith("### "):
            current_sec = None
            continue
        if current_sec is None or current_sec not in sections:
            continue
        if not sections[current_sec]:
            continue
        m_cc = cc_re.match(ln)
        if not m_cc:
            continue
        indent, inline_rest = m_cc.group(1), m_cc.group(2).strip()

        # The composer (compose_threat_model Pass 2) bulletizes the
        # `**Controls covered:**` link line into a header-only line followed by a
        # `- [name](#slug)` list. When that bullet layout is present, the LIST is
        # the canonical rendering — re-inlining the links onto the header here
        # produced the §7 double-listing the user reported (the inline `· `-joined
        # links AND the bullet list both showing the same sub-controls). So in
        # the bulletized form we keep the header bare and only refresh the bullet
        # anchors for heading-rename drift; we never re-add inline links.
        j = idx + 1
        while j < len(lines) and lines[j].strip() == "":
            j += 1
        if j < len(lines) and bullet_re.match(lines[j]):
            if inline_rest:
                lines[idx] = f"{indent}**Controls covered:**"
                n_fixes += 1
            canon = sections[current_sec]
            k, bi = j, 0
            while k < len(lines) and bullet_re.match(lines[k]) and bi < len(canon):
                h, s = canon[bi]
                new_b = f"{indent}- [{h}](#{s})"
                if lines[k] != new_b:
                    lines[k] = new_b
                    n_fixes += 1
                k += 1
                bi += 1
            continue

        # Legacy inline form (no bullet list follows): preserve the historical
        # single-line `**Controls covered:** a · b` rendering with fresh anchors.
        bullets = [f"[{h}](#{s})" for h, s in sections[current_sec]]
        canonical = f"{indent}**Controls covered:** " + " · ".join(bullets)
        if ln != canonical:
            lines[idx] = canonical
            n_fixes += 1
    return "\n".join(lines), n_fixes


_THREAT_TABLE_ROW_RE = re.compile(
    r"^(\s*\|\s*(?:<a\s+id=\"[^\"]+\"></a>\s*)*(?:T|F|M)-\d{3,4}\s*\|\s*)"
    r"([^|]+?)"
    r"(\s*\|)"
)


def _bulletize_relevant_findings(text: str) -> tuple[str, int]:
    """Rewrite ``**Relevant findings:** [F-NNN](...) ... [F-NNN](...)``
    single-line dense paragraphs into the canonical bullet-list form:

        **Relevant findings**

        - [F-NNN](#f-nnn) — title

    The QA helper ``paragraph_density`` warns whenever 3+ finding refs
    appear in one prose line; auto-converting closes that warning class
    deterministically. The colon-suffixed inline form is also forbidden
    by the renderer prompt (``agents/appsec-threat-renderer.md`` § "Per-
    H4 subcontrol block — required elements").
    """
    inline_re = re.compile(
        r"^(?P<indent>\s*)\*\*Relevant findings:\*\*\s+(?P<body>.+?)$",
        re.MULTILINE,
    )
    finding_re = re.compile(r"\[(?:F|T|M)-\d{3,4}\]\(#(?:f|t|m)-\d{3,4}\)")
    n_fixes = 0
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        m = inline_re.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        body = m.group("body")
        indent = m.group("indent")
        # Split into finding-with-rationale tuples, splitting on bullet
        # separators commonly used in inline forms (·, ,, ;).
        # Use the finding_re to walk the body in order.
        items: list[tuple[str, str]] = []
        matches = list(finding_re.finditer(body))
        for pos, fm in enumerate(matches):
            link = fm.group(0)
            next_start = matches[pos + 1].start() if pos + 1 < len(matches) else len(body)
            tail = body[fm.end() : next_start]
            rationale = re.sub(r"^\s*[—\-,;·•]\s*", "", tail).strip().rstrip(".·,;")
            items.append((link, rationale))
        if len(items) < 2:
            # Single finding — leave alone (already concise).
            out.append(lines[i])
            i += 1
            continue
        out.append(f"{indent}**Relevant findings**")
        out.append("")
        for link, rationale in items:
            if rationale:
                out.append(f"{indent}- {link} — {rationale}")
            else:
                out.append(f"{indent}- {link}")
        n_fixes += 1
        i += 1
    return "\n".join(out), n_fixes


def _normalize_title_path_tail(text: str) -> tuple[str, int]:
    """Normalize legacy ``Weakness — file[:line]`` title cells to the
    canonical parenthesised form ``Weakness (file[:line])``.

    Matches patterns like ``Hardcoded RSA private key — lib/insecurity.ts:23``
    inside a threat-register table row. Skips cells that already contain
    backticks because those are usually code identifiers rather than the
    canonical title suffix.
    """
    path_tail_re = re.compile(r"(\s—\s+)((?:[A-Za-z][\w.-]*/)+[\w./-]+\.\w+(?::\d+)?)(?=\s*$)")
    n = 0
    new_lines = []
    for ln in text.split("\n"):
        m = _THREAT_TABLE_ROW_RE.match(ln)
        if not m:
            new_lines.append(ln)
            continue
        title_cell = m.group(2)
        if "`" in title_cell:
            new_lines.append(ln)
            continue
        new_title, c = path_tail_re.subn(lambda mm: f" ({mm.group(2)})", title_cell)
        if c:
            n += c
            new_lines.append(m.group(1) + new_title + m.group(3) + ln[m.end() :])
        else:
            new_lines.append(ln)
    return "\n".join(new_lines), n


_ANCHOR_ONLY_LINE = re.compile(r'^[ \t]*(?:<a id="[^"]*"></a>)+[ \t]*$')


def _collapse_consecutive_anchors(text: str) -> tuple[str, int]:
    """Join runs of consecutive anchor-only lines (``<a id="x"></a>``) into ONE
    line. Stacked empty-anchor blocks render with inconsistent vertical gaps
    before headings (a heading with 2 alias anchors gets more whitespace than
    one with 1 — the 2026-05-30 "uneinheitliche Freiräume vor 7.8.1" report).
    Collapsing every run to a single line makes the pre-heading spacing uniform.
    Skips fenced code blocks."""
    lines = text.split("\n")
    out: list[str] = []
    fixes = 0
    i = 0
    in_fence = False
    while i < len(lines):
        ln = lines[i]
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(ln)
            i += 1
            continue
        if not in_fence and _ANCHOR_ONLY_LINE.match(ln):
            run = [ln.strip()]
            j = i + 1
            while j < len(lines) and not lines[j].lstrip().startswith("```") and _ANCHOR_ONLY_LINE.match(lines[j]):
                run.append(lines[j].strip())
                j += 1
            fixes += len(run) - 1
            out.append("".join(run))
            i = j
        else:
            out.append(ln)
            i += 1
    return "\n".join(out), fixes


def _escape_bare_dollars(text: str) -> tuple[str, int]:
    """Escape unescaped ``$`` in prose so a ``$where``-style token cannot open a
    KaTeX/LaTeX math span in math-enabled markdown viewers — which then swallows
    everything up to the next ``$``/``#`` and throws a parse error (the
    2026-05-30 "ParseError: KaTeX … got '#'" report in the Findings index).
    Skips fenced code blocks AND inline code spans (``$`` is literal there).
    ``\\$`` also renders as a plain ``$`` in non-math markdown, so this is safe
    everywhere. Runs LAST so no earlier transform re-introduces a bare ``$``."""
    fixes = 0
    out_parts: list[str] = []
    for chunk in re.split(r"(```.*?```)", text, flags=re.DOTALL):
        if chunk.startswith("```"):
            out_parts.append(chunk)
            continue
        sub: list[str] = []
        for piece in re.split(r"(`[^`\n]*`)", chunk):
            if len(piece) >= 2 and piece.startswith("`") and piece.endswith("`"):
                sub.append(piece)
            else:
                new, n = re.subn(r"(?<!\\)\$", r"\\$", piece)
                fixes += n
                sub.append(new)
        out_parts.append("".join(sub))
    return "".join(out_parts), fixes


def apply_fixes(text: str) -> tuple[str, int]:
    """Apply all prose-fix classes outside fenced blocks. Returns
    (new_text, n_fixes_total)."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_fence = False
    in_html_block = False
    inline_fixes = 0
    padding_fixes = 0
    rhetorical_fixes = 0
    perimeter_fixes = 0
    for raw in lines:
        # Strip trailing newline for inspection, restore at write time.
        nl = "\n" if raw.endswith("\n") else ""
        line = raw[:-1] if nl else raw
        stripped = line.lstrip()
        # Track fence state.
        if stripped.startswith("```"):
            in_fence = not in_fence
            out.append(raw)
            continue
        if in_fence:
            out.append(raw)
            continue
        # Skip headings; track HTML-blockquote blocks. Table rows used to
        # be skipped entirely; 2026-05 R-7 fix changes that — the §8
        # Findings Register cells embed prose ("Issue", "Impact",
        # "Classification" labelled fields) that benefit from code-token
        # wrapping just like normal prose. The expanded forbidden-zone
        # mask in ``_wrap_line`` (now includes <details>, <pre>, <code>
        # blocks and Markdown link labels) protects the embedded source
        # snippets from accidental rewriting.
        is_heading = stripped.startswith("#")
        is_table_row = stripped.startswith("|")
        if "<blockquote" in stripped:
            in_html_block = True
        if in_html_block:
            if "</blockquote>" in stripped:
                in_html_block = False
            out.append(raw)
            continue
        if is_heading:
            out.append(raw)
            continue
        # Path-wrapping runs on prose AND table rows. AI-padding /
        # rhetorical / perimeter passes stay prose-only — they would
        # change the visible cell content in ways that the table reader
        # cannot easily reconcile against the YAML source.
        new_line, n1 = _wrap_line(line)
        inline_fixes += n1
        # R-7 (2026-05): unwrap labels / field names / bare HTTP methods
        # that got incorrectly backticked. Runs on prose AND table rows
        # so a `**Notes**` column reference (legitimately a label) in §5
        # Attack Surface or §8 Findings Register doesn't read as code.
        new_line, n5 = _apply_label_as_code_unwrap(new_line)
        inline_fixes += n5
        if not is_table_row:
            new_line, n2 = _apply_ai_padding_fixes(new_line)
            padding_fixes += n2
            new_line, n3 = _apply_rhetorical_severity(new_line)
            rhetorical_fixes += n3
            new_line, n4 = _apply_perimeter_claim_strip(new_line)
            perimeter_fixes += n4
        out.append(new_line + nl)
    body = "".join(out)
    # Whole-document post-processors (need cross-line context).
    body, anchor_fixes = _rewrite_controls_covered_anchors(body)
    body, title_fixes = _normalize_title_path_tail(body)
    body, bullet_fixes = _bulletize_relevant_findings(body)
    body, anchor_collapse_fixes = _collapse_consecutive_anchors(body)
    body, dollar_fixes = _escape_bare_dollars(body)  # run LAST
    body, section8_fixes = _canonicalize_section8_name(body)
    total = (
        inline_fixes
        + padding_fixes
        + rhetorical_fixes
        + perimeter_fixes
        + anchor_fixes
        + title_fixes
        + bullet_fixes
        + anchor_collapse_fixes
        + dollar_fixes
        + section8_fixes
    )
    return body, total


def _canonicalize_section8_name(text: str) -> tuple[str, int]:
    """Rewrite the renamed §8 section everywhere it survives in LLM-authored
    fragments (2026-06-02 'Threat Register' → 'Findings Register'). The heading
    and the deterministic cross-refs already use the new name; this catches the
    stale label + dead `#8-threat-register` anchor that older fragments (or LLM
    drift) still carry, so the links resolve to the renamed heading. Idempotent."""
    n = text.count("#8-threat-register") + text.count("Threat Register")
    text = text.replace("#8-threat-register", "#8-findings-register")
    text = text.replace("§8 Threat Register", "§8 Findings Register")
    text = text.replace('Section 8 "Threat Register"', 'Section 8 "Findings Register"')
    text = text.replace("Threat Register", "Findings Register")  # any residual label
    return text, n


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: apply_prose_fixes.py <threat-model.md>", file=sys.stderr)
        return 2
    md_path = Path(argv[0])
    if not md_path.is_file():
        print(f"apply_prose_fixes: no md at {md_path}", file=sys.stderr)
        return 1
    text = md_path.read_text(encoding="utf-8")
    new_text, n_fixes = apply_fixes(text)
    if n_fixes:
        md_path.write_text(new_text, encoding="utf-8")
        print(
            # Note: `rhetorical-severity` here only rewrites the one phrase
            # `trivially crackable` → `recoverable by GPU dictionary attack
            # within seconds`. The full prose-style.md Rule 2 vocabulary
            # (catastrophic / devastating / wreaks havoc / …) is DETECTED by
            # `qa_checks.check_rhetorical_severity` (9 patterns) but is NOT
            # auto-rewritten here because those phrases require context to
            # replace meaningfully. Treat residual `rhetorical_severity`
            # QA issues as Stage-2-LLM authoring drift, not a fixer gap.
            f"apply_prose_fixes: applied {n_fixes} fix(es) in {md_path.name} "
            f"(path-backticks + ai-padding + rhetorical-severity[crackable-phrase only] "
            f"+ perimeter-claim + controls-covered-anchors + title-path-normalization "
            f"+ relevant-findings-bullets)"
        )
    else:
        print("apply_prose_fixes: no fixable prose-style violations found")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
