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
    "ts", "tsx", "js", "jsx", "json", "yaml", "yml",
    "py", "go", "rs", "java", "kt", "rb", "php", "cs",
    "c", "h", "cpp", "hpp", "swift", "scala",
    "md", "html", "css", "scss", "sql",
    "sh", "bash", "ps1", "toml", "lock", "env",
    # Common backup / build artefacts (2026-05): the LLM-authored prose
    # frequently mentions `package.json.bak`, `acquisitions.md`,
    # `incident-support.kdbx` etc. as bare tokens — wrap them too.
    "bak", "kdbx", "pem", "crt", "p12", "key", "pub",
)
_PATH_RE = re.compile(
    r"(?P<path>[A-Za-z][\w.-]*/[\w./-]+\.(?:"
    + "|".join(_EXTENSIONS)
    + r")(?::\d+)?)"
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
    r"(?<![\w`/])"
    # First segment requires ≥ 3 chars after `/` so accidental tokens like
    # `and/or` (`/or` would be only 2 chars) are rejected. Additional
    # segments are optional so `/ftp` and `/etc/passwd` both match.
    r"(?P<urlpath>/[A-Za-z][\w-]{2,}(?:/[\w%:&=.-]+)*)"
    # Allow `.`, `,`, `;`, `)`, `?`, `!` as next character — those are
    # sentence punctuation that the trailing-punct stripper takes care of.
    r"(?![\w/`])"
)
#   - Bare standalone source-filename tokens (no preceding path):
#     `login.ts`, `search.ts:23`, `package.json.bak`, `app.guard.ts:54`.
#     Excludes tokens that already contain a slash (handled by `_PATH_RE`)
#     and excludes domain-like tokens (`owasp.org`, `juice.shop`, `Node.js`)
#     by requiring the extension to be one of our recognised source
#     extensions (a TLD allowlist would be brittle — the extension list IS
#     the allowlist).
_BARE_FILENAME_RE = re.compile(
    r"(?<![\w./`])"
    # Allow multi-dot filenames like `package.json.bak`. The
    # ``(?:\.[A-Za-z0-9-]+)*`` allows zero or more middle dot-segments
    # before the final recognised extension (was ``?`` which capped at
    # one middle segment).
    r"(?P<file>[A-Za-z][\w-]+(?:\.[A-Za-z0-9-]+)*\.(?:"
    + "|".join(_EXTENSIONS)
    + r")(?::\d+)?)"
    # Trailing punctuation (period, comma, semicolon, `)`) is allowed —
    # the trailing-punct stripper handles them.
    r"(?![\w/`])"
)
# 2026-05 — well-known product names that match _BARE_FILENAME_RE but are
# NOT files. Excluded from wrapping so `Node.js` reads as a product name
# in prose ("crashes the Node.js process") instead of as a file token.
# Keep this list narrow — adding a name suppresses wrapping for every
# context, including legitimate file references.
_BARE_FILENAME_ALLOWLIST: frozenset[str] = frozenset({
    "Node.js", "node.js",
    "Vue.js", "vue.js",
    "Next.js", "next.js",
    "Nuxt.js", "nuxt.js",
    "Express.js", "express.js",
    "Backbone.js", "backbone.js",
    "Ember.js", "ember.js",
    "Three.js", "three.js",
})
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
    r"|method:(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)))"
    r"(?![\w`])"
)
#   - HTTP method + URL path pairs: backtick the path portion of
#     `GET /support/logs` → `GET \`/support/logs\``.  The method stays
#     bare so the sentence reads naturally; only the route gets the code
#     span.
_HTTP_METHOD_PATH_RE = re.compile(
    r"\b(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(?P<route>/[A-Za-z][\w/.:%-]+)"
    r"(?![\w/`])"
)
_BACKTICK_SPAN_RE = re.compile(r"`[^`\n]+`")
_MD_LINK_URL_RE = re.compile(r"\]\(([^)]+)\)")
_HTML_ATTR_RE = re.compile(r'(?:href|src|action|formaction)="[^"]+"')
# 2026-05 — additional forbidden zones for the §8 Threat Register cells.
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
        (_URL_PATH_RE, "urlpath"),
        (_BARE_FILENAME_RE, "file"),
        (_FUNCTION_CALL_RE, "fn"),
        (_LITERAL_TOKEN_RE, "lit"),
        (_PATH_RE, "path"),
    ]

    for pat, group_or_special in pass_order:
        forbidden: list[tuple[int, int]] = []
        for span_re in (
            _BACKTICK_SPAN_RE,
            _MD_LINK_URL_RE,
            _MD_LINK_LABEL_RE,
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
_LABEL_TOKENS_TO_UNWRAP: frozenset[str] = frozenset({
    # MS / threat-register / mitigation-register field labels
    "Why", "How", "Effort", "Priority", "Severity",
    "Addresses", "Component", "Components", "Mitigation", "Mitigations",
    "Notes", "Vektor", "Classification", "Issue", "Impact", "Fix",
    "Location", "Evidence",
    "Verification", "Steps",
    # Schema column / field names in lower case
    "notes", "addresses", "priority", "effort", "severity",
    "verify",
    # HTTP methods written as bare nouns
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
})
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
    new = _RHETORICAL_SEVERITY_RE.sub(
        "recoverable by GPU dictionary attack within seconds", line
    )
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
    cc_re = re.compile(r"^(\s*)\*\*Controls covered:\*\*\s*.*$")
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
        indent = m_cc.group(1)
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
            tail = body[fm.end():next_start]
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
    path_tail_re = re.compile(
        r"(\s—\s+)((?:[A-Za-z][\w.-]*/)+[\w./-]+\.\w+(?::\d+)?)(?=\s*$)"
    )
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
        new_title, c = path_tail_re.subn(
            lambda mm: f" ({mm.group(2)})", title_cell
        )
        if c:
            n += c
            new_lines.append(m.group(1) + new_title + m.group(3) + ln[m.end():])
        else:
            new_lines.append(ln)
    return "\n".join(new_lines), n


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
        # Threat Register cells embed prose ("Issue", "Impact",
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
        # Attack Surface or §8 Threat Register doesn't read as code.
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
    total = (
        inline_fixes
        + padding_fixes
        + rhetorical_fixes
        + perimeter_fixes
        + anchor_fixes
        + title_fixes
        + bullet_fixes
    )
    return body, total


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
            f"apply_prose_fixes: applied {n_fixes} fix(es) in {md_path.name} "
            f"(path-backticks + ai-padding + rhetorical-severity + perimeter-claim "
            f"+ controls-covered-anchors + title-path-normalization + "
            f"relevant-findings-bullets)"
        )
    else:
        print("apply_prose_fixes: no fixable prose-style violations found")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
