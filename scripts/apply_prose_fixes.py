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
   line under a ``### 6.x`` section, recompute the link targets from the
   ``#### ...`` subsection headings actually present in the rendered MD.
   This closes the LLM-rename slug-drift class entirely (was the source
   of all 60 §6.x ``toc_closure`` / ``control_subsection_coverage`` issues
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
  - Backtick or tilde fenced code blocks
  - Headings (`#`/`##`/… lines)
  - Existing backticked spans
  - Markdown-link URLs `[label](path)`
  - HTML attributes (`href="…"`, `src="…"`)
  - Raw `<details>`, `<pre>`, and `<code>` blocks

Tables and blockquote prose are included so the same token is formatted in every visible report section. Globs are code under prose-style Rule 6.

Whole-document post-processors still touch narrowly scoped table rows for
canonical threat-title fallback normalization.

Idempotent — a second run on the same file produces no diff.

Usage:
    python3 apply_prose_fixes.py <threat-model.md>
"""

from __future__ import annotations

import functools
import html
import re
import sys
from pathlib import Path
from typing import Iterable

import yaml
from _atomic_io import atomic_write_text
from _slug import github_render_slug
from inline_code_formatter import (
    MarkdownScanState,
)
from inline_code_formatter import (
    format_inline_code as _format_inline_code_canonical,
)
from perimeter_patterns import strip_perimeter_absence_sentences

PLUGIN_ROOT = Path(__file__).resolve().parent.parent

# --- Split code-span repair -------------------------------------------------
# The LLM routinely backticks only the HEAD of a code token and leaves the
# continuation bare:
#     `request.data`['role']            `requests.get`(url, timeout=3)
#     `/api/integration/fetch`?url=     `JWT_SIGNING_KEY` = b'…'
# The result is worse than no span at all, because the break lands INSIDE an
# identifier and the reader sees two half-tokens. These passes pull the
# continuation back into the span. They run at the TOP of `_wrap_line`, so the
# repaired span is already a forbidden zone for every token pass that follows.
# Idempotent by construction: once merged, the tail is inside the backticks and
# no pattern matches again.
# The head must be a single code TOKEN — no whitespace. A permissive
# `[^`\n]+` head does not know that backticks pair up, so the engine happily
# treats the CLOSING backtick of one span and the OPENING backtick of the next
# as a pair and swallows the prose between them:
#     available in `.route-inventory.json`
#   → `…category … available in .route`-inventory.json`
# (found 2026-07-19 by re-running the formatter over a whole real report —
# per-string tests cannot surface it, because it needs two spans on one line).
# Prose between two spans always contains a space, so excluding whitespace
# eliminates the entire class. Every legitimate head is space-free:
# `request.data`, `/api/legacy-admin/audit`, `db.py:461`, `requests.get`.
_SPAN_HEAD = r"`(?P<head>[^`\s\n]+)`"
# The tail must start with a LETTER. Allowing a leading `_` made the pass merge
# a Markdown emphasis closer into the span — ``\`pentest-tasks.yaml\`._`` (the
# `_` closing an italic run) became ``\`pentest-tasks.yaml._\``, silently
# eating the emphasis marker. Members that genuinely start with `_` are rare
# and dunders are covered by `_CONST_IDENT_RE`.
_SPLIT_DOTTED_RE = re.compile(_SPAN_HEAD + r"\.(?P<tail>[A-Za-z]\w*(?:\.[A-Za-z_]\w*)*)(?![\w`(])")
# No tail may CONTAIN a backtick. A continuation is by definition outside every
# span, so a tick inside one means the pattern has crossed into the next span
# and is reading the line on a wrong pairing. Without this, a remediation line
# whose snippet already had ticks interleaved mid-expression got merged further
# apart instead of being left alone (2026-07-19, real report line 3881).
_SPLIT_SUBSCRIPT_RE = re.compile(_SPAN_HEAD + r"(?P<tail>(?:\[[^\[\]`\n]{1,40}\])+)(?![\w`])")
_SPLIT_QUERY_RE = re.compile(_SPAN_HEAD + r"(?P<tail>\?[\w=&%.:/<>-]{1,80})(?![\w`])")
_SPLIT_RANGE_RE = re.compile(r"`(?P<head>[^`\n]*:\d+)`-(?P<tail>\d+)\b")
# `requests.get`(url, timeout=3) — the head must be a bare dotted identifier
# (no `:`), so a `file.py:550`(…) evidence ref can never be swallowed.
_SPLIT_CALLARGS_RE = re.compile(r"`(?P<head>[A-Za-z_][\w.]*)`(?P<tail>\([^()`\n]{1,60}\))(?![\w`])")
# `JWT_SIGNING_KEY` = b'…' — the VALUE gets its own span rather than being
# merged into the name's. The `=` sits in prose ("obtains X = Y"); swallowing
# it would turn a sentence fragment into one long unreadable code token.
_SPLIT_ASSIGN_VALUE_RE = re.compile(r"(?P<lead>`[A-Za-z_][\w.]*`\s*=\s*)(?P<val>[bru]?[\"'][^\"'\n]{1,80}[\"'])(?!`)")
# Prose words that mark a `(...)` as an English aside rather than call args.
_PROSE_ASIDE_RE = re.compile(r"\b(?:the|a|an|which|that|and|or|not|see|e\.g|i\.e|via)\b", re.IGNORECASE)


def _looks_like_call_args(tail: str) -> bool:
    """True when a trailing ``(...)`` reads as call ARGUMENTS, not a prose aside.

    ``(url, timeout=3)`` → arguments. ``(the legacy path)`` → prose. Without
    this gate the call-args merge would swallow ordinary parentheticals that
    happen to follow a code span.
    """
    inner = tail.strip("()").strip()
    if not inner:
        return True
    if _PROSE_ASIDE_RE.search(inner):
        return False
    # English optional-plural suffix — `weakness(es)`, `finding(s)`, `step(s)`,
    # `point(s)`. Structurally identical to a one-argument call, so only the
    # shape of the argument separates them: no real argument is a bare
    # one-to-three-letter lowercase word. Without this the formatter backticked
    # nine distinct prose pluralisations in a single real report (2026-07-19).
    if re.fullmatch(r"[a-z]{1,3}", inner):
        return False
    return bool(re.fullmatch(r"[\w'\"`.,:=\[\]{}*/+\s-]+", inner))


def _merge_split_code_spans(line: str) -> tuple[str, int]:
    """Pull un-backticked continuations back into the code span they belong to."""
    # Ambiguous-pairing guard. Every pattern here assumes the backticks on the
    # line pair up, so it can tell a span's closing tick from the next span's
    # opening tick. On an odd count that assumption is false and a merge lands
    # on the wrong boundary, deepening damage the composer already shipped
    # (real case: a §9 remediation line whose LLM-authored snippet interleaved
    # ticks mid-expression). Leaving a malformed line untouched is strictly
    # better than rewriting it on a wrong reading.
    if line.count("`") % 2:
        return line, 0
    n = 0
    for pat, repl in (
        (_SPLIT_DOTTED_RE, r"`\g<head>.\g<tail>`"),
        (_SPLIT_SUBSCRIPT_RE, r"`\g<head>\g<tail>`"),
        (_SPLIT_QUERY_RE, r"`\g<head>\g<tail>`"),
        (_SPLIT_RANGE_RE, r"`\g<head>-\g<tail>`"),
        (_SPLIT_ASSIGN_VALUE_RE, r"\g<lead>`\g<val>`"),
    ):
        line, k = pat.subn(repl, line)
        n += k

    def _merge_call(m: re.Match[str]) -> str:
        if not _looks_like_call_args(m.group("tail")):
            return m.group(0)
        return f"`{m.group('head')}{m.group('tail')}`"

    line, k = _SPLIT_CALLARGS_RE.subn(_merge_call, line)
    return line, n + k


_BACKTICK_SPAN_RE = re.compile(r"`[^`\n]+`")


def _html_block_body_wrappable(stripped: str) -> bool:
    """True when a line inside an HTML `<blockquote>` block is plain Markdown
    prose that should still get code-token backticking.

    The styled `<blockquote>` the §1 Management-Summary critical-gaps list is
    rendered in is presentation only — its BODY is ordinary prose. Skipping the
    whole block meant `.github/workflows/image_actions.yml:33` stayed bare there
    while every other section rendered it wrapped, and the QA reference-format
    gate then raised a `manual_review` the repair loop structurally cannot clear
    (it is composed, not authored in any fragment — juice-shop 2026-07-27, F-010).

    Conservative boundary: any line carrying markup — the wrapper tags
    themselves, `<br/>`, inline HTML — is left untouched. `_wrap_line`'s mask
    does protect HTML attributes, but not rewriting those lines at all is the
    cheaper guarantee and keeps this fix off the styled-wrapper path entirely.
    """
    return "<" not in stripped


_HTML_CELL_RE = re.compile(r"<t[dh][\s>]")


def _html_cell_code_spans(line: str) -> tuple[str, int]:
    """Re-emit backtick code spans as `<code>` inside a raw-HTML table cell.

    Every pass above speaks Markdown, which is correct for the GFM pipe tables
    they were written for: a later QA pass converts those to HTML and turns the
    backticks into `<code>` on the way. The §1 Trust Boundaries catalogue is
    different — the composer emits it as a raw `<table>` BEFORE this formatter
    runs, so `stripped.startswith("|")` is false, the row falls through to the
    prose path, and a backtick added there is never converted. Markdown does not
    render inside raw HTML, so the reader saw the character itself (user
    2026-08-01: `` `encryptionkeys/jwt.pub` `` in the assumption column).

    Emitting the tag directly keeps the token formatted in the context it
    actually lands in, rather than dropping the fix on HTML rows. Spans the
    renderer already wrote as `<code>` sit in `_wrap_line`'s forbidden mask and
    never reach this point, so this only ever sees Markdown that would other-
    wise render literally.
    """
    if not _HTML_CELL_RE.search(line):
        return line, 0
    return _backticks_to_code(line)


def _backticks_to_code(text: str) -> tuple[str, int]:
    """`` `x` `` → ``<code>x</code>``. Uses the module's existing span regex
    (no capture group) rather than a second one under the same name — the
    duplicate silently won for `_wrap_line`'s forbidden mask."""
    n = 0

    def _sub(match: re.Match[str]) -> str:
        nonlocal n
        n += 1
        return f"<code>{html.escape(match.group(0)[1:-1], quote=False)}</code>"

    return _BACKTICK_SPAN_RE.sub(_sub, text), n


def _wrap_line(line: str, known_tokens: Iterable[str] = ()) -> tuple[str, int]:
    """Return (rewritten_line, n_changes).

    Multi-pass wrapper — applies each of the registered code-token regexes
    in order, refreshing the ``forbidden`` mask after every pass so a token
    backticked in pass N is treated as forbidden by pass N+1 (prevents
    nested-backtick artifacts like `` ``login.ts`` ``).
    """
    # Repair half-backticked tokens BEFORE any wrapping pass, so the merged
    # span is a single forbidden zone for everything below and no pass sees a
    # token fragment (2026-07-19).
    line, n_total = _merge_split_code_spans(line)

    # The canonical syntax-aware recognizer claims complete balanced
    # expressions. All renderer, walkthrough, autofix, and QA entry points use
    # this same candidate set; there is no second token-pattern pass here.
    line, n_canonical = _format_inline_code_canonical(line, known_tokens)
    n_total += n_canonical

    # A second merge sweep handles a continuation made visible by wrapping a
    # previously bare head. This is delimiter repair, not token recognition.
    line, n_merge = _merge_split_code_spans(line)
    line, n_html = _html_cell_code_spans(line)
    return line, n_total + n_merge + n_html


def format_inline_code(line: str, known_tokens: Iterable[str] = ()) -> tuple[str, int]:
    """Public canonical inline-code API used by every report renderer."""

    return _wrap_line(line, known_tokens)


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


# `**Violates:**` quotes normative requirement text verbatim from the configured
# catalog. The prose passes exist to strip wording the model invented about
# *this* system; a quoted requirement is neither invented nor a claim about it.
# The perimeter strip in particular removes the whole sentence up to the first
# `.`, which takes the label, the link and the requirement ID with it whenever a
# catalog entry happens to mention WAF, SIEM, firewall or the like.
# Anchored on the composer's own shape — the label followed by a requirement ID
# in a code span — so an LLM-authored fragment cannot claim the exemption for
# free prose that merely opens with the same label.
_QUOTED_REQUIREMENT_LINE_RE = re.compile(r"^\s*\*\*Violates:\*\*\s*\[?`[A-Z]")


def _apply_perimeter_claim_strip(line: str) -> tuple[str, int]:
    """Remove standalone perimeter-absence sentences. Only collapses
    interior runs of whitespace introduced by the deletion — the leading
    indentation is preserved so bullet structures are not flattened."""
    new, removed = strip_perimeter_absence_sentences(line)
    return new, len(removed)


def _rewrite_controls_covered_anchors(text: str) -> tuple[str, int]:
    """Recompute every `**Controls covered:**` link target under §6.x.
    Slugs are derived from the actual `#### ...` subsection headings
    inside the same `### 6.x` block, so any LLM rename of a subsection
    no longer breaks the link mapping."""
    lines = text.split("\n")
    # Build per-section list of (heading_text, slug).
    sections: dict[str, list[tuple[str, str]]] = {}
    current_sec: str | None = None
    sec_header_re = re.compile(r"^###\s+(6\.\d+)\s+(.+?)\s*$")
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
            # Link TARGET must be github_render_slug — the anchor GitHub/pandoc
            # actually render — NOT github_slug (the collapsed form). They
            # diverge for any subsection heading carrying ` / `, ` & `, ` — `
            # (e.g. `7.2.3 OAuth / Google Social Login` → GitHub
            # `#623-oauth--google-social-login`, github_slug
            # `#623-oauth-google-social-login`), so the Controls-covered bullet
            # dangled for every such control. toc_closure verifies with
            # render_slug, so this makes them agree; non-divergent headings are
            # byte-identical under both functions (juice-shop 2026-07-02).
            sections[current_sec].append((h, github_render_slug(h)))

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
        # produced the §6 double-listing the user reported (the inline `· `-joined
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
    one with 1 — the 2026-05-30 "inconsistent spacing before 7.8.1" report).
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


_ACTOR_ID_RE = re.compile(r"\bACT-[A-Z]-\d+\b")
_ACTOR_LABEL_EXPAND = {"dev": "developer", "ops": "operator"}


@functools.lru_cache(maxsize=1)
def _actor_id_labels() -> dict:
    """id → human noun phrase from the actor library (e.g. ACT-D-04 →
    'malicious insider developer')."""
    path = PLUGIN_ROOT / "data" / "actors" / "default-library.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    out: dict[str, str] = {}
    for a in data.get("actors") or []:
        aid = a.get("id")
        label = a.get("label") or ""
        if not aid or not label:
            continue
        out[aid] = " ".join(_ACTOR_LABEL_EXPAND.get(w, w) for w in label.split("-"))
    return out


def _humanize_actor_ids(text: str) -> tuple[str, int]:
    """Replace bare ``ACT-<layer>-NN`` library ids in prose with the actor's
    human label (``ACT-D-04`` → ``a malicious insider developer``).

    The §1 actor table now uses the consolidated Management-Summary taxonomy
    (posture ``vektor`` values), so raw ACT-* ids left in LLM-authored scenario
    prose are dangling references. Humanising them keeps the document
    self-consistent without reintroducing the discovery-library codes. Skips
    fenced code, is article-aware (a/an), capitalises at sentence start, and is
    idempotent (the rendered phrase no longer matches the id pattern)."""
    labels = _actor_id_labels()
    if not labels:
        return text, 0
    count = 0

    def _sub(m: re.Match) -> str:
        nonlocal count
        phrase = labels.get(m.group(0))
        if not phrase:
            return m.group(0)
        count += 1
        article = "an" if phrase[:1].lower() in "aeiou" else "a"
        prefix = m.string[: m.start()].rstrip()
        if (not prefix) or prefix.endswith((".", "!", "?", ":")):
            article = article.capitalize()
        return f"{article} {phrase}"

    out_lines: list[str] = []
    in_fence = False
    for raw in text.splitlines(keepends=True):
        if raw.lstrip().startswith("```"):
            in_fence = not in_fence
            out_lines.append(raw)
            continue
        out_lines.append(raw if in_fence else _ACTOR_ID_RE.sub(_sub, raw))
    return "".join(out_lines), count


# Compose drops a column whose every row says the same thing — Source when all
# rows share one provenance, the "/ status" header half when every row is
# `resolved` — so four header forms arrive. All of them keep the crossing at
# index 1 and the assumption at index 4, so the prose-column set is shared.
_TRUST_BOUNDARY_TABLE_HEADERS = tuple(
    tuple(
        ["ID", "Boundary / crossing", "Exposure", kind, "Assumption & verdict"]
        + (["Source"] if with_source else [])
        + ["Linked findings"]
    )
    for kind in ("Kind", "Kind / status")
    for with_source in (False, True)
)
_TRUST_BOUNDARY_PROSE_COLUMNS = frozenset({1, 4})


def _split_unescaped_table_pipes(line: str) -> list[str]:
    """Split a GFM row at unescaped pipes while preserving exact cell text."""
    parts: list[str] = []
    start = 0
    for index, char in enumerate(line):
        if char != "|":
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and line[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2:
            continue
        parts.append(line[start:index])
        start = index + 1
    parts.append(line[start:])
    return parts


def _table_header_cells(line: str) -> tuple[str, ...]:
    parts = _split_unescaped_table_pipes(line.strip())
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return tuple(part.strip() for part in parts)


_HTML_TH_RE = re.compile(r"<th[^>]*>(.*?)</th>", re.S)
_HTML_TD_RE = re.compile(r"(<td[^>]*>)(.*?)(</td>)", re.S)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _html_table_header_cells(line: str) -> tuple[str, ...]:
    """Header texts of a raw-HTML `<thead>` row, shaped like `_table_header_cells`.

    The catalogue reaches this formatter as a GFM pipe table on a clean run, but
    as raw `<table>` on any pass that runs after the QA autofix converted it.
    Without this the row failed `startswith("|")`, the column exemption silently
    lapsed, and every pass ran over the narrative columns (user 2026-08-01).
    """
    # Entities are decoded before comparing. The header text is the join key
    # against `_TRUST_BOUNDARY_TABLE_HEADERS`, and the HTML conversion escapes
    # what it emits — an `&` in a column name arrives here as `&amp;` and would
    # fail to match a header this module spells with a literal `&`, lapsing the
    # exemption exactly as the raw-HTML form did before this function existed.
    return tuple(html.unescape(_HTML_TAG_RE.sub("", cell)).strip() for cell in _HTML_TH_RE.findall(line))


def _format_trust_boundary_html_row(line: str, known_tokens: Iterable[str] = ()) -> tuple[str, int]:
    """`_format_trust_boundary_table_row` for the raw-HTML form of the table."""
    total = 0
    index = -1

    def _cell(match: re.Match[str]) -> str:
        nonlocal total, index
        index += 1
        if index in _TRUST_BOUNDARY_PROSE_COLUMNS:
            return match.group(0)
        formatted, n = _wrap_line(match.group(2), known_tokens)
        formatted, n_unwrap = _apply_label_as_code_unwrap(formatted)
        # `_wrap_line` sees only the cell's inner text, so its own HTML-cell
        # guard cannot fire — convert here, where the context IS known.
        formatted, _ = _backticks_to_code(formatted)
        total += n + n_unwrap
        return match.group(1) + formatted + match.group(3)

    return _HTML_TD_RE.sub(_cell, line), total


def _format_trust_boundary_table_row(line: str, known_tokens: Iterable[str] = ()) -> tuple[str, int]:
    """Format non-prose cells while keeping boundary narrative typography."""
    parts = _split_unescaped_table_pipes(line)
    if len(parts) < min(len(header) for header in _TRUST_BOUNDARY_TABLE_HEADERS) + 2:
        return line, 0
    total = 0
    for part_index in range(1, len(parts) - 1):
        column_index = part_index - 1
        if column_index in _TRUST_BOUNDARY_PROSE_COLUMNS:
            continue
        formatted, n_wrap = _wrap_line(parts[part_index], known_tokens)
        formatted, n_unwrap = _apply_label_as_code_unwrap(formatted)
        parts[part_index] = formatted
        total += n_wrap + n_unwrap
    return "|".join(parts), total


def apply_fixes(text: str, known_tokens: Iterable[str] = ()) -> tuple[str, int]:
    """Apply all prose-fix classes outside fenced blocks. Returns
    (new_text, n_fixes_total)."""
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    scan_state = MarkdownScanState()
    in_html_block = False
    inline_fixes = 0
    padding_fixes = 0
    rhetorical_fixes = 0
    perimeter_fixes = 0
    in_trust_boundary_table = False
    for raw in lines:
        # Strip trailing newline for inspection, restore at write time.
        nl = "\n" if raw.endswith("\n") else ""
        line = raw[:-1] if nl else raw
        stripped = line.lstrip()
        if not scan_state.scannable(line):
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
        is_html_cell_row = "<td" in stripped or "<th" in stripped
        if is_table_row and _table_header_cells(line) in _TRUST_BOUNDARY_TABLE_HEADERS:
            in_trust_boundary_table = True
        elif "<th" in stripped and _html_table_header_cells(line) in _TRUST_BOUNDARY_TABLE_HEADERS:
            in_trust_boundary_table = True
        elif "</table>" in stripped:
            in_trust_boundary_table = False
        elif not is_table_row and not is_html_cell_row and not stripped.startswith("<"):
            # `</table>` ends the raw-HTML form; structural lines between the
            # header and the rows (`<tbody>`, a bare `<tr>`) must NOT, or the
            # column exemption lapses again one line after it was established.
            in_trust_boundary_table = False
        if "<blockquote" in stripped:
            in_html_block = True
        if in_html_block:
            if "</blockquote>" in stripped:
                in_html_block = False
            if _html_block_body_wrappable(stripped):
                new_line, n_bq = _wrap_line(line, known_tokens)
                inline_fixes += n_bq
                out.append(new_line + nl)
            else:
                out.append(raw)
            continue
        if is_heading:
            out.append(raw)
            continue
        if in_trust_boundary_table and is_table_row:
            new_line, n_table = _format_trust_boundary_table_row(line, known_tokens)
            inline_fixes += n_table
            out.append(new_line + nl)
            continue
        if in_trust_boundary_table and "<td" in stripped:
            new_line, n_table = _format_trust_boundary_html_row(line, known_tokens)
            inline_fixes += n_table
            out.append(new_line + nl)
            continue
        # Path-wrapping runs on prose AND table rows. AI-padding /
        # rhetorical / perimeter passes stay prose-only — they would
        # change the visible cell content in ways that the table reader
        # cannot easily reconcile against the YAML source.
        new_line, n1 = _wrap_line(line, known_tokens)
        inline_fixes += n1
        # R-7 (2026-05): unwrap labels / field names / bare HTTP methods
        # that got incorrectly backticked. Runs on prose AND table rows
        # so a `**Notes**` column reference (legitimately a label) in §5
        # Attack Surface or §8 Findings Register doesn't read as code.
        new_line, n5 = _apply_label_as_code_unwrap(new_line)
        inline_fixes += n5
        if not is_table_row and not _QUOTED_REQUIREMENT_LINE_RE.match(line):
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
    body, actor_id_fixes = _humanize_actor_ids(body)
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
        + actor_id_fixes
        + dollar_fixes
        + section8_fixes
    )
    return body, total


def apply_code_formatting(text: str, known_tokens: Iterable[str] = ()) -> tuple[str, int]:
    """Formatting-only subset of ``apply_fixes`` — backtick code/path tokens
    (and normalise title path tails) WITHOUT the prose-content passes
    (AI-padding, rhetorical-severity, perimeter-claim strip).

    This exists so ``qa_checks.cmd_autofix`` can run code-token backticking as a
    self-contained pass right before the §4/§5 GFM→HTML conversion. The skill's
    canonical flow backticks paths via the standalone ``apply_prose_fixes`` step,
    but that runs BEFORE the cell-rebuilding autofix passes, so a later recompose
    (diagnostic, ``--rerender``, or the Re-Render Loop's fragment-fixer) shipped
    the deliverable with bare ``server.ts:663`` / unconverted tables. Folding the
    formatting into autofix makes ``compose → qa_checks autofix`` fully recover.
    Idempotent: an already-backticked token is in the forbidden-zone mask.
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    scan_state = MarkdownScanState()
    in_html_block = False
    in_trust_boundary_table = False
    total = 0
    for raw in lines:
        nl = "\n" if raw.endswith("\n") else ""
        line = raw[:-1] if nl else raw
        stripped = line.lstrip()
        if not scan_state.scannable(line):
            out.append(raw)
            continue
        is_table_row = stripped.startswith("|")
        is_html_cell_row = "<td" in stripped or "<th" in stripped
        if is_table_row and _table_header_cells(line) in _TRUST_BOUNDARY_TABLE_HEADERS:
            in_trust_boundary_table = True
        elif "<th" in stripped and _html_table_header_cells(line) in _TRUST_BOUNDARY_TABLE_HEADERS:
            in_trust_boundary_table = True
        elif "</table>" in stripped:
            in_trust_boundary_table = False
        elif not is_table_row and not is_html_cell_row and not stripped.startswith("<"):
            # `</table>` ends the raw-HTML form; structural lines between the
            # header and the rows (`<tbody>`, a bare `<tr>`) must NOT, or the
            # column exemption lapses again one line after it was established.
            in_trust_boundary_table = False
        if "<blockquote" in stripped:
            in_html_block = True
        if in_html_block:
            if "</blockquote>" in stripped:
                in_html_block = False
            # Same rule as apply_fixes: the wrapper is presentation, its
            # Markdown body still needs code-token backticking.
            if _html_block_body_wrappable(stripped):
                new_line, n_bq = _wrap_line(line, known_tokens)
                total += n_bq
                out.append(new_line + nl)
            else:
                out.append(raw)
            continue
        if in_trust_boundary_table and is_table_row:
            new_line, n_table = _format_trust_boundary_table_row(line, known_tokens)
            total += n_table
            out.append(new_line + nl)
            continue
        if in_trust_boundary_table and "<td" in stripped:
            new_line, n_table = _format_trust_boundary_html_row(line, known_tokens)
            total += n_table
            out.append(new_line + nl)
            continue
        new_line, n1 = _wrap_line(line, known_tokens)
        new_line, n5 = _apply_label_as_code_unwrap(new_line)
        total += n1 + n5
        out.append(new_line + nl)
    body = "".join(out)
    body, title_fixes = _normalize_title_path_tail(body)
    return body, total + title_fixes


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
        atomic_write_text(md_path, new_text)
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
