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
)
_PATH_RE = re.compile(
    r"(?P<path>[A-Za-z][\w.-]*/[\w./-]+\.(?:"
    + "|".join(_EXTENSIONS)
    + r")(?::\d+)?)"
)
_BACKTICK_SPAN_RE = re.compile(r"`[^`\n]+`")
_MD_LINK_URL_RE = re.compile(r"\]\(([^)]+)\)")
_HTML_ATTR_RE = re.compile(r'(?:href|src|action|formaction)="[^"]+"')


def _wrap_line(line: str) -> tuple[str, int]:
    """Return (rewritten_line, n_changes)."""
    # Build a mask of byte ranges that must NOT be rewritten.
    forbidden: list[tuple[int, int]] = []
    for span_re in (_BACKTICK_SPAN_RE, _MD_LINK_URL_RE, _HTML_ATTR_RE):
        for m in span_re.finditer(line):
            forbidden.append((m.start(), m.end()))
    forbidden.sort()

    def overlaps_forbidden(s: int, e: int) -> bool:
        for fs, fe in forbidden:
            if s < fe and e > fs:
                return True
        return False

    matches = list(_PATH_RE.finditer(line))
    if not matches:
        return line, 0
    out: list[str] = []
    last = 0
    n_changes = 0
    for m in matches:
        s, e = m.start(), m.end()
        tok = m.group("path")
        if "*" in tok:
            continue
        if overlaps_forbidden(s, e):
            continue
        out.append(line[last:s])
        out.append(f"`{tok}`")
        last = e
        n_changes += 1
    out.append(line[last:])
    return "".join(out), n_changes


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
        # Skip headings + table rows for prose-only fix classes;
        # path-wrapping still runs everywhere except code / blockquote.
        is_heading_or_table = stripped.startswith("#") or stripped.startswith("|")
        # Track HTML blockquote blocks (best-effort).
        if "<blockquote" in stripped:
            in_html_block = True
        if in_html_block:
            if "</blockquote>" in stripped:
                in_html_block = False
            out.append(raw)
            continue
        if is_heading_or_table:
            out.append(raw)
            continue
        new_line, n1 = _wrap_line(line)
        inline_fixes += n1
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
