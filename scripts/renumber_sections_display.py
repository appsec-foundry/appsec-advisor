#!/usr/bin/env python3
"""Cosmetically renumber §7-§11 to §6-§10 in an ALREADY-RENDERED, ALREADY-VALIDATED
threat-model.md so the reader sees contiguous 1..10 top-level numbering instead of
the 1-5, 7-11 gap left by §6's retirement.

Why this is a separate, LAST-mile script instead of a contract rename
-----------------------------------------------------------------------
§7.x subsection titles ("7.2 Identity and Authentication Controls", …) are semantic
contract keys matched verbatim by `qa_checks.py` (method_whitelist, domain_required_rules,
finding_routing) and authored verbatim by the architect LLM agent from
`data/sections-contract.yaml`. Renaming those everywhere (contract + qa_checks +
agent prompts + ~40 scripts + ~90 tests) is a large, coupled, all-repo change with
real collision risk that a prior session explicitly avoided (commit 64029a2).

Instead, this script relabels ONLY the final rendered document text — heading
numbers, anchor ids/hrefs, and inline `§N` prose references — leaving every
internal contract key, LLM prompt, and qa_checks match target as "7.x" forever.
It MUST run strictly AFTER `qa_checks.py contract`/`final_structure` have
validated the canonical (7-11)-numbered document, never before or in place of
`compose_threat_model.render()` — running it earlier would make qa_checks reject
the renumbered headings as not matching the contract's literal titles.

Usage
-----
    python3 scripts/renumber_sections_display.py <threat-model.md> [--dry-run]

Writes the renumbered document back to the same path (atomic write), unless
--dry-run is given (prints a unified diff to stdout instead).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _slug import github_slug  # noqa: E402  (single source of truth, mirrors compose)

# Top-level number remap. Order matters only for readability — each is matched by
# its own capture, not by sequential string replacement, so there is no cascade risk
# (see _renumber_heading_line / _collect_anchor_map below).
_TOP_LEVEL_MAP = {"7b": "6b", "7": "6", "8": "7", "9": "8", "10": "9", "11": "10"}

# A heading's own top-level number, e.g. "7.2.1" -> "7", "7b" -> "7b", "11" -> "11".
_TOP_TOKEN_RE = re.compile(r"^(\d+)(b)?")

_HEADING_RE = re.compile(r"^(#{2,4})\s+(\d+[a-z]?(?:\.\d+){0,2})\.?\s+(.*)$")
_TOC_TOP_RE = re.compile(r"^(\d+[a-z]?)\.\s+\[")
_BARE_BRACKET_SUBSECTION_RE = re.compile(r"\[(\d+(?:\.\d+){1,2})\s")
_SECTION_SYMBOL_RE = re.compile(r"§(\d+[a-z]?(?:\.\d+){0,2})\b")
_GAP_NOTE_RE = re.compile(
    r"\n?> _Section numbering is non-contiguous:.*?_\n?",
)


def _new_top_level(old_top: str) -> str | None:
    return _TOP_LEVEL_MAP.get(old_top)


def _renumber_token(old_number: str) -> str | None:
    """ "7.2.1" -> "6.2.1"; "7b" -> "6b"; "11" -> "10". None when not in scope."""
    m = _TOP_TOKEN_RE.match(old_number)
    if not m:
        return None
    top = m.group(1) + (m.group(2) or "")
    new_top = _new_top_level(top)
    if new_top is None:
        return None
    return new_top + old_number[len(top) :]


def _collect_heading_renumbers(text: str) -> list[tuple[str, str, str, str]]:
    """Scan heading lines in scope; return [(old_heading_line, new_heading_line,
    old_anchor, new_anchor), ...] using the SAME slug function compose uses, so
    anchors round-trip byte-identically instead of being hand-derived."""
    out: list[tuple[str, str, str, str]] = []
    for line in text.splitlines():
        m = _HEADING_RE.match(line)
        if not m:
            continue
        hashes, number, title = m.group(1), m.group(2), m.group(3)
        new_number = _renumber_token(number)
        if new_number is None:
            continue
        # Top-level headings ("## 7. Title") carry a period after the number;
        # subsection/sub-subsection headings ("### 7.2 Title", "#### 7.2.1
        # Title") do not — preserve whichever the ORIGINAL heading used
        # instead of always injecting one (that produced a stray "6.2." for
        # subsections).
        sep = ". " if "." not in number else " "
        new_heading_text = f"{new_number}{sep}{title}"
        old_anchor = github_slug(f"{number}{sep}{title}")
        new_anchor = github_slug(new_heading_text)
        new_line = f"{hashes} {new_heading_text}"
        out.append((line, new_line, old_anchor, new_anchor))
    return out


_CANONICAL_MARKER_RE = re.compile(r'(?m)^## 7\. Security Architecture$|id="7-security-architecture"')


def renumber_sections_display(text: str) -> str:
    """Return `text` with §7-§11 cosmetically relabeled to §6-§10.

    Guarded, NOT purely idempotent by construction: after one run, the document's
    headings are 6-10, and a naive number-in-scope check would treat the new "7"
    (from the old "8") as still-in-scope and shift it again on a second run. So
    this checks for the CANONICAL "## 7. Security Architecture" marker (present
    only in an un-renumbered, --standard/--thorough document) as an explicit
    precondition — absent that marker (already renumbered, or a --quick run
    where §7 never rendered), this is a no-op.
    """
    if not _CANONICAL_MARKER_RE.search(text):
        return text
    heading_renumbers = _collect_heading_renumbers(text)
    if not heading_renumbers:
        return text

    out = text

    # 1. Heading lines themselves (## / ### / #### with an in-scope number).
    for old_line, new_line, _old_anchor, _new_anchor in heading_renumbers:
        out = out.replace(old_line, new_line)

    # 2. Anchor ids/hrefs — longest anchor first so e.g. "72" is swapped before
    #    a hypothetical shorter overlapping anchor, then apply the `id="..."`
    #    declaration form, the markdown `(#...)` / `#...)` link-target form, AND
    #    the raw HTML `href="#..."` form. The HTML form is emitted by the
    #    control-overview / posture tables (e.g.
    #    `<a href="#7-security-architecture">§6</a>`): step 5 rewrites the visible
    #    `§7`→`§6` text but the href target is a distinct token — without this the
    #    link stays pointed at the old `#7-...` anchor while every heading/id moved
    #    to `#6-...`, leaving a dangling in-page link.
    anchor_pairs = sorted(
        {(old_a, new_a) for _o, _n, old_a, new_a in heading_renumbers if old_a != new_a},
        key=lambda p: -len(p[0]),
    )
    for old_anchor, new_anchor in anchor_pairs:
        out = out.replace(f'id="{old_anchor}"', f'id="{new_anchor}"')
        out = out.replace(f'href="#{old_anchor}"', f'href="#{new_anchor}"')
        out = out.replace(f"(#{old_anchor})", f"(#{new_anchor})")
        out = out.replace(f"(#{old_anchor} ", f"(#{new_anchor} ")  # defensive: trailing-space anchor forms

    # 3. TOC top-level ordered-list entries: "8. [Findings Register](#..." — the
    #    anchor swap already happened in step 2; only the leading "8. " marker
    #    (not covered by the heading regex, which requires 2-4 leading `#`) remains.
    def _toc_top_sub(m: re.Match[str]) -> str:
        new_top = _new_top_level(m.group(1))
        return f"{new_top}. [" if new_top else m.group(0)

    out = "\n".join(_TOC_TOP_RE.sub(_toc_top_sub, line) for line in out.splitlines())

    # 4. Bracketed subsection references without a leading § (TOC children:
    #    "- [7.2 Identity and Authentication Controls](#...)").
    def _bracket_sub(m: re.Match[str]) -> str:
        new_num = _renumber_token(m.group(1))
        return f"[{new_num} " if new_num else m.group(0)

    out = _BARE_BRACKET_SUBSECTION_RE.sub(_bracket_sub, out)

    # 5. Inline `§N` / `§N.M` / `§N.M.K` prose references (linked or bare —
    #    covers HTML-comment section markers like `<!-- §7.1 ... -->` too).
    def _section_symbol_sub(m: re.Match[str]) -> str:
        new_num = _renumber_token(m.group(1))
        return f"§{new_num}" if new_num else m.group(0)

    out = _SECTION_SYMBOL_RE.sub(_section_symbol_sub, out)

    # 6. The "numbering is non-contiguous" explanatory box is no longer accurate
    #    once the displayed numbers are contiguous — drop it.
    out = _GAP_NOTE_RE.sub("", out)

    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="renumber_sections_display.py")
    ap.add_argument("threat_model_md", type=Path)
    ap.add_argument("--dry-run", action="store_true", help="Print a diff instead of writing.")
    ns = ap.parse_args(argv)

    if not ns.threat_model_md.is_file():
        print(f"renumber_sections_display: no such file {ns.threat_model_md}", file=sys.stderr)
        return 1

    original = ns.threat_model_md.read_text(encoding="utf-8")
    renumbered = renumber_sections_display(original)

    if renumbered == original:
        print("renumber_sections_display: no §7-§11 headings found — nothing to do", file=sys.stderr)
        return 0

    if ns.dry_run:
        import difflib

        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            renumbered.splitlines(keepends=True),
            fromfile=str(ns.threat_model_md),
            tofile=f"{ns.threat_model_md} (renumbered)",
        )
        sys.stdout.writelines(diff)
        return 0

    tmp = ns.threat_model_md.with_suffix(".md.tmp")
    tmp.write_text(renumbered, encoding="utf-8")
    tmp.replace(ns.threat_model_md)
    print("renumber_sections_display: relabeled §7-§11 to §6-§10 (display-only)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
