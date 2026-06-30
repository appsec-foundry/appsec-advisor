#!/usr/bin/env python3
"""Collapse the permanently-retired §6 (Use Cases) numbering gap in a composed
threat-model.md so the DELIVERED document reads with contiguous top-level
section numbers (§1…§10) instead of the §5 → §7 jump.

Why this is a final, post-validation pass and NOT a change inside
``compose_threat_model.py``
---------------------------------------------------------------------------
The whole internal pipeline — the section contract, every fragment authored by
the renderer agents, ``qa_checks.py`` (which hard-asserts ``## 7. Security
Architecture`` / ``## 8.`` / ``### 7.N`` by literal number in ~15 places),
``section_integrity.py``, and the incremental baseline — is keyed on the stable
contract numbers (§7.x stays §7.x). Renumbering anywhere upstream of those gates
would break them. So the contract keeps §7.x as the canonical key and this
script runs LAST — after Stage 3 QA, the contract gate, section-integrity, and
toc_closure have all validated the canonically-numbered document — rewriting
only the human-facing deliverable (and, via the skill, its stamped copies /
PDF / HTML exports).

What it rewrites (driven by the document's own headings, never by guesswork)
---------------------------------------------------------------------------
1. Top-level + sub-section headings:  ``## 7.`` → ``## 6.``, ``### 7.2`` →
   ``### 6.2``, ``#### 7.2.1`` → ``#### 6.2.1`` … (every top-level N > 6 → N-1).
2. Numbered GFM anchor link targets:  ``](#7-security-architecture)`` →
   ``](#6-…)``, ``](#72-…)`` → ``](#62-…)``, ``](#8-findings-register)`` →
   ``](#7-…)`` … — remapped from a slug table built off the ACTUAL headings,
   so the mapping is exact and collision-free.
3. Bare-number link labels:  ``[7.2 Identity …](#…)`` → ``[6.2 Identity …]``.
4. Inline section refs:  ``§7`` → ``§6``, ``§7.2`` → ``§6.2``, ``§8`` → ``§7`` …
   (covers both bare ``§8`` and linked ``[§7.2](#…)`` label halves).
5. TOC ordered-list markers:  ``7. [Security Architecture](#…)`` → ``6. [ …``.
6. Removes the now-obsolete "Section numbering is non-contiguous …" note.

Idempotent: a marker comment is written on first run; a second invocation is a
no-op. Anchors are produced with the canonical ``_slug.github_slug`` so they are
byte-identical to what the composer emits. Transformations skip fenced code
blocks. Exit 0 on success (incl. idempotent no-op), 2 on read/write error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _slug import github_slug  # noqa: E402  (single source of truth for anchors)

# Top-level sections that were PERMANENTLY removed from the contract (not merely
# depth-suppressed). §6 "Use Cases" was retired 2026-05. A display number is the
# contract number minus the count of retired sections below it.
RETIRED_SECTIONS: tuple[int, ...] = (6,)

MARKER = "<!-- appsec:sections-renumbered v1 -->"

_FENCE_RE = re.compile(r"^\s*(```|~~~)")
# A numbered heading line: hashes, number (N or N.M or N.M.K), optional trailing
# dot, then the title.
_HEADING_RE = re.compile(r"^(#{1,6})([ \t]+)(\d+(?:\.\d+)*)(\.?)([ \t]+)(.*\S)\s*$")
# A markdown link `[label](#anchor)` — anchor is a bare fragment id.
_LINK_RE = re.compile(r"\[([^\]]*)\]\(#([A-Za-z0-9_-]+)\)")
# Inline section ref `§N` / `§N.M` / `§N.M.K`.
_SECTION_REF_RE = re.compile(r"§(\d+)((?:\.\d+)*)")
# TOC ordered-list marker `7. [`.
_TOC_MARKER_RE = re.compile(r"^(\s*)(\d+)(\.\s+\[)")
# The obsolete numbering-gap note.
_GAP_NOTE_RE = re.compile(r"^>\s*_Section numbering is non-contiguous.*_\s*$")


def display_top(n: int) -> int:
    """Map a contract top-level number to its contiguous display number."""
    return n - sum(1 for r in RETIRED_SECTIONS if r < n)


def _renumber_numstr(num: str) -> str:
    """`"7.2.1"` → `"6.2.1"` (only the top-level component shifts)."""
    parts = num.split(".")
    top = int(parts[0])
    new_top = display_top(top)
    if new_top == top:
        return num
    parts[0] = str(new_top)
    return ".".join(parts)


def _needs_renumber(num: str) -> bool:
    top = int(num.split(".")[0])
    return display_top(top) != top


def renumber(text: str) -> tuple[str, dict]:
    """Return (rewritten_text, stats). A no-op (returns text unchanged) when the
    idempotency marker is already present."""
    stats = {"headings": 0, "link_targets": 0, "section_refs": 0, "toc_markers": 0, "notes_removed": 0}
    if MARKER in text:
        stats["skipped"] = "already-renumbered"
        return text, stats

    lines = text.split("\n")
    fence: str | None = None

    # ---- Pass 1: build the slug remap + rewrite heading lines -------------
    slug_remap: dict[str, str] = {}
    for i, line in enumerate(lines):
        fm = _FENCE_RE.match(line)
        if fm:
            tok = fm.group(1)
            if fence is None:
                fence = tok
            elif fence == tok:
                fence = None
            continue
        if fence is not None:
            continue
        hm = _HEADING_RE.match(line)
        if not hm:
            continue
        hashes, sp1, num, dot, sp2, title = hm.groups()
        if not _needs_renumber(num):
            continue
        new_num = _renumber_numstr(num)
        old_line = line
        new_line = f"{hashes}{sp1}{new_num}{dot}{sp2}{title}"
        old_slug = github_slug(old_line)
        new_slug = github_slug(new_line)
        if old_slug != new_slug:
            slug_remap[old_slug] = new_slug
        lines[i] = new_line
        stats["headings"] += 1

    # ---- Pass 2: inline §-refs (whole doc, fence-aware) ------------------
    def _sub_section_ref(m: re.Match[str]) -> str:
        num = m.group(1) + m.group(2)
        if not _needs_renumber(num):
            return m.group(0)
        stats["section_refs"] += 1
        return "§" + _renumber_numstr(num)

    # ---- Pass 3: links — remap target slug + bare-number label ------------
    def _sub_link(m: re.Match[str]) -> str:
        label, slug = m.group(1), m.group(2)
        new_slug = slug_remap.get(slug)
        if new_slug is None:
            return m.group(0)  # not a renumbered section anchor — leave alone
        stats["link_targets"] += 1
        # Renumber a bare-number label (`[7.2 Title]`). §-prefixed labels were
        # already handled by Pass 2, so they read `§6.2` here and are skipped.
        lm = re.match(r"^(\d+(?:\.\d+)*)(\b.*)$", label)
        if lm and _needs_renumber(lm.group(1)):
            label = _renumber_numstr(lm.group(1)) + lm.group(2)
        return f"[{label}](#{new_slug})"

    fence = None
    in_toc = False
    for i, line in enumerate(lines):
        fm = _FENCE_RE.match(line)
        if fm:
            tok = fm.group(1)
            if fence is None:
                fence = tok
            elif fence == tok:
                fence = None
            continue
        if fence is not None:
            continue
        # Track the Table of Contents block for the ordered-marker pass.
        if re.match(r"^##\s+Table of Contents\s*$", line, re.IGNORECASE):
            in_toc = True
        elif in_toc and re.match(r"^##\s+\S", line):
            in_toc = False

        new = _SECTION_REF_RE.sub(_sub_section_ref, line)
        new = _LINK_RE.sub(_sub_link, new)
        if in_toc:
            tm = _TOC_MARKER_RE.match(new)
            if tm and _needs_renumber(tm.group(2)):
                new = _TOC_MARKER_RE.sub(lambda mm: f"{mm.group(1)}{display_top(int(mm.group(2)))}{mm.group(3)}", new)
                stats["toc_markers"] += 1
        lines[i] = new

    # ---- Pass 4: drop the obsolete numbering-gap note --------------------
    kept: list[str] = []
    for line in lines:
        if _GAP_NOTE_RE.match(line):
            stats["notes_removed"] += 1
            continue
        kept.append(line)
    lines = kept

    out = "\n".join(lines)
    # Stamp the marker right after the first heading line so re-runs no-op.
    if MARKER not in out:
        out = out.replace("\n", "\n" + MARKER + "\n", 1) if "\n" in out else out + "\n" + MARKER
    return out, stats


def main() -> int:
    ap = argparse.ArgumentParser(description="Collapse the retired §6 numbering gap in a composed threat-model.md.")
    ap.add_argument("md_path", help="path to threat-model.md (or a stamped copy)")
    ap.add_argument("--in-place", action="store_true", help="rewrite the file in place")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    p = Path(args.md_path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        print(f"renumber_sections: cannot read {p}: {e}", file=sys.stderr)
        return 2

    out, stats = renumber(text)

    if stats.get("skipped"):
        if not args.quiet:
            print(f"renumber_sections: {p.name} already renumbered — no-op")
        return 0

    if args.in_place:
        try:
            p.write_text(out, encoding="utf-8")
        except OSError as e:
            print(f"renumber_sections: cannot write {p}: {e}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(out)

    if not args.quiet:
        print(
            f"renumber_sections: {p.name} — {stats['headings']} headings, "
            f"{stats['link_targets']} link targets, {stats['section_refs']} §-refs, "
            f"{stats['toc_markers']} TOC markers, {stats['notes_removed']} gap-note(s) removed",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
