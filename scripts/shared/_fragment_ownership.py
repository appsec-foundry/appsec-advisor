"""Which render fragment literally carries a report defect, and whether a repair there sticks.

A repair plan may name a fragment only when an edit to it survives the next
compose. The fragments below are rebuilt from ``threat-model.yaml`` on every
compose, so an edit there is overwritten and the gate re-fires forever (the
non-convergent loop of 7ac5cfa). A defect whose text occurs in one of them, or
in no fragment at all, belongs to deterministic producer code instead.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

# `pregenerate_fragments.py --force --only <these>` runs before every compose.
FORCE_REGENERATED_FRAGMENTS: tuple[str, ...] = (
    "system-overview.md",
    "architecture-diagrams.md",
    "assets.md",
    "attack-surface.md",
    "out-of-scope.md",
    "attack-walkthroughs.md",
)

# Model-free fragments the generator rebuilds from the yaml without `--force`.
_SELF_REBUILT_FRAGMENTS: tuple[str, ...] = ("ms-ai-exposure.json",)

RECOMPOSE_REGENERATED_FRAGMENTS = frozenset(FORCE_REGENERATED_FRAGMENTS + _SELF_REBUILT_FRAGMENTS)


def locate_defect_fragments(
    frag_dir: Path,
    candidates: Iterable[str],
    patterns: Iterable[re.Pattern[str]],
) -> tuple[list[str], list[str]]:
    """Return ``(persistent, regenerated)`` candidate paths whose text matches a pattern.

    ``candidates`` are ``.fragments/<name>`` paths. The match is literal (the
    caller builds the patterns from the exact defect text), never a similarity
    guess, so a hit is the fragment that emitted the defect.
    """
    compiled = list(patterns)
    persistent: list[str] = []
    regenerated: list[str] = []
    if not compiled or not frag_dir.is_dir():
        return persistent, regenerated
    for rel in sorted(set(candidates)):
        name = rel.rsplit("/", 1)[-1]
        try:
            text = (frag_dir / name).read_text(encoding="utf-8")
        except OSError:
            continue
        if any(p.search(text) for p in compiled):
            (regenerated if name in RECOMPOSE_REGENERATED_FRAGMENTS else persistent).append(rel)
    return persistent, regenerated
