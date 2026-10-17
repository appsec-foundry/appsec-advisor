"""Stage-3 runtime contract: repair routing, release-receipt source, stats rows.

A non-actionable ``repair_required`` plan has nothing a repair can apply, so it
reaches the release gate without a loop iteration; the release receipt after a
reviewer dispatch keeps the source the reviewer wrote; and every Stage-3 stats
row carries its own ``--variant``, or ``runtime/record_stage_stats.py`` skips the later
row as a replay of the first.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STAGE3 = REPO_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage3.md"


def _flat() -> str:
    return " ".join(STAGE3.read_text(encoding="utf-8").split())


def test_a_non_actionable_repair_required_plan_skips_the_loop():
    text = _flat()
    assert "`repair_required` enters the repair loop only when `.qa-repair-plan.json` is actionable" in text
    assert "goes to §4 with 0 repair iterations" in text
    assert "A non-actionable plan never enters this loop" in text


def test_every_stage3_stats_row_has_its_own_variant():
    text = _flat()
    variants = {v for v in re.findall(r"`(qa-gate|qa-review|repair-<n>)`", text)}
    assert variants == {"qa-gate", "qa-review", "repair-<n>"}
    command = re.search(r"record_stage_stats\.py[^`]*", STAGE3.read_text(encoding="utf-8")).group(0)
    assert "--variant" in command
    # A silenced skip notice is how a second row disappeared unnoticed.
    assert "2>/dev/null" not in command
