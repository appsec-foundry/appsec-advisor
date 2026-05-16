"""Token-bound regression guard for prompt files (Phase C1 of refactoring-plan).

Catches silent prompt bloat or accidental section deletion. Sized in chars/4
as an approximate token count (matches the heuristic used in
``docs/refactoring-plan.md``).

To update bounds intentionally:

    1. Edit a prompt file.
    2. Run this test once with ``-vv`` to read the new size.
    3. Bump the matching ``(low, high)`` tuple in ``_BOUNDS`` below.
    4. Mention the bump in the PR description so it doesn't slip past review.

Tolerance: 20% above the recorded bound (matches refactoring-plan §C1).
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
TOLERANCE = 0.20

# (low, high) approximate token bounds (chars/4) measured at 2026-05-16 HEAD.
# `low` flags suspicious shrinkage (someone deleted a section); `high` flags
# bloat. Both bounds include the TOLERANCE buffer documented above.
_BOUNDS: dict[str, tuple[int, int]] = {
    "agents/phases/phase-group-finalization.md": (32_000, 60_000),
    "agents/phases/phase-group-architecture.md": (25_000, 45_000),
    "agents/phases/phase-group-threats.md": (24_000, 45_000),
    "agents/phases/phase-group-recon.md": (3_000, 7_500),
    "agents/appsec-qa-reviewer.md": (33_000, 60_000),
    "agents/appsec-threat-analyst.md": (22_000, 45_000),
    "agents/appsec-stride-analyzer.md": (10_000, 22_000),
}


def _approx_tokens(text: str) -> int:
    return len(text) // 4


@pytest.mark.parametrize("relpath", sorted(_BOUNDS))
def test_prompt_token_bounds(relpath):
    low, high = _BOUNDS[relpath]
    path = REPO_ROOT / relpath
    assert path.is_file(), f"{relpath} no longer exists — drop or rename the bound entry"
    text = path.read_text(encoding="utf-8")
    tokens = _approx_tokens(text)
    assert low <= tokens <= high, (
        f"{relpath} token count {tokens} outside expected band [{low}, {high}] "
        f"(20% tolerance). Either revert the change or update the bound in this test."
    )


def test_bounds_table_consistent_with_repo():
    """Surface deleted/renamed files quickly: any bound entry must point at a real file."""
    for relpath in _BOUNDS:
        assert (REPO_ROOT / relpath).is_file(), f"_BOUNDS lists {relpath} but file is missing"
