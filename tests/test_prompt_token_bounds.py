"""Token-bound regression guard for prompt files (Phase C1 of refactoring-plan).

Catches silent prompt bloat or accidental section deletion. Sized in chars/4
as an approximate token count (matches the heuristic used in
``docs/internal/analysis/refactoring-plan.md``).

To update bounds intentionally:

    1. Edit a prompt file.
    2. Run this test once with ``-vv`` to read the new size.
    3. Bump the ceiling in ``data/context-budgets.yaml`` when the surface is
       budgeted there — this guard then checks only ``low``. Otherwise bump the
       ``high`` in ``_BOUNDS`` below.
    4. Mention the bump in the PR description so it doesn't slip past review.

Tolerance: 20% above the recorded bound (matches refactoring-plan §C1).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
TOLERANCE = 0.20
BUDGETS = REPO_ROOT / "data" / "context-budgets.yaml"

# (low, high) approximate token bounds (chars/4) measured at 2026-05-16 HEAD.
# `low` flags suspicious shrinkage (someone deleted a section); `high` flags
# bloat. Both bounds include the TOLERANCE buffer documented above.
_BOUNDS: dict[str, tuple[int, int]] = {
    # Lowered 2026-07-20: the canonical post-autofix gate now owns all
    # mechanical checks. The exceptional reviewer consumes only a compact
    # repair plan or an explicitly forced semantic sample.
    "agents/appsec-qa-reviewer.md": (1_200, 3_000),
    "agents/appsec-architecture-analyst.md": (500, 3_000),
    "agents/appsec-control-analyst.md": (500, 3_000),
    "agents/appsec-post-stride-synthesizer.md": (500, 3_000),
    "skills/internal-threat-analysis-kernel/SKILL.md": (700, 4_000),
    # Ceiling lives in data/context-budgets.yaml; the `high` here is ignored for
    # any surface budgeted there (see _resolved_bounds). Only `low` applies.
    "agents/appsec-stride-analyzer-v2.md": (2_500, 3_000),
    # Parallel Stage-2 specialists intentionally keep only role-local
    # instructions. They load their relevant legacy contract slice on demand.
    "agents/appsec-secarch-renderer.md": (500, 1_200),
    "agents/appsec-ms-renderer.md": (500, 1_200),
}


def _approx_tokens(text: str) -> int:
    return len(text) // 4


def _byte_budgets() -> dict[str, int]:
    """Prompt surfaces that `data/context-budgets.yaml` already caps, in bytes."""
    doc = yaml.safe_load(BUDGETS.read_text(encoding="utf-8")) or {}
    return {
        spec["path"]: spec["max_bytes"]
        for spec in (doc.get("surfaces") or {}).values()
        if isinstance(spec, dict) and "path" in spec and "max_bytes" in spec
    }


def _resolved_bounds() -> dict[str, tuple[int, int | None]]:
    """Drop the ceiling for surfaces `data/context-budgets.yaml` already caps.

    Both guards measure the same file, and `_approx_tokens` is `len // 4`, so a
    byte budget of N is the same ceiling as a token high of N // 4 — today all
    five shared surfaces carry exactly that pair. Asserting it twice makes one
    oversized prompt fail two tests and lets a later bump move one copy and
    leave the other behind. The byte budget owns the ceiling; this guard keeps
    `low`, which nothing else checks and which is what catches a gutted prompt.
    """
    budgeted = _byte_budgets()
    return {relpath: (low, None if relpath in budgeted else high) for relpath, (low, high) in _BOUNDS.items()}


def test_ceiling_is_not_recorded_in_both_places():
    """No surface may carry a token ceiling next to its byte budget."""
    shared = sorted(set(_BOUNDS) & set(_byte_budgets()))
    assert shared, "expected some surface to be budgeted in both places"
    for relpath in shared:
        assert _resolved_bounds()[relpath][1] is None


@pytest.mark.parametrize("relpath", sorted(_BOUNDS))
def test_prompt_token_bounds(relpath):
    low, high = _resolved_bounds()[relpath]
    path = REPO_ROOT / relpath
    assert path.is_file(), f"{relpath} no longer exists — drop or rename the bound entry"
    text = path.read_text(encoding="utf-8")
    tokens = _approx_tokens(text)
    assert low <= tokens, (
        f"{relpath} shrank to {tokens} tokens, below the recorded floor {low} — "
        "a section was probably deleted. Revert, or lower `low` in _BOUNDS."
    )
    if high is not None:
        assert tokens <= high, (
            f"{relpath} token count {tokens} above the ceiling {high} (20% tolerance). "
            "Either revert the change or raise `high` in _BOUNDS."
        )


def test_bounds_table_consistent_with_repo():
    """Surface deleted/renamed files quickly: any bound entry must point at a real file."""
    for relpath in _BOUNDS:
        assert (REPO_ROOT / relpath).is_file(), f"_BOUNDS lists {relpath} but file is missing"
