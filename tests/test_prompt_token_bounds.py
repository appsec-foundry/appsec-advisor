"""Token-bound regression guard for prompt files (Phase C1 of refactoring-plan).

Catches silent prompt bloat or accidental section deletion. Sized in chars/4
as an approximate token count (matches the heuristic used in
``docs/internal/runbooks/refactoring-plan.md``).

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
    # Raised 2026-06-26: commit 77721d7 added the ⛔ "never re-dispatch
    # context-resolver/recon-scanner after a stall" rule (real token-waste
    # bugfix, pinned by a drift guard). Measured 7_613; high = ~20% buffer.
    "agents/phases/phase-group-recon.md": (3_000, 9_100),
    # Lowered 2026-07-20: the canonical post-autofix gate now owns all
    # mechanical checks. The exceptional reviewer consumes only a compact
    # repair plan or an explicitly forced semantic sample.
    "agents/appsec-qa-reviewer.md": (1_200, 3_000),
    "agents/appsec-threat-analyst.md": (22_000, 45_000),
    # Lowered 2026-05-23 after shared-file extraction (finding-title-contract,
    # supply-chain-patterns, spa-threats, cvss-metrics) and dedup of the
    # ops/progress sections. Measured 8_040.
    # Raised 2026-06-05: STRIDE parallel-dispatch + abuse-case guidance added.
    # Measured 10_694; high = ~20% buffer above the new size.
    # Raised 2026-06-24: OAuth/OIDC FT-091/092/093 finding-type rows + the
    # evidence_summary "short inline identifiers only" code-formatting rule.
    # Measured 13_011; high = ~14% buffer above the new size.
    # 2026-07-19: + the "Authoring attack_steps" contract, so §3 walkthroughs
    # are authored attacker-first instead of being sentence-split out of
    # `scenario`. Measured 15_130; high = ~3% buffer above the new size.
    "agents/appsec-stride-analyzer.md": (6_500, 15_600),
    # Parallel Stage-2 specialists intentionally keep only role-local
    # instructions. They load their relevant legacy contract slice on demand.
    "agents/appsec-secarch-renderer.md": (500, 1_200),
    "agents/appsec-ms-renderer.md": (500, 1_200),
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
