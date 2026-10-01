"""Deterministic component complexity and STRIDE turn-budget classifier.

Runtime consumers import the turn-budget helpers, not ``classify``:
`orchestrator/build_stride_dispatch_manifest.py` applies
``_footprint_turn_floor`` / ``footprint_turns_needed`` to each component's
tier budget, and `orchestrator/stride_dispatch_waves.py` uses
``escalated_retry_turns`` for a retry after a budget-caused death.
``classify`` and the CLI return the full (complexity, max_turns,
estimated_threat_count) verdict for one component.

Inputs (CLI):
    analyzers/classify_component.py <COMPONENT_ID> --recon-summary FILE
        --interfaces N --depth {quick,standard,thorough}
        [--canonical-id ID]

Output (JSON on stdout):
    {
      "component_id": "auth-identity",
      "complexity": "complex",
      "max_turns": 31,
      "estimated_threat_count": "high",
      "reason": "auth/identity: always high-risk regardless of file count"
    }

Decision tree:

  1. **Auth/identity** (``--canonical-id`` if given, else the component id,
     after alias resolution is ``auth`` or starts with ``auth-``) → ALWAYS
     complexity=complex. Auth is never
     thin even when its file footprint is small, because the threat surface
     is concentrated and high-impact.

  2. **Trivial-skip eligible** (≤2 interfaces, no dangerous-sink, secret or
     input-handling matches in recon Sections 7.8 / 7.12 / 7.4, not
     frontend-spa) → complexity=trivial, max_turns=0 (caller writes a stub
     stride file and skips dispatch).

  3. **Thin** (<3 interfaces, no dangerous-sink and no secret matches) →
     complexity=simple, max_turns=8, estimated_threat_count=low.

  4. **Moderate** (≤6 interfaces AND ≤2 dangerous-sink matches in recon
     Section 7.8) → complexity=moderate.

  5. **Complex** (otherwise: ≥7 interfaces OR ≥3 dangerous-sink matches) →
     complexity=complex.

  6. **Per-type floor** (``TYPE_COMPLEXITY_FLOOR``): file-handling and
     data-persistence are raised to at least moderate, admin-panel to
     complex; frontend-spa and backend-api keep the heuristic verdict.

max_turns for moderate/complex comes from ``TURN_BUDGETS`` at the given depth;
the result is then raised by the file-footprint floor (``_footprint_turn_floor``).
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import re
import sys
from pathlib import Path

# Per-depth turn budgets. The moderate/complex values equal
# runtime/resolve_config.py DEPTH_PARAMS; simple does not (it is a flat 8 here,
# 10/15/20 there). No test compares the two tables, so keep them aligned by hand.
TURN_BUDGETS = {
    "quick": {"simple": 8, "moderate": 15, "complex": 20},
    "standard": {"simple": 8, "moderate": 22, "complex": 31},
    "thorough": {"simple": 8, "moderate": 28, "complex": 35},
}

# Per-component-type complexity floor: a type whose analysis consistently needs
# more budget than its heuristic tier grants is raised to at least this tier.
# auth-identity never reaches the floor step; rule 1 returns earlier.
TYPE_COMPLEXITY_FLOOR = {
    "file-handling": "moderate",
    "data-persistence": "moderate",
    "auth-identity": "complex",
    "admin-panel": "complex",
    # backend-api, frontend-spa: heuristic-driven (no floor)
}

# Aliases that map to canonical IDs — kept in sync with
# data/component-canonical.yaml (only the IDs we use in floors above).
ALIASES_TO_CANONICAL = {
    # auth
    "auth-core": "auth-identity",
    "auth-jwt": "auth-identity",
    "auth-login": "auth-identity",
    "auth-module": "auth-identity",
    "auth-session": "auth-identity",
    # api
    "rest-api": "backend-api",
    "express-api": "backend-api",
    "express-rest-api": "backend-api",
    "express-backend": "backend-api",
    # data
    "data-layer": "data-persistence",
    "database": "data-persistence",
    "database-layer": "data-persistence",
    "nosql-layer": "data-persistence",
    # file
    "file-services": "file-handling",
    "file-upload": "file-handling",
    "file-handling": "file-handling",
    "file-delivery": "file-handling",
    "file-upload-ftp": "file-handling",
    # frontend
    "angular-spa": "frontend-spa",
    "angular-frontend": "frontend-spa",
    "frontend-spa": "frontend-spa",
    "frontend": "frontend-spa",
}


def _to_canonical(component_id: str, hint: str | None = None) -> str:
    """Canonical id for classification, with the auth rule applied last.

    The hint (else ``component_id``) is lowercased and resolved through
    ``ALIASES_TO_CANONICAL``; any result equal to ``auth`` or starting with
    ``auth-`` then becomes ``auth-identity``. The rule is a prefix match rather
    than an alias list so an unlisted name such as ``auth-service`` cannot miss
    the complex verdict, and it also applies to the hint: the hint comes from
    an LLM-authored inventory and must not opt a component out of that floor.
    """
    candidate = (hint or component_id).lower()
    if candidate in ALIASES_TO_CANONICAL:
        candidate = ALIASES_TO_CANONICAL[candidate]
    if candidate.startswith("auth-") or candidate == "auth":
        return "auth-identity"
    return candidate


def _bump_complexity(current: str, floor: str) -> str:
    order = {"simple": 0, "moderate": 1, "complex": 2}
    if order.get(floor, 0) > order.get(current, 0):
        return floor
    return current


def _count_recon_pattern(recon_summary: str, section_pattern: str, component_hint: str) -> int:
    """Count entries in a recon-summary section that mention the component.

    Heuristic: lines under a "## 7.X" header that contain the component_hint
    (substring match, case-insensitive). Used for dangerous-sinks and
    secret patterns (Sections 7.8, 7.12).
    """
    if not recon_summary:
        return 0
    text = recon_summary.lower()
    hint_low = component_hint.lower()
    # Find the section
    m = re.search(rf"##\s+{re.escape(section_pattern)}", text)
    if not m:
        return 0
    start = m.end()
    # Section ends at next "##" header
    end_m = re.search(r"\n##\s+", text[start:])
    end = start + end_m.start() if end_m else len(text)
    section = text[start:end]
    # Count lines mentioning the component hint
    count = 0
    for line in section.splitlines():
        if hint_low in line:
            count += 1
    return count


# A dispatch must read 8 mandatory context files before it touches source:
# 4 under .dispatch-context/<id>/ and 4 taxonomy-slice files. On top of the
# per-source-file reads it needs turns for the pre-seed write, the six
# per-category overwrites and the step logging.
_MANDATORY_CONTEXT_READS = 8
_WRITE_AND_LOGGING_RESERVE = 10
# Ceiling on the footprint-derived floor. Analyzers are expected to sample wide
# components rather than read exhaustively; the cap keeps a 400-file component
# from demanding an absurd budget.
#
# 80 admits (80 - 8 - 10) = 62 files exhaustively; a cap of 48 admitted only 30.
# A wider component is clamped explicitly (see ``budget_clamped``) so the analyzer
# samples. A clamp without a sampling instruction makes it read exhaustively and
# run out of turns.
_FOOTPRINT_TURN_CAP = 80


# A retry after a budget-caused death must not repeat the identical dispatch: a
# component that died at its ceiling dies there again with the same budget. The
# escalated value stays below the harness ceiling so the retry can spend what it
# is granted.
_RETRY_TURN_MULTIPLIER = 1.5
_RETRY_TURN_CAP = 88


def escalated_retry_turns(max_turns: int) -> int:
    """Turn budget for a retry of a component that died without completing work.

    Bounded by ``_RETRY_TURN_CAP`` so it stays under the analyzer's harness
    ceiling (see agents/appsec-stride-analyzer-v2.md frontmatter ``maxTurns``); the
    invariant is enforced by
    tests/test_stage1_coverage_recovery_2026_07_20.py::test_harness_ceiling_exceeds_the_highest_derivable_budget.
    """
    try:
        base = int(max_turns)
    except (TypeError, ValueError):
        return _RETRY_TURN_CAP
    if base <= 0:
        return base
    return min(int(base * _RETRY_TURN_MULTIPLIER), _RETRY_TURN_CAP)


def footprint_turns_needed(file_count: int) -> int:
    """Turns an exhaustive pass over ``file_count`` files would cost.

    Kept separate from the clamp so callers can tell the requirement from the
    granted budget.
    """
    return int(file_count) + _MANDATORY_CONTEXT_READS + _WRITE_AND_LOGGING_RESERVE


def _footprint_turn_floor(file_count: int | None, current: int) -> tuple[int, str, bool]:
    """Raise the turn budget when a component's file footprint outgrows it.

    Returns ``(turns, reason_suffix, budget_clamped)``. ``budget_clamped`` is
    True when an exhaustive pass does not fit in ``_FOOTPRINT_TURN_CAP`` -- the
    component is then in the *sampling* regime and the dispatch MUST tell the
    analyzer so (see ``build_stride_dispatch_manifest`` → ``sampling_required``).

    Complexity is a risk signal and says nothing about how much reading a
    component requires, so the file count is a second, independent input. A
    `moderate` component (22 soft turns, 40-turn harness ceiling) spanning 24
    files needs 32 reads with the 8 mandatory context reads before analysis
    starts, so it cannot finish. A 47-file component needs 65 turns; granting
    48 against a 56-turn ceiling without a sampling instruction ended both
    attempts at the ceiling with no STRIDE category completed. Clamping a very
    wide component is valid only when the analyzer is told to sample.
    """
    if not file_count or file_count <= 0:
        return current, "", False
    needed = footprint_turns_needed(file_count)
    granted = min(needed, _FOOTPRINT_TURN_CAP)
    clamped = needed > _FOOTPRINT_TURN_CAP
    if granted <= current:
        # The tier already covers the footprint. A clamp is still reported so a
        # very wide component in a high tier is not mistaken for a narrow one.
        return current, "", clamped
    suffix = f" + footprint floor ({file_count} files → {granted} turns)"
    if clamped:
        suffix += f", sampling (exhaustive would need {needed})"
    return granted, suffix, clamped


def classify(
    component_id: str,
    recon_summary: str,
    interfaces: int,
    depth: str,
    canonical_id: str | None = None,
    file_count: int | None = None,
) -> dict:
    """Return the classification dict (see module docstring)."""
    canonical = _to_canonical(component_id, canonical_id)
    budgets = TURN_BUDGETS.get(depth, TURN_BUDGETS["standard"])

    # Step 1 — auth-identity invariant
    if canonical == "auth-identity":
        # The complexity verdict ignores file footprint by design, but
        # the turn budget must not: reading N files costs N turns whatever the
        # risk rating says.
        auth_turns, auth_floor, auth_clamped = _footprint_turn_floor(file_count, budgets["complex"])
        return {
            "component_id": component_id,
            "canonical_id": canonical,
            "complexity": "complex",
            "max_turns": auth_turns,
            "estimated_threat_count": "high",
            "budget_clamped": auth_clamped,
            "reason": "auth/identity: always high-risk regardless of file footprint (M19/M8)" + auth_floor,
        }

    # Recon counts for this component
    sinks = _count_recon_pattern(recon_summary, "7.8 ", component_id)
    sinks = max(sinks, _count_recon_pattern(recon_summary, "7.8 ", canonical))
    secrets = _count_recon_pattern(recon_summary, "7.12 ", component_id)
    secrets = max(secrets, _count_recon_pattern(recon_summary, "7.12 ", canonical))
    inputs = _count_recon_pattern(recon_summary, "7.4 ", component_id)
    inputs = max(inputs, _count_recon_pattern(recon_summary, "7.4 ", canonical))

    # Step 2 — trivial skip
    is_frontend = canonical == "frontend-spa"
    if interfaces <= 2 and sinks == 0 and secrets == 0 and inputs == 0 and not is_frontend:
        return {
            "component_id": component_id,
            "canonical_id": canonical,
            "complexity": "trivial",
            "max_turns": 0,
            "estimated_threat_count": "low",
            "budget_clamped": False,
            "reason": "M24 trivial-skip: no dangerous-sinks/secrets/input-handling, ≤2 interfaces, not auth, not frontend",
        }

    # Step 3 — thin (cap to 8 turns)
    if interfaces < 3 and sinks == 0 and secrets == 0:
        complexity = "simple"
        reason = "thin component: <3 interfaces + 0 dangerous-sinks + 0 secrets"
    # Step 4 — moderate
    elif interfaces <= 6 and sinks <= 2:
        complexity = "moderate"
        reason = f"moderate: {interfaces} interfaces, {sinks} dangerous-sinks"
    # Step 5 — complex
    else:
        complexity = "complex"
        reason = f"complex: {interfaces} interfaces, {sinks} dangerous-sinks"

    # Step 6 — per-type floor
    floor = TYPE_COMPLEXITY_FLOOR.get(canonical)
    if floor:
        bumped = _bump_complexity(complexity, floor)
        if bumped != complexity:
            reason += f" + M18 {canonical} floor → {bumped}"
            complexity = bumped

    # ESTIMATED_THREAT_COUNT mapping
    etc_map = {"simple": "low", "moderate": "moderate", "complex": "high"}
    max_turns = budgets[complexity] if complexity != "simple" else 8
    floor_turns, floor_reason, budget_clamped = _footprint_turn_floor(file_count, max_turns)
    if floor_turns > max_turns:
        max_turns = floor_turns
        reason += floor_reason
    return {
        "component_id": component_id,
        "canonical_id": canonical,
        "complexity": complexity,
        "max_turns": max_turns,
        "estimated_threat_count": etc_map[complexity],
        "budget_clamped": budget_clamped,
        "reason": reason,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("component_id")
    p.add_argument(
        "--recon-summary",
        type=Path,
        required=False,
        default=None,
        help="Path to .recon-summary.md (omit to skip count-based heuristics)",
    )
    p.add_argument("--interfaces", type=int, required=True, help="Number of interfaces this component exposes")
    p.add_argument("--depth", choices=("quick", "standard", "thorough"), default="standard")
    p.add_argument(
        "--canonical-id",
        default=None,
        help="Override the canonical ID lookup (e.g. when Phase 3 already canonicalized the component)",
    )
    args = p.parse_args(argv)

    recon_text = ""
    if args.recon_summary and args.recon_summary.is_file():
        try:
            recon_text = args.recon_summary.read_text(encoding="utf-8")
        except OSError:
            recon_text = ""

    result = classify(
        args.component_id,
        recon_text,
        args.interfaces,
        args.depth,
        canonical_id=args.canonical_id,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
