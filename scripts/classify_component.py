"""M8 + M18 — Deterministic component complexity + MAX_TURNS classifier.

Replaces the LLM-discretionary "thin-component cap" / "moderate / complex"
heuristics in `phase-group-threats.md:185-198`. The orchestrator runs this
script per component AFTER recon-summary is in working memory, BEFORE Phase
9 dispatch — and uses the returned (complexity, max_turns, estimated_threat_count)
triple to populate the STRIDE-analyzer prompt parameters.

Inputs (CLI):
    classify_component.py <COMPONENT_ID> --recon-summary FILE
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

  1. **Auth/identity** (canonical_id == auth-identity OR component_id matches
     `auth-*`) → ALWAYS complexity=complex (M19 invariant — auth is never
     thin even when its file footprint is small, because the threat surface
     is concentrated and high-impact).

  2. **Trivial-skip eligible** (per M24 conditions) → complexity=trivial,
     max_turns=0 (caller writes stub stride file and skips dispatch).

  3. **Thin** (per phase-group-threats.md:185 thin-cap conditions) →
     complexity=simple, max_turns=8, estimated_threat_count=low.

  4. **Moderate** (3-6 interfaces AND ≤2 dangerous-sink matches in recon
     Section 7.8) → complexity=moderate, max_turns=STRIDE_TURNS_MODERATE.

  5. **Complex** (≥7 interfaces OR ≥3 dangerous-sink matches OR component
     is admin/payment/PII handler) → complexity=complex,
     max_turns=STRIDE_TURNS_COMPLEX.

  6. **Per-type calibration (M18)** — based on 8-run telemetry:
     - file-handling: bump complexity floor to moderate (rarely simple in
       practice; small file count masks genuine I/O complexity)
     - data-persistence: bump complexity floor to moderate (multi-hop
       reasoning over models + queries justifies extra budget)
     - frontend-spa: keep heuristic-driven (varies wildly with template
       count)
     - backend-api: respect heuristic (small APIs really are simple)

The per-depth turn-budget tables come from `data/depth-params.yaml` (or
the duplicate copy in resolve_config.py.DEPTH_PARAMS — kept in sync via
test_resolve_config.py).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Per-depth turn budgets (mirror of resolve_config.py.DEPTH_PARAMS values
# for simple/moderate/complex tiers).
TURN_BUDGETS = {
    "quick":    {"simple":  8, "moderate": 15, "complex": 20},
    "standard": {"simple":  8, "moderate": 22, "complex": 31},
    "thorough": {"simple":  8, "moderate": 28, "complex": 35},
}

# M18 — per-component-type complexity floor. Empirical: when the component
# type historically takes 1.5× longer than its tier-mean, bump the floor.
TYPE_COMPLEXITY_FLOOR = {
    "file-handling":   "moderate",
    "data-persistence": "moderate",
    "auth-identity":   "complex",
    "admin-panel":     "complex",
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
    if hint:
        return hint.lower()
    cid_lower = component_id.lower()
    if cid_lower in ALIASES_TO_CANONICAL:
        return ALIASES_TO_CANONICAL[cid_lower]
    return cid_lower


def _bump_complexity(current: str, floor: str) -> str:
    order = {"simple": 0, "moderate": 1, "complex": 2}
    if order.get(floor, 0) > order.get(current, 0):
        return floor
    return current


def _count_recon_pattern(
    recon_summary: str, section_pattern: str, component_hint: str
) -> int:
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


def classify(
    component_id: str,
    recon_summary: str,
    interfaces: int,
    depth: str,
    canonical_id: str | None = None,
) -> dict:
    """Return the classification dict (see module docstring)."""
    canonical = _to_canonical(component_id, canonical_id)
    budgets = TURN_BUDGETS.get(depth, TURN_BUDGETS["standard"])

    # Step 1 — auth-identity invariant
    if canonical == "auth-identity":
        return {
            "component_id": component_id,
            "canonical_id": canonical,
            "complexity": "complex",
            "max_turns": budgets["complex"],
            "estimated_threat_count": "high",
            "reason": "auth/identity: always high-risk regardless of file footprint (M19/M8)",
        }

    # Recon counts for this component
    sinks = _count_recon_pattern(recon_summary, "7.8 ", component_id)
    sinks = max(sinks, _count_recon_pattern(recon_summary, "7.8 ", canonical))
    secrets = _count_recon_pattern(recon_summary, "7.12 ", component_id)
    secrets = max(secrets, _count_recon_pattern(recon_summary, "7.12 ", canonical))
    inputs = _count_recon_pattern(recon_summary, "7.4 ", component_id)
    inputs = max(inputs, _count_recon_pattern(recon_summary, "7.4 ", canonical))

    # Step 2 — trivial skip (M24)
    is_frontend = canonical == "frontend-spa"
    if (interfaces <= 2 and sinks == 0 and secrets == 0 and inputs == 0
            and not is_frontend):
        return {
            "component_id": component_id,
            "canonical_id": canonical,
            "complexity": "trivial",
            "max_turns": 0,
            "estimated_threat_count": "low",
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

    # Step 6 — M18 per-type floor
    floor = TYPE_COMPLEXITY_FLOOR.get(canonical)
    if floor:
        bumped = _bump_complexity(complexity, floor)
        if bumped != complexity:
            reason += f" + M18 {canonical} floor → {bumped}"
            complexity = bumped

    # ESTIMATED_THREAT_COUNT mapping
    etc_map = {"simple": "low", "moderate": "moderate", "complex": "high"}
    return {
        "component_id": component_id,
        "canonical_id": canonical,
        "complexity": complexity,
        "max_turns": budgets[complexity] if complexity != "simple" else 8,
        "estimated_threat_count": etc_map[complexity],
        "reason": reason,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("component_id")
    p.add_argument("--recon-summary", type=Path, required=False, default=None,
                   help="Path to .recon-summary.md (omit to skip count-based heuristics)")
    p.add_argument("--interfaces", type=int, required=True,
                   help="Number of interfaces this component exposes")
    p.add_argument("--depth", choices=("quick", "standard", "thorough"),
                   default="standard")
    p.add_argument("--canonical-id", default=None,
                   help="Override the canonical ID lookup (e.g. when Phase 3 "
                        "already canonicalized the component)")
    args = p.parse_args(argv)

    recon_text = ""
    if args.recon_summary and args.recon_summary.is_file():
        try:
            recon_text = args.recon_summary.read_text(encoding="utf-8")
        except OSError:
            recon_text = ""

    result = classify(
        args.component_id, recon_text, args.interfaces, args.depth,
        canonical_id=args.canonical_id,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
