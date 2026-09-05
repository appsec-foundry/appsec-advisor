#!/usr/bin/env python3
"""project_run_cost.py — what a run is expected to cost, before it starts.

Admission needs one number: can this invocation plausibly fit the declared soft
budget? A refusal before the first dispatch costs nothing, while the same
refusal taken halfway through a run costs everything already spent.

Two sources, in priority order:

  1. ``last_run_cost_usd`` in ``<output>/.appsec-cache/baseline.json``, written
     by ``persist_run_baseline.py`` at the end of a run and accepted only for
     the same mode and depth. This is a measurement of this repository.
  2. A parametric floor, used only to reject a budget that no run of that depth
     could meet.

WHY THE PARAMETRIC TERM IS A FLOOR AND NOT A PREDICTION
-------------------------------------------------------
Before recon has produced ``.components.json`` the component count is unknown,
and the component count is the only term that scales. A first run against an
unknown repository therefore cannot be predicted here; it can only be checked
against the fixed work that every run of that depth performs. Slice 2 of the
change in ``specs/changes/a-cost-budget-steers-the-run`` moves the real
comparison to the boundaries, where the count is known and the run's own
per-component cost has been observed.

The constants are anchored on ONE measured run: juice-shop, 2026-08-31,
``--full`` at standard depth, seven components, $29.59 total with $9.94 on the
host session and $19.65 across 24 sub-agents, read with
``cost_running_total.py --format json``. Treat them as an order of magnitude.
A second anchor should replace them rather than be averaged into them, and a
figure taken under subscription billing is a price-table valuation of tokens
rather than money billed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Sub-agent spend that does not scale with the component count: recon, actor
# discovery, architecture, trust boundary, controls, merge, evidence, the
# post-STRIDE synthesis, abuse-case verification, and both renderers.
FIXED_SUB_USD = 12.30
# Sub-agent spend per analyzed STRIDE component.
PER_COMPONENT_SUB_USD = 1.05
# The host session is not attributable to a stage; it accrues across the whole
# run. Measured at 9.94 against 19.65 of sub-agent spend.
HOST_FACTOR = 1.506
# Depth scales the per-component turn budgets in resolve_config.DEPTH_PARAMS
# (simple/moderate/complex: 10/15/20, 15/22/31, 20/28/35). These are the mean
# ratios against standard.
DEPTH_FACTOR = {"quick": 0.67, "standard": 1.0, "thorough": 1.25}
# The floor rests on a single anchor, so it refuses only a budget that is
# clearly below it. A wrong refusal costs the user a run they could have had;
# a wrong admission is what the boundary checkpoints exist for.
FLOOR_MARGIN = 0.75


def _depth_factor(depth: str) -> float:
    return DEPTH_FACTOR.get((depth or "standard").lower(), 1.0)


def parametric_floor(depth: str) -> float:
    """Cheapest plausible total for a run at this depth, host share included."""
    return round(FIXED_SUB_USD * _depth_factor(depth) * HOST_FACTOR, 2)


def parametric_total(depth: str, components: int) -> float:
    """Expected total for a known component count, host share included."""
    sub = FIXED_SUB_USD + PER_COMPONENT_SUB_USD * max(components, 0)
    return round(sub * _depth_factor(depth) * HOST_FACTOR, 2)


def last_run_cost(output_dir: Path, mode: str, depth: str) -> float | None:
    """The recorded cost of the last run on this output, same mode and depth."""
    try:
        cache = json.loads((Path(output_dir) / ".appsec-cache" / "baseline.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(cache, dict):
        return None
    value = cache.get("last_run_cost_usd")
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    for key, current in (("last_run_mode", mode), ("last_run_depth", depth)):
        recorded = (cache.get(key) or "").lower() if isinstance(cache.get(key), str) else ""
        if recorded and current and recorded != current.lower():
            return None
    return float(value)


def project(output_dir: Path | str, mode: str, depth: str, budget_usd: float | None = None) -> dict[str, Any]:
    """Project the run's cost and say whether the declared budget can hold it.

    ``fits`` is False only when the projection says so on evidence: a measured
    previous run of the same shape, or a budget below the depth's floor. An
    unknown first run is admitted with ``basis`` ``"none"``.
    """
    depth = (depth or "standard").lower()
    measured = last_run_cost(Path(output_dir), mode, depth)
    floor = parametric_floor(depth)
    result: dict[str, Any] = {
        "basis": "last_run_cache" if measured is not None else "none",
        "projected_usd": measured,
        "floor_usd": floor,
        "budget_usd": budget_usd,
        "fits": True,
        "reason": None,
    }
    if budget_usd is None:
        return result
    # The floor describes a run that analyzes source. A rerender only rebuilds
    # the report from existing Stage-1 artifacts and costs a fraction of it, so
    # holding it against the analysis floor would refuse a run that easily fits.
    analyses_source = (mode or "").lower() in {"full", "rebuild"}
    if measured is not None and budget_usd < measured:
        result["fits"] = False
        result["reason"] = (
            f"the last {mode} run at {depth} depth on this output cost ${measured:.2f}, "
            f"above the declared budget of ${budget_usd:.2f}"
        )
        return result
    if analyses_source and budget_usd < floor * FLOOR_MARGIN:
        result["basis"] = "parametric_floor"
        result["fits"] = False
        result["reason"] = (
            f"a run at {depth} depth costs about ${floor:.2f} before any component is analyzed, "
            f"above the declared budget of ${budget_usd:.2f}"
        )
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Project a run's cost before it starts")
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--mode", default="full")
    ap.add_argument("--depth", default="standard")
    ap.add_argument("--budget", type=float, default=None)
    ap.add_argument("--components", type=int, default=None)
    args = ap.parse_args(argv)

    result = project(args.output_dir, args.mode, args.depth, args.budget)
    if args.components is not None:
        result["parametric_usd"] = parametric_total(args.depth, args.components)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if result["fits"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
