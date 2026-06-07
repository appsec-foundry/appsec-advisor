#!/usr/bin/env python3
"""requirements_gate.py — deterministic exit-code decision for verify-requirements.

The appsec-requirements-verifier subagent writes a verdict JSON
(`schemas/requirements-verification.schema.json`). This script is the ONLY
authority on whether a change blocks: it recomputes the gating set from
`results[]` — never trusting the agent's advisory `gating` / `gating_failures`
fields — and exits accordingly. Keeping the gate in deterministic Python (not
the LLM) is the AGENTS.md §1/§12 rule: agents produce structured findings;
scripts decide.

A requirement gates when ALL hold:
    in_scope is true  AND  status == "FAIL"  AND  priority >= floor
where priority rank is MUST(3) > SHOULD(2) > MAY(1) and `floor` is the
resolved priority floor (default MUST). With --gate-on partial, PARTIAL of an
in-scope at-or-above-floor requirement also gates.

Exit codes:
    0  advisory mode (always), OR gate mode with zero gating failures
    1  gate mode AND >=1 gating failure
    2  usage / load / malformed-verdict error
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PRIORITY_RANK = {"MUST": 3, "SHOULD": 2, "MAY": 1}


def _err(msg: str) -> int:
    print(f"requirements-gate: {msg}", file=sys.stderr)
    return 2


def _is_gating(result: dict, floor_rank: int, gate_on_partial: bool) -> bool:
    if not result.get("in_scope"):
        return False
    status = result.get("status")
    if status == "FAIL":
        pass
    elif status == "PARTIAL" and gate_on_partial:
        pass
    else:
        return False
    rank = _PRIORITY_RANK.get(result.get("priority", ""), 0)
    return rank >= floor_rank


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compute the verify-requirements gate exit code.")
    parser.add_argument("--verdict", required=True, help="Path to .requirements-verification.json")
    parser.add_argument("--gate", action="store_true", help="Enforce: non-zero exit on a gating failure. Without it, advisory (always exit 0).")
    parser.add_argument("--priority-floor", default="MUST", choices=["MUST", "SHOULD", "MAY"], help="Lowest priority that may gate (default MUST).")
    parser.add_argument("--gate-on", default="fail", choices=["fail", "partial"], help="`fail` (default) gates only FAIL; `partial` also gates PARTIAL.")
    args = parser.parse_args(argv)

    path = Path(args.verdict)
    if not path.exists():
        return _err(f"verdict file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _err(f"could not read verdict: {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return _err("verdict malformed: missing results[] array")

    floor_rank = _PRIORITY_RANK[args.priority_floor]
    gate_on_partial = args.gate_on == "partial"

    gating = [r for r in data["results"] if isinstance(r, dict) and _is_gating(r, floor_rank, gate_on_partial)]
    n = len(gating)

    if n == 0:
        print(f"requirements-gate: PASS — no gating failures (floor={args.priority_floor}, gate-on={args.gate_on}).")
    else:
        verb = "BLOCK" if args.gate else "WARN"
        print(f"requirements-gate: {verb} — {n} gating requirement(s) (floor={args.priority_floor}, gate-on={args.gate_on}):")
        for r in gating:
            print(f"  - {r.get('priority')} {r.get('id')} [{r.get('status')}]: {r.get('finding', '(no finding text)')}")

    if args.gate and n > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
