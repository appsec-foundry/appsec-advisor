#!/usr/bin/env python3
"""verify_abuse_cases.py — merge per-agent abuse-case verdicts + budget guard.

Agent dispatch itself is done by the Phase-10b skill orchestration (one
`appsec-abuse-case-verifier` agent per candidate, dispatched in parallel like
the Phase-9 STRIDE fan-out). Each agent writes one
`<output-dir>/.abuse-case-verdict-<AC-ID>.json` file. This script is the
deterministic glue around that fan-out:

  merge   Collect every `.abuse-case-verdict-*.json`, validate the basic shape,
          and write the consolidated `<output-dir>/.abuse-case-verdicts.json`.
          When `.budget-critical` is present, candidates without a verdict file
          are recorded as `inconclusive` (no agent ran for them) rather than
          dropped — keeping the report honest about what was not verified.

Run `match_abuse_cases.py finalize` afterwards to fold these step verdicts into
per-chain verdicts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_VALID_STEP_VERDICTS = {"confirmed", "blocked", "inconclusive"}


def _is_unfinalized_preseed(verdict: dict) -> bool:
    """True when a verdict file is an untouched write-first pre-seed.

    The verifier contract (`agents/appsec-abuse-case-verifier.md` → "Budget
    discipline") pre-seeds every step `inconclusive`, then MUST re-write each step
    with a concrete `reason` as it investigates — even a legitimately-undecided
    step ends with a non-empty reason. So a file whose steps are ALL `inconclusive`
    AND carry no non-empty `reason` is one the agent never finalized (it came to
    rest / hit the turn ceiling before re-writing — AC-T-003 on the 2026-06-21
    juice-shop run). This is deterministically distinguishable from a genuine
    inconclusive (which carries reasons) and must be surfaced as such rather than
    silently folded into the same bucket.
    """
    steps = verdict.get("step_verdicts") or []
    if not steps:
        return False
    if any((s.get("verdict") or "") != "inconclusive" for s in steps):
        return False
    return not any((s.get("reason") or "").strip() for s in steps)


def _candidates(output_dir: Path) -> list[str]:
    matches = output_dir / ".abuse-case-matches.json"
    if not matches.exists():
        return []
    doc = json.loads(matches.read_text(encoding="utf-8"))
    return [
        m["abuse_case_id"]
        for m in doc.get("matches", [])
        if m.get("structural_verdict") in ("candidate", "partial_candidate")
    ]


def _load_verdict_files(output_dir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in sorted(output_dir.glob(".abuse-case-verdict-*.json")):
        try:
            v = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"WARN: skipping unreadable {path.name}: {exc}\n")
            continue
        cid = v.get("abuse_case_id")
        if not cid:
            sys.stderr.write(f"WARN: {path.name} has no abuse_case_id\n")
            continue
        # normalise unknown step verdicts to inconclusive
        for s in v.get("step_verdicts") or []:
            if s.get("verdict") not in _VALID_STEP_VERDICTS:
                s["verdict"] = "inconclusive"
        # Flag an untouched write-first pre-seed so downstream / operators can
        # tell "verifier never finalized" apart from a reasoned inconclusive.
        if _is_unfinalized_preseed(v):
            v["_not_finalized"] = True
        out[cid] = v
    return out


def cmd_merge(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    verdicts = _load_verdict_files(output_dir)
    budget_critical = (output_dir / ".budget-critical").exists()

    # Candidates with no verdict file → inconclusive stub (esp. under budget pressure).
    for cid in _candidates(output_dir):
        if cid not in verdicts:
            verdicts[cid] = {
                "abuse_case_id": cid,
                "step_verdicts": [],
                "note": "no verifier verdict" + (" (budget-critical)" if budget_critical else ""),
            }

    merged = {"schema_version": 1, "verdicts": list(verdicts.values())}
    (output_dir / ".abuse-case-verdicts.json").write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    not_finalized = sorted(
        v["abuse_case_id"] for v in verdicts.values() if v.get("_not_finalized") and v.get("abuse_case_id")
    )
    sys.stderr.write(
        f"VERIFY: merged {len(verdicts)} verdict(s)" + (" [budget-critical]" if budget_critical else "") + "\n"
    )
    if not_finalized:
        # Distinct, operator-visible signal — these chains are inconclusive
        # because the verifier never finalized (turn ceiling / came to rest),
        # NOT because the code was genuinely ambiguous. Mirrored into
        # .agent-run.log so aggregate_run_issues / a human can act on it.
        sys.stderr.write(
            "VERIFY: "
            + str(len(not_finalized))
            + " verifier(s) did not finalize (untouched pre-seed, all steps "
            + "inconclusive with no reason): "
            + ", ".join(not_finalized)
            + " — re-run or raise the verifier turn budget to verify these chains end-to-end\n"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge abuse-case verifier verdicts.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    mg = sub.add_parser("merge", help="merge per-agent verdict files")
    mg.add_argument("--output-dir", required=True)
    mg.set_defaults(func=cmd_merge)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
