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
    sys.stderr.write(
        f"VERIFY: merged {len(verdicts)} verdict(s)" + (" [budget-critical]" if budget_critical else "") + "\n"
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
