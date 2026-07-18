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


def _is_untouched_preseed_step(step: dict) -> bool:
    """True when a single step is an untouched write-first pre-seed.

    The verifier pre-seeds every step ``inconclusive`` with an empty evidence
    ``excerpt``, then MUST re-write the step with a concrete ``reason`` (and, for
    a confirmed/blocked step, a real excerpt) as it investigates. A step that is
    STILL ``inconclusive`` AND carries no non-empty ``reason`` AND no non-empty
    ``excerpt`` is therefore one the agent never re-wrote — the turn ceiling hit
    before it recorded its finding (AC-T-002 step 1 on the 2026-07-15 juice-shop
    run: the verifier had determined ``address.ts:11`` was protected by
    ``appendUserId()`` but never wrote the verdict). All three conditions must
    hold so a legitimately-undecided step (which carries a reason) is never
    mistaken for an untouched pre-seed.
    """
    if (step.get("verdict") or "") != "inconclusive":
        return False
    if (step.get("reason") or "").strip():
        return False
    excerpt = ((step.get("evidence") or {}).get("excerpt") or "").strip()
    return not excerpt


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


def _unverified_preseed_steps(verdict: dict) -> list:
    """Step numbers that are untouched pre-seeds within a PARTIALLY-verified file.

    Complements `_is_unfinalized_preseed` (which flags a file where EVERY step is
    an untouched pre-seed). A verifier that confirmed some steps then hit the turn
    ceiling leaves a MIX — decided step(s) plus untouched pre-seed step(s) — which
    the whole-file check misses because one decided step makes it return False
    (AC-T-001 on the 2026-07-15 juice-shop run: step 1 confirmed, steps 2-3
    untouched). Such a chain would otherwise render as if fully verified. Returns
    the untouched step numbers so the merge can surface a partial-finalization
    signal; empty for a genuinely finalized (or fully-unfinalized) file.
    """
    steps = verdict.get("step_verdicts") or []
    return [s.get("step") for s in steps if _is_untouched_preseed_step(s)]


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
        # Whole-file (every step untouched) vs partial (some steps decided, some
        # left as untouched pre-seed after a mid-chain turn-ceiling cut-off) are
        # distinct signals — the partial case previously escaped detection.
        if _is_unfinalized_preseed(v):
            v["_not_finalized"] = True
        else:
            unverified = _unverified_preseed_steps(v)
            if unverified:
                v["_partially_finalized"] = True
                v["_unverified_steps"] = unverified
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
    partial = sorted(
        v["abuse_case_id"] for v in verdicts.values() if v.get("_partially_finalized") and v.get("abuse_case_id")
    )
    if partial:
        # A verifier that decided some steps then hit the turn ceiling leaves the
        # remaining steps as untouched pre-seeds; the chain would otherwise render
        # as fully verified. Surface it like the whole-file signal above.
        sys.stderr.write(
            "VERIFY: "
            + str(len(partial))
            + " verifier(s) partially finalized (some steps decided, others left as "
            + "untouched pre-seed after a mid-chain cut-off): "
            + ", ".join(partial)
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
