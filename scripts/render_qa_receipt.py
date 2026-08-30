#!/usr/bin/env python3
"""render_qa_receipt.py — what Stage 3 actually did, on disk and on screen.

Stage 3 decides whether the report is released: it runs the canonical QA gate,
optionally dispatches the reviewer, and may loop a bounded repair. Until this
script runs, none of that reaches the console. `.qa-status.json` records only
the verdict (`pass` / `repair_required`) and its source, the repair plan is
deleted on a clean gate, and the reviewer's own account of what it changed dies
with the agent's return value. The completion summary, half an hour later,
prints one word: `QA : pass`.

Stage 4 has had `render_editorial_receipt.py` for exactly this reason. This is
its Stage-3 counterpart, with the same three effects:

  * prints a short receipt for the console, immediately after the stage;
  * appends one ``QA_GATE`` line to ``.agent-run.log``, which survives cleanup;
  * leaves ``.qa-status.json`` untouched — Stage 3 writes it last, on purpose,
    and this script is a reader.

Runtime facts the filesystem cannot carry — the gate's exit code, whether a
reviewer or fixer was dispatched, how many repair iterations ran — come in as
flags from the runtime that knows them. Everything else is read from disk.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from event_log import format_line  # noqa: E402

STATUS_NAME = ".qa-status.json"
REPAIR_PLAN_NAME = ".qa-repair-plan.json"
CONTENT_PLAN_NAME = ".qa-content-repair-plan.json"
SECRET_SCAN_NAME = ".qa-secret-scan.json"
LOG_NAME = ".agent-run.log"

# What each `qa_checks.py gate` exit means for a reader, in the gate's own
# vocabulary. Kept here rather than in the runtime prose so the receipt and the
# gate cannot drift apart silently.
GATE_OUTCOMES = {
    0: "clean — no violations",
    1: "actionable violations — repair loop entered",
    2: "tool error — reviewer triage",
    3: "manual-review violations — re-render cannot fix them",
    4: "cosmetic advisories only — surfaced, not re-rendered",
}


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _plan_summary(plan: Any) -> dict:
    """Action counts by severity for a residual repair plan.

    A plan that survives to the receipt is one the loop did not resolve:
    manual-review or cosmetic. Its severities are what the reader has to act
    on, so they belong in the receipt rather than in a file nobody opens.
    """
    if not isinstance(plan, dict):
        return {}
    actions = plan.get("actions") or []
    if not isinstance(actions, list):
        return {}
    severities = Counter(
        str(a.get("severity") or "unclassified") for a in actions if isinstance(a, dict)
    )
    return {
        "status": str(plan.get("status") or "unknown"),
        "action_count": len(actions),
        "by_severity": dict(severities),
    }


def build_status(
    output_dir: Path,
    *,
    gate_exit: int | None,
    repair_iterations: int,
    dispatched: list[str],
) -> dict:
    status_file = _load(output_dir / STATUS_NAME) or {}
    secret_scan = _load(output_dir / SECRET_SCAN_NAME) or {}

    return {
        "verdict": str(status_file.get("status") or "unknown"),
        "source": str(status_file.get("source") or "unknown"),
        "qa_skipped": bool(status_file.get("qa_skipped")),
        "gate_exit": gate_exit,
        "repair_iterations": repair_iterations,
        "dispatched": dispatched,
        "cosmetic_advisories": list(status_file.get("cosmetic_advisories") or []),
        "repair_plan": _plan_summary(_load(output_dir / REPAIR_PLAN_NAME)),
        "content_repair_plan": _plan_summary(_load(output_dir / CONTENT_PLAN_NAME)),
        "secret_issues": int(secret_scan.get("issue_count") or 0),
        "secret_scan_ran": bool(secret_scan),
    }


def render(status: dict) -> str:
    lines = ["", "Stage 3 — QA gate"]

    if status["qa_skipped"]:
        lines.append("  QA skipped by configuration — only the secret-leak gate ran")
    elif status["gate_exit"] == 0 and not status["dispatched"]:
        lines.append("  Passed deterministically — no reviewer dispatch needed, report unchanged")
    else:
        outcome = GATE_OUTCOMES.get(status["gate_exit"], "outcome not reported by the runtime")
        lines.append(f"  Gate: {outcome}")

    if status["dispatched"]:
        lines.append(f"  Dispatched: {', '.join(status['dispatched'])}")
    if status["repair_iterations"]:
        lines.append(
            f"  Repaired: {status['repair_iterations']} iteration(s) — the report was re-composed and re-gated"
        )

    for label, key in (("Open repair plan", "repair_plan"), ("Open content repairs", "content_repair_plan")):
        plan = status[key]
        if not plan:
            continue
        breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(plan["by_severity"].items()))
        lines.append(f"  {label}: {plan['action_count']} action(s) [{plan['status']}] — {breakdown}")

    advisories = status["cosmetic_advisories"]
    if advisories:
        lines.append(f"  Cosmetic advisories ({len(advisories)}, not re-rendered):")
        for item in advisories[:5]:
            lines.append(f"    · {item if isinstance(item, str) else json.dumps(item)}")
        if len(advisories) > 5:
            lines.append(f"    · … {len(advisories) - 5} more in {STATUS_NAME}")

    if not status["secret_scan_ran"]:
        lines.append("  Secret-leak gate: no scan on disk")
    elif status["secret_issues"]:
        lines.append(f"  Secret-leak gate: {status['secret_issues']} unmasked secret(s) — release blocked")
    else:
        lines.append("  Secret-leak gate: clean")

    lines.append(f"  Verdict: {status['verdict']} ({status['source']})")
    return "\n".join(lines)


def log_detail(status: dict) -> str:
    """The counts a later diagnosis needs, as one flat key=value detail."""
    return (
        f"verdict={status['verdict']} "
        f"source={status['source']} "
        f"skipped={str(status['qa_skipped']).lower()} "
        f"gate_exit={'none' if status['gate_exit'] is None else status['gate_exit']} "
        f"repairs={status['repair_iterations']} "
        f"dispatched={len(status['dispatched'])} "
        f"open_actions={status['repair_plan'].get('action_count', 0)} "
        f"cosmetic={len(status['cosmetic_advisories'])} "
        f"secret_issues={status['secret_issues']}"
    )


def append_log(output_dir: Path, status: dict) -> None:
    """Best-effort — a failed log write never fails the stage."""
    try:
        with open(output_dir / LOG_NAME, "a", encoding="utf-8") as fh:
            fh.write(format_line("QA_GATE", log_detail(status), component="qa-reviewer"))
    except OSError:
        pass


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="render_qa_receipt.py", description=__doc__)
    parser.add_argument("output_dir")
    parser.add_argument(
        "--gate-exit",
        type=int,
        default=None,
        help="exit code of the final `qa_checks.py gate` call (0/1/2/3/4)",
    )
    parser.add_argument(
        "--repair-iterations",
        type=int,
        default=0,
        help="how many repair iterations the bounded loop consumed",
    )
    parser.add_argument(
        "--dispatched",
        action="append",
        default=[],
        metavar="AGENT",
        help="an agent Stage 3 dispatched; repeatable",
    )
    parser.add_argument("--no-print", action="store_true", help="append the log line, print nothing")
    args = parser.parse_args(argv)

    # An unset `$OUTPUT_DIR` reaches us as an empty argument, and `Path("")` is
    # `PosixPath('.')` — under an agent that is the scanned repository's root.
    # The `is_dir()` check below cannot catch it, because `'.'` is always a
    # directory, so the log write would land in a foreign worktree. An option
    # name in this slot means the arguments shifted for the same reason. Refuse
    # both, as every writer under `tests/test_run_path_guard.py` does.
    raw = args.output_dir.strip()
    if not raw:
        print("render_qa_receipt.py: output_dir is empty — is $OUTPUT_DIR exported?", file=sys.stderr)
        return 2
    if raw.startswith("-"):
        print(f"render_qa_receipt.py: output_dir looks like an option: {raw!r}", file=sys.stderr)
        return 2

    output_dir = Path(raw)
    if not output_dir.is_dir():
        print(f"render_qa_receipt.py: output dir not found: {output_dir}", file=sys.stderr)
        return 2

    status = build_status(
        output_dir,
        gate_exit=args.gate_exit,
        repair_iterations=max(0, args.repair_iterations),
        dispatched=[str(d) for d in args.dispatched if str(d).strip()],
    )
    append_log(output_dir, status)

    if not args.no_print:
        print(render(status))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
