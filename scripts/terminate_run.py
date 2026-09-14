#!/usr/bin/env python3
"""Converge a non-clean run on one terminal result.

A run ends in one of four ways: it completes, the controller aborts it, the
provider fails, or the operator interrupts it. Only the first two passed
through code that left a consistent terminal state. An operator interrupt
reached the shell wrapper alone, which cleared the live tool markers and
exited — leaving the lock held, the checkpoint mid-flight, no ``RUN_ABORTED``
record and no run issues, so ``appsec_status.py --live`` reported an unknown
phase until the heartbeat aged out.

This is the single terminator for every non-clean exit class. It is idempotent
and best-effort in every direction: the terminator must never mask the failure
that brought the run here, so it reports what it did on stdout and always
exits 0.

It is also scoped to one directory's own run. Every surface it converges —
``RUN_ABORTED``, the checkpoint, the live agent markers, the run issues, the
lock — is the lock holder's state, so a run whose exit class is "somebody else
holds this output directory" terminates nothing in it.

Usage
-----

  python3 terminate_run.py --output-dir <dir> --outcome interrupt \\
      [--reason "<text>"] [--run-id <id>] [--repo-root <path>]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import acquire_lock  # noqa: E402
import agent_logger  # noqa: E402
import cutoff_cause  # noqa: E402
from event_log import format_line  # noqa: E402

#: The exit classes the wrapper can tell apart. The value is the word that
#: reaches `RUN_ABORTED`, the checkpoint, and the cut-off classifier, so one
#: run is described the same way everywhere. A controller abort needs no entry:
#: it writes its own verdict, and this terminator then leaves it standing.
OUTCOMES = {
    "interrupt": "operator_interrupt",
    "failure": "run_failed",
}

AGGREGATOR_TIMEOUT_S = 120


def _append_event(output_dir: Path, event: str, detail: str, level: str = "WARN ") -> None:
    try:
        with (output_dir / ".agent-run.log").open("a", encoding="utf-8") as handle:
            handle.write(format_line(event, detail, level=level, component="run-terminator"))
    except OSError:
        pass


def _aggregate_issues(output_dir: Path, repo_root: str, depth: str) -> str:
    command = [sys.executable, str(SCRIPT_DIR / "aggregate_run_issues.py"), str(output_dir)]
    if repo_root and Path(repo_root).is_dir():
        command.extend(["--repo-root", str(repo_root)])
    if depth:
        command.extend(["--depth", depth])
    try:
        subprocess.run(command, capture_output=True, timeout=AGGREGATOR_TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError):
        return "aggregation failed"
    return "aggregated"


def _repo_root_from_config(output_dir: Path, given: str) -> str:
    if given:
        return given
    try:
        config = json.loads((output_dir / ".skill-config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(config.get("repo_root") or "") if isinstance(config, dict) else ""


def terminate(output_dir: Path, outcome: str, reason: str, run_id: str, repo_root: str, depth: str = "") -> list[str]:
    """Bring every terminal surface into agreement. Returns what it did.

    A run that never held this directory terminates nothing in it. The wrapper
    calls the terminator on every non-clean exit, and ``LOCK_BLOCKED`` is one of
    them: the blocked run exits 1 having touched nothing, and without this guard
    the terminator would then abort the *holder's* checkpoint, fail the agents
    it still has in flight and overwrite its run issues — the collision the lock
    was refused to prevent, delivered by the failure path instead.
    """
    if acquire_lock.lock_held_by_live_other_run(output_dir / ".appsec-lock", run_id):
        return ["lock held-by-other", "foreign live run — nothing terminated"]

    steps: list[str] = []
    kind = OUTCOMES[outcome]
    detail = f"outcome={kind}  reason={reason or kind}"

    if cutoff_cause.detect_abort(output_dir):
        steps.append("run already terminal")
    else:
        _append_event(output_dir, "RUN_ABORTED", detail)
        steps.append("RUN_ABORTED recorded")

    phase = agent_logger.mark_checkpoint_aborted_if_dirty(kind, output_dir)
    steps.append(f"checkpoint aborted at phase {phase}" if phase else "checkpoint already terminal")

    try:
        agent_logger.clear_terminal_active_tool_calls(output_dir)
        steps.append("live calls closed")
    except Exception:  # noqa: BLE001 — cleanup never blocks the terminator
        steps.append("live-call cleanup failed")

    steps.append(f"lock {acquire_lock.release_lock(output_dir / '.appsec-lock', run_id)}")
    steps.append(_aggregate_issues(output_dir, _repo_root_from_config(output_dir, repo_root), depth))
    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--outcome", required=True, choices=sorted(OUTCOMES))
    parser.add_argument("--reason", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--repo-root", default="")
    parser.add_argument("--depth", default="")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(f"no run directory at {output_dir}; nothing to terminate")
        return 0
    steps = terminate(
        output_dir,
        args.outcome,
        args.reason.strip(),
        args.run_id.strip(),
        args.repo_root,
        args.depth.strip(),
    )
    for step in steps:
        print(step)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
