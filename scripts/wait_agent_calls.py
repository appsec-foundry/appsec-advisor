#!/usr/bin/env python3
"""Join the plugin agent calls a stage dispatched, in one blocking command.

Claude Code launches every Agent call asynchronously. A runtime that only says
"wait for" an agent therefore ends the orchestrator's turn while the agent
runs, and that turn fills with log polling and status prose. STRIDE and abuse
fan-outs have their own result-validating waiters, wait_stride_progress.py and
wait_abuse_progress.py; this waiter joins every other dispatch (OR-24): the
Stage-1 single jobs such as recon, architecture, and the threat merger, the
Stage-2 renderers and repair fixer, the Stage-3 QA reviewer and fixer, and the
Stage-4 editorial waves. The STRIDE waiter reads only STRIDE progress, so a
single job joined with it idles a full slice after its agent has finished.

Completion is read from the call lifecycle, never from an agent's files: a
renderer rewrites its fragment in place and the threat merger rewrites its
decisions after validating a draft, so a file proves nothing, while the
child's stop is the single terminal boundary of an async call: its
SubagentStop, or its handback when no SubagentStop can follow (see
agent_lifecycle.child_has_stopped). The waiter only reads that
state; settling a call stays the hooks' job. ``still_waiting`` is the one rule
for which calls still hold a join: the controller rejects a context-v2
boundary on the same rule (OR-14), so a boundary never judges output that its
producer may still rewrite.

Exit codes: 0 every joined call finished; 75 calls are still running when this
slice ends, so repeat the identical command; 1 the join cannot see the calls,
or a call outlived the deadline, so continue and let the controller's checks
decide; 2 invalid arguments.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import agent_lifecycle

PENDING_EXIT_CODE = 75
PLUGIN_AGENT_PREFIX = "appsec-advisor:"
UNOBSERVED_ROUNDS = 3
DEFAULT_DEADLINE_MINUTES = 60


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Join the plugin agent calls a stage dispatched.")
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--since", default="", help="ISO-8601 time taken just before the dispatch")
    parser.add_argument("--interval", type=int, default=20)
    parser.add_argument("--rounds", type=int, default=24)
    parser.add_argument("--deadline-minutes", type=int, default=DEFAULT_DEADLINE_MINUTES)
    return parser


def parse_since(value: str) -> float | None:
    """Epoch seconds for ``--since``, or ``None`` when empty. A naive time is local."""
    value = value.strip()
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def joined_calls(output_dir: Path, since: float | None) -> list[dict] | None:
    """Plugin agent calls spawned at or after ``since``; ``None`` when the state cannot be read.

    The hooks register a call at PreToolUse, before its launch returns, so a
    missing state file right after a dispatch means the join cannot see the
    calls, not that none exist.
    """
    try:
        text = agent_lifecycle.state_path(output_dir).read_text(encoding="utf-8")
        state = agent_lifecycle.validate_state(json.loads(text))
    except (OSError, ValueError, agent_lifecycle.LifecycleError):
        return None
    return [
        call
        for call in state["calls"]
        if str(call.get("agent_type", "")).startswith(PLUGIN_AGENT_PREFIX)
        and (since is None or call.get("spawned_at", 0) >= int(since))
    ]


def is_live(call: dict, now: float | None = None) -> bool:
    """A running call whose child has not stopped; a stopped child being settled no longer holds a join."""
    return call.get("state") == "running" and not agent_lifecycle.child_has_stopped(call, now)


def still_waiting(calls: list[dict], now: float, deadline_seconds: float) -> list[dict]:
    """The live calls a join still waits for; a call past the deadline never holds one."""
    return [call for call in calls if is_live(call, now) and now - call.get("spawned_at", 0) <= deadline_seconds]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        since = parse_since(args.since)
    except ValueError:
        print(f"invalid --since {args.since!r}: expected ISO-8601 such as 2026-09-12T13:09:25Z", file=sys.stderr)
        return 2
    if since is not None and since > time.time() + 60:
        print(f"--since {args.since} lies in the future; joining every live plugin call instead", file=sys.stderr)
        since = None
    deadline = max(args.deadline_minutes, 1) * 60
    rounds = max(args.rounds, 1)

    started = time.time()
    reported: int | None = None
    observed = False
    unobserved = 0
    for round_no in range(1, rounds + 1):
        calls = joined_calls(args.output_dir, since)
        if calls is None:
            unobserved += 1
            if unobserved >= UNOBSERVED_ROUNDS:
                break
        else:
            observed = True
            unobserved = 0
            now = time.time()
            live = [call for call in calls if is_live(call, now)]
            waiting = still_waiting(live, now, deadline)
            if not waiting:
                if live:
                    names = ", ".join(sorted({str(call.get("agent_type")) for call in live}))
                    print(
                        f"BASH_WARN no longer waiting for {len(live)} call(s) past the "
                        f"{args.deadline_minutes}-minute deadline: {names}",
                        file=sys.stderr,
                    )
                    return 1
                print(f"  ↳ {len(calls)} agent call(s) finished")
                return 0
            if len(waiting) != reported:
                elapsed = int(now - started)
                print(
                    f"  ↳ (+{elapsed // 60}m{elapsed % 60:02d}s) {len(waiting)} of {len(calls)} agent call(s) still running"
                )
                reported = len(waiting)
        if round_no < rounds:
            time.sleep(max(args.interval, 1))

    if unobserved >= UNOBSERVED_ROUNDS or (unobserved and not observed):
        print(
            "BASH_WARN the agent lifecycle state is missing or unreadable, so the join cannot see the calls; "
            "continue and let the controller's checks decide",
            file=sys.stderr,
        )
        return 1
    print(
        "Agents still running when this join slice ended. This is expected, not a failure: "
        "exit 75 means repeat the identical command.",
        file=sys.stderr,
    )
    return PENDING_EXIT_CODE


if __name__ == "__main__":
    raise SystemExit(main())
