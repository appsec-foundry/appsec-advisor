#!/usr/bin/env python3
"""Wait for a background abuse-verifier wave to finalize every candidate.

Exit codes: 0 every candidate finalized; 75 the slice ended while a verifier
call is still live, so repeat the identical command; 1 the cap was reached with
no live verifier left, so its jobs are closed and finalize-abuse owns the retry;
2 invalid arguments.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

import agent_lifecycle
import budget_watchdog
import verify_abuse_cases
import wait_agent_calls

PENDING_EXIT_CODE = 75

_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def candidate_status(output_dir: Path, candidate_id: str) -> str:
    """Return ``complete``, ``pending``, or ``invalid`` for one verdict."""
    path = output_dir / f".abuse-case-verdict-{candidate_id}.json"
    try:
        verdict = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return "pending"
    except (OSError, json.JSONDecodeError):
        return "invalid"
    if not isinstance(verdict, dict) or verdict.get("abuse_case_id") != candidate_id:
        return "invalid"
    return "complete" if verify_abuse_cases.is_finalized_verdict(verdict) else "pending"


def _close_jobs(output_dir: Path, candidate_ids: list[str], *, success: bool, reason: str = "") -> None:
    events = agent_lifecycle.finish_jobs(
        output_dir,
        [f"phase10c-abuse-{candidate}" for candidate in candidate_ids],
        success=success,
        reason=reason,
    )
    agent_lifecycle.append_events(output_dir, events)
    for event in events:
        budget_watchdog.close_call(str(event.call.get("agent_call_id") or ""), output_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("candidate_ids", nargs="*")
    parser.add_argument("--interval", type=int, default=20)
    parser.add_argument("--rounds", type=int, default=24)
    args = parser.parse_args(argv)

    if not args.candidate_ids:
        return 0
    if len(args.candidate_ids) > 64 or len(set(args.candidate_ids)) != len(args.candidate_ids):
        print("invalid abuse verifier candidate list", file=sys.stderr)
        return 2
    if any(not _CANDIDATE_RE.fullmatch(item) for item in args.candidate_ids):
        print("unsafe abuse verifier candidate id", file=sys.stderr)
        return 2

    started = time.time()
    reported: int | None = None
    for round_no in range(1, args.rounds + 1):
        states = {candidate: candidate_status(args.output_dir, candidate) for candidate in args.candidate_ids}
        complete = sum(state == "complete" for state in states.values())
        completed_ids = [candidate for candidate, state in states.items() if state == "complete"]
        _close_jobs(args.output_dir, completed_ids, success=True)
        pending = [candidate for candidate, state in states.items() if state != "complete"]
        elapsed = int(time.time() - started)
        # A round is reported only when the count moves; the caller reads the last one.
        if complete != reported:
            print(f"  ↳ (+{elapsed // 60}m{elapsed % 60:02d}s) abuse verification {complete}/{len(states)} complete")
            reported = complete
        if not pending:
            return 0
        if round_no in {12, 24, 36}:
            print("BASH_WARN abuse verifier polling slow — still waiting", file=sys.stderr)
        if round_no < args.rounds:
            time.sleep(max(args.interval, 1))

    # One Bash call cannot outlast a verifier. Closing a call that still runs
    # lets finalize-abuse re-dispatch a duplicate beside it.
    pending_jobs = {f"phase10c-abuse-{candidate}" for candidate in pending}
    live = [call for call in agent_lifecycle.running_calls(args.output_dir) if call.get("job_id") in pending_jobs]
    if wait_agent_calls.still_waiting(live, time.time(), wait_agent_calls.DEFAULT_DEADLINE_MINUTES * 60):
        print(
            "Abuse verifiers still running when this join slice ended. This is expected, not a failure: "
            "exit 75 means repeat the identical command.",
            file=sys.stderr,
        )
        return PENDING_EXIT_CODE
    print(
        "BASH_WARN abuse verifier poll cap reached; unfinished: " + ", ".join(pending),
        file=sys.stderr,
    )
    _close_jobs(args.output_dir, pending, success=False, reason="join_deadline_expired")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
