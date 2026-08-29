#!/usr/bin/env python3
"""Wait for background STRIDE analyzers with bounded progress reporting.

This wraps ``stride_progress.py`` in one deterministic process so the
orchestrator does not spend one LLM turn per 20-second poll.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import stride_dispatch_waves

PENDING_EXIT_CODE = 75


def _run_progress(script: Path, output_dir: Path, expected: int, *, force: bool) -> tuple[int, str]:
    """Poll once; return the exit code and the progress text for the caller.

    The text is returned rather than printed so the poll loop can drop a round
    that repeats the previous one. A wave joined over 24 rounds forwarded 24
    full progress dumps into the orchestrator's context, 23 of them already
    stale by the time the call returned — measured at 5.8KB for a single
    waiter call on run a2a0e355.
    """
    cmd = [sys.executable, str(script), str(output_dir), str(expected)]
    if force:
        cmd.append("--force")
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode, proc.stdout or ""


def _wave_status(output_dir: Path, component_ids: list[str]) -> str | None:
    """Return status for the dispatched jobs, or ``None`` without a plan.

    A background analyzer writes a schema-valid seed before doing its work.
    File-count progress therefore cannot prove completion. Validate only the
    component IDs in the current controller action; future waves must not keep
    this join open.
    """
    if not (output_dir / ".dispatch-waves.json").is_file():
        return None
    if not component_ids:
        print("STRIDE waiter requires --component for a persisted wave plan", file=sys.stderr)
        return "invalid"
    try:
        status = stride_dispatch_waves.load_wait_status(output_dir, component_ids, begin=True).get("status")
    except (OSError, ValueError, stride_dispatch_waves.WavePlanError) as exc:
        print(f"invalid STRIDE wave state: {exc}", file=sys.stderr)
        return "invalid"
    return status if status in {"complete", "pending", "expired"} else "invalid"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("expected", type=int)
    parser.add_argument("--interval", type=int, default=20)
    parser.add_argument("--rounds", type=int, default=24)
    parser.add_argument("--plugin-root", type=Path, default=None)
    parser.add_argument("--component", action="append", default=[])
    args = parser.parse_args(argv)

    if args.expected <= 0:
        return 0

    plugin_root = args.plugin_root or Path(__file__).resolve().parent.parent
    progress_script = plugin_root / "scripts" / "stride_progress.py"
    if not progress_script.is_file():
        print(f"missing progress script: {progress_script}", file=sys.stderr)
        return 2

    start = time.time()
    last_rc = 1
    last_wave_status: str | None = None
    previous_progress: str | None = None
    for round_no in range(1, args.rounds + 1):
        elapsed = int(time.time() - start)
        elapsed_s = f"{elapsed // 60}m{elapsed % 60:02d}s"
        last_rc, progress = _run_progress(progress_script, args.output_dir, args.expected, force=(round_no == 1))
        # Report a round only when it says something the last one did not, so
        # the caller sees every state transition — including the final ready
        # count the stage runtime reads — without the identical rounds between.
        if progress != previous_progress:
            print(f"  ↳ (+{elapsed_s}) STRIDE progress poll {round_no}/{args.rounds}")
            if progress:
                print(progress, end="")
            previous_progress = progress
        last_wave_status = _wave_status(args.output_dir, args.component)
        if last_wave_status == "complete" or (last_wave_status is None and last_rc == 0):
            return 0
        if last_wave_status == "expired":
            print(
                "BASH_WARN STRIDE wave join deadline reached — returning to controller retry ownership", file=sys.stderr
            )
            return 1
        if last_wave_status == "invalid":
            return 2
        if last_rc >= 2:
            return last_rc
        if round_no in {12, 24, 36}:
            print(
                f"BASH_WARN STRIDE polling slow — still waiting after {elapsed_s}",
                file=sys.stderr,
            )
        if round_no < args.rounds:
            time.sleep(max(args.interval, 1))

    # Only the pending path is repeatable, so only it may say so. The host
    # renders every non-zero exit as a failed call; without this wording the
    # operator reads a healthy wave-in-progress as a broken run.
    if last_wave_status == "pending":
        print(
            "STRIDE join slice exhausted while the wave is still running and its cumulative "
            "deadline has not expired. This is expected, not a failure: exit 75 means repeat "
            "the identical waiter call.",
            file=sys.stderr,
        )
        return PENDING_EXIT_CODE
    print(
        "STRIDE join slice exhausted while the cumulative wave deadline remains",
        file=sys.stderr,
    )
    return last_rc


if __name__ == "__main__":
    raise SystemExit(main())
