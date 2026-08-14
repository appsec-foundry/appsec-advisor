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


def _run_progress(script: Path, output_dir: Path, expected: int, *, force: bool) -> int:
    cmd = [sys.executable, str(script), str(output_dir), str(expected)]
    if force:
        cmd.append("--force")
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def _wave_status(output_dir: Path) -> str | None:
    """Return validated wave status, or ``None`` without a wave plan.

    A background analyzer writes a schema-valid seed before doing its work.
    File-count progress therefore cannot prove completion. When the deterministic
    wave plan exists, use its normal completion validator so the waiter does not
    release the controller while an analyzer is still replacing its seed.
    """
    if not (output_dir / ".dispatch-waves.json").is_file():
        return None
    try:
        status = stride_dispatch_waves.load_status(output_dir).get("status")
    except (OSError, ValueError, stride_dispatch_waves.WavePlanError) as exc:
        print(f"invalid STRIDE wave state: {exc}", file=sys.stderr)
        return "invalid"
    return status if status in {"complete", "pending"} else "invalid"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("expected", type=int)
    parser.add_argument("--interval", type=int, default=20)
    parser.add_argument("--rounds", type=int, default=45)
    parser.add_argument("--plugin-root", type=Path, default=None)
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
    for round_no in range(1, args.rounds + 1):
        elapsed = int(time.time() - start)
        elapsed_s = f"{elapsed // 60}m{elapsed % 60:02d}s"
        print(f"  ↳ (+{elapsed_s}) STRIDE progress poll {round_no}/{args.rounds}")
        last_rc = _run_progress(progress_script, args.output_dir, args.expected, force=(round_no == 1))
        last_wave_status = _wave_status(args.output_dir)
        if last_wave_status == "complete" or (last_wave_status is None and last_rc == 0):
            return 0
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

    print(
        f"BASH_WARN STRIDE poll cap reached — proceeding after {args.rounds} rounds",
        file=sys.stderr,
    )
    return 1 if last_wave_status == "pending" else last_rc


if __name__ == "__main__":
    raise SystemExit(main())
