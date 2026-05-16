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
    for round_no in range(1, args.rounds + 1):
        elapsed = int(time.time() - start)
        elapsed_s = f"{elapsed // 60}m{elapsed % 60:02d}s"
        print(f"  ↳ (+{elapsed_s}) STRIDE progress poll {round_no}/{args.rounds}")
        last_rc = _run_progress(progress_script, args.output_dir, args.expected, force=(round_no == 1))
        if last_rc == 0:
            return 0
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
    return last_rc


if __name__ == "__main__":
    raise SystemExit(main())
