#!/usr/bin/env python3
"""
acquire_lock.py — assessment concurrency lock helper.

Replaces the compound Bash lock script in appsec-threat-analyst.md so the
operation runs under a single `python3:*` permission entry instead of
requiring compound-command approval from Claude Code.

Usage:
  python3 acquire_lock.py <lock_file_path> [--reset-dirs]

Positional argument:
  <lock_file_path>   Path to the lock file (e.g. $OUTPUT_DIR/.appsec-lock).

Options:
  --reset-dirs   Wipe $OUTPUT_DIR/.progress and recreate it (and ensure
                 .appsec-cache and .fragments exist). Use this in step 7 of
                 the pre-phase checklist to avoid a separate mkdir call.
                 When --reset-dirs is given the lock check is SKIPPED — the
                 lock was already acquired in step 2.

Exit codes:
  0  — LOCK_ACQUIRED (or DIRS_RESET when --reset-dirs); directories created
  1  — LOCK_BLOCKED; another assessment is running
  2  — usage error

The lock file contains the current PID. A lock older than 3600 s is
considered stale and overwritten (same semantics as the prior Bash script).
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

STALE_SECONDS = 3600

# Standard subdirectories created alongside the lock so the orchestrator
# never needs a separate mkdir -p call (which would cause compound-command
# permission prompts when batched with this python3 invocation).
STANDARD_SUBDIRS = (".appsec-cache", ".fragments")
# .progress is handled separately because --reset-dirs wipes+recreates it.
PROGRESS_DIR = ".progress"


def _ensure_dirs(output_dir: Path, reset_progress: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for sub in STANDARD_SUBDIRS:
        (output_dir / sub).mkdir(exist_ok=True)
    progress = output_dir / PROGRESS_DIR
    if reset_progress and progress.exists():
        shutil.rmtree(progress, ignore_errors=True)
    progress.mkdir(exist_ok=True)


def main(argv: list[str]) -> int:
    # Parse args: positional lock path + optional --reset-dirs flag
    args = [a for a in argv[1:] if a != "--reset-dirs"]
    reset_dirs = "--reset-dirs" in argv[1:]

    if len(args) != 1:
        print(f"usage: {argv[0]} <lock_file_path> [--reset-dirs]", file=sys.stderr)
        return 2

    lock_path = Path(args[0])
    output_dir = lock_path.parent

    if reset_dirs:
        # Called from step 7 — lock already held, just reset dirs.
        _ensure_dirs(output_dir, reset_progress=True)
        print("DIRS_RESET")
        return 0

    # Normal lock acquisition (step 2).
    _ensure_dirs(output_dir, reset_progress=False)

    if lock_path.exists():
        try:
            mtime = lock_path.stat().st_mtime
            age = time.time() - mtime
        except OSError:
            age = STALE_SECONDS + 1  # treat unreadable lock as stale

        if age < STALE_SECONDS:
            print(
                f"LOCK_BLOCKED: Another assessment is running "
                f"(lock age: {int(age)}s). Remove {lock_path} if stale."
            )
            return 1
        # stale — fall through and overwrite

    lock_path.write_text(str(os.getpid()) + "\n", encoding="utf-8")
    print("LOCK_ACQUIRED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
