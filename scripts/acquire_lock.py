#!/usr/bin/env python3
"""
acquire_lock.py — assessment concurrency lock helper.

Replaces the compound Bash lock script in appsec-threat-analyst.md so the
operation runs under a single `python3:*` permission entry instead of
requiring compound-command approval from Claude Code.

Usage:
  python3 acquire_lock.py <lock_file_path> [--reset-dirs]
  python3 acquire_lock.py <lock_file_path> --heartbeat

Positional argument:
  <lock_file_path>   Path to the lock file (e.g. $OUTPUT_DIR/.appsec-lock).

Options:
  --reset-dirs   Wipe $OUTPUT_DIR/.progress and recreate it (and ensure
                 .appsec-cache and .fragments exist). Use this in step 7 of
                 the pre-phase checklist to avoid a separate mkdir call.
                 When --reset-dirs is given the lock check is SKIPPED — the
                 lock was already acquired in step 2.
  --heartbeat    Refresh the liveness heartbeat on an existing lock. The
                 lock file must exist and be held by this process (same
                 PID); otherwise the call exits 0 without mutating so the
                 orchestrator can fire heartbeats defensively at every
                 phase boundary without racing a cleanup pass.

Lock file format
----------------
Version 2 (current):
    <pid>\n
    <heartbeat_unix_ts>\n

Version 1 (pre-heartbeat, still accepted for reads):
    <pid>\n

When a v2 lock's heartbeat timestamp is older than HEARTBEAT_STALE_SECONDS
(5 min), the lock is considered **hung** — the PID is alive but the
orchestrator has not emitted any observable progress in a threshold window.
The lock is reaped in that case as if the PID were dead. V1 locks continue
to use the legacy mtime-based STALE_SECONDS fallback (1 h).

Exit codes:
  0  — LOCK_ACQUIRED / DIRS_RESET / HEARTBEAT_OK; directories created
  1  — LOCK_BLOCKED; another assessment is running
  2  — usage error
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

STALE_SECONDS = 3600                # 1h mtime fallback for v1 / ambiguous locks
HEARTBEAT_STALE_SECONDS = 300       # 5m — how long we tolerate an un-pinged v2 lock


def _pid_alive(pid: int) -> bool:
    """Return True when the OS considers ``pid`` alive.

    Mirrors ``check_state._pid_alive`` — kept as a local copy so this script
    stays importable without a dependency on the sibling module.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Signal denied ⇒ process exists under another user.
        return True
    except OSError:
        return False
    return True

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


def _parse_lock(lock_path: Path) -> tuple[int | None, int | None]:
    """Return (pid, heartbeat_ts) — either value may be None.

    Malformed locks return (None, None). A v1 lock (PID-only) returns
    (pid, None). A v2 lock returns (pid, heartbeat_ts). Extra lines are
    ignored so future versions can append without breaking older readers.
    """
    try:
        raw = lock_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return (None, None)
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return (None, None)
    try:
        pid = int(lines[0].split()[0])
    except (ValueError, IndexError):
        return (None, None)
    heartbeat: int | None = None
    if len(lines) >= 2:
        try:
            heartbeat = int(lines[1].split()[0])
        except (ValueError, IndexError):
            heartbeat = None
    return (pid, heartbeat)


def _write_lock(lock_path: Path, pid: int, heartbeat_ts: int) -> None:
    lock_path.write_text(f"{pid}\n{heartbeat_ts}\n", encoding="utf-8")


def _classify_lock(lock_path: Path) -> tuple[str, dict]:
    """Return (state, info). state in {'fresh', 'hung', 'dead', 'stale_mtime', 'malformed', 'absent'}.

    'fresh'        — live PID, recent heartbeat (or legacy v1 with fresh mtime).
    'hung'         — live PID, v2 heartbeat older than HEARTBEAT_STALE_SECONDS.
    'dead'         — PID no longer maps to a process.
    'stale_mtime'  — v1 lock with mtime older than STALE_SECONDS (legacy path).
    'malformed'    — unparseable lock file.
    'absent'       — no lock file.
    """
    if not lock_path.exists():
        return ("absent", {})
    try:
        mtime = lock_path.stat().st_mtime
    except OSError:
        return ("malformed", {"reason": "stat failed"})
    age_mtime = time.time() - mtime

    pid, heartbeat = _parse_lock(lock_path)
    if pid is None:
        return ("malformed", {"mtime_age": int(age_mtime)})

    alive = _pid_alive(pid)
    info = {"pid": pid, "heartbeat": heartbeat, "mtime_age": int(age_mtime)}

    if not alive:
        return ("dead", info)

    # Live PID — decide between fresh and hung.
    if heartbeat is not None:
        hb_age = time.time() - heartbeat
        info["heartbeat_age"] = int(hb_age)
        if hb_age > HEARTBEAT_STALE_SECONDS:
            return ("hung", info)
        return ("fresh", info)

    # Legacy v1 lock — fall back to the mtime heuristic.
    if age_mtime > STALE_SECONDS:
        return ("stale_mtime", info)
    return ("fresh", info)


def _do_heartbeat(lock_path: Path) -> int:
    """Refresh heartbeat on an existing lock we own. No-op when conditions unmet."""
    if not lock_path.exists():
        # Lock was already reaped — perhaps by a concurrent --clean-state pass.
        # Heartbeat is defensive; no need to fail.
        print("HEARTBEAT_SKIP: lock file absent", file=sys.stderr)
        return 0
    pid, _ = _parse_lock(lock_path)
    if pid != os.getpid():
        # Some other process owns this lock — do not overwrite.
        print(
            f"HEARTBEAT_SKIP: lock held by pid={pid} (not our pid={os.getpid()})",
            file=sys.stderr,
        )
        return 0
    _write_lock(lock_path, os.getpid(), int(time.time()))
    print("HEARTBEAT_OK")
    return 0


def main(argv: list[str]) -> int:
    # Parse args: positional lock path + optional flags
    flags = {"--reset-dirs", "--heartbeat"}
    args = [a for a in argv[1:] if a not in flags]
    reset_dirs = "--reset-dirs" in argv[1:]
    heartbeat = "--heartbeat" in argv[1:]

    if len(args) != 1:
        print(
            f"usage: {argv[0]} <lock_file_path> [--reset-dirs | --heartbeat]",
            file=sys.stderr,
        )
        return 2

    lock_path = Path(args[0])
    output_dir = lock_path.parent

    if heartbeat:
        return _do_heartbeat(lock_path)

    if reset_dirs:
        # Called from step 7 — lock already held, just reset dirs.
        _ensure_dirs(output_dir, reset_progress=True)
        print("DIRS_RESET")
        return 0

    # Normal lock acquisition (step 2).
    _ensure_dirs(output_dir, reset_progress=False)

    state, info = _classify_lock(lock_path)

    if state == "fresh":
        hb = info.get("heartbeat_age")
        hb_str = f", hb_age={hb}s" if hb is not None else ""
        print(
            f"LOCK_BLOCKED: Another assessment is running "
            f"(pid={info['pid']}, mtime_age={info['mtime_age']}s{hb_str}). "
            f"Remove {lock_path} if stale."
        )
        return 1

    if state == "hung":
        hb = info.get("heartbeat_age", "?")
        print(
            f"LOCK_STALE: prior lock held by pid={info['pid']} but heartbeat "
            f"is {hb}s old (> {HEARTBEAT_STALE_SECONDS}s threshold) — reaped.",
            file=sys.stderr,
        )
    elif state == "dead":
        print(
            f"LOCK_STALE: prior lock held by dead PID {info['pid']} — reaped.",
            file=sys.stderr,
        )
    elif state == "stale_mtime":
        print(
            f"LOCK_STALE: prior lock mtime {info['mtime_age']}s > "
            f"{STALE_SECONDS}s threshold — reaped.",
            file=sys.stderr,
        )
    elif state == "malformed":
        print(
            f"LOCK_STALE: prior lock file was malformed — reaped.",
            file=sys.stderr,
        )
    # state == "absent" — fall through and write a fresh lock.

    _write_lock(lock_path, os.getpid(), int(time.time()))
    print("LOCK_ACQUIRED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
