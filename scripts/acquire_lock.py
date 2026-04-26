#!/usr/bin/env python3
"""
acquire_lock.py — assessment concurrency lock helper.

Replaces the compound Bash lock script in appsec-threat-analyst.md so the
operation runs under a single `python3:*` permission entry instead of
requiring compound-command approval from Claude Code.

Usage:
  python3 acquire_lock.py <lock_file_path> [--reset-dirs]
  python3 acquire_lock.py <lock_file_path> --heartbeat [--phase=<P>] [--step=<S>]

Positional argument:
  <lock_file_path>   Path to the lock file (e.g. $OUTPUT_DIR/.appsec-lock).

Options:
  --reset-dirs       Wipe $OUTPUT_DIR/.progress and recreate it (and ensure
                     .appsec-cache and .fragments exist). Use this in step 7 of
                     the pre-phase checklist to avoid a separate mkdir call.
                     When --reset-dirs is given the lock check is SKIPPED — the
                     lock was already acquired in step 2.
  --heartbeat        Refresh the liveness heartbeat on an existing lock. The
                     lock file must exist; otherwise the call exits 0 without
                     mutating so the orchestrator can fire heartbeats defensively
                     at every phase boundary without racing a cleanup pass.
                     Each heartbeat additionally appends a single
                     ``HEARTBEAT`` line to ``$OUTPUT_DIR/.hook-events.log`` so
                     external watchers (status command, monitor scripts, IDE
                     plugins) see liveness without parsing the lock file.
  --phase=<P>        Optional phase label written into the HEARTBEAT event
                     detail (e.g. ``--phase=10b``). Defaults to "?".
  --step=<S>         Optional step label written into the HEARTBEAT event
                     detail (e.g. ``--step=triage``). Defaults to "".

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
from datetime import datetime, timezone
from pathlib import Path

STALE_SECONDS = 3600                # 1h mtime fallback for v1 / ambiguous locks
HEARTBEAT_STALE_SECONDS = 300       # 5m — how long we tolerate an un-pinged v2 lock

# Hook-log line shape mirrors agent_logger._write so a HEARTBEAT line is
# indistinguishable from any other event for downstream parsers. Session-ID
# is unknown to this script (it runs from Bash, not from a Claude Code hook
# context), so the bracketed slot is left blank and padded to 8 chars to
# keep column alignment.
_LOG_FILENAME = ".hook-events.log"
_HEARTBEAT_EVENT = "HEARTBEAT"


def _emit_hook_event(output_dir: Path, level: str, event: str, detail: str) -> None:
    """Append a single line to ``$OUTPUT_DIR/.hook-events.log``.

    Best-effort: any IO error is silently swallowed because the heartbeat
    must never fail the run. The format is byte-compatible with the lines
    written by ``agent_logger._write`` so existing parsers (`render_completion_summary`,
    `aggregate_run_issues`, etc.) handle it uniformly.
    """
    try:
        log_path = output_dir / _LOG_FILENAME
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sid = " " * 8  # unknown — we run outside the hook context
        line = f"{ts}  [{sid}]  {level:<5}  {event:<18}  {detail}\n"
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        # Never crash the heartbeat caller — the run is the priority, not
        # the audit log.
        pass


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

    Classification precedence (heartbeat-first, because the stored PID is an
    ephemeral Python-subprocess PID that is always dead shortly after
    acquisition — see `_do_heartbeat` docstring):

      'fresh'        — v2 heartbeat is within HEARTBEAT_STALE_SECONDS.
      'hung'         — v2 heartbeat is older than HEARTBEAT_STALE_SECONDS
                       AND the stored PID is still alive. A live PID with a
                       silent heartbeat is the signature of a thinking-loop
                       stall — the anti-stall caller reaps it.
      'dead'         — v2 lock whose heartbeat is stale AND the PID is gone
                       (process exited, crash, Ctrl-C).
      'stale_mtime'  — v1 lock (no heartbeat) with mtime older than STALE_SECONDS.
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

    # v2 lock with heartbeat — heartbeat freshness is authoritative.
    if heartbeat is not None:
        hb_age = time.time() - heartbeat
        info["heartbeat_age"] = int(hb_age)
        if hb_age <= HEARTBEAT_STALE_SECONDS:
            return ("fresh", info)
        # Stale heartbeat — distinguish hung (PID still alive) from dead.
        if alive:
            return ("hung", info)
        return ("dead", info)

    # Legacy v1 lock (pre-heartbeat). PID liveness is the only signal.
    if not alive:
        return ("dead", info)
    if age_mtime > STALE_SECONDS:
        return ("stale_mtime", info)
    return ("fresh", info)


def _do_heartbeat(lock_path: Path, phase: str = "?", step: str = "") -> int:
    """Refresh the heartbeat timestamp on the existing lock and emit a
    ``HEARTBEAT`` event into ``$OUTPUT_DIR/.hook-events.log``.

    The stored PID stays the PID originally written at acquisition time — we
    only update the heartbeat timestamp. This matters because every orchestrator
    Bash turn spawns a fresh short-lived Python interpreter (different PID from
    the one that acquired the lock), so a PID-match gate would silently no-op
    every heartbeat and leave the anti-stall classifier blind. File-based lock
    semantics make this safe: whoever owns the lock file owns the lock; if two
    runs race, the loser's `acquire_lock.py` (without `--heartbeat`) sees the
    existing file and either blocks or reaps.

    The hook-log line keeps the heartbeat visible to any external watcher
    that tails ``.hook-events.log`` — previously the heartbeat was silent
    (lock-file-only) and there was no way for ``/appsec-advisor:status`` or
    a monitor script to see "the agent is alive" without parsing the lock
    file. Format is identical to the other ``INFO`` events so existing
    parsers handle it uniformly. Skipped heartbeats also emit a line so a
    silent run is never misclassified as alive.
    """
    output_dir = lock_path.parent
    if not lock_path.exists():
        _emit_hook_event(output_dir, "WARN", _HEARTBEAT_EVENT,
                         f"skip=lock_absent  phase={phase}{('  step='+step) if step else ''}")
        print("HEARTBEAT_SKIP: lock file absent", file=sys.stderr)
        return 0
    pid, _ = _parse_lock(lock_path)
    if pid is None:
        _emit_hook_event(output_dir, "WARN", _HEARTBEAT_EVENT,
                         f"skip=lock_malformed  phase={phase}{('  step='+step) if step else ''}")
        print("HEARTBEAT_SKIP: lock file malformed", file=sys.stderr)
        return 0
    # Preserve the original acquirer PID — only bump the heartbeat timestamp.
    now = int(time.time())
    _write_lock(lock_path, pid, now)
    _emit_hook_event(output_dir, "INFO", _HEARTBEAT_EVENT,
                     f"pid={pid}  phase={phase}{('  step='+step) if step else ''}  ts={now}")
    print("HEARTBEAT_OK")
    return 0


def main(argv: list[str]) -> int:
    # Parse args: positional lock path + optional flags. ``--phase=<P>`` and
    # ``--step=<S>`` are key=value flags consumed by the heartbeat path.
    bare_flags = {"--reset-dirs", "--heartbeat"}
    rest = argv[1:]
    reset_dirs = "--reset-dirs" in rest
    heartbeat = "--heartbeat" in rest
    phase = "?"
    step = ""
    args: list[str] = []
    for tok in rest:
        if tok in bare_flags:
            continue
        if tok.startswith("--phase="):
            phase = tok.split("=", 1)[1] or "?"
            continue
        if tok.startswith("--step="):
            step = tok.split("=", 1)[1]
            continue
        args.append(tok)

    if len(args) != 1:
        print(
            f"usage: {argv[0]} <lock_file_path> "
            f"[--reset-dirs | --heartbeat [--phase=<P>] [--step=<S>]]",
            file=sys.stderr,
        )
        return 2

    lock_path = Path(args[0])
    output_dir = lock_path.parent

    if heartbeat:
        return _do_heartbeat(lock_path, phase=phase, step=step)

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
