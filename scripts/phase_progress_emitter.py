#!/usr/bin/env python3
"""
phase_progress_emitter.py — Tail .agent-run.log and emit one structured line
per phase lifecycle event.

Built for consumption by the Claude Code Monitor tool: every stdout line is a
notification that the skill translates into a TaskUpdate. The output vocabulary
is deliberately narrow so the conversation doesn't get flooded.

Usage:
  python3 phase_progress_emitter.py <output_dir> [--once]

Emitted lines (stdout, one per event, line-buffered):
  PHASE_BEGIN|<id>|<label>
  PHASE_DONE|<id>|<label>|<duration>
  ASSESSMENT_END

Where `<id>` matches the orchestrator's numbering (``1``, ``2``, …, ``8b``,
``10b``, ``11``). The script exits 0 after it sees ``ASSESSMENT_END`` so the
Monitor task terminates cleanly when the orchestrator is done.

``--once`` processes whatever is already on disk and exits without tailing —
useful for replaying a completed run or for unit tests.
"""

from __future__ import annotations

import argparse
import re
import signal
import sys
import time
from pathlib import Path

_PHASE_START_RE = re.compile(
    r"PHASE_START\s+\[Phase\s+(?P<id>\d+[a-z]?)/\d+\]\s*[▶⟳]?\s*(?P<label>.+?)\s*$"
)
_PHASE_END_RE = re.compile(
    r"PHASE_END\s+\[Phase\s+(?P<id>\d+[a-z]?)/\d+\]\s*[✓]?\s*(?P<label>.+?)\s*$"
)
_ASSESSMENT_END_RE = re.compile(r"ASSESSMENT_END")
_DURATION_RE = re.compile(r"[\[(](\d+m\s*\d+s|\d+m|\d+s)[\])]")


def _clean_label(raw: str) -> tuple[str, str]:
    """Return (short_label, duration_if_found). ``raw`` is the tail of a
    PHASE_START / PHASE_END line after the [Phase N/11] prefix. The duration
    is accepted in either ``[Xm YYs]`` or ``(Xm YYs)`` bracketing — different
    phase groups use different conventions."""
    duration = ""
    # Scan all bracketed spans and keep the last one that looks like a
    # duration. Non-duration parens like "(Critical: 7, High: 13, …)" are
    # ignored because they don't match the Xm YYs / Xm / Xs shape.
    for m in _DURATION_RE.finditer(raw):
        duration = m.group(1).strip()
    if duration:
        # Strip the duration span out of the label for a clean subject.
        raw = _DURATION_RE.sub("", raw).rstrip()
    # Drop trailing " — <details>" noise so the Task subject stays compact.
    for sep in (" — ", " - ", ": "):
        if sep in raw:
            raw = raw.split(sep, 1)[0]
            break
    return raw.strip(), duration


def _emit(line: str) -> None:
    print(line, flush=True)


def _process(line: str, seen: set[str]) -> bool:
    """Parse one log line, emit an event if applicable, and return True when
    the orchestrator has finished (ASSESSMENT_END)."""
    m = _PHASE_START_RE.search(line)
    if m:
        phase_id = m.group("id")
        label, _ = _clean_label(m.group("label"))
        key = f"BEGIN:{phase_id}"
        if key not in seen:
            seen.add(key)
            _emit(f"PHASE_BEGIN|{phase_id}|{label}")
        return False

    m = _PHASE_END_RE.search(line)
    if m:
        phase_id = m.group("id")
        label, duration = _clean_label(m.group("label"))
        key = f"DONE:{phase_id}"
        if key not in seen:
            seen.add(key)
            _emit(f"PHASE_DONE|{phase_id}|{label}|{duration}")
        return False

    if _ASSESSMENT_END_RE.search(line):
        _emit("ASSESSMENT_END")
        return True

    return False


def _run_once(log_path: Path) -> None:
    if not log_path.exists():
        return
    seen: set[str] = set()
    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            _process(line, seen)


def _tail(log_path: Path, poll_interval: float = 0.5) -> None:
    seen: set[str] = set()
    # Wait for the log file to appear (orchestrator may not have started yet).
    deadline = time.time() + 60
    while not log_path.exists() and time.time() < deadline:
        time.sleep(poll_interval)
    if not log_path.exists():
        # Orchestrator never produced a log — nothing to emit. Exit quietly.
        return

    fh = log_path.open("r", encoding="utf-8", errors="replace")
    try:
        # Replay existing lines so late-started monitors catch up.
        for line in fh:
            if _process(line, seen):
                return

        inode = log_path.stat().st_ino
        while True:
            where = fh.tell()
            line = fh.readline()
            if line:
                if _process(line, seen):
                    return
                continue
            # No new data — brief sleep, then check for log rotation.
            time.sleep(poll_interval)
            try:
                current_inode = log_path.stat().st_ino
            except FileNotFoundError:
                current_inode = inode
            if current_inode != inode:
                fh.close()
                fh = log_path.open("r", encoding="utf-8", errors="replace")
                inode = current_inode
            else:
                fh.seek(where)
    finally:
        fh.close()


def _install_signal_handlers() -> None:
    def _graceful_exit(_signum, _frame):
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _graceful_exit)
        except (ValueError, OSError):
            pass  # Non-main thread or restricted env — best effort.


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("output_dir", help="Directory containing .agent-run.log")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process the existing log and exit (no tailing).",
    )
    args = parser.parse_args()

    log_path = Path(args.output_dir) / ".agent-run.log"
    _install_signal_handlers()

    if args.once:
        _run_once(log_path)
    else:
        _tail(log_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
