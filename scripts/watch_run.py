#!/usr/bin/env python3
"""
watch_run.py — phase-aware live watchdog for an in-progress threat-model run.

Tails ``$OUTPUT_DIR/.hook-events.log`` and emits one event per relevant log
line (PHASE_*, STEP_*, AGENT_INVOKE, FILE_WRITE/EDIT, HEARTBEAT, ERROR/FAIL,
SCAN_START/COMPLETE, ASSESSMENT_*). Periodically inspects the most recent
``.appsec-checkpoint`` to derive the active phase and applies a per-phase
silence threshold from ``PHASE_DURATION_LIMITS_SECONDS`` — emitting a single
``STALL`` line when the gap between the latest event and now exceeds the
phase-specific threshold (multiplied by ``stall_multiplier``, default 1.5×).

Why this is needed
------------------
The 2026-04-26 19:55 run surfaced two problems with naive log tailing:

  • Flat 180-second STALL threshold fires false positives during legitimately
    silent phases (Phase 10b Triage runs 8 min as a single LLM call; Phase 11
    fragment authoring runs 5 min between FILE_WRITEs).
  • There is no built-in helper — the user has to construct a Bash
    ``tail -f | grep`` pipeline by hand. Phase context is lost.

This helper centralises the watchdog logic so any caller (the user's
secondary terminal, ``/appsec-advisor:status``, IDE plugin) can subscribe
to ``stdin``-style line events without re-implementing the threshold
matrix.

Usage
-----

  python3 watch_run.py <output_dir>
  python3 watch_run.py <output_dir> --depth thorough
  python3 watch_run.py <output_dir> --print-budgets    # JSON, do not tail
  python3 watch_run.py <output_dir> --stall-multiplier 2.0
  python3 watch_run.py <output_dir> --once             # snapshot, no follow

Output
------
Each emitted line has shape:

    HH:MM:SS  EVENT_NAME            phase=<P>  detail=…

Plus periodic synthetic events:

    HH:MM:SS  STALL                 phase=<P>  gap=<S>s  threshold=<T>s  last=<truncated>
    HH:MM:SS  STATUS                phase=<P>  age=<S>s  events=<N>

Always tail-friendly (line-buffered). Exit codes: 0 normal exit (only
reachable with ``--once``), 1 missing output dir, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --- Phase budgets — single source of truth in data/phase-budgets.yaml ------
# Loaded via the shared phase_budgets module so watch_run, acquire_lock,
# check_state, aggregate_run_issues and skill_watchdog all see the same
# numbers. Falls back to the historical hard-coded table when the YAML or
# loader is unavailable so this script stays standalone.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import phase_budgets  # type: ignore  # noqa: E402
except Exception:  # pragma: no cover
    phase_budgets = None  # type: ignore[assignment]

PHASE_DURATION_LIMITS_SECONDS: dict[str, dict[str, int]] = (
    {d: phase_budgets.budgets_for_depth(d) for d in ("quick", "standard", "thorough")}
    if phase_budgets
    else {
        "quick": {"1": 180, "2": 120, "3": 60, "9": 180, "10b": 60, "11": 300},
        "standard": {"1": 240, "2": 180, "3": 120, "9": 360, "10b": 120, "11": 600},
        "thorough": {"1": 360, "2": 240, "3": 180, "9": 720, "10b": 180, "11": 900},
    }
)

DEFAULT_PHASE_FALLBACK_SECONDS = phase_budgets.unlisted_phase_fallback_seconds() if phase_budgets else 180
ABSOLUTE_HARD_CEILING_SECONDS = phase_budgets.hard_ceiling_seconds() if phase_budgets else 1800

# Events worth emitting verbatim. Anything not in this set is ignored to
# keep the stdout signal-to-noise ratio high. Any event matching `_ERR_RE`
# is also forwarded regardless of name (errors must always reach the user).
_RELAY_EVENTS = {
    "PHASE_START",
    "PHASE_END",
    "STEP_START",
    "STEP_END",
    "AGENT_INVOKE",
    "AGENT_DISPATCH",
    "AGENT_COMPLETE",
    "AGENT_SPAWN",
    "SCAN_START",
    "SCAN_COMPLETE",
    "ASSESSMENT_START",
    "ASSESSMENT_END",
    "ASSESSMENT_SUMMARY",
    "ASSESSMENT_TOKENS",
    "ASSESSMENT_PHASES",
    "ASSESSMENT_FILES",
    "FILE_WRITE",
    "FILE_EDIT",
    "TOOL_ERROR",
    "MAX_TURNS",
    "SESSION_STOP",
    "CONTEXT_READY",
    "HEARTBEAT",
    "BASH_WARN",  # surfaced because it correlates with sub-optimal Bash usage
}


def _now_local_short() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _read_phase_from_checkpoint(output_dir: Path) -> tuple[str, str]:
    """Return (phase, status) from .appsec-checkpoint or ('?', '?') on miss."""
    cp = output_dir / ".appsec-checkpoint"
    if not cp.is_file():
        return ("?", "?")
    try:
        line = cp.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    except (OSError, IndexError):
        return ("?", "?")
    phase = "?"
    status = "?"
    for tok in line.split():
        if tok.startswith("phase="):
            phase = tok.split("=", 1)[1] or "?"
        elif tok.startswith("status="):
            status = tok.split("=", 1)[1] or "?"
    return (phase, status)


def _threshold_for_phase(phase: str, depth: str, multiplier: float) -> int:
    limits = PHASE_DURATION_LIMITS_SECONDS.get(depth, PHASE_DURATION_LIMITS_SECONDS["standard"])
    expected = limits.get(phase, DEFAULT_PHASE_FALLBACK_SECONDS)
    return min(int(expected * multiplier), ABSOLUTE_HARD_CEILING_SECONDS)


def _parse_event_name(line: str) -> str | None:
    """Best-effort extraction of the event token from a hook-log line."""
    # Format: "<ts>  [<sid>]  <level>  <event>  <detail>"
    parts = line.split(None, 4)
    if len(parts) < 4:
        return None
    # parts[0]=ts, parts[1]=[sid], parts[2]=level, parts[3]=event
    return parts[3]


def _parse_ts(line: str) -> int | None:
    """Return UTC epoch seconds for the leading ts token."""
    try:
        return int(
            datetime.strptime(line.split(None, 1)[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        )
    except (ValueError, IndexError):
        return None


def _emit(text: str) -> None:
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def _read_progress_state(output_dir: Path) -> tuple[int, str] | None:
    path = output_dir / ".appsec-progress.json"
    if not path.is_file():
        return None
    try:
        mtime = int(path.stat().st_mtime)
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    bits: list[str] = []
    phase = data.get("phase")
    if phase:
        total = f"/{data.get('phase_total')}" if data.get("phase_total") else ""
        bits.append(f"phase={phase}{total}")
    if data.get("step") and data.get("step_total"):
        bits.append(f"step={data['step']}/{data['step_total']}")
    if data.get("agent"):
        bits.append(f"agent={data['agent']}")
    if data.get("label"):
        bits.append(f"label={data['label']}")
    elif data.get("detail"):
        bits.append(f"label={data['detail']}")
    return mtime, "  ".join(bits)


def _print_budgets(depth: str | None) -> int:
    if depth and depth not in PHASE_DURATION_LIMITS_SECONDS:
        sys.stderr.write(f"unknown depth: {depth!r}\n")
        return 2
    payload = {depth: PHASE_DURATION_LIMITS_SECONDS[depth]} if depth else PHASE_DURATION_LIMITS_SECONDS
    payload["_meta"] = {  # type: ignore[assignment]
        "default_fallback_seconds": DEFAULT_PHASE_FALLBACK_SECONDS,
        "absolute_hard_ceiling_seconds": ABSOLUTE_HARD_CEILING_SECONDS,
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


def watch(
    output_dir: Path,
    depth: str,
    stall_multiplier: float,
    once: bool,
    poll_seconds: float,
) -> int:
    log_path = output_dir / ".hook-events.log"
    if not output_dir.is_dir():
        sys.stderr.write(f"output_dir not found: {output_dir}\n")
        return 1

    _emit(f"{_now_local_short()}  WATCH_START           depth={depth}  multiplier={stall_multiplier}  log={log_path}")

    # Position at end of file (we only stream new events).
    pos = log_path.stat().st_size if log_path.is_file() else 0
    last_event_ts: int | None = None
    last_relay_text: str = ""
    last_phase: str = "?"
    last_progress_mtime: int = 0
    last_stall_announced_at: int = 0
    event_count = 0
    stall_count = 0

    deadline = None
    if once:
        deadline = time.time() + poll_seconds  # snapshot pass

    while True:
        # ── Read new lines ───────────────────────────────────────────────
        if log_path.is_file():
            try:
                size = log_path.stat().st_size
                if size < pos:  # log rotated/truncated
                    pos = 0
                if size > pos:
                    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(pos)
                        for raw in fh:
                            pos = fh.tell()
                            line = raw.rstrip("\n")
                            if not line.strip():
                                continue
                            ev = _parse_event_name(line)
                            ts = _parse_ts(line)
                            if ts is not None:
                                last_event_ts = ts
                            if ev and (ev in _RELAY_EVENTS or "ERROR" in ev or "FAIL" in ev):
                                event_count += 1
                                last_relay_text = (line[:200] + "…") if len(line) > 200 else line
                                _emit(line)
            except OSError:
                pass

        # ── Phase + stall detection ──────────────────────────────────────
        phase, _status = _read_phase_from_checkpoint(output_dir)
        if phase != last_phase:
            _emit(f"{_now_local_short()}  PHASE_TRACK           phase={last_phase}→{phase}")
            last_phase = phase

        progress_state = _read_progress_state(output_dir)
        if progress_state is not None:
            progress_mtime, progress_detail = progress_state
            if progress_mtime > last_progress_mtime:
                _emit(f"{_now_local_short()}  PROGRESS              {progress_detail}")
                last_progress_mtime = progress_mtime

        if last_event_ts is not None:
            now = int(time.time())
            gap = now - last_event_ts
            threshold = _threshold_for_phase(phase, depth, stall_multiplier)
            # Throttle stall emission: re-emit at most once per threshold/2 seconds.
            if gap > threshold and (now - last_stall_announced_at) > max(threshold // 2, 30):
                stall_count += 1
                _emit(
                    f"{_now_local_short()}  STALL                 "
                    f"phase={phase}  gap={gap}s  threshold={threshold}s  "
                    f"last={last_relay_text[:120]}"
                )
                last_stall_announced_at = now

        # ── Loop control ─────────────────────────────────────────────────
        if once:
            if deadline is not None and time.time() >= deadline:
                _emit(f"{_now_local_short()}  WATCH_END             events={event_count}  stalls={stall_count}")
                return 0
        time.sleep(poll_seconds)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=os.environ.get("OUTPUT_DIR"),
        help="Path to $OUTPUT_DIR (positional, or set $OUTPUT_DIR env)",
    )
    parser.add_argument(
        "--depth",
        choices=("quick", "standard", "thorough"),
        default="standard",
    )
    parser.add_argument(
        "--stall-multiplier",
        type=float,
        default=1.5,
        help="Multiply phase budget by this factor before flagging STALL (default 1.5).",
    )
    parser.add_argument(
        "--print-budgets",
        action="store_true",
        help="Print the per-depth phase-budget table as JSON and exit "
        "(no tailing). Useful for external watchdogs that want to "
        "share the threshold matrix.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single ~5 s snapshot pass instead of streaming.",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=2.0,
        help="Poll interval (default 2.0 s).",
    )
    args = parser.parse_args(argv[1:])

    if args.print_budgets:
        return _print_budgets(args.depth if args.depth != "standard" or "--depth" in argv else None)

    if not args.output_dir:
        parser.error("output_dir is required (positional or $OUTPUT_DIR env)")

    return watch(
        output_dir=Path(args.output_dir).resolve(),
        depth=args.depth,
        stall_multiplier=args.stall_multiplier,
        once=args.once,
        poll_seconds=args.poll_seconds,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
