#!/usr/bin/env python3
"""cutoff_cause.py — cause-aware ``Cause:`` block for Stage-cut-off banners.

A Stage cut-off (Stage 1 returned without producing ``threat-model.md``) has two
very different root causes that the historic banners conflated into a single
"orchestrator died (window closed / OOM / network drop)" message:

  * **API stream stall** — the sub-agent's model API response stream stopped
    emitting tokens and Claude Code's stream watchdog killed the *returning*
    ``Agent`` call. The orchestrator is alive; this is server-side API latency
    or a network interruption. ``stall_notice.py`` records a ``STALL_RECOVERY``
    line in ``.agent-run.log`` whenever this path is taken.

  * **Session death** — the parent Claude Code session itself vanished
    mid-run (window closed, OOM-kill, host network loss) before its ``Stop``
    hook could fire. No ``STALL_RECOVERY`` line is written because no ``Agent``
    call ever returned to the orchestrator.

This helper reads ``.agent-run.log``, decides which case the current run is in
(a ``STALL_RECOVERY`` within the run window ⇒ ``api_stall``), and prints the
matching indented ``Cause:`` block on stdout so compact-runtime cut-off banners
surface the real reason instead of hard-coding a crash.

Usage
-----

  cutoff_cause.py <output_dir> [--default session_death|budget]

  --default  wording to use when NO API stall is detected. The
             ``STAGE1_CUTOFF_NO_STRIDE`` banner passes ``session_death``
             (early death is its normal non-stall cause); the
             ``STAGE11_CUTOFF`` banner passes ``budget`` (turn-budget
             exhaustion is its normal non-stall cause). Default: session_death.

Output contract
---------------

  stdout: one indented multi-line ``Cause:`` block (2-space indent). Always
          non-empty — a missing/unreadable log falls back to the --default block.
  exit  : 0 always (best-effort; never blocks the banner it feeds).
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from event_log import parse_line

# 2-space-indented blocks sized to the ~62-col cut-off banner body.
_CAUSE_BLOCKS = {
    "api_stall": (
        "  Cause:   the model API response stream stalled — the sub-agent\n"
        "           stopped emitting tokens and Claude Code's stream watchdog\n"
        "           terminated the returning call. This is a server-side API\n"
        "           or network interruption (the API was slow or briefly\n"
        "           unreachable), NOT a crash of the orchestrator, your\n"
        "           repository, or your configuration. Re-running later\n"
        "           usually clears transient API congestion."
    ),
    "session_death": (
        "  Cause:   the parent Claude Code session ended mid-pipeline before\n"
        "           its Stop hook could fire — typically the window was\n"
        "           closed, the process was OOM-killed, or the host lost its\n"
        "           network link."
    ),
    "interrupted": (
        "  Cause:   the run stopped before report composition completed.\n"
        "           The retained artifacts cannot\n"
        "           distinguish a manual abort from a terminated session."
    ),
    "controller_abort": (
        "  Cause:   the controller stopped at an authoritative validation\n"
        "           gate. Inspect the terminal RUN_ABORTED reason; the run is\n"
        "           no longer active and must not be resumed."
    ),
    "budget": (
        "  Cause:   the orchestrator exhausted its per-session turn budget\n"
        "           before reaching composition. Inspect retained artifacts;\n"
        "           use --rerender only when its validation gate admits them."
    ),
}


def _run_start_epoch(output_dir: Path) -> int | None:
    """Unix epoch of the current run's start, from ``.scan-start-epoch``.

    Returns ``None`` when the marker is absent/unparseable — the caller then
    stays conservative and does NOT claim an API stall without in-window
    evidence (``.agent-run.log`` is appended across re-runs in the same
    OUTPUT_DIR, so an undated match could be a stale prior-run stall).
    """
    try:
        raw = (output_dir / ".scan-start-epoch").read_text(encoding="utf-8").strip()
        return int(raw.splitlines()[0])
    except Exception:
        return None


def _line_epoch(line: str) -> int | None:
    """Parse the leading ``2026-07-14T15:37:29Z`` ISO token of a log line."""
    tok = line.split(None, 1)[0] if line.strip() else ""
    try:
        dt = datetime.strptime(tok, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return None


def detect_stall(output_dir: Path) -> bool:
    """True iff a ``STALL_RECOVERY`` line was logged within the current run."""
    log = output_dir / ".agent-run.log"
    start = _run_start_epoch(output_dir)
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    for line in text.splitlines():
        if "STALL_RECOVERY" not in line:
            continue
        if start is None:
            # No run window to bound against — cannot safely attribute an
            # (possibly stale) stall to this run; defer to the default cause.
            return False
        ep = _line_epoch(line)
        if ep is not None and ep >= start:
            return True
    return False


def detect_abort(output_dir: Path) -> bool:
    """True iff the current run's LATEST abort/clear event is an abort.

    The latch used to be one-way: any in-window ``RUN_ABORTED`` blocked every
    later boundary forever and no script cleared it, so the only exit from a
    repairable fault was a full re-scan — 75 minutes of completed Stage-1
    analysis discarded because one field of one finding was malformed
    (2026-08-21, ``analysis-title-contract-abort-2026-08-21.md``).

    ``RUN_ABORT_CLEARED`` reopens it and the later of the two wins, so a second
    abort after a clear latches again. Clearing APPENDS an event and never
    removes the ``RUN_ABORTED`` line: a latch you can erase is a latch nobody
    can audit.
    """
    log = output_dir / ".agent-run.log"
    start = _run_start_epoch(output_dir)
    if start is None:
        return False
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return False
    latched = False
    for line in lines:
        parsed = parse_line(line)
        if parsed is None or parsed.event not in ("RUN_ABORTED", "RUN_ABORT_CLEARED"):
            continue
        epoch = _line_epoch(line)
        if epoch is not None and epoch >= start:
            latched = parsed.event == "RUN_ABORTED"
    return latched


def cause_for(output_dir: Path, default: str = "session_death") -> tuple[str, str]:
    """Return ``(kind, block)`` for a cut-off run — the single-source classifier.

    ``kind`` is one of ``api_stall`` / ``session_death`` / ``interrupted`` /
    ``controller_abort`` / ``budget``; ``block`` is the matching indented
    ``Cause:`` text. An in-window controller abort wins over a stall, which wins
    over ``default``. Used by the cut-off banners (via ``main``) and by
    ``appsec_status.py`` for its post-hoc last-run verdict so both surface the
    same wording.
    """
    kind = "controller_abort" if detect_abort(output_dir) else "api_stall" if detect_stall(output_dir) else default
    return kind, _CAUSE_BLOCKS[kind]


def main() -> int:
    ap = argparse.ArgumentParser(description="Emit the cause-aware cut-off banner block.")
    ap.add_argument("output_dir", help="Run output directory (holds .agent-run.log)")
    ap.add_argument(
        "--default",
        dest="default_cause",
        choices=("session_death", "budget"),
        default="session_death",
        help="Cause wording when no API stall is detected in the run window.",
    )
    args = ap.parse_args()

    _, block = cause_for(Path(args.output_dir), args.default_cause)
    sys.stdout.write(block)
    return 0


if __name__ == "__main__":
    sys.exit(main())
