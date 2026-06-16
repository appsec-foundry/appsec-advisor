#!/usr/bin/env python3
"""Net-vs-wall run timing with explicit standby/suspend isolation.

A single source of truth, consumed by two callers:

  1. ``render_completion_summary.py`` — to render the per-stage breakdown
     with net agent compute, idle, and (when present) the standby/suspend
     gap broken out, so the user sees the *net* time unambiguously.
  2. the skill's run-end ``last_run_seconds`` writer — to persist a
     standby-corrected wall-clock (``net_wall_secs``) instead of the raw
     end-to-end span, so the next run's duration estimate is accurate even
     when the machine slept mid-run.

The distinction the script makes:

  * ``net_compute``  — sum of per-stage ``duration_ms`` (the Agent tool's
    API-billed time). Pure agent work; immune to machine standby because a
    suspended process bills no API time.
  * ``wall``         — true end-to-end elapsed clock time (``.scan-wall-
    seconds``, written by the skill as ``now - .scan-start-epoch``).
  * ``standby``      — real dead-time gaps between consecutive timestamped
    log events (``.hook-events.log`` / ``.agent-run.log``) that exceed
    ``STANDBY_GAP_THRESHOLD_S``. Every unit of work emits a timestamped
    line — including nested sub-agent activity — so a gap that large means
    nothing ran (machine sleep / suspend / a hung dispatch), not API
    latency. This replaces the lossy ``wall_secs_observed - duration_ms``
    proxy, which also fired on a stage whose compute was merely
    under-recorded across multiple dispatches (Analyst-A + N×STRIDE +
    Analyst-B folded into one Stage-1 row). The proxy remains as a
    fallback only when no event stream is available. Isolated so it can be
    excluded from the net figure and from the estimator's cache.
  * ``other_idle``   — everything else (API waits, between-dispatch
    orchestration, preamble). Part of a normal run; kept in ``net_wall``.

  net_wall = wall - standby   (what the run *would* have taken without sleep)

All inputs are files already in ``$OUTPUT_DIR``; no clock reads, no LLM.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# A per-stage wall-minus-compute gap above this is treated as standby/suspend
# (machine asleep or a hung dispatch), not normal API latency. 10 min is well
# above the worst observed API-tier stall yet below any real sleep gap.
STANDBY_GAP_THRESHOLD_S = 600


def _read_stage_records(output_dir: Path) -> list[dict]:
    path = output_dir / ".stage-stats.jsonl"
    if not path.is_file():
        return []
    records: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(rec, dict):
                records.append(rec)
    except OSError:
        return []
    return records


def _read_int_file(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw:
        return None
    try:
        val = int(raw)
    except ValueError:
        return None
    return val if val > 0 else None


HOOK_LOG_FILENAME = ".hook-events.log"
AGENT_LOG_FILENAME = ".agent-run.log"
# Leading ISO8601 UTC timestamp on every hook/agent log line.
_LEADING_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\b")


def _read_event_epochs(output_dir: Path) -> list[int]:
    """Return sorted epoch-seconds of every timestamped log event.

    Reads ``.hook-events.log`` (preferred — one line per tool call / agent
    event, including nested sub-agent activity) and falls back to merging
    ``.agent-run.log`` when present. Every meaningful unit of work the run
    performed emits at least one timestamped line, so consecutive timestamps
    are a direct, side-effect-free record of when the machine was actually
    busy. A large gap between two adjacent events is genuine dead time
    (machine standby / suspend / a hung dispatch) — unlike the lossy
    ``wall_secs_observed - duration_ms`` proxy, which also fires on a stage
    whose compute was simply under-recorded across multiple dispatches.
    """
    epochs: list[int] = []
    for name in (HOOK_LOG_FILENAME, AGENT_LOG_FILENAME):
        path = output_dir / name
        if not path.is_file():
            continue
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = _LEADING_TS_RE.match(line)
                    if not m:
                        continue
                    try:
                        dt = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue
                    epochs.append(int(dt.timestamp()))
        except OSError:
            continue
    epochs.sort()
    return epochs


def _standby_from_event_gaps(
    output_dir: Path,
    gap_threshold_s: int,
    window: tuple[int, int] | None = None,
) -> int | None:
    """Sum real dead-time gaps between consecutive log events.

    Returns the total seconds spent in gaps larger than ``gap_threshold_s``,
    or ``None`` when no usable event stream exists (so the caller can fall
    back to the per-stage ``wall - compute`` heuristic). A run that streamed
    events steadily — even while long sub-agents were working — yields 0,
    which is the correct answer for "how long was the machine actually idle".

    ``window`` is an optional ``(start_epoch, end_epoch)`` bound. Events
    outside it are dropped before gap computation so post-run activity (e.g.
    the operator inspecting artifacts after the completion summary) cannot be
    miscounted as in-run standby. The run window is ``[scan-start-epoch,
    scan-start-epoch + .scan-wall-seconds]``.
    """
    epochs = _read_event_epochs(output_dir)
    if window is not None:
        lo, hi = window
        epochs = [e for e in epochs if lo <= e <= hi]
    if len(epochs) < 2:
        return None
    standby = 0
    for prev, cur in zip(epochs, epochs[1:]):
        gap = cur - prev
        if gap > gap_threshold_s:
            standby += gap
    return standby


def compute_timing(output_dir: Path, gap_threshold_s: int = STANDBY_GAP_THRESHOLD_S) -> dict:
    """Return the net-vs-wall breakdown for a completed run.

    Keys:
        net_compute_secs   sum of per-stage duration_ms (agent compute)
        wall_secs          end-to-end elapsed (.scan-wall-seconds) or None
        standby_secs       sum of per-stage idle gaps > gap_threshold_s
        other_idle_secs    remaining idle (API + orchestration)
        net_wall_secs      wall_secs - standby_secs (or net_compute + other
                           idle when wall_secs is unavailable)
        has_standby        bool — any stage exceeded the gap threshold
        stages             list of per-stage dicts (compute/wall/idle/standby)
    """
    records = _read_stage_records(output_dir)

    net_compute = 0
    nonstandby_stage_idle = 0
    heuristic_standby = 0  # legacy wall−compute proxy, used only as fallback
    stage_idles: list[tuple[int, dict]] = []  # (idle_secs, stage_dict) for attribution
    stages: list[dict] = []

    for rec in records:
        ms = rec.get("duration_ms")
        compute_s = int(ms) // 1000 if isinstance(ms, (int, float)) and ms > 0 else 0
        net_compute += compute_s

        wall_obs = rec.get("wall_secs_observed")
        wall_s = int(wall_obs) if isinstance(wall_obs, (int, float)) and wall_obs > 0 else None

        idle_s = None
        if wall_s is not None:
            idle_s = max(0, wall_s - compute_s)
            if idle_s > gap_threshold_s:
                heuristic_standby += idle_s
            else:
                nonstandby_stage_idle += idle_s

        stage_dict = {
            "stage": rec.get("stage"),
            "variant": rec.get("variant") or "",
            "name": rec.get("name") or "",
            "agent": (rec.get("agent") or "—").split(":")[-1],
            "model": rec.get("model") or "?",
            "compute_secs": compute_s,
            "wall_secs": wall_s,
            "idle_secs": idle_s,
            "is_standby": False,
        }
        stages.append(stage_dict)
        if idle_s is not None:
            stage_idles.append((idle_s, stage_dict))

    # Authoritative standby signal: real dead-time gaps between consecutive
    # timestamped log events. A multi-dispatch stage that under-records
    # duration_ms (Analyst-A + N×STRIDE + Analyst-B all folded into one
    # stage row) produces a large wall−compute idle that is NOT standby —
    # the machine was busy, the compute was simply unrecorded. The event
    # stream distinguishes the two: it only shows a gap when nothing ran.
    # Bound the gap scan to the actual run window so post-run inspection
    # (operator reading artifacts after the completion summary) is not
    # miscounted as in-run standby.
    wall_secs = _read_int_file(output_dir / ".scan-wall-seconds")
    scan_start = _read_int_file(output_dir / ".scan-start-epoch")
    run_window: tuple[int, int] | None = None
    if scan_start is not None and wall_secs is not None:
        # +gap_threshold slack so a final event landing just past the frozen
        # wall marker (summary render writes .scan-wall-seconds slightly early)
        # is still counted, without admitting genuinely post-run activity.
        run_window = (scan_start, scan_start + wall_secs + gap_threshold_s)
    log_standby = _standby_from_event_gaps(output_dir, gap_threshold_s, run_window)
    if log_standby is not None:
        standby = log_standby
        # Per-stage flag: only attribute standby to a stage when a real gap
        # exists overall AND that stage's idle is itself over the threshold.
        # When log_standby == 0 no stage is flagged, so an under-recorded
        # compute can never masquerade as standby in the per-row breakdown.
        if standby > 0:
            for idle_s, sd in stage_idles:
                if idle_s > gap_threshold_s:
                    sd["is_standby"] = True
    else:
        # No event stream (e.g. logs cleaned) — fall back to the legacy
        # wall−compute proxy so behaviour is unchanged on old artifacts.
        standby = heuristic_standby
        if standby > 0:
            for idle_s, sd in stage_idles:
                if idle_s > gap_threshold_s:
                    sd["is_standby"] = True

    if wall_secs is not None:
        net_wall = max(net_compute, wall_secs - standby)
        # Idle the user actually sat through on a normal run = everything that
        # is not compute and not standby (API waits + between-stage orchestration).
        other_idle = max(0, wall_secs - net_compute - standby)
    else:
        # No end-to-end marker — approximate from per-stage walls only.
        net_wall = net_compute + nonstandby_stage_idle
        other_idle = nonstandby_stage_idle

    return {
        "net_compute_secs": net_compute,
        "wall_secs": wall_secs,
        "standby_secs": standby,
        "other_idle_secs": other_idle,
        "net_wall_secs": net_wall,
        "has_standby": standby > 0,
        "stages": stages,
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="run_timing.py", add_help=True)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument(
        "--net-wall-seconds",
        action="store_true",
        help="print only the standby-corrected wall-clock integer (for the "
        "skill's last_run_seconds writer); empty string when undeterminable",
    )
    p.add_argument(
        "--gap-threshold-seconds",
        type=int,
        default=STANDBY_GAP_THRESHOLD_S,
        help="per-stage idle gap above which time is classed as standby/suspend",
    )
    args = p.parse_args(argv[1:])

    timing = compute_timing(args.output_dir, args.gap_threshold_seconds)

    if args.net_wall_seconds:
        nw = timing["net_wall_secs"]
        print(nw if nw and nw > 0 else "")
        return 0

    print(json.dumps(timing, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
