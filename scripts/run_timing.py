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
  * ``standby``      — per-stage ``wall_secs_observed - duration_ms`` gaps
    that exceed ``STANDBY_GAP_THRESHOLD_S``. A gap that large between a
    stage's first AGENT_SPAWN and last AGENT_COMPLETE is machine sleep or a
    hang, not API latency (which is seconds-to-low-minutes). Isolated so it
    can be excluded from the net figure and from the estimator's cache.
  * ``other_idle``   — everything else (API waits, between-dispatch
    orchestration, preamble). Part of a normal run; kept in ``net_wall``.

  net_wall = wall - standby   (what the run *would* have taken without sleep)

All inputs are files already in ``$OUTPUT_DIR``; no clock reads, no LLM.
"""

from __future__ import annotations

import argparse
import json
import sys
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
    standby = 0
    nonstandby_stage_idle = 0
    stage_wall_sum = 0
    stages: list[dict] = []

    for rec in records:
        ms = rec.get("duration_ms")
        compute_s = int(ms) // 1000 if isinstance(ms, (int, float)) and ms > 0 else 0
        net_compute += compute_s

        wall_obs = rec.get("wall_secs_observed")
        wall_s = int(wall_obs) if isinstance(wall_obs, (int, float)) and wall_obs > 0 else None

        idle_s = None
        is_standby = False
        if wall_s is not None:
            stage_wall_sum += wall_s
            idle_s = max(0, wall_s - compute_s)
            if idle_s > gap_threshold_s:
                is_standby = True
                standby += idle_s
            else:
                nonstandby_stage_idle += idle_s

        stages.append(
            {
                "stage": rec.get("stage"),
                "variant": rec.get("variant") or "",
                "name": rec.get("name") or "",
                "agent": (rec.get("agent") or "—").split(":")[-1],
                "model": rec.get("model") or "?",
                "compute_secs": compute_s,
                "wall_secs": wall_s,
                "idle_secs": idle_s,
                "is_standby": is_standby,
            }
        )

    wall_secs = _read_int_file(output_dir / ".scan-wall-seconds")

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
