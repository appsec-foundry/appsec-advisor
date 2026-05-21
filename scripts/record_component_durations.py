"""M5 — record per-component STRIDE durations into .appsec-cache/baseline.json.

Called by the skill at the end of a successful Stage-1 (Phase 9 complete).
Reads `.stride-*.json` mtimes vs Phase-9 start-time to derive each
component's wall-clock duration, then merges into
`baseline.json.component_durations` so the next run's `estimate_duration.py`
can estimate Phase 9 accurately per-component.

Usage:
    python3 record_component_durations.py <OUTPUT_DIR> [--phase-9-start <epoch>]

If `--phase-9-start` is omitted, the script reads the value from the latest
`PHASE_START   [Phase 9/11]` entry in `.agent-run.log`.

Idempotent — re-running for the same Phase-9-start replaces the existing
component_durations entry deterministically.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def _read_phase_9_start(log_path: Path) -> int | None:
    """Return Unix-epoch seconds of the most recent Phase 9 PHASE_START line."""
    if not log_path.is_file():
        return None
    pattern = re.compile(r"^(\S+)\s+.*PHASE_START\s+\[Phase 9/", re.IGNORECASE)
    last_ts = None
    try:
        with log_path.open() as fh:
            for line in fh:
                m = pattern.match(line)
                if m:
                    last_ts = m.group(1)
    except OSError:
        return None
    if not last_ts:
        return None
    try:
        # ISO 8601: 2026-04-27T13:34:05Z
        dt = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


_AGENT_INVOKE_RE = re.compile(
    r"^(\S+)\s+.*?stride-analyzer\s+AGENT_INVOKE\s+STRIDE analysis:\s+"
    r"(?P<comp>[a-z0-9\-]+)"
)
_AGENT_DONE_RE = re.compile(
    r"^(\S+)\s+.*?stride-analyzer\s+AGENT_DONE\s+STRIDE analysis:\s+"
    r"(?P<comp>[a-z0-9\-]+)"
)


def _per_component_marker_pairs(log_path: Path) -> dict[str, int]:
    """Per-component duration from AGENT_INVOKE / AGENT_DONE pairs.

    Fix #8 — previously the script used ``mtime(.stride-<comp>.json) -
    phase_9_start`` for every component. Because STRIDE analyzers run in
    parallel and write their result file at the end of their own session,
    every `.stride-*.json` lands within seconds of every other one, yielding
    identical per-component numbers (the 2026-05 juice-shop run recorded
    three identical 71 s entries). Per-component LLM time is therefore
    invisible from the file system alone.

    The orchestrator does log per-component dispatch markers though:
        ``stride-analyzer AGENT_INVOKE   STRIDE analysis: <comp> (model: …)``
        ``stride-analyzer AGENT_DONE     STRIDE analysis: <comp> complete``
    Parsing those marker pairs gives the true wall-clock span the orchestrator
    saw for each component (still bounded by the parallel-fan-out — when
    every dispatch happens in the same turn, the marker timestamps collapse,
    and that collapsed value is the most honest measurement available).

    Returns an empty dict when the log is unavailable or no markers were
    captured; the caller then falls back to the mtime-based heuristic.
    """
    if not log_path.is_file():
        return {}
    starts: dict[str, int] = {}
    ends: dict[str, int] = {}
    try:
        with log_path.open() as fh:
            for line in fh:
                m = _AGENT_INVOKE_RE.match(line)
                if m:
                    ep = _parse_ts(m.group(1))
                    comp = m.group("comp")
                    if ep and comp not in starts:
                        starts[comp] = ep
                    continue
                m = _AGENT_DONE_RE.match(line)
                if m:
                    ep = _parse_ts(m.group(1))
                    comp = m.group("comp")
                    if ep:
                        ends[comp] = ep
    except OSError:
        return {}
    durations: dict[str, int] = {}
    for comp, start_ep in starts.items():
        end_ep = ends.get(comp)
        if not end_ep:
            continue
        delta = end_ep - start_ep
        if delta < 0 or delta > 7200:
            continue
        durations[comp] = delta
    return durations


def _parse_ts(ts: str) -> int | None:
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


def _self_reported_durations(output_dir: Path) -> dict[str, int]:
    """Read `started_at` / `analyzed_at` from each .stride-<comp>.json.

    Fix #8 root cause — when the sub-agent writes both timestamps from its
    own clock, the duration is per-component-accurate even under parallel
    dispatch (the orchestrator's AGENT_INVOKE/AGENT_DONE markers collapse to
    near-identical timestamps under parallelism; the agent's own clock does
    not). This is the canonical source when present.
    """
    durations: dict[str, int] = {}
    for path in sorted(output_dir.glob(".stride-*.json")):
        comp_id = path.stem.lstrip(".").removeprefix("stride-")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            # Older / malformed stride files may be lists or scalars — skip
            # silently and let the fallback paths handle them.
            continue
        started = data.get("started_at")
        analyzed = data.get("analyzed_at")
        if not started or not analyzed:
            continue
        try:
            s = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            a = datetime.strptime(analyzed, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        delta = int(a.timestamp() - s.timestamp())
        if delta < 0 or delta > 7200:
            continue
        durations[comp_id] = delta
    return durations


def _stride_durations(output_dir: Path, phase_9_start: int) -> dict[str, int]:
    """Map component_id → wall-clock seconds, in priority order:

    1. Self-reported `started_at` / `analyzed_at` from `.stride-<comp>.json`
       (Fix #8 root cause — captured by the agent's own clock).
    2. AGENT_INVOKE / AGENT_DONE markers in `.agent-run.log` (Fix #8
       symptom-patch — accurate when sub-agents dispatched sequentially;
       collapses to identical values under parallelism).
    3. mtime delta against ``phase_9_start`` (legacy fallback — accurate
       only when STRIDE analyzers were dispatched sequentially).
    """
    durations = _self_reported_durations(output_dir)
    if durations:
        return durations
    durations = _per_component_marker_pairs(output_dir / ".agent-run.log")
    if durations:
        return durations
    # Legacy fallback — mtime-based heuristic.
    for path in sorted(output_dir.glob(".stride-*.json")):
        comp_id = path.stem.lstrip(".").removeprefix("stride-")
        try:
            mtime = int(path.stat().st_mtime)
        except OSError:
            continue
        delta = mtime - phase_9_start
        if delta < 0 or delta > 7200:
            # Sanity bounds: 0-2 h. Clip negative (clock skew) and
            # absurd outliers (file from earlier failed run).
            continue
        durations[comp_id] = delta
    return durations


def _merge_into_baseline(
    cache_path: Path,
    durations: dict[str, int],
    phase_9_start: int,
) -> bool:
    """Merge component_durations into existing baseline.json (or seed new).

    Returns True on successful write, False on failure.
    """
    existing: dict[str, object] = {}
    if cache_path.is_file():
        try:
            existing = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}

    existing["component_durations"] = durations
    existing["component_durations_recorded_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    existing["component_durations_phase_9_start"] = phase_9_start

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(existing, indent=2, sort_keys=True))
        tmp.replace(cache_path)
        return True
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--phase-9-start", type=int, default=None, help="Unix-epoch seconds. If omitted, derive from .agent-run.log."
    )
    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir
    if not output_dir.is_dir():
        print(f"Error: not a directory: {output_dir}", file=sys.stderr)
        return 2

    phase_9_start = args.phase_9_start
    if phase_9_start is None:
        phase_9_start = _read_phase_9_start(output_dir / ".agent-run.log")
    if phase_9_start is None:
        # Soft-fail: no Phase 9 found — nothing to record. Not an error.
        print("(no Phase 9 PHASE_START found in .agent-run.log — skipping)", file=sys.stderr)
        return 0

    durations = _stride_durations(output_dir, phase_9_start)
    if not durations:
        print("(no .stride-*.json files found — skipping)", file=sys.stderr)
        return 0

    cache_path = output_dir / ".appsec-cache" / "baseline.json"
    if _merge_into_baseline(cache_path, durations, phase_9_start):
        for comp, sec in sorted(durations.items()):
            print(f"  {comp:<25} {sec:>4} s", file=sys.stderr)
        return 0
    print("Error: failed to write baseline.json", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
