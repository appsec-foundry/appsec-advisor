#!/usr/bin/env python3
"""persist_run_baseline.py — run-end writer for `.appsec-cache/baseline.json`.

Persists the just-finished run's duration + mode + depth so the next
invocation's `estimate_duration.py` can use it as its highest-priority data
source (`source=last_run_cache` instead of `source=parametric`).

WHY THIS IS A SCRIPT AND NOT A SKILL-LEVEL BASH BLOCK
-----------------------------------------------------
It replaces inline Bash that the orchestrator previously had to reproduce
verbatim, including four exact JSON key names. That is a
contract carried in prose, and it broke twice:

  * 2026-06 — a later baseline write wiped the fields (fixed defensively in
    `baseline_state.py` by carrying them forward).
  * 2026-07-27 — the orchestrator resumed after a context compaction, read the
    descriptive paragraph ("write the total wall-clock + mode + depth") but not
    the bash block three lines below it, and invented `last_wall_seconds` /
    `last_mode` / `last_depth`. `estimate_duration.py` reads only
    `last_run_seconds`, so the cache looked populated while the estimator
    silently fell back to the parametric formula (66 min instead of the
    measured 101 min). Nothing detected it: a misspelled key is indistinguishable
    from a missing one.

Keeping the key names in code — with tests — removes the failure mode instead of
documenting it. The skill layer now calls this and passes only run facts.

START-TIME PRECEDENCE (unchanged from the original block)
--------------------------------------------------------
1. First ``ASSESSMENT_START`` timestamp in ``.agent-run.log`` — the actual
   orchestrator start, which EXCLUDES time spent waiting on the permission
   prompt. Including that wait would inflate the next run's estimate.
2. The durable ``.scan-start-epoch`` file — survives across the skill's separate
   Bash invocations, unlike an in-memory shell variable.
3. ``--fallback-epoch`` (the caller's ``ASSESSMENT_START_EPOCH``), usually empty
   by the time finalization runs.

When ``run_timing.py --net-wall-seconds`` reports a SMALLER value (idle/standby
excluded), that value wins: a run that sat idle must not teach the estimator
that it takes that long.

Best-effort by contract: with no usable start signal the write is skipped and
the estimator falls back to the parametric formula. The skip is reported on
stderr rather than passing silently.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# The canonical field names. `estimate_duration._last_run_cache` reads exactly
# these; `baseline_state.py` carries exactly these forward. Changing a name here
# means changing it in all three places — that is the point of having one owner.
KEY_SECONDS = "last_run_seconds"
KEY_MODE = "last_run_mode"
KEY_DEPTH = "last_run_depth"
KEY_ISO = "last_run_iso"

_ASSESSMENT_START_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s.*ASSESSMENT_START\b")


def _epoch_from_log(log_path: Path) -> int | None:
    """First ASSESSMENT_START timestamp, or None."""
    try:
        with log_path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _ASSESSMENT_START_RE.match(line)
                if m:
                    dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=datetime.timezone.utc
                    )
                    return int(dt.timestamp())
    except OSError:
        pass
    return None


def _epoch_from_marker(marker_path: Path) -> int | None:
    try:
        raw = marker_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def resolve_start_epoch(output_dir: Path, fallback_epoch: int | None) -> tuple[int | None, str]:
    """Return (epoch, source_label) following the documented precedence."""
    epoch = _epoch_from_log(output_dir / ".agent-run.log")
    if epoch:
        return epoch, "agent-run.log:ASSESSMENT_START"
    epoch = _epoch_from_marker(output_dir / ".scan-start-epoch")
    if epoch:
        return epoch, ".scan-start-epoch"
    if fallback_epoch and fallback_epoch > 0:
        return fallback_epoch, "--fallback-epoch"
    return None, "none"


def _net_wall_seconds(output_dir: Path, plugin_root: Path | None) -> int | None:
    """`run_timing.py --net-wall-seconds`, or None when unavailable."""
    root = plugin_root or Path(__file__).resolve().parent.parent
    script = root / "scripts" / "run_timing.py"
    if not script.is_file():
        script = Path(__file__).resolve().parent / "run_timing.py"
    try:
        out = subprocess.run(
            [sys.executable, str(script), "--output-dir", str(output_dir), "--net-wall-seconds"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    raw = (out.stdout or "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else None


def persist(
    output_dir: Path,
    mode: str,
    depth: str,
    *,
    fallback_epoch: int | None = None,
    now_epoch: int | None = None,
    plugin_root: Path | None = None,
) -> dict | None:
    """Write the run-end fields into `.appsec-cache/baseline.json`.

    Returns the written fields, or None when no usable start signal exists
    (the documented best-effort skip).
    """
    start_epoch, source = resolve_start_epoch(output_dir, fallback_epoch)
    if start_epoch is None:
        return None

    end_epoch = now_epoch if now_epoch is not None else int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    seconds = end_epoch - start_epoch
    if seconds <= 0:
        return None

    # Idle/standby-excluding measurement wins when it is smaller.
    net_wall = _net_wall_seconds(output_dir, plugin_root)
    if net_wall is not None and net_wall < seconds:
        seconds = net_wall

    iso = datetime.datetime.fromtimestamp(end_epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fields = {KEY_SECONDS: seconds, KEY_MODE: mode, KEY_DEPTH: depth, KEY_ISO: iso}

    cache_dir = output_dir / ".appsec-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "baseline.json"

    data: dict = {}
    if cache_file.is_file():
        try:
            loaded = json.loads(cache_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}  # a corrupt cache must not block the write
    data.update(fields)

    tmp = cache_file.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, cache_file)

    fields["_start_source"] = source
    return fields


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Persist run-end timing into .appsec-cache/baseline.json")
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--depth", default="standard")
    ap.add_argument("--fallback-epoch", type=int, default=0, help="ASSESSMENT_START_EPOCH, if the caller still has it")
    ap.add_argument("--plugin-root", type=Path, default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    written = persist(
        args.output_dir,
        args.mode,
        args.depth,
        fallback_epoch=args.fallback_epoch,
        plugin_root=args.plugin_root,
    )
    if written is None:
        # Visible, not silent: the next run will estimate parametrically.
        sys.stderr.write(
            "persist_run_baseline: no usable start signal "
            "(.agent-run.log ASSESSMENT_START / .scan-start-epoch / --fallback-epoch) — "
            "baseline not written; next run estimates parametrically\n"
        )
        return 0  # best-effort by contract: never fail the run
    if not args.quiet:
        print(
            f"run-baseline: {written[KEY_SECONDS]}s ({written[KEY_MODE]}/{written[KEY_DEPTH]}) "
            f"via {written['_start_source']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
