#!/usr/bin/env python3
"""Reproducible per-run measurement (Phase A0 of docs/internal/runbooks/refactoring-plan.md).

Folds the telemetry the plugin already emits into one ``.run-metrics.json``
file so that performance and cost claims become falsifiable. This is *not*
a greenfield parser — it composes outputs from helpers that already exist:

    .stage-stats.jsonl     (per-stage tokens/duration/tool_uses)
    .hook-events.log       (SESSION_STOP cumulative cost + ASSESSMENT_TOKENS)
    verify_run_costs.py    (delta-based token/cost verification, --json)

What it does NOT do:

    - Naively sum ``SESSION_STOP`` lines; those are cumulative. The deltas
      are sourced through ``verify_run_costs.py --json``.
    - Replace ``cost_running_total.py`` — that script prints a running
      ticker during a run; this one summarises after the run is finished.

Usage::

    python3 scripts/measure_run.py <output-dir> [--out .run-metrics.json]

Exits 0 on success (metrics written), 1 on missing inputs.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PLUGIN_ROOT = Path(__file__).resolve().parent.parent


def _read_stage_stats(output_dir: Path) -> list[dict]:
    path = output_dir / ".stage-stats.jsonl"
    if not path.is_file():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _stage_summary(records: list[dict]) -> dict[str, Any]:
    """Aggregate per-stage stats; deduplicate by stage id (last write wins)."""
    by_stage: dict[Any, dict] = {}
    for r in records:
        key = r.get("stage") or r.get("name")
        if key is None:
            continue
        by_stage[key] = r
    stages = sorted(by_stage.values(), key=lambda r: r.get("stage", 0) or 0)
    total_tokens = sum(int(r.get("tokens") or 0) for r in stages)
    total_duration_ms = sum(int(r.get("duration_ms") or 0) for r in stages)
    total_tool_uses = sum(int(r.get("tool_uses") or 0) for r in stages)
    return {
        "stage_count": len(stages),
        "tokens_total": total_tokens,
        "duration_ms_total": total_duration_ms,
        "tool_uses_total": total_tool_uses,
        "stages": [
            {
                "stage": r.get("stage"),
                "name": r.get("name"),
                "agent": r.get("agent"),
                "model": r.get("model"),
                "tokens": r.get("tokens"),
                "duration_ms": r.get("duration_ms"),
                "tool_uses": r.get("tool_uses"),
            }
            for r in stages
        ],
    }


def _run_verify_costs(output_dir: Path) -> dict[str, Any] | None:
    """Shell out to verify_run_costs.py --json so its cumulative-handling
    logic stays the single source of truth for token/cost deltas."""
    script = PLUGIN_ROOT / "scripts" / "verify_run_costs.py"
    if not script.is_file():
        return None
    try:
        proc = subprocess.run(
            [sys.executable, str(script), str(output_dir), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        return {"error": f"verify_run_costs invocation failed: {e}"}
    if not proc.stdout.strip():
        return {"error": proc.stderr.strip() or "verify_run_costs produced no output"}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"error": f"verify_run_costs output not JSON: {e}"}


def _read_hook_events(output_dir: Path) -> dict[str, Any]:
    """Extract structural signals (stop_reasons, retry hints) from .hook-events.log
    without re-implementing the cumulative-cost parser that already lives in
    verify_run_costs.py."""
    path = output_dir / ".hook-events.log"
    if not path.is_file():
        return {"present": False}
    # The real emitter (agent_logger.py) writes "stop_reason=<r>" on SESSION_STOP
    # lines; tolerate a bare "reason=" too. The \b before the optional "stop_"
    # is a word boundary, so "reason=" never matches *inside* "stop_reason=".
    reason_re = re.compile(r"\b(?:stop_)?reason=(\S+)")
    stop_reasons: dict[str, int] = {}
    retries = 0
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "SESSION_STOP" in raw:
            m = reason_re.search(raw)
            if m:
                reason = m.group(1)
                stop_reasons[reason] = stop_reasons.get(reason, 0) + 1
        if "RETRY" in raw or "REPAIR_MODE" in raw:
            retries += 1
    return {
        "present": True,
        "stop_reasons": stop_reasons,
        "retry_hints": retries,
    }


def _read_compose_stats(output_dir: Path) -> dict[str, Any] | None:
    path = output_dir / ".compose-stats.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def measure(output_dir: Path) -> dict[str, Any]:
    if not output_dir.is_dir():
        raise SystemExit(f"measure_run: not a directory: {output_dir}")
    return {
        "output_dir": str(output_dir),
        "stages": _stage_summary(_read_stage_stats(output_dir)),
        "verify_run_costs": _run_verify_costs(output_dir),
        "hook_events": _read_hook_events(output_dir),
        "compose_stats": _read_compose_stats(output_dir),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compose .run-metrics.json from existing run telemetry.")
    p.add_argument("output_dir", help="OUTPUT_DIR containing .stage-stats.jsonl + .hook-events.log")
    p.add_argument(
        "--out",
        default=None,
        help="Output path (default: <output-dir>/.run-metrics.json). Pass - for stdout.",
    )
    args = p.parse_args(argv)
    out_dir = Path(args.output_dir).resolve()
    metrics = measure(out_dir)
    payload = json.dumps(metrics, indent=2, sort_keys=True)
    if args.out == "-":
        print(payload)
        return 0
    target = Path(args.out).resolve() if args.out else out_dir / ".run-metrics.json"
    target.write_text(payload + "\n", encoding="utf-8")
    print(f"Wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
