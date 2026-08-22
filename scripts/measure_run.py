#!/usr/bin/env python3
"""Reproducible per-run measurement (Phase A0 of docs/internal/runbooks/refactoring-plan.md).

Folds the telemetry the plugin already emits into one ``.run-metrics.json``
file so that performance and cost claims become falsifiable. This is *not*
a greenfield parser — it composes outputs from helpers that already exist:

    .stage-stats.jsonl     (per-role tokens/duration/tool_uses)
    .hook-events.log       (SESSION_STOP cumulative cost + ASSESSMENT_TOKENS)
    .headless-result.json  (exact total turns and per-model token/cost classes)
    verify_run_costs.py    (delta-based token/cost verification, --json)

What it does NOT do:

    - Naively sum ``SESSION_STOP`` lines; those are cumulative. The deltas
      are sourced through ``verify_run_costs.py --json``.
    - Replace ``cost_running_total.py`` — that script prints a running
      ticker during a run; this one summarises after the run is finished.
    - Invent per-role turns or cost. Agent usage blocks do not expose either
      turns or the priced token classes needed for additive cost attribution.

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
from collections import Counter
from pathlib import Path
from typing import Any

import headless_usage

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _path_guard import run_path_arg  # noqa: E402

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
    """Aggregate per-stage stats; deduplicate by stage and variant."""
    by_stage: dict[Any, dict] = {}
    for r in records:
        stage = r.get("stage")
        if stage is None and not r.get("name"):
            continue
        key = (stage, r.get("variant") or "") if stage is not None else (r.get("name"), "")
        by_stage[key] = r
    stages = sorted(by_stage.values(), key=lambda r: (r.get("stage", 0) or 0, r.get("variant") or ""))
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
                "variant": r.get("variant") or "",
                "name": r.get("name"),
                "agent": r.get("agent"),
                "model": r.get("model"),
                "tokens": r.get("tokens"),
                "duration_ms": r.get("duration_ms"),
                "tool_uses": r.get("tool_uses"),
                "dispatch_count": r.get("dispatch_count"),
            }
            for r in stages
        ],
    }


_AGENT_SPAWN_RE = re.compile(r"\bAGENT_SPAWN\s+(?P<agent>\S+)")


def _short_agent(value: Any) -> str:
    agent = str(value or "")
    if ":" in agent:
        agent = agent.rsplit(":", 1)[-1]
    return agent.removeprefix("appsec-")


def _role_telemetry_coverage(output_dir: Path, stages: list[dict]) -> dict[str, Any]:
    dispatched: Counter[str] = Counter()
    hook_path = output_dir / ".hook-events.log"
    if hook_path.is_file():
        try:
            for line in hook_path.read_text(encoding="utf-8", errors="replace").splitlines():
                match = _AGENT_SPAWN_RE.search(line)
                if match:
                    dispatched[_short_agent(match.group("agent"))] += 1
        except OSError:
            pass
    recorded: Counter[str] = Counter()
    for row in stages:
        agent = _short_agent(row.get("agent"))
        if agent:
            recorded[agent] += 1
    roles = [
        {
            "role": role,
            "dispatched": dispatched[role],
            "stats_records": recorded[role],
            "covered": dispatched[role] == 0 or recorded[role] > 0,
        }
        for role in sorted(set(dispatched) | set(recorded))
    ]
    return {
        "complete": bool(dispatched) and all(row["covered"] for row in roles),
        "roles": roles,
    }


def _read_headless_usage(output_dir: Path) -> dict[str, Any] | None:
    result = headless_usage.load_result(output_dir / ".headless-result.json")
    return headless_usage.extract_usage(result) if result is not None else None


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
    stage_records = _read_stage_stats(output_dir)
    exact_usage = _read_headless_usage(output_dir)
    return {
        "output_dir": str(output_dir),
        "stages": _stage_summary(stage_records),
        "role_telemetry_coverage": _role_telemetry_coverage(output_dir, stage_records),
        "headless_usage": exact_usage,
        "attribution": {
            "run_turns": "exact" if exact_usage is not None else "unavailable",
            "run_cost_by_model": "exact" if exact_usage is not None else "unavailable",
            "role_tokens_tools_duration": "agent_usage_blocks",
            "role_turns": "unavailable",
            "role_cost": "unavailable",
            "reason": (
                "Agent usage blocks expose total tokens, tool uses, and duration but not the priced token classes "
                "or turns required for additive per-role cost attribution."
            ),
        },
        "verify_run_costs": _run_verify_costs(output_dir),
        "hook_events": _read_hook_events(output_dir),
        "compose_stats": _read_compose_stats(output_dir),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compose .run-metrics.json from existing run telemetry.")
    p.add_argument("output_dir", type=run_path_arg, help="OUTPUT_DIR containing .stage-stats.jsonl + .hook-events.log")
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
