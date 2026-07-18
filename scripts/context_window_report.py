#!/usr/bin/env python3
"""Measure resident context and compaction boundaries in Claude JSONL sessions.

``cache_read_input_tokens`` is cache throughput for one model turn.  It is not
itself current context occupancy.  For a turn, Claude's resident input is:

    input_tokens + cache_read_input_tokens + cache_creation_input_tokens

The report keeps main sessions and ``subagents/`` sessions separate and treats
only ``system/subtype=compact_boundary`` as a compaction event.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

_STAGE_RE = re.compile(r"\b(?:Stage|Phase)\s+([0-9]+(?:\.[0-9]+)?[a-z]?)\b", re.IGNORECASE)
_USAGE_FIELDS = (
    "input_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
)


def _iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if isinstance(value, dict):
                yield value


def _message(entry: dict[str, Any]) -> dict[str, Any]:
    value = entry.get("message")
    return value if isinstance(value, dict) else {}


def _usage(entry: dict[str, Any]) -> dict[str, Any]:
    value = _message(entry).get("usage")
    return value if isinstance(value, dict) else {}


def _resident_tokens(entry: dict[str, Any]) -> int | None:
    usage = _usage(entry)
    if not usage:
        return None
    values: list[int] = []
    for name in _USAGE_FIELDS:
        raw = usage.get(name, 0)
        values.append(raw if isinstance(raw, int) and raw >= 0 else 0)
    return sum(values)


def _message_id(entry: dict[str, Any]) -> str | None:
    value = _message(entry).get("id")
    return value if isinstance(value, str) else None


def _walk_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_text(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key in {"text", "content", "message", "detail", "name"}:
                yield from _walk_text(item)


def _latest_stage(entry: dict[str, Any], current: str | None) -> str | None:
    for text in _walk_text(entry):
        matches = list(_STAGE_RE.finditer(text))
        if matches:
            current = matches[-1].group(0)
    return current


def _source_chars(entry: dict[str, Any], totals: Counter[str]) -> None:
    entry_type = str(entry.get("type") or "unknown")
    message = _message(entry)
    content = message.get("content", entry.get("content"))
    if isinstance(content, str):
        totals[entry_type] += len(content)
        return
    if not isinstance(content, list):
        return
    for block in content:
        if isinstance(block, str):
            totals[entry_type] += len(block)
            continue
        if not isinstance(block, dict):
            continue
        block_type = str(block.get("type") or entry_type)
        chars = sum(len(text) for text in _walk_text(block))
        totals[block_type] += chars


def _first_int(entry: dict[str, Any], names: tuple[str, ...]) -> int | None:
    stack: list[Any] = [entry]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, item in value.items():
                if key in names and isinstance(item, int) and item > 0:
                    return item
                if isinstance(item, (dict, list)):
                    stack.append(item)
        elif isinstance(value, list):
            stack.extend(value)
    return None


def analyze_session(path: Path) -> dict[str, Any]:
    peak = 0
    turns = 0
    cache_read_throughput = 0
    boundaries: list[dict[str, Any]] = []
    model_ids: set[str] = set()
    versions: set[str] = set()
    nominal_windows: set[int] = set()
    source_chars: Counter[str] = Counter()
    stage_metrics: dict[str, dict[str, int]] = {}
    stage: str | None = None
    last_resident: int | None = None
    seen_message_ids: set[str] = set()

    for index, entry in enumerate(_iter_jsonl(path), 1):
        _source_chars(entry, source_chars)
        stage = _latest_stage(entry, stage)

        message = _message(entry)
        model = message.get("model") or entry.get("model")
        if isinstance(model, str) and model:
            model_ids.add(model)
        version = entry.get("version") or entry.get("claudeCodeVersion")
        if isinstance(version, str) and version:
            versions.add(version)
        nominal = _first_int(
            entry,
            ("context_window", "context_window_tokens", "max_context_tokens"),
        )
        if nominal:
            nominal_windows.add(nominal)

        resident = _resident_tokens(entry)
        if resident is not None:
            msg_id = _message_id(entry)
            is_duplicate = msg_id is not None and msg_id in seen_message_ids
            if msg_id is not None:
                seen_message_ids.add(msg_id)
            if not is_duplicate:
                turns += 1
                peak = max(peak, resident)
                last_resident = resident
                cache_read = _usage(entry).get("cache_read_input_tokens", 0)
                if isinstance(cache_read, int) and cache_read > 0:
                    cache_read_throughput += cache_read
                stage_name = stage or "unknown"
                metrics = stage_metrics.setdefault(
                    stage_name,
                    {
                        "assistant_turns_with_usage": 0,
                        "peak_resident_context": 0,
                        "cache_read_throughput": 0,
                    },
                )
                metrics["assistant_turns_with_usage"] += 1
                metrics["peak_resident_context"] = max(metrics["peak_resident_context"], resident)
                if isinstance(cache_read, int) and cache_read > 0:
                    metrics["cache_read_throughput"] += cache_read

        if entry.get("type") == "system" and entry.get("subtype") == "compact_boundary":
            boundaries.append(
                {
                    "entry": index,
                    "resident_before": last_resident,
                    "stage_before": stage,
                    "timestamp": entry.get("timestamp"),
                }
            )

    kind = "subagent" if "subagents" in path.parts else "main"
    return {
        "path": str(path),
        "kind": kind,
        "assistant_turns_with_usage": turns,
        "peak_resident_context": peak,
        "compact_boundaries": boundaries,
        "cache_read_throughput": cache_read_throughput,
        "cache_read_note": "cumulative per-turn throughput; not resident occupancy",
        "content_chars_by_source": dict(sorted(source_chars.items())),
        "stages": dict(sorted(stage_metrics.items())),
        "models": sorted(model_ids),
        "claude_code_versions": sorted(versions),
        "nominal_context_windows": sorted(nominal_windows),
    }


def build_report(paths: Iterable[Path]) -> dict[str, Any]:
    sessions = [analyze_session(path) for path in paths]
    grouped: dict[str, dict[str, int]] = {}
    for kind in ("main", "subagent"):
        selected = [item for item in sessions if item["kind"] == kind]
        grouped[kind] = {
            "sessions": len(selected),
            "peak_resident_context": max(
                (item["peak_resident_context"] for item in selected),
                default=0,
            ),
            "compact_boundaries": sum(len(item["compact_boundaries"]) for item in selected),
        }
    return {
        "schema_version": 1,
        "metric": ("input_tokens + cache_read_input_tokens + cache_creation_input_tokens"),
        "groups": grouped,
        "sessions": sessions,
    }


def _discover(inputs: list[str]) -> list[Path]:
    paths: list[Path] = []
    for raw in inputs:
        path = Path(raw).expanduser()
        if path.is_dir():
            paths.extend(sorted(path.rglob("*.jsonl")))
        elif path.is_file():
            paths.append(path)
        else:
            raise ValueError(f"not found: {path}")
    return list(dict.fromkeys(path.resolve() for path in paths))


def _render_text(report: dict[str, Any]) -> str:
    lines = [
        "Claude context-window report",
        f"Metric: {report['metric']}",
        "cache_read: throughput, not current occupancy",
    ]
    for kind in ("main", "subagent"):
        group = report["groups"][kind]
        lines.append(
            f"{kind}: sessions={group['sessions']} "
            f"peak={group['peak_resident_context']:,} "
            f"compactions={group['compact_boundaries']}"
        )
    for session in report["sessions"]:
        lines.append(
            f"- {session['kind']} {session['path']}: "
            f"peak={session['peak_resident_context']:,}, "
            f"compactions={len(session['compact_boundaries'])}"
        )
        for boundary in session["compact_boundaries"]:
            lines.append(
                "    compact_boundary "
                f"entry={boundary['entry']} "
                f"resident_before={boundary['resident_before']} "
                f"stage={boundary['stage_before'] or 'unknown'}"
            )
        for stage, metrics in session["stages"].items():
            lines.append(
                f"    stage={stage} "
                f"turns={metrics['assistant_turns_with_usage']} "
                f"peak={metrics['peak_resident_context']:,} "
                f"cache_read={metrics['cache_read_throughput']:,}"
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="JSONL file(s) or directories")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        paths = _discover(args.paths)
        if not paths:
            raise ValueError("no JSONL files found")
        report = build_report(paths)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_text(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
