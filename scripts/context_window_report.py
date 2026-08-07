#!/usr/bin/env python3
"""Measure resident context and compaction boundaries in Claude JSONL sessions.

``cache_read_input_tokens`` is cache throughput for one model turn.  It is not
itself current context occupancy.  For a turn, Claude's resident input is:

    input_tokens + cache_read_input_tokens + cache_creation_input_tokens

The report keeps main sessions and ``subagents/`` sessions separate and treats
only ``system/subtype=compact_boundary`` as a compaction event.

``--turn-diagnostics`` adds benchmark-only turn-purpose telemetry to JSON
output.  Classification happens after all assistant content blocks with the
same ``message.id`` have been aggregated.  When a turn has several category
candidates, the primary category is selected in this order: agent dispatch,
repair, artifact write, validation, status or logging, workflow routing,
evidence request, semantic decision.  Secondary candidates and low-confidence
classifications remain visible for manual adjudication.  These diagnostics are
not authoritative runtime state.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from verify_run_costs import PRICING_MODELS, PRICING_TABLE_VERSION

_STAGE_RE = re.compile(r"\b(?:Stage|Phase)\s+([0-9]+(?:\.[0-9]+)?[a-z]?)\b", re.IGNORECASE)
_USAGE_FIELDS = (
    "input_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
)
_COST_USAGE_FIELDS = (*_USAGE_FIELDS, "output_tokens")

_TURN_CATEGORIES = (
    "semantic_decision",
    "evidence_request",
    "agent_dispatch",
    "artifact_write",
    "validation",
    "repair",
    "status_or_logging",
    "workflow_routing",
)
_CATEGORY_PRECEDENCE = (
    "agent_dispatch",
    "repair",
    "artifact_write",
    "validation",
    "status_or_logging",
    "workflow_routing",
    "evidence_request",
    "semantic_decision",
)
_AGENT_TOOLS = {"agent", "task"}
_EVIDENCE_TOOLS = {"read", "grep", "glob", "webfetch", "websearch"}
_WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit"}
_STATUS_TOOLS = {"todowrite"}
_ROUTING_TOOLS = {"skill", "askuserquestion", "taskoutput"}

_BASH_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "repair",
        re.compile(r"\b(?:repair|autofix|apply_prose_fixes(?:\.py)?)\b", re.IGNORECASE),
        "bash:repair",
    ),
    (
        "validation",
        re.compile(
            r"\b(?:pytest|validate[_a-z0-9-]*(?:\.py)?|qa_checks(?:\.py)?|"
            r"mermaid_validate(?:\.mjs)?|ruff|mypy|shellcheck)\b|"
            r"\bmake\s+(?:test|lint|check)\b",
            re.IGNORECASE,
        ),
        "bash:validation",
    ),
    (
        "status_or_logging",
        re.compile(
            r"\b(?:log_event|appsec_status|watch_run)(?:\.py)?\b|"
            r"\.(?:agent-run|hook-events)\.log\b",
            re.IGNORECASE,
        ),
        "bash:status_or_logging",
    ),
    (
        "workflow_routing",
        re.compile(r"\b(?:orchestration_controller|check_state)(?:\.py)?\b", re.IGNORECASE),
        "bash:workflow_routing",
    ),
    (
        "artifact_write",
        re.compile(
            r"\b(?:compose_threat_model|build_threat_model_yaml|"
            r"render_completion_summary|export_[a-z0-9_]+)(?:\.py)?\b",
            re.IGNORECASE,
        ),
        "bash:artifact_write",
    ),
    (
        "evidence_request",
        re.compile(
            r"(?:^|[;&|]\s*)(?:rg|grep|sed|jq|find|head|tail|wc|ls|cat)\b|"
            r"\bgit\s+(?:diff|show|status|log)\b",
            re.IGNORECASE,
        ),
        "bash:evidence_request",
    ),
)

_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("repair", re.compile(r"\b(?:repairing|fixing|autofix)\b", re.IGNORECASE), "text:repair"),
    (
        "validation",
        re.compile(r"\b(?:validat(?:e|ing|ion)|test(?:ing)?|lint(?:ing)?)\b", re.IGNORECASE),
        "text:validation",
    ),
    (
        "status_or_logging",
        re.compile(r"\b(?:status update|logging|log event|progress update)\b", re.IGNORECASE),
        "text:status_or_logging",
    ),
    (
        "workflow_routing",
        re.compile(r"\b(?:advance|resume|route|next (?:phase|stage)|workflow)\b", re.IGNORECASE),
        "text:workflow_routing",
    ),
    (
        "evidence_request",
        re.compile(r"\b(?:read|inspect|search|look up|gather evidence)\b", re.IGNORECASE),
        "text:evidence_request",
    ),
    (
        "artifact_write",
        re.compile(r"\b(?:write|emit|save|compose|render)(?:d|s|ing)?\b", re.IGNORECASE),
        "text:artifact_write",
    ),
    (
        "semantic_decision",
        re.compile(
            r"\b(?:assess|analy[sz]e|threat|severity|security judgment|decision)\b",
            re.IGNORECASE,
        ),
        "text:semantic_decision",
    ),
)

_STARTUP_LAYERS = {
    "empty_runtime_floor",
    "tool_allow_list",
    "shared_kernel",
    "role_definition",
    "dispatch_task",
    "state_manifest",
}
_STARTUP_METHODS = {"provider_token_count", "controlled_startup_ab"}
_STARTUP_RECORD_KEYS = {
    "measurement_id",
    "layer",
    "label",
    "measurement_method",
    "measured_tokens",
    "baseline_resident_tokens",
    "variant_resident_tokens",
    "changed_variable",
    "claude_code_version",
    "model_id",
    "pricing_table_version",
    "tool_allow_list",
    "task_sha256",
    "agent_definition_sha256",
    "input_sha256",
    "review_status",
}
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def _parse_timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value}") from exc
    if timestamp.tzinfo is None:
        raise ValueError(f"timestamp must include a UTC offset: {value}")
    return timestamp


def _entries_through(entries: list[dict[str, Any]], before: str | None) -> list[dict[str, Any]]:
    if before is None:
        return entries
    cutoff = _parse_timestamp(before)
    selected: list[dict[str, Any]] = []
    for entry in entries:
        raw_timestamp = entry.get("timestamp")
        if isinstance(raw_timestamp, str) and raw_timestamp:
            timestamp = _parse_timestamp(raw_timestamp)
            if timestamp > cutoff:
                break
        selected.append(entry)
    return selected


def _pricing_model(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    model = raw.casefold()
    for prefix in ("claude-", "anthropic/"):
        if model.startswith(prefix):
            model = model[len(prefix) :]
    model = re.sub(r"-\d{8}$", "", model)
    aliases = {
        "sonnet": "sonnet-4-6",
        "opus": "opus-4-6",
        "haiku": "haiku-4-5",
    }
    return aliases.get(model, model)


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


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)


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


def _content_blocks(entry: dict[str, Any]) -> list[Any]:
    message = _message(entry)
    content = message.get("content", entry.get("content"))
    if isinstance(content, list):
        return list(content)
    if isinstance(content, (str, dict)):
        return [content]
    return []


def _tool_input_text(block: dict[str, Any]) -> str:
    value = block.get("input")
    if not isinstance(value, (dict, list, str)):
        return ""
    return "\n".join(_walk_strings(value))


def _aggregate_assistant_turns(
    entries: list[dict[str, Any]],
    stages: list[str | None],
) -> list[dict[str, Any]]:
    """Join every assistant block for one message before turn classification."""
    turns: dict[str, dict[str, Any]] = {}
    for index, (entry, stage) in enumerate(zip(entries, stages, strict=True), 1):
        if entry.get("type") != "assistant":
            continue
        message_id = _message_id(entry)
        key = message_id or f"entry:{index}"
        turn = turns.setdefault(
            key,
            {
                "message_id": message_id,
                "entry_numbers": [],
                "content_blocks": [],
                "timestamps": [],
                "stage": stage,
                "role": None,
                "resident_snapshots": set(),
                "models": set(),
                "usage": {name: 0 for name in _COST_USAGE_FIELDS},
                "has_usage": False,
                "usage_recorded": False,
            },
        )
        turn["entry_numbers"].append(index)
        turn["content_blocks"].extend(_content_blocks(entry))
        timestamp = entry.get("timestamp")
        if isinstance(timestamp, str) and timestamp:
            turn["timestamps"].append(timestamp)
        if stage is not None:
            turn["stage"] = stage
        role = entry.get("attributionAgent") or entry.get("agentId")
        if turn["role"] is None and isinstance(role, str) and role:
            turn["role"] = role
        model = _pricing_model(_message(entry).get("model") or entry.get("model"))
        if model is not None:
            turn["models"].add(model)
        usage = _usage(entry)
        # Claude Code repeats the metered turn snapshot on each content record.
        # Later records can carry a growing output_tokens transport value; keep
        # the first snapshot to preserve the established invoice reconstruction
        # while still aggregating every content block for classification.
        if usage and not turn["usage_recorded"]:
            for name in _COST_USAGE_FIELDS:
                raw = usage.get(name, 0)
                if isinstance(raw, int) and raw >= 0:
                    turn["usage"][name] = raw
            turn["usage_recorded"] = True
        resident = _resident_tokens(entry)
        if resident is not None:
            turn["has_usage"] = True
            turn["resident_snapshots"].add(resident)
    return [turn for turn in turns.values() if turn["has_usage"]]


def _classify_turn(turn: dict[str, Any]) -> dict[str, Any]:
    candidates: dict[str, dict[str, Any]] = {}
    tool_names: list[str] = []
    unknown_tools: set[str] = set()

    def add(category: str, strength: int, signal: str) -> None:
        candidate = candidates.setdefault(category, {"strength": 0, "signals": set()})
        candidate["strength"] = max(candidate["strength"], strength)
        candidate["signals"].add(signal)

    text_blocks: list[str] = []
    for block in turn["content_blocks"]:
        if isinstance(block, str):
            text_blocks.append(block)
            continue
        if not isinstance(block, dict):
            continue
        block_type = str(block.get("type") or "")
        if block_type == "text" and isinstance(block.get("text"), str):
            text_blocks.append(block["text"])
        if block_type != "tool_use":
            continue
        raw_name = block.get("name")
        name = raw_name if isinstance(raw_name, str) and raw_name else "unknown"
        tool_names.append(name)
        normalized = name.casefold()
        if normalized in _AGENT_TOOLS:
            add("agent_dispatch", 3, f"tool:{name}")
            continue
        if normalized in _EVIDENCE_TOOLS:
            add("evidence_request", 3, f"tool:{name}")
            continue
        if normalized in _WRITE_TOOLS:
            add("artifact_write", 3, f"tool:{name}")
            continue
        if normalized in _STATUS_TOOLS:
            add("status_or_logging", 3, f"tool:{name}")
            continue
        if normalized in _ROUTING_TOOLS:
            add("workflow_routing", 2, f"tool:{name}")
            continue
        if normalized == "bash":
            command = _tool_input_text(block)
            matched = False
            for category, pattern, signal in _BASH_PATTERNS:
                if pattern.search(command):
                    add(category, 3, signal)
                    matched = True
            if not matched:
                unknown_tools.add(name)
            continue
        unknown_tools.add(name)

    if not candidates:
        text = "\n".join(text_blocks)
        for category, pattern, signal in _TEXT_PATTERNS:
            if pattern.search(text):
                add(category, 2, signal)
        if text.strip() and not candidates:
            add("semantic_decision", 1, "text:fallback")
        elif turn["content_blocks"] and not candidates:
            add("semantic_decision", 1, "content:fallback")

    ordered = [category for category in _CATEGORY_PRECEDENCE if category in candidates]
    primary = ordered[0] if ordered else None
    secondary = ordered[1:]
    inconsistent_usage = len(turn["resident_snapshots"]) > 1
    primary_strength = candidates[primary]["strength"] if primary is not None else 0
    if primary_strength >= 3 and not secondary and not unknown_tools and not inconsistent_usage:
        confidence = "high"
    elif primary_strength >= 2 and not unknown_tools and not inconsistent_usage:
        confidence = "medium"
    else:
        confidence = "low"
    mixed = bool(secondary)
    requires_adjudication = primary is None or mixed or confidence == "low"
    timestamps = turn["timestamps"]
    models = sorted(turn["models"])
    pricing = PRICING_MODELS.get(models[0]) if len(models) == 1 else None
    usage = turn["usage"]
    reconstructed_cost = None
    if pricing is not None:
        reconstructed_cost = round(
            usage["input_tokens"] * pricing["input"] / 1_000_000
            + usage["output_tokens"] * pricing["output"] / 1_000_000
            + usage["cache_creation_input_tokens"] * pricing["cache_write"] / 1_000_000
            + usage["cache_read_input_tokens"] * pricing["cache_read"] / 1_000_000,
            8,
        )
    return {
        "message_id": turn["message_id"],
        "entry_numbers": turn["entry_numbers"],
        "timestamp_start": timestamps[0] if timestamps else None,
        "timestamp_end": timestamps[-1] if timestamps else None,
        "stage": turn["stage"],
        "role": turn["role"] or "unknown",
        "models": models,
        "primary_category": primary,
        "secondary_categories": secondary,
        "confidence": confidence,
        "mixed": mixed,
        "requires_manual_adjudication": requires_adjudication,
        "content_block_count": len(turn["content_blocks"]),
        "tool_use_count": len(tool_names),
        "tool_names": tool_names,
        "unknown_tool_names": sorted(unknown_tools),
        "usage_snapshots_consistent": not inconsistent_usage,
        "usage": dict(usage),
        "reconstructed_cost_usd": reconstructed_cost,
        "signals": {category: sorted(candidate["signals"]) for category, candidate in sorted(candidates.items())},
    }


def _diagnostic_summary(turns: list[dict[str, Any]]) -> dict[str, Any]:
    primary = Counter(turn["primary_category"] for turn in turns if turn["primary_category"])
    secondary = Counter(category for turn in turns for category in turn["secondary_categories"])
    roles = Counter(turn["role"] for turn in turns)
    models = Counter(model for turn in turns for model in turn["models"])
    token_totals = Counter()
    role_costs: Counter[str] = Counter()
    reconstructed_cost = 0.0
    unpriced_turns = 0
    for turn in turns:
        token_totals.update(turn["usage"])
        cost = turn["reconstructed_cost_usd"]
        if cost is None:
            unpriced_turns += 1
        else:
            reconstructed_cost += cost
            role_costs[turn["role"]] += cost
    unclassified = sum(turn["primary_category"] is None for turn in turns)
    manual = sum(turn["requires_manual_adjudication"] for turn in turns)
    return {
        "turns": len(turns),
        "primary_category_counts": {category: primary.get(category, 0) for category in _TURN_CATEGORIES},
        "secondary_category_counts": {category: secondary.get(category, 0) for category in _TURN_CATEGORIES},
        "role_counts": dict(sorted(roles.items())),
        "role_costs_usd": {role: round(cost, 4) for role, cost in sorted(role_costs.items())},
        "model_turn_counts": dict(sorted(models.items())),
        "token_totals": {name: token_totals.get(name, 0) for name in _COST_USAGE_FIELDS},
        "reconstructed_cost_usd": round(reconstructed_cost, 2),
        "unpriced_turns": unpriced_turns,
        "mixed_turns": sum(turn["mixed"] for turn in turns),
        "low_confidence_turns": sum(turn["confidence"] == "low" for turn in turns),
        "unclassified_turns": unclassified,
        "manual_adjudication_required": manual,
        "zero_category_claims_blocked": manual > 0,
    }


def _turn_diagnostics(
    entries: list[dict[str, Any]],
    stages: list[str | None],
    *,
    default_role: str,
) -> dict[str, Any]:
    aggregated = _aggregate_assistant_turns(entries, stages)
    for turn in aggregated:
        if turn["role"] is None:
            turn["role"] = default_role
    turns = [_classify_turn(turn) for turn in aggregated]
    compaction_duration_ms = 0
    compactions_with_duration = 0
    for entry in entries:
        if entry.get("type") != "system" or entry.get("subtype") != "compact_boundary":
            continue
        metadata = entry.get("compactMetadata")
        duration = metadata.get("durationMs") if isinstance(metadata, dict) else None
        if isinstance(duration, int) and duration >= 0:
            compaction_duration_ms += duration
            compactions_with_duration += 1
    return {
        "summary": _diagnostic_summary(turns),
        "compaction_duration_ms": compaction_duration_ms,
        "compactions_with_duration": compactions_with_duration,
        "turns": turns,
    }


def analyze_session(
    path: Path,
    *,
    include_turn_diagnostics: bool = False,
    before: str | None = None,
) -> dict[str, Any]:
    entries = _entries_through(list(_iter_jsonl(path)), before)
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
    stages: list[str | None] = []

    for index, entry in enumerate(entries, 1):
        _source_chars(entry, source_chars)
        stage = _latest_stage(entry, stage)
        stages.append(stage)

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
    result = {
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
    if include_turn_diagnostics:
        result["turn_diagnostics"] = _turn_diagnostics(
            entries,
            stages,
            default_role="unknown_subagent" if kind == "subagent" else "thin_top_level",
        )
    return result


def build_report(
    paths: Iterable[Path],
    *,
    include_turn_diagnostics: bool = False,
    before: str | None = None,
) -> dict[str, Any]:
    sessions = [
        analyze_session(
            path,
            include_turn_diagnostics=include_turn_diagnostics,
            before=before,
        )
        for path in paths
    ]
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
    report = {
        "schema_version": 1,
        "metric": ("input_tokens + cache_read_input_tokens + cache_creation_input_tokens"),
        "groups": grouped,
        "sessions": sessions,
    }
    if include_turn_diagnostics:
        turns = [turn for session in sessions for turn in session["turn_diagnostics"]["turns"]]
        report["turn_diagnostics"] = {
            "schema_version": 1,
            "telemetry_only": True,
            "measurement_method": "transcript_usage",
            "pricing_table_version": PRICING_TABLE_VERSION,
            "before": before,
            "classification_precedence": list(_CATEGORY_PRECEDENCE),
            "manual_adjudication_rule": ("required for mixed, low-confidence, or unclassified turns"),
            "startup_context_note": (
                "transcript usage measures assembled resident context; it does not "
                "attribute runtime, agent, task, tool-schema, or preloaded-skill layers"
            ),
            "summary": _diagnostic_summary(turns),
        }
    return report


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


def _bounded_string(value: Any, field: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"startup measurement {field} must be 1-{maximum} characters")
    return value


def _startup_measurement_record(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"startup measurement {index} must be an object")
    unknown = set(value) - _STARTUP_RECORD_KEYS
    missing = _STARTUP_RECORD_KEYS - set(value)
    if unknown:
        raise ValueError(f"startup measurement {index} has unknown fields: {sorted(unknown)}")
    if missing:
        raise ValueError(f"startup measurement {index} is missing fields: {sorted(missing)}")

    record = dict(value)
    _bounded_string(record["measurement_id"], "measurement_id", maximum=64)
    layer = _bounded_string(record["layer"], "layer", maximum=32)
    if layer not in _STARTUP_LAYERS:
        raise ValueError(f"startup measurement {index} has unknown layer: {layer}")
    _bounded_string(record["label"], "label")
    method = _bounded_string(record["measurement_method"], "measurement_method", maximum=32)
    if method not in _STARTUP_METHODS:
        raise ValueError(f"startup measurement {index} has unknown method: {method}")
    tokens = record["measured_tokens"]
    if not isinstance(tokens, int) or isinstance(tokens, bool) or not 0 <= tokens <= 1_000_000:
        raise ValueError(f"startup measurement {index} has invalid measured_tokens")
    _bounded_string(record["changed_variable"], "changed_variable")
    _bounded_string(record["claude_code_version"], "claude_code_version", maximum=64)
    _bounded_string(record["model_id"], "model_id", maximum=128)
    if record["pricing_table_version"] != PRICING_TABLE_VERSION:
        raise ValueError(f"startup measurement {index} pricing_table_version must be {PRICING_TABLE_VERSION}")
    tools = record["tool_allow_list"]
    if not isinstance(tools, list) or len(tools) > 32:
        raise ValueError(f"startup measurement {index} tool_allow_list must contain at most 32 tools")
    for tool in tools:
        _bounded_string(tool, "tool_allow_list item", maximum=64)
    if len(tools) != len(set(tools)):
        raise ValueError(f"startup measurement {index} tool_allow_list contains duplicates")
    for field in ("task_sha256", "agent_definition_sha256", "input_sha256"):
        if not isinstance(record[field], str) or not _SHA256_RE.fullmatch(record[field]):
            raise ValueError(f"startup measurement {index} {field} must be a sha256 digest")
    if record["review_status"] not in {"pending", "reviewed"}:
        raise ValueError(f"startup measurement {index} has invalid review_status")

    baseline = record["baseline_resident_tokens"]
    variant = record["variant_resident_tokens"]
    if method == "provider_token_count":
        if baseline is not None or variant is not None:
            raise ValueError(f"startup measurement {index} provider_token_count cannot contain A/B observations")
    else:
        for field, observed in (
            ("baseline_resident_tokens", baseline),
            ("variant_resident_tokens", variant),
        ):
            if not isinstance(observed, int) or isinstance(observed, bool) or not 0 <= observed <= 1_000_000:
                raise ValueError(f"startup measurement {index} has invalid {field}")
        if abs(variant - baseline) != tokens:
            raise ValueError(f"startup measurement {index} measured_tokens must equal the controlled A/B delta")
    return record


def load_startup_measurements(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid startup measurement JSON: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"schema_version", "measurements"}:
        raise ValueError("startup measurements require only schema_version and measurements")
    if value["schema_version"] != 1:
        raise ValueError("unsupported startup measurement schema_version")
    raw_records = value["measurements"]
    if not isinstance(raw_records, list) or not 1 <= len(raw_records) <= 128:
        raise ValueError("startup measurements must contain 1-128 records")
    records = [_startup_measurement_record(record, index) for index, record in enumerate(raw_records, 1)]
    ids = [record["measurement_id"] for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("startup measurement IDs must be unique")
    layer_counts = Counter(record["layer"] for record in records)
    reviewed = sum(record["review_status"] == "reviewed" for record in records)
    return {
        "schema_version": 1,
        "telemetry_only": True,
        "records": records,
        "summary": {
            "measurements": len(records),
            "reviewed": reviewed,
            "pending_review": len(records) - reviewed,
            "layers": dict(sorted(layer_counts.items())),
            "release_claim_blocked": reviewed != len(records),
        },
    }


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
    parser.add_argument(
        "--turn-diagnostics",
        action="store_true",
        help="add benchmark-only turn-purpose diagnostics to --json output",
    )
    parser.add_argument(
        "--before",
        metavar="TIMESTAMP",
        help="include entries through this ISO-8601 timestamp",
    )
    parser.add_argument(
        "--startup-measurements",
        type=Path,
        metavar="JSON",
        help="attach validated provider-count or controlled startup A/B measurements",
    )
    args = parser.parse_args(argv)
    if args.turn_diagnostics and not args.as_json:
        print("Error: --turn-diagnostics requires --json", file=sys.stderr)
        return 2
    if args.startup_measurements and not args.as_json:
        print("Error: --startup-measurements requires --json", file=sys.stderr)
        return 2
    try:
        paths = _discover(args.paths)
        if not paths:
            raise ValueError("no JSONL files found")
        report = build_report(
            paths,
            include_turn_diagnostics=args.turn_diagnostics,
            before=args.before,
        )
        if args.startup_measurements:
            report["startup_layer_measurements"] = load_startup_measurements(args.startup_measurements)
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
