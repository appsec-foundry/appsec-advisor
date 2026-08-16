#!/usr/bin/env python3
"""Call-scoped lifecycle state for Agent tool invocations.

The hook session id is shared by the parent and every nested Agent call.  It is
therefore unsuitable as role ownership.  This module keys the observable
lifecycle by the Agent tool's immutable ``tool_use_id`` and keeps the state in
the already-transient ``.active-tool-calls/`` directory.

The controller ledger and persisted wave claim remain authoritative.  The
registry is used only to attribute lifecycle, usage, and budget telemetry; a
call is current only while it is running and, for a STRIDE attempt, while its
component and attempt still match the controller-owned active claim.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from event_log import format_line

SCHEMA_VERSION = 1
STATE_DIR = ".active-tool-calls"
STATE_FILENAME = "agent-lifecycle.json"
LOCK_FILENAME = ".agent-lifecycle.lock"
MAX_CALLS = 128

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")
_TERMINAL = frozenset({"done", "failed"})


class LifecycleError(RuntimeError):
    """The lifecycle state or requested transition is invalid."""


@dataclass(frozen=True)
class LifecycleEvent:
    event: str
    call: dict[str, Any]
    reason: str = ""


def _now() -> int:
    return int(time.time())


def _state_dir(output_dir: str | Path) -> Path:
    return Path(output_dir) / STATE_DIR


def state_path(output_dir: str | Path) -> Path:
    return _state_dir(output_dir) / STATE_FILENAME


def _fresh_state() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "calls": []}


def validate_state(state: object) -> dict[str, Any]:
    """Validate the persisted shape without making hook safety depend on jsonschema."""
    if not isinstance(state, dict) or set(state) != {"schema_version", "calls"}:
        raise LifecycleError("agent lifecycle state has an invalid root shape")
    if state.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleError("agent lifecycle state has an unsupported schema version")
    calls = state.get("calls")
    if not isinstance(calls, list) or len(calls) > MAX_CALLS:
        raise LifecycleError("agent lifecycle calls must be a bounded array")
    seen: set[str] = set()
    for call in calls:
        if not isinstance(call, dict):
            raise LifecycleError("agent lifecycle call is not an object")
        required = {
            "agent_call_id",
            "session_id",
            "agent",
            "agent_type",
            "model",
            "description",
            "background",
            "state",
            "spawned_at",
            "running_at",
        }
        if not required.issubset(call):
            raise LifecycleError("agent lifecycle call is missing required identity fields")
        allowed = required | {
            "runtime_agent_id",
            "action_id",
            "job_id",
            "component_id",
            "attempt",
            "analysis_depth",
            "max_turns",
            "launch_acknowledged_at",
            "finished_at",
            "failure_reason",
            "usage_recorded_at",
            "usage",
        }
        if not set(call).issubset(allowed):
            raise LifecycleError("agent lifecycle call has unknown fields")
        call_id = call.get("agent_call_id")
        if not isinstance(call_id, str) or not _ID_RE.fullmatch(call_id) or call_id in seen:
            raise LifecycleError("agent lifecycle call id is invalid or duplicated")
        seen.add(call_id)
        if call.get("state") not in {"running", "done", "failed"}:
            raise LifecycleError("agent lifecycle state is invalid")
        if not isinstance(call.get("background"), bool):
            raise LifecycleError("agent lifecycle background flag is invalid")
        for key in ("spawned_at", "running_at", "finished_at", "usage_recorded_at"):
            if key in call and (isinstance(call[key], bool) or not isinstance(call[key], int) or call[key] < 0):
                raise LifecycleError(f"agent lifecycle {key} is invalid")
        attempt = call.get("attempt")
        if attempt is not None and (isinstance(attempt, bool) or not isinstance(attempt, int) or not 1 <= attempt <= 5):
            raise LifecycleError("agent lifecycle attempt is invalid")
        component = call.get("component_id")
        if component is not None and (not isinstance(component, str) or not _COMPONENT_RE.fullmatch(component)):
            raise LifecycleError("agent lifecycle component id is invalid")
        depth = call.get("analysis_depth")
        if depth is not None and depth not in {"full", "light"}:
            raise LifecycleError("agent lifecycle analysis depth is invalid")
        runtime_agent_id = call.get("runtime_agent_id")
        if runtime_agent_id is not None and (
            not isinstance(runtime_agent_id, str) or not _ID_RE.fullmatch(runtime_agent_id)
        ):
            raise LifecycleError("agent lifecycle runtime agent id is invalid")
        if call.get("state") in _TERMINAL and not call.get("finished_at"):
            raise LifecycleError("terminal agent lifecycle call has no finish time")
        max_turns = call.get("max_turns")
        if max_turns is not None and (
            isinstance(max_turns, bool) or not isinstance(max_turns, int) or not 1 <= max_turns <= 1000
        ):
            raise LifecycleError("agent lifecycle max turns is invalid")
        usage = call.get("usage")
        if usage is not None:
            token_keys = {
                "input_tokens",
                "output_tokens",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
            }
            if (
                not isinstance(usage, dict)
                or not token_keys.issubset(usage)
                or not set(usage).issubset(token_keys | {"tool_uses"})
            ):
                raise LifecycleError("agent lifecycle usage is invalid")
            if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in usage.values()):
                raise LifecycleError("agent lifecycle usage counters are invalid")
    return state


def _read_state_unlocked(output_dir: str | Path) -> dict[str, Any]:
    path = state_path(output_dir)
    if not path.is_file():
        return _fresh_state()
    try:
        return validate_state(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise LifecycleError(f"cannot read agent lifecycle state: {exc}") from exc


def _write_state_unlocked(output_dir: str | Path, state: dict[str, Any]) -> None:
    validate_state(state)
    directory = _state_dir(output_dir)
    fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".agent-lifecycle-tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp, state_path(output_dir))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@contextmanager
def _locked(output_dir: str | Path) -> Iterator[None]:
    directory = _state_dir(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink():
        raise LifecycleError("agent lifecycle directory must not be a symlink")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(directory / LOCK_FILENAME, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _bounded(value: object, limit: int = 512) -> str:
    return str(value or "").replace("\n", " ").replace("\r", " ")[:limit]


def _identity(identity: dict[str, Any]) -> dict[str, Any]:
    call_id = _bounded(identity.get("agent_call_id"), 256)
    if not _ID_RE.fullmatch(call_id):
        raise LifecycleError("Agent call requires a valid tool_use_id")
    attempt = identity.get("attempt")
    if attempt in ("", None):
        attempt = None
    elif isinstance(attempt, str) and attempt.isdigit():
        attempt = int(attempt)
    component = _bounded(identity.get("component_id"), 100) or None
    depth = _bounded(identity.get("analysis_depth"), 16) or None
    max_turns = identity.get("max_turns")
    if isinstance(max_turns, str) and max_turns.isdigit():
        max_turns = int(max_turns)
    if isinstance(max_turns, bool) or not isinstance(max_turns, int) or max_turns < 1:
        max_turns = None
    call = {
        "agent_call_id": call_id,
        "session_id": _bounded(identity.get("session_id"), 8),
        "agent": _bounded(identity.get("agent"), 100) or "unknown",
        "agent_type": _bounded(identity.get("agent_type"), 256) or "unknown",
        "model": _bounded(identity.get("model"), 100) or "?",
        "description": _bounded(identity.get("description"), 512),
        "background": bool(identity.get("background", False)),
        "action_id": _bounded(identity.get("action_id"), 256) or None,
        "job_id": _bounded(identity.get("job_id"), 256) or None,
        "component_id": component,
        "attempt": attempt,
        "analysis_depth": depth,
        "max_turns": max_turns,
        "state": "running",
        "spawned_at": _now(),
        "running_at": _now(),
    }
    return {key: value for key, value in call.items() if value is not None}


def register_call(output_dir: str | Path, identity: dict[str, Any]) -> list[LifecycleEvent]:
    """Open one immutable call and return its ordered lifecycle events."""
    new_call = _identity(identity)
    events: list[LifecycleEvent] = []
    with _locked(output_dir):
        state = _read_state_unlocked(output_dir)
        for existing in state["calls"]:
            if existing["agent_call_id"] == new_call["agent_call_id"]:
                if existing.get("state") == "running" and all(
                    existing.get(key) == new_call.get(key)
                    for key in ("session_id", "agent", "agent_type", "action_id", "job_id", "attempt")
                ):
                    return []
                return [LifecycleEvent("AGENT_LIFECYCLE_REJECTED", existing, "duplicate_or_reordered_spawn")]
        if not new_call["background"]:
            for existing in state["calls"]:
                if (
                    existing.get("state") == "running"
                    and not existing.get("background")
                    and existing.get("session_id") == new_call["session_id"]
                ):
                    existing["state"] = "failed"
                    existing["finished_at"] = _now()
                    existing["failure_reason"] = "superseded_without_return"
                    events.append(LifecycleEvent("AGENT_FAILED", dict(existing), "superseded_without_return"))
        state["calls"].append(new_call)
        if len(state["calls"]) > MAX_CALLS:
            terminal = [call for call in state["calls"] if call.get("state") in _TERMINAL]
            while len(state["calls"]) > MAX_CALLS and terminal:
                state["calls"].remove(terminal.pop(0))
        _write_state_unlocked(output_dir, state)
    events.extend(
        [
            LifecycleEvent("AGENT_SPAWN", dict(new_call)),
            LifecycleEvent("AGENT_RUNNING", dict(new_call)),
        ]
    )
    return events


def _terminal_transition(
    output_dir: str | Path,
    call_id: str,
    *,
    success: bool,
    reason: str = "",
) -> list[LifecycleEvent]:
    call_id = _bounded(call_id, 256)
    with _locked(output_dir):
        state = _read_state_unlocked(output_dir)
        call = next((row for row in state["calls"] if row.get("agent_call_id") == call_id), None)
        if call is None:
            tombstone = {
                "agent_call_id": call_id if _ID_RE.fullmatch(call_id) else "unknown-call",
                "session_id": "",
                "agent": "unknown",
                "agent_type": "unknown",
                "model": "?",
                "description": "",
                "background": False,
                "state": "failed",
                "spawned_at": 0,
                "running_at": 0,
                "finished_at": _now(),
                "failure_reason": "terminal_before_spawn",
            }
            state["calls"].append(tombstone)
            _write_state_unlocked(output_dir, state)
            return [LifecycleEvent("AGENT_LIFECYCLE_REJECTED", tombstone, "terminal_before_spawn")]
        if call.get("state") in _TERMINAL:
            return []
        call["state"] = "done" if success else "failed"
        call["finished_at"] = _now()
        if reason:
            call["failure_reason"] = _bounded(reason, 512)
        _write_state_unlocked(output_dir, state)
        event = "AGENT_DONE" if success else "AGENT_FAILED"
        return [LifecycleEvent(event, dict(call), reason)]


def finish_call(output_dir: str | Path, call_id: str) -> list[LifecycleEvent]:
    return _terminal_transition(output_dir, call_id, success=True)


def fail_call(output_dir: str | Path, call_id: str, reason: str) -> list[LifecycleEvent]:
    return _terminal_transition(output_dir, call_id, success=False, reason=reason)


def acknowledge_background_call(output_dir: str | Path, call_id: str) -> list[LifecycleEvent]:
    """Record launch acknowledgement without treating it as Agent completion."""
    with _locked(output_dir):
        state = _read_state_unlocked(output_dir)
        call = next((row for row in state["calls"] if row.get("agent_call_id") == call_id), None)
        if call is None:
            tombstone = {
                "agent_call_id": call_id if _ID_RE.fullmatch(call_id) else "unknown-call",
                "session_id": "",
                "agent": "unknown",
                "agent_type": "unknown",
                "model": "?",
                "description": "",
                "background": False,
                "state": "failed",
                "spawned_at": 0,
                "running_at": 0,
                "finished_at": _now(),
                "failure_reason": "post_before_spawn",
            }
            state["calls"].append(tombstone)
            _write_state_unlocked(output_dir, state)
            return [LifecycleEvent("AGENT_LIFECYCLE_REJECTED", tombstone, "post_before_spawn")]
        if call.get("state") in _TERMINAL:
            return []
        if not call.get("background"):
            raise LifecycleError("foreground call cannot be acknowledged as background")
        if call.get("launch_acknowledged_at"):
            return []
        call["launch_acknowledged_at"] = _now()
        _write_state_unlocked(output_dir, state)
    return []


def running_calls(output_dir: str | Path, session_id: str | None = None) -> list[dict[str, Any]]:
    try:
        with _locked(output_dir):
            state = _read_state_unlocked(output_dir)
    except (LifecycleError, OSError):
        return []
    calls = [dict(call) for call in state["calls"] if call.get("state") == "running"]
    if session_id is not None:
        calls = [call for call in calls if call.get("session_id") == session_id[:8]]
    return calls


def unique_running_call(output_dir: str | Path, session_id: str) -> dict[str, Any] | None:
    calls = running_calls(output_dir, session_id)
    return calls[0] if len(calls) == 1 else None


def bind_runtime_agent_id(output_dir: str | Path, call_id: str, runtime_agent_id: str) -> dict[str, Any] | None:
    """Bind Claude Code's existing agent id to the immutable Agent tool call."""
    call_id = _bounded(call_id, 256)
    runtime_agent_id = _bounded(runtime_agent_id, 256)
    if not _ID_RE.fullmatch(call_id) or not _ID_RE.fullmatch(runtime_agent_id):
        return None
    with _locked(output_dir):
        state = _read_state_unlocked(output_dir)
        call = next((row for row in state["calls"] if row.get("agent_call_id") == call_id), None)
        if call is None or call.get("state") != "running":
            return None
        if any(row is not call and row.get("runtime_agent_id") == runtime_agent_id for row in state["calls"]):
            raise LifecycleError("runtime agent id is already bound to another call")
        existing = call.get("runtime_agent_id")
        if existing not in (None, runtime_agent_id):
            raise LifecycleError("Agent call runtime identity cannot change")
        if existing is None:
            call["runtime_agent_id"] = runtime_agent_id
            _write_state_unlocked(output_dir, state)
        return dict(call)


def bind_runtime_agent_start(
    output_dir: str | Path,
    runtime_agent_id: str,
    agent_type: str,
) -> dict[str, Any] | None:
    """Bind SubagentStart only when its type selects one unbound call."""
    runtime_agent_id = _bounded(runtime_agent_id, 256)
    raw_type = _bounded(agent_type, 256).split(":")[-1]
    if not _ID_RE.fullmatch(runtime_agent_id) or not raw_type:
        return None
    with _locked(output_dir):
        state = _read_state_unlocked(output_dir)
        already = [row for row in state["calls"] if row.get("runtime_agent_id") == runtime_agent_id]
        if len(already) == 1:
            return dict(already[0])
        candidates = [
            row
            for row in state["calls"]
            if row.get("state") == "running"
            and not row.get("runtime_agent_id")
            and str(row.get("agent_type") or "").split(":")[-1] == raw_type
        ]
        if len(candidates) != 1:
            return None
        candidates[0]["runtime_agent_id"] = runtime_agent_id
        _write_state_unlocked(output_dir, state)
        return dict(candidates[0])


def call_by_runtime_agent_id(output_dir: str | Path, runtime_agent_id: str) -> dict[str, Any] | None:
    """Find a call by its bound runtime id, running or already terminal.

    Usage arrives on SubagentStop, which necessarily fires after the Agent tool
    has returned. Claude Code >=2.x returns an async handle the moment the
    agent is launched, so the call is already `done` by then and a
    running-only lookup rejected every SubagentStop usage record on the
    2026-08-15 juice-shop run (23 x `no_running_agent_call`), leaving the run
    with no per-call usage at all. The binding is one-to-one and
    `usage_recorded_at` keeps attribution single-shot, so matching a terminal
    call is safe.
    """
    try:
        with _locked(output_dir):
            state = _read_state_unlocked(output_dir)
            matches = [call for call in state["calls"] if call.get("runtime_agent_id") == runtime_agent_id]
    except (OSError, ValueError, LifecycleError):
        return None
    return dict(matches[0]) if len(matches) == 1 else None


def _record_usage_for_call(
    output_dir: str | Path,
    call_id: str,
    usage: dict[str, Any],
    *,
    tool_uses: int | None = None,
) -> list[LifecycleEvent]:
    with _locked(output_dir):
        state = _read_state_unlocked(output_dir)
        # Terminal calls accept usage too: SubagentStop is the only per-call
        # usage source and always arrives after the Agent tool's async return
        # has already closed the call. `usage_recorded_at` keeps this single-shot.
        call = next(
            (row for row in state["calls"] if row.get("agent_call_id") == call_id),
            None,
        )
        if call is None or call.get("usage_recorded_at"):
            return []
        call["usage_recorded_at"] = _now()
        call["usage"] = {
            key: int(usage.get(key) or 0)
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
            )
        }
        if tool_uses is not None:
            call["usage"]["tool_uses"] = max(0, int(tool_uses))
        _write_state_unlocked(output_dir, state)
        return [LifecycleEvent("AGENT_USAGE", dict(call))]


def record_call_usage(
    output_dir: str | Path,
    call_id: str,
    usage: dict[str, Any],
    *,
    tool_uses: int | None = None,
) -> list[LifecycleEvent]:
    """Attribute usage to a call by its own ID, for a source that knows it."""
    return _record_usage_for_call(output_dir, call_id, usage, tool_uses=tool_uses)


def record_runtime_usage(
    output_dir: str | Path,
    runtime_agent_id: str,
    usage: dict[str, Any],
    *,
    tool_uses: int | None = None,
) -> list[LifecycleEvent]:
    call = call_by_runtime_agent_id(output_dir, runtime_agent_id)
    if call is None:
        return []
    return _record_usage_for_call(
        output_dir,
        call["agent_call_id"],
        usage,
        tool_uses=tool_uses,
    )


def finish_jobs(
    output_dir: str | Path,
    job_ids: list[str],
    *,
    success: bool,
    reason: str = "",
) -> list[LifecycleEvent]:
    """Close background calls selected by controller-owned job identities."""
    wanted = set(job_ids)
    events: list[LifecycleEvent] = []
    with _locked(output_dir):
        state = _read_state_unlocked(output_dir)
        for call in state["calls"]:
            if call.get("state") != "running" or call.get("job_id") not in wanted:
                continue
            call["state"] = "done" if success else "failed"
            call["finished_at"] = _now()
            if reason:
                call["failure_reason"] = _bounded(reason, 512)
            events.append(LifecycleEvent("AGENT_DONE" if success else "AGENT_FAILED", dict(call), reason))
        if events:
            _write_state_unlocked(output_dir, state)
    return events


def fail_all_running(output_dir: str | Path, reason: str) -> list[LifecycleEvent]:
    """Terminalize every remaining call before live-state cleanup."""
    events: list[LifecycleEvent] = []
    with _locked(output_dir):
        state = _read_state_unlocked(output_dir)
        for call in state["calls"]:
            if call.get("state") != "running":
                continue
            call["state"] = "failed"
            call["finished_at"] = _now()
            call["failure_reason"] = _bounded(reason, 512)
            events.append(LifecycleEvent("AGENT_FAILED", dict(call), reason))
        if events:
            _write_state_unlocked(output_dir, state)
    return events


def is_current_claim(output_dir: str | Path, call: dict[str, Any]) -> bool:
    """Return whether telemetry still belongs to a current authoritative claim."""
    call_id = call.get("agent_call_id")
    if not call_id or not any(row.get("agent_call_id") == call_id for row in running_calls(output_dir)):
        return False
    action_id = call.get("action_id")
    if action_id:
        try:
            plan = json.loads((Path(output_dir) / ".context-routing-plan.json").read_text(encoding="utf-8"))
            job_id = call.get("job_id")
            if not any(
                row.get("action_id") == action_id and (not job_id or job_id in (row.get("job_ids") or []))
                for row in plan.get("actions", [])
            ):
                return False
        except (OSError, json.JSONDecodeError, AttributeError):
            return False
    component = call.get("component_id")
    attempt = call.get("attempt")
    if component and attempt is not None:
        try:
            waves = json.loads((Path(output_dir) / ".dispatch-waves.json").read_text(encoding="utf-8"))
            active = waves.get("active_claim") or {}
            if component not in (active.get("component_ids") or []):
                return False
            if (active.get("attempts") or {}).get(component) != attempt:
                return False
        except (OSError, json.JSONDecodeError, AttributeError):
            return False
    return True


def event_detail(event: LifecycleEvent) -> str:
    call = event.call
    fields = [
        f"agent_call_id={call.get('agent_call_id', '?')}",
        f"agent_type={call.get('agent_type', '?')}",
        f"model={call.get('model', '?')}",
        f"background={str(bool(call.get('background'))).lower()}",
    ]
    for key in ("action_id", "job_id", "component_id", "attempt", "analysis_depth"):
        if call.get(key) not in (None, ""):
            fields.append(f"{key}={call[key]}")
    if event.event == "AGENT_USAGE":
        usage = call.get("usage") or {}
        fields.extend(
            [
                f"in={usage.get('input_tokens', 0)}",
                f"out={usage.get('output_tokens', 0)}",
                f"cache_write={usage.get('cache_creation_input_tokens', 0)}",
                f"cache_read={usage.get('cache_read_input_tokens', 0)}",
            ]
        )
        if "tool_uses" in usage:
            fields.append(f"tool_uses={usage['tool_uses']}")
    if event.reason:
        fields.append(f"reason={_bounded(event.reason, 512)}")
    if call.get("description"):
        fields.append(f"description={_bounded(call['description'], 512)}")
    return "  ".join(fields)


def append_events(output_dir: str | Path, events: list[LifecycleEvent]) -> None:
    """Persist lifecycle events through the canonical event formatter."""
    if not events:
        return
    root = Path(output_dir)
    for item in events:
        call = item.call
        level = "WARN" if item.event in {"AGENT_FAILED", "AGENT_LIFECYCLE_REJECTED"} else "INFO"
        detail = event_detail(item)
        try:
            with (root / ".hook-events.log").open("a", encoding="utf-8") as handle:
                handle.write(format_line(item.event, detail, level=level, sid=call.get("session_id")))
            with (root / ".agent-run.log").open("a", encoding="utf-8") as handle:
                handle.write(
                    format_line(
                        item.event,
                        detail,
                        level=level,
                        component=call.get("agent") or "hook-logger",
                        sid=call.get("session_id"),
                    )
                )
        except OSError:
            pass
