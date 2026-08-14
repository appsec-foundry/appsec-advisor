"""Call-scoped turn-budget telemetry for Agent tool invocations.

The hook session id is shared by parent and child calls, so it is never used as
budget ownership. Counters and marker entries are keyed by the immutable Agent
``tool_use_id``. A marker is actionable only while that call remains running
and, for retryable STRIDE work, still matches the controller-owned active
component/attempt claim.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import agent_lifecycle

WARN_THRESHOLD = 0.75
CRITICAL_THRESHOLD = 0.90
MAX_THRESHOLD = 1.00

STATE_FILENAME = ".budget-state.json"
STATE_LOCK_FILENAME = ".budget-state.lock"
WARN_FLAG_FILENAME = ".budget-warning"
CRITICAL_FLAG_FILENAME = ".budget-critical"
LOCK_FILENAME = ".appsec-lock"
LOCK_FRESH_SECONDS = 300
DEFAULT_MAX_TURNS = 250
STATE_SCHEMA_VERSION = 2

_MAXTURNS_RE = re.compile(r"^maxTurns:\s*(\d+)\s*$", re.MULTILINE)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")
_MAX_TURNS_CACHE: dict[str, int] = {}


def _plugin_root() -> Optional[Path]:
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    return Path(root) if root and Path(root).is_dir() else None


def get_max_turns(agent_name: str) -> int:
    if not agent_name:
        return DEFAULT_MAX_TURNS
    if agent_name in _MAX_TURNS_CACHE:
        return _MAX_TURNS_CACHE[agent_name]
    root = _plugin_root()
    if not root:
        _MAX_TURNS_CACHE[agent_name] = DEFAULT_MAX_TURNS
        return DEFAULT_MAX_TURNS
    candidates = [agent_name]
    if not agent_name.startswith("appsec-"):
        candidates.append(f"appsec-{agent_name}")
    for candidate in candidates:
        path = root / "agents" / f"{candidate}.md"
        if not path.is_file():
            continue
        try:
            match = _MAXTURNS_RE.search(path.read_text(encoding="utf-8", errors="replace"))
            if match:
                value = int(match.group(1))
                _MAX_TURNS_CACHE[agent_name] = value
                return value
        except OSError:
            continue
    _MAX_TURNS_CACHE[agent_name] = DEFAULT_MAX_TURNS
    return DEFAULT_MAX_TURNS


def _state_path(output_dir: str | Path) -> Path:
    return Path(output_dir) / STATE_FILENAME


def _fresh_state() -> dict:
    return {"schema_version": STATE_SCHEMA_VERSION, "calls": {}}


def _valid_state(state: object) -> bool:
    if not isinstance(state, dict) or set(state) != {"schema_version", "calls"}:
        return False
    calls = state.get("calls")
    if state.get("schema_version") != STATE_SCHEMA_VERSION or not isinstance(calls, dict) or len(calls) > 256:
        return False
    required = {
        "agent_call_id",
        "sid",
        "agent",
        "agent_type",
        "turns",
        "max_turns",
        "warn_emitted",
        "critical_emitted",
        "max_emitted",
        "first_seen",
    }
    optional = {"action_id", "job_id", "component_id", "attempt", "last_seen"}
    for call_id, entry in calls.items():
        if not isinstance(call_id, str) or not _ID_RE.fullmatch(call_id):
            return False
        if not isinstance(entry, dict) or not required.issubset(entry):
            return False
        if entry.get("agent_call_id") != call_id or not set(entry).issubset(required | optional):
            return False
        if any(not isinstance(entry.get(key), bool) for key in ("warn_emitted", "critical_emitted", "max_emitted")):
            return False
        for key in ("turns", "max_turns", "first_seen", "last_seen"):
            if key in entry and (isinstance(entry[key], bool) or not isinstance(entry[key], int) or entry[key] < 0):
                return False
        if entry["max_turns"] < 1 or entry["max_turns"] > 1000:
            return False
        if not isinstance(entry.get("sid"), str) or len(entry["sid"]) > 8:
            return False
        if any(not isinstance(entry.get(key), str) or not entry[key] for key in ("agent", "agent_type")):
            return False
        for key in ("action_id", "job_id"):
            value = entry.get(key)
            if value is not None and (not isinstance(value, str) or not _ID_RE.fullmatch(value)):
                return False
        component = entry.get("component_id")
        if component is not None and (not isinstance(component, str) or not _COMPONENT_RE.fullmatch(component)):
            return False
        attempt = entry.get("attempt")
        if attempt is not None and (isinstance(attempt, bool) or not isinstance(attempt, int) or not 1 <= attempt <= 5):
            return False
    return True


def _read_state(output_dir: str | Path) -> dict:
    path = _state_path(output_dir)
    if not path.is_file():
        return _fresh_state()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _fresh_state()
    if not _valid_state(state):
        # Version 1 keyed counters only by session and cannot be migrated without
        # inventing call ownership. Discard it rather than carrying ambiguity.
        return _fresh_state()
    return state


def _write_state(output_dir: str | Path, state: dict) -> None:
    if not _valid_state(state):
        return
    path = _state_path(output_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".budget-tmp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass


@contextmanager
def _state_lock(output_dir: str | Path) -> Iterator[None]:
    root = Path(output_dir) / agent_lifecycle.STATE_DIR
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise OSError("budget state lock directory must not be a symlink")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(root / STATE_LOCK_FILENAME, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _live_lock_owner(output_dir: str | Path) -> Optional[str]:
    try:
        raw = (Path(output_dir) / LOCK_FILENAME).read_text(encoding="utf-8")
    except OSError:
        return None
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) < 3:
        return None
    try:
        heartbeat = int(lines[1].split()[0])
    except (ValueError, IndexError):
        return None
    if time.time() - heartbeat > LOCK_FRESH_SECONDS:
        return None
    return lines[2][:8] or None


def _valid_marker_entry(entry: object) -> bool:
    required = {"agent_call_id", "sid", "agent", "agent_type", "turns", "max", "pct"}
    optional = {"action_id", "job_id", "component_id", "attempt"}
    if not isinstance(entry, dict) or not required.issubset(entry) or not set(entry).issubset(required | optional):
        return False
    if not isinstance(entry.get("agent_call_id"), str) or not _ID_RE.fullmatch(entry["agent_call_id"]):
        return False
    if not isinstance(entry.get("sid"), str) or len(entry["sid"]) > 8:
        return False
    if any(not isinstance(entry.get(key), str) or not entry[key] for key in ("agent", "agent_type")):
        return False
    for key in ("turns", "max"):
        if isinstance(entry.get(key), bool) or not isinstance(entry.get(key), int) or entry[key] < 0:
            return False
    if entry["max"] < 1 or entry["max"] > 1000:
        return False
    pct = entry.get("pct")
    if isinstance(pct, bool) or not isinstance(pct, (int, float)) or pct < 0:
        return False
    for key in ("action_id", "job_id"):
        value = entry.get(key)
        if value is not None and (not isinstance(value, str) or not _ID_RE.fullmatch(value)):
            return False
    component = entry.get("component_id")
    if component is not None and (not isinstance(component, str) or not _COMPONENT_RE.fullmatch(component)):
        return False
    attempt = entry.get("attempt")
    return attempt is None or (not isinstance(attempt, bool) and isinstance(attempt, int) and 1 <= attempt <= 5)


def _marker_entries(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [entry for entry in value if _valid_marker_entry(entry)] if isinstance(value, list) else []


def _write_marker_entries(path: Path, entries: list[dict]) -> None:
    try:
        if entries:
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}-tmp-")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(entries, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                os.replace(tmp, path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        elif path.is_file() or path.is_symlink():
            path.unlink()
    except OSError:
        pass


def _write_flag(output_dir: str | Path, filename: str, payload: dict) -> None:
    if not _valid_marker_entry(payload):
        return
    owner = _live_lock_owner(output_dir)
    if owner is not None and payload.get("sid") != owner:
        return
    path = Path(output_dir) / filename
    existing = _marker_entries(path)
    call_id = payload.get("agent_call_id")
    existing = [entry for entry in existing if entry.get("agent_call_id") != call_id]
    existing.append(payload)
    _write_marker_entries(path, existing)


def _normalise_call(call_or_sid: dict | str, agent: str | None = None, budget_agent: str | None = None) -> dict:
    if isinstance(call_or_sid, dict):
        return dict(call_or_sid)
    # Compatibility for direct callers. Production hook attribution always
    # supplies the concrete lifecycle record.
    sid = str(call_or_sid or "")[:8]
    name = agent or "unknown"
    return {
        "agent_call_id": f"legacy:{sid}:{name}"[:256],
        "session_id": sid,
        "agent": name,
        "agent_type": budget_agent or name,
        "max_turns": get_max_turns(budget_agent or name),
        "state": "running",
        "legacy_compat": True,
    }


def _new_entry(call: dict, max_turns: int) -> dict:
    return {
        "agent_call_id": call.get("agent_call_id"),
        "sid": str(call.get("session_id") or "")[:8],
        "agent": call.get("agent") or "unknown",
        "agent_type": call.get("agent_type") or "unknown",
        "action_id": call.get("action_id"),
        "job_id": call.get("job_id"),
        "component_id": call.get("component_id"),
        "attempt": call.get("attempt"),
        "turns": 0,
        "max_turns": max_turns,
        "warn_emitted": False,
        "critical_emitted": False,
        "max_emitted": False,
        "first_seen": int(time.time()),
    }


def _call_max_turns(call: dict) -> int:
    value = call.get("max_turns")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        value = get_max_turns(str(call.get("agent") or call.get("agent_type") or "unknown"))
    return value


def open_call(call: dict, output_dir: str | Path) -> None:
    """Open a zero-count budget record for one admitted lifecycle call."""
    call_id = str(call.get("agent_call_id") or "")
    max_turns = _call_max_turns(call)
    if not call_id or max_turns <= 0 or not agent_lifecycle.is_current_claim(output_dir, call):
        return
    with _state_lock(output_dir):
        state = _read_state(output_dir)
        state["calls"].setdefault(call_id, _new_entry(call, max_turns))
        _write_state(output_dir, state)


def _threshold_event(entry: dict, destination: str | Path) -> Optional[dict]:
    max_turns = int(entry["max_turns"])
    pct = int(entry["turns"]) / max_turns
    payload = {
        key: entry.get(key)
        for key in (
            "agent_call_id",
            "sid",
            "agent",
            "agent_type",
            "action_id",
            "job_id",
            "component_id",
            "attempt",
        )
        if entry.get(key) not in (None, "")
    }
    payload.update({"turns": entry["turns"], "max": max_turns, "pct": round(pct, 3)})
    event = None
    if pct >= MAX_THRESHOLD and not entry["max_emitted"]:
        event = "MAX_TURNS"
        entry["max_emitted"] = entry["critical_emitted"] = entry["warn_emitted"] = True
    elif pct >= CRITICAL_THRESHOLD and not entry["critical_emitted"]:
        event = "BUDGET_CRITICAL"
        entry["critical_emitted"] = entry["warn_emitted"] = True
    elif pct >= WARN_THRESHOLD and not entry["warn_emitted"]:
        event = "BUDGET_WARN"
        entry["warn_emitted"] = True
    if event:
        _write_flag(destination, CRITICAL_FLAG_FILENAME if event != "BUDGET_WARN" else WARN_FLAG_FILENAME, payload)
        return {"event": event, **payload}
    return None


def tally_and_check(
    call_or_sid: dict | str,
    agent_or_output_dir: str,
    output_dir: str | None = None,
    budget_agent: Optional[str] = None,
) -> Optional[dict]:
    """Increment exactly one running Agent call and report a new threshold."""
    if isinstance(call_or_sid, dict):
        call = _normalise_call(call_or_sid)
        destination = agent_or_output_dir
    else:
        call = _normalise_call(call_or_sid, agent_or_output_dir, budget_agent)
        destination = output_dir or ""
    call_id = str(call.get("agent_call_id") or "")
    sid = str(call.get("session_id") or "")[:8]
    if not call_id or not destination:
        return None
    if not call.get("legacy_compat") and not agent_lifecycle.is_current_claim(destination, call):
        return None
    max_turns = _call_max_turns(call)
    if max_turns <= 0:
        return None
    with _state_lock(destination):
        state = _read_state(destination)
        entry = state["calls"].get(
            call_id,
            _new_entry(call, max_turns),
        )
        entry["turns"] = int(entry.get("turns") or 0) + 1
        entry["max_turns"] = max_turns
        entry["last_seen"] = int(time.time())
        state["calls"][call_id] = entry
        _write_state(destination, state)
        crossing = _threshold_event(entry, destination)
        if crossing:
            state["calls"][call_id] = entry
            _write_state(destination, state)
            return crossing
    return None


def observe_tool_uses(call: dict, turns: int, output_dir: str | Path) -> Optional[dict]:
    """Idempotently record the exact tool-use total from a SubagentStop transcript."""
    if isinstance(turns, bool) or not isinstance(turns, int) or turns < 0:
        return None
    if not agent_lifecycle.is_current_claim(output_dir, call):
        return None
    call_id = str(call.get("agent_call_id") or "")
    max_turns = _call_max_turns(call)
    if not call_id or max_turns <= 0:
        return None
    with _state_lock(output_dir):
        state = _read_state(output_dir)
        entry = state["calls"].get(call_id, _new_entry(call, max_turns))
        if turns <= int(entry.get("turns") or 0):
            return None
        entry["turns"] = turns
        entry["max_turns"] = max_turns
        entry["last_seen"] = int(time.time())
        crossing = _threshold_event(entry, output_dir)
        state["calls"][call_id] = entry
        _write_state(output_dir, state)
        return crossing


def close_call(agent_call_id: str, output_dir: str | Path) -> None:
    """Atomically retire counter ownership; stale markers become inert immediately."""
    if not agent_call_id or not output_dir:
        return
    with _state_lock(output_dir):
        state = _read_state(output_dir)
        state["calls"].pop(agent_call_id, None)
        _write_state(output_dir, state)
        for filename in (WARN_FLAG_FILENAME, CRITICAL_FLAG_FILENAME):
            path = Path(output_dir) / filename
            remaining = [entry for entry in _marker_entries(path) if entry.get("agent_call_id") != agent_call_id]
            _write_marker_entries(path, remaining)


def reset_session(sid: str, output_dir: str) -> None:
    """Compatibility cleanup: retire every call explicitly bound to one session."""
    if not sid or not output_dir:
        return
    sid = sid[:8]
    try:
        with _state_lock(output_dir):
            state = _read_state(output_dir)
            call_ids = {call_id for call_id, entry in state["calls"].items() if entry.get("sid") == sid}
            for call_id in call_ids:
                state["calls"].pop(call_id, None)
            _write_state(output_dir, state)
            for filename in (WARN_FLAG_FILENAME, CRITICAL_FLAG_FILENAME):
                path = Path(output_dir) / filename
                remaining = [
                    entry
                    for entry in _marker_entries(path)
                    if entry.get("agent_call_id") not in call_ids and entry.get("sid") != sid
                ]
                _write_marker_entries(path, remaining)
    except Exception:
        pass


def active_marker_entries(output_dir: str | Path, filename: str = CRITICAL_FLAG_FILENAME) -> list[dict]:
    active: list[dict] = []
    for entry in _marker_entries(Path(output_dir) / filename):
        call_id = entry.get("agent_call_id")
        call = next(
            (row for row in agent_lifecycle.running_calls(output_dir) if row.get("agent_call_id") == call_id),
            None,
        )
        identity_matches = call is not None and all(
            entry.get(key) == call.get(key)
            for key in ("agent_call_id", "action_id", "job_id", "component_id", "attempt")
            if entry.get(key) is not None or call.get(key) is not None
        )
        if identity_matches and agent_lifecycle.is_current_claim(output_dir, call):
            active.append(entry)
    return active


def has_active_critical_claim(output_dir: str | Path) -> bool:
    return bool(active_marker_entries(output_dir, CRITICAL_FLAG_FILENAME))


def format_detail(payload: dict) -> str:
    return (
        f"agent={payload.get('agent', '?')}  "
        f"agent_call_id={payload.get('agent_call_id', '?')}  "
        f"turns={payload.get('turns', '?')}/{payload.get('max', '?')}  "
        f"pct={int(payload.get('pct', 0) * 100)}%"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    active = sub.add_parser("active-critical")
    active.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "active-critical":
        return 0 if has_active_critical_claim(args.output_dir) else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
