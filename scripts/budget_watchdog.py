"""Turn-budget watchdog — track per-session tool-call count and emit
warnings before an agent runs into its `maxTurns` ceiling.

Called from ``agent_logger.handle_post_tool_use`` once per tool call.
State lives in ``$OUTPUT_DIR/.budget-state.json``; flag files are written
to ``$OUTPUT_DIR/.budget-warning`` and ``$OUTPUT_DIR/.budget-critical``
so agents can poll them at phase boundaries and execute a graceful
wrap-up before the harness hard-terminates the session.

Thresholds:
  * 75% — BUDGET_WARN  (heads-up, no wrap-up trigger)
  * 90% — BUDGET_CRITICAL (writes flag file; agents must wrap up)
  * 100% — MAX_TURNS (emitted deterministically even when the harness
    does not surface a native event)

Each threshold fires AT MOST ONCE per (session, level) — the state file
records `warn_emitted` / `critical_emitted` / `max_emitted` booleans.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Optional

WARN_THRESHOLD = 0.75
CRITICAL_THRESHOLD = 0.90
MAX_THRESHOLD = 1.00

STATE_FILENAME = ".budget-state.json"
WARN_FLAG_FILENAME = ".budget-warning"
CRITICAL_FLAG_FILENAME = ".budget-critical"

# Fallback when an agent file has no `maxTurns:` line. Mirrors the
# Claude Code harness default; conservative so missing-frontmatter never
# triggers false-positive criticals.
DEFAULT_MAX_TURNS = 250

_MAXTURNS_RE = re.compile(r"^maxTurns:\s*(\d+)\s*$", re.MULTILINE)

# Cache: agent_name -> max_turns. Lookup happens on every tool call; the
# agent .md files are immutable for the duration of a run.
_MAX_TURNS_CACHE: dict[str, int] = {}


def _plugin_root() -> Optional[Path]:
    """Resolve $CLAUDE_PLUGIN_ROOT — required to locate agents/*.md."""
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root and Path(root).is_dir():
        return Path(root)
    return None


def get_max_turns(agent_name: str) -> int:
    """Read `maxTurns:` from agents/<agent_name>.md, caching the result.

    Returns DEFAULT_MAX_TURNS on any error (missing file, malformed
    frontmatter, missing CLAUDE_PLUGIN_ROOT). The fallback ensures the
    watchdog NEVER blocks a run because of its own bookkeeping failure.
    """
    if not agent_name:
        return DEFAULT_MAX_TURNS
    if agent_name in _MAX_TURNS_CACHE:
        return _MAX_TURNS_CACHE[agent_name]

    root = _plugin_root()
    if not root:
        _MAX_TURNS_CACHE[agent_name] = DEFAULT_MAX_TURNS
        return DEFAULT_MAX_TURNS

    # Try both bare name and `appsec-` prefixed variant. agent_logger stores
    # the prefixed name (`appsec-stride-analyzer`); some callers may pass
    # the bare form (`stride-analyzer`).
    candidates = [agent_name]
    if not agent_name.startswith("appsec-"):
        candidates.append(f"appsec-{agent_name}")

    for candidate in candidates:
        path = root / "agents" / f"{candidate}.md"
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            m = _MAXTURNS_RE.search(content)
            if m:
                value = int(m.group(1))
                _MAX_TURNS_CACHE[agent_name] = value
                return value
        except OSError:
            continue

    _MAX_TURNS_CACHE[agent_name] = DEFAULT_MAX_TURNS
    return DEFAULT_MAX_TURNS


def _state_path(output_dir: str) -> Path:
    return Path(output_dir) / STATE_FILENAME


def _read_state(output_dir: str) -> dict:
    path = _state_path(output_dir)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(output_dir: str, state: dict) -> None:
    """Atomic write — temp file in same dir, then rename. Survives
    parallel watchdog calls (the hook runs in the calling tool's process
    so two sessions can race here)."""
    path = _state_path(output_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".budget-tmp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        # Never block a run because state could not be persisted.
        pass


def _write_flag(output_dir: str, filename: str, payload: dict) -> None:
    """Write a flag file (.budget-warning / .budget-critical).

    Single file shared across sessions — content is a JSON list of all
    currently-flagged (sid, agent, percent_used) tuples. Agents poll the
    *file's existence* as a binary trigger; the content is for human
    debugging and skill-layer summary.
    """
    path = Path(output_dir) / filename
    existing: list[dict] = []
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except (OSError, json.JSONDecodeError):
            existing = []

    # De-duplicate by sid+agent — re-entrant calls just refresh the entry.
    key = (payload.get("sid"), payload.get("agent"))
    existing = [e for e in existing if (e.get("sid"), e.get("agent")) != key]
    existing.append(payload)

    try:
        path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    except OSError:
        pass


def tally_and_check(sid: str, agent: str, output_dir: str) -> Optional[dict]:
    """Increment turn counter for (sid, agent) and check thresholds.

    Returns a dict describing the threshold crossing when one occurs:
      {
        "event": "BUDGET_WARN" | "BUDGET_CRITICAL" | "MAX_TURNS",
        "agent": <agent_name>,
        "sid":   <session_id>,
        "turns": <current_count>,
        "max":   <max_turns>,
        "pct":   <0.0-1.0+>,
      }

    Returns None when no new threshold was crossed (no work for caller).

    The function is robust against missing inputs — empty sid, empty
    agent, malformed state — and never raises. The caller (agent_logger)
    must remain crash-free.
    """
    if not sid or not output_dir:
        return None

    sid = sid[:8]
    agent = agent or "unknown"
    max_turns = get_max_turns(agent)
    if max_turns <= 0:
        return None

    state = _read_state(output_dir)
    entry = state.get(sid, {
        "agent": agent,
        "turns": 0,
        "max_turns": max_turns,
        "warn_emitted": False,
        "critical_emitted": False,
        "max_emitted": False,
        "first_seen": int(time.time()),
    })
    # Refresh agent name (initial Pre may fire before session-agent map is
    # populated; later Post will have it).
    if agent != "unknown":
        entry["agent"] = agent
    entry["max_turns"] = max_turns
    entry["turns"] = int(entry.get("turns", 0)) + 1
    entry["last_seen"] = int(time.time())
    state[sid] = entry
    _write_state(output_dir, state)

    pct = entry["turns"] / max_turns
    payload_base = {
        "agent": entry["agent"],
        "sid": sid,
        "turns": entry["turns"],
        "max": max_turns,
        "pct": round(pct, 3),
    }

    # Threshold crossings are checked from highest to lowest — if turns
    # somehow jump multiple thresholds in one call (replay/restart),
    # the most severe event is reported.
    if pct >= MAX_THRESHOLD and not entry["max_emitted"]:
        entry["max_emitted"] = True
        entry["critical_emitted"] = True
        entry["warn_emitted"] = True
        state[sid] = entry
        _write_state(output_dir, state)
        _write_flag(output_dir, CRITICAL_FLAG_FILENAME, payload_base)
        return {"event": "MAX_TURNS", **payload_base}

    if pct >= CRITICAL_THRESHOLD and not entry["critical_emitted"]:
        entry["critical_emitted"] = True
        entry["warn_emitted"] = True
        state[sid] = entry
        _write_state(output_dir, state)
        _write_flag(output_dir, CRITICAL_FLAG_FILENAME, payload_base)
        return {"event": "BUDGET_CRITICAL", **payload_base}

    if pct >= WARN_THRESHOLD and not entry["warn_emitted"]:
        entry["warn_emitted"] = True
        state[sid] = entry
        _write_state(output_dir, state)
        _write_flag(output_dir, WARN_FLAG_FILENAME, payload_base)
        return {"event": "BUDGET_WARN", **payload_base}

    return None


def reset_session(sid: str, output_dir: str) -> None:
    """Drop all watchdog state + flag entries for ``sid``, giving the next
    delegated unit of work a fresh turn budget.

    Called when the orchestrator dispatches a sub-agent (Agent tool). In
    ``claude -p`` headless mode every sub-agent shares the outermost
    orchestrator session id, so the per-session turn counter would otherwise
    accumulate the WHOLE pipeline's tool calls (Stage 1 + STRIDE fan-out +
    abuse fan-out + Stage 2 render + Stage 3 repair) against a single
    sub-agent's ``maxTurns`` — tripping BUDGET_CRITICAL mid-run and poisoning
    the fresh-budget renderer via the shared ``.budget-critical`` flag. A
    reset at each dispatch boundary scopes the budget to one stage at a time,
    which matches the documented "fresh budget per stage" design intent.

    Never raises — a reset failure must not break a run.
    """
    if not sid or not output_dir:
        return
    sid = sid[:8]

    # 1. Drop the per-session turn counter.
    try:
        state = _read_state(output_dir)
        if sid in state:
            del state[sid]
            _write_state(output_dir, state)
    except Exception:
        pass

    # 2. Drop this session's entries from both flag files; remove a flag file
    #    entirely once no session is flagged (agents poll existence).
    for filename in (WARN_FLAG_FILENAME, CRITICAL_FLAG_FILENAME):
        path = Path(output_dir) / filename
        if not path.is_file():
            continue
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except (OSError, json.JSONDecodeError):
            existing = []
        remaining = [e for e in existing if e.get("sid") != sid]
        try:
            if remaining:
                path.write_text(json.dumps(remaining, indent=2), encoding="utf-8")
            else:
                path.unlink()
        except OSError:
            pass


def format_detail(payload: dict) -> str:
    """Format a threshold-crossing payload for the .hook-events.log line."""
    return (
        f"agent={payload.get('agent', '?')}  "
        f"turns={payload.get('turns', '?')}/{payload.get('max', '?')}  "
        f"pct={int(payload.get('pct', 0) * 100)}%"
    )
