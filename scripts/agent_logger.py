#!/usr/bin/env python3
"""
appsec-advisor hook logger — writes to docs/security/.hook-events.log
in the current working directory (the analyzed repo).

This is SEPARATE from docs/security/.agent-run.log which is written
by the agents themselves via bash echo commands. Keeping them apart
avoids confusing chronological interleaving.

Triggered by: PreToolUse, PostToolUse, SubagentStart, Stop, SubagentStop

Events logged:
  AGENT_SPAWN   — any Agent tool call is about to start (PreToolUse, all depths)
  AGENT_RUNNING — the admitted Agent call is running under its tool_use_id
  AGENT_DONE    — one foreground return or validated background join succeeded
  AGENT_FAILED  — one call failed, expired, was superseded, or was terminally cleaned
  AGENT_USAGE   — SubagentStop usage bound through agent_id to the Agent call
  SCAN_START    — threat-analyst dispatched / scan beginning (PreToolUse, top-level only)
  SCAN_COMPLETE — threat-analyst finished (PostToolUse, top-level only)
  CONTEXT_READY — context resolver wrote .threat-modeling-context.md (size)
  FILE_WRITE    — Write tool completed (path, size, duration)
  FILE_EDIT     — Edit tool completed (path, char delta, duration)
  FILE_READ     — Read tool completed (path, byte/line size, duration)
  GREP_RUN      — Grep tool completed (pattern, path, duration)
  GLOB_RUN      — Glob tool completed (pattern, path, duration)
  BASH_OK       — Bash tool completed without WARN indicators (cmd clip, duration)
  TOOL_ERROR    — any tool returned is_error=true
  BASH_WARN     — Bash output contains permission/error indicators
  SESSION_STOP  — agent session ended (reason, token usage, estimated cost)
  MAX_TURNS     — agent hit its maxTurns limit (logged as ERROR)
  ASSESSMENT_SUMMARY — final summary (duration, mode, threat counts, tokens, cost, models)
  ASSESSMENT_FILES   — all files written during the assessment (full paths, deduplicated)

Performance-diagnostic note (added 2026-05-23): FILE_READ / GREP_RUN / GLOB_RUN /
BASH_OK were added to close the visibility gap — previously only ~15% of tool calls
appeared in this log (only Write/Edit and WARN-Bash), making "silent" stretches in
the run impossible to attribute. With this addition every PostToolUse emits an event,
and each event carries a `dur=<seconds>` tail computed from the matching PreToolUse
manifest in `.active-tool-calls/`. Use `dur` to spot slow tools (e.g. long-running
compose_threat_model.py invocations) without re-instrumenting the agents themselves.

Agent lifecycle identity
  PreToolUse opens AGENT_SPAWN -> AGENT_RUNNING under the host tool_use_id.
  PostToolUse closes a foreground call, acknowledges a background launch, or
  rejects a return without a matching call. SubagentStart and SubagentStop bind
  the host agent_id to that call for usage. Session IDs remain observational and
  never select lifecycle, usage, or budget ownership.

Why both PreToolUse (AGENT_SPAWN / SCAN_START) and PostToolUse (SCAN_COMPLETE / AGENT_DONE)?
  PostToolUse for the Agent tool only fires in the *outermost* Claude session —
  the one where the skill runs. Sub-agents spawned from within appsec-threat-analyst
  (context-resolver, recon-scanner, dep-scanner, stride-analyzer) are invisible to
  PostToolUse because that hook does not propagate through nested agent sessions.
  PreToolUse fires in the session that is *about to call* the tool, which includes
  sub-agent sessions, giving full visibility at dispatch time.

  SCAN_START is emitted at PreToolUse so it appears *before* the threat-analyst's
  own SESSION_STOP in the chronological log. SCAN_COMPLETE replaces the old
  PostToolUse SCAN_START which incorrectly appeared *after* SESSION_STOP.
"""

import html
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import agent_lifecycle
from event_log import format_line
from jsonschema import Draft202012Validator

# ---------------------------------------------------------------------------
# Config loading — single cached read of config.json
# ---------------------------------------------------------------------------
_CONFIG_CACHE = None


def _load_config() -> dict:
    """Load and cache config. config.local.json overrides config.json when present."""
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if plugin_root:
        local_path = os.path.join(plugin_root, "config.local.json")
        base_path = os.path.join(plugin_root, "config.json")
        config_path = local_path if os.path.isfile(local_path) else base_path
        try:
            with open(config_path) as fh:
                _CONFIG_CACHE = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            _CONFIG_CACHE = {}
            try:
                sys.stderr.write(f"[appsec] warning: failed to load config {config_path}: {exc}\n")
            except Exception:
                pass
    else:
        _CONFIG_CACHE = {}
    return _CONFIG_CACHE


# ---------------------------------------------------------------------------
# Pricing (USD per 1 M tokens) — derived from cached config
# ---------------------------------------------------------------------------
def _load_pricing() -> dict:
    """Load pricing from plugin config.json, fall back to built-in defaults."""
    defaults = {
        "input": 3.00,
        "output": 15.00,
        "cache_write": 3.75,
        "cache_read": 0.30,
    }
    pricing = _load_config().get("pricing", {})
    if pricing:
        return {
            "input": pricing.get("input_per_1m", defaults["input"]),
            "output": pricing.get("output_per_1m", defaults["output"]),
            "cache_write": pricing.get("cache_write_per_1m", defaults["cache_write"]),
            "cache_read": pricing.get("cache_read_per_1m", defaults["cache_read"]),
        }
    return defaults


_PRICING = _load_pricing()


# ---------------------------------------------------------------------------
# Verbose mode — mirror log lines to stderr for real-time terminal output
# ---------------------------------------------------------------------------
def _is_verbose() -> bool:
    """Check whether verbose logging is enabled.

    Enabled by any of:
      - Environment variable APPSEC_VERBOSE=1 (or any truthy value)
      - config.json logging.verbose: true
      - Per-user marker file at ${TMPDIR:-/tmp}/.appsec-verbose-<uid>
        (written by the create-threat-model skill when --verbose is passed;
        hooks cannot inherit env vars set by Bash tool calls inside a Claude
        Code session, so a filesystem marker is the only way for a skill
        to flip verbose mode on for the duration of its own run)
    """
    env = os.environ.get("APPSEC_VERBOSE", "").strip()
    if env and env not in ("0", "false", "no"):
        return True
    if _load_config().get("logging", {}).get("verbose", False):
        return True
    tmpdir = os.environ.get("TMPDIR", "/tmp")
    try:
        uid = os.getuid()
    except AttributeError:
        uid = 0
    marker = os.path.join(tmpdir, f".appsec-verbose-{uid}")
    return os.path.exists(marker)


_VERBOSE = _is_verbose()


# ---------------------------------------------------------------------------
# Tracing mode — per-agent token/turn breakdown to .appsec-trace.log
# ---------------------------------------------------------------------------
def _is_tracing() -> bool:
    """Check whether --tracing mode is active.

    Enabled by:
      - Environment variable APPSEC_TRACING=1 (or any truthy value)
      - Per-user marker file at ${TMPDIR:-/tmp}/.appsec-tracing-<uid>
        (written by the create-threat-model skill when --tracing is passed)
    """
    env = os.environ.get("APPSEC_TRACING", "").strip()
    if env and env not in ("0", "false", "no"):
        return True
    tmpdir = os.environ.get("TMPDIR", "/tmp")
    try:
        uid = os.getuid()
    except AttributeError:
        uid = 0
    marker = os.path.join(tmpdir, f".appsec-tracing-{uid}")
    return os.path.exists(marker)


_TRACING = _is_tracing()


def _output_dir() -> str:
    """Resolve the appsec output directory.

    Preference order:
      1. OUTPUT_DIR environment variable (set by the skill dispatch).
      2. cwd itself when it already ends in docs/security — prevents the
         nested docs/security/docs/security/ path that appears when a hook
         fires from a session whose cwd is already inside the output dir.
      3. cwd + /docs/security (legacy default).
    """
    env = os.environ.get("OUTPUT_DIR")
    if env:
        return env
    cwd = os.getcwd()
    norm = cwd.replace("\\", "/").rstrip("/")
    if norm.endswith("/docs/security") or norm == "docs/security":
        return cwd
    return os.path.join(cwd, "docs", "security")


def _trace_path() -> str:
    """Return path to .appsec-trace.log (separate from .hook-events.log)."""
    log_dir = _output_dir()
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, ".appsec-trace.log")


# --------------------------------------------------------------------------
# Checkpoint-abort marker for unclean orchestrator stops
# --------------------------------------------------------------------------
# Stop-reason values that the Claude Code harness emits on a clean completion.
# Anything else (unknown, cancelled, max_turns, error, …) indicates the
# orchestrator did NOT reach the Phase 11 `status=completed` write, so the
# on-disk checkpoint lies about the run state. We rewrite it to reflect the
# abort so the next pre-flight treats it as cleanable without a 1-hour wait.
_CLEAN_STOP_REASONS = {"end_turn", "stop_sequence"}


def _mark_checkpoint_aborted_if_dirty(stop_reason: str) -> str | None:
    """Rewrite `$OUTPUT_DIR/.appsec-checkpoint` to status=aborted on unclean stop.

    Returns the ``phase`` of the checkpoint it transitioned to ``aborted`` (so
    the caller can emit a SESSION_ABORTED_MIDRUN event), or ``None`` when it made
    no change.

    No-op (returns ``None``) when:
      * the checkpoint file does not exist (run never reached Phase 1, or
        already cleaned),
      * its current status is `completed` (clean finalization),
      * the stop_reason is on the whitelist of clean completions.

    Best-effort — failures are swallowed because this runs inside a hook and
    must never break the Stop event.
    """
    if stop_reason in _CLEAN_STOP_REASONS:
        return None
    try:
        cp_path = os.path.join(_output_dir(), ".appsec-checkpoint")
        if not os.path.isfile(cp_path):
            return None
        with open(cp_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
        if not raw:
            return None
        # Parse key=value pairs on a single line (or whitespace-separated).
        fields: dict[str, str] = {}
        for token in raw.split():
            if "=" in token:
                k, v = token.split("=", 1)
                fields[k.strip()] = v.strip()
        status = fields.get("status", "")
        if status in ("completed", "aborted"):
            # Already terminal — do not overwrite a legitimate final state.
            return None
        phase = fields.get("phase", "?")
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # Atomic rewrite so a concurrent reader never sees a half-written line.
        try:
            # Defer import to avoid a hard dependency cycle at module import time.
            from _atomic_io import atomic_write_text  # type: ignore

            atomic_write_text(
                cp_path,
                f"phase={phase} status=aborted reason={stop_reason} aborted_at={ts}\n",
            )
        except Exception:
            # Fall back to direct write — worse-case same behaviour as the
            # pre-atomic code, still better than leaving a stale status=started.
            with open(cp_path, "w", encoding="utf-8") as fh:
                fh.write(f"phase={phase} status=aborted reason={stop_reason} aborted_at={ts}\n")
        return phase
    except Exception:
        # Never let a hook crash the session. The worst-case regression is
        # the pre-existing behaviour (status=started lingers until auto-clean).
        pass
    return None


def _write_trace(event: str, detail: str, sid: str = "") -> None:
    """Append a structured line to .appsec-trace.log when tracing is active."""
    if not _TRACING:
        return
    line = format_line(event, detail, level="TRACE", sid=sid)
    try:
        trace_file = _trace_path()
        _rotate_if_needed(trace_file)
        with open(trace_file, "a") as fh:
            fh.write(line)
    except Exception:
        pass  # never crash a hook


# Store for agent dispatch timestamps, keyed by sid[:8], used to compute
# wall-time per agent invocation.
#
# This MUST be disk-backed. hooks.json runs `python3 agent_logger.py` as a fresh
# process for every event, so the PreToolUse process that records the dispatch
# time and the Stop process that reads it share no memory. A plain module-level
# dict is therefore always empty at read time -- the 2026-07-20 juice-shop run
# emitted wall_secs=? on 211 of 211 AGENT_COMPLETE trace lines. The in-memory
# dict is kept as a same-process fast path; the sidecar is the source of truth.
_DISPATCH_TIMES: dict[str, float] = {}
_DISPATCH_TIMES_FILE = "dispatch-times.json"


def _dispatch_time_path() -> str:
    """Sidecar holding dispatch timestamps across hook process boundaries."""
    return os.path.join(_active_tools_dir(), _DISPATCH_TIMES_FILE)


def _read_dispatch_times() -> dict[str, float]:
    try:
        with open(_dispatch_time_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return {k: float(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except Exception:
        return {}


def _record_dispatch_time(key: str, when: float) -> None:
    """Persist one dispatch timestamp; best-effort and never raises."""
    _DISPATCH_TIMES[key] = when
    try:
        os.makedirs(_active_tools_dir(), exist_ok=True)
        times = _read_dispatch_times()
        times[key] = when
        # Bound growth: a run has far fewer than 200 dispatches.
        if len(times) > 200:
            times = dict(sorted(times.items(), key=lambda kv: kv[1])[-200:])
        path = _dispatch_time_path()
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(times, fh)
        os.replace(tmp, path)
    except Exception:
        pass


def _take_dispatch_time(key: str) -> float | None:
    """Pop a dispatch timestamp, preferring the sidecar over in-process state."""
    when = _DISPATCH_TIMES.pop(key, None)
    try:
        times = _read_dispatch_times()
        if key in times:
            when = times.pop(key)
            path = _dispatch_time_path()
            tmp = f"{path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(times, fh)
            os.replace(tmp, path)
    except Exception:
        pass
    return when


def _take_dispatch_time_for_agent(agent_short: str) -> float | None:
    """Pop the OLDEST pending dispatch timestamp recorded for ``agent_short``.

    The sid-keyed lookup above cannot work for a subagent: the timestamp is
    recorded in the PreToolUse hook under the *parent* session id, while the
    Stop hook runs in the *child* session under a different id, so the key
    never matched and `wall_secs` stayed `?` for every dispatched agent
    (juice-shop 2026-07-24). The agent short name is derived identically at
    both ends, which makes it the one key both sides share.

    Timestamps are stored under ``agent:<short>:<ts>`` so that a parallel
    fan-out (8 concurrent STRIDE analyzers) keeps one entry per dispatch;
    popping the oldest matches them FIFO. With equal-duration siblings that is
    exact, and with uneven ones it still bounds the true value — far better
    than reporting nothing."""
    if not agent_short:
        return None
    prefix = f"agent:{agent_short}:"
    try:
        times = _read_dispatch_times()
    except Exception:
        return None
    keys = sorted((k for k in times if k.startswith(prefix)), key=lambda k: times[k])
    if not keys:
        return None
    key = keys[0]
    when = times.pop(key)
    _DISPATCH_TIMES.pop(key, None)
    try:
        path = _dispatch_time_path()
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(times, fh)
        os.replace(tmp, path)
    except Exception:
        pass
    return when


# ---------------------------------------------------------------------------
# Log rotation — rotate when file exceeds threshold
# ---------------------------------------------------------------------------
_MAX_LOG_BYTES = 5 * 1024 * 1024  # 5 MB default


def _load_max_log_bytes() -> int:
    """Load max log size from plugin config.json."""
    return _load_config().get("logging", {}).get("max_log_bytes", _MAX_LOG_BYTES)


def _rotate_if_needed(log_file: str) -> None:
    """Rotate log file if it exceeds the configured size limit."""
    try:
        if not os.path.exists(log_file):
            return
        size = os.path.getsize(log_file)
        max_bytes = _load_max_log_bytes()
        if size > max_bytes:
            # Keep up to 2 rotated copies
            rotated_2 = log_file + ".2"
            rotated_1 = log_file + ".1"
            if os.path.exists(rotated_2):
                os.remove(rotated_2)
            if os.path.exists(rotated_1):
                os.rename(rotated_1, rotated_2)
            os.rename(log_file, rotated_1)
    except Exception:
        pass  # never crash a hook


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _agent_model(subtype: str, tool_input: dict) -> str:
    """Return the model name for an agent invocation.

    Priority:
      1. Explicit 'model' field in tool_input (runtime override)
      2. 'model:' frontmatter in CLAUDE_PLUGIN_ROOT/agents/<name>.md
      3. '?' if not determinable
    """
    override = tool_input.get("model")
    if override:
        return str(override)

    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if plugin_root:
        short = subtype.split(":")[-1] if ":" in subtype else subtype
        agent_file = os.path.join(plugin_root, "agents", f"{short}.md")
        try:
            with open(agent_file) as fh:
                head = fh.read(4096)
            m = re.search(r"^model:\s*(\S+)", head, re.MULTILINE)
            if m:
                return m.group(1)
        except (OSError, UnicodeDecodeError):
            pass

    return "?"


def _calc_cost(usage: dict) -> float:
    """Return estimated USD cost from a Stop-event usage dict."""
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    cw = usage.get("cache_creation_input_tokens", 0)
    cr = usage.get("cache_read_input_tokens", 0)
    return (
        inp * _PRICING["input"] / 1_000_000
        + out * _PRICING["output"] / 1_000_000
        + cw * _PRICING["cache_write"] / 1_000_000
        + cr * _PRICING["cache_read"] / 1_000_000
    )


def _log_path() -> str:
    log_dir = _output_dir()
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, ".hook-events.log")


def _agent_run_log_path() -> str:
    """Return the path to .agent-run.log (written by agents, mirrored for key events)."""
    return os.path.join(_output_dir(), ".agent-run.log")


def _write_agent_run(level: str, agent: str, event: str, detail: str) -> None:
    """Append a line to .agent-run.log mirroring critical hook events.

    This bridges the gap between hook-events.log (written by this script)
    and agent-run.log (written by agents via Bash). Key events like
    MAX_TURNS and SESSION_STOP are duplicated so the agent-run.log is
    self-contained for diagnostics.
    """
    line = format_line(event, detail, level=level, component=agent)
    try:
        log_file = _agent_run_log_path()
        if os.path.exists(log_file):
            with open(log_file, "a") as fh:
                fh.write(line)
    except Exception:
        pass  # never crash a hook


# Map subagent_type identifiers to short agent names for .agent-run.log
_AGENT_SHORT_NAMES = {
    "appsec-threat-analyst": "threat-analyst",
    "appsec-context-resolver": "context-resolver",
    "appsec-recon-scanner": "recon-scanner",
    "appsec-dep-scanner": "dep-scanner",
    "appsec-stride-analyzer": "stride-analyzer",
    "appsec-qa-reviewer": "qa-reviewer",
}


def _short_agent_name(subtype: str) -> str:
    """Canonical log name for a plugin-owned Agent subtype."""
    raw = subtype.split(":")[-1]
    if raw in _AGENT_SHORT_NAMES:
        return _AGENT_SHORT_NAMES[raw]
    if raw.startswith("appsec-"):
        return raw.removeprefix("appsec-")
    return ""


def _session_map_path() -> str:
    """Path to the lightweight session→agent mapping file."""
    return os.path.join(_output_dir(), ".session-agent-map")


def _save_session_agent(sid: str, agent: str) -> None:
    """Persist a session_id → agent_name mapping for SESSION_STOP attribution.

    Serialize the bounded read-modify-write so concurrent Agent dispatch hooks
    cannot replace one another's registrations.
    """
    try:
        import fcntl

        map_file = _session_map_path()
        os.makedirs(os.path.dirname(map_file), exist_ok=True)
        with open(map_file, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            fh.seek(0)
            lines = fh.readlines()[-19:]
            lines.append(f"{sid}={agent}\n")
            fh.seek(0)
            fh.truncate()
            fh.writelines(lines)
            fh.flush()
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass  # never crash a hook


def _lookup_session_agent_registrations(sid: str) -> list[str]:
    """Every agent registration for ``sid``, oldest first."""
    registrations: list[str] = []
    try:
        map_file = _session_map_path()
        if not os.path.exists(map_file):
            return registrations
        with open(map_file, encoding="utf-8") as fh:
            for line in fh:
                parts = line.strip().split("=", 1)
                if len(parts) == 2 and parts[0] == sid:
                    registrations.append(parts[1])
    except Exception:
        pass
    return registrations


def _lookup_session_agents(sid: str) -> list[str]:
    """Every distinct agent registered for ``sid``, oldest first.

    Sub-agents inherit the parent's ``session_id``, so this map is one-to-many
    per run: an assessment registers ``threat-analyst``, ``recon-scanner``,
    ``stride-analyzer`` (once per dispatch) and so on under a single key. The
    hook payload carries no sub-agent identifier, so the individual entries
    cannot be told apart from a tool call alone.
    """
    seen: list[str] = []
    for agent in _lookup_session_agent_registrations(sid):
        if agent not in seen:
            seen.append(agent)
    return seen


def _lookup_session_agent(sid: str) -> str:
    """Most recently registered agent for a session_id. '' if not found.

    2026-08-02: this returned the FIRST match, so once ``threat-analyst`` was
    registered for a run every later lookup answered ``threat-analyst`` forever
    -- every STRIDE dispatch was mis-attributed, and the assessment trace
    repeated one stale record for all 20 agent completions. Most-recent is the
    best available answer; during a parallel wave several same-type dispatches
    are genuinely indistinguishable, which is why budget decisions must NOT rely
    on this (see ``_budget_scope_agent``).
    """
    agents = _lookup_session_agents(sid)
    return agents[-1] if agents else ""


def _session_agent_label(sid: str) -> str:
    """Honest telemetry label when hook events share one session ID."""
    registrations = _lookup_session_agent_registrations(sid)
    if not registrations:
        return ""
    if len(registrations) > 1:
        return "shared-session"
    return registrations[0]


def _budget_scope_agent(sid: str) -> str | None:
    """Agent whose maxTurns bounds a single-agent session counter.

    The counter aggregates the orchestrator's calls and every concurrent
    sub-agent's calls, because they all arrive under one ``session_id``. Once a
    second dispatch is registered, no individual maxTurns value can bound that
    shared total. Return ``None`` so the caller clears and disables the shared
    watchdog for that session.

    Per-sub-agent budgeting is therefore NOT enforced here -- it cannot be, with
    the fields hooks receive. It is enforced by the analyzer's harness
    ``maxTurns`` ceiling and its Step-2 read budget instead.
    """
    registrations = _lookup_session_agent_registrations(sid)
    if not registrations:
        return ""
    if len(registrations) > 1:
        return None
    return registrations[0]


# ---------------------------------------------------------------------------
# Active tool-call tracking (M3.6 #2 + #4) — per-file marker of in-flight
# tool calls so /appsec-advisor:status --live can answer "what is happening
# right now?" without parsing the entire .hook-events.log.
#
# Per-file (one ``<tool_use_id>.json`` per call) instead of a shared JSON
# eliminates the lost-update race on parallel hook processes — no fcntl
# needed, no atomic-rename ceremony.
#
# Design note — sub-agent visibility limit. PreToolUse fires in every
# session depth (sub-agents included), but PostToolUse only fires in the
# outermost session for the Agent tool, and is only reliably visible
# top-level for other tools. Sub-agent tool calls therefore get a Pre
# entry but may not get a Post cleanup. The status reader compensates by
# expiring entries older than the phase-aware stall threshold from
# data/phase-budgets.yaml — a stale Pre entry never blocks the live view.
# ---------------------------------------------------------------------------

_ACTIVE_TOOLS_DIR = ".active-tool-calls"


def _active_tools_dir() -> str:
    return os.path.join(_output_dir(), _ACTIVE_TOOLS_DIR)


def _active_tool_path(tool_use_id: str) -> str:
    """Per-call file path. Caller has already validated tool_use_id."""
    safe = "".join(c for c in (tool_use_id or "") if c.isalnum() or c in "-_")
    if not safe:
        safe = "anon"
    return os.path.join(_active_tools_dir(), f"{safe[:64]}.json")


def _path_redact_enabled() -> bool:
    """Opt-in: replace concrete file paths in logs with a stable hash.

    Enabled when ``APPSEC_LOG_REDACT_PATHS`` is truthy. Useful when the
    log file leaves the reviewer's machine and ``.agent-run.log``
    entries like ``FILE_WRITE /path/to/secrets.ts`` would otherwise
    reveal sensitive filenames.
    """
    return os.environ.get("APPSEC_LOG_REDACT_PATHS", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _redact_path(path_str: str) -> str:
    """Replace an absolute path with ``<basename>:<sha8>`` while keeping
    enough signal for log correlation and debugging."""
    if not path_str:
        return path_str
    try:
        import hashlib

        digest = hashlib.sha256(path_str.encode("utf-8", errors="replace")).hexdigest()[:8]
    except Exception:
        digest = "????????"
    base = os.path.basename(path_str.rstrip("/")) or "path"
    return f"<redacted:{base}:{digest}>"


def _summarise_tool_input(tool: str, inp: dict, max_len: int = 160) -> str:
    """One-line summary of a tool call's payload — never exposes secrets.

    Uses the existing ``_mask_secrets`` + ``_clip`` helpers so any token /
    credential in a Bash command body or Read path is redacted before it
    lands on disk. When ``APPSEC_LOG_REDACT_PATHS`` is set, file paths
    in Read/Write/Edit summaries are additionally replaced with a
    deterministic hash so the log carries no sensitive filenames.
    """
    if not isinstance(inp, dict):
        return ""
    if tool == "Bash":
        return _mask_secrets(_clip(str(inp.get("command", "")), max_len))
    if tool in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        raw = str(inp.get("file_path", ""))
        if _path_redact_enabled():
            raw = _redact_path(raw)
        return _mask_secrets(_clip(raw, max_len))
    if tool == "Agent":
        subtype = inp.get("subagent_type", "")
        desc = _plain_log_text(inp.get("description", ""))
        return _mask_secrets(_clip(f"{subtype}: {desc}", max_len))
    if tool == "Grep":
        return _mask_secrets(_clip(str(inp.get("pattern", "")), max_len))
    if tool == "Glob":
        return _mask_secrets(_clip(str(inp.get("pattern", "")), max_len))
    return ""


def _record_tool_start(data: dict, sid: str) -> None:
    """Write ``.active-tool-calls/<tool_use_id>.json`` at PreToolUse.

    Best-effort — any failure is silently swallowed so the run is never
    broken by an observability artifact write. Skipped when ``tool_use_id``
    is missing (some Claude Code harness paths emit Pre events without an
    ID; those calls are invisible to the live view by design).
    """
    try:
        tool_use_id = (data.get("tool_use_id") or "").strip()
        if not tool_use_id:
            return
        d = _active_tools_dir()
        os.makedirs(d, exist_ok=True)
        tool = data.get("tool_name", "?")
        inp = data.get("tool_input", {}) or {}
        if tool == "Agent":
            subtype = str(inp.get("subagent_type", ""))
            agent = _short_agent_name(subtype) or subtype.split(":")[-1]
            _retire_superseded_context_v2_agent_calls((sid or "")[:8], agent)
        else:
            agent = _session_agent_label((sid or "")[:8]) or ""
        record = {
            "tool_use_id": tool_use_id,
            "session_id": (sid or "")[:8],
            "agent": agent,
            "tool": tool,
            "background": bool(inp.get("run_in_background", False)) if tool == "Agent" else False,
            "started_at": int(time.time()),
            "input_summary": _summarise_tool_input(tool, inp),
        }
        with open(_active_tool_path(tool_use_id), "w", encoding="utf-8") as fh:
            json.dump(record, fh)
    except Exception:
        pass


def _retire_superseded_context_v2_agent_calls(sid: str, next_agent: str) -> None:
    """Remove foreground markers made obsolete by a later v2 role dispatch.

    Current Claude Code builds do not reliably emit PostToolUse for nested
    Agent calls. Context-v2 dispatches different semantic roles sequentially,
    while parallel waves use one shared role. A later different foreground
    role therefore proves that an older role returned; equal-role markers are
    retained so STRIDE and abuse fan-outs remain visible.
    """
    if not sid or not next_agent:
        return
    try:
        config = json.loads(Path(_output_dir(), ".skill-config.json").read_text(encoding="utf-8"))
        if config.get("runtime_generation") != "context-v2":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(_active_tools_dir(), flags)
    except (OSError, ValueError):
        return
    try:
        with os.scandir(directory_fd) as entries:
            for marker in entries:
                if not marker.name.endswith(".json") or not marker.is_file(follow_symlinks=False):
                    continue
                try:
                    marker_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                    marker_fd = os.open(marker.name, marker_flags, dir_fd=directory_fd)
                    with os.fdopen(marker_fd, encoding="utf-8") as handle:
                        entry = json.load(handle)
                except (OSError, ValueError):
                    continue
                if (
                    entry.get("tool") == "Agent"
                    and entry.get("session_id") == sid
                    and not entry.get("background", False)
                    and entry.get("agent")
                    and entry.get("agent") != next_agent
                ):
                    try:
                        os.unlink(marker.name, dir_fd=directory_fd)
                    except OSError:
                        pass
    except OSError:
        pass
    finally:
        try:
            os.close(directory_fd)
        except OSError:
            pass


def _record_tool_end(data: dict) -> int:
    """Remove the per-call marker at PostToolUse and return the matching
    `started_at` epoch (0 if no manifest was found). Idempotent.

    The returned value lets callers compute tool-call duration without a
    second filesystem read. Diagnostic events (FILE_READ, GREP_RUN, etc.)
    append a `dur=<seconds>` suffix when the manifest could be located.
    """
    started_at = 0
    try:
        tool_use_id = (data.get("tool_use_id") or "").strip()
        if not tool_use_id:
            return 0
        path = _active_tool_path(tool_use_id)
        try:
            with open(path, encoding="utf-8") as fh:
                started_at = int(json.load(fh).get("started_at", 0))
        except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
            pass
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    except Exception:
        pass
    return started_at


def clear_terminal_active_tool_calls(output_dir: str | Path | None = None) -> None:
    """Remove live-only call state after the outer session has terminated.

    Sub-agent PreToolUse hooks do not reliably receive matching PostToolUse
    events. Their markers are useful while the run is live, but retaining them
    after the terminal outer Stop or controller abort makes preserved-runtime
    diagnostics report work that can no longer be active.
    """
    destination = os.fspath(output_dir) if output_dir is not None else _output_dir()
    try:
        events = agent_lifecycle.fail_all_running(destination, "outer_session_terminal")
        agent_lifecycle.append_events(destination, events)
        if events:
            from budget_watchdog import close_call

            for event in events:
                close_call(str(event.call.get("agent_call_id") or ""), destination)
    except Exception:
        pass
    directory = os.path.join(destination, _ACTIVE_TOOLS_DIR)
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(directory, flags)
    except OSError:
        try:
            if os.path.islink(directory):
                os.unlink(directory)
        except OSError:
            pass
        return
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if entry.is_file(follow_symlinks=False) or entry.is_symlink():
                    try:
                        os.unlink(entry.name, dir_fd=directory_fd)
                    except OSError:
                        pass
    except OSError:
        pass
    finally:
        try:
            os.close(directory_fd)
        except OSError:
            pass
    try:
        os.rmdir(directory)
    except OSError:
        pass


def _dur_suffix(started_at: int) -> str:
    """Format `dur=<seconds>s` tail when started_at is known, else empty."""
    if not started_at:
        return ""
    d = max(0, int(time.time()) - started_at)
    return f"  dur={d}s"


# Events that are ALWAYS mirrored to stderr, even without --verbose. These
# are low-volume and high-signal — the user needs to see them live to know
# the run started / finished / hit an error, without opting in to the
# full verbose firehose. Higher-volume events (FILE_WRITE, FILE_EDIT,
# AGENT_INVOKE, BASH_WARN, CONTEXT_READY) stay behind the _VERBOSE gate.
_HIGH_SIGNAL_EVENTS = frozenset(
    {
        "SCAN_START",
        "SCAN_COMPLETE",
        "TOOL_ERROR",
        "MAX_TURNS",
        "SESSION_STOP",
        "ASSESSMENT_SUMMARY",
        "BUDGET_WARN",
        "BUDGET_CRITICAL",
        "WRAP_UP_TRIGGERED",
    }
)


def _write(level: str, event: str, detail: str, sid: str = "") -> None:
    line = format_line(event, detail, level=level, sid=sid)
    try:
        log_file = _log_path()
        _rotate_if_needed(log_file)
        with open(log_file, "a") as fh:
            fh.write(line)
    except Exception:
        pass  # never crash a hook
    # Mirror to stderr when verbose is on OR when the event is high-signal.
    # High-signal events surface even on default verbosity so a user who did
    # not pass --verbose still sees scan start/end + errors in real time.
    # Errors/warnings at level=ERROR always surface regardless of event name.
    force_mirror = event.strip() in _HIGH_SIGNAL_EVENTS or level.strip() == "ERROR"
    if _VERBOSE or force_mirror:
        try:
            sys.stderr.write(f"[appsec] {line}")
            sys.stderr.flush()
        except Exception:
            pass


def _clip(s, n: int = 120) -> str:
    s = str(s).replace("\n", " ").strip()
    return s[:n] + "…" if len(s) > n else s


def _runtime_agent_id(value: object) -> str:
    """Extract Claude Code's existing agentId from a tool result."""
    if isinstance(value, dict):
        for key in ("agentId", "agent_id"):
            candidate = value.get(key)
            if isinstance(candidate, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", candidate):
                return candidate
        for child in value.values():
            candidate = _runtime_agent_id(child)
            if candidate:
                return candidate
    elif isinstance(value, list):
        for child in value:
            candidate = _runtime_agent_id(child)
            if candidate:
                return candidate
    elif isinstance(value, str):
        match = re.search(r"\bagent(?:Id|_id):\s*([A-Za-z0-9][A-Za-z0-9._:-]{0,255})", value)
        if match:
            return match.group(1)
    return ""


def _plain_log_text(value: object) -> str:
    """Normalize tool-protocol display text for one-line plaintext logs.

    Claude Code may HTML-encode an Agent description before delivering the
    hook payload. Event logs are plaintext, so retaining ``&amp;`` corrupts the
    displayed component name. Decode exactly once, then replace control
    characters (including encoded newlines) so untrusted descriptions cannot
    inject additional log records.
    """
    decoded = html.unescape(str(value or ""))
    return "".join(" " if ord(char) < 32 or ord(char) == 127 else char for char in decoded)


# Patterns that match secret values in grep output or command results.
# Each pattern captures the "prefix" group to keep and the "secret" group to mask.
_SECRET_PATTERNS = [
    # key = "value" or key = 'value'  (password, secret, token, api_key, etc.)
    re.compile(
        r"""(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"""
        r"""api[_-]?secret|auth[_-]?token|client[_-]?secret|"""
        r"""aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?)"""
        r"""([^'"\s]{4,})"""
    ),
    # JDBC connection strings: jdbc:driver://user:PASSWORD@host
    re.compile(r"(jdbc:[a-z]+://[^:]+:)([^@]+)(@)"),
    # Bearer tokens: Bearer <token> or Authorization: Bearer <token>
    re.compile(r"(?i)(bearer\s+)(\S{8,})"),
    # PEM private key blocks
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.+?)(-----END)", re.DOTALL),
]


def _mask_secrets(text: str) -> str:
    """Replace secret values with redacted versions (first 4 chars + ****)."""
    for pat in _SECRET_PATTERNS:

        def _redact(m):
            groups = m.groups()
            if len(groups) == 3:
                # jdbc or PEM: prefix + masked + suffix
                val = groups[1]
                masked = val[:4] + "****" if len(val) > 4 else "****"
                return groups[0] + masked + groups[2]
            # key=value: prefix + masked
            val = groups[1]
            masked = val[:4] + "****" if len(val) > 4 else "****"
            return groups[0] + masked

        text = pat.sub(_redact, text)
    return text


def _extract_param(text: str, key: str, max_len: int = 80) -> str:
    """Return value of KEY=<value> from a prompt string, or ''.

    The value is the first whitespace-delimited token after ``KEY=``, with
    surrounding shell/markdown delimiters stripped. Stripping matters because
    a prompt frequently embeds the assignment inside an inline-code span or a
    quoted shell command, e.g.::

        Your FIRST Bash call MUST be `export OUTPUT_DIR=/abs/docs/security`

    The naïve ``raw.split()[0]`` keeps the trailing backtick, yielding
    ``/abs/docs/security``` — a path that does not exist. When the
    PreToolUse OUTPUT_DIR-recovery feeds that to ``os.makedirs`` + the hook
    log, every ``AGENT_SPAWN`` lands in a junk ``docs/security``` directory
    instead of the run's real ``$OUTPUT_DIR/.hook-events.log``. That silently
    blinds the count-based ``check_stride_dispatch.py`` gate (2026-06-06
    juice-shop run: 0 stride spawns logged, gate false-tripped). A backtick or
    quote can never be part of a real path/identifier value, so trimming them
    is safe for every caller (OUTPUT_DIR, REPO_ROOT, COMPONENT_ID, …).
    """
    marker = f"{key}="
    if marker not in text:
        return ""
    raw = text.split(marker, 1)[1]
    # stop at first whitespace or newline
    val = raw.split()[0] if raw.split() else ""
    # Strip wrapping/trailing shell + markdown delimiters that can never be
    # part of a legitimate path or identifier value (back-tick from inline
    # code spans, quotes from shell-quoted commands, trailing punctuation).
    val = val.strip("`'\"").rstrip("`'\",;)")
    return val[:max_len]


# ---------------------------------------------------------------------------
# Tracing summary — reads .appsec-trace.log and emits per-agent table
# ---------------------------------------------------------------------------


def _write_trace_summary(sid: str) -> None:
    """Parse AGENT_DISPATCH / AGENT_COMPLETE pairs and write ASSESSMENT_TRACE.

    Emits a Markdown table to .appsec-trace.log so the user can open it after
    the run to see which agent was the most expensive.
    """
    trace_file = _trace_path()
    if not os.path.isfile(trace_file):
        return

    # Collect AGENT_DISPATCH and AGENT_COMPLETE entries (this run only:
    # look backwards from end to find the last SCAN_START boundary).
    dispatches: dict[str, dict] = {}
    completes: list[dict] = []

    try:
        with open(trace_file) as fh:
            lines = fh.readlines()

        # Find the last AGENT_DISPATCH line for each agent (most recent run)
        for line in lines:
            if "AGENT_DISPATCH" in line:
                m_agent = re.search(r"agent=(\S+)", line)
                m_model = re.search(r"model=(\S+)", line)
                m_ctx = re.search(r"context_ktok=([\d.]+)", line)
                m_max = re.search(r"max_turns=(\S+)", line)
                if m_agent:
                    agent = m_agent.group(1)
                    dispatches[agent] = {
                        "model": m_model.group(1) if m_model else "?",
                        "context_ktok": m_ctx.group(1) if m_ctx else "?",
                        "max_turns": m_max.group(1) if m_max else "?",
                    }
            elif "AGENT_COMPLETE" in line:
                m_agent = re.search(r"agent=(\S+)", line)
                m_in = re.search(r"in=([\d,]+)", line)
                m_out = re.search(r"out=([\d,]+)", line)
                m_cost = re.search(r"cost=\$([\d.]+)", line)
                m_turns = re.search(r"turns=(\S+)", line)
                m_wall = re.search(r"wall_secs=(\S+)", line)
                m_stop = re.search(r"stop=(\S+)", line)
                if m_agent:
                    completes.append(
                        {
                            "agent": m_agent.group(1),
                            "in": m_in.group(1).replace(",", "") if m_in else "0",
                            "out": m_out.group(1).replace(",", "") if m_out else "0",
                            "cost": m_cost.group(1) if m_cost else "n/a",
                            "turns": m_turns.group(1) if m_turns else "?",
                            "wall_secs": m_wall.group(1) if m_wall else "?",
                            "stop": m_stop.group(1) if m_stop else "?",
                        }
                    )
    except Exception:
        return

    if not completes:
        return

    # Build table
    rows = []
    for c in completes:
        agent = c["agent"]
        d = dispatches.get(agent, {})
        in_ktok = round(int(c["in"]) / 1000, 1) if c["in"].isdigit() else "?"
        out_ktok = round(int(c["out"]) / 1000, 1) if c["out"].isdigit() else "?"
        wall_m = (
            f"{int(c['wall_secs']) // 60}m{int(c['wall_secs']) % 60:02d}s"
            if c["wall_secs"].isdigit()
            else c["wall_secs"]
        )
        rows.append(
            f"| {agent:<28} | {d.get('model', '?'):<22} | "
            f"{d.get('context_ktok', '?'):>10} | "
            f"{str(in_ktok):>8} | {str(out_ktok):>8} | "
            f"{'$' + c['cost'] if c['cost'] != 'n/a' else 'n/a':>8} | "
            f"{c['turns']:>5}/{d.get('max_turns', '?'):<5} | "
            f"{c['stop']:<12} | {wall_m} |"
        )

    header = (
        "| Agent                        | Model                  | Ctx (ktok) | "
        "In (ktok) | Out (ktok) |    Cost | Turns    | Stop         | Wall     |\n"
        "|------------------------------|------------------------|------------|"
        "----------|------------|---------|----------|--------------|----------|\n"
    )
    table = header + "\n".join(rows)

    try:
        with open(trace_file, "a") as fh:
            fh.write(
                f"\n## ASSESSMENT_TRACE — Per-Agent Breakdown\n\n"
                f"_Generated at session end. Context (ktok) = estimated input context "
                f"size at dispatch time (~3.5 chars/token)._\n\n"
                f"{table}\n"
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Assessment summary — aggregated on outermost Stop event
# ---------------------------------------------------------------------------


def _run_lock_owner_sid() -> str:
    """Return the persisted run owner without applying a heartbeat-age test."""
    try:
        lock_path = os.path.join(_output_dir(), ".appsec-lock")
        with open(lock_path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        return lines[2].strip()[:8] if len(lines) >= 3 else ""
    except (OSError, IndexError):
        return ""


def _write_assessment_summary(sid: str) -> None:
    """Parse log files and write an aggregated ASSESSMENT_SUMMARY.

    Called once when the outermost session ends (Stop event, not SubagentStop).
    Aggregates token/cost data from all SESSION_STOP entries, collects agent
    models from AGENT_SPAWN entries, parses threat counts from threat-model.md,
    and determines mode and duration.
    """
    log_file = _log_path()
    if not os.path.exists(log_file):
        return

    # Reject ghost summaries from sessions that did not spawn the current
    # assessment.  SCAN_START writes the owner SID; if a different (older)
    # session reaches here first, its summary would aggregate stale data.
    owner_path = os.path.join(os.path.dirname(log_file), ".assessment-owner-sid")
    if os.path.exists(owner_path):
        try:
            owner_sid = open(owner_path, encoding="utf-8").read().strip()
            if sid[:8] != owner_sid:
                return
        except Exception:
            pass

    # --- Aggregate from .hook-events.log ---
    # Only aggregate lines from the CURRENT assessment run.  The log file
    # persists across runs (rotated only at 5 MB), so we must find the last
    # SCAN_START marker and ignore everything before it.
    total_in = 0
    total_out = 0
    total_cw = 0
    total_cr = 0
    total_cost = 0.0
    # SESSION_STOP lines are CUMULATIVE per-session snapshots that each session
    # re-emits on every stop/heartbeat. Bucket by session id and keep only the
    # largest (latest) cumulative snapshot per session; the post-loop rollup then
    # sums across distinct sessions. Summing every line instead multiplies the
    # true figure by the number of re-emissions (the 2026-07-02 juice-shop run
    # reported $2636 / 2.79B tokens for a run whose real per-session cumulative
    # maxed at ~$38).
    session_usage: dict[str, dict] = {}  # session key → max-cost cumulative record
    agent_models: dict[str, str] = {}  # short_name → model
    threat_model_path = ""
    written_files: list[str] = []  # all FILE_WRITE paths (deduplicated later)
    first_ts = ""
    last_ts = ""

    try:
        with open(log_file) as fh:
            all_lines = fh.readlines()

        # Anchor the run boundary on the FIRST SCAN_START of the *current*
        # session. The threat-analyst is dispatched once per stage (Stage 1
        # plus a Stage-3 repair re-dispatch), so SCAN_START fires multiple
        # times with the SAME session id within one logical run. The previous
        # logic took the LAST SCAN_START, which truncated both the measured
        # duration and the token rollup to only the final stage — the
        # 2026-06-03 juice-shop run (true wall-clock ~60m) was reported as
        # 9m 14s because its repair re-dispatch fired SCAN_START at +50m.
        # Everything before the current session's first SCAN_START belongs to
        # an earlier (different-session) run in the persistent log and stays
        # excluded; we fall back to the last SCAN_START when no line carries
        # this session id.
        sid8 = (sid or "")[:8]
        scan_start_idx = 0
        first_owned_idx = None
        last_scan_idx = 0
        for idx, line in enumerate(all_lines):
            if "SCAN_START" in line:
                last_scan_idx = idx
                if first_owned_idx is None and sid8 and f"[{sid8}" in line:
                    first_owned_idx = idx
        scan_start_idx = first_owned_idx if first_owned_idx is not None else last_scan_idx

        for line in all_lines[scan_start_idx:]:
            # Track timestamps for duration
            ts_m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", line)
            if ts_m:
                if not first_ts:
                    first_ts = ts_m.group(1)
                last_ts = ts_m.group(1)

            # Collect the CUMULATIVE SESSION_STOP snapshot per session — deduped
            # to the max-cost record so re-emitted running totals are not summed
            # repeatedly (see session_usage note above). Rolled up after the loop.
            if "SESSION_STOP" in line:
                sid_m = re.search(r"\[([0-9a-fA-F-]{8})\]", line)
                # Un-attributable lines ([--------] or none) cannot be deduped by
                # session, so give each its own key to preserve prior summing.
                if sid_m and sid_m.group(1) != "--------":
                    sess_key = sid_m.group(1)
                else:
                    sess_key = f"_anon{len(session_usage)}"

                def _num(pat: str) -> int:
                    mm = re.search(pat, line)
                    return int(mm.group(1).replace(",", "")) if mm else 0

                cost_m = re.search(r"cost=\$([\d.]+)", line)
                rec = {
                    "in": _num(r"in=([\d,]+)"),
                    "out": _num(r"out=([\d,]+)"),
                    "cw": _num(r"cache_write=([\d,]+)"),
                    "cr": _num(r"cache_read=([\d,]+)"),
                    "cost": float(cost_m.group(1)) if cost_m else 0.0,
                }
                prev = session_usage.get(sess_key)
                if prev is None or rec["cost"] >= prev["cost"]:
                    session_usage[sess_key] = rec

            # Collect agent → model from AGENT_SPAWN
            # AGENT_SPAWN lines look like:
            #   AGENT_SPAWN  appsec-advisor:appsec-threat-analyst  model=sonnet  ...
            # The old regex r"(appsec-[\w-]+)" matched the registry prefix
            # `appsec-advisor` instead of the actual agent name after the colon,
            # which caused ASSESSMENT_MODELS to collapse every agent into a
            # single "appsec-advisor" entry (missing from _AGENT_SHORT_NAMES so
            # the fallback printed the raw prefix) or, when AGENT_SPAWN lines
            # were absent between SCAN_START and the summary, to print
            # "agents: none detected".
            if "AGENT_SPAWN" in line:
                agent_m = re.search(r"(?:appsec-advisor:)?(appsec-[\w-]+)", line)
                model_m = re.search(r"model=(\S+)", line)
                if agent_m and model_m:
                    raw = agent_m.group(1)
                    short = _AGENT_SHORT_NAMES.get(raw, raw)
                    agent_models[short] = model_m.group(1)

            # Collect all FILE_WRITE paths
            if "FILE_WRITE" in line:
                m = re.search(r"FILE_WRITE\s+(\S+)", line)
                if m:
                    written_files.append(m.group(1))
                if "threat-model.md" in line:
                    m2 = re.search(r"FILE_WRITE\s+(\S+threat-model\.md)", line)
                    if m2:
                        threat_model_path = m2.group(1)

        # Roll up the per-session cumulative maxima into the run totals.
        for rec in session_usage.values():
            total_in += rec["in"]
            total_out += rec["out"]
            total_cw += rec["cw"]
            total_cr += rec["cr"]
            total_cost += rec["cost"]
    except Exception:
        pass

    # --- Duration ---
    duration = "?"
    duration_secs: int | None = None
    if first_ts and last_ts:
        try:
            t1 = datetime.strptime(first_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            t2 = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            secs = int((t2 - t1).total_seconds())
            duration = f"{secs // 60}m {secs % 60:02d}s"
            duration_secs = secs
        except Exception:
            pass

    # --- Mode and per-phase durations from .agent-run.log ---
    mode = "full"
    phase_starts: dict[str, str] = {}  # phase_key → ISO timestamp
    phase_durations: list[tuple[str, int]] = []  # (phase_label, seconds)
    # Idle accounting: the skill_watchdog logs RUN_RESUMED with the peak idle
    # of each resolved stall ("...after {N}s idle"). Summing them gives the
    # wall-clock the run spent waiting on slow/standard-tier API responses, so
    # the summary can report honest active time (active ≈ wall − idle). An
    # unresolved trailing RUN_IDLE (watchdog killed before activity resumed)
    # contributes its last reported idle as a conservative floor.
    idle_secs_total = 0
    run_idle_count = 0
    run_resumed_count = 0
    last_run_idle_secs = 0
    try:
        arl = _agent_run_log_path()
        if os.path.exists(arl):
            with open(arl) as fh:
                for line in fh:
                    if "ASSESSMENT_START" in line:
                        if "incremental" in line.lower():
                            mode = "incremental"
                        elif "dry-run" in line.lower():
                            mode = "dry-run"

                    if "RUN_RESUMED" in line:
                        mr = re.search(r"after\s+(\d+)s\s+idle", line)
                        if mr:
                            idle_secs_total += int(mr.group(1))
                            run_resumed_count += 1
                        continue
                    if "RUN_IDLE" in line:
                        mi = re.search(r"no run activity for\s+(\d+)s", line)
                        if mi:
                            last_run_idle_secs = int(mi.group(1))
                            run_idle_count += 1
                        continue

                    # Collect PHASE_START/PHASE_END pairs for per-phase timing.
                    # Format: "... PHASE_START   [Phase N/11] <label>…"
                    #         "... PHASE_END     [Phase N/11] <label> …"
                    ps = re.search(
                        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*PHASE_START\s+\[(Phase \S+)\]",
                        line,
                    )
                    if ps:
                        phase_starts[ps.group(2)] = ps.group(1)
                        continue
                    pe = re.search(
                        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*PHASE_END\s+\[(Phase \S+)\]\s*(.*)",
                        line,
                    )
                    if pe:
                        key = pe.group(2)
                        end_ts = pe.group(1)
                        label = pe.group(3).split("—")[0].split("–")[0].strip().rstrip("…")
                        start_ts = phase_starts.get(key)
                        if start_ts:
                            try:
                                t_s = datetime.strptime(start_ts, "%Y-%m-%dT%H:%M:%SZ")
                                t_e = datetime.strptime(end_ts, "%Y-%m-%dT%H:%M:%SZ")
                                secs = int((t_e - t_s).total_seconds())
                                phase_durations.append((f"{key} {label}".strip(), secs, start_ts, end_ts))
                            except Exception:
                                pass
    except Exception:
        pass

    # Unresolved trailing stall: more RUN_IDLE than RUN_RESUMED means the
    # watchdog was killed mid-stall. Add the last reported idle as a floor so
    # the active-time estimate is not silently optimistic.
    if run_idle_count > run_resumed_count and last_run_idle_secs:
        idle_secs_total += last_run_idle_secs

    # --- Smear batched phase timestamps (F3 fix, 2026-04-25) ---
    #
    # When the orchestrator batches multiple PHASE_START/PHASE_END entries onto
    # the same second (legal for Phases 5+6+7 per phase-group-architecture.md
    # design, but also seen as a regression for Phases 3-8 in Run 4), every
    # batched phase ends up with `secs=0` because start_ts == end_ts at
    # second resolution. The Run Statistics appendix then shows misleading
    # zeros for the entire architecture phase group.
    #
    # Fix: when N phases share an identical (start_ts, end_ts) pair, the
    # batch took some real wall-clock duration that we can recover by looking
    # at the gap between this batch and the next *non-batched* PHASE_START or
    # PHASE_END elsewhere in the log. We approximate by spreading the group's
    # total elapsed seconds across the N phases. The total is computed as the
    # delta between the batch's start_ts and the next dissimilar timestamp
    # downstream — usually the first event of the *next* phase or sub-agent
    # invocation. If we cannot find a downstream event we leave the durations
    # as-is (the user gets honest zeros rather than fabricated numbers).
    #
    # The smear divides the recovered gap evenly across the batched phases.
    # That is an approximation: phases inside a batch may have run for very
    # different amounts of work. But "all phases share roughly equal share of
    # the batch's wall-clock" is a far more accurate report than "all phases
    # took 0 seconds."
    if phase_durations:
        from collections import defaultdict

        by_endpoints: dict[tuple[str, str], list[int]] = defaultdict(list)
        for idx, (_, secs, sts, ets) in enumerate(phase_durations):
            if secs == 0 and sts == ets:
                by_endpoints[(sts, ets)].append(idx)
        for (sts, _ets), indices in by_endpoints.items():
            if len(indices) <= 1:
                continue  # single 0s phase isn't a batch — leave it
            # Find the next event timestamp strictly after `sts` in the
            # collected phase list. Use the next phase's start_ts (or end_ts
            # if start was also batched) — both are post-batch.
            try:
                start_dt = datetime.strptime(sts, "%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                continue
            next_dt = None
            for jdx, (_, _s2, sts2, ets2) in enumerate(phase_durations):
                if jdx in indices:
                    continue
                for cand in (sts2, ets2):
                    try:
                        cand_dt = datetime.strptime(cand, "%Y-%m-%dT%H:%M:%SZ")
                    except Exception:
                        continue
                    if cand_dt > start_dt:
                        if next_dt is None or cand_dt < next_dt:
                            next_dt = cand_dt
                        break
            if next_dt is None:
                continue
            total_secs = max(0, int((next_dt - start_dt).total_seconds()))
            if total_secs == 0:
                continue
            per_phase = max(1, total_secs // len(indices))
            for idx in indices:
                label, _, sts3, ets3 = phase_durations[idx]
                phase_durations[idx] = (label, per_phase, sts3, ets3)

    # Strip the auxiliary timestamp tuple slots before downstream code that
    # expects (label, secs) two-tuples. Keep the in-function variable as 4-tuples
    # for readability; emit a 2-tuple list for the existing emitter below.
    phase_durations = [(label, secs) for (label, secs, *_rest) in phase_durations]

    # --- Threat counts ---
    #
    # Canonical source: threat-model.yaml's `threats[]` (or `findings[]` /
    # `threat_categories[].findings[]` depending on schema version). The yaml
    # is what compose_threat_model.py wrote and what `validate_intermediate.py`
    # has already accepted — counting from it is single-truth.
    #
    # The 2026-04-25 juice-shop Run 4 surfaced why the previous Markdown-emoji
    # heuristic was wrong: a single threat appears in MULTIPLE tables (Threat
    # Register, Mitigations Register, Architectural Risks, per-component cells)
    # all of which carry the `🔴 Critical` badge text. Counting badge-bearing
    # rows produced an inflated 64-threat / 33-Critical total when the actual
    # canonical count was 33 / 7 (run-end Phase 9 PHASE_END agreed). Reading
    # from yaml drops the inflation entirely and the total matches the merger.
    #
    # Fall back to the old Markdown heuristic only when yaml is missing
    # (legacy runs, dry-run paths) so existing tests do not regress.
    threats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_threats = 0
    counted_from = "none"

    # M3.4 fix — threat-model.yaml lookup MUST NOT depend on a FILE_WRITE
    # hook event for threat-model.md being present in the log. Since M2.10
    # threat-model.md is written by compose_threat_model.py (a Python
    # subprocess), which does NOT trigger Claude's FILE_WRITE hooks. As a
    # result, the previous threat_model_path-derivation chain stayed empty
    # → yaml lookup skipped → ASSESSMENT_SUMMARY reported threats=0 even
    # when threat-model.yaml had 30 valid threats on disk (verified on the
    # 2026-04-27 18:31Z juice-shop run).
    #
    # Fix: derive yaml_path directly from the deterministic OUTPUT_DIR
    # (which is always known via _output_dir() / config). Fall back to the
    # FILE_WRITE-derived path only as a secondary signal.
    yaml_path = ""
    output_dir = _output_dir()
    if output_dir:
        candidate = os.path.join(output_dir, "threat-model.yaml")
        if os.path.exists(candidate):
            yaml_path = candidate
    if not yaml_path and threat_model_path:
        candidate = threat_model_path.replace("threat-model.md", "threat-model.yaml")
        if os.path.exists(candidate):
            yaml_path = candidate

    if yaml_path:
        try:
            import yaml as _yaml  # type: ignore

            with open(yaml_path) as fh:
                _data = _yaml.safe_load(fh) or {}
            findings_list: list = []
            # v2 schema: top-level threat_categories[].findings[]
            for cat in _data.get("threat_categories", []) or []:
                if isinstance(cat, dict):
                    findings_list.extend(cat.get("findings", []) or [])
            # v1 schema fallback: top-level threats[]
            if not findings_list:
                findings_list = list(_data.get("threats", []) or [])
            # v1 fallback #2: top-level findings[]
            if not findings_list:
                findings_list = list(_data.get("findings", []) or [])
            for item in findings_list:
                if not isinstance(item, dict):
                    continue
                sev = item.get("severity") or item.get("risk") or item.get("effective_severity") or ""
                sev = str(sev).strip().capitalize()
                if sev in threats:
                    threats[sev] += 1
            total_threats = sum(threats.values())
            if total_threats > 0:
                counted_from = "yaml"
        except Exception:
            # Yaml read failed — fall through to Markdown heuristic.
            pass

    if counted_from != "yaml" and threat_model_path and os.path.exists(threat_model_path):
        try:
            with open(threat_model_path) as fh:
                lines = fh.readlines()
            # Markdown heuristic — known to over-count when threats are
            # cross-referenced across tables. Used only as a last-resort
            # fallback when yaml is missing.
            _EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            for sev, emoji in _EMOJI.items():
                badge = f"{emoji} {sev}"
                threats[sev] = sum(1 for ln in lines if ln.startswith("|") and badge in ln)
            total_threats = sum(threats.values())
            if total_threats > 0:
                counted_from = "md_heuristic"
        except Exception:
            pass

    # --- Billing model ---
    is_api = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())

    # --- Plugin version metadata (best-effort, never crash) ---
    plugin_version = "unknown"
    analysis_version = "?"
    try:
        plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
        if plugin_root:
            pj = os.path.join(plugin_root, ".claude-plugin", "plugin.json")
            if os.path.exists(pj):
                with open(pj) as fh:
                    pjdata = json.load(fh)
                plugin_version = str(pjdata.get("version", "unknown"))
                analysis_version = str(pjdata.get("analysis_version", "?"))
    except Exception:
        pass

    # --- Idle / active wall-clock split ---
    #
    # Surface the time the run spent waiting on slow (standard-tier) API
    # responses so "37 min" reads honestly as e.g. "16m active + 21m API
    # idle" rather than implying 37 min of work. Only shown when a stall was
    # actually detected and we have a real wall-clock total to subtract from.
    idle_str = ""
    if idle_secs_total > 0 and duration_secs is not None:
        active_secs = max(0, duration_secs - idle_secs_total)
        idle_str = (
            f"idle≈{idle_secs_total // 60}m {idle_secs_total % 60:02d}s (API waits)  "
            f"active≈{active_secs // 60}m {active_secs % 60:02d}s  "
        )

    # --- Write summary events ---
    _write(
        "INFO ",
        "ASSESSMENT_SUMMARY",
        f"mode={mode}  duration={duration}  "
        f"{idle_str}"
        f"plugin_version={plugin_version}  analysis_version={analysis_version}  "
        f"threats={total_threats} "
        f"(Critical={threats['Critical']}, High={threats['High']}, "
        f"Medium={threats['Medium']}, Low={threats['Low']})",
        sid,
    )

    # Separate the throughput (sum of all four token streams) from the
    # semantic input/output totals. `input` = everything the model saw as
    # context (fresh + cache_write + cache_read). `output` = generated
    # tokens. `throughput` = input + output, which is what Anthropic bills
    # against (at four different rates, correctly applied in _calc_cost).
    # The input split is shown in parentheses so the reader sees both the
    # aggregate and the cache-hit ratio at a glance.
    total_input = total_in + total_cw + total_cr
    total_throughput = total_input + total_out
    billing = "api" if is_api else "subscription"
    cost_str = f"cost=${total_cost:.4f}  billing={billing}"
    _write(
        "INFO ",
        "ASSESSMENT_TOKENS",
        f"throughput={total_throughput:,}  "
        f"input={total_input:,}  output={total_out:,}  "
        f"(input split: fresh={total_in:,} cache_write={total_cw:,} cache_read={total_cr:,})  "
        f"{cost_str}",
        sid,
    )

    models_str = ", ".join(f"{a}={m}" for a, m in sorted(agent_models.items()))
    _write("INFO ", "ASSESSMENT_MODELS", f"agents: {models_str}" if models_str else "agents: none detected", sid)

    # --- Deduplicate and emit written files ---
    seen: set[str] = set()
    unique_files: list[str] = []
    for f in written_files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)
    if unique_files:
        files_str = "  ".join(unique_files)
        _write("INFO ", "ASSESSMENT_FILES", f"count={len(unique_files)}  files: {files_str}", sid)

    # --- Mirror to .agent-run.log ---
    _write_agent_run(
        "INFO",
        "hook-logger",
        "ASSESSMENT_SUMMARY",
        f"mode={mode}  duration={duration}  "
        f"plugin_version={plugin_version}  analysis_version={analysis_version}  "
        f"threats={total_threats} "
        f"(Critical={threats['Critical']}, High={threats['High']}, "
        f"Medium={threats['Medium']}, Low={threats['Low']})",
    )
    _write_agent_run(
        "INFO",
        "hook-logger",
        "ASSESSMENT_TOKENS",
        f"throughput={total_throughput:,}  "
        f"input={total_input:,}  output={total_out:,}  "
        f"(input split: fresh={total_in:,} cache_write={total_cw:,} cache_read={total_cr:,})  "
        f"cost=${total_cost:.4f}  billing={billing}",
    )
    _write_agent_run(
        "INFO", "hook-logger", "ASSESSMENT_MODELS", f"agents: {models_str}" if models_str else "agents: none detected"
    )
    if unique_files:
        _write_agent_run("INFO", "hook-logger", "ASSESSMENT_FILES", f"count={len(unique_files)}  files: {files_str}")

    # --- Per-phase durations ---
    if phase_durations:

        def _fmt_dur(s: int) -> str:
            return f"{s // 60}m {s % 60:02d}s" if s >= 60 else f"{s}s"

        phases_str = "  ".join(f"{label}={_fmt_dur(secs)}" for label, secs in phase_durations)
        _write("INFO ", "ASSESSMENT_PHASES", phases_str, sid)
        _write_agent_run("INFO", "hook-logger", "ASSESSMENT_PHASES", phases_str)

    # --- Tracing: emit ASSESSMENT_TRACE summary table from .appsec-trace.log ---
    if _TRACING:
        _write_trace_summary(sid)


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------


def _stride_tier(component_id: str) -> str:
    """``screening`` / ``full`` for a dispatched STRIDE component, else ``''``.

    Read from the dispatch manifest's ``cheap_stride`` marker rather than from
    the prompt: the tier is already deterministic there, so the orchestrator
    cannot forget to pass it, and the analyzer prompt — which sits at its size
    budget — pays nothing for the disclosure. Best-effort; any failure leaves
    the tier unstated rather than guessed.
    """
    if not component_id:
        return ""
    try:
        path = os.path.join(_output_dir(), ".stride-dispatch-manifest.json")
        with open(path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        for comp in manifest.get("components") or []:
            if isinstance(comp, dict) and comp.get("component_id") == component_id:
                return "screening" if comp.get("cheap_stride") else "full"
    except Exception:
        pass
    return ""


def _stride_plan_policy(component_id: str, plan_path: str, job_id: str, action_id: str) -> dict:
    """Return validated controller-owned STRIDE policy fields, or ``{}``.

    The full schema is enforced before dispatch.  The hook repeats the identity
    and closed-vocabulary checks needed for telemetry so model-authored prompt
    prose cannot relabel the depth or turn budget.
    """
    if not component_id or not plan_path:
        return {}
    try:
        output_dir = Path(_output_dir()).resolve()
        expected = (output_dir / ".dispatch-context" / component_id / "context-plan.json").resolve()
        supplied = Path(plan_path).resolve()
        if supplied != expected or output_dir not in supplied.parents:
            return {}
        plan = json.loads(supplied.read_text(encoding="utf-8"))
        schema = json.loads(
            (
                Path(__file__).resolve().parent.parent / "schemas" / "stride-component-context-plan.schema.json"
            ).read_text(encoding="utf-8")
        )
        if next(Draft202012Validator(schema).iter_errors(plan), None) is not None:
            return {}
        analysis = plan.get("analysis") or {}
        depth = analysis.get("depth")
        max_turns = analysis.get("max_turns")
        if plan.get("component_id") != component_id or depth not in {"full", "light"}:
            return {}
        if isinstance(max_turns, bool) or not isinstance(max_turns, int) or max_turns < 1:
            return {}
        routing = json.loads((output_dir / ".context-routing-plan.json").read_text(encoding="utf-8"))
        if not any(
            row.get("action_id") == action_id and job_id in (row.get("job_ids") or [])
            for row in routing.get("actions", [])
        ):
            return {}
        attempt_match = re.search(r":attempt-(\d+)$", job_id)
        if attempt_match is None:
            return {}
        active = json.loads((output_dir / ".dispatch-waves.json").read_text(encoding="utf-8")).get("active_claim", {})
        if component_id not in (active.get("component_ids") or []):
            return {}
        if (active.get("attempts") or {}).get(component_id) != int(attempt_match.group(1)):
            return {}
        return {"ANALYSIS_DEPTH": depth, "MAX_TURNS": max_turns}
    except (OSError, ValueError, AttributeError):
        return {}


def _agent_params(prompt: str) -> dict:
    """Extract well-known KEY=value pairs from an agent prompt.

    STRIDE dispatches additionally carry ``ANALYSIS_DEPTH``, resolved from the
    manifest by ``_stride_tier``, so ``.agent-run.log`` and the headless
    progress view record which components ran at screening depth.
    """
    params = {}
    for key in (
        "REPO_ROOT",
        "COMPONENT_ID",
        "MANIFESTS",
        "CONTEXT_FILE",
        "JOB_ID",
        "ACTION_ID",
        "COMPONENT_CONTEXT_PLAN_PATH",
    ):
        limit = 512 if key in {"REPO_ROOT", "CONTEXT_FILE", "COMPONENT_CONTEXT_PLAN_PATH"} else 256
        val = _extract_param(prompt, key, max_len=limit)
        if val:
            params[key] = val
    policy = _stride_plan_policy(
        params.get("COMPONENT_ID", ""),
        params.get("COMPONENT_CONTEXT_PLAN_PATH", ""),
        params.get("JOB_ID", ""),
        params.get("ACTION_ID", ""),
    )
    if policy:
        params.update(policy)
    elif not params.get("COMPONENT_CONTEXT_PLAN_PATH"):
        tier = _stride_tier(params.get("COMPONENT_ID", ""))
        if tier:
            params["ANALYSIS_DEPTH"] = tier
    return params


def _mirror_lifecycle_events(events: list[agent_lifecycle.LifecycleEvent]) -> None:
    """Preserve verbose hook feedback without writing duplicate log records."""
    if not _VERBOSE:
        return
    for item in events:
        level = "WARN" if item.event in {"AGENT_FAILED", "AGENT_LIFECYCLE_REJECTED"} else "INFO"
        try:
            sys.stderr.write(
                "[appsec] "
                + format_line(
                    item.event,
                    agent_lifecycle.event_detail(item),
                    level=level,
                    sid=item.call.get("session_id"),
                )
            )
            sys.stderr.flush()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Verbose-only: extract substep progress from Bash echo commands
# ---------------------------------------------------------------------------

# Patterns that indicate a progress event in a Bash echo to .agent-run.log.
# We extract the human-readable description and emit it to stderr only.
_PROGRESS_EVENTS = re.compile(
    r"(?:PHASE_START|PHASE_END|STEP_START|STEP_END|ASSESSMENT_START|ASSESSMENT_END"
    r"|AGENT_INVOKE|AGENT_DONE|AGENT_DISPATCH)"
)


_PHASE_BOUNDARY_RE = re.compile(r"\b(PHASE_START|PHASE_END)\b")


def _refresh_progress_snapshot(event: str, detail: str, sid: str = "") -> None:
    """Keep ``.appsec-progress.json`` fresh for phase events emitted via raw
    ``echo … >> .agent-run.log`` writes.

    Those echoes bypass ``log_event.py`` (the only other writer of the
    snapshot besides ``stride_progress.py``), so without this refresh the
    live-status readers (``appsec_status.py``, ``watch_run.py``,
    ``/appsec-advisor:status --live``) freeze on the last phase that happened
    to route through ``log_event.py`` — typically the Phase 1 context-resolver
    ``STEP_START`` — for the entire remainder of the run, while the pipeline
    silently advances through ``.agent-run.log`` to Phase 11.

    Reuses ``log_event``'s payload builder so the snapshot shape stays
    identical across both producers. Best-effort; never raises.
    """
    try:
        from log_event import _progress_payload, _write_progress  # type: ignore

        kind = "phase-start" if event == "PHASE_START" else "phase-end"
        payload = _progress_payload(kind, event, detail, "threat-analyst")
        _write_progress(Path(_output_dir()), payload)
    except Exception:
        pass


def _mirror_phase_events_to_hook_log(cmd: str, sid: str = "") -> None:
    """Mirror PHASE_START / PHASE_END lines from .agent-run.log Bash writes
    into .hook-events.log so that external tooling and tests that read the
    hook log see phase-boundary events.

    Also refreshes ``.appsec-progress.json`` so the live-status snapshot keeps
    advancing for phases emitted via raw echo (see _refresh_progress_snapshot).

    Called only when the Bash command writes to .agent-run.log.
    """
    m = _PHASE_BOUNDARY_RE.search(cmd)
    if not m:
        return
    event = m.group(1)
    # Extract the detail that follows the event keyword in the echo string.
    after = cmd[m.end() :].lstrip()
    for stop in ('" >>', "' >>", ">> ", '"$', "'$", '" 2>', "' 2>"):
        idx = after.find(stop)
        if idx >= 0:
            after = after[:idx]
    detail = after.strip().rstrip('"').rstrip("'").strip()
    if not detail:
        return
    _write("INFO ", event, detail, sid)
    _refresh_progress_snapshot(event, detail, sid)


def _emit_substep_progress(cmd: str) -> None:
    """Parse a Bash echo command that writes to .agent-run.log and emit the
    human-readable substep description to stderr.

    Called for every PostToolUse Bash whose command writes to .agent-run.log.
    The internal _PROGRESS_EVENTS regex filters to phase/step boundary
    keywords (PHASE_*, STEP_*, AGENT_INVOKE/DONE/DISPATCH, ASSESSMENT_*),
    so default-on operation does not flood the terminal.  Does NOT write
    to the log file — the agent's Bash command already handles that.
    """
    # The echo command looks like:
    #   echo "<timestamp>  [--------]  INFO   threat-analyst  STEP_START   [Phase 8] Rating Identity and Authentication…" >> ".../.agent-run.log"
    # We want to extract the event type and the message after it.
    m = _PROGRESS_EVENTS.search(cmd)
    if not m:
        return
    event = m.group(0)

    # Extract the message that follows the event keyword.
    # The message is everything after the event name up to the closing quote
    # or end of the echo string.
    after = cmd[m.end() :]
    # Strip leading whitespace/separator
    msg = after.lstrip()
    # Trim trailing shell redirects and quotes
    for stop in ('" >>', "' >>", ">> ", '"$', "'$", '" 2>', "' 2>"):
        idx = msg.find(stop)
        if idx >= 0:
            msg = msg[:idx]
    msg = msg.strip().rstrip('"').rstrip("'").strip()

    if not msg:
        return

    # Format a compact progress line for stderr
    label = event.replace("_", " ").title()
    if event in ("PHASE_START", "STEP_START", "AGENT_INVOKE", "AGENT_DISPATCH", "ASSESSMENT_START"):
        prefix = "▶"
    elif event in ("PHASE_END", "STEP_END", "AGENT_DONE", "ASSESSMENT_END"):
        prefix = "✓"
    else:
        prefix = "·"

    try:
        sys.stderr.write(f"[appsec] {prefix} {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Verbose-only: sub-agent activity indicator (throttled)
# ---------------------------------------------------------------------------

# Tool name → human-readable verb for activity lines
_TOOL_VERBS = {
    "Read": "reading",
    "Grep": "searching",
    "Glob": "scanning",
    "Bash": "executing",
    "Write": "writing",
    "Edit": "editing",
}

# Throttle: max one activity line per session per this many seconds
_ACTIVITY_THROTTLE_SECS = 5

# File-based throttle state (each hook invocation is a separate process)
_THROTTLE_FILE = None


def _throttle_path() -> str:
    """Return path to the throttle state file."""
    global _THROTTLE_FILE
    if _THROTTLE_FILE is None:
        log = _log_path()
        _THROTTLE_FILE = os.path.join(os.path.dirname(log), ".activity-throttle")
    return _THROTTLE_FILE


def _should_emit_activity(sid: str) -> bool:
    """Check if enough time has passed since the last activity line for this
    session.  Updates the throttle file atomically."""
    now = time.time()
    throttle = _throttle_path()
    key = (sid or "")[:8]
    last_times: dict[str, float] = {}

    # Read existing throttle state
    try:
        if os.path.exists(throttle):
            with open(throttle) as fh:
                for line in fh:
                    parts = line.strip().split("=", 1)
                    if len(parts) == 2:
                        last_times[parts[0]] = float(parts[1])
    except Exception:
        pass

    last = last_times.get(key, 0.0)
    if now - last < _ACTIVITY_THROTTLE_SECS:
        return False

    # Update throttle
    last_times[key] = now
    try:
        with open(throttle, "w") as fh:
            for k, v in last_times.items():
                fh.write(f"{k}={v}\n")
    except Exception:
        pass
    return True


def _emit_activity(tool: str, inp: dict, sid: str) -> None:
    """Emit a compact activity line to stderr for a sub-agent tool call.

    Only called when _VERBOSE is True.  Throttled to avoid flooding.
    Does NOT write to the log file — this is purely a real-time progress
    indicator for the terminal.
    """
    if not _should_emit_activity(sid):
        return

    verb = _TOOL_VERBS.get(tool, "working")
    agent = _session_agent_label((sid or "")[:8])
    if not agent:
        # Tool call from the outermost session (orchestrator / skill) —
        # those are already covered by PHASE_START / STEP_START logging.
        return

    # Build a compact context hint (not the full path — just enough to
    # show what area the agent is working on)
    hint = ""
    if tool == "Read":
        path = inp.get("file_path", "")
        if path:
            hint = os.path.basename(path)
    elif tool == "Grep":
        pattern = inp.get("pattern", "")
        if pattern:
            hint = _clip(pattern, 40)
    elif tool == "Bash":
        cmd = inp.get("command", "")
        if cmd:
            hint = _clip(cmd, 40)
    elif tool == "Write":
        path = inp.get("file_path", "")
        if path:
            hint = os.path.basename(path)

    line = f"[appsec] · {agent} — {verb}"
    if hint:
        line += f" ({hint})"
    line += "…\n"

    try:
        sys.stderr.write(line)
        sys.stderr.flush()
    except Exception:
        pass


# Matches a clean, single python3 invocation of one of the plugin's own
# background watchdog scripts (heartbeat / deadline) and nothing else. Used by
# the PreToolUse auto-approve guard below.
_WATCHDOG_CMD_RE = re.compile(r'^python3?\s+["\']?\S*scripts/(?:skill_watchdog|budget_watchdog)\.py\b')


def _is_sanctioned_background_watchdog(cmd: str) -> bool:
    """True iff `cmd` is a bare invocation of a known plugin watchdog script.

    Deliberately strict: the sanctioned watchdog dispatch is a single clean
    `python3 "$CLAUDE_PLUGIN_ROOT/scripts/skill_watchdog.py" ...` command with
    NO shell chaining, redirection, or command substitution. Any such
    metacharacter disqualifies the command, so an "allow" decision can never
    blanket-approve a compound that smuggles another command past the prompt.
    """
    if not cmd or not _WATCHDOG_CMD_RE.match(cmd):
        return False
    # `;` `` ` `` `|` `<` `>` `&` newline and `$(` all enable chaining/redirection.
    if re.search(r"[;`|<>&\n]|\$\(", cmd):
        return False
    return True


def _context_v2_parallel_foreground_reason(data: dict) -> str | None:
    """Reject a blocking Agent call that would serialize a context-v2 wave."""
    if data.get("tool_name") != "Agent":
        return None
    tool_input = data.get("tool_input", {}) or {}
    subtype = tool_input.get("subagent_type")
    waiters = {
        "appsec-advisor:appsec-stride-analyzer-v2": ("STRIDE", "wait_stride_progress.py"),
        "appsec-advisor:appsec-abuse-case-verifier": ("abuse verifier", "wait_abuse_progress.py"),
    }
    if subtype not in waiters:
        return None
    if tool_input.get("run_in_background") is True:
        return None
    try:
        config = json.loads(Path(_output_dir(), ".skill-config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if config.get("runtime_generation") != "context-v2":
        return None
    wave, waiter = waiters[subtype]
    return (
        f"Context-v2 {wave} jobs must use run_in_background:true. "
        "A foreground Agent call serializes the controller's dispatch_parallel wave; "
        f"launch every job before entering {waiter}."
    )


def _context_v2_agent_identity_reason(data: dict) -> str | None:
    """Require controller and call identity on context-v2 semantic dispatches."""
    if data.get("tool_name") != "Agent":
        return None
    try:
        config = json.loads(Path(_output_dir(), ".skill-config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if config.get("runtime_generation") != "context-v2":
        return None
    subtype = str((data.get("tool_input") or {}).get("subagent_type") or "")
    context_v2_agents = {
        "appsec-advisor:appsec-context-resolver",
        "appsec-advisor:appsec-recon-scanner",
        "appsec-advisor:appsec-config-scanner",
        "appsec-advisor:appsec-actor-discoverer",
        "appsec-advisor:appsec-architecture-analyst",
        "appsec-advisor:appsec-trust-boundary-analyst",
        "appsec-advisor:appsec-control-analyst",
        "appsec-advisor:appsec-stride-analyzer-v2",
        "appsec-advisor:appsec-threat-merger",
        "appsec-advisor:appsec-evidence-verifier",
        "appsec-advisor:appsec-triage-validator",
        "appsec-advisor:appsec-post-stride-synthesizer",
        "appsec-advisor:appsec-abuse-case-verifier",
    }
    if subtype not in context_v2_agents:
        return None
    if not str(data.get("tool_use_id") or "").strip():
        return "Context-v2 Agent dispatch requires the host tool_use_id as agent_call_id."
    prompt = str((data.get("tool_input") or {}).get("prompt") or "")
    if not _extract_param(prompt, "JOB_ID"):
        return "Context-v2 Agent dispatch requires controller-owned JOB_ID."
    if not _extract_param(prompt, "ACTION_ID"):
        return "Context-v2 Agent dispatch requires controller-owned ACTION_ID."
    if subtype.endswith("appsec-stride-analyzer-v2"):
        params = _agent_params(prompt)
        if params.get("ANALYSIS_DEPTH") not in {"full", "light"} or not params.get("MAX_TURNS"):
            return "Context-v2 STRIDE dispatch requires a valid current component context plan."
    return None


def _context_v2_terminal_abort_reason() -> str | None:
    """Reject tool use after a current-run context-v2 controller abort."""
    output_dir = Path(_output_dir())
    config_path = output_dir / ".skill-config.json"
    if not config_path.is_file():
        return None
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, AttributeError):
        return (
            "The persisted run configuration is unreadable, so the hook cannot prove that this invocation may "
            "continue. Preserve the runtime artifacts for diagnosis and start a fresh rebuild invocation."
        )
    if not isinstance(config, dict):
        return (
            "The persisted run configuration is invalid, so the hook cannot prove that this invocation may "
            "continue. Preserve the runtime artifacts for diagnosis and start a fresh rebuild invocation."
        )
    if config.get("runtime_generation") != "context-v2":
        return None
    try:
        import cutoff_cause

        aborted = cutoff_cause.detect_abort(output_dir)
    except Exception:
        return (
            "The context-v2 abort state is unreadable, so the hook cannot prove that this invocation may continue. "
            "Preserve the runtime artifacts for diagnosis and start a fresh rebuild invocation."
        )
    if not aborted:
        return None
    return (
        "This context-v2 invocation has already emitted an authoritative RUN_ABORTED event. "
        "No later tool call or semantic producer may continue it; preserve the runtime artifacts "
        "for diagnosis and start a fresh rebuild invocation."
    )


def _emit_pretool_denial(reason: str) -> None:
    """Emit one fail-closed PreToolUse decision."""
    try:
        sys.stdout.write(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                }
            )
        )
        sys.stdout.flush()
    except Exception:
        sys.stderr.write(reason + "\n")
        sys.stderr.flush()
        sys.exit(2)


def handle_pre_tool_use(data: dict, sid: str) -> None:
    """Log AGENT_SPAWN for Agent tool calls, and emit verbose activity
    indicators for all other tool calls from sub-agent sessions.

    PreToolUse fires in the session that makes the tool call (any depth),
    so this handler captures sub-agent activity that PostToolUse misses
    (PostToolUse only fires in the outermost session).
    """
    tool = data.get("tool_name", "")

    # OUTPUT_DIR recovery (2026-06-05) — this PreToolUse hook runs as a SEPARATE
    # process that does NOT inherit the skill's OUTPUT_DIR env. Without this,
    # every AGENT_SPAWN landed in the plugin-root `docs/security/.hook-events.log`
    # (the cwd+docs/security default in `_output_dir()`) instead of the run's
    # `$OUTPUT_DIR/.hook-events.log`. That silently blinded the count-based
    # `check_stride_dispatch.py` gate (it always degraded to the `.progress/`
    # fallback in headless/CI — the very mode the count gate was meant to harden)
    # and zeroed `record_stage_stats` / `verify_run_costs`, which read
    # `$OUTPUT_DIR/.hook-events.log`. Every skill dispatch prompt carries
    # `OUTPUT_DIR=<abs>` (SKILL-impl §3c hard-requirement), so recover it into the
    # env THIS process reads. Each hook call is a fresh process, so the mutation
    # cannot leak across runs; only set when unset; non-Agent tools have no
    # `prompt` field, so `_extract_param` returns '' and this is a no-op.
    if not os.environ.get("OUTPUT_DIR"):
        _od = _extract_param(
            (data.get("tool_input", {}) or {}).get("prompt", "") or "",
            "OUTPUT_DIR",
            max_len=512,
        )
        if _od:
            os.environ["OUTPUT_DIR"] = _od

    abort_reason = _context_v2_terminal_abort_reason()
    if abort_reason is not None:
        _emit_pretool_denial(abort_reason)
        return

    serial_reason = _context_v2_parallel_foreground_reason(data)
    if serial_reason is not None:
        _emit_pretool_denial(serial_reason)
        return

    identity_reason = _context_v2_agent_identity_reason(data)
    if identity_reason is not None:
        _emit_pretool_denial(identity_reason)
        return

    lifecycle_events: list[agent_lifecycle.LifecycleEvent] = []
    if tool == "Agent":
        inp = data.get("tool_input", {}) or {}
        subtype = str(inp.get("subagent_type") or "unknown")
        params = _agent_params(str(inp.get("prompt") or ""))
        job_id = params.get("JOB_ID") or ""
        attempt_match = re.search(r":attempt-(\d+)$", str(job_id))
        identity = {
            "agent_call_id": data.get("tool_use_id"),
            "session_id": (sid or "")[:8],
            "agent": _short_agent_name(subtype) or subtype.split(":")[-1] or "unknown",
            "agent_type": subtype,
            "model": _agent_model(subtype, inp),
            "description": _plain_log_text(inp.get("description", "")),
            "background": bool(inp.get("run_in_background", False)),
            "action_id": params.get("ACTION_ID"),
            "job_id": job_id,
            "component_id": params.get("COMPONENT_ID"),
            "attempt": int(attempt_match.group(1)) if attempt_match else None,
            "analysis_depth": params.get("ANALYSIS_DEPTH")
            if params.get("ANALYSIS_DEPTH") in {"full", "light"}
            else None,
            "max_turns": params.get("MAX_TURNS"),
        }
        try:
            lifecycle_events = agent_lifecycle.register_call(_output_dir(), identity)
            agent_lifecycle.append_events(_output_dir(), lifecycle_events)
            _mirror_lifecycle_events(lifecycle_events)
        except agent_lifecycle.LifecycleError as exc:
            _emit_pretool_denial(f"Agent lifecycle admission failed: {exc}")
            return
        try:
            from budget_watchdog import close_call, open_call

            for event in lifecycle_events:
                if event.event in {"AGENT_DONE", "AGENT_FAILED"}:
                    close_call(str(event.call.get("agent_call_id") or ""), _output_dir())
            call = next(
                (
                    row
                    for row in agent_lifecycle.running_calls(_output_dir())
                    if row.get("agent_call_id") == str(data.get("tool_use_id") or "")
                ),
                None,
            )
            if call is not None:
                open_call(call, _output_dir())
        except Exception:
            pass

    # M3.6 #2 — record an in-flight marker file so /appsec-advisor:status
    # --live can answer "what is happening right now?". One file per
    # tool_use_id; PostToolUse removes it. Sub-agent calls without a
    # propagating Post are aged out by the status reader.
    _record_tool_start(data, sid)

    # --- Auto-approve the plugin's own background watchdogs (2026-07-12) ---
    #
    # The skill dispatches scripts/skill_watchdog.py (and, when a wall-time /
    # cost deadline is set, scripts/budget_watchdog.py) via the Bash tool with
    # run_in_background=true (see SKILL-impl "Skill-layer heartbeat watchdog").
    # Claude Code shows an interactive "& background operator" safety
    # confirmation for every backgrounded Bash call, which forces the user to
    # answer a Yes/No prompt one or more times per run. These commands are
    # plugin-internal, side-effect-free heartbeat/deadline loops, so pre-approve
    # them here — but ONLY when the command is a clean single invocation of the
    # known script (see _is_sanctioned_background_watchdog for the strict
    # matcher; anything with shell chaining/redirection falls through to the
    # normal prompt). NOTE: whether this "allow" decision actually suppresses
    # the background-operator confirmation is Claude-Code-version dependent and
    # must be verified in a live run — if it is a hardcoded circuit-breaker the
    # decision is ignored and the prompt still fires (harmless, just no-op).
    if tool == "Bash" and (data.get("tool_input", {}) or {}).get("run_in_background"):
        cmd = ((data.get("tool_input", {}) or {}).get("command") or "").strip()
        if _is_sanctioned_background_watchdog(cmd):
            try:
                sys.stdout.write(
                    json.dumps(
                        {
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "allow",
                                "permissionDecisionReason": (
                                    "appsec-advisor internal background watchdog "
                                    "(heartbeat/deadline) — pre-approved by plugin hook."
                                ),
                            }
                        }
                    )
                )
                sys.stdout.flush()
            except Exception:
                pass
            return

    # --- Direct-write guard for threat-model.md (added 2026-04-25) ---
    #
    # AGENTS.md invariant: "agents never write threat-model.md directly".
    # The only legal writer is `compose_threat_model.py`. The 2026-04-25
    # juice-shop Run 4 surfaced that this rule was a documentation-only ask
    # — the orchestrator skipped Phase 11 substeps and hand-authored a 90 KB
    # threat-model.md, bypassing the schema-validated renderer entirely. This
    # guard makes the bypass physically impossible: any Write/Edit tool call
    # targeting `<output_dir>/threat-model.md` is denied at PreToolUse.
    #
    # Allowed paths (intentional):
    #   - hook receives no file_path → not a Write/Edit, skip
    #   - file_path is a `<...>/threat-model.md` other than the canonical one
    #     → also blocked (we cannot tell from the hook payload whether the
    #     write originates inside compose_threat_model.py — but Python writes
    #     from compose_threat_model.py do NOT go through the Claude Code Write
    #     tool, they go through the Python `open()` syscall which the hook
    #     does not see. So blocking ALL Write/Edit calls to a `threat-model.md`
    #     is safe: it catches LLM-driven writes only.)
    #
    # The guard also covers `MultiEdit` — same blast radius.
    if tool in ("Write", "Edit", "MultiEdit"):
        inp = data.get("tool_input", {}) or {}
        path = (inp.get("file_path") or "").strip()
        if path and Path(path).name == "threat-model.md":
            reason = (
                "Direct Write/Edit of threat-model.md is forbidden. "
                "The only legal writer is scripts/compose_threat_model.py, "
                "which renders from .fragments/* — see AGENTS.md "
                "(invariant: agents never write threat-model.md directly). "
                "If you reached this point in Phase 11, you skipped substep 4 "
                "(fragment authoring); go back, write the fragments under "
                "$OUTPUT_DIR/.fragments/, and run compose_threat_model.py."
            )
            try:
                sys.stdout.write(
                    json.dumps(
                        {
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "deny",
                                "permissionDecisionReason": reason,
                            }
                        }
                    )
                )
                sys.stdout.flush()
            except Exception:
                # If JSON emission fails, fall back to non-zero exit which
                # also signals a deny in Claude Code's hook protocol.
                sys.stderr.write(reason + "\n")
                sys.stderr.flush()
                sys.exit(2)
            # Best-effort: also write a marker so a later QA check can
            # confirm the guard fired (audit / debugging only).
            try:
                marker = os.path.join(os.path.dirname(_log_path()), ".direct-write-blocked")
                with open(marker, "a") as fh:
                    fh.write(f"{datetime.utcnow().isoformat()}Z\t{path}\n")
            except Exception:
                pass
            return

    # --- Non-Agent tools: verbose-only activity indicator ---
    if tool != "Agent":
        if _VERBOSE:
            _emit_activity(tool, data.get("tool_input", {}), sid)
        return

    inp = data.get("tool_input", {})
    subtype = inp.get("subagent_type", "unknown")
    desc = _plain_log_text(inp.get("description", ""))
    bg = inp.get("run_in_background", False)
    bg_tag = " [bg]" if bg else "     "
    model = _agent_model(subtype, inp)
    params = _agent_params(inp.get("prompt", "") or "")
    pairs = "  ".join(f"{k}={v}" for k, v in params.items())

    # Tracing: record dispatch time and emit AGENT_DISPATCH with context size estimate
    if _TRACING:
        prompt_str = inp.get("prompt", "") or ""
        context_chars = len(prompt_str)
        context_ktok = round(context_chars / 3500, 1)  # ~3.5 chars/token
        max_turns_val = _extract_param(prompt_str, "MAX_TURNS") or "?"
        _dispatch_ts = time.time()
        _record_dispatch_time((sid or "")[:8], _dispatch_ts)
        # Also index by agent short name: the Stop hook runs in the CHILD
        # session, whose id differs from the parent id used above, so the
        # sid key alone can never be redeemed for a dispatched subagent.
        _record_dispatch_time(
            f"agent:{_AGENT_SHORT_NAMES.get(subtype.split(':')[-1], subtype.split(':')[-1])}:{_dispatch_ts}",
            _dispatch_ts,
        )
        _write_trace(
            "AGENT_DISPATCH",
            f"agent={_short_agent_name(subtype) or subtype.split(':')[-1]}  "
            f"model={model}  bg={str(bg).lower()}  "
            f"context_chars={context_chars:,}  context_ktok={context_ktok}  "
            f"max_turns={max_turns_val}",
            sid,
        )

    # Map session_id → agent short name so SESSION_STOP can attribute
    # token/cost data to the correct agent in .agent-run.log.
    # Each hook invocation is a separate process, so we persist the
    # mapping in a lightweight file.
    raw_name = subtype.split(":")[-1] if ":" in subtype else subtype
    short = _short_agent_name(subtype)
    if short and sid:
        _save_session_agent(sid[:8], short)

    # SCAN_START fires at PreToolUse (dispatch time) so it precedes
    # the threat-analyst's own SESSION_STOP in the log. Emitting it
    # here (before the agent runs) fixes the ordering bug where
    # SCAN_START was previously logged at PostToolUse (after completion).
    if "threat-analyst" in raw_name:
        repo = params.get("REPO_ROOT", "unknown")
        _write("INFO ", "SCAN_START", f"repo={repo}  agent={subtype}  model={model}", sid)
        # Reset the summary sentinel so this new assessment gets its own summary
        sentinel = os.path.join(os.path.dirname(_log_path()), ".assessment-summary-emitted")
        try:
            os.remove(sentinel)
        except FileNotFoundError:
            pass
        # Record which session owns this assessment so ghost summaries from
        # lingering prior sessions are suppressed in _write_assessment_summary.
        owner_path = os.path.join(os.path.dirname(_log_path()), ".assessment-owner-sid")
        try:
            with open(owner_path, "w") as fh:
                fh.write(sid[:8] if sid else "unknown")
        except Exception:
            pass


def _usage_from_transcript(transcript_path: str) -> dict:
    """Parse the full JSONL transcript and sum usage across ALL assistant
    messages. Returns a dict with the four token fields summed, or {} if no
    usage data was found.

    This is the authoritative source for per-session token totals. The
    Anthropic API returns usage per API call (per turn), not as a session
    cumulative — so a correct session total requires summing every assistant
    turn in the transcript. Claude Code's Stop-event payload carries at best
    the last turn's usage (often nothing at all in Subscription mode), which
    is why an earlier version of this function that returned the "last usage
    block" logged only one turn's worth of tokens and made ASSESSMENT_TOKENS
    useless.

    Streaming line-by-line keeps memory flat regardless of transcript size;
    typical transcripts run a few MB with 50–200 assistant turns.
    """
    if not transcript_path or not os.path.isfile(transcript_path):
        return {}
    totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }
    found_any = False
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                # Transcript records vary in shape across claude-code versions;
                # we look for any `usage` dict nested inside.
                msg = obj.get("message") or obj
                if not isinstance(msg, dict):
                    continue
                usage = msg.get("usage")
                if not isinstance(usage, dict):
                    # Some shapes place the usage under message.content / delta
                    inner = msg.get("content") or msg.get("delta")
                    if isinstance(inner, dict):
                        usage = inner.get("usage")
                if not isinstance(usage, dict) or not usage:
                    continue
                found_any = True
                for k in totals:
                    v = usage.get(k, 0)
                    if isinstance(v, (int, float)):
                        totals[k] += int(v)
    except Exception:
        pass
    return totals if found_any else {}


def _stop_reason_from_transcript(transcript_path: str) -> str:
    """Terminal ``stop_reason`` of the last assistant turn in the transcript.

    The Stop/SubagentStop hook payload does not carry a stop reason, but every
    assistant record in the JSONL transcript does. The LAST non-null value is
    the terminal one and separates the two cases we care about:

    * ``end_turn`` / ``stop_sequence`` — the session finished on its own;
    * ``tool_use`` — the session was still in its tool loop when it stopped,
      i.e. it was cut off (turn ceiling, cancellation, transport death).

    Returns ``""`` when the transcript is missing, unreadable, or carries no
    assistant record, so the caller keeps its ``unknown`` fallback rather than
    inventing a verdict."""
    if not transcript_path:
        return ""
    last = ""
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                msg = obj.get("message") or obj
                if not isinstance(msg, dict) or msg.get("role") != "assistant":
                    continue
                reason = msg.get("stop_reason")
                if isinstance(reason, str) and reason:
                    last = reason
    except Exception:
        return ""
    return last


def _tool_uses_from_transcript(transcript_path: str) -> int:
    """Count distinct tool-use blocks in one agent transcript."""
    if not transcript_path:
        return 0
    tool_ids: set[str] = set()
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                if not raw.lstrip().startswith("{"):
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue
                msg = obj.get("message") or obj
                content = msg.get("content") if isinstance(msg, dict) else None
                if not isinstance(content, list):
                    continue
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_use":
                        continue
                    tool_id = block.get("id")
                    if isinstance(tool_id, str) and tool_id:
                        tool_ids.add(tool_id)
    except OSError:
        return 0
    return len(tool_ids)


def _stop_transcript_path(data: dict, event_name: str) -> str:
    """Return the transcript owned by the session that is stopping.

    ``SubagentStop`` carries both the parent session's ``transcript_path`` and
    the child's ``agent_transcript_path``. Lifecycle, usage, and tool totals
    belong to the child call, so the child-specific path must win. The common
    path remains a compatibility fallback for older hook payloads.
    """
    key = "agent_transcript_path" if event_name == "SubagentStop" else "transcript_path"
    value = data.get(key)
    if not isinstance(value, str) or not value:
        value = data.get("transcript_path")
    return value if isinstance(value, str) else ""


def handle_stop(data: dict, sid: str, event_name: str = "") -> None:
    transcript = _stop_transcript_path(data, event_name)
    reason = data.get("stop_reason", "") or ""
    if not reason:
        # The Claude Code Stop/SubagentStop payload carries no `stop_reason`
        # key at all — juice-shop 2026-07-24 logged `stop=unknown` on 325 of
        # 325 sessions. That made every downstream consumer blind:
        # `_CLEAN_STOP_REASONS` never matched, so SESSION_ABORTED_MIDRUN fired
        # on EVERY stop (11 false WARNs on a fully successful run) and
        # rewrote the live checkpoint to status=aborted; and the `max_turns`
        # branch below was unreachable, so two abuse-case verifiers that
        # demonstrably burned their turn ceiling were never flagged.
        # The transcript does carry it, and it discriminates cleanly: a
        # session that finished ends on `end_turn`, one cut off mid-tool-loop
        # ends on `tool_use`.
        reason = _stop_reason_from_transcript(transcript) or "unknown"
    level = "ERROR" if reason == "max_turns" else "INFO "

    # ------------------------------------------------------------------
    # Transcript is the authoritative source for per-session totals.
    # The Stop-event payload carries at best a single turn's usage (and in
    # Subscription mode usually nothing at all). The transcript, parsed by
    # _usage_from_transcript, streams the full JSONL and sums every assistant
    # turn's usage block — that's the correct session cumulative total.
    # Payload usage is kept as a fallback for the unlikely case where the
    # transcript path is not provided or the file is unreadable.
    # ------------------------------------------------------------------
    usage = _usage_from_transcript(transcript) if transcript else {}
    usage_source = "transcript" if usage else ""

    if not usage:
        payload_usage = data.get("usage", {}) or {}
        if payload_usage:
            usage = payload_usage
            usage_source = "payload-last-turn"

    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    cw = usage.get("cache_creation_input_tokens", 0)
    cr = usage.get("cache_read_input_tokens", 0)
    has_usage = bool(usage)  # False when neither the payload nor the transcript had usage

    runtime_agent_id = str(data.get("agent_id") or "") if event_name == "SubagentStop" else ""
    if runtime_agent_id:
        agent_lifecycle.bind_runtime_agent_start(_output_dir(), runtime_agent_id, str(data.get("agent_type") or ""))
    tool_uses = _tool_uses_from_transcript(transcript) if runtime_agent_id and transcript else 0
    runtime_call = (
        agent_lifecycle.running_call_by_runtime_agent_id(_output_dir(), runtime_agent_id) if runtime_agent_id else None
    )
    if runtime_call is not None:
        try:
            from budget_watchdog import format_detail, observe_tool_uses

            crossing = observe_tool_uses(runtime_call, tool_uses, _output_dir())
            if crossing is not None:
                _write("WARN ", crossing["event"], format_detail(crossing), sid)
        except Exception:
            pass
    if has_usage and runtime_agent_id:
        try:
            events = agent_lifecycle.record_runtime_usage(_output_dir(), runtime_agent_id, usage, tool_uses=tool_uses)
            agent_lifecycle.append_events(_output_dir(), events)
            if not events:
                _write(
                    "WARN ",
                    "AGENT_USAGE_UNATTRIBUTED",
                    f"runtime_agent_id={runtime_agent_id}  reason=no_running_agent_call",
                    sid,
                )
        except agent_lifecycle.LifecycleError:
            pass
    elif has_usage:
        _write(
            "WARN ",
            "AGENT_USAGE_UNATTRIBUTED",
            "reason=no_agent_call_identity",
            sid,
        )

    # SubagentStop is the concrete child-call return boundary. Close lifecycle
    # and budget ownership here so a missing/delayed Agent PostToolUse cannot
    # charge later parent tools to the finished child. The later PostToolUse is
    # an idempotent acknowledgement; background output promotion remains owned
    # by the controller waiter, not by this telemetry transition.
    if runtime_call is not None:
        try:
            clean = reason in _CLEAN_STOP_REASONS
            events = (
                agent_lifecycle.finish_call(_output_dir(), runtime_call["agent_call_id"])
                if clean
                else agent_lifecycle.fail_call(
                    _output_dir(),
                    runtime_call["agent_call_id"],
                    f"subagent_stop:{reason}",
                )
            )
            agent_lifecycle.append_events(_output_dir(), events)
            from budget_watchdog import close_call

            close_call(runtime_call["agent_call_id"], _output_dir())
        except (agent_lifecycle.LifecycleError, OSError):
            pass

    # Always emit token fields so the ASSESSMENT_SUMMARY aggregation regex
    # can find and sum them. Emitting zeros explicitly when no usage is
    # available makes the absence of data visible instead of silently dropped.
    detail = f"stop_reason={reason}  in={inp:,}  out={out:,}"
    if cw:
        detail += f"  cache_write={cw:,}"
    if cr:
        detail += f"  cache_read={cr:,}"
    if has_usage:
        detail += f"  cost=${_calc_cost(usage):.4f}"
        # Flag the fallback explicitly — payload-last-turn is significantly
        # less accurate than the transcript sum and should be noticeable in
        # logs so operators know the total is an under-count.
        if usage_source == "payload-last-turn":
            detail += "  src=payload-last-turn"
    else:
        detail += "  cost=n/a (no usage data in transcript or payload)"

    _write(level, "SESSION_STOP", detail, sid)

    # Emit a dedicated MAX_TURNS error so it stands out in logs
    if reason == "max_turns":
        _write(
            "ERROR",
            "MAX_TURNS",
            "Agent terminated — maxTurns limit reached. Increase maxTurns in agent frontmatter or reduce task scope.",
            sid,
        )

    # --- Mirror critical events to .agent-run.log ---
    # The session map is observational only. Multiple call registrations are
    # rendered as shared-session instead of assigning Stop to the latest role.
    registrations = _lookup_session_agent_registrations(sid[:8]) if sid else []
    telemetry_agent = _session_agent_label(sid[:8]) if sid else ""
    owner_sid = ""
    try:
        owner_sid = Path(_output_dir(), ".assessment-owner-sid").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    assessment_owner = bool(sid and (owner_sid == sid[:8] or (not owner_sid and registrations == ["threat-analyst"])))

    if telemetry_agent:
        # Mirror SESSION_STOP with token/cost summary to agent-run.log.
        # SubagentStop fires on the *parent* session for the same child
        # completion that already fired a Stop event — suppress the duplicate.
        if event_name != "SubagentStop":
            _write_agent_run(level, telemetry_agent, "SESSION_STOP", detail)

        # Mirror MAX_TURNS to agent-run.log so it's visible in the unified log
        if reason == "max_turns":
            _write_agent_run("ERROR", telemetry_agent, "MAX_TURNS", "Agent terminated — maxTurns limit reached")

        # Stamp the checkpoint as aborted when the outermost orchestrator
        # session ends uncleanly. Leaves a durable signal that the next
        # pre-flight (check_state.py --auto-clean) can act on without waiting
        # for the mtime-based stale threshold.
        # G-4: also mark on any non-clean stop in the top-level skill session
        # (registrations may be empty when the skill Bash layer itself dies without
        # a sub-agent name being registered — e.g. context-compaction kills the
        # outer session between Stage 1 return and Stage 2 dispatch).
        if assessment_owner or not registrations:
            aborted_phase = _mark_checkpoint_aborted_if_dirty(reason)
            if aborted_phase is not None:
                # The outer session ended uncleanly while a run was mid-flight.
                # Log it as a first-class event so post-hoc analysis can find it
                # (the raw signal was previously only a checkpoint rewrite). When
                # the registration list is empty when the skill-Bash layer died without a
                # sub-agent registered — context-compaction between stages is the
                # common cause; we record the fact without asserting the cause.
                who = "threat-analyst" if assessment_owner else "skill-session"
                detail = (
                    f"phase={aborted_phase}  reason={reason}  agent={who}  "
                    f"(unclean stop mid-run; if agent=skill-session, "
                    f"context-compaction between stages is the common cause)"
                )
                _write("WARN ", "SESSION_ABORTED_MIDRUN", detail, sid)
                _write_agent_run("WARN", who, "SESSION_ABORTED_MIDRUN", f"phase={aborted_phase}  reason={reason}")

    # --- Tracing: emit AGENT_COMPLETE with per-session token/cost/wall-time ---
    if _TRACING and telemetry_agent:
        trace_agent = telemetry_agent
        wall_secs = "?"
        dispatch_key = (sid or "")[:8]
        dispatched_at = _take_dispatch_time(dispatch_key)
        if dispatched_at is None:
            # Subagent: the dispatch was recorded under the parent session id,
            # so fall back to the agent-name index (see
            # _take_dispatch_time_for_agent).
            dispatched_at = _take_dispatch_time_for_agent(trace_agent)
        if dispatched_at is not None:
            wall_secs = str(round(time.time() - dispatched_at))
        turns_used = "?"
        if transcript:
            try:
                count = 0
                with open(transcript, encoding="utf-8", errors="replace") as fh:
                    for raw in fh:
                        raw = raw.strip()
                        if not raw or not raw.startswith("{"):
                            continue
                        try:
                            obj = json.loads(raw)
                        except Exception:
                            continue
                        msg = obj.get("message") or obj
                        if isinstance(msg, dict) and msg.get("role") == "assistant":
                            count += 1
                turns_used = str(count)
            except Exception:
                pass
        cost_val = f"${_calc_cost(usage):.4f}" if has_usage else "n/a"
        _write_trace(
            "AGENT_COMPLETE",
            f"agent={trace_agent}  scope=session-cumulative  "
            f"in={inp:,}  out={out:,}  cache_write={cw:,}  cache_read={cr:,}  "
            f"cost={cost_val}  turns={turns_used}  stop={reason}  "
            f"wall_secs={wall_secs}",
            sid,
        )

    # --- Assessment summary on outermost session Stop ---
    # Guard: only emit the summary ONCE per assessment. The sentinel is written
    # with O_CREAT|O_EXCL ("x" mode) so that concurrent hook processes cannot
    # both pass the exists()-check before either has written it (TOCTOU fix).
    # The sentinel is written BEFORE the summary so that a second process racing
    # on the same event always loses — summary runs at most once.
    # Current Claude Code releases also emit `Stop` inside sub-agent sessions,
    # all with the parent's session_id. While the run lock is still owned by
    # this session, that event cannot be the completed outer assessment. The
    # happy path releases the lock before its final Stop.
    run_still_owned = bool(sid and _run_lock_owner_sid() == sid[:8])
    if event_name == "Stop" and not run_still_owned:
        clear_terminal_active_tool_calls()
        sentinel = os.path.join(os.path.dirname(_log_path()), ".assessment-summary-emitted")
        try:
            with open(sentinel, "x") as fh:  # atomic O_CREAT|O_EXCL
                fh.write(sid[:8] if sid else "unknown")
        except FileExistsError:
            pass  # already claimed — skip duplicate summary
        except Exception:
            pass  # never crash a hook
        else:
            # Only reached when this process successfully claimed the sentinel
            try:
                _write_assessment_summary(sid)
            except Exception:
                pass


def handle_post_tool_use(data: dict, sid: str) -> None:
    tool = data.get("tool_name", "")
    inp = data.get("tool_input", {})
    resp = data.get("tool_response", "")
    is_err = data.get("is_error", False)

    # M3.6 #2 — clear the in-flight marker file. Idempotent and silent on
    # missing files (sub-agent Pre + missing-Post case is handled by the
    # reader's age-based filter).
    started_at = _record_tool_end(data)
    dur_tail = _dur_suffix(started_at)

    # --- Agent invocation ---
    if tool == "Agent":
        subtype = inp.get("subagent_type", "unknown")
        desc = _plain_log_text(inp.get("description", ""))
        bg = inp.get("run_in_background", False)
        bg_tag = " [bg]" if bg else "     "
        model = _agent_model(subtype, inp)
        params = _agent_params(inp.get("prompt", "") or "")
        pairs = "  ".join(f"{k}={v}" for k, v in params.items())

        call_id = str(data.get("tool_use_id") or "")
        try:
            runtime_agent_id = _runtime_agent_id(resp)
            if runtime_agent_id:
                agent_lifecycle.bind_runtime_agent_id(_output_dir(), call_id, runtime_agent_id)
            if is_err:
                events = agent_lifecycle.fail_call(_output_dir(), call_id, "agent_tool_error")
            elif bg:
                events = agent_lifecycle.acknowledge_background_call(_output_dir(), call_id)
            else:
                events = agent_lifecycle.finish_call(_output_dir(), call_id)
            agent_lifecycle.append_events(_output_dir(), events)
        except agent_lifecycle.LifecycleError as exc:
            _write("WARN ", "AGENT_LIFECYCLE_REJECTED", f"agent_call_id={call_id or '?'}  reason={exc}", sid)
        if is_err or not bg:
            try:
                from budget_watchdog import close_call

                close_call(call_id, _output_dir())
            except Exception:
                pass

        if is_err:
            _write("ERROR", "TOOL_ERROR", f"tool={tool}  {_mask_secrets(_clip(resp))}{dur_tail}", sid)
            return

        # Emit a SCAN_COMPLETE line when the orchestrator agent finishes.
        # (SCAN_START is now emitted at PreToolUse / dispatch time, so the
        # chronological order in the log is correct: SCAN_START → SESSION_STOP
        # → SCAN_COMPLETE. Previously both were emitted at PostToolUse which
        # placed SCAN_START *after* SESSION_STOP.)
        if "threat-analyst" in subtype:
            repo = params.get("REPO_ROOT", "unknown")
            _write("INFO ", "SCAN_COMPLETE", f"repo={repo}  agent={subtype}  model={model}", sid)
            return

        # A successful background Agent PostToolUse acknowledges launch only.
        # The deterministic waiter closes that call after validating its
        # attempt-specific output. It must never create a second start event.

    # --- errors from non-Agent tools take priority ---
    elif is_err:
        _write("ERROR", "TOOL_ERROR", f"tool={tool}  {_mask_secrets(_clip(resp))}{dur_tail}", sid)
        return

    # --- Write tool ---
    elif tool == "Write":
        path = inp.get("file_path", "?")
        content = inp.get("content", "")
        size = len(content) if isinstance(content, str) else 0
        _write("INFO ", "FILE_WRITE", f"{path}  ({size:,} chars){dur_tail}", sid)

        # Dedicated marker: context resolver finished — context is now available
        # for all subsequent phases.
        if ".threat-modeling-context.md" in path:
            _write("INFO ", "CONTEXT_READY", f"context_file={path}  ({size:,} chars)", sid)

    # --- Edit tool ---
    elif tool == "Edit":
        path = inp.get("file_path", "?")
        old = inp.get("old_string", "")
        new = inp.get("new_string", "")
        rall = inp.get("replace_all", False)
        delta = len(new) - len(old) if isinstance(new, str) and isinstance(old, str) else 0
        tag = " (replace_all)" if rall else ""
        _write("INFO ", "FILE_EDIT", f"{path}  delta={delta:+,} chars{tag}{dur_tail}", sid)

    # --- MultiEdit tool ---
    elif tool == "MultiEdit":
        path = inp.get("file_path", "?")
        edits = inp.get("edits", []) or []
        n_edits = len(edits) if isinstance(edits, list) else 0
        _write("INFO ", "FILE_EDIT", f"{path}  multi_edits={n_edits}{dur_tail}", sid)

    # --- Read tool — diagnostic (closes visibility gap on silent stretches) ---
    elif tool == "Read":
        path = inp.get("file_path", "?")
        offset = inp.get("offset")
        limit = inp.get("limit")
        rng = ""
        if offset is not None or limit is not None:
            rng = f"  range=offset={offset or 0},limit={limit or 'eof'}"
        _write("INFO ", "FILE_READ", f"{path}{rng}{dur_tail}", sid)

    # --- Grep tool — diagnostic ---
    elif tool == "Grep":
        pattern = _clip(str(inp.get("pattern", "")), 60)
        path = inp.get("path", "")
        glob_pat = inp.get("glob", "")
        scope = f"  path={path}" if path else (f"  glob={glob_pat}" if glob_pat else "")
        _write("INFO ", "GREP_RUN", f"pattern={pattern}{scope}{dur_tail}", sid)

    # --- Glob tool — diagnostic ---
    elif tool == "Glob":
        pattern = _clip(str(inp.get("pattern", "")), 80)
        path = inp.get("path", "")
        scope = f"  path={path}" if path else ""
        _write("INFO ", "GLOB_RUN", f"pattern={pattern}{scope}{dur_tail}", sid)

    # --- Bash tool — warn on errors + extract substep progress for verbose ---
    elif tool == "Bash":
        cmd_str = str(inp.get("command", ""))
        resp_str = str(resp).lower()
        ERROR_KW = (
            "permission denied",
            "no such file or directory",
            "command not found",
            "operation not permitted",
            "exit status 1",
            "exit code 1",
            "traceback",
            "syntaxerror",
            "error:",
            # Sprint 1B (M3.5): a script that prints `usage:` typically
            # means argparse rejected the invocation — caller almost
            # certainly mistyped a flag. Without this trigger the
            # orchestrator may treat the call as a success and waste
            # the rest of its turn budget waiting (the 2026-04-27
            # Phase-10b regression burnt 5+ minutes this way).
            "usage:",
        )
        # Exclude legitimate `--help` / `-h` discovery calls — they print
        # `usage:` to stdout but are not failures. Without this guard the
        # orchestrator's help-discovery noise (typically 10+ calls per run)
        # drowned out genuine errors in the log.
        is_help_call = "--help" in cmd_str or cmd_str.endswith(" -h") or " -h " in cmd_str
        is_warn = any(kw in resp_str for kw in ERROR_KW) and not is_help_call
        if is_warn:
            cmd = _mask_secrets(_clip(cmd_str, 80))
            _write("WARN ", "BASH_WARN", f"cmd={cmd}  resp={_mask_secrets(_clip(str(resp), 100))}{dur_tail}", sid)
        else:
            # BASH_OK closes the diagnostic gap: previously only WARN-Bash hit
            # the log, so any successful long-running script (compose_threat_model.py,
            # validate_intermediate.py, pregenerate_fragments.py) was invisible.
            # With BASH_OK + dur=<seconds> a 10-minute compose call shows up directly.
            # Skip noisy `.agent-run.log` echo commands (the agent emits the canonical
            # PHASE_START / PHASE_END entries via that channel, so logging the wrapper
            # bash call would duplicate every phase event).
            if ".agent-run.log" not in cmd_str:
                cmd = _mask_secrets(_clip(cmd_str, 80))
                _write("INFO ", "BASH_OK", f"cmd={cmd}{dur_tail}", sid)

        # --- Surface STEP_START / PHASE_START / PHASE_END / AGENT_INVOKE /
        #     AGENT_DONE from orchestrator Bash echo commands.  These are
        #     written to .agent-run.log by the agent.  Mirror PHASE_START
        #     and PHASE_END to .hook-events.log so test_hook_log_records_phase_progression
        #     (and any external tooling that reads .hook-events.log) can see
        #     phase boundaries without parsing .agent-run.log.  All other
        #     events are emitted to stderr only (no duplication in the log).
        if ".agent-run.log" in cmd_str:
            _emit_substep_progress(cmd_str)
            _mirror_phase_events_to_hook_log(cmd_str, sid)

    # ----- Budget watchdog (count this tool call against agent's maxTurns) -----
    # Runs LAST so any earlier early-return paths still count the call. Failures
    # are swallowed inside the watchdog itself — never blocks the hook.
    try:
        from budget_watchdog import format_detail, tally_and_check

        call = agent_lifecycle.unique_running_call(_output_dir(), (sid or "")[:8])
        if call is not None:
            crossing = tally_and_check(call, _output_dir())
            if crossing is not None:
                _write("WARN ", crossing["event"], format_detail(crossing), sid)
    except Exception:
        # Watchdog must never break a run.
        pass


def handle_subagent_start(data: dict, sid: str) -> None:
    runtime_agent_id = str(data.get("agent_id") or "")
    agent_type = str(data.get("agent_type") or "")
    try:
        call = agent_lifecycle.bind_runtime_agent_start(_output_dir(), runtime_agent_id, agent_type)
    except agent_lifecycle.LifecycleError as exc:
        _write(
            "WARN ",
            "AGENT_LIFECYCLE_REJECTED",
            f"runtime_agent_id={runtime_agent_id or '?'}  reason={exc}",
            sid,
        )
        return
    if call is None:
        _write(
            "WARN ",
            "AGENT_LIFECYCLE_REJECTED",
            f"runtime_agent_id={runtime_agent_id or '?'}  agent_type={agent_type or '?'}  reason=unmatched_subagent_start",
            sid,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    if sys.argv[1:] == ["--clear-active-tool-calls"]:
        clear_terminal_active_tool_calls()
        return
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        try:
            sys.stderr.write(f"[appsec] warning: hook received invalid JSON on stdin: {exc}\n")
        except Exception:
            pass
        return

    sid = data.get("session_id", "")
    event_name = data.get("hook_event_name", "")

    if event_name == "SubagentStart":
        handle_subagent_start(data, sid)
        return

    # Stop / SubagentStop
    if event_name in ("Stop", "SubagentStop") or "stop_reason" in data:
        handle_stop(data, sid, event_name)
        return

    # PreToolUse — captures Agent spawns at all session depths
    if event_name == "PreToolUse":
        handle_pre_tool_use(data, sid)
        return

    # PostToolUse (default)
    handle_post_tool_use(data, sid)


if __name__ == "__main__":
    main()
