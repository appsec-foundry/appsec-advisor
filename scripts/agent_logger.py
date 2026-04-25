#!/usr/bin/env python3
"""
appsec-advisor hook logger — writes to docs/security/.hook-events.log
in the current working directory (the analyzed repo).

This is SEPARATE from docs/security/.agent-run.log which is written
by the agents themselves via bash echo commands. Keeping them apart
avoids confusing chronological interleaving.

Triggered by: PreToolUse (all tools), PostToolUse (all tools), Stop, SubagentStop

Events logged:
  AGENT_SPAWN   — any Agent tool call is about to start (PreToolUse, all depths)
  SCAN_START    — threat-analyst dispatched / scan beginning (PreToolUse, top-level only)
  SCAN_COMPLETE — threat-analyst finished (PostToolUse, top-level only)
  CONTEXT_READY — context resolver wrote .threat-modeling-context.md (size)
  AGENT_INVOKE  — non-orchestrator agent completed (PostToolUse, top-level only)
  FILE_WRITE    — Write tool completed (path, size)
  FILE_EDIT     — Edit tool completed (path, char delta)
  TOOL_ERROR    — any tool returned is_error=true
  BASH_WARN     — Bash output contains permission/error indicators
  SESSION_STOP  — agent session ended (reason, token usage, estimated cost)
  MAX_TURNS     — agent hit its maxTurns limit (logged as ERROR)
  ASSESSMENT_SUMMARY — final summary (duration, mode, threat counts, tokens, cost, models)
  ASSESSMENT_FILES   — all files written during the assessment (full paths, deduplicated)

Why both PreToolUse (AGENT_SPAWN / SCAN_START) and PostToolUse (SCAN_COMPLETE / AGENT_INVOKE)?
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
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

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
        "input":       3.00,
        "output":     15.00,
        "cache_write": 3.75,
        "cache_read":  0.30,
    }
    pricing = _load_config().get("pricing", {})
    if pricing:
        return {
            "input":       pricing.get("input_per_1m", defaults["input"]),
            "output":      pricing.get("output_per_1m", defaults["output"]),
            "cache_write": pricing.get("cache_write_per_1m", defaults["cache_write"]),
            "cache_read":  pricing.get("cache_read_per_1m", defaults["cache_read"]),
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


def _mark_checkpoint_aborted_if_dirty(stop_reason: str) -> None:
    """Rewrite `$OUTPUT_DIR/.appsec-checkpoint` to status=aborted on unclean stop.

    No-op when:
      * the checkpoint file does not exist (run never reached Phase 1, or
        already cleaned),
      * its current status is `completed` (clean finalization),
      * the stop_reason is on the whitelist of clean completions.

    Best-effort — failures are swallowed because this runs inside a hook and
    must never break the Stop event.
    """
    if stop_reason in _CLEAN_STOP_REASONS:
        return
    try:
        cp_path = os.path.join(_output_dir(), ".appsec-checkpoint")
        if not os.path.isfile(cp_path):
            return
        with open(cp_path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
        if not raw:
            return
        # Parse key=value pairs on a single line (or whitespace-separated).
        fields: dict[str, str] = {}
        for token in raw.split():
            if "=" in token:
                k, v = token.split("=", 1)
                fields[k.strip()] = v.strip()
        status = fields.get("status", "")
        if status in ("completed", "aborted"):
            # Already terminal — do not overwrite a legitimate final state.
            return
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
                fh.write(
                    f"phase={phase} status=aborted reason={stop_reason} aborted_at={ts}\n"
                )
    except Exception:
        # Never let a hook crash the session. The worst-case regression is
        # the pre-existing behaviour (status=started lingers until auto-clean).
        pass


def _write_trace(event: str, detail: str, sid: str = "") -> None:
    """Append a structured line to .appsec-trace.log when tracing is active."""
    if not _TRACING:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sid_tag = (sid or "")[:8].ljust(8)
    line = f"{ts}  [{sid_tag}]  TRACE  {event:<22}  {detail}\n"
    try:
        trace_file = _trace_path()
        _rotate_if_needed(trace_file)
        with open(trace_file, "a") as fh:
            fh.write(line)
    except Exception:
        pass  # never crash a hook


# In-memory store for agent dispatch timestamps, keyed by sid[:8].
# Used to compute wall-time per agent invocation.
_DISPATCH_TIMES: dict[str, float] = {}


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
                head = fh.read(512)
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
    cw  = usage.get("cache_creation_input_tokens", 0)
    cr  = usage.get("cache_read_input_tokens", 0)
    return (
        inp * _PRICING["input"]       / 1_000_000
        + out * _PRICING["output"]      / 1_000_000
        + cw  * _PRICING["cache_write"] / 1_000_000
        + cr  * _PRICING["cache_read"]  / 1_000_000
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
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts}  [--------]  {level:<5}  {agent:<18}  {event:<18}  {detail}\n"
    try:
        log_file = _agent_run_log_path()
        if os.path.exists(log_file):
            with open(log_file, "a") as fh:
                fh.write(line)
    except Exception:
        pass  # never crash a hook


# Map subagent_type identifiers to short agent names for .agent-run.log
_AGENT_SHORT_NAMES = {
    "appsec-threat-analyst":   "threat-analyst",
    "appsec-context-resolver": "context-resolver",
    "appsec-recon-scanner":    "recon-scanner",
    "appsec-dep-scanner":      "dep-scanner",
    "appsec-stride-analyzer":  "stride-analyzer",
    "appsec-qa-reviewer":      "qa-reviewer",
}


def _session_map_path() -> str:
    """Path to the lightweight session→agent mapping file."""
    return os.path.join(_output_dir(), ".session-agent-map")


def _save_session_agent(sid: str, agent: str) -> None:
    """Persist a session_id → agent_name mapping for SESSION_STOP attribution.

    Uses atomic write (write to temp file, then rename) to avoid corruption
    when multiple parallel agents write simultaneously.
    """
    try:
        import tempfile
        map_file = _session_map_path()
        # Read existing mappings (keep last 20 to avoid unbounded growth)
        lines = []
        if os.path.exists(map_file):
            with open(map_file) as fh:
                lines = fh.readlines()[-20:]
        lines.append(f"{sid}={agent}\n")
        # Atomic write: write to temp file in same directory, then rename
        dir_name = os.path.dirname(map_file)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".session-map-tmp-")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.writelines(lines[-20:])
            os.replace(tmp_path, map_file)
        except Exception:
            # Clean up temp file on failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception:
        pass  # never crash a hook


def _lookup_session_agent(sid: str) -> str:
    """Look up the agent name for a session_id. Returns '' if not found."""
    try:
        map_file = _session_map_path()
        if not os.path.exists(map_file):
            return ""
        with open(map_file) as fh:
            for line in fh:
                parts = line.strip().split("=", 1)
                if len(parts) == 2 and parts[0] == sid:
                    return parts[1]
    except Exception:
        pass
    return ""


# Events that are ALWAYS mirrored to stderr, even without --verbose. These
# are low-volume and high-signal — the user needs to see them live to know
# the run started / finished / hit an error, without opting in to the
# full verbose firehose. Higher-volume events (FILE_WRITE, FILE_EDIT,
# AGENT_INVOKE, BASH_WARN, CONTEXT_READY) stay behind the _VERBOSE gate.
_HIGH_SIGNAL_EVENTS = frozenset({
    "SCAN_START",
    "SCAN_COMPLETE",
    "TOOL_ERROR",
    "MAX_TURNS",
    "SESSION_STOP",
    "ASSESSMENT_SUMMARY",
})


def _write(level: str, event: str, detail: str, sid: str = "") -> None:
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sid = (sid or "")[:8].ljust(8)
    line = f"{ts}  [{sid}]  {level:<5}  {event:<18}  {detail}\n"
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


# Patterns that match secret values in grep output or command results.
# Each pattern captures the "prefix" group to keep and the "secret" group to mask.
_SECRET_PATTERNS = [
    # key = "value" or key = 'value'  (password, secret, token, api_key, etc.)
    re.compile(
        r"""(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"""
        r"""api[_-]?secret|auth[_-]?token|client[_-]?secret|"""
        r"""aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?)"""
        r"""([^'"\s]{4,})"""),
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
    """Return value of KEY=<value> from a prompt string, or ''."""
    marker = f"{key}="
    if marker not in text:
        return ""
    raw = text.split(marker, 1)[1]
    # stop at first whitespace or newline
    val = raw.split()[0] if raw.split() else ""
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
                    completes.append({
                        "agent": m_agent.group(1),
                        "in": m_in.group(1).replace(",", "") if m_in else "0",
                        "out": m_out.group(1).replace(",", "") if m_out else "0",
                        "cost": m_cost.group(1) if m_cost else "n/a",
                        "turns": m_turns.group(1) if m_turns else "?",
                        "wall_secs": m_wall.group(1) if m_wall else "?",
                        "stop": m_stop.group(1) if m_stop else "?",
                    })
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
            f"{int(c['wall_secs'])//60}m{int(c['wall_secs'])%60:02d}s"
            if c["wall_secs"].isdigit() else c["wall_secs"]
        )
        rows.append(
            f"| {agent:<28} | {d.get('model', '?'):<22} | "
            f"{d.get('context_ktok', '?'):>10} | "
            f"{str(in_ktok):>8} | {str(out_ktok):>8} | "
            f"{'$'+c['cost'] if c['cost'] != 'n/a' else 'n/a':>8} | "
            f"{c['turns']:>5}/{d.get('max_turns','?'):<5} | "
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

    # --- Aggregate from .hook-events.log ---
    # Only aggregate lines from the CURRENT assessment run.  The log file
    # persists across runs (rotated only at 5 MB), so we must find the last
    # SCAN_START marker and ignore everything before it.
    total_in = 0
    total_out = 0
    total_cw = 0
    total_cr = 0
    total_cost = 0.0
    agent_models: dict[str, str] = {}  # short_name → model
    threat_model_path = ""
    written_files: list[str] = []  # all FILE_WRITE paths (deduplicated later)
    first_ts = ""
    last_ts = ""

    try:
        with open(log_file) as fh:
            all_lines = fh.readlines()

        # Find the last SCAN_START line — everything before it belongs to
        # a previous assessment and must be excluded.
        scan_start_idx = 0
        for idx, line in enumerate(all_lines):
            if "SCAN_START" in line:
                scan_start_idx = idx

        for line in all_lines[scan_start_idx:]:
            # Track timestamps for duration
            ts_m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", line)
            if ts_m:
                if not first_ts:
                    first_ts = ts_m.group(1)
                last_ts = ts_m.group(1)

            # Sum SESSION_STOP token/cost data
            if "SESSION_STOP" in line:
                m = re.search(r"in=([\d,]+)", line)
                if m:
                    total_in += int(m.group(1).replace(",", ""))
                m = re.search(r"out=([\d,]+)", line)
                if m:
                    total_out += int(m.group(1).replace(",", ""))
                m = re.search(r"cache_write=([\d,]+)", line)
                if m:
                    total_cw += int(m.group(1).replace(",", ""))
                m = re.search(r"cache_read=([\d,]+)", line)
                if m:
                    total_cr += int(m.group(1).replace(",", ""))
                m = re.search(r"cost=\$([\d.]+)", line)
                if m:
                    total_cost += float(m.group(1))

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
    except Exception:
        pass

    # --- Duration ---
    duration = "?"
    if first_ts and last_ts:
        try:
            t1 = datetime.strptime(first_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            t2 = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            secs = int((t2 - t1).total_seconds())
            duration = f"{secs // 60}m {secs % 60:02d}s"
        except Exception:
            pass

    # --- Mode and per-phase durations from .agent-run.log ---
    mode = "full"
    phase_starts: dict[str, str] = {}  # phase_key → ISO timestamp
    phase_durations: list[tuple[str, int]] = []  # (phase_label, seconds)
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
                                phase_durations.append((f"{key} {label}".strip(), secs))
                            except Exception:
                                pass
    except Exception:
        pass

    # --- Threat counts from threat-model.md ---
    threats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_threats = 0
    if threat_model_path and os.path.exists(threat_model_path):
        try:
            with open(threat_model_path) as fh:
                lines = fh.readlines()
            # Count threat-register table rows (lines starting with '|') that
            # carry an emoji risk badge in the Risk column.  The old pattern
            # `>{sev}</span>` matched HTML span badges that the threat model no
            # longer emits; the canonical format is `🔴 Critical`, `🟠 High`,
            # `🟡 Medium`, `🟢 Low` inside a table cell.
            _EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            for sev, emoji in _EMOJI.items():
                badge = f"{emoji} {sev}"
                threats[sev] = sum(
                    1 for ln in lines
                    if ln.startswith("|") and badge in ln
                )
            total_threats = sum(threats.values())
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

    # --- Write summary events ---
    _write("INFO ", "ASSESSMENT_SUMMARY",
           f"mode={mode}  duration={duration}  "
           f"plugin_version={plugin_version}  analysis_version={analysis_version}  "
           f"threats={total_threats} "
           f"(Critical={threats['Critical']}, High={threats['High']}, "
           f"Medium={threats['Medium']}, Low={threats['Low']})",
           sid)

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
    _write("INFO ", "ASSESSMENT_TOKENS",
           f"throughput={total_throughput:,}  "
           f"input={total_input:,}  output={total_out:,}  "
           f"(input split: fresh={total_in:,} cache_write={total_cw:,} cache_read={total_cr:,})  "
           f"{cost_str}",
           sid)

    models_str = ", ".join(f"{a}={m}" for a, m in sorted(agent_models.items()))
    _write("INFO ", "ASSESSMENT_MODELS",
           f"agents: {models_str}" if models_str else "agents: none detected",
           sid)

    # --- Deduplicate and emit written files ---
    seen: set[str] = set()
    unique_files: list[str] = []
    for f in written_files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)
    if unique_files:
        files_str = "  ".join(unique_files)
        _write("INFO ", "ASSESSMENT_FILES",
               f"count={len(unique_files)}  files: {files_str}",
               sid)

    # --- Mirror to .agent-run.log ---
    _write_agent_run("INFO", "hook-logger", "ASSESSMENT_SUMMARY",
                     f"mode={mode}  duration={duration}  "
                     f"plugin_version={plugin_version}  analysis_version={analysis_version}  "
                     f"threats={total_threats} "
                     f"(Critical={threats['Critical']}, High={threats['High']}, "
                     f"Medium={threats['Medium']}, Low={threats['Low']})")
    _write_agent_run("INFO", "hook-logger", "ASSESSMENT_TOKENS",
                     f"throughput={total_throughput:,}  "
                     f"input={total_input:,}  output={total_out:,}  "
                     f"(input split: fresh={total_in:,} cache_write={total_cw:,} cache_read={total_cr:,})  "
                     f"cost=${total_cost:.4f}  billing={billing}")
    _write_agent_run("INFO", "hook-logger", "ASSESSMENT_MODELS",
                     f"agents: {models_str}" if models_str else "agents: none detected")
    if unique_files:
        _write_agent_run("INFO", "hook-logger", "ASSESSMENT_FILES",
                         f"count={len(unique_files)}  files: {files_str}")

    # --- Per-phase durations ---
    if phase_durations:
        def _fmt_dur(s: int) -> str:
            return f"{s // 60}m {s % 60:02d}s" if s >= 60 else f"{s}s"

        phases_str = "  ".join(
            f"{label}={_fmt_dur(secs)}" for label, secs in phase_durations
        )
        _write("INFO ", "ASSESSMENT_PHASES", phases_str, sid)
        _write_agent_run("INFO", "hook-logger", "ASSESSMENT_PHASES", phases_str)

    # --- Tracing: emit ASSESSMENT_TRACE summary table from .appsec-trace.log ---
    if _TRACING:
        _write_trace_summary(sid)


# ---------------------------------------------------------------------------
# Event handlers
# ---------------------------------------------------------------------------

def _agent_params(prompt: str) -> dict:
    """Extract well-known KEY=value pairs from an agent prompt."""
    params = {}
    for key in ("REPO_ROOT", "COMPONENT_ID", "MANIFESTS", "CONTEXT_FILE"):
        val = _extract_param(prompt, key)
        if val:
            params[key] = val
    return params


# ---------------------------------------------------------------------------
# Verbose-only: extract substep progress from Bash echo commands
# ---------------------------------------------------------------------------

# Patterns that indicate a progress event in a Bash echo to .agent-run.log.
# We extract the human-readable description and emit it to stderr only.
_PROGRESS_EVENTS = re.compile(
    r"(?:PHASE_START|PHASE_END|STEP_START|STEP_END|ASSESSMENT_START|ASSESSMENT_END"
    r"|AGENT_INVOKE|AGENT_DONE|AGENT_DISPATCH)"
)


def _emit_substep_progress(cmd: str) -> None:
    """Parse a Bash echo command that writes to .agent-run.log and emit the
    human-readable substep description to stderr.

    Only called when _VERBOSE is True.  Does NOT write to the log file —
    the agent's Bash command already handles that.
    """
    # The echo command looks like:
    #   echo "<timestamp>  [--------]  INFO   threat-analyst  STEP_START   [Phase 8] Rating IAM…" >> ".../.agent-run.log"
    # We want to extract the event type and the message after it.
    m = _PROGRESS_EVENTS.search(cmd)
    if not m:
        return
    event = m.group(0)

    # Extract the message that follows the event keyword.
    # The message is everything after the event name up to the closing quote
    # or end of the echo string.
    after = cmd[m.end():]
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
    if event in ("PHASE_START", "STEP_START", "AGENT_INVOKE", "AGENT_DISPATCH",
                 "ASSESSMENT_START"):
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
    "Read":  "reading",
    "Grep":  "searching",
    "Glob":  "scanning",
    "Bash":  "executing",
    "Write": "writing",
    "Edit":  "editing",
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
    agent = _lookup_session_agent((sid or "")[:8])
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


def handle_pre_tool_use(data: dict, sid: str) -> None:
    """Log AGENT_SPAWN for Agent tool calls, and emit verbose activity
    indicators for all other tool calls from sub-agent sessions.

    PreToolUse fires in the session that makes the tool call (any depth),
    so this handler captures sub-agent activity that PostToolUse misses
    (PostToolUse only fires in the outermost session).
    """
    tool = data.get("tool_name", "")

    # --- Non-Agent tools: verbose-only activity indicator ---
    if tool != "Agent":
        if _VERBOSE:
            _emit_activity(tool, data.get("tool_input", {}), sid)
        return

    inp     = data.get("tool_input", {})
    subtype = inp.get("subagent_type", "unknown")
    desc    = inp.get("description", "")
    bg      = inp.get("run_in_background", False)
    bg_tag  = " [bg]" if bg else "     "
    model   = _agent_model(subtype, inp)
    params  = _agent_params(inp.get("prompt", "") or "")
    pairs   = "  ".join(f"{k}={v}" for k, v in params.items())

    _write("INFO ", "AGENT_SPAWN",
           f"{subtype:<38}{bg_tag}  model={model}  {desc}"
           + (f"  [{pairs}]" if pairs else ""),
           sid)

    # Tracing: record dispatch time and emit AGENT_DISPATCH with context size estimate
    if _TRACING:
        prompt_str = inp.get("prompt", "") or ""
        context_chars = len(prompt_str)
        context_ktok = round(context_chars / 3500, 1)  # ~3.5 chars/token
        max_turns_val = _extract_param(prompt_str, "MAX_TURNS") or "?"
        _DISPATCH_TIMES[(sid or "")[:8]] = time.time()
        _write_trace("AGENT_DISPATCH",
                     f"agent={_AGENT_SHORT_NAMES.get(subtype.split(':')[-1], subtype.split(':')[-1])}  "
                     f"model={model}  bg={str(bg).lower()}  "
                     f"context_chars={context_chars:,}  context_ktok={context_ktok}  "
                     f"max_turns={max_turns_val}",
                     sid)

    # Map session_id → agent short name so SESSION_STOP can attribute
    # token/cost data to the correct agent in .agent-run.log.
    # Each hook invocation is a separate process, so we persist the
    # mapping in a lightweight file.
    raw_name = subtype.split(":")[-1] if ":" in subtype else subtype
    short = _AGENT_SHORT_NAMES.get(raw_name, "")
    if short and sid:
        _save_session_agent(sid[:8], short)

    # SCAN_START fires at PreToolUse (dispatch time) so it precedes
    # the threat-analyst's own SESSION_STOP in the log. Emitting it
    # here (before the agent runs) fixes the ordering bug where
    # SCAN_START was previously logged at PostToolUse (after completion).
    if "threat-analyst" in raw_name:
        repo = params.get("REPO_ROOT", "unknown")
        _write("INFO ", "SCAN_START",
               f"repo={repo}  agent={subtype}  model={model}", sid)
        # Reset the summary sentinel so this new assessment gets its own summary
        sentinel = os.path.join(os.path.dirname(_log_path()), ".assessment-summary-emitted")
        try:
            os.remove(sentinel)
        except FileNotFoundError:
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
        with open(transcript_path, "r", encoding="utf-8", errors="replace") as fh:
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


def handle_stop(data: dict, sid: str, event_name: str = "") -> None:
    reason = data.get("stop_reason", "unknown")
    level  = "ERROR" if reason == "max_turns" else "INFO "

    # ------------------------------------------------------------------
    # Transcript is the authoritative source for per-session totals.
    # The Stop-event payload carries at best a single turn's usage (and in
    # Subscription mode usually nothing at all). The transcript, parsed by
    # _usage_from_transcript, streams the full JSONL and sums every assistant
    # turn's usage block — that's the correct session cumulative total.
    # Payload usage is kept as a fallback for the unlikely case where the
    # transcript path is not provided or the file is unreadable.
    # ------------------------------------------------------------------
    transcript = data.get("transcript_path", "")
    usage = _usage_from_transcript(transcript) if transcript else {}
    usage_source = "transcript" if usage else ""

    if not usage:
        payload_usage = data.get("usage", {}) or {}
        if payload_usage:
            usage = payload_usage
            usage_source = "payload-last-turn"

    inp   = usage.get("input_tokens", 0)
    out   = usage.get("output_tokens", 0)
    cw    = usage.get("cache_creation_input_tokens", 0)
    cr    = usage.get("cache_read_input_tokens", 0)
    has_usage = bool(usage)  # False when neither the payload nor the transcript had usage

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
        _write("ERROR", "MAX_TURNS",
               "Agent terminated — maxTurns limit reached. "
               "Increase maxTurns in agent frontmatter or reduce task scope.",
               sid)

    # --- Mirror critical events to .agent-run.log ---
    # Look up which appsec agent owns this session via the file-based
    # mapping written during AGENT_SPAWN (each hook call is a new process).
    agent_name = _lookup_session_agent(sid[:8]) if sid else ""

    if agent_name:
        # Mirror SESSION_STOP with token/cost summary to agent-run.log
        _write_agent_run(level, agent_name, "SESSION_STOP", detail)

        # Mirror MAX_TURNS to agent-run.log so it's visible in the unified log
        if reason == "max_turns":
            _write_agent_run("ERROR", agent_name, "MAX_TURNS",
                             "Agent terminated — maxTurns limit reached")

        # Stamp the checkpoint as aborted when the outermost orchestrator
        # session ends uncleanly. Leaves a durable signal that the next
        # pre-flight (check_state.py --auto-clean) can act on without waiting
        # for the mtime-based stale threshold.
        if agent_name == "threat-analyst":
            _mark_checkpoint_aborted_if_dirty(reason)

    # --- Tracing: emit AGENT_COMPLETE with per-session token/cost/wall-time ---
    if _TRACING and agent_name:
        wall_secs = "?"
        dispatch_key = (sid or "")[:8]
        if dispatch_key in _DISPATCH_TIMES:
            wall_secs = str(round(time.time() - _DISPATCH_TIMES.pop(dispatch_key)))
        turns_used = "?"
        if transcript:
            try:
                count = 0
                with open(transcript, "r", encoding="utf-8", errors="replace") as fh:
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
        _write_trace("AGENT_COMPLETE",
                     f"agent={agent_name}  "
                     f"in={inp:,}  out={out:,}  cache_write={cw:,}  cache_read={cr:,}  "
                     f"cost={cost_val}  turns={turns_used}  stop={reason}  "
                     f"wall_secs={wall_secs}",
                     sid)

    # --- Assessment summary on outermost session Stop ---
    # Guard: only emit the summary ONCE per assessment. Previous versions emitted
    # it on every Stop event, producing 5-6 duplicate ASSESSMENT_SUMMARY blocks
    # in .hook-events.log and .agent-run.log. The sentinel file ensures idempotency.
    if event_name == "Stop":
        sentinel = os.path.join(os.path.dirname(_log_path()), ".assessment-summary-emitted")
        if not os.path.exists(sentinel):
            try:
                _write_assessment_summary(sid)
                # Write sentinel so subsequent Stop events in the same assessment
                # (e.g. QA reviewer session stop) skip the summary.
                with open(sentinel, "w") as fh:
                    fh.write(sid[:8] if sid else "unknown")
            except Exception:
                pass  # never crash a hook


def handle_post_tool_use(data: dict, sid: str) -> None:
    tool    = data.get("tool_name", "")
    inp     = data.get("tool_input", {})
    resp    = data.get("tool_response", "")
    is_err  = data.get("is_error", False)

    # --- errors from any tool take priority ---
    if is_err:
        _write("ERROR", "TOOL_ERROR",
               f"tool={tool}  {_mask_secrets(_clip(resp))}", sid)
        return

    # --- Agent invocation ---
    if tool == "Agent":
        subtype = inp.get("subagent_type", "unknown")
        desc    = inp.get("description", "")
        bg      = inp.get("run_in_background", False)
        bg_tag  = " [bg]" if bg else "     "
        model   = _agent_model(subtype, inp)
        params  = _agent_params(inp.get("prompt", "") or "")
        pairs   = "  ".join(f"{k}={v}" for k, v in params.items())

        # Emit a SCAN_COMPLETE line when the orchestrator agent finishes.
        # (SCAN_START is now emitted at PreToolUse / dispatch time, so the
        # chronological order in the log is correct: SCAN_START → SESSION_STOP
        # → SCAN_COMPLETE. Previously both were emitted at PostToolUse which
        # placed SCAN_START *after* SESSION_STOP.)
        if "threat-analyst" in subtype:
            repo = params.get("REPO_ROOT", "unknown")
            _write("INFO ", "SCAN_COMPLETE",
                   f"repo={repo}  agent={subtype}  model={model}", sid)
            return

        # Regular sub-agent completion (only visible at the top-level session)
        _write("INFO ", "AGENT_INVOKE",
               f"{subtype:<38}{bg_tag}  model={model}  {desc}"
               + (f"  [{pairs}]" if pairs else ""),
               sid)

    # --- Write tool ---
    elif tool == "Write":
        path    = inp.get("file_path", "?")
        content = inp.get("content", "")
        size    = len(content) if isinstance(content, str) else 0
        _write("INFO ", "FILE_WRITE", f"{path}  ({size:,} chars)", sid)

        # Dedicated marker: context resolver finished — context is now available
        # for all subsequent phases.
        if ".threat-modeling-context.md" in path:
            _write("INFO ", "CONTEXT_READY",
                   f"context_file={path}  ({size:,} chars)", sid)

    # --- Edit tool ---
    elif tool == "Edit":
        path = inp.get("file_path", "?")
        old  = inp.get("old_string", "")
        new  = inp.get("new_string", "")
        rall = inp.get("replace_all", False)
        delta = len(new) - len(old) if isinstance(new, str) and isinstance(old, str) else 0
        tag   = " (replace_all)" if rall else ""
        _write("INFO ", "FILE_EDIT",
               f"{path}  delta={delta:+,} chars{tag}", sid)

    # --- Bash tool — warn on errors + extract substep progress for verbose ---
    elif tool == "Bash":
        cmd_str = str(inp.get("command", ""))
        resp_str = str(resp).lower()
        ERROR_KW = ("permission denied", "no such file or directory",
                    "command not found", "operation not permitted",
                    "exit status 1", "exit code 1", "traceback",
                    "syntaxerror", "error:")
        if any(kw in resp_str for kw in ERROR_KW):
            cmd = _mask_secrets(_clip(cmd_str, 80))
            _write("WARN ", "BASH_WARN",
                   f"cmd={cmd}  resp={_mask_secrets(_clip(str(resp), 100))}",
                   sid)

        # --- Verbose-only: surface STEP_START / PHASE_START / PHASE_END from
        #     orchestrator Bash echo commands.  These are written to
        #     .agent-run.log by the agent but never pass through the hook
        #     pipeline, so interactive verbose mode would miss them.  Extract
        #     the human-readable part and emit it to stderr only (no log file
        #     write — the agent already wrote the canonical entry).
        if _VERBOSE and ".agent-run.log" in cmd_str:
            _emit_substep_progress(cmd_str)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        try:
            sys.stderr.write(f"[appsec] warning: hook received invalid JSON on stdin: {exc}\n")
        except Exception:
            pass
        return

    sid        = data.get("session_id", "")
    event_name = data.get("hook_event_name", "")

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


main()
