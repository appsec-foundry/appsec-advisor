#!/usr/bin/env python3
"""
appsec-plugin hook logger — writes to docs/security/.hook-events.log
in the current working directory (the analyzed repo).

This is SEPARATE from docs/security/.agent-run.log which is written
by the agents themselves via bash echo commands. Keeping them apart
avoids confusing chronological interleaving.

Triggered by: PreToolUse (Agent tool only), PostToolUse (all tools), Stop

Events logged:
  AGENT_SPAWN   — any Agent tool call is about to start (PreToolUse, all depths)
  SCAN_START    — threat-analyst completed (PostToolUse, top-level only)
  CONTEXT_READY — context resolver wrote .threat-modeling-context.md (size)
  AGENT_INVOKE  — non-orchestrator agent completed (PostToolUse, top-level only)
  FILE_WRITE    — Write tool completed (path, size)
  FILE_EDIT     — Edit tool completed (path, char delta)
  TOOL_ERROR    — any tool returned is_error=true
  BASH_WARN     — Bash output contains permission/error indicators
  SESSION_STOP  — agent session ended (reason, token usage, estimated cost)
  MAX_TURNS     — agent hit its maxTurns limit (logged as ERROR)

Why both PreToolUse (AGENT_SPAWN) and PostToolUse (SCAN_START / AGENT_INVOKE)?
  PostToolUse for the Agent tool only fires in the *outermost* Claude session —
  the one where the skill runs. Sub-agents spawned from within appsec-threat-analyst
  (context-resolver, recon-scanner, dep-scanner, stride-analyzer) are invisible to
  PostToolUse because that hook does not propagate through nested agent sessions.
  PreToolUse fires in the session that is *about to call* the tool, which includes
  sub-agent sessions, giving full visibility at dispatch time.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Pricing (USD per 1 M tokens) — loaded from config or defaults
# ---------------------------------------------------------------------------
def _load_pricing() -> dict:
    """Load pricing from plugin config.json, fall back to built-in defaults."""
    defaults = {
        "input":       3.00,
        "output":     15.00,
        "cache_write": 3.75,
        "cache_read":  0.30,
    }
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if plugin_root:
        config_path = os.path.join(plugin_root, "config.json")
        try:
            with open(config_path) as fh:
                cfg = json.load(fh)
            pricing = cfg.get("pricing", {})
            if pricing:
                return {
                    "input":       pricing.get("input_per_1m", defaults["input"]),
                    "output":      pricing.get("output_per_1m", defaults["output"]),
                    "cache_write": pricing.get("cache_write_per_1m", defaults["cache_write"]),
                    "cache_read":  pricing.get("cache_read_per_1m", defaults["cache_read"]),
                }
        except Exception:
            pass
    return defaults

_PRICING = _load_pricing()


# ---------------------------------------------------------------------------
# Verbose mode — mirror log lines to stderr for real-time terminal output
# ---------------------------------------------------------------------------
def _is_verbose() -> bool:
    """Check whether verbose logging is enabled.

    Enabled by either:
      - Environment variable APPSEC_VERBOSE=1 (or any truthy value)
      - config.json logging.verbose: true
    """
    env = os.environ.get("APPSEC_VERBOSE", "").strip()
    if env and env not in ("0", "false", "no"):
        return True
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if plugin_root:
        config_path = os.path.join(plugin_root, "config.json")
        try:
            with open(config_path) as fh:
                cfg = json.load(fh)
            return bool(cfg.get("logging", {}).get("verbose", False))
        except Exception:
            pass
    return False


_VERBOSE = _is_verbose()

# ---------------------------------------------------------------------------
# Log rotation — rotate when file exceeds threshold
# ---------------------------------------------------------------------------
_MAX_LOG_BYTES = 5 * 1024 * 1024  # 5 MB default

def _load_max_log_bytes() -> int:
    """Load max log size from plugin config.json."""
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if plugin_root:
        config_path = os.path.join(plugin_root, "config.json")
        try:
            with open(config_path) as fh:
                cfg = json.load(fh)
            return cfg.get("logging", {}).get("max_log_bytes", _MAX_LOG_BYTES)
        except Exception:
            pass
    return _MAX_LOG_BYTES

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
        except Exception:
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
    log_dir = os.path.join(os.getcwd(), "docs", "security")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, ".hook-events.log")


def _agent_run_log_path() -> str:
    """Return the path to .agent-run.log (written by agents, mirrored for key events)."""
    return os.path.join(os.getcwd(), "docs", "security", ".agent-run.log")


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
    return os.path.join(os.getcwd(), "docs", "security", ".session-agent-map")


def _save_session_agent(sid: str, agent: str) -> None:
    """Persist a session_id → agent_name mapping for SESSION_STOP attribution."""
    try:
        map_file = _session_map_path()
        # Read existing mappings (keep last 20 to avoid unbounded growth)
        lines = []
        if os.path.exists(map_file):
            with open(map_file) as fh:
                lines = fh.readlines()[-20:]
        lines.append(f"{sid}={agent}\n")
        with open(map_file, "w") as fh:
            fh.writelines(lines[-20:])
    except Exception:
        pass


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
    if _VERBOSE:
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


def handle_pre_tool_use(data: dict, sid: str) -> None:
    """Log AGENT_SPAWN for every Agent tool call at any session depth.

    PostToolUse for the Agent tool only fires in the outermost session.
    PreToolUse fires in the session that is dispatching the agent, so this
    handler captures internal spawns (context-resolver, recon-scanner, etc.)
    that are otherwise invisible in the log.
    """
    if data.get("tool_name") != "Agent":
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

    # Map session_id → agent short name so SESSION_STOP can attribute
    # token/cost data to the correct agent in .agent-run.log.
    # Each hook invocation is a separate process, so we persist the
    # mapping in a lightweight file.
    raw_name = subtype.split(":")[-1] if ":" in subtype else subtype
    short = _AGENT_SHORT_NAMES.get(raw_name, "")
    if short and sid:
        _save_session_agent(sid[:8], short)


def handle_stop(data: dict, sid: str) -> None:
    reason = data.get("stop_reason", "unknown")
    level  = "ERROR" if reason == "max_turns" else "INFO "

    usage = data.get("usage", {})
    inp   = usage.get("input_tokens", 0)
    out   = usage.get("output_tokens", 0)
    cw    = usage.get("cache_creation_input_tokens", 0)
    cr    = usage.get("cache_read_input_tokens", 0)

    detail = f"stop_reason={reason}"
    if inp or out:
        detail += f"  in={inp:,}  out={out:,}"
        if cw:
            detail += f"  cache_write={cw:,}"
        if cr:
            detail += f"  cache_read={cr:,}"
        detail += f"  cost=${_calc_cost(usage):.4f}"

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

        # Emit a dedicated SCAN_START line for the orchestrator agent
        if "threat-analyst" in subtype:
            repo = params.get("REPO_ROOT", "unknown")
            _write("INFO ", "SCAN_START",
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

    # --- Bash tool — only warn on error indicators ---
    elif tool == "Bash":
        resp_str = str(resp).lower()
        ERROR_KW = ("permission denied", "no such file or directory",
                    "command not found", "operation not permitted",
                    "exit status 1", "exit code 1", "traceback",
                    "syntaxerror", "error:")
        if any(kw in resp_str for kw in ERROR_KW):
            cmd = _mask_secrets(_clip(str(inp.get("command", "")), 80))
            _write("WARN ", "BASH_WARN",
                   f"cmd={cmd}  resp={_mask_secrets(_clip(str(resp), 100))}",
                   sid)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return

    sid        = data.get("session_id", "")
    event_name = data.get("hook_event_name", "")

    # Stop / SubagentStop
    if event_name in ("Stop", "SubagentStop") or "stop_reason" in data:
        handle_stop(data, sid)
        return

    # PreToolUse — captures Agent spawns at all session depths
    if event_name == "PreToolUse":
        handle_pre_tool_use(data, sid)
        return

    # PostToolUse (default)
    handle_post_tool_use(data, sid)


main()
