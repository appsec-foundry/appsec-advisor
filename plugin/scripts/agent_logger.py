#!/usr/bin/env python3
"""
appsec-plugin hook logger — writes to docs/security/.agent-run.log
in the current working directory (the analyzed repo).

Triggered by: PostToolUse (all tools), Stop

Events logged:
  SCAN_START   — threat-analyst spawned (full vs. incremental, repo path)
  AGENT_INVOKE — any sub-agent spawned (name, description, background flag)
  FILE_WRITE   — Write tool completed (path, size)
  TOOL_ERROR   — any tool returned is_error=true
  BASH_WARN    — Bash output contains permission/error indicators
  SESSION_STOP — agent session ended (reason: end_turn | max_turns | error | …)
"""
import json
import os
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log_path() -> str:
    log_dir = os.path.join(os.getcwd(), "docs", "security")
    os.makedirs(log_dir, exist_ok=True)
    return os.path.join(log_dir, ".agent-run.log")


def _write(level: str, event: str, detail: str, sid: str = "") -> None:
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sid = (sid or "")[:8].ljust(8)
    line = f"{ts}  [{sid}]  {level:<5}  {event:<18}  {detail}\n"
    try:
        with open(_log_path(), "a") as fh:
            fh.write(line)
    except Exception:
        pass  # never crash a hook


def _clip(s, n: int = 120) -> str:
    s = str(s).replace("\n", " ").strip()
    return s[:n] + "…" if len(s) > n else s


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

def handle_stop(data: dict, sid: str) -> None:
    reason = data.get("stop_reason", "unknown")
    level  = "ERROR" if reason == "max_turns" else "INFO "
    _write(level, "SESSION_STOP", f"stop_reason={reason}", sid)


def handle_post_tool_use(data: dict, sid: str) -> None:
    tool    = data.get("tool_name", "")
    inp     = data.get("tool_input", {})
    resp    = data.get("tool_response", "")
    is_err  = data.get("is_error", False)

    # --- errors from any tool take priority ---
    if is_err:
        _write("ERROR", "TOOL_ERROR", f"tool={tool}  {_clip(resp)}", sid)
        return

    # --- Agent invocation ---
    if tool == "Agent":
        subtype = inp.get("subagent_type", "unknown")
        desc    = inp.get("description", "")
        prompt  = inp.get("prompt", "") or ""
        bg      = inp.get("run_in_background", False)
        bg_tag  = " [bg]" if bg else "     "

        # Extract useful scanning parameters from the prompt
        params = {}
        for key in ("FORCE_FULL", "REPO_ROOT", "COMPONENT_ID", "MANIFESTS", "CONTEXT_FILE"):
            val = _extract_param(prompt, key)
            if val:
                params[key] = val

        # Emit a dedicated SCAN_START line for the orchestrator agent
        if "threat-analyst" in subtype:
            mode = "FULL" if params.get("FORCE_FULL") == "true" else \
                   "INCREMENTAL" if params.get("FORCE_FULL") == "false" else "AUTO"
            repo = params.get("REPO_ROOT", "unknown")
            _write("INFO ", "SCAN_START",
                   f"mode={mode:<11}  repo={repo}  agent={subtype}", sid)
            return

        # Regular sub-agent invocation
        param_pairs = "  ".join(f"{k}={v}" for k, v in params.items())
        _write("INFO ", "AGENT_INVOKE",
               f"{subtype:<38}{bg_tag}  {desc}"
               + (f"  [{param_pairs}]" if param_pairs else ""),
               sid)

    # --- Write tool ---
    elif tool == "Write":
        path    = inp.get("file_path", "?")
        content = inp.get("content", "")
        size    = len(content) if isinstance(content, str) else 0
        _write("INFO ", "FILE_WRITE", f"{path}  ({size:,} chars)", sid)

    # --- Bash tool — only warn on error indicators ---
    elif tool == "Bash":
        resp_str = str(resp).lower()
        ERROR_KW = ("permission denied", "no such file or directory",
                    "command not found", "operation not permitted",
                    "exit status 1", "exit code 1", "traceback",
                    "syntaxerror", "error:")
        if any(kw in resp_str for kw in ERROR_KW):
            cmd = _clip(str(inp.get("command", "")), 80)
            _write("WARN ", "BASH_WARN",
                   f"cmd={cmd}  resp={_clip(str(resp), 100)}", sid)


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

    # PostToolUse (default)
    handle_post_tool_use(data, sid)


main()
