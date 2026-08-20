#!/usr/bin/env python3
"""Structured evaluators for the coding-agent checks in the Config/IaC catalog.

A regex cannot decide whether a settings file *enables* an agent sandbox: the
key may be absent, nested, or present and false, and the surrounding keys decide
whether its absence is a defect at all. Catalog entries with
``expect: structured`` name one of the evaluators below; each parses the
document and returns ``(line, snippet)`` for a violation, or ``None``.

Shared false-positive exclusion for the absence checks: a repository that
commits no agent autonomy is never flagged. Missing isolation is a violation
only where the same committed file pre-approves tool use — a permission
allow-list, an accept-edits default, auto-accepted tool calls, or a trusted
MCP server. An allow-list that grants nothing but read access does not count:
it reaches no shell and writes no file, so isolation buys nothing there.
Explicit weakening is covered by the regex checks in the catalog.

An unparsable file yields no violation: it carries no evidence of a posture,
and the surrounding recon inventory already reports the file itself.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Iterator

# Claude Code permission modes that let tool calls run without asking. The full
# set (`claude --help`) also carries `auto`, `manual` and `plan`; `auto` still
# routes through a decision the user can see, so only the unambiguous grants
# count as a reason to expect isolation.
_CLAUDE_AUTONOMOUS_MODES = {"acceptEdits", "bypassPermissions", "dontAsk"}
# Tools whose allow rules grant read access only. An unrecognised tool name
# counts as a grant: a rule the catalog does not know may still reach a shell.
_CLAUDE_READ_ONLY_TOOLS = {"Glob", "Grep", "LS", "NotebookRead", "Read"}
# Gemini CLI accepts a boolean or a container runtime name for `sandbox`.
_GEMINI_SANDBOX_RUNTIMES = {"docker", "podman"}


def _document(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _locate(text: str, *needles: str) -> tuple[int, str]:
    """First line carrying the earliest matching needle, else the file's first.

    Needles are tried in the order given, each against the whole file, so a
    caller can list a precise anchor before a fallback one. Scanning line by
    line instead would let a fallback that happens to sit higher in the file
    win over the exact evidence.
    """
    lines = text.splitlines()
    for needle in needles:
        for index, line in enumerate(lines, start=1):
            if needle in line:
                return index, line.strip()[:500]
    return 1, (lines[0].strip()[:500] if lines else "")


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


# --- Claude Code (.claude/settings*.json) ---------------------------------


def _claude_sandbox_enabled(data: dict[str, Any]) -> bool:
    sandbox = data.get("sandbox")
    if sandbox is True:
        return True
    return _mapping(sandbox).get("enabled") is True


def _grants_more_than_read(rule: Any) -> bool:
    """True for an allow rule that reaches beyond reading, e.g. ``Bash(...)``."""
    if not isinstance(rule, str) or not rule.strip():
        return False
    tool = rule.split("(", 1)[0].strip()
    return tool not in _CLAUDE_READ_ONLY_TOOLS


def _claude_grants_autonomy(data: dict[str, Any]) -> bool:
    permissions = _mapping(data.get("permissions"))
    allow = permissions.get("allow")
    if isinstance(allow, list) and any(_grants_more_than_read(rule) for rule in allow):
        return True
    mode = permissions.get("defaultMode") or data.get("defaultMode")
    if isinstance(mode, str) and mode.strip() in _CLAUDE_AUTONOMOUS_MODES:
        return True
    return data.get("enableAllProjectMcpServers") is True


def claude_sandbox_absent(text: str, path: Path) -> tuple[int, str] | None:
    data = _document(text)
    if data is None or _claude_sandbox_enabled(data) or not _claude_grants_autonomy(data):
        return None
    return _locate(text, '"permissions"', '"defaultMode"', '"enableAllProjectMcpServers"')


# --- Gemini CLI (.gemini/settings.json) -----------------------------------


def _gemini_sandbox_enabled(data: dict[str, Any]) -> bool:
    # v0.3 nests tool settings; earlier releases keep `sandbox` at the top level.
    sandbox = _mapping(data.get("tools")).get("sandbox", data.get("sandbox"))
    if sandbox is True:
        return True
    return isinstance(sandbox, str) and sandbox.strip().lower() in _GEMINI_SANDBOX_RUNTIMES


def _gemini_trusted_servers(data: dict[str, Any]) -> bool:
    return any(_mapping(server).get("trust") is True for server in _mapping(data.get("mcpServers")).values())


def _gemini_auto_accepts(data: dict[str, Any]) -> bool:
    return _mapping(data.get("tools")).get("autoAccept", data.get("autoAccept")) is True


def gemini_sandbox_absent(text: str, path: Path) -> tuple[int, str] | None:
    data = _document(text)
    if data is None or _gemini_sandbox_enabled(data):
        return None
    if not (_gemini_auto_accepts(data) or _gemini_trusted_servers(data)):
        return None
    return _locate(text, '"autoAccept"', '"trust"', '"tools"')


def gemini_tool_auto_trust(text: str, path: Path) -> tuple[int, str] | None:
    data = _document(text)
    if data is None or not (_gemini_auto_accepts(data) or _gemini_trusted_servers(data)):
        return None
    return _locate(text, '"trust"', '"autoAccept"')


# --- Kiro (.kiro/settings/mcp.json) ---------------------------------------


def kiro_mcp_auto_approve(text: str, path: Path) -> tuple[int, str] | None:
    data = _document(text)
    if data is None:
        return None
    for server in _mapping(data.get("mcpServers")).values():
        server = _mapping(server)
        # A disabled server approves nothing, so its list is not a live grant.
        if server.get("disabled") is True:
            continue
        approved = server.get("autoApprove")
        if isinstance(approved, list) and any(isinstance(tool, str) and tool.strip() for tool in approved):
            return _locate(text, '"autoApprove"')
    return None


# --- Committed hooks and permission rules ---------------------------------


def _locate_command(text: str, command: str) -> tuple[int, str]:
    """Locate a hook command in the raw JSON, tolerating string escaping."""
    escaped = json.dumps(command)[1:-1]
    return _locate(text, escaped[:80], command[:80], '"hooks"')


def _hook_violation(text: str, kinds: set[str]) -> tuple[int, str] | None:
    data = _document(text)
    if data is None:
        return None
    for event, command in iter_hook_commands(data):
        verdict = classify_hook_command(event, command)
        if verdict is not None and verdict["kind"] in kinds:
            return _locate_command(text, command)
    return None


def _permission_violation(text: str, severities: set[str]) -> tuple[int, str] | None:
    data = _document(text)
    if data is None:
        return None
    allow = _mapping(data.get("permissions")).get("allow")
    if not isinstance(allow, list):
        return None
    for rule in allow:
        if not isinstance(rule, str):
            continue
        verdict = classify_permission_rule(rule)
        if verdict is not None and verdict["severity"] in severities:
            return _locate(text, rule)
    return None


def claude_hook_runs_untrusted_command(text: str, path: Path) -> tuple[int, str] | None:
    return _hook_violation(text, {"remote-execution", "command-construction"})


def claude_hook_egresses_or_destroys(text: str, path: Path) -> tuple[int, str] | None:
    return _hook_violation(text, {"egress", "destructive"})


def claude_permission_grants_host_control(text: str, path: Path) -> tuple[int, str] | None:
    return _permission_violation(text, {"Critical", "High"})


def claude_permission_grants_broad_access(text: str, path: Path) -> tuple[int, str] | None:
    return _permission_violation(text, {"Medium"})


EVALUATORS: dict[str, Callable[[str, Path], tuple[int, str] | None]] = {
    "claude_sandbox_absent": claude_sandbox_absent,
    "gemini_sandbox_absent": gemini_sandbox_absent,
    "gemini_tool_auto_trust": gemini_tool_auto_trust,
    "kiro_mcp_auto_approve": kiro_mcp_auto_approve,
    "claude_hook_runs_untrusted_command": claude_hook_runs_untrusted_command,
    "claude_hook_egresses_or_destroys": claude_hook_egresses_or_destroys,
    "claude_permission_grants_host_control": claude_permission_grants_host_control,
    "claude_permission_grants_broad_access": claude_permission_grants_broad_access,
}


# --- Shared grading: permission rules and hook command bodies --------------
# Both graders were written for the recon evidence rows in `recon_patterns.py`
# and now also decide findings. They live here so one signal cannot be graded
# two ways; `recon_patterns` imports them and keeps its own row shaping.

_PERM_RULE_RE = re.compile(r"^(?P<tool>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\((?P<arg>.*)\))?$", re.DOTALL)
_PERM_WILDCARDS = {"", "*", "*:*", "**", "**/*"}
# Commands that hand over the host (or an exfil channel) when granted with a
# `:*` argument wildcard. Deliberately narrow: `git`/`npm`/`pip` are omitted
# because `Bash(git:*)`-style rules are near-universal and mostly benign, and a
# noisy Cat 28b table would get ignored wholesale.
_BASH_HIGH_RISK = {
    "sudo",
    "su",
    "rm",
    "chmod",
    "chown",
    "ssh",
    "scp",
    "nc",
    "ncat",
    "eval",
    "exec",
    "dd",
    "mkfs",
    "curl",
    "wget",
}
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.ssh|\.aws|\.gnupg|\.kube|\.netrc|\.npmrc|\.env\b|id_rsa|id_ed25519|credential|\.git/config)"
)


def classify_permission_rule(rule: str) -> dict[str, str] | None:
    """Grade one `permissions.allow` entry. Returns None when not a real risk."""
    match = _PERM_RULE_RE.match(rule.strip())
    if not match:
        return None
    tool = match.group("tool")
    arg = (match.group("arg") or "").strip()
    arg_is_wildcard = arg in _PERM_WILDCARDS

    if tool == "Bash":
        if arg_is_wildcard:
            return {
                "severity": "Critical",
                "reason": f"`{rule}` grants unrestricted shell execution without a permission prompt",
            }
        command = arg.split(":", 1)[0].strip()
        if command in _BASH_HIGH_RISK:
            return {
                "severity": "High",
                "reason": f"`{rule}` pre-approves the high-risk command `{command}` with an argument wildcard",
            }
        return None

    if tool in {"Write", "Edit", "MultiEdit", "NotebookEdit"}:
        if arg_is_wildcard:
            return {
                "severity": "High",
                "reason": f"`{rule}` allows unprompted writes to any path",
            }
        if _SENSITIVE_PATH_RE.search(arg):
            return {
                "severity": "High",
                "reason": f"`{rule}` allows unprompted writes to a credential-bearing path",
            }
        return None

    if tool == "Read":
        if _SENSITIVE_PATH_RE.search(arg):
            return {
                "severity": "High",
                "reason": f"`{rule}` grants read access to a credential-bearing path",
            }
        if arg_is_wildcard:
            return {
                "severity": "Medium",
                "reason": f"`{rule}` grants unrestricted read access, including files outside the project",
            }
        return None

    if tool in {"WebFetch", "WebSearch"} and (arg_is_wildcard or arg.lower() in {"domain:*", "domain:  *"}):
        return {
            "severity": "Medium",
            "reason": f"`{rule}` permits requests to any host — a usable exfiltration channel",
        }

    return None


_HOOK_EVENTS = {
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "Stop",
    "SubagentStop",
    "SessionStart",
    "SessionEnd",
    "Notification",
    "PreCompact",
}
_HOOK_PIPE_TO_SHELL_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba)?sh\b")
_HOOK_SUBSTITUTION_RE = re.compile(r"\$\(|`")
_HOOK_EGRESS_RE = re.compile(r"(?i)(\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bscp\b|https?://)")
_HOOK_DESTRUCTIVE_RE = re.compile(r"(?i)(\brm\s+-[rf]{1,2}\b|\bchmod\s+777\b|\bdd\s+if=)")


def classify_hook_command(event: str, command: str) -> dict[str, str] | None:
    """Grade one hook `command` body. Returns None when not a real risk."""
    if _HOOK_PIPE_TO_SHELL_RE.search(command):
        return {
            "kind": "remote-execution",
            "severity": "Critical",
            "reason": f"`{event}` hook fetches and pipes remote content into a shell — remote code execution on every trigger",
        }
    if _HOOK_SUBSTITUTION_RE.search(command):
        if event == "UserPromptSubmit":
            # Attacker-controlled prompt text reaches the command line before
            # any filtering, so substitution here is directly injectable.
            return {
                "kind": "command-construction",
                "severity": "Critical",
                "reason": "`UserPromptSubmit` hook builds a shell command via substitution — prompt text reaches the command line unfiltered",
            }
        return {
            "kind": "command-construction",
            "severity": "High",
            "reason": f"`{event}` hook uses shell command substitution — tool payload can influence the executed command",
        }
    if _HOOK_EGRESS_RE.search(command):
        return {
            "kind": "egress",
            "severity": "High",
            "reason": f"`{event}` hook network-egresses on every trigger — a continuous exfiltration channel",
        }
    if _HOOK_DESTRUCTIVE_RE.search(command):
        return {
            "kind": "destructive",
            "severity": "High",
            "reason": f"`{event}` hook runs a destructive command on every trigger",
        }
    return None


def iter_hook_commands(data: Any) -> Iterator[tuple[str, str]]:
    """Yield (event, command) for every hook entry in a settings/hooks object."""
    if not isinstance(data, dict):
        return
    events = data.get("hooks") if isinstance(data.get("hooks"), dict) else data
    if not isinstance(events, dict):
        return
    for event, groups in events.items():
        if event not in _HOOK_EVENTS or not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            entries = group.get("hooks")
            entries = entries if isinstance(entries, list) else [group]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                command = entry.get("command")
                if isinstance(command, str) and command.strip():
                    yield str(event), command
