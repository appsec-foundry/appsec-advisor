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
MCP server. Explicit weakening is covered by the regex checks in the catalog.

An unparsable file yields no violation: it carries no evidence of a posture,
and the surrounding recon inventory already reports the file itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

# Claude Code permission modes that let tool calls run without asking. The full
# set (`claude --help`) also carries `auto`, `manual` and `plan`; `auto` still
# routes through a decision the user can see, so only the unambiguous grants
# count as a reason to expect isolation.
_CLAUDE_AUTONOMOUS_MODES = {"acceptEdits", "bypassPermissions", "dontAsk"}
# Gemini CLI accepts a boolean or a container runtime name for `sandbox`.
_GEMINI_SANDBOX_RUNTIMES = {"docker", "podman"}


def _document(text: str) -> dict[str, Any] | None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _locate(text: str, *needles: str) -> tuple[int, str]:
    """First line carrying any of ``needles``, else the first line of the file."""
    lines = text.splitlines()
    for index, line in enumerate(lines, start=1):
        if any(needle in line for needle in needles):
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


def _claude_grants_autonomy(data: dict[str, Any]) -> bool:
    permissions = _mapping(data.get("permissions"))
    allow = permissions.get("allow")
    if isinstance(allow, list) and any(isinstance(rule, str) and rule.strip() for rule in allow):
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


EVALUATORS: dict[str, Callable[[str, Path], tuple[int, str] | None]] = {
    "claude_sandbox_absent": claude_sandbox_absent,
    "gemini_sandbox_absent": gemini_sandbox_absent,
    "gemini_tool_auto_trust": gemini_tool_auto_trust,
    "kiro_mcp_auto_approve": kiro_mcp_auto_approve,
}
