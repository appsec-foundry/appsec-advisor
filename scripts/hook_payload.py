#!/usr/bin/env python3
"""One typed record per hook event, built before any consumer reads a field.

Hook payload fields used to be read independently at each consumer, so an
assumption about the host contract was restated rather than validated — and the
tests restated it too. postfix6 is what that costs: ``SubagentStop`` was read as
if it carried the stopping child's ``transcript_path``, and a completed recon
call was persisted as failed with zero tokens while its artifacts had already
been accepted.

Two rules hold here:

* **The stopping session owns its transcript.** ``SubagentStop`` carries the
  parent session's ``transcript_path`` *and* the child's
  ``agent_transcript_path``. Stop reason, usage, and tool totals belong to the
  child, so ``owner_transcript`` resolves to it. Every other event is about the
  session it fired in.
* **Nothing raises.** A hook that throws takes the session with it, so a
  payload that does not match the contract yields an empty-but-typed record and
  a note in ``problems`` — which the caller can log once — instead of an
  exception or a silent zero.

The pinned payload shapes live in ``tests/fixtures/hook-payloads/``; the
contract test drives this module with them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Per event, the keys a consumer here actually depends on. Deliberately not
#: the host's full key set: reporting a field nobody reads would be an alert
#: nobody can act on. An event that is not listed carries no expectation.
REQUIRED_KEYS = {
    "PreToolUse": ("tool_name", "tool_use_id", "tool_input"),
    "PostToolUse": ("tool_name", "tool_use_id", "tool_input", "tool_response"),
    "SubagentStart": ("agent_id", "agent_type"),
    "SubagentStop": ("agent_id", "agent_type", "agent_transcript_path"),
    "Stop": ("transcript_path",),
}

_MAX_ID = 256


def _text(payload: dict, key: str, limit: int = _MAX_ID) -> str:
    value = payload.get(key)
    return value[:limit] if isinstance(value, str) else ""


def _mapping(payload: dict, key: str) -> dict:
    value = payload.get(key)
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class HookEvent:
    """One hook delivery, normalized. Absent fields are empty, never ``None``."""

    name: str = ""
    session_id: str = ""
    cwd: str = ""
    #: The transcript of the session the hook fired in — always the parent.
    session_transcript: str = ""
    #: The transcript of the session this event is *about*. Differs from
    #: ``session_transcript`` only on ``SubagentStop``, which is the whole point.
    owner_transcript: str = ""
    agent_id: str = ""
    agent_type: str = ""
    tool_name: str = ""
    tool_use_id: str = ""
    tool_input: dict = field(default_factory=dict)
    tool_response: Any = ""
    is_error: bool = False
    #: Keys the event should carry and does not, or carries with a wrong type.
    problems: tuple[str, ...] = ()

    @property
    def is_agent_call(self) -> bool:
        return self.tool_name == "Agent"


def _problems(payload: dict, name: str) -> tuple[str, ...]:
    found = []
    for key in REQUIRED_KEYS.get(name, ()):
        value = payload.get(key)
        if value is None:
            found.append(f"{key}=absent")
        elif key.endswith(("_path", "_id", "_name", "_type")) and not isinstance(value, str):
            found.append(f"{key}={type(value).__name__}")
    return tuple(found)


def parse(payload: object, event_name: str = "") -> HookEvent:
    """Normalize one hook payload. Never raises."""
    if not isinstance(payload, dict):
        return HookEvent(name=event_name, problems=("payload=not-an-object",))
    name = event_name or _text(payload, "hook_event_name", 64)
    session_transcript = _text(payload, "transcript_path", 4096)
    owner = session_transcript
    if name == "SubagentStop":
        # The child's own transcript is the authority for its stop reason,
        # usage, and tool-use count. Older payloads without the key fall back
        # to the common path rather than losing the event.
        owner = _text(payload, "agent_transcript_path", 4096) or session_transcript
    return HookEvent(
        name=name,
        session_id=_text(payload, "session_id", 64),
        cwd=_text(payload, "cwd", 4096),
        session_transcript=session_transcript,
        owner_transcript=owner,
        agent_id=_text(payload, "agent_id"),
        agent_type=_text(payload, "agent_type"),
        tool_name=_text(payload, "tool_name", 64),
        tool_use_id=_text(payload, "tool_use_id"),
        tool_input=_mapping(payload, "tool_input"),
        tool_response=payload.get("tool_response", ""),
        # Not part of the pinned PostToolUse contract, which reports a failed
        # tool through its own event. Kept because a host that does send it
        # must still be believed.
        is_error=bool(payload.get("is_error", False)),
        problems=_problems(payload, name),
    )
