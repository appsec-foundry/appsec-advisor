"""Tests for scripts/hook_payload.py — the one place a hook payload is read.

The adapter exists because the same assumption used to be restated at every
consumer, and the tests restated it too. So these tests assert the two rules it
enforces — the stopping session owns its transcript, and nothing raises — plus
that it reports drift instead of degrading silently.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import hook_payload  # noqa: E402


def test_subagent_stop_owner_is_the_child_transcript() -> None:
    event = hook_payload.parse(
        {
            "hook_event_name": "SubagentStop",
            "transcript_path": "/parent.jsonl",
            "agent_transcript_path": "/child.jsonl",
            "agent_id": "agent_1",
            "agent_type": "appsec-advisor:appsec-recon-scanner",
        }
    )
    assert event.owner_transcript == "/child.jsonl"
    assert event.session_transcript == "/parent.jsonl"
    assert event.problems == ()


def test_every_other_event_owns_the_session_transcript() -> None:
    for name in ("Stop", "PreToolUse", "PostToolUse", "SubagentStart"):
        event = hook_payload.parse({"hook_event_name": name, "transcript_path": "/parent.jsonl"})
        assert event.owner_transcript == "/parent.jsonl", name


def test_a_subagent_stop_without_the_child_key_falls_back_to_the_parent() -> None:
    """An older host that does not send the child path must still terminalize
    the call rather than lose the event."""
    event = hook_payload.parse(
        {"hook_event_name": "SubagentStop", "transcript_path": "/parent.jsonl", "agent_id": "a", "agent_type": "t"}
    )
    assert event.owner_transcript == "/parent.jsonl"
    assert "agent_transcript_path=absent" in event.problems


def test_missing_and_mistyped_keys_are_named_not_swallowed() -> None:
    event = hook_payload.parse({"hook_event_name": "PreToolUse", "tool_name": 7, "tool_input": {"a": 1}})
    assert "tool_use_id=absent" in event.problems
    assert "tool_name=int" in event.problems
    assert event.tool_name == ""
    assert event.tool_input == {"a": 1}


def test_a_key_no_consumer_reads_is_not_reported() -> None:
    """Reporting a field nobody uses would be an alert nobody can act on."""
    event = hook_payload.parse(
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "t", "tool_input": {}}
    )
    assert event.problems == ()


@pytest.mark.parametrize("payload", [None, "", 7, [], {"hook_event_name": "PreToolUse", "tool_input": "not-a-dict"}])
def test_nothing_raises_on_a_payload_that_is_not_the_contract(payload: object) -> None:
    event = hook_payload.parse(payload)
    assert isinstance(event, hook_payload.HookEvent)
    assert event.tool_input == {}


def test_the_event_name_comes_from_the_caller_or_the_payload() -> None:
    assert hook_payload.parse({"hook_event_name": "Stop"}).name == "Stop"
    assert hook_payload.parse({"hook_event_name": "Stop"}, "SubagentStop").name == "SubagentStop"


def test_identifiers_are_bounded() -> None:
    event = hook_payload.parse({"hook_event_name": "PreToolUse", "tool_use_id": "x" * 5000, "tool_name": "Agent"})
    assert len(event.tool_use_id) == hook_payload._MAX_ID
    assert event.is_agent_call
