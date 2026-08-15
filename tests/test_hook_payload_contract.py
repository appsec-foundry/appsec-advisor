"""Pin the Claude Code hook payload boundary against a captured host version.

Every other lifecycle test builds its own payload dict, so a wrong assumption
about the host contract is repeated by the test that is supposed to catch it.
The postfix6 failure was exactly that: `SubagentStop` was read as if it carried
the child's `transcript_path`, and synthetic payloads agreed.

This module drives one full Agent call — PreToolUse, SubagentStart,
SubagentStop, delayed PostToolUse — from a sanitized payload fixture of the
supported host version, and pins:

* the key set and types the host actually sends;
* parent vs. child transcript ownership;
* usage attribution to the child;
* idempotency of the delayed parent PostToolUse.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import agent_lifecycle as lifecycle  # noqa: E402
import agent_logger  # noqa: E402
import budget_watchdog as budget  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "hook-payloads" / "claude-code-2.1.233.json"


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _transcript(path: Path, *, stop_reason: str, inp: int, out: int, tool_ids: list[str]) -> None:
    path.write_text(
        json.dumps(
            {
                "message": {
                    "role": "assistant",
                    "stop_reason": stop_reason,
                    "usage": {"input_tokens": inp, "output_tokens": out},
                    "content": [{"type": "tool_use", "id": tool_id} for tool_id in tool_ids],
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _localize(payload: dict, tmp_path: Path, parent: Path, child: Path) -> dict:
    """Repoint the fixture's sanitized transcript paths at real temp files."""
    payload = dict(payload)
    payload["cwd"] = str(tmp_path)
    payload["transcript_path"] = str(parent)
    if "agent_transcript_path" in payload:
        payload["agent_transcript_path"] = str(child)
    return payload


def test_fixture_pins_the_host_payload_keys_and_types() -> None:
    data = _fixture()
    assert data["host"]["version"] == "2.1.233"
    base_required = set(data["base_keys"]["required"])
    base_allowed = base_required | set(data["base_keys"]["optional"])

    expected = {
        "PreToolUse": {"tool_name", "tool_use_id", "tool_input"},
        "SubagentStart": {"agent_id", "agent_type"},
        "SubagentStop": {"stop_hook_active", "agent_id", "agent_type", "agent_transcript_path"},
        "PostToolUse": {"tool_name", "tool_use_id", "tool_input", "tool_response"},
    }
    for event, required in expected.items():
        payload = data["events"][event]
        assert payload["hook_event_name"] == event
        assert base_required | required <= set(payload)
        unknown = set(payload) - base_allowed - required - {"duration_ms", "last_assistant_message"}
        assert not unknown, f"{event} fixture carries keys the host contract does not define: {sorted(unknown)}"
        assert all(isinstance(payload[key], str) for key in base_required)

    stop = data["events"]["SubagentStop"]
    # The two fields the lifecycle consumer needs are absent by contract, which
    # is why they are derived from the child transcript rather than the payload.
    assert "stop_reason" not in stop
    assert "usage" not in stop
    assert stop["transcript_path"] != stop["agent_transcript_path"]


def test_real_payload_sequence_attributes_the_child_and_stays_idempotent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    events = _fixture()["events"]
    parent = tmp_path / "parent.jsonl"
    child = tmp_path / "child.jsonl"
    # Conflicting values: the parent session is still mid-tool-loop and has
    # spent far more tokens than the child it is waiting on.
    _transcript(parent, stop_reason="tool_use", inp=910_000, out=48_000, tool_ids=["toolu_parent_a", "toolu_parent_b"])
    _transcript(child, stop_reason="end_turn", inp=105_000, out=755, tool_ids=[f"toolu_child_{i}" for i in range(31)])

    sid = events["PreToolUse"]["session_id"]
    agent_logger.handle_pre_tool_use(_localize(events["PreToolUse"], tmp_path, parent, child), sid)
    agent_logger.handle_subagent_start(_localize(events["SubagentStart"], tmp_path, parent, child), sid)
    agent_logger.handle_stop(_localize(events["SubagentStop"], tmp_path, parent, child), sid, "SubagentStop")

    call_id = events["PreToolUse"]["tool_use_id"]
    state = json.loads(lifecycle.state_path(tmp_path).read_text(encoding="utf-8"))
    call = next(row for row in state["calls"] if row["agent_call_id"] == call_id)
    assert call["state"] == "done"
    assert call["job_id"] == "phase2-recon"
    assert call["runtime_agent_id"] == events["SubagentStart"]["agent_id"]
    assert call["usage"] == {
        "input_tokens": 105_000,
        "output_tokens": 755,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "tool_uses": 31,
    }
    assert json.loads((tmp_path / budget.STATE_FILENAME).read_text(encoding="utf-8"))["calls"] == {}

    log = (tmp_path / ".hook-events.log").read_text(encoding="utf-8")
    assert log.count("AGENT_SPAWN") == 1
    assert log.count("AGENT_DONE") == 1
    assert "AGENT_FAILED" not in log
    assert "stop_reason=end_turn" in log

    # The parent's Agent PostToolUse arrives after the child already
    # terminalized: it acknowledges, it does not re-open or duplicate.
    agent_logger.handle_post_tool_use(_localize(events["PostToolUse"], tmp_path, parent, child), sid)
    after = json.loads(lifecycle.state_path(tmp_path).read_text(encoding="utf-8"))
    assert after["calls"] == state["calls"]
    log = (tmp_path / ".hook-events.log").read_text(encoding="utf-8")
    assert log.count("AGENT_SPAWN") == 1
    assert log.count("AGENT_DONE") == 1
    assert "AGENT_INVOKE" not in log
