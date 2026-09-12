"""Hook telemetry belongs to the run that dispatched it.

Two properties of the call lifecycle are held here.

* A session keeps working in the repository after a run ends, and the hook
  resolves the output directory from the working tree. Agents that are no call
  of the run — a user's own subagent, a fork — must not land in the finished
  run's logs, where a completion summary counts them as dispatches.
* A child the API refuses never sends SubagentStop. The terminal sweep must
  still charge its real usage and name the error that ended it, read from the
  child transcript the host keeps beside the session transcript.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).parent.parent / "scripts"
SCRIPT = SCRIPTS / "agent_logger.py"
sys.path.insert(0, str(SCRIPTS))

import agent_lifecycle  # noqa: E402

RUN_IDENTITY_VARS = ("APPSEC_RUN_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "OUTPUT_DIR")
RUN_ID = "run-1788592678-3277507"


def _run(event: dict, cwd: Path, extra_env: dict | None = None) -> str:
    env = os.environ.copy()
    for name in RUN_IDENTITY_VARS:
        env.pop(name, None)
    env.update(extra_env or {})
    env["CLAUDE_PLUGIN_ROOT"] = str(SCRIPTS.parent)
    subprocess.run(
        [sys.executable, str(SCRIPT)], input=json.dumps(event), capture_output=True, text=True, cwd=str(cwd), env=env
    )
    log = cwd / "docs" / "security" / ".hook-events.log"
    return log.read_text(encoding="utf-8") if log.exists() else ""


def _out(tmp_path: Path) -> Path:
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _hold_lock(out: Path) -> dict:
    (out / ".appsec-lock").write_text(f"123\n0\n{RUN_ID}\n", encoding="utf-8")
    return {"APPSEC_RUN_ID": RUN_ID}


def _pre(subagent_type: str, call_id: str) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "sess0001",
        "tool_name": "Agent",
        "tool_use_id": call_id,
        "tool_input": {"subagent_type": subagent_type, "description": "look around", "prompt": "x"},
    }


def _registered(out: Path, call_id: str) -> bool:
    state = agent_lifecycle.state_path(out)
    if not state.is_file():
        return False
    return any(call["agent_call_id"] == call_id for call in json.loads(state.read_text(encoding="utf-8"))["calls"])


def test_a_non_plugin_agent_outside_a_run_leaves_no_trace(tmp_path: Path) -> None:
    out = _out(tmp_path)
    log = _run(_pre("general-purpose", "toolu_outside1"), tmp_path)
    ack = {
        "hook_event_name": "PostToolUse",
        "session_id": "sess0001",
        "tool_name": "Agent",
        "tool_use_id": "toolu_outside1",
        "tool_input": {"subagent_type": "general-purpose", "description": "look around"},
        "tool_response": {"agentId": "agentoutside1", "isAsync": True, "outputFile": "/tmp/x", "status": "async"},
    }
    log = _run(ack, tmp_path)
    log = _run(
        {"hook_event_name": "SubagentStart", "session_id": "sess0001", "agent_id": "agentoutside1", "agent_type": ""},
        tmp_path,
    )
    log = _run(
        {
            "hook_event_name": "SubagentStop",
            "session_id": "sess0001",
            "agent_id": "agentoutside1",
            "agent_type": "",
            "agent_transcript_path": str(tmp_path / "missing.jsonl"),
        },
        tmp_path,
    )
    assert "toolu_outside1" not in log
    assert "AGENT_SPAWN" not in log
    assert "AGENT_RETURN_FIELDS" not in log
    assert "AGENT_LIFECYCLE_REJECTED" not in log
    assert "AGENT_USAGE_UNAVAILABLE" not in log
    assert not _registered(out, "toolu_outside1")
    budget = out / ".budget-state.json"
    assert not budget.exists() or "toolu_outside1" not in budget.read_text(encoding="utf-8")


def test_a_non_plugin_agent_inside_a_run_is_recorded(tmp_path: Path) -> None:
    out = _out(tmp_path)
    log = _run(_pre("general-purpose", "toolu_inside1"), tmp_path, _hold_lock(out))
    assert "AGENT_SPAWN" in log and "toolu_inside1" in log
    assert _registered(out, "toolu_inside1")


def test_a_plugin_agent_outside_a_run_is_still_recorded(tmp_path: Path) -> None:
    out = _out(tmp_path)
    log = _run(_pre("appsec-advisor:appsec-run-diagnostician", "toolu_plugin1"), tmp_path)
    assert "AGENT_SPAWN" in log and "toolu_plugin1" in log
    assert _registered(out, "toolu_plugin1")


def _bound_call(out: Path, call_id: str, runtime_id: str) -> None:
    agent_lifecycle.register_call(
        out,
        {
            "agent_call_id": call_id,
            "session_id": "sess0001",
            "agent": "threat-renderer",
            "agent_type": "appsec-advisor:appsec-threat-renderer",
            "model": "sonnet",
            "description": "Render",
            "background": False,
        },
    )
    agent_lifecycle.bind_runtime_agent_id(out, call_id, runtime_id)
    agent_lifecycle.acknowledge_background_call(out, call_id)


def _assistant(model: str, output_tokens: int, agent_id: str) -> dict:
    return {
        "type": "assistant",
        "agentId": agent_id,
        "message": {
            "role": "assistant",
            "model": model,
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 10,
                "output_tokens": output_tokens,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
            "content": [{"type": "text", "text": "ok"}],
        },
    }


def _api_error(code: str, agent_id: str) -> dict:
    return {
        "type": "assistant",
        "agentId": agent_id,
        "isApiErrorMessage": True,
        "error": code,
        "message": {"role": "assistant", "model": "<synthetic>", "content": [{"type": "text", "text": "API Error"}]},
    }


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return path


def test_subagent_stop_reports_the_release_the_child_ran_on(tmp_path: Path) -> None:
    out = _out(tmp_path)
    _bound_call(out, "toolu_render1", "agentrender1")
    child = _write_jsonl(
        tmp_path / "child.jsonl",
        [_assistant("claude-opus-5", 300, "agentrender1"), _assistant("claude-opus-5", 200, "agentrender1")],
    )
    log = _run(
        {
            "hook_event_name": "SubagentStop",
            "session_id": "sess0001",
            "agent_id": "agentrender1",
            "agent_type": "appsec-advisor:appsec-threat-renderer",
            "agent_transcript_path": str(child),
            "stop_reason": "end_turn",
        },
        tmp_path,
    )
    usage = next(line for line in log.splitlines() if "AGENT_USAGE " in line and "toolu_render1" in line)
    assert "resolved_model=claude-opus-5" in usage
    assert "out=500" in usage


def _sweep(tmp_path: Path, session: Path) -> str:
    return _run(
        {
            "hook_event_name": "Stop",
            "session_id": "sess0001",
            "transcript_path": str(session),
            "stop_reason": "end_turn",
        },
        tmp_path,
    )


def test_terminal_sweep_charges_a_dead_child_and_names_its_api_error(tmp_path: Path) -> None:
    out = _out(tmp_path)
    _bound_call(out, "toolu_dead1", "agentdead1")
    session = _write_jsonl(tmp_path / "sessions" / "sess0001.jsonl", [])
    _write_jsonl(
        tmp_path / "sessions" / "sess0001" / "subagents" / "agent-agentdead1.jsonl",
        [
            _assistant("claude-sonnet-4-6", 32_000, "agentdead1"),
            _assistant("claude-sonnet-4-6", 32_000, "agentdead1"),
            _api_error("max_output_tokens", "agentdead1"),
        ],
    )
    log = _sweep(tmp_path, session)
    lines = [line for line in log.splitlines() if "toolu_dead1" in line]
    usage = next(line for line in lines if "AGENT_USAGE " in line)
    assert "resolved_model=claude-sonnet-4-6" in usage and "out=64000" in usage
    failed = next(line for line in lines if "AGENT_FAILED" in line)
    assert "reason=subagent_api_error:max_output_tokens" in failed
    assert not any("outer_session_terminal" in line for line in lines)
    assert not agent_lifecycle.running_calls(out)


def test_terminal_sweep_without_a_child_transcript_keeps_the_generic_reason(tmp_path: Path) -> None:
    out = _out(tmp_path)
    _bound_call(out, "toolu_gone1", "agentgone1")
    session = _write_jsonl(tmp_path / "sessions" / "sess0001.jsonl", [])
    lines = [line for line in _sweep(tmp_path, session).splitlines() if "toolu_gone1" in line]
    assert any("AGENT_FAILED" in line and "reason=outer_session_terminal" in line for line in lines)
    assert not any("AGENT_USAGE " in line for line in lines)


def test_terminal_sweep_ignores_a_transcript_that_names_another_agent(tmp_path: Path) -> None:
    out = _out(tmp_path)
    _bound_call(out, "toolu_other1", "agentother1")
    session = _write_jsonl(tmp_path / "sessions" / "sess0001.jsonl", [])
    _write_jsonl(
        tmp_path / "sessions" / "sess0001" / "subagents" / "agent-agentother1.jsonl",
        [_assistant("claude-sonnet-4-6", 10, "someoneelse"), _api_error("max_output_tokens", "someoneelse")],
    )
    lines = [line for line in _sweep(tmp_path, session).splitlines() if "toolu_other1" in line]
    assert any("reason=outer_session_terminal" in line for line in lines)
    assert not any("AGENT_USAGE " in line for line in lines)
