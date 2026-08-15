from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import agent_lifecycle as lifecycle  # noqa: E402
import agent_logger  # noqa: E402
import budget_watchdog as budget  # noqa: E402


def _identity(
    call_id: str,
    *,
    session: str = "shared01",
    agent: str = "recon-scanner",
    background: bool = False,
    max_turns: int = 36,
    **extra: object,
) -> dict:
    value = {
        "agent_call_id": call_id,
        "session_id": session,
        "agent": agent,
        "agent_type": f"appsec-advisor:appsec-{agent}",
        "model": "sonnet",
        "description": f"Run {agent}",
        "background": background,
        "max_turns": max_turns,
    }
    value.update(extra)
    return value


def _running(output_dir: Path, call_id: str) -> dict:
    return next(call for call in lifecycle.running_calls(output_dir) if call["agent_call_id"] == call_id)


def _budget_state(output_dir: Path) -> dict:
    return json.loads((output_dir / budget.STATE_FILENAME).read_text(encoding="utf-8"))


def _seed_claim(output_dir: Path, *, attempt: int = 1) -> dict:
    action_id = "phase9-stride"
    component_id = "api"
    job_id = f"stride:{component_id}:attempt-{attempt}"
    (output_dir / ".context-routing-plan.json").write_text(
        json.dumps({"actions": [{"action_id": action_id, "job_ids": [job_id]}]}),
        encoding="utf-8",
    )
    (output_dir / ".dispatch-waves.json").write_text(
        json.dumps(
            {
                "active_claim": {
                    "component_ids": [component_id],
                    "attempts": {component_id: attempt},
                }
            }
        ),
        encoding="utf-8",
    )
    return {
        "action_id": action_id,
        "job_id": job_id,
        "component_id": component_id,
        "attempt": attempt,
        "analysis_depth": "full",
    }


def test_lifecycle_is_ordered_and_replay_is_idempotent(tmp_path: Path) -> None:
    identity = _identity("toolu_recon")
    assert [event.event for event in lifecycle.register_call(tmp_path, identity)] == [
        "AGENT_SPAWN",
        "AGENT_RUNNING",
    ]
    assert lifecycle.register_call(tmp_path, identity) == []
    assert [event.event for event in lifecycle.finish_call(tmp_path, "toolu_recon")] == ["AGENT_DONE"]
    assert lifecycle.finish_call(tmp_path, "toolu_recon") == []

    lifecycle.append_events(tmp_path, lifecycle.register_call(tmp_path, _identity("toolu_next")))
    lifecycle.append_events(tmp_path, lifecycle.finish_call(tmp_path, "toolu_next"))
    log = (tmp_path / ".hook-events.log").read_text(encoding="utf-8")
    assert log.count("AGENT_SPAWN") == 1
    assert log.count("AGENT_DONE") == 1
    assert "AGENT_INVOKE" not in log


def test_missing_late_and_reordered_transitions_are_visible_or_noops(tmp_path: Path) -> None:
    rejected = lifecycle.finish_call(tmp_path, "toolu_missing")
    assert [(event.event, event.reason) for event in rejected] == [
        ("AGENT_LIFECYCLE_REJECTED", "terminal_before_spawn")
    ]
    duplicate_spawn = lifecycle.register_call(tmp_path, _identity("toolu_missing"))
    assert duplicate_spawn[0].event == "AGENT_LIFECYCLE_REJECTED"

    lifecycle.register_call(tmp_path, _identity("toolu_old"))
    events = lifecycle.register_call(tmp_path, _identity("toolu_new", agent="architecture-analyst"))
    assert [event.event for event in events] == ["AGENT_FAILED", "AGENT_SPAWN", "AGENT_RUNNING"]
    assert events[0].reason == "superseded_without_return"
    assert lifecycle.finish_call(tmp_path, "toolu_old") == []


def test_sequential_roles_sharing_one_session_keep_usage_and_budget_separate(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_recon", max_turns=10))
    recon = _running(tmp_path, "toolu_recon")
    budget.open_call(recon, tmp_path)
    assert budget.observe_tool_uses(recon, 8, tmp_path)["event"] == "BUDGET_WARN"
    lifecycle.finish_call(tmp_path, "toolu_recon")
    budget.close_call("toolu_recon", tmp_path)

    lifecycle.register_call(
        tmp_path,
        _identity("toolu_arch", agent="architecture-analyst", max_turns=10),
    )
    architecture = _running(tmp_path, "toolu_arch")
    budget.open_call(architecture, tmp_path)
    assert budget.tally_and_check(architecture, tmp_path) is None

    state = _budget_state(tmp_path)
    assert set(state["calls"]) == {"toolu_arch"}
    assert state["calls"]["toolu_arch"]["turns"] == 1
    assert state["calls"]["toolu_arch"]["agent"] == "architecture-analyst"


def test_parallel_calls_with_one_session_remain_distinct(tmp_path: Path) -> None:
    for call_id in ("toolu_a", "toolu_b"):
        lifecycle.register_call(tmp_path, _identity(call_id, background=True, max_turns=10))
        budget.open_call(_running(tmp_path, call_id), tmp_path)

    call_a = lifecycle.bind_runtime_agent_id(tmp_path, "toolu_a", "agent-a")
    call_b = lifecycle.bind_runtime_agent_id(tmp_path, "toolu_b", "agent-b")
    assert call_a is not None and call_b is not None
    budget.observe_tool_uses(call_a, 8, tmp_path)
    budget.observe_tool_uses(call_b, 2, tmp_path)
    assert lifecycle.unique_running_call(tmp_path, "shared01") is None

    state = _budget_state(tmp_path)["calls"]
    assert state["toolu_a"]["turns"] == 8
    assert state["toolu_b"]["turns"] == 2

    usage = {"input_tokens": 10, "output_tokens": 5}
    assert lifecycle.record_runtime_usage(tmp_path, "agent-a", usage, tool_uses=8)
    assert lifecycle.record_runtime_usage(tmp_path, "agent-a", usage, tool_uses=8) == []
    assert _running(tmp_path, "toolu_a")["usage"]["tool_uses"] == 8
    assert "usage" not in _running(tmp_path, "toolu_b")


def test_31_tool_use_agent_closes_before_parent_tools(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_31", max_turns=36))
    call = _running(tmp_path, "toolu_31")
    budget.open_call(call, tmp_path)
    crossing = budget.observe_tool_uses(call, 31, tmp_path)
    assert crossing is not None and crossing["event"] == "BUDGET_WARN"
    assert _budget_state(tmp_path)["calls"]["toolu_31"]["turns"] == 31

    lifecycle.finish_call(tmp_path, "toolu_31")
    budget.close_call("toolu_31", tmp_path)
    assert lifecycle.unique_running_call(tmp_path, "shared01") is None
    assert budget.tally_and_check(call, tmp_path) is None
    assert _budget_state(tmp_path)["calls"] == {}


def test_stop_usage_without_agent_id_is_not_assigned_by_session(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    lifecycle.register_call(tmp_path, _identity("toolu_running", max_turns=36))
    call = _running(tmp_path, "toolu_running")
    budget.open_call(call, tmp_path)
    budget.observe_tool_uses(call, 31, tmp_path)

    agent_logger.handle_stop(
        {
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 100, "output_tokens": 20},
        },
        "shared01",
        "SubagentStop",
    )

    assert "usage" not in _running(tmp_path, "toolu_running")
    assert _budget_state(tmp_path)["calls"]["toolu_running"]["turns"] == 31
    assert "AGENT_USAGE_UNATTRIBUTED" in (tmp_path / ".hook-events.log").read_text(encoding="utf-8")


def test_subagent_stop_closes_missing_post_and_late_duplicate_post_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    events = lifecycle.register_call(tmp_path, _identity("toolu_stop", max_turns=36))
    lifecycle.append_events(tmp_path, events)
    call = lifecycle.bind_runtime_agent_id(tmp_path, "toolu_stop", "agent-stop")
    assert call is not None
    budget.open_call(call, tmp_path)

    agent_logger.handle_stop(
        {
            "agent_id": "agent-stop",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 100, "output_tokens": 20},
        },
        "shared01",
        "SubagentStop",
    )
    assert lifecycle.running_calls(tmp_path) == []
    assert _budget_state(tmp_path)["calls"] == {}

    post = {
        "tool_name": "Agent",
        "tool_use_id": "toolu_stop",
        "tool_input": {
            "subagent_type": "appsec-advisor:appsec-recon-scanner",
            "description": "Run recon",
            "run_in_background": False,
        },
        "tool_response": {"content": []},
        "is_error": False,
    }
    agent_logger.handle_post_tool_use(post, "shared01")
    agent_logger.handle_post_tool_use(post, "shared01")
    log = (tmp_path / ".hook-events.log").read_text(encoding="utf-8")
    assert log.count("AGENT_DONE") == 1
    assert "AGENT_INVOKE" not in log


def test_subagent_stop_reads_child_transcript_not_parent_transcript(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    events = lifecycle.register_call(tmp_path, _identity("toolu_child", max_turns=36))
    lifecycle.append_events(tmp_path, events)
    call = lifecycle.bind_runtime_agent_id(tmp_path, "toolu_child", "agent-child")
    assert call is not None
    budget.open_call(call, tmp_path)

    parent_transcript = tmp_path / "parent.jsonl"
    parent_transcript.write_text(
        json.dumps(
            {
                "message": {
                    "role": "assistant",
                    "stop_reason": "tool_use",
                    "usage": {"input_tokens": 900, "output_tokens": 800},
                    "content": [{"type": "tool_use", "id": "toolu_parent"}],
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    child_transcript = tmp_path / "child.jsonl"
    child_transcript.write_text(
        json.dumps(
            {
                "message": {
                    "role": "assistant",
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 100, "output_tokens": 20},
                    "content": [{"type": "tool_use", "id": "toolu_child_read"}],
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )

    agent_logger.handle_stop(
        {
            "agent_id": "agent-child",
            "transcript_path": str(parent_transcript),
            "agent_transcript_path": str(child_transcript),
        },
        "shared01",
        "SubagentStop",
    )

    state = json.loads(lifecycle.state_path(tmp_path).read_text(encoding="utf-8"))
    finished = next(row for row in state["calls"] if row["agent_call_id"] == "toolu_child")
    assert finished["state"] == "done"
    assert finished["usage"]["input_tokens"] == 100
    assert finished["usage"]["output_tokens"] == 20
    assert finished["usage"]["tool_uses"] == 1
    assert _budget_state(tmp_path)["calls"] == {}
    log = (tmp_path / ".hook-events.log").read_text(encoding="utf-8")
    assert "AGENT_DONE" in log
    assert "AGENT_FAILED" not in log
    assert "stop_reason=end_turn" in log


def test_reordered_post_before_spawn_is_rejected_without_a_start(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    agent_logger.handle_post_tool_use(
        {
            "tool_name": "Agent",
            "tool_use_id": "toolu_reordered",
            "tool_input": {
                "subagent_type": "appsec-advisor:appsec-recon-scanner",
                "description": "Run recon",
                "run_in_background": False,
            },
            "tool_response": {"content": []},
            "is_error": False,
        },
        "shared01",
    )
    log = (tmp_path / ".hook-events.log").read_text(encoding="utf-8")
    assert "AGENT_LIFECYCLE_REJECTED" in log
    assert "AGENT_SPAWN" not in log


def test_critical_marker_requires_the_current_call(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_old", max_turns=10))
    old = _running(tmp_path, "toolu_old")
    budget.open_call(old, tmp_path)
    assert budget.observe_tool_uses(old, 9, tmp_path)["event"] == "BUDGET_CRITICAL"
    stale_marker = (tmp_path / budget.CRITICAL_FLAG_FILENAME).read_text(encoding="utf-8")
    assert budget.has_active_critical_claim(tmp_path)

    lifecycle.finish_call(tmp_path, "toolu_old")
    budget.close_call("toolu_old", tmp_path)
    lifecycle.register_call(tmp_path, _identity("toolu_new", max_turns=10))
    budget.open_call(_running(tmp_path, "toolu_new"), tmp_path)
    (tmp_path / budget.CRITICAL_FLAG_FILENAME).write_text(stale_marker, encoding="utf-8")
    assert not budget.has_active_critical_claim(tmp_path)

    new = _running(tmp_path, "toolu_new")
    assert budget.observe_tool_uses(new, 9, tmp_path)["event"] == "BUDGET_CRITICAL"
    assert budget.has_active_critical_claim(tmp_path)


def test_marker_becomes_inert_when_attempt_claim_changes(tmp_path: Path) -> None:
    claim = _seed_claim(tmp_path)
    lifecycle.register_call(tmp_path, _identity("toolu_claim", max_turns=10, background=True, **claim))
    call = _running(tmp_path, "toolu_claim")
    budget.open_call(call, tmp_path)
    assert budget.observe_tool_uses(call, 9, tmp_path)["event"] == "BUDGET_CRITICAL"
    assert budget.has_active_critical_claim(tmp_path)

    waves = json.loads((tmp_path / ".dispatch-waves.json").read_text(encoding="utf-8"))
    waves["active_claim"]["attempts"]["api"] = 2
    (tmp_path / ".dispatch-waves.json").write_text(json.dumps(waves), encoding="utf-8")
    assert not budget.has_active_critical_claim(tmp_path)


def test_five_parallel_starts_exist_before_any_join(tmp_path: Path) -> None:
    for index in range(5):
        lifecycle.register_call(
            tmp_path,
            _identity(f"toolu_{index}", agent="stride-analyzer-v2", background=True),
        )
    assert len(lifecycle.running_calls(tmp_path, "shared01")) == 5
    assert all(call["state"] == "running" for call in lifecycle.running_calls(tmp_path))


def test_terminal_cleanup_fails_calls_and_removes_live_state(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_interrupted", max_turns=10))
    budget.open_call(_running(tmp_path, "toolu_interrupted"), tmp_path)
    agent_logger.clear_terminal_active_tool_calls(tmp_path)

    assert not (tmp_path / lifecycle.STATE_DIR).exists()
    log = (tmp_path / ".hook-events.log").read_text(encoding="utf-8")
    assert "AGENT_FAILED" in log
    assert "reason=outer_session_terminal" in log


def test_persisted_lifecycle_and_budget_match_published_schemas(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_schema", max_turns=10))
    budget.open_call(_running(tmp_path, "toolu_schema"), tmp_path)
    root = Path(__file__).parent.parent
    for value_path, schema_name in (
        (lifecycle.state_path(tmp_path), "agent-call-lifecycle.schema.json"),
        (tmp_path / budget.STATE_FILENAME, "agent-call-budget-state.schema.json"),
    ):
        value = json.loads(value_path.read_text(encoding="utf-8"))
        schema = json.loads((root / "schemas" / schema_name).read_text(encoding="utf-8"))
        assert list(Draft202012Validator(schema).iter_errors(value)) == []


def test_existing_300_turn_agent_limit_is_valid_telemetry_not_a_limit_change(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_analyst", max_turns=300))
    call = _running(tmp_path, "toolu_analyst")
    budget.open_call(call, tmp_path)
    assert _budget_state(tmp_path)["calls"]["toolu_analyst"]["max_turns"] == 300


def test_critical_marker_matches_its_published_schema(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_marker", max_turns=10))
    call = _running(tmp_path, "toolu_marker")
    budget.open_call(call, tmp_path)
    budget.observe_tool_uses(call, 9, tmp_path)
    value = json.loads((tmp_path / budget.CRITICAL_FLAG_FILENAME).read_text(encoding="utf-8"))
    schema = json.loads(
        (Path(__file__).parent.parent / "schemas" / "agent-call-budget-marker.schema.json").read_text(encoding="utf-8")
    )
    assert list(Draft202012Validator(schema).iter_errors(value)) == []
