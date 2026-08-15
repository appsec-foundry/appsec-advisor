"""Tests for scripts/telemetry_consistency.py and its controller boundary.

The check exists because four locally correct producers can still disagree
about one call. Each case below makes exactly one surface contradict the
others and asserts the disagreement is named, that a coherent call is silent,
and that only `APPSEC_TELEMETRY_STRICT` turns a report into an abort.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import agent_lifecycle as lifecycle  # noqa: E402
import budget_watchdog as budget  # noqa: E402
import orchestration_controller as controller  # noqa: E402
import telemetry_consistency as telemetry  # noqa: E402

ACTION_ID = "stage1c:b078fb4269a6b5c5"
CALL_ID = "toolu_recon"
AGENT_TYPE = "appsec-advisor:appsec-recon-scanner"


def _seed(output_dir: Path, *, state: str = "done", usage: bool = True) -> None:
    """Write a coherent set of telemetry surfaces for one returned recon call."""
    (output_dir / ".context-routing-plan.json").write_text(
        json.dumps({"actions": [{"action_id": ACTION_ID, "job_ids": ["phase2-recon"]}]}),
        encoding="utf-8",
    )
    lifecycle.register_call(
        output_dir,
        {
            "agent_call_id": CALL_ID,
            "session_id": "shared01",
            "agent": "recon-scanner",
            "agent_type": AGENT_TYPE,
            "model": "sonnet",
            "description": "Reconnaissance",
            "background": False,
            "action_id": ACTION_ID,
            "job_id": "phase2-recon",
            "max_turns": 36,
        },
    )
    if usage:
        lifecycle.bind_runtime_agent_id(output_dir, CALL_ID, "agent-recon")
        lifecycle.record_runtime_usage(
            output_dir,
            "agent-recon",
            {"input_tokens": 105_000, "output_tokens": 755},
            tool_uses=31,
        )
    if state == "done":
        lifecycle.finish_call(output_dir, CALL_ID)
    elif state == "failed":
        lifecycle.fail_call(output_dir, CALL_ID, "subagent_stop:unknown")
    (output_dir / ".stage-stats.jsonl").write_text(
        json.dumps({"stage": 1, "variant": "recon_scanner", "agent": AGENT_TYPE, "tokens": 105_755}) + "\n",
        encoding="utf-8",
    )


def _codes(output_dir: Path) -> list[str]:
    return [finding["code"] for finding in telemetry.check_returned_calls(output_dir)]


def test_coherent_call_reports_nothing(tmp_path: Path) -> None:
    _seed(tmp_path)
    assert telemetry.check_returned_calls(tmp_path) == []


def test_no_dispatch_and_unreadable_state_report_nothing(tmp_path: Path) -> None:
    assert telemetry.check_returned_calls(tmp_path) == []
    lifecycle.state_path(tmp_path).parent.mkdir(parents=True, exist_ok=True)
    lifecycle.state_path(tmp_path).write_text("{not json", encoding="utf-8")
    assert telemetry.check_returned_calls(tmp_path) == []


def test_postfix6_shape_names_the_failed_call_and_the_missing_usage(tmp_path: Path) -> None:
    """Accepted recon output, lifecycle failed, no child usage — the exact
    disagreement the postfix6 run produced."""
    _seed(tmp_path, state="failed", usage=False)
    assert _codes(tmp_path) == ["lifecycle_failed_after_accepted_output"]


def test_terminal_call_without_child_usage_is_named(tmp_path: Path) -> None:
    _seed(tmp_path, usage=False)
    assert _codes(tmp_path) == ["usage_unattributed"]


def test_running_call_at_an_accept_boundary_is_named(tmp_path: Path) -> None:
    _seed(tmp_path, state="running")
    assert _codes(tmp_path) == ["lifecycle_not_terminal"]


def test_unretired_budget_entry_is_named(tmp_path: Path) -> None:
    _seed(tmp_path)
    (tmp_path / budget.STATE_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": budget.STATE_SCHEMA_VERSION,
                "calls": {
                    CALL_ID: {
                        "agent_call_id": CALL_ID,
                        "sid": "shared01",
                        "agent": "recon-scanner",
                        "agent_type": AGENT_TYPE,
                        "turns": 27,
                        "max_turns": 36,
                        "warn_emitted": True,
                        "critical_emitted": False,
                        "max_emitted": False,
                        "first_seen": 1,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    assert _codes(tmp_path) == ["budget_not_retired"]


def test_stage_stats_reporting_zero_for_a_charged_call_is_named(tmp_path: Path) -> None:
    _seed(tmp_path)
    (tmp_path / ".stage-stats.jsonl").write_text(
        json.dumps({"stage": 1, "variant": "recon_scanner", "agent": AGENT_TYPE, "tokens": 0}) + "\n",
        encoding="utf-8",
    )
    assert _codes(tmp_path) == ["stage_stats_zero_usage"]


def test_stage_stats_not_yet_written_is_not_a_finding(tmp_path: Path) -> None:
    """The skill records a wave's stats around the same boundary; both orders
    are legitimate, so absence must not be reported as a contradiction."""
    _seed(tmp_path)
    (tmp_path / ".stage-stats.jsonl").unlink()
    assert telemetry.check_returned_calls(tmp_path) == []


def test_only_the_latest_action_is_checked(tmp_path: Path) -> None:
    """A superseded earlier attempt is not re-reported at every later boundary:
    a controller-owned retry opens a new action, and only that one is current."""
    _seed(tmp_path, state="failed", usage=False)
    (tmp_path / ".context-routing-plan.json").write_text(
        json.dumps(
            {
                "actions": [
                    {"action_id": ACTION_ID, "job_ids": ["phase2-recon"]},
                    {"action_id": "stage1c:retry", "job_ids": ["phase2-recon:attempt-2"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    lifecycle.register_call(
        tmp_path,
        {
            "agent_call_id": "toolu_recon_retry",
            "session_id": "shared01",
            "agent": "recon-scanner",
            "agent_type": AGENT_TYPE,
            "model": "sonnet",
            "description": "Reconnaissance",
            "background": False,
            "action_id": "stage1c:retry",
            "job_id": "phase2-recon:attempt-2",
            "max_turns": 36,
        },
    )
    lifecycle.bind_runtime_agent_id(tmp_path, "toolu_recon_retry", "agent-retry")
    lifecycle.record_runtime_usage(
        tmp_path, "agent-retry", {"input_tokens": 90_000, "output_tokens": 600}, tool_uses=20
    )
    lifecycle.finish_call(tmp_path, "toolu_recon_retry")
    assert telemetry.check_returned_calls(tmp_path) == []


def test_boundary_reports_by_default_and_aborts_only_under_strict(tmp_path: Path, monkeypatch) -> None:
    _seed(tmp_path, state="failed", usage=False)
    monkeypatch.delenv("APPSEC_TELEMETRY_STRICT", raising=False)
    controller._check_returned_call_telemetry(tmp_path)
    log = (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
    assert "TELEMETRY_MISMATCH" in log
    assert "code=lifecycle_failed_after_accepted_output" in log
    assert "job_id=phase2-recon" in log

    monkeypatch.setenv("APPSEC_TELEMETRY_STRICT", "1")
    try:
        controller._check_returned_call_telemetry(tmp_path)
    except controller.ControllerError as exc:
        assert "lifecycle_failed_after_accepted_output on phase2-recon" in str(exc)
    else:
        raise AssertionError("strict mode must abort on a telemetry mismatch")


def test_a_broken_check_fails_open_but_not_under_strict(tmp_path: Path, monkeypatch) -> None:
    def explode(_output_dir):
        raise RuntimeError("state reader broke")

    monkeypatch.setattr(telemetry, "check_returned_calls", explode)
    monkeypatch.delenv("APPSEC_TELEMETRY_STRICT", raising=False)
    controller._check_returned_call_telemetry(tmp_path)

    monkeypatch.setenv("APPSEC_TELEMETRY_STRICT", "1")
    try:
        controller._check_returned_call_telemetry(tmp_path)
    except controller.ControllerError as exc:
        assert "state reader broke" in str(exc)
    else:
        raise AssertionError("strict mode must surface a broken check")


def test_every_semantic_return_command_is_gated() -> None:
    """Every boundary that runs after a producer returned goes through the
    check — a new one must be added deliberately, not forgotten."""
    assert "context-v2-begin" not in controller._SEMANTIC_RETURN_COMMANDS
    source = (SCRIPTS / "orchestration_controller.py").read_text(encoding="utf-8")
    commands = {
        line.split('sub.add_parser("')[1].split('"')[0]
        for line in source.splitlines()
        if 'sub.add_parser("context-v2-post' in line or 'sub.add_parser("context-v2-finalize' in line
    }
    assert commands <= controller._SEMANTIC_RETURN_COMMANDS


def test_a_dispatched_job_without_a_lifecycle_call_is_named(tmp_path: Path) -> None:
    """One job of a wave whose admission hook never fired: the controller
    accepted a wave the lifecycle has no record of."""
    _seed(tmp_path)
    (tmp_path / ".context-routing-plan.json").write_text(
        json.dumps({"actions": [{"action_id": ACTION_ID, "job_ids": ["phase2-recon", "phase2-config"]}]}),
        encoding="utf-8",
    )
    assert _codes(tmp_path) == ["lifecycle_call_missing"]


def test_a_legacy_run_without_an_effective_plan_is_not_checked(tmp_path: Path) -> None:
    _seed(tmp_path, state="failed", usage=False)
    (tmp_path / ".context-routing-plan.json").unlink()
    assert telemetry.check_returned_calls(tmp_path) == []
