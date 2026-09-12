"""Tests for the lifecycle-based join of asynchronous plugin agent calls."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import agent_lifecycle
import pytest
import wait_agent_calls as wac

SKILL_DIR = Path(__file__).resolve().parents[1] / "skills" / "create-threat-model"
POST_STAGE1_RUNTIMES = ("SKILL-thin-stage2.md", "SKILL-thin-stage3.md", "SKILL-thin-stage4.md")


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _call(
    call_id: str,
    spawned_at: int,
    *,
    state: str = "running",
    agent_type: str = "appsec-advisor:appsec-secarch-renderer",
    **extra: object,
) -> dict:
    call = {
        "agent_call_id": call_id,
        "session_id": "sid00001",
        "agent": agent_type.rsplit(":", 1)[-1],
        "agent_type": agent_type,
        "model": "sonnet",
        "description": "",
        "background": True,
        "state": state,
        "spawned_at": spawned_at,
        "running_at": spawned_at,
    }
    if state != "running":
        call["finished_at"] = spawned_at + 1
    call.update(extra)
    return call


def _write_calls(output_dir: Path, *calls: dict) -> None:
    path = agent_lifecycle.state_path(output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, "calls": list(calls)}), encoding="utf-8")


def _join(output_dir: Path, since: str, *extra: str) -> int:
    return wac.main([str(output_dir), "--since", since, "--rounds", "1", *extra])


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(wac.time, "sleep", lambda _seconds: None)


def test_finished_calls_release_the_join(tmp_path):
    now = int(time.time())
    _write_calls(
        tmp_path,
        _call("toolu_ms", now - 5, state="done"),
        _call("toolu_sa", now - 5, state="failed", failure_reason="api_error"),
    )
    assert _join(tmp_path, _iso(now - 30)) == 0


def test_a_running_call_holds_the_join_and_asks_for_a_repeat(tmp_path, capsys):
    now = int(time.time())
    _write_calls(tmp_path, _call("toolu_sa", now - 5))
    assert _join(tmp_path, _iso(now - 30)) == wac.PENDING_EXIT_CODE
    assert "exit 75 means repeat the identical command" in capsys.readouterr().err


def test_a_stopped_child_no_longer_holds_the_join(tmp_path):
    now = int(time.time())
    _write_calls(tmp_path, _call("toolu_sa", now - 5, stopped_at=now - 1))
    assert _join(tmp_path, _iso(now - 30)) == 0


def test_calls_from_before_the_dispatch_and_foreign_agents_are_not_joined(tmp_path):
    now = int(time.time())
    _write_calls(
        tmp_path,
        _call("toolu_leaked", now - 600),
        _call("toolu_user", now - 5, agent_type="general-purpose"),
    )
    assert _join(tmp_path, _iso(now - 30)) == 0


def test_a_call_past_the_deadline_is_released_with_a_warning(tmp_path, capsys):
    now = int(time.time())
    _write_calls(tmp_path, _call("toolu_sa", now - 3700))
    assert _join(tmp_path, _iso(now - 3800), "--deadline-minutes", "60") == 1
    assert "past the 60-minute deadline" in capsys.readouterr().err


def test_an_empty_since_joins_every_live_plugin_call(tmp_path):
    now = int(time.time())
    _write_calls(tmp_path, _call("toolu_sa", now - 5))
    assert _join(tmp_path, "") == wac.PENDING_EXIT_CODE


def test_a_since_in_the_future_does_not_skip_the_join(tmp_path):
    now = int(time.time())
    _write_calls(tmp_path, _call("toolu_sa", now - 5))
    assert _join(tmp_path, _iso(now + 7200)) == wac.PENDING_EXIT_CODE


def test_an_invalid_since_is_rejected(tmp_path):
    assert _join(tmp_path, "yesterday") == 2


@pytest.mark.parametrize("content", [None, "{", '{"schema_version": 1}'])
def test_missing_or_unreadable_state_is_never_reported_as_finished(tmp_path, no_sleep, capsys, content):
    if content is not None:
        path = agent_lifecycle.state_path(tmp_path)
        path.parent.mkdir(parents=True)
        path.write_text(content, encoding="utf-8")
    assert wac.main([str(tmp_path), "--since", _iso(time.time() - 30)]) == 1
    assert "cannot see the calls" in capsys.readouterr().err


def test_the_join_waits_across_rounds_and_reports_each_change_once(tmp_path, monkeypatch, no_sleep, capsys):
    now = int(time.time())
    running = [_call("toolu_ms", now - 5), _call("toolu_sa", now - 5)]
    ms_done = _call("toolu_ms", now - 5, state="done")
    rounds = iter(
        [
            running,
            running,
            [ms_done, running[1]],
            [ms_done, _call("toolu_sa", now - 5, state="done")],
        ]
    )
    monkeypatch.setattr(wac, "joined_calls", lambda _output_dir, _since: next(rounds))

    assert wac.main([str(tmp_path), "--since", _iso(now - 30)]) == 0
    out = capsys.readouterr().out
    assert out.count("2 of 2 agent call(s) still running") == 1
    assert out.count("1 of 2 agent call(s) still running") == 1


def test_the_join_reads_state_the_real_lifecycle_writes(tmp_path):
    since = _iso(time.time() - 5)
    agent_lifecycle.register_call(
        tmp_path,
        {
            "agent_call_id": "toolu_real_renderer",
            "session_id": "sid00001",
            "agent": "appsec-secarch-renderer",
            "agent_type": "appsec-advisor:appsec-secarch-renderer",
            "model": "sonnet",
            "description": "Render: §7 Security Architecture",
            "background": False,
        },
    )
    # The host answers the Agent call with a launch, which promotes it to background.
    agent_lifecycle.acknowledge_background_call(tmp_path, "toolu_real_renderer")
    assert _join(tmp_path, since) == wac.PENDING_EXIT_CODE

    agent_lifecycle.finish_call(tmp_path, "toolu_real_renderer")
    assert _join(tmp_path, since) == 0


@pytest.mark.parametrize("runtime", POST_STAGE1_RUNTIMES)
def test_every_post_stage1_runtime_that_dispatches_agents_joins_them(runtime):
    text = (SKILL_DIR / runtime).read_text(encoding="utf-8")
    if re.search(r"appsec-advisor:appsec-[a-z-]+", text):
        assert "scripts/wait_agent_calls.py" in text, f"{runtime} dispatches agents but never joins them"


@pytest.mark.parametrize("runtime", POST_STAGE1_RUNTIMES)
def test_runtime_join_commands_use_real_flags(runtime):
    accepted = set(re.findall(r"--[a-z-]+", wac.build_parser().format_help()))
    text = (SKILL_DIR / runtime).read_text(encoding="utf-8")
    for command in re.findall(r"wait_agent_calls\.py[^`\n]*", text):
        for flag in re.findall(r"--[a-z-]+", command):
            assert flag in accepted, f"{runtime}: {flag} is not a wait_agent_calls.py flag"
