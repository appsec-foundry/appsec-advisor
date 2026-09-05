"""Tests for the run-ownership rule shared by the lock writer and its readers.

`.appsec-lock` line 3 carries the *run id*. `orchestration_controller` writes
it; `agent_logger` reads it to decide whether a `Stop` event is the end of the
outer assessment, and `budget_watchdog` reads it to decide whether a budget flag
belongs to the running assessment. A reader that resolves the id differently
from the writer compares two namespaces: under `run-headless.sh` the lock says
`run-<epoch>-<pid>` while a hook payload says a Claude session id, and the two
never match.

The consequence is silent and total. Every `Stop` — including the ones Claude
Code emits inside sub-agent sessions with the parent's session id — reads as the
terminal outer Stop, so live agents are marked failed, the assessment summary
fires minutes into the run, and the sentinel it claims suppresses the real one.
On the budget surface the run fails its own ownership test and drops every flag
it raises, disabling turn exhaustion detection for the whole run.

These tests therefore assert the *agreement* between writer and readers across
every environment shape, not the id a particular run happens to produce.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import acquire_lock  # noqa: E402
import orchestration_controller as controller  # noqa: E402

# The environment shapes a run can start in. `run-headless.sh` exports
# APPSEC_RUN_ID before the Claude session exists; an interactive run has only
# the session variables; a bare invocation has neither.
RUN_ENVIRONMENTS = [
    pytest.param({"APPSEC_RUN_ID": "run-1788592678-3277507"}, id="headless"),
    pytest.param(
        {"CLAUDE_CODE_SESSION_ID": "6b851f4b-8235-4a64-bf25-7563d1377a0f"},
        id="interactive",
    ),
    pytest.param({"CLAUDE_SESSION_ID": "6b851f4b-8235-4a64-bf25-7563d1377a0f"}, id="legacy-session-var"),
    pytest.param(
        {
            "APPSEC_RUN_ID": "run-1788592678-3277507",
            "CLAUDE_CODE_SESSION_ID": "6b851f4b-8235-4a64-bf25-7563d1377a0f",
        },
        id="headless-inside-a-session",
    ),
]

_RUN_VARIABLES = ("APPSEC_RUN_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID")


@pytest.fixture
def run_env(monkeypatch):
    """Return a setter that makes the process's run identity explicit.

    The suite itself runs inside a Claude Code session, so CLAUDE_CODE_SESSION_ID
    is set ambiently. A test that left it in place would assert against whichever
    session happened to run it.
    """

    def _set(environment: dict[str, str]) -> None:
        for name in _RUN_VARIABLES:
            monkeypatch.delenv(name, raising=False)
        for name, value in environment.items():
            monkeypatch.setenv(name, value)

    return _set


def _write_lock(lock_path: Path, run_id: str, *, fresh: bool = True) -> None:
    heartbeat = int(time.time()) - (0 if fresh else 3600)
    lock_path.write_text(f"12345\n{heartbeat}\n{run_id}\nacquired={heartbeat}\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# The rule: what the controller writes, the readers recognise as their own.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("environment", RUN_ENVIRONMENTS)
def test_the_reader_recognises_the_run_id_the_controller_writes(tmp_path, run_env, environment):
    run_env(environment)
    lock_path = tmp_path / ".appsec-lock"

    _write_lock(lock_path, controller._run_id_for_this_run())

    assert acquire_lock.lock_is_owned_by_this_run(lock_path, "6b851f4b-8235-4a64-bf25-7563d1377a0f")


@pytest.mark.parametrize("environment", RUN_ENVIRONMENTS)
def test_a_foreign_run_is_never_recognised_as_this_one(tmp_path, run_env, environment):
    """A second assessment sharing OUTPUT_DIR must stay foreign in every shape."""
    run_env(environment)
    lock_path = tmp_path / ".appsec-lock"

    _write_lock(lock_path, "run-1700000000-42")
    if environment.get("APPSEC_RUN_ID") == "run-1700000000-42":  # pragma: no cover - guard the fixture
        pytest.fail("the foreign id must differ from every shape's own id")

    assert not acquire_lock.lock_is_owned_by_this_run(lock_path, "9617b066-0000-0000-0000-000000000000")


def test_a_generated_run_id_is_outside_the_hook_contract(tmp_path, run_env):
    """The controller's last-resort id names a run no hook can identify with.

    It is reachable only when the environment names neither a run nor a session,
    which is a controller invoked outside a Claude session — where no Stop or
    PostToolUse event is produced either. Pinned so that a future caller which
    does reach it from inside a session sees this boundary rather than the
    silent mismatch that motivated these tests.
    """
    run_env({})
    lock_path = tmp_path / ".appsec-lock"

    generated = controller._run_id_for_this_run()
    assert generated.startswith("run-")
    _write_lock(lock_path, generated)

    assert not acquire_lock.lock_is_owned_by_this_run(lock_path, "6b851f4b-8235-4a64-bf25-7563d1377a0f")


def test_a_lock_without_a_run_id_is_owned_by_nobody(tmp_path, run_env):
    """v1/v2 locks and a v3 lock whose 3rd line is a labeled field."""
    run_env({"APPSEC_RUN_ID": "run-1"})
    lock_path = tmp_path / ".appsec-lock"

    lock_path.write_text("12345\n1788592678\n", encoding="utf-8")
    assert not acquire_lock.lock_is_owned_by_this_run(lock_path, "6b851f4b")

    lock_path.write_text("12345\n1788592678\nacquired=1788592678\n", encoding="utf-8")
    assert not acquire_lock.lock_is_owned_by_this_run(lock_path, "6b851f4b")


def test_a_released_lock_is_owned_by_nobody(tmp_path, run_env):
    """The happy path: the outer session releases the lock before its last Stop."""
    run_env({"APPSEC_RUN_ID": "run-1788592678-3277507"})

    assert not acquire_lock.lock_is_owned_by_this_run(tmp_path / ".appsec-lock", "6b851f4b")


def test_the_session_id_identifies_the_run_only_without_an_environment(tmp_path, run_env):
    """The payload session is the last resort, and it loses to a named run id.

    Without this, a hook whose environment names run B would still claim a lock
    held by run A whenever the two sessions shared an id prefix.
    """
    lock_path = tmp_path / ".appsec-lock"
    _write_lock(lock_path, "6b851f4b-8235-4a64-bf25-7563d1377a0f")

    run_env({})
    assert acquire_lock.lock_is_owned_by_this_run(lock_path, "6b851f4b-8235-4a64-bf25-7563d1377a0f")

    run_env({"APPSEC_RUN_ID": "run-1788592678-3277507"})
    assert not acquire_lock.lock_is_owned_by_this_run(lock_path, "6b851f4b-8235-4a64-bf25-7563d1377a0f")
