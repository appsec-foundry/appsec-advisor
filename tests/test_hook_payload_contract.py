"""Replay real hook sequences against the pinned host payload fixtures.

Every other lifecycle test builds its own payload dict, so a wrong assumption
about the host contract is repeated by the test that is supposed to catch it.
The postfix6 failure was exactly that: `SubagentStop` was read as if it carried
the child's `transcript_path`, and synthetic payloads agreed.

Two layers here:

* the fixture contract — key sets, types, and parent/child transcript
  ownership, checked for every supported host version in
  ``fixtures/hook-payloads/``;
* the replay table — whole event sequences a real run produces, driven through
  ``agent_logger.main()`` so the host dispatch is covered too, each asserting
  the terminal state the sequence must leave behind.

Adding a supported host version means dropping its sanitized fixture into the
directory; every case below then runs against it.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import agent_lifecycle as lifecycle  # noqa: E402
import agent_logger  # noqa: E402
import budget_watchdog as budget  # noqa: E402

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "hook-payloads"
FIXTURES = sorted(FIXTURE_DIR.glob("claude-code-*.json"))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(params=FIXTURES, ids=lambda path: path.stem)
def host(request) -> dict:
    return _load(request.param)


def test_at_least_one_supported_host_is_pinned() -> None:
    assert FIXTURES, "no host payload fixture — the contract would be unpinned"


def test_fixture_pins_the_host_payload_keys_and_types(host: dict) -> None:
    assert host["host"]["version"]
    base_required = set(host["base_keys"]["required"])
    base_allowed = base_required | set(host["base_keys"]["optional"])

    expected = {
        "PreToolUse": {"tool_name", "tool_use_id", "tool_input"},
        "SubagentStart": {"agent_id", "agent_type"},
        "SubagentStop": {"stop_hook_active", "agent_id", "agent_type", "agent_transcript_path"},
        "PostToolUse": {"tool_name", "tool_use_id", "tool_input", "tool_response"},
    }
    for event, required in expected.items():
        payload = host["events"][event]
        assert payload["hook_event_name"] == event
        assert base_required | required <= set(payload)
        unknown = set(payload) - base_allowed - required - {"duration_ms", "last_assistant_message"}
        assert not unknown, f"{event} fixture carries keys the host contract does not define: {sorted(unknown)}"
        assert all(isinstance(payload[key], str) for key in base_required)

    stop = host["events"]["SubagentStop"]
    # The two fields the lifecycle consumer needs are absent by contract, which
    # is why they are derived from the child transcript rather than the payload.
    assert "stop_reason" not in stop
    assert "usage" not in stop
    assert stop["transcript_path"] != stop["agent_transcript_path"]


# ---------------------------------------------------------------------------
# Replay harness
# ---------------------------------------------------------------------------


def _transcript(path: Path, *, stop_reason: str, inp: int, out: int, tool_uses: int) -> str:
    path.write_text(
        json.dumps(
            {
                "message": {
                    "role": "assistant",
                    "stop_reason": stop_reason,
                    "usage": {"input_tokens": inp, "output_tokens": out},
                    "content": [{"type": "tool_use", "id": f"toolu_{path.stem}_{i}"} for i in range(tool_uses)],
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return str(path)


class Run:
    """One replayed run: mints payload variants and delivers them like the host."""

    ACTION_ID = "stage1:a"

    def __init__(self, host: dict, tmp_path: Path) -> None:
        self.events = host["events"]
        self.tmp_path = tmp_path
        self.parent = _transcript(
            tmp_path / "parent.jsonl", stop_reason="tool_use", inp=900_000, out=40_000, tool_uses=2
        )
        self.claimed: list[str] = []

    def _claim(self, job_id: str) -> None:
        """Record the controller claim a turn budget is scoped to.

        Budget tracking is claim-scoped in production: without the routing plan
        entry the call is not current and no counter opens. A replay that
        skipped this would test a code path no run takes.
        """
        self.claimed.append(job_id)
        (self.tmp_path / ".context-routing-plan.json").write_text(
            json.dumps({"actions": [{"action_id": self.ACTION_ID, "job_ids": self.claimed}]}),
            encoding="utf-8",
        )

    def child(self, name: str, *, stop_reason: str = "end_turn", out: int = 700, tool_uses: int = 12) -> str:
        return _transcript(
            self.tmp_path / f"{name}.jsonl", stop_reason=stop_reason, inp=100_000, out=out, tool_uses=tool_uses
        )

    def deliver(self, event: str, **overrides) -> None:
        """Send one payload through the host entry point, not a handler."""
        payload = dict(self.events[event])
        payload["transcript_path"] = self.parent
        payload["cwd"] = str(self.tmp_path)
        if "agent_transcript_path" in payload:
            payload["agent_transcript_path"] = self.parent
        payload.update(overrides)
        stdin = sys.stdin
        sys.stdin = io.StringIO(json.dumps(payload))
        try:
            agent_logger.main()
        finally:
            sys.stdin = stdin

    def call(self, call_id: str, agent_id: str, agent_type: str, job_id: str, **child) -> None:
        """The full happy sequence for one Agent call."""
        self.spawn(call_id, agent_type, job_id)
        self.deliver("SubagentStart", agent_id=agent_id, agent_type=agent_type)
        self.stop(agent_id, agent_type, **child)
        self.post(call_id, agent_type, job_id)

    def spawn(self, call_id: str, agent_type: str, job_id: str, background: bool = False, claimed: bool = True) -> None:
        if claimed:
            self._claim(job_id)
        self.deliver(
            "PreToolUse",
            tool_use_id=call_id,
            tool_input={
                **self.events["PreToolUse"]["tool_input"],
                "subagent_type": agent_type,
                "run_in_background": background,
                "prompt": (f"OUTPUT_DIR={self.tmp_path}\nACTION_ID={self.ACTION_ID}\nJOB_ID={job_id}\nMAX_TURNS=36\n"),
            },
        )

    def stop(self, agent_id: str, agent_type: str, **child) -> None:
        self.deliver(
            "SubagentStop",
            agent_id=agent_id,
            agent_type=agent_type,
            agent_transcript_path=self.child(agent_id, **child),
        )

    def post(self, call_id: str, agent_type: str, job_id: str) -> None:
        self.deliver(
            "PostToolUse",
            tool_use_id=call_id,
            tool_input={
                **self.events["PostToolUse"]["tool_input"],
                "subagent_type": agent_type,
                "prompt": f"OUTPUT_DIR={self.tmp_path}\nACTION_ID={self.ACTION_ID}\nJOB_ID={job_id}\n",
            },
        )

    @property
    def log(self) -> str:
        return (self.tmp_path / ".hook-events.log").read_text(encoding="utf-8")

    def calls(self) -> list[dict]:
        return json.loads(lifecycle.state_path(self.tmp_path).read_text(encoding="utf-8"))["calls"]

    def budget_calls(self) -> dict:
        path = self.tmp_path / budget.STATE_FILENAME
        return json.loads(path.read_text(encoding="utf-8"))["calls"] if path.is_file() else {}


@pytest.fixture
def run(host: dict, tmp_path: Path, monkeypatch) -> Run:
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    return Run(host, tmp_path)


def test_one_foreground_role_returns_with_child_usage(run: Run) -> None:
    run.call("toolu_a", "agent_a", "appsec-advisor:appsec-recon-scanner", "phase2-recon")

    call = run.calls()[0]
    assert call["state"] == "done"
    assert call["job_id"] == "phase2-recon"
    assert call["usage"]["output_tokens"] == 700
    assert call["usage"]["tool_uses"] == 12
    assert run.budget_calls() == {}
    assert run.log.count("AGENT_SPAWN") == 1
    assert run.log.count("AGENT_DONE") == 1
    assert "AGENT_FAILED" not in run.log


def test_two_sequential_roles_keep_their_usage_apart(run: Run) -> None:
    run.call("toolu_a", "agent_a", "appsec-advisor:appsec-recon-scanner", "phase2-recon", out=700)
    run.call("toolu_b", "agent_b", "appsec-advisor:appsec-architecture-analyst", "phase3-6-architecture", out=1_500)

    usage = {call["job_id"]: call["usage"]["output_tokens"] for call in run.calls()}
    assert usage == {"phase2-recon": 700, "phase3-6-architecture": 1_500}
    assert all(call["state"] == "done" for call in run.calls())


def test_a_parallel_wave_terminalizes_every_job_once(run: Run) -> None:
    jobs = [(f"toolu_{i}", f"agent_{i}", f"stride:c{i}:attempt-1") for i in range(3)]
    agent_type = "appsec-advisor:appsec-stride-analyzer-v2"
    for call_id, _, job_id in jobs:
        run.spawn(call_id, agent_type, job_id, background=True)
    for _, agent_id, _ in jobs:
        run.deliver("SubagentStart", agent_id=agent_id, agent_type=agent_type)
    for _, agent_id, _ in jobs:
        run.stop(agent_id, agent_type)
    for call_id, _, job_id in jobs:
        run.post(call_id, agent_type, job_id)

    assert len(run.calls()) == 3
    assert {call["state"] for call in run.calls()} == {"done"}
    assert run.log.count("AGENT_SPAWN") == 3
    assert run.log.count("AGENT_DONE") == 3
    assert run.budget_calls() == {}


def test_a_missing_post_still_closes_the_call(run: Run) -> None:
    """PostToolUse does not reliably reach the parent for every dispatch;
    SubagentStop is the return boundary that must not depend on it."""
    run.spawn("toolu_a", "appsec-advisor:appsec-recon-scanner", "phase2-recon")
    run.deliver("SubagentStart", agent_id="agent_a", agent_type="appsec-advisor:appsec-recon-scanner")
    run.stop("agent_a", "appsec-advisor:appsec-recon-scanner")

    assert run.calls()[0]["state"] == "done"
    assert run.budget_calls() == {}


def test_every_hook_delivered_twice_changes_nothing(run: Run) -> None:
    for _ in range(2):
        run.call("toolu_a", "agent_a", "appsec-advisor:appsec-recon-scanner", "phase2-recon")

    assert len(run.calls()) == 1
    assert run.log.count("AGENT_SPAWN") == 1
    assert run.log.count("AGENT_DONE") == 1
    assert "AGENT_INVOKE" not in run.log


def test_an_interrupted_call_is_failed_by_terminal_cleanup(run: Run) -> None:
    """No SubagentStop and no PostToolUse ever arrive — the operator killed the
    session. The call must not stay running once the run is over."""
    run.spawn("toolu_a", "appsec-advisor:appsec-architecture-analyst", "phase3-6-architecture")
    run.deliver("SubagentStart", agent_id="agent_a", agent_type="appsec-advisor:appsec-architecture-analyst")
    assert run.calls()[0]["state"] == "running"

    agent_logger.clear_terminal_active_tool_calls(run.tmp_path)
    assert "AGENT_FAILED" in run.log
    assert "outer_session_terminal" in run.log
    assert not lifecycle.state_path(run.tmp_path).exists()


def test_a_retry_opens_a_new_call_and_only_that_one_returns(run: Run) -> None:
    agent_type = "appsec-advisor:appsec-stride-analyzer-v2"
    run.spawn("toolu_1", agent_type, "stride:api:attempt-1", background=True)
    run.deliver("SubagentStart", agent_id="agent_1", agent_type=agent_type)
    run.stop("agent_1", agent_type, stop_reason="max_turns", out=50)

    run.spawn("toolu_2", agent_type, "stride:api:attempt-2", background=True)
    run.deliver("SubagentStart", agent_id="agent_2", agent_type=agent_type)
    run.stop("agent_2", agent_type)

    states = {call["job_id"]: call["state"] for call in run.calls()}
    assert states == {"stride:api:attempt-1": "failed", "stride:api:attempt-2": "done"}
    assert "MAX_TURNS" in run.log
    assert run.budget_calls() == {}


def test_a_long_running_child_crosses_its_turn_budget_on_return(run: Run) -> None:
    """The provider-wait case as it is observable here: nothing arrives between
    start and stop, and the child returns having spent most of its ceiling."""
    run.spawn("toolu_a", "appsec-advisor:appsec-recon-scanner", "phase2-recon")
    run.deliver("SubagentStart", agent_id="agent_a", agent_type="appsec-advisor:appsec-recon-scanner")
    run.stop("agent_a", "appsec-advisor:appsec-recon-scanner", tool_uses=30)

    assert "BUDGET_" in run.log
    assert run.calls()[0]["usage"]["tool_uses"] == 30
    assert run.calls()[0]["state"] == "done"


def test_a_call_outside_the_current_claim_gets_no_turn_budget(run: Run) -> None:
    """Budget counters are claim-scoped. A dispatch the controller does not
    claim must not open one, or a superseded attempt would keep counting."""
    run.spawn("toolu_a", "appsec-advisor:appsec-recon-scanner", "phase2-recon", claimed=False)
    assert run.budget_calls() == {}
    run.deliver("SubagentStart", agent_id="agent_a", agent_type="appsec-advisor:appsec-recon-scanner")
    run.stop("agent_a", "appsec-advisor:appsec-recon-scanner", tool_uses=30)
    assert "BUDGET_" not in run.log
    assert run.calls()[0]["state"] == "done"
