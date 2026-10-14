"""End-to-end controller runs through the real `claude -p` transport, offline.

`tests/e2e/fake_claude.py` stands in for the CLI: it answers each tool-less
exchange with the suite's contract-valid replies in the CLI's own result
format and fails planned calls the way the API does. Unlike the in-process
`FullHost` tests, these runs cross the process boundaries a real run crosses:
`scripts/run-headless.sh` dispatch, `ClaudeCliTransport` argv, environment and
stream parsing, and the controller's exit status and messages.

Run them alone with `make e2e-controller`; each run takes under a minute.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from orchestrator import orchestration_controller as controller
from runtime import multi_repo_discovery
from runtime.analyst_host import TransportError
from validators.validate_intermediate import validate_threat_model_output

from tests.test_multi_repo_controller import checkout

ROOT = Path(__file__).resolve().parents[1]
FAKE_CLAUDE = ROOT / "tests" / "e2e" / "fake_claude.py"
DELIVERABLES = ("threat-model.md", "threat-model.yaml", "threat-model.figure1.svg")


def _system(tmp_path, names, faults=""):
    roots = [tmp_path / name for name in names]
    for root in roots:
        checkout(root)
    out, state = tmp_path / "out", tmp_path / "fake-claude"
    env = {
        "APPSEC_CLAUDE_EXECUTABLE": str(FAKE_CLAUDE),
        "FAKE_CLAUDE_REPOS": os.pathsep.join(str(root) for root in roots),
        "FAKE_CLAUDE_OUTPUT": str(out),
        "FAKE_CLAUDE_STATE": str(state),
        "FAKE_CLAUDE_FAULTS": faults,
        # API billing skips the subscription login check.
        "ANTHROPIC_API_KEY": "offline-test",
    }
    if len(roots) == 1:
        env["APPSEC_SINGLE_REPO_CONTROLLER"] = "1"
    argv = [arg for root in roots for arg in ("--repo", str(root))]
    argv += ["--output", str(out), "--hard-budget", "5", "--trust-mode", "trusted", "--model", "haiku", "--no-pdf"]
    return argv, env, out, state


def _calls(state):
    path = state / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def _headless(argv, env, *extra):
    # The stub runs under the interpreter that runs the tests.
    path = f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"
    return subprocess.run(
        [str(ROOT / "scripts" / "run-headless.sh"), *argv, *extra],
        env={**os.environ, **env, "PATH": path},
        capture_output=True,
        text=True,
        timeout=600,
    )


def _assert_published(out, repositories):
    for name in DELIVERABLES:
        assert (out / name).is_file(), name
    model = yaml.safe_load((out / "threat-model.yaml").read_text())
    assert model["meta"]["schema_version"] == (1 if repositories == 1 else 2)
    assert model["threats"] and validate_threat_model_output(model)[0]


@pytest.mark.parametrize("names", [("solo",), ("frontend", "backend")])
def test_headless_runner_publishes_through_the_cli_transport(tmp_path, names):
    argv, env, out, state = _system(tmp_path, names)
    result = _headless(argv, env)
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    assert "Traceback" not in result.stderr
    _assert_published(out, len(names))
    calls = _calls(state)
    # Every call went through the CLI with the requested model.
    assert calls and {call["model"] for call in calls} == {"haiku"}
    assert {"recon_scanner", "architecture_analyst", "stride_analyzer"} <= {call["role"] for call in calls}


def test_a_login_failure_stops_with_its_reason_and_publishes_nothing(tmp_path):
    argv, env, out, state = _system(tmp_path, ("solo",), faults="*:auth:99")
    result = _headless(argv, env)
    assert result.returncode != 0
    assert "authentication_failed" in result.stderr and "/login" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (out / "threat-model.md").exists()
    # A login failure is never retried.
    assert len(_calls(state)) == 1


@pytest.fixture
def in_process(monkeypatch):
    """Run the controller in this process, so retry waits can be shortened."""
    monkeypatch.setattr(multi_repo_discovery, "TRANSIENT_RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}")

    def run(argv, env, *extra):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        return controller.assess_repositories([*argv, *extra], progress=lambda text: None)

    return run


@pytest.mark.parametrize(
    "faults",
    [
        "recon_scanner:rate_limit:2",
        "architecture_analyst:server_error:1",
        "stride_analyzer:text:3",
        "*:rate_limit:1,control_analyst:server_error:2",
    ],
)
def test_transient_api_failures_are_retried_and_the_run_completes(tmp_path, in_process, faults):
    argv, env, out, state = _system(tmp_path, ("solo",), faults=faults)
    outcome = in_process(argv, env)
    assert outcome["status"] == "complete"
    _assert_published(out, 1)
    planned = sum(int(entry.rsplit(":", 1)[1]) for entry in faults.split(","))
    assert sum(1 for call in _calls(state) if call["fault"]) == planned


def test_a_run_stopped_by_a_persistent_api_failure_resumes_without_redoing_accepted_jobs(tmp_path, in_process):
    argv, env, out, state = _system(tmp_path, ("solo",), faults="stride_analyzer:server_error:4")
    with pytest.raises(TransportError, match="server_error.*--resume"):
        in_process(argv, env)
    assert not (out / "threat-model.md").exists()
    before = _calls(state)
    assert [call["fault"] for call in before if call["role"] == "stride_analyzer"] == ["server_error"] * 4

    outcome = in_process(argv, {**env, "FAKE_CLAUDE_FAULTS": ""}, "--resume")
    assert outcome["status"] == "complete"
    _assert_published(out, 1)
    resumed = {call["role"] for call in _calls(state)[len(before) :]}
    # Discovery, architecture and controls were accepted before the stop.
    assert "stride_analyzer" in resumed
    assert not {"recon_scanner", "architecture_analyst", "control_analyst"} & resumed
