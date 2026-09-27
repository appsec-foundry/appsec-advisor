"""Exercise worker bounds with real local processes and no paid model calls."""

import json
import os
import sys
import time
from pathlib import Path

import architect_review_worker as worker
import pytest
from architect_review import ReviewError

from tests.test_build_architect_context import build


@pytest.mark.skipif(os.name != "posix", reason="transport requires process groups")
def test_silent_worker_is_terminated_at_deadline(tmp_path):
    start = time.monotonic()
    result = worker._run_bounded(
        [sys.executable, "-c", "import time; time.sleep(60)"], b"", cwd=tmp_path, timeout_seconds=0.2
    )
    assert result.status == "deadline_exceeded"
    assert time.monotonic() - start < 3
    assert result.output == b""


@pytest.mark.skipif(os.name != "posix", reason="transport requires process groups")
def test_deadline_kills_descendants_before_they_can_write(tmp_path):
    marker = tmp_path / "late-result"
    child = "import time; from pathlib import Path; time.sleep(1); Path('late-result').write_text('late')"
    parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(60)"
    result = worker._run_bounded([sys.executable, "-c", parent], b"", cwd=tmp_path, timeout_seconds=0.3)
    assert result.status == "deadline_exceeded"
    time.sleep(1.1)
    assert not marker.exists()


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_flood_is_bounded_and_discards_diagnostics(tmp_path, stream):
    program = f"import sys; sys.{stream}.write('x' * 1000000); sys.{stream}.flush()"
    result = worker._run_bounded([sys.executable, "-c", program], b"", cwd=tmp_path, timeout_seconds=3)
    assert result.status == "output_limit_exceeded"
    assert result.output == b""


def test_large_stdin_and_stdout_do_not_deadlock(tmp_path):
    payload = b"q" * 131_072
    result = worker._run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        payload,
        cwd=tmp_path,
        timeout_seconds=3,
    )
    assert result.status == "completed"
    assert result.output == payload


def test_process_error_does_not_disclose_stderr(tmp_path):
    result = worker._run_bounded(
        [sys.executable, "-c", "import sys; sys.stderr.write('sensitive diagnostic'); sys.exit(1)"],
        b"",
        cwd=tmp_path,
        timeout_seconds=3,
    )
    assert result == worker.WorkerResult("failed")


def test_print_worker_drops_only_the_interactive_nesting_marker(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setenv("ARCHITECT_TEST_CONTEXT", "retained")
    result = worker._run_bounded(
        [sys.executable, "-c", "import os; print('CLAUDECODE' in os.environ, os.environ['ARCHITECT_TEST_CONTEXT'])"],
        b"",
        cwd=tmp_path,
        timeout_seconds=3,
    )
    assert result.status == "completed"
    assert result.output.strip() == b"False retained"


def fake_transport(monkeypatch, response, *, flags=None):
    calls = []
    monkeypatch.setattr(worker.shutil, "which", lambda _name: sys.executable)

    def run(argv, payload, *, cwd, timeout_seconds):
        assert cwd.is_dir()
        assert cwd != Path.cwd()
        calls.append((argv, payload, cwd, timeout_seconds))
        if argv[-1] == "--help":
            return worker.WorkerResult("completed", " ".join(flags or worker._REQUIRED_FLAGS).encode())
        return worker.WorkerResult("completed", json.dumps(response).encode())

    monkeypatch.setattr(worker, "_run_bounded", run)
    return calls


def test_model_gets_only_packet_and_has_no_tools_or_customizations(monkeypatch):
    packet = build()["packets"][0]
    proposal = {
        "schema_version": 1,
        "run_id": packet["run_id"],
        "packet_id": packet["packet_id"],
        "input_sha256": packet["input_sha256"],
        "decisions": [],
    }
    calls = fake_transport(monkeypatch, {"is_error": False, "result": json.dumps(proposal)})
    status, value = worker.run_packet(packet, model="sonnet", timeout_seconds=10)
    assert (status, value) == ("completed", proposal)
    assert len(calls) == 2
    argv, payload, cwd, timeout = calls[-1]
    assert argv[argv.index("--tools") + 1] == ""
    assert argv[argv.index("--mcp-config") + 1] == '{"mcpServers":{}}'
    assert "--strict-mcp-config" in argv and "--safe-mode" in argv
    assert "--disable-slash-commands" in argv and "--no-session-persistence" in argv
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"
    assert "--dangerously-skip-permissions" not in argv
    assert json.loads(payload) == packet
    assert 0 < timeout <= 10
    assert not cwd.exists()


def test_unsupported_host_never_calls_model(monkeypatch):
    calls = fake_transport(monkeypatch, {}, flags=["--print"])
    assert worker.run_packet(build()["packets"][0], model="sonnet", timeout_seconds=10) == ("unsupported_host", None)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        [],
        {"is_error": False, "result": "[]"},
        {"is_error": False, "result": "```json\n{}\n```"},
        {"is_error": False, "result": "x" * 131073},
    ],
)
def test_untrusted_host_response_has_no_fallback_or_repair(monkeypatch, response):
    calls = fake_transport(monkeypatch, response)
    assert worker.run_packet(build()["packets"][0], model="sonnet", timeout_seconds=10) == ("invalid_response", None)
    assert len(calls) == 2


def test_deeply_nested_model_json_is_rejected_without_a_crash(monkeypatch):
    nested = '{"decisions":' + "[" * 2000 + "0" + "]" * 2000 + "}"
    fake_transport(monkeypatch, {"is_error": False, "result": nested})
    assert worker.run_packet(build()["packets"][0], model="sonnet", timeout_seconds=10) == ("invalid_response", None)


def test_host_error_is_distinct_from_a_malformed_model_proposal(monkeypatch):
    calls = fake_transport(monkeypatch, {"is_error": True, "result": "private host diagnostic"})
    assert worker.run_packet(build()["packets"][0], model="sonnet", timeout_seconds=10) == ("failed", None)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "model,timeout", [("--tools=Bash", 10), ("sonnet", float("inf")), ("sonnet", True), ("sonnet", 0)]
)
def test_invalid_admission_never_launches_worker(monkeypatch, model, timeout):
    calls = fake_transport(monkeypatch, {})
    with pytest.raises(ReviewError):
        worker.run_packet(build()["packets"][0], model=model, timeout_seconds=timeout)
    assert calls == []


def test_missing_host_returns_explicit_outcome(monkeypatch):
    monkeypatch.setattr(worker.shutil, "which", lambda _name: None)
    assert worker.run_packet(build()["packets"][0], model="sonnet", timeout_seconds=10) == ("unavailable", None)


@pytest.mark.parametrize("failure", ["deadline_exceeded", "failed", "output_limit_exceeded"])
def test_failed_calls_retain_elapsed_time_without_raw_diagnostics(monkeypatch, failure):
    monkeypatch.setattr(worker.shutil, "which", lambda _name: sys.executable)

    def run(argv, payload, *, cwd, timeout_seconds):
        if argv[-1] == "--help":
            return worker.WorkerResult("completed", " ".join(worker._REQUIRED_FLAGS).encode())
        return worker.WorkerResult(failure, b"private diagnostic")

    monkeypatch.setattr(worker, "_run_bounded", run)
    telemetry = {"old_run": "stale"}
    assert worker.run_packet(build()["packets"][0], model="sonnet", timeout_seconds=10, telemetry=telemetry) == (
        failure,
        None,
    )
    assert set(telemetry) == {"wall_seconds"}
    assert 0 <= telemetry["wall_seconds"] < 10


def test_a_repository_relative_host_is_not_executed(monkeypatch):
    monkeypatch.setattr(worker.shutil, "which", lambda _name: "./claude")
    assert worker.run_packet(build()["packets"][0], model="sonnet", timeout_seconds=10) == ("unavailable", None)


def test_telemetry_preserves_only_bounded_host_numbers(monkeypatch):
    fake_transport(
        monkeypatch,
        {
            "is_error": False,
            "result": "{}",
            "num_turns": 1,
            "duration_ms": 500,
            "usage": {
                "input_tokens": 42,
                "output_tokens": 10,
                "cache_read_input_tokens": True,
                "raw_prompt": "private",
            },
            "total_cost_usd": 0.02,
            "modelUsage": {"claude-sonnet-test": {}},
            "raw_prompt": "private",
        },
    )
    telemetry = {"old_run": "stale"}
    assert worker.run_packet(build()["packets"][0], model="sonnet", timeout_seconds=10, telemetry=telemetry) == (
        "completed",
        {},
    )
    assert telemetry["usage"] == {"input_tokens": 42, "output_tokens": 10}
    assert telemetry["total_cost_usd"] == 0.02
    assert telemetry["model_ids"] == ["claude-sonnet-test"]
    assert "raw_prompt" not in telemetry and "old_run" not in telemetry
