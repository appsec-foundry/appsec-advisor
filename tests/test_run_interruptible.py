"""Tests for scripts/run-interruptible.sh.

Covers the happy-path exit-code passthrough and the Ctrl-C abort path: a single
SIGINT to the wrapper must promptly tear down the backgrounded command group
(even a plain `sleep`) and surface a non-zero exit, never hanging.
"""

import os
import pty
import signal
import subprocess
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "run-interruptible.sh"


def _run(log_path, *cmd, **popen_kwargs):
    return subprocess.Popen(
        ["bash", str(SCRIPT), str(log_path), *cmd],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **popen_kwargs,
    )


def test_happy_path_exit_zero_and_log(tmp_path):
    log = tmp_path / "out.log"
    proc = _run(log, "bash", "-c", "echo hello-world")
    assert proc.wait(timeout=10) == 0
    assert "hello-world" in log.read_text()


def test_exit_code_passthrough(tmp_path):
    log = tmp_path / "out.log"
    proc = _run(log, "bash", "-c", "exit 7")
    assert proc.wait(timeout=10) == 7


def test_usage_error_when_missing_command(tmp_path):
    proc = _run(tmp_path / "out.log")  # only the logfile arg, no command
    assert proc.wait(timeout=10) == 2


def test_nested_job_control_does_not_stop_under_tty(tmp_path):
    """A nested ``set -m`` must not SIGTTOU-stop the command session."""
    log = tmp_path / "out.log"
    pid, master_fd = pty.fork()
    if pid == 0:  # pragma: no cover - child replaces the test interpreter
        os.execv(
            "/bin/bash",
            [
                "bash",
                str(SCRIPT),
                str(log),
                "bash",
                "-c",
                "set -m; true & wait",
            ],
        )

    status = None
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline:
            waited_pid, status = os.waitpid(pid, os.WNOHANG)
            if waited_pid == pid:
                break
            time.sleep(0.05)
    finally:
        os.close(master_fd)
        if status is None:
            os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)

    assert status is not None, "wrapper hung after a nested script enabled job control"
    assert os.waitstatus_to_exitcode(status) == 0


def test_sigint_aborts_long_command_promptly(tmp_path):
    log = tmp_path / "out.log"
    marker = tmp_path / "finished"
    # A command that would run for 60s and only then touch `marker`. A working
    # abort kills it long before that, so `marker` must never appear.
    proc = _run(
        log,
        "bash",
        "-c",
        f"sleep 60; touch {marker}",
        # Own session so the test's SIGINT to proc.pid mimics a terminal Ctrl-C
        # reaching the foreground process without disturbing the pytest runner.
        start_new_session=True,
    )
    time.sleep(2)  # let the wrapper start the group and install its trap
    os.kill(proc.pid, signal.SIGINT)

    try:
        rc = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:  # pragma: no cover - failure path
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        pytest.fail("wrapper did not exit promptly after SIGINT")

    assert rc != 0
    assert not marker.exists(), "inner command survived the interrupt"
