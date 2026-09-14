"""Tests for scripts/terminate_run.py — one terminal result per exit class.

The operator-interrupt case is the one that had no owner: the shell wrapper
cleared the live markers and exited, leaving the lock held, the checkpoint
mid-flight and no `RUN_ABORTED` record. These tests pin what "terminal" means
for that class, and pin that the terminator never takes a lock that is not its
run's to release.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import acquire_lock  # noqa: E402
import agent_lifecycle as lifecycle  # noqa: E402
import terminate_run  # noqa: E402


def _run_dir(tmp_path: Path, *, phase: str = "9", status: str = "started") -> Path:
    """A mid-flight run: assessment started, checkpoint open, lock held.

    `.scan-start-epoch` is the run window every log-reading classifier bounds
    against — without it a `RUN_ABORTED` line could belong to a prior run in
    the same output directory.
    """
    (tmp_path / ".scan-start-epoch").write_text("1786000000\n", encoding="utf-8")
    (tmp_path / ".agent-run.log").write_text(
        "2026-08-15T04:43:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START"
        "   Assessment started  mode=rebuild\n",
        encoding="utf-8",
    )
    (tmp_path / ".appsec-checkpoint").write_text(f"phase={phase} status={status}\n", encoding="utf-8")
    (tmp_path / ".appsec-lock").write_text("999999\n1\n", encoding="utf-8")
    return tmp_path


def _checkpoint(output_dir: Path) -> str:
    return (output_dir / ".appsec-checkpoint").read_text(encoding="utf-8")


def test_interrupt_converges_every_terminal_surface(tmp_path: Path) -> None:
    _run_dir(tmp_path)
    lifecycle.register_call(
        tmp_path,
        {
            "agent_call_id": "toolu_live",
            "session_id": "shared01",
            "agent": "architecture-analyst",
            "agent_type": "appsec-advisor:appsec-architecture-analyst",
            "model": "sonnet",
            "description": "Architecture",
            "background": False,
            "max_turns": 20,
        },
    )

    steps = terminate_run.terminate(tmp_path, "interrupt", "Ctrl-C", "", str(tmp_path))

    assert "RUN_ABORTED recorded" in steps
    assert "checkpoint aborted at phase 9" in steps
    assert "lock released" in steps
    assert not (tmp_path / ".appsec-lock").exists()
    assert "status=aborted" in _checkpoint(tmp_path)
    assert "reason=operator_interrupt" in _checkpoint(tmp_path)
    assert "RUN_ABORTED" in (tmp_path / ".agent-run.log").read_text(encoding="utf-8")

    # Terminal cleanup fails the remaining call and then removes the live
    # directory, so the event log — not the state file — is where the closed
    # call survives.
    assert "AGENT_FAILED" in (tmp_path / ".hook-events.log").read_text(encoding="utf-8")
    assert not lifecycle.state_path(tmp_path).exists()
    assert (tmp_path / ".run-issues.json").is_file()


def test_a_controller_verdict_is_not_relabelled(tmp_path: Path) -> None:
    """The controller already wrote the authoritative reason; the terminator
    still releases the lock, but must not overwrite that verdict."""
    _run_dir(tmp_path)
    with (tmp_path / ".agent-run.log").open("a", encoding="utf-8") as handle:
        handle.write(
            "2026-08-15T04:50:00Z  [--------]  WARN   skill-controller  RUN_ABORTED"
            "   recon output failed its contract\n"
        )

    steps = terminate_run.terminate(tmp_path, "failure", "wrapper exit 1", "", str(tmp_path))

    assert "run already terminal" in steps
    assert "lock released" in steps
    log = (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
    assert log.count("RUN_ABORTED") == 1
    assert "recon output failed its contract" in log


def test_a_completed_checkpoint_is_never_reopened(tmp_path: Path) -> None:
    _run_dir(tmp_path, status="completed")
    steps = terminate_run.terminate(tmp_path, "failure", "artifact gate", "", str(tmp_path))
    assert "checkpoint already terminal" in steps
    assert "status=completed" in _checkpoint(tmp_path)


def test_a_live_foreign_lock_is_left_alone(tmp_path: Path) -> None:
    """Two runs sharing an output directory: releasing a lock whose holder is
    alive would hand both of them the same run state.

    Liveness is the heartbeat, not the PID — under a sandbox the stored PID
    comes from the holder's own namespace and says nothing about this host.
    """
    _run_dir(tmp_path)
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n{int(time.time())}\n", encoding="utf-8")
    steps = terminate_run.terminate(tmp_path, "interrupt", "Ctrl-C", "", str(tmp_path))
    assert "lock held-by-other" in steps
    assert (tmp_path / ".appsec-lock").is_file()


def test_a_foreign_lock_with_a_dead_heartbeat_is_reaped(tmp_path: Path) -> None:
    """A live PID no longer protects a lock whose heartbeat stopped.

    The 2026-08-30 juice-shop2 lock stored PID 10 — the watchdog's sandbox
    namespace PID, unrelated to any host process. Deciding on that number let
    acquisition and release disagree about the same file.
    """
    _run_dir(tmp_path)
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n1\n", encoding="utf-8")
    steps = terminate_run.terminate(tmp_path, "interrupt", "Ctrl-C", "", str(tmp_path))
    assert "lock released" in steps
    assert not (tmp_path / ".appsec-lock").is_file()


def test_our_own_live_lock_is_released_by_run_id(tmp_path: Path) -> None:
    _run_dir(tmp_path)
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n1\nrun-42\n", encoding="utf-8")
    steps = terminate_run.terminate(tmp_path, "interrupt", "Ctrl-C", "run-42", str(tmp_path))
    assert "lock released" in steps


def test_release_lock_reports_each_outcome(tmp_path: Path) -> None:
    lock = tmp_path / ".appsec-lock"
    assert acquire_lock.release_lock(lock) == "absent"
    lock.write_text("999999\n1\n", encoding="utf-8")
    assert acquire_lock.release_lock(lock) == "released"
    # Fresh heartbeat, so the lock is somebody's live run.
    lock.write_text(f"{os.getpid()}\n{int(time.time())}\n", encoding="utf-8")
    assert acquire_lock.release_lock(lock) == "held-by-other"
    assert acquire_lock.release_lock(lock, "other-run") == "held-by-other"
    # Our own live lock is ours to release, by run id.
    lock.write_text(f"{os.getpid()}\n{int(time.time())}\nrun-42\n", encoding="utf-8")
    assert acquire_lock.release_lock(lock, "run-42") == "released"


def test_a_missing_run_directory_is_not_an_error(tmp_path: Path, capsys) -> None:
    assert terminate_run.main(["--output-dir", str(tmp_path / "gone"), "--outcome", "interrupt"]) == 0
    assert "nothing to terminate" in capsys.readouterr().out


def test_cli_reports_each_step(tmp_path: Path, capsys) -> None:
    _run_dir(tmp_path)
    assert terminate_run.main(["--output-dir", str(tmp_path), "--outcome", "failure", "--depth", "quick"]) == 0
    out = capsys.readouterr().out
    assert "RUN_ABORTED recorded" in out
    assert "lock released" in out


def _snapshot(output_dir: Path) -> dict[str, bytes]:
    """Every file under the run directory, by relative path."""
    return {str(p.relative_to(output_dir)): p.read_bytes() for p in sorted(output_dir.rglob("*")) if p.is_file()}


@pytest.mark.parametrize(
    ("third_line", "run_id"),
    [
        # A v3 lock naming a different run — the LOCK_BLOCKED shape.
        ("run-other", "run-mine"),
        # A v2 lock: a live holder we cannot prove is ours.
        ("", "run-mine"),
        # Refused before this run had a lock of its own to name.
        ("run-other", ""),
    ],
)
def test_a_blocked_run_terminates_nothing_in_a_live_foreign_directory(
    tmp_path: Path, third_line: str, run_id: str
) -> None:
    """The failure path must not deliver the collision the lock refused.

    `LOCK_BLOCKED` is a non-clean exit, so the wrapper calls the terminator —
    against a directory that is somebody else's live run. Releasing the lock was
    already guarded; the checkpoint, the in-flight agent markers and the run
    issues were not, so a blocked run aborted the holder's checkpoint and closed
    its running agents as `outer_session_terminal`. The holder's controller then
    read that `RUN_ABORTED` as its own verdict and stopped (2026-09-05,
    insecure-python-app: 43 minutes of Phase 9 lost).

    The rule is scope, not a list of surfaces: nothing in the directory changes.
    """
    _run_dir(tmp_path)
    lock = f"{os.getpid()}\n{int(time.time())}\n" + (f"{third_line}\n" if third_line else "")
    (tmp_path / ".appsec-lock").write_text(lock, encoding="utf-8")
    lifecycle.register_call(
        tmp_path,
        {
            "agent_call_id": "toolu_live",
            "session_id": "6b851f4b",
            "agent": "stride-analyzer-v2",
            "agent_type": "appsec-advisor:appsec-stride-analyzer-v2",
            "model": "sonnet",
            "description": "STRIDE (full): fastapi-app",
            "background": False,
            "max_turns": 40,
        },
    )
    before = _snapshot(tmp_path)

    steps = terminate_run.terminate(tmp_path, "failure", "wrapper exit 1", run_id, str(tmp_path))

    assert "lock held-by-other" in steps
    assert _snapshot(tmp_path) == before
    # The holder's agent is still in flight, so its live state must survive.
    assert lifecycle.state_path(tmp_path).exists()
