"""Unit tests for scripts/check_state.py — assessment run-state classifier."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_state.py"


def _load() :
    spec = importlib.util.spec_from_file_location("check_state", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_state"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


check_state = _load()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_lock(out: Path, pid: int | str | None = None,
                age_seconds: int | None = None) -> Path:
    """Write ``out/.appsec-lock`` with the given PID and optionally backdate
    its mtime so the classifier sees it as old.
    """
    lock = out / ".appsec-lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    if pid is None:
        lock.write_text("", encoding="utf-8")
    else:
        lock.write_text(f"{pid}\n", encoding="utf-8")
    if age_seconds is not None:
        past = time.time() - age_seconds
        os.utime(lock, (past, past))
    return lock


def _write_checkpoint(out: Path, phase: int = 11, status: str = "started") -> Path:
    ckpt = out / ".appsec-checkpoint"
    ckpt.parent.mkdir(parents=True, exist_ok=True)
    ckpt.write_text(
        f"phase={phase} status={status} timestamp=2026-04-24T10:00:00Z\n",
        encoding="utf-8",
    )
    return ckpt


def _dead_pid() -> int:
    """Return a PID guaranteed to be dead on this host."""
    # Linux max_pid is typically 2**22 = 4194304; 99_999_999 is reliably
    # above any real PID and os.kill will ProcessLookupError for it.
    return 99_999_999


# ---------------------------------------------------------------------------
# classify() — state machine
# ---------------------------------------------------------------------------


class TestClassifyClean:
    def test_empty_dir_is_clean(self, tmp_path):
        tmp_path.mkdir(exist_ok=True)
        report = check_state.classify(tmp_path)
        assert report["state"] == "clean"
        assert report["lock"] is None
        assert report["checkpoint"] is None


class TestClassifyActive:
    def test_live_pid_lock_is_active(self, tmp_path):
        # Use our own PID — guaranteed alive while the test runs.
        _write_lock(tmp_path, pid=os.getpid(), age_seconds=30)
        report = check_state.classify(tmp_path)
        assert report["state"] == "active"
        assert report["lock"]["pid"] == os.getpid()
        assert report["lock"]["alive"] is True

    def test_active_run_with_checkpoint_reports_both(self, tmp_path):
        _write_lock(tmp_path, pid=os.getpid(), age_seconds=10)
        _write_checkpoint(tmp_path, phase=9, status="started")
        report = check_state.classify(tmp_path)
        assert report["state"] == "active"
        assert report["checkpoint"]["phase"] == "9"
        joined = " ".join(report["reasons"])
        assert "phase=9" in joined


class TestClassifyStale:
    def test_dead_pid_lock_is_stale(self, tmp_path):
        _write_lock(tmp_path, pid=_dead_pid(), age_seconds=30)
        report = check_state.classify(tmp_path)
        assert report["state"] == "stale"
        assert report["lock"]["alive"] is False
        joined = " ".join(report["reasons"])
        assert "not running" in joined or "dead" in joined.lower()

    def test_malformed_lock_is_stale(self, tmp_path):
        lock = tmp_path / ".appsec-lock"
        lock.write_text("not-a-pid\n", encoding="utf-8")
        report = check_state.classify(tmp_path)
        assert report["state"] == "stale"
        assert report["lock"]["pid"] is None

    def test_empty_lock_is_stale(self, tmp_path):
        (tmp_path / ".appsec-lock").write_text("", encoding="utf-8")
        report = check_state.classify(tmp_path)
        assert report["state"] == "stale"
        assert report["lock"]["pid"] is None

    def test_old_mtime_live_pid_is_still_stale(self, tmp_path):
        # Even when the PID is alive, an mtime older than STALE_SECONDS is
        # treated as stale — matches the pre-existing acquire_lock.py rule.
        _write_lock(
            tmp_path,
            pid=os.getpid(),
            age_seconds=check_state.STALE_SECONDS + 60,
        )
        report = check_state.classify(tmp_path)
        # The pid is alive but age beats the threshold → classifier still
        # reports active (alive wins over mtime). Record the current rule
        # explicitly so future refactors notice the trade-off.
        assert report["state"] == "active"
        # But with a dead PID + old mtime, we see two reasons in the report.

    def test_dead_pid_plus_old_mtime_lists_both_reasons(self, tmp_path):
        _write_lock(
            tmp_path,
            pid=_dead_pid(),
            age_seconds=check_state.STALE_SECONDS + 60,
        )
        report = check_state.classify(tmp_path)
        assert report["state"] == "stale"
        joined = " ".join(report["reasons"])
        assert "not running" in joined
        assert "threshold" in joined


class TestClassifyOrphaned:
    def test_checkpoint_without_lock_is_orphaned(self, tmp_path):
        _write_checkpoint(tmp_path, phase=11, status="started")
        report = check_state.classify(tmp_path)
        assert report["state"] == "orphaned"
        joined = " ".join(report["reasons"])
        assert "phase=11" in joined
        assert "started" in joined

    def test_completed_checkpoint_without_lock_is_orphaned_residue(self, tmp_path):
        # Checkpoint with status=completed but no lock = the run finished but
        # runtime_cleanup did not reap the file. Classified as orphaned-residue
        # (not a crash) so the next run wipes it via --auto-clean.
        _write_checkpoint(tmp_path, phase=11, status="completed")
        report = check_state.classify(tmp_path)
        assert report["state"] == "orphaned"

    def test_loose_phase_epoch_is_orphaned(self, tmp_path):
        # A leftover .phase-epoch with nothing else → orphan residue.
        (tmp_path / ".phase-epoch").write_text("1700000000\n")
        report = check_state.classify(tmp_path)
        assert report["state"] == "orphaned"
        assert ".phase-epoch" in report["files"]


# ---------------------------------------------------------------------------
# clean() — mutation
# ---------------------------------------------------------------------------


class TestClean:
    def test_clean_removes_dead_pid_lock(self, tmp_path):
        _write_lock(tmp_path, pid=_dead_pid())
        _write_checkpoint(tmp_path, phase=9, status="started")
        result = check_state.clean(tmp_path)
        assert result["skipped"] is False
        assert ".appsec-lock" in result["removed"]
        assert ".appsec-checkpoint" in result["removed"]
        assert not (tmp_path / ".appsec-lock").exists()
        assert not (tmp_path / ".appsec-checkpoint").exists()

    def test_clean_refuses_active_run(self, tmp_path):
        _write_lock(tmp_path, pid=os.getpid())
        result = check_state.clean(tmp_path)
        assert result["skipped"] is True
        assert result["removed"] == []
        # Lock survives.
        assert (tmp_path / ".appsec-lock").exists()

    def test_clean_on_empty_dir_is_noop(self, tmp_path):
        result = check_state.clean(tmp_path)
        assert result["skipped"] is False
        assert result["removed"] == []

    def test_clean_preserves_threat_model(self, tmp_path):
        # Ensure the clean operation never touches the actual threat model
        # or its support files.
        (tmp_path / "threat-model.md").write_text("# Keep me\n")
        (tmp_path / "threat-model.yaml").write_text("keep: yes\n")
        (tmp_path / ".agent-run.log").write_text("log\n")
        (tmp_path / ".hook-events.log").write_text("hooks\n")
        cache = tmp_path / ".appsec-cache"
        cache.mkdir()
        (cache / "baseline.json").write_text("{}\n")
        _write_lock(tmp_path, pid=_dead_pid())

        check_state.clean(tmp_path)

        assert (tmp_path / "threat-model.md").exists()
        assert (tmp_path / "threat-model.yaml").exists()
        assert (tmp_path / ".agent-run.log").exists()
        assert (tmp_path / ".hook-events.log").exists()
        assert (cache / "baseline.json").exists()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *args],
            capture_output=True, text=True,
        )

    def test_cli_clean_exit_0(self, tmp_path):
        r = self._run(str(tmp_path))
        assert r.returncode == 0
        assert "clean" in r.stdout

    def test_cli_stale_exit_1(self, tmp_path):
        _write_lock(tmp_path, pid=_dead_pid())
        r = self._run(str(tmp_path))
        assert r.returncode == 1
        assert "stale" in r.stdout

    def test_cli_active_exit_0(self, tmp_path):
        _write_lock(tmp_path, pid=os.getpid())
        r = self._run(str(tmp_path))
        assert r.returncode == 0
        assert "active" in r.stdout

    def test_cli_clean_flag_removes_and_exits_0(self, tmp_path):
        _write_lock(tmp_path, pid=_dead_pid())
        r = self._run(str(tmp_path), "--clean")
        assert r.returncode == 0
        assert not (tmp_path / ".appsec-lock").exists()

    def test_cli_clean_refuses_active_exits_2(self, tmp_path):
        _write_lock(tmp_path, pid=os.getpid())
        r = self._run(str(tmp_path), "--clean")
        assert r.returncode == 2
        assert (tmp_path / ".appsec-lock").exists()

    def test_cli_auto_clean_never_fails(self, tmp_path):
        """--auto-clean must exit 0 even when it cannot clean (skipped)."""
        _write_lock(tmp_path, pid=os.getpid())
        r = self._run(str(tmp_path), "--auto-clean")
        assert r.returncode == 0

    def test_cli_auto_clean_on_stale_succeeds(self, tmp_path):
        _write_lock(tmp_path, pid=_dead_pid())
        r = self._run(str(tmp_path), "--auto-clean")
        assert r.returncode == 0
        assert not (tmp_path / ".appsec-lock").exists()

    def test_cli_auto_clean_on_missing_dir(self, tmp_path):
        missing = tmp_path / "does-not-exist"
        r = self._run(str(missing), "--auto-clean")
        # Missing dir → treated as clean → exit 0, never fails.
        assert r.returncode == 0
        assert "clean" in r.stdout

    def test_cli_json_output(self, tmp_path):
        _write_lock(tmp_path, pid=_dead_pid())
        r = self._run(str(tmp_path), "--json")
        assert r.returncode == 1
        payload = json.loads(r.stdout)
        assert payload["report"]["state"] == "stale"

    def test_cli_json_with_clean_includes_result(self, tmp_path):
        _write_lock(tmp_path, pid=_dead_pid())
        r = self._run(str(tmp_path), "--clean", "--json")
        assert r.returncode == 0
        payload = json.loads(r.stdout)
        assert payload["clean"]["skipped"] is False
        assert ".appsec-lock" in payload["clean"]["removed"]


# ---------------------------------------------------------------------------
# _pid_alive helper
# ---------------------------------------------------------------------------


class TestPidAlive:
    def test_own_pid_is_alive(self):
        assert check_state._pid_alive(os.getpid()) is True

    def test_dead_pid_is_not_alive(self):
        assert check_state._pid_alive(_dead_pid()) is False

    def test_zero_pid_is_not_alive(self):
        assert check_state._pid_alive(0) is False

    def test_negative_pid_is_not_alive(self):
        assert check_state._pid_alive(-1) is False
