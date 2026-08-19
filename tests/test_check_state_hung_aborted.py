"""Hung-lock and aborted-checkpoint tests for scripts/check_state.py."""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_state.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_state", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_state"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


check_state = _load()


def test_reads_v2_lock_with_heartbeat(tmp_path: Path):
    lock = tmp_path / ".appsec-lock"
    timestamp = int(time.time())
    lock.write_text(f"{os.getpid()}\n{timestamp}\n")
    info = check_state._read_lock(tmp_path)
    assert info is not None
    assert info["pid"] == os.getpid()
    assert info["heartbeat"] == timestamp
    assert info["heartbeat_age"] is not None


def test_reads_v1_lock_with_none_heartbeat(tmp_path: Path):
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n")
    info = check_state._read_lock(tmp_path)
    assert info is not None
    assert info["heartbeat"] is None
    assert info["heartbeat_age"] is None


def test_live_pid_fresh_heartbeat_is_active(tmp_path: Path):
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n{int(time.time())}\n")
    assert check_state.classify(tmp_path)["state"] == "active"


def test_live_pid_stale_heartbeat_is_stale_with_hung_reason(tmp_path: Path):
    (tmp_path / ".appsec-lock").write_text(f"{os.getpid()}\n{int(time.time()) - 600}\n")
    report = check_state.classify(tmp_path)
    assert report["state"] == "stale"
    assert any("hung" in reason.lower() for reason in report["reasons"])


def test_hung_lock_is_cleaned(tmp_path: Path):
    lock = tmp_path / ".appsec-lock"
    lock.write_text(f"{os.getpid()}\n{int(time.time()) - 600}\n")
    result = check_state.clean(tmp_path)
    assert not result["skipped"]
    assert ".appsec-lock" in result["removed"]
    assert not lock.exists()


def test_aborted_checkpoint_is_orphaned_and_cleaned(tmp_path: Path):
    checkpoint = tmp_path / ".appsec-checkpoint"
    checkpoint.write_text("phase=7 status=aborted reason=max_turns\n")
    report = check_state.classify(tmp_path)
    assert report["state"] == "orphaned"
    assert any("aborted" in reason for reason in report["reasons"])
    result = check_state.clean(tmp_path, report)
    assert ".appsec-checkpoint" in result["removed"]
    assert not checkpoint.exists()
