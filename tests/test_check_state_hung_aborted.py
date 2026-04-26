"""Unit tests for scripts/check_state.py — new hung/aborted states + resume-guard."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path


REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_state.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_state", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_state"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


check_state = _load()


# ---------------------------------------------------------------------------
# v2 lock parsing
# ---------------------------------------------------------------------------


def test_reads_v2_lock_with_heartbeat(tmp_path: Path):
    lp = tmp_path / ".appsec-lock"
    ts = int(time.time())
    lp.write_text(f"{os.getpid()}\n{ts}\n")
    info = check_state._read_lock(tmp_path)
    assert info is not None
    assert info["pid"] == os.getpid()
    assert info["heartbeat"] == ts
    assert info["heartbeat_age"] is not None


def test_reads_v1_lock_with_none_heartbeat(tmp_path: Path):
    lp = tmp_path / ".appsec-lock"
    lp.write_text(f"{os.getpid()}\n")
    info = check_state._read_lock(tmp_path)
    assert info is not None
    assert info["heartbeat"] is None
    assert info["heartbeat_age"] is None


# ---------------------------------------------------------------------------
# Hung lock detection
# ---------------------------------------------------------------------------


def test_live_pid_fresh_heartbeat_is_active(tmp_path: Path):
    lp = tmp_path / ".appsec-lock"
    lp.write_text(f"{os.getpid()}\n{int(time.time())}\n")
    rep = check_state.classify(tmp_path)
    assert rep["state"] == "active"


def test_live_pid_stale_heartbeat_is_stale_with_hung_reason(tmp_path: Path):
    lp = tmp_path / ".appsec-lock"
    lp.write_text(f"{os.getpid()}\n{int(time.time()) - 600}\n")
    rep = check_state.classify(tmp_path)
    assert rep["state"] == "stale"
    assert any("hung" in r.lower() for r in rep["reasons"])


def test_hung_lock_is_cleaned(tmp_path: Path):
    lp = tmp_path / ".appsec-lock"
    lp.write_text(f"{os.getpid()}\n{int(time.time()) - 600}\n")
    result = check_state.clean(tmp_path)
    assert not result["skipped"]
    assert ".appsec-lock" in result["removed"]
    assert not lp.exists()


# ---------------------------------------------------------------------------
# Aborted checkpoint
# ---------------------------------------------------------------------------


def test_aborted_checkpoint_is_orphaned(tmp_path: Path):
    (tmp_path / ".appsec-checkpoint").write_text(
        "phase=7 status=aborted reason=max_turns aborted_at=2026-04-24T12:00:00Z\n"
    )
    rep = check_state.classify(tmp_path)
    assert rep["state"] == "orphaned"
    assert any("aborted" in r for r in rep["reasons"])


def test_aborted_checkpoint_is_cleaned(tmp_path: Path):
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=3 status=aborted reason=unknown\n")
    result = check_state.clean(tmp_path)
    assert ".appsec-checkpoint" in result["removed"]
    assert not cp.exists()


# ---------------------------------------------------------------------------
# Resume guard
# ---------------------------------------------------------------------------


def test_resume_guard_allows_fresh_checkpoint(tmp_path: Path):
    (tmp_path / ".appsec-checkpoint").write_text("phase=5 status=started\n")
    code, msg = check_state._resume_guard_result(tmp_path, 900)
    assert code == 0


def test_resume_guard_allows_completed_checkpoint(tmp_path: Path):
    (tmp_path / ".appsec-checkpoint").write_text("phase=11 status=completed\n")
    code, msg = check_state._resume_guard_result(tmp_path, 900)
    assert code == 0


def test_resume_guard_allows_missing_checkpoint(tmp_path: Path):
    code, msg = check_state._resume_guard_result(tmp_path, 900)
    assert code == 0


def test_resume_guard_refuses_stale_started(tmp_path: Path):
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=5 status=started\n")
    old = time.time() - 1200  # > 15 min
    os.utime(cp, (old, old))
    code, msg = check_state._resume_guard_result(tmp_path, 900)
    assert code == 3
    assert "Refusing" in msg


def test_resume_guard_refuses_stale_aborted(tmp_path: Path):
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=7 status=aborted reason=unknown\n")
    old = time.time() - 1200
    os.utime(cp, (old, old))
    code, msg = check_state._resume_guard_result(tmp_path, 900)
    assert code == 3


def test_resume_guard_cli_writes_json(tmp_path: Path, capsys):
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=5 status=started\n")
    old = time.time() - 1200
    os.utime(cp, (old, old))
    code = check_state.main([str(tmp_path), "--resume-guard", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["allow"] is False
    assert payload["exit_code"] == 3
    assert code == 3


def test_resume_guard_cli_exit_0_when_allowed(tmp_path: Path, capsys):
    (tmp_path / ".appsec-checkpoint").write_text("phase=11 status=completed\n")
    code = check_state.main([str(tmp_path), "--resume-guard"])
    assert code == 0


def test_resume_guard_configurable_max_age(tmp_path: Path):
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=3 status=started\n")
    old = time.time() - 300  # 5 min
    os.utime(cp, (old, old))
    # With default 900 s window → allowed
    code, _ = check_state._resume_guard_result(tmp_path, 900)
    assert code == 0
    # With tight 120 s window → refused
    code, _ = check_state._resume_guard_result(tmp_path, 120)
    assert code == 3


# ---------------------------------------------------------------------------
# Resume guard — dead-PID override
#
# The 15-min checkpoint-age threshold guards against racing with a possibly-
# still-running orchestrator. When the lock proves the prior process is dead
# (PID gone AND heartbeat stale), the race is impossible and resume becomes
# safe regardless of checkpoint age.
# ---------------------------------------------------------------------------


def _pick_dead_pid() -> int:
    """Return a PID that is reliably not alive on this system."""
    candidate = 999999
    for _ in range(20):
        try:
            os.kill(candidate, 0)
        except ProcessLookupError:
            return candidate
        except PermissionError:
            pass
        candidate += 1
    raise RuntimeError("could not find a dead PID for the test")


def test_resume_guard_allows_stale_checkpoint_when_lock_proves_dead(tmp_path: Path):
    """Stale checkpoint + dead PID + stale heartbeat → resume allowed."""
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=3 status=started\n")
    old_cp = time.time() - 7200  # 2 h — well past 15 min
    os.utime(cp, (old_cp, old_cp))

    dead_pid = _pick_dead_pid()
    lock = tmp_path / ".appsec-lock"
    lock.write_text(f"{dead_pid}\n{int(time.time()) - 3600}\n")  # heartbeat 1 h old

    code, msg = check_state._resume_guard_result(tmp_path, 900)
    assert code == 0
    assert "dead" in msg.lower()


def test_resume_guard_still_refuses_stale_checkpoint_when_lock_pid_alive(tmp_path: Path):
    """Stale checkpoint + alive PID → keep refusing (race still possible)."""
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=3 status=started\n")
    old_cp = time.time() - 7200
    os.utime(cp, (old_cp, old_cp))

    # Use our own PID — guaranteed alive — with a stale heartbeat. Together
    # with the stale checkpoint this is the "hung but technically still running"
    # case where we must not auto-allow resume.
    lock = tmp_path / ".appsec-lock"
    lock.write_text(f"{os.getpid()}\n{int(time.time()) - 3600}\n")

    code, msg = check_state._resume_guard_result(tmp_path, 900)
    assert code == 3
    assert "Refusing" in msg


def test_resume_guard_dead_pid_v1_lock_without_heartbeat(tmp_path: Path):
    """Legacy v1 lock (PID-only, no heartbeat) + dead PID + stale checkpoint
    → resume allowed (heartbeat absence is not a blocker when PID is dead)."""
    cp = tmp_path / ".appsec-checkpoint"
    cp.write_text("phase=5 status=started\n")
    old_cp = time.time() - 7200
    os.utime(cp, (old_cp, old_cp))

    dead_pid = _pick_dead_pid()
    lock = tmp_path / ".appsec-lock"
    lock.write_text(f"{dead_pid}\n")  # v1: PID only, no heartbeat line

    code, msg = check_state._resume_guard_result(tmp_path, 900)
    assert code == 0
    assert "dead" in msg.lower()
