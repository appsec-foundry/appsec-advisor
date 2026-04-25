"""Unit tests for scripts/acquire_lock.py — heartbeat + hung-lock detection."""
from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest


REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "acquire_lock.py"


def _load():
    spec = importlib.util.spec_from_file_location("acquire_lock", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["acquire_lock"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


acquire_lock = _load()


# ---------------------------------------------------------------------------
# Lock classification
# ---------------------------------------------------------------------------


def _lock_path(tmp_path: Path) -> Path:
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True, exist_ok=True)
    return out / ".appsec-lock"


def test_absent_lock_classifies_absent(tmp_path: Path):
    state, _ = acquire_lock._classify_lock(_lock_path(tmp_path))
    assert state == "absent"


def test_fresh_heartbeat_classifies_fresh(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()))
    state, info = acquire_lock._classify_lock(lp)
    assert state == "fresh"
    assert info["pid"] == os.getpid()


def test_stale_heartbeat_classifies_hung(tmp_path: Path):
    """Live PID + heartbeat older than HEARTBEAT_STALE_SECONDS → hung."""
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 600)
    state, info = acquire_lock._classify_lock(lp)
    assert state == "hung"
    assert info["heartbeat_age"] >= 600


def test_dead_pid_classifies_dead(tmp_path: Path):
    """Dead PID classifies as 'dead' only when the heartbeat is also stale.

    A fresh heartbeat is authoritative — the stored PID is an ephemeral
    Python-subprocess PID that is usually dead shortly after acquisition
    (every orchestrator Bash turn writes a different ephemeral PID into
    the lock). Freshness is proof that someone is still refreshing the
    heartbeat, so the lock is alive regardless of the stored PID.
    """
    lp = _lock_path(tmp_path)
    # Fresh heartbeat but dead PID → 'fresh' (someone is actively refreshing).
    acquire_lock._write_lock(lp, 99_999_999, int(time.time()))
    state, _ = acquire_lock._classify_lock(lp)
    assert state == "fresh", (
        "A fresh heartbeat overrides a dead-PID signal — the heartbeat proves "
        "the run is progressing."
    )
    # Stale heartbeat AND dead PID → 'dead' (no one is refreshing; process gone).
    acquire_lock._write_lock(lp, 99_999_999, int(time.time()) - 600)
    state, _ = acquire_lock._classify_lock(lp)
    assert state == "dead"


def test_v1_lock_fresh_mtime_classifies_fresh(tmp_path: Path):
    """Legacy PID-only lock with a recent mtime is still 'fresh'."""
    lp = _lock_path(tmp_path)
    lp.write_text(f"{os.getpid()}\n")
    state, _ = acquire_lock._classify_lock(lp)
    assert state == "fresh"


def test_v1_lock_stale_mtime_classifies_stale_mtime(tmp_path: Path):
    lp = _lock_path(tmp_path)
    lp.write_text(f"{os.getpid()}\n")
    old = time.time() - 4000  # > 1 h
    os.utime(lp, (old, old))
    state, _ = acquire_lock._classify_lock(lp)
    assert state == "stale_mtime"


def test_malformed_lock_classifies_malformed(tmp_path: Path):
    lp = _lock_path(tmp_path)
    lp.write_text("garbage text no pid")
    state, _ = acquire_lock._classify_lock(lp)
    assert state == "malformed"


# ---------------------------------------------------------------------------
# Heartbeat refresh
# ---------------------------------------------------------------------------


def test_heartbeat_refreshes_existing_lock(tmp_path: Path):
    lp = _lock_path(tmp_path)
    original_ts = int(time.time()) - 60
    acquire_lock._write_lock(lp, os.getpid(), original_ts)
    time.sleep(1.1)
    rc = acquire_lock._do_heartbeat(lp)
    assert rc == 0
    _, hb = acquire_lock._parse_lock(lp)
    assert hb is not None
    assert hb > original_ts


def test_heartbeat_on_absent_lock_is_noop(tmp_path: Path):
    lp = _lock_path(tmp_path)
    rc = acquire_lock._do_heartbeat(lp)
    assert rc == 0
    assert not lp.exists()


def test_heartbeat_skips_other_process_lock(tmp_path: Path):
    """Heartbeat refuses to overwrite a lock held by a different PID."""
    lp = _lock_path(tmp_path)
    other_pid = (os.getpid() + 1) % 65535 or 1  # definitely not us
    ts = int(time.time())
    acquire_lock._write_lock(lp, other_pid, ts)
    rc = acquire_lock._do_heartbeat(lp)
    assert rc == 0
    pid, hb = acquire_lock._parse_lock(lp)
    assert pid == other_pid, "other process's PID was overwritten"
    assert hb == ts, "other process's heartbeat was overwritten"


# ---------------------------------------------------------------------------
# End-to-end acquire flow
# ---------------------------------------------------------------------------


def test_acquire_after_hung_lock_reaps_it(tmp_path: Path, capsys):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 600)
    # Call main() — it should detect hung and overwrite.
    rc = acquire_lock.main(["acquire_lock.py", str(lp)])
    assert rc == 0
    _, hb = acquire_lock._parse_lock(lp)
    assert hb is not None
    # Heartbeat is now fresh
    assert int(time.time()) - hb < 5


def test_acquire_blocks_on_fresh_lock(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()))
    rc = acquire_lock.main(["acquire_lock.py", str(lp)])
    assert rc == 1
