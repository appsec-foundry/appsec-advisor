"""Unit tests for scripts/acquire_lock.py — heartbeat + hung-lock detection."""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
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
        "A fresh heartbeat overrides a dead-PID signal — the heartbeat proves the run is progressing."
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


# ---------------------------------------------------------------------------
# M3.2 — HEARTBEAT hook-event emission
# ---------------------------------------------------------------------------
#
# Pre-M3.2 the heartbeat was silent (lock-file-only). External watchers had
# no way to see "the agent is alive" without parsing the lock. Each
# heartbeat now appends a single line to ``$OUTPUT_DIR/.hook-events.log``
# in a format byte-compatible with the lines written by
# ``agent_logger._write`` so downstream parsers (status, aggregator)
# handle it uniformly.


def _hook_log(tmp_path: Path) -> Path:
    return _lock_path(tmp_path).parent / ".hook-events.log"


def test_heartbeat_emits_hook_event_on_success(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 60)
    rc = acquire_lock._do_heartbeat(lp, phase="10b", step="triage")
    assert rc == 0

    log = _hook_log(tmp_path)
    assert log.exists(), "heartbeat must append to .hook-events.log"
    content = log.read_text()
    assert "HEARTBEAT" in content
    assert "phase=10b" in content
    assert "step=triage" in content
    assert "INFO" in content  # success → INFO level
    # Format: ts space "[<sid>]" space level event detail. acquire_lock runs
    # outside the hook context, so the session-id slot carries the canonical
    # no-session sentinel from event_log (eight dashes), e.g. "[--------]".
    line = content.strip().splitlines()[-1]
    assert line.startswith("2026-") or line.startswith("202"), (
        "line must start with UTC timestamp (got: %r)" % line[:10]
    )
    assert "[--------]" in line, "session-id slot must be present and 8-char-padded"


def test_heartbeat_logs_warn_when_lock_absent(tmp_path: Path):
    lp = _lock_path(tmp_path)  # not written
    rc = acquire_lock._do_heartbeat(lp, phase="2")
    assert rc == 0  # non-fatal exit
    log = _hook_log(tmp_path)
    assert log.exists()
    content = log.read_text()
    assert "WARN" in content
    assert "skip=lock_absent" in content
    assert "phase=2" in content


def test_heartbeat_logs_warn_when_lock_malformed(tmp_path: Path):
    lp = _lock_path(tmp_path)
    lp.write_text("not-an-int\n")
    rc = acquire_lock._do_heartbeat(lp, phase="?")
    assert rc == 0
    log = _hook_log(tmp_path)
    content = log.read_text()
    assert "WARN" in content
    assert "skip=lock_malformed" in content


def test_emit_hook_event_swallows_oserror(tmp_path: Path, monkeypatch):
    """Best-effort: the hook-log emit helper must never crash the
    heartbeat caller. We simulate a disk-write failure by making
    builtins.open() raise inside a nested context, then assert the helper
    returns silently."""

    def boom(*_args, **_kwargs):
        raise OSError("simulated disk full")

    monkeypatch.setattr("builtins.open", boom)
    # Must not raise.
    acquire_lock._emit_hook_event(tmp_path, "INFO", "HEARTBEAT", "phase=9")


def test_heartbeat_phase_step_via_main_flag(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 30)
    rc = acquire_lock.main(["acquire_lock.py", str(lp), "--heartbeat", "--phase=11", "--step=compose"])
    assert rc == 0
    log = _hook_log(tmp_path)
    content = log.read_text()
    assert "phase=11" in content
    assert "step=compose" in content


# ---------------------------------------------------------------------------
# Placeholder-phase resolution from the run log (.agent-run.log)
# ---------------------------------------------------------------------------


def _write_run_log(tmp_path: Path, *phase_lines: str) -> None:
    out = _lock_path(tmp_path).parent
    out.mkdir(parents=True, exist_ok=True)
    (out / ".agent-run.log").write_text("\n".join(phase_lines) + "\n")


def _phase_start(num: str, total: str, name: str) -> str:
    return (
        f"2026-06-06T17:21:26Z  [--------]  INFO   threat-analyst"
        f"    PHASE_START   [Phase {num}/{total}] {name} — dispatching…"
    )


def test_bare_heartbeat_phase_derived_from_run_log(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 30)
    _write_run_log(tmp_path, _phase_start("2", "11", "Reconnaissance"))
    acquire_lock._do_heartbeat(lp)  # no explicit phase → defaults to "?"
    content = _hook_log(tmp_path).read_text()
    assert "phase=2/11" in content
    assert "phase=?" not in content


def test_watchdog_skill_phase_overridden_by_real_phase(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 30)
    _write_run_log(tmp_path, _phase_start("9", "11", "STRIDE Threat Enumeration"))
    acquire_lock._do_heartbeat(lp, phase="skill", step="watchdog")
    content = _hook_log(tmp_path).read_text()
    assert "phase=9/11" in content
    assert "phase=skill" not in content
    assert "step=watchdog" in content  # the watchdog tag is preserved


def test_explicit_phase_is_not_overridden(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 30)
    _write_run_log(tmp_path, _phase_start("2", "11", "Reconnaissance"))
    acquire_lock._do_heartbeat(lp, phase="10b", step="triage")
    content = _hook_log(tmp_path).read_text()
    assert "phase=10b" in content
    assert "phase=2/11" not in content


def test_phase_derivation_picks_latest_phase_start(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 30)
    _write_run_log(
        tmp_path,
        _phase_start("1", "11", "Context Resolution"),
        _phase_start("2", "11", "Reconnaissance"),
        _phase_start("3", "11", "Architecture Modeling"),
    )
    acquire_lock._do_heartbeat(lp)
    assert "phase=3/11" in _hook_log(tmp_path).read_text()


def test_placeholder_kept_when_no_phase_resolvable(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 30)
    # No .agent-run.log, no checkpoint → honest "?" (run hasn't entered a phase).
    acquire_lock._do_heartbeat(lp)
    assert "phase=?" in _hook_log(tmp_path).read_text()


def test_phase_falls_back_to_checkpoint(tmp_path: Path):
    lp = _lock_path(tmp_path)
    acquire_lock._write_lock(lp, os.getpid(), int(time.time()) - 30)
    # No PHASE_START in the run log, but a checkpoint carries the phase.
    (lp.parent / ".appsec-checkpoint").write_text("phase=10b step=2 status=running")
    acquire_lock._do_heartbeat(lp, phase="skill")
    assert "phase=10b" in _hook_log(tmp_path).read_text()
