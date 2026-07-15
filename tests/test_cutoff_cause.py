from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cutoff_cause.py"


def _run(output_dir: Path, *args: str):
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(output_dir), *args],
        capture_output=True,
        text=True,
    )


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stall_line(epoch: int) -> str:
    return (
        f"{_iso(epoch)}  [--------]  WARN   skill               STALL_RECOVERY"
        "      stage=Stage 1 — API stream stall caught by watchdog; auto-retry\n"
    )


def _write_run(tmp_path: Path, *, start: int | None, log: str) -> Path:
    if start is not None:
        (tmp_path / ".scan-start-epoch").write_text(f"{start}\n", encoding="utf-8")
    (tmp_path / ".agent-run.log").write_text(log, encoding="utf-8")
    return tmp_path


def test_in_window_stall_yields_api_cause(tmp_path):
    _write_run(tmp_path, start=1_000_000_000, log=_stall_line(1_000_000_500))
    r = _run(tmp_path, "--default", "session_death")
    assert r.returncode == 0
    assert "model API response stream stalled" in r.stdout
    assert "server-side API" in r.stdout
    # An in-window stall MUST win over the default, whatever the default is.
    r2 = _run(tmp_path, "--default", "budget")
    assert "model API response stream stalled" in r2.stdout


def test_no_stall_uses_default_session_death(tmp_path):
    _write_run(tmp_path, start=1_000_000_000, log="")
    r = _run(tmp_path, "--default", "session_death")
    assert "parent Claude Code session ended" in r.stdout
    assert "model API response stream stalled" not in r.stdout


def test_no_stall_default_budget(tmp_path):
    _write_run(tmp_path, start=1_000_000_000, log="")
    r = _run(tmp_path, "--default", "budget")
    assert "per-session turn budget" in r.stdout


def test_stale_prior_run_stall_ignored(tmp_path):
    # STALL_RECOVERY from BEFORE this run's start window must not be attributed.
    _write_run(tmp_path, start=1_000_000_000, log=_stall_line(999_999_000))
    r = _run(tmp_path, "--default", "session_death")
    assert "parent Claude Code session ended" in r.stdout
    assert "model API response stream stalled" not in r.stdout


def test_missing_start_epoch_is_conservative(tmp_path):
    # No run window to bound against ⇒ do NOT claim a stall; use the default.
    _write_run(tmp_path, start=None, log=_stall_line(1_000_000_500))
    r = _run(tmp_path, "--default", "session_death")
    assert "parent Claude Code session ended" in r.stdout


def test_missing_log_falls_back_to_default(tmp_path):
    r = _run(tmp_path / "does-not-exist", "--default", "session_death")
    assert r.returncode == 0
    assert "parent Claude Code session ended" in r.stdout


def _import_cutoff_cause():
    import importlib.util

    spec = importlib.util.spec_from_file_location("cutoff_cause", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cause_for_returns_kind_and_block(tmp_path):
    mod = _import_cutoff_cause()
    _write_run(tmp_path, start=1_000_000_000, log=_stall_line(1_000_000_500))
    kind, block = mod.cause_for(tmp_path, "session_death")
    assert kind == "api_stall"
    assert "model API response stream stalled" in block


def test_cause_for_default_when_no_stall(tmp_path):
    mod = _import_cutoff_cause()
    _write_run(tmp_path, start=1_000_000_000, log="")
    assert mod.cause_for(tmp_path, "session_death")[0] == "session_death"
    assert mod.cause_for(tmp_path, "budget")[0] == "budget"
