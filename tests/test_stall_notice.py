from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "stall_notice.py"


def _run(*args: str):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )


def test_banner_to_stderr_and_log(tmp_path):
    r = _run(str(tmp_path), "--stage", "Stage 1 — Threat Analysis", "--phase", "Phase 1 (recon)")
    assert r.returncode == 0
    # User-facing reassurance is on stderr, framed as retry-not-defect.
    assert "AUTOMATIC RETRY" in r.stderr
    assert "not a plugin error" in r.stderr
    assert "Stage 1 — Threat Analysis" in r.stderr
    assert "Phase 1 (recon)" in r.stderr
    # Canonical forensic line is appended to the run log.
    log = (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
    assert "STALL_RECOVERY" in log
    assert "auto-retry" in log


def test_attempt_counter_rendered(tmp_path):
    r = _run(str(tmp_path), "--stage", "Stage 2", "--attempt", "1", "--max", "1")
    assert r.returncode == 0
    assert "attempt 1/1" in r.stderr


def test_nothing_on_stdout(tmp_path):
    # stdout must stay empty so the caller never captures banner text.
    r = _run(str(tmp_path), "--stage", "Stage 1")
    assert r.stdout == ""
