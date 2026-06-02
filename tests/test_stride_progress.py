"""
Tests for stride_progress.py — progress line dedup, heartbeat cadence,
and TTY-aware marker fallback.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PLUGIN_SCRIPTS = Path(__file__).parent.parent / "scripts"


def _run(
    output_dir: Path, expected: int, force: bool = False, env_extra: dict | None = None
) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PLUGIN_SCRIPTS / "stride_progress.py"), str(output_dir), str(expected)]
    if force:
        cmd.append("--force")
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(PLUGIN_SCRIPTS)}
    if env_extra:
        env.update(env_extra)
    # Ensure stderr is not a tty so ASCII fallback is exercised
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def _write_progress(output_dir: Path, cid: str, name: str, step: int, total: int, label: str) -> None:
    d = output_dir / ".progress"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{cid}.json").write_text(
        json.dumps(
            {
                "component_id": cid,
                "component_name": name,
                "step": step,
                "total": total,
                "label": label,
            }
        )
    )


def test_first_call_prints_line(tmp_path):
    _write_progress(tmp_path, "auth", "Auth Service", 3, 9, "Tampering")
    res = _run(tmp_path, expected=2)
    assert res.returncode == 1  # not ready yet
    assert "[stride] 0/2 ready" in res.stdout
    assert "Auth Service" in res.stdout


def test_identical_state_dedups_second_call(tmp_path):
    _write_progress(tmp_path, "auth", "Auth Service", 3, 9, "Tampering")
    first = _run(tmp_path, expected=2)
    second = _run(tmp_path, expected=2)
    assert first.stdout.strip(), "first call must emit"
    assert second.stdout.strip() == "", "second identical call must be silent"


def test_state_change_reprints(tmp_path):
    _write_progress(tmp_path, "auth", "Auth Service", 3, 9, "Tampering")
    _run(tmp_path, expected=2)  # prime state
    _write_progress(tmp_path, "auth", "Auth Service", 4, 9, "Repudiation")
    res = _run(tmp_path, expected=2)
    assert "Repudiation" in res.stdout


def test_force_bypasses_dedup(tmp_path):
    _write_progress(tmp_path, "auth", "Auth Service", 3, 9, "Tampering")
    _run(tmp_path, expected=2)
    res = _run(tmp_path, expected=2, force=True)
    assert res.stdout.strip(), "--force must always emit"


def test_heartbeat_after_unchanged_ticks(tmp_path):
    _write_progress(tmp_path, "auth", "Auth Service", 3, 9, "Tampering")
    # 1st emits, next HEARTBEAT_TICKS (6) are silent, then 7th re-emits as heartbeat
    outputs = [_run(tmp_path, expected=2).stdout.strip() for _ in range(8)]
    first = outputs[0]
    silent_runs = outputs[1:7]  # calls 2..7 should be silent
    heartbeat = outputs[7]  # call 8 = 7th unchanged → heartbeat threshold
    assert first
    assert all(not s for s in silent_runs), f"expected silence, got {silent_runs}"
    assert heartbeat, "heartbeat did not reprint after HEARTBEAT_TICKS unchanged polls"


def test_ascii_fallback_on_non_tty(tmp_path):
    # subprocess.run pipes stderr → not a tty → markers must be ASCII
    (tmp_path / ".stride-auth.json").write_text("{}")
    _write_progress(tmp_path, "auth", "Auth Service", 9, 9, "done")
    res = _run(tmp_path, expected=1)
    # The done marker for a completed component must fall back to "[done]"
    assert "[done]" in res.stdout or "Auth Service ✓" not in res.stdout
    # No unicode chars expected in non-tty output
    assert "✓" not in res.stdout
    assert "⧗" not in res.stdout


def test_completion_exits_zero(tmp_path):
    (tmp_path / ".stride-auth.json").write_text("{}")
    _write_progress(tmp_path, "auth", "Auth Service", 9, 9, "done")
    res = _run(tmp_path, expected=1)
    assert res.returncode == 0


def test_bridges_into_appsec_progress_json(tmp_path):
    # When a line is emitted, the collapsed state must be mirrored into
    # .appsec-progress.json so the streaming watcher (watch_run.py) shows it.
    _write_progress(tmp_path, "auth", "Auth Service", 4, 9, "Tampering")
    _run(tmp_path, expected=2)
    bridged = tmp_path / ".appsec-progress.json"
    assert bridged.is_file(), ".appsec-progress.json must be written on emit"
    data = json.loads(bridged.read_text())
    assert data["phase"] == "9"
    assert data["phase_total"] == "11"
    assert data["step"] == 0  # 0 of 2 .stride-*.json ready
    assert data["step_total"] == 2
    assert data["agent"] == "stride-analyzer"
    assert "Auth Service" in data["label"]
    assert data["status"] == "step_started"


def test_bridge_marks_completed_when_ready(tmp_path):
    (tmp_path / ".stride-auth.json").write_text("{}")
    _write_progress(tmp_path, "auth", "Auth Service", 9, 9, "done")
    _run(tmp_path, expected=1)
    data = json.loads((tmp_path / ".appsec-progress.json").read_text())
    assert data["step"] == 1
    assert data["step_total"] == 1
    assert data["status"] == "step_completed"
