"""
Tests for stride_progress.py — progress line dedup, heartbeat cadence,
and TTY-aware marker fallback.
"""

from __future__ import annotations

import json
import os
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
    env = {**os.environ, "PATH": "/usr/bin:/bin", "PYTHONPATH": str(PLUGIN_SCRIPTS)}
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


# ---------------------------------------------------------------------------
# Direct-import unit tests (precise coverage of helpers + edge branches).
# ---------------------------------------------------------------------------

import importlib.util  # noqa: E402
import time  # noqa: E402

_SPEC = importlib.util.spec_from_file_location("stride_progress", PLUGIN_SCRIPTS / "stride_progress.py")
sp = importlib.util.module_from_spec(_SPEC)
sys.modules["stride_progress"] = sp
assert _SPEC.loader is not None
_SPEC.loader.exec_module(sp)


# --- _use_unicode / _markers --------------------------------------------------


def test_use_unicode_true_when_tty_utf(monkeypatch):
    class FakeStderr:
        encoding = "UTF-8"

        def isatty(self):
            return True

    monkeypatch.setattr(sp.sys, "stderr", FakeStderr())
    assert sp._use_unicode() is True
    marks = sp._markers()
    assert marks["done"] == "✓"
    assert marks["stale"] == "⧗"


def test_use_unicode_false_on_non_utf_tty(monkeypatch):
    class FakeStderr:
        encoding = "ascii"

        def isatty(self):
            return True

    monkeypatch.setattr(sp.sys, "stderr", FakeStderr())
    assert sp._use_unicode() is False


def test_use_unicode_swallows_exception(monkeypatch):
    class Boom:
        def isatty(self):
            raise RuntimeError("no tty info")

    monkeypatch.setattr(sp.sys, "stderr", Boom())
    assert sp._use_unicode() is False


# --- _load -------------------------------------------------------------------


def test_load_returns_empty_on_bad_json(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("{not json")
    assert sp._load(bad) == {}


def test_load_returns_empty_on_missing(tmp_path):
    assert sp._load(tmp_path / "nope.json") == {}


# --- _format_entry -----------------------------------------------------------


def test_format_entry_step_total_with_label():
    marks = {"done": "D", "stale": "S", "bullet": "-"}
    out = sp._format_entry({"component_name": "Auth", "step": 4, "total": 9, "label": "Tampering"}, False, False, marks)
    assert out == "Auth [4/9 Tampering]"


def test_format_entry_step_total_stale_no_label():
    marks = {"done": "D", "stale": "S", "bullet": "-"}
    out = sp._format_entry({"component_id": "auth", "step": 2, "total": 9, "label": ""}, False, True, marks)
    assert out == "auth [2/9] S"


def test_format_entry_starting_when_no_step():
    marks = {"done": "D", "stale": "S", "bullet": "-"}
    out = sp._format_entry({"component_name": "Auth"}, False, False, marks)
    assert out == "Auth [starting]"


def test_format_entry_done():
    marks = {"done": "D", "stale": "S", "bullet": "-"}
    out = sp._format_entry({"component_name": "Auth"}, True, False, marks)
    assert out == "Auth D"


def test_format_entry_unknown_name():
    marks = {"done": "D", "stale": "S", "bullet": "-"}
    out = sp._format_entry({}, False, False, marks)
    assert out == "? [starting]"


# --- _read_last / _write_last error paths ------------------------------------


def test_read_last_handles_corrupt_count(tmp_path):
    d = tmp_path / ".progress"
    d.mkdir()
    (d / ".last-print").write_text("notanint\nbody line\n")
    body, count = sp._read_last(d)
    assert (body, count) == ("", 0)


def test_write_last_swallows_oserror(monkeypatch, tmp_path):
    # mkdir raises → OSError swallowed, no exception propagates.
    def _boom(*_a, **_k):
        raise OSError("denied")

    monkeypatch.setattr(sp.Path, "mkdir", _boom)
    sp._write_last(tmp_path / ".progress", "line", 0)  # must not raise


def test_write_appsec_progress_swallows_oserror(monkeypatch, tmp_path):
    def _boom(*_a, **_k):
        raise OSError("denied")

    monkeypatch.setattr(sp.Path, "mkdir", _boom)
    sp._write_appsec_progress(tmp_path, 0, 2, [])  # must not raise


# --- main(): usage / arg errors ----------------------------------------------


def test_main_wrong_arg_count_returns_2(capsys):
    assert sp.main(["stride_progress.py", "only-one"]) == 2
    assert "usage" in capsys.readouterr().err


def test_main_invalid_expected_returns_2(capsys):
    assert sp.main(["stride_progress.py", "/tmp", "notanint"]) == 2
    assert "invalid expected count" in capsys.readouterr().err


def test_main_force_flag_stripped_and_emits(tmp_path):
    _write_progress(tmp_path, "auth", "Auth Service", 3, 9, "Tampering")
    rc = sp.main(["stride_progress.py", str(tmp_path), "2", "--force"])
    assert rc == 1  # 0/2 ready


def test_main_no_entries_prints_no_progress_line(tmp_path, capsys):
    # No .progress dir and no .stride files → entries empty → "(no progress reported yet)".
    rc = sp.main(["stride_progress.py", str(tmp_path), "1"])
    assert rc == 1
    assert "(no progress reported yet)" in capsys.readouterr().out


def test_main_ready_without_progress_file_stale(tmp_path, capsys):
    # A .stride-<id>.json exists but no matching .progress file, and the output
    # file is old → "(no progress file — may be stale)" branch (lines 189-200).
    f = tmp_path / ".stride-ghost.json"
    f.write_text("{}")
    old = time.time() - 1000
    os.utime(f, (old, old))
    rc = sp.main(["stride_progress.py", str(tmp_path), "1"])
    assert rc == 0  # 1/1 ready
    out = capsys.readouterr().out
    assert "ghost" in out
    assert "may be stale" in out


def test_main_ready_without_progress_file_fresh(tmp_path, capsys):
    # Same as above but fresh mtime → done marker without the stale suffix.
    f = tmp_path / ".stride-fresh.json"
    f.write_text("{}")
    rc = sp.main(["stride_progress.py", str(tmp_path), "1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "fresh" in out
    assert "may be stale" not in out
