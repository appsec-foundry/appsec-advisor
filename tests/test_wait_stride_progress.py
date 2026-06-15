"""Unit tests for scripts/wait_stride_progress.py.

The script polls stride_progress.py in a bounded loop. We stub time.sleep and
the subprocess-running helper so the loop is fast and deterministic.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import wait_stride_progress as wsp


# ---------------------------------------------------------------------------
# _run_progress
# ---------------------------------------------------------------------------
def test_run_progress_returns_code_and_forwards_output(monkeypatch, capsys):
    captured_cmd = {}

    def fake_run(cmd, text, capture_output):
        captured_cmd["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="hello-out", stderr="hello-err")

    monkeypatch.setattr(wsp.subprocess, "run", fake_run)
    rc = wsp._run_progress(Path("/x/stride_progress.py"), Path("/out"), 3, force=False)
    assert rc == 0
    out, err = capsys.readouterr()
    assert "hello-out" in out
    assert "hello-err" in err
    # No --force when force=False
    assert "--force" not in captured_cmd["cmd"]
    assert captured_cmd["cmd"][2:] == ["/out", "3"]


def test_run_progress_appends_force_flag(monkeypatch, capsys):
    captured_cmd = {}

    def fake_run(cmd, text, capture_output):
        captured_cmd["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    monkeypatch.setattr(wsp.subprocess, "run", fake_run)
    rc = wsp._run_progress(Path("/x/sp.py"), Path("/out"), 5, force=True)
    assert rc == 1
    assert "--force" in captured_cmd["cmd"]


# ---------------------------------------------------------------------------
# main — early-exit / guard paths
# ---------------------------------------------------------------------------
def test_main_expected_non_positive_returns_zero(tmp_path):
    assert wsp.main([str(tmp_path), "0"]) == 0
    assert wsp.main([str(tmp_path), "-3"]) == 0


def test_main_missing_progress_script_returns_2(tmp_path, monkeypatch):
    # plugin_root points at a dir with no scripts/stride_progress.py
    empty_root = tmp_path / "empty_root"
    (empty_root / "scripts").mkdir(parents=True)
    rc = wsp.main([str(tmp_path), "2", "--plugin-root", str(empty_root)])
    assert rc == 2


# ---------------------------------------------------------------------------
# main — polling loop
# ---------------------------------------------------------------------------
def _make_root_with_progress(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "scripts").mkdir(parents=True)
    (root / "scripts" / "stride_progress.py").write_text("# stub\n")
    return root


def test_main_returns_0_on_first_round_success(tmp_path, monkeypatch):
    root = _make_root_with_progress(tmp_path)
    calls = []

    def fake_run_progress(script, output_dir, expected, *, force):
        calls.append(force)
        return 0  # ready immediately

    monkeypatch.setattr(wsp, "_run_progress", fake_run_progress)
    slept = []
    monkeypatch.setattr(wsp.time, "sleep", lambda s: slept.append(s))

    rc = wsp.main([str(tmp_path), "2", "--plugin-root", str(root)])
    assert rc == 0
    assert calls == [True]  # first round uses force
    assert slept == []  # never sleeps when round 1 succeeds


def test_main_returns_high_rc_immediately(tmp_path, monkeypatch):
    root = _make_root_with_progress(tmp_path)
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: 2)
    monkeypatch.setattr(wsp.time, "sleep", lambda s: None)

    rc = wsp.main([str(tmp_path), "4", "--plugin-root", str(root)])
    assert rc == 2


def test_main_succeeds_after_a_few_rounds(tmp_path, monkeypatch):
    root = _make_root_with_progress(tmp_path)
    rcs = iter([1, 1, 0])  # not-ready, not-ready, ready

    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: next(rcs))
    slept = []
    monkeypatch.setattr(wsp.time, "sleep", lambda s: slept.append(s))

    rc = wsp.main([str(tmp_path), "3", "--plugin-root", str(root), "--interval", "20"])
    assert rc == 0
    assert slept == [20, 20]  # slept between the two failing rounds


def test_main_interval_floor_is_one(tmp_path, monkeypatch):
    root = _make_root_with_progress(tmp_path)
    rcs = iter([1, 0])
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: next(rcs))
    slept = []
    monkeypatch.setattr(wsp.time, "sleep", lambda s: slept.append(s))

    rc = wsp.main([str(tmp_path), "1", "--plugin-root", str(root), "--interval", "0"])
    assert rc == 0
    assert slept == [1]  # max(0, 1) == 1


def test_main_cap_reached_emits_warn_and_returns_last_rc(tmp_path, monkeypatch, capsys):
    root = _make_root_with_progress(tmp_path)
    # Always not-ready -> exhaust all rounds. Use 13 rounds to also hit the
    # round==12 slow-warning branch.
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: 1)
    monkeypatch.setattr(wsp.time, "sleep", lambda s: None)

    rc = wsp.main([str(tmp_path), "5", "--plugin-root", str(root), "--rounds", "13"])
    assert rc == 1
    _out, err = capsys.readouterr()
    assert "poll cap reached" in err
    assert "polling slow" in err  # round 12 warning


def test_main_default_plugin_root(tmp_path, monkeypatch):
    # Exercise the `args.plugin_root or <derived>` branch (no --plugin-root).
    # Point the derived progress script lookup at the real repo, then short
    # circuit the loop with a ready first round.
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: 0)
    monkeypatch.setattr(wsp.time, "sleep", lambda s: None)
    # Real repo has scripts/stride_progress.py, so the is_file() guard passes.
    rc = wsp.main([str(tmp_path), "2"])
    assert rc == 0
