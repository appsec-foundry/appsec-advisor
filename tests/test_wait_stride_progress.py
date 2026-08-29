"""Unit tests for scripts/wait_stride_progress.py.

The script polls stride_progress.py in a bounded loop. We stub time.sleep and
the subprocess-running helper so the loop is fast and deterministic.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import stride_dispatch_waves as waves
import wait_stride_progress as wsp


# ---------------------------------------------------------------------------
# _run_progress
# ---------------------------------------------------------------------------
def test_run_progress_returns_code_and_progress_text(monkeypatch, capsys):
    captured_cmd = {}

    def fake_run(cmd, text, capture_output):
        captured_cmd["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="hello-out", stderr="hello-err")

    monkeypatch.setattr(wsp.subprocess, "run", fake_run)
    rc, progress = wsp._run_progress(Path("/x/stride_progress.py"), Path("/out"), 3, force=False)
    assert rc == 0
    # Progress text is handed back rather than printed, so the poll loop can
    # decide whether this round says anything the previous one did not.
    assert progress == "hello-out"
    out, err = capsys.readouterr()
    assert "hello-out" not in out
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
    rc, progress = wsp._run_progress(Path("/x/sp.py"), Path("/out"), 5, force=True)
    assert rc == 1
    assert progress == ""
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
        return 0, ""  # ready immediately

    monkeypatch.setattr(wsp, "_run_progress", fake_run_progress)
    slept = []
    monkeypatch.setattr(wsp.time, "sleep", lambda s: slept.append(s))

    rc = wsp.main([str(tmp_path), "2", "--plugin-root", str(root)])
    assert rc == 0
    assert calls == [True]  # first round uses force
    assert slept == []  # never sleeps when round 1 succeeds


def test_main_waits_for_wave_validation_after_seed_file_appears(tmp_path, monkeypatch):
    """OR-5: a background analyzer's write-first seed is not completion."""
    root = _make_root_with_progress(tmp_path)
    (tmp_path / ".dispatch-waves.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (0, ""))
    states = iter(["pending", "complete"])
    monkeypatch.setattr(wsp, "_wave_status", lambda _out, _components: next(states))
    slept = []
    monkeypatch.setattr(wsp.time, "sleep", lambda seconds: slept.append(seconds))

    assert wsp.main([str(tmp_path), "1", "--plugin-root", str(root), "--component", "backend-api"]) == 0
    assert slept == [20]


def test_wave_status_treats_real_write_first_seed_as_pending(tmp_path):
    manifest = {
        "generated_at": "2026-08-14T10:16:16Z",
        "components": [{"component_id": "backend-api"}],
    }
    (tmp_path / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    plan = waves.build_plan(manifest, 1)
    waves.claim(plan, manifest, tmp_path)
    (tmp_path / waves.PLAN_NAME).write_text(json.dumps(plan), encoding="utf-8")
    (tmp_path / ".stride-backend-api.json").write_text(
        json.dumps(
            {
                "component_id": "backend-api",
                "partial": True,
                "seed_only": True,
                "skipped_categories": ["S", "T", "R", "I", "D", "E"],
                "threats": [],
            }
        ),
        encoding="utf-8",
    )

    assert wsp._wave_status(tmp_path, ["backend-api"]) == "pending"


def test_main_pending_wave_cannot_exit_zero_at_poll_cap(tmp_path, monkeypatch, capsys):
    """OR-5: ready-looking seed counts must not turn a pending wave green."""
    root = _make_root_with_progress(tmp_path)
    (tmp_path / ".dispatch-waves.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (0, ""))
    monkeypatch.setattr(wsp, "_wave_status", lambda _out, _components: "pending")
    monkeypatch.setattr(wsp.time, "sleep", lambda _seconds: None)

    assert (
        wsp.main(
            [
                str(tmp_path),
                "1",
                "--plugin-root",
                str(root),
                "--rounds",
                "1",
                "--component",
                "backend-api",
            ]
        )
        == wsp.PENDING_EXIT_CODE
    )
    # The host renders exit 75 as a failed call, so the message must name the
    # condition as expected rather than as a warning the operator should act on.
    _out, err = capsys.readouterr()
    assert "join slice exhausted" in err
    assert "expected, not a failure" in err
    assert "BASH_WARN" not in err


def test_main_returns_high_rc_immediately(tmp_path, monkeypatch):
    root = _make_root_with_progress(tmp_path)
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (2, ""))
    monkeypatch.setattr(wsp.time, "sleep", lambda s: None)

    rc = wsp.main([str(tmp_path), "4", "--plugin-root", str(root)])
    assert rc == 2


def test_main_succeeds_after_a_few_rounds(tmp_path, monkeypatch):
    root = _make_root_with_progress(tmp_path)
    rcs = iter([1, 1, 0])  # not-ready, not-ready, ready

    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (next(rcs), ""))
    slept = []
    monkeypatch.setattr(wsp.time, "sleep", lambda s: slept.append(s))

    rc = wsp.main([str(tmp_path), "3", "--plugin-root", str(root), "--interval", "20"])
    assert rc == 0
    assert slept == [20, 20]  # slept between the two failing rounds


def test_main_interval_floor_is_one(tmp_path, monkeypatch):
    root = _make_root_with_progress(tmp_path)
    rcs = iter([1, 0])
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (next(rcs), ""))
    slept = []
    monkeypatch.setattr(wsp.time, "sleep", lambda s: slept.append(s))

    rc = wsp.main([str(tmp_path), "1", "--plugin-root", str(root), "--interval", "0"])
    assert rc == 0
    assert slept == [1]  # max(0, 1) == 1


def test_main_cap_reached_emits_warn_and_returns_last_rc(tmp_path, monkeypatch, capsys):
    root = _make_root_with_progress(tmp_path)
    # Always not-ready -> exhaust all rounds. Use 13 rounds to also hit the
    # round==12 slow-warning branch.
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (1, ""))
    monkeypatch.setattr(wsp.time, "sleep", lambda s: None)

    rc = wsp.main([str(tmp_path), "5", "--plugin-root", str(root), "--rounds", "13"])
    assert rc == 1
    _out, err = capsys.readouterr()
    assert "join slice exhausted" in err
    assert "polling slow" in err  # round 12 warning


def test_main_default_plugin_root(tmp_path, monkeypatch):
    # Exercise the `args.plugin_root or <derived>` branch (no --plugin-root).
    # Point the derived progress script lookup at the real repo, then short
    # circuit the loop with a ready first round.
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (0, ""))
    monkeypatch.setattr(wsp.time, "sleep", lambda s: None)
    # Real repo has scripts/stride_progress.py, so the is_file() guard passes.
    rc = wsp.main([str(tmp_path), "2"])
    assert rc == 0


# ---------------------------------------------------------------------------
# Repeated poll rounds must not be forwarded
#
# A wave joined over 24 rounds sent 24 full progress dumps into the
# orchestrator's context, 23 already stale by the time the call returned —
# 5.8KB for one waiter call on run a2a0e355.
# ---------------------------------------------------------------------------


def test_identical_rounds_are_reported_once(tmp_path, monkeypatch, capsys):
    root = _make_root_with_progress(tmp_path)
    monkeypatch.setattr(wsp.time, "sleep", lambda s: None)
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (1, "[stride] 0/2 ready\n"))

    wsp.main([str(tmp_path), "2", "--rounds", "6", "--plugin-root", str(root)])
    out = capsys.readouterr().out
    assert out.count("[stride] 0/2 ready") == 1, "an unchanged round must not repeat itself"
    assert out.count("STRIDE progress poll") == 1


def test_every_state_transition_is_still_reported(tmp_path, monkeypatch, capsys):
    root = _make_root_with_progress(tmp_path)
    monkeypatch.setattr(wsp.time, "sleep", lambda s: None)
    steps = iter(
        [
            (1, "[stride] 0/2 ready\n"),
            (1, "[stride] 0/2 ready\n"),
            (1, "[stride] 1/2 ready\n"),
            (1, "[stride] 1/2 ready\n"),
            (1, "[stride] 2/2 ready\n"),
        ]
    )
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: next(steps))

    wsp.main([str(tmp_path), "2", "--rounds", "5", "--plugin-root", str(root)])
    out = capsys.readouterr().out
    for expected in ("0/2 ready", "1/2 ready", "2/2 ready"):
        assert out.count(expected) == 1, f"transition to {expected} must survive deduplication"
