"""Unit tests for scripts/skill_watchdog.py — the M3.6 Python rewrite."""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "skill_watchdog.py"


def _load():
    spec = importlib.util.spec_from_file_location("skill_watchdog", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["skill_watchdog"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    """A pre-populated $OUTPUT_DIR with a held lock and progress dir."""
    (tmp_path / ".appsec-lock").write_text("12345\n" + str(int(time.time())) + "\n")
    (tmp_path / ".progress").mkdir()
    return tmp_path


@pytest.fixture
def silent_heartbeat(monkeypatch):
    """Replace the sub-process call so tests do not actually shell out."""
    sw = _load()
    monkeypatch.setattr(sw, "_refresh_heartbeat", lambda *_a, **_k: None)
    return sw


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_exits_immediately_when_lock_absent(tmp_path, silent_heartbeat):
    sw = silent_heartbeat
    # No lock file at all — loop should bail before iter 1.
    rc = sw.watch(
        output_dir=tmp_path,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=10,
        stride_canary_seconds=10,
        component_timeout_seconds=10,
        max_iterations=10,
    )
    assert rc == 0
    log = (tmp_path / ".agent-run.log").read_text()
    assert "WATCHDOG_START" in log
    assert "WATCHDOG_END" in log


def test_iteration_cap_is_honoured(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    rc = sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=999,
        max_iterations=2,
    )
    assert rc == 0
    log = (out_dir / ".agent-run.log").read_text()
    assert "iterations_capped" in log
    # Tick file should reflect the last iteration.
    tick = (out_dir / ".skill-watchdog.tick").read_text().splitlines()
    assert int(tick[0]) == 2


# ---------------------------------------------------------------------------
# Phase-9 detection + canary
# ---------------------------------------------------------------------------


def test_canary_fires_when_progress_present_but_no_stride(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    # A .progress entry → Phase 9 considered started; no .stride-*.json
    # → canary should fire on the same tick.
    (out_dir / ".progress" / "auth.json").write_text(
        json.dumps({"component_id": "auth", "step": 1, "total": 9, "label": "starting"})
    )
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=0,  # immediate
        component_timeout_seconds=999,
        max_iterations=2,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "PHASE9_DETECTED" in log
    assert "STRIDE_CANARY_TIMEOUT" in log


def test_canary_does_not_fire_before_phase9_signals(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    # No .progress files, no .stride files — Phase 9 has not started yet.
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=0,
        component_timeout_seconds=999,
        max_iterations=3,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "PHASE9_DETECTED" not in log
    assert "STRIDE_CANARY_TIMEOUT" not in log


# ---------------------------------------------------------------------------
# Per-component timeout (M3.6 #7) — the new escalation path.
# ---------------------------------------------------------------------------


def test_component_timeout_fires_for_idle_component(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    pf = out_dir / ".progress" / "billing.json"
    pf.write_text(json.dumps({"component_id": "billing", "step": 2, "total": 9}))
    # Backdate the mtime so the component is "idle".
    old = time.time() - 600
    import os

    os.utime(pf, (old, old))
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=60,
        max_iterations=2,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "STRIDE_COMPONENT_TIMEOUT" in log
    assert "component=billing" in log


def test_component_timeout_skips_completed_components(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    # progress + final stride file = component is done. No timeout warning.
    pf = out_dir / ".progress" / "frontend.json"
    pf.write_text(json.dumps({"component_id": "frontend"}))
    (out_dir / ".stride-frontend.json").write_text("{}")
    import os

    old = time.time() - 600
    os.utime(pf, (old, old))
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=60,
        max_iterations=2,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "STRIDE_COMPONENT_TIMEOUT" not in log


def test_component_timeout_disabled_with_zero(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    pf = out_dir / ".progress" / "auth.json"
    pf.write_text(json.dumps({"component_id": "auth"}))
    import os

    old = time.time() - 9999
    os.utime(pf, (old, old))
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=0,  # disabled
        max_iterations=2,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "STRIDE_COMPONENT_TIMEOUT" not in log


# ---------------------------------------------------------------------------
# Self-liveness tick (#10 enabler)
# ---------------------------------------------------------------------------


def test_self_liveness_tick_advances_each_iteration(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=999,
        max_iterations=4,
    )
    n, ts = (out_dir / ".skill-watchdog.tick").read_text().splitlines()[:2]
    assert int(n) == 4
    assert abs(int(ts) - int(time.time())) < 5


# ---------------------------------------------------------------------------
# Fix E (2026-05-25) — STRIDE_PROGRESS gating on past_stride. After
# `.appsec-checkpoint` advances past phase=9 the .stride-*.json snapshot
# is frozen; emitting STRIDE_PROGRESS heartbeats every 60s through Stage 2
# / Stage 3 / repair was the source of ~17 false-progress entries per run.
# ---------------------------------------------------------------------------


def test_stride_progress_suppressed_when_past_stride_phase(out_dir, silent_heartbeat):
    """With .appsec-checkpoint at phase=11, STRIDE_PROGRESS must NOT fire."""
    sw = silent_heartbeat
    # Phase-9 markers present (so phase9_detected goes True), but the
    # checkpoint says we've moved on to Phase 11.
    (out_dir / ".progress" / "auth.json").write_text(
        json.dumps({"component_id": "auth", "step": 9, "total": 9, "label": "done"})
    )
    (out_dir / ".stride-auth.json").write_text(json.dumps({"threats": []}))
    (out_dir / ".appsec-checkpoint").write_text("phase=11 status=writing_output timestamp=2026-05-25T07:00:00Z\n")
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=999,
        max_iterations=3,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "STRIDE_PROGRESS" not in log, (
        "STRIDE_PROGRESS must be suppressed once .appsec-checkpoint indicates "
        "the orchestrator has moved past Phase 9 (otherwise emits identical "
        "heartbeats through Stage 2/3/repair, creating audit-log noise)."
    )


def test_stride_progress_emitted_when_phase9_active(out_dir, silent_heartbeat):
    """Without a checkpoint past phase=9, STRIDE_PROGRESS still fires as before."""
    sw = silent_heartbeat
    (out_dir / ".progress" / "auth.json").write_text(
        json.dumps({"component_id": "auth", "step": 3, "total": 9, "label": "scanning"})
    )
    (out_dir / ".stride-auth.json").write_text(json.dumps({"threats": []}))
    # No .appsec-checkpoint at all → _is_past_stride_phase returns False.
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=999,
        max_iterations=2,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "STRIDE_PROGRESS" in log, (
        "STRIDE_PROGRESS must keep firing while Phase 9 is still the active "
        "phase (legacy behaviour preserved when checkpoint is absent or =9)."
    )


def test_stride_progress_suppressed_during_repair_phase(out_dir, silent_heartbeat):
    """A `phase=repair/N` checkpoint must also suppress STRIDE_PROGRESS."""
    sw = silent_heartbeat
    (out_dir / ".stride-auth.json").write_text(json.dumps({"threats": []}))
    (out_dir / ".appsec-checkpoint").write_text("phase=repair/1 status=in_progress timestamp=2026-05-25T07:00:00Z\n")
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=999,
        max_iterations=3,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "STRIDE_PROGRESS" not in log


# ---------------------------------------------------------------------------
# Substep 2 idle detection (review-recommendations §4 Fix 3).
# Guards against the 2026-05-25 juice-shop 1h 39min stall pattern:
# STEP_START Substep 2 appears in .agent-run.log but no non-watchdog log
# event lands within `substep2_idle_seconds`, and no FILE_WRITE of
# threat-model.yaml occurs. The watchdog must escalate LOUDLY:
#   1. ERROR-level line in .agent-run.log
#   2. stderr banner (so the terminal user sees it)
#   3. sentinel file `.substep2-idle`
#   4. defect-severity entry appended to .run-issues.json
# ---------------------------------------------------------------------------


class TestSubstep2IdleDetection:
    """Hard-limit detector for the Phase 11 / Substep 2 stall class."""

    SUBSTEP2_START_LINE = (
        "2026-05-25T10:00:00Z  [a]  INFO   threat-analyst  "
        "STEP_START   [Phase 11] [2/3] Writing threat-model.yaml "
        "(canonical baseline)…\n"
    )

    def test_fires_loud_error_when_idle_exceeds_threshold(self, out_dir, silent_heartbeat, capsys):
        sw = silent_heartbeat
        # STEP_START 1 hour ago, no FILE_WRITE → idle ~3600s, threshold 300s
        (out_dir / ".agent-run.log").write_text(self.SUBSTEP2_START_LINE)
        sw.watch(
            output_dir=out_dir,
            plugin_root=REPO_ROOT,
            heartbeat_interval=0,
            stride_stale_seconds=999,
            stride_canary_seconds=999,
            component_timeout_seconds=999,
            max_iterations=1,
            substep2_idle_seconds=300,
        )
        # 1. ERROR line in .agent-run.log
        log = (out_dir / ".agent-run.log").read_text()
        assert "ERROR" in log and "SUBSTEP2_IDLE" in log
        # 2. stderr banner with the ⛔ glyph
        captured = capsys.readouterr()
        assert "⛔" in captured.err and "SUBSTEP2_IDLE" in captured.err
        # 3. sentinel file present and points at the failure mode
        sentinel = out_dir / ".substep2-idle"
        assert sentinel.exists()
        body = sentinel.read_text()
        assert "Phase 11 Substep 2 idle" in body
        # 4. structured defect in .run-issues.json
        issues = json.loads((out_dir / ".run-issues.json").read_text())
        assert isinstance(issues, list) and len(issues) == 1
        assert issues[0]["severity"] == "defect"
        assert issues[0]["type"] == "substep2_idle"
        assert issues[0]["source"] == "skill-watchdog"
        assert "remedy" in issues[0] and "build_threat_model_yaml.py" in issues[0]["remedy"]

    def test_does_not_fire_when_substep2_completed(self, out_dir, silent_heartbeat):
        """STEP_START + FILE_WRITE both present → substep is done, no alarm."""
        sw = silent_heartbeat
        (out_dir / ".agent-run.log").write_text(
            self.SUBSTEP2_START_LINE + "2026-05-25T10:00:04Z  [a]  INFO   threat-analyst  "
            "FILE_WRITE   /tmp/threat-model.yaml\n"
        )
        sw.watch(
            output_dir=out_dir,
            plugin_root=REPO_ROOT,
            heartbeat_interval=0,
            stride_stale_seconds=999,
            stride_canary_seconds=999,
            component_timeout_seconds=999,
            max_iterations=1,
            substep2_idle_seconds=300,
        )
        assert not (out_dir / ".substep2-idle").exists()
        assert not (out_dir / ".run-issues.json").exists()

    def test_does_not_fire_when_yaml_on_disk_without_filewrite_marker(self, out_dir, silent_heartbeat):
        """STEP_START present, NO FILE_WRITE log marker, but threat-model.yaml
        exists on disk (fresh mtime) → Substep 2 is done, no alarm.

        Regression for the 2026-06-04 juice-shop pstride-e2e false-positive:
        the analyst writes the yaml via build_threat_model_yaml.py, which does
        not emit the FILE_WRITE marker the log-only check keyed on, so the
        watchdog kept measuring idle and mis-flagged the Stage-2 renderer's
        long compose turn (no interim logs) as a Substep-2 stall.
        """
        sw = silent_heartbeat
        # STEP_START 1h ago, NO FILE_WRITE marker in the log…
        (out_dir / ".agent-run.log").write_text(self.SUBSTEP2_START_LINE)
        # …but the deliverable IS on disk with a current mtime.
        (out_dir / "threat-model.yaml").write_text("schema_version: 1\n")
        sw.watch(
            output_dir=out_dir,
            plugin_root=REPO_ROOT,
            heartbeat_interval=0,
            stride_stale_seconds=999,
            stride_canary_seconds=999,
            component_timeout_seconds=999,
            max_iterations=1,
            substep2_idle_seconds=300,
        )
        assert not (out_dir / ".substep2-idle").exists()
        assert not (out_dir / ".run-issues.json").exists()

    def test_does_not_fire_before_substep2_starts(self, out_dir, silent_heartbeat):
        """No STEP_START Substep 2 yet → detector quiet."""
        sw = silent_heartbeat
        (out_dir / ".agent-run.log").write_text(
            "2026-05-25T10:00:00Z  [a]  INFO   threat-analyst  ASSESSMENT_START   started\n"
        )
        sw.watch(
            output_dir=out_dir,
            plugin_root=REPO_ROOT,
            heartbeat_interval=0,
            stride_stale_seconds=999,
            stride_canary_seconds=999,
            component_timeout_seconds=999,
            max_iterations=1,
            substep2_idle_seconds=300,
        )
        assert not (out_dir / ".substep2-idle").exists()

    def test_does_not_fire_when_disabled_with_zero(self, out_dir, silent_heartbeat):
        """`substep2_idle_seconds=0` disables the check (parity with
        --component-timeout-seconds 0)."""
        sw = silent_heartbeat
        (out_dir / ".agent-run.log").write_text(self.SUBSTEP2_START_LINE)
        sw.watch(
            output_dir=out_dir,
            plugin_root=REPO_ROOT,
            heartbeat_interval=0,
            stride_stale_seconds=999,
            stride_canary_seconds=999,
            component_timeout_seconds=999,
            max_iterations=1,
            substep2_idle_seconds=0,
        )
        assert not (out_dir / ".substep2-idle").exists()

    def test_watchdog_own_lines_do_not_reset_idle_window(self, out_dir, silent_heartbeat):
        """The watchdog emits WATCHDOG_START to .agent-run.log; that line
        must NOT count as orchestrator activity (it is the watchdog speaking
        about itself, not the agent making progress)."""
        sw = silent_heartbeat
        (out_dir / ".agent-run.log").write_text(self.SUBSTEP2_START_LINE)
        sw.watch(
            output_dir=out_dir,
            plugin_root=REPO_ROOT,
            heartbeat_interval=0,
            stride_stale_seconds=999,
            stride_canary_seconds=999,
            component_timeout_seconds=999,
            max_iterations=1,
            substep2_idle_seconds=300,
        )
        # WATCHDOG_START is now in the log (idle would be ~0 if mtime-based)
        # but the detector must still fire because it filters skill-watchdog lines.
        assert (out_dir / ".substep2-idle").exists()


# ---------------------------------------------------------------------------
# Global RUN_IDLE detection (all phases) — 2026-05-31 juice-shop regression:
# ~23 min lost to standard-tier API-latency stalls in the recon/context phase,
# a window covered by NONE of the phase-9 / substep-2 detectors. RUN_IDLE
# fires one WARN per distinct stall and re-arms after activity resumes.
# ---------------------------------------------------------------------------


class TestRunIdleHelper:
    """`_run_idle_seconds` takes the FRESHEST of two activity signals: the
    latest NON-heartbeat line in .hook-events.log (tool granularity) and the
    last non-watchdog .agent-run.log entry. Either one being recent means
    'not idle'. Heartbeat lines are content-filtered, NOT trusted via mtime —
    the skill appends one every 60 s and a raw mtime would mask real stalls
    (2026-06-06 juice-shop: 21-min Stage-1 stall went unsurfaced)."""

    OLD_FLOOR = "2020-01-01T00:00:00Z"

    def _hook_line(self, sw, event="FILE_WRITE", ts=None):
        ts = ts or sw._ts_now()
        return f"{ts}  [a]  INFO   {event}   /repo/x.md  (10 chars)\n"

    def test_fresh_hook_activity_masks_stale_agent_log(self, out_dir, silent_heartbeat):
        sw = silent_heartbeat
        # agent-run.log last non-watchdog entry is ancient → that signal is huge…
        (out_dir / ".agent-run.log").write_text("2026-05-25T10:00:00Z  [a]  INFO   threat-analyst  STEP_START   x\n")
        # …but a tool just appended a timestamped non-heartbeat line → fresh.
        (out_dir / ".hook-events.log").write_text(self._hook_line(sw))
        idle = sw._run_idle_seconds(out_dir, self.OLD_FLOOR)
        assert idle < 5  # freshest signal wins → not idle

    def test_heartbeat_only_hook_does_not_mask_idle(self, out_dir, silent_heartbeat):
        # Regression for the 2026-06-06 masking bug: hook-events.log advances
        # every 60 s with HEARTBEAT lines while the run is genuinely stalled.
        # Those must NOT count as activity, so the stale agent-run signal wins.
        sw = silent_heartbeat
        (out_dir / ".agent-run.log").write_text("2026-05-25T10:00:00Z  [a]  INFO   threat-analyst  STEP_START   x\n")
        # Only fresh HEARTBEAT lines in the hook log — no real tool activity.
        now = sw._ts_now()
        (out_dir / ".hook-events.log").write_text(
            f"{now}  [--------]  INFO   HEARTBEAT   pid=23  phase=skill  step=watchdog\n"
        )
        idle = sw._run_idle_seconds(out_dir, self.OLD_FLOOR)
        assert idle > 600  # heartbeat ignored → stale agent-run signal surfaces

    def test_reports_idle_when_both_signals_stale(self, out_dir, silent_heartbeat):
        sw = silent_heartbeat
        (out_dir / ".agent-run.log").write_text("2026-05-25T10:00:00Z  [a]  INFO   threat-analyst  STEP_START   x\n")
        # Hook log's latest non-heartbeat line is ~10 min old (no tool since).
        old_ts = (datetime.now(timezone.utc) - timedelta(seconds=600)).strftime("%Y-%m-%dT%H:%M:%SZ")
        (out_dir / ".hook-events.log").write_text(self._hook_line(sw, ts=old_ts))
        idle = sw._run_idle_seconds(out_dir, self.OLD_FLOOR)
        assert 590 <= idle <= 620  # ~10 min idle


class TestRunIdleDetection:
    """Loop wiring for the global stall WARN (gated on --run-idle-seconds)."""

    def _run(self, sw, out_dir, idle_fn, *, run_idle_seconds=300, iters=1):
        # Drive the detector with a controllable idle reading.
        sw._run_idle_seconds = idle_fn  # type: ignore[assignment]
        return sw.watch(
            output_dir=out_dir,
            plugin_root=REPO_ROOT,
            heartbeat_interval=0,
            stride_stale_seconds=999,
            stride_canary_seconds=999,
            component_timeout_seconds=999,
            max_iterations=iters,
            run_idle_seconds=run_idle_seconds,
        )

    def test_fires_warn_when_idle_exceeds_threshold(self, out_dir, silent_heartbeat):
        sw = silent_heartbeat
        self._run(sw, out_dir, lambda *_a, **_k: 500.0)
        log = (out_dir / ".agent-run.log").read_text()
        assert "WARN" in log and "RUN_IDLE" in log
        assert "API" in log  # message steers the user toward the real cause

    def test_quiet_when_run_is_active(self, out_dir, silent_heartbeat):
        sw = silent_heartbeat
        self._run(sw, out_dir, lambda *_a, **_k: 5.0)
        log = (out_dir / ".agent-run.log").read_text()
        assert "RUN_IDLE" not in log

    def test_disabled_with_zero(self, out_dir, silent_heartbeat):
        sw = silent_heartbeat
        self._run(sw, out_dir, lambda *_a, **_k: 9999.0, run_idle_seconds=0)
        log = (out_dir / ".agent-run.log").read_text()
        assert "RUN_IDLE" not in log

    def test_fires_once_then_rearms_on_resume(self, out_dir, silent_heartbeat):
        sw = silent_heartbeat
        # idle high (fire) → low (resume) → high (fire again): 2 RUN_IDLE, 1 RESUMED.
        seq = iter([500.0, 10.0, 500.0])
        self._run(sw, out_dir, lambda *_a, **_k: next(seq), iters=3)
        log = (out_dir / ".agent-run.log").read_text()
        assert log.count("RUN_IDLE") == 2
        assert log.count("RUN_RESUMED") == 1


# ---------------------------------------------------------------------------
# main() / argparse wiring + missing-output-dir guard (lines 479, 500-501,
# 755-827).
# ---------------------------------------------------------------------------


class TestMainCli:
    def test_missing_output_dir_returns_2(self, tmp_path, monkeypatch):
        sw = _load()
        monkeypatch.setattr(sw, "_refresh_heartbeat", lambda *_a, **_k: None)
        rc = sw.watch(
            output_dir=tmp_path / "does-not-exist",
            plugin_root=REPO_ROOT,
            heartbeat_interval=0,
            stride_stale_seconds=1,
            stride_canary_seconds=1,
            component_timeout_seconds=1,
            max_iterations=1,
        )
        assert rc == 2

    def test_main_dispatches_to_watch_with_parsed_args(self, out_dir, monkeypatch):
        sw = _load()
        monkeypatch.setattr(sw, "_refresh_heartbeat", lambda *_a, **_k: None)
        # max-iterations cap so the loop terminates without a real lock removal.
        rc = sw.main(
            [
                "skill_watchdog.py",
                str(out_dir),
                "--plugin-root",
                str(REPO_ROOT),
                "--heartbeat-interval",
                "0",
                "--stride-stale-seconds",
                "999",
                "--stride-canary-seconds",
                "999",
                "--component-timeout-seconds",
                "999",
                "--substep2-idle-seconds",
                "0",
                "--run-idle-seconds",
                "0",
                "--max-iterations",
                "1",
            ]
        )
        assert rc == 0
        assert (out_dir / ".agent-run.log").read_text().count("WATCHDOG_START") == 1

    def test_main_missing_output_dir_returns_2(self, tmp_path, monkeypatch):
        sw = _load()
        monkeypatch.setattr(sw, "_refresh_heartbeat", lambda *_a, **_k: None)
        rc = sw.main(["skill_watchdog.py", str(tmp_path / "ghost"), "--max-iterations", "1"])
        assert rc == 2

    def test_main_defaults_plugin_root_when_blank(self, out_dir, monkeypatch):
        sw = _load()
        monkeypatch.setattr(sw, "_refresh_heartbeat", lambda *_a, **_k: None)
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        # No --plugin-root and empty env → falls back to __file__-relative root.
        rc = sw.main(
            [
                "skill_watchdog.py",
                str(out_dir),
                "--heartbeat-interval",
                "0",
                "--substep2-idle-seconds",
                "0",
                "--run-idle-seconds",
                "0",
                "--max-iterations",
                "1",
            ]
        )
        assert rc == 0


# ---------------------------------------------------------------------------
# _refresh_heartbeat — real sub-process invocation (lines 390-411) + the
# exception-swallow contract.
# ---------------------------------------------------------------------------


class TestRefreshHeartbeat:
    def test_invokes_subprocess_run(self, tmp_path, monkeypatch):
        sw = _load()
        calls = {}

        def _fake_run(cmd, **kwargs):
            calls["cmd"] = cmd
            calls["kwargs"] = kwargs

            class R:
                returncode = 0

            return R()

        import subprocess

        monkeypatch.setattr(subprocess, "run", _fake_run)
        sw._refresh_heartbeat(REPO_ROOT, tmp_path / ".appsec-lock")
        assert "acquire_lock.py" in " ".join(str(c) for c in calls["cmd"])
        assert "--heartbeat" in calls["cmd"]
        assert calls["kwargs"]["check"] is False

    def test_swallows_subprocess_exception(self, tmp_path, monkeypatch):
        sw = _load()

        def _boom(*_a, **_k):
            raise OSError("python3 not found")

        import subprocess

        monkeypatch.setattr(subprocess, "run", _boom)
        # Must not raise.
        sw._refresh_heartbeat(REPO_ROOT, tmp_path / ".appsec-lock")


# ---------------------------------------------------------------------------
# Helper-level coverage: error-swallow paths, scan, idle, stale, checkpoint.
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_log_swallows_write_error(self, tmp_path, monkeypatch):
        sw = _load()

        def _boom(*_a, **_k):
            raise OSError("denied")

        # mkdir raising triggers the broad except in _log.
        monkeypatch.setattr(sw.Path, "mkdir", _boom)
        sw._log(tmp_path, "INFO", "EV", "detail")  # must not raise

    def test_log_error_loud_handles_corrupt_run_issues(self, out_dir, capsys):
        sw = _load()
        # Pre-existing .run-issues.json that is NOT a list → reset to [].
        (out_dir / ".run-issues.json").write_text('{"not": "a list"}')
        sw._log_error_loud(out_dir, "SUBSTEP2_IDLE", "stalled", "do x")
        issues = json.loads((out_dir / ".run-issues.json").read_text())
        assert isinstance(issues, list)
        assert issues[-1]["type"] == "substep2_idle"
        assert "⛔" in capsys.readouterr().err

    def test_log_error_loud_handles_unparseable_run_issues(self, out_dir):
        sw = _load()
        (out_dir / ".run-issues.json").write_text("{broken json")
        sw._log_error_loud(out_dir, "SUBSTEP2_IDLE", "stalled", "do x")
        issues = json.loads((out_dir / ".run-issues.json").read_text())
        assert isinstance(issues, list) and len(issues) == 1

    def test_find_substep2_start_absent_log(self, tmp_path):
        sw = _load()
        assert sw._find_substep2_start(tmp_path) is None

    def test_find_substep2_start_no_match(self, out_dir):
        sw = _load()
        (out_dir / ".agent-run.log").write_text("2026-05-25T10:00:00Z  [a]  INFO  x  NOPE  y\n")
        assert sw._find_substep2_start(out_dir) is None

    def test_substep2_completed_after_filewrite_marker(self, out_dir):
        sw = _load()
        started = "2026-05-25T10:00:00Z"
        (out_dir / ".agent-run.log").write_text(
            "2026-05-25T10:00:05Z  [a]  INFO  threat-analyst  FILE_WRITE   /x/threat-model.yaml\n"
        )
        assert sw._substep2_completed_after(out_dir, started) is True

    def test_substep2_completed_after_no_signal(self, out_dir):
        sw = _load()
        (out_dir / ".agent-run.log").write_text("2026-05-25T10:00:05Z  [a]  INFO  x  STEP_START  y\n")
        assert sw._substep2_completed_after(out_dir, "2026-05-25T10:00:00Z") is False

    def test_substep2_completed_after_missing_log(self, tmp_path):
        sw = _load()
        # No log, no yaml on disk → False.
        assert sw._substep2_completed_after(tmp_path, "2026-05-25T10:00:00Z") is False

    def test_log_idle_seconds_missing_log(self, tmp_path):
        sw = _load()
        assert sw._log_idle_seconds(tmp_path, "2026-05-25T10:00:00Z") == 0.0

    def test_log_idle_seconds_skips_pre_start_and_watchdog(self, out_dir):
        sw = _load()
        # One line before start (ignored), one watchdog line (ignored), one real.
        old = (datetime.now(timezone.utc) - timedelta(seconds=600)).strftime("%Y-%m-%dT%H:%M:%SZ")
        (out_dir / ".agent-run.log").write_text(
            "2020-01-01T00:00:00Z  [a]  INFO  threat-analyst  STEP_START  early\n"
            f"{old}  [a]  INFO  skill-watchdog  WATCHDOG_START  self\n"
            f"{old}  [a]  INFO  threat-analyst  STEP_START  real\n"
        )
        idle = sw._log_idle_seconds(out_dir, "2020-01-02T00:00:00Z")
        assert 590 <= idle <= 620

    def test_hook_log_idle_seconds_absent(self, tmp_path):
        sw = _load()
        assert sw._hook_log_idle_seconds(tmp_path) is None

    def test_hook_log_idle_seconds_only_heartbeats_returns_none(self, out_dir):
        sw = _load()
        (out_dir / ".hook-events.log").write_text("2026-05-25T10:00:00Z  [--------]  INFO  HEARTBEAT  pid=1\n")
        assert sw._hook_log_idle_seconds(out_dir) is None

    def test_scan_stride_counts_bytes_and_progress(self, out_dir):
        sw = _load()
        (out_dir / ".stride-a.json").write_text('{"x":1}')
        (out_dir / ".stride-b.json").write_text('{"y":2}')
        (out_dir / ".progress" / "a.json").write_text("{}")
        snap = sw._scan_stride(out_dir)
        assert snap["stride_count"] == 2
        assert snap["stride_bytes"] > 0
        assert len(snap["progress_files"]) == 1

    def test_component_idle_seconds_maps_mtime(self, out_dir):
        sw = _load()
        import os

        pf = out_dir / ".progress" / "auth.json"
        pf.write_text("{}")
        old = time.time() - 120
        os.utime(pf, (old, old))
        out = sw._component_idle_seconds([pf])
        assert out["auth"] >= 110

    def test_is_past_stride_phase_missing_checkpoint(self, tmp_path):
        sw = _load()
        assert sw._is_past_stride_phase(tmp_path) is False

    def test_is_past_stride_phase_phase9_false(self, out_dir):
        sw = _load()
        (out_dir / ".appsec-checkpoint").write_text("phase=9 status=active\n")
        assert sw._is_past_stride_phase(out_dir) is False

    def test_is_past_stride_phase_no_phase_token(self, out_dir):
        sw = _load()
        (out_dir / ".appsec-checkpoint").write_text("status=active\n")
        assert sw._is_past_stride_phase(out_dir) is False

    def test_is_past_stride_phase_phase11_true(self, out_dir):
        sw = _load()
        (out_dir / ".appsec-checkpoint").write_text("phase=11 status=writing\n")
        assert sw._is_past_stride_phase(out_dir) is True

    def test_bump_tick_swallows_oserror(self, tmp_path, monkeypatch):
        sw = _load()

        def _boom(*_a, **_k):
            raise OSError("ro fs")

        monkeypatch.setattr(sw.Path, "write_text", _boom)
        sw._bump_tick(tmp_path, 3)  # must not raise


# ---------------------------------------------------------------------------
# Stagnation (STRIDE_STALE) wiring — lines 585-597.
# ---------------------------------------------------------------------------


def test_stride_stale_fires_when_output_frozen(out_dir, silent_heartbeat):
    """Phase 9 active, stride output present but unchanged across ticks for
    >= stride_stale_seconds → STRIDE_STALE warning fires once."""
    sw = silent_heartbeat
    (out_dir / ".stride-auth.json").write_text(json.dumps({"threats": []}))
    (out_dir / ".progress" / "auth.json").write_text(json.dumps({"component_id": "auth", "step": 3, "total": 9}))
    # heartbeat_interval=10, threshold=10 → after one stagnant tick (10s) it fires.
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=10,
        stride_stale_seconds=10,
        stride_canary_seconds=999,
        component_timeout_seconds=999,
        max_iterations=2,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "STRIDE_STALE" in log


# ---------------------------------------------------------------------------
# RUN_PROGRESS — coarse % + net-runtime liner (Element 1 + 2)
# ---------------------------------------------------------------------------


def test_phase_position_mapping():
    sw = _load()
    assert sw._phase_position("1") == 1.0
    assert sw._phase_position("2.5") == 2.5
    assert sw._phase_position("9") == 9.0
    assert sw._phase_position("10b") == 10.5
    assert sw._phase_position("11") == 11.0
    # Non-numeric finalization/repair tokens saturate near the end.
    assert sw._phase_position("repair/1") == 99.0
    assert sw._phase_position("writing_output") == 99.0


def test_fmt_hms():
    sw = _load()
    assert sw._fmt_hms(5) == "5s"
    assert sw._fmt_hms(65) == "1m05s"
    assert sw._fmt_hms(3725) == "1h02m"
    assert sw._fmt_hms(-10) == "0s"


def test_progress_snapshot_percent_is_completed_lower_bound(out_dir):
    sw = _load()
    weights = sw._PROGRESS_WEIGHTS["standard"]
    # phase=9 → completed phases 1..8 over the total. For the standard table
    # that is 11.0 / 27.5 = 40%.
    (out_dir / ".appsec-checkpoint").write_text("phase=9 status=in_progress\n")
    pct, token = sw._progress_snapshot(out_dir, weights)
    assert token == "9"
    assert pct == 40
    # phase=11 (finalization still running) → ~96%, never a premature 100.
    (out_dir / ".appsec-checkpoint").write_text("phase=11 status=writing_output\n")
    pct11, _ = sw._progress_snapshot(out_dir, weights)
    assert pct11 == 96
    # repair/completed token saturates to 100.
    (out_dir / ".appsec-checkpoint").write_text("phase=repair/1 status=in_progress\n")
    pct_done, _ = sw._progress_snapshot(out_dir, weights)
    assert pct_done == 100
    # Terminal status=completed at phase=11 saturates to 100, not 96.
    (out_dir / ".appsec-checkpoint").write_text("phase=11 status=completed\n")
    pct_term, _ = sw._progress_snapshot(out_dir, weights)
    assert pct_term == 100


def test_progress_snapshot_mid_run_completed_is_not_terminal(out_dir):
    """`status=completed` is a per-phase marker (batch_checkpoint.py writes it
    at every phase end). Reading it as run-terminal pinned the live progress
    line at ~100% from Phase 3 onward for the whole run."""
    sw = _load()
    weights = sw._PROGRESS_WEIGHTS["standard"]
    # Phase 8 done, Phase 9 running → phases 1..8 count, not 100%.
    (out_dir / ".appsec-checkpoint").write_text("phase=8 status=completed\n")
    pct, token = sw._progress_snapshot(out_dir, weights)
    assert token == "8"
    assert pct == 40  # same numerator as "phase=9 in_progress"
    # And it advances stepwise rather than sitting flat.
    seen = []
    for n in (3, 5, 8):
        (out_dir / ".appsec-checkpoint").write_text(f"phase={n} status=completed\n")
        seen.append(sw._progress_snapshot(out_dir, weights)[0])
    assert seen == sorted(seen) and len(set(seen)) == 3
    assert max(seen) < 100


def test_progress_snapshot_none_without_checkpoint(out_dir):
    sw = _load()
    weights = sw._PROGRESS_WEIGHTS["standard"]
    # No checkpoint at all.
    assert sw._progress_snapshot(out_dir, weights) is None
    # Checkpoint without a phase= token.
    (out_dir / ".appsec-checkpoint").write_text("status=started\n")
    assert sw._progress_snapshot(out_dir, weights) is None


def test_run_progress_emitted_for_timeable_run(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    (out_dir / ".appsec-checkpoint").write_text("phase=9 status=in_progress\n")
    (out_dir / ".skill-config.json").write_text(json.dumps({"assessment_depth": "standard"}))
    (out_dir / ".scan-start-epoch").write_text(str(int(time.time()) - 120))
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=999,
        max_iterations=1,
        run_idle_seconds=0,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "RUN_PROGRESS" in log
    assert "~40%" in log
    assert "phase=9" in log
    # ~120s elapsed, no standby tracking (run_idle_seconds=0) → net shown.
    assert "net=2m" in log


def test_run_progress_silent_without_scan_start_epoch(out_dir, silent_heartbeat):
    sw = silent_heartbeat
    # Checkpoint present but no .scan-start-epoch → not a timeable run → silent.
    (out_dir / ".appsec-checkpoint").write_text("phase=9 status=in_progress\n")
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=999,
        component_timeout_seconds=999,
        max_iterations=1,
        run_idle_seconds=0,
    )
    log = (out_dir / ".agent-run.log").read_text()
    assert "RUN_PROGRESS" not in log
