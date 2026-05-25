"""Unit tests for scripts/skill_watchdog.py — the M3.6 Python rewrite."""

from __future__ import annotations

import importlib.util
import json
import sys
import time
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
    (out_dir / ".appsec-checkpoint").write_text(
        "phase=11 status=writing_output timestamp=2026-05-25T07:00:00Z\n"
    )
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
    (out_dir / ".appsec-checkpoint").write_text(
        "phase=repair/1 status=in_progress timestamp=2026-05-25T07:00:00Z\n"
    )
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

    def test_fires_loud_error_when_idle_exceeds_threshold(
        self, out_dir, silent_heartbeat, capsys
    ):
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
            self.SUBSTEP2_START_LINE
            + "2026-05-25T10:00:04Z  [a]  INFO   threat-analyst  "
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

    def test_does_not_fire_before_substep2_starts(self, out_dir, silent_heartbeat):
        """No STEP_START Substep 2 yet → detector quiet."""
        sw = silent_heartbeat
        (out_dir / ".agent-run.log").write_text(
            "2026-05-25T10:00:00Z  [a]  INFO   threat-analyst  "
            "ASSESSMENT_START   started\n"
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

    def test_watchdog_own_lines_do_not_reset_idle_window(
        self, out_dir, silent_heartbeat
    ):
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
