"""Unit tests for scripts/skill_watchdog.py — the M3.6 Python rewrite."""
from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest


REPO_ROOT   = Path(__file__).parent.parent
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
    (out_dir / ".progress" / "auth.json").write_text(json.dumps({
        "component_id": "auth", "step": 1, "total": 9, "label": "starting"
    }))
    sw.watch(
        output_dir=out_dir,
        plugin_root=REPO_ROOT,
        heartbeat_interval=0,
        stride_stale_seconds=999,
        stride_canary_seconds=0,        # immediate
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
        component_timeout_seconds=0,    # disabled
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
