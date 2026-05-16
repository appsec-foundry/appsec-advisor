"""Unit tests for ``appsec_status.py --live`` (M3.6 #4)."""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "appsec_status.py"


@pytest.fixture
def appsec_status():
    spec = importlib.util.spec_from_file_location("appsec_status", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["appsec_status"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _seed_run(
    tmp_path: Path,
    *,
    phase: str = "9",
    current_progress: dict | None = None,
    progress_components: list[tuple[str, int]] | None = None,
    active_tool_age: int | None = None,
    completed_components: list[str] | None = None,
) -> None:
    """Build a fake $OUTPUT_DIR with the artefacts the live snapshot reads."""
    (tmp_path / ".appsec-lock").write_text(f"12345\n{int(time.time())}\n")
    (tmp_path / ".appsec-checkpoint").write_text(f"phase={phase} status=started timestamp=2026-05-04T00:00:00Z")
    (tmp_path / ".skill-config.json").write_text(json.dumps({"assessment_depth": "standard"}))
    if current_progress is not None:
        payload = {
            "event": "STEP_START",
            "kind": "step-start",
            "agent": "threat-analyst",
            "phase": phase,
            "phase_total": "11",
            "step": 2,
            "step_total": 5,
            "label": "default progress",
            "status": "step_started",
            "updated_at": "2026-05-04T00:00:00Z",
        }
        payload.update(current_progress)
        (tmp_path / ".appsec-progress.json").write_text(json.dumps(payload))
    (tmp_path / ".progress").mkdir(exist_ok=True)
    (tmp_path / ".active-tool-calls").mkdir(exist_ok=True)
    for comp, step in progress_components or []:
        (tmp_path / ".progress" / f"{comp}.json").write_text(
            json.dumps(
                {"component_id": comp, "component_name": comp.title(), "step": step, "total": 9, "label": "running"}
            )
        )
    for comp in completed_components or []:
        (tmp_path / f".stride-{comp}.json").write_text("{}")
    if active_tool_age is not None:
        (tmp_path / ".active-tool-calls" / "toolu_abc.json").write_text(
            json.dumps(
                {
                    "tool_use_id": "toolu_abc",
                    "session_id": "abc12345",
                    "agent": "stride-analyzer",
                    "tool": "Bash",
                    "started_at": int(time.time()) - active_tool_age,
                    "input_summary": "grep -rn JWT lib/",
                }
            )
        )


# ---------------------------------------------------------------------------
# has_run / no-run flag
# ---------------------------------------------------------------------------


def test_returns_no_run_when_output_dir_empty(tmp_path, appsec_status):
    snap = appsec_status._live_snapshot(tmp_path)
    assert snap["has_run"] is False
    assert snap["active_tool_calls"] == []


def test_returns_run_state_when_artefacts_present(tmp_path, appsec_status):
    _seed_run(tmp_path, progress_components=[("auth", 4)], active_tool_age=10)
    snap = appsec_status._live_snapshot(tmp_path)
    assert snap["has_run"] is True
    assert snap["checkpoint"]["phase"] == "9"


def test_current_progress_state_is_surfaced(tmp_path, appsec_status):
    _seed_run(
        tmp_path,
        current_progress={"label": "Watching 5 STRIDE analyzers", "step": 3, "step_total": 7},
    )
    snap = appsec_status._live_snapshot(tmp_path)
    assert snap["current"]["label"] == "Watching 5 STRIDE analyzers"
    text = appsec_status._render_live(snap)
    assert "Current progress" in text
    assert "Phase 9/11" in text
    assert "step 3/7" in text
    assert "Watching 5 STRIDE analyzers" in text


# ---------------------------------------------------------------------------
# Phase-aware threshold lookup
# ---------------------------------------------------------------------------


def test_threshold_matches_phase_budget(tmp_path, appsec_status):
    _seed_run(tmp_path, phase="9")  # standard depth → 360 × 1.5 = 540s
    snap = appsec_status._live_snapshot(tmp_path)
    assert snap["threshold_seconds"] == 540


def test_threshold_uses_skill_config_depth(tmp_path, appsec_status):
    _seed_run(tmp_path, phase="9")
    (tmp_path / ".skill-config.json").write_text(json.dumps({"assessment_depth": "thorough"}))
    snap = appsec_status._live_snapshot(tmp_path)
    assert snap["threshold_seconds"] == 1080  # 720 × 1.5


# ---------------------------------------------------------------------------
# Active tool-call age filter — sub-agent missing-Post must not pollute view.
# ---------------------------------------------------------------------------


def test_recent_active_tool_call_is_listed(tmp_path, appsec_status):
    _seed_run(tmp_path, active_tool_age=30)
    snap = appsec_status._live_snapshot(tmp_path)
    assert len(snap["active_tool_calls"]) == 1
    assert snap["active_tool_calls"][0]["age_s"] >= 30


def test_stale_active_tool_call_is_filtered(tmp_path, appsec_status):
    # Phase 9 standard threshold = 540s; entries older than 2x = 1080s drop.
    _seed_run(tmp_path, active_tool_age=2000)
    snap = appsec_status._live_snapshot(tmp_path)
    assert snap["active_tool_calls"] == []


# ---------------------------------------------------------------------------
# Progress sort + age tracking
# ---------------------------------------------------------------------------


def test_progress_entries_include_step_label(tmp_path, appsec_status):
    _seed_run(tmp_path, progress_components=[("auth", 4), ("billing", 2)])
    snap = appsec_status._live_snapshot(tmp_path)
    comps = {p["component"] for p in snap["progress"]}
    assert comps == {"Auth", "Billing"}
    for p in snap["progress"]:
        assert p["step"] is not None
        assert p["total"] == 9


def test_completed_stride_count_is_surfaced(tmp_path, appsec_status):
    _seed_run(
        tmp_path,
        progress_components=[("auth", 9), ("billing", 9)],
        completed_components=["auth"],
    )
    snap = appsec_status._live_snapshot(tmp_path)
    assert snap["stride_files"] == 1


# ---------------------------------------------------------------------------
# Render — guard against accidental sub-second floats reappearing
# ---------------------------------------------------------------------------


def test_render_human_view_uses_integer_age(tmp_path, appsec_status):
    _seed_run(tmp_path, progress_components=[("auth", 4)], active_tool_age=42)
    snap = appsec_status._live_snapshot(tmp_path)
    text = appsec_status._render_live(snap)
    assert "Phase 9" in text
    # heartbeat_age must look like "Ns" (integer + s), no decimal point.
    import re

    m = re.search(r"heartbeat_age=([\w?]+)", text)
    assert m is not None
    val = m.group(1)
    assert val == "?" or "." not in val
