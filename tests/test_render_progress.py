"""Tests for render_progress — the headless live-progress renderer.

Covers canonical-line parsing (5-field hook events vs 6-field agent-run lines,
incl. details that contain their own double-spaces) and the stateful rendering
of the events run-headless.sh surfaces by default: phase banners, sub-agent
spawn/invoke, sub-steps, and phase-anchored heartbeats.
"""

from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import render_progress as rp  # noqa: E402


def _render(lines: list[str]) -> str:
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO("\n".join(lines) + "\n")
    sys.stdout = io.StringIO()
    try:
        rp.main()
        return sys.stdout.getvalue()
    finally:
        sys.stdin, sys.stdout = old_in, old_out


def test_parse_5_field_heartbeat_detail_keeps_internal_spaces():
    line = (
        "2026-06-06T17:18:21Z  [--------]  INFO   HEARTBEAT"
        "           pid=28  phase=skill  step=stage1-dispatch  ts=1780766301"
    )
    ts, comp, event, detail = rp.parse_line(line)
    assert ts == "2026-06-06T17:18:21Z"
    assert comp == ""  # 5-field shape has no component column
    assert event == "HEARTBEAT"
    assert "step=stage1-dispatch" in detail


def test_parse_6_field_extracts_component_and_event():
    line = "2026-06-06T17:21:26Z  [--------]  INFO   context-resolver  AGENT_INVOKE  Context resolution (model: haiku)"
    ts, comp, event, detail = rp.parse_line(line)
    assert comp == "context-resolver"
    assert event == "AGENT_INVOKE"
    assert detail == "Context resolution (model: haiku)"


def test_phase_start_banner_and_action():
    out = _render(
        [
            "2026-06-06T17:21:26Z  [--------]  INFO   threat-analyst    PHASE_START"
            "   [Phase 2/11] Reconnaissance — dispatching recon-scanner… (expect ~4m)",
        ]
    )
    assert "▶ Phase 2/11 · Reconnaissance" in out
    assert "dispatching recon-scanner" in out


def test_run_progress_line_is_rendered():
    out = _render(
        [
            "2026-06-20T15:45:37Z  [--------]  INFO   skill-watchdog      RUN_PROGRESS"
            "        ~41%  phase=3  elapsed=10m55s  net=10m55s",
        ]
    )
    assert "progress · ~41%" in out
    assert "net=10m55s" in out


def test_stride_stall_and_timeout_warnings_are_rendered():
    out = _render(
        [
            "2026-06-20T15:01:00Z  [--------]  WARN   skill-watchdog    STRIDE_STALE"
            "        no progress for 900s  stride_files=2  threshold=900s",
            "2026-06-20T15:02:00Z  [--------]  WARN   skill-watchdog    STRIDE_CANARY_TIMEOUT"
            "  no stride output 180s after Phase 9 start — Phase 9 likely wedged",
            "2026-06-20T15:03:00Z  [--------]  WARN   skill-watchdog    STRIDE_COMPONENT_TIMEOUT"
            "  component=api  idle=480s  threshold=480s",
        ]
    )
    assert "⚠ stride stale —" in out
    assert "⚠ stride canary timeout —" in out
    assert "⚠ stride component timeout —" in out
    assert "component=api" in out


def test_substep2_idle_hard_limit_is_rendered():
    out = _render(
        [
            "2026-06-20T15:04:00Z  [--------]  ERROR  skill-watchdog    SUBSTEP2_IDLE"
            "        Phase 11 Substep 2 idle for 600s (threshold=600s).",
        ]
    )
    assert "⛔ substep-2 idle —" in out
    assert "600s" in out


def test_assessment_models_line_is_rendered():
    out = _render(
        [
            "2026-06-20T15:05:00Z  [--------]  INFO   hook-logger       ASSESSMENT_MODELS"
            "   agents: stride-analyzer=sonnet, recon-scanner=haiku",
        ]
    )
    assert "models · agents: stride-analyzer=sonnet" in out


def test_agent_invoke_uses_component_and_model():
    out = _render(
        [
            "2026-06-06T17:21:26Z  [--------]  INFO   recon-scanner     AGENT_INVOKE"
            "  Reconnaissance scan (model: haiku)",
        ]
    )
    assert "↳ recon-scanner (haiku): Reconnaissance scan" in out


def test_agent_spawn_strips_repo_root_and_model_field():
    out = _render(
        [
            "2026-06-06T17:20:13Z  [067fff5c]  INFO   AGENT_SPAWN"
            "         appsec-advisor:appsec-threat-analyst         model=sonnet"
            "  Threat Analysis & Triage  [REPO_ROOT=/home/mrohr/juice-shop]",
        ]
    )
    assert "↳ appsec-threat-analyst (sonnet): Threat Analysis & Triage" in out
    assert "REPO_ROOT" not in out


def test_heartbeat_anchored_to_current_phase():
    out = _render(
        [
            "2026-06-06T17:21:26Z  [--------]  INFO   threat-analyst    PHASE_START"
            "   [Phase 2/11] Reconnaissance — dispatching recon-scanner… (expect ~4m)",
            # Off-TTY (test harness) heartbeats throttle; space this one past the
            # interval so it surfaces and we can assert the rendered phase.
            "2026-06-06T17:26:26Z  [--------]  INFO   HEARTBEAT"
            "           pid=23  phase=skill  step=watchdog  ts=1780766606",
        ]
    )
    # The raw heartbeat says step=watchdog; the renderer reports the real phase.
    assert "still in Phase 2/11 Reconnaissance — 5m" in out


def test_heartbeats_throttled_off_tty():
    # Two heartbeats < throttle interval apart (off-TTY): only the first shows.
    out = _render(
        [
            "2026-06-06T17:21:26Z  [--------]  INFO   threat-analyst    PHASE_START"
            "   [Phase 2/11] Reconnaissance — dispatching recon-scanner… (expect ~4m)",
            "2026-06-06T17:22:26Z  [--------]  INFO   HEARTBEAT"
            "           pid=23  phase=skill  step=watchdog  ts=1",  # +1m, suppressed
            "2026-06-06T17:23:26Z  [--------]  INFO   HEARTBEAT"
            "           pid=23  phase=skill  step=watchdog  ts=2",  # +2m, suppressed
        ]
    )
    assert "still in Phase" not in out


def test_heartbeat_before_first_phase_shows_startup():
    out = _render(
        [
            "2026-06-06T17:18:21Z  [--------]  INFO   HEARTBEAT"
            "           pid=28  phase=skill  step=stage1-dispatch  ts=1780766301",
        ]
    )
    assert "starting up (stage1-dispatch)" in out


def test_clock_column_uses_local_system_timezone():
    # UTC log timestamps must render in the host's local zone. Pin TZ to Berlin
    # so 17:18:21Z deterministically becomes 19:18:21 (CEST, +02:00).
    old_tz = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Berlin"
    time.tzset()
    try:
        out = _render(
            [
                "2026-06-06T17:18:21Z  [--------]  INFO   HEARTBEAT"
                "           pid=28  phase=skill  step=stage1-dispatch  ts=1780766301",
            ]
        )
    finally:
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        time.tzset()
    assert out.startswith("19:18:21  ")


def test_assessment_start_renders_requirements_and_roadmap():
    out = _render(
        [
            "2026-06-06T17:20:42Z  [--------]  INFO   threat-analyst  ASSESSMENT_START"
            "   Assessment started (CET: 2026-06-06 19:20:42 CEST)  mode=full"
            "  flags=[CHECK_REQUIREMENTS=true,"
            " REQUIREMENTS_URL_OVERRIDE=/tmp/reqs.yaml, WRITE_YAML=true]",
        ]
    )
    assert "mode=full" in out and "requirements=on" in out
    assert "requirements ← /tmp/reqs.yaml" in out
    assert "Pipeline:" in out and "9 STRIDE" in out
