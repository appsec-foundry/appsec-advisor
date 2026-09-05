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


def test_run_progress_phase_token_follows_the_live_banner():
    """The watchdog reads `phase=` from `.appsec-checkpoint`, written only at
    phase end — so it lags the banner by one phase. The banner wins."""
    out = _render(
        [
            "2026-06-06T17:21:26Z  [--------]  INFO   threat-analyst    PHASE_START   [Phase 9/11] STRIDE Enumeration",
            "2026-06-06T17:25:37Z  [--------]  INFO   skill-watchdog      RUN_PROGRESS"
            "        ~40%  phase=8  elapsed=10m55s  net=10m55s",
        ]
    )
    assert "phase=9" in out
    assert "phase=8" not in out


def _progress_lines(pcts: list[str], start_min: int = 0) -> list[str]:
    return [
        f"2026-06-06T17:{start_min + i:02d}:00Z  [--------]  INFO   skill-watchdog      RUN_PROGRESS"
        f"        ~{p}%  phase=9  elapsed={i}m00s  net={i}m00s"
        for i, p in enumerate(pcts)
    ]


def test_repeated_identical_percentage_is_not_relogged():
    """The percentage is phase-granular and sits flat through a long phase.
    Off-TTY, an unchanged reading must not scroll a fresh line every minute —
    but it must not go fully silent either: the watchdog emits no HEARTBEAT of
    its own, so this line is the only liveness signal during flat stretches.
    Twelve minutes of flat readings → 1 permanent line + a 300s-throttled tick
    at minutes 5 and 10, instead of 12 lines."""
    out = _render(_progress_lines(["40"] * 12))
    assert out.count("progress · ") == 3
    assert "elapsed=5m00s" in out and "elapsed=10m00s" in out  # ticks kept
    assert "elapsed=3m00s" not in out  # in-between repeats dropped


def test_each_changed_percentage_gets_its_own_line():
    """Dedup must not swallow real movement — every step still scrolls."""
    out = _render(_progress_lines(["18", "22", "25", "40"]))
    assert out.count("progress · ") == 4
    for pct in ("~18%", "~22%", "~25%", "~40%"):
        assert pct in out


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


def test_budget_and_agent_error_events_are_rendered():
    """Budget kills, maxTurns terminations and agent errors reach the live
    monitor via the tailed logs but had no handler — they were silently dropped
    because render matches event names and ignores the WARN/ERROR column.

    Budget thresholds are reported without a glyph: they are consumption
    notices an operator cannot act on, and a healthy agent crosses 75% on its
    way to finishing. A glyph that fires on the normal case teaches the
    operator to ignore the glyph that does not."""
    out = _render(
        [
            "2026-06-20T15:05:00Z  [abcdef12]  WARN   budget-watchdog   BUDGET_CRITICAL  90% budget consumed  turns=250",
            "2026-06-20T15:06:00Z  [abcdef12]  WARN   budget-watchdog   BUDGET_WARN  75% budget consumed  turns=200",
            "2026-06-20T15:07:00Z  [abcdef12]  ERROR  threat-analyst  MAX_TURNS  Agent terminated — maxTurns limit reached",
            "2026-06-20T15:08:00Z  [abcdef12]  ERROR  evidence-verifier  AGENT_ERROR  all sampled findings failed verification",
        ]
    )
    assert "budget · 90% budget consumed" in out
    assert "budget · 75% budget consumed" in out
    assert "⛔" not in out
    assert "⚠ budget" not in out
    assert "⚠ max turns —" in out
    assert "⚠ agent error —" in out
    assert "turns=250" in out


def test_assessment_models_line_is_rendered():
    out = _render(
        [
            "2026-06-20T15:05:00Z  [--------]  INFO   hook-logger       ASSESSMENT_MODELS"
            "   agents: stride-analyzer=sonnet, recon-scanner=haiku",
        ]
    )
    assert "models · agents: stride-analyzer=sonnet" in out


def test_legacy_agent_invoke_is_not_rendered_as_a_start():
    out = _render(
        [
            "2026-06-06T17:21:26Z  [--------]  INFO   recon-scanner     AGENT_INVOKE"
            "  Reconnaissance scan (model: haiku)",
        ]
    )
    assert out == ""


def test_agent_spawn_strips_repo_root_and_model_field():
    out = _render(
        [
            "2026-06-06T17:20:13Z  [067fff5c]  INFO   AGENT_SPAWN"
            "         appsec-advisor:appsec-threat-analyst         model=sonnet"
            "  Threat Analysis & Triage  [REPO_ROOT=/workspace/juice-shop]",
        ]
    )
    assert "↳ appsec-threat-analyst (sonnet): Threat Analysis & Triage" in out
    assert "REPO_ROOT" not in out


def test_context_v2_agent_spawn_anchors_later_heartbeat_to_phase():
    out = _render(
        [
            "2026-06-06T17:20:13Z  [067fff5c]  INFO   AGENT_SPAWN"
            "         appsec-advisor:appsec-architecture-analyst  model=sonnet"
            "  Architecture analyst: phase3-6-architecture",
            "2026-06-06T17:25:13Z  [--------]  INFO   HEARTBEAT           pid=23  phase=skill  step=watchdog  ts=1",
        ]
    )
    assert "still in Phase 3/11 Architecture — 5m" in out


def test_scan_end_is_a_publication_milestone_not_a_terminal_outcome():
    out = _render(
        [
            "2026-06-06T17:21:26Z  [--------]  INFO   recon-scanner  SCAN_END  Reconnaissance complete",
        ]
    )
    assert "· recon-scanner output ready — Reconnaissance complete" in out
    assert "done" not in out


def test_postfix6_recon_sequence_renders_one_start_and_one_terminal_outcome():
    """Replay of the postfix6 order: spawn, semantic publication, SubagentStop
    terminal, delayed PostToolUse acknowledgement. `SCAN_END` publishes output
    and `AGENT_INVOKE` acknowledges a return — only the call-scoped hook
    lifecycle may render a terminal agent outcome, and only once."""
    out = _render(
        [
            "2026-08-15T04:43:42Z  [b0ba1e2f]  INFO   AGENT_SPAWN"
            "  agent_call_id=toolu_01TkvNUF1iKrgk6L5basHv3Y"
            "  agent_type=appsec-advisor:appsec-recon-scanner  model=sonnet  background=false"
            "  description=Reconnaissance",
            "2026-08-15T04:47:28Z  [--------]  INFO   recon-scanner  SCAN_END  Reconnaissance complete",
            "2026-08-15T04:47:36Z  [b0ba1e2f]  INFO   AGENT_DONE"
            "  agent_call_id=toolu_01TkvNUF1iKrgk6L5basHv3Y"
            "  agent_type=appsec-advisor:appsec-recon-scanner  stop_reason=end_turn",
            "2026-08-15T04:47:40Z  [b0ba1e2f]  INFO   AGENT_INVOKE  agent_call_id=toolu_01TkvNUF1iKrgk6L5basHv3Y",
        ]
    )
    assert out.count("↳ appsec-recon-scanner") == 1
    assert out.count("recon-scanner done") == 1
    assert "output ready" in out
    assert "failed" not in out


def test_agent_spawn_surfaces_stride_tier_from_stripped_param_block():
    """The [KEY=value] block is stripped as noise, but in the default headless
    view this line is the only per-component record — so the tier must be
    lifted out before the strip, not discarded with it. The serialized value is
    `screening`; every view shows the tier as `light`."""
    out = _render(
        [
            "2026-06-06T17:20:13Z  [067fff5c]  INFO   AGENT_SPAWN"
            "         appsec-advisor:appsec-stride-analyzer         model=sonnet"
            "  STRIDE (light): CI/CD Pipeline"
            "  [REPO_ROOT=/workspace/juice-shop  COMPONENT_ID=ci-cd  ANALYSIS_DEPTH=screening]",
        ]
    )
    assert "↳ appsec-stride-analyzer (sonnet, light): STRIDE (light): CI/CD Pipeline" in out
    assert "COMPONENT_ID" not in out


def test_call_scoped_stride_spawn_renders_canonical_full_depth_once():
    line = (
        "2026-08-14T17:20:13Z  [067fff5c]  INFO   AGENT_SPAWN"
        "  agent_call_id=toolu_api  agent_type=appsec-advisor:appsec-stride-analyzer-v2"
        "  model=sonnet  background=true  component_id=api  attempt=1"
        "  analysis_depth=full  description=STRIDE: API"
    )
    out = _render([line, line])
    assert out.count("↳ appsec-stride-analyzer-v2 (sonnet, full): STRIDE: API") == 1
    assert "↳ :" not in out


def test_legacy_agent_invoke_with_depth_is_not_rendered_as_a_start():
    out = _render(
        [
            "2026-06-06T17:21:26Z  [--------]  INFO   stride-analyzer   AGENT_INVOKE"
            "  STRIDE analysis for ci-cd (model: sonnet, MAX_TURNS=8, depth=screening)",
        ]
    )
    assert out == ""


def test_agent_tag_unchanged_for_agents_without_a_tier():
    assert rp._agent_tag("haiku", "") == " (haiku)"
    assert rp._agent_tag("", "") == ""


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


def test_session_bloat_event_renders():
    out = _render(
        [
            "2026-06-20T10:00:00Z  [abcdef12]  WARN   hook-logger  SESSION_BLOAT"
            "  cache_read=19000000  threshold=8000000  choice=continue  mode=interactive",
        ]
    )
    assert "session context bloat" in out
    assert "choice=continue" in out


def test_session_aborted_midrun_event_renders():
    out = _render(
        [
            "2026-06-20T10:00:00Z  [abcdef12]  WARN   skill-session  SESSION_ABORTED_MIDRUN  phase=9  reason=unknown",
        ]
    )
    assert "aborted mid-run" in out
    assert "phase=9" in out


def test_mirrored_phase_boundary_renders_once():
    """`log_event.py` writes PHASE_START/PHASE_END to `.agent-run.log` and
    mirrors it to `.hook-events.log` from the same formatted line; run-headless
    tails both, so the identical line arrives twice and must render once."""
    line = "2026-08-31T08:55:57Z  [--------]  INFO   threat-renderer  PHASE_START  [Phase 11/11] Finalization"
    out = _render([line, line])
    assert out.count("▶ Phase 11/11") == 1


def test_a_repeat_in_a_later_second_is_not_suppressed():
    """Only the mirror is deduplicated. A genuinely repeated event — same text,
    a later timestamp — stays visible; suppressing it would hide a stuck run."""
    out = _render(
        [
            "2026-08-31T08:55:57Z  [--------]  INFO   stride-analyzer  STEP_START  Reading focus path source files",
            "2026-08-31T08:57:57Z  [--------]  INFO   stride-analyzer  STEP_START  Reading focus path source files",
        ]
    )
    assert out.count("Reading focus path source files") == 2


def test_terminal_line_names_the_call_instead_of_echoing_the_dispatch():
    """AGENT_DONE repeats the dispatch parameters the spawn line already showed.
    The view keeps what identifies the finished call and drops the echo."""
    out = _render(
        [
            "2026-08-31T08:17:44Z  [b0ba1e2f]  INFO   AGENT_DONE"
            "  agent_call_id=toolu_01FgPyBi6TshkNrqEszCdxsJ"
            "  agent_type=appsec-advisor:appsec-stride-analyzer-v2  model=sonnet  background=true"
            "  action_id=stage1c:872a05ac10a64c48  job_id=stride:auth-session:attempt-1"
            "  component_id=auth-session  attempt=1  analysis_depth=full"
            "  description=STRIDE (full): auth-session",
        ]
    )
    assert "✓ appsec-stride-analyzer-v2 done (auth-session)" in out
    for echoed in ("toolu_", "action_id", "background=true", "description="):
        assert echoed not in out


def test_terminal_line_keeps_a_reported_stop_reason():
    out = _render(
        [
            "2026-08-15T04:47:36Z  [b0ba1e2f]  INFO   AGENT_DONE"
            "  agent_call_id=toolu_01TkvNUF1iKrgk6L5basHv3Y"
            "  agent_type=appsec-advisor:appsec-recon-scanner  stop_reason=max_turns",
        ]
    )
    assert "✓ appsec-recon-scanner done (reason: max_turns)" in out


def test_a_failure_keeps_its_whole_reason():
    """`agent_lifecycle.event_detail` puts the failure explanation in a free-text
    `reason=` field that runs to the next double space — a trim at the first
    space would leave the failure line saying nothing."""
    out = _render(
        [
            "2026-08-31T08:31:02Z  [b0ba1e2f]  WARN   AGENT_FAILED"
            "  agent_call_id=toolu_015q4jYSPeJmLhF5PvCmTxYg"
            "  agent_type=appsec-advisor:appsec-stride-analyzer-v2  model=sonnet  background=true"
            "  component_id=web3-nft"
            "  reason=call expired without a terminal hook event"
            "  description=STRIDE (full): web3-nft",
        ]
    )
    assert "⚠ appsec-stride-analyzer-v2 failed (web3-nft, reason: call expired without a terminal hook event)" in out
    assert "description=" not in out


def _stride_spawn(ts: str, call_id: str, component: str) -> str:
    return (
        f"2026-08-31T{ts}Z  [b0ba1e2f]  INFO   AGENT_SPAWN  agent_call_id={call_id}"
        f"  agent_type=appsec-advisor:appsec-stride-analyzer-v2  model=sonnet"
        f"  analysis_depth=full  description=STRIDE (full): {component}"
    )


def _stride_done(ts: str, call_id: str, component: str) -> str:
    return (
        f"2026-08-31T{ts}Z  [b0ba1e2f]  INFO   AGENT_DONE  agent_call_id={call_id}"
        f"  agent_type=appsec-advisor:appsec-stride-analyzer-v2  component_id={component}"
    )


def test_stride_tally_counts_finished_components_against_dispatched():
    """Phase 9 runs the analyzers in parallel and interleaves their lines; the
    tally is the only reading of how far the phase has come."""
    out = _render(
        [
            _stride_spawn("08:09:06", "toolu_a", "frontend-spa"),
            _stride_spawn("08:09:17", "toolu_b", "backend-api"),
            _stride_done("08:17:44", "toolu_b", "backend-api"),
            _stride_done("08:20:26", "toolu_a", "frontend-spa"),
        ]
    )
    assert "[STRIDE 1/2 components done]" in out
    assert "[STRIDE 2/2 components done]" in out


def test_stride_tally_rides_along_on_the_phase_9_heartbeat():
    out = _render(
        [
            _stride_spawn("08:09:06", "toolu_a", "frontend-spa"),
            _stride_spawn("08:09:17", "toolu_b", "backend-api"),
            _stride_done("08:17:44", "toolu_b", "backend-api"),
            "2026-08-31T08:22:44Z  [--------]  INFO   HEARTBEAT  step=watchdog",
        ]
    )
    assert "still in Phase 9/11 STRIDE — 13m, STRIDE 1/2 components done" in out


def test_a_non_stride_agent_gets_no_tally():
    out = _render(
        [
            "2026-08-31T08:09:06Z  [b0ba1e2f]  INFO   AGENT_SPAWN  agent_call_id=toolu_c"
            "  agent_type=appsec-advisor:appsec-control-analyst  model=sonnet  description=Control analyst",
            "2026-08-31T08:12:06Z  [b0ba1e2f]  INFO   AGENT_DONE  agent_call_id=toolu_c"
            "  agent_type=appsec-advisor:appsec-control-analyst",
        ]
    )
    assert "STRIDE" not in out


def test_step_line_drops_the_injected_correlation_ids_but_keeps_the_component():
    """`log_event.py` prepends `component= depth= action_id= job_id= attempt=`
    to a component-scoped event. The two ids repeat what `component=` and
    `attempt=` already say and are dropped from the view."""
    out = _render(
        [
            "2026-08-31T08:09:42Z  [--------]  INFO   stride-analyzer  STEP_START"
            "  component=auth-session depth=full action_id=stage1c:872a05ac10a64c48"
            " job_id=stride:auth-session:attempt-1 attempt=1  AGENT_START model=sonnet",
        ]
    )
    assert "component=auth-session depth=full attempt=1  AGENT_START model=sonnet" in out
    assert "action_id" not in out and "job_id" not in out


def test_a_warning_keeps_its_job_id_locator():
    """The step-line strip must not reach a warning: `job_id` is the only thing
    that says which dispatch the mismatch belongs to."""
    out = _render(
        [
            "2026-08-31T08:00:08Z  [b0ba1e2f]  WARN   hook-logger  TELEMETRY_MISMATCH"
            "  code=lifecycle_not_terminal  job_id=phase7-boundary  agent_call_id=toolu_016f5eRBaNTT",
        ]
    )
    assert "job_id=phase7-boundary" in out
    assert "toolu_" not in out
