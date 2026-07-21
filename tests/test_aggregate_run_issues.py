"""Unit tests for scripts/aggregate_run_issues.py — phase pairing + run scoping.

These tests lock in the M3.2 fixes for the bugs surfaced during the
2026-04-26 19:55 ``--rebuild --verbose`` run:

  • Duplicate PHASE_START lines for the same phase number caused
    ``_extract_phase_durations`` to emit two pairs (one against an orphan
    early START, one against the real START), producing a ghost
    "Phase 2 ran 6m 31s" perf anomaly alongside the real "3m 46s".

  • The shared, append-only ``.hook-events.log`` accumulates events
    across runs. Without scoping, the aggregator picked up
    ``SESSION_STOP``, ``BASH_WARN``, etc. from days-old runs and
    reported them as if they happened in the current invocation
    (observed 19/20 ``SESSION_STOP unknown`` events flagged from a
    72h-old log).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "aggregate_run_issues.py"


def _load():
    spec = importlib.util.spec_from_file_location("aggregate_run_issues", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["aggregate_run_issues"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


agg = _load()


# ---------------------------------------------------------------------------
# _extract_phase_durations
# ---------------------------------------------------------------------------


def _line(ts: str, event: str, detail: str) -> str:
    """Build a canonical agent-run.log line."""
    return f"{ts}  [--------]  INFO   threat-analyst  {event}   {detail}"


def test_simple_pair_yields_one_duration():
    log = [
        (1, _line("2026-04-26T17:55:00Z", "PHASE_START", "[Phase 2/11] Reconnaissance")),
        (2, _line("2026-04-26T17:58:00Z", "PHASE_END", "[Phase 2/11] Reconnaissance complete")),
    ]
    out = agg._extract_phase_durations(log)
    assert len(out) == 1
    assert out[0]["phase"] == "2"
    assert out[0]["duration_seconds"] == 180


# ---------------------------------------------------------------------------
# _extract_stride_model_mismatch
# ---------------------------------------------------------------------------


def _stride_invoke(model: str) -> str:
    return (
        "2026-06-22T08:20:00Z  [d95edeed]  INFO   AGENT_INVOKE        "
        f"appsec-advisor:appsec-stride-analyzer        model={model}  "
        "STRIDE: Express Backend  [COMPONENT_ID=express-backend]"
    )


def _write_stride_cfg(tmp_path, stride_model):
    import json

    (tmp_path / ".skill-config.json").write_text(json.dumps({"stride_model": stride_model}), encoding="utf-8")


def test_stride_model_mismatch_flagged_when_sonnet_but_opus_expected(tmp_path):
    _write_stride_cfg(tmp_path, "opus")
    hook = [(1, _stride_invoke("sonnet")), (2, _stride_invoke("sonnet"))]
    out = agg._extract_stride_model_mismatch(tmp_path, hook, [])
    assert len(out) == 1
    assert out[0]["category"] == "stride_model_mismatch"
    assert out[0]["severity"] == "warning"
    assert out[0]["evidence"]["expected_stride_model"] == "opus"
    assert out[0]["evidence"]["observed_models"] == {"sonnet": 2}


def test_stride_model_match_no_issue(tmp_path):
    """Full Opus id resolves to family 'opus' → matches expected → no warning."""
    _write_stride_cfg(tmp_path, "opus")
    hook = [(1, _stride_invoke("claude-opus-4-8"))]
    assert agg._extract_stride_model_mismatch(tmp_path, hook, []) == []


def test_stride_model_no_config_no_issue(tmp_path):
    hook = [(1, _stride_invoke("sonnet"))]
    assert agg._extract_stride_model_mismatch(tmp_path, hook, []) == []


def test_stride_model_no_stride_invokes_no_issue(tmp_path):
    _write_stride_cfg(tmp_path, "opus")
    assert agg._extract_stride_model_mismatch(tmp_path, [], []) == []


# ---------------------------------------------------------------------------
# _extract_stride_ceiling_events (large-repo cap-lift surfacing)
# ---------------------------------------------------------------------------


def _write_selection(tmp_path, sel):
    import json

    (tmp_path / ".stride-selection.json").write_text(json.dumps(sel), encoding="utf-8")


def test_stride_ceiling_lift_is_surfaced(tmp_path):
    _write_selection(
        tmp_path,
        {"ceiling": 10, "lifted": True, "selected": [{"id": f"c{i}"} for i in range(14)], "excluded": []},
    )
    issues = agg._extract_stride_ceiling_events(tmp_path)
    cats = {i["category"] for i in issues}
    assert "stride_ceiling_lifted" in cats
    assert issues[0]["severity"] == "warning"


def test_stride_ceiling_overflow_dropped_is_surfaced(tmp_path):
    _write_selection(
        tmp_path,
        {
            "ceiling": 10,
            "lifted": False,
            "selected": [{"id": f"c{i}"} for i in range(10)],
            "excluded": [
                {"id": "internal-db", "reason": "ceiling-overflow"},
                {"id": "x", "reason": "out-of-scope at depth=standard"},
            ],
        },
    )
    issues = agg._extract_stride_ceiling_events(tmp_path)
    dropped = next(i for i in issues if i["category"] == "stride_ceiling_overflow_dropped")
    assert dropped["evidence"]["dropped_components"] == ["internal-db"]


def test_stride_ceiling_no_event_when_within_budget(tmp_path):
    # The normal case (juice-shop): earned set fits the ceiling, nothing dropped.
    _write_selection(
        tmp_path,
        {
            "ceiling": 10,
            "lifted": False,
            "selected": [{"id": f"c{i}"} for i in range(7)],
            "excluded": [{"id": "x", "reason": "out-of-scope at depth=standard"}],
        },
    )
    assert agg._extract_stride_ceiling_events(tmp_path) == []


def test_stride_ceiling_no_selection_file_no_issue(tmp_path):
    assert agg._extract_stride_ceiling_events(tmp_path) == []


def test_orphan_start_followed_by_real_start_pairs_only_once():
    """Bug #5 from 2026-04-26 19:55 — orphan PHASE_START preceded the real one.

    Pre-M3.2 the aggregator paired BOTH starts with the single end:
      orphan START (17:56:42) ──► END (18:03:13)  → 6m 31s  (false anomaly)
      real   START (17:59:27) ──► END (18:03:13)  → 3m 46s  (real)

    Post-M3.2: only the latest unmatched START before the END pairs.
    """
    log = [
        (1, _line("2026-04-26T17:56:42Z", "PHASE_START", "[Phase 2/11] Reconnaissance")),
        (2, _line("2026-04-26T17:59:27Z", "PHASE_START", "[Phase 2/11] Reconnaissance")),
        (3, _line("2026-04-26T18:03:13Z", "PHASE_END", "[Phase 2/11] Reconnaissance complete")),
    ]
    out = agg._extract_phase_durations(log)
    assert len(out) == 1, "duplicate STARTs must collapse to one duration"
    assert out[0]["duration_seconds"] == 226  # 17:59:27 → 18:03:13


def test_dangling_start_uses_next_start_as_fallback_end():
    """Mid-run crash: a START with no matching END falls back to the next
    START as approximate end (preserves the original behaviour for the
    crash case)."""
    log = [
        (1, _line("2026-04-26T18:00:00Z", "PHASE_START", "[Phase 9/11] STRIDE")),
        (2, _line("2026-04-26T18:05:00Z", "PHASE_START", "[Phase 10/11] Synthesis")),
    ]
    out = agg._extract_phase_durations(log)
    # Both STARTs are "leftover" (no END for either). The first uses the
    # second as approximate end; the second has nothing after it, so it
    # is dropped (consistent with the original behaviour).
    assert len(out) == 1
    assert out[0]["phase"] == "9"
    assert out[0]["duration_seconds"] == 300
    assert out[0]["end_inferred"] is True


def test_multi_phase_run_pairs_correctly():
    log = [
        (1, _line("2026-04-26T18:00:00Z", "PHASE_START", "[Phase 1/11] Context")),
        (2, _line("2026-04-26T18:01:30Z", "PHASE_END", "[Phase 1/11] Context complete")),
        (3, _line("2026-04-26T18:01:35Z", "PHASE_START", "[Phase 2/11] Recon")),
        (4, _line("2026-04-26T18:05:00Z", "PHASE_END", "[Phase 2/11] Recon complete")),
        (5, _line("2026-04-26T18:05:10Z", "PHASE_START", "[Phase 9/11] STRIDE")),
        (6, _line("2026-04-26T18:11:00Z", "PHASE_END", "[Phase 9/11] STRIDE complete")),
    ]
    out = agg._extract_phase_durations(log)
    durations = {p["phase"]: p["duration_seconds"] for p in out}
    assert durations == {"1": 90, "2": 205, "9": 350}


# ---------------------------------------------------------------------------
# _scope_to_current_run
# ---------------------------------------------------------------------------


def test_scope_drops_old_lines_outside_window():
    """Lines older than RUN_WINDOW_SECONDS before the latest event are dropped."""
    # Oldest event (4h ago) — should be dropped.
    # Recent events — should be kept.
    log = [
        (1, _line("2026-04-26T14:00:00Z", "SESSION_STOP", "stop_reason=unknown  in=10  out=20  cost=$0.10")),
        (2, _line("2026-04-26T17:55:00Z", "SCAN_START", "repo=/x  agent=foo  model=sonnet")),
        (3, _line("2026-04-26T17:56:00Z", "FILE_WRITE", "/x/.recon-summary.md  (1000 chars)")),
        (4, _line("2026-04-26T18:00:00Z", "ASSESSMENT_END", "complete")),
    ]
    scoped = agg._scope_to_current_run(log)
    line_nos = [ln for ln, _ in scoped]
    assert 1 not in line_nos, "stale 14:00 event must be dropped"
    assert {2, 3, 4}.issubset(set(line_nos))


def test_scope_keeps_everything_when_no_timestamps():
    """Legacy logs without parseable timestamps are returned unchanged."""
    log = [
        (1, "garbage line 1"),
        (2, "garbage line 2"),
    ]
    scoped = agg._scope_to_current_run(log)
    assert scoped == log


def test_scope_keeps_everything_when_log_short_and_recent():
    """A normal in-progress run with all events within the 90 min window
    is returned unchanged."""
    log = [
        (1, _line("2026-04-26T17:55:00Z", "SCAN_START", "...")),
        (2, _line("2026-04-26T17:56:00Z", "PHASE_START", "[Phase 1/11] Context")),
        (3, _line("2026-04-26T18:30:00Z", "FILE_WRITE", "/x/threat-model.md  (1000 chars)")),
    ]
    scoped = agg._scope_to_current_run(log)
    assert len(scoped) == 3


def test_scope_window_is_90_minutes():
    """Hard-coded contract: window is 5400 s (1.5 h)."""
    assert agg._RUN_WINDOW_SECONDS == 5400


def test_scope_handles_empty_input():
    assert agg._scope_to_current_run([]) == []


# ---------------------------------------------------------------------------
# Sprint 4B — scale_phase_limits + repo-size-aware perf anomalies
# ---------------------------------------------------------------------------


class TestScalePhaseLimits:
    """Pin the budget-scaler formula `factor = 1 + log10(max(n/100, 1))`."""

    def test_small_repo_returns_base_unchanged(self):
        base = {"1": 60, "2": 120, "9": 180}
        out = agg.scale_phase_limits(base, file_count=50)
        assert out == base, "≤100 files → factor 1.0 → no change"

    def test_factor_at_threshold_is_one(self):
        base = {"1": 60}
        out = agg.scale_phase_limits(base, file_count=100)
        assert out == base

    def test_negative_count_treated_as_zero(self):
        base = {"1": 60}
        assert agg.scale_phase_limits(base, file_count=-42) == base

    def test_non_numeric_count_treated_as_zero(self):
        base = {"1": 60}
        assert agg.scale_phase_limits(base, file_count="not a number") == base  # type: ignore[arg-type]

    def test_huge_repo_capped_by_log_growth(self):
        """Even 50000 files give a modest factor (~3.7), not exponential."""
        base = {"1": 60}
        out = agg.scale_phase_limits(base, file_count=50_000)
        # 1 + log10(500) ≈ 3.699 → 60 * 3.699 ≈ 222
        assert 200 <= out["1"] <= 240


class TestEconomyModelPerfFactor:
    """sonnet-economy slows the model-bound recon phases (1, 2); the perf
    threshold must widen for them so an economy run does not false-flag.
    """

    def _phase_dur(self, phase: str, dur: int) -> dict:
        return {
            "phase": phase,
            "duration_seconds": dur,
            "label": f"Phase {phase} test",
            "start_line": 4,
            "start_ts": "2026-05-31T14:26:07Z",
            "end_ts": "2026-05-31T14:34:21Z",
            "end_inferred": False,
        }

    def test_economy_widens_recon_budget(self):
        base2 = agg.PHASE_DURATION_LIMITS_SECONDS["standard"]["2"]
        # A duration 1.3× over the base budget: flagged WITHOUT economy
        # (mult ≥ 1.20, slack ≥ 30s for base ≥ 100s), suppressed WITH it.
        dur = int(base2 * 1.3)
        without = agg._extract_perf_anomalies([self._phase_dur("2", dur)], "standard")
        assert len(without) == 1, "size-only budget should flag a 1.3× overshoot"
        with_eco = agg._extract_perf_anomalies([self._phase_dur("2", dur)], "standard", economy=True)
        assert with_eco == [], "economy factor (×1.5) should absorb a 1.3× overshoot on phase 2"

    def test_economy_does_not_scale_orchestrator_phases(self):
        base9 = agg.PHASE_DURATION_LIMITS_SECONDS["standard"]["9"]
        dur = int(base9 * 1.3)
        # Phase 9 runs on sonnet regardless of reasoning tier → economy must
        # NOT widen its budget; the overshoot stays flagged.
        flagged = agg._extract_perf_anomalies([self._phase_dur("9", dur)], "standard", economy=True)
        assert len(flagged) == 1, "phase 9 is not economy-bound; overshoot must still flag"


# ---------------------------------------------------------------------------
# Sprint 4C — session_stop_unknown filter (skip when output_tokens > 0)
# ---------------------------------------------------------------------------


class TestSessionStopUnknownFilter:
    """Pin the Sprint-4C noise filter: `unknown` with output > 0 = normal."""

    def _stop_line(self, out_tokens: int, reason: str = "unknown") -> str:
        ts = "2026-04-27T18:10:12Z"
        detail = (
            f"stop_reason={reason}  in=131  out={out_tokens:,}  cache_write=297,927  cache_read=2,612,375  cost=$2.1882"
        )
        return f"{ts}  [--------]  INFO   threat-analyst  SESSION_STOP   {detail}"

    def test_unknown_with_moderate_output_is_skipped(self):
        """Real Subscription-mode sub-agent stops produce stop_reason=unknown
        with moderate non-zero output (a few thousand to ~50k tokens).
        Filter must drop them."""
        log = [(1, self._stop_line(out_tokens=19_123))]
        issues = agg._extract_session_stop_anomalies(log)
        assert issues == [], (
            f"unknown + moderate output is normal; expected zero issues, got {[i['title'] for i in issues]}"
        )

    def test_unknown_with_high_output_still_flagged(self):
        """Output > 50k is independently interesting even with stop=unknown —
        a 50k+ token session that cannot say why it ended is worth a look.
        Pre-Sprint-4C the test_run_issues_pipeline regression caught this."""
        log = [(1, self._stop_line(out_tokens=399_660))]
        issues = agg._extract_session_stop_anomalies(log)
        assert len(issues) == 1, f"high-output unknown stop must still warn; got {issues}"

    def test_unknown_with_zero_output_is_flagged(self):
        """A genuinely-suspicious case: session ended without output —
        could be budget exhaustion or crash. Must still warn."""
        log = [(1, self._stop_line(out_tokens=0))]
        issues = agg._extract_session_stop_anomalies(log)
        assert len(issues) == 1
        assert issues[0]["category"] == "session_stop_unknown"

    def test_high_output_token_stop_still_flagged(self):
        """`output_tokens > SUBAGENT_OUTPUT_TOKEN_WARN` (50k) always emits
        a high_token_usage warning, regardless of stop_reason."""
        log = [(1, self._stop_line(out_tokens=99_999, reason="end_turn"))]
        issues = agg._extract_session_stop_anomalies(log)
        assert len(issues) == 1
        assert issues[0]["category"] == "high_token_usage"

    def test_cumulative_snapshots_collapse_to_one(self):
        """RC-5 (2026-06-21 juice-shop): SESSION_STOP fires repeatedly for the
        SAME session with a growing cumulative `out`. The aggregator must
        collapse those snapshots to a single final entry per source, not emit
        one warning per snapshot (18 → 1)."""
        log = [(i, self._stop_line(out_tokens=100_000 + i * 5_000)) for i in range(1, 19)]
        issues = agg._extract_session_stop_anomalies(log)
        assert len(issues) == 1, f"expected 1 collapsed issue, got {len(issues)}"
        ev = issues[0]["evidence"]
        assert ev["output_tokens"] == 100_000 + 18 * 5_000  # final/max snapshot kept
        assert ev["folded_snapshots"] == 18
        assert "final of 18 cumulative snapshots" in issues[0]["title"]

    def test_distinct_sources_not_collapsed_together(self):
        """Two different source agents each keep their own (final) entry."""
        a = self._stop_line(out_tokens=120_000).replace("threat-analyst", "threat-analyst")
        b = self._stop_line(out_tokens=130_000).replace("threat-analyst", "threat-renderer")
        log = [(1, a), (2, b)]
        issues = agg._extract_session_stop_anomalies(log)
        assert {i["evidence"]["source_agent"] for i in issues} == {"threat-analyst", "threat-renderer"}

    def _assessment_end(self, detail: str) -> str:
        ts = "2026-06-27T17:41:16Z"
        return f"{ts}  [--------]  INFO   threat-analyst  ASSESSMENT_END   {detail}"

    def test_planned_exit_any_assessment_end_skips_high_output_unknown(self):
        """RC (2026-06-27): an agent that logged ANY ASSESSMENT_END completed its
        planned work — its high-token cumulative unknown stop is not exhaustion.
        The Analyst-A/B planned exits use descriptive text without the literal
        STAGE1_PHASE_LIMIT token, so the old token-only guard mis-flagged them."""
        log = [
            (1, self._assessment_end("Analyst-B complete — Stage 1 done, need_render=true")),
            (2, self._stop_line(out_tokens=148_786)),
        ]
        issues = agg._extract_session_stop_anomalies(log)
        assert issues == [], f"planned-exit source must skip; got {[i['title'] for i in issues]}"

    def test_planned_exit_source_still_flags_zero_output_crash(self):
        """A planned ASSESSMENT_END must NOT mask a later out==0 crash stop —
        a genuine kill dies mid-phase with no output, which is still surfaced."""
        log = [
            (1, self._assessment_end("Analyst-A complete — Phases 1-8 done")),
            (2, self._stop_line(out_tokens=0)),
        ]
        issues = agg._extract_session_stop_anomalies(log)
        assert len(issues) == 1
        assert issues[0]["category"] == "session_stop_unknown"

    def test_high_output_unknown_without_assessment_end_still_flagged(self):
        """No ASSESSMENT_END for the source → not a proven planned exit → a
        50k+ unknown stop remains worth a look (unchanged behaviour)."""
        log = [(1, self._stop_line(out_tokens=148_786))]
        issues = agg._extract_session_stop_anomalies(log)
        assert len(issues) == 1
        assert issues[0]["category"] == "session_stop_unknown"


# ---------------------------------------------------------------------------
# _extract_gate_events — persistent gate artifacts (2026-06-12 blind spot)
# ---------------------------------------------------------------------------


class TestExtractGateEvents:
    def test_unresolved_contract_repair_plan_flagged(self, tmp_path):
        (tmp_path / ".qa-repair-plan.json").write_text(
            '{"status":"fail","issue_count":1,"actions":'
            '[{"type":"missing_section","heading":"## 4. Assets","section_id":"assets"}]}',
            encoding="utf-8",
        )
        issues = agg._extract_gate_events(tmp_path)
        assert any(i["category"] == "contract_gate_drift" for i in issues)
        i = next(i for i in issues if i["category"] == "contract_gate_drift")
        assert i["severity"] == "warning"
        assert "## 4. Assets" in i["evidence"]["items"]

    def test_non_pass_qa_status_flagged(self, tmp_path):
        (tmp_path / ".qa-status.json").write_text('{"status":"fail"}', encoding="utf-8")
        issues = agg._extract_gate_events(tmp_path)
        assert any(i["category"] == "qa_status_not_pass" for i in issues)

    def test_inline_shortcut_plan_flagged_as_error(self, tmp_path):
        (tmp_path / ".inline-shortcut-repair-plan.json").write_text("{}", encoding="utf-8")
        issues = agg._extract_gate_events(tmp_path)
        i = next(i for i in issues if i["category"] == "inline_shortcut_unresolved")
        assert i["severity"] == "error"

    def test_clean_run_yields_no_gate_issues(self, tmp_path):
        # The shape a clean run leaves: qa-status=pass, no repair plans.
        (tmp_path / ".qa-status.json").write_text('{"status":"pass"}', encoding="utf-8")
        assert agg._extract_gate_events(tmp_path) == []

    def test_stale_repair_plan_superseded_by_newer_pass_is_skipped(self, tmp_path):
        """RC (2026-06-27): under --keep-runtime-files (cleanup skipped) or an
        out-of-order gate sequence, a repair plan survives on disk after the
        gate later recorded `pass`. A `.qa-status.json:{pass}` at least as new as
        the plan proves the drift was resolved → the plan is stale, not live."""
        import os

        plan = tmp_path / ".qa-repair-plan.json"
        plan.write_text(
            '{"status":"fail","issue_count":1,"actions":[{"type":"x","heading":"## Critical Attack Tree"}]}',
            encoding="utf-8",
        )
        status = tmp_path / ".qa-status.json"
        status.write_text('{"status":"pass"}', encoding="utf-8")
        # qa-status written AFTER the plan → plan superseded.
        os.utime(plan, (1000, 1000))
        os.utime(status, (2000, 2000))
        issues = agg._extract_gate_events(tmp_path)
        assert not any(i["category"] == "contract_gate_drift" for i in issues)

    def test_live_repair_plan_newer_than_pass_still_flagged(self, tmp_path):
        """A plan written AFTER a passing status is a genuine re-trip — the gate
        found fresh drift, so it must still be flagged (no false suppression)."""
        import os

        plan = tmp_path / ".qa-repair-plan.json"
        plan.write_text(
            '{"status":"fail","issue_count":1,"actions":[{"type":"x","heading":"H"}]}',
            encoding="utf-8",
        )
        status = tmp_path / ".qa-status.json"
        status.write_text('{"status":"pass"}', encoding="utf-8")
        # Plan newer than the passing status → live drift.
        os.utime(status, (1000, 1000))
        os.utime(plan, (2000, 2000))
        issues = agg._extract_gate_events(tmp_path)
        assert any(i["category"] == "contract_gate_drift" for i in issues)


# ---------------------------------------------------------------------------
# Aborted-mid-run phase duration is not a perf anomaly (2026-06-27)
# ---------------------------------------------------------------------------


class TestAbortedMidrunPerfSkip:
    """A phase whose [start, end] window straddles a SESSION_ABORTED_MIDRUN is
    not a contiguous compute window — its duration is the dead abort→resume gap
    (watchdog heartbeats only), not slow work, so it must not perf-flag."""

    def _l(self, ts: str, event: str, detail: str) -> str:
        return f"{ts}  [--------]  INFO   threat-analyst  {event}   {detail}"

    def test_phase_with_midrun_abort_flagged_and_skipped(self):
        log = [
            (1, self._l("2026-06-27T17:26:19Z", "PHASE_START", "[Phase 10b/11] Triage Validation")),
            (2, self._l("2026-06-27T17:26:37Z", "SESSION_ABORTED_MIDRUN", "session ended mid-run")),
            (3, self._l("2026-06-27T17:39:36Z", "PHASE_END", "[Phase 10b/11] Triage Validation")),
        ]
        durs = agg._extract_phase_durations(log)
        assert durs and durs[0]["aborted_midrun"] is True
        # 13m17s wall but abort-inflated → no perf anomaly at quick (limit 60s).
        assert agg._extract_perf_anomalies(durs, "quick") == []

    def test_clean_slow_phase_without_abort_still_flagged(self):
        # Same 13min span, NO abort → a genuinely slow phase, still flagged.
        log = [
            (1, self._l("2026-06-27T17:26:19Z", "PHASE_START", "[Phase 10b/11] Triage Validation")),
            (2, self._l("2026-06-27T17:39:36Z", "PHASE_END", "[Phase 10b/11] Triage Validation")),
        ]
        durs = agg._extract_phase_durations(log)
        assert durs and durs[0].get("aborted_midrun") is False
        issues = agg._extract_perf_anomalies(durs, "quick")
        assert any(i["category"] == "perf_anomaly_phase" for i in issues)

    def test_aggregate_surfaces_drift_instead_of_clean(self, tmp_path):
        """End-to-end: a completed run that left an unresolved repair plan must
        NOT be reported as run_status=clean (the 2026-06-12 regression)."""
        (tmp_path / ".qa-repair-plan.json").write_text(
            '{"status":"fail","issue_count":1,"actions":[]}', encoding="utf-8"
        )
        data = agg.aggregate(tmp_path, "quick")
        assert data["run_status"] == "issues"
        assert any(i["category"] == "contract_gate_drift" for i in data["issues"])


# ---------------------------------------------------------------------------
# Coverage extension: parsers, helpers, extractors, CLI
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402


def _hline(ts: str, event: str, detail: str, source: str = "post-tool") -> str:
    """Canonical hook-events.log line (5-field-ish, same regex)."""
    return f"{ts}  [--------]  WARN   {source}  {event}   {detail}"


class TestParseHelpers:
    def test_parse_iso_valid(self):
        assert agg._parse_iso("2026-04-26T17:55:00Z") is not None

    def test_parse_iso_invalid_returns_none(self):
        assert agg._parse_iso("nonsense") is None

    def test_parse_event_line_non_matching(self):
        assert agg._parse_event_line("garbage line no fields") is None

    def test_read_log_missing_file(self, tmp_path):
        assert agg._read_log(tmp_path / "nope.log") == []

    def test_read_log_reads_lines(self, tmp_path):
        p = tmp_path / "x.log"
        p.write_text("a\nb\n", encoding="utf-8")
        assert agg._read_log(p) == [(1, "a"), (2, "b")]

    def test_read_log_oserror_returns_empty(self, tmp_path, monkeypatch):
        p = tmp_path / "x.log"
        p.write_text("a\n", encoding="utf-8")

        def _boom(*a, **k):
            raise OSError("io error")

        monkeypatch.setattr(Path, "open", _boom)
        assert agg._read_log(p) == []

    def test_clip_short_and_long(self):
        assert agg._clip("hi", 80) == "hi"
        clipped = agg._clip("x" * 100, 10)
        assert clipped.endswith("…") and len(clipped) == 10

    def test_clip_none(self):
        assert agg._clip(None, 5) == ""  # type: ignore[arg-type]

    def test_fmt_dur_sub_minute(self):
        assert agg._fmt_dur(45) == "45s"

    def test_fmt_dur_minutes(self):
        assert agg._fmt_dur(125) == "2m 05s"

    def test_now_iso_z_format(self):
        assert agg._now_iso_z().endswith("Z")


class TestPhaseDurationsTsNone:
    def test_phase_start_with_bad_ts_skipped(self):
        # Structurally valid PHASE_START line whose timestamp won't parse:
        # _parse_iso returns None -> START not recorded (line 365 branch).
        log = [
            (1, "garbage unparseable line"),  # hits `if not ev: continue`
            (2, "notatime  [--------]  INFO   src  PHASE_START   [Phase 1/11] X"),
            (3, _line("2026-04-26T18:00:10Z", "PHASE_END", "[Phase 1/11] X")),
        ]
        # No usable START -> no pairs.
        assert agg._extract_phase_durations(log) == []


class TestScopeUnparseableTail:
    def test_unparseable_line_kept(self):
        # A parseable recent line establishes latest_ts; an unparseable
        # continuation line is kept (lines 308-309 branch).
        log = [
            (1, _line("2026-04-26T17:55:00Z", "PHASE_START", "[Phase 1/11] X")),
            (2, "   continuation payload with no fields"),
        ]
        scoped = agg._scope_to_current_run(log)
        assert (2, "   continuation payload with no fields") in scoped

    def test_line_with_unparseable_ts_field_dropped_when_old(self):
        # parseable structure but ts cannot be parsed -> _parse_iso None.
        good = _line("2026-04-26T18:00:00Z", "PHASE_START", "[Phase 1/11] X")
        badts = "notatimestamp  [--------]  INFO   src  EVENT   detail"
        scoped = agg._scope_to_current_run([(1, good), (2, badts)])
        # bad-ts line is structurally parseable but ts None -> kept (>= cutoff path)
        assert any(r[0] == 2 for r in scoped)


class TestCountRepoFiles:
    def test_git_ls_files_path(self, tmp_path, monkeypatch):
        import subprocess

        class _R:
            returncode = 0
            stdout = "a.py\nb.js\n\n"

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _R())
        assert agg._count_repo_files(tmp_path) == 2

    def test_fallback_walk_on_git_failure(self, tmp_path, monkeypatch):
        import subprocess

        def _boom(*a, **k):
            raise FileNotFoundError("no git")

        monkeypatch.setattr(subprocess, "run", _boom)
        (tmp_path / "a.py").write_text("x", encoding="utf-8")
        (tmp_path / "b.txt").write_text("x", encoding="utf-8")  # excluded ext
        assert agg._count_repo_files(tmp_path) == 1


class TestRunUsedEconomyModel:
    def test_economy_config(self, tmp_path):
        (tmp_path / ".skill-config.json").write_text(
            _json.dumps({"reasoning_model": "sonnet-economy"}), encoding="utf-8"
        )
        assert agg._run_used_economy_model(tmp_path) is True

    def test_missing_config(self, tmp_path):
        assert agg._run_used_economy_model(tmp_path) is False

    def test_malformed_config(self, tmp_path):
        (tmp_path / ".skill-config.json").write_text("{bad json", encoding="utf-8")
        assert agg._run_used_economy_model(tmp_path) is False


class TestExtractErrors:
    def test_tool_error_and_max_turns(self):
        hook = [(1, _hline("2026-04-26T18:00:00Z", "TOOL_ERROR", "boom failed"))]
        agent = [(2, _line("2026-04-26T18:00:01Z", "MAX_TURNS", "agent exhausted"))]
        issues = agg._extract_errors(hook, agent)
        cats = {i["category"] for i in issues}
        assert cats == {"tool_error", "max_turns_subagent"}
        assert all(i["severity"] == "error" for i in issues)

    def test_unparseable_lines_ignored(self):
        assert agg._extract_errors([(1, "junk")], [(1, "junk")]) == []


class TestExtractBudgetEvents:
    def test_wrap_up_and_budget_critical(self):
        agent = [
            (1, _line("2026-04-26T18:00:00Z", "WRAP_UP_TRIGGERED", "renderer wound down")),
            (2, _line("2026-04-26T18:00:01Z", "BUDGET_CRITICAL", "90% turns")),
        ]
        issues = agg._extract_budget_events(agent)
        cats = {i["category"] for i in issues}
        assert cats == {"wrap_up_triggered", "budget_critical"}
        assert all(i["severity"] == "warning" for i in issues)

    def test_irrelevant_event_skipped(self):
        assert agg._extract_budget_events([(1, _line("2026-04-26T18:00:00Z", "PHASE_START", "x"))]) == []


class TestExtractWarnings:
    def test_bash_warn_flagged(self):
        hook = [(1, _hline("2026-04-26T18:00:00Z", "BASH_WARN", "error: something"))]
        issues = agg._extract_warnings(hook)
        assert len(issues) == 1
        assert issues[0]["category"] == "bash_warn"

    def test_other_event_ignored(self):
        assert agg._extract_warnings([(1, _hline("2026-04-26T18:00:00Z", "OTHER", "x"))]) == []


class TestPerfAnomaliesCeilingAndHysteresis:
    def _pd(self, phase, dur, label="Lbl"):
        return {
            "phase": phase,
            "label": label,
            "duration_seconds": dur,
            "start_line": 1,
            "start_ts": "t0",
            "end_ts": "t1",
            "end_inferred": False,
        }

    def test_hard_ceiling_phase_1_category(self):
        issues = agg._extract_perf_anomalies([self._pd("1", 2000)], "standard")
        assert issues and issues[0]["category"] == "stage1_excessive_duration"
        assert issues[0]["severity"] == "error"

    def test_hard_ceiling_other_phase_category(self):
        issues = agg._extract_perf_anomalies([self._pd("9", 2000)], "standard")
        assert issues[0]["category"] == "perf_anomaly_phase"

    def test_micro_overshoot_skipped(self):
        # standard phase 2 budget = 180; 190s is <1.20x and <30s slack -> skip
        issues = agg._extract_perf_anomalies([self._pd("2", 190)], "standard")
        assert issues == []

    def test_genuine_overshoot_flagged_warning(self):
        # 180 * 1.5 = 270 -> >=1.2x and >=30s slack
        issues = agg._extract_perf_anomalies([self._pd("2", 270)], "standard")
        assert issues and issues[0]["severity"] == "warning"
        assert "multiplier" in issues[0]["evidence"]

    def test_unknown_depth_falls_back_to_standard(self):
        issues = agg._extract_perf_anomalies([self._pd("2", 270)], "bogusdepth")
        assert issues and issues[0]["severity"] == "warning"

    def test_file_count_scales_budget(self):
        # large repo widens budget so the same dur is no longer over
        issues = agg._extract_perf_anomalies([self._pd("2", 270)], "standard", file_count=5000)
        assert issues == []


class TestSessionStopCostParse:
    def test_non_numeric_out_field_fails_regex_and_is_skipped(self):
        # _SESSION_STOP_RE out= only matches [\d,]+, so a non-numeric out=
        # value makes the whole regex fail -> the line is skipped.
        # (Pins current behavior; the int() ValueError guard is unreachable.)
        line = (
            "2026-04-26T18:00:00Z  [--------]  INFO   orchestrator  SESSION_STOP   "
            "stop_reason=unknown in=1,000 out=abc cost=$0.05"
        )
        assert agg._extract_session_stop_anomalies([(1, line)]) == []

    def test_no_session_stop_match_skipped(self):
        line = _line("2026-04-26T18:00:00Z", "SESSION_STOP", "no structured fields here")
        assert agg._extract_session_stop_anomalies([(1, line)]) == []

    def test_non_session_stop_event_skipped(self):
        assert (
            agg._extract_session_stop_anomalies([(1, _line("2026-04-26T18:00:00Z", "PHASE_END", "[Phase 1/11] x"))])
            == []
        )


class TestExtractRecoveryEvents:
    def test_inline_retry_counter(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("2", encoding="utf-8")
        issues = agg._extract_recovery_events(tmp_path)
        assert any(i["category"] == "auto_retry_fired" for i in issues)

    def test_inline_retry_zero_ignored(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("0", encoding="utf-8")
        assert agg._extract_recovery_events(tmp_path) == []

    def test_inline_retry_malformed(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("not-int", encoding="utf-8")
        assert agg._extract_recovery_events(tmp_path) == []

    def test_compose_section_retries(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text(
            _json.dumps({"section_retries": {"7": 2, "8": 1}}), encoding="utf-8"
        )
        issues = agg._extract_recovery_events(tmp_path)
        cats = [i for i in issues if i["category"] == "compose_retries_section"]
        # only sid '7' (n>1) flagged
        assert len(cats) == 1 and cats[0]["evidence"]["section"] == "7"

    def test_compose_stats_malformed(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text("{bad", encoding="utf-8")
        assert agg._extract_recovery_events(tmp_path) == []

    def test_compose_stats_non_dict(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text("[]", encoding="utf-8")
        assert agg._extract_recovery_events(tmp_path) == []


class TestExtractAbuseCaseOutcomes:
    def test_missing_file_returns_empty(self, tmp_path):
        assert agg._extract_abuse_case_outcomes(tmp_path) == []

    def test_malformed_json(self, tmp_path):
        (tmp_path / ".abuse-case-verdicts.json").write_text("{bad", encoding="utf-8")
        assert agg._extract_abuse_case_outcomes(tmp_path) == []

    def test_inconclusive_chain_flagged(self, tmp_path):
        (tmp_path / ".abuse-case-verdicts.json").write_text(
            _json.dumps(
                {
                    "verdicts": [
                        {
                            "abuse_case_id": "AC-001",
                            "title": "Token replay",
                            "step_verdicts": [
                                {"verdict": "confirmed"},
                                {"verdict": "inconclusive"},
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        issues = agg._extract_abuse_case_outcomes(tmp_path)
        assert len(issues) == 1
        assert issues[0]["category"] == "abuse_case_inconclusive"
        assert issues[0]["evidence"]["inconclusive_steps"] == 1

    def test_blocked_step_closes_chain(self, tmp_path):
        (tmp_path / ".abuse-case-verdicts.json").write_text(
            _json.dumps(
                {
                    "verdicts": [
                        {
                            "abuse_case_id": "AC-002",
                            "step_verdicts": [
                                {"verdict": "inconclusive"},
                                {"verdict": "blocked"},
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        assert agg._extract_abuse_case_outcomes(tmp_path) == []

    def test_non_dict_verdict_entries_skipped(self, tmp_path):
        (tmp_path / ".abuse-case-verdicts.json").write_text(
            _json.dumps({"verdicts": ["bad", {"step_verdicts": [{"verdict": "inconclusive"}]}]}),
            encoding="utf-8",
        )
        issues = agg._extract_abuse_case_outcomes(tmp_path)
        assert len(issues) == 1


class TestGateEventsExtraBranches:
    def test_qa_plan_malformed_json(self, tmp_path):
        (tmp_path / ".qa-repair-plan.json").write_text("{bad", encoding="utf-8")
        # malformed -> plan {} -> no status -> no issue from branch 1
        assert agg._extract_gate_events(tmp_path) == []

    def test_qa_status_malformed_json(self, tmp_path):
        (tmp_path / ".qa-status.json").write_text("{bad", encoding="utf-8")
        assert agg._extract_gate_events(tmp_path) == []

    def test_qa_status_pass_no_issue(self, tmp_path):
        (tmp_path / ".qa-status.json").write_text('{"status":"pass"}', encoding="utf-8")
        assert agg._extract_gate_events(tmp_path) == []


class TestAggregateInference:
    def test_repo_root_from_env(self, tmp_path, monkeypatch):
        out = tmp_path / "docs" / "security"
        out.mkdir(parents=True)
        monkeypatch.setenv("REPO_ROOT", str(tmp_path))
        data = agg.aggregate(out, "quick")
        assert data["run_status"] == "clean"
        assert data["assessment_depth"] == "quick"

    def test_clean_run_structure(self, tmp_path):
        data = agg.aggregate(tmp_path, "standard")
        assert data["schema_version"] == agg.SCHEMA_VERSION
        assert data["summary"]["errors"] == 0


class TestMainCLI:
    def test_output_dir_not_directory(self, tmp_path, capsys):
        rc = agg.main([str(tmp_path / "nope")])
        assert rc == 1
        assert "not a directory" in capsys.readouterr().err

    def test_no_recommend_writes_file(self, tmp_path, capsys):
        rc = agg.main([str(tmp_path), "--depth", "quick", "--no-recommend"])
        assert rc == 0
        out = _json.loads((tmp_path / ".run-issues.json").read_text(encoding="utf-8"))
        assert out["run_status"] == "clean"
        assert "run-issues:" in capsys.readouterr().out

    def test_recommend_enrichment_attempted(self, tmp_path, monkeypatch, capsys):
        # Force the import to fail so we hit the except branch (warning).
        monkeypatch.setitem(sys.modules, "recommend_fixes", None)
        rc = agg.main([str(tmp_path), "--depth", "standard"])
        # Either enrichment ran or warning printed — both return 0 & write file.
        assert rc == 0
        assert (tmp_path / ".run-issues.json").is_file()

    def test_enrichment_runs_when_available(self, tmp_path):
        # Default path (no --no-recommend) imports recommend_fixes and calls
        # enrich_with_recommendations (line 1003). recommend_fixes imports
        # cleanly in this repo, so enrichment runs on a clean run dir.
        rc = agg.main([str(tmp_path), "--depth", "quick"])
        assert rc == 0
        out = _json.loads((tmp_path / ".run-issues.json").read_text(encoding="utf-8"))
        assert out["run_status"] == "clean"

    def test_write_failure_returns_1(self, tmp_path, monkeypatch, capsys):
        # Make write_text raise OSError to hit the error branch.
        orig = Path.write_text

        def _fail(self, *a, **k):
            if self.name == ".run-issues.json":
                raise OSError("disk full")
            return orig(self, *a, **k)

        monkeypatch.setattr(Path, "write_text", _fail)
        rc = agg.main([str(tmp_path), "--no-recommend"])
        assert rc == 1
        assert "cannot write" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# reconcile_recovered_events + RUN_RECONCILED annotation
# ---------------------------------------------------------------------------


def _abort(phase: str) -> str:
    return f"2026-07-16T08:00:00Z  [--------]  WARN   threat-analyst  SESSION_ABORTED_MIDRUN   phase={phase}  reason=unknown"


def test_reconcile_all_recovered_when_run_completed(tmp_path):
    # 2 mid-run stops + 1 build-FATAL, but a later build succeeded and the
    # deliverable exists → everything recovered, nothing unrecovered.
    (tmp_path / "threat-model.md").write_text("# report", encoding="utf-8")
    log = [
        (1, _abort("8")),
        (2, "FATAL: schema validation failed"),
        (3, "✓ threat-model.yaml built deterministically — 68 threats"),
        (4, _abort("11")),
    ]
    rec = agg.reconcile_recovered_events(log, tmp_path)
    assert rec == {
        "mid_run_stops": 2,
        "transient_build_fatals": 1,
        "run_completed": True,
        "unrecovered": 0,
    }


def test_reconcile_flags_unrecovered_when_no_completion(tmp_path):
    # A build-FATAL with no successful rebuild and no deliverable → unrecovered.
    log = [
        (1, _abort("10b")),
        (2, "FATAL: schema validation failed"),
    ]
    rec = agg.reconcile_recovered_events(log, tmp_path)
    assert rec["run_completed"] is False
    assert rec["transient_build_fatals"] == 0  # the FATAL was NOT recovered
    assert rec["unrecovered"] == 2  # 1 abort (no completion) + 1 unrecovered FATAL


def test_append_reconciliation_writes_all_clear_line(tmp_path):
    log_path = tmp_path / ".agent-run.log"
    log_path.write_text("existing\n", encoding="utf-8")
    agg._append_reconciliation_line(
        tmp_path, {"mid_run_stops": 3, "transient_build_fatals": 1, "run_completed": True, "unrecovered": 0}
    )
    tail = log_path.read_text(encoding="utf-8")
    assert "RUN_RECONCILED" in tail
    assert "all recovered" in tail
    assert "INFO" in tail.splitlines()[-1]


def test_append_reconciliation_silent_when_nothing_transient(tmp_path):
    log_path = tmp_path / ".agent-run.log"
    log_path.write_text("existing\n", encoding="utf-8")
    agg._append_reconciliation_line(
        tmp_path, {"mid_run_stops": 0, "transient_build_fatals": 0, "run_completed": True, "unrecovered": 0}
    )
    assert log_path.read_text(encoding="utf-8") == "existing\n"  # untouched


# ---------------------------------------------------------------------------
# _extract_run_outcome — a run that produced no deliverable must be flagged even
# without an abort/FATAL log signature. Regression for the 2026-07-21 juice-shop
# run: a subscription usage-limit kill left neither SESSION_ABORTED_MIDRUN nor a
# build FATAL, so `unrecovered` was 0 and the run aggregated to "clean" despite
# producing no threat-model.md.
# ---------------------------------------------------------------------------


def test_run_outcome_flags_external_stop_after_analysis_started(tmp_path):
    # A clean external kill: no abort, no FATAL. The run reached the STRIDE
    # merge (.threats-merged.json) but produced no report.
    (tmp_path / ".threats-merged.json").write_text("{}", encoding="utf-8")
    log = [(1, _line("2026-07-21T07:01:00Z", "ASSESSMENT_START", "mode=full"))]
    out = agg._extract_run_outcome(log, tmp_path)
    assert len(out) == 1
    assert out[0]["category"] == "run_incomplete"
    assert out[0]["severity"] == "error"
    assert "no threat-model.md" in out[0]["title"]


def test_run_outcome_silent_when_completed(tmp_path):
    (tmp_path / "threat-model.md").write_text("# report", encoding="utf-8")
    (tmp_path / ".threats-merged.json").write_text("{}", encoding="utf-8")
    log = [(1, _line("2026-07-21T07:01:00Z", "ASSESSMENT_START", "mode=full"))]
    assert agg._extract_run_outcome(log, tmp_path) == []


def test_run_outcome_silent_when_no_analysis_started(tmp_path):
    # Empty output dir / dry-run: no merged threats and no ASSESSMENT_START must
    # not flag, or every scope preview would trip the gate.
    assert agg._extract_run_outcome([], tmp_path) == []


def test_append_reconciliation_warns_on_unrecovered(tmp_path):
    log_path = tmp_path / ".agent-run.log"
    log_path.write_text("", encoding="utf-8")
    agg._append_reconciliation_line(
        tmp_path, {"mid_run_stops": 1, "transient_build_fatals": 0, "run_completed": False, "unrecovered": 1}
    )
    last = log_path.read_text(encoding="utf-8").splitlines()[-1]
    assert "WARN" in last and "UNRECOVERED" in last
