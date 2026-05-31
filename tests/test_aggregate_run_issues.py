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
    """haiku-economy slows the model-bound recon phases (1, 2); the perf
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
        with_eco = agg._extract_perf_anomalies(
            [self._phase_dur("2", dur)], "standard", economy=True
        )
        assert with_eco == [], "economy factor (×1.5) should absorb a 1.3× overshoot on phase 2"

    def test_economy_does_not_scale_orchestrator_phases(self):
        base9 = agg.PHASE_DURATION_LIMITS_SECONDS["standard"]["9"]
        dur = int(base9 * 1.3)
        # Phase 9 runs on sonnet regardless of reasoning tier → economy must
        # NOT widen its budget; the overshoot stays flagged.
        flagged = agg._extract_perf_anomalies(
            [self._phase_dur("9", dur)], "standard", economy=True
        )
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
