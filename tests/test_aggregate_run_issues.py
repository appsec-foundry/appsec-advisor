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

REPO_ROOT   = Path(__file__).parent.parent
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
        (2, _line("2026-04-26T17:58:00Z", "PHASE_END",   "[Phase 2/11] Reconnaissance complete")),
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
        (3, _line("2026-04-26T18:03:13Z", "PHASE_END",   "[Phase 2/11] Reconnaissance complete")),
    ]
    out = agg._extract_phase_durations(log)
    assert len(out) == 1, "duplicate STARTs must collapse to one duration"
    assert out[0]["duration_seconds"] == 226   # 17:59:27 → 18:03:13


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
        (2, _line("2026-04-26T18:01:30Z", "PHASE_END",   "[Phase 1/11] Context complete")),
        (3, _line("2026-04-26T18:01:35Z", "PHASE_START", "[Phase 2/11] Recon")),
        (4, _line("2026-04-26T18:05:00Z", "PHASE_END",   "[Phase 2/11] Recon complete")),
        (5, _line("2026-04-26T18:05:10Z", "PHASE_START", "[Phase 9/11] STRIDE")),
        (6, _line("2026-04-26T18:11:00Z", "PHASE_END",   "[Phase 9/11] STRIDE complete")),
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
        (2, _line("2026-04-26T17:55:00Z", "SCAN_START",   "repo=/x  agent=foo  model=sonnet")),
        (3, _line("2026-04-26T17:56:00Z", "FILE_WRITE",   "/x/.recon-summary.md  (1000 chars)")),
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
