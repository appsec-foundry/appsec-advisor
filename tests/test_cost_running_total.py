"""Tests for scripts/cost_running_total.py — running token + cost
aggregation since the assessment start.

Verifies:
  - Cumulative SESSION_STOP delta math (last-in-window minus baseline-before-window)
  - Multi-session aggregation (orchestrator + sub-agents)
  - Window detection from ASSESSMENT_START
  - Banner / JSON / total-only output formatters
  - Graceful handling of missing logs
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "cost_running_total.py"


def _load():
    spec = importlib.util.spec_from_file_location("_crt", ROOT / "scripts" / "cost_running_total.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def fresh_run_dir(tmp_path) -> Path:
    """Empty output dir — for missing-log path tests."""
    return tmp_path


@pytest.fixture
def populated_run_dir(tmp_path) -> Path:
    """Output dir with realistic .hook-events.log + .agent-run.log."""
    hook_log = tmp_path / ".hook-events.log"
    hook_log.write_text(
        "2026-05-01T10:00:00Z  [abc12345]  INFO   AGENT_SPAWN   threat-analyst\n"
        "2026-05-01T10:05:00Z  [abc12345]  INFO   SESSION_STOP   reason=ok "
        "in=15000 out=2500 cache_write=8000 cache_read=12000 cost=$0.18\n"
        "2026-05-01T10:15:00Z  [def67890]  INFO   SESSION_STOP   reason=ok "
        "in=22000 out=4000 cache_write=5000 cache_read=8000 cost=$0.34\n"
        "2026-05-01T10:25:00Z  [abc12345]  INFO   SESSION_STOP   reason=ok "
        "in=28000 out=4500 cache_write=15000 cache_read=22000 cost=$0.42\n"
    )
    agent_log = tmp_path / ".agent-run.log"
    agent_log.write_text(
        "2026-05-01T10:00:00Z  [abc12345]  INFO   threat-analyst  ASSESSMENT_START   Threat model assessment\n"
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Aggregation correctness
# ---------------------------------------------------------------------------


class TestAggregation:
    def test_no_log_returns_zero(self, fresh_run_dir):
        crt = _load()
        result = crt.aggregate_running_total(fresh_run_dir)
        assert result["status"] == "no-log"
        assert result["total_tokens"] == 0
        assert result["cost_usd"] == 0.0

    def test_full_window_sums_per_session(self, populated_run_dir):
        crt = _load()
        result = crt.aggregate_running_total(populated_run_dir)
        assert result["status"] == "ok"
        # Session abc12345: last cumulative snapshot = (28k in / 4.5k out / 15k cw / 22k cr)
        # Session def67890: last cumulative snapshot = (22k / 4k / 5k / 8k)
        # Both windows start at ASSESSMENT_START (no baseline subtract)
        assert result["in_tokens"] == 28000 + 22000  # 50000
        assert result["out_tokens"] == 4500 + 4000  # 8500
        assert result["cache_write"] == 15000 + 5000  # 20000
        assert result["cache_read"] == 22000 + 8000  # 30000
        assert result["total_tokens"] == 108500
        assert result["session_count"] == 2

    def test_reported_cost_summed_across_sessions(self, populated_run_dir):
        crt = _load()
        result = crt.aggregate_running_total(populated_run_dir)
        # Session abc12345 latest cost: $0.42; def67890: $0.34 → total $0.76
        assert result["cost_usd"] == pytest.approx(0.76, abs=0.01)

    def test_since_iso_filter(self, populated_run_dir):
        """Window starting at 10:10 should drop session abc12345's first
        snapshot but include the 10:25 cumulative snapshot, plus def67890."""
        crt = _load()
        result = crt.aggregate_running_total(populated_run_dir, since_iso="2026-05-01T10:10:00Z")
        # abc12345: baseline = 10:05 snapshot (15k/2.5k/8k/12k);
        #           latest = 10:25 snapshot (28k/4.5k/15k/22k);
        #           delta = 13k/2k/7k/10k
        # def67890: baseline = empty; latest = 22k/4k/5k/8k
        # Sum: 35k in, 6k out, 12k cw, 18k cr
        assert result["in_tokens"] == 13000 + 22000  # 35000
        assert result["out_tokens"] == 2000 + 4000  # 6000
        assert result["cache_write"] == 7000 + 5000  # 12000
        assert result["cache_read"] == 10000 + 8000  # 18000


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


class TestFormatters:
    def test_banner_no_log(self, fresh_run_dir):
        crt = _load()
        result = crt.aggregate_running_total(fresh_run_dir)
        line = crt.format_banner(result)
        assert "n/a" in line

    def test_banner_with_data(self, populated_run_dir):
        crt = _load()
        result = crt.aggregate_running_total(populated_run_dir)
        line = crt.format_banner(result)
        assert "108k tokens" in line
        assert "$0.76" in line
        assert "running total" in line

    def test_total_only_machine_readable(self, populated_run_dir):
        crt = _load()
        result = crt.aggregate_running_total(populated_run_dir)
        out = crt.format_total_only(result)
        # Bash-comparable float output
        assert float(out) == pytest.approx(0.76, abs=0.01)


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------


class TestCLI:
    def test_banner_format(self, populated_run_dir):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(populated_run_dir), "--format", "banner"], capture_output=True, text=True
        )
        assert result.returncode == 0
        assert "running total" in result.stdout
        assert "108k tokens" in result.stdout

    def test_total_only_format(self, populated_run_dir):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(populated_run_dir), "--format", "total-only"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert float(result.stdout.strip()) == pytest.approx(0.76, abs=0.01)

    def test_json_format(self, populated_run_dir):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(populated_run_dir), "--format", "json"], capture_output=True, text=True
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["session_count"] == 2

    def test_missing_output_dir(self, tmp_path):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(tmp_path / "does-not-exist"), "--format", "banner"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1


# ---------------------------------------------------------------------------
# _model_key_from_session (lines 55-67)
# ---------------------------------------------------------------------------


class TestModelKeyFromSession:
    def test_no_map_file_returns_none(self, tmp_path):
        crt = _load()
        agent_log = tmp_path / ".agent-run.log"
        assert crt._model_key_from_session("abc", agent_log) is None

    def test_session_found_in_map(self, tmp_path):
        crt = _load()
        agent_log = tmp_path / ".agent-run.log"
        (tmp_path / ".session-agent-map").write_text(
            "abc12345=opus-4-1\n"
            "\n"  # blank line skipped
            "noequalsline\n"  # no '=' skipped
            "def67890=haiku-4-5\n"
        )
        assert crt._model_key_from_session("abc12345", agent_log) == "opus-4-1"
        assert crt._model_key_from_session("def67890", agent_log) == "haiku-4-5"

    def test_session_not_in_map_returns_none(self, tmp_path):
        crt = _load()
        agent_log = tmp_path / ".agent-run.log"
        (tmp_path / ".session-agent-map").write_text("xyz=opus-4-1\n")
        assert crt._model_key_from_session("abc12345", agent_log) is None


# ---------------------------------------------------------------------------
# _compute_cost_from_snapshot (lines 76-82) — incl. unknown-model fallback
# ---------------------------------------------------------------------------


class TestComputeCost:
    def test_known_model_pricing(self):
        crt = _load()
        snap = crt.vrc.TokenSnapshot()
        snap.in_tokens = 1_000_000
        snap.out_tokens = 0
        snap.cache_write = 0
        snap.cache_read = 0
        cost = crt._compute_cost_from_snapshot(snap, "sonnet-4-6")
        assert cost == pytest.approx(crt.vrc.PRICING_MODELS["sonnet-4-6"]["input"])

    def test_unknown_model_falls_back_to_sonnet(self):
        crt = _load()
        snap = crt.vrc.TokenSnapshot()
        snap.in_tokens = 1_000_000
        unknown = crt._compute_cost_from_snapshot(snap, "totally-made-up-model")
        sonnet = crt._compute_cost_from_snapshot(snap, "sonnet-4-6")
        assert unknown == sonnet


# ---------------------------------------------------------------------------
# find_assessment_start (lines 93-109)
# ---------------------------------------------------------------------------


class TestFindAssessmentStart:
    def test_from_agent_log(self, tmp_path):
        crt = _load()
        agent_log = tmp_path / ".agent-run.log"
        agent_log.write_text(
            "2026-05-01T09:59:00Z  [abc]  INFO  threat-analyst  ASSESSMENT_START  go\n"
        )
        hook_log = tmp_path / ".hook-events.log"
        ts = crt.find_assessment_start(hook_log, agent_log)
        assert ts == "2026-05-01T09:59:00Z"

    def test_fallback_to_earliest_session_stop(self, tmp_path):
        crt = _load()
        # No agent log → fall back to earliest SESSION_STOP in hook log
        hook_log = tmp_path / ".hook-events.log"
        hook_log.write_text(
            "2026-05-01T10:00:00Z  [abc]  INFO   SESSION_STOP   reason=ok "
            "in=1 out=1 cache_write=0 cache_read=0 cost=$0.01\n"
        )
        agent_log = tmp_path / ".agent-run.log"  # does not exist
        ts = crt.find_assessment_start(hook_log, agent_log)
        assert ts == "2026-05-01T10:00:00Z"

    def test_no_sources_returns_none(self, tmp_path):
        crt = _load()
        ts = crt.find_assessment_start(tmp_path / "nohook.log", tmp_path / "noagent.log")
        assert ts is None


# ---------------------------------------------------------------------------
# Aggregation fallback path: no reported cost → compute from tokens (line 197)
# ---------------------------------------------------------------------------


class TestAggregationCostFallback:
    def test_no_reported_cost_computes_from_tokens(self, tmp_path):
        crt = _load()
        hook_log = tmp_path / ".hook-events.log"
        # cost=$0.00 everywhere → used_reported stays False → fallback compute
        hook_log.write_text(
            "2026-05-01T10:05:00Z  [abc]  INFO   SESSION_STOP   reason=ok "
            "in=1000000 out=0 cache_write=0 cache_read=0 cost=$0.00\n"
        )
        # ASSESSMENT_START strictly before the snapshot so the window does
        # not subtract the snapshot as its own baseline.
        (tmp_path / ".agent-run.log").write_text(
            "2026-05-01T10:00:00Z  [abc]  INFO   threat-analyst  ASSESSMENT_START  go\n"
        )
        result = crt.aggregate_running_total(tmp_path)
        assert result["status"] == "ok"
        # cost computed from token counts at sonnet pricing, > 0
        expected = round(crt.vrc.PRICING_MODELS["sonnet-4-6"]["input"], 4)
        assert result["cost_usd"] == pytest.approx(expected, abs=0.001)


# ---------------------------------------------------------------------------
# Banner formatter branches (lines 223-232)
# ---------------------------------------------------------------------------


class TestBannerBranches:
    def test_banner_zero_tokens(self):
        crt = _load()
        result = {"status": "ok", "total_tokens": 0, "cost_usd": 0.0}
        assert crt.format_banner(result) == "  ↳ running total: 0 tokens, $0.00"

    def test_banner_millions_suffix(self):
        crt = _load()
        result = {"status": "ok", "total_tokens": 2_500_000, "cost_usd": 12.5}
        line = crt.format_banner(result)
        assert "2.5M tokens" in line
        assert "$12.50" in line

    def test_banner_raw_count_under_1k(self):
        crt = _load()
        result = {"status": "ok", "total_tokens": 750, "cost_usd": 0.01}
        line = crt.format_banner(result)
        assert "750 tokens" in line

    def test_banner_thousands_suffix(self):
        crt = _load()
        result = {"status": "ok", "total_tokens": 12_000, "cost_usd": 0.5}
        line = crt.format_banner(result)
        assert "12k tokens" in line
