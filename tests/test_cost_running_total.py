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
    spec = importlib.util.spec_from_file_location(
        "_crt", ROOT / "scripts" / "cost_running_total.py"
    )
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
        "2026-05-01T10:00:00Z  [abc12345]  INFO   threat-analyst  "
        "ASSESSMENT_START   Threat model assessment\n"
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
        assert result["in_tokens"] == 28000 + 22000     # 50000
        assert result["out_tokens"] == 4500 + 4000      # 8500
        assert result["cache_write"] == 15000 + 5000    # 20000
        assert result["cache_read"] == 22000 + 8000     # 30000
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
        result = crt.aggregate_running_total(
            populated_run_dir, since_iso="2026-05-01T10:10:00Z"
        )
        # abc12345: baseline = 10:05 snapshot (15k/2.5k/8k/12k);
        #           latest = 10:25 snapshot (28k/4.5k/15k/22k);
        #           delta = 13k/2k/7k/10k
        # def67890: baseline = empty; latest = 22k/4k/5k/8k
        # Sum: 35k in, 6k out, 12k cw, 18k cr
        assert result["in_tokens"] == 13000 + 22000     # 35000
        assert result["out_tokens"] == 2000 + 4000      # 6000
        assert result["cache_write"] == 7000 + 5000     # 12000
        assert result["cache_read"] == 10000 + 8000     # 18000


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
            [sys.executable, str(SCRIPT), str(populated_run_dir),
             "--format", "banner"],
            capture_output=True, text=True
        )
        assert result.returncode == 0
        assert "running total" in result.stdout
        assert "108k tokens" in result.stdout

    def test_total_only_format(self, populated_run_dir):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(populated_run_dir),
             "--format", "total-only"],
            capture_output=True, text=True
        )
        assert result.returncode == 0
        assert float(result.stdout.strip()) == pytest.approx(0.76, abs=0.01)

    def test_json_format(self, populated_run_dir):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(populated_run_dir),
             "--format", "json"],
            capture_output=True, text=True
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["status"] == "ok"
        assert data["session_count"] == 2

    def test_missing_output_dir(self, tmp_path):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(tmp_path / "does-not-exist"),
             "--format", "banner"],
            capture_output=True, text=True
        )
        assert result.returncode == 1
