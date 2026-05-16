"""Integration tests for the M2.15 Sprint-7 run-issues pipeline.

Covers aggregate_run_issues.py + recommend_fixes.py + the rendered
§Run Issues appendix and -- Run Issues -- completion-summary block.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPTS = PLUGIN_ROOT / "scripts"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


agg = _load("aggregate_run_issues", SCRIPTS / "aggregate_run_issues.py")
rec = _load("recommend_fixes", SCRIPTS / "recommend_fixes.py")


# ---------------------------------------------------------------------------
# Aggregator — issue extraction
# ---------------------------------------------------------------------------


@pytest.fixture
def output_dir(tmp_path):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    return out


def _write_log(out: Path, name: str, lines: list[str]) -> None:
    (out / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestAggregator:
    def test_clean_run_returns_clean_status(self, output_dir):
        _write_log(
            output_dir,
            ".agent-run.log",
            [
                "2026-04-26T10:00:00Z  [test1234]  INFO   threat-analyst  ASSESSMENT_START  ok",
            ],
        )
        _write_log(output_dir, ".hook-events.log", [])
        data = agg.aggregate(output_dir, "standard")
        assert data["run_status"] == "clean"
        assert data["summary"]["errors"] == 0
        assert data["summary"]["warnings"] == 0
        assert data["issues"] == []

    def test_max_turns_creates_error_issue(self, output_dir):
        _write_log(
            output_dir,
            ".agent-run.log",
            [
                "2026-04-26T10:00:00Z  [t1]  ERROR  stride-analyzer  MAX_TURNS  hit 31/31",
            ],
        )
        _write_log(output_dir, ".hook-events.log", [])
        data = agg.aggregate(output_dir, "standard")
        assert data["run_status"] == "issues"
        assert data["summary"]["errors"] == 1
        assert data["issues"][0]["category"] == "max_turns_subagent"
        assert data["issues"][0]["evidence"]["source_agent"] == "stride-analyzer"

    def test_session_stop_unknown_with_high_tokens_warns(self, output_dir):
        _write_log(
            output_dir,
            ".agent-run.log",
            [
                "2026-04-26T10:00:00Z  [t1]  INFO   threat-analyst  SESSION_STOP  "
                "stop_reason=unknown  in=42  out=399,660  cache_write=10  cache_read=20  cost=$51.61",
            ],
        )
        _write_log(output_dir, ".hook-events.log", [])
        data = agg.aggregate(output_dir, "standard")
        assert data["summary"]["warnings"] == 1
        issue = data["issues"][0]
        assert issue["category"] == "session_stop_unknown"
        assert issue["evidence"]["output_tokens"] == 399660
        assert issue["evidence"]["cost_usd"] == pytest.approx(51.61, rel=1e-3)

    def test_perf_anomaly_phase_exceeds_depth_limit(self, output_dir):
        # Phase 11 limit at standard depth is 600s — make it run 1500s
        _write_log(
            output_dir,
            ".agent-run.log",
            [
                "2026-04-26T10:00:00Z  [t1]  INFO   threat-analyst  PHASE_START  [Phase 11/11] Finalization",
                "2026-04-26T10:25:00Z  [t1]  INFO   threat-analyst  PHASE_END    [Phase 11/11] Finalization",
            ],
        )
        _write_log(output_dir, ".hook-events.log", [])
        data = agg.aggregate(output_dir, "standard")
        anomalies = [i for i in data["issues"] if i["category"].startswith("perf_anomaly")]
        assert len(anomalies) == 1
        assert anomalies[0]["evidence"]["duration_seconds"] == 1500
        assert anomalies[0]["evidence"]["expected_max_seconds"] == 600

    def test_phase_hard_ceiling_flagged_regardless(self, output_dir):
        # 35 min on Phase 1 — exceeds hard ceiling (1800s = 30 min)
        _write_log(
            output_dir,
            ".agent-run.log",
            [
                "2026-04-26T10:00:00Z  [t1]  INFO   threat-analyst  PHASE_START  [Phase 1/11] Context",
                "2026-04-26T10:35:00Z  [t1]  INFO   threat-analyst  PHASE_END    [Phase 1/11] Context",
            ],
        )
        _write_log(output_dir, ".hook-events.log", [])
        data = agg.aggregate(output_dir, "thorough")  # even thorough has 360s limit
        anomalies = [i for i in data["issues"] if "stage1" in i["category"] or "perf_anomaly" in i["category"]]
        assert len(anomalies) >= 1
        # Must be classified as severity=error because it crossed the hard ceiling
        assert any(i["severity"] == "error" for i in anomalies)

    def test_recovery_event_from_inline_retry_count(self, output_dir):
        _write_log(output_dir, ".agent-run.log", [])
        _write_log(output_dir, ".hook-events.log", [])
        (output_dir / ".inline-shortcut-retry-count").write_text("2\n")
        data = agg.aggregate(output_dir, "standard")
        recovery = [i for i in data["issues"] if i["category"] == "auto_retry_fired"]
        assert len(recovery) == 1
        assert recovery[0]["evidence"]["iterations"] == 2

    def test_compose_retries_from_compose_stats(self, output_dir):
        _write_log(output_dir, ".agent-run.log", [])
        _write_log(output_dir, ".hook-events.log", [])
        (output_dir / ".compose-stats.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "compose_status": "warned",
                    "warning_count": 0,
                    "warnings": [],
                    "section_retries": {"attack_walkthroughs": 2, "security_architecture": 3},
                    "total_retry_attempts": 5,
                    "compose_invocation_iso": "2026-04-26T10:00:00Z",
                }
            )
        )
        data = agg.aggregate(output_dir, "standard")
        retries = [i for i in data["issues"] if i["category"] == "compose_retries_section"]
        assert len(retries) == 2
        assert {r["evidence"]["section"] for r in retries} == {"attack_walkthroughs", "security_architecture"}


# ---------------------------------------------------------------------------
# Phase-duration extraction tolerance
# ---------------------------------------------------------------------------


class TestPhaseDurationParsing:
    def test_pair_normal_start_end(self, output_dir):
        _write_log(
            output_dir,
            ".agent-run.log",
            [
                "2026-04-26T10:00:00Z  [t1]  INFO   x  PHASE_START  [Phase 1/11] A",
                "2026-04-26T10:01:30Z  [t1]  INFO   x  PHASE_END    [Phase 1/11] A",
            ],
        )
        log = agg._read_log(output_dir / ".agent-run.log")
        durs = agg._extract_phase_durations(log)
        assert len(durs) == 1
        assert durs[0]["duration_seconds"] == 90
        assert durs[0]["end_inferred"] is False

    def test_pair_with_missing_end_uses_next_start(self, output_dir):
        _write_log(
            output_dir,
            ".agent-run.log",
            [
                "2026-04-26T10:00:00Z  [t1]  INFO   x  PHASE_START  [Phase 1/11] A",
                "2026-04-26T10:05:00Z  [t1]  INFO   x  PHASE_START  [Phase 2/11] B",
                "2026-04-26T10:06:00Z  [t1]  INFO   x  PHASE_END    [Phase 2/11] B",
            ],
        )
        log = agg._read_log(output_dir / ".agent-run.log")
        durs = agg._extract_phase_durations(log)
        # Phase 1 end is inferred from Phase 2 start
        phase1 = next(d for d in durs if d["phase"] == "1")
        assert phase1["duration_seconds"] == 300
        assert phase1["end_inferred"] is True
        # Phase 2 has explicit end
        phase2 = next(d for d in durs if d["phase"] == "2")
        assert phase2["end_inferred"] is False


# ---------------------------------------------------------------------------
# Recommender — auto-applicable categorization
# ---------------------------------------------------------------------------


class TestRecommender:
    def test_max_turns_subagent_is_auto_applicable(self):
        issue = {
            "category": "max_turns_subagent",
            "severity": "error",
            "title": "MAX_TURNS",
            "evidence": {"source_agent": "stride-analyzer"},
        }
        rec_dict = rec._recommend_max_turns_subagent(issue, Path("/tmp"))
        assert rec_dict["auto_applicable"] is True
        assert rec_dict["confidence"] == "high"
        assert rec_dict["category"] == "agent_def"
        # Should compute a bumped value (current 31 → ≥46)
        assert any("maxTurns" in (a.get("find") or "") for a in rec_dict["actions"])

    def test_session_stop_unknown_is_manual(self):
        issue = {
            "category": "session_stop_unknown",
            "severity": "warning",
            "title": "SESSION_STOP unknown",
            "evidence": {"source_agent": "threat-analyst", "output_tokens": 399660, "cost_usd": 51.61},
        }
        rec_dict = rec._recommend_session_stop_unknown(issue, Path("/tmp"))
        assert rec_dict["auto_applicable"] is False
        assert rec_dict["confidence"] == "high"

    def test_stage1_excessive_duration_is_high_alert(self):
        issue = {
            "category": "stage1_excessive_duration",
            "severity": "error",
            "title": "8h on Phase 1",
            "evidence": {"duration_seconds": 28800, "phase": "1"},
        }
        rec_dict = rec._recommend_stage1_excessive_duration(issue, Path("/tmp"))
        assert rec_dict["auto_applicable"] is False
        assert rec_dict["risk_level"] == "high"
        assert "runaway" in rec_dict["summary"].lower()

    def test_default_recommender_for_unknown_category(self):
        issue = {
            "category": "wibble_wobble",
            "severity": "info",
            "title": "Unknown thing",
            "evidence": {"log_file": "x"},
        }
        rec_dict = rec._recommend_default(issue, Path("/tmp"))
        assert rec_dict["auto_applicable"] is False
        assert rec_dict["category"] == "investigate"


class TestEnrichment:
    def test_enrichment_counts_auto_applicable(self):
        data = {
            "schema_version": 1,
            "run_status": "issues",
            "summary": {
                "errors": 1,
                "warnings": 1,
                "perf_anomalies": 0,
                "recovery_events": 0,
                "auto_applicable_fixes": 0,
            },
            "issues": [
                {
                    "id": "ISSUE-001",
                    "category": "max_turns_subagent",
                    "severity": "error",
                    "title": "MAX_TURNS",
                    "evidence": {"source_agent": "stride-analyzer"},
                },
                {
                    "id": "ISSUE-002",
                    "category": "bash_warn",
                    "severity": "warning",
                    "title": "Bash warn",
                    "evidence": {"log_file": "x", "log_line": 1},
                },
            ],
        }
        rec.enrich_with_recommendations(data, Path("/tmp"))
        assert data["summary"]["auto_applicable_fixes"] == 1
        assert data["issues"][0]["fix_recommendation"]["auto_applicable"] is True
        assert data["issues"][1]["fix_recommendation"]["auto_applicable"] is False


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------


class TestCli:
    def test_aggregator_writes_file(self, output_dir):
        _write_log(
            output_dir,
            ".agent-run.log",
            [
                "2026-04-26T10:00:00Z  [t1]  ERROR  stride-analyzer  MAX_TURNS  hit",
            ],
        )
        _write_log(output_dir, ".hook-events.log", [])
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "aggregate_run_issues.py"), str(output_dir), "--depth", "standard"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        out = json.loads((output_dir / ".run-issues.json").read_text())
        assert out["run_status"] == "issues"
        # Auto-recommendation should have run automatically
        assert out["issues"][0]["fix_recommendation"]["auto_applicable"] is True

    def test_aggregator_handles_missing_logs(self, output_dir):
        # No .agent-run.log, no .hook-events.log — must succeed cleanly
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "aggregate_run_issues.py"), str(output_dir), "--depth", "quick"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        out = json.loads((output_dir / ".run-issues.json").read_text())
        assert out["run_status"] == "clean"

    def test_aggregator_missing_output_dir_exits_one(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "aggregate_run_issues.py"),
                str(tmp_path / "no-such-dir"),
                "--depth",
                "standard",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 1


# ---------------------------------------------------------------------------
# Skill discovery — fix-run-issues exists and has --help
# ---------------------------------------------------------------------------


def test_fix_run_issues_skill_exists():
    skill = PLUGIN_ROOT / "skills" / "fix-run-issues" / "SKILL.md"
    assert skill.is_file(), "fix-run-issues SKILL.md must exist"
    text = skill.read_text(encoding="utf-8")
    # Frontmatter present
    assert text.startswith("---\n")
    assert "name: fix-run-issues" in text
    # Help block present
    assert "/appsec-advisor:fix-run-issues — " in text
    # Safety rules documented
    assert "auto_applicable=false" in text
    assert 'confidence != "high"' in text
    # Audit trail mentioned
    assert ".run-issues-fixes.json" in text
