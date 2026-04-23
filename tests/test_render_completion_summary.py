"""Tests for scripts/render_completion_summary.py.

Drives the module via its public API plus a handful of CLI smoke tests.
Fixtures build minimal fake OUTPUT_DIR layouts on disk so each test
exercises the extraction + rendering contract in isolation.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_completion_summary.py"


def _load_module():
    if "render_completion_summary" in sys.modules:
        return sys.modules["render_completion_summary"]
    spec = importlib.util.spec_from_file_location(
        "render_completion_summary", SCRIPT_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["render_completion_summary"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rcs = _load_module()


# ---------------------------------------------------------------------------
# Metric extraction
# ---------------------------------------------------------------------------


class TestExtractMetrics:
    def test_counts_threats_by_severity_from_risk_field(self):
        yaml_data = {
            "threats": [
                {"id": "T-001", "risk": "Critical"},
                {"id": "T-002", "risk": "Critical"},
                {"id": "T-003", "risk": "High"},
                {"id": "T-004", "risk": "Medium"},
                {"id": "T-005", "risk": "Low"},
            ]
        }
        m = rcs.extract_metrics(yaml_data, "")
        assert m["threats_total"] == 5
        assert m["threats_by_sev"] == {"Critical": 2, "High": 1, "Medium": 1, "Low": 1}

    def test_falls_back_to_severity_field(self):
        yaml_data = {"threats": [{"id": "T-001", "severity": "high"}]}
        m = rcs.extract_metrics(yaml_data, "")
        assert m["threats_by_sev"]["High"] == 1

    def test_controls_counts_effectiveness(self):
        yaml_data = {
            "security_controls": [
                {"effectiveness": "adequate"},
                {"effectiveness": "Partial"},  # case-insensitive
                {"effectiveness": "missing"},
                {"effectiveness": "missing"},
            ]
        }
        m = rcs.extract_metrics(yaml_data, "")
        assert m["controls_total"] == 4
        assert m["control_status"]["adequate"] == 1
        assert m["control_status"]["partial"] == 1
        assert m["control_status"]["missing"] == 2

    def test_components_count_from_yaml(self):
        yaml_data = {"components": [{"id": "c1"}, {"id": "c2"}, {"id": "c3"}]}
        m = rcs.extract_metrics(yaml_data, "")
        assert m["n_components"] == 3

    def test_components_fallback_to_md_headings(self):
        md = "## 2. Architecture\n### 2.3 Component A\n### 2.3 Component B\n"
        m = rcs.extract_metrics({}, md)
        assert m["n_components"] == 2


# ---------------------------------------------------------------------------
# Change Summary extraction
# ---------------------------------------------------------------------------


class TestChangeSummary:
    def test_first_run_returns_none(self):
        assert rcs.extract_change_summary({}) is None

    def test_empty_changelog_returns_none(self):
        assert rcs.extract_change_summary({"changelog": []}) is None

    def test_first_run_with_empty_deltas_returns_none(self):
        """A v1 changelog entry without deltas is still a first-run full."""
        yaml_data = {
            "changelog": [{
                "version": 1,
                "date": "2026-04-22",
                "mode": "full",
                "baseline_sha": None,
                "added": {"threats": []},
                "changed": {"threats": []},
                "resolved": {"threats": []},
            }]
        }
        assert rcs.extract_change_summary(yaml_data) is None

    def test_incremental_run_with_deltas(self):
        yaml_data = {
            "changelog": [{
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "abcdef1234567890",
                "added": {"threats": ["T-010", "T-011"]},
                "changed": {
                    "threats": ["T-003"],
                    "notes_by_id": {"T-003": "severity bumped"},
                },
                "resolved": {
                    "threats": ["T-001"],
                    "reason_by_id": {"T-001": "mitigation landed"},
                },
                "reanalyzed_components": ["express-api"],
                "carried_forward_components": ["sqlite-tier", "angular-spa"],
            }]
        }
        cs = rcs.extract_change_summary(yaml_data)
        assert cs["added_n"] == 2
        assert cs["changed_n"] == 1
        assert cs["resolved_n"] == 1
        assert "T-010" in cs["added_ids"]
        assert "severity bumped" in cs["changed_ids"]
        assert "mitigation landed" in cs["resolved_ids"]
        assert cs["cl_mode"] == "incremental"
        assert cs["baseline_short"] == "abcdef123456"

    def test_sample_ids_truncates_over_five(self):
        ids = [f"T-{i:03d}" for i in range(1, 10)]
        sampled = rcs._sample_ids(ids)
        assert "+4 more" in sampled
        assert sampled.count(",") == 5  # five shown + comma before "+4 more"


# ---------------------------------------------------------------------------
# Duration formatting helpers
# ---------------------------------------------------------------------------


def test_fmt_duration():
    assert rcs._fmt_duration(0) == "0m 00s"
    assert rcs._fmt_duration(59) == "0m 59s"
    assert rcs._fmt_duration(60) == "1m 00s"
    assert rcs._fmt_duration(3725) == "62m 05s"


# ---------------------------------------------------------------------------
# Run statistics extraction
# ---------------------------------------------------------------------------


class TestRunStatistics:
    @pytest.fixture
    def output_dir(self, tmp_path: Path) -> Path:
        # Minimal agent-run.log with PHASE events + QA timestamps.
        log = textwrap.dedent("""\
            2026-04-22T17:41:16Z  [--------]  INFO   threat-analyst  ASSESSMENT_START   Assessment started
            2026-04-22T17:41:31Z  [--------]  INFO   threat-analyst  PHASE_START   [Phase 1/11] Context Resolution…
            2026-04-22T17:43:53Z  [--------]  INFO   threat-analyst  PHASE_END     [Phase 1/11] Context Resolution complete (2m22s)
            2026-04-22T17:44:03Z  [--------]  INFO   threat-analyst  PHASE_START   [Phase 3/11] ▶ Architecture Modeling
            2026-04-22T17:45:05Z  [--------]  INFO   threat-analyst  PHASE_END     [Phase 3/11] ✓ Architecture Modeling — done (1m02s)
            2026-04-22T17:46:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_END   completed in 4 min 44 s
            2026-04-22T17:50:00Z  [--------]  INFO   qa-reviewer  AGENT_START   Starting QA review (model: claude-sonnet-4-6) threat-model=/tmp/x.md
            2026-04-22T17:55:00Z  [--------]  INFO   qa-reviewer  CHECK_END   Check 10/10 — passed
        """)
        (tmp_path / ".agent-run.log").write_text(log)

        hooks = textwrap.dedent("""\
            2026-04-22T17:41:16Z  [sess123]  INFO   AGENT_SPAWN         appsec-advisor:appsec-threat-analyst         model=sonnet  Threat Model Orchestrator
            2026-04-22T17:50:00Z  [sess123]  INFO   AGENT_SPAWN         appsec-advisor:appsec-qa-reviewer            model=sonnet  QA review of threat model
        """)
        (tmp_path / ".hook-events.log").write_text(hooks)
        return tmp_path

    def test_assessment_duration_from_yaml_when_present(self, tmp_path: Path):
        (tmp_path / ".agent-run.log").write_text("")
        stats = rcs.extract_run_statistics(
            tmp_path,
            {"meta": {"analysis_duration_seconds": 300}},
        )
        assert stats["assess_secs"] == 300

    def test_assessment_duration_from_assessment_end_line(self, output_dir: Path):
        stats = rcs.extract_run_statistics(output_dir, {})
        assert stats["assess_secs"] == 284  # 4*60 + 44

    def test_phase_pairs_are_detected(self, output_dir: Path):
        stats = rcs.extract_run_statistics(output_dir, {})
        phase_ids = [p[0] for p in stats["phases"]]
        assert phase_ids == ["1", "3"]
        durations = {p[0]: p[2] for p in stats["phases"]}
        assert durations["1"] == (17 * 3600 + 43 * 60 + 53) - (17 * 3600 + 41 * 60 + 31)
        assert durations["1"] == 142

    def test_qa_duration_from_agent_start_and_check_end(self, output_dir: Path):
        stats = rcs.extract_run_statistics(output_dir, {})
        assert stats["qa_secs"] == 300  # 17:55:00 - 17:50:00

    def test_agent_roster_merges_hook_and_agent_log(self, output_dir: Path):
        stats = rcs.extract_run_statistics(output_dir, {})
        # From hooks + agent-run.log AGENT_START.
        assert stats["agents"]["threat-analyst"] == "sonnet-4-6"
        assert stats["agents"]["qa-reviewer"] == "sonnet-4-6"


# ---------------------------------------------------------------------------
# Next Steps conditional rules
# ---------------------------------------------------------------------------


class TestNextSteps:
    def _cfg(self, **overrides):
        base = {
            "mode": "full",
            "reasoning_model": "opus-cheap",
            "write_yaml": True, "write_sarif": False,
            "write_pentest_tasks": False,
            "check_requirements": False,
            "architect_review": False,
            "with_sca": False,
        }
        base.update(overrides)
        return base

    def _metrics(self, critical=0, high=0):
        return {"threats_by_sev": {"Critical": critical, "High": high, "Medium": 0, "Low": 0}}

    def test_always_line_1_present(self, tmp_path):
        lines = rcs.build_next_steps(tmp_path, tmp_path, self._metrics(), self._cfg())
        assert "Management Summary" in lines[0]

    def test_line_2_only_when_critical_or_high(self, tmp_path):
        lines_with = rcs.build_next_steps(
            tmp_path, tmp_path, self._metrics(critical=2), self._cfg()
        )
        assert any("Critical findings" in l for l in lines_with)
        lines_without = rcs.build_next_steps(
            tmp_path, tmp_path, self._metrics(), self._cfg()
        )
        assert not any("Section 8" in l for l in lines_without)

    def test_architect_review_shown_when_file_exists(self, tmp_path):
        (tmp_path / ".architect-review.md").write_text("# review\n")
        lines = rcs.build_next_steps(
            tmp_path, tmp_path, self._metrics(critical=1),
            self._cfg(architect_review=True),
        )
        assert any("architect-review.md" in l for l in lines)

    def test_sarif_hint_shown_when_file_exists(self, tmp_path):
        (tmp_path / "threat-model.sarif.json").write_text("{}")
        lines = rcs.build_next_steps(
            tmp_path, tmp_path, self._metrics(),
            self._cfg(write_sarif=True),
        )
        assert any("sarif" in l.lower() for l in lines)

    def test_requirements_hint_only_when_disabled(self, tmp_path):
        lines = rcs.build_next_steps(
            tmp_path, tmp_path, self._metrics(), self._cfg(),
        )
        assert any("--requirements" in l for l in lines)
        lines_on = rcs.build_next_steps(
            tmp_path, tmp_path, self._metrics(),
            self._cfg(check_requirements=True),
        )
        assert not any("--requirements" in l for l in lines_on)

    def test_reasoning_hint_only_for_sonnet_with_findings(self, tmp_path):
        sonnet_many = rcs.build_next_steps(
            tmp_path, tmp_path, self._metrics(critical=2, high=2),
            self._cfg(reasoning_model="sonnet"),
        )
        assert any("--reasoning-model opus" in l for l in sonnet_many)

        opus_cheap = rcs.build_next_steps(
            tmp_path, tmp_path, self._metrics(critical=2, high=2),
            self._cfg(reasoning_model="opus-cheap"),
        )
        assert not any("--reasoning-model opus" in l for l in opus_cheap)

    def test_capped_at_five_items(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / ".architect-review.md").write_text("# review\n")
        (tmp_path / "threat-model.sarif.json").write_text("{}")
        lines = rcs.build_next_steps(
            tmp_path, tmp_path,
            self._metrics(critical=3, high=5),
            self._cfg(
                reasoning_model="sonnet",
                architect_review=True,
                write_sarif=True,
                with_sca=False,
            ),
        )
        assert len(lines) <= 5


# ---------------------------------------------------------------------------
# Security notice
# ---------------------------------------------------------------------------


class TestSecurityNotice:
    def test_no_notice_when_git_ignores_file(self, tmp_path, monkeypatch):
        import subprocess as sp

        def fake_run(cmd, **kwargs):
            r = sp.CompletedProcess(cmd, returncode=0)
            r.stdout = b""
            r.stderr = b""
            return r

        monkeypatch.setattr(sp, "run", fake_run)
        lines = rcs.render_security_notice(tmp_path)
        assert lines == []

    def test_notice_when_file_not_ignored(self, tmp_path, monkeypatch):
        import subprocess as sp

        def fake_run(cmd, **kwargs):
            r = sp.CompletedProcess(cmd, returncode=1)
            r.stdout = b""
            r.stderr = b""
            return r

        monkeypatch.setattr(sp, "run", fake_run)
        lines = rcs.render_security_notice(tmp_path)
        assert any("Security Notice" in l for l in lines)
        assert any("git-ignored" in l for l in lines)

    def test_no_notice_when_git_unavailable(self, tmp_path, monkeypatch):
        import subprocess as sp

        def fake_run(cmd, **kwargs):
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(sp, "run", fake_run)
        lines = rcs.render_security_notice(tmp_path)
        assert lines == []


# ---------------------------------------------------------------------------
# Full render — CLI smoke test
# ---------------------------------------------------------------------------


class TestCLISmoke:
    def _minimal_output_dir(self, tmp_path: Path) -> Path:
        (tmp_path / "threat-model.md").write_text("# Threat Model\n")
        (tmp_path / "threat-model.yaml").write_text(
            "meta: {schema_version: 1}\n"
            "threats: []\n"
            "mitigations: []\n"
            "components: []\n"
            "security_controls: []\n"
        )
        return tmp_path

    def test_missing_output_dir_exits_2(self, tmp_path: Path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH),
             "--output-dir", str(tmp_path / "nope"),
             "--repo-root", str(tmp_path)],
            capture_output=True, text=True,
        )
        assert r.returncode == 2

    def test_missing_md_exits_2(self, tmp_path: Path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH),
             "--output-dir", str(tmp_path),
             "--repo-root", str(tmp_path)],
            capture_output=True, text=True,
        )
        assert r.returncode == 2

    def test_minimal_full_run(self, tmp_path: Path):
        out = self._minimal_output_dir(tmp_path)
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH),
             "--output-dir", str(out),
             "--repo-root", str(out),
             "--mode", "full"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "ASSESSMENT COMPLETE" in r.stdout
        assert "-- Files" in r.stdout
        assert "-- Metrics" in r.stdout
        assert "-- Next Steps" in r.stdout

    def test_dry_run_output_format(self, tmp_path: Path):
        out = self._minimal_output_dir(tmp_path)
        (out / "threat-model.md").write_text(
            "# Threat Model\n\n"
            "## Management Summary\n\n"
            "### Verdict\n\n<blockquote>Critical</blockquote>\n\n"
            "## 1. System Overview\n\nNot part of MS.\n"
        )
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH),
             "--output-dir", str(out),
             "--repo-root", str(out),
             "--mode", "dry-run"],
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert "Dry-Run — Threat Model Preview" in r.stdout
        assert "### Verdict" in r.stdout
        assert "Critical" in r.stdout
        assert "Not part of MS" not in r.stdout
        assert "No files were written" in r.stdout


# ---------------------------------------------------------------------------
# Placeholder patching
# ---------------------------------------------------------------------------


class TestPatchPlaceholders:
    def test_replaces_pending_markers(self, tmp_path: Path):
        md = tmp_path / "threat-model.md"
        md.write_text(textwrap.dedent("""\
            ## Appendix: Run Statistics

            | Agent | Phase | Model | Duration |
            |-------|-------|-------|----------|
            | **Assessment Total** |  |  | **_pending_** |
            | QA Review | 11 | sonnet-4-6 | _pending_ |
            | **Grand Total** |  |  | **_pending_** |
        """))
        stats = {
            "assess_secs": 284,
            "qa_secs":     300,
            "arch_secs":   None,
            "agents":      {"qa-reviewer": "sonnet-4-6"},
            "phases":      [],
        }
        n = rcs.patch_placeholders(tmp_path, stats)
        text = md.read_text()
        assert n == 3
        assert "**4m 44s**" in text
        assert "5m 00s" in text
        assert "**9m 44s**" in text
        assert "_pending_" not in text

    def test_idempotent(self, tmp_path: Path):
        md = tmp_path / "threat-model.md"
        md.write_text(
            "| **Assessment Total** |  |  | **_pending_** |\n"
        )
        stats = {"assess_secs": 100, "qa_secs": None, "arch_secs": None,
                 "agents": {}, "phases": []}
        rcs.patch_placeholders(tmp_path, stats)
        second = rcs.patch_placeholders(tmp_path, stats)
        assert second == 0
