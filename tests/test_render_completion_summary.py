"""Tests for scripts/render_completion_summary.py.

Drives the module via its public API plus a handful of CLI smoke tests.
Fixtures build minimal fake OUTPUT_DIR layouts on disk so each test
exercises the extraction + rendering contract in isolation.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_completion_summary.py"


def _load_module():
    if "render_completion_summary" in sys.modules:
        return sys.modules["render_completion_summary"]
    spec = importlib.util.spec_from_file_location("render_completion_summary", SCRIPT_PATH)
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

    def test_controls_breakdown_includes_unsafe_and_reconciles(self):
        # Regression (2026-06): the `unsafe` effectiveness bucket was omitted,
        # so a control rated Unsafe counted toward controls_total but appeared
        # in no sub-bucket and the breakdown did not sum to the total.
        yaml_data = {
            "security_controls": [
                {"effectiveness": "Adequate"},
                {"effectiveness": "Partial"},
                {"effectiveness": "Weak"},
                {"effectiveness": "Unsafe"},
                {"effectiveness": "Unsafe"},
                {"effectiveness": "Missing"},
            ]
        }
        m = rcs.extract_metrics(yaml_data, "")
        cs = m["control_status"]
        assert cs["unsafe"] == 2
        # Every cataloged control lands in exactly one bucket → sub-counts
        # reconcile with the total.
        assert sum(cs.values()) == m["controls_total"] == 6

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
            "changelog": [
                {
                    "version": 1,
                    "date": "2026-04-22",
                    "mode": "full",
                    "baseline_sha": None,
                    "added": {"threats": []},
                    "changed": {"threats": []},
                    "resolved": {"threats": []},
                }
            ]
        }
        assert rcs.extract_change_summary(yaml_data) is None

    def test_incremental_run_with_deltas(self):
        yaml_data = {
            "threats": [
                {"id": "T-010", "risk": "Critical", "title": "Unsigned callback state accepted"},
                {"id": "T-011", "risk": "High", "title": "Admin role check bypass"},
                {"id": "T-003", "risk": "High", "title": "Tenant isolation bypass"},
            ],
            "changelog": [
                {
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
                }
            ],
        }
        cs = rcs.extract_change_summary(yaml_data)
        assert cs["added_n"] == 2
        assert cs["changed_n"] == 1
        assert cs["resolved_n"] == 1
        assert "T-010" in cs["added_ids"]
        assert "severity bumped" in cs["changed_ids"]
        assert "mitigation landed" in cs["resolved_ids"]
        assert "T-010 Critical Unsigned callback state accepted" in cs["added_entries"]
        assert any("Tenant isolation bypass" in line for line in cs["changed_entries"])
        assert "T-001 mitigation landed" in cs["resolved_entries"]
        assert cs["cl_mode"] == "incremental"
        assert cs["baseline_short"] == "abcdef123456"

    def test_incremental_new_and_removed_ids_listed_without_titles(self):
        yaml_data = {
            "threats": [{"id": "T-010", "risk": "High", "title": "X"}],
            "changelog": [
                {
                    "date": "2026-04-23",
                    "mode": "incremental",
                    "delta_basis": "incremental",
                    "baseline_sha": "abcdef1234567890",
                    "added": {"threats": ["T-010", "T-011"]},
                    "changed": {"threats": []},
                    "resolved": {"threats": ["T-001"], "reason_by_id": {"T-001": "fixed"}},
                },
                {"date": "2026-04-19", "mode": "full"},
            ],
        }
        cs = rcs.extract_change_summary(yaml_data)
        assert cs["is_iterative"] is True
        assert cs["added_id_list"] == ["T-010", "T-011"]
        assert cs["resolved_id_list"] == ["T-001"]
        lines = rcs.render_change_summary(cs)
        assert "  New IDs    : T-010, T-011" in lines
        assert "  Removed IDs: T-001" in lines

    def test_incremental_no_changes_still_reports(self):
        yaml_data = {
            "threats": [],
            "changelog": [
                {
                    "date": "2026-04-23",
                    "mode": "incremental",
                    "delta_basis": "incremental",
                    "baseline_sha": "abcdef1234567890",
                    "added": {"threats": []},
                    "changed": {"threats": []},
                    "resolved": {"threats": []},
                },
                {"date": "2026-04-19", "mode": "full"},
            ],
        }
        # An unchanged iterative run is NOT suppressed — it reports explicitly.
        cs = rcs.extract_change_summary(yaml_data)
        assert cs is not None
        lines = rcs.render_change_summary(cs)
        assert "  New IDs    : none" in lines
        assert "  Removed IDs: none" in lines
        assert "  (no new or resolved findings since the baseline)" in lines

    def test_resolved_ids_from_fingerprint_delta_on_full_run(self):
        # A full run over a fingerprinted prior carries resolved findings as
        # prior fingerprint labels (T-IDs aren't stable across full runs).
        yaml_data = {
            "threats": [],
            "changelog": [
                {
                    "date": "2026-04-23",
                    "mode": "full",
                    "delta_basis": "fingerprint",
                    "previous_date": "2026-04-19",
                    "added": {"threats": []},
                    "changed": {"threats": []},
                    "resolved": {"threats": [], "fingerprints": ["data-layer|CWE-639|idor"]},
                },
                {"date": "2026-04-19", "mode": "full"},
            ],
        }
        cs = rcs.extract_change_summary(yaml_data)
        assert cs["is_iterative"] is True
        assert cs["resolved_id_list"] == ["idor"]
        lines = rcs.render_change_summary(cs)
        assert "  Removed IDs: idor" in lines

    def test_threat_delta_limits_each_group_to_three(self):
        yaml_data = {
            "threats": [{"id": f"T-{i:03d}", "risk": "High", "title": f"Threat {i}"} for i in range(1, 6)],
            "changelog": [
                {
                    "version": 2,
                    "date": "2026-04-23",
                    "mode": "incremental",
                    "baseline_sha": "abcdef1234567890",
                    "added": {"threats": [f"T-{i:03d}" for i in range(1, 6)]},
                    "changed": {"threats": []},
                    "resolved": {"threats": []},
                }
            ],
        }
        cs = rcs.extract_change_summary(yaml_data)
        lines = rcs.render_threat_delta(cs)
        assert "Threat Delta" in lines
        assert sum(1 for line in lines if line.startswith("    T-")) == 3
        assert "    ... +2 more" in lines

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
            2026-04-22T17:41:16Z  [sess123]  INFO   AGENT_SPAWN         appsec-advisor:appsec-threat-analyst         model=sonnet  Threat Analysis & Triage
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

    def test_duplicate_phase_end_does_not_invent_phantom_run(self, tmp_path: Path):
        """RCA 2026-06-11: in STAGE1_PHASE_LIMIT=10b mode the analyst emits a
        SECOND PHASE_END mislabeled `[Phase 10b/11]` (actually a Phase-11 substep
        close). The old dict-keyed-without-pop pairing re-paired that stray end
        against the still-open 10b start, inventing a phantom "(run 2)" whose
        duration absorbed the following Phase-11 wall time (observed 5m17s for a
        deterministic sub-second step). The stack-with-pop pairing must consume
        the start on the first end and DROP the stray duplicate end → exactly one
        10b row at its real ~29s, no phantom 317s row."""
        log = textwrap.dedent("""\
            2026-06-11T13:32:32Z  [--------]  INFO   threat-analyst  PHASE_START   [Phase 10b/11] Triage Validation — deterministic
            2026-06-11T13:33:01Z  [--------]  INFO   threat-analyst  PHASE_END     [Phase 10b/11] Triage — 23 flags computed_by=deterministic
            2026-06-11T13:33:12Z  [--------]  INFO   threat-analyst  PHASE_START   [Phase 11/11] Substeps 1-3
            2026-06-11T13:37:49Z  [--------]  INFO   threat-analyst  PHASE_END     [Phase 10b/11] Triage + Substeps 1-3 complete — yaml written
        """)
        (tmp_path / ".agent-run.log").write_text(log)
        stats = rcs.extract_run_statistics(tmp_path, {})
        tenb = [p for p in stats["phases"] if p[0] == "10b"]
        assert len(tenb) == 1, f"expected exactly one 10b row, got {tenb}"
        assert tenb[0][2] == 29  # 13:33:01 - 13:32:32 — the real deterministic triage
        # The phantom 317s (5m17s) "run 2" must NOT appear anywhere.
        assert all(p[2] != 317 for p in stats["phases"]), stats["phases"]

    def test_same_phase_id_in_two_stages_still_yields_two_rows(self, tmp_path: Path):
        """The stack-with-pop pairing must NOT regress the legitimate dual-stage
        case: the same phase-id (e.g. Phase 11) appearing once in Stage 1
        (threat-analyst, substeps) and once in Stage 2 (threat-renderer, compose),
        each with its own START+END, yields two correctly-paired durations."""
        log = textwrap.dedent("""\
            2026-06-11T10:00:00Z  [--------]  INFO   threat-analyst   PHASE_START   [Phase 11/11] Finalization (substeps 1-3)
            2026-06-11T10:01:00Z  [--------]  INFO   threat-analyst   PHASE_END     [Phase 11/11] Finalization substeps done
            2026-06-11T10:05:00Z  [--------]  INFO   threat-renderer  PHASE_START   [Phase 11/11] Finalization (compose)
            2026-06-11T10:07:30Z  [--------]  INFO   threat-renderer  PHASE_END     [Phase 11/11] Finalization compose done
        """)
        (tmp_path / ".agent-run.log").write_text(log)
        stats = rcs.extract_run_statistics(tmp_path, {})
        p11 = [p for p in stats["phases"] if p[0] == "11"]
        assert len(p11) == 2, f"expected two Phase-11 rows (Stage1+Stage2), got {p11}"
        assert {p[2] for p in p11} == {60, 150}  # 1m00s and 2m30s

    def test_qa_duration_from_agent_start_and_check_end(self, output_dir: Path):
        stats = rcs.extract_run_statistics(output_dir, {})
        assert stats["qa_secs"] == 300  # 17:55:00 - 17:50:00

    def test_agent_roster_merges_hook_and_agent_log(self, output_dir: Path):
        stats = rcs.extract_run_statistics(output_dir, {})
        # From hooks + agent-run.log AGENT_START.
        assert stats["agents"]["threat-analyst"] == "sonnet-4-6"
        assert stats["agents"]["qa-reviewer"] == "sonnet-4-6"


class TestCostExtraction:
    def test_extract_costs_skips_subprocess_without_usage_signal(self, tmp_path: Path, monkeypatch):
        plugin_root = tmp_path / "plugin"
        scripts = plugin_root / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "verify_run_costs.py").write_text("# exists\n")
        (tmp_path / ".hook-events.log").write_text("AGENT_SPAWN model=sonnet\n")

        def fail_run(*args, **kwargs):
            raise AssertionError("verify_run_costs.py should not be called")

        monkeypatch.setattr(rcs.subprocess, "run", fail_run)
        assert rcs.extract_costs(tmp_path, plugin_root) is None

    def test_extract_costs_runs_when_usage_signal_exists(self, tmp_path: Path, monkeypatch):
        plugin_root = tmp_path / "plugin"
        scripts = plugin_root / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "verify_run_costs.py").write_text("# exists\n")
        (tmp_path / ".hook-events.log").write_text("ASSESSMENT_TOKENS input=1 output=2\n")

        class Result:
            returncode = 0
            stdout = '{"ok": true}'

        monkeypatch.setattr(rcs.subprocess, "run", lambda *args, **kwargs: Result())
        assert rcs.extract_costs(tmp_path, plugin_root) == {"ok": True}


# ---------------------------------------------------------------------------
# Next Steps conditional rules
# ---------------------------------------------------------------------------


class TestNextSteps:
    def _cfg(self, **overrides):
        base = {
            "mode": "full",
            "reasoning_model": "opus-cheap",
            "write_yaml": True,
            "write_sarif": False,
            "write_pentest_tasks": False,
            "check_requirements": False,
            "architect_review": False,
        }
        base.update(overrides)
        return base

    def _metrics(self, critical=0, high=0):
        return {"threats_by_sev": {"Critical": critical, "High": high, "Medium": 0, "Low": 0}}

    def test_always_line_1_present(self, tmp_path):
        lines = rcs.build_next_steps(tmp_path, tmp_path, self._metrics(), self._cfg())
        assert "Management Summary" in lines[0]

    def test_line_2_only_when_critical_or_high(self, tmp_path):
        lines_with = rcs.build_next_steps(tmp_path, tmp_path, self._metrics(critical=2), self._cfg())
        assert any("Critical findings" in l for l in lines_with)
        lines_without = rcs.build_next_steps(tmp_path, tmp_path, self._metrics(), self._cfg())
        assert not any("Section 8" in l for l in lines_without)

    def test_architect_review_shown_when_file_exists(self, tmp_path):
        (tmp_path / ".architect-review.md").write_text("# review\n")
        lines = rcs.build_next_steps(
            tmp_path,
            tmp_path,
            self._metrics(critical=1),
            self._cfg(architect_review=True),
        )
        assert any("architect-review.md" in l for l in lines)

    def test_sarif_hint_shown_when_file_exists(self, tmp_path):
        (tmp_path / "threat-model.sarif.json").write_text("{}")
        lines = rcs.build_next_steps(
            tmp_path,
            tmp_path,
            self._metrics(),
            self._cfg(write_sarif=True),
        )
        assert any("sarif" in l.lower() for l in lines)

    def test_requirements_hint_only_when_disabled(self, tmp_path):
        lines = rcs.build_next_steps(
            tmp_path,
            tmp_path,
            self._metrics(),
            self._cfg(),
        )
        assert any("--requirements" in l for l in lines)
        lines_on = rcs.build_next_steps(
            tmp_path,
            tmp_path,
            self._metrics(),
            self._cfg(check_requirements=True),
        )
        assert not any("--requirements" in l for l in lines_on)

    def test_reasoning_hint_only_for_sonnet_with_findings(self, tmp_path):
        sonnet_many = rcs.build_next_steps(
            tmp_path,
            tmp_path,
            self._metrics(critical=2, high=2),
            self._cfg(reasoning_model="sonnet"),
        )
        assert any("--reasoning-model opus" in l for l in sonnet_many)

        opus_cheap = rcs.build_next_steps(
            tmp_path,
            tmp_path,
            self._metrics(critical=2, high=2),
            self._cfg(reasoning_model="opus-cheap"),
        )
        assert not any("--reasoning-model opus" in l for l in opus_cheap)

    def test_capped_at_five_items(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / ".architect-review.md").write_text("# review\n")
        (tmp_path / "threat-model.sarif.json").write_text("{}")
        lines = rcs.build_next_steps(
            tmp_path,
            tmp_path,
            self._metrics(critical=3, high=5),
            self._cfg(
                reasoning_model="sonnet",
                architect_review=True,
                write_sarif=True,
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


class TestRenderRunIssues:
    def _make_data(self, n_auto: int = 1) -> dict:
        issue = {
            "severity": "error",
            "title": "Agent exceeded maxTurns",
            "fix_recommendation": {
                "auto_applicable": n_auto > 0,
                "summary": "Bump maxTurns by 50%",
                "category": "agent_def",
            },
        }
        return {
            "schema_version": 1,
            "issues": [issue],
            "summary": {
                "errors": 1,
                "warnings": 0,
                "perf_anomalies": 0,
                "recovery_events": 0,
                "auto_applicable_fixes": n_auto,
            },
        }

    def test_fix_suggestions_hidden_by_default(self):
        lines = rcs.render_run_issues(self._make_data())
        assert not any("Auto-fix available" in l for l in lines)
        assert not any("fix-run-issues" in l for l in lines)
        assert not any("Auto-applicable" in l for l in lines)

    def test_fix_suggestions_shown_with_plugin_dev(self):
        lines = rcs.render_run_issues(self._make_data(), plugin_dev=True)
        assert any("Auto-fix available" in l for l in lines)
        assert any("fix-run-issues" in l for l in lines)

    def test_issue_title_always_shown(self):
        lines = rcs.render_run_issues(self._make_data())
        assert any("Agent exceeded maxTurns" in l for l in lines)

    def test_empty_data_returns_empty(self):
        assert rcs.render_run_issues(None) == []
        assert rcs.render_run_issues({"schema_version": 1, "issues": [], "summary": {}}) == []


class TestCLISmoke:
    def _minimal_output_dir(self, tmp_path: Path) -> Path:
        (tmp_path / "threat-model.md").write_text("# Threat Model\n")
        (tmp_path / "threat-model.yaml").write_text(
            "meta: {schema_version: 1}\nthreats: []\nmitigations: []\ncomponents: []\nsecurity_controls: []\n"
        )
        return tmp_path

    def test_missing_output_dir_exits_2(self, tmp_path: Path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--output-dir", str(tmp_path / "nope"), "--repo-root", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 2

    def test_missing_md_exits_2(self, tmp_path: Path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--output-dir", str(tmp_path), "--repo-root", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 2

    def test_minimal_full_run(self, tmp_path: Path):
        out = self._minimal_output_dir(tmp_path)
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--output-dir", str(out), "--repo-root", str(out), "--mode", "full"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Assessment complete: Create Threat Model" in r.stdout
        assert "Outputs" in r.stdout
        assert "Results" in r.stdout
        assert "Next Steps" in r.stdout

    def test_assessment_depth_reflected_in_run_block(self, tmp_path: Path):
        """Regression: --assessment-depth must surface in the Run block.
        Pre-fix the cfg dict omitted assessment_depth so the Depth line
        always fell back to 'standard' regardless of the flag (observed
        juice-shop 2026-05-30 --thorough run printed 'Depth: standard')."""
        out = self._minimal_output_dir(tmp_path)
        r = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--output-dir",
                str(out),
                "--repo-root",
                str(out),
                "--mode",
                "full",
                "--assessment-depth",
                "thorough",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "Depth     : thorough" in r.stdout
        assert "Depth     : standard" not in r.stdout

    def test_no_print_suppresses_summary(self, tmp_path: Path):
        """--no-print flag (added M2.13) suppresses stdout so Stage 2 can
        invoke the script just to patch placeholders without leaking the
        completion summary mid-pipeline."""
        out = self._minimal_output_dir(tmp_path)
        r = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--output-dir",
                str(out),
                "--repo-root",
                str(out),
                "--mode",
                "full",
                "--no-print",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert r.stdout == "", f"--no-print must suppress all stdout, got: {r.stdout!r}"

    def test_no_print_with_patch_placeholders(self, tmp_path: Path):
        """The canonical Stage 2 combo: --patch-placeholders --no-print.
        Patches markers in MD, prints nothing on stdout."""
        out = self._minimal_output_dir(tmp_path)
        # Inject a _pending_ marker so we can verify the patch ran
        md = out / "threat-model.md"
        md.write_text(md.read_text() + "\n## Appendix: Run Statistics\n\n_pending_\n")
        r = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--output-dir",
                str(out),
                "--repo-root",
                str(out),
                "--mode",
                "full",
                "--patch-placeholders",
                "--no-print",
            ],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert r.stdout == ""

    def test_dry_run_output_format(self, tmp_path: Path):
        out = self._minimal_output_dir(tmp_path)
        (out / "threat-model.md").write_text(
            "# Threat Model\n\n"
            "## Management Summary\n\n"
            "### Verdict\n\n<blockquote>Critical</blockquote>\n\n"
            "## 1. System Overview\n\nNot part of MS.\n"
        )
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--output-dir", str(out), "--repo-root", str(out), "--mode", "dry-run"],
            capture_output=True,
            text=True,
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
        md.write_text(
            textwrap.dedent("""\
            ## Appendix: Run Statistics

            | Agent | Phase | Model | Duration |
            |-------|-------|-------|----------|
            | **Assessment Total** |  |  | **_pending_** |
            | QA Review | 11 | sonnet-4-6 | _pending_ |
            | **Grand Total** |  |  | **_pending_** |
        """)
        )
        stats = {
            "assess_secs": 284,
            "qa_secs": 300,
            "arch_secs": None,
            "agents": {"qa-reviewer": "sonnet-4-6"},
            "phases": [],
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
        md.write_text("| **Assessment Total** |  |  | **_pending_** |\n")
        stats = {"assess_secs": 100, "qa_secs": None, "arch_secs": None, "agents": {}, "phases": []}
        rcs.patch_placeholders(tmp_path, stats)
        second = rcs.patch_placeholders(tmp_path, stats)
        assert second == 0

    def test_no_md_file_returns_zero(self, tmp_path: Path):
        stats = {"assess_secs": 1, "qa_secs": None, "arch_secs": None, "agents": {}, "phases": []}
        assert rcs.patch_placeholders(tmp_path, stats) == 0


# ===========================================================================
# Coverage extension
# ===========================================================================


class TestLoaders:
    def test_load_yaml_missing_file(self, tmp_path: Path):
        assert rcs._load_yaml(tmp_path / "nope.yaml") == {}

    def test_load_yaml_non_mapping(self, tmp_path: Path):
        p = tmp_path / "x.yaml"
        p.write_text("- a\n- b\n")
        assert rcs._load_yaml(p) == {}

    def test_load_text_missing(self, tmp_path: Path):
        assert rcs._load_text(tmp_path / "nope.txt") == ""


class TestRunStatisticsStageRows:
    def test_stage_rows_and_total_from_jsonl(self, tmp_path: Path):
        jsonl = tmp_path / ".stage-stats.jsonl"
        jsonl.write_text(
            '{"stage": 1, "variant": "", "name": "Assessment", "agent": "x:threat-analyst", '
            '"model": "sonnet", "duration_ms": 120000}\n'
            "\n"  # blank line skipped
            "not json\n"  # decode error skipped
            '{"stage": 2, "variant": "abuse-verification", "name": "Abuse", "agent": "merger", '
            '"model": "opus", "duration_ms": 0}\n'
        )
        (tmp_path / ".agent-run.log").write_text("")
        stats = rcs.extract_run_statistics(tmp_path, {})
        assert stats["total_secs_from_stages"] == 120
        assert len(stats["stage_rows"]) == 2

    def test_wall_seconds_file(self, tmp_path: Path):
        (tmp_path / ".scan-wall-seconds").write_text("450\n")
        (tmp_path / ".agent-run.log").write_text("")
        stats = rcs.extract_run_statistics(tmp_path, {})
        assert stats["wall_secs"] == 450

    def test_arch_duration(self, tmp_path: Path):
        log = textwrap.dedent("""\
            2026-04-22T10:00:00Z  [--------]  INFO  architect-reviewer  AGENT_START  begin
            2026-04-22T10:03:00Z  [--------]  INFO  architect-reviewer  AGENT_COMPLETE  done
        """)
        (tmp_path / ".agent-run.log").write_text(log)
        stats = rcs.extract_run_statistics(tmp_path, {})
        assert stats["arch_secs"] == 180

    def test_assessment_crash_fallback_to_last_phase(self, tmp_path: Path):
        # No ASSESSMENT_END / no "completed in" → fall back to last PHASE_END.
        log = textwrap.dedent("""\
            2026-04-22T10:00:00Z  [--------]  INFO  threat-analyst  ASSESSMENT_START  go
            2026-04-22T10:00:05Z  [--------]  INFO  threat-analyst  PHASE_START  [Phase 1/11] Context…
            2026-04-22T10:04:00Z  [--------]  INFO  threat-analyst  PHASE_END  [Phase 1/11] done
        """)
        (tmp_path / ".agent-run.log").write_text(log)
        stats = rcs.extract_run_statistics(tmp_path, {})
        assert stats["assess_secs"] == 240


class TestRenderRunStatistics:
    def test_empty_block_when_nothing(self):
        stats = {
            "assess_secs": None,
            "qa_secs": None,
            "arch_secs": None,
            "phases": [],
            "stage_rows": [],
            "agents": {},
            "total_secs_from_stages": None,
            "wall_secs": None,
            "timing": {},
        }
        assert rcs.render_run_statistics(stats, None) == []

    def test_net_and_wall_default(self):
        stats = {
            "assess_secs": None,
            "qa_secs": None,
            "arch_secs": None,
            "phases": [],
            "stage_rows": [("1", "", "Assess", "ta", "sonnet", 100)],
            "agents": {},
            "total_secs_from_stages": 100,
            "wall_secs": 200,
            "timing": {"net_compute_secs": 100, "wall_secs": 200, "standby_secs": 0},
        }
        out = "\n".join(rcs.render_run_statistics(stats, None, verbose=False))
        assert "Net agent compute" in out
        assert "Idle / standby" in out
        assert "Total elapsed (wall)" in out
        # Default (non-verbose) stops at the timing headline — no per-stage rows.
        assert "Stage 1" not in out

    def test_verbose_stage_breakdown_and_agents(self):
        stats = {
            "assess_secs": None,
            "qa_secs": 60,
            "arch_secs": 90,
            "phases": [],
            "stage_rows": [("1", "", "Assessment", "threat-analyst", "sonnet-4-6", 100)],
            "agents": {"threat-analyst": "sonnet-4-6", "qa-reviewer": "sonnet-4-6"},
            "total_secs_from_stages": 100,
            "wall_secs": 250,
            "timing": {"net_compute_secs": 100, "wall_secs": 250, "standby_secs": 0, "stages": []},
        }
        out = "\n".join(rcs.render_run_statistics(stats, None, verbose=True))
        assert "Stage 1" in out
        assert "QA Review" in out
        assert "Architect Review" in out  # arch_secs present, stage 4 absent
        assert "Agents" in out

    def test_verbose_standby_detail(self):
        stats = {
            "assess_secs": None,
            "qa_secs": None,
            "arch_secs": None,
            "phases": [],
            "stage_rows": [],
            "agents": {},
            "total_secs_from_stages": 100,
            "wall_secs": 1000,
            "timing": {
                "net_compute_secs": 100,
                "wall_secs": 1000,
                "standby_secs": 700,
                "net_wall_secs": 300,
                "stages": [],
            },
        }
        out = "\n".join(rcs.render_run_statistics(stats, None, verbose=True))
        assert "Standby / suspend" in out
        assert "Net run (wall−sleep)" in out
        assert "standby" in out

    def test_legacy_total_fallback(self):
        stats = {
            "assess_secs": 100,
            "qa_secs": 50,
            "arch_secs": 25,
            "phases": [],
            "stage_rows": [],
            "agents": {},
            "total_secs_from_stages": None,
            "wall_secs": None,
            "timing": {},
        }
        out = "\n".join(rcs.render_run_statistics(stats, None, verbose=False))
        assert "Total (legacy)" in out
        assert "assessment" in out

    def test_subscription_cost_and_tokens(self):
        stats = {
            "assess_secs": None,
            "qa_secs": None,
            "arch_secs": None,
            "phases": [],
            "stage_rows": [],
            "agents": {},
            "total_secs_from_stages": 10,
            "wall_secs": 10,
            "timing": {"net_compute_secs": 10, "wall_secs": 10, "standby_secs": 0, "stages": []},
        }
        cost = {
            "totals": {
                "total_tokens": 1000,
                "in": 600,
                "out": 400,
                "cache_write": 5,
                "cache_read": 50,
                "cache_savings_pct": 80.0,
            },
            "billing": "subscription",
        }
        out = "\n".join(rcs.render_run_statistics(stats, cost, verbose=True))
        assert "Tokens" in out
        assert "Cache savings" in out
        assert "subscription" in out

    def test_measured_cost_with_mix(self):
        stats = {
            "assess_secs": None,
            "qa_secs": None,
            "arch_secs": None,
            "phases": [],
            "stage_rows": [],
            "agents": {},
            "total_secs_from_stages": 10,
            "wall_secs": 10,
            "timing": {"net_compute_secs": 10, "wall_secs": 10, "standby_secs": 0, "stages": []},
        }
        cost = {
            "totals": {"total_tokens": 100, "in": 60, "out": 40, "cache_savings_pct": 50.0, "cost": 1.23},
            "billing": "api",
            "mixed_model_costs": {"sonnet": {"cached": 0.5, "no_cache": 1.0}},
        }
        out = "\n".join(rcs.render_run_statistics(stats, cost, verbose=True))
        assert "Cost (measured)" in out
        assert "sonnet" in out
        assert "Billing" in out

    def test_tokens_not_captured(self):
        stats = {
            "assess_secs": None,
            "qa_secs": None,
            "arch_secs": None,
            "phases": [],
            "stage_rows": [],
            "agents": {},
            "total_secs_from_stages": 10,
            "wall_secs": 10,
            "timing": {"net_compute_secs": 10, "wall_secs": 10, "standby_secs": 0, "stages": []},
        }
        cost = {"totals": {"total_tokens": 0, "cost": 0}, "billing": "api"}
        out = "\n".join(rcs.render_run_statistics(stats, cost, verbose=True))
        assert "not captured by Claude Code hooks" in out

    def test_cost_none_unavailable_line(self):
        stats = {
            "assess_secs": None,
            "qa_secs": None,
            "arch_secs": None,
            "phases": [],
            "stage_rows": [],
            "agents": {},
            "total_secs_from_stages": 10,
            "wall_secs": 10,
            "timing": {"net_compute_secs": 10, "wall_secs": 10, "standby_secs": 0, "stages": []},
        }
        out = "\n".join(rcs.render_run_statistics(stats, None, verbose=True))
        assert "verify_run_costs.py failed" in out


class TestRenderFiles:
    def test_all_optional_files(self, tmp_path: Path):
        (tmp_path / "threat-model.sarif.json").write_text("{}")
        (tmp_path / ".architect-review.md").write_text("x")
        (tmp_path / "analysis-model.md").write_text("x")
        cfg = {"write_yaml": True, "write_sarif": True, "architect_review": True}
        out = "\n".join(rcs.render_files(tmp_path, cfg))
        assert "YAML" in out and "SARIF" in out and "Architect" in out and "Analysis" in out

    def test_no_yaml(self, tmp_path: Path):
        out = "\n".join(rcs.render_files(tmp_path, {"write_yaml": False}))
        assert "YAML" not in out


class TestRunIssues:
    def test_extract_missing(self, tmp_path: Path):
        assert rcs.extract_run_issues(tmp_path) is None

    def test_extract_clean_returns_none(self, tmp_path: Path):
        (tmp_path / ".run-issues.json").write_text('{"schema_version": 1, "run_status": "clean", "issues": []}')
        assert rcs.extract_run_issues(tmp_path) is None

    def test_extract_wrong_schema(self, tmp_path: Path):
        (tmp_path / ".run-issues.json").write_text('{"schema_version": 2}')
        assert rcs.extract_run_issues(tmp_path) is None

    def test_extract_with_issues(self, tmp_path: Path):
        (tmp_path / ".run-issues.json").write_text(
            '{"schema_version": 1, "run_status": "issues", '
            '"summary": {"errors": 1}, "issues": [{"severity": "error", "title": "boom"}]}'
        )
        data = rcs.extract_run_issues(tmp_path)
        assert data and data["issues"]

    def test_render_plugin_dev_with_autofix(self):
        data = {
            "summary": {
                "errors": 2,
                "warnings": 1,
                "perf_anomalies": 1,
                "recovery_events": 1,
                "auto_applicable_fixes": 1,
            },
            "issues": [
                {
                    "severity": "error",
                    "title": "x" * 90,
                    "fix_recommendation": {"auto_applicable": True, "summary": "do the fix"},
                },
                {
                    "severity": "warning",
                    "title": "warn",
                    "fix_recommendation": {"auto_applicable": False, "category": "manual"},
                },
                {"severity": "info", "title": "third"},
            ],
        }
        out = "\n".join(rcs.render_run_issues(data, plugin_dev=True))
        assert "Run Issues" in out
        assert "Auto-fix available" in out
        assert "Manual review" in out
        assert "1 more" in out
        assert "Auto-applicable" in out
        assert "fix-run-issues" in out

    def test_render_empty_when_no_issues(self):
        assert rcs.render_run_issues({"issues": []}) == []
        assert rcs.render_run_issues(None) == []


class TestCompositionHealth:
    def test_clean_returns_none(self, tmp_path: Path):
        assert rcs.extract_composition_health(tmp_path) is None

    def test_warned(self, tmp_path: Path):
        (tmp_path / ".compose-stats.json").write_text(
            '{"schema_version": 1, "warnings": [{"section": "§3", "detail": "y"}], "section_retries": {"3": 2}}'
        )
        (tmp_path / ".inline-shortcut-retry-count").write_text("1")
        health = rcs.extract_composition_health(tmp_path)
        assert health and health["status"] == "warned"
        out = "\n".join(rcs.render_composition_health(health))
        assert "Composition Health" in out
        assert "Section retries" in out
        assert "Soft warning" in out
        assert "Auto-retries" in out

    def test_forward_incompatible_schema(self, tmp_path: Path):
        (tmp_path / ".compose-stats.json").write_text('{"schema_version": 99}')
        # No retries, no warnings → clean → None.
        assert rcs.extract_composition_health(tmp_path) is None

    def test_render_none(self):
        assert rcs.render_composition_health(None) == []

    def test_render_many_warnings_truncates(self):
        health = {
            "status": "warned",
            "warning_count": 3,
            "warnings": [{"section": f"§{i}", "detail": "d" * 100} for i in range(3)],
            "section_retries": {},
            "auto_retries": 0,
        }
        out = "\n".join(rcs.render_composition_health(health))
        assert "more in §Composition Notes" in out


class TestRenderMisc:
    def test_render_next_steps(self):
        out = rcs.render_next_steps(["step a", "step b"])
        assert out[1] == "Next Steps"
        assert "1. step a" in out[2]

    def test_render_next_steps_empty(self):
        assert rcs.render_next_steps([]) == []

    def test_render_log_files(self, tmp_path: Path):
        (tmp_path / ".qa-status.json").write_text("{}")
        out = "\n".join(rcs.render_log_files(tmp_path))
        assert "Agent run" in out
        assert "QA status" in out

    def test_security_notice_ignored_file(self, tmp_path: Path, monkeypatch):
        class R:
            returncode = 0

        monkeypatch.setattr(rcs.subprocess, "run", lambda *a, **k: R())
        assert rcs.render_security_notice(tmp_path) == []

    def test_security_notice_tracked_file(self, tmp_path: Path, monkeypatch):
        class R:
            returncode = 1

        monkeypatch.setattr(rcs.subprocess, "run", lambda *a, **k: R())
        out = "\n".join(rcs.render_security_notice(tmp_path))
        assert "NOT git-ignored" in out

    def test_security_notice_git_error(self, tmp_path: Path, monkeypatch):
        def boom(*a, **k):
            raise OSError("no git")

        monkeypatch.setattr(rcs.subprocess, "run", boom)
        assert rcs.render_security_notice(tmp_path) == []


class TestSummaryHelpers:
    def test_summary_duration_from_stages(self):
        assert rcs._summary_duration({"total_secs_from_stages": 120}) == "2m 00s"

    def test_summary_duration_legacy_sum(self):
        assert (
            rcs._summary_duration({"total_secs_from_stages": None, "assess_secs": 60, "qa_secs": 30, "arch_secs": None})
            == "1m 30s"
        )

    def test_summary_duration_wall_fallback(self):
        assert (
            rcs._summary_duration(
                {
                    "total_secs_from_stages": None,
                    "assess_secs": None,
                    "qa_secs": None,
                    "arch_secs": None,
                    "timing": {"wall_secs": 90},
                }
            )
            == "1m 30s"
        )

    def test_summary_duration_na(self):
        assert rcs._summary_duration({}) == "n/a"

    def test_summary_cost_variants(self):
        assert rcs._summary_cost(None) == "unavailable"
        assert rcs._summary_cost({"error": "x"}) == "unavailable"
        assert rcs._summary_cost({"billing": "subscription", "totals": {}}) == "subscription"
        assert rcs._summary_cost({"billing": "api", "totals": {"cost": 1.5}}) == "$1.50"
        assert rcs._summary_cost({"billing": "api", "totals": {"cost": 0}}) == "not captured"

    def test_summary_qa(self, tmp_path: Path):
        assert rcs._summary_qa(tmp_path, {"skip_qa": True}) == "skipped"
        assert rcs._summary_qa(tmp_path, {}) == "not recorded"
        (tmp_path / ".qa-status.json").write_text('{"status": "passed_clean"}')
        assert rcs._summary_qa(tmp_path, {}) == "passed clean"
        (tmp_path / ".qa-status.json").write_text("not json")
        assert rcs._summary_qa(tmp_path, {}) == "status unreadable"

    def test_summary_architect(self, tmp_path: Path):
        assert rcs._summary_architect(tmp_path, {}) == "skipped"
        assert rcs._summary_architect(tmp_path, {"architect_review": True}) == "not recorded"
        (tmp_path / ".architect-review.md").write_text("x")
        assert rcs._summary_architect(tmp_path, {"architect_review": True}) == "completed"
        (tmp_path / ".architect-status.json").write_text('{"status": "ok_clean"}')
        assert rcs._summary_architect(tmp_path, {"architect_review": True}) == "ok clean"
        (tmp_path / ".architect-status.json").write_text("bad")
        assert rcs._summary_architect(tmp_path, {"architect_review": True}) == "status unreadable"


class TestRunOverview:
    def test_incremental_with_change(self, tmp_path: Path):
        cfg = {"mode": "incremental", "assessment_depth": "thorough"}
        stats = {"total_secs_from_stages": 60}
        change = {"added_n": 1, "changed_n": 2, "resolved_n": 3}
        out = "\n".join(rcs.render_run_overview(tmp_path, tmp_path, cfg, stats, None, change))
        assert "incremental (delta: +1 / ~2 / -3)" in out
        assert "security-relevant delta" in out

    def test_rebuild_scope(self, tmp_path: Path):
        out = "\n".join(
            rcs.render_run_overview(tmp_path, tmp_path, {"mode": "rebuild"}, {"total_secs_from_stages": 1}, None, None)
        )
        assert "fresh full repository assessment" in out


class TestDryRunAndMS:
    def test_render_dry_run_with_ms(self, tmp_path: Path):
        (tmp_path / "threat-model.yaml").write_text("components:\n- {name: a}\nthreats:\n- {risk: critical}\n")
        (tmp_path / "threat-model.md").write_text(
            "## Management Summary\nVerdict: bad <br/> details <blockquote>x</blockquote>\n\n## 1. Scope\nbody\n"
        )
        out = rcs.render_dry_run(tmp_path, tmp_path)
        assert "Dry-Run" in out
        assert "Verdict" in out
        assert "<br/>" not in out
        assert "No files were written" in out

    def test_extract_management_summary_absent(self):
        assert rcs._extract_management_summary("## Other\nbody") == ""


# ---------------------------------------------------------------------------
# Verdict echo on the console summary (default on; --quiet suppresses)
# ---------------------------------------------------------------------------

_VERDICT_MD = (
    "# Threat Model\n\n"
    "## Management Summary\n\n"
    "### Verdict\n\n"
    "🔴 Broad attack surface with no server-side authorization boundary.\n\n"
    "**Risk distribution:** 🔴 Critical: 24 · **Total: 72**\n\n"
    "<br/>\n\n"
    '<blockquote style="border-left: 3px solid #dc2626;">\n\n'
    "- **Admin takeover via forged JWT** — key committed at lib/insecurity.ts:23.\n\n"
    "</blockquote>\n\n"
    "Rotate the key before production.\n\n"
    "### Security Posture & Top Threats\n\n"
    "Not part of the verdict.\n"
)


class TestVerdictEcho:
    def test_extract_verdict_strips_html_and_stops_at_next_heading(self):
        v = rcs._extract_verdict(_VERDICT_MD)
        assert "Broad attack surface" in v
        assert "Admin takeover via forged JWT" in v
        assert "Rotate the key before production." in v
        # HTML stripped, and the next ### subsection is excluded
        assert "<blockquote" not in v and "<br/>" not in v and "style=" not in v
        assert "Not part of the verdict" not in v

    def test_extract_verdict_absent(self):
        assert rcs._extract_verdict("## Management Summary\n\nNo verdict here.\n") == ""

    def test_render_verdict_default_on(self):
        block = rcs.render_verdict(_VERDICT_MD, {})
        joined = "\n".join(block)
        assert "-- Verdict" in joined
        assert "Broad attack surface" in joined

    def test_render_verdict_quiet_suppresses(self):
        assert rcs.render_verdict(_VERDICT_MD, {"quiet": True}) == []

    def test_render_verdict_absent_section_omits_block(self):
        assert rcs.render_verdict("# Threat Model\n\n## 1. Scope\nbody\n", {}) == []

    def _output_dir_with_verdict(self, tmp_path: Path) -> Path:
        (tmp_path / "threat-model.md").write_text(_VERDICT_MD)
        (tmp_path / "threat-model.yaml").write_text(
            "meta: {schema_version: 1}\nthreats: []\nmitigations: []\ncomponents: []\nsecurity_controls: []\n"
        )
        return tmp_path

    def test_full_run_echoes_verdict_by_default(self, tmp_path: Path):
        out = self._output_dir_with_verdict(tmp_path)
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--output-dir", str(out), "--repo-root", str(out), "--mode", "full"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "-- Verdict" in r.stdout
        assert "Broad attack surface" in r.stdout
        assert "<blockquote" not in r.stdout

    def test_full_run_quiet_is_compact(self, tmp_path: Path):
        """--quiet: essentials only — keeps Repository/Run/Results/Outputs,
        drops the verdict, next steps, run statistics, and log listing."""
        out = self._output_dir_with_verdict(tmp_path)
        full = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--output-dir", str(out), "--repo-root", str(out), "--mode", "full"],
            capture_output=True,
            text=True,
        )
        quiet = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--output-dir",
                str(out),
                "--repo-root",
                str(out),
                "--mode",
                "full",
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        assert full.returncode == 0 and quiet.returncode == 0
        # essentials retained
        assert "Assessment complete: Create Threat Model" in quiet.stdout
        assert "Results" in quiet.stdout
        assert "Outputs" in quiet.stdout
        # verdict + verbose/narrative blocks dropped
        assert "-- Verdict" not in quiet.stdout
        assert "Broad attack surface" not in quiet.stdout
        assert "Next Steps" not in quiet.stdout
        assert "-- Run Statistics" not in quiet.stdout
        assert "Logs" not in quiet.stdout
        # quiet really is shorter than the default
        assert len(quiet.stdout) < len(full.stdout)
        # default (non-quiet) still shows the dropped blocks
        assert "Next Steps" in full.stdout and "-- Verdict" in full.stdout


# ---------------------------------------------------------------------------
# Slug-stamp backstop (second anchor) — regression for the recurring
# post-compaction "slug never stamped" bug (2026-07-15).
# ---------------------------------------------------------------------------


class TestStampSlugBackstop:
    def _seed(self, tmp_path: Path, slug):
        (tmp_path / "threat-model.md").write_text("# report\n")
        cfg = {"slug": slug} if slug is not None else {}
        import json as _json

        (tmp_path / ".skill-config.json").write_text(_json.dumps(cfg))

    def test_stamps_when_slug_set_and_no_stamped_copy(self, tmp_path: Path, monkeypatch):
        self._seed(tmp_path, "my-slug")
        calls = []
        monkeypatch.setattr(rcs.subprocess, "run", lambda *a, **k: calls.append(a[0]) or None)
        rcs._stamp_slug_if_configured(tmp_path)
        assert len(calls) == 1
        assert "stamp_threat_model.py" in " ".join(calls[0])
        assert "my-slug" in calls[0]

    def test_noop_when_no_slug(self, tmp_path: Path, monkeypatch):
        self._seed(tmp_path, None)
        calls = []
        monkeypatch.setattr(rcs.subprocess, "run", lambda *a, **k: calls.append(a[0]) or None)
        rcs._stamp_slug_if_configured(tmp_path)
        assert calls == []

    def test_noop_when_no_config(self, tmp_path: Path, monkeypatch):
        (tmp_path / "threat-model.md").write_text("# report\n")
        calls = []
        monkeypatch.setattr(rcs.subprocess, "run", lambda *a, **k: calls.append(a[0]) or None)
        rcs._stamp_slug_if_configured(tmp_path)
        assert calls == []

    def test_idempotent_when_stamped_copy_is_fresh(self, tmp_path: Path, monkeypatch):
        self._seed(tmp_path, "my-slug")
        stamped = tmp_path / "threat-model-my-slug.md"
        stamped.write_text("# stamped\n")
        # make the stamped copy strictly newer than the canonical report
        import os

        md = tmp_path / "threat-model.md"
        st = md.stat()
        os.utime(stamped, (st.st_atime + 10, st.st_mtime + 10))
        calls = []
        monkeypatch.setattr(rcs.subprocess, "run", lambda *a, **k: calls.append(a[0]) or None)
        rcs._stamp_slug_if_configured(tmp_path)
        assert calls == []

    def test_restamps_when_canonical_is_newer(self, tmp_path: Path, monkeypatch):
        self._seed(tmp_path, "my-slug")
        stamped = tmp_path / "threat-model-my-slug.md"
        stamped.write_text("# stale\n")
        import os

        md = tmp_path / "threat-model.md"
        st = md.stat()
        # canonical report is newer than the stamped copy -> must re-stamp
        os.utime(stamped, (st.st_atime - 10, st.st_mtime - 10))
        calls = []
        monkeypatch.setattr(rcs.subprocess, "run", lambda *a, **k: calls.append(a[0]) or None)
        rcs._stamp_slug_if_configured(tmp_path)
        assert len(calls) == 1

    def test_never_raises_on_subprocess_error(self, tmp_path: Path, monkeypatch):
        self._seed(tmp_path, "my-slug")

        def _boom(*a, **k):
            raise OSError("stamp exploded")

        monkeypatch.setattr(rcs.subprocess, "run", _boom)
        # must swallow — the completion summary must never fail on the stamp
        rcs._stamp_slug_if_configured(tmp_path)
