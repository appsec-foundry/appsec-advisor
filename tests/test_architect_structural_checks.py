"""
Tests for scripts/architect_structural_checks.py — Sprint 2 Item #4.

Covers the three deterministic architect-reviewer checks:
  - Check 1  Architecture ↔ Recon Consistency
  - Check 3  Management Summary Verdict Plausibility
  - Check 6  CVSS ↔ Likelihood×Impact Alignment

Plus CLI smoke tests.
Also verifies the compact architecture input pack consumed by the LLM
architect reviewer.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import architect_structural_checks as asc  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "architect_structural_checks.py"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def out_dir(tmp_path):
    """Fresh output dir with no files — individual tests write what they need."""
    return tmp_path


def _write_yaml(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


# ---------------------------------------------------------------------------
# Check 1 — arch_recon
# ---------------------------------------------------------------------------


class TestArchRecon:
    def test_absent_files_produce_no_findings(self, out_dir):
        r = asc.check_arch_recon(out_dir / "missing.yaml", out_dir / "missing.md")
        assert r["findings"] == []
        assert r["tm_yaml_present"] is False
        assert r["recon_md_present"] is False

    def test_consistent_model_and_recon(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            meta:
              schema_version: 1
            components:
              - id: auth-service
                name: Auth Service
                kind: service
                paths: ["services/auth/**"]
              - id: payment-api
                name: Payment API
                kind: service
                paths: ["services/payment/**"]
        """,
        )
        _write_text(
            out_dir / ".recon-summary.md",
            """
            # Recon
            ## 1. Tech Stack

            Services: `auth-service`, `payment-api`
            Paths: services/auth, services/payment
        """,
        )
        r = asc.check_arch_recon(out_dir / "threat-model.yaml", out_dir / ".recon-summary.md")
        assert r["findings"] == []

    def test_invented_component_flagged(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            components:
              - id: ghost-service
                name: Ghost Service
                kind: service
                paths: ["nowhere/**"]
        """,
        )
        _write_text(
            out_dir / ".recon-summary.md",
            """
            # Recon
            ## 1. Tech Stack
            Nothing here references the ghost.
        """,
        )
        r = asc.check_arch_recon(out_dir / "threat-model.yaml", out_dir / ".recon-summary.md")
        kinds = [f["kind"] for f in r["findings"]]
        assert "invented_component" in kinds

    def test_missing_component_flagged_when_recon_has_service_suffix(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            components:
              - id: auth-service
                name: Auth Service
                paths: ["services/auth/**"]
        """,
        )
        _write_text(
            out_dir / ".recon-summary.md",
            """
            # Recon
            ## 1. Tech Stack
            Services: `auth-service`, `analytics-worker`, `billing-service`
        """,
        )
        r = asc.check_arch_recon(out_dir / "threat-model.yaml", out_dir / ".recon-summary.md")
        kinds = [f["kind"] for f in r["findings"]]
        tokens = [f.get("recon_token") for f in r["findings"] if f["kind"] == "missing_component"]
        assert "missing_component" in kinds
        assert "analytics-worker" in tokens
        assert "billing-service" in tokens

    def test_bare_words_in_recon_do_not_trigger_missing(self, out_dir):
        """Random nouns in the recon summary must not produce missing-component
        findings. Only tokens that look like a deployable (hyphen + known
        suffix, or services/ path) count."""
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            components:
              - id: auth-service
                name: Auth Service
                paths: ["services/auth/**"]
        """,
        )
        _write_text(
            out_dir / ".recon-summary.md",
            """
            # Recon
            ## 1. Tech Stack
            Uses `express`, `postgres`, `redis`, `jwt` libraries.
        """,
        )
        r = asc.check_arch_recon(out_dir / "threat-model.yaml", out_dir / ".recon-summary.md")
        # Only auth-service in model → must match recon → zero findings
        assert [f for f in r["findings"] if f["kind"] == "missing_component"] == []


# ---------------------------------------------------------------------------
# Check 3 — ms_verdict
# ---------------------------------------------------------------------------


class TestMsVerdict:
    def test_absent_files_produce_no_findings(self, out_dir):
        r = asc.check_ms_verdict(out_dir / "missing.md", out_dir / "missing.json")
        assert r["findings"] == []
        assert r["verdict_found"] is False

    def test_verdict_understates_critical(self, out_dir):
        _write_text(
            out_dir / "threat-model.md",
            """
            # Threat Model
            ## Management Summary

            > **Verdict**: The system has an acceptable risk posture.

            **Risk Distribution:** Critical: 2 · High: 5 · Medium: 3 · Low: 0 · **Total:** 10
        """,
        )
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [
                    {"risk": "Critical"},
                    {"risk": "Critical"},
                    {"risk": "High"},
                    {"risk": "High"},
                    {"risk": "High"},
                    {"risk": "High"},
                    {"risk": "High"},
                    {"risk": "Medium"},
                    {"risk": "Medium"},
                    {"risk": "Medium"},
                ],
            },
        )
        r = asc.check_ms_verdict(out_dir / "threat-model.md", out_dir / ".threats-merged.json")
        kinds = [f["kind"] for f in r["findings"]]
        assert "verdict_understates_critical" in kinds

    def test_verdict_negated_production_ready_not_understated(self, out_dir):
        """Regression (2026-06-13 juice-shop): a verdict saying the system is
        'not production-ready' over a Critical-laden model must NOT trip
        verdict_understates_critical — the substring 'production-ready' is
        negated. Root cause was a bare substring match ignoring negation."""
        _write_text(
            out_dir / "threat-model.md",
            """
            # Threat Model
            ## Management Summary

            > **Verdict**: The system is not production-ready; ten Critical
            > findings allow full account takeover and server-side RCE.

            **Risk Distribution:** Critical: 10 · High: 30 · Medium: 6 · Low: 2 · **Total:** 48
        """,
        )
        _write_json(
            out_dir / ".threats-merged.json",
            {"threats": [{"risk": "Critical"}] * 10 + [{"risk": "High"}] * 30},
        )
        r = asc.check_ms_verdict(out_dir / "threat-model.md", out_dir / ".threats-merged.json")
        kinds = [f["kind"] for f in r["findings"]]
        assert "verdict_understates_critical" not in kinds

    def test_verdict_overstates_risk(self, out_dir):
        _write_text(
            out_dir / "threat-model.md",
            """
            # Threat Model
            ## Management Summary

            > **Verdict**: The system needs immediate remediation and is not fit for production.

            **Risk Distribution:** Critical: 0 · High: 1 · Medium: 4 · Low: 2 · **Total:** 7
        """,
        )
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [{"risk": "High"}] + [{"risk": "Medium"}] * 4 + [{"risk": "Low"}] * 2,
            },
        )
        r = asc.check_ms_verdict(out_dir / "threat-model.md", out_dir / ".threats-merged.json")
        kinds = [f["kind"] for f in r["findings"]]
        assert "verdict_overstates_risk" in kinds

    def test_risk_distribution_mismatch(self, out_dir):
        """Reported counts in the MS must match actual .threats-merged.json."""
        _write_text(
            out_dir / "threat-model.md",
            """
            # Threat Model
            ## Management Summary

            > **Verdict**: Balanced posture with known gaps.

            **Risk Distribution:** Critical: 2 · High: 5 · Medium: 10 · Low: 3 · **Total:** 20
        """,
        )
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [{"risk": "Critical"}, {"risk": "Critical"}, {"risk": "Critical"}, {"risk": "High"}],
            },
        )
        r = asc.check_ms_verdict(out_dir / "threat-model.md", out_dir / ".threats-merged.json")
        kinds = [f["kind"] for f in r["findings"]]
        assert "risk_distribution_mismatch" in kinds
        mismatch = next(f for f in r["findings"] if f["kind"] == "risk_distribution_mismatch")
        assert mismatch["reported"]["Critical"] == 2
        assert mismatch["actual"]["Critical"] == 3

    def test_bold_colon_inside_markers_parses(self, out_dir):
        """Regression: the '**Risk Distribution:**' variant (colon inside
        the bold markers) must parse."""
        _write_text(
            out_dir / "threat-model.md",
            """
            ## Management Summary
            > **Verdict**: fine.
            **Risk Distribution:** Critical: 1 · High: 2 · Medium: 3 · Low: 4
        """,
        )
        _write_json(out_dir / ".threats-merged.json", {"threats": [{"risk": "Critical"}]})
        r = asc.check_ms_verdict(out_dir / "threat-model.md", out_dir / ".threats-merged.json")
        assert r["reported_counts"] == {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}

    def test_consistent_verdict_no_findings(self, out_dir):
        _write_text(
            out_dir / "threat-model.md",
            """
            ## Management Summary
            > **Verdict**: Several Critical findings require remediation before the next release.
            **Risk Distribution:** Critical: 2 · High: 3 · Medium: 1 · Low: 0
        """,
        )
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [
                    {"risk": "Critical"},
                    {"risk": "Critical"},
                    {"risk": "High"},
                    {"risk": "High"},
                    {"risk": "High"},
                    {"risk": "Medium"},
                ],
            },
        )
        r = asc.check_ms_verdict(out_dir / "threat-model.md", out_dir / ".threats-merged.json")
        assert r["findings"] == []


# ---------------------------------------------------------------------------
# Check 6 — cvss_risk
# ---------------------------------------------------------------------------


class TestCvssRisk:
    def test_no_threats_no_findings(self, out_dir):
        _write_json(out_dir / ".threats-merged.json", {"threats": []})
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        assert r["findings"] == []

    def test_aligned_cvss_no_findings(self, out_dir):
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [
                    {
                        "t_id": "T-001",
                        "risk": "Critical",
                        "cvss_v4": {"base_score": 9.5, "vector": "..."},
                        "source": "stride",
                    },
                    {
                        "t_id": "T-002",
                        "risk": "High",
                        "cvss_v4": {"base_score": 7.5, "vector": "..."},
                        "source": "stride",
                    },
                    {
                        "t_id": "T-003",
                        "risk": "Medium",
                        "cvss_v4": {"base_score": 5.0, "vector": "..."},
                        "source": "stride",
                    },
                ]
            },
        )
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        assert r["findings"] == []

    def test_critical_risk_low_cvss_flagged(self, out_dir):
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [
                    {
                        "t_id": "T-001",
                        "risk": "Critical",
                        "cvss_v4": {"base_score": 3.0, "vector": "..."},
                        "source": "stride",
                    }
                ]
            },
        )
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        kinds = [f["kind"] for f in r["findings"]]
        assert "cvss_out_of_band" in kinds

    def test_low_risk_high_cvss_flagged(self, out_dir):
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [
                    {
                        "t_id": "T-002",
                        "risk": "Low",
                        "cvss_v4": {"base_score": 9.2, "vector": "..."},
                        "source": "stride",
                    }
                ]
            },
        )
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        kinds = [f["kind"] for f in r["findings"]]
        assert "cvss_out_of_band" in kinds

    def test_critical_without_cvss_flagged(self, out_dir):
        _write_json(
            out_dir / ".threats-merged.json", {"threats": [{"t_id": "T-003", "risk": "Critical", "source": "stride"}]}
        )
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        kinds = [f["kind"] for f in r["findings"]]
        assert "critical_without_cvss" in kinds

    def test_architectural_critical_without_cvss_accepted(self, out_dir):
        """Architectural violations can carry Critical risk without a CVSS."""
        _write_json(
            out_dir / ".threats-merged.json",
            {"threats": [{"t_id": "T-004", "risk": "Critical", "source": "stride", "architectural_violation": True}]},
        )
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        assert r["findings"] == []

    def test_known_vuln_critical_without_cvss_accepted(self, out_dir):
        """Only 'source: stride' threats are flagged — known-vuln
        critical-without-cvss entries are handled elsewhere. The dep-scan
        source was removed in 2026-05 (this test previously asserted on
        source=dep-scan)."""
        _write_json(
            out_dir / ".threats-merged.json",
            {"threats": [{"t_id": "T-005", "risk": "Critical", "source": "known-vuln"}]},
        )
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        assert [f for f in r["findings"] if f["kind"] == "critical_without_cvss"] == []

    def test_triage_flagged_threat_is_skipped(self, out_dir):
        """Threats already flagged by the triage-validator must not be
        re-flagged by the architect."""
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [
                    {
                        "t_id": "T-006",
                        "risk": "Critical",
                        "cvss_v4": {"base_score": 2.0, "vector": "..."},
                        "source": "stride",
                        "triage_flags": [{"kind": "cvss_out_of_band", "note": "..."}],
                    }
                ]
            },
        )
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        assert r["findings"] == []

    def test_boundary_cvss_is_info_not_warning(self, out_dir):
        """CVSS right at a band boundary (7.0 / 9.0) is a soft info, not a
        warning."""
        _write_json(
            out_dir / ".threats-merged.json",
            {
                "threats": [
                    {
                        "t_id": "T-007",
                        "risk": "Low",
                        "cvss_v4": {"base_score": 9.0, "vector": "..."},
                        "source": "stride",
                    }
                ]
            },
        )
        r = asc.check_cvss_risk(out_dir / ".threats-merged.json")
        assert len(r["findings"]) == 1
        assert r["findings"][0]["severity"] == "info"

    @pytest.mark.parametrize(
        "base,expected",
        [
            (10.0, {"Critical", "High"}),
            (9.0, {"Critical", "High"}),
            (8.9, {"Critical", "High", "Medium"}),
            (7.0, {"Critical", "High", "Medium"}),
            (6.9, {"High", "Medium", "Low"}),
            (4.0, {"High", "Medium", "Low"}),
            (3.9, {"Medium", "Low"}),
            (0.0, {"Medium", "Low"}),
        ],
    )
    def test_expected_bands(self, base, expected):
        assert asc._expected_risk_bands(base) == expected


# ---------------------------------------------------------------------------
# run_all + CLI
# ---------------------------------------------------------------------------


class TestRunAll:
    def test_end_to_end(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            components:
              - id: auth-service
                name: Auth Service
                paths: ["services/auth/**"]
        """,
        )
        _write_text(
            out_dir / ".recon-summary.md",
            """
            # Recon
            ## 1. Tech Stack
            Services: `auth-service`
        """,
        )
        _write_text(
            out_dir / "threat-model.md",
            """
            ## Management Summary
            > **Verdict**: acceptable risk posture
            **Risk Distribution:** Critical: 1 · High: 0 · Medium: 0 · Low: 0
        """,
        )
        _write_json(
            out_dir / ".threats-merged.json", {"threats": [{"t_id": "T-001", "risk": "Critical", "source": "stride"}]}
        )
        r = asc.run_all(out_dir)
        assert r["findings_total"] >= 2  # verdict_understates + critical_without_cvss


class TestArchitectureInputPack:
    def test_highlights_weak_controls_and_uncovered_high_findings(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            security_controls:
              - id: SC-01
                domain: SecretMgmt
                control: Externalized signing keys
                effectiveness: Missing
                linked_threats: [T-001]
                gaps:
                  - "Signing key is committed to source"
              - id: SC-02
                domain: AuditLogging
                control: Structured audit trail
                effectiveness: Adequate
            threats:
              - id: T-001
                title: JWT signing key in source
                risk: Critical
                component: api
                cwe: CWE-321
                architectural_theme: SecretManagement
              - id: T-002
                title: Admin route lacks authorization
                risk: High
                component: api
                cwe: CWE-862
                architectural_theme: Authorization
            trust_boundaries:
              - name: Internet to API
        """,
        )
        r = asc.run_all(out_dir)
        pack = r["architecture_input_pack"]
        assert pack["check"] == "architecture-input-pack"
        assert pack["weak_or_missing_controls_top"][0]["id"] == "SC-01"
        cluster_themes = {c["theme"] for c in pack["architecture_theme_clusters_top"]}
        assert "SecretManagement" in cluster_themes
        assert "Authorization" in cluster_themes
        high_ids = {f["id"] for f in pack["high_findings_top"]}
        assert {"T-001", "T-002"} <= high_ids
        assert pack["trust_boundaries_total"] == 1


class TestCLI:
    def test_all_subcommand(self, out_dir):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "all", "--output-dir", str(out_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(r.stdout)
        for key in ("arch_recon", "ms_verdict", "cvss_risk", "architecture_input_pack", "findings", "findings_total"):
            assert key in out

    def test_arch_recon_subcommand(self, out_dir):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "arch-recon", "--output-dir", str(out_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(r.stdout)
        assert out["check"] == "arch-recon"

    def test_ms_verdict_subcommand(self, out_dir):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "ms-verdict", "--output-dir", str(out_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(r.stdout)
        assert out["check"] == "ms-verdict"

    def test_cvss_risk_subcommand(self, out_dir):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "cvss-risk", "--output-dir", str(out_dir)],
            capture_output=True,
            text=True,
            check=True,
        )
        out = json.loads(r.stdout)
        assert out["check"] == "cvss-risk"

    def test_missing_output_dir(self, tmp_path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "all", "--output-dir", str(tmp_path / "nope")],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1


# ---------------------------------------------------------------------------
# Check 5 — mitigation_realism
# ---------------------------------------------------------------------------


class TestMitigationRealism:
    def test_critical_without_mitigation_flagged(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-001
                cwe: CWE-89
                stride: Tampering
                effective_severity: Critical
                mitigation_ids: []
            mitigations: []
            """,
        )
        r = asc.check_mitigation_realism(out_dir / "threat-model.yaml")
        kinds = {f["kind"] for f in r["findings"]}
        assert "missing_mitigation" in kinds

    def test_tls_for_injection_flagged(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-002
                cwe: CWE-89
                stride: Tampering
                effective_severity: High
                mitigation_ids: [M-001]
            mitigations:
              - id: M-001
                title: Enforce TLS / HTTPS everywhere
                threat_ids: [T-002]
                effort: Low
            """,
        )
        r = asc.check_mitigation_realism(out_dir / "threat-model.yaml")
        assert any(f["kind"] == "mitigation_type_mismatch" for f in r["findings"])

    def test_rootcause_mitigation_suppresses_flag(self, out_dir):
        # TLS co-listed with a real parameterization fix → no flag.
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-003
                cwe: CWE-89
                stride: Tampering
                effective_severity: High
                mitigation_ids: [M-001, M-002]
            mitigations:
              - id: M-001
                title: Enforce TLS everywhere
                threat_ids: [T-003]
                effort: Low
              - id: M-002
                title: Replace raw SQL with parameterized Sequelize ORM query
                threat_ids: [T-003]
                effort: Medium
            """,
        )
        r = asc.check_mitigation_realism(out_dir / "threat-model.yaml")
        assert r["findings"] == []

    def test_absent_yaml_no_findings(self, out_dir):
        r = asc.check_mitigation_realism(out_dir / "missing.yaml")
        assert r["findings"] == []


# ---------------------------------------------------------------------------
# Check 12 — remediation_roi
# ---------------------------------------------------------------------------


class TestRemediationRoi:
    def test_high_roi_not_prioritized_flagged(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-001
                effective_severity: Critical
              - id: T-002
                effective_severity: High
              - id: T-003
                effective_severity: High
            mitigations:
              - id: M-001
                title: One fix closes three
                threat_ids: [T-001, T-002, T-003]
                effort: Low
                priority: P3
            """,
        )
        r = asc.check_remediation_roi(out_dir / "threat-model.yaml")
        assert any(f["kind"] == "high_roi_mitigation_not_prioritized" for f in r["findings"])
        assert r["top5"][0]["roi"] == 3.0

    def test_p1_low_roi_info(self, out_dir):
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-001
                effective_severity: Medium
            mitigations:
              - id: M-001
                title: Expensive fix for one medium
                threat_ids: [T-001]
                effort: High
                priority: P1
            """,
        )
        r = asc.check_remediation_roi(out_dir / "threat-model.yaml")
        assert any(f["kind"] == "p1_low_roi" for f in r["findings"])


# ---------------------------------------------------------------------------
# Check 13 — config_iac
# ---------------------------------------------------------------------------


class TestConfigIac:
    def test_skip_when_absent(self, out_dir):
        r = asc.check_config_iac(out_dir)
        assert r["skipped"] is True
        assert r["findings"] == []

    def test_orphan_config_findings_flagged(self, out_dir):
        _write_json(out_dir / ".config-scan-findings.json", {"findings": [{"id": "C1"}, {"id": "C2"}]})
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-001
                source: stride
            """,
        )
        r = asc.check_config_iac(out_dir)
        assert r["skipped"] is False
        assert any(f["kind"] == "config_findings_orphan" for f in r["findings"])

    def test_config_mapped_no_finding(self, out_dir):
        _write_json(out_dir / ".config-scan-findings.json", {"findings": [{"id": "C1"}]})
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-001
                source: configuration-defect
            """,
        )
        r = asc.check_config_iac(out_dir)
        assert r["findings"] == []


# ---------------------------------------------------------------------------
# Check 15 — actor_coverage
# ---------------------------------------------------------------------------


class TestActorCoverage:
    def test_skip_when_absent(self, out_dir):
        r = asc.check_actor_coverage(out_dir)
        assert r["skipped"] is True

    def test_whole_model_gap_flagged(self, out_dir):
        _write_json(out_dir / ".actors-resolved.json", {"actors": [{"id": "internet-anon"}]})
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-001
                actor_ids: []
              - id: T-002
                actor_ids: []
            """,
        )
        r = asc.check_actor_coverage(out_dir)
        assert any(f["kind"] == "whole_model_no_actor_attribution" for f in r["findings"])

    def test_disabled_without_rationale_flagged(self, out_dir):
        _write_json(
            out_dir / ".actors-resolved.json",
            {"actors": [{"id": "ghost", "_provenance": {"disabled_by": "op", "disable_reason": ""}}]},
        )
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-001
                actor_ids: [internet-anon]
            """,
        )
        r = asc.check_actor_coverage(out_dir)
        assert any(f["kind"] == "actor_disabled_without_rationale" for f in r["findings"])

    def test_reads_resolved_actors_and_flags_unused_proposal(self, out_dir):
        _write_json(
            out_dir / ".actors-resolved.json",
            {
                "resolved_actors": [
                    {
                        "id": "ACT-X-1",
                        "_provenance": {"layer": "discovery", "proposed": True, "active": True},
                    }
                ]
            },
        )
        _write_yaml(
            out_dir / "threat-model.yaml",
            """
            threats:
              - id: T-001
                actor_ids: [ACT-D-01]
            """,
        )
        r = asc.check_actor_coverage(out_dir)
        assert r["actor_count"] == 1
        assert any(f["kind"] == "proposed_actor_no_findings" for f in r["findings"])


# ---------------------------------------------------------------------------
# Check 14 — sec7_quality_bar
# ---------------------------------------------------------------------------


_CLEAN_SEC7 = """
### 6.1 Security Control Overview

| Control category | Verdict | Main reason |
|---|---|---|
| Authentication | Unsafe | raw SQL |

### 6.2 Identity and Authentication Controls

**Controls covered:** [Password-Based Authentication](#x)

#### 6.2.1 Password-Based Authentication

**Status:** 🔴 Missing - raw SQL login.

`routes/login.ts` builds a raw query.

**Security assessment**

The login query interpolates input.

**Relevant findings**

- [F-001](#f-001)
"""


def _sec7_doc(body: str) -> str:
    head = "# Threat Model\n\n## 6. Security Architecture\n\n"
    tail = "\n\n## 8. Threat Register\n\nrows\n"
    return head + body.strip() + tail


class TestSec7QualityBar:
    def _full_clean(self) -> str:
        # 6.1 + 6.2 + 6.3..6.13 stub headings so the heading-set check passes.
        extra = "\n".join(f"### 6.{n} Section {n}\n\nprose\n" for n in range(3, 14))
        return _sec7_doc(_CLEAN_SEC7 + "\n" + extra)

    def test_clean_sec7_no_findings(self, out_dir):
        _write_text(out_dir / "threat-model.md", self._full_clean())
        r = asc.check_sec7_quality_bar(out_dir / "threat-model.md")
        assert r["skipped"] is False
        assert r["findings"] == [], [f["kind"] for f in r["findings"]]

    def test_missing_heading_flagged(self, out_dir):
        # Drop 6.13 → heading-set violation.
        body = _CLEAN_SEC7 + "\n" + "\n".join(f"### 6.{n} Section {n}\n\nprose\n" for n in range(3, 13))
        _write_text(out_dir / "threat-model.md", _sec7_doc(body))
        r = asc.check_sec7_quality_bar(out_dir / "threat-model.md")
        assert any(f["kind"] == "sec7_v2_heading_set" for f in r["findings"])

    def test_h4_missing_status_flagged(self, out_dir):
        bad = _CLEAN_SEC7.replace("**Status:** 🔴 Missing - raw SQL login.\n\n", "")
        body = bad + "\n" + "\n".join(f"### 6.{n} S{n}\n\np\n" for n in range(3, 14))
        _write_text(out_dir / "threat-model.md", _sec7_doc(body))
        r = asc.check_sec7_quality_bar(out_dir / "threat-model.md")
        assert any(f["kind"] == "section7_h4_status" for f in r["findings"])

    def test_h4_labels_with_colon_inside_span_not_flagged(self, out_dir):
        """Regression (2026-06-13 juice-shop): the renderer emits
        `**Security assessment:**` (colon INSIDE the bold span). A literal
        `'**Security assessment**' not in block` check false-positived
        sec7_v2_h4_labels on every H4 block. The label probe must tolerate the
        optional colon."""
        colon = _CLEAN_SEC7.replace("**Security assessment**", "**Security assessment:**")
        # sanity: the fixture really does use the colon form now
        assert "**Security assessment:**" in colon
        body = colon + "\n" + "\n".join(f"### 6.{n} S{n}\n\np\n" for n in range(3, 14))
        _write_text(out_dir / "threat-model.md", _sec7_doc(body))
        r = asc.check_sec7_quality_bar(out_dir / "threat-model.md")
        assert not any(f["kind"] == "sec7_v2_h4_labels" for f in r["findings"]), [f["kind"] for f in r["findings"]]

    def test_legacy_flow_flagged(self, out_dir):
        body = (
            _CLEAN_SEC7
            + "\n**Findings in this flow:** F-001\n\n"
            + "\n".join(f"### 6.{n} S{n}\n\np\n" for n in range(3, 14))
        )
        _write_text(out_dir / "threat-model.md", _sec7_doc(body))
        r = asc.check_sec7_quality_bar(out_dir / "threat-model.md")
        assert any(f["kind"] == "sec7_v2_no_legacy_flows" for f in r["findings"])

    def test_skip_when_no_sec7(self, out_dir):
        _write_text(out_dir / "threat-model.md", "# Threat Model\n\n## 8. Threats\n\nrows\n")
        r = asc.check_sec7_quality_bar(out_dir / "threat-model.md")
        assert r["skipped"] is True
