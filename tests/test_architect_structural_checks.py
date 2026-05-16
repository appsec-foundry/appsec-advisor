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

    def test_dep_scan_critical_without_cvss_accepted(self, out_dir):
        """Only 'source: stride' threats are flagged — dep-scan / known-vuln
        critical-without-cvss entries are handled elsewhere."""
        _write_json(
            out_dir / ".threats-merged.json", {"threats": [{"t_id": "T-005", "risk": "Critical", "source": "dep-scan"}]}
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
            architectural_findings:
              - id: AF-001
                title: Secrets in source
                architectural_theme: SecretManagement
                severity: High
                aggregates_findings:
                  - ref: T-001
                    label: JWT signing key
                primary_mitigations:
                  - ref: M-001
                    label: Move keys to KMS
            threats:
              - id: T-001
                title: JWT signing key in source
                risk: Critical
                component: api
                cwe: CWE-321
              - id: T-002
                title: Admin route lacks authorization
                risk: High
                component: api
                cwe: CWE-862
            trust_boundaries:
              - name: Internet to API
        """,
        )
        r = asc.run_all(out_dir)
        pack = r["architecture_input_pack"]
        assert pack["check"] == "architecture-input-pack"
        assert pack["weak_or_missing_controls_top"][0]["id"] == "SC-01"
        assert pack["high_leverage_architectural_findings_top"][0]["id"] == "AF-001"
        assert pack["uncovered_high_findings_top"][0]["id"] == "T-002"
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
