"""Tests for CVSS v4 vector eligibility rules in validate_intermediate.py.

Locks in the policy that:
  * known-vuln threats MUST carry a vector (dep-scan source removed 2026-05)
  * design / policy / coverage-gap threats MUST NOT
  * stride threats may carry one only when the CWE is on the positive list
    AND evidence.line is set
  * severity must be within one band of the qualitative risk
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

VALIDATE_PATH = Path(__file__).parent.parent / "scripts" / "validate_intermediate.py"


@pytest.fixture(scope="module")
def vi():
    spec = importlib.util.spec_from_file_location("validate_intermediate", VALIDATE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_intermediate"] = module
    spec.loader.exec_module(module)
    return module


def _stride_threat(**overrides):
    base = {
        "id": "T-001",
        "source": "stride",
        "title": "x",
        "stride": "T",
        "risk": "High",
        "cwe": "CWE-89",  # SQL Injection — assumed to be on the eligible list
        "evidence": {"file": "src/db.py", "line": 42},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Eligibility list loads
# ---------------------------------------------------------------------------


class TestEligibilityList:
    def test_eligible_list_loads_and_is_non_empty(self, vi):
        cwes = vi._eligible_cwes()
        assert isinstance(cwes, frozenset)
        assert len(cwes) > 0, "cvss-eligible-cwes.yaml produced an empty set"

    def test_common_injection_cwes_present(self, vi):
        cwes = vi._eligible_cwes()
        # CWE-89 (SQLi) is the canonical example in plugin docs
        assert "CWE-89" in cwes, (
            "CWE-89 (SQL Injection) must be in cvss-eligible-cwes.yaml — "
            "the plugin's STRIDE analyzer relies on it as the eligibility anchor"
        )


# ---------------------------------------------------------------------------
# Required sources (known-vuln only since 2026-05; dep-scan source removed)
# ---------------------------------------------------------------------------


class TestRequiredSources:
    @pytest.mark.parametrize("source", ["known-vuln"])
    def test_missing_cvss_for_required_source(self, vi, source):
        data = {"threats": [{"id": "T-001", "source": source, "risk": "High"}]}
        errors = vi._check_cvss_eligibility(data)
        assert any("cvss_v4 is required" in e for e in errors)

    def test_present_cvss_for_required_source_passes(self, vi):
        data = {
            "threats": [
                {
                    "id": "T-001",
                    "source": "known-vuln",
                    "risk": "High",
                    "cvss_v4": {
                        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                        "severity": "High",
                    },
                }
            ]
        }
        assert vi._check_cvss_eligibility(data) == []


# ---------------------------------------------------------------------------
# Forbidden sources
# ---------------------------------------------------------------------------


class TestForbiddenSources:
    @pytest.mark.parametrize(
        "source",
        ["requirements-compliance", "architectural-anti-pattern", "coverage-gap"],
    )
    def test_cvss_forbidden(self, vi, source):
        data = {
            "threats": [
                {
                    "id": "T-001",
                    "source": source,
                    "risk": "Medium",
                    "cvss_v4": {"vector": "CVSS:4.0/AV:N/...", "severity": "Medium"},
                }
            ]
        }
        errors = vi._check_cvss_eligibility(data)
        assert any("not permitted" in e for e in errors)

    @pytest.mark.parametrize(
        "source",
        ["requirements-compliance", "architectural-anti-pattern", "coverage-gap"],
    )
    def test_no_cvss_for_forbidden_source_passes(self, vi, source):
        data = {"threats": [{"id": "T-001", "source": source, "risk": "Medium"}]}
        assert vi._check_cvss_eligibility(data) == []


# ---------------------------------------------------------------------------
# STRIDE source — conditional eligibility
# ---------------------------------------------------------------------------


class TestStrideSource:
    def test_stride_eligible_cwe_with_line_passes(self, vi):
        data = {
            "threats": [
                _stride_threat(
                    cvss_v4={"vector": "CVSS:4.0/...", "severity": "High"},
                )
            ]
        }
        assert vi._check_cvss_eligibility(data) == []

    def test_stride_no_cvss_passes(self, vi):
        data = {"threats": [_stride_threat()]}
        assert vi._check_cvss_eligibility(data) == []

    def test_stride_ineligible_cwe_rejected(self, vi):
        data = {
            "threats": [
                _stride_threat(
                    cwe="CWE-1234567",  # synthetic, never eligible
                    cvss_v4={"vector": "CVSS:4.0/...", "severity": "High"},
                )
            ]
        }
        errors = vi._check_cvss_eligibility(data)
        assert any("not in cvss-eligible-cwes.yaml" in e for e in errors)

    def test_stride_missing_evidence_line_rejected(self, vi):
        data = {
            "threats": [
                _stride_threat(
                    evidence={"file": "src/db.py"},  # no line
                    cvss_v4={"vector": "CVSS:4.0/...", "severity": "High"},
                )
            ]
        }
        errors = vi._check_cvss_eligibility(data)
        assert any("requires evidence.line" in e for e in errors)

    def test_stride_invalid_cwe_format_rejected(self, vi):
        data = {
            "threats": [
                _stride_threat(
                    cwe="SQLi",  # not CWE-NNN
                    cvss_v4={"vector": "CVSS:4.0/...", "severity": "High"},
                )
            ]
        }
        errors = vi._check_cvss_eligibility(data)
        assert any("requires a valid CWE reference" in e for e in errors)


# ---------------------------------------------------------------------------
# Severity-band coherence
# ---------------------------------------------------------------------------


class TestSeverityBand:
    def test_severity_critical_with_low_risk_rejected(self, vi):
        data = {
            "threats": [
                _stride_threat(
                    risk="Low",
                    cvss_v4={"vector": "CVSS:4.0/...", "severity": "Critical"},
                )
            ]
        }
        errors = vi._check_cvss_eligibility(data)
        assert any("more than one band away" in e for e in errors)

    def test_severity_one_band_off_passes(self, vi):
        data = {
            "threats": [
                _stride_threat(
                    risk="High",
                    cvss_v4={"vector": "CVSS:4.0/...", "severity": "Medium"},
                )
            ]
        }
        # Only severity gap — should not flag (one-band tolerance)
        errors = [e for e in vi._check_cvss_eligibility(data) if "band" in e]
        assert errors == []

    def test_severity_match_passes(self, vi):
        data = {
            "threats": [
                _stride_threat(
                    risk="High",
                    cvss_v4={"vector": "CVSS:4.0/...", "severity": "High"},
                )
            ]
        }
        assert vi._check_cvss_eligibility(data) == []
