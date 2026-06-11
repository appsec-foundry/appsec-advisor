"""Tests for scripts/qa_arch_coverage.py — completeness + semantic gates.

Per arch.md §Pipeline-Integration Punkt 7: applicable rule with
{partial, weak, missing, anti_pattern} status MUST be visible downstream.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "qa_arch_coverage.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import qa_arch_coverage as qa  # noqa: E402


def _coverage(rule_status: str, rule_id: str = "ARCH-CORS-001", applies: bool = True) -> dict:
    return {
        "version": 1,
        "rules_evaluated": [
            {
                "rule_id": rule_id,
                "title": "x",
                "status": rule_status,
                "applies": applies,
                "confidence": "high",
                "control": "CORS Policy",
                "domain": "FrontendSec",
                "evidence": [],
                "decision": "emit_control_and_threat_candidate",
            }
        ],
        "control_assessments": [],
        "threat_hypotheses": [],
        "anti_pattern_candidates": [],
        "warnings": [],
    }


# ---------------------------------------------------------------------------
# Completeness
# ---------------------------------------------------------------------------


def test_applicable_rule_invisible_downstream_fails():
    cov = _coverage("anti_pattern")
    issues = qa.check_completeness(cov, threat_model={}, threats_merged={})
    assert len(issues) == 1
    assert issues[0]["rule_id"] == "ARCH-CORS-001"
    assert issues[0]["kind"] == "invisible_downstream"


def test_rule_visible_via_security_controls_passes():
    cov = _coverage("weak")
    tm = {
        "security_controls": [
            {
                "control": "CORS Policy",
                "rule_id": "ARCH-CORS-001",
                "effectiveness": "Weak",
            }
        ]
    }
    assert qa.check_completeness(cov, tm, {}) == []


def test_rule_visible_via_security_controls_notes_passes():
    cov = _coverage("weak")
    tm = {
        "security_controls": [
            {
                "control": "CORS Policy",
                "effectiveness": "Weak",
                "notes": "Auto-flagged from ARCH-CORS-001 evaluator (wildcard origin + creds).",
            }
        ]
    }
    assert qa.check_completeness(cov, tm, {}) == []


def test_rule_visible_via_threat_hypotheses_passes():
    cov = _coverage("weak", rule_id="ARCH-SQLI-001")
    tm = {
        "threat_hypotheses": [
            {
                "id": "HYP-001",
                "rule_id": "ARCH-SQLI-001",
                "source_hypothesis_id": "ARCH-HYP-SQLI-001",
                "title": "x",
                "threat_category_id": "TH-01",
                "cwe": "CWE-89",
                "proof_state": "control-derived",
                "confidence": "medium",
            }
        ]
    }
    assert qa.check_completeness(cov, tm, {}) == []


def test_rule_visible_via_threats_merged_passes():
    cov = _coverage("anti_pattern", rule_id="ARCH-TLS-001")
    merged = {
        "threats": [
            {
                "t_id": "T-001",
                "source": "architecture-coverage",
                "rule_id": "ARCH-TLS-001",
                "cwe": "CWE-319",
                "risk": "High",
            }
        ]
    }
    assert qa.check_completeness(cov, {}, merged) == []


def test_present_rule_not_required_downstream():
    """Per arch.md: present and not_applicable are audit-only."""
    cov = _coverage("present")
    assert qa.check_completeness(cov, {}, {}) == []


def test_not_applicable_rule_not_required_downstream():
    cov = _coverage("not_applicable", applies=False)
    assert qa.check_completeness(cov, {}, {}) == []


def test_threats_merged_source_must_be_arch_to_count():
    """A stride threat that happens to carry the rule_id token doesn't
    satisfy completeness — wiring must be authentic."""
    cov = _coverage("anti_pattern", rule_id="ARCH-TLS-001")
    merged = {
        "threats": [
            {
                "t_id": "T-001",
                "source": "stride",
                "rule_id": "ARCH-TLS-001",  # invalid in the validator but kept to test the gate
                "cwe": "CWE-319",
                "risk": "High",
            }
        ]
    }
    issues = qa.check_completeness(cov, {}, merged)
    assert len(issues) == 1


# ---------------------------------------------------------------------------
# Semantics
# ---------------------------------------------------------------------------


def test_cvss_on_architecture_coverage_threat_flagged():
    merged = {
        "threats": [
            {
                "t_id": "T-001",
                "source": "architecture-coverage",
                "rule_id": "ARCH-CORS-001",
                "cvss_v4": {"vector": "CVSS:4.0/AV:N", "base_score": 9.8, "severity": "Critical"},
            }
        ]
    }
    issues = qa.check_semantics({}, merged)
    assert any(i["kind"] == "cvss_on_arch_source" for i in issues)


def test_critical_on_architecture_coverage_threat_flagged():
    merged = {
        "threats": [
            {
                "t_id": "T-001",
                "source": "architecture-coverage",
                "rule_id": "ARCH-CORS-001",
                "risk": "Critical",
            }
        ]
    }
    issues = qa.check_semantics({}, merged)
    assert any(i["kind"] == "critical_on_arch_source" for i in issues)


def test_cvss_on_hypothesis_flagged():
    tm = {
        "threat_hypotheses": [
            {
                "id": "HYP-001",
                "rule_id": "ARCH-SQLI-001",
                "cvss_v4": {"vector": "x", "base_score": 1.0, "severity": "Low"},
            }
        ]
    }
    issues = qa.check_semantics(tm, {})
    assert any(i["kind"] == "cvss_on_hypothesis" for i in issues)


def test_critical_on_hypothesis_flagged():
    tm = {
        "threat_hypotheses": [
            {
                "id": "HYP-001",
                "rule_id": "ARCH-SQLI-001",
                "risk": "Critical",
            }
        ]
    }
    issues = qa.check_semantics(tm, {})
    assert any(i["kind"] == "critical_on_hypothesis" for i in issues)


def test_stride_source_unaffected_by_semantic_check():
    """Regression guard — semantic checks only target the new sources."""
    merged = {
        "threats": [
            {
                "t_id": "T-001",
                "source": "stride",
                "risk": "Critical",
                "cvss_v4": {"vector": "x", "base_score": 9.5, "severity": "Critical"},
            }
        ]
    }
    assert qa.check_semantics({}, merged) == []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _write_output_dir(
    tmp_path: Path, coverage: dict | None, threat_model: dict | None = None, threats_merged: dict | None = None
) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    if coverage is not None:
        (out / ".architecture-coverage.json").write_text(json.dumps(coverage))
    if threat_model is not None:
        (out / "threat-model.yaml").write_text(yaml.dump(threat_model))
    if threats_merged is not None:
        (out / ".threats-merged.json").write_text(json.dumps(threats_merged))
    return out


def test_cli_skips_silently_when_no_coverage_file(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    result = subprocess.run([sys.executable, str(SCRIPT), str(out)], capture_output=True, text=True)
    assert result.returncode == 0
    assert "SKIP" in result.stdout


def test_cli_fails_when_completeness_violation(tmp_path: Path):
    out = _write_output_dir(tmp_path, coverage=_coverage("anti_pattern"))
    result = subprocess.run([sys.executable, str(SCRIPT), str(out)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "invisible_downstream" in result.stdout
    assert "ARCH-CORS-001" in result.stdout


def test_cli_passes_when_rule_visible(tmp_path: Path):
    cov = _coverage("anti_pattern", rule_id="ARCH-TLS-001")
    merged = {
        "version": 1,
        "generated_at": "x",
        "threats": [
            {
                "t_id": "T-001",
                "source": "architecture-coverage",
                "rule_id": "ARCH-TLS-001",
                "cwe": "CWE-319",
                "risk": "High",
            }
        ],
    }
    out = _write_output_dir(tmp_path, coverage=cov, threats_merged=merged)
    result = subprocess.run([sys.executable, str(SCRIPT), str(out)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_cli_json_output_shape(tmp_path: Path):
    out = _write_output_dir(tmp_path, coverage=_coverage("weak"))
    result = subprocess.run([sys.executable, str(SCRIPT), str(out), "--json"], capture_output=True, text=True)
    payload = json.loads(result.stdout)
    assert payload["total"] >= 1
    assert "completeness_issues" in payload
    assert "semantic_issues" in payload
