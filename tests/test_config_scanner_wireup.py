"""Tests for the Config-Scanner Phase 2.5 wire-up (M3.5).

Verifies:
  - Schema is registered in validate_intermediate.py
  - Schema accepts well-formed examples and rejects malformed ones
  - phase-group-recon.md contains the dispatch block
  - appsec-threat-analyst.md references Phase 2.5 in its process flow
  - AGENTS.md lists Phase 2.5
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCHEMAS_DIR = ROOT / "schemas"
SCHEMA_PATH = SCHEMAS_DIR / "config-scan-findings.schema.yaml"
VALIDATE = ROOT / "scripts" / "validate_intermediate.py"


# ---------------------------------------------------------------------------
# Schema integration
# ---------------------------------------------------------------------------


class TestSchemaRegistration:
    def test_schema_file_exists(self):
        assert SCHEMA_PATH.exists(), (
            f"{SCHEMA_PATH} must exist for Phase 2.5 output validation"
        )

    def test_schema_registered_in_validate_intermediate(self):
        text = VALIDATE.read_text()
        assert "config_scan_findings" in text, (
            "validate_intermediate.py must register config_scan_findings kind"
        )
        assert "config-scan-findings.schema.yaml" in text, (
            "validate_intermediate.py must reference the schema filename"
        )


# ---------------------------------------------------------------------------
# Schema content shape (well-formed accepted, malformed rejected)
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_findings_doc():
    return {
        "version": 1,
        "generated_at": "2026-05-01T10:00:00Z",
        "checks_run": 5,
        "violations": 2,
        "findings": [
            {
                "local_id": "CFG-001",
                "check_id": "IAC-001",
                "iac_type": "Dockerfile",
                "file": "Dockerfile",
                "line": 1,
                "evidence_snippet": "FROM node:24",
                "title": "Docker base image not digest-pinned",
                "severity": "High",
                "cwe": ["CWE-1104"],
                "breach_vector": "Build-Time",
            },
            {
                "local_id": "CFG-002",
                "check_id": "IAC-027a",
                "iac_type": "github_workflow",
                "file": ".github/workflows/ci.yml",
                "line": 12,
                "title": "pull_request_target with HEAD checkout",
                "severity": "Critical",
                "cwe": ["CWE-829"],
                "breach_vector": "Build-Time",
            },
        ],
    }


def _validate_with_schema(doc, kind="config_scan_findings"):
    """Round-trip a doc through validate_intermediate.py."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                     delete=False) as f:
        json.dump(doc, f)
        path = f.name
    try:
        result = subprocess.run(
            [sys.executable, str(VALIDATE), kind, path],
            capture_output=True, text=True
        )
        return result.returncode, result.stdout, result.stderr
    finally:
        os.unlink(path)


class TestSchemaValidation:
    def test_well_formed_doc_accepted(self, valid_findings_doc):
        rc, _, err = _validate_with_schema(valid_findings_doc)
        assert rc == 0, f"Valid doc rejected: {err}"

    def test_missing_required_field_rejected(self, valid_findings_doc):
        broken = dict(valid_findings_doc)
        del broken["findings"]
        rc, _, _ = _validate_with_schema(broken)
        assert rc != 0, "Doc missing 'findings' must fail validation"

    def test_bad_severity_rejected(self, valid_findings_doc):
        valid_findings_doc["findings"][0]["severity"] = "Catastrophic"
        rc, _, _ = _validate_with_schema(valid_findings_doc)
        assert rc != 0, "Bad severity must fail validation"

    def test_malformed_local_id_rejected(self, valid_findings_doc):
        valid_findings_doc["findings"][0]["local_id"] = "X-1"
        rc, _, _ = _validate_with_schema(valid_findings_doc)
        assert rc != 0, "Local-ID must match CFG-NNN pattern"

    def test_unknown_iac_type_rejected(self, valid_findings_doc):
        valid_findings_doc["findings"][0]["iac_type"] = "MyCustomFormat"
        rc, _, _ = _validate_with_schema(valid_findings_doc)
        assert rc != 0, "iac_type must be from enum"

    def test_empty_findings_list_accepted(self, valid_findings_doc):
        valid_findings_doc["findings"] = []
        valid_findings_doc["violations"] = 0
        rc, _, err = _validate_with_schema(valid_findings_doc)
        assert rc == 0, f"Empty findings list must be valid: {err}"

    def test_error_stub_accepted(self):
        stub = {"parse_error": "yaml load failed", "findings": []}
        rc, _, err = _validate_with_schema(stub)
        assert rc == 0, f"Error stub must be accepted: {err}"


# ---------------------------------------------------------------------------
# Spec docs reference Phase 2.5
# ---------------------------------------------------------------------------


class TestSpecIntegration:
    def test_phase_group_recon_has_phase_2_5_block(self):
        text = (ROOT / "agents" / "phases" / "phase-group-recon.md").read_text()
        assert "Phase 2.5" in text, (
            "phase-group-recon.md must define Phase 2.5"
        )
        assert "appsec-config-scanner" in text, (
            "phase-group-recon.md Phase 2.5 must reference the config-scanner agent"
        )
        assert "$CONFIG_SCANNER_MODEL" in text, (
            "Phase 2.5 dispatch must thread $CONFIG_SCANNER_MODEL"
        )
        assert ".config-scan-findings.json" in text, (
            "Phase 2.5 must reference the output filename"
        )

    def test_threat_analyst_references_phase_2_5(self):
        text = (ROOT / "agents" / "appsec-threat-analyst.md").read_text()
        assert "Phase 2.5" in text, (
            "appsec-threat-analyst.md must reference Phase 2.5 in its process flow"
        )

    def test_agents_md_lists_phase_2_5(self):
        text = (ROOT / "AGENTS.md").read_text()
        assert "2.5. Config" in text or "Phase 2.5" in text, (
            "AGENTS.md phase list must include Phase 2.5"
        )

    def test_agents_md_no_longer_calls_config_scanner_wip(self):
        """The Roadmap entry should be removed once wire-up is done."""
        text = (ROOT / "AGENTS.md").read_text()
        assert "WIP agent" not in text or "appsec-config-scanner" not in (
            t.split("WIP agent")[1].split("\n")[0]
            for t in [text] if "WIP agent" in text
        ).__next__() if "WIP agent" in text else True


# ---------------------------------------------------------------------------
# Pre-check correctness — skip when no IaC surface
# ---------------------------------------------------------------------------


class TestPreCheck:
    def test_phase_recon_documents_skip_condition(self):
        text = (ROOT / "agents" / "phases" / "phase-group-recon.md").read_text()
        assert "HAS_IAC_SURFACE" in text, (
            "phase-group-recon.md must define the IaC pre-check"
        )
        assert "no IaC surface" in text or "skipped" in text.lower(), (
            "Pre-check must document skip behaviour"
        )
