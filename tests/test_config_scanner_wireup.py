"""Tests for the Config-Scanner Phase 2.5 wire-up (M3.5).

Verifies:
  - Schema is registered in validate_intermediate.py
  - Schema accepts well-formed examples and rejects malformed ones
  - orchestration_controller.py owns the dispatch block
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import config_iac_scanner as scanner
import pytest
import yaml

ROOT = Path(__file__).parent.parent
SCHEMAS_DIR = ROOT / "schemas"
SCHEMA_PATH = SCHEMAS_DIR / "config-scan-findings.schema.yaml"
VALIDATE = ROOT / "scripts" / "validate_intermediate.py"
CATALOG = yaml.safe_load((ROOT / "data" / "config-iac-checks.yaml").read_text(encoding="utf-8"))["checks"]
CATALOG_SIZE = len(CATALOG)


# ---------------------------------------------------------------------------
# Schema integration
# ---------------------------------------------------------------------------


class TestSchemaRegistration:
    def test_schema_file_exists(self):
        assert SCHEMA_PATH.exists(), f"{SCHEMA_PATH} must exist for Phase 2.5 output validation"

    def test_schema_registered_in_validate_intermediate(self):
        text = VALIDATE.read_text()
        assert "config_scan_findings" in text, "validate_intermediate.py must register config_scan_findings kind"
        assert "config-scan-findings.schema.yaml" in text, "validate_intermediate.py must reference the schema filename"


# ---------------------------------------------------------------------------
# Schema content shape (well-formed accepted, malformed rejected)
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_findings_doc():
    return {
        "version": 1,
        "generated_at": "2026-05-01T10:00:00Z",
        "checks_run": CATALOG_SIZE,
        "violations": 2,
        "findings": [
            {
                "local_id": "CFG-001",
                "check_id": "IAC-001",
                **scanner.canonical_finding_fields(next(check for check in CATALOG if check["id"] == "IAC-001")),
                "file": "Dockerfile",
                "line": 1,
                "evidence_snippet": "FROM node:24",
                "breach_vector": "Build-Time",
            },
            {
                "local_id": "CFG-002",
                "check_id": None,
                "check_slug": "runtime-cors",
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
    import os
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(doc, f)
        path = f.name
    try:
        result = subprocess.run([sys.executable, str(VALIDATE), kind, path], capture_output=True, text=True)
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

    def test_partial_catalog_count_is_rejected(self, valid_findings_doc):
        valid_findings_doc["checks_run"] = 12
        rc, out, err = _validate_with_schema(valid_findings_doc)
        assert rc != 0
        assert "complete catalog size" in out + err

    def test_stale_violation_count_is_rejected(self, valid_findings_doc):
        valid_findings_doc["violations"] = 1
        rc, out, err = _validate_with_schema(valid_findings_doc)
        assert rc != 0
        assert "violations must equal findings length" in out + err

    def test_canonical_check_metadata_drift_is_rejected(self, valid_findings_doc):
        valid_findings_doc["findings"][0]["severity"] = "Low"
        rc, out, err = _validate_with_schema(valid_findings_doc)
        assert rc != 0
        assert "differs from canonical check IAC-001" in out + err

    def test_error_stub_accepted(self):
        stub = {"parse_error": "yaml load failed", "findings": []}
        rc, _, err = _validate_with_schema(stub)
        assert rc == 0, f"Error stub must be accepted: {err}"


# ---------------------------------------------------------------------------
# Producer → validator round trip over the shipped catalog
# ---------------------------------------------------------------------------


def _scan_then_validate(repo: Path, output: Path) -> tuple[int, str, list[dict]]:
    assert scanner.main(["--repo-root", str(repo), "--output", str(output)]) == 0
    result = subprocess.run(
        [sys.executable, str(VALIDATE), "config_scan_findings", str(output)], capture_output=True, text=True
    )
    return result.returncode, result.stdout + result.stderr, json.loads(output.read_text(encoding="utf-8"))["findings"]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


WORKFLOW = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: vendor/action@v1\n"


class TestScannerOutputPassesItsValidator:
    def test_container_and_workflow_violations_validate(self, tmp_path):
        repo = tmp_path / "service"
        _write(repo / "Dockerfile", "FROM runtime:latest\nRUN make\n")
        _write(repo / ".github" / "workflows" / "build.yml", WORKFLOW)
        rc, detail, findings = _scan_then_validate(repo, tmp_path / "scan.json")
        assert findings
        assert rc == 0, detail

    def test_nested_images_and_workflows_with_other_names_validate(self, tmp_path):
        repo = tmp_path / "platform"
        _write(repo / "images" / "worker" / "Dockerfile.release", "FROM base-image:3\nUSER root\n")
        _write(repo / "deploy" / ".github" / "workflows" / "release.yaml", WORKFLOW)
        rc, detail, findings = _scan_then_validate(repo, tmp_path / "scan.json")
        assert {finding["iac_type"] for finding in findings} >= {"Dockerfile", "github_workflow"}
        assert rc == 0, detail

    def test_a_title_restated_as_the_desired_state_is_still_rejected(self, tmp_path):
        repo = tmp_path / "service"
        _write(repo / "Dockerfile", "FROM runtime:latest\n")
        output = tmp_path / "scan.json"
        _scan_then_validate(repo, output)
        doc = json.loads(output.read_text(encoding="utf-8"))
        first = doc["findings"][0]
        first["title"] = next(check["name"] for check in CATALOG if check["id"] == first["check_id"])
        output.write_text(json.dumps(doc), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(VALIDATE), "config_scan_findings", str(output)], capture_output=True, text=True
        )
        assert result.returncode != 0
        assert f"findings[0].title differs from canonical check {first['check_id']}" in result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Runtime integration
# ---------------------------------------------------------------------------


class TestSpecIntegration:
    def test_context_v2_dispatch_supplies_config_depth_alias(self):
        text = (ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md").read_text()
        assert "config gets `ASSESSMENT_DEPTH`" in text

    def test_config_scanner_contains_all_repository_access_and_output_paths(self):
        text = (ROOT / "agents" / "appsec-config-scanner.md").read_text()
        assert "scripts/config_iac_scanner.py" in text
        assert "Do not independently read the catalog" in text
        assert "only `scripts/config_iac_scanner.py` may emit this artifact" in text
        assert "derive `checks_run` and `violations` from those exact final bytes" in text

    def test_controller_routes_the_config_scanner(self):
        text = (ROOT / "scripts" / "orchestration_controller.py").read_text()
        assert '"agent": "appsec-config-scanner"' in text


# ---------------------------------------------------------------------------
# Pre-check correctness — skip when no IaC surface
# ---------------------------------------------------------------------------


class TestPreCheck:
    def test_controller_owns_the_iac_surface_precheck(self):
        text = (ROOT / "scripts" / "orchestration_controller.py").read_text()
        assert "_has_iac_surface" in text
        assert "config scan skipped: no IaC surface" in text
