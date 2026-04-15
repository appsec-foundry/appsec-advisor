"""
Tests for the newly added validators: triage-flags, threat-model output,
and user-supplied known-threats.

Covers happy-path, schema-level violations, and the Python post-checks
that JSONSchema Draft 2020-12 cannot express (sequential TF-NNN, counter
consistency, unique known-threat IDs).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "plugin" / "scripts"))

from validate_intermediate import (  # noqa: E402
    validate_known_threats,
    validate_threat_model_output,
    validate_triage_flags,
)


# ---------------------------------------------------------------------------
# triage-flags
# ---------------------------------------------------------------------------


def _valid_triage() -> dict:
    return {
        "version": 1,
        "generated_at": "2026-04-15T12:00:00Z",
        "flags": [
            {
                "flag_id": "TF-001",
                "type": "consistency",
                "severity": "warning",
                "threat_ids": ["T-001"],
                "message": "Rating drift across similar components",
            },
            {
                "flag_id": "TF-002",
                "type": "cvss_band_mismatch",
                "severity": "info",
                "threat_ids": ["T-003"],
                "message": "CVSS severity differs from risk band",
            },
        ],
        "summary": {
            "total_flags": 2,
            "warnings": 1,
            "info": 1,
            "threats_reviewed": 2,
        },
    }


def test_triage_flags_valid():
    ok, errors = validate_triage_flags(_valid_triage())
    assert ok, errors


def test_triage_flags_empty_valid():
    data = {
        "version": 1,
        "generated_at": "2026-04-15T12:00:00Z",
        "flags": [],
        "summary": {
            "total_flags": 0,
            "warnings": 0,
            "info": 0,
            "threats_reviewed": 0,
        },
    }
    ok, errors = validate_triage_flags(data)
    assert ok, errors


def test_triage_flags_nonsequential_tf_id():
    data = _valid_triage()
    data["flags"][1]["flag_id"] = "TF-005"
    ok, errors = validate_triage_flags(data)
    assert not ok
    assert any("breaks sequential order" in e for e in errors)


def test_triage_flags_duplicate_tf_id():
    data = _valid_triage()
    data["flags"][1]["flag_id"] = "TF-001"
    ok, errors = validate_triage_flags(data)
    assert not ok
    assert any("duplicated" in e for e in errors)


def test_triage_flags_summary_total_mismatch():
    data = _valid_triage()
    data["summary"]["total_flags"] = 99
    ok, errors = validate_triage_flags(data)
    assert not ok
    assert any("total_flags" in e for e in errors)


def test_triage_flags_summary_warnings_info_mismatch():
    data = _valid_triage()
    # warnings + info no longer sums to total_flags
    data["summary"]["warnings"] = 2
    data["summary"]["info"] = 2
    data["summary"]["total_flags"] = 2
    ok, errors = validate_triage_flags(data)
    assert not ok


def test_triage_flags_invalid_type_enum():
    data = _valid_triage()
    data["flags"][0]["type"] = "not-a-real-type"
    ok, errors = validate_triage_flags(data)
    assert not ok


# ---------------------------------------------------------------------------
# threat-model.output
# ---------------------------------------------------------------------------


def test_threat_model_output_canonical_example_validates():
    path = ROOT / "docs" / "security" / "threat-model.yaml"
    if not path.exists():
        pytest.skip("no canonical threat-model.yaml example present")
    data = yaml.safe_load(path.read_text())
    ok, errors = validate_threat_model_output(data)
    assert ok, errors


def test_threat_model_output_missing_required_top_level():
    data = {
        "meta": {
            "schema_version": 1,
            "project": "x",
            "generated": "2026-04-15T00:00:00Z",
            "mode": "full",
            "model": "sonnet",
        },
        # missing components, assets, threats, etc.
    }
    ok, errors = validate_threat_model_output(data)
    assert not ok
    assert any("'components' is a required" in e or "components" in e for e in errors)


def test_threat_model_output_bad_threat_id_pattern():
    data = {
        "meta": {
            "schema_version": 1,
            "project": "x",
            "generated": "2026-04-15T00:00:00Z",
            "mode": "full",
            "model": "sonnet",
        },
        "components": [],
        "assets": [],
        "attack_surface": [],
        "trust_boundaries": [],
        "security_controls": [],
        "mitigations": [],
        "threats": [
            {
                "id": "BAD-1",
                "component": "x",
                "stride": "Spoofing",
                "scenario": "a scenario long enough",
                "likelihood": "Low",
                "impact": "Low",
                "risk": "Low",
            }
        ],
    }
    ok, errors = validate_threat_model_output(data)
    assert not ok


# ---------------------------------------------------------------------------
# known-threats
# ---------------------------------------------------------------------------


def _valid_known_threats() -> dict:
    return {
        "threats": [
            {
                "id": "PT-2025-001",
                "title": "Example",
                "stride": "Spoofing",
                "component": "auth",
                "severity": "High",
                "status": "open",
                "description": "A real finding.",
            }
        ]
    }


def test_known_threats_valid():
    ok, errors = validate_known_threats(_valid_known_threats())
    assert ok, errors


def test_known_threats_example_file_validates():
    path = ROOT / "examples" / "known-threats.yaml"
    if not path.exists():
        pytest.skip("example known-threats.yaml not present")
    data = yaml.safe_load(path.read_text())
    ok, errors = validate_known_threats(data)
    assert ok, errors


def test_known_threats_duplicate_ids_rejected():
    data = _valid_known_threats()
    data["threats"].append(dict(data["threats"][0]))
    ok, errors = validate_known_threats(data)
    assert not ok
    assert any("duplicated" in e for e in errors)


def test_known_threats_bad_status_enum():
    data = _valid_known_threats()
    data["threats"][0]["status"] = "someday-maybe"
    ok, errors = validate_known_threats(data)
    assert not ok


def test_known_threats_missing_required_field():
    data = {"threats": [{"id": "X-1", "title": "t"}]}
    ok, errors = validate_known_threats(data)
    assert not ok
