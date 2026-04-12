"""
Schema validation tests for .threats-merged.json — the canonical merged
threat list produced by Phase 9 after global T-NNN assignment. Downstream
tooling (diagram annotator, YAML/SARIF export, changelog writer) consumes
this file, so its schema is a load-bearing contract.
"""

import copy
import json
import sys
from pathlib import Path

import pytest

PLUGIN_SCRIPTS = Path(__file__).parent.parent / "plugin" / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))
from validate_intermediate import validate_threats_merged  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _load() -> dict:
    with (FIXTURES / "valid_threats_merged.json").open() as f:
        return json.load(f)


def test_valid_fixture_passes():
    ok, errors = validate_threats_merged(_load())
    assert ok, f"valid fixture failed: {errors}"
    assert errors == []


def test_missing_top_level_field():
    data = _load()
    del data["version"]
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("version" in e for e in errors)


def test_version_must_be_one():
    data = _load()
    data["version"] = 2
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("version" in e for e in errors)


def test_root_not_object():
    ok, errors = validate_threats_merged([])
    assert not ok
    assert errors == ["root must be a JSON object"]


def test_threats_must_be_array():
    data = _load()
    data["threats"] = {"not": "a list"}
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("threats" in e and "array" in e for e in errors)


def test_t_id_format_enforced():
    data = _load()
    data["threats"][0]["t_id"] = "TX-001"
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("t_id" in e for e in errors)


def test_t_id_must_be_sequential():
    data = _load()
    data["threats"][1]["t_id"] = "T-005"
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("sequential" in e for e in errors)


def test_t_id_uniqueness():
    data = _load()
    data["threats"][1]["t_id"] = "T-001"
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("duplicated" in e for e in errors)


def test_stride_category_enforced():
    data = _load()
    data["threats"][0]["stride"] = "S"  # single-letter is invalid; full word required
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("stride" in e for e in errors)


def test_risk_values_enforced():
    data = _load()
    data["threats"][0]["risk"] = "Severe"
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("risk" in e for e in errors)


def test_likelihood_allows_critical():
    data = _load()
    data["threats"][0]["likelihood"] = "Critical"
    ok, errors = validate_threats_merged(data)
    assert ok, f"Critical likelihood should be valid per Phase 9 risk matrix: {errors}"


def test_cwe_format_enforced():
    data = _load()
    data["threats"][0]["cwe"] = "CWE_321"
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("cwe" in e for e in errors)


def test_source_values_enforced():
    data = _load()
    data["threats"][0]["source"] = "manual"
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("source" in e for e in errors)


def test_architectural_violation_must_be_bool():
    data = _load()
    data["threats"][0]["architectural_violation"] = "no"
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("architectural_violation" in e for e in errors)


def test_evidence_missing_file():
    data = _load()
    del data["threats"][0]["evidence"]["file"]
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("evidence" in e and "file" in e for e in errors)


def test_evidence_line_may_be_null():
    data = _load()
    data["threats"][0]["evidence"]["line"] = None
    ok, errors = validate_threats_merged(data)
    assert ok, f"null line should be permitted: {errors}"


def test_evidence_line_must_be_int():
    data = _load()
    data["threats"][0]["evidence"]["line"] = "22"
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("line" in e for e in errors)


def test_title_must_not_be_empty():
    data = _load()
    data["threats"][0]["title"] = "   "
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("title" in e for e in errors)


def test_missing_row_field_detected():
    data = _load()
    del data["threats"][0]["component_id"]
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("component_id" in e for e in errors)


def test_deepcopy_does_not_mutate_fixture():
    original = _load()
    mutated = copy.deepcopy(original)
    mutated["threats"][0]["risk"] = "Low"
    validate_threats_merged(mutated)
    assert original["threats"][0]["risk"] == "Critical"
