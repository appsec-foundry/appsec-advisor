"""Schema-validation tests for schemas/abuse-cases.schema.yaml.

A valid library document passes; each required field, enum, and pattern is
exercised through a tiny mutation on a deep-copied valid case.
"""

from __future__ import annotations

from pathlib import Path

import jsonschema
import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "abuse-cases.schema.yaml"
LIBRARY_PATH = REPO_ROOT / "data" / "abuse-cases" / "default-library.yaml"


@pytest.fixture(scope="module")
def schema() -> dict:
    return yaml.safe_load(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def valid_case() -> dict:
    return {
        "id": "AC-T-001",
        "title": "Example",
        "source": "mandatory",
        "attacker": {"actor_id": "external-attacker", "initial_access": "unauthenticated"},
        "goal": "Take over an account.",
        "chain": [
            {
                "step": 1,
                "label": "First",
                "grants": "foothold",
                "probe": {"sink_patterns": ["eval\\("]},
            }
        ],
    }


def _doc(case: dict) -> dict:
    return {"schema_version": 1, "abuse_cases": [case]}


def _errors(schema: dict, doc: dict) -> list[str]:
    v = jsonschema.Draft202012Validator(schema)
    return [e.message for e in v.iter_errors(doc)]


def test_schema_is_valid_jsonschema(schema):
    jsonschema.Draft202012Validator.check_schema(schema)


def test_shipped_library_validates(schema):
    doc = yaml.safe_load(LIBRARY_PATH.read_text(encoding="utf-8"))
    assert _errors(schema, doc) == []


def test_valid_case_passes(schema, valid_case):
    assert _errors(schema, _doc(valid_case)) == []


@pytest.mark.parametrize("field", ["id", "title", "source", "attacker", "goal", "chain"])
def test_missing_required_top_field_fails(schema, valid_case, field):
    del valid_case[field]
    assert _errors(schema, _doc(valid_case)), f"removing {field} should fail"


def test_bad_id_pattern_fails(schema, valid_case):
    valid_case["id"] = "XYZ-1"
    assert _errors(schema, _doc(valid_case))


def test_org_and_discovered_id_patterns_pass(schema, valid_case):
    for cid in ("AC-001", "ORG-AC-042", "AC-T-999"):
        valid_case["id"] = cid
        assert _errors(schema, _doc(valid_case)) == [], cid


def test_bad_initial_access_enum_fails(schema, valid_case):
    valid_case["attacker"]["initial_access"] = "telepathy"
    assert _errors(schema, _doc(valid_case))


def test_chain_step_requires_probe_sink_patterns(schema, valid_case):
    del valid_case["chain"][0]["probe"]["sink_patterns"]
    assert _errors(schema, _doc(valid_case))


def test_empty_chain_fails(schema, valid_case):
    valid_case["chain"] = []
    assert _errors(schema, _doc(valid_case))


def test_release_gate_enum_enforced(schema, valid_case):
    valid_case["release_gate"] = {"fail_on": ["sometimes"]}
    assert _errors(schema, _doc(valid_case))


def test_release_gate_valid_values_pass(schema, valid_case):
    valid_case["release_gate"] = {
        "fail_on": ["fully_viable", "partially_blocked"],
        "applies_to_presets": ["ci-standard"],
    }
    assert _errors(schema, _doc(valid_case)) == []


def test_unknown_field_rejected(schema, valid_case):
    valid_case["surprise"] = True
    assert _errors(schema, _doc(valid_case))
