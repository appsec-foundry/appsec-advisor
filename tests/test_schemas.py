"""
Smoke tests for schemas/*.schema.yaml.

Guards the invariant that every schema is loadable, valid under the
JSONSchema Draft 2020-12 meta-schema, and that the canonical example
`docs/security/threat-model.yaml` satisfies `threat-model.output.schema.yaml`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).parent.parent
SCHEMAS_DIR = ROOT / "schemas"

ALL_SCHEMAS = sorted(SCHEMAS_DIR.glob("*.schema.yaml"))
ALL_JSON_SCHEMAS = sorted(SCHEMAS_DIR.glob("*.schema.json"))


@pytest.mark.parametrize("schema_path", ALL_SCHEMAS, ids=lambda p: p.name)
def test_schema_is_valid_jsonschema(schema_path: Path) -> None:
    schema = yaml.safe_load(schema_path.read_text())
    # Raises SchemaError if the schema itself is malformed against the
    # Draft 2020-12 meta-schema.
    Draft202012Validator.check_schema(schema)


def test_schemas_directory_not_empty() -> None:
    assert ALL_SCHEMAS, "schemas/ must contain at least one *.schema.yaml"


def test_threat_model_output_example_validates() -> None:
    schema_path = SCHEMAS_DIR / "threat-model.output.schema.yaml"
    example_path = ROOT / "tests" / "fixtures" / "schema" / "threat-model.valid.yaml"

    schema = yaml.safe_load(schema_path.read_text())
    data = yaml.safe_load(example_path.read_text())
    errors = sorted(
        Draft202012Validator(schema).iter_errors(data),
        key=lambda e: list(e.absolute_path),
    )
    assert not errors, "\n".join(f"{'.'.join(str(p) for p in e.absolute_path) or 'root'}: {e.message}" for e in errors)


def test_boundary_verdict_fields_are_constrained() -> None:
    """`trust_boundaries` items are `additionalProperties: false`, so the two
    fields triage writes back have to be declared — and constrained, because a
    free-text verdict would let the scoring and the report drift apart."""
    schema = yaml.safe_load((SCHEMAS_DIR / "threat-model.output.schema.yaml").read_text())
    data = yaml.safe_load((ROOT / "tests" / "fixtures" / "schema" / "threat-model.valid.yaml").read_text())
    row = data["trust_boundaries"][0]
    validator = Draft202012Validator(schema)

    assert row["assumption_verdict"] == "unconfirmed"
    assert not list(validator.iter_errors(data))

    row["assumption_verdict"] = "probably-fine"
    assert list(validator.iter_errors(data)), "an unknown verdict must not validate"

    row["assumption_verdict"] = "clean"
    row["adjacent_finding_ids"] = ["F-001"]
    assert list(validator.iter_errors(data)), "the yaml stores T-ids, not F-ids"


@pytest.mark.parametrize("schema_path", ALL_JSON_SCHEMAS, ids=lambda p: p.name)
def test_json_schema_is_valid_jsonschema(schema_path: Path) -> None:
    import json

    schema = json.loads(schema_path.read_text())
    # Raises SchemaError if the schema itself is malformed against the
    # Draft 2020-12 meta-schema. Top-level schemas/*.schema.json were
    # previously loaded by no meta-check (TG-2, audit 2026-06-11).
    Draft202012Validator.check_schema(schema)


def test_json_schemas_directory_not_empty() -> None:
    assert ALL_JSON_SCHEMAS, "schemas/ must contain at least one top-level *.schema.json"


def test_default_actor_library_validates_actor_schema() -> None:
    schema = yaml.safe_load((SCHEMAS_DIR / "actors.schema.yaml").read_text())
    library = yaml.safe_load((ROOT / "data" / "actors" / "default-library.yaml").read_text())
    validator = Draft202012Validator(schema)
    errors = []
    for actor in library.get("actors", []):
        errors.extend(validator.iter_errors(actor))
    assert not errors, "\n".join(
        f"{'.'.join(str(p) for p in error.absolute_path) or 'root'}: {error.message}" for error in errors
    )
