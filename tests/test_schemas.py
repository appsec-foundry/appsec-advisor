"""
Smoke tests for schemas/*.schema.yaml.

Guards the invariant that every schema is loadable, valid under the
JSONSchema Draft 2020-12 meta-schema, and that the canonical example
`docs/security/threat-model.yaml` satisfies `threat-model.output.schema.yaml`.
"""

from __future__ import annotations

import json
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


def _json_validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS_DIR / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _component_context_plan() -> dict:
    sha256 = "0" * 64
    return {
        "schema_version": 1,
        "component_id": "api",
        "source_manifest_sha256": sha256,
        "analysis": {
            "depth": "full",
            "max_turns": 8,
            "sampling_required": False,
            "file_count": 1,
            "estimated_threat_count": "low",
            "stride_profile": {"stride_profile_label": "full"},
        },
        "lens_ids": [],
        "inputs": [
            {
                "context_id": "controls.component_evidence",
                "artifact_path": ".dispatch-context/api/evidence-bundle.json",
                "sha256": sha256,
            },
            {
                "context_id": "threats.component_taxonomy",
                "artifact_path": ".taxonomy-slices/api/threat-category-taxonomy.yaml",
                "sha256": sha256,
            },
        ],
    }


def test_component_context_plan_requires_each_mandatory_input_exactly_once() -> None:
    validator = _json_validator("stride-component-context-plan.schema.json")
    plan = _component_context_plan()
    assert not list(validator.iter_errors(plan))

    plan["inputs"] = [plan["inputs"][0], dict(plan["inputs"][0])]
    assert list(validator.iter_errors(plan)), "duplicate evidence inputs must fail schema validation"

    plan = _component_context_plan()
    plan["inputs"][1] = {
        "context_id": "threats.related_repositories",
        "artifact_path": ".dispatch-context/api/repository-roots.json",
        "sha256": "0" * 64,
    }
    assert list(validator.iter_errors(plan)), "the optional projection cannot replace the taxonomy input"


def test_component_context_plan_accepts_independently_selectable_business_context() -> None:
    validator = _json_validator("stride-component-context-plan.schema.json")
    plan = _component_context_plan()
    plan["inputs"].append(
        {
            "context_id": "business.component_context",
            "artifact_path": ".dispatch-context/api/business-context.json",
            "sha256": "0" * 64,
        }
    )
    assert not list(validator.iter_errors(plan))


def test_component_business_context_schema_keeps_human_attributes_bounded() -> None:
    validator = _json_validator("stride-component-business-context.schema.json")
    value = {
        "schema_version": 1,
        "component_id": "api",
        "source": "stride-analyst-context-v1",
        "source_content_sha256": "0" * 64,
        "attributes": {
            "business_purpose": "Authorize customer payments.",
            "security_assumptions": ["The upstream identity provider authenticates workforce users."],
        },
    }
    assert not list(validator.iter_errors(value))

    invalid = json.loads(json.dumps(value))
    invalid["attributes"] = {"controls": ["A gateway validates every request."]}
    assert list(validator.iter_errors(invalid)), "controls must remain an independently routable context"

    invalid = json.loads(json.dumps(value))
    invalid["attributes"] = {}
    assert list(validator.iter_errors(invalid)), "an empty projection must be physically omitted"


def test_component_repository_roots_reject_primary_and_identical_duplicates() -> None:
    validator = _json_validator("stride-component-repository-roots.schema.json")
    roots = {
        "schema_version": 1,
        "component_id": "api",
        "source_registry_sha256": "0" * 64,
        "repositories": [{"repository_id": "orders", "kind": "related", "root": "/srv/orders"}],
    }
    assert not list(validator.iter_errors(roots))

    roots["repositories"][0]["repository_id"] = "primary"
    assert list(validator.iter_errors(roots)), "the primary repository is never a related-root projection"

    roots["repositories"] = [
        {"repository_id": "orders", "kind": "related", "root": "/srv/orders"},
        {"repository_id": "orders", "kind": "related", "root": "/srv/orders"},
    ]
    assert list(validator.iter_errors(roots)), "identical repository rows must not validate twice"


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
