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


def test_attack_surface_output_requires_closed_boolean_auth_contract() -> None:
    schema = yaml.safe_load((SCHEMAS_DIR / "threat-model.output.schema.yaml").read_text())
    data = yaml.safe_load((ROOT / "tests" / "fixtures" / "schema" / "threat-model.valid.yaml").read_text())
    validator = Draft202012Validator(schema)

    data["attack_surface"][0]["auth_required"] = None
    assert list(validator.iter_errors(data)), "unknown authentication must not reach the final report contract"

    data["attack_surface"][0]["auth_required"] = True
    data["attack_surface"][0]["uncontracted"] = "value"
    assert list(validator.iter_errors(data)), "attack-surface rows are closed structured artifacts"


def test_attack_surface_override_additions_require_boolean_auth() -> None:
    validator = _json_validator("fragments/attack-surface-overrides.schema.json")
    value = {
        "schema_version": 1,
        "additions": [
            {
                "entry_point": "/socket.io",
                "protocol": "WebSocket",
                "auth_required": False,
                "notes": "No connection middleware was observed.",
            }
        ],
    }
    assert not list(validator.iter_errors(value))

    value["additions"][0]["auth_required"] = None
    assert list(validator.iter_errors(value)), "null authentication must fail at the Phase-6 producer gate"

    value["additions"][0]["auth_required"] = False
    value["additions"][0]["uncontracted"] = "value"
    assert list(validator.iter_errors(value)), "Phase-6 additions must reject undeclared fields"


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


def test_context_v2_dispatch_vocabularies_do_not_drift_between_schemas() -> None:
    action = json.loads((SCHEMAS_DIR / "orchestration-action.schema.json").read_text(encoding="utf-8"))
    plan = json.loads((SCHEMAS_DIR / "stride-component-context-plan.schema.json").read_text(encoding="utf-8"))
    manifest = yaml.safe_load((SCHEMAS_DIR / "stride-dispatch-manifest.schema.yaml").read_text(encoding="utf-8"))

    job = action["$defs"]["dispatch_job"]["properties"]
    analysis = plan["properties"]["analysis"]["properties"]
    manifest_component = manifest["properties"]["components"]["items"]["properties"]

    assert job["analysis_depth"]["enum"] == analysis["depth"]["enum"]
    assert job["estimated_threat_count"]["enum"] == analysis["estimated_threat_count"]["enum"]
    assert job["estimated_threat_count"]["enum"] == manifest_component["estimated_threat_count_label"]["enum"]
    assert job["lens_ids"]["items"]["enum"] == plan["properties"]["lens_ids"]["items"]["enum"]
    assert job["lens_ids"]["items"]["enum"] == manifest_component["lens_ids"]["items"]["enum"]


def test_context_v2_projection_vocabularies_do_not_drift_between_schemas() -> None:
    action = json.loads((SCHEMAS_DIR / "orchestration-action.schema.json").read_text(encoding="utf-8"))
    plan = json.loads((SCHEMAS_DIR / "stride-component-context-plan.schema.json").read_text(encoding="utf-8"))
    security = json.loads((SCHEMAS_DIR / "stride-component-security-context.schema.json").read_text(encoding="utf-8"))
    effective = json.loads((SCHEMAS_DIR / "context-effective-plan.schema.json").read_text(encoding="utf-8"))
    bindings = json.loads((SCHEMAS_DIR / "context-routing-bindings.schema.json").read_text(encoding="utf-8"))

    security_ids = set(security["properties"]["context_id"]["enum"])
    action_ids = set(
        action["$defs"]["dispatch_job"]["properties"]["security_context_projections"]["items"]["properties"][
            "context_id"
        ]["enum"]
    )
    plan_ids = set(plan["properties"]["inputs"]["items"]["properties"]["context_id"]["enum"])

    assert security_ids == action_ids
    assert security_ids < plan_ids
    assert (
        effective["$defs"]["delivery"]["properties"]["projector"]["enum"]
        == bindings["$defs"]["context_binding"]["properties"]["projector"]["enum"]
    )


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


def test_component_context_plan_accepts_independently_selectable_architecture_context() -> None:
    validator = _json_validator("stride-component-context-plan.schema.json")
    plan = _component_context_plan()
    plan["inputs"].append(
        {
            "context_id": "architecture.component_context",
            "artifact_path": ".dispatch-context/api/architecture-context.json",
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


def test_component_architecture_context_schema_keeps_categories_separate() -> None:
    validator = _json_validator("stride-component-architecture-context.schema.json")
    value = {
        "schema_version": 1,
        "component_id": "api",
        "source": "stride-analyst-context-v1",
        "source_content_sha256": "0" * 64,
        "attributes": {
            "security_role": "Validate and route authenticated API requests.",
            "architecture_assumptions": ["The ingress preserves the authenticated principal."],
        },
    }
    assert not list(validator.iter_errors(value))

    invalid = json.loads(json.dumps(value))
    invalid["attributes"] = {"mitigations": ["Validate tokens at the gateway."]}
    assert list(validator.iter_errors(invalid)), "mitigations must remain an independently routable context"

    invalid = json.loads(json.dumps(value))
    invalid["attributes"] = {}
    assert list(validator.iter_errors(invalid)), "an empty projection must be physically omitted"


def test_component_security_context_schema_binds_category_source_and_truncation() -> None:
    validator = _json_validator("stride-component-security-context.schema.json")
    value = {
        "schema_version": 1,
        "component_id": "api",
        "context_id": "controls.component_context",
        "source": {
            "kind": "component_manifest",
            "manifest_field": "controls",
            "content_sha256": "0" * 64,
        },
        "records": [
            {
                "source": "controls",
                "value": "Authorization middleware",
                "content_sha256": "1" * 64,
                "truncated": False,
            }
        ],
        "limits": {
            "original_count": 1,
            "retained_count": 1,
            "omitted_count": 0,
            "value_truncations": 0,
            "serialized_bytes": 500,
            "estimated_tokens": 125,
        },
    }
    assert not list(validator.iter_errors(value))

    invalid = json.loads(json.dumps(value))
    invalid["source"]["kind"] = "component_index"
    invalid["source"].pop("manifest_field")
    invalid["source"].update({"artifact_path": ".controls.json", "artifact_sha256": "2" * 64})
    assert list(validator.iter_errors(invalid)), "control projections must originate in the component manifest"

    invalid = json.loads(json.dumps(value))
    invalid["records"][0].update({"truncated": True, "value": "x" * 4096})
    assert list(validator.iter_errors(invalid)), "truncated records must disclose their original length"


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
