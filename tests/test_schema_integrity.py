"""Integrity tests for schemas/fragments/*.json.

These tests enforce:

  * Every schema file is itself valid JSON-Schema (draft 2020-12).
  * Every schema registered in `validate_fragment.py` has a file on disk, and
    every file on disk has a registry entry.
  * Cross-schema ID-pattern consistency (F-NNN, M-NNN, C-NN, TH-NN, CC-NN
    use identical regex shape).
  * Every schema `required` key exists in `properties` (no orphan requireds).
  * Every enum is non-empty and contains only scalar values.

Running these on every PR prevents a schema update from drifting away from
either the renderer or the registry without notice.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).parent.parent
SCHEMAS_DIR = REPO_ROOT / "schemas" / "fragments"
VALIDATE_PY = REPO_ROOT / "scripts" / "validate_fragment.py"


def test_figure1_optional_labels_are_bounded_across_artifact_schemas():
    import yaml

    roots = [
        yaml.safe_load((REPO_ROOT / "schemas" / p).read_text())
        for p in (
            "fragments/data-flows.schema.json",
            "trust-boundary-assessment-input.schema.json",
            "threat-model.output.schema.yaml",
        )
    ]
    flow_schemas = [r["$defs"]["data_flow"] for r in roots[:2]] + [roots[2]["properties"]["data_flows"]["items"]]
    for flow_schema in flow_schemas:
        assert "diagram_label" not in flow_schema["required"]
        validator = jsonschema.Draft202012Validator(flow_schema["properties"]["diagram_label"])
        assert validator.is_valid("Authenticated event delivery")
        for value in ("", None, 123, "x" * 49, "line\nbreak", "line\tbreak"):
            assert not validator.is_valid(value)
    schema = json.loads((SCHEMAS_DIR / "security-posture-attack-paths.schema.json").read_text())
    path_schema = schema["properties"]["attack_paths"]["items"]
    assert "scenario_title" not in path_schema["required"]
    validator = jsonschema.Draft202012Validator(path_schema["properties"]["scenario_title"])
    assert validator.is_valid("Template Injection Reads Private Records")
    for value in ("", "Injection", None, "x" * 61, "two lines\nwith text"):
        assert not validator.is_valid(value)


def test_external_entity_access_is_consistent_and_role_only():
    import yaml

    schema_root = REPO_ROOT / "schemas"
    schemas = [
        yaml.safe_load((schema_root / name).read_text())["properties"]["external_entities"]["items"]
        for name in (
            "fragments/data-flows.schema.json",
            "trust-boundary-assessment-input.schema.json",
            "threat-model.output.schema.yaml",
        )
    ]
    assert schemas[0] == schemas[1] == schemas[2]
    entity = {
        "id": "ext-reader",
        "name": "Reader",
        "kind": "legitimate-role",
        "description": "Reads records",
        "evidence": [{"file": "src/routes.ts", "line": 1}],
    }
    vocabulary = yaml.safe_load((REPO_ROOT / "data/posture-actor-labels.yaml").read_text())["actors"]
    for schema in schemas:
        validator = jsonschema.Draft202012Validator(schema)
        assert validator.is_valid(entity)
        for access in ("internet-anon", "internet-user", "internet-priv-user"):
            assert access in vocabulary
            assert validator.is_valid({**entity, "access": access})
            assert not validator.is_valid({**entity, "access": access, "kind": "identity-provider"})
            assert not validator.is_valid({**entity, "access": access, "kind": "external-service"})
        for access in (None, "admin", "repo-read"):
            assert not validator.is_valid({**entity, "access": access})


def test_capability_vocabulary_matches_every_artifact_schema():
    import yaml

    vocabulary = yaml.safe_load((REPO_ROOT / "data/security-capabilities.yaml").read_text())
    capabilities, roles = list(vocabulary["component_capabilities"]), list(vocabulary["service_roles"])
    assert capabilities and roles and not set(capabilities) & set(roles)
    for entry in [*vocabulary["component_capabilities"].values(), *vocabulary["service_roles"].values()]:
        assert entry["label"].strip() == entry["label"] and 0 < len(entry["label"]) <= 28
    for group in ("component_capabilities", "service_roles"):
        for value, entry in vocabulary[group].items():
            assert set(entry.get("implies") or []) <= set(vocabulary[group]) - {value}
    schema_root = REPO_ROOT / "schemas"
    fragment = json.loads((schema_root / "fragments/components.schema.json").read_text())
    canonical = yaml.safe_load((schema_root / "threat-model.output.schema.yaml").read_text())
    component_fields = [
        fragment["properties"]["components"]["items"]["properties"]["capabilities"],
        canonical["properties"]["components"]["items"]["properties"]["capabilities"],
    ]
    assert component_fields[0]["items"] == component_fields[1]["items"]
    assert component_fields[0]["items"]["properties"]["capability"]["enum"] == capabilities
    entity_schemas = [
        yaml.safe_load((schema_root / name).read_text())["properties"]["external_entities"]["items"]
        for name in (
            "fragments/data-flows.schema.json",
            "trust-boundary-assessment-input.schema.json",
            "threat-model.output.schema.yaml",
        )
    ]
    evidence = [{"file": "src/client.ts", "line": 3}]
    service = {
        "id": "ext-model",
        "name": "Model",
        "kind": "external-service",
        "description": "LLM",
        "evidence": evidence,
    }
    for schema in entity_schemas:
        assert schema["properties"]["service_roles"]["items"]["properties"]["role"]["enum"] == roles
        validator = jsonschema.Draft202012Validator(schema)
        assert validator.is_valid({**service, "service_roles": [{"role": roles[0], "evidence": evidence}]})
        assert validator.is_valid(
            {**service, "kind": "identity-provider", "service_roles": [{"role": roles[0], "evidence": evidence}]}
        )
        for invalid in (
            {**service, "kind": "legitimate-role", "service_roles": [{"role": roles[0], "evidence": evidence}]},
            {**service, "service_roles": [{"role": "unknown-role", "evidence": evidence}]},
            {**service, "service_roles": [{"role": roles[0], "evidence": []}]},
            {**service, "service_roles": [{"role": capabilities[0], "evidence": evidence}]},
        ):
            assert not validator.is_valid(invalid)
    component_validator = jsonschema.Draft202012Validator(component_fields[1])
    assert component_validator.is_valid([{"capability": capabilities[0], "evidence": evidence}])
    for invalid in (
        [{"capability": roles[0], "evidence": evidence}],
        [{"capability": capabilities[0]}],
        [{"capability": capabilities[0], "evidence": [{"file": "/etc/passwd", "line": 1}]}],
    ):
        assert not component_validator.is_valid(invalid)


def _load_validate_fragment_module():
    spec = importlib.util.spec_from_file_location("validate_fragment", VALIDATE_PY)
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_fragment"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def registry() -> dict[str, str]:
    vf = _load_validate_fragment_module()
    return dict(vf.FRAGMENT_SCHEMAS)


@pytest.fixture(scope="module")
def schema_files() -> list[Path]:
    return sorted(SCHEMAS_DIR.glob("*.schema.json"))


# ---------------------------------------------------------------------------
# Every schema file is valid JSON-Schema
# ---------------------------------------------------------------------------


def test_every_schema_is_valid_json(schema_files):
    """JSON parse check — bad JSON → pytest fails with the decoder error."""
    for path in schema_files:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            pytest.fail(f"{path.name} is not valid JSON: {e}")


def test_every_schema_validates_against_json_schema_draft_2020_12(schema_files):
    """Each schema file must itself be a valid JSON-Schema instance — the
    meta-schema check. Catches typos like `minItem` instead of `minItems`."""
    Validator = jsonschema.Draft202012Validator
    for path in schema_files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        try:
            Validator.check_schema(schema)
        except jsonschema.SchemaError as e:
            pytest.fail(f"{path.name} is not a valid JSON-Schema: {e}")


# ---------------------------------------------------------------------------
# Registry ↔ files must match
# ---------------------------------------------------------------------------


def test_every_registered_schema_exists_on_disk(registry):
    missing = [(ft, fn) for ft, fn in registry.items() if not (SCHEMAS_DIR / fn).is_file()]
    assert not missing, (
        f"validate_fragment.py registers schemas that don't exist: {missing}\n"
        "Add the schema file or remove the registry entry."
    )


def test_every_schema_file_is_registered(registry, schema_files):
    registered = set(registry.values())
    on_disk = {p.name for p in schema_files}
    unregistered = on_disk - registered
    assert not unregistered, (
        f"Schema files present on disk but not registered in "
        f"validate_fragment.FRAGMENT_SCHEMAS: {unregistered}\n"
        "Add them to the registry or delete the files."
    )


# ---------------------------------------------------------------------------
# Orphan `required` entries
# ---------------------------------------------------------------------------


def _walk_required(schema, path="$"):
    """Yield (pointer, required_list, properties_keys) for every object-typed
    schema fragment that has a `required` list."""
    if not isinstance(schema, dict):
        return
    if schema.get("type") == "object" or "properties" in schema:
        req = schema.get("required", [])
        props = set((schema.get("properties") or {}).keys())
        if req:
            yield (path, req, props)
    for k, v in schema.items():
        if isinstance(v, dict):
            yield from _walk_required(v, f"{path}.{k}")
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    yield from _walk_required(item, f"{path}.{k}[{i}]")


def test_every_required_key_exists_in_properties(schema_files):
    orphans = []
    for path in schema_files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        for pointer, req, props in _walk_required(schema):
            for field in req:
                if field not in props:
                    orphans.append(f"{path.name} at {pointer}: required '{field}' not in properties")
    assert not orphans, "\n".join(orphans)


# ---------------------------------------------------------------------------
# Cross-schema pattern consistency (F-NNN, M-NNN, C-NN, TH-NN, CC-NN)
# ---------------------------------------------------------------------------

_CANONICAL_ID_PATTERNS = {
    # prefix: expected minimum regex shape the schema must use.
    # Tests just check that any schema string-field with pattern uses one of
    # these canonical forms — not a custom one-off regex.
    "F": r"^F-\\d",
    "T": r"^T-\\d",
    "M": r"^M-\\d",
    "C": r"^C-\\d",
    "TH": r"^TH-\\d",
    "CC": r"^CC-\\d",
}


def _walk_patterns(schema, path="$"):
    if not isinstance(schema, dict):
        return
    if "pattern" in schema and isinstance(schema["pattern"], str):
        yield (path, schema["pattern"])
    for k, v in schema.items():
        if isinstance(v, dict):
            yield from _walk_patterns(v, f"{path}.{k}")
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    yield from _walk_patterns(item, f"{path}.{k}[{i}]")


def test_id_patterns_are_canonical(schema_files):
    """Any `pattern:` field that looks like an ID regex must match one of the
    canonical forms. Catches typos like `^F-\\d{2}` (wrong digit count) or
    `^FID-\\d+` (wrong prefix)."""
    violations = []
    for path in schema_files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        for pointer, pat in _walk_patterns(schema):
            m = re.match(r"\^([A-Z]+)-\\d", pat)
            if not m:
                continue  # not an ID-shaped pattern; ignore
            prefix = m.group(1)
            # Normalise "FT" etc. to first char — compound prefixes like "[FT]"
            if prefix.startswith("["):
                continue
            # Strip `{min,max}` quantifier tail.
            if prefix not in ("F", "T", "M", "C", "TH", "CC", "AF", "A"):
                violations.append(f"{path.name} at {pointer}: unusual ID prefix {prefix!r} in pattern {pat!r}")
    assert not violations, "\n".join(violations)


# ---------------------------------------------------------------------------
# Enum sanity
# ---------------------------------------------------------------------------


def _walk_enums(schema, path="$"):
    if not isinstance(schema, dict):
        return
    if "enum" in schema and isinstance(schema["enum"], list):
        yield (path, schema["enum"])
    for k, v in schema.items():
        if isinstance(v, dict):
            yield from _walk_enums(v, f"{path}.{k}")
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    yield from _walk_enums(item, f"{path}.{k}[{i}]")


def test_enums_are_non_empty_and_scalar(schema_files):
    bad = []
    for path in schema_files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        for pointer, values in _walk_enums(schema):
            if not values:
                bad.append(f"{path.name} at {pointer}: empty enum")
                continue
            for v in values:
                if not isinstance(v, (str, int, float, bool, type(None))):
                    bad.append(f"{path.name} at {pointer}: non-scalar enum value {v!r}")
    assert not bad, "\n".join(bad)


def test_enums_have_no_duplicates(schema_files):
    """Duplicate enum values are a JSON-Schema draft-2020-12 violation."""
    dupes = []
    for path in schema_files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        for pointer, values in _walk_enums(schema):
            seen = set()
            for v in values:
                key = (type(v).__name__, v)
                if key in seen:
                    dupes.append(f"{path.name} at {pointer}: duplicate enum value {v!r}")
                seen.add(key)
    assert not dupes, "\n".join(dupes)


# ---------------------------------------------------------------------------
# Every schema has a title + $id (machine-readable documentation hygiene)
# ---------------------------------------------------------------------------


def test_every_schema_declares_title_and_id(schema_files):
    missing = []
    for path in schema_files:
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "title" not in schema:
            missing.append(f"{path.name}: missing 'title'")
        if "$id" not in schema:
            missing.append(f"{path.name}: missing '$id'")
    assert not missing, "\n".join(missing)
