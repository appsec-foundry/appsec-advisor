"""Validate version-2 architecture sources against the admitted immutable scope.

The legacy architecture validators remain the semantic owners. Repository
qualification is checked here before projecting one repository's components
to those validators; no model-selected root or filesystem path is admitted.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from runtime.multi_repo_scope import AssessmentScope, ScopeError

ROOT = Path(__file__).resolve().parents[2]
MAX_SOURCE_REFERENCES = 20_000
COMPONENT_SCHEMA = "fragments/components-v2.schema.json"
RECEIPT_SCHEMA = "component-inventory-finalization-v2.schema.json"
FLOW_SCHEMA = "fragments/data-flows-v2.schema.json"
SCHEMAS = (
    "fragments/components.schema.json",
    COMPONENT_SCHEMA,
    "component-inventory-finalization.schema.json",
    RECEIPT_SCHEMA,
    FLOW_SCHEMA,
)


class AssessmentArchitectureError(ValueError):
    """The combined architecture has invalid ownership, evidence, or identity."""


def validate_schema(document: dict, name: str) -> None:
    if name not in SCHEMAS:
        raise AssessmentArchitectureError("Unsupported assessment architecture contract")
    schemas = {p: json.loads((ROOT / "schemas" / p).read_text(encoding="utf-8")) for p in SCHEMAS}
    # Only these plugin-owned resources can resolve. Missing references never
    # trigger network access or repository-selected schema retrieval.
    registry = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas.values())
    if not Draft202012Validator(schemas[name], registry=registry).is_valid(document):
        raise AssessmentArchitectureError("Assessment architecture violates its schema")


def validate_source(scope: AssessmentScope, row: dict, *, path_key: str) -> None:
    rid, path = row.get("repository_id"), row.get(path_key)
    repo = next((r for r in scope.repositories if r.repository_id == rid), None)
    if repo is None or not isinstance(path, str) or path not in repo.files:
        raise AssessmentArchitectureError("Architecture source is outside admitted scope")
    if row.get("sha256") != hashlib.sha256(repo.files[path]).hexdigest():
        raise AssessmentArchitectureError("Architecture source content hash does not match admitted bytes")
    if path_key == "file":
        try:
            scope.read(rid, path, row["line"], row["line"])
        except (ScopeError, KeyError):
            raise AssessmentArchitectureError("Architecture evidence line is not in admitted source") from None


def _evidence_rows(value):
    if isinstance(value, dict):
        if "file" in value:
            yield value
        for child in value.values():
            yield from _evidence_rows(child)
    elif isinstance(value, list):
        for child in value:
            yield from _evidence_rows(child)


def _repository_projection(value, repository_id):
    """Project only one root's locations to the unchanged legacy path guards."""
    if isinstance(value, dict):
        projected = {key: _repository_projection(child, repository_id) for key, child in value.items()}
        if "paths" in value:
            projected["paths"] = [r["path"] for r in value["paths"] if r["repository_id"] == repository_id]
        return projected
    if isinstance(value, list):
        return [
            _repository_projection(row, repository_id)
            for row in value
            if not isinstance(row, dict) or "file" not in row or row["repository_id"] == repository_id
        ]
    return value


def _legacy_source_guards(scope, fragment_type, document):
    from validators.validate_fragment import repository_path_errors

    for repo in scope.repositories:
        projection = _repository_projection(document, repo.repository_id)
        if fragment_type == "components":
            projection["components"] = [r for r in projection["components"] if r["paths"]]
        with scope.scanner_snapshot(repo.repository_id) as root:
            errors = repository_path_errors(fragment_type, projection, root)
            if fragment_type == "data-flows":
                from analyzers.discover_identity_providers import identity_authentication_errors

                errors += identity_authentication_errors(root, projection.get("data_flows", []))
            if errors:
                raise AssessmentArchitectureError(
                    "Assessment architecture violates repository evidence or ownership rules"
                )


def validate_components(scope: AssessmentScope, document: dict) -> None:
    validate_schema(document, COMPONENT_SCHEMA)
    if document["source_scope_sha256"] != scope.inventory()["scope_sha256"]:
        raise AssessmentArchitectureError("Component inventory belongs to another source scope")
    ids = [c["id"] for c in document["components"]]
    if len(ids) != len(set(ids)):
        raise AssessmentArchitectureError("Component identities are not unique")
    owners = set()
    count = 0
    for component in document["components"]:
        rows = component["paths"]
        count += len(rows)
        if count > MAX_SOURCE_REFERENCES:
            raise AssessmentArchitectureError("Component inventory exceeds its source-reference limit")
        repositories = {r["repository_id"] for r in rows}
        if set(component["repository_ids"]) != repositories:
            raise AssessmentArchitectureError("Component ownership disagrees with its source paths")
        owners.update(repositories)
        for row in rows:
            validate_source(scope, row, path_key="path")
        for row in _evidence_rows(component):
            validate_source(scope, row, path_key="file")
            if row["repository_id"] not in repositories:
                raise AssessmentArchitectureError("Component evidence is owned by another repository")
    if owners != {r.repository_id for r in scope.repositories}:
        raise AssessmentArchitectureError("Component inventory omits a selected repository")
    _legacy_source_guards(scope, "components", document)


def validate_finalization(scope: AssessmentScope, components: dict, receipt: dict) -> None:
    from model.finalize_component_inventory import component_inventory_fingerprint

    validate_components(scope, components)
    validate_schema(receipt, RECEIPT_SCHEMA)
    if receipt["source_scope_sha256"] != components["source_scope_sha256"]:
        raise AssessmentArchitectureError("Component receipt belongs to another source scope")
    rows = components["components"]
    if receipt["component_ids"] != [r["id"] for r in rows]:
        raise AssessmentArchitectureError("Component receipt identities disagree with the inventory")
    if receipt["component_inventory_fingerprint"] != component_inventory_fingerprint(rows):
        raise AssessmentArchitectureError("Component inventory changed after finalization")
    if set(receipt["injected_component_ids"]) != {r["id"] for r in rows if r.get("origin") == "reconciliation"}:
        raise AssessmentArchitectureError("Component receipt reconciliation identities disagree")


def validate_flows(scope: AssessmentScope, components: dict, receipt: dict, document: dict) -> None:
    """Check the canonical flow handoff, including nested source evidence."""
    from validators.validate_fragment import fragment_invariant_errors

    validate_finalization(scope, components, receipt)
    validate_schema(document, FLOW_SCHEMA)
    if document["source_scope_sha256"] != components["source_scope_sha256"]:
        raise AssessmentArchitectureError("Data flows belong to another source scope")
    if document["component_inventory_fingerprint"] != receipt["component_inventory_fingerprint"]:
        raise AssessmentArchitectureError("Data flows refer to a stale component inventory")
    for row in _evidence_rows(document):
        validate_source(scope, row, path_key="file")

    # A read-only view preserves repository identity for existing relational
    # guards, including client-owned interaction evidence. These are virtual
    # names for comparisons only, never filesystem paths or rendered output.
    def qualify(value):
        if isinstance(value, dict):
            result = {k: qualify(v) for k, v in value.items()}
            if "file" in value:
                result["file"] = value["repository_id"] + "/" + value["file"]
            if "paths" in value:
                result["paths"] = [p["repository_id"] + "/" + p["path"] for p in value["paths"]]
            return result
        if isinstance(value, list):
            return [qualify(v) for v in value]
        return value

    errors = fragment_invariant_errors("data-flows", qualify(document), context=qualify(components))
    if errors:
        raise AssessmentArchitectureError("Data flows violate architecture reference or interaction invariants")
    _legacy_source_guards(scope, "data-flows", document)
    for flow in document["data_flows"]:
        # Keep the legacy code-evidence rule for authentication claims. The
        # repository-qualified lookup prevents equal paths in another target
        # from satisfying the receiving interface's evidence.
        auth = flow.get("authentication")
        if auth:
            receiver = next((c for c in components["components"] if c["id"] == flow["to"]), None)
            for evidence in auth["evidence"]:
                if receiver and evidence["repository_id"] not in receiver["repository_ids"]:
                    raise AssessmentArchitectureError(
                        "Authentication evidence is not owned by the receiving repository"
                    )
