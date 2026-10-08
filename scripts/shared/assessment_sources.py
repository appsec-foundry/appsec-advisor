"""Portable source identity and read-only views of multi-repository models.

The delivered version-2 model retains separate repository and relative-path
fields. Legacy algorithms receive namespaced comparison/display strings only;
these views never select a filesystem root or replace the canonical artifact.
"""

from __future__ import annotations

import copy
import hashlib
import json
from functools import lru_cache
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
OUTPUT_SCHEMA = "threat-model.output-v2.schema.yaml"
RESOURCES = (
    "threat-model.output.schema.yaml",
    OUTPUT_SCHEMA,
    "multi-repo-scope.schema.json",
    "fragments/components.schema.json",
    "fragments/components-v2.schema.json",
)
MAX_MODEL_NODES = 2_000_000
MAX_MODEL_DEPTH = 64


@lru_cache(maxsize=1)
def output_validator():
    documents = {name: yaml.safe_load((ROOT / "schemas" / name).read_text(encoding="utf-8")) for name in RESOURCES}
    registry = Registry().with_resources(
        (document["$id"], Resource.from_contents(document)) for document in documents.values()
    )
    return Draft202012Validator(documents[OUTPUT_SCHEMA], registry=registry)


def source_key(reference: dict) -> str:
    """Keep equal relative paths in different repositories distinct."""
    path = reference.get("file", reference.get("path", ""))
    repository = reference.get("repository_id")
    return f"{repository}/{path}" if repository else path


def source_rows(value):
    """Bound traversal, including YAML alias expansion and cyclic input."""
    stack = [(value, 0, frozenset())]
    count = 0
    while stack:
        current, depth, ancestors = stack.pop()
        count += 1
        if count > MAX_MODEL_NODES or depth > MAX_MODEL_DEPTH:
            raise ValueError("Model exceeds its structural limits")
        if not isinstance(current, (dict, list)):
            continue
        identity = id(current)
        if identity in ancestors:
            raise ValueError("Model contains a cyclic structure")
        ancestors = ancestors | {identity}
        if isinstance(current, dict):
            if not all(isinstance(key, str) for key in current):
                raise ValueError("Model object keys must be strings")
            if "file" in current:
                yield current
            children = current.values()
        else:
            children = current
        stack.extend((child, depth + 1, ancestors) for child in children)


def validate_portable_model(document: dict) -> None:
    """Validate the portable model without granting access to local sources."""
    # Check expansion before recursive JSON-Schema validation.
    list(source_rows(document))
    if not output_validator().is_valid(document):
        raise ValueError("Multi-repository model violates its versioned output schema")
    inventory = document["source_inventory"]
    rows = inventory["repositories"]
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    if hashlib.sha256(encoded).hexdigest() != inventory["scope_sha256"]:
        raise ValueError("Portable source inventory fingerprint does not match")
    repositories = {row["repository_id"]: row for row in rows}
    if len(repositories) != len(rows):
        raise ValueError("Portable repository identities are not unique")
    sources = {}
    for repo in rows:
        for file in repo["files"]:
            key = (repo["repository_id"], file["path"])
            if key in sources:
                raise ValueError("Portable source paths are not unique")
            sources[key] = file["sha256"]

    def check(row, path_key):
        key = (row.get("repository_id"), row.get(path_key))
        if key not in sources or row.get("sha256") != sources[key]:
            raise ValueError("Model source reference is outside its inventory or has a stale hash")

    owners = set()
    components = document["components"]
    component_ids = {row["id"] for row in components}
    if len(component_ids) != len(components):
        raise ValueError("Model component identities are not unique")
    for component in components:
        paths = component["paths"]
        owned = {row["repository_id"] for row in paths}
        if set(component["repository_ids"]) != owned:
            raise ValueError("Model component ownership differs from its source paths")
        owners.update(owned)
        for row in paths:
            check(row, "path")
        for row in source_rows(component):
            if row["repository_id"] not in owned:
                raise ValueError("Component evidence belongs to another repository")
    if owners != set(repositories):
        raise ValueError("Model omits a selected repository")
    for row in source_rows(document):
        check(row, "file")
    by_component = {row["id"]: row for row in components}
    for finding in document["threats"]:
        if finding["component"] not in component_ids:
            raise ValueError("Finding refers to an unknown component")
        anchor = (finding.get("evidence") or [None])[0]
        owned = {(p["repository_id"], p["path"]) for p in by_component[finding["component"]]["paths"]}
        if anchor and (anchor["repository_id"], anchor["file"]) not in owned:
            raise ValueError("Finding anchor is outside its component ownership")
        for instance in finding.get("instances") or []:
            cid = instance.get("component_id") or finding["component"]
            if cid not in component_ids:
                raise ValueError("Finding instance refers to an unknown component")
            if instance.get("file") and instance["repository_id"] not in by_component[cid]["repository_ids"]:
                raise ValueError("Finding instance source is outside its component ownership")
    for control in document["security_controls"]:
        ids = control.get("component_ids") or []
        if not set(ids) <= component_ids:
            raise ValueError("Security control refers to an unknown component")
        owned = {(p["repository_id"], p["path"]) for cid in ids for p in by_component[cid]["paths"]}
        if any((e["repository_id"], e["file"]) not in owned for e in control.get("evidence") or []):
            raise ValueError("Security control evidence is outside its component ownership")
    entities = document.get("external_entities") or []
    entity_ids = {row["id"] for row in entities}
    if len(entity_ids) != len(entities):
        raise ValueError("External entity identities are not unique")
    flow_ids = set()
    for flow in document.get("data_flows") or []:
        if flow["id"] in flow_ids:
            raise ValueError("Data flow identities are not unique")
        flow_ids.add(flow["id"])
        for end in ("from", "to"):
            if flow[end] not in component_ids | {"external"}:
                raise ValueError("Data flow refers to an unknown component")
            entity = flow.get(end + "_entity")
            if entity and (flow[end] != "external" or entity not in entity_ids):
                raise ValueError("Data flow refers to an unknown or misplaced external entity")
    for asset in document["assets"]:
        for reference in asset.get("component_refs") or []:
            if reference["component_id"] not in component_ids:
                raise ValueError("Asset refers to an unknown component")


def presentation_model(document: dict) -> dict:
    """Create a namespaced view for existing renderers and comparisons."""
    meta = document.get("meta")
    if not isinstance(meta, dict) or meta.get("schema_version") != 2:
        return document
    validate_portable_model(document)
    view = copy.deepcopy(document)
    labels = {row["repository_id"]: row["label"] for row in view["source_inventory"]["repositories"]}
    for component in view["components"]:
        component["paths"] = [source_key(row) for row in component["paths"]]
        component["repository_labels"] = [labels[rid] for rid in component["repository_ids"]]
    # File strings are comparison/display locators. No caller may interpret
    # them as local paths; selected roots exist only in the admitted scope.
    seen = set()
    for row in source_rows(view):
        if id(row) not in seen:
            row["file"] = source_key(row)
            seen.add(id(row))
    return view


def location_label(reference: dict, document: dict) -> str:
    """Human-readable locator with an explicit, unambiguous owner."""
    if not reference.get("repository_id"):
        return reference.get("file", "")
    labels = {
        row["repository_id"]: row["label"] for row in (document.get("source_inventory") or {}).get("repositories", [])
    }
    rid = reference["repository_id"]
    if rid not in labels:
        raise ValueError("Source location has no repository in the model inventory")
    return f"{labels[rid]}:{reference['file']}"
