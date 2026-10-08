"""Scoped adapters for semantic stages owned by the assessment controller.

These functions own contracts, source checks and read-only projections. They
do not sequence stages, dispatch models, choose roles or publish reports.
"""

from __future__ import annotations

import copy
import hashlib
import json
from functools import lru_cache
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from runtime.assessment_host import ExchangeError
from shared.assessment_sources import source_key, source_rows
from validators.validate_assessment_architecture import validate_source

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = (
    "multi-repo-architecture.schema.json",
    "multi-repo-stride.schema.json",
    "multi-repo-controls.schema.json",
    "multi-repo-evidence-review.schema.json",
    "stride.schema.yaml",
    "threat-model.output.schema.yaml",
    "fragments/components.schema.json",
    "fragments/components-v2.schema.json",
    "fragments/data-flows-v2.schema.json",
    "fragments/assets.schema.json",
    "fragments/security-controls.schema.json",
    "threats-merged-v2.schema.json",
    "threats-merged.schema.yaml",
    "trust-boundary-assessment-input-v2.schema.json",
    "trust-boundary-assessment-input.schema.json",
    "fragments/trust-boundary-candidates-v2.schema.json",
    "fragments/trust-boundary-candidates.schema.json",
    "fragments/trust-boundaries-v3.schema.json",
    "fragments/trust-boundaries.schema.json",
    "trust-boundary-coverage-v2.schema.json",
    "trust-boundary-coverage.schema.json",
)
STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


def contract(name: str) -> dict:
    return copy.deepcopy(_contract(name))


@lru_cache(maxsize=len(CONTRACTS))
def _contract(name: str) -> dict:
    """Resolve only known plugin contracts to a tool-host-compatible schema."""
    if name not in CONTRACTS:
        raise ExchangeError("Unknown multi-repository stage contract")
    documents = {n: yaml.safe_load((ROOT / "schemas" / n).read_text(encoding="utf-8")) for n in CONTRACTS}
    by_id = {document["$id"]: document for document in documents.values()}

    def expand(value, document, depth=0):
        if depth > 64:
            raise ExchangeError("Stage schema exceeds its reference-depth limit")
        if isinstance(value, list):
            return [expand(row, document, depth + 1) for row in value]
        if not isinstance(value, dict):
            return value
        if "$ref" in value:
            uri, _, fragment = value["$ref"].partition("#")
            target = by_id.get(uri) if uri else document
            if target is None:
                raise ExchangeError("Stage schema refers to an unavailable plugin contract")
            resource = target
            if fragment:
                if not fragment.startswith("/"):
                    raise ExchangeError("Stage schema uses an unsupported reference")
                for segment in fragment[1:].split("/"):
                    key = segment.replace("~1", "/").replace("~0", "~")
                    try:
                        resource = resource[int(key)] if isinstance(resource, list) else resource[key]
                    except (KeyError, IndexError, ValueError, TypeError):
                        raise ExchangeError("Stage schema contains an invalid local reference") from None
            resolved = expand(resource, target, depth + 1)
            siblings = expand({k: v for k, v in value.items() if k != "$ref"}, document, depth + 1)
            return {"allOf": [resolved, siblings]} if siblings else resolved
        return {k: expand(v, document, depth + 1) for k, v in value.items() if k not in ("$id", "$defs")}

    result = expand(documents[name], documents[name])
    Draft202012Validator.check_schema(result)
    return result


def source_selection(components: list[dict]) -> frozenset:
    return frozenset((row["repository_id"], row["path"]) for c in components for row in c["paths"])


def component_neighborhood(components: dict, flows: dict, component_id: str) -> list[dict]:
    """Include only finalized incident peers, including evidenced broker hops."""
    by_id = {row["id"]: row for row in components["components"]}
    if component_id not in by_id:
        raise ExchangeError("Analysis component is outside the finalized inventory")
    ids = {component_id}
    for row in flows["data_flows"]:
        if component_id in (row["from"], row["to"]):
            ids.update(endpoint for endpoint in (row["from"], row["to"]) if endpoint in by_id)
    # A broker is an incident peer, not an authorization to read every tenant
    # or consumer connected to that broker. Further hops need a scoped job.
    return [by_id[key] for key in sorted(ids)]


def validate_retrieved_sources(scope, artifact, ranges, allowed_sources):
    """Every evidence claim must cite bytes actually delivered to this job."""
    for row in source_rows(artifact):
        validate_source(scope, row, path_key="file")
        key = (row["repository_id"], row["file"])
        if key not in allowed_sources or not any(
            (r["repository_id"], r["path"]) == key
            and r["sha256"] == row["sha256"]
            and r["start_line"] <= row["line"] <= r["end_line"]
            for r in ranges
        ):
            raise ExchangeError("Analysis evidence was not retrieved by its authorized job")


def validate_identity(scope, artifact, component_fingerprint):
    if artifact["source_scope_sha256"] != scope.inventory()["scope_sha256"]:
        raise ExchangeError("Analysis artifact belongs to another source scope")
    if artifact["component_inventory_fingerprint"] != component_fingerprint:
        raise ExchangeError("Analysis artifact refers to a stale component inventory")


def validate_controls(scope, components, component_fingerprint, artifact, ranges):
    if not Draft202012Validator(contract("multi-repo-controls.schema.json")).is_valid(artifact):
        raise ExchangeError("Controls violate their versioned contract")
    validate_identity(scope, artifact, component_fingerprint)
    allowed = source_selection(components)
    validate_retrieved_sources(scope, artifact, ranges, allowed)
    by_id = {row["id"]: row for row in components}
    for control in artifact["security_controls"]:
        if not set(control["component_ids"]) <= set(by_id):
            raise ExchangeError("Control refers to a component outside its authorized job")
        related = source_selection([by_id[key] for key in control["component_ids"]])
        if any((row["repository_id"], row["file"]) not in related for row in control["evidence"]):
            raise ExchangeError("Control evidence is not owned by its declared components")


def validate_local_architecture(scope, repository_id, components, receipt, artifact, ranges):
    if not Draft202012Validator(contract("multi-repo-architecture.schema.json")).is_valid(artifact):
        raise ExchangeError("Local architecture violates its versioned contract")
    if (
        artifact["repository_id"] != repository_id
        or artifact["source_scope_sha256"] != components["source_scope_sha256"]
        or artifact["component_inventory_fingerprint"] != receipt["component_inventory_fingerprint"]
    ):
        raise ExchangeError("Local architecture changed its admitted input identity")
    local = [c for c in components["components"] if c["repository_ids"] == [repository_id]]
    local_ids = {c["id"] for c in local}
    allowed = source_selection(local)
    validate_retrieved_sources(scope, artifact, ranges, allowed)
    for flow in artifact["data_flows"]:
        if flow["from"] not in local_ids | {"external"} or flow["to"] not in local_ids | {"external"}:
            raise ExchangeError("Local architecture cannot create a cross-repository connection")
        if flow["from"] == flow["to"] == "external":
            raise ExchangeError("Local architecture must attach each flow to a selected component")
    for asset in artifact["assets"]:
        if any(ref["component_id"] not in local_ids for ref in asset["component_refs"]):
            raise ExchangeError("Local asset refers to a component outside its repository")


def _comparison(value):
    if isinstance(value, dict):
        projected = {key: _comparison(child) for key, child in value.items() if key not in ("repository_id", "sha256")}
        if "file" in value:
            # Opaque comparison locators stay within legacy path-length
            # constraints. They are never used for rendering or file access.
            projected["file"] = "source-" + hashlib.sha256(source_key(value).encode()).hexdigest()
        return projected
    if isinstance(value, list):
        return [_comparison(row) for row in value]
    return value


def validate_stride(scope, component, neighborhood, flows, artifact, ranges, *, boundaries=()):
    """Preserve legacy policy/trace checks and scoped executable evidence."""
    from validators.validate_fragment import repository_evidence_errors
    from validators.validate_intermediate import validate_stride as legacy_validate

    if not Draft202012Validator(contract("multi-repo-stride.schema.json")).is_valid(artifact):
        raise ExchangeError("STRIDE job violates its versioned contract")
    if artifact["component_id"] != component["id"] or artifact["component_name"] != component["name"]:
        raise ExchangeError("STRIDE job changed its component identity")
    if artifact["source_scope_sha256"] != scope.inventory()["scope_sha256"]:
        raise ExchangeError("STRIDE job belongs to another source scope")
    if artifact["component_inventory_fingerprint"] != flows["component_inventory_fingerprint"]:
        raise ExchangeError("STRIDE job refers to a stale component inventory")
    categories = artifact["coverage"]
    if {row["category"] for row in categories} != set(STRIDE_CATEGORIES) or len(categories) != 6:
        raise ExchangeError("STRIDE job must assess all six categories exactly once")
    identifiers = [row["local_id"] for row in artifact["threats"]]
    if len(identifiers) != len(set(identifiers)):
        raise ExchangeError("STRIDE finding identities are not unique")
    for row in categories:
        actual = {t["local_id"] for t in artifact["threats"] if t["stride"] == row["category"]}
        if set(row["finding_ids"]) != actual or bool(actual) != (row["disposition"] == "finding"):
            raise ExchangeError("STRIDE category coverage does not match its findings")
    allowed = source_selection(neighborhood)
    validate_retrieved_sources(scope, artifact, ranges, allowed)
    own = source_selection([component])
    if not any((row["repository_id"], row["path"]) in own for row in ranges):
        raise ExchangeError("STRIDE job did not retrieve its component's source")
    for finding in artifact["threats"]:
        anchor = finding["evidence"]
        if (anchor["repository_id"], anchor["file"]) not in own:
            raise ExchangeError("Finding evidence is not owned by the assessed component")
        if finding.get("violated_requirements"):
            raise ExchangeError("Finding cites requirements absent from this job's catalog")
        trace = finding.get("mechanism_trace")
        if trace and trace["input"]["repository_id"] != anchor["repository_id"]:
            start = {
                c["id"]
                for c in neighborhood
                if (trace["input"]["repository_id"], trace["input"]["file"]) in source_selection([c])
            }
            reached = set(start)
            for _ in range(len(flows["data_flows"]) + 1):
                following = {f["to"] for f in flows["data_flows"] if f["from"] in reached}
                if following <= reached:
                    break
                reached.update(following)
            if component["id"] not in reached:
                raise ExchangeError("Cross-repository finding trace has no reviewed directional connection")
    projection = _comparison(artifact)
    projection.pop("schema_version", None)
    ok, _ = legacy_validate(projection)
    if not ok:
        raise ExchangeError("STRIDE job violates existing evidence, trace or remediation rules")
    from contexts.prepare_trust_boundary_context import validate_finding_boundary_refs

    adjacent = {
        row["id"]
        for row in boundaries
        if component["id"] in (row.get("from"), row.get("to"))
        or component["id"] in (row.get("covers_components") or [])
    }
    for finding in projection["threats"]:
        if finding.get("boundary_refs"):
            refs, diagnostics = validate_finding_boundary_refs(
                finding,
                boundaries=_comparison(list(boundaries)),
                origin_component_id=component["id"],
                candidate_ids=adjacent,
                require_candidate=True,
                known_component_ids={row["id"] for row in neighborhood},
            )
            if diagnostics or len(refs) != len(finding["boundary_refs"]):
                raise ExchangeError("Finding refers to a boundary absent from its validated neighborhood")
    evidence = list(source_rows(artifact))
    for repo in scope.repositories:
        own_evidence = [row for row in evidence if row["repository_id"] == repo.repository_id]
        if own_evidence:
            with scope.scanner_snapshot(repo.repository_id) as root:
                if repository_evidence_errors(own_evidence, root, require_line=True, require_code=True):
                    raise ExchangeError("STRIDE evidence does not cite an executable implementation")


def validate_evidence_review(scope, findings, component_fingerprint, artifact, ranges, allowed_sources):
    if not Draft202012Validator(contract("multi-repo-evidence-review.schema.json")).is_valid(artifact):
        raise ExchangeError("Evidence review violates its versioned contract")
    validate_identity(scope, artifact, component_fingerprint)
    expected = {finding["local_id"] for finding in findings}
    supplied = [row["local_id"] for row in artifact["decisions"]]
    if len(supplied) != len(set(supplied)) or set(supplied) != expected:
        raise ExchangeError("Evidence review must decide each finding exactly once")
    validate_retrieved_sources(scope, artifact, ranges, allowed_sources)
    for decision in artifact["decisions"]:
        original = next(finding for finding in findings if finding["local_id"] == decision["local_id"])
        anchor = original["evidence"]
        if decision["verdict"] == "verified" and not any(
            (row["repository_id"], row["file"], row["line"])
            == (anchor["repository_id"], anchor["file"], anchor["line"])
            for row in decision["evidence"]
        ):
            raise ExchangeError("Verified finding lacks an independent reading of its anchor")


def validate_boundary_candidates(scope, assessment, artifact, ranges, allowed_sources):
    from validators.validate_fragment import fragment_invariant_errors

    if not Draft202012Validator(contract("trust-boundary-assessment-input-v2.schema.json")).is_valid(assessment):
        raise ExchangeError("Crossing input violates its versioned contract")
    fingerprint_body = {k: v for k, v in assessment.items() if k != "assessment_input_fingerprint"}
    expected_input = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(fingerprint_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    )
    if assessment["assessment_input_fingerprint"] != expected_input:
        raise ExchangeError("Crossing input fingerprint does not match its immutable contents")
    if not Draft202012Validator(contract("fragments/trust-boundary-candidates-v2.schema.json")).is_valid(artifact):
        raise ExchangeError("Boundary candidates violate their versioned contract")
    validate_identity(scope, artifact, assessment["component_inventory_fingerprint"])
    if artifact["assessment_input_fingerprint"] != assessment["assessment_input_fingerprint"]:
        raise ExchangeError("Boundary candidates belong to another immutable crossing input")
    validate_retrieved_sources(scope, artifact, ranges, allowed_sources)
    errors = fragment_invariant_errors(
        "trust-boundary-candidates", _comparison(artifact), context=_comparison(assessment)
    )
    if errors:
        raise ExchangeError("Boundary candidates violate existing coverage and crossing invariants")
