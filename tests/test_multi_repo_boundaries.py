"""Qualified crossings preserve existing normalization and separate owners."""

import copy
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from contexts.build_trust_boundary_assessment_input import (
    _crossing_connections,
    _signal_specs,
    build_assessment,
    project_assessment_signal,
)
from contexts.prepare_trust_boundary_context import (
    _canonical_evidence,
    _consolidate_candidates,
    _evidence_line,
    _merge_evidence,
    normalize_assessment_boundaries,
)
from model.finalize_component_inventory import component_inventory_fingerprint
from runtime.multi_repo_scope import admit


def fixture(tmp_path, *, names=("edge", "service")):
    roots = []
    for name in names:
        root = tmp_path / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "initial",
            ],
            check=True,
        )
        (root / "app.py").write_text("return_value = validate_request(payload)\n")
        roots.append(root)
    scope = admit([str(r) for r in roots], str(tmp_path / "out"))
    components, evidence = [], []
    for index, repo in enumerate(scope.repositories, 1):
        sha = hashlib.sha256(repo.files["app.py"]).hexdigest()
        evidence.append(dict(repository_id=repo.repository_id, file="app.py", line=1, sha256=sha))
        components.append(
            dict(
                id=f"component-{index}",
                name="Service",
                description="Application service.",
                tier="application",
                repository_ids=[repo.repository_id],
                paths=[dict(repository_id=repo.repository_id, path="app.py", sha256=sha)],
            )
        )
    return (
        scope,
        dict(schema_version=2, source_scope_sha256=scope.inventory()["scope_sha256"], components=components),
        evidence,
    )


def candidate(key, target, evidence):
    return dict(
        candidate_key=key,
        name="Request boundary",
        **{"from": "external", "to": target},
        kind="network",
        assumption="Every request must satisfy the receiver's accepted input contract.",
        evidence=[evidence],
        confidence="confirmed",
        enforcement_point="RequestValidation middleware",
        covered_signal_ids=[],
        covered_flow_ids=[],
    )


def test_equal_source_names_and_control_names_do_not_merge_separate_roots(tmp_path):
    scope, components, evidence = fixture(tmp_path)
    rows = [
        candidate(f"candidate-{i}", comp["id"], ev)
        for i, (comp, ev) in enumerate(zip(components["components"], evidence, strict=True), 1)
    ]
    scope.output.mkdir()
    document, warnings = normalize_assessment_boundaries(scope, components, rows, output_dir=scope.output)
    assert document["schema_version"] == 3 and len(document["trust_boundaries"]) == 2
    assert {b["evidence"][0]["repository_id"] for b in document["trust_boundaries"]} == {
        e["repository_id"] for e in evidence
    }
    assert {b["to"] for b in document["trust_boundaries"]} == {c["id"] for c in components["components"]}
    assert len(_merge_evidence([evidence[0]], [evidence[1]])) == 2


def test_source_claims_use_the_admitted_frozen_view(tmp_path):
    scope, _, evidence = fixture(tmp_path)
    (scope.repositories[0].root / "app.py").write_text("changed = True\n")
    assert _evidence_line(scope, evidence[0]).strip() == "return_value = validate_request(payload)"
    forged = {**evidence[0], "sha256": "0" * 64}
    assert _evidence_line(scope, forged) == ""
    with pytest.raises(ValueError):
        _canonical_evidence(scope, [forged], [], "test")


@pytest.mark.parametrize("kind", ["foreign", "traversal", "missing-line", "overflow"])
def test_qualified_normalization_rejects_invalid_evidence(tmp_path, kind):
    scope, _, evidence = fixture(tmp_path)
    rows = [dict(evidence[0])]
    if kind == "foreign":
        rows[0]["repository_id"] = "repo-ffffffffffffffff"
    elif kind == "traversal":
        rows[0]["file"] = "../app.py"
    elif kind == "missing-line":
        rows[0].pop("line")
    else:
        rows *= 6
    with pytest.raises(ValueError):
        _canonical_evidence(scope, rows, [], "test")


def test_repository_membership_does_not_establish_a_crossing(tmp_path):
    _, components, _ = fixture(tmp_path)
    cards = {c["id"]: c for c in components["components"]}
    flow = dict(**{"from": "component-1", "to": "component-2"}, label="Records", protocol="HTTPS")
    assert not _signal_specs(flow, cards)
    connected = {**flow, "connection_id": "connection-" + "a" * 16}
    specs = _signal_specs(connected, cards, _crossing_connections([connected], cards))
    assert len(specs) == 1 and specs[0][0] == "third-party-or-cross-repository"
    assert "same process" in specs[0][2][0]


def test_legacy_same_control_consolidation_remains_available(tmp_path):
    scope, components, evidence = fixture(tmp_path)
    # Legacy cards carry no multi-root ownership. Keep their existing grouping
    # behavior; the new ownership guard is only on qualified components.
    cards = {c["id"]: {**c, "paths": ["app.py"], "repository_ids": []} for c in components["components"]}
    rows = [
        candidate(f"candidate-{i}", comp["id"], ev)
        for i, (comp, ev) in enumerate(zip(components["components"], evidence, strict=True), 1)
    ]
    merged, _, _ = _consolidate_candidates(rows, components=cards, repo_root=scope)
    assert len(merged) == 1


@pytest.mark.parametrize("names", [("edge", "service"), ("gateway", "processor")])
def test_same_crossing_keeps_equal_relative_evidence_from_both_participants(tmp_path, names):
    scope, components, evidence = fixture(tmp_path, names=names)
    source, target = (row["id"] for row in components["components"])
    rows = [{**candidate(f"candidate-{index}", target, entry), "from": source} for index, entry in enumerate(evidence)]
    cards = {row["id"]: row for row in components["components"]}
    merged, _, _ = _consolidate_candidates(rows, components=cards, repo_root=scope)
    assert len(merged) == 1
    assert {e["repository_id"] for e in merged[0]["evidence"]} == {e["repository_id"] for e in evidence}


def crossing_input(tmp_path, *, names=("edge", "service")):
    scope, components, evidence = fixture(tmp_path, names=names)
    fingerprint = component_inventory_fingerprint(components["components"])
    receipt = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=fingerprint,
        component_ids=[c["id"] for c in components["components"]],
        injected_component_ids=[],
        collapsed_duplicate_count=0,
    )
    flows = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=fingerprint,
        data_flows=[
            dict(
                id="df-001",
                **{"from": "component-1", "to": "component-2"},
                label="Request data",
                protocol="HTTPS",
                data_classification="unknown",
                direction="request-response",
                evidence=evidence,
                provenance="architecture",
                connection_id="connection-" + "a" * 16,
            )
        ],
    )
    context = dict(
        route_inventory=dict(status="missing", routes=[]),
        attack_surface_additions=[],
        cross_repository=dict(status="missing", entries=[]),
        recon_signals=dict(
            values={
                key: False
                for key in (
                    "has_public_routes",
                    "has_auth_surface",
                    "has_role_concept",
                    "has_ci_pipeline",
                    "has_external_apis",
                    "has_client_storage",
                    "has_multi_tenancy_signal",
                )
            },
            evidence=[],
        ),
        boundary_declarations=dict(status="missing", fingerprint=None, keys=[]),
        incremental=False,
    )
    return scope, components, receipt, flows, context


def test_assessment_crossing_input_preserves_owners_and_requires_reviewed_connection(tmp_path):
    scope, components, receipt, flows, context = crossing_input(tmp_path)
    assessment = build_assessment(scope, components, receipt, flows, context, "standard")
    assert len(assessment["signals"]) == 1
    assert assessment["signals"][0]["class"] == "third-party-or-cross-repository"
    assert assessment["components"][0]["paths"][0]["repository_id"] == scope.repositories[0].repository_id
    assert "connection_id" not in assessment["data_flows"][0]
    projected = project_assessment_signal(assessment, assessment["signals"][0]["id"], flows["data_flows"])
    assert projected == assessment
    assert not scope.output.exists()
    flows["data_flows"][0].pop("connection_id")
    assert build_assessment(scope, components, receipt, flows, context, "standard")["signals"] == []


def test_signal_projection_cannot_expand_sources_to_unrelated_components(tmp_path):
    scope, components, receipt, flows, context = crossing_input(tmp_path)
    assessment = build_assessment(scope, components, receipt, flows, context, "standard")
    extra = copy.deepcopy(assessment["components"][0])
    extra["id"] = "unrelated-component"
    assessment["components"].append(extra)
    projected = project_assessment_signal(assessment, assessment["signals"][0]["id"], flows["data_flows"])
    assert {c["id"] for c in projected["components"]} == {"component-1", "component-2"}
    assert len(assessment["components"]) == 3
    with pytest.raises(ValueError, match="controller-selected"):
        project_assessment_signal(assessment, "signal-model-selected", flows["data_flows"])


def test_assessment_input_rejects_foreign_source_context_and_missing_measurements(tmp_path):
    scope, components, receipt, flows, context = crossing_input(tmp_path)
    context["recon_signals"]["evidence"] = [
        {**flows["data_flows"][0]["evidence"][0], "repository_id": "repo-ffffffffffffffff"}
    ]
    with pytest.raises(ValueError):
        build_assessment(scope, components, receipt, flows, context, "standard")
    with pytest.raises(ValidationError):
        build_assessment(scope, components, receipt, flows, {}, "standard")
