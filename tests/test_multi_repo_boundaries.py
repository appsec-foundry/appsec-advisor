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
    assessment_source_context,
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


def fixture(tmp_path, *, names=("edge", "service"), files=None):
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
        for relative, text in (files or {}).get(name, {}).items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text)
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


@pytest.mark.parametrize("points", [("Route guard", "Session check"), ("Route guard", "Route guard")])
def test_merging_two_crossings_of_one_receiver_stays_within_the_evidence_contract(tmp_path, points):
    """Two contract-sized rows for one crossing fold into one row instead of aborting the assessment."""
    source = "".join(f"check_{n} = guard(request)\n" for n in range(1, 7))
    scope, components, _ = fixture(tmp_path, files={"edge": {"app.py": source}})
    repository = scope.repositories[0]
    sha = hashlib.sha256(repository.files["app.py"]).hexdigest()
    components["components"][0]["paths"][0]["sha256"] = sha
    rows = []
    for index, (point, lines) in enumerate(zip(points, ((1, 2, 3), (4, 5, 6)), strict=True), 1):
        row = candidate(f"candidate-{index}", "component-1", None)
        row.update(
            name=f"Ingress {index}",
            enforcement_point=point,
            evidence=[dict(repository_id=repository.repository_id, file="app.py", line=n, sha256=sha) for n in lines],
        )
        rows.append(row)
    scope.output.mkdir()
    document, _ = normalize_assessment_boundaries(scope, components, rows, output_dir=scope.output)
    merged = [b for b in document["trust_boundaries"] if b["to"] == "component-1"]
    assert len(merged) == 1
    lines = [e["line"] for e in merged[0]["evidence"]]
    assert len(lines) == 5 and set(lines) <= set(range(1, 7))
    # The surviving row keeps all of its own evidence.
    assert {1, 2, 3} <= set(lines) or {4, 5, 6} <= set(lines)


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


def test_shared_source_paths_do_not_erase_a_qualified_privilege_transition(tmp_path):
    scope, components, evidence = fixture(tmp_path)
    caller = components["components"][0]
    components["components"].append({**copy.deepcopy(caller), "id": "component-3", "name": "Processor"})
    row = candidate("candidate-1", "component-3", evidence[0])
    row.update({"from": "component-1", "kind": "privilege"})
    row.pop("enforcement_point")
    scope.output.mkdir()
    document, _warnings = normalize_assessment_boundaries(scope, components, [row], output_dir=scope.output)
    [boundary] = document["trust_boundaries"]
    assert (boundary["kind"], boundary["surface"], boundary["transition"]) == ("privilege", "network", ["privilege"])


def test_qualified_in_process_privilege_transition_survives(tmp_path):
    scope, components, evidence = fixture(tmp_path)
    caller = components["components"][0]
    components["components"].append({**copy.deepcopy(caller), "id": "component-3", "name": "Processor"})
    row = candidate("candidate-1", "component-3", evidence[0])
    row.update({"from": "component-1", "kind": "privilege", "surface": "in-process"})
    row.pop("enforcement_point")
    scope.output.mkdir()
    document, _warnings = normalize_assessment_boundaries(scope, components, [row], output_dir=scope.output)
    [boundary] = document["trust_boundaries"]
    assert (boundary["surface"], boundary["transition"]) == ("in-process", ["privilege"])


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


def crossing_input(tmp_path, *, names=("edge", "service"), files=None):
    scope, components, evidence = fixture(tmp_path, names=names, files=files)
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


def flask_routes(*routes):
    lines = ["from flask import Flask", "app = Flask(__name__)", ""]
    for path, decorators in routes:
        lines += [
            f'@app.route("{path}", methods=["GET"])',
            *decorators,
            f"def handler_{len(lines)}():",
            "    return 1",
            "",
        ]
    return "\n".join(lines)


@pytest.mark.parametrize(
    ("names", "layout"),
    [
        (("edge", "service"), {"api": "src/api.py", "workflow": ".github/workflows/ci.yml"}),
        (("north", "south"), {"api": "lib/handlers/views.py", "workflow": "pkg/.github/workflows/build.yaml"}),
    ],
)
def test_measured_source_context_qualifies_every_repository(tmp_path, names, layout):
    files = {
        names[0]: {layout["api"]: flask_routes(("/session", ["@login_required"]))},
        names[1]: {
            layout["api"]: flask_routes(("/records", [])),
            layout["workflow"]: "on: push\njobs: {}\n",
        },
    }
    scope, components, receipt, flows, _ = crossing_input(tmp_path, names=names, files=files)
    context = assessment_source_context(scope)
    by_label = {r.root.name: r for r in scope.repositories}
    routes = context["route_inventory"]["routes"]
    assert [row["route_id"] for row in routes] == ["R-001", "R-002"]
    assert {(row["path"], row["evidence"][0]["repository_id"]) for row in routes} == {
        ("/session", by_label[names[0]].repository_id),
        ("/records", by_label[names[1]].repository_id),
    }
    for row in routes:
        repo = next(r for r in scope.repositories if r.repository_id == row["evidence"][0]["repository_id"])
        assert row["evidence"][0]["sha256"] == hashlib.sha256(repo.files[layout["api"]]).hexdigest()
    values = context["recon_signals"]["values"]
    assert values["has_public_routes"] is values["has_auth_surface"] is values["has_ci_pipeline"] is True
    assert values["has_external_apis"] is values["has_client_storage"] is values["has_multi_tenancy_signal"] is None
    assert (by_label[names[1]].repository_id, layout["workflow"]) in {
        (row["repository_id"], row["file"]) for row in context["recon_signals"]["evidence"]
    }
    assessment = build_assessment(scope, components, receipt, flows, context, "standard")
    assert assessment["source_context"] == context
    # The controller's earlier inventories stand in for a second scan unchanged.
    from orchestrator.orchestration_controller import _assessment_inventories

    earlier = {rid: row["routes"] for rid, row in _assessment_inventories(scope).items()}
    assert assessment_source_context(scope, earlier) == context


def test_unmeasured_recon_signals_stay_null_instead_of_false(tmp_path):
    scope, components, receipt, flows, _ = crossing_input(tmp_path)
    context = assessment_source_context(scope)
    assert context["route_inventory"] == {"status": "present", "routes": []}
    assert set(context["recon_signals"]["values"].values()) == {None}
    assert context["recon_signals"]["evidence"] == []
    assert build_assessment(scope, components, receipt, flows, context, "standard")["signals"]


def test_route_cap_keeps_every_repository_represented(tmp_path):
    many = flask_routes(*((f"/item{index}", []) for index in range(105)))
    files = {"edge": {"src/api.py": many}, "service": {"src/api.py": flask_routes(("/only", []))}}
    scope, *_ = crossing_input(tmp_path, files=files)
    routes = assessment_source_context(scope)["route_inventory"]["routes"]
    assert len(routes) == 100
    assert "/only" in {row["path"] for row in routes}
    assert len({row["route_id"] for row in routes}) == 100


def test_an_unreadable_boundary_declaration_stops_the_assessment(tmp_path):
    scope, *_ = crossing_input(tmp_path, files={"service": {".appsec/trust-boundaries.yaml": "boundaries: [x\n"}})
    with pytest.raises(ValueError):
        assessment_source_context(scope)
