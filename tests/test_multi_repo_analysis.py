"""Semantic jobs retain qualified evidence and cannot invent peer authority."""

import copy
import hashlib
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from contexts import multi_repo_analysis as stage
from runtime.assessment_host import ExchangeError
from runtime.multi_repo_scope import AssessmentScope, RepositoryView

FP = "sha256:" + "a" * 64


def sources(tmp_path):
    repos = tuple(
        RepositoryView(
            f"repo-{i:016x}", tmp_path / f"repo{i}", "b" * 40, "c" * 64, {"app.py": b"result = request.args['input']\n"}
        )
        for i in (1, 2)
    )
    scope = AssessmentScope(repos, tmp_path / "output")
    components = [
        dict(
            id=f"component-{i}",
            name="Service",
            tier="application",
            repository_ids=[r.repository_id],
            paths=[
                dict(repository_id=r.repository_id, path="app.py", sha256=hashlib.sha256(r.files["app.py"]).hexdigest())
            ],
        )
        for i, r in enumerate(repos, 1)
    ]
    evidence = [
        dict(repository_id=r.repository_id, file="app.py", line=1, sha256=components[i]["paths"][0]["sha256"])
        for i, r in enumerate(repos)
    ]
    ranges = [
        dict(repository_id=e["repository_id"], path=e["file"], sha256=e["sha256"], start_line=1, end_line=1)
        for e in evidence
    ]
    identity = dict(
        schema_version=2, source_scope_sha256=scope.inventory()["scope_sha256"], component_inventory_fingerprint=FP
    )
    return scope, components, evidence, ranges, identity


def stride(component, evidence, identity):
    finding = dict(
        local_id="issue-1",
        title="Unvalidated input reaches the request handler",
        stride="Tampering",
        scenario="An attacker submits malformed input to the request handler.",
        likelihood="Medium",
        impact="Medium",
        risk="Medium",
        evidence=evidence,
        evidence_tier="insecure-practice",
        threat_category_id="TH-01",
        cwe="CWE-20",
        remediation=dict(
            effort="Low",
            steps=["Validate the input against the accepted data type."],
            verification="Submit malformed input and assert that the endpoint rejects it.",
        ),
    )
    coverage = [
        dict(
            category=category,
            disposition="finding" if category == "Tampering" else "no-evidence",
            finding_ids=["issue-1"] if category == "Tampering" else [],
            reason="Retrieved source does not establish another finding.",
        )
        for category in stage.STRIDE_CATEGORIES
    ]
    return dict(
        **identity,
        component_id=component["id"],
        component_name=component["name"],
        analyzed_at="2026-01-01T00:00:00Z",
        partial=False,
        skipped_categories=[],
        coverage=coverage,
        threats=[finding],
    )


def test_valid_stride_and_independent_verification_preserve_sources(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    original = copy.deepcopy(artifact)
    stage.validate_stride(
        scope, components[0], components, dict(component_inventory_fingerprint=FP, data_flows=[]), artifact, ranges[:1]
    )
    assert artifact == original
    review = dict(
        **identity,
        decisions=[
            dict(
                local_id="issue-1",
                verdict="verified",
                reason="The independently read anchor implements the reported practice.",
                evidence=[evidence[0]],
            )
        ],
    )
    stage.validate_evidence_review(
        scope, artifact["threats"], FP, review, ranges[:1], stage.source_selection(components)
    )


@pytest.mark.parametrize(
    "kind",
    [
        "owner",
        "hash",
        "unknown-field",
        "coverage",
        "identity",
        "missing-source",
        "unretrieved",
        "requirements",
        "partial",
    ],
)
def test_stride_rejects_forged_or_incomplete_work(tmp_path, kind):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    if kind == "owner":
        artifact["threats"][0]["evidence"] = evidence[1]
    elif kind == "hash":
        artifact["threats"][0]["evidence"]["sha256"] = "0" * 64
    elif kind == "unknown-field":
        artifact["execute"] = "command"
    elif kind == "coverage":
        artifact["coverage"][1]["finding_ids"] = []
    elif kind == "identity":
        artifact["component_id"] = components[1]["id"]
    elif kind == "requirements":
        artifact["threats"][0]["violated_requirements"] = ["INVENTED-01"]
    elif kind == "partial":
        artifact["partial"] = True
    else:
        ranges = []
        if kind == "missing-source":
            artifact["threats"] = []
            for row in artifact["coverage"]:
                row.update(disposition="no-evidence", finding_ids=[])
    with pytest.raises(ValueError):
        stage.validate_stride(
            scope, components[0], components, dict(component_inventory_fingerprint=FP, data_flows=[]), artifact, ranges
        )


def test_peer_neighborhood_does_not_expand_through_a_shared_broker(tmp_path):
    _, components, _, _, _ = sources(tmp_path)
    broker = dict(id="broker", paths=[], repository_ids=[])
    another = dict(id="another-consumer", paths=[], repository_ids=[])
    flows = dict(
        data_flows=[
            {"from": components[0]["id"], "to": "broker"},
            {"from": "broker", "to": components[1]["id"]},
            {"from": "broker", "to": "another-consumer"},
        ]
    )
    neighborhood = stage.component_neighborhood(
        dict(components=components + [broker, another]), flows, components[0]["id"]
    )
    assert {c["id"] for c in neighborhood} == {components[0]["id"], "broker"}


@pytest.mark.parametrize("connected", [False, True])
def test_cross_repository_trace_requires_a_directional_reviewed_flow(tmp_path, connected):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[1], evidence[1], identity)
    finding = artifact["threats"][0]
    finding.update(
        cwe="CWE-89",
        evidence_tier="confirmed-exploitable",
        mechanism_trace=dict(
            input=evidence[0],
            sink=evidence[1],
            connection="The sender's request reaches the receiver's query without parameterization.",
            control=dict(
                status="absent-at-sink",
                location=evidence[1],
                explanation="The query at the cited sink executes the unvalidated request value.",
            ),
        ),
    )
    flows = dict(
        component_inventory_fingerprint=FP,
        data_flows=[dict(**{"from": components[0]["id"], "to": components[1]["id"]})] if connected else [],
    )
    if connected:
        stage.validate_stride(scope, components[1], components, flows, artifact, ranges)
    else:
        with pytest.raises(ExchangeError, match="directional"):
            stage.validate_stride(scope, components[1], components, flows, artifact, ranges)


def test_comment_cannot_substitute_for_implementation_evidence(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    views = list(scope.repositories)
    views[0] = RepositoryView(
        views[0].repository_id, views[0].root, "b" * 40, "c" * 64, {"app.py": b"# result = request.args['input']\n"}
    )
    scope = AssessmentScope(tuple(views), scope.output)
    evidence[0]["sha256"] = hashlib.sha256(views[0].files["app.py"]).hexdigest()
    ranges[0]["sha256"] = evidence[0]["sha256"]
    identity["source_scope_sha256"] = scope.inventory()["scope_sha256"]
    artifact = stride(components[0], evidence[0], identity)
    with pytest.raises(ExchangeError, match="executable"):
        stage.validate_stride(
            scope,
            components[0],
            components,
            dict(component_inventory_fingerprint=FP, data_flows=[]),
            artifact,
            ranges[:1],
        )


@pytest.mark.parametrize("kind", ["stale", "missing", "duplicate", "borrowed-anchor"])
def test_evidence_review_cannot_forge_completion(tmp_path, kind):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    review = dict(
        **identity,
        decisions=[
            dict(
                local_id="issue-1",
                verdict="verified",
                reason="Independent source review supports the finding.",
                evidence=[evidence[0]],
            )
        ],
    )
    if kind == "stale":
        review["component_inventory_fingerprint"] = "sha256:" + "0" * 64
    elif kind == "missing":
        review["decisions"] = []
    elif kind == "duplicate":
        review["decisions"] *= 2
    else:
        review["decisions"][0]["evidence"] = [evidence[1]]
    with pytest.raises(ExchangeError):
        stage.validate_evidence_review(
            scope, artifact["threats"], FP, review, ranges, stage.source_selection(components)
        )


def test_local_architecture_cannot_promote_a_peer_without_connection_review(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = dict(
        **identity, repository_id=evidence[0]["repository_id"], data_flows=[], external_entities=[], assets=[]
    )
    stage.validate_local_architecture(
        scope,
        evidence[0]["repository_id"],
        dict(components=components, source_scope_sha256=identity["source_scope_sha256"]),
        dict(component_inventory_fingerprint=FP),
        artifact,
        [],
    )
    artifact["assets"] = [
        dict(
            id="asset-records",
            name="Records",
            classification="Internal",
            description="Application records.",
            component_refs=[dict(component_id=components[1]["id"], relation="processed", evidence=[evidence[0]])],
        )
    ]
    with pytest.raises(ExchangeError, match="outside"):
        stage.validate_local_architecture(
            scope,
            evidence[0]["repository_id"],
            dict(components=components, source_scope_sha256=identity["source_scope_sha256"]),
            dict(component_inventory_fingerprint=FP),
            artifact,
            ranges[:1],
        )


def test_controls_cannot_borrow_evidence_from_another_owner(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = dict(
        **identity,
        security_controls=[
            dict(
                domain="Input Validation",
                control="Request Validation",
                effectiveness="Partial",
                assessment="Only part of the request is validated.",
                component_ids=[components[0]["id"]],
                evidence=[evidence[0]],
            )
        ],
    )
    stage.validate_controls(scope, components, FP, artifact, ranges)
    artifact["security_controls"][0]["evidence"] = [evidence[1]]
    with pytest.raises(ExchangeError, match="owned"):
        stage.validate_controls(scope, components, FP, artifact, ranges)


def test_stage_contracts_are_closed_and_local_refs_do_not_fetch_network():
    for name in stage.CONTRACTS[:4]:
        schema = stage.contract(name)
        assert schema["additionalProperties"] is False
        Draft202012Validator.check_schema(schema)
    with pytest.raises(ExchangeError, match="Unknown"):
        stage.contract("https://example.invalid/remote.json")
