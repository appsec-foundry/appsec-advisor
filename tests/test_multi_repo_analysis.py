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
            steps=["Validate the input against the accepted data type.", "Reject requests that fail validation."],
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


@pytest.mark.parametrize(
    ("cited", "allowed", "accepted"),
    [
        (["SEC-AUTH-1"], {"SEC-AUTH-1", "SEC-LOG-2"}, True),
        (["SEC-AUTH-1", "SEC-AUTH-9"], {"SEC-AUTH-1"}, False),
        (["SEC-AUTH-1"], frozenset(), False),
    ],
)
def test_stride_cites_only_requirements_of_its_supplied_catalog(tmp_path, cited, allowed, accepted):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    artifact["threats"][0]["violated_requirements"] = cited
    original = copy.deepcopy(artifact)

    def run():
        stage.validate_stride(
            scope,
            components[0],
            components,
            dict(component_inventory_fingerprint=FP, data_flows=[]),
            artifact,
            ranges[:1],
            allowed_requirement_ids=allowed,
        )

    if accepted:
        run()
        assert artifact == original
    else:
        with pytest.raises(ExchangeError, match="requirements absent"):
            run()


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
    with pytest.raises(ExchangeError) as raised:
        stage.validate_evidence_review(
            scope, artifact["threats"], FP, review, ranges, stage.source_selection(components)
        )
    # The correction turn must learn which decision to fix, not only that one is off.
    expected = {"missing": "missing: issue-1", "duplicate": "repeated: issue-1"}.get(kind)
    if expected:
        assert expected in str(raised.value)


@pytest.mark.parametrize("repositories", [1, 2])
def test_a_sole_repository_must_name_a_protected_asset(tmp_path, repositories):
    combined, components, evidence, ranges, _identity = sources(tmp_path)
    scope = AssessmentScope(combined.repositories[:repositories], tmp_path / "output")
    rid = components[0]["repository_ids"][0]
    inventory = dict(components=components[:repositories], source_scope_sha256=scope.inventory()["scope_sha256"])
    identity = dict(
        schema_version=2, source_scope_sha256=inventory["source_scope_sha256"], component_inventory_fingerprint=FP
    )
    empty = dict(**identity, repository_id=rid, data_flows=[], external_entities=[], assets=[])
    arguments = (scope, rid, inventory, dict(component_inventory_fingerprint=FP))
    if repositories == 1:
        with pytest.raises(ExchangeError, match="no protected asset"):
            stage.validate_local_architecture(*arguments, empty, ranges)
    else:
        stage.validate_local_architecture(*arguments, empty, ranges)
    asset = dict(
        id="asset-orders",
        name="Order records",
        classification="Confidential",
        description="Customer orders the service stores.",
        component_refs=[dict(component_id=components[0]["id"], relation="processed", evidence=[evidence[0]])],
    )
    stage.validate_local_architecture(*arguments, {**empty, "assets": [asset]}, ranges)


def test_evidence_batches_keep_every_anchor_readable_within_one_review():
    def finding(local_id, file, line=10, kind=None):
        evidence = {"repository_id": "r", "file": file, "line": line, **({"kind": kind} if kind else {})}
        return {"local_id": local_id, "evidence": evidence}

    findings = [finding(f"f{i}", f"wf/{i % 13}.yml") for i in range(29)] + [
        finding("same-window", "wf/0.yml", 20),
        finding("absence", "wf/1.yml", None, "absence"),
    ]
    batches = stage.evidence_batches(findings, max_windows=8, max_findings=15, window_lines=400)
    assert sorted(f["local_id"] for batch in batches for f in batch) == sorted(f["local_id"] for f in findings)
    for batch in batches:
        assert len(batch) <= 15
        assert len({(f["evidence"]["file"], (f["evidence"]["line"] or 0) // 400) for f in batch}) <= 8
    # Findings that one slice can show stay in one review.
    assert len(stage.evidence_batches(findings[:3], max_windows=8, max_findings=15, window_lines=400)) == 1


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


def _role_architecture(evidence, identity, schemes, *, via_client, access=None):
    """One legitimate role whose request path carries the given authentication schemes."""
    role = dict(id="ext-member", name="Member", kind="legitimate-role", description="Uses the service.")
    role["evidence"] = [evidence]
    if access:
        role["access"] = access

    def flow(number, source, target, scheme=None, **extra):
        row = dict(
            id=f"df-{number:03d}",
            label="Request",
            protocol="HTTPS",
            data_classification="internal",
            direction="unidirectional",
            evidence=[evidence],
            provenance="architecture",
            **{"from": source, "to": target},
            **extra,
        )
        if scheme:
            row["authentication"] = dict(scheme=scheme, scope="Request handler check.", evidence=[evidence])
        return row

    if via_client:
        flows = [flow(1, "external", "component-ui", from_entity="ext-member", interaction=True)]
        flows += [flow(n, "component-ui", "component-api", s) for n, s in enumerate(schemes, 2)]
    else:
        flows = [flow(n, "external", "component-api", s, from_entity="ext-member") for n, s in enumerate(schemes, 1)]
    return dict(
        **identity,
        repository_id=evidence["repository_id"],
        data_flows=flows,
        external_entities=[role],
        assets=[],
    )


@pytest.mark.parametrize("via_client", [False, True])
@pytest.mark.parametrize(
    ("schemes", "access"),
    [(["none", "bearer"], None), (["none", "bearer"], "internet-user"), (["none", "none"], None)],
)
def test_local_architecture_leaves_a_mixed_role_path_to_classification(tmp_path, via_client, schemes, access):
    """A mixed request path is no analyst error; the controller splits the role after the handoff."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    rid = evidence[0]["repository_id"]
    local = [dict(components[0], id="component-api")]
    if via_client:
        local.append(dict(components[0], id="component-ui", name="Browser client", tier="client"))
    artifact = _role_architecture(evidence[0], identity, schemes, via_client=via_client, access=access)
    call = (
        lambda: stage.validate_local_architecture(  # noqa: E731
            scope,
            rid,
            dict(components=local + components[1:], source_scope_sha256=identity["source_scope_sha256"]),
            dict(component_inventory_fingerprint=FP),
            artifact,
            ranges[:1],
        )
    )
    call()


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


@pytest.mark.parametrize(
    ("domain", "control"),
    [
        ("Trust-boundary enforcement", "postMessage origin validation"),
        ("Perimeter hygiene", "Open redirect and navigation validation"),
    ],
)
def test_a_control_no_report_section_takes_is_corrected_in_its_job(tmp_path, domain, control):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    row = dict(
        domain=domain,
        control=control,
        effectiveness="Missing",
        assessment="No check was found.",
        component_ids=[components[0]["id"]],
        evidence=[evidence[0]],
    )
    artifact = dict(**identity, security_controls=[row])
    with pytest.raises(ExchangeError, match="Browser and Cross-Origin Controls") as caught:
        stage.validate_controls(scope, components, FP, artifact, ranges)
    assert "Security Control Overview" not in str(caught.value)
    # The everyday domains the report normalizes keep passing.
    artifact["security_controls"] = [dict(row, domain="Authentication", control="Password hashing")]
    stage.validate_controls(scope, components, FP, artifact, ranges)


def test_stage_contracts_are_closed_and_local_refs_do_not_fetch_network():
    for name in stage.CONTRACTS[:4]:
        schema = stage.contract(name)
        assert schema["additionalProperties"] is False
        Draft202012Validator.check_schema(schema)
    with pytest.raises(ExchangeError, match="Unknown"):
        stage.contract("https://example.invalid/remote.json")


@pytest.mark.parametrize(("kind", "accepted"), [("absence", True), (None, False)])
def test_an_absence_is_verified_by_any_retrieved_range_of_its_anchor_file(tmp_path, kind, accepted):
    data = b"COPY . .\nRUN install\nCMD start\n"
    repo, other = (
        RepositoryView(f"repo-{i:016x}", tmp_path / f"repo{i}", "b" * 40, "c" * 64, {"Dockerfile": data})
        for i in (1, 2)
    )
    scope = AssessmentScope((repo, other), tmp_path / "output")
    sha = hashlib.sha256(data).hexdigest()
    anchor = dict(repository_id=repo.repository_id, file="Dockerfile", line=1, sha256=sha)
    if kind:
        anchor.update(kind=kind, searched_files=["Dockerfile"], searched_file_count=1)
    identity = dict(
        schema_version=2, source_scope_sha256=scope.inventory()["scope_sha256"], component_inventory_fingerprint=FP
    )
    cited = dict(repository_id=repo.repository_id, file="Dockerfile", line=3, sha256=sha)
    review = dict(
        **identity,
        decisions=[
            dict(
                local_id="cfg-1",
                verdict="verified",
                reason="The whole file declares no runtime user.",
                evidence=[cited],
            )
        ],
    )
    ranges = [dict(repository_id=repo.repository_id, path="Dockerfile", sha256=sha, start_line=2, end_line=3)]
    allowed = frozenset({(repo.repository_id, "Dockerfile")})
    check = lambda: stage.validate_evidence_review(  # noqa: E731
        scope, [dict(local_id="cfg-1", evidence=anchor)], FP, review, ranges, allowed
    )
    if accepted:
        check()
    else:
        with pytest.raises(ExchangeError, match="independent reading"):
            check()


def test_local_architecture_returns_every_combined_flow_invariant_to_its_author(tmp_path):
    """Rules beyond the role check, here a human interaction aimed at a server, reach the analyst too."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    local = [dict(components[0], id="component-api")]
    artifact = _role_architecture(evidence[0], identity, ["none"], via_client=False, access="internet-anon")
    artifact["data_flows"][0]["interaction"] = True
    artifact["data_flows"][0].pop("authentication")
    with pytest.raises(ExchangeError, match="human interaction must target a client component"):
        stage.validate_local_architecture(
            scope,
            evidence[0]["repository_id"],
            dict(components=local + components[1:], source_scope_sha256=identity["source_scope_sha256"]),
            dict(component_inventory_fingerprint=FP),
            artifact,
            ranges[:1],
        )


@pytest.mark.parametrize(
    ("scheme", "entity_kind", "with_client"),
    [
        # The run that exposed it: a password login and a cookie request marked as interactions, no client at all.
        ("password", "legitimate-role", False),
        ("cookie", "legitimate-role", False),
        # The same flag on an unauthenticated server request, or from a non-human entity, beside a real client.
        (None, "legitimate-role", True),
        (None, "external-service", True),
    ],
)
def test_an_impossible_interaction_flag_is_removed_not_returned_for_correction(
    tmp_path, scheme, entity_kind, with_client
):
    """The controller knows every fact that decides an interaction; a wrong flag never costs a correction turn."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    local = [dict(components[0], id="component-api")]
    artifact = _role_architecture(evidence[0], identity, [scheme or "none"], via_client=False)
    if with_client:
        local.append(dict(components[0], id="component-ui", name="Browser client", tier="client"))
        artifact["data_flows"].append(
            dict(artifact["data_flows"][0], id="df-009", to="component-ui", interaction=True, authentication=None)
        )
        artifact["data_flows"][-1].pop("authentication")
    artifact["external_entities"][0]["kind"] = entity_kind
    artifact["data_flows"][0]["interaction"] = True
    if scheme is None:
        artifact["data_flows"][0].pop("authentication", None)
    validate = (
        lambda value: stage.validate_local_architecture(  # noqa: E731
            scope,
            evidence[0]["repository_id"],
            dict(components=local + components[1:], source_scope_sha256=identity["source_scope_sha256"]),
            dict(component_inventory_fingerprint=FP),
            value,
            ranges[:1],
        )
    )
    if entity_kind == "legitimate-role":
        with pytest.raises(ExchangeError, match="interaction"):
            validate(copy.deepcopy(artifact))
    normalize = stage.local_architecture_normalizer(local)
    fixed = normalize(copy.deepcopy(artifact))
    assert "interaction" not in fixed["data_flows"][0]
    # The flow stays an analyzed access with its own authentication claim.
    assert fixed["data_flows"][0].get("authentication") == artifact["data_flows"][0].get("authentication")
    assert normalize(copy.deepcopy(fixed)) == fixed
    if entity_kind == "legitimate-role":
        validate(fixed)
    if with_client:
        # A human-to-client interaction is kept; a non-human entity's is not.
        assert ("interaction" in fixed["data_flows"][-1]) is (entity_kind == "legitimate-role")


@pytest.mark.parametrize(("jobs", "used", "expected"), [(5, 0, 100), (2, 100, 200), (3, 500, 0)])
def test_each_job_gets_its_share_of_a_combined_list_limit(jobs, used, expected):
    """Concatenated job lists can no longer exceed the combined contract that bounds them."""
    schema = stage.job_share(
        stage.contract("multi-repo-architecture.schema.json"),
        "fragments/data-flows-v2.schema.json",
        jobs=jobs,
        used={"data_flows": used},
    )
    assert schema["properties"]["data_flows"]["maxItems"] == expected
    assert schema["properties"]["external_entities"]["maxItems"] == 64 // jobs
    assert stage.contract("multi-repo-architecture.schema.json")["properties"]["data_flows"]["maxItems"] == 500


def test_local_group_names_of_two_repositories_never_join_their_flows():
    from orchestrator.orchestration_controller import _namespace_local_flow

    def local():
        return {
            "id": "df-001",
            "from": "external",
            "from_entity": "ext-client",
            "to": "component-api",
            "access_group": {"id": "inbound-api", "mode": "alternatives", "label": "Inbound API"},
            "protocol_group": "Sign-in",
        }

    first = _namespace_local_flow(local(), "repo-0000000000000001", "edge", {"ext-client": "ext-a"})
    second = _namespace_local_flow(local(), "repo-0000000000000002", "service", {"ext-client": "ext-b"})
    assert first["access_group"]["id"] != second["access_group"]["id"]
    assert first["protocol_group"] != second["protocol_group"]
    assert first["access_group"]["label"] == "Inbound API" and first["protocol_group"].startswith("Sign-in")


def test_a_local_flow_cannot_claim_a_reviewed_connection(tmp_path):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = _role_architecture(evidence[0], identity, ["none"], via_client=False, access="internet-anon")
    artifact["data_flows"][0]["connection_id"] = "connection-" + "a" * 16
    with pytest.raises(ExchangeError, match="reviewed cross-repository connection"):
        stage.validate_local_architecture(
            scope,
            evidence[0]["repository_id"],
            dict(
                components=[dict(components[0], id="component-api")] + components[1:],
                source_scope_sha256=identity["source_scope_sha256"],
            ),
            dict(component_inventory_fingerprint=FP),
            artifact,
            ranges[:1],
        )


@pytest.mark.parametrize(("kind", "rejected"), [("external-service", True), ("legitimate-role", False)])
def test_local_architecture_cannot_repeat_a_reviewed_call_as_an_external_service(tmp_path, kind, rejected):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    rid = evidence[0]["repository_id"]
    local = next(c for c in components if c["repository_ids"] == [rid])
    peer = dict(id="ext-peer", name="peer", kind=kind, description="Called peer.", evidence=[evidence[0]])
    flow = dict(
        id="df-001",
        **(
            {"from": local["id"], "to": "external", "to_entity": "ext-peer"}
            if kind != "legitimate-role"
            else {"from": "external", "from_entity": "ext-peer", "to": local["id"]}
        ),
        label="Peer call",
        protocol="HTTP",
        data_classification="unknown",
        direction="unidirectional",
        evidence=[evidence[0]],
        provenance="architecture",
    )
    artifact = dict(**identity, repository_id=rid, data_flows=[flow], external_entities=[peer], assets=[])
    reviewed = [dict(connection_id="connection-" + "a" * 16, evidence=[evidence[0]])]
    arguments = (
        scope,
        rid,
        dict(components=components, source_scope_sha256=identity["source_scope_sha256"]),
        dict(component_inventory_fingerprint=FP),
        artifact,
        ranges,
    )
    if rejected:
        with pytest.raises(ExchangeError, match="connection-a"):
            stage.validate_local_architecture(*arguments, reviewed)
    # Without a reviewed connection the same external call stays a valid local flow.
    assert stage._reviewed_call_flows(rid, artifact, []) == []
    assert stage._reviewed_call_flows(rid, artifact, reviewed) == (["connection-" + "a" * 16] if rejected else [])
