"""The production controller joins scoped fresh stages without imported models."""

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from orchestrator import orchestration_controller as controller
from runtime.analyst_host import HostReply
from runtime.assessment_host import MARKER
from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
from runtime.multi_repo_scope import admit


def checkout(root):
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
    (root / "app.py").write_text(
        'cluster = "neutral-a"; endpoint = "https://api.example.invalid"; operation = "GET /records"\nvalue = request.args["record"]\n'
    )


class Host:
    def __init__(self, scope):
        self.scope = scope
        self.calls = []

    def factory(self, role, ceiling):
        owner = self

        class Transport:
            def invoke(self, system, prompt, schema, timeout_s, should_stop):
                return owner.invoke(role, prompt)

        return Transport()

    def invoke(self, role, prompt):
        packet = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
        ctx, slices = packet["context"], packet["source_slices"]
        self.calls.append((role, copy.deepcopy(ctx)))
        rid = ctx.get("repository_id")
        if role == "recon_scanner":
            allowed = [(rid, "app.py")]
        elif "candidate" in ctx:
            allowed = [(p["repository_id"], p["path"]) for c in ctx["components"] for p in c["paths"]]
        else:
            components = ctx.get("components", [ctx.get("component")])
            allowed = [(p["repository_id"], p["path"]) for c in components if c for p in c["paths"]]
        if not slices:
            return HostReply(
                dict(
                    action="read",
                    artifact=None,
                    reads=[dict(repository_id=r, path=p, start_line=1, end_line=2) for r, p in sorted(set(allowed))],
                ),
                0.01,
            )
        evidence = [dict(repository_id=s["repository_id"], file=s["path"], line=2, sha256=s["sha256"]) for s in slices]
        if role == "recon_scanner":
            artifact = dict(
                schema_version=1,
                repository_id=rid,
                components=[
                    dict(
                        id="service",
                        name="Service",
                        description="Application service.",
                        tier="application",
                        paths=["app.py"],
                    )
                ],
                interfaces=[
                    dict(
                        id="api",
                        component_id="service",
                        role="request" if rid == self.scope.repositories[0].repository_id else "serve",
                        protocol="HTTPS",
                        address="https://api.example.invalid",
                        deployment="neutral-a",
                        operation="GET /records",
                        evidence=[dict(file="app.py", line=1, quote=slices[0]["lines"][0])],
                    )
                ],
            )
        elif "candidate" in ctx:
            artifact = dict(
                schema_version=1,
                scope_sha256=ctx["scope_sha256"],
                candidates_sha256=ctx["candidates_sha256"],
                component_inventory_fingerprint=ctx["component_inventory_fingerprint"],
                decisions=[
                    dict(
                        candidate_id=ctx["candidate"]["id"],
                        disposition="resolved",
                        reason="Both implementation endpoints and their deployment binding establish this communication.",
                        evidence=[
                            dict(repository_id=s["repository_id"], file=s["path"], line=1, quote=s["lines"][0])
                            for s in slices
                        ],
                    )
                ],
            )
        else:
            identity = dict(
                schema_version=2,
                source_scope_sha256=ctx["source_scope_sha256"],
                component_inventory_fingerprint=ctx["component_inventory_fingerprint"],
            )
            if role == "architecture_analyst":
                artifact = dict(**identity, repository_id=rid, external_entities=[], data_flows=[], assets=[])
            elif role == "control_analyst":
                artifact = dict(
                    **identity,
                    security_controls=[
                        dict(
                            domain="Input Validation",
                            control="Request Validation",
                            effectiveness="Partial",
                            assessment="The handler reads a request parameter directly.",
                            component_ids=[ctx["component"]["id"]],
                            evidence=[evidence[0]],
                        )
                    ],
                )
            elif role == "stride_analyzer":
                finding = dict(
                    local_id="issue-1",
                    title="Unvalidated input reaches the request handler",
                    stride="Tampering",
                    scenario="An attacker submits malformed input to the request handler.",
                    likelihood="Medium",
                    impact="Medium",
                    risk="Medium",
                    cwe="CWE-20",
                    evidence=evidence[0],
                    evidence_tier="insecure-practice",
                    threat_category_id="TH-01",
                    remediation=dict(
                        effort="Low",
                        steps=["Validate the accepted input type in the request handler."],
                        verification="Submit malformed input and assert that the handler rejects it.",
                    ),
                )
                from contexts.multi_repo_analysis import STRIDE_CATEGORIES

                artifact = dict(
                    **identity,
                    component_id=ctx["component"]["id"],
                    component_name=ctx["component"]["name"],
                    analyzed_at="2026-01-01T00:00:00Z",
                    partial=False,
                    skipped_categories=[],
                    threats=[finding],
                    coverage=[
                        dict(
                            category=category,
                            disposition="finding" if category == "Tampering" else "no-evidence",
                            finding_ids=["issue-1"] if category == "Tampering" else [],
                            reason="The retrieved implementation establishes no other finding.",
                        )
                        for category in STRIDE_CATEGORIES
                    ],
                )
            else:
                artifact = dict(
                    **identity,
                    decisions=[
                        dict(
                            local_id="issue-1",
                            verdict="verified",
                            reason="Independent reading confirms the insecure practice at the anchor.",
                            evidence=[evidence[0]],
                        )
                    ],
                )
        return HostReply(dict(action="complete", reads=[], artifact=artifact), 0.01)


@pytest.mark.parametrize("names", [("edge", "service"), ("west", "east")])
def test_controller_fresh_architecture_controls_and_stride_keep_equal_paths_distinct(tmp_path, names):
    roots = [tmp_path / name for name in names]
    for root in roots:
        checkout(root)
    scope = admit([str(r) for r in roots], str(tmp_path / "out"))
    host = Host(scope)
    jobs = AssessmentJobs(
        scope,
        scope.output / ".assessment/jobs",
        AssessmentBudget(2, 0.05, 60, 120),
        host.factory,
        lambda: False,
        lambda: None,
    )
    before = [
        {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()} for root in roots
    ]
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    assert len(architecture["components"]["components"]) == 2
    assert len(architecture["data_flows"]["data_flows"]) == 1
    assert architecture["connection_review"]["decisions"][0]["disposition"] == "resolved"
    controls = controller._assessment_controls(scope, jobs, architecture, progress=lambda text: None)
    documents, reviews, merged = controller._assessment_stride(
        scope, jobs, architecture, controls, [], progress=lambda text: None
    )
    assert len(documents) == len(reviews) == 2
    assert len(merged["threats"]) == 2
    assert {t["evidence"]["repository_id"] for t in merged["threats"]} == {r.repository_id for r in scope.repositories}
    assert all(t["evidence"]["file"] == "app.py" for t in merged["threats"])
    calls = len(host.calls)
    resumed = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    assert resumed == architecture and len(host.calls) == calls
    assert before == [
        {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()} for root in roots
    ]


def test_controller_rejects_unknown_semantic_owner():
    with pytest.raises(controller.ControllerError):
        controller._assessment_role_instructions("model_selected_role", "execute anything")


def test_controller_analysis_sessions_hold_owned_state_and_resume_without_new_calls(tmp_path, monkeypatch):
    for name in ("caller", "receiver"):
        checkout(tmp_path / name)
    scope = admit([str(tmp_path / name) for name in ("caller", "receiver")], str(tmp_path / "out"))
    host = Host(scope)
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: "a" * 64)
    models = []

    def factory(role, model, ceiling):
        models.append((role, model))
        return host.factory(role, ceiling)

    def analyze(resume):
        with controller._assessment_session(
            scope,
            ["--no-requirements"],
            budget=AssessmentBudget(2, 0.05, 60, 120),
            host_factory=factory,
            resume=resume,
            model="haiku",
        ) as (cfg, state, jobs):
            assert cfg["assessment_scope"] == "multiple-repositories" and "repo_root" not in cfg
            architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
            controls = controller._assessment_controls(scope, jobs, architecture, progress=lambda text: None)
            _, _, merged = controller._assessment_stride(
                scope,
                jobs,
                architecture,
                controls,
                [],
                progress=lambda text: None,
                started_at=state.state["started_at"],
            )
            assert state.budget.calls == len(host.calls)
            return merged

    merged = analyze(False)
    calls = len(host.calls)
    assert analyze(True) == merged and len(host.calls) == calls
    assert models and {model for _, model in models} == {"haiku"}
    state = json.loads((scope.output / ".assessment-state.json").read_text())
    assert state["status"] == "interrupted" and state["deliverables"] == {}
    assert not (scope.output / ".appsec-lock").exists()


def test_session_rejects_runtime_changes_before_returning_completion(tmp_path, monkeypatch):
    for name in ("caller", "receiver"):
        checkout(tmp_path / name)
    scope = admit([str(tmp_path / name) for name in ("caller", "receiver")], str(tmp_path / "out"))
    current = ["a" * 64]
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: current[0])
    with pytest.raises(controller.ControllerError, match="runtime changed"):
        with controller._assessment_session(
            scope, ["--no-requirements"], budget=AssessmentBudget(1, 0.05, 10, 60), host_factory=lambda *args: None
        ):
            current[0] = "b" * 64
    assert json.loads((scope.output / ".assessment-state.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("change", ["code", "instruction", "schema", "data"])
def test_runtime_identity_binds_plugin_bytes_without_local_path_dependence(tmp_path, monkeypatch, change):
    plugin = tmp_path / "plugin"
    paths = {
        "code": "scripts/runtime.py",
        "instruction": "agents/role.md",
        "schema": "schemas/output.json",
        "data": "data/policy.yaml",
    }
    for path in (*paths.values(), "config.json", ".claude-plugin/plugin.json"):
        target = plugin / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("original")
    monkeypatch.setattr(controller, "PLUGIN_ROOT", plugin)
    before = controller._assessment_runtime_fingerprint()
    (plugin / paths[change]).write_text("changed")
    assert controller._assessment_runtime_fingerprint() != before


def test_runtime_identity_rejects_linked_code(tmp_path, monkeypatch):
    plugin = tmp_path / "plugin"
    (plugin / "scripts").mkdir(parents=True)
    (plugin / "scripts/linked").symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(controller, "PLUGIN_ROOT", plugin)
    with pytest.raises(controller.ControllerError, match="directory links"):
        controller._assessment_runtime_fingerprint()


class BoundaryHost:
    def __init__(self, *, disposition="boundary", foreign=False):
        self.disposition, self.foreign, self.calls = disposition, foreign, 0

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        packet = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
        context, slices = packet["context"], packet["source_slices"]
        self.calls += 1
        if not slices:
            return HostReply(
                dict(
                    action="read",
                    artifact=None,
                    reads=[
                        dict(repository_id=row["repository_id"], path=row["path"], start_line=1, end_line=1)
                        for comp in context["components"]
                        for row in comp["paths"]
                    ],
                ),
                0.01,
            )
        signal = context["signals"][0]
        candidates = []
        if self.disposition == "boundary":
            candidates.append(
                dict(
                    candidate_key="candidate-request",
                    name="Request interpretation",
                    kind="network",
                    **{"from": signal["from"], "to": "foreign-component" if self.foreign else signal["to"]},
                    assumption="The receiver accepts only the expected request representation.",
                    confidence="inferred",
                    evidence=[
                        dict(repository_id=s["repository_id"], file=s["path"], line=1, sha256=s["sha256"])
                        for s in slices
                    ],
                    covered_signal_ids=[signal["id"]],
                    covered_flow_ids=signal["flow_ids"],
                )
            )
        artifact = dict(
            schema_version=2,
            source_scope_sha256=context["source_scope_sha256"],
            component_inventory_fingerprint=context["component_inventory_fingerprint"],
            assessment_input_fingerprint=context["assessment_input_fingerprint"],
            candidates=candidates,
            dispositions=[
                dict(
                    signal_id=signal["id"],
                    disposition=self.disposition,
                    candidate_keys=[row["candidate_key"] for row in candidates],
                    rationale="The retrieved receiver establishes an input interpretation point."
                    if candidates
                    else "The available implementation does not establish a separate enforcement condition.",
                )
            ],
        )
        return HostReply(dict(action="complete", reads=[], artifact=artifact), 0.01)


@pytest.mark.parametrize("names", [("edge", "service"), ("west", "east")])
def test_controller_accounts_for_crossings_and_namespaces_candidate_keys(tmp_path, names):
    from tests.test_multi_repo_boundaries import crossing_input

    scope, components, receipt, flows, context = crossing_input(tmp_path, names=names)
    inbound = copy.deepcopy(flows["data_flows"][0])
    inbound.update(id="df-002", **{"from": "external", "to": components["components"][0]["id"]})
    inbound.pop("connection_id")
    inbound["evidence"] = [inbound["evidence"][0]]
    flows["data_flows"].append(inbound)
    architecture = dict(components=components, finalization=receipt, data_flows=flows)
    host = BoundaryHost()
    jobs = AssessmentJobs(
        scope,
        scope.output / ".assessment/jobs",
        AssessmentBudget(1, 0.05, 20, 60),
        lambda role, ceiling: host,
        lambda: False,
        lambda: None,
    )
    assessment, candidates = controller._assessment_boundary_candidates(
        scope, jobs, architecture, context, "standard", progress=lambda text: None
    )
    assert len(assessment["signals"]) == len(candidates["dispositions"]) == 2
    assert len({row["candidate_key"] for row in candidates["candidates"]}) == 2
    assert {row["signal_id"] for row in candidates["dispositions"]} == {row["id"] for row in assessment["signals"]}
    calls = host.calls
    assert controller._assessment_boundary_candidates(
        scope, jobs, architecture, context, "standard", progress=lambda text: None
    ) == (assessment, candidates)
    assert host.calls == calls
    from contexts.prepare_trust_boundary_context import promote_assessment_boundaries

    canonical, coverage, warnings = promote_assessment_boundaries(
        scope, components, assessment, candidates, output_dir=scope.output
    )
    assert len(canonical["trust_boundaries"]) == 2
    assert coverage["schema_version"] == 2 and len(coverage["signals"]) == 2
    assert all(row["boundary_ids"] for row in coverage["signals"])
    assert {row["evidence"][0]["repository_id"] for row in coverage["signals"]} <= {
        r.repository_id for r in scope.repositories
    }


@pytest.mark.parametrize("disposition", ["same-trust", "unresolved"])
def test_same_trust_and_unresolved_crossings_do_not_mint_boundary_candidates(tmp_path, disposition):
    from tests.test_multi_repo_boundaries import crossing_input

    scope, components, receipt, flows, context = crossing_input(tmp_path)
    host = BoundaryHost(disposition=disposition)
    jobs = AssessmentJobs(
        scope,
        scope.output / ".assessment/jobs",
        AssessmentBudget(1, 0.05, 10, 60),
        lambda role, ceiling: host,
        lambda: False,
        lambda: None,
    )
    _, candidates = controller._assessment_boundary_candidates(
        scope,
        jobs,
        dict(components=components, finalization=receipt, data_flows=flows),
        context,
        "standard",
        progress=lambda text: None,
    )
    assert candidates["candidates"] == []
    assert candidates["dispositions"][0]["disposition"] == disposition
    from contexts.prepare_trust_boundary_context import promote_assessment_boundaries

    canonical, coverage, _warnings = promote_assessment_boundaries(
        scope, components, _, candidates, output_dir=scope.output
    )
    assert canonical["trust_boundaries"] == []
    assert coverage["signals"][0]["disposition"] == disposition
    assert bool(coverage["issues"]) == (disposition == "unresolved")


def test_boundary_analyst_cannot_select_a_foreign_component(tmp_path):
    from runtime.assessment_host import ExchangeError

    from tests.test_multi_repo_boundaries import crossing_input

    scope, components, receipt, flows, context = crossing_input(tmp_path)
    jobs = AssessmentJobs(
        scope,
        scope.output / ".assessment/jobs",
        AssessmentBudget(1, 0.05, 10, 60),
        lambda role, ceiling: BoundaryHost(foreign=True),
        lambda: False,
        lambda: None,
    )
    with pytest.raises(ExchangeError):
        controller._assessment_boundary_candidates(
            scope,
            jobs,
            dict(components=components, finalization=receipt, data_flows=flows),
            context,
            "standard",
            progress=lambda text: None,
        )
