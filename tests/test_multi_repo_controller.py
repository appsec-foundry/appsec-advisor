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
        # The (repository_id, path, start, end) slices each call's packet carried.
        self.packets = []
        self.systems = []

    def factory(self, role, ceiling):
        owner = self

        class Transport:
            def invoke(self, system, prompt, schema, timeout_s, should_stop):
                owner.systems.append(system)
                return owner.invoke(role, prompt)

        return Transport()

    def invoke(self, role, prompt):
        packet = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
        ctx, slices = packet["context"], packet["source_slices"]
        self.calls.append((role, copy.deepcopy(ctx)))
        self.packets.append([(s["repository_id"], s["path"], s["start_line"], s["end_line"]) for s in slices])
        rid = ctx.get("repository_id")
        # Discovery carries each serving unit by listing its first entry file.
        carried = [
            unit["entry_files"][0]
            for unit in ctx.get("deterministic_inventory", {}).get("serving_units", {}).get("units", [])
        ]
        if role == "recon_scanner":
            allowed = [(rid, "app.py"), *((rid, path) for path in carried)]
        elif "candidate" in ctx:
            allowed = [(p["repository_id"], p["path"]) for c in ctx["components"] for p in c["paths"]]
        else:
            components = ctx.get("components", [ctx.get("component")])
            allowed = [(p["repository_id"], p["path"]) for c in components if c for p in c["paths"]]
            allowed += [(f["evidence"]["repository_id"], f["evidence"]["file"]) for f in ctx.get("findings", [])]
        if not slices:
            targets = ctx.get("investigation_targets", ctx.get("findings", []))
            target_reads = {}
            for target in targets:
                anchor = target["evidence"]
                r, p = anchor["repository_id"], anchor["file"]
                start = max(1, ((anchor.get("line") or 1) // 400) * 400)
                repo = next(repo for repo in self.scope.repositories if repo.repository_id == r)
                target_reads[r, p, start] = dict(
                    repository_id=r,
                    path=p,
                    start_line=start,
                    end_line=min(start + 399, len(repo.files[p].splitlines())),
                )
            return HostReply(
                dict(
                    action="read",
                    artifact=None,
                    reads=[
                        dict(repository_id=r, path=p, start_line=1, end_line=20 if "findings" in ctx else 2)
                        for r, p in sorted(set(allowed))
                    ]
                    if not targets
                    else list(target_reads.values()),
                ),
                0.01,
            )
        evidence = [
            dict(
                repository_id=s["repository_id"],
                file=s["path"],
                line=min(s["start_line"] + 1, s["end_line"]),
                sha256=s["sha256"],
            )
            for s in slices
        ]
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
                        paths=["app.py", *carried],
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
                        evidence=[dict(file="app.py", line=1, quote=slices[0]["lines"][0].split(": ", 1)[1])],
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
                            dict(
                                repository_id=s["repository_id"],
                                file=s["path"],
                                line=1,
                                quote=s["lines"][0].split(": ", 1)[1],
                            )
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
                        steps=[
                            "Validate the accepted input type in the request handler.",
                            "Reject requests that fail validation.",
                        ],
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
                    surface_coverage=[
                        dict(
                            target_id=t["local_id"],
                            disposition="examined",
                            reason="The target implementation was read and investigated.",
                            finding_ids=["issue-1"],
                            evidence=[t["evidence"]],
                        )
                        for t in ctx.get("investigation_targets", [])
                    ],
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
                            local_id=finding["local_id"],
                            verdict="verified",
                            reason="Independent reading confirms the insecure practice at the anchor.",
                            evidence=[{k: finding["evidence"][k] for k in ("repository_id", "file", "line", "sha256")}],
                        )
                        for finding in ctx["findings"]
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


def _inventory_checkouts(tmp_path):
    roots = [tmp_path / "edge", tmp_path / "pay"]
    for root in roots:
        checkout(root)
    (roots[0] / "package.json").write_text(json.dumps({"name": "edge", "dependencies": {"express": "4.18.0"}}))
    (roots[0] / "server.js").write_text(
        "const express = require('express')\nconst app = express()\n"
        "app.get('/records/:id', (req, res) => res.json({}))\napp.listen(8080)\n"
    )
    (roots[1] / "package.json").write_text(json.dumps({"name": "pay", "dependencies": {"axios": "1.6.0"}}))
    (roots[1] / "client.js").write_text(
        "const axios = require('axios')\n"
        "export async function charge(order) { return axios.post('https://api.payments-provider.net/charge', order) }\n"
    )
    return roots


def test_stride_splits_surface_work_without_losing_findings_or_reading_foreign_sources(tmp_path):
    root = tmp_path / "service"
    checkout(root)
    path = root / "app.py"
    # Long lines make seven 400-line target windows exceed one job's preload room.
    path.write_text(path.read_text() + ("value = request.args['input'] + '" + "x" * 60 + "'\n") * 2400)
    peer = tmp_path / "peer"
    checkout(peer)
    scope = admit([str(root), str(peer)], str(tmp_path / "out"))
    host = Host(scope)
    jobs = AssessmentJobs(
        scope,
        scope.output / ".assessment/jobs",
        AssessmentBudget(2, 0.05, 60, 120),
        host.factory,
        lambda: False,
        lambda: None,
    )
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda _: None)
    rid = next(r.repository_id for r in scope.repositories if r.root == root)
    architecture["route_inventories"] = {
        rid: {"routes": [dict(handler_file="app.py", handler_line=line) for line in range(1, 2402, 400)]}
    }
    documents, reviews, merged = controller._assessment_stride(
        scope,
        jobs,
        architecture,
        [],
        [],
        progress=lambda _: None,
        depth="thorough",
    )
    contexts = [
        ctx for role, ctx in host.calls if role == "stride_analyzer" and ctx["component"]["repository_ids"] == [rid]
    ]
    # The controller preloads every target window, so each job completes in one exchange;
    # the job count follows source size, and every target is decided exactly once.
    supplied = [t["local_id"] for ctx in contexts for t in ctx["investigation_targets"]]
    assert len(contexts) > 1 and len(supplied) == len(set(supplied)) == 7
    assert all(ctx["assessment_depth"] == "thorough" for ctx in contexts)
    assert len(documents) == len(reviews) == 2
    document = next(d for d in documents if d["threats"][0]["evidence"]["repository_id"] == rid)
    # Every job's finding survives the combination, anchored in that job's first window.
    first_windows = {
        max(1, min(t["evidence"]["line"] for t in ctx["investigation_targets"]) // 400 * 400) + 1 for ctx in contexts
    }
    assert len(document["threats"]) == len(contexts)
    assert {t["evidence"]["line"] for t in document["threats"]} == first_windows
    # Every finding is reviewed: one per job of this component plus the peer's single finding.
    peer = next(d for d in documents if d is not document)
    assert sum(len(r["decisions"]) for r in reviews) == len(contexts) + len(peer["threats"]) == len(contexts) + 1
    assert all(t["evidence"]["repository_id"] == rid for t in document["threats"])
    assert merged["threats"]


@pytest.mark.parametrize("line", [900, 1500])
def test_only_the_first_job_of_a_split_component_carries_its_context_lines(tmp_path, line):
    """Context-only weaknesses are one job's duty, so later jobs keep their room and do not repeat them."""
    root = tmp_path / "service"
    checkout(root)
    path = root / "app.py"
    path.write_text(path.read_text() + ("value = request.args['input'] + '" + "x" * 60 + "'\n") * 2400)
    peer = tmp_path / "peer"
    checkout(peer)
    scope = admit([str(root), str(peer)], str(tmp_path / "out"))
    host = Host(scope)
    jobs = AssessmentJobs(
        scope,
        scope.output / ".assessment/jobs",
        AssessmentBudget(2, 0.05, 60, 120),
        host.factory,
        lambda: False,
        lambda: None,
    )
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda _: None)
    rid = next(r.repository_id for r in scope.repositories if r.root == root)
    architecture["route_inventories"] = {
        rid: {"routes": [dict(handler_file="app.py", handler_line=n) for n in range(1, 2402, 400)]}
    }
    component = next(c for c in architecture["components"]["components"] if c["repository_ids"] == [rid])
    controls = [
        dict(
            domain="Input Validation",
            control="Request Validation",
            effectiveness="Partial",
            assessment="The handler reads a request parameter directly.",
            component_ids=[component["id"]],
            evidence=[
                dict(repository_id=rid, file="app.py", line=line, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            ],
        )
    ]
    calls = len(host.calls)
    controller._assessment_stride(scope, jobs, architecture, controls, [], progress=lambda _: None)
    stride = [
        (system, slices)
        for (role, ctx), slices, system in zip(host.calls[calls:], host.packets[calls:], host.systems[calls:])
        if role == "stride_analyzer" and ctx["component"]["id"] == component["id"]
    ]
    context_window = (rid, "app.py", line - 10)
    carriers = [index for index, (_, slices) in enumerate(stride) if any(key[:3] == context_window for key in slices)]
    assert len(stride) > 1 and carriers == [0]
    assert f"job 1 of {len(stride)}" in stride[0][0]
    assert all(f"job {n} of {len(stride)}" in system for n, (system, _) in enumerate(stride[1:], 2))
    # A component analyzed in one job is not told about other jobs.
    single = [
        system
        for (role, ctx), system in zip(host.calls[calls:], host.systems[calls:])
        if role == "stride_analyzer" and ctx["component"]["id"] != component["id"]
    ]
    assert single and not any("job 1 of" in system for system in single)


def test_a_job_with_more_preloaded_windows_than_reads_passes_its_receipt(tmp_path):
    """Preloaded windows join the receipt; its contract must admit more ranges than MAX_READS."""
    from runtime.assessment_host import MAX_READS

    root = tmp_path / "service"
    checkout(root)
    path = root / "app.py"
    # Short lines keep twenty-one 400-line windows within one job's preload room.
    path.write_text(path.read_text() + "v = 1\n" * 8000)
    peer = tmp_path / "peer"
    checkout(peer)
    scope = admit([str(root), str(peer)], str(tmp_path / "out"))
    host = Host(scope)
    jobs = AssessmentJobs(
        scope,
        scope.output / ".assessment/jobs",
        AssessmentBudget(2, 0.05, 60, 120),
        host.factory,
        lambda: False,
        lambda: None,
    )
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda _: None)
    rid = next(r.repository_id for r in scope.repositories if r.root == root)
    architecture["route_inventories"] = {
        rid: {"routes": [dict(handler_file="app.py", handler_line=line) for line in range(1, 8002, 400)]}
    }
    controller._assessment_stride(scope, jobs, architecture, [], [], progress=lambda _: None)
    receipts = [json.loads(p.read_text()) for p in (scope.output / ".assessment/jobs").glob("*.receipt.json")]
    stride = [r for r in receipts if r["role"] == "stride_analyzer" and r["source_ranges"][0]["repository_id"] == rid]
    assert max(len(r["source_ranges"]) for r in stride) > MAX_READS


def test_toolless_architect_receives_the_shared_remediation_policy():
    policy = (controller.PLUGIN_ROOT / "agents/shared/architect-semantic-review.md").read_text()
    instructions = controller._assessment_role_instructions("architect_reviewer", "Review the supplied findings.")
    assert policy in instructions
    assert "fix.effect: prevents-mechanism" in instructions


def test_discovery_and_architecture_receive_their_own_repository_inventories(tmp_path):
    roots = _inventory_checkouts(tmp_path)
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
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    rid = {repo.root.name: repo.repository_id for repo in scope.repositories}
    discovery = {
        ctx["repository_id"]: ctx["deterministic_inventory"] for role, ctx in host.calls if role == "recon_scanner"
    }
    local = {
        ctx["repository_id"]: ctx["deterministic_inventory"]
        for role, ctx in host.calls
        if role == "architecture_analyst" and "deterministic_inventory" in ctx
    }
    # Discovery lists every file already; it gets only the small inventories.
    assert all(set(rows) == {"role_units", "egress", "topology", "serving_units"} for rows in discovery.values())
    assert [u["id"] for u in discovery[rid["edge"]]["serving_units"]["units"]] == ["http-api:."]
    assert discovery[rid["pay"]]["serving_units"]["units"] == []
    assert [d["host"] for d in discovery[rid["pay"]]["egress"]["destinations"]] == ["api.payments-provider.net"]
    assert discovery[rid["edge"]]["egress"]["destinations"] == []
    # Each repository's job sees its own routes, repository-relative, never the other's.
    edge_routes = local[rid["edge"]]["route_projection"]["routes"]
    assert [(r["path"], r["handler_file"]) for r in edge_routes] == [("/records/:id", "server.js")]
    assert local[rid["pay"]]["route_projection"]["routes"] == []
    sent = json.dumps([ctx for _, ctx in host.calls])
    assert str(tmp_path) not in sent and '"match"' not in sent and "generated_at" not in sent
    assert set(architecture["route_inventories"]) == set(rid.values())


def test_architecture_receives_model_integration_leads_and_reports_unmodelled_ones(tmp_path):
    roots = _inventory_checkouts(tmp_path)
    with (roots[1] / "app.py").open("a") as handle:
        handle.write("from anthropic import Anthropic\nclient = Anthropic()\n")
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
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    rid = {repo.root.name: repo.repository_id for repo in scope.repositories}
    leads = {
        ctx["repository_id"]: ctx["deterministic_inventory"]["model_integrations"]
        for role, ctx in host.calls
        if role == "architecture_analyst" and "deterministic_inventory" in ctx
    }
    assert leads[rid["edge"]] == []
    # The lead names the call (line 4), never the import the evidence rule rejects (line 3).
    assert [row["evidence"] for row in leads[rid["pay"]]] == [[{"file": "app.py", "line": 4}]]
    # The test host models no inference service, so the lead stays a reported gap.
    assert architecture["model_integration_gaps"] == ["Service"]


def test_inventories_at_their_bounds_leave_most_of_the_context_for_source(tmp_path):
    from runtime.assessment_host import MAX_CONTEXT_BYTES

    roots = _inventory_checkouts(tmp_path)
    segment = "/".join(f"segment{j:02d}" for j in range(60))
    (roots[0] / "server.js").write_text(
        "const express = require('express')\nconst app = express()\n"
        + "".join(f"app.post('/{segment}/{i}/:id', (req, res) => res.json({{}}))\n" for i in range(400))
    )
    scope = admit([str(r) for r in roots], str(tmp_path / "out"))
    inventories = controller._assessment_inventories(scope)
    edge = inventories[next(repo.repository_id for repo in scope.repositories if repo.root.name == "edge")]
    sent = {key: edge[key] for key in ("route_projection", "role_units", "egress", "topology")}
    assert all(len(r["path"]) <= 180 for r in edge["route_projection"]["routes"])
    assert len(json.dumps(sent).encode()) <= MAX_CONTEXT_BYTES // 4


def test_render_tail_gives_actor_resolution_the_source_auth_evidence(tmp_path, monkeypatch):
    """Registration evidence must exist before posture and actor resolution read it."""
    from orchestrator import assessment_declarations

    calls = []
    monkeypatch.setattr(controller, "_run_script", lambda name, args, **_: calls.append((name, list(args))))

    class Stop(Exception):
        pass

    def stop(*args, **kwargs):
        raise Stop

    monkeypatch.setattr(assessment_declarations, "related_register", stop)
    workspace, root = tmp_path / "workspace", tmp_path / "root"
    with pytest.raises(Stop):
        controller._assessment_render(None, None, None, {}, workspace, root, captured=None, progress=lambda text: None)
    names = [name for name, _ in calls]
    assert names.index("analyzers/route_inventory.py") < names.index("analyzers/source_auth_scanner.py")
    args = dict(zip(*[iter(calls[names.index("analyzers/source_auth_scanner.py")][1][:4])] * 2))
    assert args == {"--repo-root": str(root), "--output-dir": str(workspace)}


def test_scanner_findings_reach_the_merge_through_independent_review(tmp_path):
    roots = [tmp_path / name for name in ("caller", "receiver")]
    for root in roots:
        checkout(root)
    tool = roots[1] / "lib/tool.py"
    tool.parent.mkdir()
    tool.write_text(
        "import subprocess\nfrom flask import request\n\ndef run():\n"
        '    name = request.args["name"]\n    return subprocess.call("ls " + name, shell=True)\n'
    )
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
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    controls = controller._assessment_controls(scope, jobs, architecture, progress=lambda text: None)
    _, reviews, merged = controller._assessment_stride(
        scope, jobs, architecture, controls, [], progress=lambda text: None
    )
    receiver = next(r.repository_id for r in scope.repositories if r.root.name == "receiver")
    [scanned] = [t for t in merged["threats"] if t["source"] == "source-scan"]
    assert scanned["evidence"]["repository_id"] == receiver
    assert scanned["evidence"]["file"] == "lib/tool.py"
    assert scanned["evidence_check"] == "verified"
    reviewed = [row["local_id"] for review in reviews for row in review["decisions"]]
    assert reviewed.count("deterministic-scan-001") == 1


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


def test_a_runtime_change_during_the_session_is_disclosed_not_fatal(tmp_path, monkeypatch):
    for name in ("caller", "receiver"):
        checkout(tmp_path / name)
    scope = admit([str(tmp_path / name) for name in ("caller", "receiver")], str(tmp_path / "out"))
    current = ["a" * 64]
    monkeypatch.setattr(controller, "_assessment_runtime_fingerprint", lambda: current[0])
    with controller._assessment_session(
        scope, ["--no-requirements"], budget=AssessmentBudget(1, 0.05, 10, 60), host_factory=lambda *args: None
    ) as (_, state, _):
        assert controller._assessment_runtime_warning(state) is None
        current[0] = "b" * 64
        assert "--rebuild" in controller._assessment_runtime_warning(state)
    assert json.loads((scope.output / ".assessment-state.json").read_text())["status"] != "failed"


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


def test_each_model_call_reports_progress_without_echoing_model_text(monkeypatch):
    import time as clock

    from orchestrator.orchestration_controller import _ReportedTransport
    from runtime.analyst_host import HostReply, HostTimeout

    class Inner:
        on_event = None

        def __init__(self, replies):
            self.replies = iter(replies)

        def invoke(self, *args):
            reply = next(self.replies)
            if isinstance(reply, Exception):
                raise reply
            for event in reply.payload.pop("events", []):
                self.on_event(event)
                clock.sleep(0.15)
            return reply

    lines = []
    monkeypatch.setattr(_ReportedTransport, "HEARTBEAT_SECONDS", 0.1)
    thinking = {"type": "system", "subtype": "thinking_tokens", "estimated_tokens": 4800}
    writing = {"type": "stream_event", "event": {"delta": {"partial_json": '{"threats": [\x1b[2J injected'}}}
    reads = [{"repository_id": "repo-1", "path": "app.py\x1b", "start_line": 1, "end_line": 159}]
    inner = Inner(
        [
            HostReply({"action": "read", "reads": reads, "artifact": None}, 0.01),
            HostReply(
                {"action": "complete", "reads": [], "artifact": {"threats": [{}] * 9}, "events": [thinking, writing]},
                0.21,
            ),
            HostTimeout("host call exceeded its time limit"),
        ]
    )
    running = {}
    transport = _ReportedTransport(inner, lines.append, {"repo-1": "user-service"}, running, "STRIDE")
    transport.invoke("s", "p", {}, 30, lambda: False)
    # A finished call leaves the console's registry of calls in flight.
    assert running == {}
    transport.invoke("s", "p", {}, 30, lambda: False)
    with pytest.raises(HostTimeout):
        transport.invoke("s", "p", {}, 30, lambda: False)
    assert lines[0].startswith("reads user-service/app.py?:1-159 (") and lines[0].endswith(" s)")
    assert any(line.endswith("model is thinking (~4,800 tokens)") for line in lines)
    assert any("model is writing its result (~" in line for line in lines)
    assert any(line.startswith("result: 9 threats (") and line.endswith(" s)") for line in lines)
    # Cost is reported only at the end of the run, never per call.
    assert not any("$" in line for line in lines)
    assert lines[-1].startswith("model call stopped after") and lines[-1].endswith("its time limit")
    assert not any("injected" in line or "\x1b" in line for line in lines)


def test_a_silent_model_call_is_reported_as_waiting_for_the_api(monkeypatch):
    import time as clock

    from orchestrator.orchestration_controller import _ReportedTransport
    from runtime.analyst_host import HostReply

    class Silent:
        on_event = None

        def invoke(self, *args):
            clock.sleep(0.35)
            return HostReply({"action": "complete", "reads": [], "artifact": {}}, None)

    lines = []
    monkeypatch.setattr(_ReportedTransport, "HEARTBEAT_SECONDS", 0.1)
    monkeypatch.setattr(_ReportedTransport, "SILENT_SECONDS", 0)
    _ReportedTransport(Silent(), lines.append).invoke("s", "p", {}, 30, lambda: False)
    assert any("no model activity for" in line and "(waiting for the API)" in line for line in lines)


def test_each_cli_host_call_records_its_events_in_its_own_file(tmp_path):
    from orchestrator.orchestration_controller import _assessment_cli_host_factory

    factory = _assessment_cli_host_factory(tmp_path / "hosts", tmp_path / "events")
    (tmp_path / "hosts").mkdir()
    first, second = factory("stride_analyzer", "sonnet", 1.0), factory("control_analyst", "sonnet", 1.0)
    assert first.events_path == tmp_path / "events" / "0001-stride_analyzer.jsonl"
    assert second.events_path == tmp_path / "events" / "0002-control_analyst.jsonl"
    assert first.max_thinking_tokens == 20_000
    unrecorded = _assessment_cli_host_factory(tmp_path / "hosts")("x", "sonnet", 1.0)
    assert unrecorded.events_path is None and unrecorded.max_thinking_tokens is None


def test_controller_host_calls_write_the_short_lived_prompt_cache(tmp_path, monkeypatch):
    """MD-11: a unique exchange prompt is not paid at the one-hour cache-write rate."""
    from orchestrator.orchestration_controller import _assessment_cli_host_factory
    from runtime.analyst_host import ClaudeCliTransport

    monkeypatch.delenv("FORCE_PROMPT_CACHING_5M", raising=False)
    (tmp_path / "hosts").mkdir()
    for events in (tmp_path / "events", None):
        transport = _assessment_cli_host_factory(tmp_path / "hosts", events)("stride_analyzer", "sonnet", 1.0)
        assert transport.environment()["FORCE_PROMPT_CACHING_5M"] == "1"
    # Other hosts keep the login's default TTL.
    assert "FORCE_PROMPT_CACHING_5M" not in ClaudeCliTransport(tmp_path / "work").environment()


class _MergerJobs:
    """Answers each merger exchange with one decision per supplied group, as the merger would."""

    def __init__(self, action="keep", reply=None):
        self.action, self.reply, self.requests = action, reply, []

    def execute(self, **request):
        self.requests.append(request)
        groups = request["context"]["candidate_groups"]
        decisions = [
            {"group_id": group["group_id"], "action": self.action, "member_indices": [0, 1], "rationale": "Same sink."}
            | ({"merge_target_index": 0} if self.action == "merge" else {})
            for group in groups
        ]
        artifact = self.reply or {"version": 2, "generated_at": "now", "model": "test", "decisions": decisions}
        request["validate"](artifact, [])
        return artifact


def _merge_groups(count):
    member = {"component_id": "edge", "title": "Unvalidated input"}
    return [
        {"group_id": f"G-{index:08x}", "member_count": 2, "members": [member, dict(member)]} for index in range(count)
    ]


@pytest.mark.parametrize("count, exchanges", [(1, 1), (controller.MERGE_REVIEW_GROUPS + 1, 2)])
def test_merge_review_decides_every_group_in_bounded_tool_less_exchanges(count, exchanges):
    jobs = _MergerJobs(action="merge")
    progress = []
    decisions = controller._assessment_merge_review(jobs, "verified", _merge_groups(count), progress=progress.append)
    assert len(jobs.requests) == exchanges
    assert all(r["role"] == "threat_merger" and r["allowed_sources"] == frozenset() for r in jobs.requests)
    assert sorted(d["group_id"] for d in decisions) == [g["group_id"] for g in _merge_groups(count)]
    assert all(line.startswith("Reviewing merge candidates (verified,") for line in progress)


def test_merge_review_rejects_a_decision_set_that_omits_a_group():
    """The rejection is a correction the exchange returns to the merger, not the end of the run."""
    from runtime.assessment_host import Rejection

    reply = {"version": 2, "generated_at": "now", "model": "test", "decisions": []}
    with pytest.raises(Rejection, match="omits candidate groups") as raised:
        controller._assessment_merge_review(_MergerJobs(reply=reply), "verified", _merge_groups(2), progress=print)
    assert isinstance(raised.value, ValueError)


@pytest.mark.parametrize(
    "asset, name, description",
    [
        ({"name": "Customer order history", "description": None}, "Customer order history", "Customer order history."),
        ({"name": "Signing keys", "description": "  "}, "Signing keys", "Signing keys."),
        (
            {"name": "Payment " + "authorization records of every merchant account " * 3, "description": "Kept."},
            None,
            "Kept.",
        ),
        ({"name": "Session tokens", "description": "Bearer tokens."}, "Session tokens", "Bearer tokens."),
    ],
)
def test_architecture_assets_fit_the_legacy_asset_fragment(asset, name, description):
    fitted = controller._assessment_asset_fields(dict(asset, id="asset-a", classification="Internal"))
    assert len(fitted["name"]) <= controller.ASSET_NAME_CHARS
    assert fitted["name"] == (name or fitted["name"]) and not fitted["name"].endswith(" of")
    assert fitted["description"] == description


@pytest.mark.parametrize("repositories, keep, kept", [(1, False, True), (2, False, False), (2, True, True)])
def test_a_sole_repository_keeps_its_run_files(tmp_path, repositories, keep, kept):
    workspace = tmp_path / "render"
    workspace.mkdir()
    (workspace / ".threats-merged.json").write_text("{}", encoding="utf-8")
    controller._assessment_discard_workspace(workspace, repositories, {"keep_runtime_files": keep})
    assert workspace.is_dir() is kept


def test_an_interrupted_assessment_exits_without_a_traceback(monkeypatch, capsys):
    def interrupted(argv):
        raise KeyboardInterrupt

    monkeypatch.setattr(controller, "assess_repositories", interrupted)
    assert controller.assess_main(["--repo", "x", "--output", "y"]) == 130
    captured = capsys.readouterr()
    assert "✗ assessment interrupted" in captured.err and "Traceback" not in captured.err


@pytest.mark.parametrize("names", [("edge", "service"), ("west", "east")])
def test_boundary_jobs_answer_from_their_preloaded_cited_source(tmp_path, names):
    """A crossing's cited source reaches the first packet, so no call only requests it."""
    from tests.test_multi_repo_boundaries import crossing_input

    scope, components, receipt, flows, context = crossing_input(tmp_path, names=names)
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
    assert assessment["signals"] and host.calls == len(assessment["signals"])
    assert len(candidates["dispositions"]) == len(assessment["signals"])


@pytest.mark.parametrize("line", [900, 1500])
def test_stride_and_review_jobs_receive_the_source_their_context_cites(tmp_path, line):
    """A cited control line and every finding anchor arrive with the first packet, never through a read-only call."""
    roots = [tmp_path / "edge", tmp_path / "service"]
    for root in roots:
        checkout(root)
    path = roots[1] / "app.py"
    path.write_text(path.read_text() + "value = request.args['input']\n" * 1600)
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
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    rid = next(r.repository_id for r in scope.repositories if r.root == roots[1])
    component = next(c for c in architecture["components"]["components"] if c["repository_ids"] == [rid])
    # A control cites a line far from every investigation target window.
    controls = [
        dict(
            domain="Input Validation",
            control="Request Validation",
            effectiveness="Partial",
            assessment="The handler reads a request parameter directly.",
            component_ids=[component["id"]],
            evidence=[
                dict(repository_id=rid, file="app.py", line=line, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            ],
        )
    ]
    calls = len(host.calls)
    controller._assessment_stride(scope, jobs, architecture, controls, [], progress=lambda text: None)
    packets = list(zip(host.calls[calls:], host.packets[calls:]))
    stride = [
        slices
        for (role, ctx), slices in packets
        if role == "stride_analyzer" and ctx["component"]["id"] == component["id"]
    ]
    assert stride and all(any(key[:2] == (rid, "app.py") and key[2] <= line <= key[3] for key in s) for s in stride)
    reviews = [slices for (role, _), slices in packets if role == "evidence_verifier"]
    assert reviews and all(reviews)


def test_control_and_stride_contexts_omit_path_hashes_and_controls_answer_in_one_call(tmp_path):
    roots = [tmp_path / "edge", tmp_path / "service"]
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
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    controls = controller._assessment_controls(scope, jobs, architecture, progress=lambda text: None)
    controller._assessment_stride(scope, jobs, architecture, controls, [], progress=lambda text: None)
    roles = [role for role, _ in host.calls]
    assert roles.count("control_analyst") == len(architecture["components"]["components"])
    model_components = [
        component
        for role, ctx in host.calls
        if role in ("control_analyst", "stride_analyzer", "evidence_verifier")
        for component in [ctx["component"], *ctx.get("incident_components", [])]
    ]
    assert model_components and all("sha256" not in row for c in model_components for row in c["paths"])
    # Acceptance still sees the full inventory: the controller's own components keep their hashes.
    assert all(row["sha256"] for c in architecture["components"]["components"] for row in c["paths"])
