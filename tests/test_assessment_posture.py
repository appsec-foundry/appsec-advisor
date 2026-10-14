"""Posture sidecars and actors of a combined assessment keep each repository's paths apart."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from analyzers import deployment_inventory
from analyzers.route_inventory import build_inventory
from jsonschema import Draft202012Validator
from model import assessment_posture
from orchestrator.assessment_workspace import Namespaces, combined_root, project_components
from runtime.analyst_host import HostReply
from runtime.assessment_host import MARKER
from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
from validators.validate_intermediate import (
    validate_actors_discovered,
    validate_actors_resolved,
    validate_config_scan_findings,
)

from tests.test_multi_repo_boundaries import fixture

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = 'FROM node:latest\nCOPY . .\nRUN npm install\nCMD ["node", "app.js"]\n'
COMPOSE = "services:\n  api:\n    image: api:latest\n    networks: [backend]\nnetworks:\n  backend: {}\n"
PACKAGE = '{"name": "neutral", "dependencies": {"request": "2.88.0"}}\n'
ROUTE = "const express = require('express');\nconst app = express();\napp.get('/records/:id', (req, res) => res.send(req.params.id));\n"


def by_label(scope):
    return {repo.root.name: repo for repo in scope.repositories}


def schema(name):
    return Draft202012Validator(json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8")))


def prepare(tmp_path, files, names=("edge", "service")):
    scope, components, _ = fixture(tmp_path, names=names, files=files)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return scope, components, Namespaces(scope), workspace


def seed(workspace, root, names, components, controls=()):
    document = {"schema_version": 1, "security_controls": list(controls)}
    (workspace / ".security-controls.json").write_text(json.dumps(document))
    (workspace / ".route-inventory.json").write_text(json.dumps(build_inventory(root)))
    (workspace / ".components.json").write_text(json.dumps(project_components(components, names)))
    (workspace / ".data-flows.json").write_text(json.dumps({"schema_version": 1, "data_flows": []}))


def run(scope, names, workspace, components, depth="standard", controls=()):
    with combined_root(scope, names) as root:
        seed(workspace, root, names, components, controls)
        cfg = {"repo_root": str(root), "assessment_depth": depth}
        return assessment_posture.run(scope, names, workspace, cfg), cfg


def read(workspace, name):
    return json.loads((workspace / name).read_text(encoding="utf-8"))


def files_of(value):
    if isinstance(value, dict):
        if isinstance(value.get("file"), str):
            yield value["file"]
        for child in value.values():
            yield from files_of(child)
    elif isinstance(value, list):
        for child in value:
            yield from files_of(child)


def assert_captured(scope, names, value):
    repos = {repo.repository_id: repo for repo in scope.repositories}
    located = list(files_of(value))
    for location in located:
        rid, path = names.split(location)
        assert path in repos[rid].files, location
    return located


@pytest.mark.parametrize(
    ("labels", "paths"),
    [
        (("edge", "service"), ("Dockerfile", "docker-compose.yml")),
        (("north", "south"), ("deploy/Dockerfile", "docker-compose.yaml")),
    ],
)
def test_sidecars_are_valid_and_every_path_resolves_to_its_repository(tmp_path, labels, paths):
    files = {labels[0]: {paths[0]: DOCKERFILE, "package.json": PACKAGE}, labels[1]: {paths[1]: COMPOSE}}
    scope, components, names, workspace = prepare(tmp_path, files, labels)
    receipts, _ = run(scope, names, workspace, components)

    coverage = read(workspace, ".architecture-coverage.json")
    assert schema("architecture-coverage.schema.json").is_valid(coverage)
    assert_captured(scope, names, coverage)
    hypotheses = [row["hypothesis_id"] for row in coverage["threat_hypotheses"]]
    assert len(hypotheses) == len(set(hypotheses))

    config = read(workspace, ".config-scan-findings.json")
    assert validate_config_scan_findings(config)[0]
    located = [row["file"] for row in config["findings"] if row.get("evidence_kind") != "absence"]
    assert located and set(located) == {f"{labels[0]}/{paths[0]}"}

    inventory = read(workspace, ".deployment-inventory.json")
    assert deployment_inventory.validation_errors(inventory) == []
    assert inventory["runtime"]["dockerfile"] == f"{labels[0]}/{paths[0]}"
    assert inventory["compose"]["file"] == f"{labels[1]}/{paths[1]}"
    assert inventory["compose"]["networks"] == [f"{labels[1]}/backend"]

    controls = read(workspace, ".security-controls.json")
    assert schema("fragments/security-controls.schema.json").is_valid(controls)
    assert {row["control"].rsplit(" (", 1)[1] for row in controls["security_controls"]} == {
        f"{label})" for label in labels
    }
    assert_captured(scope, names, controls)
    [library] = read(workspace, ".known-bad-libs-findings.json")["findings"]
    assert library["evidence"] == [{"file": f"{labels[0]}/package.json", "line": 1}]
    assert_captured(scope, names, read(workspace, ".sca-practice-findings.json"))

    activity = read(workspace, ".dep-update-activity.json")
    assert activity["cadence"] == "unknown" and activity["manifests_seen"] == [f"{labels[0]}/package.json"]
    assert validate_actors_resolved(read(workspace, ".actors-resolved.json"))[0]
    assert any("Git history is not read" in row for row in receipts)


def test_equal_relative_paths_in_two_repositories_stay_distinct(tmp_path):
    files = {name: {"Dockerfile": DOCKERFILE, "package.json": PACKAGE} for name in ("edge", "service")}
    scope, components, names, workspace = prepare(tmp_path, files)
    receipts, _ = run(scope, names, workspace, components)
    located = {row["file"] for row in read(workspace, ".config-scan-findings.json")["findings"]}
    assert {"edge/Dockerfile", "service/Dockerfile"} <= located
    # One figure cannot show two runtimes; the omission is receipted.
    assert read(workspace, ".deployment-inventory.json")["runtime"] is None
    assert any("2 repositories declare a runtime" in row for row in receipts)
    [library] = read(workspace, ".known-bad-libs-findings.json")["findings"]
    assert sorted(row["file"] for row in library["evidence"]) == ["edge/package.json", "service/package.json"]


def test_a_model_control_that_covers_a_theme_receives_its_checks_instead_of_a_row(tmp_path):
    scope, components, names, workspace = prepare(tmp_path, {"edge": {"Dockerfile": DOCKERFILE}})
    control = {"domain": "Supply Chain", "control": "Base Image Pinning", "effectiveness": "Weak"}
    run(scope, names, workspace, components, controls=[control])
    rows = read(workspace, ".security-controls.json")["security_controls"]
    assert rows[0] == {**control, "linked_checks": ["IAC-001"]}
    titles = {sub["title"] for row in rows[1:] for sub in row["subcontrols"]}
    assert "Base image pinning" not in titles


def test_repositories_without_iac_yield_a_valid_status_and_no_config_findings(tmp_path):
    scope, components, names, workspace = prepare(tmp_path, {"edge": {"lib/tool.py": "VALUE = 1\n"}})
    receipts, _ = run(scope, names, workspace, components)
    config = read(workspace, ".config-scan-findings.json")
    assert config == assessment_posture.NO_IAC_STUB and validate_config_scan_findings(config)[0]
    assert sum("no IaC surface" in row for row in receipts) == 2
    assert deployment_inventory.validation_errors(read(workspace, ".deployment-inventory.json")) == []


def test_thorough_depth_evaluates_database_separation_per_repository(tmp_path, monkeypatch):
    scope, components, names, workspace = prepare(tmp_path, {})
    calls = []
    original = assessment_posture.database_privilege_separation._main
    monkeypatch.setattr(
        assessment_posture.database_privilege_separation, "_main", lambda argv: calls.append(argv) or original(argv)
    )
    run(scope, names, workspace, components, depth="thorough")
    assert len(calls) == 2
    run(scope, names, workspace, components, depth="standard")
    assert len(calls) == 2


def test_an_unreadable_repository_actor_configuration_stops_the_assessment(tmp_path):
    files = {"edge": {".appsec/actors.yaml": "actors: [unclosed\n"}}
    scope, components, names, workspace = prepare(tmp_path, files)
    with pytest.raises(ValueError):
        run(scope, names, workspace, components)


def test_a_failed_producer_stops_the_assessment(tmp_path, monkeypatch):
    scope, components, names, workspace = prepare(tmp_path, {})
    monkeypatch.setattr(assessment_posture.emit_known_bad_libs, "run", lambda *args: 2)
    with pytest.raises(ValueError, match="known-bad-library producer failed"):
        run(scope, names, workspace, components)


class Discoverer:
    """Read every authorized source, then answer with evidence at ``line``."""

    def __init__(self, line=1):
        self.line = line
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
        self.calls.append((role, ctx))
        if not slices:
            reads = sorted({(p["repository_id"], p["path"]) for c in ctx["components"] for p in c["paths"]})
            return HostReply(
                dict(
                    action="read",
                    artifact=None,
                    reads=[dict(repository_id=r, path=p, start_line=1, end_line=2) for r, p in reads],
                ),
                0.01,
            )
        evidence = [
            dict(repository_id=s["repository_id"], file=s["path"], line=self.line, sha256=s["sha256"]) for s in slices
        ]
        artifact = dict(
            schema_version=1,
            confirmed_relevant=[
                dict(
                    id=ctx["active_static_actors"][0]["id"],
                    label=ctx["active_static_actors"][0]["label"],
                    relevance_evidence="The request handler is reachable without credentials.",
                    confidence="high",
                    evidence=evidence[:1],
                )
            ],
            proposed_additional=[
                dict(
                    id="ACT-X-1",
                    label="partner-integration-client",
                    access=["partner-network"],
                    trust_positions=["partner-api-credential"],
                    distinct_trust_positions=["partner-api-credential"],
                    distinct_trust_position_evidence="A partner credential grants an authority no static actor holds.",
                    capabilities=dict(
                        sophistication="medium", tooling=["http-client"], dwell_time="weeks", surface_reach=["internet"]
                    ),
                    motivation="financial",
                    rationale="A partner credential holder calls the request handler of both repositories.",
                    confidence="high",
                    discovery_method="heuristic-section-A",
                    evidence=evidence,
                )
            ],
            inputs_questioned=[],
            coverage_rationale="Static actors cover the anonymous request surface.",
        )
        return HostReply(dict(action="complete", reads=[], artifact=artifact), 0.01)


def discover(tmp_path, host, depth="standard"):
    scope, components, names, workspace = prepare(tmp_path, {"edge": {"src/server.js": ROUTE}})
    jobs = AssessmentJobs(
        scope, tmp_path / "jobs", AssessmentBudget(2, 0.05, 60, 120), host.factory, lambda: False, lambda: None
    )
    with combined_root(scope, names) as root:
        seed(workspace, root, names, components)
        cfg = {"repo_root": str(root), "assessment_depth": depth}
        assessment_posture.run(scope, names, workspace, cfg)
        receipts = assessment_posture.discover_actors(
            scope, jobs, names, workspace, cfg, lambda role, text: f"{role}: {text}"
        )
    return scope, names, workspace, receipts


def test_actor_discovery_cites_retrieved_sources_and_reaches_the_resolver(tmp_path):
    host = Discoverer()
    scope, names, workspace, receipts = discover(tmp_path, host)
    assert [role for role, _ in host.calls] == ["actor_discoverer", "actor_discoverer"]
    # Bounded cards only: no source text reaches the job outside its reads.
    context = host.calls[0][1]
    assert set(context) == {"active_static_actors", "components", "external_entities", "data_flows", "routes"}
    [route] = context["routes"]
    assert route["evidence"][0]["repository_id"] == by_label(scope)["edge"].repository_id
    assert route["evidence"][0]["file"] == "src/server.js"
    discovered = read(workspace, ".actors-discovered.json")
    assert validate_actors_discovered(discovered)[0]
    text = discovered["proposed_additional"][0]["distinct_trust_position_evidence"]
    assert "edge/app.py:1" in text and "service/app.py:1" in text
    resolved = read(workspace, ".actors-resolved.json")
    assert validate_actors_resolved(resolved)[0]
    assert "ACT-X-1" in {row["id"] for row in resolved["resolved_actors"]} | {
        row["id"] for row in resolved["rejected_discovery_actors"]
    }
    assert receipts == ["actor discovery: 1 proposed, 1 confirmed"]


def test_actor_discovery_rejects_evidence_it_did_not_retrieve(tmp_path):
    # The unretrieved evidence is never accepted; after STRIDE the failed job is replaced (OR-39).
    _, _, workspace, receipts = discover(tmp_path, Discoverer(line=3))
    assert receipts == ["actor discovery unavailable: the model job failed; deterministic actors kept"]
    assert not (workspace / ".actors-discovered.json").exists()


def test_quick_depth_skips_actor_discovery(tmp_path):
    host = Discoverer()
    _, _, workspace, receipts = discover(tmp_path, host, depth="quick")
    assert host.calls == [] and receipts == ["actor discovery skipped: quick depth"]
    assert read(workspace, ".actors-resolved.json")["quick_mode"] is True


@pytest.mark.parametrize(("labels", "named"), [(("solo",), False), (("edge", "service"), True)])
def test_posture_names_a_repository_only_when_several_are_selected(tmp_path, labels, named):
    from runtime.multi_repo_scope import admit

    from tests.test_multi_repo_controller import checkout

    for label in labels:
        checkout(tmp_path / label)
    scope = admit([str(tmp_path / label) for label in labels], str(tmp_path / "out"), minimum=1)
    names = Namespaces(scope)
    repo = assessment_posture._Repo(scope.repositories[0], names)
    label = repo.label
    document = {"topology": {"zones": [{"name": "backend"}], "workloads": [{"zones": ["backend"]}]}}
    zoned = assessment_posture._zones(document, None if names.single else label)
    assert zoned["topology"]["zones"][0]["name"] == (f"{label}/backend" if named else "backend")
    assert repo.text("see app.py:1", {("app.py", 1)}) == (f"see {label}/app.py:1" if named else "see app.py:1")
    row = assessment_posture._sca_row(repo, {"control": "Dependency pinning", "evidence": []})
    assert row["control"] == (f"Dependency pinning ({label})" if named else "Dependency pinning")
