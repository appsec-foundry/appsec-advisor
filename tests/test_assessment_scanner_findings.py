"""Deterministic scanner findings keep their repository, hash and local owner."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from model import assessment_scanner_findings
from model.assessment_scanner_findings import scan

from tests.test_multi_repo_boundaries import fixture

JWT = 'const jwt = require("jsonwebtoken");\nfunction read(token) {\n  return jwt.decode(token);\n}\n'
SHELL = (
    "import subprocess\nfrom flask import request\n\ndef run():\n"
    '    name = request.args["name"]\n    return subprocess.call("ls " + name, shell=True)\n'
)


def by_label(scope):
    return {repo.root.name: repo for repo in scope.repositories}


@pytest.mark.parametrize(
    ("names", "paths"),
    [(("edge", "service"), ("src/token.js", "lib/tool.py")), (("north", "south"), ("web/auth.js", "jobs/run.py"))],
)
def test_findings_are_qualified_and_owned_inside_their_repository(tmp_path, names, paths):
    files = {names[0]: {paths[0]: JWT}, names[1]: {paths[1]: SHELL}}
    scope, components, _ = fixture(tmp_path, names=names, files=files)
    repos = by_label(scope)
    owner = {row["repository_ids"][0]: row["id"] for row in components["components"]}
    result = scan(scope, components)
    assert set(result) == set(owner.values())
    for name, path in zip(names, paths, strict=True):
        repo = repos[name]
        [threat] = result[owner[repo.repository_id]]
        assert threat["source"] == "source-scan"
        assert threat["component_id"] == owner[repo.repository_id]
        assert threat["local_id"] == "deterministic-scan-001"
        assert threat["evidence"] == {
            "repository_id": repo.repository_id,
            "file": path,
            "line": threat["evidence"]["line"],
            "sha256": hashlib.sha256(repo.files[path]).hexdigest(),
        }
        assert threat["evidence"]["line"] >= 1


def test_the_most_specific_component_of_the_same_repository_owns_a_finding(tmp_path):
    scope, components, _ = fixture(tmp_path, files={"edge": {"src/token.js": JWT}})
    repo = by_label(scope)["edge"]
    sha = hashlib.sha256(repo.files["src/token.js"]).hexdigest()
    components["components"].append(
        dict(
            id="component-token",
            name="Token reader",
            description="Token handling module.",
            tier="application",
            repository_ids=[repo.repository_id],
            paths=[dict(repository_id=repo.repository_id, path="src/token.js", sha256=sha)],
        )
    )
    result = scan(scope, components)
    assert [t["evidence"]["file"] for t in result["component-token"]] == ["src/token.js"]
    assert sum(map(len, result.values())) == 1


def test_equal_relative_paths_in_two_repositories_stay_two_findings(tmp_path):
    scope, components, _ = fixture(tmp_path, files={"edge": {"lib/tool.py": SHELL}, "service": {"lib/tool.py": SHELL}})
    threats = [t for rows in scan(scope, components).values() for t in rows]
    assert len(threats) == 2
    assert {t["evidence"]["repository_id"] for t in threats} == {r.repository_id for r in scope.repositories}


def test_repositories_without_scanner_findings_yield_empty_owners(tmp_path):
    scope, components, _ = fixture(tmp_path)
    assert scan(scope, components) == {row["id"]: [] for row in components["components"]}


def test_a_failed_scanner_stops_the_assessment(tmp_path, monkeypatch):
    scope, components, _ = fixture(tmp_path)
    monkeypatch.setattr(assessment_scanner_findings.mass_assignment_scanner, "main", lambda argv: 2)
    with pytest.raises(ValueError, match="scanner failed"):
        scan(scope, components)


def test_an_error_stub_cannot_stand_in_for_a_scan(tmp_path, monkeypatch):
    scope, components, _ = fixture(tmp_path)

    def stub(argv):
        output = Path(argv[argv.index("--output-dir") + 1])
        (output / ".source-auth-findings.json").write_text(json.dumps({"parse_error": "boom", "findings": []}))
        return 0

    monkeypatch.setattr(assessment_scanner_findings.source_auth_scanner, "main", stub)
    with pytest.raises(ValueError, match="invalid sidecar"):
        scan(scope, components)


DOCKERFILE = 'FROM node:latest\nCOPY . .\nRUN npm install\nCMD ["node", "app.js"]\n'


@pytest.mark.parametrize(
    ("names", "path"), [(("edge", "service"), "Dockerfile"), (("north", "south"), "deploy/Dockerfile")]
)
def test_config_findings_with_a_source_line_are_qualified_and_owned(tmp_path, names, path):
    scope, components, _ = fixture(tmp_path, names=names, files={names[0]: {path: DOCKERFILE}})
    repo = by_label(scope)[names[0]]
    owner = {row["repository_ids"][0]: row["id"] for row in components["components"]}
    threats = [t for t in scan(scope, components)[owner[repo.repository_id]] if t["source"] == "config-scan"]
    assert threats
    for threat in threats:
        assert threat["component_id"] == owner[repo.repository_id]
        assert threat["evidence"]["repository_id"] == repo.repository_id
        assert threat["evidence"]["file"] == path and threat["evidence"]["line"] >= 1
        assert threat["evidence"]["sha256"] == hashlib.sha256(repo.files[path]).hexdigest()
        assert threat["local_id"].startswith("deterministic-scan-")


def test_equal_config_paths_in_two_repositories_stay_distinct(tmp_path):
    files = {"edge": {"Dockerfile": DOCKERFILE}, "service": {"Dockerfile": DOCKERFILE}}
    scope, components, _ = fixture(tmp_path, files=files)
    threats = [t for rows in scan(scope, components).values() for t in rows if t["source"] == "config-scan"]
    by_repository = {}
    for threat in threats:
        by_repository.setdefault(threat["evidence"]["repository_id"], set()).add(threat["config_check_id"])
    assert set(by_repository) == {r.repository_id for r in scope.repositories}
    assert by_repository[scope.repositories[0].repository_id] == by_repository[scope.repositories[1].repository_id]


def test_a_repository_without_iac_yields_no_config_findings(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(assessment_scanner_findings.config_iac_scanner, "main", lambda argv: called.append(argv) or 2)
    scope, components, _ = fixture(tmp_path, files={"edge": {"lib/tool.py": "VALUE = 1\n"}})
    assert scan(scope, components) == {row["id"]: [] for row in components["components"]}
    assert called == []


def test_depth_reaches_the_config_scanner_and_its_failure_stops_the_assessment(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(assessment_scanner_findings.config_iac_scanner, "main", lambda argv: called.append(argv) or 2)
    scope, components, _ = fixture(tmp_path, files={"edge": {"Dockerfile": DOCKERFILE}})
    with pytest.raises(ValueError, match="config/IaC scanner failed"):
        scan(scope, components, depth="quick")
    assert called[0][called[0].index("--assessment-depth") + 1] == "quick"


ROOTLESS = "COPY . .\nRUN make build\n"
HARDENED = "FROM base@sha256:" + "a" * 64 + "\nUSER app\nHEALTHCHECK CMD true\nCOPY . .\n"


def absences(threats):
    return {t["config_check_id"]: t for t in threats if t["evidence"].get("kind") == "absence"}


@pytest.mark.parametrize(
    ("names", "path", "check"),
    [(("edge", "service"), "Dockerfile", "IAC-002"), (("north", "south"), ".github/workflows/build.yml", "IAC-041")],
)
def test_an_absence_is_anchored_at_the_file_it_searched_and_owned_by_its_repository(tmp_path, names, path, check):
    workflow = "name: build\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
    text = ROOTLESS if path == "Dockerfile" else workflow
    scope, components, _ = fixture(tmp_path, names=names, files={names[0]: {path: text}})
    repo = by_label(scope)[names[0]]
    owner = {row["repository_ids"][0]: row["id"] for row in components["components"]}
    result = scan(scope, components)
    threat = absences(result[owner[repo.repository_id]])[check]
    assert threat["evidence"] == {
        "kind": "absence",
        "searched_files": [path],
        "searched_file_count": 1,
        "repository_id": repo.repository_id,
        "file": path,
        "line": 1,
        "sha256": hashlib.sha256(repo.files[path]).hexdigest(),
    }
    other = next(r for r in scope.repositories if r is not repo)
    assert absences(result[owner[other.repository_id]]) == {}


def test_a_present_control_yields_no_absence(tmp_path):
    scope, components, _ = fixture(tmp_path, files={"edge": {"Dockerfile": HARDENED}})
    threats = [t for rows in scan(scope, components).values() for t in rows]
    assert {"IAC-002", "IAC-003"}.isdisjoint(absences(threats))


def test_an_absence_is_reviewed_by_reading_its_file_and_merged(tmp_path):
    from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
    from runtime.multi_repo_scope import admit

    from tests.test_multi_repo_controller import Host, checkout, controller

    roots = [tmp_path / name for name in ("caller", "receiver")]
    for root in roots:
        checkout(root)
    (roots[1] / "Dockerfile").write_text(ROOTLESS)
    scope = admit([str(r) for r in roots], str(tmp_path / "out"))
    host = Host(scope)
    jobs = AssessmentJobs(
        scope, scope.output / ".jobs", AssessmentBudget(2, 0.05, 60, 120), host.factory, lambda: False, lambda: None
    )
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    controls = controller._assessment_controls(scope, jobs, architecture, progress=lambda text: None)
    _, _, merged = controller._assessment_stride(scope, jobs, architecture, controls, [], progress=lambda text: None)
    receiver = by_label(scope)["receiver"].repository_id
    rootless = [t for t in merged["threats"] if t.get("config_check_id") == "IAC-002"]
    assert len(rootless) == 1
    assert rootless[0]["evidence"]["repository_id"] == receiver and rootless[0]["evidence"]["file"] == "Dockerfile"
    assert rootless[0]["evidence"]["kind"] == "absence"
    assert rootless[0]["evidence_check"] == "verified"
    owners = {c["id"] for c in architecture["components"]["components"] if c["repository_ids"] == [receiver]}
    assert rootless[0]["component_id"] in owners
    reviews = [ctx for role, ctx in host.calls if role == "evidence_verifier"]
    assert any(f["evidence"]["file"] == "Dockerfile" for ctx in reviews for f in ctx["findings"])
