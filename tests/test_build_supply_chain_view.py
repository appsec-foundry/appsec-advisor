"""The supply-chain view behind Figure 1b (RA-30), proven on neutral repositories.

Facts come from the real producer run over temporary repositories, so each case
exercises the path a scan takes; names, ecosystems and layouts differ from any
reference target on purpose.
"""

from __future__ import annotations

import json
from pathlib import Path

import analyzers.supply_chain_facts as facts_module
import pytest
import yaml
from analyzers.scan_excludes import repo_inventory
from jsonschema import Draft202012Validator
from model.build_supply_chain_view import build_view, has_build_evidence, view_checks

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((PLUGIN_ROOT / "schemas" / "supply-chain-view.schema.json").read_text(encoding="utf-8"))
ACTORS = [{"id": "ACT-X", "heatmap_slug": "build-time"}, {"id": "ACT-I", "heatmap_slug": "internet-anon"}]

RELEASE_WITH_INSTALL = """\
name: publish
on: push
jobs:
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements.txt
      - uses: docker/build-push-action@v6
        with:
          push: true
          tags: ghcr.io/example-org/ledger:${{ github.sha }}
"""

TEST_ONLY = """\
name: checks
on: pull_request
jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - run: pip install -r requirements.txt
      - run: pytest
"""

IMAGE_ONLY = """\
name: ship
on: push
jobs:
  container:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@0123456789abcdef0123456789abcdef01234567
        with:
          file: deploy/Containerfile
          push: true
          tags: quay.io/example-org/ledger:stable
"""

PACKAGE_ONLY = """\
name: library
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
      - run: npm publish
"""


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    for rel, text in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return repo


def _facts(repo: Path) -> dict:
    return facts_module.collect(repo, repo_inventory(repo))


def _threat(tid, title, cwe, file, line, *, risk="High", actor="ACT-X", component="release", check=None):
    threat = {
        "id": tid,
        "title": title,
        "cwe": cwe,
        "risk": risk,
        "effective_severity": risk,
        "actor_ids": [actor],
        "component": component,
        "evidence": [{"file": file, "line": line}],
    }
    if check:
        threat["config_check_id"] = check
        threat["source"] = "config-scan"
    return threat


def _model(threats, components=None):
    components = components or [{"id": "release", "paths": [".github/workflows/*"]}, {"id": "api", "paths": ["src/**"]}]
    return {"components": components, "threats": threats, "actors": ACTORS}


def _view(model, facts, inventory=None, build_time=0):
    view = build_view(model, facts, inventory or {}, build_time)
    if view is not None:
        Draft202012Validator(SCHEMA).validate(view)
    return view


def _edge(view, src, dst):
    return next((e for e in view["edges"] if e["from"] == src and e["to"] == dst), None)


def test_a_dependency_installed_in_the_pushing_job_is_evidenced_up_to_the_artifact(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/publish.yml": RELEASE_WITH_INSTALL, "requirements.txt": "flask>=2\n"})
    facts = _facts(repo)
    threat = _threat("T-007", "Dependencies resolved by range", "CWE-1104", ".github/workflows/publish.yml", 8)
    view = _view(_model([threat]), facts)
    artifact = "artifact:image:ghcr-io-example-org-ledger"
    assert {e["id"] for e in view["elements"]} >= {"input:package:pip", "ci:github-actions", artifact, "execution"}
    assert view["highlighted_path"]["finding"] == "F-007"
    assert [(s["from"], s["to"]) for s in view["highlighted_path"]["steps"]] == [
        ("input:package:pip", "ci:github-actions"),
        ("ci:github-actions", artifact),
    ]
    # A push never proves that production runs the image.
    assert _edge(view, artifact, "execution")["status"] == "unknown"


def test_independent_workflows_are_never_joined_into_one_path(tmp_path):
    repo = _repo(
        tmp_path,
        {
            ".github/workflows/checks.yml": TEST_ONLY,
            ".github/workflows/ship.yml": IMAGE_ONLY,
            "deploy/Containerfile": "FROM python:3.12\n",
            "requirements.txt": "flask>=2\n",
        },
    )
    threat = _threat("T-003", "Unpinned test dependency", "CWE-1104", ".github/workflows/checks.yml", 7)
    view = _view(_model([threat]), _facts(repo))
    steps = view["highlighted_path"]["steps"]
    # The install sits in the test job; the image comes from another workflow, so the path stops at the build.
    assert [(s["from"], s["to"]) for s in steps] == [("input:package:pip", "ci:github-actions")]


def test_a_publish_only_repository_asserts_no_execution(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/library.yml": PACKAGE_ONLY, "package.json": "{}"})
    view = _view(_model([]), _facts(repo))
    assert _edge(view, "artifact:package:npm", "execution")["status"] == "unknown"
    assert view["highlighted_path"] is None and view["entries"] == []


def test_an_unsigned_pushed_image_is_an_entry_and_a_missing_sbom_alone_is_not(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/ship.yml": IMAGE_ONLY, "deploy/Containerfile": "FROM python:3.12\n"})
    facts = _facts(repo)
    signing = _threat(
        "T-011",
        "Missing Container Image Signing",
        "CWE-347",
        ".github/workflows/ship.yml",
        1,
        risk="Medium",
        check="IAC-040",
    )
    sbom = _threat(
        "T-012", "Missing SBOM Generation", "CWE-1104", ".github/workflows/ship.yml", 1, risk="Medium", check="IAC-041"
    )
    with_signing = _view(_model([signing, sbom]), facts)
    assert [e["entry"] for e in with_signing["entries"]] == ["artifact"]
    only_sbom = _view(_model([sbom]), facts)
    assert only_sbom["entries"] == []
    assert any(f["id"] == "F-012" and f["entry"] is None for f in only_sbom["findings"])


def test_a_workflow_injection_finding_is_a_repository_entry_shown_on_its_ci_system(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/ship.yml": IMAGE_ONLY, "deploy/Containerfile": "FROM python:3.12\n"})
    finding = _threat(
        "T-004", "Workflow Script Injection from Event Data", "CWE-78", ".github/workflows/ship.yml", 5, check="IAC-013"
    )
    view = _view(_model([finding]), _facts(repo))
    (row,) = view["findings"]
    assert row["element"] == "ci:github-actions" and row["entry"] == "repository"
    assert view["highlighted_path"]["steps"][0]["from"] == "repository"


def test_runtime_checks_and_runtime_findings_stay_out_of_the_view(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/ship.yml": IMAGE_ONLY, "deploy/Containerfile": "FROM python:3.12\n"})
    root = _threat(
        "T-020", "Container Runs as Root", "CWE-250", "deploy/Containerfile", 1, check="IAC-002", component="api"
    )
    xss = _threat("T-021", "Stored XSS", "CWE-79", "src/view.py", 9, actor="ACT-I", component="api")
    assert _view(_model([root, xss]), _facts(repo))["findings"] == []


@pytest.mark.parametrize("check, file", [("IAC-002", "ci/smoke/Containerfile"), ("IAC-003", "tools/e2e/Dockerfile")])
def test_runtime_hardening_on_a_build_component_is_listed_without_an_entry(tmp_path, check, file):
    # Figure 1a draws no build component, so the finding would otherwise appear in neither figure.
    repo = _repo(tmp_path, {".github/workflows/ship.yml": IMAGE_ONLY, file: "FROM python:3.12\n"})
    finding = _threat("T-022", "Hardening gap in a CI container", "CWE-250", file, 1, check=check)
    view = _view(_model([finding]), _facts(repo))
    assert [(f["id"], f["element"], f["entry"]) for f in view["findings"]] == [("F-022", "unowned", None)]
    assert view["entries"] == []


@pytest.mark.parametrize(
    "config, ecosystem, install",
    [(".npmrc", "npm", "npm ci"), ("pip.conf", "pip", "pip install -r requirements.txt")],
)
def test_a_package_manager_config_finding_belongs_to_its_ecosystem(tmp_path, config, ecosystem, install):
    workflow = PACKAGE_ONLY.replace("npm ci", install)
    repo = _repo(tmp_path, {".github/workflows/library.yml": workflow, config: "x=1\n"})
    finding = _threat("T-023", "Lockfile generation disabled", "CWE-829", config, 1)
    (row,) = _view(_model([finding]), _facts(repo))["findings"]
    assert (row["element"], row["entry"]) == (f"input:package:{ecosystem}", "dependency")


def test_a_build_finding_in_an_unrelated_config_file_stays_unowned(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/library.yml": PACKAGE_ONLY, "settings.toml": "x=1\n"})
    finding = _threat("T-024", "Registry override", "CWE-829", "settings.toml", 1)
    (row,) = _view(_model([finding]), _facts(repo))["findings"]
    assert row["element"] == "unowned"


def test_a_finding_at_a_push_step_belongs_to_the_published_artifact_unless_it_is_about_the_input(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/ship.yml": IMAGE_ONLY, "deploy/Containerfile": "FROM python:3.12\n"})
    unsigned = _threat("T-025", "Published image is not signed", "CWE-345", ".github/workflows/ship.yml", 7)
    unpinned = _threat("T-026", "Build action from a mutable source", "CWE-829", ".github/workflows/ship.yml", 7)
    rows = {f["id"]: (f["element"], f["entry"]) for f in _view(_model([unsigned, unpinned]), _facts(repo))["findings"]}
    assert rows["F-025"] == ("artifact:image:quay-io-example-org-ledger", None)
    assert rows["F-026"] == ("input:github_action", "ci-input")


def _channels(inventory):
    view = _view(_model([]), {}, inventory, build_time=1)
    return next(e for e in view["elements"] if e["id"] == "execution")["channels"]


def test_a_platform_publish_adds_a_channel_only_without_an_evidenced_environment_of_that_platform():
    ci = [{"system": "Example CI", "source": "ci.yml", "facts": [], "publishes": ["Kubernetes (kubectl/Helm)"]}]
    cluster = {
        "platform": "kubernetes",
        "label": "Kubernetes · deploy/manifests",
        "source": "deploy/manifests/app.yaml",
    }
    assert _channels({"ci": ci, "environments": [cluster]}) == ["Kubernetes · deploy/manifests"]
    assert _channels({"ci": ci}) == ["Kubernetes (kubectl/Helm)"]
    compose = {"platform": "compose", "label": "Docker Compose", "source": "compose.yaml"}
    assert _channels({"ci": ci, "environments": [compose]}) == ["Docker Compose", "Kubernetes (kubectl/Helm)"]


def test_a_gitlab_only_repository_is_inventory_only_without_entries(tmp_path):
    inventory = {
        "ci": [{"system": "GitLab CI", "source": ".gitlab-ci.yml", "facts": [], "publishes": ["GitLab registry"]}]
    }
    view = _view(_model([]), {}, inventory)
    ci = next(e for e in view["elements"] if e["id"] == "ci:gitlab-ci")
    assert ci["coverage"] == "inventory-only"
    assert _edge(view, "ci:gitlab-ci", "artifact:inventory:gitlab-ci:gitlab-registry")["status"] == "unknown"
    assert view["entries"] == []


def test_without_ci_a_build_time_finding_still_opens_the_view(tmp_path):
    finding = _threat("T-030", "Missing lockfile", "CWE-1104", "Cargo.lock", 0, component="api")
    view = _view(_model([finding]), {}, {}, build_time=1)
    assert any(e["id"] == "ci:none" for e in view["elements"])
    assert has_build_evidence({}, {}, 0) is False
    assert _view(_model([finding]), {}, {}, build_time=0) is None


def test_a_dockerfile_no_job_builds_has_no_evidenced_edge_to_ci(tmp_path):
    repo = _repo(
        tmp_path,
        {
            ".github/workflows/library.yml": PACKAGE_ONLY,
            "package.json": "{}",
            "Dockerfile": "FROM node:22\nRUN npm install\n",
        },
    )
    view = _view(_model([]), _facts(repo))
    edge = _edge(view, "input:base_image", "ci:github-actions")
    assert edge is None  # a local build is not completed into a CI path


def test_a_build_finding_with_ambiguous_ci_owner_is_listed_unowned(tmp_path):
    inventory = {
        "ci": [{"system": "Jenkins", "source": "Jenkinsfile"}, {"system": "Travis CI", "source": ".travis.yml"}]
    }
    finding = _threat("T-040", "Build secret exposure", "CWE-532", "scripts/release.sh", 3)
    view = _view(_model([finding]), {}, inventory)
    assert view["findings"][0]["element"] == "unowned"


def test_every_config_check_is_classified_exactly_once():
    catalog = yaml.safe_load((PLUGIN_ROOT / "data" / "config-iac-checks.yaml").read_text(encoding="utf-8"))
    ids = [c["id"] for c in (catalog.get("checks") or catalog)]
    mapping = view_checks()
    classified = list(mapping["checks"]) + list(mapping["runtime"])
    assert sorted(classified) == sorted(ids)
    assert len(classified) == len(set(classified))
    assert {rule.get("entry") for rule in mapping["checks"].values()} <= set(mapping["entries"]) | {None}


def _boundary(tid, file, line=4, **extra):
    row = {
        "id": tid,
        "from": "external",
        "to": "release",
        "kind": "build",
        "confidence": "confirmed",
        "resolution_status": "resolved",
        "evidence": [{"file": file, "line": line}],
    }
    return {**row, **extra}


def _mapped(view):
    return {e["id"]: [b["id"] for b in e.get("boundaries") or []] for e in view["elements"] if e.get("boundaries")}


@pytest.mark.parametrize(
    ("systems", "cited"),
    [
        ((("Jenkins", "Jenkinsfile"), ("Travis CI", ".travis.yml")), "Jenkinsfile"),
        ((("Buildkite", ".buildkite/pipeline.yml"), ("CircleCI", ".circleci/config.yml")), ".circleci/config.yml"),
    ],
)
def test_a_boundary_marks_only_the_ci_system_whose_definition_evidences_it(systems, cited):
    inventory = {"ci": [{"system": name, "source": source} for name, source in systems]}
    model = _model([])
    model["trust_boundaries"] = [_boundary("tb-3", cited)]
    view = _view(model, {}, inventory)
    owner = next(e["id"] for e in view["elements"] if e["kind"] == "ci" and e["sources"][0]["file"] == cited)
    assert _mapped(view) == {owner: ["tb-3"]}


def test_a_workflow_boundary_maps_to_its_ci_system_not_to_the_repository_row(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/publish.yml": RELEASE_WITH_INSTALL, "requirements.txt": "flask>=2\n"})
    model = _model([])
    model["trust_boundaries"] = [_boundary("tb-2", ".github/workflows/publish.yml", 8, confidence="inferred")]
    view = _view(model, _facts(repo))
    assert "repository" not in _mapped(view) and "execution" not in _mapped(view)
    ci = next(e for e in view["elements"] if e["id"] == "ci:github-actions")
    assert ci["boundaries"] == [
        {
            "id": "tb-2",
            "confidence": "inferred",
            "crossing": "ingress",
            "evidence": {"file": ".github/workflows/publish.yml", "line": 8},
        }
    ]


@pytest.mark.parametrize(
    ("frm", "to", "crossing"),
    [
        ("external", "release", "ingress"),  # a supplier enters the build
        ("release", "external", "egress"),  # a push leaves it for a registry
        ("release", "api", "egress"),  # a deploy step reaches the runtime
    ],
)
def test_a_mapped_boundary_says_whether_it_enters_or_leaves_the_build(frm, to, crossing):
    inventory = {"ci": [{"system": "Jenkins", "source": "Jenkinsfile"}]}
    model = _model([])
    model["trust_boundaries"] = [_boundary("tb-1", "Jenkinsfile", **{"from": frm, "to": to})]
    view = _view(model, {}, inventory)
    rows = [b for e in view["elements"] for b in e.get("boundaries") or []]
    assert [(b["id"], b["crossing"]) for b in rows] == [("tb-1", crossing)]


@pytest.mark.parametrize(
    "row",
    [
        _boundary("tb-5", "src/app.py"),  # nothing in the view cites its evidence
        _boundary("tb-5", "Jenkinsfile", kind="network", to="api"),  # a runtime crossing
        _boundary("tb-5", "Jenkinsfile", surface="in-process", transition=[], kind="process", to="api"),
        _boundary("tb-5", "Jenkinsfile", resolution_status="unresolved"),
    ],
)
def test_a_boundary_without_build_scope_or_cited_evidence_is_not_mapped(row):
    inventory = {"ci": [{"system": "Jenkins", "source": "Jenkinsfile"}]}
    model = _model([])
    model["trust_boundaries"] = [row]
    assert _mapped(_view(model, {}, inventory)) == {}


INSTALLER_AND_PUSH = """\
name: images
on: push
jobs:
  bake:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://get.example.dev/tool.sh | sh
      - run: poetry install
      - run: docker build -t quay.io/example-team/catalog:1 .
      - run: docker push quay.io/example-team/catalog:1
"""


@pytest.mark.parametrize(
    ("workflow", "line", "element"),
    [
        (RELEASE_WITH_INSTALL, 7, "input:github_action"),  # actions/checkout, a step that publishes nothing
        (RELEASE_WITH_INSTALL, 8, "input:package:pip"),
        (INSTALLER_AND_PUSH, 7, "input:remote_script"),
        (INSTALLER_AND_PUSH, 9, "artifact:image:quay-io-example-team-catalog"),
    ],
    ids=["action", "pip-install", "remote-script", "pushed-image"],
)
def test_a_step_boundary_marks_only_the_element_of_that_step_and_its_ci_system(tmp_path, workflow, line, element):
    repo = _repo(tmp_path, {".github/workflows/build.yml": workflow, "requirements.txt": "flask>=2\n"})
    model = _model([])
    model["trust_boundaries"] = [_boundary("tb-1", ".github/workflows/build.yml", line)]
    view = _view(model, _facts(repo))
    assert _mapped(view) == {"ci:github-actions": ["tb-1"], element: ["tb-1"]}


def test_a_boundary_on_a_fact_row_beyond_the_displayed_sources_still_marks_its_element(tmp_path):
    steps = "".join(f"      - uses: example-org/step-{n}@v1\n" for n in range(8))
    workflow = f"name: many\non: push\njobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"
    repo = _repo(tmp_path, {".github/workflows/many.yml": workflow})
    model = _model([])
    model["trust_boundaries"] = [_boundary("tb-1", ".github/workflows/many.yml", 14)]  # the eighth action
    view = _view(model, _facts(repo))
    actions = next(e for e in view["elements"] if e["id"] == "input:github_action")
    assert {"file": ".github/workflows/many.yml", "line": 14} not in actions["sources"]
    assert _mapped(view) == {"ci:github-actions": ["tb-1"], "input:github_action": ["tb-1"]}


@pytest.mark.parametrize(
    ("file", "line"),
    [
        (".github/workflows/build.yml", 5),  # runs-on: no fact row sits on this line
        (".github/workflows/other.yml", 8),  # pytest, on the line the install holds in build.yml
    ],
    ids=["non-fact-line", "other-workflow"],
)
def test_a_boundary_without_a_fact_row_on_its_line_marks_only_the_ci_system(tmp_path, file, line):
    repo = _repo(
        tmp_path,
        {".github/workflows/build.yml": INSTALLER_AND_PUSH, ".github/workflows/other.yml": TEST_ONLY},
    )
    model = _model([])
    model["trust_boundaries"] = [_boundary("tb-1", file, line)]
    assert _mapped(_view(model, _facts(repo))) == {"ci:github-actions": ["tb-1"]}
