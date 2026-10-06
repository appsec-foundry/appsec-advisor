"""Repository supply-chain facts and the repository-scope checks built on them."""

from __future__ import annotations

import json
from pathlib import Path

import analyzers.config_iac_scanner as scanner
import analyzers.supply_chain_facts as facts_module
import pytest
import yaml
from analyzers.scan_excludes import repo_inventory
from jsonschema import Draft202012Validator

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCHEMA = yaml.safe_load((PLUGIN_ROOT / "schemas" / "config-scan-findings.schema.yaml").read_text(encoding="utf-8"))

BUILD_AND_PUSH = """\
name: release
on: push
permissions:
  contents: read
jobs:
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - uses: docker/build-push-action@v6
        with:
          push: true
"""
BUILD_ONLY = BUILD_AND_PUSH.replace("push: true", "push: false")
TEST_ONLY = """\
name: test
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
"""


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    for rel, text in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    repo.mkdir(exist_ok=True)
    return repo


def _facts(repo: Path) -> dict:
    return facts_module.collect(repo, repo_inventory(repo))


def _repository_findings(repo: Path, tmp_path: Path) -> dict[str, dict]:
    result = scanner.scan(repo, scanner.DEFAULT_CHECKS, depth="standard", output=tmp_path / "out.json")
    Draft202012Validator(SCHEMA).validate(json.loads(json.dumps(result)))
    return {
        row["check_id"]: row
        for row in result["findings"]
        if row["check_id"] in {"IAC-030", "IAC-031", "IAC-032", "IAC-040", "IAC-041"}
    }


@pytest.mark.parametrize(
    "files",
    [
        {
            ".github/workflows/a.yml": TEST_ONLY,
            ".github/workflows/b.yml": TEST_ONLY + "      - run: npx @cyclonedx/cyclonedx-npm\n",
        },
        {".github/workflows/a.yml": TEST_ONLY, "Dockerfile": "FROM node:24\nRUN npm i -g @cyclonedx/cyclonedx-npm\n"},
        {".github/workflows/a.yml": TEST_ONLY, "package.json": '{"scripts": {"sbom": "syft . -o cyclonedx-json"}}'},
    ],
    ids=["one-workflow-of-two", "dockerfile-only", "package-script"],
)
def test_sbom_anywhere_in_the_build_satisfies_the_repository(tmp_path, files):
    repo = _repo(tmp_path, files)
    assert _facts(repo)["capabilities"]["sbom"]["present"] is True
    assert "IAC-041" not in _repository_findings(repo, tmp_path)


def test_a_missing_sbom_is_one_absence_finding_that_lists_every_searched_file(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/a.yml": TEST_ONLY, ".github/workflows/b.yml": TEST_ONLY})
    finding = _repository_findings(repo, tmp_path)["IAC-041"]
    assert finding["evidence_kind"] == "absence"
    assert finding["line"] == 0
    assert finding["searched_files"] == [".github/workflows/a.yml", ".github/workflows/b.yml"]
    assert finding["searched_file_count"] == 2


def test_no_build_pipeline_means_no_sbom_finding(tmp_path):
    repo = _repo(tmp_path, {"src/app.js": "console.log(1)\n"})
    assert "IAC-041" not in _repository_findings(repo, tmp_path)


@pytest.mark.parametrize(
    ("workflow", "expected"),
    [
        (BUILD_AND_PUSH, True),
        (BUILD_ONLY, False),
        (BUILD_AND_PUSH + "      - uses: sigstore/cosign-installer@v3\n      - run: cosign sign img\n", False),
        (BUILD_AND_PUSH + "      - uses: actions/attest-build-provenance@v1\n", False),
        (TEST_ONLY, False),
    ],
    ids=["pushes-unsigned", "builds-not-pushed", "cosign", "attestation", "no-image"],
)
def test_image_signing_applies_only_to_a_repository_that_pushes_an_image(tmp_path, workflow, expected):
    repo = _repo(tmp_path, {".github/workflows/release.yml": workflow, ".github/workflows/test.yml": TEST_ONLY})
    findings = _repository_findings(repo, tmp_path)
    assert ("IAC-040" in findings) is expected
    if expected:
        assert findings["IAC-040"]["searched_files"] == [".github/workflows/release.yml", ".github/workflows/test.yml"]


@pytest.mark.parametrize(
    ("config", "missing"),
    [
        ({".github/dependabot.yml": 'version: 2\nupdates:\n  - package-ecosystem: "npm"\n'}, {"IAC-031", "IAC-032"}),
        ({"renovate.json": "{}"}, set()),
        ({"renovate.json": '{"enabledManagers": ["npm"]}'}, {"IAC-031", "IAC-032"}),
        ({"renovate.json": '{"enabled": false}'}, set()),
        ({}, set()),
    ],
    ids=["dependabot-npm-only", "renovate-unrestricted", "renovate-npm-only", "renovate-disabled", "no-tool"],
)
def test_dependency_update_checks_judge_coverage_of_the_ecosystems_in_use(tmp_path, config, missing):
    repo = _repo(
        tmp_path,
        {"package.json": "{}", "Dockerfile": "FROM node:24\n", ".github/workflows/test.yml": TEST_ONLY, **config},
    )
    assert set(_repository_findings(repo, tmp_path)) & {"IAC-030", "IAC-031", "IAC-032"} == missing


def test_an_ecosystem_the_repository_does_not_use_is_not_required(tmp_path):
    repo = _repo(
        tmp_path, {"requirements.txt": "flask\n", ".github/dependabot.yml": "updates:\n  - package-ecosystem: pip\n"}
    )
    assert not set(_repository_findings(repo, tmp_path)) & {"IAC-030", "IAC-031", "IAC-032"}


def test_inputs_record_each_third_party_reference_with_its_pinning(tmp_path):
    workflow = """\
jobs:
  build:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - uses: some/action@v2.1.0
      - uses: other/action@main
      - uses: ./local-action
      - uses: docker://alpine@sha256:abc
      - run: curl -fsSL https://example.test/install.sh | sh
"""
    dockerfile = """\
FROM node:24 AS build
FROM build AS test
FROM scratch
FROM gcr.io/distroless/nodejs@sha256:def
FROM alpine
"""
    repo = _repo(tmp_path, {".github/workflows/ci.yml": workflow, "Dockerfile": dockerfile})
    rows = {(row["kind"], row["reference"]): row["pinning"] for row in _facts(repo)["inputs"]}
    assert rows == {
        ("github_action", "actions/checkout@0123456789abcdef0123456789abcdef01234567"): "commit-sha",
        ("github_action", "some/action@v2.1.0"): "tag",
        ("github_action", "other/action@main"): "branch",
        ("github_action", "docker://alpine@sha256:abc"): "digest",
        ("remote_script", "curl -fsSL https://example.test/install.sh | sh"): "none",
        ("base_image", "node:24"): "tag",
        ("base_image", "gcr.io/distroless/nodejs@sha256:def"): "digest",
        ("base_image", "alpine"): "none",
    }


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ("permissions: read-all\njobs:\n  a: {runs-on: x}\n", "workflow"),
        ("jobs:\n  a: {permissions: {contents: read}}\n  b: {permissions: {}}\n", "per-job"),
        ("jobs:\n  a: {permissions: {contents: read}}\n  b: {runs-on: x}\n", "partial"),
        ("jobs:\n  a: {runs-on: x}\n", "default"),
    ],
)
def test_each_workflow_records_how_it_scopes_its_token(tmp_path, document, expected):
    repo = _repo(tmp_path, {".github/workflows/w.yml": document})
    assert _facts(repo)["workflows"][0]["token_permissions"] == expected


def test_outputs_record_pushed_images_and_published_packages(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/release.yml": BUILD_AND_PUSH + "      - run: npm publish\n"})
    outputs = _facts(repo)["outputs"]
    assert [(row["kind"], row.get("pushed"), row.get("ecosystem")) for row in outputs] == [
        ("container_image", True, None),
        ("package", None, "npm"),
    ]


# --- job association, installs, built Dockerfile and push destination (RA-30) ---

TWO_JOBS = """\
name: ci
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
      - run: npm install
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: registry.example.org/team/service:${{ github.sha }}
"""


def test_inputs_installs_and_outputs_carry_their_workflow_job(tmp_path):
    repo = _repo(tmp_path, {".github/workflows/ci.yml": TWO_JOBS, "Dockerfile": "FROM node:22\nRUN npm ci\n"})
    facts = _facts(repo)
    jobs = {(row["kind"], row["reference"]): row.get("job") for row in facts["inputs"]}
    assert jobs[("github_action", "actions/setup-node@v4")] == "test"
    assert jobs[("github_action", "docker/build-push-action@v6")] == "release"
    assert jobs[("base_image", "node:22")] is None  # Dockerfile rows sit outside any job
    workflow_install = next(row for row in facts["installs"] if row["file"] == ".github/workflows/ci.yml")
    assert workflow_install == {
        "ecosystem": "npm",
        "command": "npm install",
        "lockfile_enforced": False,
        "file": ".github/workflows/ci.yml",
        "line": 8,
        "job": "test",
    }
    dockerfile_install = next(row for row in facts["installs"] if row["file"] == "Dockerfile")
    assert dockerfile_install["lockfile_enforced"] is True and "job" not in dockerfile_install
    (image,) = [row for row in facts["outputs"] if row["kind"] == "container_image"]
    assert image["job"] == "release"
    assert image["dockerfile"] == "Dockerfile"
    assert image["destination"] == {"registry": "registry.example.org", "repository": "team/service"}
    Draft202012Validator({"$defs": SCHEMA["$defs"], **SCHEMA["$defs"]["supplyChainFacts"]}).validate(facts)


def test_a_destination_hidden_behind_an_expression_and_an_unbuilt_dockerfile_stay_absent(tmp_path):
    workflow = TWO_JOBS.replace("registry.example.org/team/service", "${{ vars.IMAGE }}").replace(
        "context: .", "file: build/Containerfile"
    )
    repo = _repo(tmp_path, {".github/workflows/ci.yml": workflow, "Dockerfile": "FROM node:22\n"})
    (image,) = [row for row in _facts(repo)["outputs"] if row["kind"] == "container_image"]
    assert "destination" not in image
    assert "dockerfile" not in image  # build/Containerfile is not in the repository


def test_a_docker_hub_short_name_resolves_to_docker_io(tmp_path):
    workflow = TWO_JOBS.replace("registry.example.org/team/service:${{ github.sha }}", "acme/web:latest")
    repo = _repo(tmp_path, {".github/workflows/ci.yml": workflow})
    (image,) = [row for row in _facts(repo)["outputs"] if row["kind"] == "container_image"]
    assert image["destination"] == {"registry": "docker.io", "repository": "acme/web"}
