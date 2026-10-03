#!/usr/bin/env python3
"""Repository build and supply-chain facts, read once from the scan inventory.

A capability such as SBOM generation or image signing belongs to the
repository, not to one file: a pipeline that generates an SBOM in one workflow
does not lack it because another workflow does not. Checks that judge such a
property (``expect: repository`` in data/config-iac-checks.yaml) are predicates
over these facts, so each gap is one finding whose evidence names every file
that was searched.

The facts are also the input of the §6.11 supply-chain view. They are written
under ``supply_chain_facts`` in ``$OUTPUT_DIR/.config-scan-findings.json`` and
shaped by ``$defs/supplyChainFacts`` in schemas/config-scan-findings.schema.yaml:

- ``workflows``: one row per CI workflow — token permissions and whether it
  builds or pushes a container image or publishes a package.
- ``inputs``: third-party code entering the build — GitHub Actions, container
  base images and piped remote installers — each with its pinning.
- ``outputs``: artifacts the pipeline produces — container images (pushed or
  not) and published packages.
- ``capabilities``: ``sbom``, ``image_signing`` and ``dependency_updates``,
  each with the evidence that establishes it and the files that were searched.

Only what the repository states is recorded: no environment, registry or
deployment target is inferred.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import re
from pathlib import Path
from typing import Any

import yaml
from shared._supply_chain_config import renovate_configs

from analyzers.scan_excludes import RepoInventory

FACTS_VERSION = 1
SEARCHED_FILES_LISTED = 50

WORKFLOW_GLOBS = ("**/.github/workflows/*.yml", "**/.github/workflows/*.yaml")
DOCKERFILE_GLOBS = ("**/Dockerfile", "**/Dockerfile.*", "**/*.dockerfile")
BUILD_SCRIPT_GLOBS = ("**/package.json", "**/Makefile")
DEPENDABOT_PATHS = (".github/dependabot.yml", ".github/dependabot.yaml")

_SBOM = (
    r"cyclonedx",
    r"\bsyft\b",
    r"anchore/sbom-action",
    r"spdx-sbom-generator",
    r"\bsbom-tool\b",
    r"docker\s+sbom\b",
    r"^\s*sbom\s*:\s*true\b",
)
_IMAGE_SIGNING = (
    r"\bcosign\b",
    r"actions/attest-build-provenance",
    r"sigstore/cosign-installer",
    r"\bnotation\s+sign\b",
    r"docker\s+trust\s+sign\b",
)
_IMAGE_BUILD = re.compile(
    r"docker/build-push-action|docker\s+(?:buildx\s+)?build\b|buildah\s+(?:bud|build)\b|kaniko|\bko\s+build\b|\bjib\b"
)
_IMAGE_PUSH = re.compile(r"(?m)^\s*push\s*:\s*true\b|docker\s+push\b|buildah\s+push\b|crane\s+push\b")
_PACKAGE_PUBLISH = (
    ("npm", re.compile(r"\b(?:npm|pnpm)\s+publish\b|\byarn\s+(?:npm\s+)?publish\b")),
    ("pypi", re.compile(r"\btwine\s+upload\b|\bpoetry\s+publish\b|\buv\s+publish\b")),
    ("cargo", re.compile(r"\bcargo\s+publish\b")),
    ("rubygems", re.compile(r"\bgem\s+push\b")),
    ("maven", re.compile(r"\bmvn\b[^\n]*\bdeploy\b|\bgradlew?\b[^\n]*\bpublish\b")),
)
_USES = re.compile(r"(?m)^\s*(?:-\s*)?uses\s*:\s*['\"]?([^\s#'\"]+)")
_FROM = re.compile(r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?")
_REMOTE_INSTALLER = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")

# Marker file -> dependency-update ecosystem, as Dependabot names them.
_ECOSYSTEM_MARKERS = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "Pipfile": "pip",
    "go.mod": "gomod",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "composer.json": "composer",
    "pom.xml": "maven",
}
# Renovate manager names -> the same ecosystem names.
_RENOVATE_MANAGERS = {
    "npm": "npm",
    "pip_requirements": "pip",
    "pip_setup": "pip",
    "pep621": "pip",
    "poetry": "pip",
    "pipenv": "pip",
    "gomod": "gomod",
    "cargo": "cargo",
    "bundler": "bundler",
    "composer": "composer",
    "maven": "maven",
    "github-actions": "github-actions",
    "dockerfile": "docker",
}

PRECONDITIONS = frozenset({"has_build_pipeline", "publishes_container_image", "dependency_update_tool_configured"})
CAPABILITIES = frozenset({"sbom", "image_signing", "dependency_updates"})


def _files(repo_root: Path, inventory: RepoInventory, globs: tuple[str, ...]) -> list[str]:
    found: set[str] = set()
    for pattern in globs:
        for path in repo_root.glob(pattern):
            rel = path.relative_to(repo_root).as_posix()
            if path.is_file() and rel in inventory:
                found.add(rel)
    return sorted(found)


def _read(repo_root: Path, rel: str) -> str:
    try:
        return (repo_root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _first_hit(text: str, patterns: tuple[str, ...]) -> int | None:
    offsets = [m.start() for p in patterns for m in [re.search(p, text, re.MULTILINE | re.IGNORECASE)] if m]
    return _line(text, min(offsets)) if offsets else None


def _listed(files: list[str]) -> dict[str, Any]:
    return {"searched_files": files[:SEARCHED_FILES_LISTED], "searched_file_count": len(files)}


def _action_pinning(reference: str) -> str:
    if reference.startswith("docker://"):
        return _image_pinning(reference.removeprefix("docker://"))
    _, separator, revision = reference.rpartition("@")
    if not separator:
        return "none"
    if re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        return "commit-sha"
    if re.fullmatch(r"v?\d+(?:\.\d+)*(?:[-+.][\w.-]+)?", revision):
        return "tag"
    return "branch"


def _image_pinning(reference: str) -> str:
    if "$" in reference:
        return "unresolved"
    if "@sha256:" in reference:
        return "digest"
    return "tag" if ":" in reference.rsplit("/", 1)[-1] else "none"


def _token_permissions(document: Any) -> str:
    """How a workflow sets its GITHUB_TOKEN scope: workflow, per-job, partial or repository default."""
    if not isinstance(document, dict):
        return "unknown"
    if "permissions" in document:
        return "workflow"
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return "unknown"
    scoped = sum(isinstance(job, dict) and "permissions" in job for job in jobs.values())
    if scoped == len(jobs):
        return "per-job"
    return "partial" if scoped else "default"


def _workflows(repo_root: Path, files: list[str]) -> tuple[list[dict], list[dict], list[dict]]:
    workflows: list[dict] = []
    inputs: list[dict] = []
    outputs: list[dict] = []
    for rel in files:
        text = _read(repo_root, rel)
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError:
            document = None
        build = _IMAGE_BUILD.search(text)
        pushed = bool(build and _IMAGE_PUSH.search(text))
        published = [(name, m) for name, pattern in _PACKAGE_PUBLISH for m in [pattern.search(text)] if m]
        workflows.append(
            {
                "file": rel,
                "token_permissions": _token_permissions(document),
                "builds_container_image": bool(build),
                "pushes_container_image": pushed,
                "publishes_packages": sorted({name for name, _ in published}),
            }
        )
        if build:
            outputs.append(
                {"kind": "container_image", "file": rel, "line": _line(text, build.start()), "pushed": pushed}
            )
        for name, match in published:
            outputs.append({"kind": "package", "ecosystem": name, "file": rel, "line": _line(text, match.start())})
        for match in _USES.finditer(text):
            reference = match.group(1)
            if reference.startswith("./"):
                continue
            inputs.append(
                {
                    "kind": "github_action",
                    "reference": reference,
                    "pinning": _action_pinning(reference),
                    "file": rel,
                    "line": _line(text, match.start(1)),
                }
            )
        inputs.extend(_remote_installers(rel, text))
    return workflows, inputs, outputs


def _remote_installers(rel: str, text: str) -> list[dict]:
    return [
        {
            "kind": "remote_script",
            "reference": match.group(0).strip()[:200],
            "pinning": "none",
            "file": rel,
            "line": _line(text, match.start()),
        }
        for match in _REMOTE_INSTALLER.finditer(text)
    ]


def _base_images(repo_root: Path, files: list[str]) -> list[dict]:
    rows: list[dict] = []
    for rel in files:
        text = _read(repo_root, rel)
        stages: set[str] = set()
        for match in _FROM.finditer(text):
            reference, alias = match.group(1), match.group(2)
            if reference.lower() != "scratch" and reference.lower() not in stages:
                rows.append(
                    {
                        "kind": "base_image",
                        "reference": reference,
                        "pinning": _image_pinning(reference),
                        "file": rel,
                        "line": _line(text, match.start(1)),
                    }
                )
            if alias:
                stages.add(alias.lower())
        rows.extend(_remote_installers(rel, text))
    return rows


def _capability(repo_root: Path, files: list[str], patterns: tuple[str, ...]) -> dict[str, Any]:
    evidence = []
    for rel in files:
        line = _first_hit(_read(repo_root, rel), patterns)
        if line is not None:
            evidence.append({"file": rel, "line": line})
    return {"present": bool(evidence), "evidence": evidence, **_listed(files)}


def _dependency_updates(repo_root: Path, inventory: RepoInventory, workflows: list[str], dockerfiles: list[str]):
    used = {_ECOSYSTEM_MARKERS[Path(rel).name] for rel in inventory.files if Path(rel).name in _ECOSYSTEM_MARKERS}
    if workflows:
        used.add("github-actions")
    if dockerfiles:
        used.add("docker")
    tools: list[str] = []
    covered: set[str] = set()
    evidence: list[dict] = []
    searched = [rel for rel in DEPENDABOT_PATHS if rel in inventory]
    for rel in searched:
        text = _read(repo_root, rel)
        tools.append("dependabot")
        for match in re.finditer(r"package-ecosystem\s*:\s*[\"']?([\w-]+)", text):
            covered.add(match.group(1))
            evidence.append({"file": rel, "line": _line(text, match.start())})
    for rel, config in renovate_configs(repo_root):
        if rel not in inventory:
            continue
        searched.append(rel)
        if config.get("enabled") is False:
            continue
        tools.append("renovate")
        evidence.append({"file": rel, "line": 1})
        managers = config.get("enabledManagers")
        if not managers:
            covered.update(used)
        elif isinstance(managers, list):
            covered.update(_RENOVATE_MANAGERS[m] for m in managers if isinstance(m, str) and m in _RENOVATE_MANAGERS)
    return {
        "present": bool(tools),
        "tools": sorted(set(tools)),
        "ecosystems_used": sorted(used),
        "ecosystems_covered": sorted(covered & used),
        "evidence": evidence,
        **_listed(sorted(searched)),
    }


def collect(repo_root: Path, inventory: RepoInventory) -> dict[str, Any]:
    """Supply-chain facts of the repository; see the module docstring for the shape."""
    repo_root = repo_root.resolve()
    workflow_files = _files(repo_root, inventory, WORKFLOW_GLOBS)
    dockerfiles = _files(repo_root, inventory, DOCKERFILE_GLOBS)
    build_scripts = _files(repo_root, inventory, BUILD_SCRIPT_GLOBS)
    workflows, inputs, outputs = _workflows(repo_root, workflow_files)
    inputs.extend(_base_images(repo_root, dockerfiles))
    build_files = sorted(set(workflow_files) | set(dockerfiles) | set(build_scripts))
    return {
        "version": FACTS_VERSION,
        "workflows": workflows,
        "inputs": inputs,
        "outputs": outputs,
        "capabilities": {
            "sbom": _capability(repo_root, build_files, _SBOM),
            "image_signing": _capability(repo_root, build_files, _IMAGE_SIGNING),
            "dependency_updates": _dependency_updates(repo_root, inventory, workflow_files, dockerfiles),
        },
    }


def precondition_holds(facts: dict[str, Any], name: str) -> bool:
    if name == "has_build_pipeline":
        return bool(facts["workflows"])
    if name == "publishes_container_image":
        return any(row["kind"] == "container_image" and row["pushed"] for row in facts["outputs"])
    if name == "dependency_update_tool_configured":
        return facts["capabilities"]["dependency_updates"]["present"]
    raise ValueError(f"unknown precondition {name!r}")


def capability_gap(facts: dict[str, Any], check: dict[str, Any]) -> dict[str, Any] | None:
    """The absence a repository check reports, or None when the repository satisfies it.

    Returns ``{"searched_files", "searched_file_count", "snippet"}`` for a finding."""
    precondition = check.get("precondition")
    if precondition and not precondition_holds(facts, precondition):
        return None
    name = check["capability"]
    capability = facts["capabilities"][name]
    if name == "dependency_updates":
        ecosystem = check["ecosystem"]
        if ecosystem not in capability["ecosystems_used"] or ecosystem in capability["ecosystems_covered"]:
            return None
        snippet = f"{', '.join(capability['tools'])} configured without the {ecosystem} ecosystem"
    elif capability["present"]:
        return None
    else:
        snippet = f"No {name.replace('_', ' ')} found in {capability['searched_file_count']} searched file(s)"
    return {
        "searched_files": capability["searched_files"],
        "searched_file_count": capability["searched_file_count"],
        "snippet": snippet,
    }
