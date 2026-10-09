#!/usr/bin/env python3
"""The supply-chain view behind Figure 1b: evidenced elements, relationships and findings (RA-30).

Composition rebuilds ``$OUTPUT_DIR/.supply-chain-view.json`` on every render
from inputs a run keeps: ``.deployment-inventory.json``, the ``supply_chain_facts``
in ``.config-scan-findings.json`` and the threat model. The artifact records a
fingerprint of these inputs; it never carries actor codes or scenario numbers,
which composition takes from the resolved attack paths that drive Figure 1a
and Figure 2.

Rules:
- An element exists only when a producer reports it. Each carries its sources.
- An edge is ``evidenced`` when the facts relate both ends through one workflow
  job (or a Dockerfile that job builds), and ``unknown`` otherwise. A registry
  push never proves that production runs the image, so an artifact reaches the
  running system over an ``unknown`` edge.
- A finding attaches to an element through its config check
  (data/supply-chain-view-checks.yaml) or through an evidence location that a
  fact row shares. Attachment never implies an attack entry: the check's
  ``entry``, or a supply-chain CWE on a matched input, establishes one.
- The highlighted path follows only evidenced edges from the most severe
  eligible entry, and stops where the evidence ends.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import hashlib
import json
import re
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from renderers._severity_rollup import SEVERITY_ORDER, display_id, register_severity
from shared._boundary_interface import is_internal_interface

from model.build_plane import build_component_ids, is_ci_definition

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = PLUGIN_ROOT / "data" / "supply-chain-view-checks.yaml"
ATTRIBUTION_PATH = PLUGIN_ROOT / "data" / "actor-attribution-rules.yaml"
VIEW_FILE = ".supply-chain-view.json"
SCHEMA_VERSION = 1
BUILD_TIME = "build-time"
GITHUB = "GitHub Actions"

INPUT_KINDS = ("package", "github_action", "base_image", "remote_script")
ECOSYSTEM_LABELS = {
    "npm": "npm registry",
    "pip": "PyPI",
    "gomod": "Go modules",
    "cargo": "crates.io",
    "bundler": "RubyGems",
    "composer": "Packagist",
    "maven": "Maven repositories",
    "gradle": "Gradle repositories",
}
MANIFEST_ECOSYSTEMS = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "poetry.lock": "pip",
    "Pipfile": "pip",
    "Pipfile.lock": "pip",
    "uv.lock": "pip",
    "go.mod": "gomod",
    "go.sum": "gomod",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "composer.json": "composer",
    "composer.lock": "composer",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "gradle.lockfile": "gradle",
}
# Package-manager configuration names that belong to exactly one ecosystem; a finding on them
# (a disabled lockfile, a registry override) is about that ecosystem's packages.
PACKAGE_MANAGER_CONFIGS = {
    ".npmrc": "npm",
    ".yarnrc": "npm",
    ".yarnrc.yml": "npm",
    "pip.conf": "pip",
    "pip.ini": "pip",
    "gradle.properties": "gradle",
}
CI_FILES = {
    "GitHub Actions": ".github/workflows/",
    "GitLab CI": ".gitlab-ci.y",
    "Jenkins": "Jenkinsfile",
    "CircleCI": ".circleci/",
    "Azure Pipelines": "azure-pipelines.y",
    "Bitbucket Pipelines": "bitbucket-pipelines.y",
    "Travis CI": ".travis.yml",
}
INPUT_ENTRY = {
    "package": "dependency",
    "github_action": "ci-input",
    "base_image": "ci-input",
    "remote_script": "ci-input",
}
MAX_SOURCES = 5
# Internal: every (file, line) of an element's fact rows, beyond the capped display sources.
# Boundary mapping reads it; build_view removes it before the view leaves this module.
EVIDENCE_KEYS = "_evidence_keys"


@cache
def view_checks() -> dict[str, Any]:
    return yaml.safe_load(CHECKS_PATH.read_text(encoding="utf-8"))


@cache
def supply_chain_cwes() -> frozenset[str]:
    rules = yaml.safe_load(ATTRIBUTION_PATH.read_text(encoding="utf-8"))
    return frozenset(rules["restricted_groups"][BUILD_TIME]["cwes"])


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "x"


def _source(row: dict) -> dict:
    out = {"file": str(row.get("file") or "")}
    if isinstance(row.get("line"), int) and row["line"] > 0:
        out["line"] = row["line"]
    return out


def _evidence_keys(rows) -> set[tuple[str, int]]:
    return {(str(row["file"]), row["line"]) for row in rows if row.get("file") and isinstance(row.get("line"), int)}


def _sources(rows) -> list[dict]:
    seen, out = set(), []
    for row in rows:
        source = _source(row)
        key = (source["file"], source.get("line"))
        if source["file"] and key not in seen:
            seen.add(key)
            out.append(source)
    return out[:MAX_SOURCES]


def _ci_system_of(path: str, systems: list[str]) -> str | None:
    owners = [name for name in systems if CI_FILES.get(name) and CI_FILES[name] in path]
    return owners[0] if len(owners) == 1 else None


def _actor_slugs(model: dict) -> dict[str, str]:
    return {
        str(a.get("id")): str(a.get("heatmap_slug") or "")
        for a in model.get("actors") or []
        if isinstance(a, dict) and a.get("id")
    }


def fingerprint(model: dict, facts: dict | None, inventory: dict | None) -> str:
    """Digest of every input the view reads, so an audit can tell which model a view belongs to."""
    threats = sorted(
        (str(t.get("id")), register_severity(t), sorted(map(str, t.get("actor_ids") or [])), str(t.get("component")))
        for t in model.get("threats") or []
        if isinstance(t, dict)
    )
    payload = json.dumps(
        {
            "threats": threats,
            "components": sorted(build_component_ids(model.get("components") or [])),
            "boundaries": sorted(
                (str(b.get("id")), str(b.get("confidence")), json.dumps(b.get("evidence"), sort_keys=True))
                for b in _build_boundaries(model)
            ),
            "facts": facts,
            "inventory": (inventory or {}).get("ci"),
            "dependencies": (inventory or {}).get("dependencies"),
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def has_build_evidence(facts: dict | None, inventory: dict | None, build_time_scenario_findings: int) -> bool:
    """The one condition behind Figure 1b, its strip, links and cleanup (proposal: When Figure 1b appears)."""
    return bool((inventory or {}).get("ci") or (facts or {}).get("workflows") or build_time_scenario_findings)


def _elements(facts: dict, inventory: dict) -> tuple[dict[str, dict], list[str]]:
    elements: dict[str, dict] = {}
    systems = [str(row.get("system")) for row in inventory.get("ci") or [] if row.get("system")]
    if facts.get("workflows") and GITHUB not in systems:
        systems.insert(0, GITHUB)
    ci_files = sorted({row["file"] for row in facts.get("workflows") or []}) or [
        str(row.get("source")) for row in inventory.get("ci") or [] if row.get("source")
    ]
    elements["repository"] = {
        "id": "repository",
        "column": "sources",
        "kind": "repository",
        "label": "Source repository",
        "detail": " · ".join(dict.fromkeys(_short_ci_path(p) for p in ci_files)) or "no CI definition",
        "sources": [{"file": p} for p in ci_files[:MAX_SOURCES]],
    }
    installs = facts.get("installs") or []
    inputs = facts.get("inputs") or []
    ecosystems = list(dict.fromkeys(row["ecosystem"] for row in installs))
    dependencies = inventory.get("dependencies") or {}
    for ecosystem in ecosystems:
        rows = [row for row in installs if row["ecosystem"] == ecosystem]
        enforced = sum(bool(row.get("lockfile_enforced")) for row in rows)
        detail = f"{len(rows)} install step{'s' if len(rows) != 1 else ''} · lockfile enforced in {enforced}"
        elements[f"input:package:{ecosystem}"] = {
            "id": f"input:package:{ecosystem}",
            "column": "sources",
            "kind": "package",
            "ecosystem": ecosystem,
            "label": ECOSYSTEM_LABELS.get(ecosystem, ecosystem),
            "detail": detail,
            "sources": _sources(rows),
            EVIDENCE_KEYS: _evidence_keys(rows),
        }
    if dependencies.get("manifests") and ecosystems:
        elements["input:package:" + ecosystems[0]]["manifest_detail"] = (
            f"{dependencies.get('declared', 0)} declared · {dependencies.get('ranges', 0)} by range · "
            f"lockfile {'present' if dependencies.get('lockfile') else 'absent'}"
        )
    for kind, label in (
        ("github_action", "GitHub Actions"),
        ("base_image", "Base images"),
        ("remote_script", "Remote installers"),
    ):
        rows = [row for row in inputs if row["kind"] == kind]
        if not rows:
            continue
        strong = {"github_action": "commit-sha", "base_image": "digest"}.get(kind)
        if strong:
            weak = sum(row["pinning"] != strong for row in rows)
            detail = f"{len(rows)} reference{'s' if len(rows) != 1 else ''} · {weak} not {'SHA' if strong == 'commit-sha' else 'digest'}-pinned"
        else:
            detail = f"{len(rows)} piped to a shell"
        elements[f"input:{kind}"] = {
            "id": f"input:{kind}",
            "column": "sources",
            "kind": kind,
            "label": label,
            "detail": detail,
            "sources": _sources(rows),
            EVIDENCE_KEYS: _evidence_keys(rows),
        }
    inventory_rows = {str(row.get("system")): row for row in inventory.get("ci") or []}
    for system in systems:
        row = inventory_rows.get(system) or {}
        full = system == GITHUB and bool(facts.get("workflows"))
        workflow_count = len(facts.get("workflows") or []) if system == GITHUB else 0
        elements[f"ci:{_slug(system)}"] = {
            "id": f"ci:{_slug(system)}",
            "column": "build",
            "kind": "ci",
            "label": system,
            "coverage": "full" if full else "inventory-only",
            "detail": f"{workflow_count} workflows" if workflow_count else str(row.get("source") or ""),
            "facts": [str(f.get("text")) for f in row.get("facts") or [] if f.get("text")][:3],
            "sources": [{"file": str(row.get("source") or CI_FILES.get(system, system))}],
        }
    if not systems:
        elements["ci:none"] = {
            "id": "ci:none",
            "column": "build",
            "kind": "ci",
            "label": "No CI evidenced",
            "coverage": "none",
            "detail": "no CI definition in the repository",
            "facts": [],
            "sources": [],
        }
    for output in facts.get("outputs") or []:
        element_id = _artifact_id(output)
        if element_id in elements:
            elements[element_id]["sources"] = _sources(elements[element_id]["sources"] + [output])
            elements[element_id][EVIDENCE_KEYS] |= _evidence_keys([output])
            continue
        if output["kind"] == "container_image":
            destination = output.get("destination") or {}
            label = f"{destination['registry']}/{destination['repository']}" if destination else "Container image"
            detail = "pushed" if output.get("pushed") else "built, not pushed"
        else:
            label = f"{output.get('ecosystem', 'package')} package"
            detail = "published"
        elements[element_id] = {
            "id": element_id,
            "column": "artifacts",
            "kind": "artifact",
            "artifact": output["kind"],
            "pushed": bool(output.get("pushed")) or output["kind"] == "package",
            "label": label,
            "detail": detail,
            "sources": _sources([output]),
            EVIDENCE_KEYS: _evidence_keys([output]),
        }
    for system, row in inventory_rows.items():
        if system == GITHUB and facts.get("workflows"):
            continue
        for target in row.get("publishes") or []:
            if str(target).lower().startswith("kubernetes"):
                continue
            element_id = f"artifact:inventory:{_slug(system)}:{_slug(target)}"
            elements[element_id] = {
                "id": element_id,
                "column": "artifacts",
                "kind": "artifact",
                "artifact": "inventory",
                "pushed": True,
                "label": str(target),
                "detail": f"published by {system} (inventory only)",
                "owner": f"ci:{_slug(system)}",
                "sources": [{"file": str(row.get("source") or "")}],
            }
    environments = [env for env in inventory.get("environments") or [] if env.get("label")]
    channels = [str(env["label"]) for env in environments]
    # A CI publish entry names only the platform; an evidenced environment names the concrete target,
    # and a second cluster is a second environment. The platform entry adds a channel only when no
    # environment of that platform is evidenced.
    if not any(str(env.get("platform") or "").lower() == "kubernetes" for env in environments):
        channels += [
            str(t)
            for row in inventory.get("ci") or []
            for t in row.get("publishes") or []
            if str(t).lower().startswith("kubernetes")
        ]
    elements["execution"] = {
        "id": "execution",
        "column": "execution",
        "kind": "execution",
        "label": "Running system",
        "channels": list(dict.fromkeys(channels))[:8],
        "sources": [],
    }
    return elements, systems


_BOUNDARY_ID_RE = re.compile(r"^tb-\d+$")


def _build_boundaries(model: dict) -> list[dict]:
    """Resolved catalogue boundaries that are about the build: a build-pipeline
    crossing, or one with a build-plane endpoint. Internal interfaces are not
    trust boundaries and never map."""
    build_ids = build_component_ids(model.get("components") or [])
    return [
        row
        for row in model.get("trust_boundaries") or []
        if isinstance(row, dict)
        and _BOUNDARY_ID_RE.fullmatch(str(row.get("id") or ""))
        and row.get("resolution_status") == "resolved"
        and not is_internal_interface(row)
        and (
            row.get("surface") == "build-pipeline"
            or row.get("kind") == "build"
            or bool({row.get("from"), row.get("to")} & build_ids)
        )
    ]


def _cites(source: dict, file: str) -> bool:
    """An element source names this file, or the directory that holds it."""
    path = str(source.get("file") or "").rstrip("/")
    return bool(path) and (file == path or file.startswith(path + "/"))


def _evidences(element: dict, entry: dict) -> bool:
    """The boundary evidence location belongs to this element.

    A CI system owns its workflow definition, so any location inside it counts.
    Every other element owns only its fact rows: one step of a workflow
    evidences that step's input or artifact, never every element the same file
    mentions.
    """
    file = entry["file"].removeprefix("./")
    if element["kind"] == "ci":
        return any(_cites(source, file) for source in element.get("sources") or [])
    line = entry.get("line")
    return isinstance(line, int) and (file, line) in element.get(EVIDENCE_KEYS, set())


def _map_boundaries(model: dict, elements: dict[str, dict]) -> None:
    """Attach each build boundary to the elements whose own evidence holds its evidence.

    The mapping is evidence, not column membership: a boundary whose evidence
    sits in one CI system's definition marks that system, and an input or
    artifact only when the boundary cites the exact line of one of its fact
    rows. The aggregate repository row and the running system are never
    mapped; a boundary nothing cites stays in the report catalogue. Each row
    says whether the crossing enters the build or leaves it, which decides the
    column border Figure 1b draws it on.
    """
    build_ids = build_component_ids(model.get("components") or [])
    for boundary in _build_boundaries(model):
        source, target = boundary.get("from"), boundary.get("to")
        leaves = target == "external" or (source in build_ids and target not in build_ids)
        crossing = "egress" if leaves else "ingress"
        for element in elements.values():
            if element["kind"] in {"repository", "execution"}:
                continue
            cited = next(
                (
                    entry
                    for entry in boundary.get("evidence") or []
                    if isinstance(entry, dict) and isinstance(entry.get("file"), str) and _evidences(element, entry)
                ),
                None,
            )
            rows = element.setdefault("boundaries", [])
            if cited is None or len(rows) >= MAX_SOURCES:
                continue
            rows.append(
                {
                    "id": boundary["id"],
                    "confidence": boundary.get("confidence")
                    if boundary.get("confidence") in {"confirmed", "inferred"}
                    else "unknown",
                    "crossing": crossing,
                    "evidence": _source(cited),
                }
            )
    for element in elements.values():
        if not element.get("boundaries"):
            element.pop("boundaries", None)


def _short_ci_path(path: str) -> str:
    return ".github/workflows" if path.startswith(".github/workflows/") or ".github/workflows/" in path else path


def _artifact_id(output: dict) -> str:
    if output["kind"] == "package":
        return f"artifact:package:{_slug(output.get('ecosystem', 'package'))}"
    destination = output.get("destination")
    if destination:
        return f"artifact:image:{_slug(destination['registry'] + '/' + destination['repository'])}"
    return f"artifact:image:{_slug(output['file'])}:{_slug(output.get('job') or 'workflow')}"


def _builds_dockerfile(outputs: list[dict], dockerfile: str) -> list[dict]:
    return [o for o in outputs if o["kind"] == "container_image" and o.get("dockerfile") == dockerfile and o.get("job")]


def _consumers(row: dict, outputs: list[dict]) -> list[dict]:
    """Outputs the job that uses ``row`` produces: its own job, or the jobs that build its Dockerfile."""
    if row.get("job"):
        return [o for o in outputs if o.get("job") == row["job"] and o["file"] == row["file"]]
    return _builds_dockerfile(outputs, row["file"])


def _used_in_ci(row: dict, outputs: list[dict]) -> list[dict]:
    """Evidence that a CI job uses ``row``: the row itself when it sits in a job, else the image builds of its Dockerfile."""
    if row.get("job"):
        return [row]
    return _builds_dockerfile(outputs, row["file"])


def _edges(elements: dict[str, dict], facts: dict) -> list[dict]:
    edges: list[dict] = []
    outputs = facts.get("outputs") or []
    github = f"ci:{_slug(GITHUB)}"
    for element in elements.values():
        if element["column"] != "sources" or element["kind"] == "repository":
            continue
        rows = _rows_of(element, facts)
        evidence = [ev for row in rows for ev in _used_in_ci(row, outputs)]
        if evidence and github in elements:
            edges.append(
                {
                    "from": element["id"],
                    "to": github,
                    "status": "evidenced",
                    "label": "fetched",
                    "sources": _sources(evidence),
                }
            )
    for ci in (e for e in elements.values() if e["kind"] == "ci" and e["coverage"] != "none"):
        edges.append(
            {"from": "repository", "to": ci["id"], "status": "evidenced", "label": "checkout", "sources": ci["sources"]}
        )
    for output in outputs:
        if output.get("job") and github in elements:
            edge = {
                "from": github,
                "to": _artifact_id(output),
                "status": "evidenced",
                "label": "push" if output.get("pushed") or output["kind"] == "package" else "build",
                "sources": _sources([output]),
            }
            if not any(e["from"] == edge["from"] and e["to"] == edge["to"] for e in edges):
                edges.append(edge)
    for element in elements.values():
        if element.get("owner"):
            edges.append(
                {
                    "from": element["owner"],
                    "to": element["id"],
                    "status": "unknown",
                    "label": "inventory only",
                    "sources": element["sources"],
                }
            )
        if element["column"] == "artifacts":
            edges.append(
                {"from": element["id"], "to": "execution", "status": "unknown", "label": "not evidenced", "sources": []}
            )
    return edges


def _rows_of(element: dict, facts: dict) -> list[dict]:
    if element["kind"] == "package":
        return [row for row in facts.get("installs") or [] if row["ecosystem"] == element["ecosystem"]]
    return [row for row in facts.get("inputs") or [] if row["kind"] == element["kind"]]


def _locations(threat: dict) -> list[tuple[str, int]]:
    rows = list(threat.get("evidence") or []) + list(threat.get("instances") or [])
    out = []
    for row in rows:
        if isinstance(row, dict) and row.get("file"):
            out.append((str(row["file"]).removeprefix("./"), int(row.get("line") or 0)))
    return out


def _attach(threat: dict, elements: dict, facts: dict, systems: list[str], build_ids: set[str], slugs: dict[str, str]):
    """``(element id, entry, matched fact row)`` of a finding, or None when Figure 1b does not show it."""
    checks = view_checks()
    check = str(threat.get("config_check_id") or "")
    if check in set(checks.get("runtime") or []):
        # Runtime hardening stays in Figure 1a, unless its component is build-plane and Figure 1a cannot draw it.
        return ("unowned", None, None) if str(threat.get("component")) in build_ids else None
    locations = _locations(threat)
    build_time = BUILD_TIME in {slugs.get(str(a)) for a in threat.get("actor_ids") or []}
    if check in checks["checks"]:
        rule = checks["checks"][check]
        element = _element_for_kind(rule["element"], rule.get("ecosystem"), locations, elements, systems)
        entry = rule.get("entry")
        if entry and rule.get("requires") == "pushed" and not (element and elements[element].get("pushed")):
            entry = None
        return (element, entry, None) if element else ("unowned", None, None)
    supply_cwe = str(threat.get("cwe") or "") in supply_chain_cwes()
    if supply_cwe or build_time:
        for path, line in locations:
            # A step that consumes an input and publishes an artifact: a supply-chain CWE is about the
            # input, any other finding about what the step publishes.
            for output, row in _facts_at(facts, path, line, outputs_first=not supply_cwe):
                if output:
                    if _artifact_id(row) in elements:
                        return _artifact_id(row), None, row
                    continue
                kind = "package" if "ecosystem" in row and "command" in row else row.get("kind")
                if kind in INPUT_KINDS:
                    element = f"input:package:{row['ecosystem']}" if kind == "package" else f"input:{kind}"
                    if element in elements:
                        return element, (INPUT_ENTRY[kind] if supply_cwe else None), row
            name = path.rsplit("/", 1)[-1]
            ecosystem = MANIFEST_ECOSYSTEMS.get(name) or PACKAGE_MANAGER_CONFIGS.get(name)
            if ecosystem and f"input:package:{ecosystem}" in elements:
                return f"input:package:{ecosystem}", ("dependency" if supply_cwe else None), None
    owned = str(threat.get("component")) in build_ids or build_time
    if not owned:
        return None
    for path, _line in locations:
        if is_ci_definition(path) and (system := _ci_system_of(path, systems)):
            return f"ci:{_slug(system)}", None, None
    return "unowned", None, None


def _element_for_kind(kind, ecosystem, locations, elements, systems) -> str | None:
    if kind == "repository":
        return "repository"
    if kind == "package":
        target = f"input:package:{ecosystem}" if ecosystem else None
        if target in elements:
            return target
        packages = [e for e in elements if e.startswith("input:package:")]
        return packages[0] if len(packages) == 1 else None
    if kind in ("github_action", "base_image", "remote_script"):
        return f"input:{kind}" if f"input:{kind}" in elements else None
    if kind == "ci":
        for path, _line in locations:
            if system := _ci_system_of(path, systems):
                return f"ci:{_slug(system)}"
        return f"ci:{_slug(systems[0])}" if len(systems) == 1 else None
    if kind == "artifact":
        # A repository-wide gap (signing) names no image; it attaches only when the repository has exactly one.
        images = [
            e for e, el in elements.items() if el["column"] == "artifacts" and el.get("artifact") == "container_image"
        ]
        return images[0] if len(images) == 1 else None
    return None


def _facts_at(facts: dict, path: str, line: int, *, outputs_first: bool) -> list[tuple[bool, dict]]:
    """``(is output, row)`` of every fact at one location, outputs first or last."""
    if line <= 0:
        return []
    consumed = [(False, row) for row in list(facts.get("inputs") or []) + list(facts.get("installs") or [])]
    produced = [(True, row) for row in facts.get("outputs") or []]
    rows = produced + consumed if outputs_first else consumed + produced
    return [(output, row) for output, row in rows if row["file"] == path and row["line"] == line]


def _path(entry: dict, elements: dict, facts: dict) -> list[dict]:
    """Evidenced edges from the entry's element towards the running system; empty when nothing is evidenced."""
    element = elements[entry["element"]]
    outputs = facts.get("outputs") or []
    github = f"ci:{_slug(GITHUB)}"
    if entry["entry"] == "repository":
        # The change enters through the repository and runs in the CI system that executes it,
        # whichever element displays the finding.
        target = element["id"] if element["kind"] == "ci" else github
        return [{"from": "repository", "to": target}] if target in elements else []
    if element["column"] != "sources" or element["kind"] == "repository" or github not in elements:
        return []
    rows = [entry["row"]] if entry.get("row") else _rows_of(element, facts)
    best: list[dict] = []
    for row in sorted(rows, key=lambda r: (r["file"], r["line"])):
        if not _used_in_ci(row, outputs):
            continue
        steps = [{"from": element["id"], "to": github, "via": _source(row)}]
        produced = sorted(_consumers(row, outputs), key=lambda o: (not o.get("pushed"), o["file"], o["line"]))
        if produced:
            steps.append({"from": github, "to": _artifact_id(produced[0]), "via": _source(produced[0])})
        if len(steps) > len(best):
            best = steps
    return best


def build_view(
    model: dict, facts: dict | None, inventory: dict | None, build_time_scenario_findings: int = 0
) -> dict | None:
    """The supply-chain view, or None when the repository has no build evidence."""
    facts = facts or {}
    inventory = inventory or {}
    if not has_build_evidence(facts, inventory, build_time_scenario_findings):
        return None
    elements, systems = _elements(facts, inventory)
    _map_boundaries(model, elements)
    for element in elements.values():
        element.pop(EVIDENCE_KEYS, None)
    edges = _edges(elements, facts)
    build_ids = build_component_ids(model.get("components") or [])
    slugs = _actor_slugs(model)
    findings, entries = [], []
    order = {name: i for i, name in enumerate(view_checks()["entries"])}
    for threat in model.get("threats") or []:
        if not isinstance(threat, dict) or not threat.get("id"):
            continue
        attached = _attach(threat, elements, facts, systems, build_ids, slugs)
        if not attached:
            continue
        element, entry, row = attached
        severity = register_severity(threat)
        location = (_locations(threat) or [("", 0)])[0]
        finding = {
            "id": display_id(str(threat["id"])),
            "title": str(threat.get("title") or "")[:160],
            "severity": severity,
            "element": element,
            "entry": entry,
            "evidence": {"file": location[0], **({"line": location[1]} if location[1] > 0 else {})},
        }
        findings.append(finding)
        if entry:
            entries.append({**finding, "row": row})
    ranked = sorted(
        entries,
        key=lambda e: (
            SEVERITY_ORDER.get(e["severity"], 99),
            order.get(e["entry"], 99),
            int(re.sub(r"\D", "", e["id"]) or 0),
        ),
    )
    highlighted = None
    if ranked:
        top = ranked[0]
        steps = _path(top, elements, facts)
        highlighted = {
            "finding": top["id"],
            "entry": top["entry"],
            "element": top["element"],
            "steps": [{"n": i, **step} for i, step in enumerate(steps, 1)],
        }
    entry_points = []
    for name in view_checks()["entries"]:
        rows = [e for e in ranked if e["entry"] == name]
        if rows:
            entry_points.append(
                {
                    "entry": name,
                    "element": rows[0]["element"],
                    "severity": rows[0]["severity"],
                    "findings": [e["id"] for e in rows],
                }
            )
    return {
        "schema_version": SCHEMA_VERSION,
        "fingerprint": fingerprint(model, facts or None, inventory or None),
        "elements": list(elements.values()),
        "edges": edges,
        "findings": findings,
        "entries": entry_points,
        "highlighted_path": highlighted,
    }
