#!/usr/bin/env python3
"""contexts/resolve_analyst_catalog.py — effective packages of one analyst job.

Resolves the question packages and methodology profiles an invoked analysis
uses, and the limits it runs under. The packaged core question set always
loads. Further packages come only from selections the caller authorizes, each
with an authority:

    core > org_required > ci_pinned > org_default > explicit

A selection names a packaged package as ``<namespace>/<id>@<version>`` or a
local package file by absolute path, optionally pinned with
``#sha256=<hex>``. In CI every selection must come from trusted configuration
(``explicit`` is refused), and every package file must be pinned and resolve
outside the checkout under review, so a change cannot choose the packages
that assess it. Packaged packages ship with the plugin release. Packages are
never downloaded.

The same package selected twice keeps its strongest authority. Two different
contents under one identity, a version mismatch, a digest mismatch, a missing
or invalid package, or more packages than the limit reject the job. Entries
are identified as ``<package id>:<entry id>``, so packages cannot overwrite
each other's entries.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PLUGIN_ROOT / "data"
SCHEMA_DIR = PLUGIN_ROOT / "schemas"
LIMITS_FILE = DATA_DIR / "analyst-limits.yaml"
CORE_ID = "appsec/core"
PACKAGED = {
    CORE_ID: DATA_DIR / "analyst-questions.yaml",
    "tmm/threat-modeling-manifesto": DATA_DIR / "analyst-methods" / "threat-modeling-manifesto.yaml",
}
AUTHORITY_RANK = {"core": 0, "org_required": 1, "ci_pinned": 2, "org_default": 3, "explicit": 4}
REQUIRED_AUTHORITIES = frozenset({"core", "org_required", "ci_pinned"})
_SCHEMAS = {"questions": "analyst-catalog.schema.json", "methodology": "analyst-methodology.schema.json"}
_REF_RE = re.compile(r"^(?P<id>[a-z0-9][a-z0-9-]{0,39}/[a-z0-9][a-z0-9-]{0,63})@(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$")
_PIN_RE = re.compile(r"^(?P<spec>.+)#sha256=(?P<sha>[0-9a-f]{64})$")


class CatalogError(Exception):
    """The requested package selection cannot be resolved."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class Selection:
    spec: str
    authority: str


def _schema_errors(schema_name: str, data: object, label: str) -> list[str]:
    try:
        from jsonschema import Draft202012Validator
    except ModuleNotFoundError:
        return ["jsonschema not installed; analyst packages fail closed"]
    schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    return [
        f"{label}: {'/'.join(str(p) for p in err.path) or '<root>'}: violates {err.validator}"
        for err in sorted(Draft202012Validator(schema).iter_errors(data), key=lambda e: list(e.path))
    ]


def _read_bounded(path: Path, max_bytes: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise CatalogError([f"{path.name}: not a regular file"])
        body = handle.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise CatalogError([f"{path.name}: exceeds the package size limit"])
    return body


def load_limits(path: Path = LIMITS_FILE) -> dict[str, int]:
    """Return the enforced limits as ``{name: value}``."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    errors = _schema_errors("analyst-limits.schema.json", data, path.name)
    if errors:
        raise CatalogError(errors)
    return {name: entry["value"] for name, entry in data["limits"].items()}


def load_package(path: Path, max_kib: int) -> tuple[dict, str]:
    """Read and validate one package file; return (document, sha256)."""
    try:
        body = _read_bounded(path, max_kib * 1024)
    except FileNotFoundError:
        raise CatalogError([f"{path.name}: package not found"]) from None
    except OSError:
        raise CatalogError([f"{path.name}: package unreadable or a symlink"]) from None
    try:
        data = yaml.safe_load(body)
    except yaml.YAMLError:
        raise CatalogError([f"{path.name}: invalid YAML"]) from None
    kind = data.get("kind") if isinstance(data, dict) else None
    if kind not in _SCHEMAS:
        raise CatalogError([f"{path.name}: unknown package kind"])
    errors = _schema_errors(_SCHEMAS[kind], data, path.name)
    if not errors:
        errors = _semantic_errors(data, path.name)
    if errors:
        raise CatalogError(errors)
    return data, hashlib.sha256(body).hexdigest()


def _semantic_errors(data: dict, label: str) -> list[str]:
    errors = []
    groups = [data["questions"]] if data["kind"] == "questions" else [data["principles"], data["criteria"]]
    if any(len({e["id"] for e in group}) != len(group) for group in groups):
        errors.append(f"{label}: duplicate entry id")
    if data["kind"] == "methodology":
        principles = {p["id"] for p in data["principles"]}
        if any(ref not in principles for c in data["criteria"] for ref in c["principles"]):
            errors.append(f"{label}: a criterion names an unknown principle")
    return errors


def _locate(selection: Selection, repo_root: Path | None, ci: bool) -> tuple[Path, str | None, str | None]:
    """Return (path, expected version or None, expected sha256 or None)."""
    spec, sha = selection.spec, None
    pinned = _PIN_RE.fullmatch(spec)
    if pinned:
        spec, sha = pinned["spec"], pinned["sha"]
    ref = _REF_RE.fullmatch(spec)
    if ci and ref is None and sha is None and selection.authority != "core":
        raise CatalogError([f"{spec}: CI package files must pin a sha256 digest"])
    if ref:
        if ref["id"] not in PACKAGED:
            raise CatalogError([f"{ref['id']}: no packaged package with this id"])
        return PACKAGED[ref["id"]], ref["version"], sha
    path = Path(spec)
    if not path.is_absolute() or os.path.normpath(spec) != spec:
        raise CatalogError([f"{spec}: a local package needs a canonical absolute path"])
    if ci and repo_root is not None and selection.authority != "core":
        resolved, root = path.resolve(), Path(repo_root).resolve()
        if resolved == root or root in resolved.parents:
            raise CatalogError([f"{path.name}: CI packages must come from outside the checkout under review"])
    return path, None, sha


def resolve(
    selections: list[Selection],
    limits: dict[str, int],
    repo_root: Path | None = None,
    ci: bool = False,
) -> dict:
    """Resolve the effective packages of one job."""
    errors: list[str] = []
    chosen: dict[str, dict] = {}
    for selection in [Selection(str(PACKAGED[CORE_ID]), "core"), *selections]:
        if selection.authority not in AUTHORITY_RANK:
            errors.append(f"{selection.spec}: unknown authority")
            continue
        if ci and selection.authority == "explicit":
            errors.append(f"{selection.spec}: CI accepts packages only from trusted configuration")
            continue
        try:
            path, version, sha = _locate(selection, repo_root, ci)
            data, digest = load_package(path, limits["package_kib"])
        except CatalogError as exc:
            errors += exc.errors
            continue
        if version is not None and data["version"] != version:
            errors.append(f"{data['id']}: version {version} requested, {data['version']} available")
            continue
        if sha is not None and digest != sha:
            errors.append(f"{data['id']}: content digest does not match the pinned digest")
            continue
        previous = chosen.get(data["id"])
        if previous is not None and previous["sha256"] != digest:
            errors.append(f"{data['id']}: selected with conflicting definitions")
            continue
        if previous is None or AUTHORITY_RANK[selection.authority] < AUTHORITY_RANK[previous["authority"]]:
            chosen[data["id"]] = {"data": data, "sha256": digest, "authority": selection.authority}
    if len(chosen) > limits["packages"]:
        errors.append(f"{len(chosen)} packages exceed the limit of {limits['packages']}")
    if errors:
        raise CatalogError(errors)
    ordered = sorted(chosen.values(), key=lambda p: (AUTHORITY_RANK[p["authority"]], p["data"]["id"]))
    packages = [
        {
            "id": p["data"]["id"],
            "kind": p["data"]["kind"],
            "version": p["data"]["version"],
            "sha256": p["sha256"],
            "authority": p["authority"],
        }
        for p in ordered
    ]
    questions, criteria = [], []
    for p in ordered:
        data = p["data"]
        if data["kind"] == "questions":
            questions += [dict(q, ref=f"{data['id']}:{q['id']}", authority=p["authority"]) for q in data["questions"]]
        else:
            principles = {pr["id"]: pr["statement"] for pr in data["principles"]}
            criteria += [
                dict(c, ref=f"{data['id']}:{c['id']}", principle_text=[principles[r] for r in c["principles"]])
                for c in data["criteria"]
            ]
    receipts = [
        dict(entry, title=p["data"]["title"], provenance=p["data"]["provenance"])
        for entry, p in zip(packages, ordered, strict=True)
    ]
    fingerprint = hashlib.sha256(json.dumps(packages, sort_keys=True).encode()).hexdigest()
    return {
        "packages": packages,
        "receipts": receipts,
        "questions": questions,
        "criteria": criteria,
        "fingerprint": fingerprint,
    }


def select_questions(resolved: dict, limit: int) -> dict:
    """Deliver questions up to ``limit`` in authority order and record the rest.

    Applicability is judged per delivered question by the analysis and recorded
    in its coverage; a question omitted here was never considered. Omitting a
    question of a required package leaves required coverage incomplete.
    """
    ordered = resolved["questions"]
    selected, rest = ordered[:limit], ordered[limit:]
    omitted = [{"ref": q["ref"], "reason": "question limit reached"} for q in rest]
    return {
        "selected": selected,
        "omitted": omitted,
        "required_complete": not any(q["authority"] in REQUIRED_AUTHORITIES for q in rest),
    }
