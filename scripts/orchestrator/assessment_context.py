"""Declared context of a combined multi-repository assessment.

A combined assessment receives the same declared inputs as a single-repository
run: each selected repository's business context and known-threat
declarations, an optional run-wide ``--context`` source, the resolved
org-profile configuration and an optional requirements catalog. This module
captures them once, through the existing loaders and their rules, and keeps
every document attached to its owning repository.

* :func:`capture` reads the frozen snapshots and the run-wide sources and
  returns one bounded, schema-validated record.
* :func:`component_context` is the slice a component's STRIDE and evidence jobs
  receive: the context of the component's repositories plus run-wide context.
* :func:`write_workspace` writes the legacy sidecars the deterministic tail
  reads, so its business-context trace and requirement traces are built from
  the delivered inputs.
* :func:`attribute_trace` names the owning repository of each document in the
  workspace model's business-context trace.

Every document is untrusted data. Its text becomes field values only. It never
selects a file, a command, a source grant or an instruction. Repository-local
requirement catalogs are refused: one run-wide catalog keeps requirement IDs
unambiguous, so they need no namespace.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import validators.secret_scan as secret_scan
import yaml
from contexts import business_impact_scope, business_use_case, load_business_context
from contexts.build_requirements_contexts import build_rows
from contexts.build_stride_evidence_bundles import business_context_projection
from contexts.build_threat_modeling_context import MAX_KNOWN_THREATS_BYTES, _bounded_lines
from jsonschema import Draft202012Validator
from requirements.requirements_state import LOCAL_REPO_FILENAMES, validate_catalog
from shared._atomic_io import atomic_write_json, atomic_write_text
from validators.validate_intermediate import validate_known_threats

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = PLUGIN_ROOT / "scripts"
KNOWN_THREATS_PATH = "docs/known-threats.yaml"
LOCAL_CATALOG_PATHS = tuple(f"docs/security/{name}" for name in LOCAL_REPO_FILENAMES)
READ_LINE_LIMIT = load_business_context.READ_LINE_LIMIT
MAX_TEXT_CHARS = 1000
MAX_ITEM_CHARS = 300
MAX_ITEMS = 8
MAX_KNOWN_THREATS = 200
MAX_KNOWN_THREAT_CHARS = 1000
MAX_CATALOG_BYTES = 1_048_576
# Mirrors MAX_CLASS_VALUES, the per-component cap the single-repository
# requirements projection applies.
MAX_REQUIREMENT_ROWS = 32
SCRIPT_TIMEOUT = 120
RUN_WIDE = "run-wide context"
TEXT_FIELDS = ("business_purpose", "impact_if_compromised")
LIST_FIELDS = ("sensitive_assets", "security_obligations", "security_assumptions")
_SECTIONS = {
    "business purpose": "business_purpose",
    "impact if compromised": "impact_if_compromised",
    "sensitive assets": "sensitive_assets",
    "security obligations": "security_obligations",
    "security assumptions": "security_assumptions",
}
_KNOWN_THREAT_FIELDS = (
    "id",
    "title",
    "stride",
    "component",
    "severity",
    "status",
    "description",
    "evidence",
    "pentest_ref",
    "accepted_risk",
    "mitigation_ref",
)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
REQUIREMENTS_DESCRIPTION = (
    "Requirements the configured catalog holds this component to. Cite an id in violated_requirements only "
    "when the component's own evidence shows the requirement is broken. Where a requirement carries "
    "blueprint_guidance, that is the implementation the organisation prescribes: base remediation.steps on "
    "it and name the blueprint in remediation.blueprint."
)

_TEXT = {"type": "string", "maxLength": MAX_TEXT_CHARS}
_LIST = {
    "type": "array",
    "maxItems": MAX_ITEMS,
    "items": {"type": "string", "minLength": 1, "maxLength": MAX_ITEM_CHARS},
}
_SHA = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
_ATTRIBUTES = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "business_purpose": _TEXT,
        "impact_if_compromised": _TEXT,
        "impact_is_material": {"type": "boolean"},
        **{name: _LIST for name in LIST_FIELDS},
    },
}
SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "source_scope_sha256", "repositories", "business_context", "org_profile"],
    "properties": {
        "schema_version": {"const": 1},
        "source_scope_sha256": _SHA,
        "repositories": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["repository_id", "label", "known_threats"],
                "properties": {
                    "repository_id": {"type": "string", "minLength": 1},
                    "label": {"type": "string", "minLength": 1},
                    "known_threats": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["path", "sha256", "entries"],
                        "properties": {
                            "path": {"type": ["string", "null"]},
                            "sha256": {"anyOf": [_SHA, {"type": "null"}]},
                            "entries": {"type": "array", "maxItems": MAX_KNOWN_THREATS, "items": {"type": "object"}},
                        },
                    },
                },
            },
        },
        "business_context": {
            "type": "object",
            "additionalProperties": False,
            "required": ["skipped", "documents"],
            "properties": {
                "skipped": {"type": "boolean"},
                "documents": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "scope",
                            "repository_id",
                            "label",
                            "path",
                            "sha256",
                            "status",
                            "text",
                            "attributes",
                        ],
                        "properties": {
                            "scope": {"enum": ["repository", "run-wide"]},
                            "repository_id": {"type": ["string", "null"]},
                            "label": {"type": ["string", "null"]},
                            "path": {"type": ["string", "null"], "maxLength": 256},
                            "sha256": _SHA,
                            "status": {"enum": ["applied", "withheld"]},
                            "text": {"type": "string", "maxLength": 20_000},
                            "truncated": {"type": "boolean"},
                            "attributes": _ATTRIBUTES,
                        },
                    },
                },
            },
        },
        "org_profile": {"type": "object"},
        "requirements": {
            "type": "object",
            "additionalProperties": False,
            "required": ["sha256", "catalog_text", "resolution", "ids", "rows"],
            "properties": {
                "sha256": _SHA,
                "catalog_text": {"type": "string", "maxLength": MAX_CATALOG_BYTES},
                "resolution": {"type": "object"},
                "ids": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"type": "string", "minLength": 1, "maxLength": 128},
                },
                "rows": {"type": "array", "items": {"type": "object"}},
            },
        },
    },
}


class ContextError(ValueError):
    """Declared context cannot be delivered faithfully; the run must stop."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rstrip()
    return (cut[: cut.rfind(" ")] if " " in cut else cut).rstrip()


def _run(script: str, args: list[str], directory: Path) -> None:
    """Run an existing producer with the private directory as its output.

    ``OUTPUT_DIR`` makes the URL guard apply the run's org-profile allow-list.
    """
    env = {**os.environ, "OUTPUT_DIR": str(directory)}
    try:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / script), *args],
            text=True,
            capture_output=True,
            check=False,
            timeout=SCRIPT_TIMEOUT,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ContextError(f"{Path(script).name} timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-800:]
        raise ContextError(f"{Path(script).name} failed with exit {completed.returncode}: {detail}")


def _sections(text: str) -> dict[str, list[str]]:
    """Lines of each documented business-context section, in document order."""
    found: dict[str, list[str]] = {}
    current = None
    for line in _COMMENT_RE.sub("", text).splitlines():
        stripped = line.strip()
        if stripped.startswith("## ") or stripped.startswith("# "):
            current = _SECTIONS.get(stripped.lstrip("#").strip().lower()) if stripped.startswith("## ") else None
            if current:
                found.setdefault(current, [])
            continue
        if current:
            found[current].append(line)
    return found


def _items(lines: list[str]) -> tuple[list[str], bool]:
    """List items: one per bullet, or one per paragraph when the section has no bullets."""
    items: list[str] = []
    bulleted = any(_BULLET_RE.match(line) for line in lines)
    start = True
    for line in lines:
        if not line.strip():
            start = start or not bulleted
            continue
        if start or (bulleted and _BULLET_RE.match(line)):
            items.append(_BULLET_RE.sub("", line))
            start = False
        else:
            items[-1] += " " + line.strip()
    values = list(dict.fromkeys(value for item in items if (value := _clip(item, MAX_ITEM_CHARS))))
    return values[:MAX_ITEMS], len(values) > MAX_ITEMS


def parse_attributes(text: str) -> tuple[dict[str, Any], bool]:
    """Bounded field values of the documented sections; never an instruction.

    ``impact_is_material`` comes only from the dialog's explicit application
    impact marker, never from wording.
    """
    sections = _sections(text)
    attributes: dict[str, Any] = {}
    truncated = False
    for name in TEXT_FIELDS:
        lines = sections.get(name) or []
        value = " ".join(_BULLET_RE.sub("", line) for line in lines if line.strip())
        truncated |= len(" ".join(value.split())) > MAX_TEXT_CHARS
        if value := _clip(value, MAX_TEXT_CHARS):
            attributes[name] = value
    if use_case := business_use_case.confirmed_use_case(text):
        attributes["business_purpose"] = use_case
    impact = business_impact_scope.application_impact(text)
    if impact:
        attributes["impact_if_compromised"] = _clip(impact["impact_if_compromised"], MAX_TEXT_CHARS)
        attributes["impact_is_material"] = impact["impact_is_material"]
    for name in LIST_FIELDS:
        values, cut = _items(sections.get(name) or [])
        truncated |= cut
        if values:
            attributes[name] = values
    return attributes, truncated


def _document(scope_name: str, rid, label, path, digest: str, text: str | None) -> dict[str, Any]:
    body = text or ""
    if secret_scan.scan_text(body):
        return {
            "scope": scope_name,
            "repository_id": rid,
            "label": label,
            "path": path,
            "sha256": digest,
            "status": "withheld",
            "text": "",
            "attributes": {},
        }
    attributes, truncated = parse_attributes(body)
    return {
        "scope": scope_name,
        "repository_id": rid,
        "label": label,
        "path": path,
        "sha256": digest,
        "status": "applied",
        "text": body,
        "truncated": truncated or body.endswith("_(truncated)_"),
        "attributes": attributes,
    }


def _known_threats(root: Path) -> list[dict[str, Any]]:
    path = root / KNOWN_THREATS_PATH
    payload = path.read_bytes()
    if len(payload) > MAX_KNOWN_THREATS_BYTES:
        raise ContextError(f"{KNOWN_THREATS_PATH} exceeds {MAX_KNOWN_THREATS_BYTES} bytes")
    try:
        data = yaml.safe_load(payload.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ContextError(f"cannot parse {KNOWN_THREATS_PATH}: {exc}") from exc
    valid, errors = validate_known_threats(data)
    if not valid:
        raise ContextError(f"invalid {KNOWN_THREATS_PATH}: " + "; ".join(errors[:5]))
    if len(data["threats"]) > MAX_KNOWN_THREATS:
        raise ContextError(f"{KNOWN_THREATS_PATH} declares more than {MAX_KNOWN_THREATS} threats")
    return [
        {
            key: _clip(str(entry[key]), MAX_KNOWN_THREAT_CHARS) if entry[key] is not None else None
            for key in _KNOWN_THREAT_FIELDS
            if key in entry
        }
        for entry in data["threats"]
    ]


def _org_profile(cfg: dict[str, Any]) -> dict[str, Any]:
    """The org-profile slice resolve_config persists for a single-repository run."""
    return {
        "org_profile": cfg.get("org_profile") or {},
        "preset": cfg.get("preset"),
        "defaults": cfg.get("org_profile_defaults") or {},
        "requirements_source": cfg.get("org_profile_requirements_source"),
        "llm_context_documents": cfg.get("org_profile_context_documents") or [],
        "skill_toggles": cfg.get("org_profile_skill_toggles") or {},
        "security_coach": cfg.get("org_profile_security_coach"),
        "llm_policy": cfg.get("org_profile_llm_policy"),
    }


def _requirements(cfg: dict[str, Any], directory: Path) -> dict[str, Any]:
    override = cfg.get("requirements_url_override")
    _run(
        "requirements/fetch_requirements.py",
        [
            "--output-dir",
            str(directory),
            "--plugin-root",
            str(PLUGIN_ROOT),
            *(["--requirements", str(override)] if override else ["--require"]),
        ],
        directory,
    )
    body = (directory / ".requirements.yaml").read_bytes()
    if len(body) > MAX_CATALOG_BYTES:
        raise ContextError(f"requirements catalog exceeds {MAX_CATALOG_BYTES} bytes")
    errors, _warnings = validate_catalog(body)
    if errors:
        raise ContextError("configured requirements catalog is invalid: " + "; ".join(errors[:5]))
    catalog = yaml.safe_load(body) or {}
    ids = list(
        dict.fromkeys(
            str(row.get("id") or "").strip()
            for category in catalog.get("categories") or []
            if isinstance(category, dict)
            for row in category.get("requirements") or []
            if isinstance(row, dict) and str(row.get("id") or "").strip()
        )
    )
    if not ids:
        raise ContextError("configured requirements catalog contains no requirements")
    resolution = json.loads((directory / ".requirements-resolution.json").read_text(encoding="utf-8"))
    if not isinstance(resolution, dict):
        raise ContextError("requirements resolution is not an object")
    return {
        "sha256": _sha(body),
        "catalog_text": body.decode("utf-8"),
        "resolution": resolution,
        "ids": ids,
        "rows": build_rows(catalog),
    }


def capture(scope, cfg: dict[str, Any], directory: Path) -> dict[str, Any]:
    """Load every declared input once; fail closed when a configured one is unavailable.

    ``directory`` is controller-private run state. The run-wide context and the
    catalog are fetched into it by the existing producers. Nothing is written
    into a selected repository, and no question is asked.
    """
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    inventory = scope.inventory()
    rows = {row["repository_id"]: row for row in inventory["repositories"]}
    skip = bool(cfg.get("skip_business_context"))
    org = _org_profile(cfg)
    atomic_write_json(directory / ".org-profile-effective.json", org)
    repositories, documents = [], []
    for rid, row in sorted(rows.items(), key=lambda item: item[1]["label"]):
        repo = next(r for r in scope.repositories if r.repository_id == rid)
        if cfg.get("check_requirements") and not cfg.get("requirements_url_override"):
            local = [path for path in LOCAL_CATALOG_PATHS if path in repo.files]
            if local:
                raise ContextError(
                    f"{row['label']}:{local[0]} is a repository-local requirements catalog; "
                    "pass --requirements <src> to assess every repository against one catalog"
                )
        with scope.scanner_snapshot(rid) as root:
            source = None if skip else load_business_context.repository_source(root)
            if source is not None:
                relative = source.relative_to(root).as_posix()
                documents.append(
                    _document(
                        "repository",
                        rid,
                        row["label"],
                        relative,
                        _sha(repo.files[relative]),
                        _bounded_lines(source, READ_LINE_LIMIT),
                    )
                )
            declared = KNOWN_THREATS_PATH in repo.files
            entries = _known_threats(root) if declared else []
        repositories.append(
            {
                "repository_id": rid,
                "label": row["label"],
                "known_threats": {
                    "path": KNOWN_THREATS_PATH if declared else None,
                    "sha256": _sha(repo.files[KNOWN_THREATS_PATH]) if declared else None,
                    "entries": entries,
                },
            }
        )
    if cfg.get("business_context_source") and not skip:
        _run(
            "contexts/load_business_context.py",
            [
                "--repo-root",
                str(directory),
                "--output-dir",
                str(directory),
                "--source",
                str(cfg["business_context_source"]),
                "--run-only",
            ],
            directory,
        )
        path = directory / load_business_context.RUN_ONLY_NAME
        documents.append(
            _document("run-wide", None, None, None, _sha(path.read_bytes()), _bounded_lines(path, READ_LINE_LIMIT))
        )
    captured = {
        "schema_version": 1,
        "source_scope_sha256": inventory["scope_sha256"],
        "repositories": repositories,
        "business_context": {"skipped": skip, "documents": documents},
        "org_profile": org,
    }
    if cfg.get("check_requirements"):
        captured["requirements"] = _requirements(cfg, directory)
    Draft202012Validator(SCHEMA).validate(captured)
    return captured


def requirement_ids(captured: dict[str, Any]) -> frozenset[str]:
    """IDs a finding may cite; empty without a configured catalog."""
    return frozenset((captured.get("requirements") or {}).get("ids") or ())


def _applied(captured: dict[str, Any], repository_ids) -> list[dict[str, Any]]:
    """Applicable documents: the owners' in label order, run-wide context last."""
    documents = [d for d in captured["business_context"]["documents"] if d["status"] == "applied"]
    owned = [d for d in documents if d["scope"] == "repository" and d["repository_id"] in set(repository_ids)]
    return owned + [d for d in documents if d["scope"] == "run-wide"]


def _merged(documents: list[dict[str, Any]]) -> dict[str, Any]:
    """One component's attributes; an owning repository's text is narrower than run-wide text."""
    attributes: dict[str, Any] = {}
    for name in TEXT_FIELDS:
        sources = [d for d in documents if d["scope"] == "repository" and name in d["attributes"]] or [
            d for d in documents if name in d["attributes"]
        ]
        if sources:
            values = list(dict.fromkeys(d["attributes"][name] for d in sources))
            attributes[name] = _clip(" / ".join(values), MAX_TEXT_CHARS)
            if name == "impact_if_compromised":
                declared = [d["attributes"].get("impact_is_material") for d in sources]
                if True in declared:
                    attributes["impact_is_material"] = True
                elif declared and all(value is False for value in declared):
                    attributes["impact_is_material"] = False
    for name in LIST_FIELDS:
        values = list(dict.fromkeys(item for d in documents for item in d["attributes"].get(name, [])))
        if values:
            attributes[name] = values[:MAX_ITEMS]
    return attributes


def _source(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "scope": document["scope"],
        "repository": document["label"],
        "path": document["path"],
        "sha256": document["sha256"],
    }


def component_context(captured: dict[str, Any], component: dict[str, Any]) -> dict[str, Any]:
    """The bounded declared context one component's STRIDE and evidence jobs receive.

    A no-harm declaration is withheld from the rating exactly as the
    single-repository bundle withholds it; triage still reads it.
    """
    owners = set(component["repository_ids"])
    documents = _applied(captured, owners)
    projection = business_context_projection(_merged(documents) or None, component["id"])
    context: dict[str, Any] = {
        "business_context": {
            "attributes": projection["attributes"] if projection else {},
            "sources": [_source(d) for d in documents],
        },
        "known_threats": [
            {"repository": row["label"], **entry}
            for row in captured["repositories"]
            if row["repository_id"] in owners
            for entry in row["known_threats"]["entries"]
        ],
    }
    requirements = captured.get("requirements")
    if requirements:
        rows = requirements["rows"]
        context["requirements"] = {
            "description": REQUIREMENTS_DESCRIPTION,
            "items": copy.deepcopy(rows[:MAX_REQUIREMENT_ROWS]),
            "limits": {
                "original_count": len(rows),
                "retained_count": min(len(rows), MAX_REQUIREMENT_ROWS),
                "omitted_count": max(0, len(rows) - MAX_REQUIREMENT_ROWS),
            },
        }
    return context


def _label(document: dict[str, Any]) -> str:
    return RUN_WIDE if document["scope"] == "run-wide" else f"{document['label']}/{document['path']}"


def write_workspace(captured: dict[str, Any], workspace: Path, names, *, components: dict[str, Any]) -> list[str]:
    """Write the sidecars the legacy tail reads; return the written names.

    ``components`` is the finalized qualified inventory. The combined
    ``.business-context-input.md`` is the bounded text the analysis read, each
    document under a provenance line; the component map carries field values
    only, for the trace, ranking and triage.
    """
    for row in captured["repositories"]:
        if names.prefix.get(row["repository_id"]) != row["label"]:
            raise ContextError("Captured context belongs to another repository namespace")
    written = [".org-profile-effective.json"]
    atomic_write_json(workspace / ".org-profile-effective.json", captured["org_profile"])
    documents = _applied(captured, set(names.prefix))
    if documents:
        parts = []
        for document in documents:
            label = load_business_context._sanitize_provenance(_label(document))
            parts.append(
                f"<!-- appsec-advisor: business context from {label} sha256={document['sha256']} -->\n\n"
                + document["text"].rstrip()
                + "\n"
            )
        atomic_write_text(workspace / load_business_context.RUN_ONLY_NAME, "\n".join(parts))
        written.append(load_business_context.RUN_ONLY_NAME)
        analyst = {}
        for component in components["components"]:
            attributes = _merged(_applied(captured, component["repository_ids"]))
            if attributes:
                analyst[component["id"]] = {"business_context": attributes}
        schema = json.loads((PLUGIN_ROOT / "schemas/stride-analyst-context.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(analyst)
        atomic_write_json(workspace / ".stride-analyst-context.json", analyst)
        written.append(".stride-analyst-context.json")
    requirements = captured.get("requirements")
    if requirements:
        body = requirements["catalog_text"].encode("utf-8")
        if _sha(body) != requirements["sha256"]:
            raise ContextError("Captured requirements catalog changed after capture")
        (workspace / ".requirements.yaml").write_bytes(body)
        atomic_write_json(workspace / ".requirements-resolution.json", requirements["resolution"])
        written += [".requirements.yaml", ".requirements-resolution.json"]
    return written


def attribute_trace(captured: dict[str, Any], model: dict[str, Any]) -> None:
    """Name each applied document's owner in the workspace model's trace.

    The digest stays the one of the combined input the analysis read. A
    run-wide source keeps the run-only kind: it is not stored in any repository.
    """
    trace = model.get("business_context_trace")
    if not isinstance(trace, dict) or trace.get("status") != "applied":
        return
    documents = [d for d in captured["business_context"]["documents"] if d["status"] == "applied"]
    source = "; ".join(_label(d) for d in documents)
    if len(source) > 256:
        source = f"{len(documents)} business-context documents"
    trace["source"] = source
    trace["source_kind"] = "run_only" if any(d["scope"] == "run-wide" for d in documents) else "repository"
    model["meta"]["business_context_source"] = source
