#!/usr/bin/env python3
"""Build and validate bounded component-local evidence for STRIDE dispatch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from _atomic_io import atomic_write_text
from reclassify_components import _glob_to_regex

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-evidence-bundle.schema.json"
BUSINESS_CONTEXT_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-component-business-context.schema.json"
ARCHITECTURE_CONTEXT_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-component-architecture-context.schema.json"
SECURITY_CONTEXT_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-component-security-context.schema.json"
REGISTRY_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-repository-registry.schema.json"
RELATED_REPOS_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "related-repos.schema.yaml"

MAX_BUNDLE_BYTES = 65_536
MAX_ESTIMATED_TOKENS = 16_384
MAX_SOURCE_LINES = 400
MAX_SOURCE_SLICES = 24
MAX_SLICE_LINES = 40
MAX_CLASS_VALUES = 32
MAX_VALUE_CHARS = 4096
MAX_ROUTING_PATHS = 16
MAX_ROUTING_PATH_CHARS = 500
MAX_FOCUS_ENUM_ENTRIES = 100_000
MAX_SUPERSEDED_EVIDENCE_PATHS = 8
BUSINESS_CONTEXT_FIELDS = (
    "business_purpose",
    "impact_if_compromised",
    "sensitive_assets",
    "security_obligations",
    "security_assumptions",
)
BUSINESS_CONTEXT_TEXT_FIELDS = {"business_purpose", "impact_if_compromised"}
MAX_BUSINESS_CONTEXT_TEXT_CHARS = 1000
MAX_BUSINESS_CONTEXT_ITEMS = 8
MAX_BUSINESS_CONTEXT_ITEM_CHARS = 300
ARCHITECTURE_CONTEXT_FIELDS = (
    "security_role",
    "exposed_interfaces",
    "security_dependencies",
    "deployment_constraints",
    "architecture_assumptions",
)
ARCHITECTURE_CONTEXT_TEXT_FIELDS = {"security_role"}

EVIDENCE_CLASSES = (
    "interfaces",
    "cross_repo",
    "recon_signals",
)
SECURITY_CONTEXT_SPECS = {
    "actors.component_context": ("relevant_actors", "actors", "actors-context.json"),
    "prior_run.component_findings": ("prior_findings", "prior_findings", "prior-findings-context.json"),
    "requirements.component_context": (
        "requirements_violations",
        "requirements",
        "requirements-context.json",
    ),
    "threats.known_threats": ("known_threats", "known_threats", "known-threats-context.json"),
    "trust_boundaries.component_context": (
        "trust_boundaries",
        "trust_boundaries",
        "trust-boundaries-context.json",
    ),
}
INLINE_SECURITY_CONTEXT_SPECS = {
    "controls.component_context": ("controls", "controls-context.json"),
}
INLINE_KNOWN_THREATS_FIELD = "known_vulns"
DETACHED_SECURITY_CONTEXT_CLASSES = (*tuple(spec[1] for spec in SECURITY_CONTEXT_SPECS.values()), "controls")
ALL_EVIDENCE_CLASSES = (*EVIDENCE_CLASSES, *DETACHED_SECURITY_CONTEXT_CLASSES)
INDEX_TO_CLASS = {
    "prior_findings": "prior_findings",
    "known_threats": "known_threats",
    "cross_repo": "cross_repo",
    "requirements_violations": "requirements",
    "relevant_actors": "actors",
    "trust_boundaries": "trust_boundaries",
}
SIGNAL_FILES = (
    ("recon-pattern", ".recon-patterns.json"),
    ("source-auth", ".source-auth-findings.json"),
    ("config-scan", ".config-scan-findings.json"),
    ("sca-practice", ".sca-practice-findings.json"),
    ("known-bad-library", ".known-bad-libs-findings.json"),
)


class BundleError(RuntimeError):
    """A stale, unsafe, malformed, or oversized evidence bundle."""


class RoutingHintError(BundleError):
    """A focus or exclude hint the builder cannot honor for this component.

    Routing is prioritization, not evidence, so this one class is what
    ``build_all`` is allowed to contain by rebuilding without the hints. Every
    other ``BundleError`` states that the bundle itself is invalid and must
    stay fatal: retrying it without routing would turn a producer defect into a
    silently degraded artifact.
    """


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_under(root: Path, relative: str) -> Path:
    rel = Path(relative)
    if not relative or "\\" in relative or rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
        raise BundleError(f"unsafe repository-relative path: {relative!r}")
    root = root.resolve()
    resolved = (root / rel).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise BundleError(f"path escapes registered repository root: {relative!r}") from exc
    return resolved


def _output_artifact(output_dir: Path, value: str) -> Path:
    """Resolve a legacy absolute/relative index while enforcing containment."""
    output_dir = output_dir.resolve()
    candidate = Path(value)
    resolved = candidate.resolve() if candidate.is_absolute() else _canonical_under(output_dir, value)
    try:
        resolved.relative_to(output_dir)
    except ValueError as exc:
        raise BundleError(f"component index escapes output directory: {value!r}") from exc
    return resolved


def _component_context_directory(output_dir: Path, component_id: str) -> Path:
    """Resolve one deterministic dispatch directory without following symlinks."""
    raw = output_dir / ".dispatch-context" / component_id
    resolved = _canonical_under(output_dir, f".dispatch-context/{component_id}")
    if resolved != raw or raw.is_symlink():
        raise BundleError(f"component dispatch directory is symlinked: {component_id}")
    if raw.exists() and not raw.is_dir():
        raise BundleError(f"component dispatch path is not a directory: {component_id}")
    return raw


def _git_output(repo_root: Path, *args: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return b""
    return completed.stdout if completed.returncode == 0 else b""


def repository_fingerprint(
    repo_root: Path,
    *,
    cited_paths: Iterable[str],
    excluded_root: Path | None = None,
) -> tuple[str, str]:
    """Bind a repository to HEAD and the exact bytes of the files a bundle cites.

    Scope is the evidence-bearing set, never the whole worktree. A bundle makes
    no claim about a file it does not cite, so an unrelated edit during the
    STRIDE phase — an editor save, a watcher, a build in the analyzed
    repository — must not invalidate it. A change to a cited file still does.
    """
    repo_root = repo_root.resolve()
    commit_raw = _git_output(repo_root, "rev-parse", "HEAD").strip().lower()
    commit = commit_raw.decode("ascii", errors="ignore")
    if len(commit) < 40 or any(char not in "0123456789abcdef" for char in commit):
        commit = "unversioned"

    digest = hashlib.sha256()
    for relative in sorted(dict.fromkeys(cited_paths)):
        digest.update(relative.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        try:
            path = _canonical_under(repo_root, relative)
            if excluded_root is not None and _is_within(path, excluded_root):
                # Run-owned output is not repository evidence; hashing it would
                # let the run invalidate its own bundles as it writes.
                digest.update(b"<excluded>")
            elif path.is_file():
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
            else:
                digest.update(b"<absent>")
        except (BundleError, OSError, UnicodeError):
            digest.update(b"<unreadable>")
        digest.update(b"\0")
    return commit, digest.hexdigest()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return False
    return True


def bundle_citation_paths(
    source_slices: Any,
    evidence: Any,
    registry: dict[str, Path],
) -> dict[str, list[str]]:
    """Group the files a bundle makes claims about, by repository.

    Builder and validator both derive this from the bundle's own admitted
    content — the bounded evidence and the retained slices — so the two sides
    cannot disagree about what was fingerprinted.
    """
    cited: dict[str, set[str]] = {}
    if isinstance(source_slices, list):
        for row in source_slices:
            if not isinstance(row, dict):
                continue
            repository_id = row.get("repository_id")
            path = row.get("path")
            if isinstance(repository_id, str) and isinstance(path, str):
                cited.setdefault(repository_id, set()).add(path)
    for path in _referenced_primary_paths(evidence):
        cited.setdefault("primary", set()).add(path)

    resolved: dict[str, list[str]] = {}
    for repository_id, paths in cited.items():
        root = registry.get(repository_id)
        if root is None:
            continue
        keep: set[str] = set()
        for relative in paths:
            try:
                _canonical_under(root, relative)
            except BundleError:
                continue
            keep.add(relative.rstrip("/"))
        resolved[repository_id] = sorted(keep)
    return resolved


def _declared_related_repositories(repo_root: Path) -> dict[str, str]:
    config = repo_root / "docs" / "related-repos.yaml"
    if not config.is_file():
        return {}
    try:
        import yaml
        from jsonschema import Draft202012Validator, SchemaError
    except ImportError as exc:
        raise BundleError("jsonschema and PyYAML are required to validate related repositories") from exc
    try:
        payload = yaml.safe_load(config.read_text(encoding="utf-8"))
        schema = yaml.safe_load(RELATED_REPOS_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except (OSError, ValueError, yaml.YAMLError, SchemaError) as exc:
        raise BundleError(f"related repository declaration is unreadable: {exc}") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path))
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise BundleError(f"related repository declaration failed schema validation: {detail}")
    related = payload.get("related", []) if isinstance(payload, dict) else []
    declared: dict[str, str] = {}
    for row in related:
        name = str(row["name"])
        if name in declared:
            raise BundleError(f"related repository declaration contains duplicate name: {name!r}")
        declared[name] = str(row["threat_model"])
    return declared


def _repository_id(name: str, resolved_model: Path, used: set[str]) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "related"
    base = base[:64].rstrip("-") or "related"
    candidate = base
    if candidate == "primary" or candidate in used:
        suffix = hashlib.sha256(f"{name}\0{resolved_model}".encode()).hexdigest()[:8]
        candidate = f"{base[:55].rstrip('-')}-{suffix}"
    if candidate == "primary" or candidate in used:
        raise BundleError(f"cannot allocate a unique related repository id for {name!r}")
    used.add(candidate)
    return candidate


def repository_registry_document(repo_root: Path) -> dict[str, Any]:
    """Derive the exact local related-repository registry from declarations."""
    repo_root = repo_root.resolve()
    rows: list[dict[str, str]] = []
    used = {"primary"}
    registered_roots = {repo_root}
    for name, declared in sorted(_declared_related_repositories(repo_root).items()):
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", declared):
            continue
        declared_path = Path(declared)
        declared_path = (
            declared_path.resolve() if declared_path.is_absolute() else (repo_root / declared_path).resolve()
        )
        if not declared_path.is_file():
            continue
        root_raw = _git_output(declared_path.parent, "rev-parse", "--show-toplevel").strip()
        if not root_raw:
            continue
        try:
            related_root = Path(root_raw.decode("utf-8")).resolve()
            declared_path.relative_to(related_root)
        except (UnicodeError, ValueError):
            continue
        if related_root in registered_roots:
            raise BundleError(f"related repository declaration reuses a registered git root: {related_root}")
        registered_roots.add(related_root)
        repo_id = _repository_id(name, declared_path, used)
        rows.append(
            {
                "repository_id": repo_id,
                "kind": "related",
                "root": str(related_root),
                "declared_name": name,
                "declared_threat_model": str(declared_path),
            }
        )
    return {"schema_version": 1, "repositories": rows}


def write_repository_registry(repo_root: Path, registry_path: Path) -> dict[str, Any]:
    """Write the controller-owned registry and validate its exact bytes."""
    payload = repository_registry_document(repo_root)
    registry_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    load_repository_registry(repo_root, registry_path)
    return payload


def load_repository_registry(repo_root: Path, registry_path: Path | None = None) -> dict[str, Path]:
    """Load the controller-owned registry and verify every related declaration."""
    registry: dict[str, Path] = {"primary": repo_root.resolve()}
    if registry_path is None:
        return registry
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"repository registry is unreadable: {exc}") from exc
    try:
        schema = json.loads(REGISTRY_SCHEMA_PATH.read_text(encoding="utf-8"))
        errors = sorted(_load_validator()(schema).iter_errors(payload), key=lambda item: list(item.path))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"repository registry schema is unreadable: {exc}") from exc
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise BundleError(f"repository registry schema validation failed: {detail}")
    expected = repository_registry_document(repo_root)
    if payload != expected:
        raise BundleError("repository registry does not match the controller-derived local declarations")

    for row in payload["repositories"]:
        repo_id = row.get("repository_id")
        related_root = Path(str(row.get("root"))).resolve()
        registry[repo_id] = related_root
    return registry


def _record(source: str, value: Any) -> dict[str, Any]:
    rendered = value if isinstance(value, str) else _canonical_bytes(value).decode("utf-8")
    original = rendered
    truncated = len(rendered) > MAX_VALUE_CHARS
    if truncated:
        rendered = rendered[:MAX_VALUE_CHARS]
    record = {
        "source": source[:200],
        "value": rendered,
        "content_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest(),
        "truncated": truncated,
    }
    if truncated:
        record["original_chars"] = len(original)
    return record


def _rows(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("findings", "threats", "entries", "actors", "trust_boundaries", "violations", "items"):
            if isinstance(value.get(key), list):
                return value[key]
        return [{key: value[key]} for key in sorted(value)]
    return [value]


def _bounded_records(source: str, values: list[Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    records = sorted((_record(source, value) for value in values), key=lambda row: _canonical_bytes(row))
    retained = records[:MAX_CLASS_VALUES]
    return retained, {"original": len(records), "value_truncations": sum(row["truncated"] for row in retained)}


def _render_security_context(value: dict[str, Any]) -> bytes:
    previous: tuple[int, int] | None = None
    for _ in range(10):
        rendered = _canonical_bytes(value) + b"\n"
        current = (len(rendered), (len(rendered) + 3) // 4)
        value["limits"]["serialized_bytes"], value["limits"]["estimated_tokens"] = current
        if current == previous:
            return _canonical_bytes(value) + b"\n"
        previous = current
    raise BundleError("component security-context size metadata did not converge")


def _finish_security_context_projection(
    *,
    component_id: str,
    context_id: str,
    source: dict[str, Any],
    record_source: str,
    rows: list[Any],
) -> tuple[dict[str, Any], bytes] | None:
    if not rows:
        return None
    records, stats = _bounded_records(record_source, rows)
    value = {
        "schema_version": 1,
        "component_id": component_id,
        "context_id": context_id,
        "source": source,
        "records": records,
        "limits": {
            "original_count": stats["original"],
            "retained_count": len(records),
            "omitted_count": stats["original"] - len(records),
            "value_truncations": stats["value_truncations"],
            "serialized_bytes": 1,
            "estimated_tokens": 1,
        },
    }
    while True:
        payload = _render_security_context(value)
        if len(payload) <= MAX_BUNDLE_BYTES and value["limits"]["estimated_tokens"] <= MAX_ESTIMATED_TOKENS:
            break
        if len(records) <= 1:
            raise BundleError(f"component security-context metadata exceeds {MAX_BUNDLE_BYTES} bytes")
        records.pop()
        value["limits"]["retained_count"] = len(records)
        value["limits"]["omitted_count"] = stats["original"] - len(records)
        value["limits"]["value_truncations"] = sum(record["truncated"] for record in records)
    validate_security_context_bytes(
        payload,
        expected_component_id=component_id,
        expected_context_id=context_id,
    )
    return value, payload


def component_security_context_projection(
    output_dir: Path,
    component: dict[str, Any],
    *,
    index_name: str,
    context_id: str,
) -> tuple[dict[str, Any], bytes] | None:
    """Project one component index independently from the required evidence bundle."""
    component_id = component["component_id"]
    source_value = (component.get("index_paths") or {}).get(index_name)
    if source_value in (None, "none"):
        return None
    source_path = _output_artifact(output_dir, str(source_value))
    try:
        source_payload = source_path.read_bytes()
        source_document = json.loads(source_payload)
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"validated component index is unreadable: {source_value}: {exc}") from exc
    rows = _rows(source_document)
    relative_source = source_path.relative_to(output_dir.resolve()).as_posix()
    return _finish_security_context_projection(
        component_id=component_id,
        context_id=context_id,
        source={
            "kind": "component_index",
            "artifact_path": relative_source,
            "artifact_sha256": hashlib.sha256(source_payload).hexdigest(),
            "content_sha256": hashlib.sha256(_canonical_bytes(rows)).hexdigest(),
        },
        record_source=index_name,
        rows=rows,
    )


def component_inline_security_context_projection(
    component: dict[str, Any],
    *,
    field_name: str,
    context_id: str,
) -> tuple[dict[str, Any], bytes] | None:
    """Project one component manifest field independently from the evidence bundle."""
    rows = _rows(component.get(field_name))
    return _finish_security_context_projection(
        component_id=component["component_id"],
        context_id=context_id,
        source={
            "kind": "component_manifest",
            "manifest_field": field_name,
            "content_sha256": hashlib.sha256(_canonical_bytes(rows)).hexdigest(),
        },
        record_source=field_name,
        rows=rows,
    )


def component_known_threats_projection(
    output_dir: Path,
    component: dict[str, Any],
) -> tuple[dict[str, Any], bytes] | None:
    """Merge analyst candidates and an optional team index into one route.

    ``known_vulns`` was historically left inline in the dispatch manifest. In
    context-v2 the manifest is deliberately not delivered to analyzers, so
    those high-value candidates vanished despite being produced correctly.
    This projector keeps the semantic ``threats.known_threats`` route singular
    while preserving the provenance of both possible producers.
    """
    component_id = component["component_id"]
    inline_rows = _rows(component.get(INLINE_KNOWN_THREATS_FIELD))
    index_name, _evidence_class, _filename = SECURITY_CONTEXT_SPECS["threats.known_threats"]
    source_value = (component.get("index_paths") or {}).get(index_name)
    index_rows: list[Any] = []
    source: dict[str, Any]
    if source_value not in (None, "none"):
        source_path = _output_artifact(output_dir, str(source_value))
        try:
            source_payload = source_path.read_bytes()
            index_rows = _rows(json.loads(source_payload))
        except (OSError, json.JSONDecodeError) as exc:
            raise BundleError(f"validated component index is unreadable: {source_value}: {exc}") from exc
        source = {
            "kind": "component_index_and_manifest" if inline_rows else "component_index",
            "artifact_path": source_path.relative_to(output_dir.resolve()).as_posix(),
            "artifact_sha256": hashlib.sha256(source_payload).hexdigest(),
        }
        if inline_rows:
            source["manifest_field"] = INLINE_KNOWN_THREATS_FIELD
    else:
        source = {
            "kind": "component_manifest",
            "manifest_field": INLINE_KNOWN_THREATS_FIELD,
        }
    rows = [*index_rows, *inline_rows]
    source["content_sha256"] = hashlib.sha256(_canonical_bytes(rows)).hexdigest()
    return _finish_security_context_projection(
        component_id=component_id,
        context_id="threats.known_threats",
        source=source,
        record_source="known_threats",
        rows=rows,
    )


def validate_security_context_bytes(
    payload: bytes,
    *,
    expected_component_id: str | None = None,
    expected_context_id: str | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    if expected_sha256 and hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise BundleError("component security-context fingerprint does not match the manifest")
    try:
        value = json.loads(payload)
        schema = json.loads(SECURITY_CONTEXT_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"component security-context projection/schema is unreadable: {exc}") from exc
    errors = sorted(_load_validator()(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise BundleError(f"component security-context projection schema validation failed: {detail}")
    if expected_component_id and value["component_id"] != expected_component_id:
        raise BundleError("component security-context component id does not match its dispatch entry")
    if expected_context_id and value["context_id"] != expected_context_id:
        raise BundleError("component security-context route does not match its dispatch entry")
    limits = value["limits"]
    records = value["records"]
    if limits["retained_count"] != len(records):
        raise BundleError("component security-context retained count is stale")
    if limits["original_count"] != limits["retained_count"] + limits["omitted_count"]:
        raise BundleError("component security-context omission count is stale")
    if limits["value_truncations"] != sum(record["truncated"] for record in records):
        raise BundleError("component security-context truncation count is stale")
    if limits["serialized_bytes"] != len(payload) or limits["estimated_tokens"] != (len(payload) + 3) // 4:
        raise BundleError("component security-context size metadata is stale")
    for record in records:
        if (
            not record["truncated"]
            and record["content_sha256"] != hashlib.sha256(record["value"].encode("utf-8")).hexdigest()
        ):
            raise BundleError("component security-context record fingerprint is stale")
    return value


def _bound_component_security_contexts(
    projections: dict[str, tuple[dict[str, Any], bytes] | None],
) -> dict[str, tuple[dict[str, Any], bytes] | None]:
    """Keep independently selectable projections within the former shared budget."""
    while True:
        present = {context_id: projection for context_id, projection in projections.items() if projection is not None}
        total_bytes = sum(len(projection[1]) for projection in present.values())
        total_tokens = sum(projection[0]["limits"]["estimated_tokens"] for projection in present.values())
        if total_bytes <= MAX_BUNDLE_BYTES and total_tokens <= MAX_ESTIMATED_TOKENS:
            return projections
        candidates = {
            context_id: projection for context_id, projection in present.items() if len(projection[0]["records"]) > 1
        }
        if not candidates:
            raise BundleError("component security-context projections exceed their aggregate admission budget")
        context_id, (value, _payload) = max(
            candidates.items(),
            key=lambda item: (len(item[1][1]), item[0]),
        )
        value["records"].pop()
        limits = value["limits"]
        limits["retained_count"] = len(value["records"])
        limits["omitted_count"] = limits["original_count"] - limits["retained_count"]
        limits["value_truncations"] = sum(record["truncated"] for record in value["records"])
        payload = _render_security_context(value)
        validate_security_context_bytes(
            payload,
            expected_component_id=value["component_id"],
            expected_context_id=context_id,
        )
        projections[context_id] = (value, payload)


def component_security_context_projections(
    output_dir: Path,
    component: dict[str, Any],
) -> dict[str, tuple[dict[str, Any], bytes] | None]:
    """Build all split security contexts under their shared admission budget."""
    projections = {
        context_id: component_security_context_projection(
            output_dir,
            component,
            index_name=index_name,
            context_id=context_id,
        )
        for context_id, (index_name, _evidence_class, _filename) in SECURITY_CONTEXT_SPECS.items()
        if context_id != "threats.known_threats"
    }
    projections["threats.known_threats"] = component_known_threats_projection(output_dir, component)
    projections.update(
        {
            context_id: component_inline_security_context_projection(
                component,
                field_name=field_name,
                context_id=context_id,
            )
            for context_id, (field_name, _filename) in INLINE_SECURITY_CONTEXT_SPECS.items()
        }
    )
    return _bound_component_security_contexts(projections)


def business_context_projection(value: Any, component_id: str) -> dict[str, Any] | None:
    """Normalize one independently selectable human-facing context projection."""
    if value in (None, {}):
        attributes: dict[str, Any] = {}
    elif not isinstance(value, dict):
        raise BundleError(f"business_context for {component_id} must be an object")
    else:
        unknown = sorted(set(value) - set(BUSINESS_CONTEXT_FIELDS))
        if unknown:
            raise BundleError(f"business_context for {component_id} contains unknown attributes: {', '.join(unknown)}")
        attributes = {}
        for name in BUSINESS_CONTEXT_FIELDS:
            if name not in value:
                continue
            raw = value[name]
            if name in BUSINESS_CONTEXT_TEXT_FIELDS:
                if not isinstance(raw, str):
                    raise BundleError(f"business_context.{name} for {component_id} must be text")
                normalized = raw.strip()
                if not normalized or len(normalized) > MAX_BUSINESS_CONTEXT_TEXT_CHARS:
                    raise BundleError(f"business_context.{name} for {component_id} is empty or oversized")
                attributes[name] = normalized
                continue
            if not isinstance(raw, list) or not raw or len(raw) > MAX_BUSINESS_CONTEXT_ITEMS:
                raise BundleError(
                    f"business_context.{name} for {component_id} must contain 1-{MAX_BUSINESS_CONTEXT_ITEMS} items"
                )
            normalized_items: list[str] = []
            for item in raw:
                if not isinstance(item, str):
                    raise BundleError(f"business_context.{name} for {component_id} contains a non-string item")
                normalized = item.strip()
                if not normalized or len(normalized) > MAX_BUSINESS_CONTEXT_ITEM_CHARS:
                    raise BundleError(f"business_context.{name} for {component_id} contains an empty or oversized item")
                if normalized not in normalized_items:
                    normalized_items.append(normalized)
            attributes[name] = normalized_items
    if not attributes:
        return None
    return {
        "schema_version": 1,
        "component_id": component_id,
        "source": "stride-analyst-context-v1",
        "source_content_sha256": hashlib.sha256(_canonical_bytes(attributes)).hexdigest(),
        "attributes": attributes,
    }


def validate_business_context_bytes(
    payload: bytes,
    *,
    expected_component_id: str | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    if expected_sha256 and hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise BundleError("business-context fingerprint does not match the manifest")
    try:
        value = json.loads(payload)
        schema = json.loads(BUSINESS_CONTEXT_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"business-context projection/schema is unreadable: {exc}") from exc
    errors = sorted(_load_validator()(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise BundleError(f"business-context projection schema validation failed: {detail}")
    if expected_component_id and value["component_id"] != expected_component_id:
        raise BundleError("business-context component id does not match its dispatch entry")
    attributes = value["attributes"]
    if value["source_content_sha256"] != hashlib.sha256(_canonical_bytes(attributes)).hexdigest():
        raise BundleError("business-context source fingerprint is stale")
    for name, attribute in attributes.items():
        if name in BUSINESS_CONTEXT_TEXT_FIELDS:
            if attribute != attribute.strip():
                raise BundleError("business-context text is not normalized")
        elif any(item != item.strip() for item in attribute):
            raise BundleError("business-context list is not normalized")
    return value


def architecture_context_projection(value: Any, component_id: str) -> dict[str, Any] | None:
    """Normalize one independently selectable security-architecture projection."""
    if value in (None, {}):
        attributes: dict[str, Any] = {}
    elif not isinstance(value, dict):
        raise BundleError(f"architecture_context for {component_id} must be an object")
    else:
        unknown = sorted(set(value) - set(ARCHITECTURE_CONTEXT_FIELDS))
        if unknown:
            raise BundleError(
                f"architecture_context for {component_id} contains unknown attributes: {', '.join(unknown)}"
            )
        attributes = {}
        for name in ARCHITECTURE_CONTEXT_FIELDS:
            if name not in value:
                continue
            raw = value[name]
            if name in ARCHITECTURE_CONTEXT_TEXT_FIELDS:
                if not isinstance(raw, str):
                    raise BundleError(f"architecture_context.{name} for {component_id} must be text")
                normalized = raw.strip()
                if not normalized or len(normalized) > MAX_BUSINESS_CONTEXT_TEXT_CHARS:
                    raise BundleError(f"architecture_context.{name} for {component_id} is empty or oversized")
                attributes[name] = normalized
                continue
            if not isinstance(raw, list) or not raw or len(raw) > MAX_BUSINESS_CONTEXT_ITEMS:
                raise BundleError(
                    f"architecture_context.{name} for {component_id} must contain 1-{MAX_BUSINESS_CONTEXT_ITEMS} items"
                )
            normalized_items: list[str] = []
            for item in raw:
                if not isinstance(item, str):
                    raise BundleError(f"architecture_context.{name} for {component_id} contains a non-string item")
                normalized = item.strip()
                if not normalized or len(normalized) > MAX_BUSINESS_CONTEXT_ITEM_CHARS:
                    raise BundleError(
                        f"architecture_context.{name} for {component_id} contains an empty or oversized item"
                    )
                if normalized not in normalized_items:
                    normalized_items.append(normalized)
            attributes[name] = normalized_items
    if not attributes:
        return None
    return {
        "schema_version": 1,
        "component_id": component_id,
        "source": "stride-analyst-context-v1",
        "source_content_sha256": hashlib.sha256(_canonical_bytes(attributes)).hexdigest(),
        "attributes": attributes,
    }


def validate_architecture_context_bytes(
    payload: bytes,
    *,
    expected_component_id: str | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    if expected_sha256 and hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise BundleError("architecture-context fingerprint does not match the manifest")
    try:
        value = json.loads(payload)
        schema = json.loads(ARCHITECTURE_CONTEXT_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"architecture-context projection/schema is unreadable: {exc}") from exc
    errors = sorted(_load_validator()(schema).iter_errors(value), key=lambda item: list(item.path))
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise BundleError(f"architecture-context projection schema validation failed: {detail}")
    if expected_component_id and value["component_id"] != expected_component_id:
        raise BundleError("architecture-context component id does not match its dispatch entry")
    attributes = value["attributes"]
    if value["source_content_sha256"] != hashlib.sha256(_canonical_bytes(attributes)).hexdigest():
        raise BundleError("architecture-context source fingerprint is stale")
    for name, attribute in attributes.items():
        if name in ARCHITECTURE_CONTEXT_TEXT_FIELDS:
            if attribute != attribute.strip():
                raise BundleError("architecture-context text is not normalized")
        elif any(item != item.strip() for item in attribute):
            raise BundleError("architecture-context list is not normalized")
    return value


def _component_glob_matches(relative: str, pattern: str) -> bool:
    """Match with the canonical component-glob semantics."""
    return bool(_glob_to_regex(pattern).search(relative))


def _owned(component_paths: list[str], relative: str) -> bool:
    if not component_paths:
        return True
    for pattern in component_paths:
        if pattern in {"**", "**/*"}:
            return True
        if _component_glob_matches(relative, pattern):
            return True
        if pattern.endswith("/**") and relative.startswith(pattern[:-3].rstrip("/") + "/"):
            return True
    return False


def _owned_routing_path(component_paths: list[str], relative: str, *, is_directory: bool) -> bool:
    """Return whether a literal routing path is inside component scope.

    Files must match a component pattern exactly. A directory may also equal
    or descend from the literal prefix of a glob: ``routes`` is a valid narrow
    scope for ``routes/**/*.ts`` even though no invented directory probe can
    satisfy the ``.ts`` suffix. Directories above that prefix remain outside
    the component, and projected files are checked individually by the bundle
    builder.
    """
    if _owned(component_paths, relative):
        return True
    if not is_directory:
        return False
    for pattern in component_paths:
        literal_parts: list[str] = []
        has_glob = False
        for part in pattern.split("/"):
            if any(char in part for char in "*?["):
                has_glob = True
                break
            literal_parts.append(part)
        if not has_glob or not literal_parts:
            continue
        prefix = "/".join(literal_parts).rstrip("/")
        if relative == prefix or relative.startswith(prefix + "/"):
            return True
    return False


def _requested_routing_paths(routing: dict[str, Any], kind: str) -> list[str]:
    """Return the hints of one kind the dispatch entry asked this bundle for.

    A hint reaches exactly one of two places: a receipt row when the build
    considered it, or the dropped list of ``degraded`` when the build could not
    honor it at all. Their concatenation is what the manifest still holds.
    """
    receipt = "focus_admission" if kind == "focus" else "exclude_application"
    dropped = (routing.get("degraded") or {}).get(f"dropped_{kind}_paths", [])
    return [row["path"] for row in routing[receipt]] + list(dropped)


def _path_overlaps(left: str, right: str) -> bool:
    """Return whether two normalized literal paths contain one another."""
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _normalize_routing_values(
    component: dict[str, Any],
    registry: dict[str, Path],
    *,
    reject_missing: bool = False,
) -> tuple[list[str], list[str]]:
    """Normalize the compatibility string-or-list routing inputs at dispatch."""
    component_id = component["component_id"]
    paths_value = component.get("component_paths") or []
    component_paths = [paths_value] if isinstance(paths_value, str) else [str(value) for value in paths_value]
    repo_root = registry["primary"]
    skipped_missing: list[str] = []

    def normalize(name: str) -> list[str]:
        raw = component.get(name)
        if raw is None:
            return []
        if isinstance(raw, str):
            values = raw.split(",")
        elif isinstance(raw, list):
            # ``build_all`` persists the canonical no-routing value as ``[]``
            # in the manifest. Reconstruction must accept its own output;
            # rejecting it made the second validation pass fail closed even
            # though the first pass had produced valid bundles.
            if not raw:
                return []
            values = raw
        else:
            raise BundleError(f"{name} for {component_id} must be a string or list")
        if not values or len(values) > MAX_ROUTING_PATHS:
            raise BundleError(f"{name} for {component_id} exceeds the {MAX_ROUTING_PATHS}-path cap")

        normalized: list[str] = []
        for raw_value in values:
            if not isinstance(raw_value, str):
                raise BundleError(f"{name} for {component_id} contains a non-string path")
            value = raw_value.strip().rstrip("/")
            if not value or len(value) > MAX_ROUTING_PATH_CHARS:
                raise BundleError(f"{name} for {component_id} contains an empty or oversized path")
            if re.match(r"^(?:[A-Za-z]:[\\/]|[A-Za-z][A-Za-z0-9+.-]*://)", value):
                raise BundleError(f"{name} for {component_id} contains an absolute path or URL")
            if any(char in value for char in "*?[]{}!"):
                raise BundleError(f"{name} for {component_id} must contain literal repository-relative paths")
            resolved = _canonical_under(repo_root, value)
            if not resolved.exists():
                if reject_missing:
                    raise BundleError(f"{name} for {component_id} does not exist: {value!r}")
                skipped_missing.append(f"{name} for {component_id}: {value!r}")
                continue
            if not _owned_routing_path(component_paths, value, is_directory=resolved.is_dir()):
                raise BundleError(f"{name} for {component_id} is outside the component paths: {value!r}")
            if value in normalized:
                continue
            if any(_path_overlaps(value, prior) for prior in normalized):
                raise BundleError(f"{name} for {component_id} contains overlapping paths: {value!r}")
            normalized.append(value)
        return normalized

    focus_paths = normalize("focus_paths")
    exclude_paths = normalize("exclude_paths")
    for missing in skipped_missing:
        print(f"ROUTING_WARN: missing path skipped — {missing}", file=sys.stderr)
    for focus in focus_paths:
        for excluded in exclude_paths:
            if _path_overlaps(focus, excluded):
                raise BundleError(
                    f"focus_paths and exclude_paths overlap for {component_id}: {focus!r} and {excluded!r}"
                )
    component["focus_paths"] = focus_paths
    component["exclude_paths"] = exclude_paths
    return focus_paths, exclude_paths


def validate_component_routing_values(
    component_id: str,
    component_paths: list[str],
    overlay: dict[str, Any],
    repo_root: Path,
) -> tuple[list[str], list[str]]:
    """Validate producer-authored routing hints against finalized ownership.

    This is the cross-artifact producer gate used before bundle construction.
    It deliberately rejects missing paths rather than applying the bundle
    builder's compatibility skip, so the semantic producer can correct its
    own artifact before returning control.
    """
    component = {
        "component_id": component_id,
        "component_paths": component_paths,
    }
    for key in ("focus_paths", "exclude_paths"):
        if key in overlay:
            component[key] = overlay[key]
    return _normalize_routing_values(
        component,
        {"primary": repo_root.resolve()},
        reject_missing=True,
    )


def _referenced_primary_paths(value: Any) -> set[str]:
    """Collect primary-repository file citations from already admitted evidence."""
    found: set[str] = set()
    if isinstance(value, dict):
        candidate = value.get("file") or value.get("path")
        repository_id = value.get("repository_id", "primary")
        if isinstance(candidate, str) and repository_id == "primary":
            found.add(candidate)
        for child in value.values():
            found.update(_referenced_primary_paths(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_referenced_primary_paths(child))
    return found


def _walk_signal_rows(value: Any, signal_kind: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        file_value = value.get("file") or value.get("path")
        line_value = value.get("line") or value.get("start_line")
        if isinstance(file_value, str) and line_value is not None:
            try:
                start = int(line_value)
                end = int(value.get("end_line") or start)
            except (TypeError, ValueError):
                pass
            else:
                found.append(
                    {
                        "repository_id": str(value.get("repository_id") or "primary"),
                        "path": file_value,
                        "start_line": start,
                        "end_line": end,
                        "signal_kind": signal_kind,
                        "summary": {
                            key: value[key]
                            for key in (
                                "rule_id",
                                "check_id",
                                "category",
                                "subcategory",
                                "severity",
                                "strength",
                                "kind",
                                "message",
                            )
                            if key in value
                        },
                    }
                )
                sink_line = value.get("sink_line")
                sink_file = value.get("sink_file") or file_value
                if sink_line is not None and isinstance(sink_file, str):
                    try:
                        sink_start = int(sink_line)
                    except (TypeError, ValueError):
                        pass
                    else:
                        if sink_start != start or sink_file != file_value:
                            sink_summary = {
                                key: value[key]
                                for key in (
                                    "rule_id",
                                    "check_id",
                                    "category",
                                    "subcategory",
                                    "severity",
                                    "strength",
                                    "message",
                                )
                                if key in value
                            }
                            sink_summary["kind"] = "sink"
                            found.append(
                                {
                                    "repository_id": str(value.get("repository_id") or "primary"),
                                    "path": sink_file,
                                    "start_line": sink_start,
                                    "end_line": sink_start,
                                    "signal_kind": signal_kind,
                                    "summary": sink_summary,
                                }
                            )
        for child in value.values():
            found.extend(_walk_signal_rows(child, signal_kind))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_signal_rows(child, signal_kind))
    return found


def _slice_hash(path: Path, start_line: int, end_line: int) -> str:
    try:
        lines = path.read_bytes().splitlines(keepends=True)
    except OSError as exc:
        raise BundleError(f"cannot read source slice {path}: {exc}") from exc
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise BundleError(f"source slice range is outside {path}: {start_line}-{end_line}")
    return hashlib.sha256(b"".join(lines[start_line - 1 : end_line])).hexdigest()


def _source_signals(
    output_dir: Path,
    component_paths: list[str],
    registry: dict[str, Path],
    focus_paths: list[str],
) -> tuple[list[dict[str, Any]], list[Any], int, set[str]]:
    candidates: list[dict[str, Any]] = []
    for signal_kind, filename in SIGNAL_FILES:
        path = output_dir / filename
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BundleError(f"validated signal artifact is unreadable: {filename}: {exc}") from exc
        candidates.extend(_walk_signal_rows(payload, signal_kind))

    normalized: list[dict[str, Any]] = []
    summaries: list[Any] = []
    for row in candidates:
        repository_id = row["repository_id"]
        if repository_id not in registry:
            raise BundleError(f"source signal selected unknown repository id: {repository_id}")
        relative = row["path"]
        if repository_id == "primary" and not _owned(component_paths, relative):
            continue
        span = row["end_line"] - row["start_line"] + 1
        if span < 1:
            continue
        if span > MAX_SLICE_LINES:
            row["end_line"] = row["start_line"] + MAX_SLICE_LINES - 1
        source_path = _canonical_under(registry[repository_id], relative)
        row_out = {key: row[key] for key in ("repository_id", "path", "start_line", "end_line", "signal_kind")}
        row_out["content_sha256"] = _slice_hash(source_path, row["start_line"], row["end_line"])
        summary = row["summary"]
        mechanism = str(
            summary.get("subcategory")
            or summary.get("check_id")
            or summary.get("rule_id")
            or summary.get("category")
            or row["signal_kind"]
        )
        row_out["_mechanism"] = mechanism + (f":{summary['kind']}" if summary.get("kind") else "")
        row_out["_severity"] = str(summary.get("severity") or "Info")
        normalized.append(row_out)
        summaries.append(
            {
                "repository_id": repository_id,
                "file": relative,
                "line": row["start_line"],
                "signal_kind": row["signal_kind"],
                **summary,
            }
        )

    keyed = {
        (row["repository_id"], row["path"], row["start_line"], row["end_line"], row["signal_kind"]): row
        for row in normalized
    }
    ordered = [keyed[key] for key in sorted(keyed)]
    severity_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    def signal_rank(row: dict[str, Any]) -> tuple[int, str, int, str]:
        return (
            severity_rank.get(row["_severity"], 5),
            row["path"],
            row["start_line"],
            row["signal_kind"],
        )

    # Selection is bounded, but it must not be lexically monopolised by many
    # observations from the first few files. Preserve one cited slice for each
    # focus path first, then one per independently detected mechanism and file,
    # before filling the remaining slots. This changes ordering, not any byte,
    # source-line, slice, or token ceiling.
    candidates: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, int, int, str]] = set()

    def append_once(row: dict[str, Any]) -> None:
        key = (row["repository_id"], row["path"], row["start_line"], row["end_line"], row["signal_kind"])
        if key not in seen_keys:
            seen_keys.add(key)
            candidates.append(row)

    focus_matches: list[list[dict[str, Any]]] = []
    for focus_path in focus_paths:
        matches = sorted(
            [
                row
                for row in ordered
                if row["repository_id"] == "primary"
                and (row["path"] == focus_path or row["path"].startswith(focus_path + "/"))
            ],
            key=signal_rank,
        )
        focus_matches.append(matches)
    # Round-robin across focus paths so one noisy focused file cannot starve a
    # later focused mechanism, while all cited source/sink lines still outrank
    # non-focused signal fan-out.
    for offset in range(max((len(matches) for matches in focus_matches), default=0)):
        for matches in focus_matches:
            if offset < len(matches):
                append_once(matches[offset])

    mechanism_first: dict[tuple[str, str], dict[str, Any]] = {}
    file_first: dict[tuple[str, str], dict[str, Any]] = {}
    for row in sorted(ordered, key=signal_rank):
        mechanism_first.setdefault((row["signal_kind"], row["_mechanism"]), row)
        file_first.setdefault((row["repository_id"], row["path"]), row)
    for row in mechanism_first.values():
        append_once(row)
    for row in file_first.values():
        append_once(row)
    for row in sorted(ordered, key=signal_rank):
        append_once(row)

    retained: list[dict[str, Any]] = []
    source_lines = 0
    for row in candidates:
        span = row["end_line"] - row["start_line"] + 1
        if len(retained) >= MAX_SOURCE_SLICES or source_lines + span > MAX_SOURCE_LINES:
            continue
        retained.append({key: value for key, value in row.items() if not key.startswith("_")})
        source_lines += span
    protected_paths = {row["path"] for row in normalized if row["repository_id"] == "primary"}
    return retained, summaries, len(ordered), protected_paths


def _focus_candidate_files(repo_root: Path, relative: str) -> tuple[list[str], bool]:
    """Enumerate one literal focus path without following an escaping symlink."""
    from scan_excludes import is_excluded, is_oversize

    root_path = _canonical_under(repo_root, relative)
    if root_path.is_file():
        candidates = [root_path]
        truncated = False
    elif root_path.is_dir():
        candidates = []
        visited = 0
        truncated = False
        for dirpath, dirnames, filenames in os.walk(root_path, followlinks=False):
            dirnames.sort()
            filenames.sort()
            visited += len(dirnames) + len(filenames)
            if visited > MAX_FOCUS_ENUM_ENTRIES:
                truncated = True
                break
            for filename in filenames:
                candidates.append(Path(dirpath) / filename)
    else:
        candidates = []
        truncated = False

    retained: list[str] = []
    for candidate in candidates:
        candidate_relative = candidate.relative_to(repo_root).as_posix()
        try:
            canonical = _canonical_under(repo_root, candidate_relative)
        except BundleError:
            # An entry that resolves outside the repository is skipped, which is
            # what this enumeration promises. Letting the containment check raise
            # instead ended the whole run over one symlink in a hinted directory.
            continue
        if not canonical.is_file() or is_excluded(candidate_relative) or is_oversize(canonical):
            continue
        retained.append(candidate_relative)
    return sorted(dict.fromkeys(retained)), truncated


def _focus_admission_reason(
    *,
    projected: bool,
    omitted: int,
    enumeration_truncated: bool,
    owned_candidates: int,
    unowned_files: int,
) -> str:
    """Derive one focus-admission reason.

    Builder and validator must agree byte-for-byte, so both call this. Keeping
    the two ladders as separate copies is what let the admission gate and the
    projection gate drift apart in the first place.
    """
    if projected and (omitted or enumeration_truncated):
        # ``omitted`` counts only files the component owns, so a focus directory
        # that also holds foreign files still reads as fully projected. Folding
        # ``unowned_files`` in here made a complete projection next to a README
        # report itself as partial.
        return "partially-projected"
    if projected:
        return "projected"
    if enumeration_truncated:
        return "enumeration-budget"
    if owned_candidates:
        return "source-budget"
    if unowned_files:
        return "outside-component"
    return "no-readable-files"


def _focus_source_slices(
    repo_root: Path,
    focus_paths: list[str],
    component_paths: list[str],
    mandatory_slices: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Project focus paths into the remaining source-slice and line budgets."""
    retained = list(mandatory_slices)
    retained_keys = {
        (row["repository_id"], row["path"], row["start_line"], row["end_line"], row["signal_kind"]) for row in retained
    }
    retained_files = {row["path"] for row in retained if row["repository_id"] == "primary"}
    source_lines = sum(row["end_line"] - row["start_line"] + 1 for row in retained)
    decisions: list[dict[str, Any]] = []

    for focus_path in focus_paths:
        candidates, enumeration_truncated = _focus_candidate_files(repo_root, focus_path)
        # A focus directory is admitted against the literal prefix of a component
        # glob, so it may legitimately contain files that glob does not own:
        # ``pkg`` is a valid narrow scope for ``pkg/*.py`` even though the pattern
        # never reaches ``pkg/sub/deep.py``. Narrowing the projection to owned
        # files keeps the component boundary exactly as strict as the pattern —
        # the same disposition ``_source_slices`` already applies to unowned
        # signal rows. Raising instead turned a benign over-broad focus hint into
        # a fatal abort of the whole run.
        files = [path for path in candidates if _owned(component_paths, path)]
        unowned = len(candidates) - len(files)
        projected: list[str] = []
        omitted = 0
        for relative in files:
            if relative in retained_files:
                projected.append(relative)
                continue
            try:
                path = _canonical_under(repo_root, relative)
                line_count = len(path.read_bytes().splitlines())
            except (BundleError, OSError) as exc:
                # The hint named a scope holding a file this build cannot turn
                # into a slice — an unreadable file, or a link leaving the
                # repository. That is the hint's problem, not a malformed
                # bundle, so it is contained per component rather than fatal.
                raise RoutingHintError(f"cannot read focus path projection {relative}: {exc}") from exc
            if line_count < 1:
                omitted += 1
                continue
            end_line = min(line_count, MAX_SLICE_LINES)
            if len(retained) >= MAX_SOURCE_SLICES or source_lines + end_line > MAX_SOURCE_LINES:
                omitted += 1
                continue
            row = {
                "repository_id": "primary",
                "path": relative,
                "start_line": 1,
                "end_line": end_line,
                "signal_kind": "focus-path",
                "content_sha256": _slice_hash(path, 1, end_line),
            }
            key = ("primary", relative, 1, end_line, "focus-path")
            if key not in retained_keys:
                retained.append(row)
                retained_keys.add(key)
                retained_files.add(relative)
                source_lines += end_line
            projected.append(relative)

        reason = _focus_admission_reason(
            projected=bool(projected),
            omitted=omitted,
            enumeration_truncated=enumeration_truncated,
            owned_candidates=len(files),
            unowned_files=unowned,
        )
        decisions.append(
            {
                "path": focus_path,
                "status": "admitted" if projected else "omitted",
                "reason": reason,
                "candidate_files": len(candidates),
                "projected_files": sorted(projected),
                "omitted_files": omitted,
                "unowned_files": unowned,
                "enumeration_truncated": enumeration_truncated,
            }
        )

    def focus_rank(row: dict[str, Any]) -> tuple[int, int, str, int, str]:
        rank = len(focus_paths)
        for index, focus_path in enumerate(focus_paths):
            if row["repository_id"] == "primary" and (
                row["path"] == focus_path or row["path"].startswith(focus_path + "/")
            ):
                rank = index
                break
        return rank, 0 if row["signal_kind"] == "focus-path" else 1, row["path"], row["start_line"], row["signal_kind"]

    return sorted(retained, key=focus_rank), decisions


def _truncation_rows(
    stats: dict[str, dict[str, int]], evidence: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for signal_class in sorted(stats):
        original = stats[signal_class]["original"]
        retained = len(evidence.get(signal_class, []))
        if original > retained:
            rows.append(
                {
                    "signal_class": signal_class,
                    "original_count": original,
                    "retained_count": retained,
                    "omitted_count": original - retained,
                    "cap": MAX_CLASS_VALUES,
                    "ordering_key": "source,canonical-json",
                }
            )
        value_truncations = stats[signal_class].get("value_truncations", 0)
        if value_truncations:
            rows.append(
                {
                    "signal_class": f"{signal_class}.value_chars",
                    "original_count": value_truncations,
                    "retained_count": value_truncations,
                    "omitted_count": 0,
                    "cap": MAX_VALUE_CHARS,
                    "ordering_key": "utf-8-character-prefix",
                }
            )
    return rows


def _render_bundle(bundle: dict[str, Any]) -> bytes:
    previous: tuple[int, int] | None = None
    for _ in range(10):
        rendered = _canonical_bytes(bundle) + b"\n"
        current = (len(rendered), (len(rendered) + 3) // 4)
        bundle["limits"]["serialized_bytes"], bundle["limits"]["estimated_tokens"] = current
        if current == previous:
            return _canonical_bytes(bundle) + b"\n"
        previous = current
    raise BundleError("bundle size metadata did not converge")


def build_bundle(
    output_dir: Path,
    component: dict[str, Any],
    registry: dict[str, Path],
    *,
    degraded: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], bytes]:
    component_id = component["component_id"]
    paths_value = component.get("component_paths") or []
    component_paths = [paths_value] if isinstance(paths_value, str) else [str(value) for value in paths_value]
    focus_paths = list(component.get("focus_paths") or [])
    exclude_paths = list(component.get("exclude_paths") or [])
    path_original = len(component_paths)
    component_paths = sorted(dict.fromkeys(component_paths))[:32]

    raw: dict[str, list[Any]] = {name: [] for name in ALL_EVIDENCE_CLASSES}
    raw["interfaces"] = _rows(component.get("interfaces"))
    raw["controls"] = _rows(component.get("controls"))
    for index_name, evidence_class in INDEX_TO_CLASS.items():
        value = (component.get("index_paths") or {}).get(index_name)
        if value in (None, "none"):
            continue
        index_path = _output_artifact(output_dir, str(value))
        try:
            raw[evidence_class].extend(_rows(json.loads(index_path.read_text(encoding="utf-8"))))
        except (OSError, json.JSONDecodeError) as exc:
            raise BundleError(f"validated component index is unreadable: {value}: {exc}") from exc

    mandatory_slices, signal_summaries, original_slice_count, protected_paths = _source_signals(
        output_dir,
        component_paths,
        registry,
        focus_paths,
    )
    raw["recon_signals"].extend(signal_summaries)
    for evidence_class in ALL_EVIDENCE_CLASSES:
        protected_paths.update(_referenced_primary_paths(raw[evidence_class]))
    normalized_protected: set[str] = set()
    for relative in protected_paths:
        try:
            _canonical_under(registry["primary"], relative)
        except BundleError:
            continue
        normalized_protected.add(relative.rstrip("/"))
    # An exclude path is an optional-discovery hint — the receipt labels its own
    # scope ``optional-discovery-only`` — while mandatory and cited evidence is a
    # hard requirement. When the two collide the hint yields and the receipt
    # discloses it. The producer cannot pre-empt the collision: protected paths
    # come from the deterministic scanner artifacts, which the routing producer
    # never receives, so enforcing the contract with an abort made a run-fatal
    # error out of an obligation nothing could satisfy.
    exclude_application: list[dict[str, Any]] = []
    applied_excludes: list[str] = []
    for excluded in exclude_paths:
        conflicts = sorted(path for path in normalized_protected if _path_overlaps(excluded, path))
        exclude_application.append(
            {
                "path": excluded,
                "status": "superseded" if conflicts else "applied",
                "scope": "optional-discovery-only",
                "superseded_by": conflicts[:MAX_SUPERSEDED_EVIDENCE_PATHS],
            }
        )
        if conflicts:
            print(
                f"ROUTING_WARN: exclude_paths for {component_id} superseded by cited evidence — "
                + ", ".join(conflicts[:5]),
                file=sys.stderr,
            )
        else:
            applied_excludes.append(excluded)
    exclude_paths = applied_excludes

    source_slices, focus_decisions = _focus_source_slices(
        registry["primary"],
        focus_paths,
        component_paths,
        mandatory_slices,
    )

    evidence: dict[str, list[dict[str, Any]]] = {}
    stats: dict[str, dict[str, int]] = {}
    for name in EVIDENCE_CLASSES:
        evidence[name], stats[name] = _bounded_records(name, raw[name])

    admitted_repository_ids = {"primary", *(row["repository_id"] for row in source_slices)}
    unknown_repository_ids = admitted_repository_ids - set(registry)
    if unknown_repository_ids:
        raise BundleError(
            "component source slices name unknown repositories: " + ", ".join(sorted(unknown_repository_ids))
        )
    citation_paths = bundle_citation_paths(source_slices, evidence, registry)
    repository_state = []
    for repository_id in sorted(admitted_repository_ids):
        root = registry[repository_id]
        commit, dirty = repository_fingerprint(
            root,
            cited_paths=citation_paths.get(repository_id, []),
            excluded_root=output_dir if repository_id == "primary" else None,
        )
        repository_state.append(
            {
                "repository_id": repository_id,
                "kind": "primary" if repository_id == "primary" else "related",
                "commit_sha": commit,
                "dirty_worktree_sha256": dirty,
            }
        )

    bundle = {
        "schema_version": 1,
        "component": {
            "id": component_id,
            "name": str(component.get("component_name") or component_id)[:300],
            "description": str(component.get("component_description") or "")[:2000],
            "paths": component_paths,
        },
        "repository_state": repository_state,
        "path_routing": {
            "focus_paths": focus_paths,
            "exclude_paths": exclude_paths,
            "focus_admission": focus_decisions,
            "exclude_application": exclude_application,
            "protected_evidence_path_count": len(normalized_protected),
            "protected_evidence_paths_sha256": hashlib.sha256(
                _canonical_bytes(sorted(normalized_protected))
            ).hexdigest(),
            # Present only when routing hints were dropped to keep the component
            # buildable. It has to live in the artifact, not just on stderr: a
            # degraded bundle is otherwise indistinguishable from one that never
            # carried routing, and nothing downstream could tell the difference.
            **({"degraded": degraded} if degraded else {}),
        },
        "evidence": evidence,
        "source_slices": source_slices,
        "truncation": [],
        "limits": {
            "serialized_bytes": 1,
            "estimated_tokens": 1,
            "referenced_source_lines": sum(row["end_line"] - row["start_line"] + 1 for row in source_slices),
        },
    }
    if path_original > len(component_paths):
        bundle["truncation"].append(
            {
                "signal_class": "component_paths",
                "original_count": path_original,
                "retained_count": len(component_paths),
                "omitted_count": path_original - len(component_paths),
                "cap": 32,
                "ordering_key": "lexical-path",
            }
        )
    if original_slice_count > len(mandatory_slices):
        bundle["truncation"].append(
            {
                "signal_class": "source_slices",
                "original_count": original_slice_count,
                "retained_count": len(mandatory_slices),
                "omitted_count": original_slice_count - len(mandatory_slices),
                "cap": MAX_SOURCE_SLICES,
                "ordering_key": "repository-id,path,start-line,end-line,signal-kind",
            }
        )

    while True:
        bundle["truncation"] = [
            row for row in bundle["truncation"] if row["signal_class"] in {"component_paths", "source_slices"}
        ] + _truncation_rows(stats, evidence)
        payload = _render_bundle(bundle)
        if len(payload) <= MAX_BUNDLE_BYTES and bundle["limits"]["estimated_tokens"] <= MAX_ESTIMATED_TOKENS:
            break
        candidates = [name for name in EVIDENCE_CLASSES if evidence[name]]
        if not candidates:
            raise BundleError(f"bundle metadata exceeds {MAX_BUNDLE_BYTES} bytes for {component_id}")
        drop_from = max(candidates, key=lambda name: (len(evidence[name]), name))
        evidence[drop_from].pop()

    validate_bundle_bytes(
        payload,
        registry,
        expected_component_id=component_id,
        excluded_root=output_dir,
    )
    return bundle, payload


def _load_validator():
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise BundleError("jsonschema is required to validate evidence bundles") from exc
    return Draft202012Validator


def validate_bundle_bytes(
    payload: bytes,
    registry: dict[str, Path],
    *,
    expected_component_id: str | None = None,
    expected_sha256: str | None = None,
    expected_focus_paths: list[str] | None = None,
    expected_exclude_paths: list[str] | None = None,
    excluded_root: Path | None = None,
) -> dict[str, Any]:
    if expected_sha256 and hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise BundleError("evidence-bundle fingerprint does not match the manifest")
    try:
        bundle = json.loads(payload)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"evidence bundle/schema is unreadable: {exc}") from exc
    errors = sorted(_load_validator()(schema).iter_errors(bundle), key=lambda item: list(item.path))
    if errors:
        detail = "; ".join(error.message for error in errors[:5])
        raise BundleError(f"evidence bundle schema validation failed: {detail}")
    if expected_component_id and bundle["component"]["id"] != expected_component_id:
        raise BundleError("evidence-bundle component id does not match its dispatch entry")
    routing = bundle.get("path_routing")
    if not isinstance(routing, dict):
        if expected_focus_paths or expected_exclude_paths:
            raise BundleError("evidence-bundle path routing is missing for a routed dispatch entry")
    else:
        # The dispatch entry states what was requested; ``focus_paths`` and
        # ``exclude_paths`` carry only what took effect. Every requested hint is
        # accounted for either by a receipt row or by the dropped list of a
        # degraded build, so the receipt is what the entry is compared against.
        # Comparing the effective set instead forced the manifest to be
        # overwritten with it, and a rebuild then could not repeat its own answer.
        if expected_focus_paths is not None and _requested_routing_paths(routing, "focus") != expected_focus_paths:
            raise BundleError("evidence-bundle focus paths do not match the dispatch entry")
        if (
            expected_exclude_paths is not None
            and _requested_routing_paths(routing, "exclude") != expected_exclude_paths
        ):
            raise BundleError("evidence-bundle exclude paths do not match the dispatch entry")
    if bundle["limits"]["serialized_bytes"] != len(payload):
        raise BundleError("evidence-bundle serialized byte count is stale")
    if bundle["limits"]["estimated_tokens"] != (len(payload) + 3) // 4:
        raise BundleError("evidence-bundle estimated token count is stale")

    required_repository_ids = {"primary", *(row["repository_id"] for row in bundle["source_slices"])}
    unknown_repository_ids = required_repository_ids - set(registry)
    if unknown_repository_ids:
        raise BundleError("source slice names unknown repository: " + ", ".join(sorted(unknown_repository_ids)))
    state_rows = bundle["repository_state"]
    state_by_id = {row["repository_id"]: row for row in state_rows}
    if len(state_rows) != len(state_by_id):
        raise BundleError("evidence-bundle repository state contains duplicate repository ids")
    if set(state_by_id) != required_repository_ids:
        raise BundleError("evidence-bundle repository state does not match its admitted source slices")
    citation_paths = bundle_citation_paths(bundle["source_slices"], bundle["evidence"], registry)
    for repository_id in sorted(required_repository_ids):
        root = registry[repository_id]
        _commit, dirty = repository_fingerprint(
            root,
            cited_paths=citation_paths.get(repository_id, []),
            excluded_root=excluded_root if repository_id == "primary" else None,
        )
        state = state_by_id[repository_id]
        expected_kind = "primary" if repository_id == "primary" else "related"
        if state["kind"] != expected_kind:
            raise BundleError(f"evidence-bundle repository kind is invalid for: {repository_id}")
        # Only the cited bytes decide staleness. `commit_sha` stays in the
        # artifact for audit but is not compared: a commit made in the analyzed
        # repository during a long STRIDE phase moves HEAD without changing a
        # single cited line, and failing the run for that punishes an actively
        # developed repository for being one.
        if state["dirty_worktree_sha256"] != dirty:
            raise BundleError(f"evidence bundle is stale for repository: {repository_id}")

    seen: set[tuple[Any, ...]] = set()
    total_lines = 0
    for row in bundle["source_slices"]:
        key = (
            row["repository_id"],
            row["path"],
            row["start_line"],
            row["end_line"],
            row["signal_kind"],
        )
        if key in seen:
            raise BundleError("evidence bundle contains a duplicate source slice")
        seen.add(key)
        repository_id = row["repository_id"]
        if repository_id not in registry:
            raise BundleError(f"source slice names unknown repository: {repository_id}")
        span = row["end_line"] - row["start_line"] + 1
        if span < 1 or span > MAX_SLICE_LINES:
            raise BundleError("source slice exceeds its line-range cap")
        total_lines += span
        path = _canonical_under(registry[repository_id], row["path"])
        if _slice_hash(path, row["start_line"], row["end_line"]) != row["content_sha256"]:
            raise BundleError(f"source slice changed after bundle creation: {repository_id}:{row['path']}")
    if total_lines != bundle["limits"]["referenced_source_lines"] or total_lines > MAX_SOURCE_LINES:
        raise BundleError("evidence-bundle referenced source-line count is stale or over budget")
    for row in bundle["truncation"]:
        if row["original_count"] != row["retained_count"] + row["omitted_count"]:
            raise BundleError("evidence-bundle truncation counts are inconsistent")
    if isinstance(routing, dict):
        focus_paths = routing["focus_paths"]
        exclude_paths = routing["exclude_paths"]
        degraded = routing.get("degraded")
        if degraded is not None:
            # The hints were dropped to make this component buildable, so none may
            # have survived into the effective routing.
            if focus_paths or exclude_paths:
                raise BundleError("evidence-bundle degraded routing still carries effective hints")
            if not (degraded["dropped_focus_paths"] or degraded["dropped_exclude_paths"]):
                raise BundleError("evidence-bundle degraded routing records no dropped hint")
        if [row["path"] for row in routing["focus_admission"]] != focus_paths:
            raise BundleError("evidence-bundle focus admission receipt is incomplete or reordered")
        # The receipt lists every requested exclude; ``exclude_paths`` carries only
        # the ones that survived the collision with cited evidence, in the same
        # order. Comparing the applied subset keeps the receipt auditable without
        # letting a superseded hint read as drift.
        if [row["path"] for row in routing["exclude_application"] if row["status"] == "applied"] != exclude_paths:
            raise BundleError("evidence-bundle exclude application receipt is incomplete or reordered")
        for row in routing["exclude_application"]:
            if (row["status"] == "superseded") != bool(row["superseded_by"]):
                raise BundleError("evidence-bundle exclude application status is inconsistent")
        component_paths = bundle["component"]["paths"]
        for name, paths in (
            ("focus_paths", focus_paths),
            ("exclude_paths", [row["path"] for row in routing["exclude_application"]]),
        ):
            for index, relative in enumerate(paths):
                if relative != relative.strip().rstrip("/"):
                    raise BundleError(f"evidence-bundle {name} is not normalized: {relative!r}")
                if any(_path_overlaps(relative, prior) for prior in paths[:index]):
                    raise BundleError(f"evidence-bundle {name} contains overlapping paths")
                resolved = _canonical_under(registry["primary"], relative)
                if not resolved.exists():
                    raise BundleError(f"evidence-bundle {name} path is stale: {relative!r}")
                if not _owned_routing_path(component_paths, relative, is_directory=resolved.is_dir()):
                    raise BundleError(f"evidence-bundle {name} escapes component paths: {relative!r}")
        for focus in focus_paths:
            if any(_path_overlaps(focus, excluded) for excluded in exclude_paths):
                raise BundleError("evidence-bundle focus and exclude paths overlap")
        for row in routing["focus_admission"]:
            projected_files = row["projected_files"]
            if row["candidate_files"] != len(projected_files) + row["omitted_files"] + row["unowned_files"]:
                raise BundleError("evidence-bundle focus admission counts are inconsistent")
            if (row["status"] == "admitted") != bool(projected_files):
                raise BundleError("evidence-bundle focus admission status is inconsistent")
            expected_reason = _focus_admission_reason(
                projected=bool(projected_files),
                omitted=row["omitted_files"],
                enumeration_truncated=row["enumeration_truncated"],
                owned_candidates=row["candidate_files"] - row["unowned_files"],
                unowned_files=row["unowned_files"],
            )
            if row["reason"] != expected_reason:
                raise BundleError("evidence-bundle focus admission reason is inconsistent")
            if any(path != row["path"] and not path.startswith(row["path"] + "/") for path in projected_files):
                raise BundleError("evidence-bundle focus receipt projects a file outside its focus path")
        projected = {path for row in routing["focus_admission"] for path in row["projected_files"]}
        slice_paths = {row["path"] for row in bundle["source_slices"] if row["repository_id"] == "primary"}
        if not projected.issubset(slice_paths):
            raise BundleError("evidence-bundle focus receipt names a source file without an admitted slice")
        if any(
            _path_overlaps(excluded, row["path"])
            for excluded in exclude_paths
            for row in bundle["source_slices"]
            if row["repository_id"] == "primary"
        ):
            raise BundleError("evidence-bundle exclude path overlaps admitted source evidence")
    return bundle


def validate_bundle(
    bundle_path: Path,
    registry: dict[str, Path],
    *,
    expected_component_id: str | None = None,
    expected_sha256: str | None = None,
    expected_focus_paths: list[str] | None = None,
    expected_exclude_paths: list[str] | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    try:
        payload = bundle_path.read_bytes()
    except OSError as exc:
        raise BundleError(f"evidence bundle is unreadable: {exc}") from exc
    return validate_bundle_bytes(
        payload,
        registry,
        expected_component_id=expected_component_id,
        expected_sha256=expected_sha256,
        expected_focus_paths=expected_focus_paths,
        expected_exclude_paths=expected_exclude_paths,
        excluded_root=output_dir,
    )


def _build_bundle_without_fatal_routing(
    output_dir: Path,
    component: dict[str, Any],
    registry: dict[str, Path],
) -> tuple[dict[str, Any], bytes]:
    """Build one component bundle, never letting a routing hint kill the run.

    ``focus_paths`` and ``exclude_paths`` are producer-authored prioritization
    hints: dropping them costs ordering, not evidence. A defect confined to them
    must therefore degrade this one component, not discard a Stage 1 that a dozen
    agents already completed.

    Only ``RoutingHintError`` says the hints are at fault. Catching every
    ``BundleError`` here instead made "it builds without routing" the proof of
    attribution, which it is not: a producer defect that merely happens to
    disappear with the hints was silently downgraded to a degraded bundle, and
    the run continued on data the validator had rejected.

    The requested hints stay on the component. They are the manifest's record of
    what was asked for, and the receipt in the bundle accounts for each of them;
    overwriting them with the effective set left a rebuild unable to repeat this
    same answer.
    """
    try:
        return build_bundle(output_dir, component, registry)
    except RoutingHintError as exc:
        dropped_focus = list(component.get("focus_paths") or [])
        dropped_exclude = list(component.get("exclude_paths") or [])
        if not (dropped_focus or dropped_exclude):
            raise
        component_id = component.get("component_id")
        print(
            f"ROUTING_WARN: routing hints dropped for {component_id} after a bundle error — {exc}",
            file=sys.stderr,
        )
        return build_bundle(
            output_dir,
            dict(component, focus_paths=[], exclude_paths=[]),
            registry,
            degraded={
                "reason": "routing-hints-dropped",
                "error": str(exc)[:500],
                "dropped_focus_paths": dropped_focus,
                "dropped_exclude_paths": dropped_exclude,
            },
        )


def build_all(
    output_dir: Path,
    repo_root: Path,
    manifest: dict[str, Any],
    *,
    repository_registry: Path | None = None,
) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    registry = load_repository_registry(repo_root, repository_registry)
    seen: set[str] = set()
    for component in manifest.get("components", []):
        component_id = component.get("component_id")
        if not isinstance(component_id, str) or component_id in seen:
            raise BundleError(f"invalid or duplicate component id: {component_id!r}")
        seen.add(component_id)
        _normalize_routing_values(component, registry)
        bundle_dir = _component_context_directory(output_dir, component_id)
        business_context = business_context_projection(component.get("business_context"), component_id)
        architecture_context = architecture_context_projection(component.get("architecture_context"), component_id)
        security_contexts = component_security_context_projections(output_dir, component)
        # The source fields stay in the manifest. Consuming them made a second
        # build over the same manifest drop the two projections it had just
        # written, so the boundary could not repeat its own answer.
        bundle, payload = _build_bundle_without_fatal_routing(output_dir, component, registry)
        bundle_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = bundle_dir / "evidence-bundle.json"
        atomic_write_text(bundle_path, payload.decode("utf-8"))
        component["evidence_bundle_path"] = bundle_path.relative_to(output_dir).as_posix()
        component["evidence_bundle_sha256"] = hashlib.sha256(payload).hexdigest()
        component["evidence_bundle_estimated_tokens"] = bundle["limits"]["estimated_tokens"]
        component.pop("security_context_projections", None)
        security_context_rows: list[dict[str, Any]] = []
        for context_id, (_index_name, _evidence_class, filename) in SECURITY_CONTEXT_SPECS.items():
            security_context_path = bundle_dir / filename
            projection = security_contexts[context_id]
            if projection is None:
                if security_context_path.exists() or security_context_path.is_symlink():
                    if not security_context_path.is_file() and not security_context_path.is_symlink():
                        raise BundleError(
                            f"component security-context projection path is not a file: {security_context_path}"
                        )
                    security_context_path.unlink()
                continue
            _, security_context_payload = projection
            atomic_write_text(security_context_path, security_context_payload.decode("utf-8"))
            security_context_rows.append(
                {
                    "context_id": context_id,
                    "artifact_path": security_context_path.relative_to(output_dir).as_posix(),
                    "sha256": hashlib.sha256(security_context_payload).hexdigest(),
                    "estimated_tokens": (len(security_context_payload) + 3) // 4,
                }
            )
        for context_id, (_field_name, filename) in INLINE_SECURITY_CONTEXT_SPECS.items():
            security_context_path = bundle_dir / filename
            projection = security_contexts[context_id]
            if projection is None:
                if security_context_path.exists() or security_context_path.is_symlink():
                    if not security_context_path.is_file() and not security_context_path.is_symlink():
                        raise BundleError(
                            f"component security-context projection path is not a file: {security_context_path}"
                        )
                    security_context_path.unlink()
                continue
            _, security_context_payload = projection
            atomic_write_text(security_context_path, security_context_payload.decode("utf-8"))
            security_context_rows.append(
                {
                    "context_id": context_id,
                    "artifact_path": security_context_path.relative_to(output_dir).as_posix(),
                    "sha256": hashlib.sha256(security_context_payload).hexdigest(),
                    "estimated_tokens": (len(security_context_payload) + 3) // 4,
                }
            )
        if security_context_rows:
            component["security_context_projections"] = security_context_rows
        business_path = bundle_dir / "business-context.json"
        for key in (
            "business_context_path",
            "business_context_sha256",
            "business_context_estimated_tokens",
        ):
            component.pop(key, None)
        if business_context is None:
            if business_path.exists() or business_path.is_symlink():
                if not business_path.is_file() and not business_path.is_symlink():
                    raise BundleError(f"business-context projection path is not a file: {business_path}")
                business_path.unlink()
        else:
            business_payload = _canonical_bytes(business_context) + b"\n"
            validate_business_context_bytes(business_payload, expected_component_id=component_id)
            atomic_write_text(business_path, business_payload.decode("utf-8"))
            component["business_context_path"] = business_path.relative_to(output_dir).as_posix()
            component["business_context_sha256"] = hashlib.sha256(business_payload).hexdigest()
            component["business_context_estimated_tokens"] = (len(business_payload) + 3) // 4
        architecture_path = bundle_dir / "architecture-context.json"
        for key in (
            "architecture_context_path",
            "architecture_context_sha256",
            "architecture_context_estimated_tokens",
        ):
            component.pop(key, None)
        if architecture_context is None:
            if architecture_path.exists() or architecture_path.is_symlink():
                if not architecture_path.is_file() and not architecture_path.is_symlink():
                    raise BundleError(f"architecture-context projection path is not a file: {architecture_path}")
                architecture_path.unlink()
        else:
            architecture_payload = _canonical_bytes(architecture_context) + b"\n"
            validate_architecture_context_bytes(architecture_payload, expected_component_id=component_id)
            atomic_write_text(architecture_path, architecture_payload.decode("utf-8"))
            component["architecture_context_path"] = architecture_path.relative_to(output_dir).as_posix()
            component["architecture_context_sha256"] = hashlib.sha256(architecture_payload).hexdigest()
            component["architecture_context_estimated_tokens"] = (len(architecture_payload) + 3) // 4
    manifest["context_version"] = 2
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_stride_evidence_bundles.py")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--repository-registry", type=Path)
    args = parser.parse_args(argv)
    manifest_path = args.manifest or args.output_dir / ".stride-dispatch-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        build_all(
            args.output_dir,
            args.repo_root,
            manifest,
            repository_registry=args.repository_registry,
        )
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, BundleError, KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"OK: wrote {len(manifest['components'])} bounded STRIDE evidence bundle(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
