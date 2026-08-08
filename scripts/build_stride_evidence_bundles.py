#!/usr/bin/env python3
"""Build and validate bounded component-local evidence for STRIDE dispatch."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-evidence-bundle.schema.json"
BUSINESS_CONTEXT_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-component-business-context.schema.json"
ARCHITECTURE_CONTEXT_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-component-architecture-context.schema.json"
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
    "controls",
    "actors",
    "trust_boundaries",
    "known_threats",
    "prior_findings",
    "requirements",
    "cross_repo",
    "recon_signals",
)
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


def repository_fingerprint(repo_root: Path, *, excluded_root: Path | None = None) -> tuple[str, str]:
    """Bind a repository to HEAD and the exact bytes of every dirty file."""
    repo_root = repo_root.resolve()
    commit_raw = _git_output(repo_root, "rev-parse", "HEAD").strip().lower()
    commit = commit_raw.decode("ascii", errors="ignore")
    if len(commit) < 40 or any(char not in "0123456789abcdef" for char in commit):
        commit = "unversioned"

    dirty = hashlib.sha256()
    worktree_names = _git_output(
        repo_root,
        "ls-files",
        "-m",
        "-o",
        "--exclude-standard",
        "-z",
    ).split(b"\0")
    index_names = _git_output(repo_root, "diff", "--cached", "--name-only", "-z").split(b"\0")
    names = {name for name in [*worktree_names, *index_names] if name}
    for raw_name in sorted(names):
        try:
            relative = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            relative = raw_name.decode("utf-8", errors="surrogateescape")
        try:
            path = _canonical_under(repo_root, relative)
            if excluded_root is not None:
                try:
                    path.relative_to(excluded_root.resolve())
                except ValueError:
                    pass
                else:
                    continue
            dirty.update(raw_name)
            dirty.update(b"\0")
            if path.is_file():
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        dirty.update(chunk)
        except (BundleError, OSError, UnicodeError):
            dirty.update(raw_name)
            dirty.update(b"\0")
            dirty.update(b"<unreadable>")
        dirty.update(b"\0")
    return commit, dirty.hexdigest()


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
        for key in ("findings", "entries", "actors", "trust_boundaries", "violations", "items"):
            if isinstance(value.get(key), list):
                return value[key]
        return [{key: value[key]} for key in sorted(value)]
    return [value]


def _bounded_records(source: str, values: list[Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    records = sorted((_record(source, value) for value in values), key=lambda row: _canonical_bytes(row))
    retained = records[:MAX_CLASS_VALUES]
    return retained, {"original": len(records), "value_truncations": sum(row["truncated"] for row in retained)}


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


def _owned(component_paths: list[str], relative: str) -> bool:
    if not component_paths:
        return True
    for pattern in component_paths:
        if pattern in {"**", "**/*"}:
            return True
        if fnmatch.fnmatchcase(relative, pattern):
            return True
        if pattern.endswith("/**") and relative.startswith(pattern[:-3].rstrip("/") + "/"):
            return True
    return False


def _path_overlaps(left: str, right: str) -> bool:
    """Return whether two normalized literal paths contain one another."""
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _normalize_routing_values(component: dict[str, Any], registry: dict[str, Path]) -> tuple[list[str], list[str]]:
    """Normalize the compatibility string-or-list routing inputs at dispatch."""
    component_id = component["component_id"]
    paths_value = component.get("component_paths") or []
    component_paths = [paths_value] if isinstance(paths_value, str) else [str(value) for value in paths_value]
    repo_root = registry["primary"]

    def normalize(name: str) -> list[str]:
        raw = component.get(name)
        if raw is None:
            return []
        if isinstance(raw, str):
            values = raw.split(",")
        elif isinstance(raw, list):
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
                raise BundleError(f"{name} for {component_id} names a missing repository path: {value!r}")
            if not (_owned(component_paths, value) or (resolved.is_dir() and _owned(component_paths, value + "/x"))):
                raise BundleError(f"{name} for {component_id} is outside the component paths: {value!r}")
            if value in normalized:
                continue
            if any(_path_overlaps(value, prior) for prior in normalized):
                raise BundleError(f"{name} for {component_id} contains overlapping paths: {value!r}")
            normalized.append(value)
        return normalized

    focus_paths = normalize("focus_paths")
    exclude_paths = normalize("exclude_paths")
    for focus in focus_paths:
        for excluded in exclude_paths:
            if _path_overlaps(focus, excluded):
                raise BundleError(
                    f"focus_paths and exclude_paths overlap for {component_id}: {focus!r} and {excluded!r}"
                )
    component["focus_paths"] = focus_paths
    component["exclude_paths"] = exclude_paths
    return focus_paths, exclude_paths


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
                            for key in ("rule_id", "category", "subcategory", "strength", "kind", "message")
                            if key in value
                        },
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
        normalized.append(row_out)
        summaries.append(
            {
                "repository_id": repository_id,
                "file": relative,
                "line": row["start_line"],
                "signal_kind": row["signal_kind"],
                **row["summary"],
            }
        )

    keyed = {
        (row["repository_id"], row["path"], row["start_line"], row["end_line"], row["signal_kind"]): row
        for row in normalized
    }
    ordered = [keyed[key] for key in sorted(keyed)]
    retained: list[dict[str, Any]] = []
    source_lines = 0
    for row in ordered:
        span = row["end_line"] - row["start_line"] + 1
        if len(retained) >= MAX_SOURCE_SLICES or source_lines + span > MAX_SOURCE_LINES:
            continue
        retained.append(row)
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
        canonical = _canonical_under(repo_root, candidate_relative)
        if not canonical.is_file() or is_excluded(candidate_relative) or is_oversize(canonical):
            continue
        retained.append(candidate_relative)
    return sorted(dict.fromkeys(retained)), truncated


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
        files, enumeration_truncated = _focus_candidate_files(repo_root, focus_path)
        if any(not _owned(component_paths, path) for path in files):
            raise BundleError(f"focus path projection escapes component paths: {focus_path!r}")
        projected: list[str] = []
        omitted = 0
        for relative in files:
            if relative in retained_files:
                projected.append(relative)
                continue
            path = _canonical_under(repo_root, relative)
            try:
                line_count = len(path.read_bytes().splitlines())
            except OSError as exc:
                raise BundleError(f"cannot read focus path projection {relative}: {exc}") from exc
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

        if projected and (omitted or enumeration_truncated):
            reason = "partially-projected"
        elif projected:
            reason = "projected"
        elif enumeration_truncated:
            reason = "enumeration-budget"
        elif files:
            reason = "source-budget"
        else:
            reason = "no-readable-files"
        decisions.append(
            {
                "path": focus_path,
                "status": "admitted" if projected else "omitted",
                "reason": reason,
                "candidate_files": len(files),
                "projected_files": sorted(projected),
                "omitted_files": omitted,
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
) -> tuple[dict[str, Any], bytes]:
    component_id = component["component_id"]
    paths_value = component.get("component_paths") or []
    component_paths = [paths_value] if isinstance(paths_value, str) else [str(value) for value in paths_value]
    focus_paths = list(component.get("focus_paths") or [])
    exclude_paths = list(component.get("exclude_paths") or [])
    path_original = len(component_paths)
    component_paths = sorted(dict.fromkeys(component_paths))[:32]

    raw: dict[str, list[Any]] = {name: [] for name in EVIDENCE_CLASSES}
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
    )
    raw["recon_signals"].extend(signal_summaries)
    for evidence_class in EVIDENCE_CLASSES:
        protected_paths.update(_referenced_primary_paths(raw[evidence_class]))
    normalized_protected: set[str] = set()
    for relative in protected_paths:
        try:
            _canonical_under(registry["primary"], relative)
        except BundleError:
            continue
        normalized_protected.add(relative.rstrip("/"))
    for excluded in exclude_paths:
        conflicts = sorted(path for path in normalized_protected if _path_overlaps(excluded, path))
        if conflicts:
            raise BundleError(
                f"exclude_paths for {component_id} would hide mandatory or cited evidence: " + ", ".join(conflicts[:5])
            )

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
    repository_state = []
    for repository_id in sorted(admitted_repository_ids):
        root = registry[repository_id]
        commit, dirty = repository_fingerprint(
            root,
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
            "exclude_application": [
                {"path": path, "status": "applied", "scope": "optional-discovery-only"} for path in exclude_paths
            ],
            "protected_evidence_path_count": len(normalized_protected),
            "protected_evidence_paths_sha256": hashlib.sha256(
                _canonical_bytes(sorted(normalized_protected))
            ).hexdigest(),
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
        if expected_focus_paths is not None and routing.get("focus_paths") != expected_focus_paths:
            raise BundleError("evidence-bundle focus paths do not match the dispatch entry")
        if expected_exclude_paths is not None and routing.get("exclude_paths") != expected_exclude_paths:
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
    for repository_id in sorted(required_repository_ids):
        root = registry[repository_id]
        commit, dirty = repository_fingerprint(
            root,
            excluded_root=excluded_root if repository_id == "primary" else None,
        )
        state = state_by_id[repository_id]
        expected_kind = "primary" if repository_id == "primary" else "related"
        if state["kind"] != expected_kind:
            raise BundleError(f"evidence-bundle repository kind is invalid for: {repository_id}")
        if state["commit_sha"] != commit or state["dirty_worktree_sha256"] != dirty:
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
        if [row["path"] for row in routing["focus_admission"]] != focus_paths:
            raise BundleError("evidence-bundle focus admission receipt is incomplete or reordered")
        if [row["path"] for row in routing["exclude_application"]] != exclude_paths:
            raise BundleError("evidence-bundle exclude application receipt is incomplete or reordered")
        component_paths = bundle["component"]["paths"]
        for name, paths in (("focus_paths", focus_paths), ("exclude_paths", exclude_paths)):
            for index, relative in enumerate(paths):
                if relative != relative.strip().rstrip("/"):
                    raise BundleError(f"evidence-bundle {name} is not normalized: {relative!r}")
                if any(_path_overlaps(relative, prior) for prior in paths[:index]):
                    raise BundleError(f"evidence-bundle {name} contains overlapping paths")
                resolved = _canonical_under(registry["primary"], relative)
                if not resolved.exists():
                    raise BundleError(f"evidence-bundle {name} path is stale: {relative!r}")
                if not (
                    _owned(component_paths, relative)
                    or (resolved.is_dir() and _owned(component_paths, relative + "/x"))
                ):
                    raise BundleError(f"evidence-bundle {name} escapes component paths: {relative!r}")
        for focus in focus_paths:
            if any(_path_overlaps(focus, excluded) for excluded in exclude_paths):
                raise BundleError("evidence-bundle focus and exclude paths overlap")
        for row in routing["focus_admission"]:
            projected_files = row["projected_files"]
            if row["candidate_files"] != len(projected_files) + row["omitted_files"]:
                raise BundleError("evidence-bundle focus admission counts are inconsistent")
            if (row["status"] == "admitted") != bool(projected_files):
                raise BundleError("evidence-bundle focus admission status is inconsistent")
            expected_reason = (
                "partially-projected"
                if projected_files and (row["omitted_files"] or row["enumeration_truncated"])
                else "projected"
                if projected_files
                else "enumeration-budget"
                if row["enumeration_truncated"]
                else "source-budget"
                if row["candidate_files"]
                else "no-readable-files"
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
        business_context = business_context_projection(component.get("business_context"), component_id)
        architecture_context = architecture_context_projection(component.get("architecture_context"), component_id)
        component.pop("business_context", None)
        component.pop("architecture_context", None)
        bundle, payload = build_bundle(output_dir, component, registry)
        bundle_dir = output_dir / ".dispatch-context" / component_id
        bundle_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = bundle_dir / "evidence-bundle.json"
        bundle_path.write_bytes(payload)
        component["evidence_bundle_path"] = bundle_path.relative_to(output_dir).as_posix()
        component["evidence_bundle_sha256"] = hashlib.sha256(payload).hexdigest()
        component["evidence_bundle_estimated_tokens"] = bundle["limits"]["estimated_tokens"]
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
            business_path.write_bytes(business_payload)
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
            architecture_path.write_bytes(architecture_payload)
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
