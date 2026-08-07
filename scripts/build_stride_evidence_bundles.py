#!/usr/bin/env python3
"""Build and validate bounded component-local evidence for STRIDE dispatch."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-evidence-bundle.schema.json"
REGISTRY_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-repository-registry.schema.json"
RELATED_REPOS_SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "related-repos.schema.yaml"

MAX_BUNDLE_BYTES = 65_536
MAX_ESTIMATED_TOKENS = 16_384
MAX_SOURCE_LINES = 400
MAX_SOURCE_SLICES = 24
MAX_SLICE_LINES = 40
MAX_CLASS_VALUES = 32
MAX_VALUE_CHARS = 4096

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
) -> tuple[list[dict[str, Any]], list[Any], int]:
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
    return retained, summaries, len(ordered)


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

    source_slices, signal_summaries, original_slice_count = _source_signals(
        output_dir,
        component_paths,
        registry,
    )
    raw["recon_signals"].extend(signal_summaries)

    evidence: dict[str, list[dict[str, Any]]] = {}
    stats: dict[str, dict[str, int]] = {}
    for name in EVIDENCE_CLASSES:
        evidence[name], stats[name] = _bounded_records(name, raw[name])

    repository_state = []
    for repository_id, root in sorted(registry.items()):
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
    if original_slice_count > len(source_slices):
        bundle["truncation"].append(
            {
                "signal_class": "source_slices",
                "original_count": original_slice_count,
                "retained_count": len(source_slices),
                "omitted_count": original_slice_count - len(source_slices),
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
    if bundle["limits"]["serialized_bytes"] != len(payload):
        raise BundleError("evidence-bundle serialized byte count is stale")
    if bundle["limits"]["estimated_tokens"] != (len(payload) + 3) // 4:
        raise BundleError("evidence-bundle estimated token count is stale")

    state_rows = bundle["repository_state"]
    state_by_id = {row["repository_id"]: row for row in state_rows}
    if len(state_rows) != len(state_by_id):
        raise BundleError("evidence-bundle repository state contains duplicate repository ids")
    if set(state_by_id) != set(registry):
        raise BundleError("evidence-bundle repository state does not match the controller registry")
    for repository_id, root in registry.items():
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
    return bundle


def validate_bundle(
    bundle_path: Path,
    registry: dict[str, Path],
    *,
    expected_component_id: str | None = None,
    expected_sha256: str | None = None,
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
        bundle, payload = build_bundle(output_dir, component, registry)
        bundle_dir = output_dir / ".dispatch-context" / component_id
        bundle_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = bundle_dir / "evidence-bundle.json"
        bundle_path.write_bytes(payload)
        component["evidence_bundle_path"] = bundle_path.relative_to(output_dir).as_posix()
        component["evidence_bundle_sha256"] = hashlib.sha256(payload).hexdigest()
        component["evidence_bundle_estimated_tokens"] = bundle["limits"]["estimated_tokens"]
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
