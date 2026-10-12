#!/usr/bin/env python3
"""Decide which prior STRIDE outputs an incremental run carries (decision IN-5).

An incremental run reuses a component's previous ``.stride-<id>.json`` only
when nothing the analysis depended on can have changed. Three steps own that
decision, in run order:

``admission_refusal``
    Read-only check at routing time. It names the first condition that keeps
    the previous model from being a carry baseline (DP-2, DP-3); the
    controller refuses the run before any output mutation when one fails.

``stash``
    Under the run lock and before the full preflight cleanup, moves each prior
    STRIDE output whose bytes still match ``.appsec-cache/baseline.json`` into
    the carry area, so the cleanup cannot delete it.

``plan``
    After the new dispatch manifest exists, restores every component that is
    still eligible and records the decision in ``.incremental-carry.json``
    (``schemas/incremental-carry.schema.json``). Everything else is
    re-analyzed by the normal STRIDE wave; the carry area is removed.

A carried file is never rewritten: it must pass the current completion gate
without repair, otherwise its component is re-analyzed.
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
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

CARRY_DIR = Path(".appsec-cache") / "carry"
PLAN_ARTIFACT = ".incremental-carry.json"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "incremental-carry.schema.json"
_DEPTH_ORDER = ("quick", "standard", "thorough")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_GLOB_CHARS = frozenset("*?[")


class CarryError(Exception):
    """The carry state cannot be read or verified."""


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load_model(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "threat-model.yaml"
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CarryError(f"the existing threat-model.yaml cannot be read: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("meta"), dict):
        raise CarryError("the existing threat-model.yaml has no meta block")
    return document


def _recorded_stride_hashes(output_dir: Path) -> dict[str, str]:
    path = output_dir / ".appsec-cache" / "baseline.json"
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CarryError(f".appsec-cache/baseline.json is missing or unreadable: {exc}") from exc
    files = baseline.get("stride_files") if isinstance(baseline, dict) else None
    if not isinstance(files, dict):
        raise CarryError(".appsec-cache/baseline.json records no STRIDE output hashes")
    return {
        component_id: record["sha256"]
        for component_id, record in files.items()
        if isinstance(record, dict) and isinstance(record.get("sha256"), str)
    }


def _git(repo_root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            text=True,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CarryError(f"git is unavailable: {exc}") from exc
    if result.returncode != 0:
        raise CarryError(f"git {args[0]} failed: {result.stderr.strip() or result.returncode}")
    return result.stdout


def _baseline_commit(model: dict[str, Any]) -> str:
    git = model["meta"].get("git")
    sha = git.get("commit_sha") if isinstance(git, dict) else None
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        raise CarryError("the existing model records no git commit to compare against")
    return sha


def _verify_commit(repo_root: Path, sha: str) -> None:
    if _git(repo_root, "rev-parse", "--is-inside-work-tree").strip() != "true":
        raise CarryError(f"{repo_root} is not a git working tree")
    try:
        _git(repo_root, "cat-file", "-e", f"{sha}^{{commit}}")
    except CarryError as exc:
        raise CarryError(f"the baseline commit {sha} is not in this repository's history") from exc


def admission_refusal(
    output_dir: Path,
    repo_root: Path,
    *,
    depth: str,
    check_requirements: bool,
    analysis_version: int,
) -> str | None:
    """Name the first condition that keeps this run from carrying, or ``None``.

    Read-only: routing must not mutate the output directory.
    """
    from shared.assessment_sources import model_file_is_portable  # noqa: PLC0415

    output_dir, repo_root = Path(output_dir), Path(repo_root)
    model_path = output_dir / "threat-model.yaml"
    if not model_path.is_file():
        return "no structured threat-model.yaml exists to carry from"
    if model_file_is_portable(model_path):
        return "the existing model is a combined multi-repository assessment, which incremental runs do not support"
    try:
        model = _load_model(output_dir)
        meta = model["meta"]
        prior_depth = str(meta.get("assessment_depth") or "").strip().lower()
        current_depth = (depth or "standard").strip().lower()
        if prior_depth not in _DEPTH_ORDER:
            return "the existing model records no assessment depth"
        if current_depth != prior_depth:
            if _DEPTH_ORDER.index(current_depth if current_depth in _DEPTH_ORDER else "standard") < _DEPTH_ORDER.index(
                prior_depth
            ):
                return (
                    f"--assessment-depth {current_depth} is shallower than the existing model's {prior_depth} "
                    "depth, and carried STRIDE output would keep the deeper depth"
                )
            return (
                f"--assessment-depth {current_depth} is deeper than the existing model's {prior_depth} depth, "
                "and carried components would not be deepened"
            )
        if meta.get("analysis_version") != analysis_version:
            return (
                f"the existing model was built with analysis version {meta.get('analysis_version')!r}, "
                f"this plugin uses {analysis_version}"
            )
        if not isinstance(meta.get("check_requirements"), bool):
            return "the existing model does not record whether it was checked against security requirements"
        if meta["check_requirements"] != bool(check_requirements):
            return "the security-requirements check was switched " + ("on" if check_requirements else "off")
        sha = _baseline_commit(model)
        _verify_commit(repo_root, sha)
        recorded = _recorded_stride_hashes(output_dir)
    except CarryError as exc:
        return str(exc)
    verified = [
        component_id
        for component_id, digest in recorded.items()
        if (output_dir / f".stride-{component_id}.json").is_file()
        and _sha256(output_dir / f".stride-{component_id}.json") == digest
    ]
    if not verified:
        return "no STRIDE output recorded in .appsec-cache/baseline.json is present with its recorded hash"
    return None


def discard(output_dir: Path) -> None:
    """Remove a carry area a previous, interrupted run left behind."""
    shutil.rmtree(Path(output_dir) / CARRY_DIR, ignore_errors=True)


def stash(output_dir: Path) -> list[str]:
    """Move hash-verified prior STRIDE outputs into the carry area.

    Call under the run lock and before the full cleanup, which would delete
    them. A file whose bytes no longer match its baseline hash stays behind
    and is cleaned like any other intermediate.
    """
    output_dir = Path(output_dir)
    discard(output_dir)
    try:
        recorded = _recorded_stride_hashes(output_dir)
    except CarryError:
        return []
    carry_dir = output_dir / CARRY_DIR
    stashed: list[str] = []
    for component_id, digest in sorted(recorded.items()):
        source = output_dir / f".stride-{component_id}.json"
        if not source.is_file() or source.is_symlink() or _sha256(source) != digest:
            continue
        carry_dir.mkdir(parents=True, exist_ok=True)
        os.replace(source, carry_dir / source.name)
        stashed.append(component_id)
    return stashed


def _relevance_filter():
    import analyzers.security_relevance_filter as security_relevance_filter  # noqa: PLC0415

    return security_relevance_filter


def _counts_as_change(
    path: str,
    *,
    repo_root: Path,
    baseline_sha: str,
    deleted: bool,
    untracked: bool,
    output_rel: str | None,
) -> bool:
    """Whether a changed file can invalidate the STRIDE output of its component.

    The single place that owns IN-5's relevance rule. A change is irrelevant
    only when its path class is documentation, test, IDE, scan-excluded or an
    irrelevant extension, or when a tracked manifest, Dockerfile, IaC or
    workflow diff is not semantic (whitespace-only, patch-level bump).
    Deletions, untracked files outside those path classes, and every
    path-undecided source file count; diff keyword patterns are never used.
    Files under the plugin's own output directory are not repository source.
    """
    if output_rel and (path == output_rel or path.startswith(output_rel.rstrip("/") + "/")):
        return False
    if deleted:
        return True
    srf = _relevance_filter()
    decision, reasons = srf.classify_by_path(path)
    if decision is False:
        return False
    # `_is_tier1_downgradeable` is private to the filter; it is imported
    # deliberately so the downgradeable reason set has one owner.
    if decision is True and not untracked and srf._is_tier1_downgradeable(reasons):
        is_semantic, _details = srf.has_semantic_diff(str(repo_root), baseline_sha, path)
        return bool(is_semantic)
    return True


def changed_files(output_dir: Path, repo_root: Path, baseline_sha: str) -> list[str]:
    """Repository files that changed since the baseline commit and count as a change.

    Covers commits since the baseline, staged and unstaged edits, deletions,
    and untracked files. A git failure raises instead of reporting no change.
    """
    output_dir, repo_root = Path(output_dir), Path(repo_root)
    status = _git(repo_root, "diff", "--name-status", "--no-renames", "-z", baseline_sha)
    fields = [field for field in status.split("\0") if field]
    entries: dict[str, tuple[bool, bool]] = {}
    for index in range(0, len(fields) - 1, 2):
        entries[fields[index + 1]] = (fields[index].startswith("D"), False)
    for path in _git(repo_root, "ls-files", "-z", "--others", "--exclude-standard").split("\0"):
        if path:
            entries.setdefault(path, (False, True))
    try:
        output_rel: str | None = output_dir.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        output_rel = None
    return sorted(
        path
        for path, (deleted, untracked) in entries.items()
        if _counts_as_change(
            path,
            repo_root=repo_root,
            baseline_sha=baseline_sha,
            deleted=deleted,
            untracked=untracked,
            output_rel=output_rel,
        )
    )


def _normalized_paths(raw: Any) -> list[str]:
    values = raw.split(",") if isinstance(raw, str) else raw if isinstance(raw, list) else []
    out = set()
    for value in values:
        text = str(value).strip().replace("\\", "/")
        while text.startswith("./"):
            text = text[2:]
        if text:
            out.add(text)
    return sorted(out)


def _owned(path: str, pattern: str) -> bool:
    """Whether ``path`` lies under a component path (glob, directory, or file)."""
    if _GLOB_CHARS & set(pattern):
        from baseline.baseline_state import _glob_to_regex  # noqa: PLC0415

        return bool(_glob_to_regex(pattern).match(path))
    stem = pattern.rstrip("/")
    return path == stem or path.startswith(stem + "/")


def _catalog_sha(output_dir: Path) -> str | None:
    path = output_dir / ".requirements.yaml"
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def plan(output_dir: Path, repo_root: Path, manifest: dict[str, Any], *, check_requirements: bool) -> dict[str, Any]:
    """Restore every still-eligible carried output and write ``.incremental-carry.json``."""
    import orchestrator.stride_dispatch_waves as stride_dispatch_waves  # noqa: PLC0415

    from baseline.baseline_state import _parse_components_from_yaml  # noqa: PLC0415

    output_dir, repo_root = Path(output_dir), Path(repo_root)
    carry_dir = output_dir / CARRY_DIR
    try:
        model = _load_model(output_dir)
        baseline_sha = _baseline_commit(model)
        recorded = _recorded_stride_hashes(output_dir)
        changed = changed_files(output_dir, repo_root, baseline_sha)
    except CarryError:
        discard(output_dir)
        raise
    prior_paths = {
        row["id"]: _normalized_paths(row.get("paths"))
        for row in _parse_components_from_yaml(output_dir / "threat-model.yaml")
    }
    requirements_changed = False
    if check_requirements:
        provenance = model.get("requirements_provenance")
        prior_catalog = provenance.get("catalog_sha256") if isinstance(provenance, dict) else None
        requirements_changed = not prior_catalog or prior_catalog != _catalog_sha(output_dir)

    carried: list[str] = []
    reanalyzed: list[dict[str, str]] = []
    for component in manifest.get("components") or []:
        component_id = component["component_id"]
        paths = _normalized_paths(component.get("component_paths"))
        source = carry_dir / f".stride-{component_id}.json"
        reason = None
        if component_id not in prior_paths:
            reason = "new_component"
        elif prior_paths[component_id] != paths:
            reason = "paths_changed"
        elif requirements_changed:
            reason = "requirements_changed"
        elif not source.is_file():
            reason = "no_prior_output"
        elif _sha256(source) != recorded.get(component_id):
            reason = "hash_mismatch"
        elif any(_owned(path, pattern) for path in changed for pattern in paths):
            reason = "files_changed"
        else:
            try:
                data = json.loads(source.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = None
            if stride_dispatch_waves.carried_output_error(output_dir, component_id, data):
                reason = "contract_rejected"
        if reason:
            reanalyzed.append({"component_id": component_id, "reason": reason})
            continue
        os.replace(source, output_dir / source.name)
        carried.append(component_id)
    discard(output_dir)

    result = {
        "schema_version": 1,
        "baseline_commit": baseline_sha,
        "changed_file_count": len(changed),
        "carried": carried,
        "reanalyzed": reanalyzed,
    }
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    from shared._atomic_io import atomic_write_json  # noqa: PLC0415

    atomic_write_json(output_dir / PLAN_ARTIFACT, result, indent=2)
    return result


def carried_ids(output_dir: Path) -> set[str]:
    """Components this run carried, from a schema-valid ``.incremental-carry.json``."""
    path = Path(output_dir) / PLAN_ARTIFACT
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    if not validator.is_valid(data):
        return set()
    return set(data["carried"])
