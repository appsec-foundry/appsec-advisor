#!/usr/bin/env python3
"""Evaluate the Config/IaC rule catalog deterministically."""

from __future__ import annotations

import argparse
import datetime as dt
import re
from pathlib import Path
from typing import Any

import yaml
from _atomic_io import atomic_write_json

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CHECKS = PLUGIN_ROOT / "data" / "config-iac-checks.yaml"
QUICK_FILES_PER_CATEGORY = 5
AUDIT_MARKERS = ("// audited:", "# audited:", "<!-- audited:")


class ConfigScanError(RuntimeError):
    """Raised when the catalog or a scan path violates the producer contract."""


def _canonical_file(repo_root: Path, path: Path) -> Path:
    root = repo_root.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ConfigScanError(f"scan path escapes repository root: {path}") from exc
    if not resolved.is_file():
        raise ConfigScanError(f"scan target is not a regular file: {path}")
    return resolved


def _catalog(path: Path) -> list[dict[str, Any]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigScanError(f"cannot load check catalog {path}: {exc}") from exc
    checks = data.get("checks") if isinstance(data, dict) else None
    if not isinstance(checks, list) or not checks:
        raise ConfigScanError("check catalog must contain a non-empty checks list")
    patterns_by_type = data.get("file_patterns_by_type", {})
    if not isinstance(patterns_by_type, dict):
        raise ConfigScanError("file_patterns_by_type must be a mapping")
    required = {"id", "name", "iac_type", "file_pattern", "expect", "severity_if_violated", "cwe"}
    seen: set[str] = set()
    for index, check in enumerate(checks):
        if not isinstance(check, dict) or not required.issubset(check):
            raise ConfigScanError(f"check catalog entry {index} is incomplete")
        check_id = check["id"]
        if not isinstance(check_id, str) or check_id in seen:
            raise ConfigScanError(f"check catalog entry {index} has an invalid or duplicate id")
        seen.add(check_id)
        configured_patterns = patterns_by_type.get(check["iac_type"], [check["file_pattern"]])
        if (
            not isinstance(configured_patterns, list)
            or not configured_patterns
            or not all(isinstance(value, str) and value for value in configured_patterns)
        ):
            raise ConfigScanError(f"{check_id} has invalid category file patterns")
        check["_file_patterns"] = configured_patterns
        pattern = check.get("pattern")
        if isinstance(pattern, str) and pattern:
            try:
                re.compile(pattern, re.MULTILINE | re.DOTALL)
            except re.error as exc:
                raise ConfigScanError(f"{check_id} has an invalid pattern: {exc}") from exc
        if check["expect"] in {"any_of", "any_of_present"}:
            alternatives = check.get("pattern_any_of")
            if (
                not isinstance(alternatives, list)
                or not alternatives
                or not all(isinstance(value, str) and value for value in alternatives)
            ):
                raise ConfigScanError(f"{check_id} requires non-empty pattern_any_of strings")
            for value in alternatives:
                try:
                    re.compile(value, re.MULTILINE | re.DOTALL)
                except re.error as exc:
                    raise ConfigScanError(f"{check_id} has an invalid pattern_any_of value: {exc}") from exc
    return checks


def _matches_for_check(repo_root: Path, check: dict[str, Any]) -> list[Path]:
    patterns = check.get("_file_patterns", [check["file_pattern"]])
    paths: list[Path] = []
    for pattern in patterns:
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ConfigScanError(f"{check['id']} has an unsafe file_pattern")
        try:
            candidates = repo_root.glob(pattern)
            paths.extend(_canonical_file(repo_root, path) for path in candidates if path.is_file())
        except (OSError, ValueError) as exc:
            raise ConfigScanError(f"{check['id']} cannot enumerate {pattern!r}: {exc}") from exc
    return sorted(set(paths), key=lambda path: path.relative_to(repo_root.resolve()).as_posix())


def _selected_files(
    repo_root: Path,
    checks: list[dict[str, Any]],
    *,
    depth: str,
) -> dict[str, list[Path]]:
    by_check = {check["id"]: _matches_for_check(repo_root, check) for check in checks}
    if depth != "quick":
        return by_check
    category_files: dict[str, set[Path]] = {}
    for check in checks:
        category_files.setdefault(check["iac_type"], set()).update(by_check[check["id"]])
    admitted = {
        category: set(
            sorted(paths, key=lambda path: path.relative_to(repo_root.resolve()).as_posix())[:QUICK_FILES_PER_CATEGORY]
        )
        for category, paths in category_files.items()
    }
    return {
        check["id"]: [path for path in by_check[check["id"]] if path in admitted[check["iac_type"]]] for check in checks
    }


def _line_for_offset(text: str, offset: int) -> tuple[int, str]:
    line = text.count("\n", 0, offset) + 1
    lines = text.splitlines()
    snippet = lines[line - 1].strip() if line <= len(lines) else ""
    return line, snippet[:500]


def _first_line(text: str) -> str:
    lines = text.splitlines()
    return (lines[0].strip() if lines else "")[:500]


def _third_party_action_violation(text: str) -> tuple[int, str] | None:
    for match in re.finditer(r"(?m)^\s*(?:-\s*)?uses\s*:\s*([^\s#]+)", text):
        reference = match.group(1).strip("\"'")
        if reference.startswith(("actions/", "./", "docker://")):
            continue
        _, separator, revision = reference.rpartition("@")
        if separator and re.fullmatch(r"[0-9a-fA-F]{40}", revision):
            continue
        return _line_for_offset(text, match.start())
    return None


def _undocumented_match(pattern: re.Pattern[str], text: str) -> tuple[int, str] | None:
    lines = text.splitlines()
    for match in pattern.finditer(text):
        line, snippet = _line_for_offset(text, match.start())
        adjacent = lines[max(0, line - 2) : min(len(lines), line + 1)]
        if not any(marker in value.lower() for value in adjacent for marker in AUDIT_MARKERS):
            return line, snippet
    return None


def _violation(check: dict[str, Any], path: Path, text: str) -> tuple[int, str] | None:
    expect = check["expect"]
    pattern_text = check.get("pattern")
    pattern = (
        re.compile(pattern_text, re.MULTILINE | re.DOTALL) if isinstance(pattern_text, str) and pattern_text else None
    )
    match = pattern.search(text) if pattern is not None else None
    if expect == "present":
        return None if match else (1, _first_line(text))
    if expect == "absent":
        return _line_for_offset(text, match.start()) if match else None
    if expect == "all_third_party_actions":
        return _third_party_action_violation(text)
    if expect in {"any_of", "any_of_present"}:
        patterns = check.get("pattern_any_of")
        if any(re.search(value, text, re.MULTILINE | re.DOTALL) for value in patterns):
            return None
        return 1, _first_line(text)
    if expect == "absent_or_documented":
        if pattern is None:
            raise ConfigScanError(f"{check['id']} requires a pattern")
        return _undocumented_match(pattern, text)
    if expect == "file_exists":
        return None
    raise ConfigScanError(f"{check['id']} has unsupported expectation {expect!r}")


def _generated_at(output: Path) -> str:
    epoch_path = output.parent / ".scan-start-epoch"
    try:
        epoch = int(epoch_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scan(repo_root: Path, checks_path: Path, *, depth: str, output: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    if not repo_root.is_dir():
        raise ConfigScanError(f"repository root is not a directory: {repo_root}")
    checks = _catalog(checks_path)
    selected = _selected_files(repo_root, checks, depth=depth)
    pending: list[dict[str, Any]] = []
    for check in checks:
        paths = selected[check["id"]]
        if check["expect"] == "file_exists" and not paths:
            pending.append({"check": check, "path": None, "line": 0, "snippet": "File not found"})
            continue
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ConfigScanError(f"cannot read scan target {path}: {exc}") from exc
            violation = _violation(check, path, text)
            if violation is not None:
                line, snippet = violation
                pending.append({"check": check, "path": path, "line": line, "snippet": snippet})

    findings: list[dict[str, Any]] = []
    for index, row in enumerate(pending, start=1):
        check = row["check"]
        relative = check["file_pattern"] if row["path"] is None else row["path"].relative_to(repo_root).as_posix()
        findings.append(
            {
                "local_id": f"CFG-{index:03d}",
                "check_id": check["id"],
                "finding_type_id": check.get("finding_type"),
                "iac_type": check["iac_type"],
                "file": relative,
                "line": row["line"],
                "evidence_snippet": row["snippet"],
                "title": check["name"],
                "scenario": f"{check['name']}: {check.get('rationale', '').strip()}",
                "severity": check["severity_if_violated"],
                "cwe": [check["cwe"]],
                "recommended_mitigation_title": check.get("remediation"),
                "breach_vector": "Build-Time",
            }
        )
    return {
        "version": 1,
        "generated_at": _generated_at(output),
        "checks_run": len(checks),
        "violations": len(findings),
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checks", type=Path, default=DEFAULT_CHECKS)
    parser.add_argument("--assessment-depth", choices=("quick", "standard", "thorough"), default="standard")
    args = parser.parse_args(argv)
    try:
        result = scan(args.repo_root, args.checks, depth=args.assessment_depth, output=args.output)
        atomic_write_json(args.output, result, sort_keys=False)
    except (ConfigScanError, OSError) as exc:
        parser.error(str(exc))
    print(f"config-iac-scanner: {result['checks_run']} checks, {result['violations']} violations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
