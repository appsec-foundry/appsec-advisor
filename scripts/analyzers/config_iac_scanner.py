#!/usr/bin/env python3
"""Evaluate the Config/IaC rule catalog deterministically.

A finding is titled with its check's ``violation_title``, which names the
defect. The check ``name`` states the desired state and would read as a pass.

Inputs: --repo-root (required), --checks (catalog, default
data/config-iac-checks.yaml), --assessment-depth quick|standard|thorough
(quick caps each IaC category to a few files; agent_config is never capped).

Output: --output JSON, conventionally $OUTPUT_DIR/.config-scan-findings.json,
shaped by schemas/config-scan-findings.schema.yaml and validated by
validators/validate_intermediate.py (config_scan_findings).

Scope: a check's glob only admits files in the repository inventory
(``analyzers.scan_excludes.repo_inventory``), so files git ignores — including
the user's global ignores — are never evidence. Agent-configuration checks
judge settings a repository hands to every contributor, so they admit only
tracked files when the inventory comes from git; a developer's untracked local
settings are not the project's posture. ``inventory_source`` in the output
records whether the inventory came from git or a filesystem walk.

Evidence: a finding cites the line that is wrong. When the defect is that
something is missing, it cites the line the statement belongs to (a check's
``anchor``) or, failing that, the absence itself: ``evidence_kind: absence``,
``line: 0`` and the ``searched_files``. Checks of a repository-wide capability
(``expect: repository`` — SBOM generation, image signing, dependency-update
coverage) are evaluated once against ``analyzers.supply_chain_facts`` rather
than per file; those facts are written as ``supply_chain_facts``.
``absence_still_holds`` re-runs an absence finding for the evidence floor.

Exit codes: 0 written; 2 bad arguments, catalog, scan, or write failure.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import datetime as dt
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from runtime.agent_config_checks import EVALUATORS as AGENT_EVALUATORS
from shared._atomic_io import atomic_write_json

from analyzers import supply_chain_facts
from analyzers.iac_resource_checks import EVALUATORS as RESOURCE_EVALUATORS
from analyzers.scan_excludes import INVENTORY_GIT, RepoInventory, repo_inventory

EVALUATORS = {**AGENT_EVALUATORS, **RESOURCE_EVALUATORS}
DEFAULT_BREACH_VECTOR = "Build-Time"
UNCOVERED_FILES_LISTED = 10

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
FINDINGS_SCHEMA = PLUGIN_ROOT / "schemas" / "config-scan-findings.schema.yaml"
DEFAULT_CHECKS = PLUGIN_ROOT / "data" / "config-iac-checks.yaml"
QUICK_FILES_PER_CATEGORY = 5
# The quick-depth cap bounds categories whose file count grows with the
# repository. `agent_config` holds one settings path per coding agent, so
# capping it would silently drop a whole tool's posture instead of sampling.
UNCAPPED_CATEGORIES = frozenset({"agent_config"})
TRACKED_ONLY_CATEGORIES = frozenset({"agent_config"})
AUDIT_MARKERS = ("// audited:", "# audited:", "<!-- audited:")


class ConfigScanError(RuntimeError):
    """Raised when the catalog or a scan path violates the producer contract."""


def canonical_finding_fields(check: dict[str, Any]) -> dict[str, Any]:
    """The finding fields a catalog check owns; the producer and its validator both read them from here."""
    return {
        "finding_type_id": check.get("finding_type"),
        "iac_type": check.get("iac_type"),
        "title": check.get("violation_title"),
        "severity": check.get("severity_if_violated"),
        "cwe": [check.get("cwe")],
        "recommended_mitigation_title": check.get("remediation"),
    }


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
    required = {"id", "name", "violation_title", "iac_type", "file_pattern", "expect", "severity_if_violated", "cwe"}
    breach_vectors = set(yaml.safe_load(FINDINGS_SCHEMA.read_text(encoding="utf-8"))["$defs"]["breachVector"]["enum"])
    seen: set[str] = set()
    for index, check in enumerate(checks):
        if not isinstance(check, dict) or not required.issubset(check):
            raise ConfigScanError(f"check catalog entry {index} is incomplete")
        check_id = check["id"]
        if not isinstance(check_id, str) or check_id in seen:
            raise ConfigScanError(f"check catalog entry {index} has an invalid or duplicate id")
        seen.add(check_id)
        violation_title = check["violation_title"]
        if not isinstance(violation_title, str) or not violation_title.strip():
            raise ConfigScanError(f"{check_id} has no violation_title")
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
        if check["expect"] == "structured" and check.get("evaluator") not in EVALUATORS:
            raise ConfigScanError(f"{check_id} names an unknown evaluator {check.get('evaluator')!r}")
        if check["expect"] == "repository":
            if check.get("capability") not in supply_chain_facts.CAPABILITIES:
                raise ConfigScanError(f"{check_id} names an unknown capability {check.get('capability')!r}")
            precondition = check.get("precondition")
            if precondition is not None and precondition not in supply_chain_facts.PRECONDITIONS:
                raise ConfigScanError(f"{check_id} names an unknown precondition {precondition!r}")
            if check["capability"] == "dependency_updates" and not isinstance(check.get("ecosystem"), str):
                raise ConfigScanError(f"{check_id} must name the ecosystem it requires")
        anchor = check.get("anchor")
        if anchor is not None:
            try:
                re.compile(anchor, re.MULTILINE)
            except (re.error, TypeError) as exc:
                raise ConfigScanError(f"{check_id} has an invalid anchor: {exc}") from exc
            if check.get("anchor_occurrence", "first") not in {"first", "last"}:
                raise ConfigScanError(f"{check_id} has an invalid anchor_occurrence")
        if check.get("breach_vector", DEFAULT_BREACH_VECTOR) not in breach_vectors:
            raise ConfigScanError(f"{check_id} names an unknown breach_vector {check.get('breach_vector')!r}")
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


def _uncovered_surfaces(
    repo_root: Path, checks_path: Path, checks: list[dict[str, Any]], inventory: RepoInventory
) -> list[dict[str, Any]]:
    """Files of inventory categories that no check covers.

    ``file_patterns_by_type`` is the scanner's inventory of recognised
    surfaces; a category listed there without a check still has files the
    catalog cannot judge. Reporting them keeps a scan with zero findings from
    reading as a repository without that surface.
    """
    patterns_by_type = yaml.safe_load(checks_path.read_text(encoding="utf-8")).get("file_patterns_by_type") or {}
    covered = {check["iac_type"] for check in checks}
    root = repo_root.resolve()
    rows: list[dict[str, Any]] = []
    for iac_type, patterns in sorted(patterns_by_type.items()):
        if iac_type in covered:
            continue
        if not isinstance(patterns, list) or not all(isinstance(value, str) and value for value in patterns):
            raise ConfigScanError(f"surface {iac_type} has invalid file patterns")
        surface = {
            "id": f"surface:{iac_type}",
            "iac_type": iac_type,
            "file_pattern": patterns[0],
            "_file_patterns": patterns,
        }
        files = [path.relative_to(root).as_posix() for path in _matches_for_check(repo_root, surface, inventory)]
        if files:
            rows.append({"iac_type": iac_type, "file_count": len(files), "files": files[:UNCOVERED_FILES_LISTED]})
    return rows


def _admitted(rel_path: str, check: dict[str, Any], inventory: RepoInventory) -> bool:
    if rel_path not in inventory:
        return False
    if check.get("iac_type") in TRACKED_ONLY_CATEGORIES and inventory.source == INVENTORY_GIT:
        return inventory.is_tracked(rel_path) is True
    return True


def _matches_for_check(repo_root: Path, check: dict[str, Any], inventory: RepoInventory) -> list[Path]:
    patterns = check.get("_file_patterns", [check["file_pattern"]])
    root = repo_root.resolve()
    paths: list[Path] = []
    for pattern in patterns:
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ConfigScanError(f"{check['id']} has an unsafe file_pattern")
        try:
            candidates = [path for path in repo_root.glob(pattern) if path.is_file()]
        except (OSError, ValueError) as exc:
            raise ConfigScanError(f"{check['id']} cannot enumerate {pattern!r}: {exc}") from exc
        for path in candidates:
            if _admitted(path.relative_to(repo_root).as_posix(), check, inventory):
                paths.append(_canonical_file(repo_root, path))
    return sorted(set(paths), key=lambda path: path.relative_to(root).as_posix())


def _selected_files(
    repo_root: Path,
    checks: list[dict[str, Any]],
    inventory: RepoInventory,
    *,
    depth: str,
) -> dict[str, list[Path]]:
    by_check = {check["id"]: _matches_for_check(repo_root, check, inventory) for check in checks}
    if depth != "quick":
        return by_check
    category_files: dict[str, set[Path]] = {}
    for check in checks:
        category_files.setdefault(check["iac_type"], set()).update(by_check[check["id"]])
    admitted = {
        category: set(
            paths
            if category in UNCAPPED_CATEGORIES
            else sorted(paths, key=lambda path: path.relative_to(repo_root.resolve()).as_posix())[
                :QUICK_FILES_PER_CATEGORY
            ]
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


def _missing_in_file(check: dict[str, Any], text: str) -> tuple[int, str]:
    """Location of a required statement that a file lacks.

    The check's ``anchor`` names the line the statement belongs to (the final
    ``FROM`` of a Dockerfile, a Dependabot ``updates:`` key). Without an anchor,
    or when the file has no such line, the evidence is the absence itself:
    line 0, the whole file searched — never a pseudo line 1."""
    anchor = check.get("anchor")
    if anchor:
        matches = list(re.finditer(anchor, text, re.MULTILINE))
        if matches:
            match = matches[-1] if check.get("anchor_occurrence") == "last" else matches[0]
            return _line_for_offset(text, match.start())
    return 0, f"{check['name']}: not found in file"


def _violation(check: dict[str, Any], path: Path, text: str) -> tuple[int, str] | None:
    expect = check["expect"]
    pattern_text = check.get("pattern")
    pattern = (
        re.compile(pattern_text, re.MULTILINE | re.DOTALL) if isinstance(pattern_text, str) and pattern_text else None
    )
    match = pattern.search(text) if pattern is not None else None
    if expect == "present":
        return None if match else _missing_in_file(check, text)
    if expect == "absent":
        return _line_for_offset(text, match.start()) if match else None
    if expect == "all_third_party_actions":
        return _third_party_action_violation(text)
    if expect in {"any_of", "any_of_present"}:
        patterns = check.get("pattern_any_of")
        if any(re.search(value, text, re.MULTILINE | re.DOTALL) for value in patterns):
            return None
        return _missing_in_file(check, text)
    if expect == "absent_or_documented":
        if pattern is None:
            raise ConfigScanError(f"{check['id']} requires a pattern")
        return _undocumented_match(pattern, text)
    if expect == "structured":
        return EVALUATORS[check["evaluator"]](text, path)
    if expect in {"file_exists", "repository"}:
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
    """Run each catalog check on its selected files: at most one finding per check and file.

    A ``file_exists`` check without a matching file is itself a finding. ``output`` only locates the scan-start
    epoch for ``generated_at``; nothing is written here.
    """
    repo_root = repo_root.resolve()
    if not repo_root.is_dir():
        raise ConfigScanError(f"repository root is not a directory: {repo_root}")
    checks = _catalog(checks_path)
    inventory = repo_inventory(repo_root)
    facts = supply_chain_facts.collect(repo_root, inventory)
    selected = _selected_files(repo_root, checks, inventory, depth=depth)
    pending: list[dict[str, Any]] = []
    for check in checks:
        if check["expect"] == "repository":
            gap = supply_chain_facts.capability_gap(facts, check)
            if gap is not None:
                pending.append({"check": check, "path": None, "line": 0, **gap})
            continue
        paths = selected[check["id"]]
        if check["expect"] == "file_exists" and not paths:
            pending.append({"check": check, "path": None, "line": 0, "snippet": "File not found", "searched_files": []})
            continue
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ConfigScanError(f"cannot read scan target {path}: {exc}") from exc
            violation = _violation(check, path, text)
            if violation is not None:
                line, snippet = violation
                row = {"check": check, "path": path, "line": line, "snippet": snippet}
                if line == 0:
                    row["searched_files"] = [path.relative_to(repo_root).as_posix()]
                pending.append(row)

    findings: list[dict[str, Any]] = []
    for index, row in enumerate(pending, start=1):
        check = row["check"]
        relative = check["file_pattern"] if row["path"] is None else row["path"].relative_to(repo_root).as_posix()
        canonical = canonical_finding_fields(check)
        finding = {
            "local_id": f"CFG-{index:03d}",
            "check_id": check["id"],
            **canonical,
            "file": relative,
            "line": row["line"],
            "evidence_snippet": row["snippet"],
            "scenario": f"{canonical['title']}: {check.get('rationale', '').strip()}",
            "breach_vector": check.get("breach_vector", DEFAULT_BREACH_VECTOR),
        }
        if "searched_files" in row:
            finding["evidence_kind"] = "absence"
            finding["searched_files"] = row["searched_files"]
            finding["searched_file_count"] = row.get("searched_file_count", len(row["searched_files"]))
        findings.append(finding)
    result: dict[str, Any] = {
        "version": 1,
        "generated_at": _generated_at(output),
        "checks_run": len(checks),
        "violations": len(findings),
        "inventory_source": inventory.source,
        "findings": findings,
        "supply_chain_facts": facts,
    }
    uncovered = _uncovered_surfaces(repo_root, checks_path, checks, inventory)
    if uncovered:
        result["uncovered_iac"] = uncovered
    return result


def absence_still_holds(
    repo_root: Path, check_id: str, searched_files: list[str], *, checks_path: Path = DEFAULT_CHECKS
) -> bool | None:
    """Re-run an absence finding's check on the repository as it is now.

    True when the check still finds the statement or capability missing, False
    when the repository now satisfies it, None when the check is unknown or is
    not an absence check. The evidence floor uses this instead of a line window,
    which cannot show that something is missing."""
    checks = {check["id"]: check for check in _catalog(checks_path)}
    check = checks.get(check_id)
    if check is None:
        return None
    repo_root = repo_root.resolve()
    expect = check["expect"]
    if expect == "repository":
        facts = supply_chain_facts.collect(repo_root, repo_inventory(repo_root))
        return supply_chain_facts.capability_gap(facts, check) is not None
    if expect == "file_exists":
        return not _matches_for_check(repo_root, check, repo_inventory(repo_root))
    if expect not in {"present", "any_of", "any_of_present"} or not searched_files:
        return None
    for rel in searched_files:
        path = repo_root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        if _violation(check, path, text) is None:
            return False
    return True


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
        # Not `parser.error`: a scan or IO failure is not an argv error, and the
        # usage block argparse prefixes displaces the reason in BASH_WARN
        # excerpts, which anchor on `usage:`.
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    uncovered = ", ".join(row["iac_type"] for row in result.get("uncovered_iac", []))
    suffix = f"; no checks for: {uncovered}" if uncovered else ""
    if result["inventory_source"] != INVENTORY_GIT:
        suffix += f"; inventory: {result['inventory_source']} (no git ignore rules applied)"
    print(f"config-iac-scanner: {result['checks_run']} checks, {result['violations']} violations{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
