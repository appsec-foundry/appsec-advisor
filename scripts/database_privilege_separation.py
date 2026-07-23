#!/usr/bin/env python3
"""Thorough-only evidence scan for database principal separation.

The scanner is deliberately narrow. It inventories explicitly named database
clients, classifies their names as privileged or unprivileged, and only
confirms a finding when a shared *literal* principal is also tied to a visible
high-privilege SQL grant or role attribute. Shared environment/secret
references are useful review evidence, but remain hypotheses because their
resolved grants may be outside the repository.

No credential value, connection string, or SQL statement is written to the
sidecar. Evidence contains source locations plus normalized signal labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from validate_intermediate import validate_db_privilege_separation  # noqa: E402

_EXTENSIONS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".java",
    ".kt",
    ".cs",
    ".properties",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".env",
    ".sql",
}
_EXCLUDED = {".git", "node_modules", "vendor", "dist", "build", "target", "out", ".venv", "venv", "__pycache__"}
_CLIENT = re.compile(
    r"(?i)\b(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:await\s+)?(?:createPool|createConnection|create_engine|new\s+Sequelize|new\s+DataSource|new\s+SqlConnection|PrismaClient)\b"
)
_PRIVILEGED_ALIAS = re.compile(
    r"(?i)(?:^|[_-])(admin|administrator|management|internal|privileged|owner)(?:[_-]|$)|(?:admin|management|privileged|owner)(?:db|data|source|pool|client)"
)
_UNPRIVILEGED_ALIAS = re.compile(
    r"(?i)(?:^|[_-])(public|user|customer|client|frontend|app)(?:[_-]|$)|(?:public|user|customer|client|app)(?:db|data|source|pool|client)"
)
_PRIVILEGED_CONTEXT = re.compile(
    r"(?i)(?:^|/)(?:admin|management|internal)(?:/|$)|(?:hasRole|requireRole|PreAuthorize|Authorize)\s*\([^\n]{0,120}(?:ADMIN|MANAGE|OWNER)|\b(?:admin|management)_?(?:only|route|endpoint)\b"
)
_ROUTE_CONTEXT = re.compile(
    r"(?i)\b(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\(|@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b|\bMap(?:Get|Post|Put|Patch|Delete)\s*\(|@app\.(?:get|post|put|patch|delete|route)\s*\("
)
_REF_PRINCIPAL = re.compile(
    r"(?i)(?:process\.env\.|System\.getenv\s*\(\s*['\"]|os\.environ\s*\[\s*['\"]|\$\{)(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_LITERAL_PRINCIPAL = re.compile(
    r"(?i)\b(?:user(?:name)?|db_user|database_user|principal)\s*[:=]\s*['\"](?P<value>[A-Za-z_][A-Za-z0-9_.-]{0,127})['\"]"
)
_GRANT_ALL = re.compile(
    r"(?is)\bGRANT\s+ALL(?:\s+PRIVILEGES)?\s+.*?\s+TO\s+(?P<principal>[A-Za-z_][A-Za-z0-9_.-]{0,127})"
)
_ROLE_PRIVILEGE = re.compile(
    r"(?is)\bALTER\s+(?:ROLE|USER)\s+(?P<principal>[A-Za-z_][A-Za-z0-9_.-]{0,127})\s+(?:WITH\s+)?(?:SUPERUSER|BYPASSRLS)\b"
)


@dataclass(frozen=True)
class Binding:
    alias: str
    classification: str
    principal_key: str
    principal_kind: str
    literal: str | None
    file: str
    line: int


@dataclass(frozen=True)
class Definition:
    alias: str
    principal_key: str
    principal_kind: str
    literal: str | None
    file: str
    line: int


def _walk(repo_root: Path) -> Iterable[Path]:
    for base, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in _EXCLUDED]
        for name in files:
            path = Path(base) / name
            if path.suffix.lower() in _EXTENSIONS:
                yield path


def _classification(alias: str) -> str | None:
    if _PRIVILEGED_ALIAS.search(alias):
        return "privileged"
    if _UNPRIVILEGED_ALIAS.search(alias):
        return "unprivileged"
    return None


def _safe_reference(name: str) -> str:
    return "reference:" + name.upper()


def _literal_key(value: str) -> str:
    return "literal:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _bindings(repo_root: Path) -> tuple[list[Binding], list[tuple[str, int, str]]]:
    definitions: list[Definition] = []
    grants: list[tuple[str, int, str]] = []
    source_files: list[tuple[str, list[str]]] = []
    for path in _walk(repo_root):
        rel = str(path.relative_to(repo_root)).replace("\\", "/")
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        source_files.append((rel, lines))
        text = "\n".join(lines)
        for pattern in (_GRANT_ALL, _ROLE_PRIVILEGE):
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                grants.append((rel, line, match.group("principal")))
        for line_no, line in enumerate(lines, 1):
            client = _CLIENT.search(line)
            if not client:
                continue
            window = " ".join(lines[line_no - 1 : min(len(lines), line_no + 7)])
            ref = _REF_PRINCIPAL.search(window)
            literal = _LITERAL_PRINCIPAL.search(window)
            if ref:
                definitions.append(
                    Definition(
                        client.group("alias"), _safe_reference(ref.group("name")), "reference", None, rel, line_no
                    )
                )
            elif literal:
                value = literal.group("value")
                definitions.append(
                    Definition(client.group("alias"), _literal_key(value), "literal", value, rel, line_no)
                )

    bindings: list[Binding] = []
    for definition in definitions:
        seen: set[tuple[str, str, int]] = set()

        def add(classification: str, file: str, line: int) -> None:
            key = (classification, file, line)
            if key in seen:
                return
            seen.add(key)
            bindings.append(
                Binding(
                    definition.alias,
                    classification,
                    definition.principal_key,
                    definition.principal_kind,
                    definition.literal,
                    file,
                    line,
                )
            )

        alias_classification = _classification(definition.alias)
        if alias_classification:
            add(alias_classification, definition.file, definition.line)
        alias_pattern = re.compile(rf"\b{re.escape(definition.alias)}\b")
        for rel, lines in source_files:
            for index, line in enumerate(lines):
                if not alias_pattern.search(line):
                    continue
                context = "\n".join(lines[max(0, index - 3) : min(len(lines), index + 4)])
                path_context = rel.replace("\\", "/")
                if _PRIVILEGED_CONTEXT.search(path_context) or _PRIVILEGED_CONTEXT.search(context):
                    add("privileged", rel, index + 1)
                elif _ROUTE_CONTEXT.search(context):
                    add("unprivileged", rel, index + 1)
    return bindings, grants


def _evidence(binding: Binding, signal: str) -> dict:
    return {"file": binding.file, "line": binding.line, "signal": signal}


def assess(repo_root: Path, assessment_depth: str) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = {
        "version": 1,
        "generated_at": now,
        "assessment_depth": assessment_depth,
        "skipped": assessment_depth != "thorough",
        "skip_reason": None,
        "confirmed_findings": [],
        "hypotheses": [],
        "warnings": [],
    }
    if assessment_depth != "thorough":
        result["skip_reason"] = "database principal separation is assessed only at thorough depth"
        return result
    bindings, grants = _bindings(repo_root)
    grouped: dict[str, list[Binding]] = {}
    for binding in bindings:
        grouped.setdefault(binding.principal_key, []).append(binding)
    serial = 0
    for key, group in sorted(grouped.items()):
        privileged = [b for b in group if b.classification == "privileged"]
        unprivileged = [b for b in group if b.classification == "unprivileged"]
        if not privileged or not unprivileged:
            continue
        serial += 1
        literal = next((b.literal for b in group if b.literal), None)
        matching_grants = [
            (file, line) for file, line, principal in grants if literal and principal.casefold() == literal.casefold()
        ]
        evidence = [
            _evidence(b, f"{b.classification} database client uses the same principal reference")
            for b in (privileged[:2] + unprivileged[:2])
        ]
        if matching_grants:
            for file, line in matching_grants[:2]:
                evidence.append(
                    {
                        "file": file,
                        "line": line,
                        "signal": "visible high-privilege database grant matches the shared principal",
                    }
                )
            destination = result["confirmed_findings"]
            title = "Shared high-privilege database principal across privileged and unprivileged clients"
        else:
            destination = result["hypotheses"]
            title = "Database principal separation requires grant review"
        destination.append(
            {
                "local_id": f"DBSEP-{serial:03d}",
                "title": title,
                "cwe": "CWE-284",
                "principal_kind": privileged[0].principal_kind,
                "privileged_aliases": sorted({b.alias for b in privileged}),
                "unprivileged_aliases": sorted({b.alias for b in unprivileged}),
                "evidence": evidence,
            }
        )
    return result


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--assessment-depth", required=True, choices=("quick", "standard", "thorough"))
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"database_privilege_separation.py: repo-root not found: {repo_root}", file=sys.stderr)
        return 1
    result = assess(repo_root, args.assessment_depth)
    ok, errors = validate_db_privilege_separation(result)
    if not ok:
        print("database_privilege_separation.py: generated invalid sidecar: " + "; ".join(errors), file=sys.stderr)
        return 1
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    path = output / ".db-privilege-separation.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.stdout:
        print(json.dumps(result, indent=2))
    else:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
