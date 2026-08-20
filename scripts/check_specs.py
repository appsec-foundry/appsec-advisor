#!/usr/bin/env python3
"""Validate the product requirements and their technical implementation bindings.

`specs/requirements.md` contains only normative product behavior. Volatile path,
decision, document, and test references live in
`data/requirement-bindings.yaml`. This checker keeps that separation honest and
supports file-to-requirement lookup without making refactors specification
changes.

The checker validates structure and exact references. It cannot decide whether
a named test semantically proves a requirement; the binding's direct, partial,
or advisory coverage label makes that review judgement explicit.
"""

from __future__ import annotations

import argparse
import ast
import glob
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "specs" / "requirements.md"
BINDINGS = ROOT / "data" / "requirement-bindings.yaml"
BINDING_SCHEMA = ROOT / "schemas" / "requirement-bindings.schema.yaml"
REGISTER = ROOT / "docs" / "internal" / "decisions.md"

HELD_PATHS = ("specs/requirements.md", "docs/internal/decisions.md")
CHANGE_DIR = "specs/changes/"

SECTION_RE = re.compile(r"^## (.+?)\s*$")
ENTRY_RE = re.compile(r"^### (REQ-[A-Z]{2,5}-\d{3}) — (.+?)\s*$")
ID_SHAPE_RE = re.compile(r"^REQ-[A-Z]{2,5}-\d{3}$")
DECISION_RE = re.compile(r"^[A-Z]{2,3}-\d+$")
TECHNICAL_FIELD_RE = re.compile(r"\*\*(?:Applies to|Source|Guard):\*\*")
PROPOSAL_RE = re.compile(r"^specs/changes/[^/]+/proposal\.md$")


@dataclass(frozen=True)
class Entry:
    rid: str
    title: str
    section: str
    line: int
    text: str = ""


@dataclass(frozen=True)
class Binding:
    rid: str
    paths: tuple[str, ...]
    decisions: tuple[str, ...]
    documents: tuple[str, ...]
    coverage: str
    guards: tuple[str, ...]


def parse(text: str) -> list[Entry]:
    """Parse the normative Markdown catalog without implementation metadata."""
    entries: list[Entry] = []
    section = ""
    current: Entry | None = None
    text_lines: list[str] = []

    def finish() -> None:
        nonlocal current, text_lines
        if current is not None:
            entries[-1] = Entry(
                current.rid,
                current.title,
                current.section,
                current.line,
                " ".join(line for line in text_lines if line).strip(),
            )
        current = None
        text_lines = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        entry_match = ENTRY_RE.match(line)
        if entry_match:
            finish()
            current = Entry(entry_match.group(1), entry_match.group(2), section, number)
            entries.append(current)
            continue
        section_match = SECTION_RE.match(line)
        if section_match:
            finish()
            section = section_match.group(1)
            continue
        if current is not None and line:
            text_lines.append(line)
    finish()
    return entries


def load_binding_document(path: Path = BINDINGS) -> object:
    """Load the binding YAML without silently normalizing an empty document."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def binding_schema_problems(document: object, schema_path: Path = BINDING_SCHEMA) -> list[str]:
    """Return deterministic JSON Schema errors for the binding document."""
    schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    problems = []
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        problems.append(f"{BINDINGS.name}:{location}: {error.message}")
    return problems


def parse_bindings(document: object) -> dict[str, Binding]:
    """Convert a schema-valid binding document to immutable records."""
    if not isinstance(document, dict) or not isinstance(document.get("requirements"), dict):
        return {}
    bindings: dict[str, Binding] = {}
    for rid, raw in document["requirements"].items():
        if not isinstance(raw, dict):
            continue
        bindings[rid] = Binding(
            rid=rid,
            paths=tuple(raw.get("applies_to", [])),
            decisions=tuple(raw.get("decisions", [])),
            documents=tuple(raw.get("documents", [])),
            coverage=str(raw.get("coverage", "")),
            guards=tuple(raw.get("guards", [])),
        )
    return bindings


def known_test_nodes(root: Path = ROOT) -> set[str]:
    """Return exact pytest node IDs defined by test modules and Test classes."""
    nodes: set[str] = set()
    tests_dir = root / "tests"
    for path in tests_dir.rglob("test_*.py") if tests_dir.exists() else ():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        relative = path.relative_to(root).as_posix()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                nodes.add(f"{relative}::{node.name}")
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name.startswith("test_"):
                        nodes.add(f"{relative}::{node.name}::{child.name}")
    return nodes


def known_decisions(root: Path = ROOT) -> set[str]:
    register = root / REGISTER.relative_to(ROOT)
    if not register.exists():
        return set()
    return set(re.findall(r"^\| ([A-Z]{2,3}-\d+) \|", register.read_text(encoding="utf-8"), re.M))


def path_matches(pattern: str, root: Path = ROOT) -> list[str]:
    return glob.glob(pattern, root_dir=root, recursive=True)


def safe_binding_pattern(pattern: str) -> bool:
    """Return whether a binding glob is a repository-relative POSIX path."""
    if not pattern or "\\" in pattern or "://" in pattern or "\x00" in pattern:
        return False
    if re.match(r"^[A-Za-z]:/", pattern):
        return False
    path = PurePosixPath(pattern)
    return not path.is_absolute() and ".." not in path.parts


def _inside_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def validate(
    entries: list[Entry],
    document: object,
    root: Path = ROOT,
    schema_path: Path = BINDING_SCHEMA,
) -> list[str]:
    """Return every catalog and binding problem as one message per problem."""
    problems = binding_schema_problems(document, schema_path)
    if problems:
        return problems
    bindings = parse_bindings(document)
    retired = set(document.get("retired_ids", [])) if isinstance(document, dict) else set()

    if not entries:
        return [f"{CATALOG.name}: no requirements found"]

    seen: dict[str, int] = {}
    active: set[str] = set()
    for entry in entries:
        where = f"{CATALOG.name}:{entry.line} {entry.rid}"
        if not ID_SHAPE_RE.fullmatch(entry.rid):
            problems.append(f"{where}: malformed id")
        if entry.rid in seen:
            problems.append(f"{where}: duplicate id, first seen at line {seen[entry.rid]}")
        seen.setdefault(entry.rid, entry.line)
        active.add(entry.rid)
        if not entry.section:
            problems.append(f"{where}: entry sits outside any section")
        if not entry.text:
            problems.append(f"{where}: no requirement text")
        if TECHNICAL_FIELD_RE.search(entry.text):
            problems.append(f"{where}: implementation metadata belongs in {BINDINGS.relative_to(ROOT)}")

    for rid in sorted(active - set(bindings)):
        problems.append(f"{BINDINGS.name}: missing binding for active requirement {rid}")
    for rid in sorted(set(bindings) - active):
        problems.append(f"{BINDINGS.name}: binding names inactive requirement {rid}")
    for rid in sorted(active & retired):
        problems.append(f"{BINDINGS.name}: active requirement is also retired: {rid}")

    tests = known_test_nodes(root)
    decisions = known_decisions(root)
    for rid, binding in sorted(bindings.items()):
        for pattern in binding.paths:
            if not safe_binding_pattern(pattern):
                problems.append(
                    f"{BINDINGS.name}:{rid}: applies_to must be a safe repository-relative pattern: {pattern}"
                )
                continue
            if not path_matches(pattern, root):
                problems.append(f"{BINDINGS.name}:{rid}: applies_to pattern matches nothing: {pattern}")
        for decision in binding.decisions:
            if not DECISION_RE.fullmatch(decision) or decision not in decisions:
                problems.append(f"{BINDINGS.name}:{rid}: unknown decision: {decision}")
        for document_path in binding.documents:
            candidate = root / document_path
            if not _inside_root(candidate, root):
                problems.append(f"{BINDINGS.name}:{rid}: document escapes the repository: {document_path}")
            elif not candidate.is_file():
                problems.append(f"{BINDINGS.name}:{rid}: document does not exist: {document_path}")
        if binding.coverage == "advisory" and binding.guards:
            problems.append(f"{BINDINGS.name}:{rid}: advisory coverage cannot name guards")
        if binding.coverage in {"direct", "partial"} and not binding.guards:
            problems.append(f"{BINDINGS.name}:{rid}: {binding.coverage} coverage requires a guard")
        for guard in binding.guards:
            if guard not in tests:
                problems.append(f"{BINDINGS.name}:{rid}: guard node does not exist: {guard}")
    return problems


def applicable(
    entries: list[Entry],
    bindings: dict[str, Binding],
    target: str,
    root: Path = ROOT,
) -> list[tuple[Entry, Binding]]:
    """Return requirements whose technical binding covers ``target``."""
    candidate = Path(target)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError:
            return []
    wanted = candidate.as_posix()
    hits = []
    for entry in entries:
        binding = bindings.get(entry.rid)
        if binding is None:
            continue
        if any(wanted in path_matches(pattern, root) or wanted == pattern for pattern in binding.paths):
            hits.append((entry, binding))
    return hits


def render(entry: Entry, binding: Binding) -> str:
    guards = ", ".join(binding.guards) if binding.guards else "none"
    decisions = ", ".join(binding.decisions) if binding.decisions else "none"
    documents = ", ".join(binding.documents) if binding.documents else "none"
    return (
        f"{entry.rid} — {entry.title}\n"
        f"  {entry.text}\n"
        f"  Technical context: decisions: {decisions}; documents: {documents}\n"
        f"  Guard coverage: {binding.coverage}; guards: {guards}"
    )


def unapproved_changes(paths: list[str]) -> list[str]:
    """Return held files changed without a proposal changed in the same diff."""
    touched = [path for path in paths if path in HELD_PATHS]
    if not touched or any(PROPOSAL_RE.fullmatch(path) for path in paths):
        return []
    return [f"{path} changed with no proposal under {CHANGE_DIR}" for path in touched]


def changed_since(ref: str) -> list[str]:
    """Return tracked and untracked paths that differ from ``ref``."""
    result = subprocess.run(
        ["git", "diff", "--name-only", ref],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.strip() or f"cannot diff against {ref}")
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    lines = result.stdout.splitlines() + untracked.stdout.splitlines()
    return [line.strip() for line in lines if line.strip()]


def _load_current() -> tuple[list[Entry], object]:
    if not CATALOG.exists():
        raise ValueError(f"{CATALOG} is missing")
    if not BINDINGS.exists():
        raise ValueError(f"{BINDINGS} is missing")
    try:
        document = load_binding_document()
    except yaml.YAMLError as error:
        raise ValueError(f"{BINDINGS}: invalid YAML: {error}") from error
    return parse(CATALOG.read_text(encoding="utf-8")), document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--for", dest="target", help="print the requirements that govern a file")
    parser.add_argument(
        "--changed-against",
        dest="ref",
        help="fail when a held file changed against this ref with no changed proposal",
    )
    args = parser.parse_args(argv)

    if args.ref:
        try:
            problems = unapproved_changes(changed_since(args.ref))
        except ValueError as error:
            print(str(error), file=sys.stderr)
            return 2
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0

    try:
        entries, document = _load_current()
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2

    problems = validate(entries, document)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1

    bindings = parse_bindings(document)
    if args.target:
        hits = applicable(entries, bindings, args.target)
        if not hits:
            return 0
        print(f"Requirements for {args.target}:")
        for entry, binding in hits:
            print(render(entry, binding))
        return 0

    counts = {coverage: 0 for coverage in ("direct", "partial", "advisory")}
    for binding in bindings.values():
        counts[binding.coverage] += 1
    print(
        f"specs: {len(entries)} requirements "
        f"({counts['direct']} direct, {counts['partial']} partial, {counts['advisory']} advisory)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
