#!/usr/bin/env python3
"""Keep test-target specifics out of production behavior.

The plugin is developed against a handful of deliberately vulnerable
repositories. Two things leak from them, and both are invisible on a run
against the target itself:

    R1  A target's *name* in a code context — a string literal, a code span
        a prompt may copy, help text. It reaches a stranger's report or
        steers an analysis of an unrelated codebase. The same name in prose
        or a comment is provenance ("the 2026-06-13 run showed X") and stays.

    R2  A target's *artifact* — a route or file that exists in one repository
        and nowhere else. A heuristic keyed on it fires only for the test
        target, so measured coverage overstates what an arbitrary repository
        gets. Rejected in every context, comments included.

Vocabulary lives in ``data/test-target-vocabulary.yaml``. Exits 1 on any
violation, 0 when clean. Tests, docs, examples, and fixtures are out of scope
by design — a fixture is where target specifics belong.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
VOCABULARY_PATH = PLUGIN_ROOT / "data" / "test-target-vocabulary.yaml"

# Production surfaces only. `tests/`, `docs/`, `examples/` are excluded because
# naming a target there is legitimate.
SCAN_ROOTS = ("scripts", "hooks", "agents", "skills", "data", "schemas")

SCANNED_SUFFIXES = frozenset({".py", ".md", ".yaml", ".yml", ".txt", ".json"})

_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_COMMENT_LINE = re.compile(r"^\s*(#|//)")


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    rule: str
    token: str
    target: str
    context: str

    def render(self, root: Path) -> str:
        rel = self.path.relative_to(root)
        return f"{rel}:{self.line}: [{self.rule}] {self.target} {self.token!r} in {self.context.strip()[:100]!r}"


def load_vocabulary(path: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return ``(names, artifacts)`` as ``(target, token)`` pairs, lower-cased."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    targets = data.get("targets") or {}
    if not isinstance(targets, dict) or not targets:
        raise ValueError(f"{path}: no targets defined")
    names: list[tuple[str, str]] = []
    artifacts: list[tuple[str, str]] = []
    for target, spec in targets.items():
        spec = spec or {}
        for token in spec.get("names") or []:
            names.append((str(target), str(token).lower()))
        for token in spec.get("artifacts") or []:
            artifacts.append((str(target), str(token).lower()))
    return names, artifacts


def _python_code_fragments(source: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line, text)`` for every string literal that is not a docstring.

    Comments never reach the AST, so provenance notes are exempt for free.
    """
    tree = ast.parse(source)
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        body = getattr(node, "body", None)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            if isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            yield node.lineno, node.value


def _markdown_code_fragments(lines: list[str]) -> Iterator[tuple[int, str]]:
    """Yield backtick code spans — the part of a prompt a model copies verbatim.

    Fenced blocks are not scanned for names: in this repository they carry as
    much instructional prose as code, and every name in them was provenance.
    R2 still reads those lines, which is the class that skews measurement.
    """
    for number, line in enumerate(lines, start=1):
        for span in _INLINE_CODE.findall(line):
            yield number, span


def _noncomment_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    for number, line in enumerate(lines, start=1):
        if not _COMMENT_LINE.match(line):
            yield number, line


def _all_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    yield from enumerate(lines, start=1)


def name_fragments(path: Path, text: str) -> Iterator[tuple[int, str]]:
    """Yield the ``(line, text)`` pairs where a target *name* is a violation."""
    lines = text.splitlines()
    if path.suffix == ".py":
        try:
            yield from _python_code_fragments(text)
        except SyntaxError:
            # Not parseable here; ruff owns syntax. Fall back to whole lines so
            # the file is still covered rather than silently skipped.
            yield from _all_lines(lines)
    elif path.suffix == ".md":
        yield from _markdown_code_fragments(lines)
    elif path.suffix in {".yaml", ".yml"}:
        yield from _noncomment_lines(lines)
    else:
        # Help text and JSON data are user-visible or machine-read in full.
        yield from _all_lines(lines)


def artifact_fragments(path: Path, text: str) -> Iterator[tuple[int, str]]:
    """Yield the ``(line, text)`` pairs where a target *artifact* is a violation.

    Wider than :func:`name_fragments` for Markdown, where an artifact in prose
    is a sample the report copies rather than a note about a past run.
    Comments and docstrings stay exempt: naming the path a rule came from
    documents the rule, it does not key behavior on it.
    """
    if path.suffix == ".md":
        yield from _all_lines(text.splitlines())
    else:
        yield from name_fragments(path, text)


def scan_file(
    path: Path,
    names: list[tuple[str, str]],
    artifacts: list[tuple[str, str]],
    root: Path,
) -> list[Violation]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    violations: list[Violation] = []

    if any(token in lowered for _, token in artifacts):
        for number, fragment in artifact_fragments(path, text):
            haystack = fragment.lower()
            for target, token in artifacts:
                if token in haystack:
                    violations.append(Violation(path, number, "R2-artifact", token, target, fragment))

    if any(token in lowered for _, token in names):
        for number, fragment in name_fragments(path, text):
            haystack = fragment.lower()
            if _is_repository_path(fragment, root):
                continue
            for target, token in names:
                if token in haystack:
                    violations.append(Violation(path, number, "R1-name", token, target, fragment))

    return violations


def _is_repository_path(fragment: str, root: Path) -> bool:
    """True when the fragment is a path to a file that exists in the repository.

    A published example carries the name of the repository it was generated
    from; pointing at it is a reference, not a dependency on that repository.
    """
    candidate = fragment.strip().strip("`\"'")
    if not candidate or len(candidate) > 120 or candidate.startswith("/") or not re.fullmatch(r"[\w./-]+", candidate):
        return False
    try:
        return (root / candidate).exists()
    except OSError:
        return False


def iter_scanned_files(root: Path, vocabulary: Path) -> Iterator[Path]:
    """Yield every production file to scan, minus the vocabulary that defines the tokens."""
    skip = vocabulary.resolve()
    for name in SCAN_ROOTS:
        base = root / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in SCANNED_SUFFIXES and path.resolve() != skip:
                yield path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=PLUGIN_ROOT, help="Repository root to scan.")
    parser.add_argument("--vocabulary", type=Path, default=VOCABULARY_PATH, help="Vocabulary YAML.")
    args = parser.parse_args(argv)

    try:
        names, artifacts = load_vocabulary(args.vocabulary)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"check_target_specificity: {exc}", file=sys.stderr)
        return 2

    violations: list[Violation] = []
    for path in iter_scanned_files(args.root, args.vocabulary):
        violations.extend(scan_file(path, names, artifacts, args.root))

    if not violations:
        return 0

    print("Test-target specifics found in production code:\n", file=sys.stderr)
    for violation in violations:
        print("  " + violation.render(args.root), file=sys.stderr)
    print(
        "\nR1-name: move the target name into a comment, or make the example generic."
        "\nR2-artifact: state the signal the rule detects, not the path one repository uses."
        "\nVocabulary: data/test-target-vocabulary.yaml",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
