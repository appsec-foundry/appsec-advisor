#!/usr/bin/env python3
"""Validate `specs/requirements.md` and answer which requirements govern a file.

Why a checker and not a convention
----------------------------------
A requirement is only binding if something breaks when it is ignored. This
script is the part that breaks. It does not judge whether a requirement is
right — it keeps the catalog's references real, so an entry cannot claim
enforcement it does not have: a guard that no test defines, a decision the
register does not carry, a path that matches nothing.

What it deliberately cannot check: whether a requirement is faithful to its
source, and whether a named guard actually bites. Both stay a review. The
honest-gap vocabulary (`— (no guard written)`, `— (guard not located)`) is the
decision register's, so an entry that has no rail says so instead of implying
one.

The `--for` mode is what puts a requirement in front of whoever is about to
change a file, which is the only moment it can still influence the change.
"""

from __future__ import annotations

import argparse
import glob
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "specs" / "requirements.md"
REGISTER = ROOT / "docs" / "internal" / "decisions.md"
TESTS_DIR = ROOT / "tests"

# The two files an agent may not write, and where a change to either is written down.
HELD_PATHS = ("specs/requirements.md", "docs/internal/decisions.md")
CHANGE_DIR = "specs/changes/"

SECTION_RE = re.compile(r"^## (.+?)\s*$")
ENTRY_RE = re.compile(r"^### (REQ-[A-Z]{2,5}-\d{3}) — (.+?)\s*$")
ID_SHAPE_RE = re.compile(r"^REQ-[A-Z]{2,5}-\d{3}$")
KEY_RE = re.compile(r"^\*\*(Applies to|Source|Guard):\*\*\s*(.*)$")
CODE_RE = re.compile(r"`([^`]+)`")
DECISION_RE = re.compile(r"^[A-Z]{2,3}-\d+$")
TEST_NAME_RE = re.compile(r"^(?:[\w./-]+\.py::)?(?:[\w]+::)?(test_\w+)$")

NO_GUARD = ("— (no guard written)", "— (guard not located)")

REQUIRED_KEYS = ("Applies to", "Source", "Guard")


@dataclass
class Entry:
    rid: str
    title: str
    section: str
    line: int
    text: str = ""
    keys: dict[str, str] = field(default_factory=dict)

    @property
    def paths(self) -> list[str]:
        return CODE_RE.findall(self.keys.get("Applies to", ""))

    @property
    def guards(self) -> list[str]:
        return CODE_RE.findall(self.keys.get("Guard", ""))

    @property
    def unguarded(self) -> bool:
        return any(marker in self.keys.get("Guard", "") for marker in NO_GUARD)


def parse(text: str) -> list[Entry]:
    """Read the catalog into entries. Unknown lines before the keys are the requirement."""
    entries: list[Entry] = []
    section = ""
    current: Entry | None = None
    key = ""
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        entry_match = ENTRY_RE.match(line)
        if entry_match:
            current = Entry(entry_match.group(1), entry_match.group(2), section, number)
            entries.append(current)
            key = ""
            continue
        section_match = SECTION_RE.match(line)
        if section_match:
            section = section_match.group(1)
            current = None
            continue
        if current is None:
            continue
        key_match = KEY_RE.match(line)
        if key_match:
            key = key_match.group(1)
            current.keys[key] = key_match.group(2)
            continue
        if not line:
            key = ""
            continue
        if key:
            current.keys[key] += " " + line.strip()
        elif not current.keys:
            current.text = (current.text + " " + line.strip()).strip()
    return entries


def known_test_names() -> set[str]:
    names: set[str] = set()
    for path in TESTS_DIR.rglob("test_*.py"):
        names.update(re.findall(r"^\s*(?:async )?def (test_\w+)", path.read_text(), re.M))
    return names


def known_decisions() -> set[str]:
    if not REGISTER.exists():
        return set()
    return set(re.findall(r"^\| ([A-Z]{2,3}-\d+) \|", REGISTER.read_text(), re.M))


def path_matches(pattern: str, root: Path) -> list[str]:
    return glob.glob(pattern, root_dir=root, recursive=True)


def validate(entries: list[Entry], root: Path = ROOT) -> list[str]:
    """Every problem found, as one message per problem."""
    problems: list[str] = []
    if not entries:
        return [f"{CATALOG.name}: no requirements found"]
    tests = known_test_names()
    decisions = known_decisions()
    seen: dict[str, int] = {}

    for entry in entries:
        where = f"{CATALOG.name}:{entry.line} {entry.rid}"
        if not ID_SHAPE_RE.match(entry.rid):
            problems.append(f"{where}: malformed id")
        if entry.rid in seen:
            problems.append(f"{where}: duplicate id, first seen at line {seen[entry.rid]}")
        seen.setdefault(entry.rid, entry.line)
        if not entry.section:
            problems.append(f"{where}: entry sits outside any section")
        if not entry.text:
            problems.append(f"{where}: no requirement text")
        for key in REQUIRED_KEYS:
            if not entry.keys.get(key, "").strip():
                problems.append(f"{where}: missing **{key}:**")

        if not entry.paths and entry.keys.get("Applies to"):
            problems.append(f"{where}: 'Applies to' names no path")
        for pattern in entry.paths:
            if not path_matches(pattern, root):
                problems.append(f"{where}: 'Applies to' pattern matches nothing: {pattern}")

        for token in CODE_RE.findall(entry.keys.get("Source", "")):
            if DECISION_RE.match(token) and token not in decisions:
                problems.append(f"{where}: source names an unknown decision: {token}")

        if entry.unguarded:
            if entry.guards:
                problems.append(f"{where}: guard is marked absent but also names a test")
            continue
        if not entry.guards:
            problems.append(
                f"{where}: no guard — name a test, or state '— (no guard written)' / '— (guard not located)'"
            )
        for token in entry.guards:
            match = TEST_NAME_RE.match(token)
            if not match:
                problems.append(f"{where}: guard is not a test name or node id: {token}")
            elif match.group(1) not in tests:
                problems.append(f"{where}: guard names a test that does not exist: {token}")
    return problems


def applicable(entries: list[Entry], target: str, root: Path = ROOT) -> list[Entry]:
    """Entries whose 'Applies to' covers ``target``, given repository-relative or absolute input."""
    candidate = Path(target)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root.resolve())
        except ValueError:
            return []
    wanted = candidate.as_posix()
    hits = []
    for entry in entries:
        for pattern in entry.paths:
            if wanted in path_matches(pattern, root) or wanted == pattern:
                hits.append(entry)
                break
    return hits


def render(entry: Entry) -> str:
    guard = entry.keys.get("Guard", "").strip()
    return f"{entry.rid} — {entry.title}\n  {entry.text}\n  Guard: {guard}"


def unapproved_changes(paths: list[str]) -> list[str]:
    """Held files changed with no change directory beside them.

    This is the after-the-fact half of approval. The hook stops the write; this
    catches the write that got in another way — a branch, a merge, a shell
    redirect on a host without the hook. It cannot prove the operator agreed,
    only that the change is written down where they will see it.
    """
    touched = [path for path in paths if path in HELD_PATHS]
    if not touched or any(path.startswith(CHANGE_DIR) for path in paths):
        return []
    return [f"{path} changed with no change directory under {CHANGE_DIR}" for path in touched]


def changed_since(ref: str) -> list[str]:
    """Paths that differ from ``ref``, working tree and untracked files included.

    Untracked files are part of the answer: a change directory that has not been
    committed yet is exactly the state this runs in most often, and leaving it
    out would report an approved change as unapproved.
    """
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--for", dest="target", help="print the requirements that govern a file")
    parser.add_argument(
        "--changed-against",
        dest="ref",
        help="fail when a held file changed against this ref with no change directory",
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

    if not CATALOG.exists():
        print(f"{CATALOG} is missing", file=sys.stderr)
        return 2
    entries = parse(CATALOG.read_text())

    if args.target:
        hits = applicable(entries, args.target)
        if not hits:
            return 0
        print(f"Requirements for {args.target}:")
        for entry in hits:
            print(render(entry))
        return 0

    problems = validate(entries)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    unguarded = [entry.rid for entry in entries if entry.unguarded]
    note = f", {len(unguarded)} without a guard ({', '.join(unguarded)})" if unguarded else ""
    print(f"specs: {len(entries)} requirements{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
