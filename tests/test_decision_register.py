"""Guards for `docs/internal/decisions.md` — the architecture decision register.

The register is only worth reading if its references are real. A row naming a test
nobody wrote, or a path that has since moved, reads as enforcement while enforcing
nothing — the failure mode is silent, because the row still looks authoritative.

These checks apply the register's own convention to itself. What they cannot check
is whether a named guard actually bites; that belongs to the guard, and
`tests/test_enforcement_mutations.py` is the model for proving it.
"""

from __future__ import annotations

import re
from collections import defaultdict
from functools import cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "docs" / "internal" / "decisions.md"
TESTS_DIR = ROOT / "tests"

ROW_RE = re.compile(r"^\| ([A-Z]{2,3}-\d+) \|")
ID_RE = re.compile(r"\b([A-Z]{2,3})-(\d+)\b")
PRINCIPLE_RE = re.compile(r"^- \*\*(P-\d+)\b", re.M)
TEST_NAME_RE = re.compile(r"`(test_\w+)`")
TEST_FILE_RE = re.compile(r"`(?:tests/)?(test_\w+\.py)`")
REPO_PATH_RE = re.compile(r"`((?:docs|data|schemas|scripts|agents|skills|tests)/[\w./-]+)`")

# Guard cells with no guard must say which of the two states they are in.
NO_GUARD_FORMS = ("— *(guard not located)*", "— *(no guard written)*")


@cache
def _register_text() -> str:
    return REGISTER.read_text(encoding="utf-8")


@cache
def _rows() -> list[tuple[str, str, str, str]]:
    """Return (id, decision, guard, rationale) for every table row."""
    rows = []
    for line in _register_text().splitlines():
        if not ROW_RE.match(line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == 4, f"{cells[0]}: expected 4 columns, got {len(cells)}"
        rows.append(tuple(cells))
    return rows


@cache
def _defined_test_names() -> set[str]:
    names: set[str] = set()
    for path in TESTS_DIR.glob("test_*.py"):
        names |= set(re.findall(r"^\s*def (test_\w+)", path.read_text(encoding="utf-8", errors="ignore"), re.M))
    return names


@cache
def _known_ids() -> set[str]:
    ids = {row[0] for row in _rows()}
    ids |= set(PRINCIPLE_RE.findall(_register_text()))
    return ids


def test_register_exists_and_has_rows():
    assert REGISTER.is_file(), "the decision register must exist"
    assert len(_rows()) > 50, "the register lost most of its entries"


def test_ids_are_unique():
    ids = [row[0] for row in _rows()]
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, f"duplicate decision IDs: {sorted(duplicates)}"


def test_ids_are_contiguous_per_prefix():
    """IDs are anchors once a guard cites one, so gaps must not appear silently."""
    seen: dict[str, list[int]] = defaultdict(list)
    for row in _rows():
        prefix, number = row[0].rsplit("-", 1)
        seen[prefix].append(int(number))
    gaps = {
        p: sorted(set(range(1, max(n) + 1)) - set(n)) for p, n in seen.items() if set(range(1, max(n) + 1)) - set(n)
    }
    assert not gaps, f"decision IDs must be contiguous per prefix; missing: {gaps}"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r[0])
def test_named_tests_exist(row):
    """A guard that names a test nobody wrote enforces nothing."""
    defined = _defined_test_names()
    missing = [name for name in TEST_NAME_RE.findall(row[2]) if name not in defined]
    assert not missing, f"{row[0]}: guard names tests that do not exist: {missing}"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r[0])
def test_named_test_files_exist(row):
    missing = [f for f in TEST_FILE_RE.findall(row[2]) if not (TESTS_DIR / f).is_file()]
    assert not missing, f"{row[0]}: guard names test files that do not exist: {missing}"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r[0])
def test_referenced_repository_paths_exist(row):
    """Rationale and guard cells cite real files, or the reader follows a dead link."""
    cited = REPO_PATH_RE.findall(row[2]) + REPO_PATH_RE.findall(row[3])
    missing = [p for p in cited if not (ROOT / p).exists()]
    assert not missing, f"{row[0]}: cites paths that do not exist: {missing}"


@pytest.mark.parametrize("row", _rows(), ids=lambda r: r[0])
def test_empty_guards_state_which_kind(row):
    """`guard not located` and `no guard written` are different facts for a reader."""
    if not row[2].startswith("—"):
        return
    assert row[2] in NO_GUARD_FORMS, f"{row[0]}: empty guard must use one of {NO_GUARD_FORMS}, got {row[2]!r}"


def test_cross_references_point_at_known_entries():
    """`see TR-4` must resolve, including after a renumbering."""
    known = _known_ids()
    prefixes = {i.rsplit("-", 1)[0] for i in known}
    dangling = set()
    for row in _rows():
        for cell in row[1:]:
            for prefix, number in ID_RE.findall(cell):
                if prefix in prefixes and f"{prefix}-{number}" not in known:
                    dangling.add(f"{row[0]} -> {prefix}-{number}")
    assert not dangling, f"cross-references to unknown entries: {sorted(dangling)}"


def test_decision_ids_used_in_assertions_exist():
    """A guard citing its decision ID in a failure message must cite a real one.

    This is how the register reaches someone who never opened it, so a stale ID in
    an assertion message is worse than none.
    """
    known = _known_ids()
    prefixes = {i.rsplit("-", 1)[0] for i in known}
    dangling = set()
    for path in TESTS_DIR.glob("test_*.py"):
        if path.name == Path(__file__).name:
            continue
        for prefix, number in re.findall(
            r'["\']([A-Z]{2,3})-(\d+):', path.read_text(encoding="utf-8", errors="ignore")
        ):
            if prefix in prefixes and f"{prefix}-{number}" not in known:
                dangling.add(f"{path.name} -> {prefix}-{number}")
    assert not dangling, f"assertion messages cite unknown decisions: {sorted(dangling)}"


def test_agents_md_points_at_the_register():
    """The pointer is the only thing that makes the register findable in a session."""
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "docs/internal/decisions.md" in agents, "AGENTS.md must point at the decision register"
