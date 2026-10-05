"""Hold the rendered report to the approved report anatomy.

The anatomy document lists every level-2 and level-3 heading, every table,
and the labelled fields of findings, mitigations, and weaknesses. These tests
render frozen runs with the current pre-generator and composer and fail when
the report gains, loses, or reorders a part the document does not describe.
The chapter order and the §6 subsections are also compared with the sections
contract, so a chapter that neither frozen run renders is still held.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
ANATOMY = REPO_ROOT / "specs" / "changes" / "report-anatomy" / "report-anatomy.md"
QUICK_RUN = REPO_ROOT / "tests" / "fixtures" / "report-anatomy" / "quick-run"
FROZEN_RUN = REPO_ROOT / "tests" / "fixtures" / "e2e" / "frozen-run"

# Fragments the pre-generator derives from the model alone. The test
# regenerates them so a structural change in the pre-generator is caught;
# LLM-authored fragments stay frozen.
DETERMINISTIC_FRAGMENTS = (
    "system-overview.md",
    "architecture-diagrams.md",
    "assets.md",
    "attack-surface.md",
    "out-of-scope.md",
    "attack-walkthroughs.md",
    "ms-ai-exposure.json",
    "ms-critical-attack-tree.json",
)


def _load_module(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("renderers.compose_threat_model", SCRIPTS / "renderers/compose_threat_model.py")
pregenerate = _load_module("renderers.pregenerate_fragments", SCRIPTS / "renderers/pregenerate_fragments.py")


# ---------------------------------------------------------------------------
# Anatomy document
# ---------------------------------------------------------------------------

_CODE_SPAN = re.compile(r"`([^`]+)`")
_HEADING_SPAN = re.compile(r"^(#{2,4}) (.+)$")


def _pattern(text: str) -> re.Pattern[str]:
    """Turn an anatomy heading or label into a regex over rendered text."""
    rx = re.escape(text)
    rx = rx.replace(re.escape("<"), "<").replace(re.escape(">"), ">")
    rx = re.sub(r"<[^>]+>", ".+", rx)
    rx = rx.replace("NNN", r"\d{3,}")
    rx = rx.replace(re.escape("(n)"), r"\(\d+\)")
    rx = re.sub(r"(?<=\\\.)[NM](?=\\\.|\\ |$)", r"\\d+", rx)
    rx = re.sub(r"(?<=\\ )N(?=\\ |$)", r"\\d+", rx)
    return re.compile(rf"^{rx}$")


@dataclass
class Heading:
    level: int
    text: str
    required: bool
    pattern: re.Pattern[str]
    tables: list[tuple[str, bool]] = field(default_factory=list)
    children: list[Heading] = field(default_factory=list)


@dataclass
class FieldTable:
    owner: re.Pattern[str]
    owner_level: int
    fields: list[tuple[re.Pattern[str], str]]  # (label pattern, "always" | "p1p2" | "optional")


@dataclass
class Anatomy:
    chapters: list[Heading]
    field_tables: list[FieldTable]


def _split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _when(cell: str) -> str:
    cell = cell.strip().lower()
    if cell == "always":
        return "always"
    if "p1 or p2" in cell:
        return "p1p2"
    return "optional"


def parse_anatomy(path: Path = ANATOMY) -> Anatomy:
    chapters: list[Heading] = []
    field_tables: list[FieldTable] = []
    current2: Heading | None = None
    last_owner: Heading | None = None
    last_any: tuple[int, str] | None = None
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("| Field |"):
            assert last_any is not None, "field table without a preceding heading"
            rows = []
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                cells = _split_row(lines[i])
                span = _CODE_SPAN.search(cells[0])
                if span:
                    label = span.group(1).strip("*").rstrip(":").strip()
                    rows.append((_pattern(label), _when(cells[-1])))
                i += 1
            field_tables.append(FieldTable(_pattern(last_any[1]), last_any[0], rows))
            continue
        for found in _CODE_SPAN.finditer(line):
            span = found.group(1)
            m = _HEADING_SPAN.match(span)
            if m:
                level, text = len(m.group(1)), m.group(2)
                last_any = (level, text)
                if level == 4:
                    continue
                # "`### X` — only when ..." marks the heading optional.
                optional = line[found.end() :].lstrip().startswith("— only when")
                heading = Heading(level, text, not optional, _pattern(text))
                if level == 2:
                    chapters.append(heading)
                    current2 = heading
                else:
                    assert current2 is not None, f"level-3 heading before any chapter: {text}"
                    current2.children.append(heading)
                last_owner = heading
            elif span.startswith("|"):
                assert last_owner is not None, f"table before any heading: {span}"
                # "Table, only when ...: `| ... |`" marks the table optional.
                optional = "only when" in line[: found.start()]
                last_owner.tables.append((_normalize_table(span), not optional))
        i += 1
    return Anatomy(chapters, field_tables)


# ---------------------------------------------------------------------------
# Rendered report
# ---------------------------------------------------------------------------


def _normalize_table(header: str) -> str:
    return "| " + " | ".join(_split_row(header)) + " |"


@dataclass
class Block:
    level: int
    text: str
    lines: list[str] = field(default_factory=list)


def rendered_blocks(markdown: str) -> list[Block]:
    """Headings with the body lines up to the next heading, outside code fences."""
    blocks: list[Block] = [Block(1, "")]
    fenced = False
    for line in markdown.splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        m = re.match(r"^(#{2,4}) (.+?)\s*$", line)
        if m:
            blocks.append(Block(len(m.group(1)), m.group(2)))
        else:
            blocks[-1].lines.append(line)
    return blocks


def _tables(block: Block) -> list[str]:
    found, previous = [], ""
    for line in block.lines:
        if line.startswith("|") and not previous.startswith("|"):
            found.append(_normalize_table(line))
        previous = line
    return found


def _match_in_order(rendered: list[str], expected: list[Heading], where: str) -> list[str]:
    """Each rendered heading must match an expected one at or after the previous match."""
    problems, index = [], 0
    for text in rendered:
        hit = next((j for j in range(index, len(expected)) if expected[j].pattern.match(text)), None)
        if hit is None:
            known = any(e.pattern.match(text) for e in expected)
            problems.append(f"{where}: {'out of order' if known else 'not in the anatomy'}: {text!r}")
            continue
        index = hit
    for e in expected:
        if e.required and not any(e.pattern.match(t) for t in rendered):
            problems.append(f"{where}: missing required heading {e.text!r}")
    return problems


def check_report(markdown: str, anatomy: Anatomy, only: set[str] | None = None) -> list[str]:
    """Return every difference between a rendered report and the anatomy.

    ``only`` limits the check to the named chapters (anatomy heading text);
    without it the whole report is checked, including required chapters.
    """
    blocks = rendered_blocks(markdown)
    problems: list[str] = []
    chapters = [b for b in blocks if b.level == 2]
    if only is None:
        problems += _match_in_order([b.text for b in chapters], anatomy.chapters, "report")

    current: Heading | None = None
    seen_children: dict[str, list[str]] = {}
    owner_tables: list[tuple[Heading, Block]] = []
    for block in blocks:
        if block.level == 2:
            current = next((c for c in anatomy.chapters if c.pattern.match(block.text)), None)
            if current is not None and (only is None or current.text in only):
                seen_children.setdefault(current.text, [])
                owner_tables.append((current, block))
            else:
                current = None
        elif block.level == 3 and current is not None:
            seen_children[current.text].append(block.text)
            child = next((c for c in current.children if c.pattern.match(block.text)), None)
            if child is not None:
                owner_tables.append((child, block))
    for chapter in anatomy.chapters:
        if chapter.text in seen_children:
            problems += _match_in_order(seen_children[chapter.text], chapter.children, chapter.text)

    for owner, block in owner_tables:
        allowed = {t for t, _ in owner.tables}
        present = _tables(block)
        problems += [f"{block.text}: table not in the anatomy: {t}" for t in present if t not in allowed]
        problems += [
            f"{block.text}: missing required table: {t}" for t, req in owner.tables if req and t not in present
        ]

    problems += _check_fields(blocks, anatomy, only)
    return problems


def _labels(lines: list[str]) -> list[str]:
    labels = []
    for line in lines:
        m = re.match(r"^\*\*(.+?)\*\*", line)
        if m:
            labels.append(m.group(1).strip().rstrip(":").strip())
    return labels


def _check_fields(blocks: list[Block], anatomy: Anatomy, only: set[str] | None) -> list[str]:
    problems: list[str] = []
    chapter, group = None, ""
    for i, block in enumerate(blocks):
        if block.level == 2:
            chapter = next((c.text for c in anatomy.chapters if c.pattern.match(block.text)), None)
        if block.level == 3:
            group = block.text
        if only is not None and chapter not in only:
            continue
        for table in anatomy.field_tables:
            if block.level != table.owner_level or not table.owner.match(block.text):
                continue
            body = list(block.lines)
            for nxt in blocks[i + 1 :]:
                if nxt.level <= block.level:
                    break
                body += nxt.lines
            labels = _labels(body)
            index = 0
            for label in labels:
                hit = next((j for j in range(index, len(table.fields)) if table.fields[j][0].match(label)), None)
                if hit is None:
                    known = any(p.match(label) for p, _ in table.fields)
                    state = "out of order" if known else "not in the anatomy"
                    problems.append(f"{block.text}: label {state}: {label!r}")
                    continue
                index = hit
            urgent = group.startswith(("P1", "P2"))
            for pattern, when in table.fields:
                needed = when == "always" or (when == "p1p2" and urgent)
                if needed and not any(pattern.match(lb) for lb in labels):
                    problems.append(f"{block.text}: missing required label {pattern.pattern!r}")
    return problems


# ---------------------------------------------------------------------------
# Frozen runs
# ---------------------------------------------------------------------------


def _render(source: Path, tmp_path: Path, fragments: tuple[str, ...]) -> str:
    run = tmp_path / source.name
    shutil.copytree(source, run)
    assert pregenerate.main(["--force", "--only", ",".join(fragments), str(run)]) == 0
    markdown, _warnings = compose.render(CONTRACT, run)
    return markdown


@pytest.fixture(scope="module")
def anatomy() -> Anatomy:
    return parse_anatomy()


@pytest.fixture(scope="module")
def contract() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_anatomy_parses_into_chapters_and_field_tables(anatomy: Anatomy) -> None:
    assert len(anatomy.chapters) >= 15
    for heading in ("F-001 · SQL injection", "M-012 — Parameterize queries", "W-003 — Missing validation"):
        assert sum(bool(t.owner.match(heading)) for t in anatomy.field_tables) == 1, heading
    assert not any(t.owner.match("F-1 · too short") for t in anatomy.field_tables)


def test_chapter_order_matches_contract(anatomy: Anatomy, contract: dict) -> None:
    sections = contract["sections"]
    ids = [item["id"] if isinstance(item, dict) else item for item in contract["document"]["order"]]
    headings = [sections[i].get("heading") or "" for i in ids]
    expected = [h[3:] for h in headings if h.startswith("## ")]
    assert [c.text for c in anatomy.chapters] == expected


def test_security_architecture_subsections_match_contract(anatomy: Anatomy, contract: dict) -> None:
    subsections = contract["sections"]["security_architecture"]["schema_v2"]["required_subsections"]
    chapter = next(c for c in anatomy.chapters if c.text == "6. Security Architecture")
    assert [c.text for c in chapter.children] == [s["title"] for s in subsections]
    assert all(c.required for c in chapter.children)


def test_quick_run_report_follows_anatomy(anatomy: Anatomy, tmp_path: Path) -> None:
    markdown = _render(QUICK_RUN, tmp_path, DETERMINISTIC_FRAGMENTS)
    assert check_report(markdown, anatomy) == []


def test_attack_walkthroughs_follow_anatomy(anatomy: Anatomy, tmp_path: Path) -> None:
    markdown = _render(FROZEN_RUN, tmp_path, ("attack-walkthroughs.md",))
    assert "## 3. Attack Walkthroughs" in markdown
    assert check_report(markdown, anatomy, only={"3. Attack Walkthroughs"}) == []


# ---------------------------------------------------------------------------
# The check itself must reject drift
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def quick_markdown(anatomy: Anatomy, tmp_path_factory: pytest.TempPathFactory) -> str:
    return _render(QUICK_RUN, tmp_path_factory.mktemp("quick"), DETERMINISTIC_FRAGMENTS)


def test_missing_required_section_is_reported(anatomy: Anatomy, quick_markdown: str) -> None:
    broken = quick_markdown.replace("\n### Not Covered by This Method\n", "\n")
    assert any("Not Covered by This Method" in p for p in check_report(broken, anatomy))


def test_unknown_section_is_reported(anatomy: Anatomy, quick_markdown: str) -> None:
    broken = quick_markdown.replace("\n## 4. Assets\n", "\n## 4. Assets\n\n### Asset Inventory\n", 1)
    assert any("Asset Inventory" in p for p in check_report(broken, anatomy))


def test_reordered_chapters_are_reported(anatomy: Anatomy, quick_markdown: str) -> None:
    broken = quick_markdown.replace("## 4. Assets", "## 4x").replace("## 5. Attack Surface", "## 4. Assets")
    broken = broken.replace("## 4x", "## 5. Attack Surface")
    assert any("out of order" in p for p in check_report(broken, anatomy))


def test_changed_table_columns_are_reported(anatomy: Anatomy, quick_markdown: str) -> None:
    broken = quick_markdown.replace("| Field | Value |", "| Field | Value | Unit |", 1)
    problems = check_report(broken, anatomy)
    assert any("Unit" in p for p in problems)
    assert any("missing required table" in p for p in problems)


def test_missing_and_reordered_finding_fields_are_reported(anatomy: Anatomy, quick_markdown: str) -> None:
    first_fix = re.search(r"^\*\*Fix:\*\*.*$", quick_markdown, re.M)
    assert first_fix is not None
    broken = quick_markdown.replace(first_fix.group(0), "", 1)
    assert any("Fix" in p for p in check_report(broken, anatomy))

    card = re.search(r"^#### F-\d+ .*?(?=^#### |^## )", quick_markdown, re.M | re.S)
    assert card is not None
    text = card.group(0)
    issue = re.search(r"^\*\*Issue:\*\*.*$", text, re.M)
    classification = re.search(r"^\*\*Classification:\*\*.*$", text, re.M)
    assert issue and classification
    swapped = text.replace(issue.group(0), "@@ISSUE@@").replace(classification.group(0), issue.group(0))
    swapped = swapped.replace("@@ISSUE@@", classification.group(0))
    problems = check_report(quick_markdown.replace(text, swapped, 1), anatomy)
    assert any("out of order" in p for p in problems)


def test_unknown_mitigation_field_is_reported(anatomy: Anatomy, quick_markdown: str) -> None:
    broken = quick_markdown.replace("**Addresses:**", "**Owner:** team\n\n**Addresses:**", 1)
    assert any("Owner" in p for p in check_report(broken, anatomy))


def test_optional_parts_may_be_absent(anatomy: Anatomy, quick_markdown: str) -> None:
    blocks = rendered_blocks(quick_markdown)
    start = next(i for i, b in enumerate(blocks) if b.text == "AI / LLM Exposure")
    trimmed = "\n".join(
        (("#" * b.level) + " " + b.text + "\n" if b.text else "") + "\n".join(b.lines)
        for i, b in enumerate(blocks)
        if i != start
    )
    assert check_report(trimmed, anatomy) == []
