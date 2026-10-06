"""Layout guard for the help page `skills/help/SKILL.md` prints.

The page is a Markdown list, not a set of column-aligned code blocks: one section
per function, one bullet per command, flag, or file, the name as inline code and a
one-line explanation after ` — `. A Markdown list re-indents when a terminal wraps
it, and it keeps its layout when `package_internal_plugin.rewrite_namespace`
replaces `appsec-advisor:` with an organization's own namespace. A code block
aligned in columns breaks under both, so the page contains none.

Every command the page names must exist as a skill; a stale name sends the reader
to a command the plugin rejects. The link to the full documentation sits directly
under the introduction of both parts, so a reader finds it without scrolling.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELP_SKILL = ROOT / "skills" / "help" / "SKILL.md"

MAX_EXPLANATION = 80
CODE_BULLET = re.compile(r"^\s*- `[^`]+`")
EXPLAINED_BULLET = re.compile(r"^\s*- `[^`]+` — (?P<explanation>\S.*)$")
COMMAND = re.compile(r"/appsec-advisor:([a-z][a-z0-9-]*)")


def printed_page() -> str:
    """Everything below `# appsec-advisor`, the part the skill prints."""
    text = HELP_SKILL.read_text(encoding="utf-8")
    _, _, page = text.partition("\n# appsec-advisor\n")
    assert page, "help page no longer starts its printed part with '# appsec-advisor'"
    return page


def printed_parts() -> dict[str, str]:
    page = printed_page()
    quick, sep, full = page.partition("\n## Full reference\n")
    assert sep, "help page lost its '## Full reference' part"
    assert "## Quick start" in quick, "help page lost its '## Quick start' part"
    return {"quick start": quick, "full reference": full}


def test_the_page_contains_no_code_block():
    assert "```" not in printed_page(), "use one bullet per command instead of an aligned code block"


def test_every_code_bullet_has_a_one_line_explanation():
    offending = []
    for line in printed_page().splitlines():
        if not CODE_BULLET.match(line):
            continue
        match = EXPLAINED_BULLET.match(line)
        if not match or len(match.group("explanation")) > MAX_EXPLANATION:
            offending.append(line)
    assert not offending, "bullets need `name` — explanation of at most %d characters:\n  %s" % (
        MAX_EXPLANATION,
        "\n  ".join(offending),
    )


def test_every_named_command_is_a_shipped_skill():
    named = set(COMMAND.findall(printed_page()))
    missing = sorted(name for name in named if not (ROOT / "skills" / name / "SKILL.md").is_file())
    assert not missing, f"help names commands that do not exist: {missing}"


@pytest.mark.parametrize("part", ["quick start", "full reference"])
def test_each_part_links_the_documentation_under_its_introduction(part):
    paragraphs = [block.strip() for block in printed_parts()[part].split("\n\n") if block.strip()]
    body = [block for block in paragraphs if not block.startswith("## ")]
    assert body[1].startswith("Documentation: https://"), (
        f"{part}: the documentation link must follow the introduction, found {body[1]!r}"
    )


@pytest.mark.parametrize("namespace", ["x:", "acme-appsec:"])
def test_a_renamed_namespace_keeps_every_bullet_intact(namespace):
    """Simulate `rewrite_namespace`: the bullet format must survive the substitution."""
    page = printed_page().replace("appsec-advisor:", namespace)
    for line in page.splitlines():
        if CODE_BULLET.match(line):
            assert EXPLAINED_BULLET.match(line), f"{namespace} breaks {line!r}"
