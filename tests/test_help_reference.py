"""Layout guard for the reference `skills/help/SKILL.md` prints.

The help page is a two-column reference: a command or path on the left, a short
explanation on the right. A terminal wraps any line wider than the window, and a
wrapped line inside a fenced block does not re-indent — the tail lands in column
zero of the next line, under the *left* column, and the whole block reads as
broken. That is a layout defect the reader sees on every invocation, so the width
is a contract rather than a style preference.

`MAX_BLOCK_WIDTH` leaves headroom below the classic 80-column terminal for the
padding a renderer adds around a code block. Two further rules keep the columns
from drifting apart again: one description column per block, and no block that
mixes namespace-prefixed command lines with other content, because
`package_internal_plugin.rewrite_namespace` substitutes `appsec-advisor:` with an
organization's own name and shifts every prefixed line by the length difference.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELP_SKILL = ROOT / "skills" / "help" / "SKILL.md"

MAX_BLOCK_WIDTH = 72
NAMESPACE = "appsec-advisor:"


def reference_blocks() -> list[list[str]]:
    """The fenced blocks of the printed reference, excluding the instructions."""
    text = HELP_SKILL.read_text(encoding="utf-8")
    _, _, reference = text.partition("\n# appsec-advisor\n")
    assert reference, "help page no longer starts its reference with '# appsec-advisor'"

    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in reference.split("\n"):
        if line.startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append(current)
                current = None
            continue
        if current is not None:
            current.append(line)
    assert current is None, "unbalanced code fence in the help reference"
    assert blocks, "help reference contains no fenced blocks"
    return blocks


def description_column(line: str) -> int | None:
    """Column the right-hand explanation starts in, or None for a single-column line."""
    match = re.search(r"\S(\s{2,})\S", line)
    return match.end(1) if match else None


def test_no_reference_line_wraps_in_a_terminal():
    too_wide = [line for block in reference_blocks() for line in block if len(line) > MAX_BLOCK_WIDTH]
    assert not too_wide, "lines wider than %d columns:\n  %s" % (
        MAX_BLOCK_WIDTH,
        "\n  ".join(f"{len(line)}  {line}" for line in too_wide),
    )


def test_each_block_keeps_one_description_column():
    for index, block in enumerate(reference_blocks()):
        columns = {description_column(line) for line in block if line.strip()} - {None}
        assert len(columns) <= 1, f"block {index} aligns its explanations at several columns: {sorted(columns)}"


def test_a_renamed_namespace_cannot_shift_a_description_column():
    """A packaged plugin replaces `appsec-advisor:` with its own namespace. Only a
    command line without an explanation may therefore share a block with lines that
    carry no namespace."""
    for index, block in enumerate(reference_blocks()):
        prefixed = [line for line in block if NAMESPACE in line]
        plain = [line for line in block if line.strip() and NAMESPACE not in line]
        if not (prefixed and plain):
            continue
        aligned = [line for line in prefixed if description_column(line) is not None]
        assert not aligned, (
            f"block {index} aligns explanations on namespace-prefixed lines while also holding "
            f"lines without the namespace, so a rename splits the column: {aligned}"
        )


@pytest.mark.parametrize("namespace", ["x:", "acme-appsec:"])
def test_a_shorter_namespace_keeps_the_reference_aligned(namespace):
    """Simulate `rewrite_namespace` and re-check both rules on the packaged text."""
    text = HELP_SKILL.read_text(encoding="utf-8").replace(NAMESPACE, namespace)
    _, _, reference = text.partition("\n# appsec-advisor\n")
    inside = False
    for line in reference.split("\n"):
        if line.startswith("```"):
            inside = not inside
            continue
        if inside and line.strip():
            assert len(line) <= MAX_BLOCK_WIDTH, f"{namespace} widens {line!r} to {len(line)} columns"
