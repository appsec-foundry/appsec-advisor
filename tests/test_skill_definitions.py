"""Tests for skills/*/SKILL.md frontmatter definitions.

Mirrors tests/test_agent_definitions.py, which has enforced agent frontmatter
for a while. Skills had no equivalent guard, and two SKILL.md files
(review-threat-model, update-threat-model) shipped with YAML-invalid
frontmatter — an unquoted description containing a bare ``": "``, which YAML
reads as a nested mapping key. Both passed review, `make test` and
`make release-check` because nothing ever parsed them.

The rules below are deliberately cheap and total: every skill, every run.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = ROOT / "skills"

# Claude Code truncates/rejects over-long skill descriptions. The description is
# the only text the model sees when deciding whether to invoke a skill, so a
# silently truncated one degrades routing rather than failing loudly.
MAX_DESCRIPTION_CHARS = 1024

# Frontmatter keys the plugin's skills use. Kept closed on purpose: a typo'd or
# unsupported key is silently ignored by the loader, which is exactly the class
# of bug this file exists to catch.
ALLOWED_KEYS = {"name", "description"}
REQUIRED_KEYS = {"name", "description"}

SKILL_FILES = sorted(SKILLS_DIR.glob("*/SKILL.md"))


def parse_frontmatter(path: Path) -> dict:
    """Parse the YAML frontmatter between the leading --- delimiters.

    Raises on malformed frontmatter — callers assert the specific failure.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("file does not start with a '---' frontmatter delimiter")
    try:
        end = lines.index("---", 1)
    except ValueError:
        raise ValueError("frontmatter is not terminated by a closing '---'") from None
    return yaml.safe_load("\n".join(lines[1:end]))


def test_skill_files_discovered():
    """Guard the glob itself — an empty parametrisation would pass vacuously."""
    assert SKILL_FILES, "no SKILL.md files found under skills/"


@pytest.mark.parametrize("skill_file", SKILL_FILES, ids=lambda p: p.parent.name)
def test_skill_frontmatter_valid(skill_file: Path):
    """Validate every frontmatter rule in one pass per skill."""
    slug = skill_file.parent.name

    try:
        meta = parse_frontmatter(skill_file)
    except ValueError as exc:
        pytest.fail(f"{slug}: {exc}")
    except yaml.YAMLError as exc:
        detail = str(exc).splitlines()[0]
        pytest.fail(
            f"{slug}: frontmatter is not valid YAML ({detail}).\n"
            f"  Most likely cause: an unquoted description containing ': ' — "
            f"YAML reads that as a nested mapping key. Use a block scalar:\n"
            f"    description: >-\n      <text>"
        )

    if not isinstance(meta, dict):
        pytest.fail(f"{slug}: frontmatter did not parse to a mapping")

    problems: list[str] = []

    missing = REQUIRED_KEYS - set(meta)
    if missing:
        problems.append(f"missing required key(s): {sorted(missing)}")

    unknown = set(meta) - ALLOWED_KEYS
    if unknown:
        problems.append(f"unsupported key(s) (silently ignored by the loader): {sorted(unknown)}")

    name = meta.get("name")
    if name != slug:
        problems.append(f"name {name!r} does not match its directory {slug!r}")

    description = meta.get("description")
    if not isinstance(description, str) or not description.strip():
        problems.append("description is empty or not a string")
    elif len(description) > MAX_DESCRIPTION_CHARS:
        problems.append(f"description is {len(description)} chars, over the {MAX_DESCRIPTION_CHARS}-char limit")

    if problems:
        pytest.fail(f"{slug} frontmatter issues:\n  - " + "\n  - ".join(problems))
