"""
Drift guard: the `threat-model.yaml` schema v1 lives in ONE place —
`schemas/threat-model.output.schema.yaml`. Agent prompts and phase-group
files must reference the schema file, not re-inline it.

Sprint 1 Item C extracted ~160 lines of duplicated schema definition from
`appsec-threat-analyst.md` and `phase-group-finalization.md`. This test
prevents regression.
"""

import re
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
SCHEMA_FILE = PLUGIN_ROOT / "schemas" / "threat-model.output.schema.yaml"

# Files that are allowed to contain schema definition content (exactly one)
ALLOWED_SCHEMA_AUTHORITIES = {
    SCHEMA_FILE,
}

# Files that are SCANNED for drift (must NOT re-inline schema structure)
SCANNED_FILES = [
    PLUGIN_ROOT / "agents" / "appsec-threat-analyst.md",
    PLUGIN_ROOT / "agents" / "phases" / "phase-group-finalization.md",
]

# Signals that indicate the schema has been re-inlined as a YAML example.
# The pattern is: a fenced yaml block whose first meaningful line is
# `meta:` followed (within a handful of lines) by `schema_version:` and
# at least one component / changelog / threats block header.
#
# A simple reference like "the yaml has a `meta:` section" shouldn't match —
# only a full multi-section structural duplication.

FENCED_YAML_BLOCK = re.compile(
    r"```ya?ml\s*\n(.*?)```",
    re.DOTALL,
)


def looks_like_full_schema_duplication(block: str) -> bool:
    """Return True iff a ```yaml``` fenced block appears to be a wholesale
    re-inline of the threat-model.yaml schema, as measured by presence of
    several distinctive top-level sections."""
    # Distinctive section headers that the schema file defines
    signals = [
        r"^\s*schema_version\s*:",
        r"^\s*components\s*:",
        r"^\s*changelog\s*:",
        r"^\s*threats\s*:",
        r"^\s*mitigations\s*:",
        r"^\s*security_controls\s*:",
        r"^\s*attack_surface\s*:",
        r"^\s*trust_boundaries\s*:",
    ]
    hits = sum(1 for pat in signals if re.search(pat, block, re.MULTILINE))
    # Four or more of the eight distinctive sections in one fenced block =
    # structural duplication. Genuine structural-reference snippets that
    # show (say) a changelog entry example typically hit ≤2.
    return hits >= 4


@pytest.mark.parametrize("path", SCANNED_FILES, ids=lambda p: str(p.relative_to(PLUGIN_ROOT)))
def test_no_inline_schema_duplication(path: Path):
    assert path.is_file(), f"expected scanned file missing: {path}"
    text = path.read_text(encoding="utf-8")
    for block in FENCED_YAML_BLOCK.findall(text):
        assert not looks_like_full_schema_duplication(block), (
            f"{path.relative_to(PLUGIN_ROOT)} contains a YAML block that looks "
            f"like a re-inline of the threat-model.yaml schema. The authoritative "
            f"schema lives in {SCHEMA_FILE.relative_to(PLUGIN_ROOT)} — reference "
            f"it instead of duplicating structure."
        )


def test_scanned_files_reference_schema_file():
    """Every scanned file must point readers at the authoritative schema file."""
    for path in SCANNED_FILES:
        text = path.read_text(encoding="utf-8")
        assert "schemas/threat-model.output.schema.yaml" in text, (
            f"{path.relative_to(PLUGIN_ROOT)} must reference "
            f"schemas/threat-model.output.schema.yaml (the canonical schema)."
        )


def test_schema_file_exists_and_nonempty():
    assert SCHEMA_FILE.is_file(), f"authoritative schema missing: {SCHEMA_FILE}"
    assert SCHEMA_FILE.stat().st_size > 1000, (
        f"schema file suspiciously small — suggests accidental truncation"
    )
