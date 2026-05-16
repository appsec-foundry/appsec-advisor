"""
Drift guard: every flag parsed by the skill's Argument Parsing table must also
appear in HELP.txt (modulo explicitly-exempt flags). Prevents the help text
from drifting out of sync with the actual flag surface — a pre-existing drift
problem that triggered the extraction of HELP.txt from SKILL.md.
"""

import re
from pathlib import Path

PLUGIN_ROOT = Path(__file__).parent.parent
SKILL_DIR = PLUGIN_ROOT / "skills" / "create-threat-model"
SKILL_MD = SKILL_DIR / "SKILL.md"
SKILL_IMPL = SKILL_DIR / "SKILL-impl.md"
HELP_TXT = SKILL_DIR / "HELP.txt"

# Flags that intentionally never appear in HELP.txt (power-user / undocumented).
# Keep this list short and justified.
HELP_EXEMPT_FLAGS = {
    "--tracing",  # power-user diagnostic; enabled via env or marker file
}

# Pre-existing drift: flags that appear in HELP.txt + scripts/run-headless.sh
# but have never been added to SKILL.md's Argument Parsing table. When someone
# finally documents them, remove from this set.
KNOWN_UNDOCUMENTED_FLAGS = {
    "--clean-cache",
    "--clean-all",
    "--force",
}

# Match flags inside the Argument Parsing table's backtick-quoted flag cell.
# Some rows document aliases such as ``--tracing`` / ``--no-tracing`` in the
# same cell, so collect every backtick-started flag, stopping at whitespace.
FLAG_ROW_RE = re.compile(r"`(--[a-z][a-z0-9-]*)")


def parsed_flags() -> set[str]:
    """Extract every --flag from the 'Argument Parsing' markdown table."""
    text = SKILL_IMPL.read_text(encoding="utf-8")
    # Isolate the Argument Parsing table — bounded by its heading and the
    # first blank line after 'Deprecated aliases:'
    start = text.index("## Argument Parsing")
    end = text.index("**Deprecated aliases:**", start)
    table = text[start:end]
    return set(FLAG_ROW_RE.findall(table))


def help_flags() -> set[str]:
    """Extract every --flag mentioned in HELP.txt."""
    text = HELP_TXT.read_text(encoding="utf-8")
    return set(re.findall(r"(--[a-z][a-z0-9-]*)", text))


def test_help_file_exists():
    assert HELP_TXT.is_file(), f"HELP.txt missing at {HELP_TXT}"


def test_help_file_non_empty():
    assert HELP_TXT.stat().st_size > 200, "HELP.txt is suspiciously small"


def test_help_file_starts_with_skill_name():
    first_line = HELP_TXT.read_text(encoding="utf-8").splitlines()[0]
    assert "create-threat-model" in first_line, f"HELP.txt should open with the skill name; got: {first_line!r}"


def test_skill_md_references_help_file():
    """SKILL.md must invoke HELP.txt via cat — prevents accidental re-inlining."""
    text = SKILL_MD.read_text(encoding="utf-8")
    assert "HELP.txt" in text, "SKILL.md no longer references HELP.txt"
    assert 'cat "$CLAUDE_PLUGIN_ROOT/skills/create-threat-model/HELP.txt"' in text, (
        "SKILL.md must invoke HELP.txt via the canonical cat command"
    )


def test_skill_md_has_no_inline_help_block():
    """The large '/appsec-advisor:create-threat-model — Architectural STRIDE ...'
    banner block must live in HELP.txt only, not back in SKILL.md."""
    text = SKILL_MD.read_text(encoding="utf-8")
    # The USAGE block is the cheapest signal that help text got re-inlined
    assert "USAGE\n  /appsec-advisor:create-threat-model [SCOPE] [FLAGS]" not in text, (
        "SKILL.md contains an inline help USAGE block — it belongs in HELP.txt"
    )


def test_all_parsed_flags_documented_in_help():
    """Every flag in the Argument Parsing table must appear in HELP.txt,
    except the explicitly exempt ones."""
    parsed = parsed_flags()
    assert parsed, "no flags parsed from SKILL.md Argument Parsing table"
    helped = help_flags()
    missing = (parsed - helped) - HELP_EXEMPT_FLAGS
    assert not missing, (
        f"flags in Argument Parsing table but not in HELP.txt: {sorted(missing)}. "
        f"Either document them in HELP.txt or add to HELP_EXEMPT_FLAGS with justification."
    )


def test_no_phantom_flags_in_help():
    """Flags in HELP.txt that are not in the Argument Parsing table are
    likely typos or removed features — fail fast (except for the known
    pre-existing drift in KNOWN_UNDOCUMENTED_FLAGS)."""
    parsed = parsed_flags()
    helped = help_flags()
    # Deprecated aliases appear in both per-flag deprecation notices in
    # SKILL.md; they may or may not appear in HELP.txt — allow either.
    known_aliases = {"--with-requirements", "--ignore-requirements", "--requirements-url"}
    # Common non-flag tokens that happen to start with --
    false_positives = {"--"}
    phantom = helped - parsed - known_aliases - false_positives - KNOWN_UNDOCUMENTED_FLAGS
    assert not phantom, (
        f"HELP.txt mentions flags that no longer exist in the Argument Parsing "
        f"table: {sorted(phantom)}. Either add them to the table or remove from HELP.txt."
    )
