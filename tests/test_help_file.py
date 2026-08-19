"""Drift guards between the active resolver parser and ``HELP.txt``."""

import re
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).parent.parent
SKILL_DIR = PLUGIN_ROOT / "skills" / "create-threat-model"
SKILL_MD = SKILL_DIR / "SKILL.md"
HELP_TXT = SKILL_DIR / "HELP.txt"
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import resolve_config  # noqa: E402


# Internal/migration controls and symmetric negative forms are intentionally
# absent from the concise user help. Keep every exception explicit so a newly
# parsed public flag cannot disappear silently.
HELP_EXEMPT_FLAGS = {
    "--emit-file",
    "--no-org-profile",
    "--no-pdf",
    "--no-pentest-tasks",
    "--no-sarif",
    "--org-profile",
    "--preset",
    "--schema-v1",
    "--schema-v2",
    "--tracing",
}

# Headless-wrapper flags and cross-command examples legitimately appear in
# HELP.txt without belonging to resolve_config's skill parser.
HELP_ONLY_FLAGS = {
    "--force",
    "--formats",
    "--model",
    "--refresh-discovery",
    "--strict-urls",
    "--trust-mode",
}


def parsed_flags() -> set[str]:
    return {
        option
        for action in resolve_config.build_parser()._actions
        for option in action.option_strings
        if option.startswith("--")
    }


def help_flags() -> set[str]:
    return set(re.findall(r"(--[a-z][a-z0-9-]*)", HELP_TXT.read_text(encoding="utf-8")))


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


def test_all_public_parser_flags_are_documented_in_help():
    missing = parsed_flags() - help_flags() - HELP_EXEMPT_FLAGS
    assert not missing, f"resolver flags missing from HELP.txt: {sorted(missing)}"


def test_help_contains_no_retired_or_phantom_skill_flags():
    phantom = help_flags() - parsed_flags() - HELP_ONLY_FLAGS
    assert not phantom, f"HELP.txt contains unknown flags: {sorted(phantom)}"
