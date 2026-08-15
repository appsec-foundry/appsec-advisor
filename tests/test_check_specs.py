"""Guards for `scripts/check_specs.py` — the checker behind `specs/requirements.md`.

The catalog is only binding if a broken reference fails. These tests break each
reference in turn and expect the complaint, so the checker cannot quietly stop
catching one.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_specs  # noqa: E402

REAL_TEST = "test_clean_project_passes"
REAL_DECISION = "RA-6"


def entry(
    rid: str = "REQ-XYZ-001",
    title: str = "A title",
    text: str = "The rule, in a sentence.",
    applies: str = "`scripts/check_specs.py`",
    source: str = f"`{REAL_DECISION}`",
    guard: str = f"`{REAL_TEST}`",
) -> str:
    return (
        f"# Plugin requirements\n\n## A section\n\n### {rid} — {title}\n\n{text}\n\n"
        f"**Applies to:** {applies}\n**Source:** {source}\n**Guard:** {guard}\n"
    )


def problems(markdown: str) -> list[str]:
    return check_specs.validate(check_specs.parse(markdown))


def test_shipped_catalog_is_valid():
    """The catalog in the repository must pass its own checker."""
    entries = check_specs.parse(check_specs.CATALOG.read_text())
    assert entries
    assert check_specs.validate(entries) == []


def test_parses_text_keys_and_section():
    parsed = check_specs.parse(entry())
    assert len(parsed) == 1
    only = parsed[0]
    assert only.rid == "REQ-XYZ-001"
    assert only.title == "A title"
    assert only.section == "A section"
    assert only.text == "The rule, in a sentence."
    assert only.paths == ["scripts/check_specs.py"]
    assert only.guards == [REAL_TEST]


def test_valid_entry_has_no_problems():
    assert problems(entry()) == []


def test_duplicate_id_is_rejected():
    doubled = entry() + entry(title="Another title").split("# Plugin requirements\n\n", 1)[1]
    assert any("duplicate id" in problem for problem in problems(doubled))


def test_malformed_id_is_not_parsed_as_an_entry():
    assert problems(entry(rid="REQ-1")) == ["requirements.md: no requirements found"]


@pytest.mark.parametrize("key", ["Applies to", "Source", "Guard"])
def test_missing_key_is_reported(key):
    text = entry().replace(f"**{key}:**", "**Removed:**")
    assert any(f"missing **{key}:**" in problem for problem in problems(text))


def test_missing_requirement_text_is_reported():
    text = entry().replace("The rule, in a sentence.\n\n", "")
    assert any("no requirement text" in problem for problem in problems(text))


def test_unknown_guard_is_reported():
    text = entry(guard="`test_this_was_renamed_away`")
    assert any("does not exist" in problem for problem in problems(text))


def test_guard_that_is_not_a_test_name_is_reported():
    text = entry(guard="`scripts/check_specs.py`")
    assert any("not a test name" in problem for problem in problems(text))


def test_node_id_guard_is_accepted():
    text = entry(guard=f"`tests/test_check_target_specificity.py::{REAL_TEST}`")
    assert problems(text) == []


def test_unknown_decision_in_source_is_reported():
    text = entry(source="`ZZ-99`")
    assert any("unknown decision" in problem for problem in problems(text))


def test_applies_to_pattern_matching_nothing_is_reported():
    text = entry(applies="`scripts/there_is_no_such_module.py`")
    assert any("matches nothing" in problem for problem in problems(text))


def test_glob_in_applies_to_is_accepted():
    assert problems(entry(applies="`scripts/**`")) == []


@pytest.mark.parametrize("marker", check_specs.NO_GUARD)
def test_absent_guard_marker_is_accepted(marker):
    assert problems(entry(guard=marker)) == []


def test_absent_guard_marker_with_a_test_is_rejected():
    text = entry(guard=f"{check_specs.NO_GUARD[0]}, `{REAL_TEST}`")
    assert any("marked absent but also names a test" in problem for problem in problems(text))


def test_empty_catalog_is_reported():
    assert problems("# Plugin requirements\n") == ["requirements.md: no requirements found"]


def test_applicable_matches_a_governed_file():
    parsed = check_specs.parse(entry(applies="`scripts/**`"))
    assert [e.rid for e in check_specs.applicable(parsed, "scripts/check_specs.py")] == ["REQ-XYZ-001"]


def test_applicable_ignores_a_file_outside_the_catalog():
    parsed = check_specs.parse(entry(applies="`scripts/check_specs.py`"))
    assert check_specs.applicable(parsed, "README.md") == []


def test_applicable_ignores_a_path_outside_the_repository():
    parsed = check_specs.parse(entry(applies="`scripts/**`"))
    assert check_specs.applicable(parsed, "/etc/passwd") == []


def test_main_reports_the_count_and_the_unguarded(capsys):
    assert check_specs.main([]) == 0
    assert "requirements" in capsys.readouterr().out


def test_main_for_prints_the_governing_requirements(capsys):
    assert check_specs.main(["--for", "scripts/merge_threats.py"]) == 0
    assert "REQ-MOD-001" in capsys.readouterr().out


def test_main_for_unknown_file_prints_nothing(capsys):
    assert check_specs.main(["--for", "scripts/does_not_exist.py"]) == 0
    assert capsys.readouterr().out == ""


def test_a_held_file_alone_is_unapproved():
    assert check_specs.unapproved_changes(["specs/requirements.md"]) == [
        "specs/requirements.md changed with no change directory under specs/changes/"
    ]


def test_a_held_file_with_a_change_directory_is_fine():
    changed = ["docs/internal/decisions.md", "specs/changes/some-change/proposal.md"]
    assert check_specs.unapproved_changes(changed) == []


def test_ordinary_changes_need_nothing():
    assert check_specs.unapproved_changes(["scripts/merge_threats.py", "README.md"]) == []


def test_changed_against_an_unknown_ref_reports_and_exits_two(capsys):
    assert check_specs.main(["--changed-against", "no-such-ref-xyz"]) == 2
    assert capsys.readouterr().err
