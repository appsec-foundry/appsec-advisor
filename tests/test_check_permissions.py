"""
Tests for scripts/check_permissions.py and data/required-permissions.yaml.

Covers:
  * YAML parses and every entry has the expected fields.
  * Template placeholders (${OUTPUT_DIR}, ${REPO_ROOT}) expand correctly.
  * Rule-coverage logic (`Bash(prefix:*)` subsumption, `/**` glob subsumption).
  * Diff against a synthetic settings.json.
  * `--update` merges without duplicating and is idempotent.
  * Drift guard: every entry shipped in `.claude/settings.json` is explainable
    via the YAML (prevents the repo's own allow-list from drifting away from
    the source of truth).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_permissions as cp  # noqa: E402

# ---------- data file --------------------------------------------------


def test_yaml_loads_and_has_required_shape():
    entries = cp.load_required(cp.DATA_FILE)
    assert entries, "required-permissions.yaml must not be empty"
    for e in entries:
        assert e["entry"], "every item needs an 'entry'"
        assert isinstance(e["category"], str)
        assert isinstance(e["reason"], str)


def test_yaml_validates_against_schema(tmp_path):
    """required-permissions.yaml must satisfy the JSON Schema contract.

    Also asserts that a deliberately invalid entry (unknown `category`)
    fails schema validation — proves the validator is wired in, not a
    no-op when jsonschema is missing.
    """
    pytest.importorskip("jsonschema")
    cp.load_required(cp.DATA_FILE)
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\n"
        "required:\n"
        "  - entry: 'Bash(git:*)'\n"
        "    reason: 'a sufficiently long reason'\n"
        "    category: bogus\n",
        encoding="utf-8",
    )
    with pytest.raises(SystemExit):
        cp.load_required(bad)


def test_yaml_entries_are_unique():
    entries = cp.load_required(cp.DATA_FILE)
    raw_entries = [e["entry"] for e in entries]
    assert len(raw_entries) == len(set(raw_entries)), "duplicate entries in required-permissions.yaml"


def test_yaml_entries_use_known_tools():
    entries = cp.load_required(cp.DATA_FILE)
    allowed_tools = {"Bash", "Write", "Edit", "Read"}
    for e in entries:
        prefix = e["entry"].split("(", 1)[0]
        assert prefix in allowed_tools, f"unknown tool prefix in entry {e['entry']!r}"


def test_controller_command_and_paths_are_covered_by_existing_rules():
    """The thin runtime adds no broader permission: Bash(*) runs the fixed
    controller command and the existing plugin/output globs cover its reads
    and writes."""
    entries = cp.load_required(cp.DATA_FILE)
    rules = [entry["entry"] for entry in entries]
    assert any(cp._rule_covers(rule, "Bash(python3 orchestration_controller.py)") for rule in rules)
    assert "Read(${PLUGIN_ROOT}/**)" in rules
    assert "Write(${OUTPUT_DIR}/**)" in rules


# ---------- template expansion ----------------------------------------


def test_expand_entry_substitutes_placeholders():
    out = cp.expand_entry(
        "Write(${OUTPUT_DIR}/**)",
        Path("/tmp/repo"),
        Path("/tmp/repo/docs/security"),
    )
    assert out == "Write(/tmp/repo/docs/security/**)"

    out2 = cp.expand_entry(
        "Edit(${REPO_ROOT}/**)",
        Path("/tmp/repo"),
        Path("/tmp/out"),
    )
    assert out2 == "Edit(/tmp/repo/**)"

    out3 = cp.expand_entry(
        "Read(${PLUGIN_ROOT}/**)",
        Path("/tmp/repo"),
        Path("/tmp/out"),
        plugin_dir=Path("/tmp/plugin"),
    )
    assert out3 == "Read(/tmp/plugin/**)"


def test_expand_entry_substitutes_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    out = cp.expand_entry(
        "Read(${HOME}/.claude/projects/**)",
        Path("/tmp/repo"),
        Path("/tmp/out"),
    )
    assert out == f"Read({tmp_path}/.claude/projects/**)"


def test_expand_entry_is_noop_without_placeholders():
    assert cp.expand_entry("Bash(grep:*)", Path("/x"), Path("/y")) == "Bash(grep:*)"


# ---------- rule coverage ---------------------------------------------


@pytest.mark.parametrize(
    "rule,needed,expected",
    [
        ("Bash(grep:*)", "Bash(grep:*)", True),
        ("Bash(grep:*)", "Bash(grep:-rn foo)", True),
        ("Bash(grep:*)", "Bash(find:*)", False),
        ("Bash(*)", "Bash(rm:*)", True),
        ("Read(*)", "Read(/tmp/foo)", True),
        ("Write(/tmp/**)", "Write(/tmp/foo/bar.md)", True),
        # /** does NOT cover direct dotfile children (Claude Code engine behavior)
        ("Write(/tmp/**)", "Write(/tmp/.sidecar.json)", False),
        # /** DOES cover files inside dot-subdirectories (2+ path components below base)
        ("Write(/tmp/**)", "Write(/tmp/.dispatch-context/x.md)", True),
        ("Write(/tmp/**)", "Write(/other/x)", False),
        # /.* covers direct dotfile children only
        ("Write(/tmp/.*)", "Write(/tmp/.sidecar.json)", True),
        ("Write(/tmp/.*)", "Write(/tmp/.dir/x.md)", False),
        ("Write(/tmp/.*)", "Write(/tmp/normal.md)", False),
        ("Edit(/repo/**)", "Edit(/repo/docs/security/a)", True),
        # different tool namespace never matches
        ("Bash(grep:*)", "Read(*)", False),
    ],
)
def test_rule_covers(rule, needed, expected):
    assert cp._rule_covers(rule, needed) is expected


# ---------- diff --------------------------------------------------------


def test_diff_finds_missing():
    required = [
        {"entry": "Bash(grep:*)", "reason": "", "category": "text"},
        {"entry": "Bash(find:*)", "reason": "", "category": "text"},
    ]
    granted = ["Bash(grep:-rn foo)"]  # not a covering rule — not "prefix:*"
    missing = cp.diff_required(required, granted)
    # grep:-rn foo does NOT cover Bash(grep:*) because coverage is one-way
    # (a specific rule doesn't subsume the wildcard). Both should be missing.
    assert {m["entry"] for m in missing} == {"Bash(grep:*)", "Bash(find:*)"}


def test_diff_subsumed_by_wildcard_rule():
    required = [
        {"entry": "Bash(grep:*)", "reason": "", "category": "text"},
        {"entry": "Bash(find:*)", "reason": "", "category": "text"},
    ]
    granted = ["Bash(*)"]
    missing = cp.diff_required(required, granted)
    assert missing == []


# ---------- write path --------------------------------------------------


def test_write_missing_creates_file_and_merges(tmp_path):
    target = tmp_path / ".claude" / "settings.json"
    added, kept = cp.write_missing(target, ["Bash(grep:*)", "Bash(find:*)"])
    assert added == 2 and kept == 0
    doc = json.loads(target.read_text())
    assert doc["permissions"]["allow"] == ["Bash(grep:*)", "Bash(find:*)"]


def test_write_missing_is_idempotent(tmp_path):
    target = tmp_path / "settings.json"
    target.write_text(json.dumps({"permissions": {"allow": ["Bash(grep:*)"]}}))
    added, kept = cp.write_missing(target, ["Bash(grep:*)", "Bash(find:*)"])
    assert added == 1 and kept == 1
    doc = json.loads(target.read_text())
    assert doc["permissions"]["allow"] == ["Bash(grep:*)", "Bash(find:*)"]

    # second call adds nothing
    added2, kept2 = cp.write_missing(target, ["Bash(grep:*)", "Bash(find:*)"])
    assert added2 == 0 and kept2 == 2


def test_write_missing_preserves_unrelated_keys(tmp_path):
    target = tmp_path / "settings.json"
    target.write_text(json.dumps({"hooks": {"foo": "bar"}, "permissions": {"deny": []}}))
    cp.write_missing(target, ["Bash(grep:*)"])
    doc = json.loads(target.read_text())
    assert doc["hooks"] == {"foo": "bar"}
    assert doc["permissions"]["deny"] == []
    assert doc["permissions"]["allow"] == ["Bash(grep:*)"]


# ---------- end-to-end main() ------------------------------------------


def test_main_exit_code_when_all_granted(tmp_path, capsys, monkeypatch):
    # build a project settings.json that grants every required entry
    entries = cp.load_required(cp.DATA_FILE)
    expanded = [
        cp.expand_entry(e["entry"], tmp_path, tmp_path / "docs" / "security", plugin_dir=tmp_path) for e in entries
    ]
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"permissions": {"allow": expanded}}))

    # empty user settings
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    rc = cp.main(["--repo-root", str(tmp_path), "--plugin-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "All permissions are already configured to scan repo path" in out


def test_main_exit_code_when_missing(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    rc = cp.main(["--repo-root", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["missing_total"] > 0


def test_main_update_fixes_missing(tmp_path, capsys, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    # first, confirm it's dirty
    rc = cp.main(["--repo-root", str(tmp_path), "--plugin-dir", str(tmp_path)])
    capsys.readouterr()  # flush
    assert rc == 1

    # now update and re-check
    rc = cp.main(["--repo-root", str(tmp_path), "--plugin-dir", str(tmp_path), "--update"])
    capsys.readouterr()
    assert rc == 0

    rc = cp.main(["--repo-root", str(tmp_path), "--plugin-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0, out


# ---------- drift guard --------------------------------------------------


def test_rule_covers_bracket_form():
    assert cp._rule_covers("Bash([:*)", "Bash([ -f /tmp/file ])")
    assert not cp._rule_covers("Bash([:*)", "Bash(test -f /tmp/file)")


def test_shipped_settings_is_covered_by_yaml():
    """
    Every Bash/* entry in the repo's own `.claude/settings.json` should be
    explainable by an equal-or-more-general rule in `data/required-permissions.yaml`
    (after template expansion). This is a drift guard: if somebody adds a
    `Bash(foo:*)` to settings.json but forgets the YAML, we catch it.

    Write()/Edit() entries are exempt because they contain absolute paths
    specific to the maintainer's machine (see AGENTS.md permission guidance).
    """
    shipped = REPO_ROOT / ".claude" / "settings.json"
    if not shipped.is_file():
        pytest.skip("no shipped .claude/settings.json")
    doc = json.loads(shipped.read_text())
    allow = doc.get("permissions", {}).get("allow", [])
    bash_entries = [a for a in allow if a.startswith("Bash(")]

    required = cp.load_required(cp.DATA_FILE)
    required_bash = [r["entry"] for r in required if r["entry"].startswith("Bash(")]

    unexplained = []
    for shipped_entry in bash_entries:
        if not any(cp._rule_covers(req, shipped_entry) or cp._rule_covers(shipped_entry, req) for req in required_bash):
            unexplained.append(shipped_entry)
    assert not unexplained, (
        f"Bash entries in .claude/settings.json not covered by data/required-permissions.yaml: "
        f"{unexplained}. Either add them to the YAML or remove them from settings.json."
    )
