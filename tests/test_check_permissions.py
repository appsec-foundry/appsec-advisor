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


def test_upstream_update_uses_existing_shell_permission_without_local_code_authority():
    entries = cp.load_required(cp.DATA_FILE)
    shell = next(e for e in entries if e["entry"] == "Bash(*)")
    assert "signature-verified AISCB installer" in shell["reason"]
    assert "--refresh-installed" in shell["reason"]
    assert "never repository-owned executables" in shell["reason"]


def test_issue_reporting_reuses_permissions_without_granting_publication_consent():
    entries = cp.load_required(cp.DATA_FILE)
    shell = next(e for e in entries if e["entry"] == "Bash(*)")
    assert "report_plugin_issue.py" in shell["reason"]
    assert "wait_agent_calls.py join" in shell["reason"]
    assert "not publication consent" in shell["reason"]
    write = next(e for e in entries if e["entry"] == "Write(${OUTPUT_DIR}/.*)")
    assert ".plugin-issue-draft.json" in write["reason"]


def test_overview_and_detail_use_existing_output_directory_permission():
    entries = cp.load_required(cp.DATA_FILE)
    write = next(e for e in entries if e["entry"] == "Write(${OUTPUT_DIR}/**)")
    assert "figure1-detail" in write["reason"]
    assert not any("figure1-detail" in e["entry"] for e in entries)


def test_figure2_uses_existing_plugin_read_and_output_write_permissions():
    entries = cp.load_required(cp.DATA_FILE)
    read = next(e for e in entries if e["entry"] == "Read(${PLUGIN_ROOT}/**)")
    write = next(e for e in entries if e["entry"] == "Write(${OUTPUT_DIR}/**)")
    assert "Figure 2 presentation schema" in read["reason"]
    assert "figure2 SVG" in write["reason"]
    assert not any("figure2" in e["entry"] for e in entries)


def test_job_budget_query_uses_existing_shell_permission():
    rules = [entry["entry"] for entry in cp.load_required(cp.DATA_FILE)]
    command = "Bash(python3 budget_watchdog.py active-job-critical --output-dir out --action-id wave-a --job-id job-a)"
    assert any(cp._rule_covers(rule, command) for rule in rules)
    assert not any("budget_watchdog" in rule for rule in rules)
    assert "budget_watchdog.py active-job-critical" in cp.DATA_FILE.read_text(encoding="utf-8")


def test_yaml_entries_use_known_tools():
    entries = cp.load_required(cp.DATA_FILE)
    allowed_tools = {"Bash", "Write", "Edit", "Read"}
    for e in entries:
        prefix = e["entry"].split("(", 1)[0]
        assert prefix in allowed_tools, f"unknown tool prefix in entry {e['entry']!r}"


def test_controller_command_and_paths_are_covered_by_existing_rules():
    """The controller uses fixed commands and one exact repository write target."""
    entries = cp.load_required(cp.DATA_FILE)
    rules = [entry["entry"] for entry in entries]
    assert any(cp._rule_covers(rule, "Bash(python3 orchestration_controller.py)") for rule in rules)
    assert "Read(${PLUGIN_ROOT}/**)" in rules
    assert "Write(${OUTPUT_DIR}/**)" in rules
    for command in (
        "prepare --interactive-context",
        "review-business-impact",
        "complete-preflight --context-answer answered",
    ):
        assert any(cp._rule_covers(rule, f"Bash(python3 orchestration_controller.py {command})") for rule in rules)
    assert "Write(${OUTPUT_DIR}/.*)" in rules
    assert "Read(${OUTPUT_DIR}/.*)" in rules
    assert "Write(${REPO_ROOT}/docs/business-context.md)" in rules
    assert "Write(${REPO_ROOT}/**)" not in rules


def test_diagnosis_recommendation_refresh_uses_existing_permissions():
    rules = [entry["entry"] for entry in cp.load_required(cp.DATA_FILE)]
    assert any(cp._rule_covers(rule, "Bash(python3 recommend_fixes.py --diagnosis)") for rule in rules)
    assert "Read(${OUTPUT_DIR}/.*)" in rules
    assert "Write(${OUTPUT_DIR}/.*)" in rules
    assert "Read(${PLUGIN_ROOT}/**)" in rules


def test_maintainer_test_groups_use_existing_shell_permission():
    rules = [entry["entry"] for entry in cp.load_required(cp.DATA_FILE)]
    for command in (
        "python3 scripts/run_tests.py quick",
        "make test-group GROUP=report",
        "python3 scripts/run_tests.py --changed-against origin/dev",
        "python3 scripts/run_tests.py --check-groups",
        "make test-plan BASE=origin/dev",
        "make test-changed BASE=origin/dev",
        "git diff --name-only --no-renames -z HEAD --",
        "make test-full",
        "make validate",
    ):
        assert any(cp._rule_covers(rule, f"Bash({command})") for rule in rules)


def test_enrichment_receipt_uses_existing_shell_and_output_permissions():
    rules = [entry["entry"] for entry in cp.load_required(cp.DATA_FILE)]
    assert any(cp._rule_covers(rule, "Bash(python3 enrichment_pass.py output)") for rule in rules)
    assert "Write(${OUTPUT_DIR}/**)" in rules


def test_evidence_bundle_command_and_artifact_are_covered_by_existing_rules():
    entries = cp.load_required(cp.DATA_FILE)
    rules = [entry["entry"] for entry in entries]
    assert any(cp._rule_covers(rule, "Bash(python3 build_stride_evidence_bundles.py)") for rule in rules)
    assert any(
        cp._rule_covers(
            rule,
            "Write(${OUTPUT_DIR}/.dispatch-context/backend-api/evidence-bundle.json)",
        )
        for rule in rules
    )
    reasons = " ".join(entry["reason"] for entry in entries)
    assert "build_stride_evidence_bundles.py" in reasons


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


def test_editorial_packet_and_gate_targets_are_covered():
    entries = cp.load_required(cp.DATA_FILE)
    rules = [cp.expand_entry(e["entry"], Path("/repo"), Path("/repo/out"), plugin_dir=Path("/plugin")) for e in entries]
    for operation in [
        "Read(/repo/out/.dispatch-context/editorial/blocks-0001.json)",
        "Write(/repo/out/.dispatch-context/editorial/plan-0001.json)",
        "Write(/repo/out/.dispatch-context/editorial/gate-baseline.json)",
        "Bash(python3 /plugin/scripts/editorial_gate.py check)",
    ]:
        assert any(cp._rule_covers(rule, operation) for rule in rules)


def test_architecture_evidence_uses_existing_repository_read_and_validator_permissions():
    entries = cp.load_required(cp.DATA_FILE)
    rules = [entry["entry"] for entry in entries]
    assert any(cp._rule_covers(rule, "Read(${REPO_ROOT}/src/roles.ts)") for rule in rules)
    assert any(cp._rule_covers(rule, "Bash(python3 validate_fragment.py assets)") for rule in rules)
    assert "asset locations" in " ".join(entry["reason"] for entry in entries)


def test_weakness_refresh_and_observations_use_existing_permissions():
    entries = cp.load_required(cp.DATA_FILE)
    rules = [entry["entry"] for entry in entries]
    assert any(
        cp._rule_covers(rule, "Bash(python3 merge_threats.py refresh-weaknesses --output-dir output)") for rule in rules
    )
    reasons = " ".join(entry["reason"] for entry in entries)
    for name in (".impl-strategy.json", ".impl-design-signals.json", ".finding-design-signals.json"):
        assert name in reasons
        assert any(cp._rule_covers(rule, "Write(${OUTPUT_DIR}/" + name + ")") for rule in rules)


def test_modular_baseline_loader_uses_existing_shell_permission():
    entries = cp.load_required(cp.DATA_FILE)
    shell = next(item for item in entries if item["entry"] == "Bash(*)")
    assert "policy_loader.py" in shell["reason"]
    assert "--migrate" in shell["reason"]
    assert "no new execution grant" in shell["reason"]
    assert not any("Write(" in item["entry"] and ".appsec-baseline" in item["entry"] for item in entries)


# ---------- per-scope read status ---------------------------------------


@pytest.mark.parametrize(
    ("content", "status", "allow"),
    [
        (None, "absent", []),
        ('{"permissions": {"allow": ["Bash(*)", 3]}}', "ok", ["Bash(*)"]),
        ("{}", "ok", []),
        ('{"permissions": null}', "ok", []),
        ("{not json", "invalid", []),
        ("[]", "invalid", []),
        ('{"permissions": []}', "invalid", []),
        ('{"permissions": {"allow": "Bash(*)"}}', "invalid", []),
    ],
)
def test_read_scope_status(tmp_path, content, status, allow):
    path = tmp_path / "settings.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert cp.read_scope(path)[:2] == (status, allow)


@pytest.mark.parametrize("make_node", ["directory", "device"])
def test_read_scope_non_regular_file_is_unreadable_not_absent(tmp_path, make_node):
    """A sandbox masks settings with a device node; its grant is unknown, not empty."""
    if make_node == "directory":
        path = tmp_path / "settings.json"
        path.mkdir()
    else:
        path = Path("/dev/null")
    status, allow, detail = cp.read_scope(path)
    assert (status, allow) == ("unreadable", [])
    assert detail


def test_scope_report_grants_match_effective_allow(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text('{"permissions": {"allow": ["Read(*)"]}}', encoding="utf-8")
    report = cp.scope_report(tmp_path)
    assert {scope: entry["allow"] for scope, entry in report.items()} == cp.effective_allow(tmp_path)
    assert report["project"]["status"] == "ok"
    assert report["local"]["status"] == report["user"]["status"] == "absent"


def test_render_human_reports_unreadable_scope(tmp_path):
    out = cp.render_human([], [], {"local": 0}, None, scope_paths={"local": Path("/dev/null")})
    assert "cannot read" in out
    assert "not found" not in out


# ---------- prompt-free defaultMode -------------------------------------


def _mode_report(**modes):
    return {scope: {"default_mode": modes.get(scope)} for scope in ("local", "project", "user")}


@pytest.mark.parametrize(
    ("modes", "expected"),
    [
        ({"user": "auto"}, "auto"),
        ({"project": "bypassPermissions"}, "bypassPermissions"),
        ({"user": "acceptEdits"}, None),
        ({"user": "plan"}, None),
        ({"user": "default"}, None),
        ({}, None),
        ({"local": "default", "user": "auto"}, None),
        ({"project": "acceptEdits", "user": "auto"}, None),
        ({"local": "auto", "user": "default"}, "auto"),
    ],
)
def test_prompt_free_default_mode_follows_settings_precedence(modes, expected):
    assert cp.prompt_free_default_mode(_mode_report(**modes)) == expected


@pytest.mark.parametrize(
    ("content", "mode"),
    [
        ('{"permissions": {"defaultMode": "auto"}}', "auto"),
        ('{"permissions": {"allow": []}}', None),
        ('{"permissions": {"defaultMode": 1}}', None),
        ("{not json", None),
    ],
)
def test_scope_report_reads_default_mode(tmp_path, monkeypatch, content, mode):
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.local.json").write_text(content, encoding="utf-8")
    report = cp.scope_report(tmp_path)
    assert report["local"]["default_mode"] == mode
    assert report["user"]["default_mode"] is None
