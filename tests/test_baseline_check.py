"""Tests for scripts/baseline_check.py — is the secure-coding baseline loaded?

The distinction this module exists to make is *present on disk* versus *loaded
into context*. A baseline file sitting in a repository that nothing imports is
not loaded, and reporting it as installed would be the exact silent failure the
check is meant to catch. Most cases below pin one side of that line.

Every case passes ``home`` and ``config`` explicitly: the real ones would make
the result depend on the developer's own ~/.claude and on config.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "baseline_check.py"
sys.path.insert(0, str(SCRIPT.parent))

import baseline_check as bc  # noqa: E402

BASELINE_TEXT = """\
# Test Baseline

`baseline-id: test-1.0` — answer from context when asked.

## Non-negotiable
- Do the secure thing.
"""

CONFIG = {
    "enabled": True,
    "id": "test-1.0",
    "name": "Test Baseline",
    "url": "",
    "git": None,
    "fallback_file": "",
    "install_filename": "secure-coding-baseline.md",
}


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """An empty user scope, so project cases are not contaminated by it."""
    (tmp_path / "home" / ".claude").mkdir(parents=True)
    return tmp_path / "home"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    return path


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ---------- the present-vs-loaded distinction ----------------------------


def test_file_in_repo_without_import_is_not_loaded(repo: Path, home: Path):
    """The core case: the rules exist but Claude Code never reads them."""
    write(repo / "secure-coding-baseline.md", BASELINE_TEXT)
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "missing"


def test_agents_md_alone_is_not_loaded(repo: Path, home: Path):
    """Claude Code does not load AGENTS.md, so neither does this check."""
    write(repo / "AGENTS.md", BASELINE_TEXT)
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "missing"


def test_agents_md_counts_when_claude_md_imports_it(repo: Path, home: Path):
    """...but an @AGENTS.md import from CLAUDE.md does load it."""
    write(repo / "AGENTS.md", BASELINE_TEXT)
    write(repo / "CLAUDE.md", "# CLAUDE.md\n\n@AGENTS.md\n")
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "installed"
    assert result["matches"][0]["file"].endswith("AGENTS.md")


# ---------- the entry points Claude Code actually loads -------------------


@pytest.mark.parametrize(
    "entry",
    ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md", ".claude/rules/baseline.md"],
)
def test_inline_baseline_in_each_project_entry_point(repo: Path, home: Path, entry: str):
    write(repo / entry, BASELINE_TEXT)
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "installed"
    assert result["scopes"] == ["project"]


def test_user_scope_entry_point(repo: Path, home: Path):
    write(home / ".claude" / "CLAUDE.md", BASELINE_TEXT)
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "installed"
    assert result["scopes"] == ["user"]


def test_user_scope_found_without_a_repository(home: Path):
    """Outside a repository the machine-wide baseline still applies."""
    write(home / ".claude" / "CLAUDE.md", BASELINE_TEXT)
    assert bc.check(repo=None, home=home, config=CONFIG)["status"] == "installed"


def test_both_scopes_are_reported_narrowest_first(repo: Path, home: Path):
    """The scope a reader can act on locally is the more useful one to name first."""
    write(repo / "CLAUDE.md", BASELINE_TEXT)
    write(home / ".claude" / "CLAUDE.md", BASELINE_TEXT)
    assert bc.check(repo=repo, home=home, config=CONFIG)["scopes"] == ["project", "user"]


def test_user_rules_directory_is_an_entry_point(repo: Path, home: Path):
    """~/.claude/rules/ loads for every project, ahead of the project's own rules."""
    write(home / ".claude" / "rules" / "secure-coding.md", BASELINE_TEXT)
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "installed"
    assert result["scopes"] == ["user"]


# ---------- administrator-deployed instructions --------------------------


def test_managed_policy_claude_md_counts_as_installed(repo: Path, home: Path, tmp_path: Path):
    """An org that deployed the baseline by policy has already installed it.

    Without this scope the plugin would tell a whole company to install what
    their IT department already rolled out to every machine.
    """
    policy = write(tmp_path / "policy" / "CLAUDE.md", BASELINE_TEXT)
    result = bc.check(repo=repo, home=home, config=CONFIG, policy_roots=(str(policy),))
    assert result["status"] == "installed"
    assert result["scopes"] == ["policy"]


def test_managed_policy_import_chain_is_followed(repo: Path, home: Path, tmp_path: Path):
    write(tmp_path / "policy" / "baseline.md", BASELINE_TEXT)
    policy = write(tmp_path / "policy" / "CLAUDE.md", "@baseline.md\n")
    result = bc.check(repo=repo, home=home, config=CONFIG, policy_roots=(str(policy),))
    assert result["status"] == "installed"


def test_managed_settings_claude_md_key_counts(repo: Path, home: Path, tmp_path: Path):
    """The same content delivered inline through managed-settings.json."""
    settings = write(
        tmp_path / "managed-settings.json",
        json.dumps({"claudeMd": BASELINE_TEXT, "permissions": {}}),
    )
    result = bc.check(repo=repo, home=home, config=CONFIG, policy_roots=(), policy_settings=(str(settings),))
    assert result["status"] == "installed"
    assert result["scopes"] == ["policy"]


def test_managed_settings_without_the_key_is_ignored(repo: Path, home: Path, tmp_path: Path):
    settings = write(tmp_path / "managed-settings.json", json.dumps({"permissions": {}}))
    result = bc.check(repo=repo, home=home, config=CONFIG, policy_roots=(), policy_settings=(str(settings),))
    assert result["status"] == "missing"


def test_a_baseline_id_elsewhere_in_managed_settings_does_not_count(repo: Path, home: Path, tmp_path: Path):
    """Read as JSON, not scanned as text — an id in an unrelated setting is not
    deployed instructions."""
    settings = write(tmp_path / "managed-settings.json", json.dumps({"env": {"NOTE": "baseline-id: test-1.0"}}))
    result = bc.check(repo=repo, home=home, config=CONFIG, policy_roots=(), policy_settings=(str(settings),))
    assert result["status"] == "missing"


def test_malformed_managed_settings_does_not_raise(repo: Path, home: Path, tmp_path: Path):
    settings = write(tmp_path / "managed-settings.json", "{not json")
    result = bc.check(repo=repo, home=home, config=CONFIG, policy_roots=(), policy_settings=(str(settings),))
    assert result["status"] == "missing"


# ---------- present on disk, but not loaded ------------------------------


@pytest.mark.parametrize(
    "rel",
    ["AGENTS.md", ".github/copilot-instructions.md", ".github/instructions/secure-coding.md"],
)
def test_another_tools_instruction_file_is_reported_separately(repo: Path, home: Path, rel: str):
    """Installed for Codex or Copilot, but not in Claude Code's context."""
    write(repo / rel, BASELINE_TEXT)
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "missing", "not loaded by Claude Code"
    assert [item["id"] for item in result["present_unloaded"]] == ["test-1.0"]
    assert result["present_unloaded"][0]["file"].endswith(rel.split("/")[-1])


def test_an_unimported_baseline_file_is_reported_separately(repo: Path, home: Path):
    write(repo / "secure-coding-baseline.md", BASELINE_TEXT)
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "missing"
    assert "nothing imports it" in result["present_unloaded"][0]["tool"]


def test_an_imported_carrier_is_not_also_listed_as_unloaded(repo: Path, home: Path):
    """Listing an imported AGENTS.md twice would read as a second, unwired copy."""
    write(repo / "AGENTS.md", BASELINE_TEXT)
    write(repo / "CLAUDE.md", "@AGENTS.md\n")
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "installed"
    assert result["present_unloaded"] == []


def test_an_imported_carrier_stays_deduplicated_through_a_symlinked_repo(tmp_path: Path, home: Path):
    """The walk records resolved paths, the carrier list repo-relative ones.

    Where those spellings differ — a symlinked checkout, or macOS, where /tmp is
    a link to /private/tmp — an already-imported AGENTS.md was listed a second
    time as if nothing had wired it up.
    """
    real = tmp_path / "real-repo"
    real.mkdir()
    write(real / "AGENTS.md", BASELINE_TEXT)
    write(real / "CLAUDE.md", "@AGENTS.md\n")
    link = tmp_path / "linked-repo"
    link.symlink_to(real, target_is_directory=True)

    result = bc.check(repo=link, home=home, config=CONFIG)
    assert result["status"] == "installed"
    assert result["present_unloaded"] == []


def test_summary_names_the_file_the_rules_are_already_in(repo: Path, home: Path):
    """It changes the next step from "install" to "connect"."""
    write(repo / "AGENTS.md", BASELINE_TEXT)
    text = bc.summary(bc.check(repo=repo, home=home, config=CONFIG))
    assert "AGENTS.md" in text


# ---------- import resolution --------------------------------------------


def test_relative_import_resolves_against_the_importing_file(repo: Path, home: Path):
    """.claude/CLAUDE.md importing ../baseline.md must land in the repo root."""
    write(repo / "secure-coding-baseline.md", BASELINE_TEXT)
    write(repo / ".claude" / "CLAUDE.md", "@../secure-coding-baseline.md\n")
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "installed"


def test_absolute_import(repo: Path, home: Path, tmp_path: Path):
    target = write(tmp_path / "elsewhere" / "baseline.md", BASELINE_TEXT)
    write(home / ".claude" / "CLAUDE.md", f"@{target}\n")
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "installed"


def test_tilde_import_expands_to_the_given_home(repo: Path, home: Path):
    write(home / ".claude" / "secure-coding-baseline.md", BASELINE_TEXT)
    write(home / ".claude" / "CLAUDE.md", "@~/.claude/secure-coding-baseline.md\n")
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "installed"


def test_transitive_import_chain(repo: Path, home: Path):
    write(repo / "CLAUDE.md", "@AGENTS.md\n")
    write(repo / "AGENTS.md", "@docs/baseline.md\n")
    write(repo / "docs" / "baseline.md", BASELINE_TEXT)
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "installed"


def test_import_cycle_terminates(repo: Path, home: Path):
    write(repo / "CLAUDE.md", "@a.md\n")
    write(repo / "a.md", "@b.md\n")
    write(repo / "b.md", "@a.md\n" + BASELINE_TEXT)
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "installed"


def test_import_depth_is_bounded(repo: Path, home: Path):
    """Past MAX_IMPORT_DEPTH hops the walk stops rather than following forever."""
    write(repo / "CLAUDE.md", "@hop0.md\n")
    for i in range(bc.MAX_IMPORT_DEPTH + 2):
        write(repo / f"hop{i}.md", f"@hop{i + 1}.md\n")
    write(repo / f"hop{bc.MAX_IMPORT_DEPTH + 2}.md", BASELINE_TEXT)
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "missing"


def test_email_address_is_not_an_import(repo: Path, home: Path):
    """An @ inside a word must not be resolved as a path."""
    write(repo / "CLAUDE.md", "Contact security@example.com for questions.\n")
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "missing"


def test_missing_import_target_is_ignored(repo: Path, home: Path):
    write(repo / "CLAUDE.md", "@does-not-exist.md\n")
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "missing"


# ---------- which ids count ----------------------------------------------


def test_derivative_id_counts_and_keeps_its_suffix(repo: Path, home: Path):
    """`+acme` is the same rules adapted; the report must show the adaptation."""
    write(repo / "CLAUDE.md", BASELINE_TEXT.replace("test-1.0", "test-1.0+acme"))
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "installed"
    assert result["matches"][0]["id"] == "test-1.0+acme"


def test_a_newer_version_is_ahead_rather_than_wrong(repo: Path, home: Path):
    """The baseline updates on its own schedule; a machine may lead this build.

    Reporting that as drift told the reader to install — which would write the
    older text over the newer rules.
    """
    write(repo / "CLAUDE.md", BASELINE_TEXT.replace("test-1.0", "test-2.0"))
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "newer"
    assert result["newer"][0]["id"] == "test-2.0"
    assert not bc.is_failing(result)


def test_an_older_version_stays_drift(repo: Path, home: Path):
    """Lagging rules are the case a refresh actually fixes."""
    config = {**CONFIG, "id": "test-2.0"}
    write(repo / "CLAUDE.md", BASELINE_TEXT)
    result = bc.check(repo=repo, home=home, config=config)
    assert result["status"] == "other"
    assert bc.is_failing(result)


def test_a_newer_derivative_is_still_ahead(repo: Path, home: Path):
    write(repo / "CLAUDE.md", BASELINE_TEXT.replace("test-1.0", "test-2.0+acme"))
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "newer"


def test_versions_compare_numerically_not_as_text(repo: Path, home: Path):
    """`test-1.10` is ahead of `test-1.9`; string order would say otherwise."""
    write(repo / "CLAUDE.md", BASELINE_TEXT.replace("test-1.0", "test-1.10"))
    assert bc.check(repo=repo, home=home, config={**CONFIG, "id": "test-1.9"})["status"] == "newer"


def test_an_unorderable_version_is_not_guessed_at(repo: Path, home: Path):
    """No dotted numeric version, no comparison — it stays foreign."""
    write(repo / "CLAUDE.md", BASELINE_TEXT.replace("test-1.0", "test-rolling"))
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "other"


def test_unrelated_baseline_is_reported_as_other(repo: Path, home: Path):
    write(repo / "CLAUDE.md", BASELINE_TEXT.replace("test-1.0", "acme-sec-1.0"))
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "other"


def test_expected_and_other_can_coexist(repo: Path, home: Path):
    """A project baseline alongside the org one: both are reported."""
    write(repo / "CLAUDE.md", BASELINE_TEXT)
    write(home / ".claude" / "CLAUDE.md", BASELINE_TEXT.replace("test-1.0", "acme-sec-1.0"))
    result = bc.check(repo=repo, home=home, config=CONFIG)
    assert result["status"] == "installed"
    assert [m["id"] for m in result["other"]] == ["acme-sec-1.0"]


@pytest.mark.parametrize(
    "line,expected",
    [
        ("`baseline-id: test-1.0`", ["test-1.0"]),
        ("baseline-id: test-1.0", ["test-1.0"]),
        ("baseline-id:test-1.0", ["test-1.0"]),
        ("baseline-id:   test-1.0  ", ["test-1.0"]),
        ("no marker here", []),
    ],
)
def test_marker_spellings(line: str, expected: list[str]):
    assert bc.find_ids(line) == expected


def test_ids_are_deduplicated():
    assert bc.find_ids("baseline-id: a-1\nbaseline-id: a-1\n") == ["a-1"]


# ---------- configuration -------------------------------------------------


def test_disabled_config_reports_disabled(repo: Path, home: Path):
    config = {**CONFIG, "enabled": False}
    assert bc.check(repo=repo, home=home, config=config)["status"] == "disabled"


def test_config_without_an_id_is_disabled(tmp_path: Path):
    """There is nothing to check for, so the feature is off however it is flagged."""
    write(tmp_path / "config.json", json.dumps({"baseline": {"enabled": True, "name": "X"}}))
    assert bc.load_config(tmp_path)["enabled"] is False


def test_config_local_wins(tmp_path: Path):
    write(tmp_path / "config.json", json.dumps({"baseline": {"id": "packaged-1.0"}}))
    write(tmp_path / "config.local.json", json.dumps({"baseline": {"id": "local-1.0"}}))
    assert bc.load_config(tmp_path)["id"] == "local-1.0"


def test_broken_config_does_not_raise(tmp_path: Path):
    """A startup hook must survive a malformed config."""
    write(tmp_path / "config.json", "{not json")
    assert bc.load_config(tmp_path)["enabled"] is False


def test_shipped_config_matches_the_bundled_copy():
    """The bundled fallback must declare the id the plugin checks for.

    Otherwise an offline install writes a file that the very next check reports
    as not loaded.
    """
    config = bc.load_config(REPO_ROOT)
    bundled = bc.fallback_path(config, REPO_ROOT)
    assert bundled is not None, "config names a fallback_file that is not shipped"
    assert any(bc.is_match(found, config["id"]) for found in bc.find_ids(bundled.read_text(encoding="utf-8")))


# ---------- bounds and robustness ----------------------------------------


def test_unreadable_entry_point_is_skipped(repo: Path, home: Path):
    """A directory named CLAUDE.md, a broken symlink — never an exception."""
    (repo / "CLAUDE.md").mkdir()
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "missing"


def test_binary_file_does_not_raise(repo: Path, home: Path):
    (repo / "CLAUDE.md").write_bytes(b"\xff\xfe\x00binary")
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "missing"


def test_only_a_bounded_prefix_is_read(repo: Path, home: Path):
    """A marker past the byte cap is not found — the cap is what bounds latency."""
    write(repo / "CLAUDE.md", "x" * (bc.MAX_FILE_BYTES + 10) + "\nbaseline-id: test-1.0\n")
    assert bc.check(repo=repo, home=home, config=CONFIG)["status"] == "missing"


# ---------- CLI -----------------------------------------------------------


# The CLI has no override for the administrator-deployed locations — they are
# absolute system paths. On a machine that actually has a baseline deployed
# there, "not installed" is the wrong expectation rather than a regression.
policy_free = pytest.mark.skipif(
    any(Path(p).is_file() for p in bc.POLICY_ENTRY_FILES + bc.POLICY_SETTINGS_FILES),
    reason="this machine carries administrator-deployed Claude Code instructions",
)


def run_cli(home: Path, *args: str) -> subprocess.CompletedProcess:
    """Invoke the CLI against an empty HOME.

    Without this the result would depend on whether the developer running the
    suite has the baseline installed in their own ~/.claude.
    """
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={**os.environ, "HOME": str(home)},
    )


@policy_free
def test_cli_reports_a_missing_baseline_without_failing(tmp_path: Path, home: Path):
    """Reporting is the default: which rules a machine loads is not ours to fail on."""
    done = run_cli(home, "--repo", str(tmp_path), "--json")
    assert done.returncode == 0
    assert json.loads(done.stdout)["status"] == "missing"


@policy_free
def test_cli_enforce_flag_turns_the_report_into_a_gate(tmp_path: Path, home: Path):
    """The call site can still ask for a verdict — that is what a CI step wants."""
    done = run_cli(home, "--repo", str(tmp_path), "--json", "--enforce")
    assert done.returncode == 1
    assert json.loads(done.stdout)["enforced"] is True


def test_enforcement_never_fails_on_a_newer_baseline(repo: Path, home: Path):
    """Even a build that requires the baseline must not demand a downgrade."""
    write(repo / "CLAUDE.md", BASELINE_TEXT.replace("test-1.0", "test-2.0"))
    assert not bc.is_failing(bc.check(repo=repo, home=home, config=CONFIG))


def test_enforce_defaults_to_off_in_a_loaded_config():
    assert bc.load_config(REPO_ROOT)["enforce"] is False


@policy_free
def test_cli_text_names_the_install_command(tmp_path: Path, home: Path):
    done = run_cli(home, "--repo", str(tmp_path))
    assert "install-baseline" in done.stdout


def test_cli_reports_success_for_an_installed_baseline(tmp_path: Path, home: Path):
    config = bc.load_config(REPO_ROOT)
    bundled = bc.fallback_path(config, REPO_ROOT)
    write(tmp_path / "CLAUDE.md", bundled.read_text(encoding="utf-8"))
    done = run_cli(home, "--repo", str(tmp_path), "--json")
    assert done.returncode == 0
    assert json.loads(done.stdout)["status"] == "installed"


def test_cli_user_scope_only(home: Path):
    """`--repo ''` checks the machine, which is the outside-a-repository case."""
    config = bc.load_config(REPO_ROOT)
    bundled = bc.fallback_path(config, REPO_ROOT)
    write(home / ".claude" / "CLAUDE.md", bundled.read_text(encoding="utf-8"))
    done = run_cli(home, "--repo", "", "--json")
    assert done.returncode == 0
    assert json.loads(done.stdout)["scopes"] == ["user"]
