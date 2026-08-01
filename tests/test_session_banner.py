"""
Tests for scripts/session_banner.py

The script is a SessionStart hook: it reads JSON from stdin and writes a
``systemMessage`` payload to stdout. The end-to-end cases run it as a
subprocess to match its real execution context; the branch cases call
``build_banner`` directly.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "session_banner.py"
sys.path.insert(0, str(SCRIPT.parent))

import session_banner  # noqa: E402

MODEL_YAML = """\
meta:
  schema_version: 1
  project: acme-api
  generated: '{generated}'
  mode: full
  analysis_version: {analysis_version}
  assessment_depth: standard
  scope: []
  team_owner: null
components:
- id: C-01
  name: gateway
threats:
- local_id: T-001
  title: first
  evidence:
    - path: a.py
- local_id: T-002
  title: second
mitigations:
- id: M-001
"""


MANIFEST = json.loads((SCRIPT.parent.parent / ".claude-plugin" / "plugin.json").read_text())
CONFIG = json.loads((SCRIPT.parent.parent / "config.json").read_text(encoding="utf-8"))
# The banner heads the baseline line with the configured name, so the tests read
# it from the same place the hook does rather than pinning this build's wording.
BASELINE_NAME = CONFIG["baseline"]["name"]


@pytest.fixture(autouse=True)
def _tmp_path_is_a_repository(tmp_path, monkeypatch):
    """Make every tmp_path look like a working tree, with an empty user scope.

    The banner only reports on a repository, and `_in_repository` walks up to
    the filesystem root — so on a machine that happens to have `/tmp/.git`, a
    bare tmp_path would pass for one and hide a regression. Creating the marker
    explicitly makes the precondition part of the test instead of the host.

    ``HOME`` is redirected for the same reason: the baseline line reads
    ``~/.claude/CLAUDE.md``, so a developer who has the baseline installed on
    their own machine would otherwise get a different banner than CI.
    """
    (tmp_path / ".git").mkdir(exist_ok=True)
    home = tmp_path / "_home"
    (home / ".claude").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    return tmp_path


def baseline_text() -> str:
    """The plugin's own bundled baseline, carrying the configured id."""
    plugin_root = SCRIPT.parent.parent
    config = json.loads((plugin_root / "config.json").read_text(encoding="utf-8"))["baseline"]
    return (plugin_root / config["fallback_file"]).read_text(encoding="utf-8")


def install_baseline_for(repo: Path) -> None:
    """Put the plugin's own baseline where the project scope loads it from."""
    (repo / "CLAUDE.md").write_text(baseline_text(), encoding="utf-8")


def install_baseline_for_user(repo: Path) -> None:
    """Put the plugin's own baseline in the machine-wide scope of the test HOME."""
    (repo / "_home" / ".claude" / "CLAUDE.md").write_text(baseline_text(), encoding="utf-8")


def write_model(
    repo: Path,
    generated: str = "2026-07-27T10:01:22Z",
    analysis_version: int | None = None,
) -> Path:
    out = repo / "docs" / "security"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "threat-model.yaml"
    if analysis_version is None:
        analysis_version = MANIFEST["compatible_analysis_versions"][-1]
    path.write_text(
        MODEL_YAML.format(generated=generated, analysis_version=analysis_version),
        encoding="utf-8",
    )
    return path


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def init_repo(repo: Path) -> None:
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "user.name", "Test")


def commit(repo: Path, name: str, date: str) -> None:
    (repo / name).write_text(name, encoding="utf-8")
    git(repo, "add", name)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-q", "-m", name],
        check=True,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": str(repo),
            "GIT_AUTHOR_DATE": date,
            "GIT_COMMITTER_DATE": date,
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
        },
    )


def run_hook(cwd: str) -> str:
    """Run the hook as a subprocess; return the systemMessage (empty when silent)."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps({"cwd": cwd}),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Script exited {result.returncode}: {result.stderr}"
    if not result.stdout.strip():
        return ""
    return json.loads(result.stdout)["systemMessage"]


def tm_line(message: str) -> str:
    """Return the threat-model domain line."""
    for line in message.splitlines():
        if line.startswith("threat model"):
            return line
    raise AssertionError(f"no threat model line in:\n{message}")


def baseline_line(message: str) -> str | None:
    for line in message.splitlines():
        if line.startswith(BASELINE_NAME):
            return line
    return None


def identity_line(message: str) -> str:
    return message.splitlines()[0]


# ---------------------------------------------------------------------------
# End-to-end: stdout contract
# ---------------------------------------------------------------------------


def test_reports_missing_model(tmp_path):
    message = run_hook(str(tmp_path))
    assert identity_line(message).startswith(f"appsec-advisor {MANIFEST['version']}")
    assert "/appsec-advisor:help" in identity_line(message)
    assert tm_line(message) == (
        "threat model · none in docs/security/ · /appsec-advisor:create-threat-model"
    )


def test_reports_existing_model(tmp_path):
    write_model(tmp_path)
    message = run_hook(str(tmp_path))
    line = tm_line(message)
    assert "acme-api" in line
    assert "2 total" in line
    assert "27 Jul 2026" in line
    # Default fixture has no Critical/High → calm → no review command.
    assert "/appsec-advisor:review-threat-model" not in line


def test_assessment_depth_is_left_out(tmp_path):
    """How the report was produced is a detail of the report, not of the state."""
    write_model(tmp_path)
    assert "standard" not in run_hook(str(tmp_path))


def test_identity_is_on_the_first_line_with_help(tmp_path):
    """Identity pays the SessionStart prefix tax; domain lines keep full width."""
    lines = run_hook(str(tmp_path)).splitlines()
    assert lines[0] == f"appsec-advisor {MANIFEST['version']} · /appsec-advisor:help"
    assert lines[1].startswith("threat model")


def test_layout_is_identity_then_threat_model_then_baseline(tmp_path):
    write_model(tmp_path)
    lines = run_hook(str(tmp_path)).splitlines()
    assert lines[0].startswith("appsec-advisor")
    assert lines[1].startswith("threat model")
    assert lines[2].startswith(BASELINE_NAME)


def test_banner_carries_no_status_glyphs(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Critical", "High"])
    banner = run_hook(str(tmp_path))
    for glyph in ("🟢", "🟠", "🔴", "⚪", "🔵"):
        assert glyph not in banner


# ---------------------------------------------------------------------------
# Outside a repository
# ---------------------------------------------------------------------------


def test_outside_a_repository_only_the_plugin_and_help_are_announced(tmp_path, monkeypatch):
    """A directory nobody meant to scan gets no complaint about a missing model."""
    monkeypatch.setattr(session_banner, "_in_repository", lambda _path: False)
    # Silence baseline so this case is identity-only when baseline is healthy/disabled.
    monkeypatch.setattr(session_banner, "_baseline_line", lambda _repo: "")
    lines = session_banner.build_banner(str(tmp_path)).splitlines()
    assert "threat model" not in " ".join(lines)
    assert lines == [f"appsec-advisor {MANIFEST['version']} · /appsec-advisor:help"]


def test_outside_a_repository_the_baseline_is_still_reported(tmp_path, monkeypatch):
    """The machine-wide baseline applies here, and this is where it gets installed.

    Unlike the threat model, it is not a claim about the current directory — so
    reporting it outside a repository is information, not a complaint.
    """
    monkeypatch.setattr(session_banner, "_in_repository", lambda _path: False)
    lines = session_banner.build_banner(str(tmp_path)).splitlines()
    assert lines[0].startswith("appsec-advisor")
    assert lines[1].startswith(BASELINE_NAME)
    assert "not installed" in lines[1]


def test_outside_a_repository_a_project_baseline_still_counts(tmp_path, monkeypatch):
    """A CLAUDE.md is loaded by Claude Code whether or not git was ever run here.

    Reporting "not installed" over rules that are in context is the worst of the
    two errors: it sends the reader to install a second, older copy beside them.
    """
    monkeypatch.setattr(session_banner, "_in_repository", lambda _path: False)
    install_baseline_for(tmp_path)
    lines = session_banner.build_banner(str(tmp_path)).splitlines()
    assert lines[1].startswith(BASELINE_NAME)
    assert CONFIG["baseline"]["id"] in lines[1]
    assert "not installed" not in lines[1]


def test_a_model_outside_a_repository_is_still_reported(tmp_path, monkeypatch):
    """An --output directory need not be a working tree; the model still counts."""
    monkeypatch.setattr(session_banner, "_in_repository", lambda _path: False)
    write_model(tmp_path)
    lines = session_banner.build_banner(str(tmp_path)).splitlines()
    assert any(line.startswith("threat model") for line in lines)


def test_repository_is_detected_from_a_parent(tmp_path):
    nested = tmp_path / "src" / "api"
    nested.mkdir(parents=True)
    assert session_banner._in_repository(nested) is True


def test_worktree_marker_file_counts_as_a_repository(tmp_path):
    worktree = tmp_path / "wt"
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: /elsewhere/.git/worktrees/wt\n", encoding="utf-8")
    assert session_banner._in_repository(worktree) is True


def test_filesystem_root_is_not_a_repository(tmp_path):
    assert session_banner._in_repository(Path(tmp_path.anchor)) is False


# ---------------------------------------------------------------------------
# Finding severity and timestamp
# ---------------------------------------------------------------------------


def write_severities(repo: Path, field: str, values: list[str]) -> None:
    out = repo / "docs" / "security"
    out.mkdir(parents=True, exist_ok=True)
    threats = "".join(f"- local_id: T-{i:03d}\n  {field}: {value}\n" for i, value in enumerate(values, 1))
    (out / "threat-model.yaml").write_text(
        f"meta:\n  project: acme-api\n  generated: '2026-07-27T10:01:22Z'\nthreats:\n{threats}",
        encoding="utf-8",
    )


def plain(text: str) -> str:
    """Drop SGR escapes so content assertions stay independent of colour."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def test_critical_and_high_are_counted_severity_first(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Critical", "Critical", "High", "Medium"])
    line = plain(tm_line(run_hook(str(tmp_path))))
    assert line.startswith("threat model · acme-api · 2 CRITICAL · 1 high · 4 total")
    assert "/appsec-advisor:review-threat-model" in line


def test_effective_severity_wins_over_risk(tmp_path):
    """effective_severity carries triage caps and boosts; risk is pre-adjustment."""
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text(
        "meta:\n  project: acme-api\nthreats:\n- local_id: T-001\n  risk: Critical\n  effective_severity: Medium\n",
        encoding="utf-8",
    )
    assert "CRITICAL" not in tm_line(session_banner.build_banner(str(tmp_path)))


def test_risk_is_used_when_effective_severity_is_absent(tmp_path):
    write_severities(tmp_path, "risk", ["Critical", "High"])
    line = tm_line(run_hook(str(tmp_path)))
    assert "1 CRITICAL" in line and "1 high" in line


def test_clean_model_shows_no_severity_marks(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Medium", "Low"])
    line = tm_line(run_hook(str(tmp_path)))
    assert "2 total" in line
    assert "CRITICAL" not in line and " high" not in line
    assert "/appsec-advisor:review-threat-model" not in line


def test_state_line_names_what_the_numbers_are(tmp_path):
    write_model(tmp_path)
    assert tm_line(run_hook(str(tmp_path))).startswith("threat model")


def test_project_name_is_shown_only_when_it_is_not_this_repository(tmp_path):
    """A model produced with --repo describes something else; that is worth columns."""
    repo = tmp_path / "web-shop"
    repo.mkdir()
    write_model(repo)  # fixture project is "acme-api"
    assert "threat model · acme-api ·" in tm_line(session_banner.build_banner(str(repo)))

    same = tmp_path / "acme-api"
    same.mkdir()
    write_model(same)
    line = tm_line(session_banner.build_banner(str(same)))
    assert line.startswith("threat model · 2 total")
    assert "acme-api" not in line


def test_zero_findings_uses_no_findings_wording(tmp_path):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text(
        "meta:\n  project: acme-api\n  generated: '2026-07-27T10:01:22Z'\nthreats: []\n",
        encoding="utf-8",
    )
    assert "no findings" in tm_line(run_hook(str(tmp_path)))


def test_timestamp_is_date_only(tmp_path):
    write_model(tmp_path)
    message = run_hook(str(tmp_path))
    assert "27 Jul 2026" in message
    assert "10:01" not in message
    assert "UTC" not in message


# ---------------------------------------------------------------------------
# No colour escapes anywhere
# ---------------------------------------------------------------------------


def test_banner_carries_no_ansi_escapes(tmp_path):
    """Emphasis is uppercase, not colour: it must survive any client and theme."""
    write_severities(tmp_path, "effective_severity", ["Critical", "High"])
    banner = run_hook(str(tmp_path))
    assert "\033" not in banner
    assert "1 CRITICAL" in banner


# ---------------------------------------------------------------------------
# Commands follow pressure / stale / calm rules
# ---------------------------------------------------------------------------


def test_critical_findings_offer_review(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Critical"])
    assert "/appsec-advisor:review-threat-model" in tm_line(run_hook(str(tmp_path)))


def test_high_findings_offer_review(tmp_path):
    write_severities(tmp_path, "effective_severity", ["High"])
    assert "/appsec-advisor:review-threat-model" in tm_line(run_hook(str(tmp_path)))


def test_calm_current_model_offers_no_threat_model_command(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Medium", "Low"])
    line = tm_line(run_hook(str(tmp_path)))
    assert "/appsec-advisor:" not in line


def test_stale_model_offers_update_not_review(tmp_path):
    init_repo(tmp_path)
    write_severities(tmp_path, "effective_severity", ["Critical"])
    # Overwrite generated to an old stamp so commits count as drift.
    model = tmp_path / "docs" / "security" / "threat-model.yaml"
    text = model.read_text(encoding="utf-8")
    model.write_text(text.replace("2026-07-27T10:01:22Z", "2026-01-01T00:00:00Z"), encoding="utf-8")
    for i in range(session_banner.STALE_COMMITS):
        commit(tmp_path, f"file{i}.txt", "2026-02-01T12:00:00+00:00")
    line = tm_line(session_banner.build_banner(str(tmp_path)))
    assert "/appsec-advisor:update-threat-model" in line
    assert "review-threat-model" not in line


def test_incompatible_model_demands_rebuild(tmp_path):
    write_model(tmp_path, analysis_version=max(MANIFEST["compatible_analysis_versions"]) + 1)
    line = tm_line(session_banner.build_banner(str(tmp_path)))
    assert "incompatible" in line
    assert line.endswith("/appsec-advisor:create-threat-model --full --rebuild")


def test_running_scan_offers_status(tmp_path, monkeypatch):
    write_model(tmp_path)
    monkeypatch.setattr(session_banner, "_scan_running", lambda _dir: True)
    line = tm_line(session_banner.build_banner(str(tmp_path)))
    assert line == "threat model · scan in progress · /appsec-advisor:status"


# ---------------------------------------------------------------------------
# The secure-coding baseline line
# ---------------------------------------------------------------------------


def test_missing_baseline_is_reported_with_its_own_command(tmp_path):
    """Baseline command stays on the baseline line, not a footer."""
    write_model(tmp_path)
    line = baseline_line(run_hook(str(tmp_path)))
    assert line is not None
    assert line.startswith(f"{BASELINE_NAME} · not installed")
    assert line.endswith("/appsec-advisor:install-baseline")


def test_installed_baseline_names_its_id_and_scope(tmp_path):
    """Which rules are in context, and from where — without running a command."""
    write_model(tmp_path)
    install_baseline_for(tmp_path)
    line = baseline_line(run_hook(str(tmp_path)))
    assert line == f"{BASELINE_NAME} · aisec-0.1 · this repo"


def test_an_organizations_baseline_appears_under_its_own_name(tmp_path, monkeypatch):
    """An org that ships its own baseline should not read a foreign product name."""
    repo = tmp_path / "repo"
    repo.mkdir()
    write_model(repo)
    root = packaged_root(tmp_path, ["create-threat-model", "install-baseline"], monkeypatch)
    (root / "config.json").write_text(
        json.dumps({"baseline": {"enabled": True, "id": "acme-sec-1.0", "name": "ACME Secure Baseline"}}),
        encoding="utf-8",
    )
    (repo / "CLAUDE.md").write_text("baseline-id: `acme-sec-1.0`\n", encoding="utf-8")
    line = next(line for line in session_banner.build_banner(str(repo)).splitlines() if "ACME" in line)
    assert line == "ACME Secure Baseline · acme-sec-1.0 · this repo"


def test_a_second_different_baseline_beside_the_loaded_one_is_named(tmp_path):
    """Both rule sets are in context; naming only the expected id calls that healthy."""
    write_model(tmp_path)
    install_baseline_for_user(tmp_path)
    (tmp_path / "CLAUDE.md").write_text("baseline-id: `acme-sec-1.0`\n", encoding="utf-8")
    line = baseline_line(run_hook(str(tmp_path)))
    assert line == f"{BASELINE_NAME} · aisec-0.1 · this machine · also acme-sec-1.0 in this repo"


def test_a_declared_derivative_beside_the_baseline_is_not_a_foreign_one(tmp_path):
    """``<id>+suffix`` is the same rules adapted, so it counts as loaded, not as drift."""
    write_model(tmp_path)
    install_baseline_for_user(tmp_path)
    (tmp_path / "CLAUDE.md").write_text("baseline-id: `aisec-0.1+acme`\n", encoding="utf-8")
    line = baseline_line(run_hook(str(tmp_path)))
    assert line == f"{BASELINE_NAME} · aisec-0.1, aisec-0.1+acme · this repo+this machine"
    assert "also" not in line


def test_a_newer_baseline_is_reported_as_ahead_without_a_command(tmp_path):
    """The reader updated the rules before the plugin caught up — not a fault.

    The only command that applies here would write the older text over the
    newer rules, so the line names the state and stops.
    """
    write_model(tmp_path)
    (tmp_path / "CLAUDE.md").write_text("baseline-id: `aisec-9.9`\n", encoding="utf-8")
    line = baseline_line(run_hook(str(tmp_path)))
    assert line == f"{BASELINE_NAME} · aisec-9.9 · this repo · ahead of aisec-0.1"
    assert "install-baseline" not in line


def test_installed_baseline_carries_no_command(tmp_path):
    """A loaded baseline asks nothing of the reader."""
    write_model(tmp_path)
    install_baseline_for(tmp_path)
    line = baseline_line(run_hook(str(tmp_path)))
    assert line is not None
    assert "install-baseline" not in line


def test_a_baseline_in_the_repo_that_nothing_imports_is_reported_missing(tmp_path):
    """Presence on disk is not loading — the banner must not claim otherwise."""
    write_model(tmp_path)
    plugin_root = SCRIPT.parent.parent
    config = json.loads((plugin_root / "config.json").read_text(encoding="utf-8"))["baseline"]
    (tmp_path / "secure-coding-baseline.md").write_text(
        (plugin_root / config["fallback_file"]).read_text(encoding="utf-8"), encoding="utf-8"
    )
    line = baseline_line(run_hook(str(tmp_path)))
    assert line is not None
    assert "not loaded" in line, "on disk is not in context"
    assert "on disk in" in line


def test_a_baseline_the_repo_carries_for_another_tool_is_named(tmp_path):
    """It changes the next step from "install" to "connect what is there"."""
    write_model(tmp_path)
    plugin_root = SCRIPT.parent.parent
    config = json.loads((plugin_root / "config.json").read_text(encoding="utf-8"))["baseline"]
    (tmp_path / "AGENTS.md").write_text(
        (plugin_root / config["fallback_file"]).read_text(encoding="utf-8"), encoding="utf-8"
    )
    line = baseline_line(run_hook(str(tmp_path)))
    assert line is not None
    assert "not loaded" in line
    assert "AGENTS.md" in line


def test_a_broken_baseline_check_does_not_break_the_banner(tmp_path, monkeypatch):
    """Failure is silence: the threat model must still be reported."""
    write_model(tmp_path)
    monkeypatch.setattr(session_banner, "_baseline_line", lambda _repo: "")
    lines = session_banner.build_banner(str(tmp_path)).splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("appsec-advisor")
    assert "threat model" in lines[1]


def test_no_baseline_configured_drops_the_line(tmp_path, monkeypatch):
    """A packaged build that configures none says nothing about it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    write_model(repo)
    packaged_root(tmp_path, ["create-threat-model"], monkeypatch)
    lines = session_banner.build_banner(str(repo)).splitlines()
    assert baseline_line("\n".join(lines)) is None
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# Help and examples
# ---------------------------------------------------------------------------


def test_help_lives_on_the_identity_line(tmp_path):
    write_model(tmp_path)
    first = identity_line(run_hook(str(tmp_path)))
    assert first.endswith("/appsec-advisor:help")


def test_examples_live_on_the_help_page_not_in_the_banner(tmp_path):
    """The banner offers one step; examples and flags belong on the help page."""
    write_model(tmp_path)
    message = run_hook(str(tmp_path))
    assert "/appsec-advisor:help" in message
    assert "ask-threat-model" not in message
    help_page = SCRIPT.parent.parent / "skills" / "help" / "SKILL.md"
    assert "what are the critical findings?" in help_page.read_text(encoding="utf-8")


def test_example_question_is_taken_from_the_ask_skill(tmp_path):
    """A question the skill does not advertise could route somewhere else."""
    skill = SCRIPT.parent.parent / "skills" / "ask-threat-model" / "SKILL.md"
    description = " ".join(skill.read_text(encoding="utf-8").split())
    assert '"what are the critical findings?"' in description


def test_without_a_model_the_create_action_is_on_the_threat_model_line(tmp_path):
    assert tm_line(run_hook(str(tmp_path))).endswith("/appsec-advisor:create-threat-model")


# ---------------------------------------------------------------------------
# Headline override and suppression
# ---------------------------------------------------------------------------


def configured(tmp_path, banner: dict, monkeypatch) -> Path:
    """Fake a plugin root carrying ``banner`` in its config.json."""
    root = tmp_path / "configured"
    (root / "skills" / "create-threat-model").mkdir(parents=True)
    (root / "skills" / "create-threat-model" / "SKILL.md").write_text("x", encoding="utf-8")
    (root / "skills" / "help").mkdir(parents=True)
    (root / "skills" / "help" / "SKILL.md").write_text("x", encoding="utf-8")
    (root / ".claude-plugin").mkdir()
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps(MANIFEST), encoding="utf-8")
    (root / "config.json").write_text(json.dumps({"banner": banner}), encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    monkeypatch.delenv("APPSEC_BANNER", raising=False)
    return root


def test_headline_replaces_the_plugin_name_on_the_identity_line(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    configured(tmp_path, {"headline": "ACME AppSec Advisor"}, monkeypatch)
    first = identity_line(session_banner.build_banner(str(repo)))
    assert first.startswith(f"ACME AppSec Advisor {MANIFEST['version']}")
    assert not first.startswith("appsec-advisor")
    assert first.endswith("/appsec-advisor:help")


def test_headline_does_not_replace_the_computed_state(tmp_path, monkeypatch):
    """The headline is an identity label; threat-model facts stay on their line."""
    repo = tmp_path / "repo"
    repo.mkdir()
    write_model(repo)
    configured(tmp_path, {"headline": "ACME AppSec Advisor"}, monkeypatch)
    message = session_banner.build_banner(str(repo))
    assert identity_line(message).startswith("ACME AppSec Advisor")
    line = tm_line(message)
    assert "acme-api" in line
    assert "27 Jul 2026" in line


def test_multiline_headline_is_flattened(tmp_path, monkeypatch):
    """A stray newline would fake extra banner lines."""
    repo = tmp_path / "repo"
    repo.mkdir()
    configured(tmp_path, {"headline": "ACME\nmore information https://evil.example"}, monkeypatch)
    # No baseline configured in fake root → identity only when no model.
    assert len(session_banner.build_banner(str(repo)).splitlines()) == 2


def test_disabled_in_config_stays_silent(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    configured(tmp_path, {"enabled": False}, monkeypatch)
    assert session_banner.build_banner(str(repo)) == ""


@pytest.mark.parametrize("value", ["0", "false", "off", "no", "FALSE"])
def test_user_env_suppresses_an_enabled_banner(tmp_path, monkeypatch, value):
    repo = tmp_path / "repo"
    repo.mkdir()
    configured(tmp_path, {"enabled": True}, monkeypatch)
    monkeypatch.setenv("APPSEC_BANNER", value)
    assert session_banner.build_banner(str(repo)) == ""


@pytest.mark.parametrize("value", ["1", "true", "on", "yes"])
def test_user_env_restores_a_disabled_banner(tmp_path, monkeypatch, value):
    repo = tmp_path / "repo"
    repo.mkdir()
    configured(tmp_path, {"enabled": False}, monkeypatch)
    monkeypatch.setenv("APPSEC_BANNER", value)
    assert session_banner.build_banner(str(repo)) != ""


def test_unrecognized_env_value_leaves_the_config_in_charge(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    configured(tmp_path, {"enabled": False}, monkeypatch)
    monkeypatch.setenv("APPSEC_BANNER", "maybe")
    assert session_banner.build_banner(str(repo)) == ""


def test_suppression_is_silent_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_BANNER", "0")
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps({"cwd": str(tmp_path)}),
        capture_output=True,
        text=True,
        env={**os.environ, "APPSEC_BANNER": "0"},
    )
    assert result.returncode == 0
    assert result.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Organization-packaged builds — the package policy may drop skills
# ---------------------------------------------------------------------------


def packaged_root(tmp_path, skills: list[str], monkeypatch) -> Path:
    """Fake a packaged plugin root that ships only ``skills``."""
    root = tmp_path / "packaged"
    for skill in skills:
        (root / "skills" / skill).mkdir(parents=True)
        (root / "skills" / skill / "SKILL.md").write_text(f"name: {skill}\n", encoding="utf-8")
    root.mkdir(exist_ok=True)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    return root


def test_dropped_skills_leave_no_dangling_commands(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_severities(repo, "effective_severity", ["Critical"])
    packaged_root(tmp_path, ["create-threat-model"], monkeypatch)
    lines = session_banner.build_banner(str(repo)).splitlines()
    assert lines[0] == "appsec-advisor"
    assert not any("review-threat-model" in line or ":help" in line for line in lines)
    assert tm_line("\n".join(lines)).startswith("threat model")


def test_dropped_update_skill_falls_back_to_incremental_mode(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    init_repo(repo)
    write_model(repo, generated="2026-01-01T00:00:00Z")
    for i in range(session_banner.STALE_COMMITS):
        commit(repo, f"file{i}.txt", "2026-02-01T12:00:00+00:00")
    packaged_root(tmp_path, ["create-threat-model"], monkeypatch)
    line = tm_line(session_banner.build_banner(str(repo)))
    assert "update-threat-model" not in line
    assert line.endswith("/appsec-advisor:create-threat-model --incremental")


def test_create_threat_model_is_always_available(tmp_path, monkeypatch):
    """apply_skill_policy pins create-threat-model, so the fallbacks are safe."""
    policy_source = (SCRIPT.parent / "package_internal_plugin.py").read_text(encoding="utf-8")
    assert 'required={"create-threat-model"}' in policy_source


def test_namespace_literals_are_rewritable_by_packaging(tmp_path):
    """Packaging rewrites `appsec-advisor:` in .py files; the constants must match."""
    source = SCRIPT.read_text(encoding="utf-8")
    for constant in ("REVIEW", "UPDATE", "CREATE", "STATUS", "HELP", "INSTALL_BASELINE"):
        assert f'{constant} = "/appsec-advisor:' in source


def test_no_information_line_in_the_banner(tmp_path):
    """The URL belongs to the help page; repeating it every session is noise."""
    message = run_hook(str(tmp_path))
    assert "more information" not in message
    assert len(message.splitlines()) == 3  # identity, threat model, baseline
    assert not any(line.startswith("http") for line in message.splitlines())
    help_page = SCRIPT.parent.parent / "skills" / "help" / "SKILL.md"
    assert "More information" in help_page.read_text(encoding="utf-8")


def test_configured_url_is_readable_for_the_help_page(tmp_path, monkeypatch):
    root = tmp_path / "plugin"
    root.mkdir()
    (root / "config.json").write_text(
        json.dumps({"banner": {"url": "https://git.acme.internal/appsec"}}), encoding="utf-8"
    )
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    assert session_banner._banner_config()["url"] == "https://git.acme.internal/appsec"


def test_local_config_overrides_the_configured_url(tmp_path, monkeypatch):
    root = tmp_path / "plugin"
    root.mkdir()
    (root / "config.json").write_text(json.dumps({"banner": {"url": "https://upstream.example"}}), encoding="utf-8")
    (root / "config.local.json").write_text(
        json.dumps({"banner": {"url": "https://internal.example/appsec"}}), encoding="utf-8"
    )
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    assert session_banner._banner_config()["url"] == "https://internal.example/appsec"


# ---------------------------------------------------------------------------
# Analysis-version compatibility — the local substitute for a release check
# ---------------------------------------------------------------------------


def test_incompatible_analysis_version_demands_a_rebuild(tmp_path):
    write_model(tmp_path, analysis_version=max(MANIFEST["compatible_analysis_versions"]) + 1)
    lines = session_banner.build_banner(str(tmp_path)).splitlines()
    assert "incompatible" in tm_line("\n".join(lines))
    assert tm_line("\n".join(lines)).endswith("/appsec-advisor:create-threat-model --full --rebuild")


def test_supported_analysis_version_is_silent(tmp_path):
    write_model(tmp_path, analysis_version=min(MANIFEST["compatible_analysis_versions"]))
    assert "incompatible" not in session_banner.build_banner(str(tmp_path))


def test_missing_analysis_version_is_treated_as_compatible(tmp_path):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text("meta:\n  project: acme-api\n", encoding="utf-8")
    assert "incompatible" not in session_banner.build_banner(str(tmp_path))


# ---------------------------------------------------------------------------
# Staleness
# ---------------------------------------------------------------------------


def test_stale_model_recommends_update(tmp_path):
    init_repo(tmp_path)
    write_model(tmp_path, generated="2026-01-01T00:00:00Z")
    for i in range(session_banner.STALE_COMMITS):
        commit(tmp_path, f"file{i}.txt", "2026-02-01T12:00:00+00:00")
    message = session_banner.build_banner(str(tmp_path))
    assert f"+{session_banner.STALE_COMMITS} commits" in message
    assert "/appsec-advisor:update-threat-model" in tm_line(message)


def test_fresh_model_below_threshold_is_not_stale(tmp_path):
    init_repo(tmp_path)
    write_severities(tmp_path, "effective_severity", ["High"])
    model = tmp_path / "docs" / "security" / "threat-model.yaml"
    text = model.read_text(encoding="utf-8")
    model.write_text(text.replace("2026-07-27T10:01:22Z", "2026-01-01T00:00:00Z"), encoding="utf-8")
    commit(tmp_path, "only.txt", "2026-02-01T12:00:00+00:00")
    line = tm_line(session_banner.build_banner(str(tmp_path)))
    assert "+1 commits" in line
    assert "/appsec-advisor:review-threat-model" in line
    assert "update-threat-model" not in line


def test_commits_before_generation_do_not_count(tmp_path):
    init_repo(tmp_path)
    write_model(tmp_path, generated="2026-07-27T10:01:22Z")
    for i in range(session_banner.STALE_COMMITS + 5):
        commit(tmp_path, f"old{i}.txt", "2026-01-01T12:00:00+00:00")
    assert "commits" not in session_banner.build_banner(str(tmp_path))


def test_non_git_directory_still_reports_the_model(tmp_path):
    write_model(tmp_path, generated="2026-01-01T00:00:00Z")
    assert "acme-api" in session_banner.build_banner(str(tmp_path))


# ---------------------------------------------------------------------------
# Tolerance: a malformed model must degrade, never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "",
        "not: yaml: at: all\n",
        "meta:\n  project: acme-api\n",  # no generated, no threats block
        "threats:\n- local_id: T-001\n",  # no meta block
    ],
)
def test_degrades_on_unexpected_model_content(tmp_path, content):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text(content, encoding="utf-8")
    message = run_hook(str(tmp_path))
    assert "threat model" in tm_line(message)


def test_unreadable_stdin_stays_silent():
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input="not json",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == ""


# ---------------------------------------------------------------------------
# Live scan takes precedence over model reporting
# ---------------------------------------------------------------------------


def test_active_scan_replaces_model_line(tmp_path, monkeypatch):
    write_model(tmp_path)
    monkeypatch.setattr(session_banner, "_scan_running", lambda _dir: True)
    message = session_banner.build_banner(str(tmp_path))
    assert "scan in progress" in message
    assert "/appsec-advisor:status" in tm_line(message)


def test_scan_running_ignores_missing_lock(tmp_path):
    assert session_banner._scan_running(tmp_path) is False


# ---------------------------------------------------------------------------
# Hook registration
# ---------------------------------------------------------------------------


def test_hook_is_registered_for_startup():
    hooks = json.loads((SCRIPT.parent.parent / "hooks" / "hooks.json").read_text())
    entries = hooks["hooks"]["SessionStart"]
    assert [e.get("matcher") for e in entries] == ["startup"]
    commands = [h["command"] for e in entries for h in e["hooks"]]
    assert commands == ["python3 ${CLAUDE_PLUGIN_ROOT}/scripts/session_banner.py"]
