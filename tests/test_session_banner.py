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


@pytest.fixture(autouse=True)
def _tmp_path_is_a_repository(tmp_path):
    """Make every tmp_path look like a working tree.

    The banner only reports on a repository, and `_in_repository` walks up to
    the filesystem root — so on a machine that happens to have `/tmp/.git`, a
    bare tmp_path would pass for one and hide a regression. Creating the marker
    explicitly makes the precondition part of the test instead of the host.
    """
    (tmp_path / ".git").mkdir(exist_ok=True)
    return tmp_path


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


# ---------------------------------------------------------------------------
# End-to-end: stdout contract
# ---------------------------------------------------------------------------


def test_reports_missing_model(tmp_path):
    message = run_hook(str(tmp_path))
    assert "no threat model in docs/security/" in message
    assert "/appsec-advisor:create-threat-model" in message


def test_reports_existing_model(tmp_path):
    write_model(tmp_path)
    message = run_hook(str(tmp_path))
    assert "acme-api" in message
    assert "2 threats" in message
    assert "27 Jul 2026" in message
    assert "/appsec-advisor:review-threat-model" in message


def test_assessment_depth_is_left_out(tmp_path):
    """How the report was produced is a detail of the report, not of the state."""
    write_model(tmp_path)
    assert "standard" not in run_hook(str(tmp_path))


def test_identity_rides_on_the_action_row_not_the_status_line(tmp_path):
    """The status line pays a 27-column prefix; the action row does not."""
    lines = run_hook(str(tmp_path)).splitlines()
    assert lines[0] == f"{session_banner.GLYPH_NONE} no threat model in docs/security/"
    assert lines[1].endswith(f"appsec-advisor {MANIFEST['version']}")


# ---------------------------------------------------------------------------
# Outside a repository
# ---------------------------------------------------------------------------


def test_outside_a_repository_only_the_plugin_and_help_are_announced(tmp_path, monkeypatch):
    """A directory nobody meant to scan gets no complaint about a missing model."""
    monkeypatch.setattr(session_banner, "_in_repository", lambda _path: False)
    assert session_banner.build_banner(str(tmp_path)) == (
        f"appsec-advisor {MANIFEST['version']} · /appsec-advisor:help"
    )


def test_a_model_outside_a_repository_is_still_reported(tmp_path, monkeypatch):
    """An --output directory need not be a working tree; the model still counts."""
    monkeypatch.setattr(session_banner, "_in_repository", lambda _path: False)
    write_model(tmp_path)
    assert "threat model" in session_banner.build_banner(str(tmp_path)).splitlines()[0]


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


def test_critical_and_high_are_counted_and_marked(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Critical", "Critical", "High", "Medium"])
    first = plain(run_hook(str(tmp_path))).splitlines()[0]
    assert "4 threats (2 CRITICAL, 1 high)" in first


def test_effective_severity_wins_over_risk(tmp_path):
    """effective_severity carries triage caps and boosts; risk is pre-adjustment."""
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text(
        "meta:\n  project: acme-api\nthreats:\n- local_id: T-001\n  risk: Critical\n  effective_severity: Medium\n",
        encoding="utf-8",
    )
    assert "CRITICAL" not in session_banner.build_banner(str(tmp_path)).splitlines()[0]


def test_risk_is_used_when_effective_severity_is_absent(tmp_path):
    write_severities(tmp_path, "risk", ["Critical", "High"])
    first = run_hook(str(tmp_path)).splitlines()[0]
    assert "1 CRITICAL" in first and "1 high" in first


def test_clean_model_shows_no_severity_marks(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Medium", "Low"])
    first = run_hook(str(tmp_path)).splitlines()[0]
    assert "2 threats" in first
    assert "CRITICAL" not in first and "high" not in first


def test_state_line_names_what_the_numbers_are(tmp_path):
    write_model(tmp_path)
    assert run_hook(str(tmp_path)).splitlines()[0].startswith(f"{session_banner.GLYPH_OK} threat model")


def test_project_name_is_shown_only_when_it_is_not_this_repository(tmp_path):
    """A model produced with --repo describes something else; that is worth columns."""
    repo = tmp_path / "web-shop"
    repo.mkdir()
    write_model(repo)  # fixture project is "acme-api"
    assert "threat model: acme-api" in session_banner.build_banner(str(repo))

    same = tmp_path / "acme-api"
    same.mkdir()
    write_model(same)
    first = session_banner.build_banner(str(same)).splitlines()[0]
    assert "acme-api" not in first


def test_a_single_threat_is_not_pluralized(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Critical"])
    assert "1 threat (" in run_hook(str(tmp_path))


def test_timestamp_carries_the_time_and_its_zone(tmp_path):
    write_model(tmp_path)
    assert "27 Jul 2026 10:01 UTC" in run_hook(str(tmp_path))


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
# State glyphs
# ---------------------------------------------------------------------------


def test_current_model_is_marked_green(tmp_path):
    write_model(tmp_path)
    assert run_hook(str(tmp_path)).startswith(session_banner.GLYPH_OK)


def test_stale_model_is_marked_amber(tmp_path):
    init_repo(tmp_path)
    write_model(tmp_path, generated="2026-01-01T00:00:00Z")
    for i in range(session_banner.STALE_COMMITS):
        commit(tmp_path, f"file{i}.txt", "2026-02-01T12:00:00+00:00")
    assert session_banner.build_banner(str(tmp_path)).startswith(session_banner.GLYPH_WARN)


def test_critical_findings_turn_the_glyph_red_on_a_current_model(tmp_path):
    """One glyph, one claim: current but full of criticals is not a green state."""
    write_severities(tmp_path, "effective_severity", ["Critical"])
    assert run_hook(str(tmp_path)).startswith(session_banner.GLYPH_ALERT)


def test_high_findings_turn_the_glyph_amber(tmp_path):
    write_severities(tmp_path, "effective_severity", ["High"])
    assert run_hook(str(tmp_path)).startswith(session_banner.GLYPH_WARN)


def test_clean_current_model_is_the_only_green_state(tmp_path):
    write_severities(tmp_path, "effective_severity", ["Medium", "Low"])
    assert run_hook(str(tmp_path)).startswith(session_banner.GLYPH_OK)


def test_incompatible_model_is_marked_red(tmp_path):
    write_model(tmp_path, analysis_version=max(MANIFEST["compatible_analysis_versions"]) + 1)
    assert session_banner.build_banner(str(tmp_path)).startswith(session_banner.GLYPH_ALERT)


def test_running_scan_is_marked_blue(tmp_path, monkeypatch):
    write_model(tmp_path)
    monkeypatch.setattr(session_banner, "_scan_running", lambda _dir: True)
    assert session_banner.build_banner(str(tmp_path)).startswith(session_banner.GLYPH_BUSY)


def test_only_the_status_line_carries_a_glyph(tmp_path):
    write_model(tmp_path)
    glyphs = (
        session_banner.GLYPH_OK,
        session_banner.GLYPH_WARN,
        session_banner.GLYPH_ALERT,
        session_banner.GLYPH_NONE,
        session_banner.GLYPH_BUSY,
    )
    for line in run_hook(str(tmp_path)).splitlines()[1:]:
        assert not any(glyph in line for glyph in glyphs)


# ---------------------------------------------------------------------------
# Action hints and the information URL
# ---------------------------------------------------------------------------


def test_action_row_offers_one_command_plus_help(tmp_path):
    write_model(tmp_path)
    lines = run_hook(str(tmp_path)).splitlines()
    assert lines[1].startswith("/appsec-advisor:review-threat-model · /appsec-advisor:help")


def test_status_line_carries_no_command(tmp_path):
    """State and action are separate roles; mixing them made both harder to see."""
    write_model(tmp_path)
    assert "/appsec-advisor:" not in run_hook(str(tmp_path)).splitlines()[0]


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


def test_without_a_model_the_create_action_is_offered(tmp_path):
    row = run_hook(str(tmp_path)).splitlines()[1]
    assert row.startswith("/appsec-advisor:create-threat-model · /appsec-advisor:help")


# ---------------------------------------------------------------------------
# Headline override and suppression
# ---------------------------------------------------------------------------


def configured(tmp_path, banner: dict, monkeypatch) -> Path:
    """Fake a plugin root carrying ``banner`` in its config.json."""
    root = tmp_path / "configured"
    (root / "skills" / "create-threat-model").mkdir(parents=True)
    (root / "skills" / "create-threat-model" / "SKILL.md").write_text("x", encoding="utf-8")
    (root / ".claude-plugin").mkdir()
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps(MANIFEST), encoding="utf-8")
    (root / "config.json").write_text(json.dumps({"banner": banner}), encoding="utf-8")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))
    monkeypatch.delenv("APPSEC_BANNER", raising=False)
    return root


def test_headline_replaces_the_plugin_identity(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    configured(tmp_path, {"headline": "ACME AppSec Advisor"}, monkeypatch)
    first = session_banner.build_banner(str(repo)).splitlines()[0]
    assert first.startswith(f"{session_banner.GLYPH_NONE} ACME AppSec Advisor ·")
    assert "appsec-advisor 0" not in first


def test_headline_does_not_replace_the_computed_state(tmp_path, monkeypatch):
    """The headline is an identity label; the state after it stays derived."""
    repo = tmp_path / "repo"
    repo.mkdir()
    write_model(repo)
    configured(tmp_path, {"headline": "ACME AppSec Advisor"}, monkeypatch)
    first = session_banner.build_banner(str(repo)).splitlines()[0]
    assert "acme-api" in first
    assert "27 Jul 2026" in first


def test_multiline_headline_is_flattened(tmp_path, monkeypatch):
    """A stray newline would fake extra banner lines."""
    repo = tmp_path / "repo"
    repo.mkdir()
    configured(tmp_path, {"headline": "ACME\nmore information https://evil.example"}, monkeypatch)
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


def test_dropped_skills_leave_the_row_without_dangling_commands(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_model(repo)
    packaged_root(tmp_path, ["create-threat-model"], monkeypatch)
    lines = session_banner.build_banner(str(repo)).splitlines()
    assert not any("review-threat-model" in line or ":help" in line for line in lines)
    assert lines[1] == "appsec-advisor"


def test_dropped_update_skill_falls_back_to_incremental_mode(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    init_repo(repo)
    write_model(repo, generated="2026-01-01T00:00:00Z")
    for i in range(session_banner.STALE_COMMITS):
        commit(repo, f"file{i}.txt", "2026-02-01T12:00:00+00:00")
    packaged_root(tmp_path, ["create-threat-model"], monkeypatch)
    row = session_banner.build_banner(str(repo)).splitlines()[1]
    assert "update-threat-model" not in row
    assert row.startswith("/appsec-advisor:create-threat-model --incremental")


def test_status_line_never_carries_a_command(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_model(repo)
    packaged_root(tmp_path, ["create-threat-model"], monkeypatch)
    first = session_banner.build_banner(str(repo)).splitlines()[0]
    assert "/appsec-advisor:" not in first
    assert first.endswith("27 Jul 2026 10:01 UTC")


def test_create_threat_model_is_always_available(tmp_path, monkeypatch):
    """apply_skill_policy pins create-threat-model, so the fallbacks are safe."""
    policy_source = (SCRIPT.parent / "package_internal_plugin.py").read_text(encoding="utf-8")
    assert 'required={"create-threat-model"}' in policy_source


def test_namespace_literals_are_rewritable_by_packaging(tmp_path):
    """Packaging rewrites `appsec-advisor:` in .py files; the constants must match."""
    source = SCRIPT.read_text(encoding="utf-8")
    for constant in ("REVIEW", "UPDATE", "CREATE", "STATUS"):
        assert f'{constant} = "/appsec-advisor:' in source


def test_no_information_line_in_the_banner(tmp_path):
    """The URL belongs to the help page; repeating it every session is noise."""
    message = run_hook(str(tmp_path))
    assert "more information" not in message
    assert len(message.splitlines()) == 2
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
    assert "no longer compatible" in lines[0]
    assert lines[1].startswith("/appsec-advisor:create-threat-model --full --rebuild")


def test_supported_analysis_version_is_silent(tmp_path):
    write_model(tmp_path, analysis_version=min(MANIFEST["compatible_analysis_versions"]))
    assert "no longer compatible" not in session_banner.build_banner(str(tmp_path))


def test_missing_analysis_version_is_treated_as_compatible(tmp_path):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.yaml").write_text("meta:\n  project: acme-api\n", encoding="utf-8")
    assert "no longer compatible" not in session_banner.build_banner(str(tmp_path))


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
    assert "/appsec-advisor:update-threat-model" in message


def test_fresh_model_below_threshold_is_not_stale(tmp_path):
    init_repo(tmp_path)
    write_model(tmp_path, generated="2026-01-01T00:00:00Z")
    commit(tmp_path, "only.txt", "2026-02-01T12:00:00+00:00")
    message = session_banner.build_banner(str(tmp_path))
    assert "+1 commits" in message
    assert "/appsec-advisor:review-threat-model" in message


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
    assert "threat model" in message.splitlines()[0]


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
    assert "/appsec-advisor:status" in message


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
