"""Tests for scripts/update_baseline.py.

Three properties carry the weight here.

*Ownership.* An update rewrites the file the rules are loaded from. Where that
file is a team's own — an ``AGENTS.md`` carrying the baseline among their own
instructions — rewriting it would delete what surrounds the rules, so the
command has to leave it alone instead.

*No silent downgrade.* Neither an unreachable source nor a newly published
version may end with older text on disk. The first must change nothing, the
second must stop and say what changed. A signed release is the one source whose
newer version is installed rather than reported, and it too leaves a copy that
is ahead of it alone.

*No install.* A machine with no baseline, or with somebody else's, is reported
rather than converted.

The network is never touched: every case either passes ``offline=True`` or stubs
the fetch.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "update_baseline.py"
sys.path.insert(0, str(SCRIPT.parent))

import baseline_check as bc  # noqa: E402
import install_baseline as ib  # noqa: E402
import update_baseline as ub  # noqa: E402

BASELINE_TEXT = "# Test Baseline\n\n`baseline-id: test-1.0`\n\n- Do the secure thing.\n"
EDITED_TEXT = "# Test Baseline\n\n`baseline-id: test-1.0`\n\n- Do the secure thing, carefully.\n"


@pytest.fixture
def bundled(tmp_path: Path) -> Path:
    path = tmp_path / "plugin" / "data" / "baselines" / "test.md"
    path.parent.mkdir(parents=True)
    path.write_text(BASELINE_TEXT, encoding="utf-8")
    return path


@pytest.fixture
def config(bundled: Path) -> dict:
    return {
        "enabled": True,
        "id": "test-1.0",
        "name": "Test Baseline",
        "url": "https://example.invalid/baseline.md",
        "git": None,
        "fallback_file": str(bundled),
        "install_filename": "secure-coding-baseline.md",
    }


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    return path


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    (path / ".claude").mkdir(parents=True)
    return path


@pytest.fixture
def installed(repo: Path, home: Path, config: dict) -> Path:
    """A project-scope install of ``BASELINE_TEXT``, and the file it wrote."""
    ib.install("project", repo, home, config, offline=True)
    return repo / config["install_filename"]


def publish(monkeypatch, text: str) -> None:
    monkeypatch.setattr(ib, "_fetch", lambda url: text.encode())


# ---------- nothing installed, or not ours --------------------------------


def test_a_missing_baseline_is_reported_not_installed(repo: Path, home: Path, config: dict):
    steps, code = ub.update(repo, home, config)
    assert code == 0
    assert any("nothing to update" in step for step in steps)
    assert any("install-baseline" in step for step in steps)
    assert not (repo / config["install_filename"]).exists()
    assert not (repo / "CLAUDE.md").exists()


def test_an_outdated_copy_is_refreshed_in_place(repo: Path, home: Path, config: dict, monkeypatch):
    """The case the command exists for: same baseline, older text on disk.

    An older version lands in its own bucket rather than under ``matches``, so
    the partition has to read both or this update finds nothing to do.
    """
    target = repo / config["install_filename"]
    target.write_text(BASELINE_TEXT.replace("test-1.0", "test-0.9"), encoding="utf-8")
    (repo / "CLAUDE.md").write_text(f"@{config['install_filename']}\n", encoding="utf-8")
    publish(monkeypatch, EDITED_TEXT)

    steps, code = ub.update(repo, home, config)

    assert code == 0
    assert target.read_text(encoding="utf-8") == EDITED_TEXT
    assert any("updated" in step for step in steps)


def test_an_outdated_carrier_is_still_left_alone(repo: Path, home: Path, config: dict, monkeypatch):
    """Ownership wins over staleness: a team's own file is not this command's."""
    carrier = repo / "AGENTS.md"
    carrier.write_text(
        "# AGENTS.md\n\nTeam rules.\n\n" + BASELINE_TEXT.replace("test-1.0", "test-0.9"),
        encoding="utf-8",
    )
    (repo / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")
    publish(monkeypatch, EDITED_TEXT)

    steps, code = ub.update(repo, home, config)

    assert code == 0
    assert carrier.read_text(encoding="utf-8").startswith("# AGENTS.md")
    assert any("left alone" in step for step in steps)


def test_a_foreign_baseline_is_left_where_it_is(repo: Path, home: Path, config: dict):
    other = repo / config["install_filename"]
    other.write_text("# Other\n\n`baseline-id: other-9.9`\n", encoding="utf-8")
    (repo / "CLAUDE.md").write_text(f"@{config['install_filename']}\n", encoding="utf-8")

    steps, code = ub.update(repo, home, config)

    assert code == 0
    assert any("other-9.9" in step for step in steps)
    assert other.read_text(encoding="utf-8").startswith("# Other")


def test_a_newer_baseline_is_not_downgraded(repo: Path, home: Path, config: dict):
    ahead = repo / config["install_filename"]
    ahead.write_text("# Test Baseline\n\n`baseline-id: test-2.0`\n", encoding="utf-8")
    (repo / "CLAUDE.md").write_text(f"@{config['install_filename']}\n", encoding="utf-8")

    steps, code = ub.update(repo, home, config)

    assert code == 0
    assert "test-2.0" in ahead.read_text(encoding="utf-8")
    assert any("ahead" in step for step in steps)


# ---------- the update itself ---------------------------------------------


def test_the_loaded_copy_is_rewritten_from_the_source(
    installed: Path, repo: Path, home: Path, config: dict, monkeypatch
):
    publish(monkeypatch, EDITED_TEXT)

    steps, code = ub.update(repo, home, config)

    assert code == 0
    assert installed.read_text(encoding="utf-8") == EDITED_TEXT
    assert any(str(installed) in step and step.startswith("updated") for step in steps)


def test_the_previous_text_is_kept_as_a_backup(installed: Path, repo: Path, home: Path, config: dict, monkeypatch):
    publish(monkeypatch, EDITED_TEXT)

    ub.update(repo, home, config)

    backup = installed.with_suffix(installed.suffix + ".bak")
    assert backup.read_text(encoding="utf-8") == BASELINE_TEXT


def test_unchanged_text_is_reported_not_rewritten(installed: Path, repo: Path, home: Path, config: dict, monkeypatch):
    publish(monkeypatch, BASELINE_TEXT)

    steps, code = ub.update(repo, home, config)

    assert code == 0
    assert any("already current" in step for step in steps)
    assert not installed.with_suffix(installed.suffix + ".bak").exists()


def test_dry_run_writes_nothing(installed: Path, repo: Path, home: Path, config: dict, monkeypatch):
    publish(monkeypatch, EDITED_TEXT)

    steps, code = ub.update(repo, home, config, dry_run=True)

    assert code == 0
    assert any(step.startswith("would update") for step in steps)
    assert installed.read_text(encoding="utf-8") == BASELINE_TEXT


def test_offline_updates_from_the_bundled_copy(installed: Path, repo: Path, home: Path, config: dict, bundled: Path):
    installed.write_text("# Damaged\n\n`baseline-id: test-1.0`\n", encoding="utf-8")

    steps, code = ub.update(repo, home, config, offline=True)

    assert code == 0
    assert installed.read_text(encoding="utf-8") == BASELINE_TEXT
    assert any(str(bundled) in step for step in steps)


# ---------- what it refuses to touch --------------------------------------


def test_a_reused_carrier_is_left_alone(repo: Path, home: Path, config: dict, monkeypatch):
    """An install that wired up AGENTS.md must not grow a second copy here."""
    carrier = repo / "AGENTS.md"
    carrier.write_text(f"# AGENTS.md\n\nTeam rules.\n\n{BASELINE_TEXT}", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    publish(monkeypatch, EDITED_TEXT)

    steps, code = ub.update(repo, home, config)

    assert code == 0
    assert carrier.read_text(encoding="utf-8").startswith("# AGENTS.md")
    assert not (repo / config["install_filename"]).exists()
    assert any("left alone" in step for step in steps)


def test_a_policy_deployment_is_not_this_command_s(config: dict):
    result = {
        "matches": [{"id": "test-1.0", "scope": "policy", "file": "/etc/claude-code/CLAUDE.md"}],
        "older": [],
    }

    targets, notes = ub._partition(result, config)

    assert targets == []
    assert any("administrator" in note for note in notes)


def aiscb_user_install(home: Path, text: str) -> Path:
    """A static aiscb user install: its copy in the data directory, linked and imported."""
    data = home / ".local" / "share" / "aiscb"
    data.mkdir(parents=True)
    copy = data / "secure-coding-baseline.md"
    copy.write_text(text, encoding="utf-8")
    (data / "install.py").write_text("# installer\n", encoding="utf-8")
    (home / ".claude" / "secure-coding-baseline.md").symlink_to(copy)
    (home / ".claude" / "CLAUDE.md").write_text("@~/.claude/secure-coding-baseline.md\n", encoding="utf-8")
    return copy


def test_a_copy_in_an_aiscb_installation_is_left_to_its_installer(repo: Path, home: Path, config: dict):
    """That installer verifies and replaces its own files; the report names its command."""
    copy = aiscb_user_install(home, EDITED_TEXT)

    steps, code = ub.update(repo, home, config, offline=True)

    assert code == 0
    assert copy.read_text(encoding="utf-8") == EDITED_TEXT
    assert any(f"python3 {copy.parent / 'install.py'} --update" in step for step in steps)


def test_a_switched_off_aiscb_install_is_not_updated(repo: Path, home: Path, config: dict, monkeypatch):
    copy = aiscb_user_install(home, EDITED_TEXT)
    helper = copy.parent / "show-baseline-version.py"
    helper.write_text("# helper\n", encoding="utf-8")
    hook = {"hooks": [{"type": "command", "command": f"python3 {helper} --session-context --part 0"}]}
    (home / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"SessionStart": [hook]}}), encoding="utf-8")
    (home / ".claude" / "CLAUDE.md").unlink()
    monkeypatch.setenv("AISCB_DISABLE", "1")

    steps, code = ub.update(repo, home, config, offline=True)

    assert code == 0
    assert "switched off" in steps[0]
    assert copy.read_text(encoding="utf-8") == EDITED_TEXT


def test_an_unreachable_source_does_not_touch_the_copy(
    installed: Path, repo: Path, home: Path, config: dict, monkeypatch
):
    def boom(url):
        raise ib.InstallError("connection refused")

    monkeypatch.setattr(ib, "_fetch", boom)

    with pytest.raises(ub.UpdateError) as excinfo:
        ub.update(repo, home, config)

    assert "--offline" in str(excinfo.value)
    assert installed.read_text(encoding="utf-8") == BASELINE_TEXT


def test_a_document_without_the_expected_id_is_refused(
    installed: Path, repo: Path, home: Path, config: dict, monkeypatch
):
    publish(monkeypatch, "<html><body>Sign in to the network</body></html>")

    with pytest.raises(ub.UpdateError):
        ub.update(repo, home, config)

    assert installed.read_text(encoding="utf-8") == BASELINE_TEXT


def test_a_newly_published_id_stops_and_changes_nothing(
    installed: Path, repo: Path, home: Path, config: dict, monkeypatch
):
    publish(monkeypatch, "# Test Baseline\n\n`baseline-id: test-1.1`\n\n- Newer rules.\n")

    steps, code = ub.update(repo, home, config)

    assert code == ub.ACTION_NEEDED
    assert installed.read_text(encoding="utf-8") == BASELINE_TEXT
    assert any("test-1.1" in step for step in steps)


def test_a_renamed_id_stops_the_same_way_a_new_version_does(
    installed: Path, repo: Path, home: Path, config: dict, monkeypatch
):
    """Upstream renames an id as readily as it bumps a version; neither is an error."""
    publish(monkeypatch, "# Test Baseline\n\n`baseline-id: tsts-0.9`\n\n- Renamed rules.\n")

    steps, code = ub.update(repo, home, config)

    assert code == ub.ACTION_NEEDED
    assert installed.read_text(encoding="utf-8") == BASELINE_TEXT
    assert any("tsts-0.9" in step for step in steps)


def test_a_derivative_of_the_configured_id_still_updates(
    installed: Path, repo: Path, home: Path, config: dict, monkeypatch
):
    derived = "# Test Baseline\n\n`baseline-id: test-1.0+acme`\n\n- House rules.\n"
    publish(monkeypatch, derived)

    steps, code = ub.update(repo, home, config)

    assert code == 0
    assert installed.read_text(encoding="utf-8") == derived


# ---------- a signed release moves forward --------------------------------

NEWER_TEXT = "# Test Baseline\n\n`baseline-id: test-1.1`\n\n- Newer rules.\n"


def from_releases(config: dict) -> dict:
    return {**config, "url": "", "release": {"repository": "example-org/baseline", "allowed_signers": ["k"]}}


def serve_release(monkeypatch, text: str) -> list[str]:
    """Serve ``text`` as the latest verified release; returns the minimums asked for."""
    asked: list[str] = []

    def fetch_latest(release, minimum):
        asked.append(minimum)
        return ub.br.Release(text, bc.find_ids(text)[0], "example-org/baseline release, signature verified")

    monkeypatch.setattr(ub.br, "fetch_latest", fetch_latest)
    return asked


def test_a_newer_signed_release_replaces_the_installed_copy(
    installed: Path, repo: Path, home: Path, config: dict, monkeypatch
):
    asked = serve_release(monkeypatch, NEWER_TEXT)

    steps, code = ub.update(repo, home, from_releases(config))

    assert code == 0
    assert installed.read_text(encoding="utf-8") == NEWER_TEXT
    assert asked == ["test-1.0"], "the configured id is the floor the release is held to"


def test_a_copy_ahead_of_the_build_still_moves_to_a_newer_release(repo: Path, home: Path, config: dict, monkeypatch):
    target = repo / config["install_filename"]
    target.write_text(NEWER_TEXT, encoding="utf-8")
    (repo / "CLAUDE.md").write_text(f"@{config['install_filename']}\n", encoding="utf-8")
    newest = NEWER_TEXT.replace("test-1.1", "test-1.2")
    serve_release(monkeypatch, newest)

    steps, code = ub.update(repo, home, from_releases(config))

    assert code == 0
    assert target.read_text(encoding="utf-8") == newest


def test_a_signed_release_never_downgrades_a_newer_copy(repo: Path, home: Path, config: dict, monkeypatch):
    target = repo / config["install_filename"]
    target.write_text(NEWER_TEXT.replace("test-1.1", "test-1.3"), encoding="utf-8")
    (repo / "CLAUDE.md").write_text(f"@{config['install_filename']}\n", encoding="utf-8")
    serve_release(monkeypatch, NEWER_TEXT)

    steps, code = ub.update(repo, home, from_releases(config))

    assert code == 0
    assert "test-1.3" in target.read_text(encoding="utf-8")
    assert any("ahead of test-1.1" in step for step in steps)


def test_a_release_that_does_not_verify_changes_nothing(
    installed: Path, repo: Path, home: Path, config: dict, monkeypatch
):
    def fetch_latest(release, minimum):
        raise ub.br.ReleaseError("the manifest signature is not from a trusted release key")

    monkeypatch.setattr(ub.br, "fetch_latest", fetch_latest)

    with pytest.raises(ub.UpdateError, match="trusted release key"):
        ub.update(repo, home, from_releases(config))

    assert installed.read_text(encoding="utf-8") == BASELINE_TEXT


def test_offline_does_not_follow_releases(installed: Path, repo: Path, home: Path, config: dict):
    """``--offline`` reads the bundled copy, which never carries a newer id."""
    installed.write_text(NEWER_TEXT, encoding="utf-8")

    steps, code = ub.update(repo, home, from_releases(config), offline=True)

    assert code == 0
    assert installed.read_text(encoding="utf-8") == NEWER_TEXT


# ---------- CLI -----------------------------------------------------------


def run_cli(home: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
    )


def test_cli_reports_a_machine_without_a_baseline(repo: Path, home: Path):
    done = run_cli(home, "--repo", str(repo))
    assert done.returncode == 0, done.stderr
    assert "nothing to update" in done.stdout


def test_cli_updates_an_offline_install(repo: Path, home: Path):
    config = bc.load_config()
    if not config["enabled"]:
        pytest.skip("this build configures no baseline")
    installed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "install_baseline.py"),
            "--scope",
            "project",
            "--repo",
            str(repo),
            "--offline",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
    )
    assert installed.returncode == 0, installed.stderr

    done = run_cli(home, "--repo", str(repo), "--offline")

    assert done.returncode == 0, done.stderr
    assert "already current" in done.stdout
