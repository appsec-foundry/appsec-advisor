"""Tests for scripts/remove_baseline.py.

Three properties carry the weight here.

*Reach.* Removing the import has to actually stop the baseline loading, in
every scope, and leave every other line of a hand-maintained instruction file
byte-for-byte where it was.

*Restraint.* An install may wire up a file the repository already had — an
``AGENTS.md``, a committed copy — instead of writing one. Deletion must never
reach those, whatever the import points at.

*Refusal.* An import written into a sentence, a file declaring a different
baseline, a scope where the file is the wiring: each is reported rather than
guessed at.

The network is never touched: installs in these tests pass ``offline=True``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "remove_baseline.py"
sys.path.insert(0, str(SCRIPT.parent))

import baseline_check as bc  # noqa: E402
import install_baseline as ib  # noqa: E402
import remove_baseline as rb  # noqa: E402

BASELINE_TEXT = "# Test Baseline\n\n`baseline-id: test-1.0`\n\n- Do the secure thing.\n"
OTHER_TEXT = "# Other Baseline\n\n`baseline-id: other-9.9`\n\n- Something else.\n"


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
        "url": None,
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


def loaded(repo: Path, home: Path, config: dict) -> bool:
    return bc.check(repo=repo, home=home, config=config)["status"] == "installed"


# ---------- the import goes, and the baseline stops loading ---------------


def test_project_scope_unwires_and_keeps_the_file(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n\nProject rules.\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    assert loaded(repo, home, config)

    rb.remove("project", repo, home, config)

    assert not loaded(repo, home, config)
    assert (repo / config["install_filename"]).is_file()
    assert "@secure-coding-baseline.md" not in (repo / "CLAUDE.md").read_text(encoding="utf-8")


def test_user_scope_unwires(repo: Path, home: Path, config: dict):
    ib.install("user", repo, home, config, offline=True)
    assert loaded(repo, home, config)

    rb.remove("user", repo, home, config)

    assert not loaded(repo, home, config)
    assert (home / ".claude" / config["install_filename"]).is_file()


def test_everything_else_in_the_file_survives(repo: Path, home: Path, config: dict):
    original = "# CLAUDE.md\n\n@other-rules.md\n\nKeep this sentence.\n"
    (repo / "CLAUDE.md").write_text(original, encoding="utf-8")
    (repo / "other-rules.md").write_text("# Other rules\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)

    rb.remove("project", repo, home, config)

    text = (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert "@other-rules.md" in text
    assert "Keep this sentence." in text


def test_the_edited_file_is_backed_up(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    before = (repo / "CLAUDE.md").read_text(encoding="utf-8")

    rb.remove("project", repo, home, config)

    assert (repo / "CLAUDE.md.bak").read_text(encoding="utf-8") == before


def test_removing_twice_is_harmless(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    rb.remove("project", repo, home, config)
    after_first = (repo / "CLAUDE.md").read_text(encoding="utf-8")

    steps = rb.remove("project", repo, home, config)

    assert (repo / "CLAUDE.md").read_text(encoding="utf-8") == after_first
    assert any("no baseline import" in step for step in steps)


def test_reinstalling_after_a_removal_restores_it(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    rb.remove("project", repo, home, config)

    ib.install("project", repo, home, config, offline=True)

    assert loaded(repo, home, config)


# ---------- deletion reaches the scope's own file and nothing else -------


def test_delete_file_removes_the_target_and_its_backup(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    target = repo / config["install_filename"]
    target.with_suffix(target.suffix + ".bak").write_text(BASELINE_TEXT, encoding="utf-8")

    rb.remove("project", repo, home, config, delete_file=True)

    assert not target.exists()
    assert not target.with_suffix(target.suffix + ".bak").exists()


def test_a_reused_carrier_is_never_deleted(repo: Path, home: Path, config: dict):
    """The install imports an existing AGENTS.md rather than copying it."""
    carrier = repo / "AGENTS.md"
    carrier.write_text(BASELINE_TEXT, encoding="utf-8")
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    assert loaded(repo, home, config)

    rb.remove("project", repo, home, config, delete_file=True)

    assert carrier.read_text(encoding="utf-8") == BASELINE_TEXT
    assert not loaded(repo, home, config)


def test_a_file_declaring_another_baseline_is_kept(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    target = repo / config["install_filename"]
    target.write_text(OTHER_TEXT, encoding="utf-8")

    steps = rb.remove("project", repo, home, config, delete_file=True)

    assert target.is_file()
    assert any("does not declare" in step for step in steps)


def test_dry_run_changes_nothing(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    before = (repo / "CLAUDE.md").read_text(encoding="utf-8")

    rb.remove("project", repo, home, config, delete_file=True, dry_run=True)

    assert (repo / "CLAUDE.md").read_text(encoding="utf-8") == before
    assert (repo / config["install_filename"]).is_file()
    assert loaded(repo, home, config)


# ---------- what it refuses to do ----------------------------------------


def test_project_rules_refuses_without_the_delete_flag(repo: Path, home: Path, config: dict):
    ib.install("project-rules", repo, home, config, offline=True)

    with pytest.raises(rb.RemoveError, match="--delete-file"):
        rb.remove("project-rules", repo, home, config)

    assert loaded(repo, home, config)


def test_project_rules_deletes_with_the_flag(repo: Path, home: Path, config: dict):
    ib.install("project-rules", repo, home, config, offline=True)

    rb.remove("project-rules", repo, home, config, delete_file=True)

    assert not loaded(repo, home, config)


def test_an_import_inside_prose_is_reported_not_rewritten(repo: Path, home: Path, config: dict):
    (repo / config["install_filename"]).write_text(BASELINE_TEXT, encoding="utf-8")
    line = "Read @secure-coding-baseline.md before writing code.\n"
    (repo / "CLAUDE.md").write_text(f"# CLAUDE.md\n\n{line}", encoding="utf-8")
    assert loaded(repo, home, config)

    steps = rb.remove("project", repo, home, config)

    assert line in (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert any("by hand" in step for step in steps)


def test_an_unknown_scope_is_refused(repo: Path, home: Path, config: dict):
    with pytest.raises(rb.RemoveError, match="unknown scope"):
        rb.remove("machine", repo, home, config)


def test_a_build_without_a_baseline_is_refused(repo: Path, home: Path, config: dict):
    with pytest.raises(rb.RemoveError, match="no secure-coding baseline is configured"):
        rb.remove("project", repo, home, dict(config, enabled=False))


# ---------- the risks the caller has to be told about --------------------


def test_a_git_tracked_file_is_named_as_the_first_risk(repo: Path, home: Path, config: dict):
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    target = repo / config["install_filename"]
    target.write_text(BASELINE_TEXT, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", target.name], check=True, capture_output=True)

    risks = rb.delete_risks(target, repo)

    assert "git tracks" in risks[0]


def test_an_untracked_file_still_warns_about_local_edits(repo: Path, home: Path, config: dict):
    target = repo / config["install_filename"]
    target.write_text(BASELINE_TEXT, encoding="utf-8")

    risks = rb.delete_risks(target, repo)

    assert len(risks) == 1
    assert "local edit" in risks[0]


def test_the_risks_reach_the_report(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)

    steps = rb.remove("project", repo, home, config, delete_file=True, dry_run=True)

    assert any(step.startswith("! ") and "local edit" in step for step in steps)


# ---------- the CLI ------------------------------------------------------


def test_cli_reports_a_refusal_without_a_traceback(repo: Path, home: Path, config: dict):
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--scope", "project", "--repo", str(repo), "--dry-run"],
        capture_output=True,
        text=True,
    )
    assert done.returncode in (0, 2)
    assert "Traceback" not in done.stderr


def test_cli_rejects_an_unknown_scope(repo: Path, home: Path, config: dict):
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--scope", "machine", "--repo", str(repo)],
        capture_output=True,
        text=True,
    )
    assert done.returncode == 2
