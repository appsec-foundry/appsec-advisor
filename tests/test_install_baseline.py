"""Tests for scripts/install_baseline.py.

Two properties carry most of the weight here.

*Convergence.* The installer appends to files a user maintains by hand, so
running it twice must leave the same result as running it once — no duplicated
import, no reordered file, nothing lost.

*Refusal.* Whatever the source, the text is written into the instruction files
the assistant obeys. A captive portal, a 404 body, or a URL that now serves
something else must be refused rather than installed, and the only thing
standing between those and `CLAUDE.md` is the baseline-id check.

The network is never touched: every case either passes ``offline=True`` or
stubs the fetch.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "install_baseline.py"
sys.path.insert(0, str(SCRIPT.parent))

import baseline_check as bc  # noqa: E402
import install_baseline as ib  # noqa: E402

BASELINE_TEXT = "# Test Baseline\n\n`baseline-id: test-1.0`\n\n- Do the secure thing.\n"


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


def loaded(repo: Path, home: Path, config: dict) -> bool:
    return bc.check(repo=repo, home=home, config=config)["status"] == "installed"


# ---------- each scope installs something Claude Code loads ---------------


def test_project_scope_wires_claude_md(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n\nProject rules.\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)

    assert (repo / "secure-coding-baseline.md").read_text(encoding="utf-8") == BASELINE_TEXT
    text = (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert "Project rules." in text, "the user's own content must survive"
    assert "@secure-coding-baseline.md" in text
    assert loaded(repo, home, config)


def test_project_scope_creates_a_missing_claude_md(repo: Path, home: Path, config: dict):
    ib.install("project", repo, home, config, offline=True)
    assert (repo / "CLAUDE.md").read_text(encoding="utf-8").splitlines()[-1] == "@secure-coding-baseline.md"
    assert loaded(repo, home, config)


def test_the_import_is_annotated_for_whoever_reads_the_file_later(repo: Path, home: Path, config: dict):
    """A bare `@path` says nothing about where it came from or how to undo it."""
    ib.install("project", repo, home, config, offline=True)
    lines = (repo / "CLAUDE.md").read_text(encoding="utf-8").splitlines()
    assert bc.IMPORT_NOTE_RE.match(lines[-2])
    assert lines[-1] == "@secure-coding-baseline.md"


def test_the_note_carries_no_baseline_id(config: dict):
    """A stale id is worse than none — and the check would read it as loaded rules."""
    assert bc.find_ids(bc.import_note(config)) == []


def test_the_note_is_written_once_however_often_install_runs(repo: Path, home: Path, config: dict):
    ib.install("project", repo, home, config, offline=True)
    ib.install("project", repo, home, config, offline=True)
    assert (repo / "CLAUDE.md").read_text(encoding="utf-8").count("remove-baseline") == 1


def test_project_rules_scope_touches_no_claude_md(repo: Path, home: Path, config: dict):
    ib.install("project-rules", repo, home, config, offline=True)
    assert (repo / ".claude" / "rules" / "secure-coding-baseline.md").is_file()
    assert not (repo / "CLAUDE.md").exists(), "this scope exists to leave CLAUDE.md alone"
    assert loaded(repo, home, config)


def test_user_scope_imports_by_absolute_path(repo: Path, home: Path, config: dict):
    """~/.claude/CLAUDE.md is read from every directory, so the import must not
    depend on which one that is."""
    ib.install("user", repo, home, config, offline=True)
    line = (home / ".claude" / "CLAUDE.md").read_text(encoding="utf-8").splitlines()[-1]
    assert line == f"@{home / '.claude' / 'secure-coding-baseline.md'}"
    assert loaded(repo, home, config)


def test_user_scope_applies_without_a_repository(repo: Path, home: Path, config: dict):
    ib.install("user", repo, home, config, offline=True)
    assert bc.check(repo=None, home=home, config=config)["status"] == "installed"


def test_unknown_scope_is_refused(repo: Path, home: Path, config: dict):
    with pytest.raises(ib.InstallError):
        ib.install("everywhere", repo, home, config, offline=True)


def test_disabled_config_refuses_to_install(repo: Path, home: Path, config: dict):
    with pytest.raises(ib.InstallError):
        ib.install("project", repo, home, {**config, "enabled": False}, offline=True)


# ---------- convergence ---------------------------------------------------


def test_second_run_adds_no_second_import(repo: Path, home: Path, config: dict):
    ib.install("project", repo, home, config, offline=True)
    ib.install("project", repo, home, config, offline=True)
    text = (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert text.count("@secure-coding-baseline.md") == 1


def test_second_run_reports_no_change(repo: Path, home: Path, config: dict):
    ib.install("project", repo, home, config, offline=True)
    steps = ib.install("project", repo, home, config, offline=True)
    assert any("unchanged" in step for step in steps)
    assert any("already imported" in step for step in steps)


def test_an_existing_equivalent_import_is_recognised(repo: Path, home: Path, config: dict):
    """A hand-written `@./secure-coding-baseline.md` is the same import."""
    (repo / "secure-coding-baseline.md").write_text(BASELINE_TEXT, encoding="utf-8")
    (repo / "CLAUDE.md").write_text("@./secure-coding-baseline.md\n", encoding="utf-8")
    steps = ib.install("project", repo, home, config, offline=True)
    assert any("already imported" in step for step in steps)
    assert (repo / "CLAUDE.md").read_text(encoding="utf-8").count("@") == 1


def test_a_file_without_a_trailing_newline_stays_valid(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\nNo trailing newline", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    lines = (repo / "CLAUDE.md").read_text(encoding="utf-8").splitlines()
    assert lines[1] == "No trailing newline", "the import must not be glued onto the last line"
    assert "@secure-coding-baseline.md" in lines


def test_refresh_replaces_a_drifted_copy_and_keeps_a_backup(repo: Path, home: Path, config: dict):
    ib.install("project", repo, home, config, offline=True)
    (repo / "secure-coding-baseline.md").write_text("edited by hand\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True, force=True)
    assert (repo / "secure-coding-baseline.md").read_text(encoding="utf-8") == BASELINE_TEXT
    assert (repo / "secure-coding-baseline.md.bak").read_text(encoding="utf-8") == "edited by hand\n"


# ---------- reusing a baseline the repository already carries -------------


@pytest.mark.parametrize("rel", ["AGENTS.md", ".github/copilot-instructions.md"])
def test_an_existing_carrier_is_imported_instead_of_copied(repo: Path, home: Path, config: dict, rel: str):
    """Two files with the same rules diverge the day one of them is edited."""
    carrier = repo / rel
    carrier.parent.mkdir(parents=True, exist_ok=True)
    carrier.write_text(BASELINE_TEXT, encoding="utf-8")

    steps = ib.install("project", repo, home, config, offline=True)

    assert not (repo / "secure-coding-baseline.md").exists(), "no second copy"
    assert f"@{rel}" in (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert any("reusing" in step for step in steps)
    assert loaded(repo, home, config)


def test_an_unimported_baseline_file_is_wired_up_rather_than_rewritten(repo: Path, home: Path, config: dict):
    """Somebody committed the file and never imported it — the common case.

    Only the wiring is missing, so only the wiring is added. Overwriting would
    replace whatever the team has, possibly a newer text than the fallback.
    """
    theirs = BASELINE_TEXT + "\n- An extra rule this team added.\n"
    (repo / "secure-coding-baseline.md").write_text(theirs, encoding="utf-8")
    steps = ib.install("project", repo, home, config, offline=True)
    assert (repo / "secure-coding-baseline.md").read_text(encoding="utf-8") == theirs
    assert any("already present" in step for step in steps)
    assert "@secure-coding-baseline.md" in (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert loaded(repo, home, config)


def test_refresh_replaces_an_unimported_copy(repo: Path, home: Path, config: dict):
    """--refresh is the way to say "take the configured source instead"."""
    (repo / "secure-coding-baseline.md").write_text(BASELINE_TEXT + "\n- theirs\n", encoding="utf-8")
    ib.install("project", repo, home, config, offline=True, force=True)
    assert (repo / "secure-coding-baseline.md").read_text(encoding="utf-8") == BASELINE_TEXT


def test_a_carrier_with_a_different_baseline_is_not_reused(repo: Path, home: Path, config: dict):
    """Someone else's rules are not this baseline, whatever file they sit in."""
    (repo / "AGENTS.md").write_text(BASELINE_TEXT.replace("test-1.0", "other-9.9"), encoding="utf-8")
    ib.install("project", repo, home, config, offline=True)
    assert (repo / "secure-coding-baseline.md").is_file()
    assert "@secure-coding-baseline.md" in (repo / "CLAUDE.md").read_text(encoding="utf-8")


def test_reuse_works_through_a_symlinked_repository_path(tmp_path: Path, home: Path, config: dict):
    """On macOS /tmp is a link to /private/tmp; a repo reached through any
    symlink must not silently lose the reuse."""
    real = tmp_path / "real-repo"
    real.mkdir()
    (real / "AGENTS.md").write_text(BASELINE_TEXT, encoding="utf-8")
    link = tmp_path / "linked-repo"
    link.symlink_to(real, target_is_directory=True)

    steps = ib.install("project", link, home, config, offline=True)

    assert any("reusing" in step for step in steps)
    assert "@AGENTS.md" in (real / "CLAUDE.md").read_text(encoding="utf-8")
    assert not (real / "secure-coding-baseline.md").exists()


def test_no_reuse_writes_its_own_copy(repo: Path, home: Path, config: dict):
    (repo / "AGENTS.md").write_text(BASELINE_TEXT, encoding="utf-8")
    ib.install("project", repo, home, config, offline=True, reuse=False)
    assert (repo / "secure-coding-baseline.md").is_file()


def test_refresh_does_not_reuse(repo: Path, home: Path, config: dict):
    """--refresh means "get the current text", which a reused carrier cannot promise."""
    (repo / "AGENTS.md").write_text(BASELINE_TEXT, encoding="utf-8")
    ib.install("project", repo, home, config, offline=True, force=True)
    assert (repo / "secure-coding-baseline.md").is_file()


def test_the_user_scope_never_imports_a_repository_path(repo: Path, home: Path, config: dict):
    """It would resolve to nothing in every other repository on the machine."""
    (repo / "AGENTS.md").write_text(BASELINE_TEXT, encoding="utf-8")
    ib.install("user", repo, home, config, offline=True)
    line = (home / ".claude" / "CLAUDE.md").read_text(encoding="utf-8").splitlines()[-1]
    assert str(repo) not in line
    assert line == f"@{home / '.claude' / 'secure-coding-baseline.md'}"


def test_project_rules_scope_does_not_reuse(repo: Path, home: Path, config: dict):
    """That scope wires no import, so it has nothing to point at a carrier."""
    (repo / "AGENTS.md").write_text(BASELINE_TEXT, encoding="utf-8")
    ib.install("project-rules", repo, home, config, offline=True)
    assert (repo / ".claude" / "rules" / "secure-coding-baseline.md").is_file()


def test_reuse_needs_no_source_at_all(repo: Path, home: Path, config: dict):
    """Nothing is fetched and no fallback is read — the text is already here."""
    (repo / "AGENTS.md").write_text(BASELINE_TEXT, encoding="utf-8")
    config = {**config, "fallback_file": ""}  # any source access would now fail
    ib.install("project", repo, home, config, offline=True)
    assert loaded(repo, home, config)


# ---------- dry run writes nothing ---------------------------------------


def test_dry_run_reports_the_reuse_without_wiring_it(repo: Path, home: Path, config: dict):
    (repo / "AGENTS.md").write_text(BASELINE_TEXT, encoding="utf-8")
    steps = ib.install("project", repo, home, config, offline=True, dry_run=True)
    assert any("reusing" in step for step in steps)
    assert not (repo / "CLAUDE.md").exists()
    assert not (repo / "secure-coding-baseline.md").exists()


def test_dry_run_changes_nothing(repo: Path, home: Path, config: dict):
    (repo / "CLAUDE.md").write_text("# CLAUDE.md\n", encoding="utf-8")
    steps = ib.install("project", repo, home, config, offline=True, dry_run=True)
    assert not (repo / "secure-coding-baseline.md").exists()
    assert (repo / "CLAUDE.md").read_text(encoding="utf-8") == "# CLAUDE.md\n"
    assert any(step.startswith("would write") for step in steps)


# ---------- source selection and refusal ---------------------------------


def test_offline_uses_the_bundled_copy(config: dict):
    text, origin, note = ib.resolve_source(config, offline=True)
    assert text == BASELINE_TEXT
    assert origin == config["fallback_file"]
    assert note == "--offline"


def test_fetch_wins_over_the_bundled_copy(config: dict, monkeypatch):
    published = BASELINE_TEXT + "\n- A newer rule.\n"
    monkeypatch.setattr(ib, "_fetch", lambda url: published.encode())
    text, origin, note = ib.resolve_source(config, offline=False)
    assert text == published
    assert origin == config["url"]
    assert note == "", "a successful fetch is not a fallback"


def test_unreachable_url_falls_back_and_says_why(config: dict, monkeypatch):
    def boom(url):
        raise ib.InstallError("Name or service not known")

    monkeypatch.setattr(ib, "_fetch", boom)
    text, origin, note = ib.resolve_source(config, offline=False)
    assert text == BASELINE_TEXT
    assert origin == config["fallback_file"]
    assert "Name or service not known" in note


def test_a_document_without_the_expected_id_is_refused(repo: Path, home: Path, config: dict, monkeypatch):
    """A captive portal or a 404 body must never reach CLAUDE.md."""
    monkeypatch.setattr(ib, "_fetch", lambda url: b"<html><body>Sign in to the network</body></html>")
    config = {**config, "fallback_file": ""}
    with pytest.raises(ib.InstallError, match="no baseline id at all"):
        ib.install("project", repo, home, config, offline=False)
    assert not (repo / "CLAUDE.md").exists()


def test_a_different_baseline_at_the_url_is_refused(config: dict, monkeypatch):
    monkeypatch.setattr(ib, "_fetch", lambda url: b"`baseline-id: other-9.9`\n")
    config = {**config, "fallback_file": ""}
    with pytest.raises(ib.InstallError, match="other-9.9"):
        ib.resolve_source(config, offline=False)


def test_a_derivative_at_the_url_is_accepted(config: dict, monkeypatch):
    derived = BASELINE_TEXT.replace("test-1.0", "test-1.0+acme")
    monkeypatch.setattr(ib, "_fetch", lambda url: derived.encode())
    text, _origin, note = ib.resolve_source(config, offline=False)
    assert text == derived
    assert note == ""


def test_an_oversized_response_is_refused(config: dict, monkeypatch):
    monkeypatch.setattr(ib, "_fetch", lambda url: b"x" * (ib.MAX_FETCH_BYTES + 1))
    config = {**config, "fallback_file": ""}
    with pytest.raises(ib.InstallError, match="larger than"):
        ib.resolve_source(config, offline=False)


def test_no_source_and_no_bundled_copy_fails_clearly(config: dict):
    config = {**config, "url": "", "git": None, "fallback_file": ""}
    with pytest.raises(ib.InstallError, match="no bundled copy"):
        ib.resolve_source(config, offline=True)


def test_a_url_blocked_by_the_guard_falls_back(config: dict, monkeypatch):
    """The SSRF guard's verdict is a fetch failure like any other."""
    monkeypatch.setattr(
        ib._url_guard,
        "validate_target_url",
        lambda url, **kw: ib._url_guard.ValidationResult(False, "host not in allowlist", None),
    )
    _text, origin, note = ib.resolve_source(config, offline=False)
    assert origin == config["fallback_file"]
    assert "not in allowlist" in note


# ---------- the git source ------------------------------------------------


def make_git_repo(path: Path, text: str) -> Path:
    path.mkdir(parents=True)
    (path / "baseline.md").write_text(text, encoding="utf-8")
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "PATH": "/usr/bin:/bin",
        "HOME": str(path),
    }
    subprocess.run(["git", "init", "-q"], cwd=path, check=True, env=env)
    subprocess.run(["git", "add", "."], cwd=path, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=path, check=True, env=env)
    return path


def test_git_source_reads_the_named_file(tmp_path: Path, config: dict):
    origin_repo = make_git_repo(tmp_path / "origin", BASELINE_TEXT)
    config = {**config, "url": "", "git": {"url": str(origin_repo), "path": "baseline.md"}}
    text, origin, note = ib.resolve_source(config, offline=False)
    assert text == BASELINE_TEXT
    assert note == ""
    assert "baseline.md" in origin


def test_git_source_falls_back_when_the_file_is_absent(tmp_path: Path, config: dict):
    origin_repo = make_git_repo(tmp_path / "origin", BASELINE_TEXT)
    config = {**config, "url": "", "git": {"url": str(origin_repo), "path": "nope.md"}}
    _text, origin, note = ib.resolve_source(config, offline=False)
    assert origin == config["fallback_file"]
    assert "nope.md" in note


def test_git_source_falls_back_when_the_repo_is_unreachable(tmp_path: Path, config: dict):
    config = {**config, "url": "", "git": {"url": str(tmp_path / "absent"), "path": "baseline.md"}}
    _text, origin, note = ib.resolve_source(config, offline=False)
    assert origin == config["fallback_file"]
    assert "git clone failed" in note


def test_git_source_rejects_a_path_escaping_the_repository(config: dict):
    config = {**config, "url": "", "git": {"url": "https://example.invalid/x.git", "path": "../../etc/passwd"}}
    _text, origin, note = ib.resolve_source(config, offline=False)
    assert origin == config["fallback_file"]
    assert "stay inside the repository" in note


def test_git_source_needs_both_url_and_path(config: dict):
    config = {**config, "url": "", "git": {"url": "https://example.invalid/x.git"}}
    _text, _origin, note = ib.resolve_source(config, offline=False)
    assert "needs both" in note


# ---------- CLI -----------------------------------------------------------


def run_cli(home: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
    )


def test_cli_installs_and_verifies(repo: Path, home: Path):
    done = run_cli(home, "--scope", "project", "--repo", str(repo), "--offline")
    assert done.returncode == 0, done.stderr
    assert "✓ verified" in done.stdout
    assert (repo / "CLAUDE.md").is_file()


def test_cli_dry_run_writes_nothing(repo: Path, home: Path):
    done = run_cli(home, "--scope", "project", "--repo", str(repo), "--offline", "--dry-run")
    assert done.returncode == 0
    assert "Would install" in done.stdout
    assert not (repo / "CLAUDE.md").exists()


def test_cli_rejects_an_unknown_scope(repo: Path, home: Path):
    done = run_cli(home, "--scope", "everywhere", "--repo", str(repo))
    assert done.returncode != 0


def test_cli_reports_an_unwritable_target_without_a_traceback(repo: Path, home: Path):
    repo.chmod(0o500)
    try:
        done = run_cli(home, "--scope", "project", "--repo", str(repo), "--offline")
        assert done.returncode == 2
        assert "Traceback" not in done.stderr
        assert "cannot write" in done.stderr
    finally:
        repo.chmod(0o700)
