"""Argument validation and exit behavior of appsec-analyst-cli."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "appsec-analyst-cli"


def run(*args: str, cwd: Path, state: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "XDG_STATE_HOME": str(state)}
    return subprocess.run(
        [sys.executable, str(CLI), *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=60
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["review", "--staged"], "interactive only"),
        (["review", "--worktree", "--staged", "--interactive"], "exactly one scope"),
        (["review", "--base", "main"], "required together"),
        (["review"], "exactly one scope"),
        (["review", "--worktree", "--exact-base", "--interactive"], "only to --base/--head"),
        (["design", "--text", "Export customers"], "interactive only"),
        (["design", "--text", " ", "--interactive"], "non-empty"),
        (
            ["review", "--base", "a", "--head", "b", "--ci", "--package", "tmm/threat-modeling-manifesto@1.0.0"],
            "--trusted-package",
        ),
        (["review", "--base", "a", "--head", "b", "--trusted-package", "/x.yaml"], "requires --ci"),
        (["review", "--base", "a", "--head", "b", "--ci", "--interactive"], "exclude each other"),
        (["answer", "--job", "aj-" + "a" * 32, "--answer", "q-001=yes"], "interactive only"),
        (["review", "--worktree", "--interactive", "--unknown"], "unrecognized"),
    ],
)
def test_invalid_invocations_exit_2_before_any_job(repo, tmp_path, args, message):
    state = tmp_path / "xdg"
    result = run(*args[:1], "--repo", str(repo), *args[1:], cwd=tmp_path, state=state)
    assert result.returncode == 2
    assert message in result.stderr
    assert not state.exists()


def test_a_repository_that_is_not_a_git_tree_is_rejected(tmp_path):
    state = tmp_path / "xdg"
    result = run("review", "--repo", str(tmp_path), "--base", "a", "--head", "b", cwd=tmp_path, state=state)
    assert result.returncode == 2 and "Rejected before analysis" in result.stdout
    assert not list(state.rglob("aj-*")) if state.exists() else True


def test_help_works_from_any_directory(tmp_path):
    result = subprocess.run(
        [sys.executable, str(CLI), "--help"], cwd=tmp_path, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0 and "usage:" in result.stdout.lower()


@pytest.mark.parametrize(
    "args,message",
    [
        (["--hypothesis", "Check access", "--revision", "HEAD"], "--path"),
        (["--hypothesis", "Check access", "--path", "src"], "--revision"),
        (["--hypothesis", " ", "--revision", "HEAD", "--path", "src"], "non-empty"),
        (["--hypothesis", "Check access", "--revision", "HEAD", "--path", "../outside"], "invalid hypothesis"),
    ],
)
def test_hypothesis_cli_rejects_missing_or_invalid_scope(repo, tmp_path, args, message):
    state = tmp_path / "xdg"
    result = run("hypothesis", "--repo", str(repo), *args, cwd=tmp_path, state=state)
    assert result.returncode == 2 and message in result.stderr + result.stdout
    assert not state.exists()


def test_hypothesis_cli_builds_a_bounded_controller_invocation(repo, monkeypatch, capsys):
    import runpy

    module = runpy.run_path(str(CLI))
    observed = []

    def invoke(invocation, transport, interactive):
        observed.append(invocation)
        return module["ctl"].Outcome(0, "complete", None, "Scoped result\n")

    monkeypatch.setattr(module["ctl"], "run", invoke)
    assert (
        module["main"](
            [
                "hypothesis",
                "--repo",
                str(repo),
                "--hypothesis",
                "Check ownership",
                "--revision",
                "HEAD",
                "--path",
                "src/api",
                "--path",
                "src/auth",
            ]
        )
        == 0
    )
    assert observed[0].mode == "hypothesis"
    assert observed[0].hypothesis == "Check ownership"
    assert observed[0].scope == {"kind": "hypothesis", "revision": "HEAD", "paths": ["src/api", "src/auth"]}
    assert "Scoped result" in capsys.readouterr().out


def _committed_repo(repo: Path) -> Path:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid"}
    env.update(GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e.invalid", GIT_CONFIG_GLOBAL=os.devnull)
    (repo / "src").mkdir()
    (repo / "src" / "session.js").write_text("const claims = jwt.verify(token, publicKey)\n")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True, env=env)
    return repo


def test_abuse_case_cli_fills_hypothesis_and_paths_from_the_case(repo, monkeypatch):
    import runpy

    module = runpy.run_path(str(CLI))
    observed = []
    monkeypatch.setattr(
        module["ctl"],
        "run",
        lambda inv, transport, interactive: observed.append(inv) or module["ctl"].Outcome(0, "complete", None, ""),
    )
    argv = ["hypothesis", "--repo", str(_committed_repo(repo)), "--abuse-case", "AC-T-003", "--revision", "HEAD"]
    assert module["main"]([*argv, "--no-org-profile"]) == 0
    assert observed[0].scope["paths"] == ["src/session.js"]
    assert observed[0].hypothesis.startswith("Abuse case AC-T-003 (technical attack chain, plugin)")
    assert "runs without a threat model" in observed[0].hypothesis


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--abuse-case", "AC-NOPE-1", "--revision", "HEAD", "--no-org-profile"], "unknown abuse case ID"),
        (["--abuse-case", "AC-T-003", "--hypothesis", "x", "--revision", "HEAD"], "not allowed with"),
        (["--hypothesis", "x", "--revision", "HEAD", "--path", "src", "--no-org-profile"], "only to --abuse-case"),
    ],
)
def test_abuse_case_cli_rejects_bad_selections_before_any_job(repo, tmp_path, args, message):
    state = tmp_path / "xdg"
    result = run("hypothesis", "--repo", str(_committed_repo(repo)), *args, cwd=tmp_path, state=state)
    assert result.returncode == 2 and message in result.stderr + result.stdout
    assert not state.exists()


@pytest.mark.parametrize(("extra", "uses_model"), [([], True), (["--isolated"], False)])
def test_abuse_case_cli_uses_the_existing_threat_model_unless_isolated(repo, monkeypatch, extra, uses_model):
    import runpy

    module = runpy.run_path(str(CLI))
    observed = []
    monkeypatch.setattr(
        module["ctl"],
        "run",
        lambda inv, transport, interactive: observed.append(inv) or module["ctl"].Outcome(0, "complete", None, ""),
    )
    repo = _committed_repo(repo)
    (repo / "docs" / "security").mkdir(parents=True)
    (repo / "docs" / "security" / "threat-model.yaml").write_text("schema_version: 1\n")
    argv = ["hypothesis", "--repo", str(repo), "--abuse-case", "AC-T-003", "--revision", "HEAD", "--no-org-profile"]
    assert module["main"]([*argv, *extra]) == 0
    model = repo / "docs" / "security" / "threat-model.yaml"
    assert (observed[0].threat_model_path == model) is uses_model
    assert ("uses the supplied threat model" in observed[0].hypothesis) is uses_model
    assert ("runs without a threat model" in observed[0].hypothesis) is not uses_model


def test_abuse_case_preview_prints_the_scope_and_starts_no_job(repo, tmp_path):
    state = tmp_path / "xdg"
    argv = ["--abuse-case", "AC-T-003", "--revision", "HEAD", "--no-org-profile", "--isolated", "--preview"]
    result = run("hypothesis", "--repo", str(_committed_repo(repo)), *argv, cwd=tmp_path, state=state)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "ABUSE-CASE CHECK",
        "  AC-T-003  Privilege Escalation to Admin via JWT Algorithm Confusion  (technical attack chain, plugin)",
        "  Revision: HEAD",
        "  Files (1):",
        "    src/session.js",
        "  Threat model: none (isolated)",
    ]
    assert not state.exists()
