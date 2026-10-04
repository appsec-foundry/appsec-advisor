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
