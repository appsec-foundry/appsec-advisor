"""appsec-reviewer-cli refuses repository-owned agent configuration and never reuses a checked-in verdict."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "appsec-reviewer-cli"


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "app.js").write_text("module.exports = 1\n")
    return repo


def fake_claude(tmp_path: Path, writes_verdict: bool) -> tuple[dict, Path]:
    """A ``claude`` on PATH that records its argv and optionally writes no verdict."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "claude-argv.json"
    body = f"import json, sys\njson.dump(sys.argv[1:], open({str(log)!r}, 'w'))\n"
    if writes_verdict:
        body += "raise SystemExit(0)\n"
    script = bindir / "claude"
    script.write_text(f"#!/usr/bin/env python3\n{body}")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    env = {**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}", "CLAUDE_PLUGIN_ROOT": str(ROOT)}
    return env, log


def run(repo: Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(CLI), "review", "--diff", "HEAD", *args],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_a_checked_in_verdict_is_never_reported_as_this_review(checkout, tmp_path):
    verdict = checkout / "docs" / "security" / ".requirements-verification.json"
    verdict.parent.mkdir(parents=True)
    verdict.write_text(json.dumps({"results": [], "summary": {"pass": 1}}))
    env, log = fake_claude(tmp_path, writes_verdict=False)
    result = run(checkout, env, "--fail-on", "must")
    assert result.returncode == 2 and "no verdict produced" in result.stderr
    assert not verdict.exists()
    argv = json.loads(log.read_text())
    assert argv[argv.index("--allowedTools") + 1] == "Read,Write,Glob,Grep,Bash,Agent"


@pytest.mark.parametrize("owned", [".claude/settings.json", ".claude/settings.local.json"])
def test_repository_owned_claude_configuration_is_refused_unless_trusted(checkout, tmp_path, owned):
    (checkout / owned).parent.mkdir(parents=True, exist_ok=True)
    (checkout / owned).write_text('{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "id"}]}]}}')
    env, log = fake_claude(tmp_path, writes_verdict=False)
    refused = run(checkout, env)
    assert refused.returncode == 2 and "--trust-mode trusted" in refused.stderr and not log.exists()
    trusted = run(checkout, env, "--trust-mode", "trusted")
    assert log.exists() and "no verdict produced" in trusted.stderr


def test_a_clean_repository_passes_the_preflight(checkout, tmp_path):
    env, log = fake_claude(tmp_path, writes_verdict=False)
    run(checkout, env)
    assert log.exists()


def test_an_unknown_trust_mode_is_rejected(checkout, tmp_path):
    env, log = fake_claude(tmp_path, writes_verdict=False)
    result = run(checkout, env, "--trust-mode", "maybe")
    assert result.returncode == 2 and "--trust-mode must be" in result.stderr and not log.exists()
