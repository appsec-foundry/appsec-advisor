"""Abuse cases checked one at a time through the Threat Analyst's hypothesis mode."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from model import abuse_case_hypothesis as ach  # noqa: E402

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}

_REPO_CASE = """\
schema_version: 2
abuse_cases:
  - id: REPO-AC-031
    kind: descriptive
    title: Clerk releases a payout they also requested
    actor: Finance clerk
    initial_access: authenticated_low_priv
    goal: Release money without a second person.
    boundary: Payouts above the approval threshold.
    steps:
      - Request a payout and release it with the same account.
    expected_controls:
      - Release checks that the releasing user differs from the requester.
    exclusions:
      - Payouts below the approval threshold.
    scope_qualifier:
      path_patterns: ["*payout*"]
"""


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env={**os.environ, **GIT_ENV})


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src" / "finance").mkdir(parents=True)
    (repo / "src" / "finance" / "PayoutController.java").write_text("class PayoutController { void release() {} }\n")
    (repo / "src" / "session.js").write_text("const claims = jwt.verify(token, publicKey)\n")
    (repo / "src" / "util.js").write_text("module.exports = (a) => a\n")
    (repo / "test").mkdir()
    (repo / "test" / "payout.test.js").write_text("it('releases', () => jwt.verify(t, k))\n")
    cases = repo / "docs" / "security" / "abuse-cases"
    cases.mkdir(parents=True)
    (cases / "finance.yaml").write_text(_REPO_CASE)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    return repo


def build(repo: Path, ids: list[str], paths=(), with_threat_model=False):
    return ach.build(repo, "HEAD", ids, list(paths), with_threat_model, no_org_profile=True)


def test_a_business_case_selects_files_by_its_path_patterns_and_names_its_origin(repo):
    hypothesis, paths = build(repo, ["REPO-AC-031"])
    assert paths == ["src/finance/PayoutController.java"]
    assert hypothesis.startswith("Abuse case REPO-AC-031 (business case, repository): Clerk releases a payout")
    assert "- Out of scope: Payouts below the approval threshold." in hypothesis
    assert "runs without a threat model" in hypothesis


def test_a_technical_case_selects_files_by_its_code_sinks_and_skips_tests(repo):
    hypothesis, paths = build(repo, ["AC-T-003"], with_threat_model=True)
    assert paths == ["src/session.js"]
    assert "(technical attack chain, plugin)" in hypothesis and "- Step 1:" in hypothesis
    assert "uses the supplied threat model" in hypothesis


def test_user_paths_come_first_and_are_kept(repo):
    _, paths = build(repo, ["REPO-AC-031"], paths=["src/util.js"])
    assert paths == ["src/util.js", "src/finance/PayoutController.java"]


def test_an_unknown_id_is_an_error_not_a_guess(repo):
    with pytest.raises(ach.AbuseCaseError, match="unknown abuse case ID"):
        build(repo, ["REPO-AC-999"])


def test_a_case_that_locates_no_file_asks_for_paths(repo):
    (repo / "src" / "finance" / "PayoutController.java").unlink()
    (repo / "src" / "session.js").unlink()
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "remove")
    with pytest.raises(ach.AbuseCaseError, match="--path"):
        build(repo, ["REPO-AC-031"])
