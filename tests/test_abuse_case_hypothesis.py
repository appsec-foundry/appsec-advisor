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
    return ach.build(repo, "HEAD", ids, list(paths), with_threat_model, no_org_profile=True)[:2]


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


def test_the_summary_names_each_case_its_origin_and_every_file(repo):
    _, paths, summary = ach.build(repo, "HEAD", ["REPO-AC-031", "AC-T-003"], [], False, no_org_profile=True)
    lines = summary.splitlines()
    assert lines[0] == "ABUSE-CASE CHECK"
    assert "  REPO-AC-031  Clerk releases a payout they also requested  (business case, repository)" in lines
    assert "    Checks: Request a payout and release it with the same account." in lines
    assert any(line.startswith("  AC-T-003  ") and "(technical attack chain, plugin)" in line for line in lines)
    assert f"  Files ({len(paths)}):" in lines and all(f"    {p}" in lines for p in paths)


def _model(repo: Path, body: dict) -> Path:
    import yaml

    path = repo / "docs" / "security" / "threat-model.yaml"
    path.write_text(yaml.safe_dump(body))
    return path


def test_a_threat_model_adds_the_previous_outcome_and_the_files_of_related_findings(repo):
    (repo / "src" / "roles.js").write_text("module.exports = (req) => req.user.role\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "roles")
    model = _model(
        repo,
        {
            "threats": [
                {
                    "id": "T-004",
                    "title": "Role taken from token",
                    "cwe": "CWE-863",
                    "evidence": [{"file": "src/roles.js", "line": 1}],
                },
                {
                    "id": "T-009",
                    "title": "Gone file",
                    "cwe": "CWE-347",
                    "evidence": [{"file": "src/removed.js", "line": 3}],
                },
                {
                    "id": "T-011",
                    "title": "Unrelated",
                    "cwe": "CWE-79",
                    "evidence": [{"file": "src/util.js", "line": 1}],
                },
            ],
            "abuse_case_analysis": {
                "cases": [
                    {
                        "id": "AC-T-003",
                        "chain_verdict": "inconclusive",
                        "matched_finding_ids": ["T-004"],
                        "open_questions": ["Which library version verifies tokens?"],
                    }
                ]
            },
        },
    )
    hypothesis, paths, summary = ach.build(
        repo, "HEAD", ["AC-T-003"], [], True, no_org_profile=True, threat_model_path=model
    )
    assert paths[0] == "src/roles.js" and "src/removed.js" not in paths and "src/util.js" not in paths
    assert "Previous threat-model result for this case: inconclusive." in hypothesis
    assert "- Related threat-model finding F-004: Role taken from token (src/roles.js:1)" in hypothesis
    assert "F-011" not in hypothesis
    assert "Open question recorded in the threat model: Which library version verifies tokens?" in hypothesis
    assert "    previously: inconclusive" in summary.splitlines()
    assert "    related findings: F-004, F-009" in summary.splitlines()


def test_an_unreadable_threat_model_adds_no_links(repo):
    broken = repo / "docs" / "security" / "threat-model.yaml"
    broken.write_text("threats: [unclosed\n")
    hypothesis, paths, _ = ach.build(
        repo, "HEAD", ["AC-T-003"], [], True, no_org_profile=True, threat_model_path=broken
    )
    assert paths == ["src/session.js"] and "Previous threat-model result" not in hypothesis


def test_every_step_gets_a_file_before_one_step_fills_the_cap(repo, monkeypatch):
    for n in range(4):
        (repo / "src" / f"verify{n}.js").write_text("jwt.verify(a, k)\n" * (n + 1))
    (repo / "src" / "roles.js").write_text("if (req.user.role === 'admin') next()\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "steps")
    monkeypatch.setattr(ach, "MAX_PATHS", 3)
    _, paths = build(repo, ["AC-T-003"])
    assert paths[0] == "src/verify3.js"  # step 1: the file with the most sink lines leads
    assert "src/roles.js" in paths  # step 2 is not crowded out by step 1's matches
    assert len(paths) == 3
