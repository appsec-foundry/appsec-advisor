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
    assert hypothesis.startswith("Abuse case REPO-AC-031 (business abuse case, repository): Clerk releases a payout")
    assert "- Out of scope: Payouts below the approval threshold." in hypothesis
    assert "runs without a threat model" in hypothesis


def test_a_technical_case_selects_files_by_its_code_sinks_and_skips_tests(repo):
    hypothesis, paths = build(repo, ["AC-T-003"], with_threat_model=True)
    assert paths == ["src/session.js"]
    assert "(technical abuse case, plugin)" in hypothesis and "- Step 1:" in hypothesis
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
    assert "  REPO-AC-031  Clerk releases a payout they also requested  (business abuse case, repository)" in lines
    assert "    Checks: Request a payout and release it with the same account." in lines
    assert any(line.startswith("  AC-T-003  ") and "(technical abuse case, plugin)" in line for line in lines)
    assert f"  Files ({len(paths)}):" in lines and all(f"    {p}" in lines for p in paths)


def _case_record(**fields) -> dict:
    record = {
        "title": fields.get("id", "case"),
        "source": "mandatory",
        "actor": "attacker",
        "goal": "",
        "prerequisite": "",
        "combined_risk": "Low",
        "chain_verdict": "inconclusive",
        "verification_complete": True,
        "unverified_steps": [],
        "matched_finding_ids": [],
        "blocking_mitigation_ids": [],
        "steps": [
            {
                "step": 1,
                "outcome": "",
                "verdict": "inconclusive",
                "finding_id": None,
                "evidence": None,
                "controls_found": [],
                "unverified": False,
            }
        ],
    }
    return {**record, **fields}


def _model(repo: Path, body: dict) -> Path:
    """Write ``body`` as a threat model that passes output validation.

    The tests name only the fields they exercise; the defaults below are what
    production composition always writes.
    """
    import yaml

    data = {
        "meta": {"schema_version": 1, "project": "Fixture", "generated": "2026-10-10T00:00:00Z", "mode": "full"},
        **{key: [] for key in ("components", "assets", "attack_surface", "trust_boundaries", "threats")},
        "security_controls": [],
        "mitigations": [],
        **body,
    }
    data["meta"].setdefault("model", "sonnet")
    for threat in data["threats"]:
        threat.setdefault("component", "C-01")
        threat.setdefault("stride", "Spoofing")
        threat.setdefault("scenario", "A test scenario with grounded evidence.")
        for key in ("likelihood", "impact", "risk"):
            threat.setdefault(key, "Low")
    for control in data["security_controls"]:
        control.setdefault("domain", "authentication")
    for mitigation in data["mitigations"]:
        mitigation.setdefault("priority", "P2")
        mitigation.setdefault(
            "threat_ids", [t["id"] for t in data["threats"] if mitigation["id"] in (t.get("mitigation_ids") or [])]
        )
    analysis = data.get("abuse_case_analysis")
    if analysis is not None:
        analysis.setdefault("status", "completed")
        analysis.setdefault("reason", None)
        analysis.setdefault("catalog_evaluated", [])
        analysis["cases"] = [_case_record(**case) for case in analysis.get("cases") or []]
    path = repo / "docs" / "security" / "threat-model.yaml"
    path.write_text(yaml.safe_dump(data))
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
                    "title": "Signature check in a removed file",
                    "cwe": "CWE-347",
                    "evidence": [{"file": "src/removed.js", "line": 3}],
                },
                {
                    "id": "T-011",
                    "title": "Unrelated reflected markup",
                    "cwe": "CWE-79",
                    "evidence": [{"file": "src/util.js", "line": 1}],
                },
            ],
            "abuse_case_analysis": {
                "cases": [
                    {
                        "id": "AC-T-003",
                        "chain_verdict": "inconclusive",
                        "matched_finding_ids": ["F-004"],
                        "steps": [
                            {
                                "step": 1,
                                "outcome": "",
                                "verdict": "inconclusive",
                                "finding_id": "F-004",
                                "evidence": None,
                                "controls_found": [],
                                "unverified": False,
                            }
                        ],
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


def test_a_multi_repository_model_is_refused_instead_of_mapped_onto_this_checkout(repo):
    model = _model(repo, {"meta": {"schema_version": 2}, "threats": [{"id": "F-001", "file": "src/session.js"}]})
    with pytest.raises(ach.AbuseCaseError, match="covers several repositories.*--isolated"):
        ach.build(repo, "HEAD", ["AC-T-003"], [], True, no_org_profile=True, threat_model_path=model)


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


def test_a_finding_that_only_shares_a_cwe_adds_no_ci_file(repo):
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("on: push\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "ci")
    model = _model(
        repo,
        {
            "threats": [
                {
                    "id": "T-002",
                    "title": "CI token",
                    "cwe": "CWE-347",
                    "evidence": [{"file": ".github/workflows/ci.yml", "line": 1}],
                }
            ]
        },
    )
    _, paths, summary = ach.build(repo, "HEAD", ["AC-T-003"], [], True, no_org_profile=True, threat_model_path=model)
    assert ".github/workflows/ci.yml" not in paths
    assert "related findings" not in summary


def test_a_threat_model_is_recommended_only_where_it_sharpens_the_check(repo):
    _, _, chain = ach.build(repo, "HEAD", ["AC-T-003"], [], False, no_org_profile=True)
    assert "  Recommendation: create a threat model first with /appsec-advisor:appsec-analyzer" in chain
    assert "    AC-T-003 has 2 steps; a threat model links the findings across them" in chain.splitlines()
    _, _, path_only = ach.build(repo, "HEAD", ["REPO-AC-031"], [], False, no_org_profile=True)
    assert "Recommendation" not in path_only
    model = _model(repo, {"threats": []})
    _, _, with_model = ach.build(repo, "HEAD", ["AC-T-003"], [], True, no_org_profile=True, threat_model_path=model)
    assert "Recommendation" not in with_model


def test_findings_carry_their_model_record_and_controls_in_checked_files_are_named(repo):
    model = _model(
        repo,
        {
            "threats": [
                {
                    "id": "T-010",
                    "title": "Insecure JWT verification",
                    "cwe": "CWE-347",
                    "evidence": [{"file": "src/session.js", "line": 1}],
                    "evidence_check": "verified",
                    "controls_in_place": "RS256 signing; verification does not pin it",
                    "mitigation_ids": ["M-001"],
                }
            ],
            "mitigations": [{"id": "M-001", "title": "Pin RS256 in JWT verification"}],
            "security_controls": [
                {
                    "control": "Token signing",
                    "effectiveness": "Unsafe",
                    "implementation": "src/session.js:1",
                    "assessment": "Key is hardcoded.",
                },
                {
                    "control": "Upload checks",
                    "effectiveness": "Weak",
                    "implementation": "src/session.json:4",
                    "assessment": "Elsewhere.",
                },
            ],
        },
    )
    hypothesis, _, summary = ach.build(
        repo, "HEAD", ["AC-T-003"], [], True, no_org_profile=True, threat_model_path=model
    )
    lines = hypothesis.splitlines()
    assert "- Related threat-model finding F-010: Insecure JWT verification (src/session.js:1)" in lines
    assert "  Evidence status in the model: verified." in lines
    assert "  Controls recorded: RS256 signing; verification does not pin it" in lines
    assert "  Planned mitigation: Pin RS256 in JWT verification" in lines
    assert "- Token signing (Unsafe): Key is hardcoded." in lines
    assert "Upload checks" not in hypothesis  # cites a different file
    assert "  Assessed controls in these files: Token signing (Unsafe)" in summary.splitlines()


def test_a_derived_case_is_checked_from_the_threat_model_that_records_it(repo):
    derived = {
        "id": "MODEL-AC-001",
        "title": "Clerk releases another clerk's payout",
        "source": "descriptive",
        "combined_risk": None,
        "check": "Check whether a clerk can release a payout another clerk requested.",
        "path_patterns": ["*payout*"],
    }
    unrecorded = {"id": "MODEL-AC-002", "title": "Older derived case", "source": "descriptive", "combined_risk": None}
    model = _model(repo, {"abuse_case_analysis": {"cases": [derived, unrecorded]}})

    hypothesis, paths, _ = ach.build(
        repo, "HEAD", ["MODEL-AC-001"], [], True, no_org_profile=True, threat_model_path=model
    )
    assert hypothesis.startswith("Abuse case MODEL-AC-001 (business abuse case, model-derived)")
    assert "- Check whether a clerk can release a payout another clerk requested." in hypothesis
    assert paths == ["src/finance/PayoutController.java"]
    with pytest.raises(ach.AbuseCaseError, match="does not record the derived check"):
        ach.build(repo, "HEAD", ["MODEL-AC-002"], [], True, no_org_profile=True, threat_model_path=model)
    with pytest.raises(ach.AbuseCaseError, match="without --isolated"):
        build(repo, ["MODEL-AC-001"])


def test_an_invalid_threat_model_is_not_cited_as_context(repo):
    model = repo / "docs" / "security" / "threat-model.yaml"
    model.write_text("components: []\nabuse_case_analysis: {status: completed, cases: []}\n")
    hypothesis, _, summary = ach.build(
        repo, "HEAD", ["AC-T-003"], [], True, no_org_profile=True, threat_model_path=model
    )
    assert "runs without a threat model" in hypothesis and "uses the supplied threat model" not in hypothesis
    assert "  Threat model: threat-model.yaml is unreadable or invalid and is not used" in summary.splitlines()


def test_chains_checked_together_number_their_steps_once_and_stay_within_the_step_limit(repo):
    hypothesis, _ = build(repo, ["AC-T-003", "AC-T-001"])
    numbers = [
        int(line.split(":")[0][len("- Step ") :]) for line in hypothesis.splitlines() if line.startswith("- Step ")
    ]
    assert numbers == list(range(1, len(numbers) + 1)) and len(numbers) > 2
    assert "- Step 1: AC-T-003: " in hypothesis and "- Step 3: AC-T-001: " in hypothesis
    alone, _ = build(repo, ["AC-T-003"])
    assert "- Step 1: JWT algorithm not pinned" in alone  # one chain keeps its plain step titles
    with pytest.raises(ach.AbuseCaseError, match="more than the 10 one check rates"):
        build(repo, [f"AC-T-00{n}" for n in range(1, 8)])


def test_a_located_file_the_snapshot_would_exclude_is_left_out_not_named(repo):
    (repo / "src" / "big_session.js").write_text("const c = jwt.verify(token, key)\n" + "// pad\n" * 12000)
    (repo / "src" / "zz_session.js").write_text("jwt.verify(a, b)\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "big")
    _, paths, summary = ach.build(repo, "HEAD", ["AC-T-003"], [], False, no_org_profile=True)
    assert "src/big_session.js" not in paths and "src/zz_session.js" in paths
    assert "  Not added, beyond the analyst's file limits: 1 located file(s)" in summary.splitlines()
    # A file the user names is passed on unchanged; the analyst reports it.
    _, named, _ = ach.build(repo, "HEAD", ["AC-T-003"], ["src/big_session.js"], False, no_org_profile=True)
    assert named[0] == "src/big_session.js"
