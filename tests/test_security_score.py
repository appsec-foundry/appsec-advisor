"""
Tests for scripts/security_score.py.

Covers:
  * The denominator: `not_applicable` rules never count as passes.
  * The applicability floor: too few applicable rules yield `undetermined`,
    never a flattering number for a repository the catalog does not cover.
  * The finding penalty: monotone, saturating, blind to unknown severities.
  * Prior-assessment filtering: an old report stored in the repository does not
    inflate the findings of the repository it describes.
  * The rendered text always carries the qualifiers, so the number cannot
    travel without them.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import security_score as ss  # noqa: E402


def _rule(rule_id: str, status: str, domain: str = "IAM", evidence: list | None = None) -> dict:
    return {"rule_id": rule_id, "status": status, "domain": domain, "evidence": evidence or []}


def _rules(*statuses: str) -> list[dict]:
    return [_rule(f"ARCH-T-{i:03d}", status) for i, status in enumerate(statuses)]


def _finding(severity: str, file: str = "src/app.ts") -> dict:
    return {"severity": severity, "file": file}


# --------------------------------------------------------------------------
# Denominator
# --------------------------------------------------------------------------


def test_not_applicable_rules_leave_the_denominator():
    rules = _rules("present", "present", "present", "present", "present")
    rules += [_rule("ARCH-NA-001", "not_applicable"), _rule("ARCH-NA-002", "not_applicable")]

    result = ss.compute(rules, [])

    assert result["rules_total"] == 7
    assert result["rules_applicable"] == 5
    assert result["control_basis"] == 100


def test_status_points_are_graded():
    result = ss.compute(_rules("present", "partial", "weak", "missing", "anti_pattern"), [])

    # (1.0 + 0.5 + 0.25 + 0 + 0) / 5
    assert result["control_basis"] == 35
    assert result["score"] == 35


def test_unknown_status_is_ignored_rather_than_scored():
    rules = _rules("present", "present", "present", "present", "present")
    rules.append(_rule("ARCH-X-001", "something-new"))

    result = ss.compute(rules, [])

    assert result["rules_applicable"] == 5


# --------------------------------------------------------------------------
# Applicability floor
# --------------------------------------------------------------------------


def test_below_the_floor_the_verdict_is_undetermined():
    result = ss.compute(_rules("present", "present"), [])

    assert result["verdict"] == "undetermined"
    assert result["score"] is None
    assert result["control_basis"] is None
    assert "does not cover it" in result["reason"]


def test_repository_the_catalog_does_not_cover_scores_no_value():
    """All rules not applicable must not read as a perfect score."""
    rules = [_rule(f"ARCH-NA-{i:03d}", "not_applicable") for i in range(15)]

    result = ss.compute(rules, [])

    assert result["verdict"] == "undetermined"
    assert result["score"] is None


def test_exactly_at_the_floor_is_scored():
    result = ss.compute(_rules(*(["present"] * ss.MIN_APPLICABLE_RULES)), [])

    assert result["verdict"] == "scored"


# --------------------------------------------------------------------------
# Finding penalty
# --------------------------------------------------------------------------


def test_no_findings_means_no_penalty():
    penalty, counts = ss.finding_penalty([])

    assert penalty == 0.0
    assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_penalty_is_monotone_and_stays_below_the_cap():
    few, _ = ss.finding_penalty([_finding("High")] * 3)
    many, _ = ss.finding_penalty([_finding("Critical")] * 200)

    assert 0 < few < many < ss.PENALTY_CAP


def test_penalty_reads_severity_case_insensitively():
    upper, counts = ss.finding_penalty([_finding("CRITICAL")])
    lower, _ = ss.finding_penalty([_finding("critical")])

    assert upper == lower > 0
    assert counts["critical"] == 1


def test_unknown_severity_is_not_counted():
    penalty, counts = ss.finding_penalty([_finding("Informational"), _finding(""), {"file": "x"}])

    assert penalty == 0.0
    assert sum(counts.values()) == 0


def test_score_never_falls_below_zero():
    result = ss.compute(_rules(*(["anti_pattern"] * 5)), [_finding("Critical")] * 500)

    assert result["score"] == 0


# --------------------------------------------------------------------------
# Weakest domains
# --------------------------------------------------------------------------


def test_weakest_domains_are_ranked_and_exclude_the_clean_ones():
    rules = [
        _rule("ARCH-A-001", "anti_pattern", domain="DataProt"),
        _rule("ARCH-B-001", "partial", domain="AuthZ"),
        _rule("ARCH-C-001", "present", domain="IAM"),
        _rule("ARCH-D-001", "present", domain="IAM"),
        _rule("ARCH-E-001", "weak", domain="InputVal"),
    ]

    result = ss.compute(rules, [])

    domains = [row["domain"] for row in result["weakest_domains"]]
    assert domains == ["DataProt", "InputVal", "AuthZ"]
    assert "IAM" not in domains


# --------------------------------------------------------------------------
# Prior assessments stored in the repository
# --------------------------------------------------------------------------


def _make_assessment_output(repo: Path) -> None:
    out = repo / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.md").write_text("# report\n", encoding="utf-8")
    (out / "threat-model.yaml").write_text("threats: []\n", encoding="utf-8")


def test_findings_quoting_a_previous_report_are_dropped(tmp_path):
    _make_assessment_output(tmp_path)
    findings = [_finding("High", "src/app.ts"), _finding("Critical", "docs/security/threat-model.md")]

    kept, dropped = ss._drop_assessment_artifacts(findings, tmp_path)

    assert dropped == 1
    assert [f["file"] for f in kept] == ["src/app.ts"]


def test_rules_judged_only_on_a_previous_report_are_reported(tmp_path):
    _make_assessment_output(tmp_path)
    rules = [
        _rule("ARCH-A-001", "present", evidence=[{"file": "docs/security/threat-model.md", "line": 3}]),
        _rule("ARCH-B-001", "present", evidence=[{"file": "src/app.ts", "line": 1}]),
        _rule("ARCH-C-001", "present", evidence=[{"file": "docs/security/threat-model.md"}, {"file": "src/app.ts"}]),
        _rule("ARCH-D-001", "not_applicable"),
    ]

    assert ss._contaminated_rules(rules, tmp_path) == ["ARCH-A-001"]


# --------------------------------------------------------------------------
# Rendering and exit codes
# --------------------------------------------------------------------------


def test_rendered_score_always_carries_its_qualifiers():
    result = ss.compute(_rules("present", "present", "partial", "weak", "missing"), [_finding("High")])
    result["warnings"] = []

    text = ss.render_text(result)

    assert "quick scan" in text
    assert "no exposure context" in text
    assert "Not a risk rating" in text
    assert "rules applicable" in text


def test_undetermined_renders_the_reason_instead_of_a_number():
    result = ss.compute(_rules("present"), [])
    result["warnings"] = []

    text = ss.render_text(result)

    assert "undetermined" in text
    assert "/ 100" not in text.splitlines()[0]


def test_warnings_are_rendered(tmp_path):
    result = ss.compute(_rules("present", "present", "present", "present", "present"), [])
    result["warnings"] = ["source-auth: timed out"]

    assert "! source-auth: timed out" in ss.render_text(result)


@pytest.mark.parametrize(
    ("statuses", "expected_exit"),
    [(["present"] * 5, 0), (["present"] * 2, 2)],
)
def test_exit_code_signals_undetermined(monkeypatch, capsys, tmp_path, statuses, expected_exit):
    monkeypatch.setattr(ss, "collect", lambda repo, work: (_rules(*statuses), [], []))

    assert ss.main(["--repo", str(tmp_path)]) == expected_exit
    assert capsys.readouterr().out.strip()


def test_missing_repository_is_an_error(capsys, tmp_path):
    assert ss.main(["--repo", str(tmp_path / "nope")]) == 1
    assert "not a directory" in capsys.readouterr().err
