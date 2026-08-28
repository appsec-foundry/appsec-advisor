"""
Tests for scripts/security_score.py.

Covers:
  * The denominator: `not_applicable` rules never count as passes.
  * Control credit: a rule that only raised a hypothesis is not half a control.
  * Indicator routing: rules and findings reach the same indicator through the
    catalog, and an unroutable config finding still lands in hardening.
  * The applicability floor: too few applicable rules yield `undetermined`,
    never a flattering number for a repository the catalog does not cover.
  * The aggregate: the weaker half decides, and an indicator without a rule is
    shown but not scored.
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


def _rule(rule_id: str, status: str, decision: str = "emit_control_only", evidence: list | None = None) -> dict:
    return {"rule_id": rule_id, "status": status, "decision": decision, "evidence": evidence or []}


def _rules(*statuses: str) -> list[dict]:
    """Applicable rules with no catalog CWE — they all land in one indicator."""
    return [_rule(f"ARCH-T-{i:03d}", status) for i, status in enumerate(statuses)]


def _finding(severity: str, file: str = "src/app.ts", cwe: str | None = None, scanner: str = "source-auth") -> dict:
    return {"severity": severity, "file": file, "cwe": cwe, "_scanner": scanner}


# --------------------------------------------------------------------------
# Denominator and control credit
# --------------------------------------------------------------------------


def test_not_applicable_rules_leave_the_denominator():
    rules = _rules(*(["present"] * 5))
    rules += [_rule("ARCH-NA-001", "not_applicable"), _rule("ARCH-NA-002", "not_applicable")]

    result = ss.compute(rules, [])

    assert result["checks_total"] == 7
    assert result["checks_applicable"] == 5
    assert result["score"] == 100


def test_status_points_are_graded():
    assert ss.rule_points(_rule("R", "present")) == 1.0
    assert ss.rule_points(_rule("R", "partial")) == 0.5
    assert ss.rule_points(_rule("R", "weak")) == 0.25
    assert ss.rule_points(_rule("R", "missing")) == 0.0


def test_a_hypothesis_is_not_half_a_control():
    """The juice-shop case: the injection rules report `partial` because the
    deterministic layer cannot prove the flow. Half credit would read as
    halfway controlled."""
    hypothesis = _rule("ARCH-SQLI-001", "partial", decision="emit_hypothesis_only")
    control = _rule("ARCH-SQLI-001", "partial", decision="emit_control_only")

    assert ss.rule_points(hypothesis) == 0.25
    assert ss.rule_points(control) == 0.5


def test_a_threat_candidate_earns_no_control_credit():
    assert ss.rule_points(_rule("R", "present", decision="emit_control_and_threat_candidate")) == 0.0


def test_unknown_status_is_ignored_rather_than_scored():
    rules = _rules(*(["present"] * 5))
    rules.append(_rule("ARCH-X-001", "something-new"))

    assert ss.compute(rules, [])["checks_applicable"] == 5


# --------------------------------------------------------------------------
# Indicator routing
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cwe", "expected"),
    [
        ("CWE-89", "output-handling"),
        ("CWE-79", "frontend-security"),
        ("CWE-862", "access-control"),
        ("CWE-306", "authentication"),
        ("CWE-798", "secrets-crypto"),
        ("CWE-829", "supply-chain"),
        ("CWE-20", "input-validation"),
        ("CWE-319", "hardening"),
        ("CWE-942", "frontend-security"),
    ],
)
def test_cwes_route_to_their_indicator(cwe, expected):
    assert ss.indicator_for([cwe]) == expected


def test_an_unroutable_config_finding_is_hardening():
    assert ss.indicator_for(["CWE-99999"], scanner="config-iac") == "hardening"


def test_an_unroutable_source_finding_falls_through_to_the_default():
    assert ss.indicator_for([], scanner="source-auth") == ss.indicators()[4]


def test_rules_and_findings_meet_in_the_same_indicator():
    rules = _rules(*(["present"] * 4)) + [_rule("ARCH-SQLI-001", "present")]
    findings = [_finding("Critical", cwe="CWE-89")]

    categories = {row["indicator"]: row for row in ss.compute(rules, findings)["categories"]}

    assert categories["output-handling"]["checks"] == 1
    assert categories["output-handling"]["findings"] == 1


# --------------------------------------------------------------------------
# Applicability floor
# --------------------------------------------------------------------------


def test_below_the_floor_the_verdict_is_undetermined():
    result = ss.compute(_rules("present", "present"), [])

    assert result["verdict"] == "undetermined"
    assert result["score"] is None
    assert "does not cover it" in result["reason"]


def test_repository_the_catalog_does_not_cover_scores_no_value():
    """All rules not applicable must not read as a perfect score."""
    rules = [_rule(f"ARCH-NA-{i:03d}", "not_applicable") for i in range(15)]

    result = ss.compute(rules, [])

    assert result["verdict"] == "undetermined"
    assert result["score"] is None


def test_exactly_at_the_floor_is_scored():
    assert ss.compute(_rules(*(["present"] * ss.MIN_APPLICABLE_RULES)), [])["verdict"] == "scored"


# --------------------------------------------------------------------------
# Findings and the aggregate
# --------------------------------------------------------------------------


def test_no_findings_means_no_penalty():
    assert ss.finding_penalty(0.0) == 0.0


def test_penalty_is_monotone_and_stays_below_the_cap():
    assert 0 < ss.finding_penalty(4.0) < ss.finding_penalty(400.0) < ss.PENALTY_CAP


def test_severity_is_read_case_insensitively():
    counts, raw = ss._tally([_finding("CRITICAL"), _finding("critical")])

    assert counts["critical"] == 2
    assert raw == 2 * ss.SEVERITY_WEIGHT["critical"]


def test_unknown_severity_is_not_counted():
    counts, raw = ss._tally([_finding("Informational"), _finding(""), {"file": "x"}])

    assert raw == 0.0
    assert sum(counts.values()) == 0


def test_findings_outweigh_a_control_that_claims_to_exist():
    """An indicator carrying many confirmed findings is not rescued by a rule
    reporting the control as present."""
    rules = _rules(*(["present"] * 4)) + [_rule("ARCH-SQLI-001", "present")]
    findings = [_finding("Critical", cwe="CWE-89") for _ in range(20)]

    categories = {row["indicator"]: row for row in ss.compute(rules, findings)["categories"]}

    assert categories["output-handling"]["score"] <= 25


def test_an_indicator_without_a_rule_is_shown_but_not_scored():
    rules = _rules(*(["present"] * 5))
    findings = [_finding("High", cwe="CWE-89")]

    categories = {row["indicator"]: row for row in ss.compute(rules, findings)["categories"]}

    assert categories["output-handling"]["score"] is None
    assert categories["output-handling"]["findings"] == 1


def test_the_weaker_half_decides_the_headline():
    rules = [
        _rule("ARCH-SQLI-001", "missing"),  # output-handling   → 0
        _rule("ARCH-XSS-001", "missing"),  # frontend-security  → 0
        _rule("ARCH-AUTHZ-001", "present"),  # access-control   → 100
        _rule("ARCH-JWT-001", "present"),  # authentication     → 100
        _rule("ARCH-SUPPLY-001", "present"),  # supply-chain    → 100
    ]

    result = ss.compute(rules, [])

    assert sorted(row["score"] for row in result["categories"]) == [0, 0, 100, 100, 100]
    # Mean of the weaker half (0, 0, 100), not the mean of all five.
    assert result["score"] == 33


def test_score_never_falls_below_zero():
    result = ss.compute(_rules(*(["missing"] * 5)), [_finding("Critical") for _ in range(50)])

    assert result["score"] == 0


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

    assert ss.CAVEAT in text.splitlines()[0]
    assert "quick scan" in text
    assert "no exposure context" in text
    assert "5 of 5 checks" in text


def test_every_scored_indicator_row_is_written_out_of_100():
    rules = _rules(*(["present"] * 4)) + [_rule("ARCH-SQLI-001", "missing")]
    result = ss.compute(rules, [])
    result["warnings"] = []

    rows = [line for line in ss.render_text(result).splitlines() if line.startswith("  ") and "/100" in line]

    assert len(rows) == len(result["categories"])


def test_an_unscored_indicator_says_so_instead_of_showing_a_number():
    result = ss.compute(_rules(*(["present"] * 5)), [_finding("High", cwe="CWE-89")])
    result["warnings"] = []

    row = next(line for line in ss.render_text(result).splitlines() if "Output Handling" in line)

    assert "no check" in row
    assert "/ 100" not in row


def test_undetermined_renders_the_reason_instead_of_a_number():
    result = ss.compute(_rules("present"), [])
    result["warnings"] = []

    text = ss.render_text(result)

    assert "undetermined" in text
    assert ss.CAVEAT in text
    assert "/100" not in text


def test_an_indicator_row_names_what_its_checks_saw_and_what_was_found():
    rules = _rules(*(["present"] * 4)) + [_rule("ARCH-SQLI-001", "partial", decision="emit_hypothesis_only")]
    result = ss.compute(rules, [_finding("Critical", cwe="CWE-89"), _finding("High", cwe="CWE-89")])
    result["warnings"] = []

    row = next(line for line in ss.render_text(result).splitlines() if "Output Handling" in line)

    assert "1 hypothesis" in row
    assert "2 findings" in row


def test_an_indicator_without_findings_says_so():
    result = ss.compute(_rules(*(["present"] * 5)), [])
    result["warnings"] = []

    assert "no findings" in ss.render_text(result)


def test_rule_signal_separates_a_control_from_a_hypothesis():
    assert ss.rule_signal(_rule("R", "present")) == "control"
    assert ss.rule_signal(_rule("R", "partial")) == "partial control"
    assert ss.rule_signal(_rule("R", "partial", decision="emit_hypothesis_only")) == "hypothesis"
    assert ss.rule_signal(_rule("R", "anti_pattern", decision="emit_control_and_threat_candidate")) == "anti-pattern"
    assert ss.rule_signal(_rule("R", "missing")) == "no control"


def test_warnings_are_rendered():
    result = ss.compute(_rules(*(["present"] * 5)), [])
    result["warnings"] = ["source-auth: timed out"]

    assert "  source-auth: timed out" in ss.render_text(result)


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
