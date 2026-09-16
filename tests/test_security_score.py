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

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

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
    assert ss.indicator_for([], scanner="source-auth") == ss.indicators()[2]


def test_a_config_check_is_routed_by_its_family_not_its_cwe():
    """A missing workflow `permissions:` block carries CWE-862, which would put
    a CI setting next to broken object authorization in the application."""
    workflow = {
        "severity": "High",
        "cwe": ["CWE-862"],
        "check_id": "IAC-010",
        "iac_type": "github_workflow",
        "_scanner": "config-iac",
    }

    assert ss.finding_indicator(workflow) == "hardening"


def test_a_named_config_check_overrides_its_family():
    """Pinning and SBOM checks live in families that are otherwise hardening."""
    pinning = {"severity": "Medium", "check_id": "IAC-011", "iac_type": "github_workflow", "_scanner": "config-iac"}

    assert ss.finding_indicator(pinning) == "supply-chain"


def test_a_source_finding_is_still_routed_by_cwe():
    finding = {"severity": "High", "cwe": ["CWE-862"], "_scanner": "source-auth"}

    assert ss.finding_indicator(finding) == "access-control"


def test_low_severity_never_reaches_the_score():
    """Every Low check in the catalog states a build practice, not a weakness."""
    counts, raw = ss._tally([_finding("Low"), _finding("Low")])

    assert raw == 0.0
    assert "low" not in counts


def test_repeated_hits_of_one_config_check_are_damped():
    repeated = [
        {"severity": "High", "check_id": "IAC-010", "iac_type": "github_workflow", "_scanner": "config-iac"}
        for _ in range(14)
    ]
    single = repeated[:1]

    _, raw_many = ss._tally(repeated)
    _, raw_one = ss._tally(single)

    assert raw_one < raw_many < 4 * raw_one


def test_repeated_source_findings_are_not_damped():
    findings = [_hit("High", "AUTHZ-001", "Broken authorization", f"r{i}.ts") for i in range(10)]

    _, raw = ss._tally(findings)

    assert raw == 10 * ss.SEVERITY_WEIGHT["high"]


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
# The finding list
# --------------------------------------------------------------------------


def _hit(severity: str, check_id: str, title: str, file: str, line: int = 1, scanner: str = "source-auth") -> dict:
    return {
        "severity": severity,
        "check_id": check_id,
        "title": title,
        "file": file,
        "line": line,
        "_scanner": scanner,
    }


def test_the_list_groups_by_check_and_counts_the_instances():
    findings = [
        _hit("Critical", "AUTHZ-001", "Broken authorization — owner id", "a.ts", 1),
        _hit("Critical", "AUTHZ-001", "Broken authorization — owner id", "b.ts", 2),
        _hit("High", "SQLI-001", "SQL injection — concatenated query", "c.ts", 3),
    ]

    rows = ss.top_findings(findings)

    assert [(row["title"], row["count"]) for row in rows] == [
        ("Broken authorization", 2),
        ("SQL injection", 1),
    ]
    assert rows[0]["location"] == "a.ts:1"


def test_the_list_is_ordered_by_severity_then_frequency():
    findings = [_hit("High", "H", "High thing", "a.ts") for _ in range(5)]
    findings += [_hit("Critical", "C", "Critical thing", "b.ts")]
    findings += [_hit("High", "H2", "Other high thing", "c.ts") for _ in range(2)]

    assert [row["title"] for row in ss.top_findings(findings)] == [
        "Critical thing",
        "High thing",
        "Other high thing",
    ]


def test_the_list_is_capped():
    findings = [_hit("High", f"CHK-{i}", f"Thing {i}", "a.ts") for i in range(30)]

    assert len(ss.top_findings(findings)) == ss.TOP_FINDINGS


def test_a_config_check_uses_the_producer_violation_title():
    """Current producers name the violation separately from its mitigation."""
    finding = {
        "severity": "Medium",
        "title": "Dependency lockfile missing",
        "recommended_mitigation_title": "Commit package-lock.json; use `npm ci` in CI",
        "_scanner": "config-iac",
    }

    assert ss.finding_title(finding) == "Dependency lockfile missing"


def test_a_source_finding_is_named_by_its_weakness_class():
    assert ss.finding_title(_hit("High", "X", "SQL injection — request data in a query", "a.ts")) == "SQL injection"


def test_the_rendered_list_names_the_findings():
    result = ss.compute(_rules(*(["present"] * 5)), [])
    result["warnings"] = []
    result["top_findings"] = ss.top_findings([_hit("Critical", "A", "Broken authorization — x", "a.ts", 9)])

    text = ss.render_text(result)

    assert "most severe findings" in text
    assert "Broken authorization" in text
    assert "a.ts:9" in text


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
    assert "limited quick check" in text
    assert "no exposure context" in text
    assert "5 of 5 checks applied" in text


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


def test_only_the_headline_carries_a_band_glyph():
    result = ss.compute(_rules("present", "present", "present", "missing", "missing"), [])
    result["warnings"] = []

    lines = ss.render_text(result).splitlines()

    assert lines[0].startswith(ss._dot(result["score"]))
    assert not any(glyph in line for line in lines[1:] for _, glyph in ss._BANDS)


def test_the_band_glyph_follows_the_score():
    assert ss._dot(0) == "🔴"
    assert ss._dot(24) == "🔴"
    assert ss._dot(25) == "🟠"
    assert ss._dot(60) == "🟡"
    assert ss._dot(75) == "🟢"
    assert ss._dot(None) == ss._UNSCORED_DOT


def test_a_finding_is_named_with_its_severity():
    result = ss.compute(_rules(*(["present"] * 5)), [])
    result["warnings"] = []
    result["top_findings"] = ss.top_findings(
        [_hit("Critical", "A", "Broken authorization", "a.ts"), _hit("Medium", "B", "Weak thing", "b.ts")]
    )

    text = ss.render_text(result)

    assert "critical  Broken authorization" in text
    assert "medium    Weak thing" in text


def test_warnings_are_rendered():
    result = ss.compute(_rules(*(["present"] * 5)), [])
    result["warnings"] = ["source-auth: timed out"]

    assert "  source-auth: timed out" in ss.render_text(result)


@pytest.mark.parametrize(
    ("statuses", "expected_exit"),
    [(["present"] * 5, 0), (["present"] * 2, 2)],
)
def test_exit_code_signals_undetermined(monkeypatch, capsys, tmp_path, statuses, expected_exit):
    monkeypatch.setattr(ss, "collect", lambda repo, work: (_rules(*statuses), [], [], _complete()))

    assert ss.main(["--repo", str(tmp_path)]) == expected_exit
    assert capsys.readouterr().out.strip()


def test_missing_repository_is_an_error(capsys, tmp_path):
    assert ss.main(["--repo", str(tmp_path / "nope")]) == 1
    assert "not a directory" in capsys.readouterr().err


@pytest.mark.parametrize(
    "url",
    [
        "https://gitlab.com/example-team/service-a.git",
        "https://github.com/another-org/worker-b.git",
    ],
)
def test_https_repository_is_cloned_scanned_and_removed(monkeypatch, capsys, url):
    checkouts = []

    def fake_clone(argv, **kwargs):
        checkout = Path(argv[-1])
        checkout.mkdir()
        (checkout / "source.txt").write_text("scan me", encoding="utf-8")
        checkouts.append(checkout)
        assert argv[-2] == url
        assert argv[-3] == "--"
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        return subprocess.CompletedProcess(argv, 0, "", "")

    def fake_collect(repo, work):
        assert repo == checkouts[-1]
        assert (repo / "source.txt").read_text(encoding="utf-8") == "scan me"
        return _rules(*(["present"] * 5)), [], [], _complete()

    monkeypatch.setattr(ss.subprocess, "run", fake_clone)
    monkeypatch.setattr(ss, "collect", fake_collect)

    assert ss.main(["--repo", url, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["repo"] == url
    assert len(checkouts) == 1
    assert not checkouts[0].exists()


def test_local_repository_does_not_clone(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(ss.subprocess, "run", lambda *a, **kw: pytest.fail("local path triggered a clone"))
    monkeypatch.setattr(ss, "collect", lambda repo, work: (_rules(*(["present"] * 5)), [], [], _complete()))

    assert ss.main(["--repo", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["repo"] == str(tmp_path)


@pytest.mark.parametrize("statuses", [["present"] * 5, ["present"] * 2])
def test_yaml_contains_the_same_result_as_json(monkeypatch, capsys, tmp_path, statuses):
    findings = [_hit("High", "CHECK-1", "Unsafe rendering", "src/über.ts")]
    monkeypatch.setattr(
        ss, "collect", lambda repo, work: (_rules(*statuses), findings, ["scanner: partial result"], _complete())
    )

    json_exit = ss.main(["--repo", str(tmp_path), "--json"])
    json_output = capsys.readouterr()
    json_result = json.loads(json_output.out)
    yaml_exit = ss.main(["--repo", str(tmp_path), "--yaml"])
    yaml_output = capsys.readouterr().out

    assert yaml_exit == json_exit
    assert json_output.err == ""
    assert yaml.safe_load(yaml_output) == json_result
    assert "über.ts" in yaml_output


def test_json_and_yaml_cannot_be_requested_together(monkeypatch, capsys):
    monkeypatch.setattr(ss, "collect", lambda repo, work: pytest.fail("conflicting formats triggered a scan"))

    with pytest.raises(SystemExit) as exc:
        ss.main(["--json", "--yaml"])

    assert exc.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


@pytest.mark.parametrize("argument,exit_code", [("--help", 0), ("--unknown-option", 2)])
def test_help_and_unknown_options_exit_before_scanning(monkeypatch, capsys, argument, exit_code):
    monkeypatch.setattr(ss, "collect", lambda repo, work: pytest.fail("argument validation triggered a scan"))

    with pytest.raises(SystemExit) as exc:
        ss.main([argument])

    output = capsys.readouterr()
    assert exc.value.code == exit_code
    assert "usage:" in (output.out if exit_code == 0 else output.err)


@pytest.mark.parametrize(
    "url",
    [
        "http://gitlab.com/team/repo.git",
        "file:///tmp/repo.git",
        "https://user:token@gitlab.com/team/repo.git",
        "https://github.com/team/repo.git?ref=main",
        "https://gitlab.com/team/repo.git#",
        "https://gitlab.com/team/other repo.git",
        "https://[broken/team/repo.git",
        "https://gitlab.com/team/../repo.git",
        "https://github.com/team/%2e%2e/repo.git",
        "https://gitlab.com//team/repo.git",
        "https://gitlab.com\\@github.com/team/repo.git",
    ],
)
def test_unsafe_remote_url_is_rejected_before_clone(monkeypatch, capsys, url):
    monkeypatch.setattr(ss.subprocess, "run", lambda *a, **kw: pytest.fail("invalid URL triggered a clone"))

    assert ss.main(["--repo", url]) == 1
    assert "error:" in capsys.readouterr().err


def test_clone_failure_stops_without_scanning(monkeypatch, capsys):
    url = "https://gitlab.com/neutral/project.git"
    checkouts = []

    def fake_clone(argv, **kw):
        checkout = Path(argv[-1])
        checkout.mkdir()
        checkouts.append(checkout)
        return subprocess.CompletedProcess(argv, 128, "", "fatal: repository not found")

    monkeypatch.setattr(
        ss.subprocess,
        "run",
        fake_clone,
    )
    monkeypatch.setattr(ss, "collect", lambda repo, work: pytest.fail("failed clone was scanned"))

    assert ss.main(["--repo", url]) == 1
    assert "repository not found" in capsys.readouterr().err
    assert len(checkouts) == 1
    assert not checkouts[0].exists()


def test_clone_timeout_is_an_error(monkeypatch, capsys):
    url = "https://github.com/neutral/project.git"

    def fake_timeout(argv, **kw):
        raise subprocess.TimeoutExpired(argv, ss.CLONE_TIMEOUT_S)

    monkeypatch.setattr(ss.subprocess, "run", fake_timeout)
    monkeypatch.setattr(ss, "collect", lambda repo, work: pytest.fail("timed-out clone was scanned"))

    assert ss.main(["--repo", url]) == 1
    assert "timed out" in capsys.readouterr().err


def test_remote_checkout_with_escaping_symlink_is_not_scanned(monkeypatch, capsys, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("private data", encoding="utf-8")
    checkouts = []

    def fake_clone(argv, **kw):
        checkout = Path(argv[-1])
        checkout.mkdir()
        (checkout / "source.txt").symlink_to(outside)
        checkouts.append(checkout)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(ss.subprocess, "run", fake_clone)
    monkeypatch.setattr(ss, "collect", lambda repo, work: pytest.fail("escaping symlink was scanned"))

    assert ss.main(["--repo", "https://github.com/neutral/project.git"]) == 1
    assert "symlink outside the repository" in capsys.readouterr().err
    assert not checkouts[0].exists()


def test_clone_command_creates_a_working_tree(tmp_path):
    source = tmp_path / "neutral-source"
    source.mkdir()
    subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
    (source / "source.txt").write_text("scan me", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "add", "source.txt"], check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.test",
            "commit",
            "-m",
            "add neutral source",
        ],
        check=True,
        capture_output=True,
    )

    checkout = tmp_path / "checkout"
    ss._clone(str(source), checkout)

    assert (checkout / "source.txt").read_text(encoding="utf-8") == "scan me"


def _complete():
    return dict.fromkeys(ss.SCANNER_SCHEMAS, "complete")


@pytest.fixture(scope="module")
def scanner_outputs(tmp_path_factory):
    root = tmp_path_factory.mktemp("score-source")
    work = tmp_path_factory.mktemp("score-output")
    (root / "service.py").write_text(
        'import jwt\njwt.decode(token, algorithms=["HS256"], options={"verify_signature": False})\n'
    )
    _, findings, warnings, statuses = ss.collect(root, work)
    assert statuses == _complete(), warnings
    assert findings
    return {p.name: p.read_text() for p in work.iterdir() if p.is_file()}


@pytest.mark.parametrize("label", list(ss.SCANNER_SCHEMAS))
@pytest.mark.parametrize("corruption", ["missing", "list", "object", "numeric", "failed", "timeout", "stub"])
def test_invalid_or_failed_producer_withholds_headline(
    monkeypatch, tmp_path, capsys, scanner_outputs, label, corruption
):
    sidecars = dict(
        zip(
            ss.SCANNER_SCHEMAS,
            [".route-inventory.json", ".architecture-coverage.json", ".config-scan.json", ".source-auth-findings.json"],
        )
    )
    original_run = ss._run

    def run(argv, warnings, current):
        out = (
            Path(argv[argv.index("--output-dir") + 1])
            if "--output-dir" in argv
            else Path(argv[argv.index("--output") + 1]).parent
        )
        path = out / sidecars[current]
        path.write_text(scanner_outputs[path.name])
        if current != label:
            return True
        if corruption in {"failed", "timeout"}:

            def fail(*args, **kwargs):
                if corruption == "timeout":
                    raise subprocess.TimeoutExpired(args[0], 600)
                return subprocess.CompletedProcess(args[0], 1, "", "scanner failed")

            monkeypatch.setattr(ss.subprocess, "run", fail)
            return original_run(argv, warnings, current)
        if corruption == "missing":
            path.unlink()
        else:
            path.write_text(
                {
                    "list": "[]",
                    "object": "{}",
                    "numeric": '{"findings":42}',
                    "stub": '{"parse_error":"bad source", "findings":[]}',
                }[corruption]
            )
        return True

    monkeypatch.setattr(ss, "_run", run)
    assert ss.main(["--repo", str(tmp_path), "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["verdict"] == "incomplete"
    assert result["score"] is None
    assert result["scanner_status"][label] != "complete"
    assert result["warnings"]
    if label != "source-auth":
        assert result["top_findings"]
    schema = yaml.safe_load((ss.HERE.parent / "schemas/security-score.schema.yaml").read_text())
    ss.jsonschema.validate(result, schema)


def test_real_empty_scan_is_complete(tmp_path):
    repo, work = tmp_path / "repo", tmp_path / "work"
    repo.mkdir()
    work.mkdir()
    _, findings, warnings, statuses = ss.collect(repo, work)
    assert statuses == _complete(), warnings
    assert not [f for f in findings if f["_scanner"] == "source-auth"]


def test_sparse_coverage_keeps_findings_and_warnings_visible():
    findings = [_hit("Critical", "CHECK-2", "Untrusted command execution", "app.py")]
    result = ss.compute(_rules("present"), findings)
    result.update(top_findings=ss.top_findings(findings), warnings=["Scanner diagnostic"])
    text = ss.render_text(result)
    assert "undetermined" in text and "Untrusted command execution" in text
    assert "1 critical" in text and "Scanner diagnostic" in text


def test_comparability_tracks_coverage_not_control_status():
    first = ss.compute(_rules(*(["present"] * 5)), [])
    changed = ss.compute(_rules(*(["missing"] * 5)), [])
    additional = ss.compute(_rules(*(["present"] * 6)), [])
    assert first["comparability"] == changed["comparability"]
    assert first["comparability"]["coverage_fingerprint"] != additional["comparability"]["coverage_fingerprint"]


@pytest.mark.parametrize("name", ["outside.py", "linked/service.js"])
def test_local_score_rejects_external_symlinks(monkeypatch, tmp_path, capsys, name):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("secret")
    link = repo / name
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside)
    monkeypatch.setattr(ss, "collect", lambda *args: pytest.fail("unsafe repo scanned"))
    assert ss.main(["--repo", str(repo)]) == 1
    assert "symlink outside" in capsys.readouterr().err


def test_unscored_and_excluded_findings_are_prominent():
    critical = {**_hit("Critical", "CHECK-CRITICAL", "Dangerous sink", "app.py"), "cwe": ["CWE-89"]}
    low = _hit("Low", "CHECK-LOW", "Build practice", "Dockerfile")
    result = ss.compute(_rules(*(["present"] * 5)), [critical, low])
    assert result["score"] == 100
    assert result["unscored_findings"] == {"critical": 1}
    assert result["excluded_findings"] == {"low": 1}
    text = ss.render_text(result)
    assert "Findings without a scored baseline: 1 critical" in text
    assert "Findings excluded by severity policy: 1 low" in text
