"""Policy ceilings are enforced before readers consume an individual risk."""

import json
from copy import deepcopy
from types import SimpleNamespace

import _severity_policy as policy
import pytest
import yaml
from _severity_rollup import register_severity, risk_distribution_counts
from build_threat_model_yaml import build_threats
from export_sarif import _build_rule
from triage_compute_ranking import (
    _bootstrap_yaml_from_merged,
    _compute_effective,
    _detect_verified_abuse_chains,
    _finding_cvss,
    compute_ranking,
    write_outputs,
)
from validate_intermediate import _check_cvss_eligibility, validate_threat_model_output, validate_threats_merged


@pytest.mark.parametrize("cwe, expected", [("CWE-778", "High"), ("CWE-548", "High"), ("CWE-601", "Medium")])
def test_policy_risk_reaches_register_summary_and_sarif(cwe, expected):
    original = {
        "t_id": "T-001",
        "component_id": "catalog",
        "cwe": cwe,
        "risk": "Critical",
        "title": "Unsafe application operation",
        "likelihood": "High",
        "impact": "High",
    }
    findings, _ = build_threats({"threats": [original]})
    finding = findings[0]
    assert original["risk"] == "Critical"
    assert finding["risk_before_policy"] == "Critical"
    assert register_severity(finding) == expected
    counts = risk_distribution_counts({"threats": findings})
    assert counts["critical"] == 0 and counts[expected.lower()] == 1
    assert _build_rule(finding, {})["properties"]["risk"] == expected


def test_normalization_preserves_valid_risks_and_is_idempotent():
    findings = [
        {"cwe": "CWE-89", "risk": "Critical"},
        {"cwe": "CWE-778", "risk": "Low"},
        {"cwe": "CWE-601", "risk": "Critical"},
    ]
    policy.normalize_risks(findings)
    before = deepcopy(findings)
    policy.normalize_risks(findings)
    assert findings == before
    assert findings[:2] == [{"cwe": "CWE-89", "risk": "Critical"}, {"cwe": "CWE-778", "risk": "Low"}]
    assert findings[2]["risk_before_policy"] == "Critical"


def test_abuse_case_priority_uses_assessed_risk_and_reach_without_context_feedback():
    remote = {"risk": "High", "breach_distance": 1, "impact": "High", "likelihood": "High"}
    protected = dict(remote, breach_distance=3, effective_severity="Critical", risk_before_policy="Critical")
    critical = dict(protected, risk="Critical")
    assert policy.abuse_case_priority([critical]) < policy.abuse_case_priority([remote])
    assert policy.abuse_case_priority([remote]) < policy.abuse_case_priority([protected])
    assert policy.abuse_case_risk([protected]) == "High"
    assert policy.abuse_case_risk([dict(critical, evidence_check="refuted"), remote]) == "High"
    assert policy.abuse_case_risk([{"risk": "Informational"}]) == "Informational"


@pytest.mark.parametrize("distance", [None, True, -1, 99, "1"])
def test_unknown_abuse_case_reach_never_wins_a_tie(distance):
    rated = {"risk": "High", "breach_distance": 4}
    assert policy.abuse_case_priority([rated]) < policy.abuse_case_priority([dict(rated, breach_distance=distance)])


def test_abuse_case_preserves_risk_normalized_with_companions_outside_the_chain():
    findings = [
        {"risk": "Critical", "cwe": "CWE-200", "threat_category_id": "TH-17"},
        {"risk": "High", "cwe": "CWE-522", "threat_category_id": "TH-17"},
        {"risk": "High", "cwe": "CWE-862", "threat_category_id": "TH-17"},
    ]
    policy.normalize_risks(findings)
    assert policy.abuse_case_risk(findings[:1]) == "Critical"


def test_builder_repairs_labels_before_policy_and_applies_floor_after_policy():
    finding = {
        "t_id": "T-001",
        "component_id": "events",
        "cwe": "CWE-778",
        "risk": "critical",
        "title": "Missing security event records",
        "likelihood": "High",
        "impact": "High",
    }
    findings, _ = build_threats({"threats": [finding]}, register_floor="high")
    assert findings[0]["risk"] == "High" and findings[0]["risk_before_policy"] == "Critical"
    findings, _ = build_threats({"threats": [finding]}, register_floor="critical")
    assert findings == []


def test_individual_ceilings_are_monotone_for_every_configured_class():
    caps, criteria = policy.load_policy()
    for entry in criteria["never_individual_critical"]:
        outputs = [policy.individual_risk({"cwe": entry["cwe"], "risk": risk}, caps, criteria) for risk in policy.RANK]
        ranks = [policy.RANK[risk] for risk in outputs]
        assert ranks == sorted(ranks), entry["cwe"]
        assert max(ranks) <= policy.RANK[entry["max_severity_individual"]]


def test_cap_exception_requires_all_companions_in_same_category():
    finding = {"cwe": "CWE-200", "risk": "Critical", "threat_category_id": "TH-17"}
    companions = [{"cwe": cwe, "threat_category_id": "TH-17"} for cwe in ("CWE-522", "CWE-862")]
    for peers, expected in [
        (companions, "Critical"),
        (companions[:1], "High"),
        ([dict(p, threat_category_id="TH-02") for p in companions], "High"),
        ([dict(p, evidence_check="refuted") for p in companions], "High"),
    ]:
        findings = [dict(finding), *peers]
        policy.normalize_risks(findings)
        assert findings[0]["risk"] == expected


@pytest.mark.parametrize("validator", [validate_threats_merged, validate_threat_model_output])
def test_artifact_gates_reject_uncorrected_policy_risk(validator):
    document = {"severity_policy_version": 1, "threats": [{"cwe": "CWE-778", "risk": "Critical"}]}
    before = deepcopy(document)
    ok, errors = validator(document)
    assert not ok and any("risk exceeds policy ceiling" in error for error in errors)
    assert document == before


def test_critical_exception_requires_critical_chain_not_just_keystone():
    caps, criteria = policy.load_policy()
    finding = {"cwe": "CWE-321", "risk": "Critical", "impact": "High"}
    assert _compute_effective(finding, "keystone", 2, caps, criteria, 2)[0] == "High"
    assert _compute_effective(finding, "keystone", 3, caps, criteria, 2)[0] == "Critical"
    assert _compute_effective(dict(finding, evidence_check="refuted"), "keystone", 3, caps, criteria, 2)[0] == "High"


def test_policy_correction_is_persisted_with_audit_flag_and_survives_repeat(tmp_path):
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump({"threats": [{"id": "T-001", "cwe": "CWE-778", "risk": "Critical"}]}))
    for _ in range(2):
        ranking = compute_ranking(tmp_path)
        write_outputs(tmp_path, ranking)
        finding = yaml.safe_load(path.read_text())["threats"][0]
        assert finding["risk"] == finding["effective_severity"] == "High"
        assert finding["risk_before_policy"] == "Critical"
        assert finding["triage_flags"] == ["TF-001"]


def test_cvss_original_assessment_survives_policy_cap():
    finding = {
        "source": "stride",
        "cwe": "CWE-601",
        "risk": "Critical",
        "evidence": {"file": "redirect.py", "line": 8},
        "cvss_v4": {"severity": "Critical", "base_score": 9.8},
    }
    policy.normalize_risks([finding])
    assert finding["risk"] == "Medium"
    assert _check_cvss_eligibility({"threats": [finding]}) == []
    assert _finding_cvss(finding) == 9.8


def test_cvss_zero_missing_legacy_and_invalid_values():
    assert _finding_cvss({"cvss_v4": {"base_score": 0}, "cvss": {"score": 8.1}}) == 0
    assert _finding_cvss({"cvss_v3_1": {"score": 8.1}}) == 8.1
    assert _finding_cvss({}) == 0
    for score in ("invalid", float("nan"), float("inf"), -1, 11):
        assert _finding_cvss({"cvss_v4": {"base_score": score}}) == 0


def test_audit_rating_cannot_excuse_an_unrelated_risk_gap():
    finding = {"cwe": "CWE-89", "risk": "Low", "risk_before_policy": "Critical"}
    assert any("does not explain" in error for error in policy.policy_errors([finding]))


def test_missing_policy_fails_instead_of_removing_caps(tmp_path, monkeypatch):
    policy.load_policy.cache_clear()
    monkeypatch.setattr(policy, "DATA_DIR", tmp_path)
    with pytest.raises(FileNotFoundError):
        policy.normalize_risks([{"cwe": "CWE-778", "risk": "Critical"}])
    policy.load_policy.cache_clear()


def test_bootstrap_retains_scoring_evidence(tmp_path):
    finding = {
        "t_id": "T-001",
        "cwe": "CWE-778",
        "risk": "Critical",
        "evidence_check": "ambiguous",
        "evidence": {"file": "events.py", "line": 14},
        "cvss_v4": {"base_score": 7.5},
        "threat_category_id": "TH-16",
    }
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": [finding]}))
    assert _bootstrap_yaml_from_merged(tmp_path)
    copied = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())["threats"][0]
    assert all(copied[key] == value for key, value in finding.items())
    ranking = compute_ranking(tmp_path)
    assert ranking["views"]["top_findings"]["findings_ranked"][0]["effective_severity"] == "High"


@pytest.mark.parametrize("state", ["refuted", "ambiguous", "missing"])
def test_unavailable_required_member_invalidates_chain(state):
    findings = [{"id": "T-001", "risk": "High"}]
    if state != "missing":
        findings.append({"id": "T-002", "risk": "Critical", "evidence_check": state})
    matches = {
        "matches": [
            {
                "abuse_case_id": "AC-T-001",
                "step_matches": [
                    {"required": True, "matched_finding_id": identifier} for identifier in ("T-001", "T-002")
                ],
            }
        ]
    }
    verdicts = {"verdicts": [{"abuse_case_id": "AC-T-001", "chain_verdict": "fully_viable"}]}
    assert _detect_verified_abuse_chains(findings, verdicts, matches) == []


def test_optional_unmatched_step_does_not_discard_verified_chain():
    matches = {
        "matches": [
            {
                "abuse_case_id": "AC-T-001",
                "step_matches": [
                    {"required": True, "matched_finding_id": "T-001"},
                    {"required": False, "matched_finding_id": None},
                ],
            }
        ]
    }
    verdicts = {"verdicts": [{"abuse_case_id": "AC-T-001", "chain_verdict": "fully_viable"}]}
    chains = _detect_verified_abuse_chains([{"id": "T-001", "risk": "High"}], verdicts, matches)
    assert len(chains) == 1 and chains[0]["severity"] == "High"


@pytest.mark.parametrize("id_key", ["id", "t_id"])
def test_category_keeps_the_highest_scored_finding_identity(tmp_path, id_key):
    findings = [
        {id_key: f"T-{index:03d}", "cwe": "CWE-79", "risk": "High", "impact": "High", "likelihood": likelihood}
        for index, likelihood in enumerate(("Low", "High"), 1)
    ]
    model = {"threats": findings, "threat_categories": [{"id": "TH-01", "findings": ["T-001", "T-002"]}]}
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(model))
    ranked = compute_ranking(tmp_path)
    assert ranked["views"]["top_threats"]["categories_ranked"][0]["top_finding_id"] == "T-002"


@pytest.mark.parametrize("filename", ["src/events.py", "handlers/trace.go"])
def test_merge_caps_before_capturing_instance_severity(tmp_path, filename):
    import merge_threats

    threats = [
        {
            "local_id": f"F-{index:03d}",
            "title": "Missing security event records",
            "cwe": "CWE-778",
            "stride": "Repudiation",
            "risk": "Critical",
            "likelihood": "High",
            "impact": "High",
            "source": "stride",
            "threat_category_id": "TH-16",
            "evidence": {"file": filename, "line": 12},
        }
        for index in (1, 2)
    ]
    (tmp_path / ".stride-events.json").write_text(json.dumps({"component_id": "events", "threats": threats}))
    args = SimpleNamespace(output_dir=str(tmp_path))
    assert merge_threats.cmd_collect(args) == 0
    assert merge_threats.cmd_finalize(args) == 0
    document = json.loads((tmp_path / ".threats-merged.json").read_text())
    assert document["severity_policy_version"] == 1
    merged = document["threats"]
    assert len(merged) == 1 and merged[0]["risk"] == "High"
    assert merged[0]["risk_before_policy"] == "Critical"
    assert merged[0]["instances"]
    assert all(instance["severity"] == "High" for instance in merged[0]["instances"])
    merged[0]["risk"] = "Critical"
    ok, errors = validate_threats_merged(document)
    assert not ok and any("risk exceeds policy ceiling" in error for error in errors)


def test_roles_cannot_be_borrowed_from_a_different_verified_chain(tmp_path):
    findings = [
        {"id": "T-001", "cwe": "CWE-321", "risk": "Medium"},
        {"id": "T-002", "cwe": "CWE-89", "risk": "Critical", "impact": "Critical"},
    ]
    matches = {
        "matches": [
            {"abuse_case_id": "AC-T-001", "step_matches": [{"matched_finding_id": "T-001", "required": True}]},
            {
                "abuse_case_id": "AC-T-002",
                "step_matches": [
                    {"matched_finding_id": "T-001", "required": False},
                    {"matched_finding_id": "T-002", "required": True},
                ],
            },
        ]
    }
    verdicts = {
        "verdicts": [
            {"abuse_case_id": match["abuse_case_id"], "chain_verdict": "fully_viable"} for match in matches["matches"]
        ]
    }
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump({"threats": findings}))
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(matches))
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(verdicts))
    ranking = compute_ranking(tmp_path)
    levels = {
        finding["id"]: finding["effective_severity"] for finding in ranking["views"]["top_findings"]["findings_ranked"]
    }
    assert levels == {"T-001": "High", "T-002": "Critical"}


def test_repeat_clears_old_unverified_chain_elevation(tmp_path):
    model = {
        "threats": [
            {
                "id": "T-001",
                "cwe": "CWE-79",
                "risk": "High",
                "effective_severity": "Critical",
                "compound_chain_ids": ["CC-01"],
                "chain_role": "keystone",
            }
        ]
    }
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(model))
    write_outputs(tmp_path, compute_ranking(tmp_path))
    finding = yaml.safe_load(path.read_text())["threats"][0]
    assert finding["effective_severity"] == "High"
    assert finding["compound_chain_ids"] == []
    assert finding["chain_role"] == "none"
