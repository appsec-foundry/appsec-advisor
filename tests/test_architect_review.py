"""Review core: corrections survive consumers without trusting proposals."""

from copy import deepcopy

import architect_review as review
import pytest
from _severity_rollup import risk_distribution_counts
from build_threat_model_yaml import apply_mitigation_overrides, build_mitigations, build_threats
from export_sarif import _build_rule
from hydrate_mitigation_details import hydrate
from validate_intermediate import validate_threats_merged


def finding(tid="T-001", component="gateway", filename="routes/orders.py"):
    return {
        "t_id": tid,
        "component_id": component,
        "component_name": component,
        "stride": "Tampering",
        "risk": "Medium",
        "likelihood": "Medium",
        "impact": "Medium",
        "title": "Missing ownership check before order changes",
        "cwe": "CWE-862",
        "evidence": {"file": filename, "line": 17},
        "source": "stride",
        "architectural_violation": False,
        "evidence_check": "verified",
        "threat_category_id": "TH-01",
        "mitigation_ids": ["M-001"],
        "mitigation_title": "Record rejected requests",
        "remediation": {
            "effort": "Low",
            "steps": ["Log attempts to update another customer's order."],
            "verification": "Check that logs were written.",
            "reference": "REQ-OWNERSHIP",
        },
    }


def merged(*findings):
    return {"version": 1, "generated_at": "2026-09-27T00:00:00Z", "threats": list(findings or [finding()])}


def decision(tid="T-001", *, rating=True, operation="replace"):
    row = {
        "t_id": tid,
        "assessment": "corrected" if rating else "unchanged",
        "remediation": "corrected",
        "reason": "The handler allows cross-account changes; logging does not prevent the write.",
        "fix": {
            "operation": operation,
            "value": {
                "title": "Enforce order ownership before writes",
                "effort": "Medium",
                "steps": [
                    "Resolve the order through the authenticated account's scope.",
                    "Reject a foreign order before changing its state.",
                ],
                "verification": "A foreign account receives 403 and leaves the order unchanged; its owner can still update it.",
            },
        },
    }
    if rating:
        row["rating"] = {"risk": "High", "likelihood": "High", "impact": "High"}
    return row


def apply(source, decisions, *, scope=None, **overrides):
    proposal = {
        "schema_version": 1,
        "run_id": "review-test-run",
        "packet_id": "packet-0001",
        "input_sha256": review.fingerprint(source),
        "decisions": decisions,
        **overrides,
    }
    return review.apply_corrections(
        source,
        proposal,
        run_id="review-test-run",
        packet_id="packet-0001",
        finding_ids=scope or [row["t_id"] for row in source["threats"]],
    )


def test_deeply_nested_proposal_is_rejected_without_mutation():
    source = merged()
    nested = []
    for _ in range(2000):
        nested = [nested]
    result, report = apply(source, nested)
    assert result == source
    assert report["outcomes"][0]["reason"] == "invalid_json_value"


@pytest.mark.parametrize("before_projection", [True, False])
def test_review_tasks_survive_corrected_fixes(before_projection):
    from emit_review_mitigations import _synthesize_evidence_review

    source = merged()
    source["threats"][0]["evidence_check"] = "ambiguous"
    changed, audit = apply(source, [decision()])
    threats, _ = build_threats(deepcopy(changed))
    model = {"threats": threats, "mitigations": build_mitigations(threats)}
    if not before_projection:
        model = review.project_reviewed_mitigations(model, audit, merged_snapshot=changed)
    cards = _synthesize_evidence_review(model, {"counter": 20}, {t["id"]: t for t in model["threats"]})
    assert len(cards) == 1
    original = deepcopy(cards[0])
    model["mitigations"].extend(cards)
    result = review.project_reviewed_mitigations(model, audit, merged_snapshot=changed)
    assert original in result["mitigations"]
    assert original["id"] in result["threats"][0]["mitigation_ids"]
    assert not review.reviewed_mitigation_errors(result, audit, merged_snapshot=changed)
    assert review.project_reviewed_mitigations(result, audit, merged_snapshot=changed) == result
    fix = next(card for card in result["mitigations"] if card.get("kind") == "fix")
    fix["verification"] = "Lost the accepted verification."
    assert review.reviewed_mitigation_errors(result, audit, merged_snapshot=changed)


def test_rating_correction_preserves_finding_fix_priority_policy():
    source = merged()
    row = decision()
    row.pop("fix")
    row["remediation"] = "unchanged"
    changed, audit = apply(source, [row])
    threats, _ = build_threats(changed)
    cards = build_mitigations(threats)
    cards[0].update(auto_source="finding-fix", effort="High", priority="P4")
    result = review.project_reviewed_mitigations(
        {"threats": threats, "mitigations": cards}, audit, merged_snapshot=changed
    )
    assert result["mitigations"][0]["priority"] == "P3"
    assert not review.reviewed_mitigation_errors(result, audit, merged_snapshot=changed)
    result["mitigations"][0]["priority"] = "P4"
    assert review.reviewed_mitigation_errors(result, audit, merged_snapshot=changed)


@pytest.mark.parametrize("component,filename", [("gateway", "routes/orders.py"), ("worker", "src/tasks/update.rs")])
def test_rating_and_fix_reach_register_priority_counts_and_sarif(component, filename):
    source = merged(finding(component=component, filename=filename))
    untouched = deepcopy(source)
    changed, audit = apply(source, [decision()])
    assert source == untouched
    assert validate_threats_merged(changed)[0]
    assert audit["accepted"][0]["rating"]["before"]["risk"] == "Medium"
    assert changed["threats"][0]["remediation"]["reference"] == "REQ-OWNERSHIP"

    threats, _ = build_threats(changed)
    cards = build_mitigations(threats)
    # Reproduce the downstream overwrite that previously defeated source edits.
    cards, _ = apply_mitigation_overrides(
        cards,
        {
            "additions": [
                {
                    "id": "M-001",
                    "title": "Record rejected requests",
                    "threat_ids": ["T-001"],
                    "priority": "P4",
                    "verification": "Check that logs were written.",
                }
            ]
        },
    )
    legacy = {"threats": threats, "mitigations": cards}
    assert review.reviewed_mitigation_errors(legacy, audit, merged_snapshot=changed)
    result = review.project_reviewed_mitigations(legacy, audit, merged_snapshot=changed)
    hydrate(result)
    assert not review.reviewed_mitigation_errors(result, audit, merged_snapshot=changed)
    assert result["mitigations"][0]["priority"] == "P2"
    assert result["mitigations"][0]["steps"] == decision()["fix"]["value"]["steps"]
    assert risk_distribution_counts(result)["high"] == 1
    rule = _build_rule(result["threats"][0], {row["id"]: row for row in result["mitigations"]})
    assert rule["properties"]["risk"] == "High"


@pytest.mark.parametrize("operation", ["add", "replace", "revise"])
def test_remediation_can_change_without_rating_or_evidence_change(operation):
    source = merged()
    if operation == "add":
        source["threats"][0].pop("remediation")
    changed, audit = apply(source, [decision(rating=False, operation=operation)])
    assert audit["outcomes"][0]["status"] == "accepted"
    before, after = source["threats"][0], changed["threats"][0]
    for key in ("risk", "likelihood", "impact", "evidence", "evidence_check"):
        assert before[key] == after[key]


def test_unchanged_negative_and_unresolved_fix_keep_values_and_distinct_coverage():
    source = merged(finding(), finding("T-002"))
    changed, audit = apply(
        source,
        [
            {"t_id": "T-001", "assessment": "unchanged", "remediation": "unchanged"},
            {
                "t_id": "T-002",
                "assessment": "unchanged",
                "remediation": "unresolved",
                "reason": "Deployment ownership is unknown.",
            },
        ],
    )
    assert changed == source and not audit["accepted"]
    assert audit["outcomes"][1]["assessment"] == "unchanged"
    assert audit["outcomes"][1]["remediation"] == "unresolved"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row.update(path="../../foreign.json"),
        lambda row: row["rating"].update(risk="Urgent"),
        lambda row: row["rating"].update(cvss_v4={"base_score": 10}),
        lambda row: row.update(evidence_check="verified"),
        lambda row: row["fix"]["value"].update(steps=[]),
        lambda row: row["fix"]["value"].update(verification=" "),
        lambda row: row["fix"]["value"].update(priority="P4"),
        lambda row: row.update(assessment="unchanged"),
        lambda row: row.pop("reason"),
    ],
)
def test_invalid_transaction_retains_whole_finding_and_accepts_independent_peer(mutation):
    source = merged(finding(), finding("T-002"))
    invalid = decision()
    mutation(invalid)
    result, audit = apply(source, [invalid, decision("T-002")])
    assert result["threats"][0] == source["threats"][0]
    assert result["threats"][1]["risk"] == "High"
    assert audit["outcomes"][0]["status"] == "rejected"


@pytest.mark.parametrize(
    "overrides",
    [
        {"run_id": "another-run"},
        {"packet_id": "packet-0002"},
        {"input_sha256": "0" * 64},
        {"command": "write elsewhere"},
    ],
)
def test_stale_or_foreign_envelope_never_changes_canonical_data(overrides):
    source = merged()
    result, audit = apply(source, [decision()], **overrides)
    assert result == source and audit["outcomes"][0]["status"] == "rejected"


def test_duplicate_and_foreign_ids_are_not_last_writer_wins():
    source = merged(finding(), finding("T-002"))
    result, audit = apply(source, [decision(), decision()])
    assert result == source and audit["outcomes"][0]["status"] == "rejected"
    assert audit["outcomes"][1]["status"] == "unreviewed"
    result, audit = apply(source, [decision("T-002")], scope=["T-001"])
    assert result == source and audit["outcomes"][0]["reason"] == "foreign_or_unidentified_finding"


def test_invalid_required_input_fails_instead_of_becoming_optional_rejection():
    source = merged()
    source["threats"][0]["risk"] = "invalid"
    with pytest.raises(review.ReviewError, match="canonical"):
        apply(source, [decision()])


def test_cap_is_applied_and_previous_policy_metadata_is_recomputed():
    source = merged()
    source["threats"][0].update(cwe="CWE-601", risk_before_policy="High")
    row = decision()
    row["rating"]["risk"] = "Critical"
    result, audit = apply(source, [row])
    assert result["threats"][0]["risk"] == "Medium"
    assert result["threats"][0]["risk_before_policy"] == "Critical"
    assert audit["accepted"][0]["rating"]["requested"]["risk"] == "Critical"
    assert audit["accepted"][0]["rating"]["after"]["risk"] == "Medium"


def test_shared_card_preserves_other_finding_and_does_not_merge_different_fixes():
    source = merged(finding(), finding("T-002"))
    result, audit = apply(source, [decision(rating=False)], scope=["T-001"])
    threats, _ = build_threats(result)
    model = {"threats": threats, "mitigations": build_mitigations(threats)}
    projected = review.project_reviewed_mitigations(model, audit, merged_snapshot=result)
    assert projected["mitigations"][0]["threat_ids"] == ["T-002"]
    assert projected["threats"][1]["mitigation_ids"] == ["M-001"]
    assert projected["mitigations"][1]["threat_ids"] == ["T-001"]
    projected["mitigations"][1]["steps"].append("Restore the ineffective logging-only fix.")
    assert review.reviewed_mitigation_errors(projected, audit, merged_snapshot=result)


def test_cvss_changes_are_rejected_until_a_real_scorer_exists():
    source = merged()
    row = decision()
    row["rating"]["cvss_vector"] = "CVSS:4.0/AV:N"
    result, audit = apply(source, [row])
    assert result == source and audit["outcomes"][0]["status"] == "rejected"


def test_projection_is_idempotent_and_rejects_another_snapshot():
    source = merged()
    changed, audit = apply(source, [decision()])
    threats, _ = build_threats(changed)
    model = {"threats": threats, "mitigations": build_mitigations(threats)}
    projected = review.project_reviewed_mitigations(model, audit, merged_snapshot=changed)
    assert review.project_reviewed_mitigations(projected, audit, merged_snapshot=changed) == projected
    with pytest.raises(review.ReviewError, match="snapshot"):
        review.project_reviewed_mitigations(model, audit, merged_snapshot=source)
    assert review.reviewed_mitigation_errors(projected, audit, merged_snapshot=source)


def test_a_rating_only_change_rederives_stale_priority_without_changing_the_fix():
    source = merged()
    row = decision()
    del row["fix"]
    row["remediation"] = "unchanged"
    changed, audit = apply(source, [row])
    threats, _ = build_threats(changed)
    cards = build_mitigations(threats)
    cards[0].update(priority="P4", verification="Existing check")
    projected = review.project_reviewed_mitigations(
        {"threats": threats, "mitigations": cards}, audit, merged_snapshot=changed
    )
    assert projected["mitigations"][0]["priority"] == "P2"
    assert projected["mitigations"][0]["verification"] == "Existing check"


def test_unproven_finding_retains_its_unproven_state_and_no_score():
    source = merged()
    source["threats"][0].update(evidence_tier="insecure-practice", evidence_check="ambiguous")
    changed, audit = apply(source, [decision()])
    assert audit["outcomes"][0]["status"] == "accepted"
    assert changed["threats"][0]["evidence_tier"] == "insecure-practice"
    assert changed["threats"][0]["evidence_check"] == "ambiguous"
    assert "cvss_v4" not in changed["threats"][0]


def test_oversized_output_and_refuted_findings_remain_unchanged():
    source = merged()
    row = decision()
    row["reason"] = "x" * (review.MAX_PROPOSAL_BYTES + 1)
    result, audit = apply(source, [row])
    assert result == source and audit["outcomes"][0]["reason"] == "proposal_too_large"
    source["threats"][0]["evidence_check"] = "refuted"
    result, audit = apply(source, [decision()])
    assert result == source and audit["outcomes"][0]["reason"] == "refuted_finding"
