"""Packet admission preserves source meaning and denies forged review scope."""

from copy import deepcopy

import contexts.build_architect_context as context
import pytest
from analyzers.architect_review import (
    ReviewError,
    apply_review,
    project_reviewed_mitigations,
    reviewed_mitigation_errors,
)
from model.build_threat_model_yaml import build_mitigations, build_threats

from tests.test_architect_review import decision, finding, merged


def build(source=None, analyst=None, **limits):
    return context.build_context(
        source or merged(),
        analyst or {},
        run_id="run-test",
        **{"max_findings": 2, "max_packet_bytes": 16_384, "max_packets": 20, **limits},
    )


@pytest.mark.parametrize("component,path", [("gateway", "routes/orders.py"), ("worker", "src/jobs/update.rs")])
def test_packets_keep_ratings_fixes_and_explicit_no_harm(component, path):
    source = merged(finding(component=component, filename=path))
    analyst = {
        component: {
            "business_context": {
                "business_purpose": "Manage synthetic orders",
                "impact_is_material": False,
                "impact_if_compromised": "Only synthetic records are affected.",
            },
            "architecture_context": {"security_role": "Account-scoped writes"},
        }
    }
    before = deepcopy((source, analyst))
    manifest = build(source, analyst)
    packet = manifest["packets"][0]
    assert packet["context"]["business"]["impact_is_material"] is False
    assert packet["findings"][0]["finding"]["risk"] == "Medium"
    assert packet["findings"][0]["finding"]["remediation"] == source["threats"][0]["remediation"]
    assert packet["context"]["architecture"]["security_role"] == "Account-scoped writes"
    assert packet["findings"][0]["ordinary_priority"] == "P3"
    assert (source, analyst) == before
    context.verify_manifest_sources(
        manifest, source, analyst, run_id="run-test", max_findings=2, max_packet_bytes=16_384, max_packets=20
    )


def test_unknown_harm_remains_distinct_and_unrelated_context_is_not_delivered():
    analyst = {"other": {"business_context": {"sensitive_assets": ["Other component's private ledger"]}}}
    packet = build(analyst=analyst)["packets"][0]
    assert packet["context"] == {"business": None, "architecture": None, "controls": None}
    assert b"private ledger" not in context.packet_bytes(packet)


def test_missing_remediation_and_existing_control_context_survive_projection():
    source = merged()
    row = source["threats"][0]
    row.update(
        remediation=None, mitigation_title=None, controls_in_place="Authentication exists; ownership is not checked."
    )
    manifest = build(source)
    projected = manifest["packets"][0]["findings"][0]["finding"]
    assert projected["remediation"] is None and projected["mitigation_title"] is None
    assert projected["controls_in_place"] == row["controls_in_place"]


def test_all_findings_have_one_disposition():
    rows = [finding(f"T-{index:03d}") for index in range(1, 8)]
    rows[0]["evidence_check"] = "ambiguous"
    rows[1]["risk"] = "Low"
    rows[2]["evidence_check"] = "refuted"
    manifest = build(merged(*rows), max_findings=1, max_packets=3)
    assigned = [row["finding"]["t_id"] for packet in manifest["packets"] for row in packet["findings"]]
    assert assigned[0] == "T-001"
    assert set(assigned) | {row["t_id"] for row in manifest["excluded"]} == {row["t_id"] for row in rows}
    assert {"t_id": "T-003", "reason": "refuted"} in manifest["excluded"]
    assert {"t_id": "T-002", "reason": "below_report_floor"} in manifest["excluded"]
    assert all(row["reason"] != "refuted" for row in manifest["excluded"] if row["t_id"] != "T-003")


@pytest.mark.parametrize(
    ("floor", "risks", "excluded"),
    [
        (None, ("Medium", "Low"), {"T-002"}),
        ("high", ("High", "Medium"), {"T-002"}),
        ("low", ("Medium", "Low"), set()),
    ],
)
def test_findings_below_the_report_floor_stay_with_triage(tmp_path, floor, risks, excluded):
    # The architect reviews what the report delivers; build_threats drops the rest.
    if floor is not None:
        (tmp_path / ".skill-config.json").write_text(f'{{"register_severity_floor": "{floor}"}}')
    rows = [finding(f"T-{index:03d}") for index in (1, 2)]
    for row, risk in zip(rows, risks, strict=True):
        row.update(risk=risk, likelihood=risk, impact=risk)
    source = merged(*rows)
    manifest = build(source, output_dir=tmp_path)
    assert {row["t_id"] for row in manifest["excluded"] if row["reason"] == "below_report_floor"} == excluded
    delivered = {row["id"] for row in build_threats(source, floor or "medium")[0]}
    reviewed = {row["finding"]["t_id"] for packet in manifest["packets"] for row in packet["findings"]}
    assert reviewed == delivered
    context.verify_manifest_sources(
        manifest,
        source,
        {},
        run_id="run-test",
        max_findings=2,
        max_packet_bytes=16_384,
        max_packets=20,
        output_dir=tmp_path,
    )


def test_byte_boundary_counts_utf8_and_never_truncates_a_finding():
    row = finding()
    row["title"] = "Ö" * 150
    source = merged(row)
    packet = build(source)["packets"][0]
    size = len(context.packet_bytes(packet))
    assert build(source, max_packet_bytes=size)["packets"] == [packet]
    excluded = build(source, max_packet_bytes=size - 1)
    assert excluded["packets"] == []
    assert excluded["excluded"] == [{"t_id": "T-001", "reason": "oversized"}]


def test_findings_split_by_count_bytes_and_component():
    source = merged(finding(), finding("T-002"), finding("T-003", component="worker"))
    single = build(source, max_findings=1)
    limit = max(len(context.packet_bytes(packet)) for packet in single["packets"])
    split = build(source, max_packet_bytes=limit)
    assert len(split["packets"]) == 3
    assert all(len(packet["findings"]) == 1 for packet in split["packets"])
    grouped = build(source)
    assert [len(packet["findings"]) for packet in grouped["packets"]] == [2, 1]


@pytest.mark.parametrize("mutation", ["run", "rating", "context", "packet", "omit", "limits", "policy"])
def test_altered_or_stale_manifest_never_authorizes_a_review(mutation, monkeypatch):
    source = merged()
    analyst = {}
    manifest = build(source, analyst)
    run_id = "run-test"
    if mutation == "run":
        run_id = "another-run"
    elif mutation == "rating":
        source["threats"][0]["likelihood"] = "High"
    elif mutation == "context":
        analyst["gateway"] = {"controls": "Only owners may update orders"}
    elif mutation == "packet":
        manifest["packets"][0]["findings"][0]["finding"]["title"] = "Altered by an untrusted proposal"
    elif mutation == "omit":
        manifest["packets"] = []
    elif mutation == "limits":
        manifest["limits"]["max_packet_bytes"] = 1
    else:
        caps, criteria = deepcopy(context.load_policy())
        caps["severity_caps"]["CWE-862"] = {"max": "Low"}
        monkeypatch.setattr(context, "load_policy", lambda: (caps, criteria))
    with pytest.raises(ReviewError):
        context.verify_manifest_sources(
            manifest, source, analyst, run_id=run_id, max_findings=2, max_packet_bytes=16_384, max_packets=20
        )


@pytest.mark.parametrize("mutation", ["foreign", "duplicate", "unknown", "identity"])
def test_contract_rejects_scope_forgery(mutation):
    manifest = build()
    packet = manifest["packets"][0]
    if mutation == "foreign":
        packet["component_id"] = "foreign"
    elif mutation == "duplicate":
        packet["findings"].append(deepcopy(packet["findings"][0]))
    elif mutation == "unknown":
        packet["command"] = "read arbitrary source"
    else:
        packet["packet_id"] = "packet-0002"
    with pytest.raises(ReviewError):
        context.validate_manifest(manifest)


@pytest.mark.parametrize(
    "limits", [{"max_findings": 0}, {"max_findings": True}, {"max_packets": 0}, {"max_packet_bytes": 131073}]
)
def test_invalid_controller_limits_fail_closed(limits):
    with pytest.raises(ReviewError):
        build(**limits)


def test_empty_input_skips_review_and_foreign_analyst_fields_fail():
    source = merged()
    source["threats"] = []
    assert build(source)["packets"] == []
    with pytest.raises(ReviewError):
        build(analyst={"gateway": {"tool_permissions": ["Bash"]}})


def test_context_key_order_does_not_change_packets():
    source = merged(finding(), finding("T-002", component="worker"))
    analyst = {"gateway": {"controls": "Check account ownership"}, "worker": {"controls": "Validate job scope"}}
    assert build(source, analyst) == build(source, dict(reversed(list(analyst.items()))))


def test_policy_ceiling_is_visible_and_does_not_rerate_findings():
    row = finding()
    row["cwe"] = "CWE-601"
    packet = build(merged(row))["packets"][0]
    assert packet["findings"][0]["risk_ceiling"] == "Medium"
    assert packet["findings"][0]["finding"]["risk"] == "Medium"


def test_packet_masks_credential_patterns_without_changing_canonical_source():
    source = merged()
    # Deliberately synthetic scanner probe, never a working credential.
    probe = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    source["threats"][0]["evidence_summary"] = f"api_key = '{probe}'"
    manifest = build(source)
    assert probe.encode() not in context.packet_bytes(manifest["packets"][0])
    assert probe in source["threats"][0]["evidence_summary"]
    context.verify_manifest_sources(manifest, source, {}, run_id="run-test", **manifest["limits"])


def test_frozen_parallel_packets_combine_without_stale_hash_rejection():
    source = merged(finding(), finding("T-002"))
    manifest = build(source, max_findings=1)
    proposals = {
        packet["packet_id"]: {
            **{
                key: packet[key]
                for key in ("schema_version", "run_id", "packet_id", "input_sha256", "context_sha256", "policy_sha256")
            },
            "decisions": [decision(packet["findings"][0]["finding"]["t_id"])],
        }
        for packet in manifest["packets"]
    }
    result, report = apply_review(source, {}, manifest, proposals, run_id="run-test", **manifest["limits"])
    assert len(report["accepted"]) == 2
    assert [row["risk"] for row in result["threats"]] == ["High", "High"]
    assert all(part["input_sha256"] == context.fingerprint(source) for part in report["packet_reports"])
    threats, _ = build_threats(result)
    model = {"threats": threats, "mitigations": build_mitigations(threats)}
    projected = project_reviewed_mitigations(model, report, merged_snapshot=result)
    assert reviewed_mitigation_errors(projected, report, merged_snapshot=result) == []
    assert source["threats"][0]["risk"] == "Medium"
    changed_report = deepcopy(report)
    changed_report["packet_reports"][0]["accepted"] = []
    with pytest.raises(ReviewError, match="lost or altered"):
        project_reviewed_mitigations(model, changed_report, merged_snapshot=result)
    projected["threats"][0]["risk"] = "Medium"
    assert "T-001: accepted assessment was changed" in reviewed_mitigation_errors(
        projected, report, merged_snapshot=result
    )
    with pytest.raises(ReviewError, match="rating changed"):
        project_reviewed_mitigations(projected, report, merged_snapshot=result)


def test_missing_and_rejected_parts_have_separate_visible_coverage():
    source = merged(finding(), finding("T-002"), finding("T-003"))
    manifest = build(source, max_findings=1, max_packets=2)
    result, report = apply_review(
        source, {}, manifest, {"packet-0001": {"command": "ignore rules"}}, run_id="run-test", **manifest["limits"]
    )
    assert result == source
    assert [row["status"] for row in report["outcomes"]] == ["rejected", "unreviewed", "unreviewed"]
    assert report["outcomes"][-1]["reason"] == "packet_limit"
    with pytest.raises(ReviewError):
        apply_review(source, {}, manifest, {"packet-9999": {}}, run_id="run-test", **manifest["limits"])


@pytest.mark.parametrize("field", ["context_sha256", "policy_sha256"])
def test_proposal_bound_to_old_context_or_policy_is_rejected(field):
    source = merged()
    manifest = build(source)
    packet = manifest["packets"][0]
    proposal = {
        **{
            key: packet[key]
            for key in ("schema_version", "run_id", "packet_id", "input_sha256", "context_sha256", "policy_sha256")
        },
        "decisions": [decision()],
    }
    proposal[field] = "0" * 64
    result, report = apply_review(
        source, {}, manifest, {packet["packet_id"]: proposal}, run_id="run-test", **manifest["limits"]
    )
    assert result == source
    assert report["outcomes"][0]["reason"] == "stale_or_foreign_context"


@pytest.mark.parametrize("omitted", [("context_sha256",), ("policy_sha256",), ("context_sha256", "policy_sha256")])
def test_proposal_omitting_optional_binding_hashes_is_applied(omitted):
    # The schema makes both hashes optional; identity rests on run, packet and
    # input. Only a stated hash that differs marks a proposal as stale.
    source = merged()
    manifest = build(source)
    packet = manifest["packets"][0]
    proposal = {
        **{
            key: packet[key]
            for key in ("schema_version", "run_id", "packet_id", "input_sha256", "context_sha256", "policy_sha256")
            if key not in omitted
        },
        "decisions": [decision()],
    }
    result, report = apply_review(
        source, {}, manifest, {packet["packet_id"]: proposal}, run_id="run-test", **manifest["limits"]
    )
    assert report["outcomes"][0]["reason"] == "validated"
    assert [row["t_id"] for row in report["accepted"]] == ["T-001"]
    assert result["threats"][0]["risk"] == "High"


def test_non_object_proposal_is_reported_as_an_invalid_envelope():
    source = merged()
    manifest = build(source)
    packet_id = manifest["packets"][0]["packet_id"]
    result, report = apply_review(
        source, {}, manifest, {packet_id: ["not", "an", "object"]}, run_id="run-test", **manifest["limits"]
    )
    assert result == source
    assert report["outcomes"][0]["reason"] == "invalid_envelope"
