"""The canonical assembler preserves scoped evidence and existing policy gates."""

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from model.build_threat_model_yaml import build_assessment_model
from model.merge_threats import merge_assessment
from shared.assessment_sources import presentation_model
from validators.validate_intermediate import validate_threat_model_output

from tests.test_multi_repo_analysis import stride
from tests.test_multi_repo_boundaries import crossing_input

ROOT = Path(__file__).resolve().parents[1]


def inputs(tmp_path, *, names=("edge", "service")):
    scope, components, receipt, flows, _ = crossing_input(tmp_path, names=names)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    documents, reviews = [], []
    for component, evidence in zip(components["components"], flows["data_flows"][0]["evidence"], strict=True):
        document = stride(component, evidence, identity)
        document["threats"][0]["cwe"] = "CWE-20"
        documents.append(document)
        reviews.append(
            dict(
                **identity,
                decisions=[
                    dict(
                        local_id="issue-1",
                        verdict="verified",
                        reason="Source confirms the practice.",
                        evidence=[evidence],
                    )
                ],
            )
        )
    merged = merge_assessment(scope, components, documents, reviews, boundaries=[])
    return scope, dict(
        skill_cfg=dict(
            assessment_scope="multiple-repositories",
            source_scope_sha256=components["source_scope_sha256"],
            mode="full",
            stride_model="test",
            invocation_args="--repo /private/root --token hidden",
        ),
        architecture=dict(components=components, finalization=receipt, data_flows=flows, assets=[]),
        controls=[],
        boundaries=dict(schema_version=3, source_scope_sha256=components["source_scope_sha256"], trust_boundaries=[]),
        merged=merged,
        plugin_root=ROOT,
        project="Combined system",
    )


@pytest.mark.parametrize("names", [("edge", "service"), ("gateway", "processor")])
def test_assembler_preserves_all_roots_and_qualified_nested_findings(tmp_path, names):
    scope, kwargs = inputs(tmp_path, names=names)
    original = copy.deepcopy(kwargs)
    document, _ = build_assessment_model(scope, **kwargs)
    assert kwargs == original
    assert validate_threat_model_output(document)[0]
    assert document["meta"]["schema_version"] == 2
    assert "git" not in document["meta"] and "repo_url" not in document["meta"]
    assert "invocation" not in document["meta"] and "enrichment_pass" not in document["meta"]
    assert document["source_inventory"] == scope.inventory()
    assert len(document["threats"]) == len(document["components"]) == 2
    anchors = [t["evidence"][0] for t in document["threats"]]
    assert len({e["repository_id"] for e in anchors}) == 2
    assert {e["file"] for e in anchors} == {"app.py"}
    assert document["abuse_case_analysis"]["status"] == "not_run"
    assert document["business_context_trace"]["status"] == "not_configured"
    assert document["mitigations"]
    for component in document["components"]:
        assert component["threat_ids"] == [t["id"] for t in document["threats"] if t["component"] == component["id"]]
    view = presentation_model(document)
    assert len({t["evidence"][0]["file"] for t in view["threats"]}) == 2
    assert not scope.output.exists()


@pytest.mark.parametrize(
    "kind", ["scope", "fingerprint", "owner", "hash", "component", "duplicate", "requirements", "business", "project"]
)
def test_assembler_rejects_stale_foreign_or_unrepresented_inputs(tmp_path, kind):
    scope, kwargs = inputs(tmp_path)
    if kind == "scope":
        kwargs["skill_cfg"]["source_scope_sha256"] = "0" * 64
    elif kind == "fingerprint":
        kwargs["merged"]["component_inventory_fingerprint"] = "sha256:" + "0" * 64
    elif kind == "owner":
        kwargs["merged"]["threats"][0]["evidence"]["repository_id"] = kwargs["merged"]["threats"][1]["evidence"][
            "repository_id"
        ]
    elif kind == "hash":
        kwargs["merged"]["threats"][0]["evidence"]["sha256"] = "0" * 64
    elif kind == "component":
        kwargs["merged"]["threats"][0]["component_id"] = "foreign-component"
    elif kind == "duplicate":
        kwargs["merged"]["threats"][1]["t_id"] = kwargs["merged"]["threats"][0]["t_id"]
    elif kind == "requirements":
        kwargs["skill_cfg"]["check_requirements"] = True
    elif kind == "business":
        kwargs["skill_cfg"]["business_context_source"] = "configured-context"
    else:
        kwargs["project"] = "Forged\nreport"
    with pytest.raises(ValueError):
        build_assessment_model(scope, **kwargs)
    assert not scope.output.exists()


def test_refuted_findings_never_reenter_through_the_weakness_register(tmp_path):
    scope, kwargs = inputs(tmp_path)
    refuted = kwargs["merged"]["threats"][0]
    refuted["evidence_check"] = "refuted"
    refuted["evidence_basis"] = "refuted"
    refuted["evidence_check_reason"] = "The implementation contradicts this claim."
    document, _ = build_assessment_model(scope, **kwargs)
    assert refuted["t_id"] not in {t["id"] for t in document["threats"]}
    for weakness in document.get("weaknesses", []):
        assert refuted["t_id"] not in str(weakness)


def test_explicit_skips_remain_distinct_from_missing_context(tmp_path):
    scope, kwargs = inputs(tmp_path)
    kwargs["skill_cfg"].update(
        skip_business_context=True, skip_abuse_case_verification=True, business_context_source="ignored-by-request"
    )
    document, _ = build_assessment_model(scope, **kwargs)
    assert document["business_context_trace"]["status"] == "skipped"
    assert document["abuse_case_analysis"]["status"] == "skipped"


def _duplicated(tmp_path, other_verdict, names=("edge", "service")):
    scope, components, receipt, flows, _ = crossing_input(tmp_path, names=names)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    documents, reviews = [], []
    for component, evidence in zip(components["components"], flows["data_flows"][0]["evidence"], strict=True):
        document = stride(component, evidence, identity)
        # Same location and mechanism, reported again with a higher rating.
        duplicate = dict(copy.deepcopy(document["threats"][0]), local_id="issue-2")
        duplicate.update(likelihood="High", impact="Critical", risk="Critical")
        document["threats"].append(duplicate)
        next(row for row in document["coverage"] if row["category"] == "Tampering")["finding_ids"].append("issue-2")
        documents.append(document)
        verdicts = {"issue-1": "verified", "issue-2": other_verdict}
        reviews.append(
            dict(
                **identity,
                decisions=[
                    dict(local_id=key, verdict=value, reason="Source review decision.", evidence=[evidence])
                    for key, value in verdicts.items()
                ],
            )
        )
    return merge_assessment(scope, components, documents, reviews, boundaries=[])


@pytest.mark.parametrize("other_verdict", ["refuted", "ambiguous"])
@pytest.mark.parametrize("names", [("edge", "service"), ("gateway", "processor")])
def test_differently_reviewed_duplicate_cannot_absorb_a_verified_finding(tmp_path, other_verdict, names):
    merged = _duplicated(tmp_path, other_verdict, names)
    verified = [t for t in merged["threats"] if t["evidence_check"] == "verified"]
    assert len(verified) == 2
    assert {t["evidence"]["repository_id"] for t in verified} == {
        t["evidence"]["repository_id"] for t in merged["threats"]
    }


def test_equally_reviewed_duplicates_still_merge(tmp_path):
    merged = _duplicated(tmp_path, "verified")
    assert len(merged["threats"]) == 2
    assert all(t["evidence_check"] == "verified" for t in merged["threats"])


def test_stride_finding_without_cwe_is_rejected_at_its_contract(tmp_path):
    from contexts.multi_repo_analysis import contract
    from jsonschema import Draft202012Validator

    scope, components, receipt, flows, _ = crossing_input(tmp_path)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    component, evidence = components["components"][0], flows["data_flows"][0]["evidence"][0]
    document = stride(component, evidence, identity)
    validator = Draft202012Validator(contract("multi-repo-stride.schema.json"))
    assert validator.is_valid(document)
    for value in (None, "missing"):
        broken = copy.deepcopy(document)
        if value is None:
            broken["threats"][0]["cwe"] = None
        else:
            del broken["threats"][0]["cwe"]
        assert not validator.is_valid(broken)
