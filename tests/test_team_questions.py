"""Tests for the presentation-neutral team-question selector."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import pytest
import team_questions as tq  # noqa: E402


def finding(number: int, *, cwe: str = "CWE-639", **overrides) -> dict:
    return {
        "id": f"T-{number:03}",
        "title": "Object owner not checked",
        "cwe": cwe,
        "risk": "Critical",
        "source": "stride",
        "evidence_tier": "confirmed-exploitable",
        "evidence_check": "verified",
        "evidence": [{"file": "src/routes.ts", "line": number}],
        **overrides,
    }


def weakness(number: int, mechanism_id: str, *instances: int) -> dict:
    return {
        "id": f"W-{number:03}",
        "mechanism_id": mechanism_id,
        "instances": [{"id": f"T-{value:03}"} for value in instances],
    }


def anchors(*ids: str) -> set[str]:
    return {item.lower() for item in ids}


def test_selector_caps_questions_and_leaves_unverified_findings_to_triage() -> None:
    model = {
        "threats": [
            finding(1),
            finding(2),
            finding(3),
            finding(4),
            finding(9, cwe="CWE-89", evidence_check="ambiguous"),
        ],
        "weaknesses": [
            weakness(1, "route-by-route-authorization", 1),
            weakness(2, "secrets-committed-to-source", 2),
            weakness(3, "missing-endpoint-authentication", 3),
            weakness(4, "build-pipeline-mutable-refs", 4),
        ],
    }
    selected = tq.select_open_questions(
        model,
        anchors("F-001", "F-002", "F-003", "F-004", "F-009", "W-001", "W-002", "W-003", "W-004"),
    )

    assert [item["weakness_id"] for item in selected["questions"]] == ["W-001", "W-002", "W-003"]
    assert set(selected) == {"questions"}


def test_refuted_step_settles_the_whole_chain() -> None:
    model = {
        "threats": [finding(1, cwe="CWE-89"), finding(2, cwe="CWE-89")],
        "abuse_case_analysis": {
            "status": "completed",
            "cases": [
                {
                    "chain_verdict": "inconclusive",
                    "verification_complete": True,
                    "unverified_steps": [],
                    "matched_finding_ids": ["F-001", "F-002"],
                    "steps": [
                        {"finding_id": "F-001", "verdict": "refuted", "unverified": False},
                        {"finding_id": "F-002", "verdict": "inconclusive", "unverified": False},
                    ],
                }
            ],
        },
    }

    assert tq.select_open_questions(model, anchors("F-001", "F-002")) == {"questions": []}


def test_visible_anchor_scan_ignores_opaque_markdown() -> None:
    report = (
        '<a id="f-001"></a>\n'
        '<a id="w-001"></a>\n'
        '<!-- <a id="f-002"></a> -->\n'
        '```html\n<a id="f-003"></a>\n```\n'
        '`<a id="f-004"></a>`\n'
    )

    assert tq.visible_anchor_ids(report) == {"f-001", "w-001"}


def test_model_anchor_inventory_normalizes_public_finding_ids() -> None:
    model = {"threats": [finding(7)], "weaknesses": [weakness(2, "route-by-route-authorization", 7)]}

    assert tq.model_anchor_ids(model) == {"f-007", "w-002"}


@pytest.mark.parametrize("source", ["onboarding.ts", "routes/accounts.py"])
def test_disputed_registration_is_shared_without_invented_finding_links(source):
    from types import SimpleNamespace

    import compose_threat_model as composer
    import render_completion_summary as completion

    model = {
        "meta": {
            "open_registration_resolution": {
                "open": False,
                "disputed": True,
                "reason": "unresolved-candidate",
                "evidence": [{"file": source, "line": 1}],
            }
        }
    }
    model.update(
        actors=[{"id": "member", "access": ["authenticated-session"]}],
        threats=[finding(1, actor_ids=["member"], component="svc")],
        components=[{"id": "svc", "name": "Order Service"}],
    )
    selected = tq.select_open_questions(model, anchors("F-001"))["questions"]
    assert len(selected) == 1
    assert [ref["id"] for ref in selected[0]["refs"]] == ["F-001"]
    question = selected[0]["question"]
    report = composer._render_ms_open_questions(SimpleNamespace(yaml_data=model))
    console = completion.build_manual_review_step(model, report + '\n<a id="f-001"></a>')
    assert "- " + question in report
    assert "- " + question in console
    assert "-  —" not in report + console
    assert "#f-001" in report
    model["meta"]["open_registration_resolution"]["disputed"] = False
    assert tq.select_open_questions(model, set())["questions"] == []


def test_disputed_registration_still_respects_three_question_cap():
    model = {
        "meta": {"open_registration_resolution": {"disputed": True, "evidence": [{"file": "entry.ts", "line": 1}]}},
        "actors": [{"id": "member", "access": ["authenticated-session"]}],
        "threats": [finding(n, actor_ids=["member"]) for n in range(1, 5)],
        "weaknesses": [weakness(n, f"mechanism-{n}", n) for n in range(1, 5)],
    }
    result = tq.select_open_questions(
        model,
        anchors("F-001", "F-002", "F-003", "F-004"),
        team_questions={f"mechanism-{n}": f"Decision {n}?" for n in range(1, 5)},
        decision_impacts={f"mechanism-{n}": "Changes the affected access policy." for n in range(1, 5)},
    )
    assert len(result["questions"]) == 3
    assert result["questions"][0]["question"] == tq.REGISTRATION_QUESTION.format(component="this application")


def _selected(model: dict, *ids: str) -> list[str]:
    return [item["question"] for item in tq.select_open_questions(model, anchors(*ids))["questions"]]


def _generated_questions(component: str) -> list[str]:
    """Every built-in question the selector can phrase, with its subject resolved from the findings."""
    components = [{"id": "svc", "name": component}]
    chain = {
        "status": "completed",
        "cases": [
            {
                "chain_verdict": "inconclusive",
                "verification_complete": True,
                "unverified_steps": [],
                "matched_finding_ids": ["F-001", "F-002"],
                "steps": [{"finding_id": "F-002", "verdict": "inconclusive", "unverified": False}],
            }
        ],
    }
    tools = "The language model invokes a refund tool from an external tool registry."
    return [
        *_selected({"components": components, "threats": [finding(1, cwe="CWE-94", component="svc")]}, "F-001"),
        *_selected({"components": components, "threats": [finding(1, cwe="CWE-78", component="svc")]}, "F-001"),
        *_selected({"components": components, "threats": [finding(1, cwe="CWE-918", component="svc")]}, "F-001"),
        *_selected(
            {
                "components": components,
                "threats": [finding(1, cwe="CWE-862", component="svc", title="LLM tool call", evidence_summary=tools)],
            },
            "F-001",
        ),
        *_selected({"threats": [finding(1), finding(2)], "abuse_case_analysis": chain}, "F-001", "F-002"),
        *_selected(
            {
                "meta": {"open_registration_resolution": {"disputed": True, "evidence": [{"file": "a.ts", "line": 1}]}},
                "actors": [{"id": "member", "access": ["authenticated-session"]}],
                "threats": [finding(1, actor_ids=["member"], component="svc")],
                "components": components,
            },
            "F-001",
        ),
    ]


@pytest.mark.parametrize("component", ["Order Service", "billing-worker"])
def test_every_team_question_is_one_plain_question_with_a_subject(component):
    generated = _generated_questions(component)
    assert len(generated) == 6
    # Questions about code a finding sits in name that component.
    assert all(component in question for question in generated[:4])
    questions = [*generated, *tq.mechanism_team_questions().values()]
    for question in questions:
        assert question.endswith("?") and question.count("?") == 1, question
        assert not re.match(r"^[A-Z][\w -]{0,40}:\s", question), question  # no "Topic:" label
        assert not re.search(r"\bshould\b|\bplanned\b", question, re.I), question  # no proposed fix


def test_questions_without_a_resolvable_component_do_not_invent_one():
    question = _selected({"threats": [finding(1, cwe="CWE-918", component="unknown-id")]}, "F-001")[0]
    assert "from this application" in question


def test_every_registered_mechanism_pairs_a_question_with_its_impact() -> None:
    questions = tq.mechanism_team_questions()
    impacts = tq.mechanism_decision_impacts()

    assert set(questions) == set(impacts)
    for key, impact in impacts.items():
        assert "?" not in impact, key  # the consequence states, the question asks
        # An id in the impact line would be rendered bare: the enrichment guard
        # only spares the bullet itself, not its continuation line.
        assert not re.search(r"\b[FWT]-\d{3,}\b", impact), key


def _actor_model(**overrides) -> dict:
    """An anonymous-reachable authentication bypass next to an account-gated finding."""
    return {
        "actors": [
            {"id": "ACT-D-01", "access": ["internet"], "trust_positions": ["public-endpoint-reach"]},
            {
                "id": "ACT-D-02",
                "access": ["internet", "authenticated-user-session"],
                "trust_positions": ["authenticated-user-authority"],
            },
        ],
        "threats": [
            finding(1, cwe="CWE-89", title="SQL injection in login", actor_ids=["ACT-D-01"], component="api"),
            finding(2, actor_ids=["ACT-D-02"], component="api"),
        ],
        **overrides,
    }


def test_authentication_bypass_is_a_finding_not_a_team_question() -> None:
    questions = [
        item["question"] for item in tq.select_open_questions(_actor_model(), anchors("F-001", "F-002"))["questions"]
    ]

    assert not any("anonymous attacker" in question for question in questions)


def test_confirmed_bypass_settles_the_registration_question() -> None:
    model = _actor_model(
        meta={"open_registration_resolution": {"disputed": True, "evidence": [{"file": "signup.ts", "line": 1}]}}
    )

    model["abuse_case_analysis"] = {
        "status": "completed",
        "cases": [
            {
                "chain_verdict": "fully_viable",
                "verification_complete": True,
                "unverified_steps": [],
                "matched_finding_ids": ["F-001", "F-002"],
            }
        ],
    }
    questions = [item["question"] for item in tq.select_open_questions(model, anchors("F-001", "F-002"))["questions"]]

    assert not any("onboarding require approval" in question for question in questions)


def test_unsettled_registration_is_asked_only_while_an_authenticated_actor_exists() -> None:
    model = {
        "actors": [{"id": "ACT-D-02", "trust_positions": ["authenticated-user-authority"]}],
        "meta": {"open_registration_resolution": {"open": False, "disputed": False, "reason": "not-established"}},
        "threats": [finding(2, actor_ids=["ACT-D-02"])],
    }

    assert tq.REGISTRATION_QUESTION.format(component="this application") in [
        q["question"] for q in tq.select_open_questions(model, anchors("F-002"))["questions"]
    ]

    model["actors"] = []
    assert tq.select_open_questions(model, anchors("F-002"))["questions"] == []


@pytest.mark.parametrize("path", ["docker-compose.yml", "src/App.java", "deploy/nginx.conf"])
def test_individual_findings_never_become_verification_questions(path) -> None:
    model = {"threats": [finding(1, evidence_check="ambiguous", evidence=[{"file": path, "line": 3}])]}

    assert tq.select_open_questions(model, anchors("F-001")) == {"questions": []}


def asset(name: str, classification: str, *linked: int, stored_in: str = "") -> dict:
    refs = [{"component_id": stored_in, "relation": "stored", "evidence": [{"file": "a.ts", "line": 1}]}]
    return {
        "name": name,
        "classification": classification,
        "linked_threats": [f"T-{n:03}" for n in linked],
        "component_refs": refs if stored_in else [],
    }


def _asset_model(**overrides) -> dict:
    return {
        "components": [{"id": "db", "tier": "data"}, {"id": "api", "tier": "application"}],
        "threats": [finding(n, component="db") for n in range(1, 5)],
        "assets": [
            asset("Signing Key", "Restricted", 1, 2, 3, 4, stored_in="api"),
            asset("Customer Records", "Confidential", 1, stored_in="db"),
            asset("Order History", "Restricted", 2, 3, stored_in="db"),
            asset("Marketing Copy", "Public", 1, 2, 3, 4, stored_in="db"),
            asset("Audit Trail", "Internal", 1, stored_in="db"),
        ],
        **overrides,
    }


@pytest.mark.parametrize("status", ["skipped", "not_configured", None])
def test_undeclared_asset_criticality_is_asked_first(status) -> None:
    model = _asset_model(business_context_trace={"status": status} if status else {})
    model["weaknesses"] = [weakness(1, "route-by-route-authorization", 1)]

    selected = tq.select_open_questions(model, anchors("F-001", "F-002", "F-003", "F-004", "W-001"))["questions"]

    # Business data held in a data store leads; a key that only protects it follows.
    assert selected[0]["question"] == (
        "How critical are Order History, Customer Records and Signing Key to the business, "
        "and what harm would their disclosure, manipulation or unavailability cause?"
    )
    assert selected[0]["refs"] == [] and selected[0]["impact"] == tq.ASSET_CRITICALITY_IMPACT
    assert selected[1]["weakness_id"] == "W-001"


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "business_context_trace": {
                "status": "applied",
                "answered_questions": [
                    {"component_id": "db", "topic": "asset-criticality", "asset_name": name}
                    for name in ["Signing Key", "Customer Records", "Order History"]
                ],
            }
        },
        {"threats": [finding(n, risk="Low") for n in range(1, 5)]},
        {"assets": [asset("Marketing Copy", "Public", 1), asset("Audit Trail", "Internal", 2)]},
        {"assets": [asset("Customer Records", "Restricted", 9, stored_in="db")]},
    ],
)
def test_declared_context_or_unreached_assets_raise_no_criticality_question(overrides) -> None:
    model = _asset_model(**overrides)

    questions = tq.select_open_questions(model, anchors("F-001", "F-002", "F-003", "F-004"))["questions"]

    assert not any(question["question"].startswith("How critical") for question in questions)


@pytest.mark.parametrize("fields", [["business_purpose"], ["sensitive_assets", "impact_if_compromised"]])
def test_declared_categories_without_asset_names_still_ask_for_criticality(fields) -> None:
    # "Personal data" answers a category, not how critical the reached assets are.
    model = _asset_model(business_context_trace={"status": "applied", "fields_present": fields})

    assert _selected(model, "F-001", "F-002", "F-003", "F-004")[0].startswith("How critical are Order History")


def test_only_the_assets_the_context_does_not_name_are_asked_about() -> None:
    model = _asset_model(
        business_context_trace={
            "status": "applied",
            "answered_questions": [{"component_id": "db", "topic": "asset-criticality", "asset_name": "Order History"}],
        }
    )

    question = _selected(model, "F-001", "F-002", "F-003", "F-004")[0]

    assert question.startswith("How critical are Customer Records and Signing Key")


def test_declared_names_of_a_skipped_context_do_not_settle_criticality() -> None:
    model = _asset_model(business_context_trace={"status": "skipped", "declared_asset_names": ["Order History"]})

    assert _selected(model, "F-001", "F-002", "F-003", "F-004")[0].startswith("How critical are Order History")


def test_asset_names_cannot_inject_markup_or_extra_questions() -> None:
    model = _asset_model(
        assets=[asset("Card [data](https://example.invalid)?\x1b`x`", "Restricted", 1, stored_in="db")]
    )

    question = _selected(model, "F-001")[0]

    assert question.count("?") == 1
    assert "](" not in question and "\x1b" not in question and "`" not in question


def test_question_that_settles_more_findings_outranks_a_narrower_one() -> None:
    model = {
        "threats": [finding(n) for n in range(1, 5)],
        # W-001 sorts first and would win on insertion order alone.
        "weaknesses": [weakness(1, "m-narrow", 1), weakness(2, "m-wide", 2, 3, 4)],
    }

    result = tq.select_open_questions(
        model,
        anchors("F-001", "F-002", "F-003", "F-004", "W-001", "W-002"),
        team_questions={"m-narrow": "Narrow?", "m-wide": "Wide?"},
        decision_impacts={"m-narrow": "Narrow impact.", "m-wide": "Wide impact."},
    )

    assert [item["question"] for item in result["questions"]] == ["Wide?", "Narrow?"]
    assert [item["impact"] for item in result["questions"]] == ["Wide impact.", "Narrow impact."]


@pytest.mark.parametrize("reason", ["not-established", "unresolved-candidate"])
@pytest.mark.parametrize("risk", [None, "Low"])
def test_onboarding_requires_an_affected_finding(reason, risk):
    model = {
        "actors": [{"id": "member", "access": ["authenticated-session"]}],
        "meta": {
            "open_registration_resolution": {
                "reason": reason,
                "disputed": True,
                "evidence": [{"file": "src/enroll.py"}],
            }
        },
        "threats": [finding(1, actor_ids=["member"], risk=risk)] if risk else [],
    }
    assert _selected(model, "F-001") == []


def test_public_onboarding_does_not_establish_privileged_access():
    model = {
        "actors": [
            {
                "id": "administrator",
                "access": ["authenticated-session"],
                "trust_positions": ["privileged-user-authority"],
            }
        ],
        "meta": {"open_registration_resolution": {"reason": "not-established"}},
        "threats": [finding(1, actor_ids=["administrator"])],
    }
    assert _selected(model, "F-001") == []


@pytest.mark.parametrize("name", ["Shipment Ledger", "Dispatch Schedule"])
def test_asset_mention_without_impact_keeps_question_open(name):
    model = _asset_model(
        assets=[asset(name, "Confidential", 1, stored_in="db")],
        business_context_trace={"status": "applied", "declared_asset_names": [name]},
    )
    assert name in _selected(model, "F-001")[0]


@pytest.mark.parametrize("component", ["dispatch-api", "ledger-service"])
def test_answer_suppresses_only_its_component_and_topic(component):
    model = {
        "components": [{"id": component, "name": component}, {"id": "other", "name": "Other Service"}],
        "threats": [finding(1, component=component), finding(2, component="other")],
        "weaknesses": [weakness(1, "route-by-route-authorization", 1, 2)],
        "business_context_trace": {
            "status": "applied",
            "answered_questions": [{"component_id": component, "topic": "route-by-route-authorization"}],
        },
    }
    questions = tq.select_open_questions(model, anchors("F-001", "F-002", "W-001"))["questions"]
    assert len(questions) == 1
    assert "Other Service" in questions[0]["question"] and component not in questions[0]["question"]
    assert [ref["id"] for ref in questions[0]["refs"]] == ["F-002"]
    model["business_context_trace"]["answered_questions"].append(
        {"component_id": "other", "topic": "route-by-route-authorization"}
    )
    assert _selected(model, "F-001", "F-002", "W-001") == []
    model["business_context_trace"]["status"] = "skipped"
    assert _selected(model, "F-001", "F-002", "W-001")


@pytest.mark.parametrize(
    "mechanism",
    [
        "application-data-as-code",
        "script-readable-sensitive-cookies",
        "application-data-as-template",
        "frontend-output-encoding",
        "application-owned-cryptography",
        "vulnerability-management-gap",
        "unprotected-cookie-mutations",
    ],
)
def test_code_investigation_is_not_a_catalog_question(mechanism):
    model = {"threats": [finding(1)], "weaknesses": [weakness(1, mechanism, 1)]}
    assert _selected(model, "F-001", "W-001") == []


def test_question_without_decision_impact_is_omitted():
    model = {"threats": [finding(1)], "weaknesses": [weakness(1, "custom", 1)]}
    assert tq.select_open_questions(
        model, anchors("F-001"), team_questions={"custom": "Why?"}, decision_impacts={}
    ) == {"questions": []}


@pytest.mark.parametrize("change", ["other-component", "unverified", "unlinked-same-component"])
def test_unrelated_or_unverified_bypass_does_not_settle_onboarding(change):
    model = _actor_model(meta={"open_registration_resolution": {"reason": "not-established"}})
    if change == "other-component":
        model["threats"][0]["component"] = "different-service"
    elif change == "unverified":
        model["threats"][0]["evidence_check"] = "ambiguous"
    assert any("onboarding require approval" in q for q in _selected(model, "F-001", "F-002"))


def test_answer_topic_vocabulary_matches_the_question_catalog_and_both_schemas():
    import json

    import yaml

    analyst = json.loads((REPO_ROOT / "schemas/stride-analyst-context.schema.json").read_text())
    canonical = yaml.safe_load((REPO_ROOT / "schemas/threat-model.output.schema.yaml").read_text())
    expected = set(tq.mechanism_team_questions()) | {
        "asset-criticality",
        "account-onboarding",
        "attack-path-connection",
        "process-reach",
        "server-request-reach",
        "model-actions",
    }
    assert set(analyst["$defs"]["answered_questions"]["items"]["properties"]["topic"]["enum"]) == expected
    meanings = analyst["$defs"]["answered_questions"]["items"]["properties"]["topic"]["description"]
    for topic, question in tq.mechanism_team_questions().items():
        assert f"{topic}: {question}" in meanings
    assert tq.REGISTRATION_QUESTION in meanings
    assert (
        set(
            canonical["properties"]["business_context_trace"]["properties"]["answered_questions"]["items"][
                "properties"
            ]["topic"]["enum"]
        )
        == expected
    )
