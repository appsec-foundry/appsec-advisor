"""Tests for the presentation-neutral team-question selector."""

from __future__ import annotations

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


def test_selector_caps_questions_but_keeps_unverified_evidence_line() -> None:
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
    assert [item["id"] for item in selected["unverified"]] == ["F-009"]


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

    assert tq.select_open_questions(model, anchors("F-001", "F-002")) == {"questions": [], "unverified": []}


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
def test_disputed_registration_is_shared_without_invented_finding_links(tmp_path, source):
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
    selected = tq.select_open_questions(model, set())["questions"]
    assert len(selected) == 1
    assert selected[0]["refs"] == []
    question = selected[0]["question"]
    report = composer._render_ms_open_questions(SimpleNamespace(yaml_data=model))
    console = completion.build_manual_review_step(model, report, tmp_path / "report.md")
    assert "- " + question in report
    assert "- " + question in console
    assert "-  —" not in report + console
    assert "#f-" not in report + console
    model["meta"]["open_registration_resolution"]["disputed"] = False
    assert tq.select_open_questions(model, set())["questions"] == []


def test_disputed_registration_still_respects_three_question_cap():
    model = {
        "meta": {"open_registration_resolution": {"disputed": True, "evidence": [{"file": "entry.ts", "line": 1}]}},
        "threats": [finding(n) for n in range(1, 5)],
        "weaknesses": [weakness(n, f"mechanism-{n}", n) for n in range(1, 5)],
    }
    result = tq.select_open_questions(
        model,
        anchors("F-001", "F-002", "F-003", "F-004"),
        team_questions={f"mechanism-{n}": f"Decision {n}?" for n in range(1, 5)},
    )
    assert len(result["questions"]) == 3
    assert result["questions"][0]["question"].startswith("Self-registration:")
