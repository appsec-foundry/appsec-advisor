from __future__ import annotations

from pathlib import Path

from validate_intermediate import LENS_CHECKLISTS, lens_coverage_errors

ROOT = Path(__file__).resolve().parent.parent


def _threat(local_id: str, *llm_ids: str, evidence: dict | None = None) -> dict:
    threat = {"local_id": local_id, "evidence": evidence if evidence is not None else {"file": "chat.ts", "line": 3}}
    if llm_ids:
        threat["owasp_llm_ids"] = list(llm_ids)
    return threat


def _covered(**overrides: dict) -> list[dict]:
    entries = {
        item: {"item": item, "disposition": "no-evidence", "reason": "checked the handler; nothing proven"}
        for item in LENS_CHECKLISTS["llm"]
    }
    for item, entry in overrides.items():
        entries[item] = {"item": item, **entry}
    return list(entries.values())


def test_the_checklists_match_the_lens_reference_files():
    for lens, name in (("llm", "owasp-llm-top10.md"), ("agentic", "owasp-asi-top10.md")):
        text = (ROOT / "agents" / "shared" / name).read_text(encoding="utf-8")
        assert all(item in text for item in LENS_CHECKLISTS[lens]), lens


def test_no_selected_checklist_lens_asks_for_nothing():
    assert lens_coverage_errors({"threats": []}, ["spa", "rag"]) == []


def test_a_complete_honest_checklist_passes_without_any_finding():
    assert lens_coverage_errors({"threats": [], "lens_coverage": _covered()}, ["llm"]) == []


def test_missing_and_duplicate_items_are_named():
    coverage = _covered()[:8] + [_covered()[0]]

    errors = lens_coverage_errors({"threats": [], "lens_coverage": coverage}, ["llm"])

    assert "lens_coverage lists LLM01 more than once" in errors
    assert "lens_coverage has no disposition for LLM09, LLM10" in errors


def test_a_finding_must_point_at_threats_carrying_the_item():
    data = {
        "threats": [_threat("c-001", "LLM01"), _threat("c-002")],
        "lens_coverage": _covered(
            LLM01={"disposition": "finding", "local_ids": ["c-001"]},
            LLM07={"disposition": "finding", "local_ids": ["c-002", "c-404"]},
            LLM10={"disposition": "finding"},
        ),
    }

    errors = lens_coverage_errors(data, ["llm"])

    assert errors == [
        "lens_coverage LLM07 names unknown threat c-404",
        "lens_coverage LLM07 names c-002, which lacks LLM07 in owasp_llm_ids",
        "lens_coverage LLM10 is a finding without local_ids",
    ]


def test_a_tagged_threat_contradicts_any_other_disposition():
    data = {"threats": [_threat("c-001", "LLM10")], "lens_coverage": _covered()}

    assert lens_coverage_errors(data, ["llm"]) == ["lens_coverage LLM10 is no-evidence but c-001 carries LLM10"]


def test_controlled_needs_the_control_location_and_a_reason():
    data = {"threats": [], "lens_coverage": _covered(LLM10={"disposition": "controlled"})}

    assert lens_coverage_errors(data, ["llm"]) == [
        "lens_coverage LLM10 is controlled without the control's evidence location",
        "lens_coverage LLM10 is controlled without a reason",
    ]


def test_an_llm_tag_without_code_evidence_is_rejected():
    data = {
        "threats": [_threat("c-001", "LLM09", evidence={})],
        "lens_coverage": _covered(LLM09={"disposition": "finding", "local_ids": ["c-001"]}),
    }

    assert lens_coverage_errors(data, ["llm"]) == ["threats[0] carries LLM09 without a code evidence location"]
