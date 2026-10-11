"""Read-only context adapters of the analyst: requirements, business context, threat model."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from contexts import build_analyst_context as bc  # noqa: E402
from contexts import resolve_analyst_catalog as rc  # noqa: E402

SECRET = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
CATALOG = {
    "categories": [
        {"id": "AC", "requirements": [{"id": "ORG-AC-1", "text": "Authorize every export.", "priority": "MUST"}]}
    ]
}


@pytest.fixture
def setup(tmp_path):
    repo = tmp_path / "repo"
    (repo / "docs" / "security").mkdir(parents=True)
    limits = rc.load_limits()
    resolved = rc.resolve([], limits)
    selection = rc.select_questions(resolved, limits["selected_questions"])
    request = {"job_id": "aj-" + "a" * 32, "repository": {"root": str(repo)}}
    return repo, request, resolved, selection


def sources(context: dict) -> dict:
    return {s["kind"]: s for s in context["sources"]}


def test_configured_catalog_is_delivered_with_arbitrary_ids(setup, tmp_path):
    repo, request, resolved, selection = setup
    catalog = tmp_path / "org.yaml"
    catalog.write_text(yaml.safe_dump(CATALOG))
    context = bc.build(request, resolved, selection, requirements_path=catalog, requirements_required=True)
    assert context["requirements"] == [{"id": "ORG-AC-1", "text": "Authorize every export.", "priority": "MUST"}]
    assert sources(context)["requirements"]["origin"] == "configured"


def test_without_configuration_the_packaged_fallback_is_used_and_labeled(setup):
    _, request, resolved, selection = setup
    context = bc.build(request, resolved, selection)
    assert sources(context)["requirements"]["origin"] == "packaged_fallback" and context["requirements"]


@pytest.mark.parametrize("content", [None, "categories: [", "{}"], ids=["missing", "broken-yaml", "no-categories"])
def test_a_required_catalog_never_falls_back(setup, tmp_path, content):
    _, request, resolved, selection = setup
    catalog = tmp_path / "org.yaml"
    if content is not None:
        catalog.write_text(content)
    with pytest.raises(bc.ContextError) as err:
        bc.build(request, resolved, selection, requirements_path=catalog, requirements_required=True)
    assert err.value.required


def test_an_optional_invalid_catalog_is_recorded_not_substituted(setup, tmp_path):
    _, request, resolved, selection = setup
    catalog = tmp_path / "org.yaml"
    catalog.write_text("{}")
    context = bc.build(request, resolved, selection, requirements_path=catalog)
    assert sources(context)["requirements"]["status"] == "invalid" and context["requirements"] == []


def test_business_context_is_delivered_or_withheld_when_sensitive(setup):
    repo, request, resolved, selection = setup
    assert sources(bc.build(request, resolved, selection))["business_context"]["status"] == "absent"
    (repo / "docs" / "security" / "business-context.md").write_text("Exports of customer data are regulated.\n")
    context = bc.build(request, resolved, selection)
    assert "regulated" in context["business_context"]
    (repo / "docs" / "security" / "business-context.md").write_text(SECRET)
    context = bc.build(request, resolved, selection)
    assert context["business_context"] is None and sources(context)["business_context"]["status"] == "sensitive"
    with pytest.raises(bc.ContextError):
        bc.build(request, resolved, selection, business_context_required=True)


def test_threat_model_is_projected_only_when_valid(setup, tmp_path):
    _, request, resolved, selection = setup
    model = tmp_path / "threat-model.yaml"
    model.write_text("components: []\n")
    context = bc.build(request, resolved, selection, threat_model_path=model)
    assert context["threat_model"] is None and sources(context)["threat_model"]["status"] == "invalid"
    with pytest.raises(bc.ContextError):
        bc.build(request, resolved, selection, threat_model_path=model, threat_model_required=True)


def test_questions_and_omissions_are_recorded(setup):
    _, request, resolved, _ = setup
    selection = rc.select_questions(resolved, 2)
    context = bc.build(request, resolved, selection)
    assert len(context["questions"]) == 2
    assert context["question_selection"]["required_complete"] is False
    assert len(context["question_selection"]["omitted"]) == len(resolved["questions"]) - 2


@pytest.mark.parametrize(
    "signals",
    [[], ["business_operation", "business_operation"], ["authorize_extra_reads"], "business_operation"],
    ids=["empty", "duplicate", "unknown-authority", "wrong-type"],
)
def test_invalid_applicability_signals_reject_context(setup, signals):
    _, request, resolved, selection = setup
    selection["selected"][0] = dict(selection["selected"][0], applies_when=signals)
    with pytest.raises(bc.ContextContractError):
        bc.build(request, resolved, selection)


def _model(threats=40, mitigations=True):
    return {
        "meta": {"generated": "2026-10-01"},
        "components": [
            {"id": "C-01", "name": "Export", "paths": ["src/export/**"]},
            {"id": "C-02", "name": "Admin", "paths": ["admin.py"]},
        ],
        "threats": [
            {
                "id": f"T-{i:03d}",
                "component": "C-02" if i % 2 else "C-01",
                "title": f"Threat {i}",
                "risk": "Critical" if i % 2 else "Low",
                "evidence": [{"file": "src/export/handler.ts", "line": 3}],
                "controls_in_place": "x" * 2000,
            }
            for i in range(1, threats + 1)
        ],
        **(
            {"mitigations": [{"id": "M-001", "title": "Bind exports", "threat_ids": ["T-002"], "priority": "P1"}]}
            if mitigations
            else {}
        ),
        "trust_boundaries": [{"id": "tb-1", "name": "Edge", "covers_components": ["C-01"], "assumption": "TLS"}],
    }


def test_projection_puts_touched_components_first_and_uses_reader_ids():
    projection = bc._project(_model(threats=4), ["src/export/handler.ts"])
    assert projection["focus_components"] == ["C-01"]
    assert [t["id"] for t in projection["threats"]][:2] == ["F-002", "F-004"]
    assert projection["threats"][0]["files"] == ["src/export/handler.ts"]
    assert len(projection["threats"][0]["controls_in_place"]) == bc.MAX_FIELD_CHARS
    assert projection["mitigations"][0]["threat_ids"] == ["F-002"]


def test_projection_without_focus_orders_by_risk_and_tolerates_missing_sections():
    projection = bc._project(_model(threats=4, mitigations=False), [])
    assert projection["focus_components"] == [] and projection["mitigations"] == []
    assert [t["risk"] for t in projection["threats"]][:2] == ["Critical", "Critical"]


def test_an_oversized_model_is_bounded_by_size_and_counts_omissions():
    projection = bc._project(_model(threats=2000), ["src/export/handler.ts"])
    assert len(__import__("json").dumps(projection)) <= bc.MAX_PROJECTION_BYTES + 1024
    assert projection["omitted"]["threats"] > 0
    assert projection["trust_boundaries"] and projection["mitigations"], "every section keeps entries"
    assert all(t["component"] == "C-01" for t in projection["threats"][:10])
