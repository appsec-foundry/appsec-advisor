"""Tests for scripts/_business_relevance.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import _business_relevance as br  # noqa: E402


def _model(**trace) -> dict:
    return {
        "business_context_trace": {"status": "applied", **trace},
        "threats": [
            {"id": "T-001"},
            {"id": "T-002", "business_context_basis": ["sensitive_assets"]},
            {"id": "T-003"},
        ],
        "assets": [
            {"name": "Order History", "linked_threats": ["T-001", "T-002"]},
            {"name": "Audit Trail", "linked_threats": ["T-003"]},
        ],
    }


def test_named_assets_and_mapped_components_both_count():
    relevant = br.relevant_findings(_model(declared_asset_names=["Order History"]))

    assert relevant["T-001"] == ("Order History",) and relevant["F-001"] == ("Order History",)
    # Mapped to its component by the control analyst, whatever the asset is called.
    assert relevant["T-002"] == ("Order History",)
    assert "T-003" not in relevant


def test_component_mapping_alone_still_counts_without_a_name():
    relevant = br.relevant_findings(_model())

    assert relevant == {"T-002": (), "F-002": ()}
    assert br.mitigation_note(["T-002"], relevant) == "Declared business context"


def test_named_synthetic_assets_with_no_harm_do_not_add_priority():
    model = _model(
        declared_asset_names=["Order History"],
        component_coverage=[
            {
                "component_id": "practice-service",
                "fields": ["impact_if_compromised"],
                "impact_is_material": False,
            }
        ],
    )
    model["threats"][0]["component"] = "practice-service"
    model["threats"][1]["component"] = "practice-service"
    relevant = br.relevant_findings(model)
    assert "T-001" not in relevant
    # Independently declared sensitive assets still apply despite a no-harm claim.
    assert "T-002" in relevant


@pytest.mark.parametrize("status", ["skipped", "not_configured", None])
def test_context_that_was_not_applied_moves_nothing(status):
    model = _model(declared_asset_names=["Order History"])
    model["business_context_trace"]["status"] = status

    assert br.relevant_findings(model) == {}
    assert br.mitigation_note(["T-001", "T-002"], {}) == ""


def test_note_names_at_most_two_assets_and_strips_markup():
    relevant = {"T-1": ("Order History", "Card [data](x)"), "T-2": ("Wallet", "Order History")}

    assert br.mitigation_note(["T-1", "T-2"], relevant) == "Business-critical: Order History, Card datax +1"


@pytest.mark.parametrize("status", ["absent", "skipped", "not_applied"])
def test_verdict_does_not_promote_unused_context_to_no_harm(status):
    from _business_relevance import verdict_context_note

    assert (
        verdict_context_note(
            {
                "components": [{"id": "training-ui"}],
                "business_context_trace": {
                    "status": status,
                    "component_coverage": [{"component_id": "training-ui", "impact_is_material": False}],
                },
            }
        )
        == ""
    )


def test_verdict_no_harm_requires_a_current_component_and_explicit_boolean():
    from _business_relevance import verdict_context_note

    for row in [
        {"component_id": "stale-component", "impact_is_material": False},
        {"component_id": "training-ui", "impact_is_material": "false"},
        {"component_id": "training-ui"},
    ]:
        assert (
            verdict_context_note(
                {
                    "components": [{"id": "training-ui"}],
                    "business_context_trace": {"status": "applied", "component_coverage": [row]},
                }
            )
            == ""
        )
