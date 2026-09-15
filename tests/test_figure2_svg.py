"""Figure 2 preserves scenario identity and evidence through every column."""

import copy
import xml.etree.ElementTree as ET

import figure2_svg as figure2
import pytest


def model(component="worker", finding="T-017"):
    return {
        "components": [{"id": component, "name": "Document service", "tier": "application"}],
        "threats": [
            {
                "id": finding,
                "component": component,
                "title": "Untrusted expression execution",
                "scenario": "An attacker submits an expression to the document processor.",
                "impact_description": "The expression can read application records.",
                "evidence_summary": "The processor evaluates request text without isolation.",
                "risk": "High",
                "evidence_tier": "confirmed-exploitable",
                "evidence_check": "verified",
            }
        ],
        "weaknesses": [
            {"id": "W-008", "title": "Untrusted expressions reach an interpreter", "instances": [{"id": finding}]}
        ],
    }


TAXONOMY = {"classes": [{"id": "expression", "label": "Expression execution"}]}
IMPACTS = {
    "impacts": [
        {"id": "records", "label": "Record disclosure", "business_harm": "Disclosure of protected business records"}
    ]
}


def paths(finding="F-017", actor="internet-user"):
    return {
        "attack_paths": [
            {
                "class": "expression",
                "actor": actor,
                "target": "application",
                "findings": [finding],
                "impact": ["records"],
            }
        ]
    }


def diagram(data=None, attack_paths=None):
    return figure2.build_figure2_data(data or model(), attack_paths or paths(), TAXONOMY, IMPACTS)


@pytest.mark.parametrize("component,finding", [("worker", "T-017"), ("processor-east", "T-203")])
def test_routes_keep_findings_weakness_and_impact_connected(component, finding):
    data = diagram(model(component, finding), paths(finding.replace("T-", "F-")))
    row = data["routes"][0]
    assert row["number"] == 1
    assert row["finding_id"] == finding.replace("T-", "F-")
    assert row["weakness_ids"] == ["W-008"]
    assert "(W-008)" in row["weakness"]
    assert row["consequence"] == "The expression can read application records."
    svg = figure2.build_figure2_svg(data)
    root = ET.fromstring(svg)
    assert root.attrib["data-glyphs"] == "1"
    assert root.attrib["data-figure2-version"] == "2"
    assert "Underlying Weakness" in svg
    assert "Disclosure of protected business records" in svg


def test_unrelated_or_design_only_weakness_does_not_gain_a_reference():
    data = model()
    data["weaknesses"][0]["instances"] = [{"id": "T-099"}]
    data["weaknesses"].append({"id": "W-009", "title": "Untrusted expression execution"})
    row = diagram(data)["routes"][0]
    assert row["weakness_ids"] == []
    assert row["weakness"] == data["threats"][0]["evidence_summary"]


def test_numbers_survive_actor_grouping_and_rows_do_not_merge():
    data = model()
    second = {**data["threats"][0], "id": "T-018"}
    data["threats"].append(second)
    ap = paths()
    ap["attack_paths"].append({**ap["attack_paths"][0], "actor": "internet-priv-user", "findings": ["F-018"]})
    data["meta"] = {"open_user_registration": True}
    result = diagram(data, ap)
    assert [r["number"] for r in result["routes"]] == [1, 2]
    assert [r["actor_slug"] for r in result["routes"]] == ["internet-anon", "internet-priv-user"]
    assert "account" in result["routes"][0]["prerequisite"].lower()


def test_unproven_status_and_risk_do_not_come_from_impact_defaults():
    data = model()
    data["threats"][0].update(evidence_tier="insecure-practice", risk="Medium", effective_severity="Critical")
    row = diagram(data)["routes"][0]
    assert row["unproven"] is True
    assert row["risk"] == "Medium"
    assert "unproven" in figure2.build_figure2_svg(diagram(data))


def test_projection_is_pure_and_svg_is_deterministic_and_escaped():
    data = model()
    data["threats"][0]["scenario"] = '<script>alert("unsafe")</script> & ' + "long expression " * 100
    before = copy.deepcopy(data)
    first = figure2.build_figure2_svg(diagram(data))
    assert first == figure2.build_figure2_svg(diagram(data))
    assert data == before
    assert "<script>" not in first
    assert "&lt;script&gt;" in first
    assert not figure2.check_figure2_svg(first)


def test_dangling_finding_is_rejected_before_rendering():
    with pytest.raises(ValueError, match="finding"):
        diagram(attack_paths=paths("F-999"))


def test_missing_semantic_data_is_explicit_not_inferred_from_the_class():
    data = model()
    data["threats"][0].pop("impact_description")
    row = diagram(data)["routes"][0]
    assert row["consequence"] == "Technical consequence not established."
    assert "admin" not in row["consequence"]


def test_svg_checker_detects_a_missing_route_and_changed_badge():
    svg = figure2.build_figure2_svg(diagram())
    assert figure2.check_figure2_svg(svg.replace('data-route-number="1"', 'data-route-number="2"'))
    assert figure2.check_figure2_svg(svg.replace('data-glyphs="1"', 'data-glyphs=""'))


def test_practice_links_are_retained_and_verified_examples_take_precedence():
    data = model()
    data["threats"].append({**data["threats"][0], "id": "T-001", "risk": "Critical", "evidence_check": "unverifiable"})
    data["weaknesses"][0]["instances"] = []
    data["weaknesses"][0]["observable_backing"] = {"practice_evidence": [{"id": "T-017"}]}
    ap = paths()
    ap["attack_paths"][0]["findings"].append("F-001")
    row = diagram(data, ap)["routes"][0]
    assert row["finding_id"] == "F-017"
    assert row["weakness_ids"] == ["W-008"]
    assert row["unproven"] is False


def test_unknown_impact_is_rejected_instead_of_inventing_harm():
    ap = paths()
    ap["attack_paths"][0]["impact"] = ["imaginary"]
    with pytest.raises(ValueError, match="unknown impact"):
        diagram(attack_paths=ap)


def test_empty_scenario_set_remains_a_valid_portable_svg():
    svg = figure2.build_figure2_svg({"schema_version": 2, "routes": []})
    assert "No attack routes in the Top Threats groups." in svg
    assert not figure2.check_figure2_svg(svg)


@pytest.mark.parametrize("token", ["expression_", "W", "東京"])
def test_compact_cards_keep_full_text_and_parenthesized_references(token):
    data = model()
    long_text = token * 300
    data["threats"][0]["scenario"] = long_text
    root = ET.fromstring(figure2.build_figure2_svg(diagram(data)))
    ns = figure2._NS
    assert long_text in root.find("s:g/s:title", ns).text
    visible = [t.text or "" for t in root.findall(".//s:text", ns)]
    assert max(map(len, visible)) < 65
    assert "(W-008)" in visible
    assert any("…" in line for line in visible)
    assert "Actors, attack routes, underlying weaknesses and impact" not in visible


def test_visible_references_and_geometry_are_checked():
    svg = figure2.build_figure2_svg(diagram())
    assert figure2.check_figure2_svg(svg.replace(">(W-008)</text>", ">removed</text>"))
    assert figure2.check_figure2_svg(svg.replace('x="40"', 'x="invalid"'))


def test_overview_grouping_retains_cvss_privileges_and_victim_interaction():
    data = model()
    data["meta"] = {"open_user_registration": True}
    data["threats"][0]["cvss_v4"] = {"vector": "CVSS:4.0/AV:N/PR:L/UI:P"}
    ap = paths()
    ap["attack_paths"][0]["target"] = "client"
    row = diagram(data, ap)["routes"][0]
    assert row["actor_slug"] == "internet-anon"
    assert "Regular account required" in row["prerequisite"]
    assert "Victim interaction required" in row["prerequisite"]
    assert row["victim"] is True
