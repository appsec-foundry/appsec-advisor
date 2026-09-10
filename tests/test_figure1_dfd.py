"""Unit tests for the Figure 1 data-flow-diagram generator (``scripts/figure1_dfd.py``).

The generator is pure (yaml + attack paths + taxonomy → SVG string). The tests
build synthetic models and assert on the returned markup and on the generator's
own verification: geometry (no crossings, no overlapping labels) and semantics
(every arrow matches its YAML flow, every flow and boundary is drawn or
explained), determinism, scaling with a capped zone, and the trust-boundary
placement rules.
"""

from __future__ import annotations

import copy
import re

import figure1_dfd as F
import pytest

_GLYPHS = ["①", "②", "③", "④", "⑤", "⑥", "⑦"]


def _model(*, app=3, stores=1, flows=True, exposed=("app0",), xss=False, intra=False, big=0):
    comps = [
        {
            "id": "spa",
            "name": "Web SPA",
            "tier": "client",
            "deployment_zones": ["client-device"],
            "framework": "angular",
        }
    ]
    comps += [
        {
            "id": f"app{i}",
            "name": f"Service {i}",
            "tier": "application",
            "deployment_zones": ["dmz"],
            "handles_sensitive_data": i == 0,
            "complexity": "complex" if i == 0 else "moderate",
        }
        for i in range(app + big)
    ]
    comps += [
        {"id": f"db{i}", "name": f"Store {i}", "tier": "data", "deployment_zones": ["prod-env"]} for i in range(stores)
    ]
    comps += [{"id": "ci", "name": "CI Pipeline", "tier": "application", "deployment_zones": ["ci-cd-runtime"]}]
    threats, n = [], 1
    for c in comps:
        for k in range(2):
            threats.append(
                {
                    "id": f"T-{n:03d}",
                    "component": c["id"],
                    "risk": "Critical" if n % 3 == 0 else "High",
                    "stride": "Spoofing" if k else "Information Disclosure",
                    "boundary_refs": [{"boundary_id": "tb-1"}] if c["id"] == "app0" else [],
                }
            )
            n += 1
    data_flows = []
    if flows:
        data_flows = [
            {"id": "df-001", "from": "external", "to": "spa", "protocol": "HTTP", "data_classification": "Public"},
            {"id": "df-002", "from": "spa", "to": "app0", "protocol": "HTTP", "data_classification": "Confidential"},
            {
                "id": "df-003",
                "from": "spa",
                "to": "app0",
                "protocol": "WebSocket",
                "data_classification": "Internal",
                "direction": "bidirectional",
            },
            {
                "id": "df-004",
                "from": "external",
                "to": "app1",
                "protocol": "HTTP",
                "data_classification": "Confidential",
            },
            {"id": "df-005", "from": "app0", "to": "db0", "protocol": "SQL", "data_classification": "Restricted"},
            {
                "id": "df-006",
                "from": "app0",
                "to": "external",
                "protocol": "HTTPS",
                "data_classification": "Internal",
                "label": "LLM",
            },
        ]
        if intra:
            data_flows.append(
                {"id": "df-007", "from": "app0", "to": "app2", "protocol": "gRPC", "data_classification": "Internal"}
            )
    tbs = [
        {
            "id": f"tb-{i}",
            "from": "external",
            "to": t,
            "confidence": "confirmed",
            "resolution_status": "resolved",
            "assumption_verdict": "refuted",
            "enforcement_point": "jwt",
        }
        for i, t in enumerate(exposed, start=1)
    ]
    tbs.append(
        {
            "id": "tb-8",
            "from": "app0",
            "to": "db0",
            "confidence": "confirmed",
            "resolution_status": "resolved",
            "assumption_verdict": "clean",
        }
    )
    tbs.append(
        {
            "id": "tb-9",
            "from": "external",
            "to": "ci",
            "confidence": "inferred",
            "resolution_status": "resolved",
            "assumption_verdict": "unconfirmed",
        }
    )
    classes = [
        {
            "id": "injection",
            "short_label": "Injection",
            "default_actor": "internet-anon",
            "default_target_tier": "application",
        },
        {
            "id": "authz",
            "short_label": "Broken Authz",
            "default_actor": "internet-user",
            "default_target_tier": "application",
        },
    ]
    paths = [
        {"class": "injection", "actor": "internet-anon", "target": "application", "findings": ["F-003", "F-009"]},
        {"class": "authz", "actor": "internet-user", "target": "application", "findings": ["F-005"]},
    ]
    if xss:
        classes.append(
            {"id": "xss", "short_label": "XSS", "default_actor": "victim-required", "default_target_tier": "client"}
        )
        paths.append({"class": "xss", "actor": "victim-required", "target": "client", "findings": ["F-001"]})
    yaml_data = {
        "meta": {"project": "synthetic"},
        "components": comps,
        "threats": threats,
        "data_flows": data_flows,
        "trust_boundaries": tbs,
        "assets": [
            {"id": "A-001", "name": "Card data", "classification": "Restricted", "linked_threats": ["T-009"]},
            {"id": "A-002", "name": "PII", "classification": "Confidential"},
        ],
    }
    return yaml_data, {"attack_paths": paths}, {"glyph_sequence": _GLYPHS, "classes": classes}


def _checked(**kw):
    y, apd, tax = _model(**kw)
    svg, problems = F.check_diagram(y, apd, tax)
    assert problems == [], problems
    return svg


def test_no_components_returns_empty():
    assert F.build_figure1_dfd_svg({"components": []}, {"attack_paths": [{"class": "x"}]}, {}) == ""


def test_well_formed_and_deterministic():
    y, apd, tax = _model()
    a = F.build_figure1_dfd_svg(copy.deepcopy(y), apd, tax)
    b = F.build_figure1_dfd_svg(copy.deepcopy(y), apd, tax)
    assert a.startswith("<svg") and a.rstrip().endswith("</svg>")
    assert a == b
    assert "_undrawn_flows" not in y  # the caller's model is never annotated


def test_geometry_and_semantics_are_clean():
    svg = _checked()
    for token in ("C-01 · Web SPA", "df-002/003", "df-005", "tb-1", "tb-8", "TRUST BOUNDARY", "Crown jewels"):
        assert token in svg, token


def test_scenarios_and_actors_come_from_attack_paths():
    y, apd, tax = _model(xss=True)
    scenarios, actors = F.scenarios_from_attack_paths(
        y, apd, tax, {"internet-anon": {"label": "Anon", "default_subtitle": "no account"}}
    )
    assert [s["n"] for s in scenarios] == ["1", "2", "3"]
    assert scenarios[0]["actor"] == "Anon" and scenarios[0]["cids"] == ["app0", "db0"]
    assert scenarios[1]["actor"] == "Authenticated Internet Attacker"
    assert scenarios[2]["victim"] is True and scenarios[2]["actor"] == "Anon"
    assert [a["name"] for a in actors] == ["Anon", "Authenticated Internet Attacker"]
    svg = _checked(xss=True)
    assert "victim of ③" in svg  # the legitimate user is marked as the XSS victim
    assert "Anon → User (victim)" not in svg  # fallback labels are not used when actor_labels are absent


def test_scenario_badges_only_on_processes_and_linked_assets():
    svg = _checked()
    # process app0 hosts scenario ① (F-003) → a badge; the store hosts F-009 but shows ① only at asset A-001,
    # which links T-009.
    assert re.search(r"A-001 Card data", svg)
    y, apd, tax = _model()
    y["assets"][0]["linked_threats"] = []
    svg2 = F.build_figure1_dfd_svg(y, apd, tax)
    assert svg2.count('font-size="9.5" fill="#ffffff"') < svg.count('font-size="9.5" fill="#ffffff"')


def test_bidirectional_flow_gets_two_heads():
    svg = _checked()
    assert 'marker-start="url(#arw-Confidential)"' in svg  # the df-002/003 bundle carries the WebSocket direction


def test_boundary_on_a_flow_is_a_chip_and_without_a_flow_a_tag():
    y, apd, tax = _model(exposed=("app0", "app1"))
    _svg, problems = F.check_diagram(y, apd, tax)
    assert problems == []
    _svg2, st = F._build(y, *F.scenarios_from_attack_paths(y, apd, tax))
    chips = {c["tb"] for c in st["chips"]}
    tags = {t for n in st["nodes"].values() for t in n.get("tags", [])}
    assert "tb-2" in chips  # external → app1 rides on df-004
    assert "tb-8" in chips  # app0 → db0 rides on df-005
    assert "tb-1" in tags and "tb-9" in tags  # no drawn flow → tag on the guarded node
    assert not chips & tags


def test_intra_column_flow_uses_the_channel_and_is_verified():
    svg = _checked(intra=True)
    assert 'transform="rotate(-90' in svg  # rotated df-007 label along the channel


def test_attackers_enter_at_the_most_attacked_entry_point():
    y, apd, tax = _model()
    _svg, st = F._build(y, *F.scenarios_from_attack_paths(y, apd, tax))
    attacks = [e for e in st["edges"] if e.get("attack")]
    assert len(attacks) == 2 and {e["dst"] for e in attacks} == {"app0"}
    for e in attacks:
        assert abs(e["pts"][-1][0] - st["nodes"]["app0"]["x"]) < 0.6  # arrow ends on the entry node's left edge


def test_large_models_collapse_and_explain():
    y, apd, tax = _model(big=9)
    svg, problems = F.check_diagram(y, apd, tax)
    assert problems == []
    assert "+4 more:" in svg
    assert "collapsed" in svg  # the legend explains the flows that are not drawn


def test_unknown_flow_endpoints_and_self_loops_are_explained():
    y, apd, tax = _model()
    y["data_flows"] += [
        {"id": "df-090", "from": "ghost", "to": "app0", "protocol": "HTTP", "data_classification": "Public"},
        {"id": "df-091", "from": "app0", "to": "app0", "protocol": "HTTP", "data_classification": "Public"},
    ]
    svg, problems = F.check_diagram(y, apd, tax)
    assert problems == []
    assert "df-090 not drawn: unknown component ghost" in svg
    assert "df-091 not drawn: self-loop" in svg


def test_multiple_stores_list_assets_in_the_legend():
    svg = _checked(stores=2)
    assert "Crown jewels (assets)" in svg and "Crown jewels stored here" not in svg


def test_audit_catches_a_misrouted_edge():
    y, apd, tax = _model()
    _svg, st = F._build(y, *F.scenarios_from_attack_paths(y, apd, tax))
    e = next(e for e in st["edges"] if e.get("ids") == ["df-005"])
    e["pts"][-1] = (e["pts"][-1][0] + 40, e["pts"][-1][1])  # arrow no longer ends on its target
    problems = F._audit(st["d"], st["nodes"], st["edges"], st["chips"], st["boundaries"])
    assert any("does not end on its target" in p for p in problems)


@pytest.mark.parametrize("flows", [True, False])
def test_models_without_flows_still_render(flows):
    _checked(flows=flows)
