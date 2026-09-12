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
import xml.etree.ElementTree as ET

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
                    **({"cwe": "CWE-862" if k else "CWE-89"} if c["id"] == "app0" else {}),
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
    for token in (
        "C-01 · Web SPA",
        "df-002/003",
        "df-005",
        "tb-1",
        "tb-8",
        "TRUST BOUNDARY",
        "Assets — location and handling",
    ):
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
    model, paths, taxonomy = _model()
    model["assets"][0]["component_refs"] = [
        {"component_id": "db0", "relation": "stored", "evidence": [{"file": "src/store.ts", "line": 1}]}
    ]
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    _, state = F._build(model, scenarios, actors)
    assert state["nodes"]["db0"]["assets"][0]["_hits"] == ["1"]
    model["assets"][0]["linked_threats"] = []
    _, state = F._build(model, scenarios, actors)
    assert state["nodes"]["db0"]["assets"][0]["_hits"] == []


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


def test_attack_edges_follow_the_scenarios():
    y, apd, tax = _model(xss=True)
    svg, problems = F.check_diagram(y, apd, tax)
    assert problems == []
    _svg2, st = F._build(y, *F.scenarios_from_attack_paths(y, apd, tax))
    attacks = {(e["src"], e["dst"]): e for e in st["edges"] if e.get("attack")}
    # ① (anon) reaches app0 and db0: only the exposed process is attacked; ② (user) reaches app1, which is not
    # exposed, so its first process stands in; ③ is a victim scenario and points back at the user.
    assert set(attacks) == {("actor:a0", "app0"), ("actor:a1", "app1"), ("actor:a0", F.USER_ID)}
    assert attacks[("actor:a0", "app0")]["scen"] == ["1"] and attacks[("actor:a0", F.USER_ID)]["victim"] is True
    assert abs(attacks[("actor:a0", "app0")]["pts"][-1][0] - st["nodes"]["app0"]["x"]) < 0.6  # ends on the target
    assert 'stroke-dasharray="5 4"' in svg  # the victim edge is dashed


def test_one_bus_per_attacker_with_stubs():
    y, apd, tax = _model(exposed=("app0", "app1"))
    apd["attack_paths"][0]["findings"] = ["F-003", "F-005"]  # ① reaches app0 and app1, both exposed
    _svg, problems = F.check_diagram(y, apd, tax)
    assert problems == []
    _svg2, st = F._build(y, *F.scenarios_from_attack_paths(y, apd, tax))
    anon = [e for e in st["edges"] if e.get("attack") and e["src"] == "actor:a0"]
    assert {e["dst"] for e in anon} == {"app0", "app1"}
    trunk = [e for e in anon if len(e["pts"]) == 4]
    stubs = [e for e in anon if len(e["pts"]) == 2]
    assert len(trunk) == 1 and len(stubs) == 1
    a0 = st["nodes"]["actor:a0"]
    assert trunk[0]["pts"][0] == (a0["x"] + a0["w"], a0["cy"])  # the trunk leaves the attacker at its middle
    assert stubs[0]["pts"][0][0] == trunk[0]["pts"][1][0]  # the stub starts on the same bus
    stubs[0]["pts"][0] = (stubs[0]["pts"][0][0] + 5, stubs[0]["pts"][0][1])
    problems = F._audit(st["d"], st["nodes"], st["edges"], st["chips"], st["boundaries"])
    assert any("stub does not start on its attacker's bus" in p for p in problems)


def test_weakness_line_uses_specific_finding_causes_without_a_parent_registry():
    y, apd, tax = _model()
    svg = _checked()
    _svg2, st = F._build(y, *F.scenarios_from_attack_paths(y, apd, tax))
    assert {label for label, _n, _r in st["nodes"]["app0"]["weak"]} == {
        "Unsafe Query Construction (SQLi)",
        "Broken Authorization",
    }
    assert st["nodes"]["app1"]["weak"] == []  # threats without a CWE stay unmapped and draw nothing
    assert "Unsafe Query Construction (SQLi)" in svg and "Broken Authorization" in svg
    assert "injection 1" not in svg


def test_arrowheads_are_fixed_size_and_stop_at_the_border():
    svg = _checked()
    assert 'markerUnits="userSpaceOnUse"' in svg
    assert F._trim([(0.0, 5.0), (10.0, 5.0)]) == [(1.2, 5.0), (8.2, 5.0)]
    assert F._trim([(0.0, 0.0), (0.0, 10.0), (20.0, 10.0)]) == [(0.0, 1.2), (0.0, 10.0), (18.2, 10.0)]
    assert 'paint-order="stroke"' in svg  # flow labels carry a halo
    assert "TRUST BOUNDARY · tb-" not in svg  # each boundary appears once, as a chip or a tag


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
    assert "Assets — location and handling" in svg and "Stored assets" not in svg


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


def test_open_registration_merges_regular_attackers_but_preserves_privileged_access():
    model, paths, taxonomy = _model()
    model["meta"]["open_user_registration"] = True
    paths["attack_paths"].append(dict(paths["attack_paths"][1], actor="internet-priv-user"))
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    assert [a["slug"] for a in actors] == ["internet-anon", "internet-priv-user"]
    assert scenarios[0]["actor"] == scenarios[1]["actor"] == "Internet Attacker"
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_roles_and_identity_provider_use_distinct_left_side_nodes():
    model, paths, taxonomy = _model()
    model["external_entities"] = [
        {"id": "ext-admin", "name": "Administrator", "kind": "legitimate-role"},
        {"id": "ext-customer", "name": "Customer", "kind": "legitimate-role"},
        {"id": "ext-login", "name": "Example Identity Provider", "kind": "identity-provider"},
    ]
    model["data_flows"][0]["from_entity"] = "ext-customer"
    model["data_flows"][3]["from_entity"] = "ext-admin"
    model["data_flows"].append(
        {
            "id": "df-010",
            "from": "spa",
            "to": "external",
            "to_entity": "ext-login",
            "protocol": "HTTPS",
            "label": "OAuth redirect",
        }
    )
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    svg, state = F._build(model, scenarios, actors)
    assert all(state["nodes"][e["id"]]["col"] == 0 for e in model["external_entities"])
    assert F.USER_ID not in state["nodes"]
    visible_text = " ".join(re.findall(r"<text[^>]*>(.*?)</text>", svg))
    assert "Example Identity Provider" in visible_text
    assert "OAuth redirect" in visible_text
    assert any("df-010" in edge["ids"] for edge in state["edges"])
    assert F.check_diagram(model, paths, taxonomy)[1] == []
    attacker_colors = {state["nodes"][e["src"]]["color"] for e in state["edges"] if e.get("attack")}
    assert len(attacker_colors) == 2


def test_sensitive_marker_is_absent_but_evidenced_asset_storage_remains():
    model, paths, taxonomy = _model()
    original = copy.deepcopy(model)
    _, state = F._build(model, [], [])
    assert "sensitive" not in state["nodes"]["app0"]
    assert not state["nodes"]["db0"]["assets"]
    assert model == original
    model["components"][1]["sensitive_data"] = [
        {
            "category": "credentials",
            "handling": "processes",
            "basis": "observed",
            "evidence": [{"file": "src/login.ts", "line": 1}],
        }
    ]
    model["assets"][0]["component_refs"] = [
        {"component_id": "db0", "relation": "stored", "evidence": [{"file": "src/store.ts", "line": 1}]}
    ]
    _, state = F._build(model, [], [])
    assert "sensitive" not in state["nodes"]["app0"]
    assert [a["id"] for a in state["nodes"]["db0"]["assets"]] == ["A-001"]
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_uncovered_weakness_causes_and_merged_component_ownership_are_visible():
    model, paths, taxonomy = _model()
    for number, cwe in enumerate(["CWE-79", "CWE-287", "CWE-798", "CWE-327"], 100):
        model["threats"].append(
            {
                "id": f"T-{number}",
                "component": "app0",
                "merged_from": ["app0", "app1"],
                "cwe": cwe,
                "risk": "High",
                "stride": "Tampering",
            }
        )
    _, state = F._build(model, [], [])
    assert len(state["nodes"]["app0"]["weak"]) == 3
    assert len(state["nodes"]["app1"]["weak"]) == 3
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_component_shows_short_parent_cause_without_register_ids_or_titles():
    model, paths, taxonomy = _model()
    first = next(t for t in model["threats"] if t.get("component") == "app0")
    model["weaknesses"] = [
        {
            "id": "W-001",
            "title": "Queries concatenate untrusted input",
            "mechanism_id": "database-query-concatenation",
            "severity": "High",
            "weakness_class": "injection",
            "instances": [{"id": first["id"]}],
            "observable_backing": {"practice_evidence": [{"file": "src/query.ts", "line": 4}]},
        }
    ]
    svg, state = F._build(model, [], [])
    labels = [row[0] for row in state["nodes"]["app0"]["weak"]]
    assert "Unsafe Query Construction (SQLi)" in labels
    assert "Queries concatenate untrusted input" not in svg
    assert not any(label.startswith(first["id"] + " ") for label in labels)
    assert not any(re.search(r"[WT]-\d+", label) for label in labels)
    assert "sensitive data handling" not in svg
    assert ">Data flows<" in svg
    assert "observed weakness classes" not in svg
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_attacker_palette_contains_only_red_and_purple_hues():
    import colorsys

    for color in F.ACTOR_COLORS:
        rgb = [int(color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        hue, saturation, _value = colorsys.rgb_to_hsv(*rgb)
        assert hue <= 0.03 or hue >= 0.74
        assert saturation > 0.35


def test_annotations_filter_medium_findings_deduplicate_and_cap_at_three():
    model, paths, taxonomy = _model()
    model["threats"] = [
        {"id": f"T-{i:03d}", "component": "app0", "cwe": cwe, "risk": severity}
        for i, (cwe, severity) in enumerate(
            [
                ("CWE-89", "Critical"),
                ("CWE-89", "High"),
                ("CWE-862", "High"),
                ("CWE-321", "High"),
                ("CWE-400", "Medium"),
                ("CWE-79", "Low"),
                ("CWE-916", "High"),
            ],
            1,
        )
    ]
    rows = F._component_weaknesses(model)["app0"]
    assert len(rows) == 3
    assert rows[0] == ("Unsafe Query Construction (SQLi)", 2, 0)
    assert all(rank <= 1 for _label, _count, rank in rows)
    assert not {"Insufficient Resource Limits", "Insecure Output Handling"} & {label for label, _count, _rank in rows}
    assert all(len(label) <= 32 for label, _count, _rank in rows)
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_credential_defects_share_one_generic_weakness_annotation():
    model, _paths, _taxonomy = _model()
    model["threats"] = [
        {"id": "T-001", "component": "app0", "cwe": "CWE-798", "risk": "Critical"},
        {"id": "T-002", "component": "app0", "cwe": "CWE-522", "risk": "Critical"},
    ]
    assert F._component_weaknesses(model)["app0"] == [("Insecure Secret Management", 2, 0)]


def test_keys_and_credentials_share_one_short_annotation():
    model, _paths, _taxonomy = _model()
    model["threats"] = [
        {"id": "T-001", "component": "app0", "cwe": "CWE-798", "risk": "High"},
        {"id": "T-002", "component": "app0", "cwe": "CWE-321", "risk": "Critical"},
    ]
    assert F._component_weaknesses(model)["app0"] == [("Insecure Secret Management", 2, 0)]


@pytest.mark.parametrize(
    "findings,label,count",
    [
        ([("CWE-89", "High"), ("CWE-89", "Critical")], "Unsafe Query Construction (SQLi)", 2),
        ([("CWE-89", "High"), ("CWE-943", "High")], "Unsafe Query Construction", 2),
        ([("CWE-943", "High"), ("CWE-89", "Medium")], "Unsafe Query Construction (NoSQLi)", 1),
        ([("CWE-89", "High"), ("CWE-943", "Medium")], "Unsafe Query Construction (SQLi)", 1),
        ([("CWE-90", "High")], "Unsafe Query Construction (LDAPi)", 1),
        ([("CWE-643", "High")], "Unsafe Query Construction (XPathi)", 1),
    ],
)
def test_query_qualifier_requires_uniform_relevant_sql_evidence(findings, label, count):
    model = {
        "threats": [
            {"id": f"T-{i:03d}", "component": "service", "cwe": cwe, "risk": severity, "title": "SQL injection"}
            for i, (cwe, severity) in enumerate(findings, 1)
        ]
    }
    before = copy.deepcopy(model)
    rows = F._component_weaknesses(model)["service"]
    assert len(rows) == 1
    assert rows[0][:2] == (label, count)
    assert model == before


def test_query_design_risk_without_sql_finding_remains_generic():
    model = {
        "weaknesses": [
            {
                "mechanism_id": "database-query-concatenation",
                "severity": "High",
                "affected_components": ["service"],
                "observable_backing": {"practice_evidence": [{"id": "P-001"}]},
            }
        ]
    }
    assert F._component_weaknesses(model) == {"service": [("Unsafe Query Construction", 0, 1)]}


@pytest.mark.parametrize(
    "cwes,label",
    [
        (["CWE-79", "CWE-80"], "Insecure Output Handling (XSS)"),
        (["CWE-79", "CWE-74"], "Insecure Output Handling"),
        (["CWE-79", "CWE-116"], "Insecure Output Handling"),
        (["CWE-611"], "Insecure XML Processing (XXE)"),
        (["CWE-91"], "Insecure XML Processing (XMLi)"),
        (["CWE-611", "CWE-91"], "Insecure XML Processing"),
        (["CWE-918"], "Insecure Outbound Requests (SSRF)"),
        (["CWE-352"], "Improper Origin Validation (CSRF)"),
        (["CWE-94"], "Insecure Code Evaluation"),
    ],
)
def test_short_attack_patterns_do_not_invent_a_subtype_or_concatenate_patterns(cwes, label):
    model, paths, taxonomy = _model()
    model["threats"] = [
        {
            "id": f"T-{i:03d}",
            "component": "app0",
            "cwe": cwe,
            "risk": "High",
            "title": "DOM XSS or remote code execution",
        }
        for i, cwe in enumerate(cwes, 1)
    ]
    assert F._component_weaknesses(model) == {"app0": [(label, len(cwes), 1)]}
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert not problems
    assert label in re.sub(r"\s+", " ", " ".join(ET.fromstring(svg).itertext()))
    assert "DOM XSS" not in svg and "(RCE)" not in svg


def test_new_attack_pattern_is_a_catalog_change_not_a_renderer_rule(monkeypatch):
    vocabulary = copy.deepcopy(F.load_weakness_classes())
    vocabulary["diagram_annotations"]["labels"]["Insecure File Handling"]["cwe_qualifiers"] = {"CWE-22": "Path"}
    monkeypatch.setattr(F, "load_weakness_classes", lambda: vocabulary)
    model = {"threats": [{"id": "T-001", "component": "service", "cwe": "CWE-22", "risk": "High"}]}
    assert F._component_weaknesses(model) == {"service": [("Insecure File Handling (Path)", 1, 1)]}


@pytest.mark.parametrize(
    "mechanism,cwes,label",
    [
        ("frontend-output-encoding", ["CWE-79", "CWE-116"], "Insecure Output Handling"),
        ("route-by-route-authorization", ["CWE-862", "CWE-863"], "Broken Authorization"),
    ],
)
def test_parent_mechanism_and_individual_defects_use_the_same_generic_annotation(mechanism, cwes, label):
    model, _paths, _taxonomy = _model()
    model["threats"] = [
        {"id": f"T-{i:03d}", "component": "app0", "cwe": cwe, "risk": "High"} for i, cwe in enumerate(cwes, 1)
    ]
    model["weaknesses"] = [
        {
            "id": "W-001",
            "mechanism_id": mechanism,
            "severity": "High",
            "instances": [{"id": "T-001"}],
        }
    ]
    assert F._component_weaknesses(model)["app0"] == [(label, 2, 1)]


@pytest.mark.parametrize(
    "cwe,label",
    [
        (cwe, f"{label} ({entry['cwe_qualifiers'][cwe]})" if cwe in entry.get("cwe_qualifiers", {}) else label)
        for label, entry in F.load_weakness_classes()["diagram_annotations"]["labels"].items()
        for cwe in entry["cwes"]
    ],
)
@pytest.mark.parametrize("severity,rank", [("Critical", 0), ("High", 1), ("Medium", None)])
def test_every_catalog_cwe_is_renderable_only_at_high_or_critical(cwe, label, severity, rank):
    model = {"threats": [{"id": "T-001", "component": "service", "cwe": cwe, "risk": severity}]}
    expected = {} if rank is None else {"service": [(label, 1, rank)]}
    assert F._component_weaknesses(model) == expected


@pytest.mark.parametrize(
    "cwe,label",
    [
        ("CWE-918", "Insecure Outbound Requests (SSRF)"),
        ("CWE-611", "Insecure XML Processing (XXE)"),
        ("CWE-614", "Insecure Session Management"),
        ("CWE-295", "Improper Certificate Validation"),
        ("CWE-311", "Missing Data Encryption"),
        ("CWE-1395", "Insecure Dependency Management"),
        ("CWE-778", "Insufficient Audit Logging"),
        ("CWE-1427", "Insecure Prompt Handling"),
    ],
)
def test_additional_security_mechanisms_reach_svg_without_technology_inference(cwe, label):
    model, paths, taxonomy = _model()
    model["threats"] = [{"id": "T-001", "component": "app0", "cwe": cwe, "risk": "Critical"}]
    before = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    assert label in re.sub(r"\s+", " ", " ".join(ET.fromstring(svg).itertext()))
    assert not re.search(r"[WT]-\d{3}", svg)
    assert F._component_weaknesses(model) == {"app0": [(label, 1, 0)]}
    assert model == before


def test_dependency_lifecycle_design_weakness_gets_a_generic_annotation():
    model = {
        "weaknesses": [
            {
                "id": "W-001",
                "mechanism_id": "vulnerability-management-gap",
                "severity": "High",
                "affected_components": ["build"],
                "observable_backing": {"practice_evidence": [{"id": "P-001"}]},
            }
        ]
    }
    assert F._component_weaknesses(model) == {"build": [("Insecure Dependency Management", 0, 1)]}


@pytest.mark.parametrize("cwe", ["CWE-999999", *F.load_weakness_classes()["diagram_annotations"]["exceptions"]])
def test_unknown_or_broad_cwe_does_not_invent_a_cause_from_titles(cwe):
    model = {
        "threats": [{"id": "T-001", "component": "service", "cwe": cwe, "risk": "Critical", "title": "SQL injection"}],
        "weaknesses": [{"mechanism_id": "unknown-mechanism", "severity": "Critical", "instances": [{"id": "T-001"}]}],
    }
    before = copy.deepcopy(model)
    assert F._component_weaknesses(model) == {}
    assert model == before
    # Specific, evidenced parent mechanisms still annotate a broad CWE.
    model["weaknesses"][0]["mechanism_id"] = "database-query-concatenation"
    assert F._component_weaknesses(model) == {"service": [("Unsafe Query Construction", 1, 0)]}


def test_disclosure_annotations_distinguish_mechanisms_without_losing_findings():
    model, paths, taxonomy = _model()
    model["threats"] = [
        {"id": f"T-{i:03d}", "component": "app0", "cwe": cwe, "risk": "High"}
        for i, cwe in enumerate(["CWE-200", "CWE-359", "CWE-538", "CWE-548", "CWE-552", "CWE-598"], 1)
    ]
    before = copy.deepcopy(model)
    assert F._component_weaknesses(model)["app0"] == [
        ("Improper File Exposure", 3, 1),
        ("Insecure URL Data Handling", 1, 1),
    ]
    _, state = F._build(model, [], [])
    assert state["nodes"]["app0"]["sev"]["High"] == 6
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    assert "Insufficient Data Protection" not in svg
    assert "Improper File Exposure" in svg and "Insecure URL Data Handling" in svg
    assert model == before


def test_missing_encryption_does_not_describe_weak_or_inappropriately_used_crypto():
    model = {
        "threats": [
            {"id": f"T-{i:03d}", "component": "service", "cwe": cwe, "risk": "Critical"}
            for i, cwe in enumerate(["CWE-311", "CWE-327", "CWE-326"], 1)
        ]
    }
    assert F._component_weaknesses(model)["service"] == [
        ("Insecure Cryptography", 2, 0),
        ("Missing Data Encryption", 1, 0),
    ]


@pytest.mark.parametrize(
    "cwe,label",
    [
        ("CWE-602", "Improper Client Trust"),
        ("CWE-565", "Improper Client Trust"),
        ("CWE-915", "Improper Attribute Modification"),
        ("CWE-1321", "Improper Attribute Modification"),
        ("CWE-345", "Improper Authenticity Checks"),
        ("CWE-347", "Improper Authenticity Checks"),
        ("CWE-610", "Insecure Resource References"),
        ("CWE-668", "Insufficient Resource Isolation"),
        ("CWE-306", "Broken Authentication"),
        ("CWE-290", "Broken Authentication"),
        ("CWE-521", "Weak Authentication"),
        ("CWE-308", "Weak Authentication"),
        ("CWE-640", "Weak Authentication"),
        ("CWE-862", "Broken Authorization"),
        ("CWE-863", "Broken Authorization"),
    ],
)
@pytest.mark.parametrize("severity", ["High", "Critical"])
def test_annotations_name_the_evidenced_defect_not_an_assumed_control_failure(cwe, label, severity):
    model = {"threats": [{"id": "T-001", "component": "service", "cwe": cwe, "risk": severity}]}
    assert F._component_weaknesses(model) == {"service": [(label, 1, F.SEV_RANK[severity])]}


@pytest.mark.parametrize(
    "mechanism,label",
    [
        ("hand-rolled-token-verification", "Insecure Authentication"),
        ("route-by-route-authorization", "Insecure Authorization"),
        ("application-owned-cryptography", "Insecure Cryptography"),
        ("browser-clients-without-bff", "Insecure Session Management"),
    ],
)
def test_architecture_alone_does_not_establish_a_weakness_or_proven_bypass(mechanism, label):
    model = {"weaknesses": [{"mechanism_id": mechanism, "severity": "Critical", "affected_components": ["service"]}]}
    assert F._component_weaknesses(model) == {}
    model["weaknesses"][0]["observable_backing"] = {"practice_evidence": [{"id": "P-001"}]}
    assert F._component_weaknesses(model) == {"service": [(label, 0, 0)]}


def test_authentication_variants_share_one_badge_without_severity_or_count_loss():
    model = {
        "threats": [
            {"id": "T-001", "component": "service", "cwe": "CWE-521", "risk": "Critical"},
            {"id": "T-002", "component": "service", "cwe": "CWE-306", "risk": "High"},
            {"id": "T-003", "component": "service", "cwe": "CWE-620", "risk": "High"},
        ],
        "weaknesses": [
            {
                "mechanism_id": "hand-rolled-token-verification",
                "severity": "High",
                "affected_components": ["service"],
                "observable_backing": {"practice_evidence": [{"id": "P-001"}]},
            }
        ],
    }
    before = copy.deepcopy(model)
    assert F._component_weaknesses(model) == {"service": [("Broken Authentication", 3, 0)]}
    assert model == before
    model["threats"].reverse()
    assert F._component_weaknesses(model) == {"service": [("Broken Authentication", 3, 0)]}
    for threat in model["threats"]:
        if threat["cwe"] != "CWE-521":
            threat["risk"] = "Medium"
    assert F._component_weaknesses(model) == {"service": [("Weak Authentication", 1, 0)]}


def test_linked_authentication_defects_refine_only_their_own_component():
    model = {
        "threats": [
            {"id": "T-001", "component": "first", "cwe": "CWE-521", "risk": "High"},
            {"id": "T-002", "component": "second", "cwe": "CWE-306", "risk": "High"},
        ],
        "weaknesses": [
            {
                "mechanism_id": "hand-rolled-token-verification",
                "severity": "High",
                "instances": [{"id": "T-001"}, {"id": "T-002"}],
            }
        ],
    }
    assert F._component_weaknesses(model) == {
        "first": [("Weak Authentication", 1, 1)],
        "second": [("Broken Authentication", 1, 1)],
    }


def test_adjectives_do_not_change_annotation_severity():
    model = {
        "threats": [
            {"id": "T-001", "component": "service", "cwe": "CWE-307", "risk": "Critical"},
            {"id": "T-002", "component": "service", "cwe": "CWE-285", "risk": "High"},
            {"id": "T-003", "component": "service", "cwe": "CWE-311", "risk": "Medium"},
        ]
    }
    assert F._component_weaknesses(model)["service"] == [
        ("Insufficient Rate Limiting", 1, 0),
        ("Broken Authorization", 1, 1),
    ]


def test_annotation_renaming_does_not_change_top_three_selection(monkeypatch):
    model = {
        "threats": [
            {"id": f"T-{i:03d}", "component": "service", "cwe": cwe, "risk": "High"}
            for i, cwe in enumerate(["CWE-285", "CWE-311", "CWE-327", "CWE-798"], 1)
        ]
    }
    expected = F._component_weaknesses(model)["service"]
    assert len(expected) == 3
    selected = expected[0][0]
    renamed = "Insecure Zulu Handling"
    vocabulary = copy.deepcopy(F.load_weakness_classes())
    labels = vocabulary["diagram_annotations"]["labels"]
    labels[renamed] = labels.pop(selected)
    # Reordering the YAML object must not affect tied selection either.
    vocabulary["diagram_annotations"]["labels"] = dict(reversed(list(labels.items())))
    monkeypatch.setattr(F, "load_weakness_classes", lambda: vocabulary)
    assert F._component_weaknesses(model)["service"] == [
        (renamed if label == selected else label, count, rank) for label, count, rank in expected
    ]


@pytest.mark.parametrize("field,key", [("cwes", "CWE-89"), ("mechanisms", "database-query-concatenation")])
def test_annotation_catalog_rejects_duplicate_assignments(monkeypatch, field, key):
    vocabulary = copy.deepcopy(F.load_weakness_classes())
    vocabulary["diagram_annotations"]["labels"]["Insecure Output Handling"].setdefault(field, []).append(key)
    monkeypatch.setattr(F, "load_weakness_classes", lambda: vocabulary)
    with pytest.raises(ValueError, match="Duplicate Figure 1 annotation"):
        F._component_weaknesses({})


def test_annotation_catalog_rejects_mapped_exceptions(monkeypatch):
    vocabulary = copy.deepcopy(F.load_weakness_classes())
    vocabulary["diagram_annotations"]["exceptions"]["CWE-89"] = "Contradictory exclusion of a mapped cause"
    monkeypatch.setattr(F, "load_weakness_classes", lambda: vocabulary)
    with pytest.raises(ValueError, match="also declared as an exception"):
        F._component_weaknesses({})


def test_annotation_catalog_rejects_ambiguous_control_variants(monkeypatch):
    vocabulary = copy.deepcopy(F.load_weakness_classes())
    vocabulary["diagram_annotations"]["labels"]["Weak Authentication"]["variant_order"] = 2
    monkeypatch.setattr(F, "load_weakness_classes", lambda: vocabulary)
    with pytest.raises(ValueError, match="control-family variant"):
        F._component_weaknesses({})


def test_annotation_catalog_rejects_unrelated_cwe_qualifiers(monkeypatch):
    vocabulary = copy.deepcopy(F.load_weakness_classes())
    vocabulary["diagram_annotations"]["labels"]["Unsafe Query Construction"]["cwe_qualifiers"]["CWE-79"] = "SQLi"
    monkeypatch.setattr(F, "load_weakness_classes", lambda: vocabulary)
    with pytest.raises(ValueError, match="qualifier requires a CWE assigned"):
        F._component_weaknesses({})


def test_report_composer_publishes_compact_annotations_without_fallback(tmp_path):
    from types import SimpleNamespace

    import compose_threat_model as composer

    model, paths, taxonomy = _model()
    model["threats"].append(
        {
            "id": "T-999",
            "component": "app0",
            "cwe": "CWE-400",
            "risk": "Medium",
            "title": "A medium-severity finding must remain in the register, not the node annotations",
        }
    )
    context = SimpleNamespace(yaml_data=model, output_dir=tmp_path, figure_basename="report.figure1.svg", warnings=[])
    markdown = composer._render_figure1_svg(context, paths, taxonomy)
    svg = (tmp_path / "report.figure1.svg").read_text()
    assert context.warnings == []
    assert "(report.figure1.svg)" in markdown
    assert "Up to 3 key causes · High/Critical only" in svg
    assert "Unsafe Query Construction (SQLi)" in svg
    assert "Insufficient Resource Limits" not in svg
    assert not re.search(r"[WT]-\d{3}", svg)
    assert ">Data flows<" in svg
    assert "sensitive data handling" not in svg


def test_shared_external_boundary_does_not_select_an_arbitrary_role_flow():
    model, paths, taxonomy = _model()
    model["external_entities"] = [
        {"id": f"ext-role-{number}", "name": f"Role {number}", "kind": "legitimate-role"} for number in (1, 2)
    ]
    for number in (1, 2):
        model["data_flows"].append(
            {
                "id": f"df-10{number}",
                "from": "external",
                "from_entity": f"ext-role-{number}",
                "to": "app0",
                "protocol": "HTTPS",
            }
        )
    _, state = F._build(model, [], [])
    assert "tb-1" in state["nodes"]["app0"]["tags"]
    assert not any("tb-1" in edge["tb"] for edge in state["edges"])
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_evidenced_application_asset_is_not_reported_as_an_unknown_location():
    model, paths, taxonomy = _model()
    model["assets"] = [model["assets"][0]]
    model["assets"][0]["component_refs"] = [
        {"component_id": "app0", "relation": "processed", "evidence": [{"file": "src/key.ts", "line": 1}]}
    ]
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    assert "processed by C-02" in svg
    assert "location not established" not in svg


def test_ambiguous_outbound_boundary_tags_the_application_not_an_external_alias():
    model, paths, taxonomy = _model()
    model["external_entities"] = [{"id": "ext-provider", "name": "Provider", "kind": "external-service"}]
    model["data_flows"].append(
        {"id": "df-101", "from": "app0", "to": "external", "to_entity": "ext-provider", "protocol": "HTTPS"}
    )
    model["trust_boundaries"].append(
        {"id": "tb-99", "from": "app0", "to": "external", "confidence": "confirmed", "resolution_status": "resolved"}
    )
    _, state = F._build(model, [], [])
    assert "tb-99" in state["nodes"]["app0"]["tags"]
    assert "tb-99" not in state["nodes"]["ext:app0"].get("tags", [])
    assert F.check_diagram(model, paths, taxonomy)[1] == []
