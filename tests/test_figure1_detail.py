"""Cross-topology scaling and publication coverage of navigable SVG detail views."""

import copy
import itertools
import re
import xml.etree.ElementTree as ET

import figure1_detail as D
import figure1_dfd as F
import pytest


def model(count, topology="chain", prefix="dispatch"):
    ids = [f"{prefix}-{i}" for i in range(count)]
    pairs = list(zip(range(count - 1), range(1, count)))
    if topology == "star":
        pairs = [(0, i) for i in range(1, count)]
    elif topology == "mesh":
        pairs = list(itertools.permutations(range(count), 2))
    elif topology == "isolated":
        pairs = []
    return {
        "components": [
            {"id": cid, "name": f"{prefix.title()} processor {i}", "tier": "application"} for i, cid in enumerate(ids)
        ],
        "data_flows": [
            {
                "id": f"df-{i:03}",
                "from": ids[a],
                "to": ids[b],
                "protocol": "gRPC",
                "label": "Record exchange",
                "data_classification": "Internal",
            }
            for i, (a, b) in enumerate(pairs, 1)
        ],
    }


@pytest.mark.parametrize("prefix", ["dispatch", "telemetry"])
@pytest.mark.parametrize("count", [1, 8, 9, 20, 100])
@pytest.mark.parametrize("topology", ["isolated", "chain", "star"])
def test_sizes_preserve_every_component_and_flow_in_bounded_views(prefix, count, topology):
    data = model(count, topology, prefix)
    before = copy.deepcopy(data)
    overview, problems = F.check_diagram(data, {}, {}, detail=False)
    assert problems == []
    assert float(ET.fromstring(overview).get("height")) < 2200
    detail, problems = F.check_diagram(data, {}, {})
    assert problems == []
    root = ET.fromstring(detail)
    assert {g.get("data-component-id") for g in root.iter() if g.get("data-component-id")} == {
        c["id"] for c in data["components"]
    }
    if count > F.ZONE_CAP:
        assert root.get("data-paged-detail") == "true"
        assert D.check_views(detail, data) == []
        assert "collapsed" not in detail
        for view in root.findall("{*}view"):
            _, _, width, height = map(float, view.get("viewBox").split())
            assert width < 1700 and height < 2400
    else:
        assert root.get("data-paged-detail") is None
    assert detail == F.build_figure1_dfd_svg(data, {}, {})
    assert data == before


@pytest.mark.parametrize("prefix", ["orders", "events"])
def test_dense_graph_has_complete_catalogue_and_bounded_overview(prefix):
    data = model(20, "mesh", prefix)
    overview, errors = F.check_diagram(data, {}, {}, detail=False)
    assert errors == []
    text = " ".join(" ".join(ET.fromstring(overview).itertext()).split())
    assert sum(int(n) for n in re.findall(r"(\d+) flows in detail views", text)) == 380 - F.OVERVIEW_FLOW_CAP
    assert float(ET.fromstring(overview).get("height")) < 2400
    detail, errors = F.check_diagram(data, {}, {})
    assert errors == []
    root = ET.fromstring(detail)
    assert len(root.findall(".//{*}text[@data-catalogue-flow]")) == 380
    assert max(float(v.get("viewBox").split()[3]) for v in root.findall("{*}view")) < 2400
    ids = [e.get("id") for e in root.iter() if e.get("id")]
    assert len(ids) == len(set(ids))


def test_many_external_services_are_grouped_only_in_overview():
    data = model(1)
    data["external_entities"] = [
        {"id": f"peer-{i}", "name": f"Provider {i}", "kind": "external-service"} for i in range(50)
    ]
    data["data_flows"] = [
        {
            "id": f"df-{i:03}",
            "from": "dispatch-0",
            "to": "external",
            "to_entity": f"peer-{i}",
            "protocol": "HTTPS",
            "label": "Event exchange",
        }
        for i in range(50)
    ]
    overview, errors = F.check_diagram(data, {}, {}, detail=False)
    assert not errors
    assert float(ET.fromstring(overview).get("height")) < 2000
    detail, errors = F.check_diagram(data, {}, {})
    assert not errors
    root = ET.fromstring(detail)
    assert {e.get("data-external-id") for e in root.iter() if e.get("data-external-id")} >= {
        e["id"] for e in data["external_entities"]
    }


def test_missing_coverage_or_navigation_blocks_detail_publication():
    data = model(9)
    svg, errors = F.check_diagram(data, {}, {})
    assert errors == []
    for old, new, diagnostic in [
        ('data-component-id="dispatch-8"', 'data-other-id="dispatch-8"', "component coverage"),
        ('data-catalogue-flow="df-008"', 'data-other-flow="df-008"', "flow coverage"),
        ('href="#view-0"', 'href="#missing"', "navigation"),
    ]:
        assert any(diagnostic in error for error in D.check_views(svg.replace(old, new), data))


def test_detail_keeps_global_component_scenario_and_authentication_numbers():
    data = model(9)
    for i, flow in enumerate(data["data_flows"]):
        flow["authentication"] = {
            "scheme": "bearer" if i % 2 else "password",
            "scope": "This access",
            "evidence": [{"file": "src/access.cfg", "line": i + 1}],
        }
    data["threats"] = [{"id": "F-001", "component": "dispatch-8", "risk": "High"}]
    paths = {"attack_paths": [{"class": "tampering", "actor": "internet-user", "findings": ["F-001"]}]}
    svg, errors = F.check_diagram(data, paths, {})
    assert errors == []
    root = ET.fromstring(svg)
    titles = [" ".join(e.itertext()) for e in root.findall(".//{*}g[@data-component-id='dispatch-8']")]
    assert titles and all("C-09" in title for title in titles)
    codes = F.profile_catalog(data["data_flows"])
    for flow in data["data_flows"]:
        profile = codes[F.authentication_profile(flow)["key"]]
        tabs = root.findall(f".//{{*}}g[@data-auth-flows='{flow['id']}']")
        assert tabs
        assert all(tab.get("data-authentication") == profile["number"] for tab in tabs)


def test_catalogue_escapes_imported_markup_and_preserves_long_labels():
    data = model(9)
    text = '<script>alert("x")</script> ' + "TelemetryPayload" * 120
    data["data_flows"][0]["label"] = text
    svg, errors = F.check_diagram(data, {}, {})
    assert not errors
    assert "<script>" not in svg
    root = ET.fromstring(svg)
    rows = root.findall(".//{*}text[@data-catalogue-flow='df-001']")
    assert text.replace(" ", "") in "".join(e.text for e in rows).replace(" ", "")


@pytest.mark.parametrize("name", ["Gateway REST API Backend", "Network REST API Backend", "API"])
@pytest.mark.parametrize("detail", [True, False])
def test_corner_boundary_tags_reserve_title_space(name, detail):
    data = model(1)
    data["components"][0]["name"] = name
    data["trust_boundaries"] = [
        {
            "id": "tb-1",
            "from": "external",
            "to": "dispatch-0",
            "confidence": "confirmed",
            "resolution_status": "resolved",
            "assumption_verdict": "refuted",
        }
    ]
    data["threats"] = [
        {"id": f"F-{i:03}", "component": "dispatch-0", "risk": "High", "boundary_refs": [{"boundary_id": "tb-1"}]}
        for i in range(4)
    ]
    _, state = F._build(data, [], [], detail=detail)
    titles = [r for r in state["canvas"].labels if r[4].startswith("node title ")]
    assert titles
    tags = [r for r in state["canvas"].badges if r[4].startswith("tag ")]
    assert bool(tags) == detail
    for tag in tags:
        assert min(t[1] for t in titles) > tag[3]
    assert F.check_diagram(data, {}, {}, detail=detail)[1] == []
    if detail:
        title = titles[0]
        state["canvas"].badges.append((*title[:4], "tag overlapping-title"))
        assert any(
            "title overlaps badge" in e
            for e in F._check_geometry(state["nodes"], state["edges"], state["canvas"], state["chips"])
        )


def test_component_view_geometry_failure_is_not_hidden(monkeypatch):
    monkeypatch.setattr(F, "_check_geometry", lambda *args, **kwargs: ["injected geometry defect"])
    _, errors = F.check_diagram(model(9), {}, {})
    assert errors and all("injected geometry defect" in error for error in errors)


@pytest.mark.parametrize("ambiguous", [True, False])
@pytest.mark.parametrize("variant", [True, False])
def test_victim_identity_survives_views_without_a_direct_role_flow(ambiguous, variant):
    from tests.test_figure1_dfd import _role_access_model

    data, paths, taxonomy, ids = _role_access_model(variant=variant)
    data["components"] += model(9, "isolated")["components"]
    data["data_flows"] = [f for f in data["data_flows"] if f["id"] != "df-011"]
    if ambiguous:
        data["external_entities"].append({"id": "unknown-role", "name": "Observer", "kind": "legitimate-role"})
    before = copy.deepcopy(data)
    svg, problems = F.check_diagram(data, paths, taxonomy)
    assert problems == []
    root = ET.fromstring(svg)
    victim_nodes = [
        node for node in root.findall(".//{*}g[@data-external-id]") if "victim of" in " ".join(node.itertext())
    ]
    assert victim_nodes
    assert {node.get("data-external-id") for node in victim_nodes} == {F.USER_ID if ambiguous else min(ids)}
    assert data == before
