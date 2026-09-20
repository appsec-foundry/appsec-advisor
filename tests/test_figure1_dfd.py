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


@pytest.mark.parametrize("names", [("app0", "db0"), ("processor", "archive")])
@pytest.mark.parametrize("detail", [False, True])
def test_boundary_inventory_distinguishes_interfaces_and_uncertainty(names, detail):
    model, paths, taxonomy = _model(exposed=("app0", "app1"))
    renames = dict(zip(("app0", "db0"), names))
    for comp in model["components"]:
        comp["id"] = renames.get(comp["id"], comp["id"])
    for threat in model["threats"]:
        threat["component"] = renames.get(threat["component"], threat["component"])
    for row in model["data_flows"] + model["trust_boundaries"]:
        for key in ("from", "to"):
            row[key] = renames.get(row[key], row[key])
    model["trust_boundaries"][2].update(surface="in-process", transition=[], kind="process")
    model["trust_boundaries"][1].update(surface="network", transition=["identity"], kind="identity")
    before = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=detail)
    assert problems == []
    root = ET.fromstring(svg)
    # The internal interface tb-8 is the only crossing towards the data column.
    assert _boundary_lines(root) == {0: ["tb-1", "tb-2", "tb-9"]}
    panel = root.find("{*}g[@data-legend-section='boundaries']")
    if not detail:
        assert "3 trust boundaries (1 inferred) · " in svg
        assert "internal interface" not in svg
        assert panel is None
        assert root.find(".//{*}g[@data-boundary-marker]") is None
        assert model == before
        return
    assert "3 trust boundaries (1 inferred) · 1 internal interface" in svg
    entries = {entry.get("data-boundary-id"): " ".join(entry.itertext()) for entry in panel.findall("{*}g")}
    assert set(entries) == {"tb-1", "tb-2", "tb-8", "tb-9"}
    assert "identity" in entries["tb-2"]
    assert "no trust transition" in entries["tb-8"]
    assert "inferred" in entries["tb-9"]
    assert "no unique drawn flow" in entries["tb-1"]
    assert root.find(".//{*}g[@data-boundary-marker='tb-2']") is not None
    assert root.find(".//{*}g[@data-boundary-marker='tb-8']") is None
    assert model == before


def _boundary_lines(root):
    return {
        int(g.get("data-boundary-line")): g.get("data-boundary-ids").split()
        for g in root.iter("{http://www.w3.org/2000/svg}g")
        if g.get("data-boundary-line") is not None
    }


@pytest.mark.parametrize("status", ["unresolved", "conflicted", "invalid-endpoint"])
def test_invalid_boundaries_cannot_create_counts_markers_or_exposure(status):
    model, paths, taxonomy = _model(exposed=("app1",))
    model["trust_boundaries"] = model["trust_boundaries"][:1]
    row = model["trust_boundaries"][0]
    if status == "invalid-endpoint":
        row["from"] = "not-a-component"
    else:
        row["resolution_status"] = status
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    assert "0 trust boundaries" in svg
    assert "data-boundary-marker=" not in svg
    assert "data-boundary-id=" not in svg
    assert "TRUST BOUNDARY" not in svg


def test_boundary_audit_requires_visible_legend_entries(monkeypatch):
    original = F._legend_blocks

    def without_boundaries(*args, **kwargs):
        return [(key, block) for key, block in original(*args, **kwargs) if key != "boundaries"]

    monkeypatch.setattr(F, "_legend_blocks", without_boundaries)
    model, paths, taxonomy = _model()
    _, problems = F.check_diagram(model, paths, taxonomy, detail=True)
    assert any("boundary legend missing" in problem for problem in problems)


@pytest.mark.parametrize("transition", [["identity"], ["privilege"], ["tenant"], ["operator"]])
@pytest.mark.parametrize("detail", [False, True])
def test_in_process_trust_changes_remain_boundaries(transition, detail):
    model, paths, taxonomy = _model()
    row = next(t for t in model["trust_boundaries"] if t["id"] == "tb-8")
    row.update(surface="in-process", transition=transition, kind="process")
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=detail)
    assert problems == []
    root = ET.fromstring(svg)
    assert "internal interface</text>" not in svg
    assert "tb-8" in _boundary_lines(root)[1]
    assert "3 trust boundaries" in svg
    assert (root.find(".//{*}g[@data-boundary-marker='tb-8']") is not None) is detail
    assert (transition[0] in svg) is detail


@pytest.mark.parametrize("endpoints", [("external", "app1", "df-004"), ("app0", "db0", "df-005")])
@pytest.mark.parametrize("count", [1, 2, 5])
@pytest.mark.parametrize("detail", [False, True])
def test_shared_crossing_keeps_all_boundaries_without_off_flow_marker_stacks(endpoints, count, detail):
    model, paths, taxonomy = _model(exposed=("app1",))
    source, target, fid = endpoints
    template = model["trust_boundaries"][0]
    model["trust_boundaries"] = [
        dict(template, id=f"tb-{i}", **{"from": source, "to": target}, kind="identity", enforcement_point=f"guard-{i}")
        for i in range(1, count + 1)
    ]
    before = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=detail)
    assert problems == []
    root = ET.fromstring(svg)
    ids = [t["id"] for t in model["trust_boundaries"]]
    assert _boundary_lines(root) == {0 if source == "external" else 1: ids}
    markers = root.findall(".//{*}g[@data-boundary-marker]")
    assert len(markers) == (1 if count == 1 and detail else 0)
    entries = root.findall("{*}g[@data-legend-section='boundaries']/{*}g[@data-boundary-id]")
    assert {e.get("data-boundary-id") for e in entries} == (set(ids) if detail else set())
    assert all(f"flow {fid}" in " ".join(entry.itertext()) for entry in entries)
    assert model == before


@pytest.mark.parametrize("detail", [False, True])
def test_same_column_boundary_resolves_flow_without_inventing_a_column_crossing(detail):
    model, paths, taxonomy = _model(intra=True)
    model["trust_boundaries"] = [
        dict(
            id="tb-1",
            **{"from": "app0", "to": "app2"},
            confidence="confirmed",
            resolution_status="resolved",
            kind="identity",
        )
    ]
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=detail)
    assert problems == []
    root = ET.fromstring(svg)
    assert _boundary_lines(root) == {}
    assert "1 trust boundary" in svg
    if detail:
        entry = root.find("{*}g[@data-legend-section='boundaries']/{*}g[@data-boundary-id='tb-1']")
        assert "flow df-007" in " ".join(entry.itertext())


@pytest.mark.parametrize("axes", [{"kind": "process"}, {"kind": "network", "surface": "in-process", "transition": []}])
def test_internal_interface_does_not_imply_internet_exposure(axes):
    model, paths, taxonomy = _model(exposed=("app1",))
    model["trust_boundaries"] = model["trust_boundaries"][:1]
    model["trust_boundaries"][0].update(axes)
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    svg, state = F._build(model, scenarios, actors, detail=False)
    assert not state["nodes"]["app1"]["exposed"]
    assert "0 trust boundaries · " in svg and "internal interface" not in svg
    detail, state = F._build(model, scenarios, actors, detail=True)
    assert not state["nodes"]["app1"]["exposed"]
    assert "0 trust boundaries · 1 internal interface" in detail


@pytest.mark.parametrize("name", ["Account access", "Telemetry access"])
@pytest.mark.parametrize("mode", ["alternatives", "sequence"])
def test_explicit_access_groups_preserve_methods_and_individual_detail(name, mode):
    from tests.test_figure1_security import auth

    model, paths, taxonomy = _model()
    model["data_flows"] = [
        {
            "id": f"df-{i:03d}",
            "from": "spa",
            "to": "app0",
            "protocol": "HTTPS",
            "label": f"Operation {i}",
            "diagram_label": name,
            "interface_refs": [f"operation-{i}"],
            "authentication": auth(scheme),
            "access_group": {
                "id": "access",
                "mode": mode,
                "label": name,
                **({"step": i} if mode == "sequence" else {}),
            },
        }
        for i, scheme in enumerate(("password", "bearer"), 1)
    ]
    original = copy.deepcopy(model)
    svg, errors = F.check_diagram(model, paths, taxonomy, detail=False)
    assert not errors
    root = ET.fromstring(svg)
    edge = root.find("{*}g[@data-flow-ids='df-001 df-002']")
    assert edge is not None and edge.get("data-access-mode") == mode
    ports = root.findall("{*}g[@data-auth-flows='df-001 df-002']/{*}g[@data-authentication]")
    assert len(ports) == 2
    assert [p.get("data-authentication") for p in ports] == (["2", "1"] if mode == "sequence" else ["1", "2"])
    assert name in svg
    assert "Client Layer" in svg
    detail, errors = F.check_diagram(model, paths, taxonomy, detail=True)
    assert not errors
    detail_root = ET.fromstring(detail)
    assert detail_root.find("{*}g[@data-flow-ids='df-001']") is not None
    assert detail_root.find("{*}g[@data-flow-ids='df-002']") is not None
    assert model == original
    for flow in model["data_flows"]:
        flow.pop("access_group")
    separate, errors = F.check_diagram(model, paths, taxonomy, detail=False)
    assert not errors
    assert ET.fromstring(separate).find("{*}g[@data-flow-ids='df-001 df-002']") is None


@pytest.mark.parametrize("provider", ["Federation Gateway", "Independent Authentication Authority With A Longer Name"])
def test_overview_reference_rows_name_peers_and_keep_authentication_at_receiver(provider):
    model, paths, taxonomy = _model()
    model["external_entities"] = [
        {"id": "ext-identity", "name": provider, "kind": "identity-provider", "description": "Identity exchange"},
        {"id": "ext-profile", "name": "Profile directory", "kind": "external-service", "description": "Profile lookup"},
    ]
    for index, source, target, entity, scheme in [
        (90, "spa", "external", "ext-identity", "none"),
        (91, "external", "spa", "ext-identity", "none"),
        (92, "spa", "external", "ext-profile", "bearer"),
    ]:
        model["data_flows"].append(
            {
                "id": f"df-{index:03d}",
                "from": source,
                "to": target,
                "to_entity" if target == "external" else "from_entity": entity,
                "label": "Identity exchange",
                "protocol": "HTTPS",
                "data_classification": "Confidential",
                "protocol_group": "Federation",
                "authentication": {
                    "scheme": scheme,
                    "scope": "This operation only",
                    "evidence": [{"file": "src/access.cfg", "line": 1}],
                },
            }
        )
    before = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    root = ET.fromstring(svg)
    rows = root.findall("{*}g[@data-integration-reference]")
    assert len(rows) == 4
    client_rows = [r for r in rows if r.get("data-reference-owner") == "spa"]
    assert len(client_rows) == 2
    identity = next(r for r in rows if r.get("data-reference-owner") == "ext-identity")
    profile = next(r for r in rows if r.get("data-reference-owner") == "ext-profile")
    assert identity.get("data-reference-direction") == "↔"
    assert profile.get("data-reference-direction") == "←"
    assert "C-01" in "".join(identity.itertext())
    assert provider in " ".join(" ".join(r.itertext()) for r in client_rows)
    assert profile.find("{*}g[@data-authentication='1']") is not None
    assert all(r.find("{*}g[@data-authentication='1']") is None for r in client_rows)
    assert "Matching E-labels indicate a connection" in svg
    assert root.find("{*}g[@data-legend-section='integrations']") is None
    assert model == before
    assert F.check_diagram(model, paths, taxonomy, detail=False)[0] == svg
    detail, detail_problems = F.check_diagram(model, paths, taxonomy, detail=True)
    assert detail_problems == []
    assert "data-integration-reference=" not in detail
    assert "df-090" in detail and "df-092" in detail


def test_authentication_markers_use_the_same_hexagon_at_accesses_and_in_legend():
    model, paths, taxonomy = _model()
    root = ET.fromstring(F.check_diagram(model, paths, taxonomy, detail=False)[0])
    markers = root.findall(".//{*}g[@data-authentication]")
    assert markers
    for marker in markers:
        assert marker.get("data-authentication-shape") == "hexagon"
        assert marker.find("{*}polygon") is not None
        assert marker.find("{*}rect") is None


@pytest.mark.parametrize("prefix", ["Portal", "Field console"])
def test_overview_keeps_inventory_and_routes_humans_into_the_client(prefix):
    from tests.test_figure1_security import auth

    model, paths, taxonomy = _model(app=4, stores=2, flows=False, xss=True)
    for comp in model["components"]:
        comp["name"] = f"{prefix} {comp['id']}"
    model["external_entities"] = [
        {
            "id": f"ext-person-{i}",
            "kind": "legitimate-role",
            "name": f"{prefix} role {i}",
            "access": "internet-user" if i == 1 else "internet-priv-user",
            "description": "Uses the application",
        }
        for i in (1, 2)
    ]
    model["data_flows"] = [
        {
            "id": f"df-{i:03d}",
            "from": "external",
            "from_entity": f"ext-person-{i}",
            "to": "spa",
            "interaction": True,
            "label": "Uses UI",
            "protocol": "UI",
        }
        for i in (1, 2)
    ]
    for i in range(4):
        model["data_flows"].append(
            {
                "id": f"df-{i + 3:03d}",
                "from": "spa",
                "to": f"app{i}",
                "label": "Application requests",
                "protocol": "HTTPS",
                "authentication": auth("bearer"),
            }
        )
    for i in range(2):
        model["data_flows"].append(
            {
                "id": f"df-{i + 7:03d}",
                "from": "app0",
                "to": f"db{i}",
                "label": "Stored records",
                "protocol": "Local call",
                **({"authentication": auth("none")} if i == 0 else {}),
            }
        )
    model["assets"] = [
        {
            "id": f"A-{i + 1:03d}",
            "name": f"Record collection {i + 1}",
            "classification": "Confidential",
            "component_refs": [
                {"component_id": f"db{i % 2}", "relation": "stored", "evidence": [{"file": "src/store.cfg", "line": 1}]}
            ],
        }
        for i in range(8)
    ]
    original = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert not problems
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    _, state = F._build(model, scenarios, actors, detail=False)
    assert {c["id"] for c in model["components"]} <= state["nodes"].keys()
    assert {a["id"] for n in state["nodes"].values() for a in n.get("assets", [])} == {a["id"] for a in model["assets"]}
    assert {fid for e in state["edges"] for fid in e["ids"]} == {f["id"] for f in model["data_flows"]}
    for edge in state["edges"]:
        if not edge.get("interaction"):
            continue
        target = state["nodes"]["spa"]
        a, b = edge["draw_pts"][-2:]
        assert edge["ui_top_entry"] and a[0] == b[0] and b[1] > a[1] + 12
        assert b[1] < target["y"] and target["x"] < b[0] < target["x"] + target["w"]
    root = ET.fromstring(svg)
    assert root.find("{*}g[@data-auth-flows='df-007'][@data-authentication='0']") is not None
    assert root.find("{*}g[@data-auth-flows='df-008'][@data-authentication='?']") is not None
    assert model == original


def test_large_access_groups_keep_every_operation_instead_of_partial_sequences():
    from tests.test_figure1_security import auth

    model, paths, taxonomy = _model()
    model["data_flows"] = [
        {
            "id": f"df-{i:03d}",
            "from": "spa",
            "to": "app0",
            "protocol": "HTTPS",
            "label": "Verification",
            "authentication": auth(scheme),
            "interface_refs": [f"check-{i}"],
            "access_group": {"id": "checks", "mode": "sequence", "label": "Three checks", "step": i},
        }
        for i, scheme in enumerate(("password", "private-key", "bearer"), 1)
    ]
    svg, errors = F.check_diagram(model, paths, taxonomy, detail=False)
    assert not errors
    root = ET.fromstring(svg)
    for i in (1, 2, 3):
        assert root.find(f"{{*}}g[@data-flow-ids='df-{i:03d}']") is not None
    # Even an equal method on the same interface cannot erase distinct steps.
    for flow in model["data_flows"]:
        flow["authentication"] = auth("password")
        flow["interface_refs"] = ["shared-interface"]
    for detail in (False, True):
        svg, errors = F.check_diagram(model, paths, taxonomy, detail=detail)
        assert not errors
        root = ET.fromstring(svg)
        for i in (1, 2, 3):
            assert root.find(f"{{*}}g[@data-flow-ids='df-{i:03d}']") is not None


def test_reference_footers_wrap_long_names_and_multiple_receiving_methods():
    model, paths, taxonomy = _model()
    model["external_entities"] = [
        {
            "id": "ext-directory",
            "kind": "external-service",
            "name": "Partner <Directory> & Federation Service",
            "description": "A distinct subtitle above the reference footer",
        }
    ]
    schemes = ["none", "bearer", "basic", "password", "mtls", "private-key", "cookie"]
    for index, scheme in enumerate(schemes, 90):
        model["data_flows"].append(
            {
                "id": f"df-{index:03d}",
                "from": "spa",
                "to": "external",
                "to_entity": "ext-directory",
                "label": "Directory request",
                "protocol": "HTTPS",
                "data_classification": "Confidential",
                "protocol_group": "Federated directory",
                "authentication": {
                    "scheme": scheme,
                    "scope": f"Operation {index}",
                    "evidence": [{"file": "src/access.cfg", "line": 1}],
                },
            }
        )
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    root = ET.fromstring(svg)
    rows = root.findall("{*}g[@data-reference-owner='ext-directory']")
    assert len(rows) == 4
    assert sum(len(r.findall("{*}g[@data-authentication]")) for r in rows) == len(schemes)
    subtitle = next(t for t in root.findall(".//{*}text") if "distinct subtitle" in (t.text or ""))
    assert float(subtitle.get("y")) < min(float(r.find("{*}rect").get("y")) for r in rows) - 4
    assert "&lt;Directory&gt; &amp;" in svg


@pytest.mark.parametrize("side", ["left", "right"])
def test_hexagon_ports_leave_a_four_unit_arrow_gap(side):
    edge = {"pts": [(0 if side == "left" else 200, 50), (100, 50)]}
    pts = F._authentication_endpoint(edge, {"_auth_catalog": {"present": True}})
    assert abs(pts[-1][0] - edge["auth_port"][0]) == 20 + 4
    assert edge["pts"][-1] == (100, 50)


@pytest.mark.parametrize("rename", [False, True])
def test_overview_authentication_ports_are_evidenced_and_geometry_checked(rename):
    model, paths, taxonomy = _model()
    for i, flow in enumerate(model["data_flows"]):
        flow["label"] = "Telemetry" if rename else "Records"
        flow["authentication"] = {
            "scheme": "bearer" if i % 2 else "none",
            "scope": "This access",
            "evidence": [{"file": "src/guard.cfg", "line": 3}],
        }
    if rename:
        for comp in model["components"]:
            comp["name"] = "Renamed " + comp["id"]
    before = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    root = ET.fromstring(svg)
    assert "Figure 1 — Architecture and Threat Overview" in svg
    assert root.find("{*}g[@data-legend-section='flows']") is None
    assert root.find("{*}g[@data-legend-section='boundaries']") is None
    assert root.find("{*}g[@data-legend-section='authentication']") is not None
    assert len(root.findall("{*}g[@data-authentication='0']")) >= 1
    assert model == before


@pytest.mark.parametrize("app", [1, 3, 9])
@pytest.mark.parametrize("stores", [0, 2])
@pytest.mark.parametrize("xss", [False, True])
@pytest.mark.parametrize("intra", [False, True])
def test_overview_layout_is_generic_across_topologies(app, stores, xss, intra):
    model, paths, taxonomy = _model(app=app, stores=stores, xss=xss, intra=intra)
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    assert "Architecture and Threat Overview" in svg


def test_geometry_rejects_longitudinal_boundary_overlap_and_label_crossings():
    canvas = F._Canvas()
    edge = {"src": "client", "dst": "api", "ids": ["df-001"], "pts": [(20, 20), (60, 20), (60, 90), (100, 90)]}
    nodes = {
        "client": {"id": "client", "x": 0, "y": 0, "w": 20, "h": 40},
        "api": {"id": "api", "x": 100, "y": 80, "w": 20, "h": 40},
    }
    assert F._check_geometry(nodes, [edge], canvas, [], boundaries=[80]) == []
    assert any("runs along" in p for p in F._check_geometry(nodes, [edge], canvas, [], boundaries=[62]))
    canvas.labels.append((55, 40, 65, 50, "payload test"))
    assert any("payload label crosses" in p for p in F._check_geometry(nodes, [edge], canvas, []))


@pytest.mark.parametrize("title", ["Template Injection Reads Private Records", "Forged Tokens Impersonate Other Users"])
def test_scenario_title_is_preserved_without_inventing_mechanisms(title):
    model, paths, taxonomy = _model()
    paths["attack_paths"][0]["scenario_title"] = title
    before = copy.deepcopy((model, paths, taxonomy))
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    assert title in svg
    assert (model, paths, taxonomy) == before


@pytest.mark.parametrize("endpoint,label", [("app0", "Signed event delivery"), ("app1", "Inventory updates")])
def test_flow_legend_groups_drawn_edges_and_keeps_all_flow_meanings(endpoint, label):
    model, paths, taxonomy = _model()
    for flow in model["data_flows"][1:3]:
        flow["to"] = endpoint
        flow["direction"] = "bidirectional"
        flow["label"] = "A complete description retained in the canonical model"
    model["data_flows"][1]["diagram_label"] = label
    model["data_flows"][2]["diagram_label"] = "Live notifications"
    before = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    panel = ET.fromstring(svg).find("{*}g[@data-legend-section='flows']")
    text = " ".join(t.text or "" for t in panel.iter("{http://www.w3.org/2000/svg}text"))
    assert "df-002/003" in text
    assert label in text and "Live notifications" in text
    assert "HTTP" in text and "WebSocket" in text
    assert "Service 0" not in text and "Web SPA" not in text
    assert model == before


def test_actor_grouping_is_explained_inside_its_node():
    model, paths, taxonomy = _model()
    model["meta"].update(open_user_registration=True, public_source_repo=True)
    paths["attack_paths"][0]["actor"] = "repo-read"
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    root = ET.fromstring(svg)
    assert root.find("{*}g[@data-legend-section='actors']") is None
    node = root.find("{*}g[@data-actor-grouping='A1']")
    assert node is not None
    text = " ".join(node.itertext())
    assert "Self-registered users" in text and "Public-source readers" in text
    assert "Login / privileges: per finding" in text


def test_actor_note_geometry_still_rejects_overflow_and_foreign_nodes():
    canvas = F._Canvas()
    canvas.label_owners["note"] = "actor"
    canvas.labels = [(10, 10, 80, 20, "note")]
    nodes = {"actor": dict(id="actor", x=0, y=0, w=100, h=40)}
    assert F._check_geometry(nodes, [], canvas, []) == []
    nodes["actor"]["w"] = 50
    assert any("outside owner" in p for p in F._check_geometry(nodes, [], canvas, []))
    nodes["actor"]["w"] = 100
    nodes["foreign"] = dict(id="foreign", x=20, y=10, w=100, h=40)
    assert any("label on node: note × foreign" in p for p in F._check_geometry(nodes, [], canvas, []))


def test_long_legacy_flow_labels_and_grouped_ids_remain_visible():
    model, paths, taxonomy = _model()
    flows = []
    for index in range(1, 9):
        flows.append(dict(model["data_flows"][1], id=f"df-{index:03d}", label="LongUnbrokenPayloadName" * 4))
    model["data_flows"] = flows
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    panel = ET.fromstring(svg).find("{*}g[@data-legend-section='flows']")
    text = "".join(t.text or "" for t in panel.iter("{http://www.w3.org/2000/svg}text"))
    assert "LongUnbrokenPayloadName" * 4 in text
    assert "df-001/002/003/004/005/006/007/008" in text.replace(" ", "")


@pytest.mark.parametrize("compact", [True, False])
@pytest.mark.parametrize(
    "protocol,purpose",
    [
        ("OIDC / HTTPS", "Identity claims and login"),
        ("MCP / stdio", "Tool calls and results"),
        ("MCP / Streamable HTTP", "Tool calls and resource reads"),
        ("TCP / binary frames", "Binary telemetry"),
        ("Unix domain socket", "Local worker messages"),
        ("UDP", "Sensor measurements"),
        ("gRPC / HTTP/2", "Inventory synchronization"),
        ("CustomWire-v42", "Proprietary device commands"),
    ],
)
def test_flow_legends_accept_arbitrary_protocols_without_catalogs(protocol, purpose, compact):
    model, paths, taxonomy = _model()
    flow = dict(model["data_flows"][1], protocol=protocol, label=purpose, direction="bidirectional")
    if compact:
        flow["diagram_label"] = purpose
        flow["label"] = "Complete canonical evidence-backed purpose of this connection"
    model["data_flows"] = [flow]
    before = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    panel = ET.fromstring(svg).find("{*}g[@data-legend-section='flows']")
    text = " ".join(t.text or "" for t in panel.iter("{http://www.w3.org/2000/svg}text"))
    assert protocol in text and purpose in text and "↔" in text
    assert model == before


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
        "df-002",
        "df-003",
        "df-005",
        "tb-1",
        "tb-8",
        "Trust boundaries and internal interfaces",
        "no displayed component mapping",
    ):
        assert token in svg, token


@pytest.mark.parametrize("name", ["Dispatch service", "Archive gateway"])
def test_legend_uses_diagram_width_and_stays_below_all_nodes(name):
    model, paths, taxonomy = _model()
    model["components"][1]["name"] = name
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    svg, state = F._build(model, scenarios, actors)
    root = ET.fromstring(svg)
    panels = root.findall("{*}g[@data-legend-section]")
    assert panels, "Legend sections must be independently placed below the diagram"
    rightmost = max(n["x"] + n["w"] for n in state["nodes"].values())
    assert float(root.get("width")) < rightmost + F.LEGEND_W
    bottom = max(n["y"] + n["h"] for n in state["nodes"].values())
    for panel in panels:
        x, y = map(float, re.fullmatch(r"translate\((\S+) (\S+)\)", panel.get("transform")).groups())
        assert y > bottom
        assert x >= F.MARGIN
        assert x + F.LEGEND_W <= float(root.get("width")) - F.MARGIN
    assert len({p.get("data-legend-column") for p in panels}) >= 2
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_legend_balances_heights_and_keeps_small_assets_with_boundaries():
    sections = [
        ("notation", 317),
        ("actors", 98),
        ("scenarios", 169),
        ("boundaries", 96),
        ("flows", 388),
        ("assets", 114),
    ]
    small = F._legend_columns(sections, 3)
    assert small == (0, 0, 1, 1, 2, 1)
    large = F._legend_columns([*sections[:-1], ("assets", 570)], 3)
    assert large != small
    assert large.count(large[-1]) == 1  # A tall asset block gets its own column.
    assert F._legend_columns(sections, 3) == small


@pytest.mark.parametrize("asset_count,flow_repetitions", [(2, 1), (18, 1), (2, 12)])
def test_legend_keeps_complete_flows_and_explains_unmapped_assets(asset_count, flow_repetitions):
    model, paths, taxonomy = _model()
    model["assets"] = [
        {"id": f"A-{index:03d}", "name": f"Record collection {index}", "classification": "Internal"}
        for index in range(asset_count)
    ]
    model["data_flows"][1]["label"] = " ".join(["Signed event payload"] * flow_repetitions)
    model["meta"]["open_user_registration"] = True
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    svg, state = F._build(model, scenarios, actors, F.overview_actor_groups(model, paths, taxonomy))
    root = ET.fromstring(svg)
    panels = {p.get("data-legend-section"): p for p in root.findall("{*}g[@data-legend-section]")}
    text = lambda p: " ".join(t.text or "" for t in p.iter("{http://www.w3.org/2000/svg}text"))
    assert model["data_flows"][1]["label"] in text(panels["flows"])
    grouped_ids = " ".join(group.get("data-flow-ids") for group in panels["flows"].findall("{*}g[@data-flow-ids]"))
    for flow in model["data_flows"]:
        assert grouped_ids.split().count(flow["id"]) == 1
        assert flow["id"] in " ".join(panels["flows"].itertext())
    assert "assets" not in panels
    assert f"{asset_count} assets have no displayed component mapping" in text(panels["notes"])
    assert state["d"]["assets"] == model["assets"]
    assert "actors" not in panels
    assert "Self-registered users" in text(root.find("{*}g[@data-actor-grouping]"))
    assert all(y1 <= float(root.get("height")) - F.MARGIN for _, _, _, y1, _ in state["canvas"].legend_boxes)
    assert F._check_geometry(state["nodes"], state["edges"], state["canvas"], state["chips"]) == []


def test_legend_omits_empty_sections_and_keeps_evidenced_assets_on_stores():
    model, _, _ = _model(flows=False)
    model["trust_boundaries"] = []
    model["assets"] = [
        {
            "id": "A-001",
            "name": "Audit records",
            "classification": "Internal",
            "component_refs": [
                {"component_id": "db0", "relation": "stored", "evidence": [{"file": "src/store.ts", "line": 4}]}
            ],
        }
    ]
    svg, state = F._build(model, [], [])
    panels = ET.fromstring(svg).findall("{*}g[@data-legend-section]")
    assert [p.get("data-legend-section") for p in panels] == ["notation"]
    assert state["nodes"]["db0"]["assets"][0]["id"] == "A-001"
    assert "Audit records" in svg


def test_legend_geometry_gate_rejects_overlapping_blocks():
    model, paths, taxonomy = _model()
    _, state = F._build(model, *F.scenarios_from_attack_paths(model, paths, taxonomy))
    canvas = state["canvas"]
    canvas.legend_boxes[1] = (*canvas.legend_boxes[0][:4], "overlapping section")
    problems = F._check_geometry(state["nodes"], state["edges"], canvas, state["chips"])
    assert any(p.startswith("legend overlap:") for p in problems)


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


@pytest.mark.parametrize(
    ("relation", "linked", "badges"),
    [("stored", ["T-009"], [("1", "Anon")]), ("processed", ["T-009"], []), ("stored", [], [])],
)
def test_a_scenario_that_hits_stored_data_badges_the_storing_component(relation, linked, badges):
    model, _, _ = _model()
    model["assets"][0]["component_refs"] = [
        {"component_id": "db0", "relation": relation, "evidence": [{"file": "src/store.ts", "line": 1}]}
    ]
    model["assets"][0]["linked_threats"] = linked
    # The finding sits in app0; only the linked stored asset connects the scenario to db0.
    scenarios = [
        dict(n="1", title="Injection", actor="Anon", actor_slug="internet-anon", victim=False, cids=["app0"], fids=[9])
    ]
    actors = [{"name": "Anon", "slug": "internet-anon", "sub": "", "attacker": True}]
    svg, state = F._build(model, scenarios, actors)
    assert state["nodes"]["db0"]["badges"] == badges
    assert state["nodes"]["app0"]["badges"] == [("1", "Anon")]
    asset = ET.fromstring(svg).find("{*}g[@data-asset-id='A-001']")
    assert not [t.text for t in asset.iter(f"{_SVG}text") if (t.text or "").isdigit()]


def test_bidirectional_flow_gets_two_heads():
    svg = _checked()
    root = ET.fromstring(svg)
    websocket = root.find("{*}g[@data-flow-ids='df-003']/{*}path")
    http = root.find("{*}g[@data-flow-ids='df-002']/{*}path")
    assert websocket.get("marker-start") == "url(#arw-Internal)"
    assert http.get("marker-start") is None


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


@pytest.mark.parametrize("offset", [3, -5, 20])
@pytest.mark.parametrize("names", [("sender", "receiver"), ("gateway", "archive")])
def test_nearly_aligned_flow_ports_avoid_micro_jogs(offset, names):
    nodes = {
        name: dict(id=name, col=col, zone="application", order=col, w=190, h=100 + col * (72 + offset * 2))
        for col, name in enumerate(names)
    }
    edge = dict(src=names[0], dst=names[1], ids=["df-081"], tb=[])
    F._layout(nodes, [edge], {}, {}, ncols=2)
    delta = edge["yd"] - edge["ys"]
    assert delta == 0  # Larger offsets can align too when both ports have room.


@pytest.mark.parametrize("occupied,attack,skip", [(True, False, False), (False, True, False), (False, False, True)])
def test_port_alignment_retains_spacing_and_special_routes(occupied, attack, skip):
    nodes = {"sink": dict(y=0, h=100, tagspace=0)}
    edge = dict(src="source", dst="sink", ys=50, yd=55, kind="forward", attack=attack, skip=skip)
    sides = {"sink": {"L": [("in", edge)]}}
    if occupied:
        sides["sink"]["L"].append(("in", dict(yd=30)))
    F._align_flow_ports(nodes, [edge], sides)
    assert edge["yd"] == 55


def _port_heights(nodes, edges):
    """Port heights per node side; one attacker's bus counts as a single port."""
    sides = {}
    for e in edges:
        if e["kind"] == "intra":
            continue
        for nid, (x, y) in ((e["src"], e["pts"][0]), (e["dst"], e["pts"][-1])):
            node = nodes[nid]
            if x not in (node["x"], node["x"] + node["w"]):
                continue  # a stub starts on its attacker's bus, not on the node
            bus = e.get("attack") and nid == e["src"] and e["kind"] == "forward" and "scen" in e
            sides.setdefault((nid, x), {})[("bus", nid) if bus else id(e)] = y
    return sides


@pytest.mark.parametrize("flows", [0, 2, 7])
@pytest.mark.parametrize("spacer", [0, 1])
def test_attack_stub_continues_straight_when_its_target_spans_the_bus(flows, spacer):
    nodes = {
        "attacker": dict(id="attacker", col=0, zone="client", order=0, col_rank=0, w=190, h=76),
        "sender": dict(id="sender", col=0, zone="client", order=1, col_rank=1, w=190, h=80),
        "target": dict(id="target", col=1, zone="application", order=0, col_rank=1, w=190, h=240),
        "other": dict(id="other", col=1, zone="application", order=1, col_rank=2, w=190, h=100),
    }
    if spacer:  # pushes the target below the attacker's bus height
        nodes["spacer"] = dict(id="spacer", col=1, zone="application", order=0, col_rank=0, w=190, h=260)
    edges = [dict(src="attacker", dst=target, ids=[], tb=[], attack=True, scen=["1"]) for target in ("target", "other")]
    edges += [dict(src="sender", dst="target", ids=[f"df-{i:03d}"], tb=[]) for i in range(flows)]
    F._layout(nodes, edges, {}, {}, ncols=2)
    stub = next(e for e in edges if e.get("attack") and e["dst"] == "target")
    target = nodes["target"]
    low, high = F._port_range(target)
    spans = low <= stub["ys"] <= high
    assert spans is not bool(spacer)
    for heights in _port_heights(nodes, edges).values():
        ordered = sorted(heights.values())
        assert all(b - a >= F.PORT_STEP - 1e-6 for a, b in zip(ordered, ordered[1:]))
    if spans and flows < 7:
        assert stub["yd"] == stub["ys"]
        assert len(F._trim(stub["pts"])) == 2 or F._trim(stub["pts"])[-2][1] == stub["ys"]
    assert low - 1e-6 <= stub["yd"] <= high + 1e-6
    assert F._check_geometry(nodes, edges, F._Canvas(), [], boundaries=[]) == []


def test_boxed_in_parallel_routes_straighten_together():
    def node(nid, x, y, h):
        return dict(id=nid, x=x, y=y, w=200, h=h, tagspace=0, col=x // 600)

    nodes = {
        "src": node("src", 0, 280, 280),
        "dst": node("dst", 600, 260, 154),
        "above": node("above", 600, 0, 250),
        "below": node("below", 600, 520, 200),
        "early": node("early", 0, 0, 250),
        "late": node("late", 0, 600, 200),
    }

    def flow(src, dst, route, i, fixed=False):
        ids = [] if fixed else [f"df-{i:03d}"]
        return dict(src=src, dst=dst, kind="forward", skip=False, ids=ids, tb=[], pts=route, attack=fixed)

    # Fixed neighbours leave each flow of the pair no straight height of its own.
    edges = [
        flow("src", "above", [(200, 313), (400, 313), (400, 200), (600, 200)], 1, fixed=True),
        flow("src", "below", [(200, 390), (410, 390), (410, 600), (600, 600)], 2, fixed=True),
        flow("early", "dst", [(200, 100), (420, 100), (420, 284.5), (600, 284.5)], 3, fixed=True),
        flow("late", "dst", [(200, 700), (430, 700), (430, 381), (600, 381)], 4, fixed=True),
        flow("src", "dst", [(200, 346), (300, 346), (300, 324), (600, 324)], 5),
        flow("src", "dst", [(200, 368), (310, 368), (310, 352.5), (600, 352.5)], 6),
    ]
    for e in edges:
        e["ys"], e["yd"] = e["pts"][0][1], e["pts"][-1][1]
    F._improve_routes(nodes, edges, [], [])
    pair = [e for e in edges if (e["src"], e["dst"]) == ("src", "dst")]
    assert all(e["pts"][0][1] == e["pts"][-1][1] for e in pair)
    for heights in _port_heights(nodes, edges).values():
        ordered = sorted(heights.values())
        assert all(b - a >= F.PORT_STEP - 1e-6 for a, b in zip(ordered, ordered[1:]))
    assert F._check_geometry(nodes, edges, F._Canvas(), [], boundaries=[]) == []


@pytest.mark.parametrize("reverse", [False, True])
def test_intra_column_arrow_tips_have_a_straight_approach(reverse):
    model, paths, taxonomy = _model(intra=True)
    if reverse:
        flow = model["data_flows"][-1]
        flow["from"], flow["to"] = flow["to"], flow["from"]
    _, state = F._build(model, *F.scenarios_from_attack_paths(model, paths, taxonomy))
    edge = next(e for e in state["edges"] if e["ids"] == ["df-007"])
    points = F._trim(edge["pts"])
    assert abs(points[1][0] - points[0][0]) >= 24
    assert abs(points[-1][0] - points[-2][0]) >= 24
    assert F.check_diagram(model, paths, taxonomy)[1] == []


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


@pytest.mark.parametrize("variant", [False, True])
@pytest.mark.parametrize("direction", ["forward", "backward"])
def test_flow_lanes_separate_opposing_stubs_at_equal_port_heights(variant, direction):
    names = ("df-063", "df-074") if variant else ("df-021", "df-032")
    flows = [
        {"ids": [name], "ys": ys, "yd": yd, "kind": direction, "skip": False, "src": name, "dst": "service"}
        for name, ys, yd in ((names[0], 50, 100), (names[1], 100, 300))
    ]
    if direction == "backward":
        for edge in flows:
            edge["ys"], edge["yd"] = edge["yd"], edge["ys"]

    def routed(order):
        edges = copy.deepcopy(order)
        for index, edge in enumerate(edges):
            lane = 140 + index * 10
            left, right = (edge["ys"], edge["yd"]) if direction == "forward" else (edge["yd"], edge["ys"])
            edge["pts"] = [(0, left), (lane, left), (lane, right), (250, right)]
        return edges

    assert any("collinear horizontal overlap" in p for p in F._check_geometry({}, routed(flows), F._Canvas(), []))
    ordered = F._flow_lane_order(flows)
    assert ordered == flows[::-1]
    assert F._check_geometry({}, routed(ordered), F._Canvas(), []) == []
    flows[1]["ys" if direction == "forward" else "yd"] += 5
    assert F._flow_lane_order(flows) == flows


def test_cyclic_lane_constraints_remain_visible_to_the_geometry_gate():
    flows = [
        {"ys": 10, "yd": 20, "kind": "forward", "skip": False},
        {"ys": 20, "yd": 10, "kind": "forward", "skip": False},
    ]
    assert F._flow_lane_order(flows) == flows
    for index, edge in enumerate(flows):
        lane = 140 + index * 10
        edge.update(src="client", dst="service", ids=[f"df-{index + 1:03d}"])
        edge["pts"] = [(0, edge["ys"]), (lane, edge["ys"]), (lane, edge["yd"]), (250, edge["yd"])]
    assert any("collinear horizontal overlap" in p for p in F._check_geometry({}, flows, F._Canvas(), []))


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
    svg, problems = F.check_diagram(y, apd, tax, detail=False)
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


def test_multiple_stores_do_not_invent_asset_locations():
    svg = _checked(stores=2)
    root = ET.fromstring(svg)
    assert root.find("{*}g[@data-legend-section='assets']") is None
    assert root.find("{*}g[@data-asset-id]") is None
    assert "no displayed component mapping" in svg


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


@pytest.mark.parametrize("registration,public_source", [(True, False), (False, True), (True, True), (False, False)])
def test_actor_grouping_is_explained_in_standalone_dfd(registration, public_source):
    model, paths, taxonomy = _model()
    model["meta"].update(open_user_registration=registration, public_source_repo=public_source)
    for actor in ("repo-read", "internet-priv-user", "build-time"):
        paths["attack_paths"].append(dict(paths["attack_paths"][0], actor=actor))
    original = copy.deepcopy((model, paths, taxonomy))
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    assert svg == F.build_figure1_dfd_svg(model, paths, taxonomy)
    text = " ".join(ET.fromstring(svg).itertext())
    assert ("Self-registered users" in text) == registration
    assert ("Public-source readers" in text) == public_source
    assert ("Includes:" in text) == (registration or public_source)
    actors = F.scenarios_from_attack_paths(model, paths, taxonomy)[1]
    assert {"internet-priv-user", "build-time"} <= {a["slug"] for a in actors}
    assert (model, paths, taxonomy) == original


@pytest.mark.parametrize(
    "label,leading_actors",
    [
        ("External caller", ()),
        ("Public client", ("internet-priv-user",)),
        ("Internet visitor", ("internet-priv-user", "build-time")),
    ],
)
def test_compact_grouping_references_the_actual_drawn_actor(label, leading_actors):
    model, paths, taxonomy = _model()
    model["meta"]["public_source_repo"] = True
    paths["attack_paths"] = [dict(paths["attack_paths"][0], actor="repo-read")]
    paths["attack_paths"][:0] = [dict(paths["attack_paths"][0], actor=a) for a in leading_actors]
    labels = {"internet-anon": {"label": label}}
    svg, problems = F.check_diagram(model, paths, taxonomy, actor_labels=labels)
    assert problems == []
    root = ET.fromstring(svg)
    panel = root.find("{*}g[@data-actor-grouping]")
    assert panel is not None
    text = " ".join(panel.itertext())
    actor_code = f"A{len(leading_actors) + 1}"
    assert actor_code in text.split()
    assert re.findall(r"\bA\d+\b", text) == [actor_code]
    assert label in text
    assert f"{actor_code} · {label}" in " ".join(root.itertext())
    assert "Public-source readers" in text
    assert "Self-registered users" not in text
    assert "because" not in text
    assert "Login / privileges: per finding" in text
    assert panel.find("{*}circle") is not None  # The note belongs to the actual actor icon.
    notation = root.find("{*}g[@data-legend-section='notation']")
    assert notation.find("{*}text").text == "Notation"


def test_grouping_hints_require_a_performed_fold_and_a_drawn_target():
    model, paths, taxonomy = _model()
    model["meta"].update(open_user_registration=True, public_source_repo=True)
    model["threats"][0]["vektor"] = "repo-read"
    paths["attack_paths"] = [dict(paths["attack_paths"][0], actor="internet-priv-user")]
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    assert ET.fromstring(svg).find("{*}g[@data-legend-section='actors']") is None
    assert ET.fromstring(svg).find("{*}g[@data-actor-grouping]") is None
    # A stale grouping supplied to the internal replay path cannot label an absent target.
    svg, _ = F._build(model, [], [], [("repo-read", "internet-anon")])
    assert ET.fromstring(svg).find("{*}g[@data-legend-section='actors']") is None
    assert ET.fromstring(svg).find("{*}g[@data-actor-grouping]") is None


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


def _role_access_model(registration=True, access=True, variant=False):
    model, paths, taxonomy = _model(xss=True)
    model["meta"]["open_user_registration"] = registration
    names = ("Editor", "Reviewer") if variant else ("Reader", "Contributor")
    ids = ("ext-alpha", "ext-beta") if variant else ("ext-first", "ext-second")
    model["external_entities"] = [
        {"id": key, "name": name, "kind": "legitimate-role", **({"access": slug} if access else {})}
        for key, name, slug in (
            (ids[0], names[0], "internet-anon"),
            (ids[1], names[1], "internet-user"),
            ("ext-operator", "User", "internet-priv-user"),
            ("ext-auditor", "Member", "internet-priv-user"),
        )
    ]
    model["data_flows"][0]["from_entity"] = ids[0]
    model["data_flows"][3]["from_entity"] = ids[1]
    model["data_flows"].append(
        {
            "id": "df-011",
            "from": "spa",
            "to": "external",
            "to_entity": ids[1],
            "protocol": "HTTPS",
        }
    )
    return model, paths, taxonomy, ids


@pytest.mark.parametrize("registration", [True, False, None, "false"])
@pytest.mark.parametrize("access", [True, False])
@pytest.mark.parametrize("variant", [True, False])
def test_role_access_projection_remaps_both_flow_ends_without_changing_canonical_model(registration, access, variant):
    model, paths, taxonomy, ids = _role_access_model(registration, access, variant)
    before = copy.deepcopy(model)
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    svg, state = F._build(model, scenarios, actors)
    folded = registration is True and access
    assert sum(key in state["nodes"] for key in ids) == (1 if folded else 2)
    assert "ext-operator" in state["nodes"] and "ext-auditor" in state["nodes"]
    assert (F.USER_ID not in state["nodes"]) is folded
    flows = {f["id"]: f for f in state["d"]["data_flows"]}
    if folded:
        target = next(key for key in ids if key in state["nodes"])
        assert (
            flows["df-001"]["from_entity"] == flows["df-004"]["from_entity"] == flows["df-011"]["to_entity"] == target
        )
        assert all(edge["dst"] == target for edge in state["edges"] if edge.get("victim"))
        assert state["nodes"][target]["victim_label"] == "victim of ③"
        assert "self-registration is open" in " ".join(F.legitimate_role_notes(model))
        assert "Individual flows may still require login" not in svg
    assert model == before
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_unclassified_role_keeps_the_generic_victim_separate():
    model, paths, taxonomy, ids = _role_access_model()
    model["external_entities"].append({"id": "ext-unknown", "name": "Participant", "kind": "legitimate-role"})
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    _, state = F._build(model, scenarios, actors)
    assert sum(key in state["nodes"] for key in ids) == 1
    assert F.USER_ID in state["nodes"]
    assert all(edge["dst"] == F.USER_ID for edge in state["edges"] if edge.get("victim"))
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def test_equal_regular_access_can_fold_without_open_registration():
    model, paths, taxonomy, ids = _role_access_model(registration=False)
    model["external_entities"][0]["access"] = "internet-user"
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    _, state = F._build(model, scenarios, actors)
    assert sum(key in state["nodes"] for key in ids) == 1
    target = next(key for key in ids if key in state["nodes"])
    assert state["nodes"][target]["name"] == f"{model['meta']['project']} User"
    assert F.check_diagram(model, paths, taxonomy)[1] == []


@pytest.mark.parametrize(("project", "prefix"), [({"name": "Order Gateway"}, "Order Gateway "), (None, "")])
def test_classified_roles_carry_the_project_name_and_privileged_roles_stay_distinct(project, prefix):
    model, paths, taxonomy, ids = _role_access_model(registration=False)
    model["meta"].pop("project")
    if project:
        model["project"] = project
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    svg, state = F._build(model, scenarios, actors, detail=False)
    names = {key: state["nodes"][key]["name"] for key in (*ids, "ext-operator", "ext-auditor")}
    # Two privileged roles would share one name, so both keep their authored names.
    assert names == {
        ids[0]: prefix + "Visitor",
        ids[1]: prefix + "User",
        "ext-operator": "User",
        "ext-auditor": "Member",
    }
    assert "Application users and administrators" in svg
    model["external_entities"] = [e for e in model["external_entities"] if e["id"] != "ext-auditor"]
    svg, state = F._build(model, scenarios, actors, detail=False)
    assert state["nodes"]["ext-operator"]["name"] == prefix + "Admin"
    model["external_entities"] = [e for e in model["external_entities"] if e["id"] != "ext-operator"]
    svg, state = F._build(model, scenarios, actors, detail=False)
    assert "Application users and administrators" not in svg and "Application users" in svg
    assert "Browser" not in " ".join(n["name"] for n in state["nodes"].values())


@pytest.mark.parametrize("second", ["app1", "app2"])
def test_attack_edge_targets_the_finding_component_and_names_other_affected_ones_in_its_tooltip(second):
    model, paths, taxonomy = _model(exposed=("app0", second))
    next(t for t in model["threats"] if t["id"] == "T-003")["merged_from"] = ["app0", second]
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    svg, state = F._build(model, scenarios, actors)
    injection = [e for e in state["edges"] if e.get("attack") and "1" in e["scen"]]
    assert [e["dst"] for e in injection] == ["app0"]
    second_name = state["nodes"][second]["name"]
    assert injection[0]["also"] == [second_name]
    assert f"its findings also affect {second_name}" in svg
    assert "1" in {n for n, _ in state["nodes"][second]["badges"]}


def test_unnamed_flows_are_not_assigned_to_the_merged_victim_role():
    model, paths, taxonomy, ids = _role_access_model()
    model["data_flows"].append({"id": "df-012", "from": "external", "to": "spa", "protocol": "HTTPS"})
    before = copy.deepcopy(model)
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    _, state = F._build(model, scenarios, actors)
    assert F.USER_ID in state["nodes"]
    assert next(edge for edge in state["edges"] if "df-012" in edge["ids"])["src"] == F.USER_ID
    assert "victim" not in state["nodes"][F.USER_ID]["sub"]
    target = next(key for key in ids if key in state["nodes"])
    assert all(edge["dst"] == target for edge in state["edges"] if edge.get("victim"))
    assert model == before
    assert F.check_diagram(model, paths, taxonomy)[1] == []


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
    assert len(state["nodes"]["app0"]["weak"]) == 5
    assert len(state["nodes"]["app1"]["weak"]) == 4
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


def test_annotations_filter_medium_findings_deduplicate_and_fill_five():
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
                ("CWE-611", "High"),
                ("CWE-22", "High"),
            ],
            1,
        )
    ]
    rows = F._component_weaknesses(model)["app0"]
    assert len(rows) == 5
    assert rows[0] == ("Unsafe Query Construction (SQLi)", 2, 0)
    assert all(rank <= 1 for _label, _count, rank in rows)
    assert not {"Insufficient Resource Limits", "Insecure Output Handling"} & {label for label, _count, _rank in rows}
    assert all(len(label) <= 32 for label, _count, _rank in rows)
    assert F.check_diagram(model, paths, taxonomy)[1] == []


@pytest.mark.parametrize("component", ["app0", "db0"])
@pytest.mark.parametrize("critical_count", [0, 2, 5, 7, 8])
def test_annotations_keep_all_critical_and_fill_remaining_slots_with_high(component, critical_count):
    model, paths, taxonomy = _model()
    cwes = ["CWE-89", "CWE-79", "CWE-78", "CWE-94", "CWE-611", "CWE-22", "CWE-798", "CWE-862"]
    model["threats"] = [
        {
            "id": f"T-{i + 1:03d}",
            "component": component,
            "cwe": cwe,
            "risk": "Critical" if i < critical_count else "High",
        }
        for i, cwe in enumerate(cwes)
    ]
    model["threats"].append(dict(model["threats"][-1], id="T-099"))
    if component == "db0":
        model["assets"][0]["component_refs"] = [
            {"component_id": component, "relation": "stored", "evidence": [{"file": "schema.sql", "line": 1}]}
        ]
    original = copy.deepcopy(model)
    rows = F._component_weaknesses(model)[component]
    assert len(rows) == max(5, critical_count)
    assert sum(rank == 0 for _label, _count, rank in rows) == critical_count
    assert sum(rank == 1 for _label, _count, rank in rows) == max(0, 5 - critical_count)
    assert [rank for _label, _count, rank in rows] == sorted(rank for _label, _count, rank in rows)
    svg, issues = F.check_diagram(model, paths, taxonomy)
    assert issues == []
    assert "All Critical · High fills to 5 · +N = omitted High categories" in svg
    texts = " ".join(node.text or "" for node in ET.fromstring(svg).iter("{http://www.w3.org/2000/svg}text"))
    for label, _count, _rank in rows:
        assert label in texts
    omitted = 8 - max(5, critical_count)
    if omitted:
        assert f"+{omitted} more High" in texts
    else:
        assert "more High" not in texts
    assert model == original
    model["threats"].reverse()
    assert F._component_weaknesses(model)[component] == rows


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


def test_annotation_renaming_does_not_change_top_five_selection(monkeypatch):
    model = {
        "threats": [
            {"id": f"T-{i:03d}", "component": "service", "cwe": cwe, "risk": "High"}
            for i, cwe in enumerate(["CWE-285", "CWE-311", "CWE-327", "CWE-798", "CWE-22", "CWE-611"], 1)
        ]
    }
    expected = F._component_weaknesses(model)["service"]
    assert len(expected) == 5
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
    facts = F.overview_facts(model, paths, taxonomy)
    intro = markdown.split("\n", 1)[0]
    assert f"has {facts['components']} components in {facts['layers']} layers" in intro
    assert f"each of the {facts['scenarios']} attack scenarios below begins" in intro
    # The in-figure legend explains the notation; the introduction does not repeat it.
    assert "hexagon" not in intro and "not established" not in intro
    assert "Detailed architecture diagram" in markdown
    assert "All Critical · High fills to 5 · +N = omitted High categories" in svg
    assert "Unsafe Query Construction (SQLi)" in svg
    assert "Insufficient Resource Limits" not in svg
    assert not re.search(r"[WT]-\d{3}", svg)
    assert ">Data flows<" not in svg
    assert ">Data flows<" in (tmp_path / "report.figure1-detail.svg").read_text()
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
                # Distinct payloads keep the two roles apart. Identical ones fold
                # into one card, leaving no second role flow to arbitrate.
                "label": f"Role {number} request",
                "protocol": "HTTPS",
            }
        )
    _, state = F._build(model, [], [])
    assert "tb-1" in state["nodes"]["app0"]["tags"]
    assert not any("tb-1" in edge["tb"] for edge in state["edges"])
    assert F.check_diagram(model, paths, taxonomy)[1] == []


def _roles_model(*entities_and_flows):
    """A model whose legitimate roles and their flows are given as (entity, flows) pairs."""
    model, _, _ = _model()
    model["external_entities"] = [entity for entity, _ in entities_and_flows]
    model["data_flows"] = [
        {"id": f"df-2{index:02d}", "from": "external", "from_entity": entity["id"], "protocol": "HTTPS", **flow}
        for index, (entity, flows) in enumerate(entities_and_flows)
        for flow in flows
    ]
    return model


def test_a_role_whose_edges_another_role_already_draws_folds_into_it():
    """Nothing in the diagram tells the two apart, so one card carries both."""
    model = _roles_model(
        (
            {"id": "ext-user", "name": "End User", "kind": "legitimate-role"},
            [{"to": "spa", "interaction": True}, {"to": "app0", "label": "Places an order"}],
        ),
        ({"id": "ext-admin", "name": "Admin", "kind": "legitimate-role"}, [{"to": "spa", "interaction": True}]),
    )

    F._merge_indistinct_roles(model)

    assert [e["id"] for e in model["external_entities"]] == ["ext-user"]
    assert model["external_entities"][0]["_covers"] == ["Admin"]
    # The absorbed role's flow survives, redirected, so no edge is lost.
    assert {f["from_entity"] for f in model["data_flows"]} == {"ext-user"}


def test_a_role_with_an_edge_of_its_own_keeps_its_card():
    """A scanner posting to its own endpoint is a difference the diagram can show."""
    model = _roles_model(
        ({"id": "ext-user", "name": "End User", "kind": "legitimate-role"}, [{"to": "app0", "label": "Places an order"}]),
        ({"id": "ext-scanner", "name": "Scanner", "kind": "legitimate-role"}, [{"to": "app0", "label": "Posts findings"}]),
    )

    F._merge_indistinct_roles(model)

    assert [e["id"] for e in model["external_entities"]] == ["ext-user", "ext-scanner"]
    assert not any(e.get("_covers") for e in model["external_entities"])


def test_a_role_without_edges_is_never_folded_into_an_arbitrary_card():
    model = _roles_model(
        ({"id": "ext-user", "name": "End User", "kind": "legitimate-role"}, [{"to": "app0", "label": "Places an order"}]),
        ({"id": "ext-ops", "name": "Operator", "kind": "legitimate-role"}, []),
    )

    F._merge_indistinct_roles(model)

    assert [e["id"] for e in model["external_entities"]] == ["ext-user", "ext-ops"]


def test_folding_roles_is_idempotent_across_the_figure_and_its_detail_variant():
    model = _roles_model(
        ({"id": "ext-user", "name": "End User", "kind": "legitimate-role"}, [{"to": "spa", "interaction": True}]),
        ({"id": "ext-admin", "name": "Admin", "kind": "legitimate-role"}, [{"to": "spa", "interaction": True}]),
    )

    F._merge_indistinct_roles(model)
    once = copy.deepcopy(model)
    F._merge_indistinct_roles(model)

    assert model == once


def test_evidenced_application_asset_is_not_reported_as_an_unknown_location():
    model, paths, taxonomy = _model()
    model["assets"] = [model["assets"][0]]
    model["assets"][0]["component_refs"] = [
        {"component_id": "app0", "relation": "processed", "evidence": [{"file": "src/key.ts", "line": 1}]}
    ]
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    asset = ET.fromstring(svg).find("{*}g[@data-asset-id='A-001']")
    assert asset.get("data-asset-component") == "app0"
    assert asset.get("data-asset-relation") == "processed"
    assert "no displayed component mapping" not in svg


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


def _routing_model(tiers, pairs, prefix):
    ids = [f"{prefix}-{i}" for i in range(len(tiers))]
    return {
        "components": [{"id": cid, "name": cid.title(), "tier": tier} for cid, tier in zip(ids, tiers)],
        "data_flows": [
            {
                "id": f"df-{i:03d}",
                "from": ids[a] if isinstance(a, int) else a,
                "to": ids[b],
                "protocol": "HTTPS",
                "label": "Record exchange",
                "direction": "unidirectional",
                "data_classification": "Internal",
            }
            for i, (a, b) in enumerate(pairs, 1)
        ],
    }


def _proper_crossings(edges):
    """Measure the actual paths independently of the renderer's quality score."""
    segments = [(i, a, b) for i, edge in enumerate(edges) for a, b in zip(edge["pts"], edge["pts"][1:]) if a != b]
    total = 0
    for i, a, b in segments:
        if a[1] != b[1]:
            continue
        for j, c, d in segments:
            if i != j and c[0] == d[0]:
                total += min(a[0], b[0]) < c[0] < max(a[0], b[0]) and min(c[1], d[1]) < a[1] < max(c[1], d[1])
    return total


@pytest.mark.parametrize("prefix", ["dispatch", "telemetry"])
@pytest.mark.parametrize("detail", [False, True])
def test_reciprocal_services_have_separate_uncrossed_routes(prefix, detail):
    model = _routing_model(["application", "application"], [(0, 1), (1, 0)], prefix)
    before = copy.deepcopy(model)
    svg, state = F._build(model, [], [], detail=detail)
    assert _proper_crossings(state["edges"]) == 0
    assert len(state["edges"]) == 2
    assert F.USER_ID not in state["nodes"]
    assert F.check_diagram(model, {}, {}, detail=detail)[1] == []
    assert F._build(model, [], [], detail=detail)[0] == svg
    assert model == before


@pytest.mark.parametrize("prefix", ["desktop", "instrument"])
@pytest.mark.parametrize("detail", [False, True])
def test_direct_store_access_uses_free_corridor(prefix, detail):
    model = _routing_model(["client", "data"], [(0, 1)], prefix)
    _, state = F._build(model, [], [], detail=detail)
    points = state["edges"][0]["pts"]
    assert len(points) <= 4
    assert max(p[1] for p in points) <= max(points[0][1], points[-1][1])
    assert F.check_diagram(model, {}, {}, detail=detail)[1] == []


@pytest.mark.parametrize("prefix", ["dispatch", "telemetry"])
@pytest.mark.parametrize("detail", [False, True])
def test_opposing_routes_reallocate_ports_before_fallback(prefix, detail):
    model = _routing_model(
        ["client", "application", "application", "application", "data", "data"],
        [(0, 5), (4, 2), (1, 5), (2, 3)],
        prefix,
    )
    _, problems = F.check_diagram(model, {}, {}, detail=detail)
    assert problems == []


@pytest.mark.parametrize("incoming,victim", [(False, False), (True, False), (False, True)])
def test_generic_user_requires_an_external_flow_or_victim(incoming, victim):
    model = _routing_model(["application"], [("external", 0)] if incoming else [], "worker")
    scenarios = [{"n": "1", "victim": True, "cids": [], "title": "Victim action"}] if victim else []
    _, state = F._build(model, scenarios, [])
    assert (F.USER_ID in state["nodes"]) == (incoming or victim)


@pytest.mark.parametrize("prefix", ["gateway", "relay"])
@pytest.mark.parametrize("detail", [False, True])
def test_flow_bundles_preserve_individual_direction(prefix, detail):
    model = _routing_model(["application", "data"], [(0, 1), (0, 1)], prefix)
    model["data_flows"][1].update(direction="bidirectional", label="Status exchange")
    _, state = F._build(model, [], [], detail=detail)
    assert [(e["ids"], e["bidi"]) for e in state["edges"]] == [(["df-001"], False), (["df-002"], True)]
    assert F.check_diagram(model, {}, {}, detail=detail)[1] == []
    model["data_flows"][0]["direction"] = "bidirectional"
    _, state = F._build(model, [], [], detail=detail)
    assert [(e["ids"], e["bidi"]) for e in state["edges"]] == [(["df-001", "df-002"], True)]


def test_legend_content_has_clearance_below_header():
    model = _routing_model(["application", "data"], [(0, 1)], "archive")
    svg, _ = F._build(model, [], [], detail=False)
    root = ET.fromstring(svg)
    notation = root.find("{*}g[@data-legend-section='notation']")
    header, first_icon = notation.findall("{*}rect")[:2]
    assert float(first_icon.get("y")) - float(header.get("height")) >= 8
    authentication = root.find("{*}g[@data-legend-section='authentication']")
    header = authentication.find("{*}rect")
    icon = authentication.find("{*}g[@data-authentication]")
    center_y = float(re.search(r"translate\([^ ]+ ([^)]+)", icon.get("transform"))[1])
    assert center_y - 9 - float(header.get("height")) >= 8
    title, description = authentication.findall("{*}text")[1:3]
    assert float(description.get("y")) - float(description.get("font-size")) - float(title.get("y")) >= 4


@pytest.mark.parametrize("prefix", ["shipment", "measurement"])
def test_composer_keeps_dfd_for_opposing_routes(tmp_path, prefix):
    from types import SimpleNamespace

    import compose_threat_model as composer

    model = _routing_model(
        ["client", "application", "application", "application", "data", "data"],
        [(0, 5), (4, 2), (1, 5), (2, 3)],
        prefix,
    )
    model["threats"] = [{"id": "F-001", "component": f"{prefix}-2", "risk": "High", "stride": "Tampering"}]
    paths = {"attack_paths": [{"class": "tampering", "actor": "internet-anon", "findings": ["F-001"]}]}
    context = SimpleNamespace(yaml_data=model, output_dir=tmp_path, figure_basename="review.figure1.svg", warnings=[])
    markdown = composer._render_figure1_svg(context, paths, {})
    assert context.warnings == []
    assert "review.figure1-detail.svg" in markdown
    assert 'data-flow-ids="df-002"' in (tmp_path / "review.figure1.svg").read_text()


@pytest.mark.parametrize("seed", [36, 74, 82, 135])
@pytest.mark.parametrize("detail", [False, True])
def test_mixed_service_topologies_retain_clean_geometry(seed, detail):
    import itertools
    import random

    rng = random.Random(seed)
    tiers = ["client", *["application"] * 4, "data", "data"]
    pairs = rng.sample(list(itertools.permutations(range(len(tiers)), 2)), rng.randrange(3, 13))
    model = _routing_model(tiers, pairs, "node")
    before = copy.deepcopy(model)
    svg, errors = F.check_diagram(model, {}, {}, detail=detail)
    assert errors == []
    assert svg == F.check_diagram(model, {}, {}, detail=detail)[0]
    assert model == before


def test_shortcut_does_not_cross_an_intervening_component():
    model = _routing_model(["client", "application", "data"], [(0, 2)], "node")
    _, state = F._build(model, [], [], detail=False)
    node = state["nodes"]["node-1"]
    rect = (node["x"], node["y"], node["x"] + node["w"], node["y"] + node["h"])
    points = state["edges"][0]["pts"]
    for a, b in zip(points, points[1:]):
        if a[1] == b[1]:
            assert not (rect[1] < a[1] < rect[3] and min(a[0], b[0]) < rect[2] and max(a[0], b[0]) > rect[0])
        else:
            assert not (rect[0] < a[0] < rect[2] and min(a[1], b[1]) < rect[3] and max(a[1], b[1]) > rect[1])
    assert F.check_diagram(model, {}, {}, detail=False)[1] == []


def test_audit_rejects_an_extra_reverse_direction():
    model = _routing_model(["application", "data"], [(0, 1)], "node")
    _, state = F._build(model, [], [])
    state["edges"][0]["bidi"] = True
    assert any(
        "one-way flow drawn with two heads" in p
        for p in F._audit(state["d"], state["nodes"], state["edges"], state["chips"], state["boundaries"])
    )


@pytest.mark.parametrize("side", ["top", "side", "bottom"])
def test_geometry_gate_rejects_compressed_legend_content(side):
    block = F._Canvas()
    block.rect(0, 0, F.LEGEND_W, F.LEGEND_HEAD)
    block.legend_content = []
    block.rect(4 if side == "side" else 14, F.LEGEND_HEAD + (1 if side == "top" else 10), 20, 18)
    block.maxy += 1 if side == "bottom" else 10
    canvas = F._Canvas()
    F._place_legend(canvas, [("test", block)], F.LEGEND_W, 0)
    assert any("legend padding" in p for p in F._check_geometry({}, [], canvas, []))


@pytest.mark.parametrize("name", ["ProcessingGateway" * 12, "TelemetryPipeline" * 10])
def test_asset_annotations_retain_long_owner_identifiers(name):
    model = _routing_model(["application"], [], "processor")
    model["components"][0]["name"] = name
    model["assets"] = [
        {
            "id": "A-001",
            "name": "Events",
            "classification": "Internal",
            "component_refs": [
                {
                    "component_id": "processor-0",
                    "relation": "processed",
                    "evidence": [{"file": "src/worker.py", "line": 1}],
                }
            ],
        }
    ]
    svg, errors = F.check_diagram(model, {}, {}, detail=False)
    assert errors == []
    asset = ET.fromstring(svg).find("{*}g[@data-asset-id='A-001']")
    assert asset.get("data-asset-component") == "processor-0"
    assert name in asset.find("{*}title").text


@pytest.mark.parametrize("prefix", ["dispatch", "telemetry"])
def test_route_simplification_keeps_payload_labels_visible(prefix):
    model = _routing_model(["client", "application", "application", "data"], [(0, 2), (3, 2), (1, 3)], prefix)
    labels = ["Credentials", "Account authentication", "Record synchronization"]
    for flow, label in zip(model["data_flows"], labels):
        flow["label"] = label
    svg, state = F._build(model, [], [], detail=False)
    assert not state["d"].get("_label_notes")
    assert all(label in svg for label in labels)
    assert F.check_diagram(model, {}, {}, detail=False)[1] == []


@pytest.mark.parametrize("detail", [False, True])
def test_flow_lines_use_payload_names_instead_of_identifiers(detail):
    model = _routing_model(["application", "data"], [(0, 1)], "shipping")
    model["data_flows"][0]["label"] = "Orders"
    svg, _ = F._build(model, [], [], detail=detail)
    root = ET.fromstring(svg)
    # Legend IDs and hover metadata retain traceability; visible diagram labels convey the payload.
    for legend in root.findall("{*}g[@data-legend-section]"):
        root.remove(legend)
    text = " ".join(node.text or "" for node in root.iter("{http://www.w3.org/2000/svg}text"))
    assert "Orders" in text
    assert "df-001" not in text


@pytest.mark.parametrize("prefix", ["kiosk", "ledger"])
def test_overview_facts_count_what_the_overview_draws(prefix):
    model = _routing_model(["client", "application", "data", "application"], [(0, 1), (1, 2)], prefix)
    model["components"][3]["deployment_zones"] = ["ci-runner"]
    model["external_entities"] = [
        {"id": "ext-person", "kind": "legitimate-role", "name": "Operator", "description": "Uses the client"},
        {"id": "ext-idp", "kind": "identity-provider", "name": "Sign-in", "description": "Account provider"},
    ]
    model["data_flows"].append({"id": "df-009", "from": f"{prefix}-1", "to": "external", "label": "Webhook"})
    # People are not external services; an unnamed external recipient is drawn and counted.
    assert F.overview_facts(model, {}, {}) == {"components": 4, "layers": 4, "external_services": 2, "scenarios": 0}
    model, paths, taxonomy = _model()
    numbers = {s["n"] for s in F.scenarios_from_attack_paths(model, paths, taxonomy)[0]}
    assert numbers and F.overview_facts(model, paths, taxonomy)["scenarios"] == len(numbers)


@pytest.mark.parametrize("payload", ["Bundle download", "Static assets"])
@pytest.mark.parametrize("detail", [False, True])
def test_human_interaction_edges_describe_use_not_the_authored_payload(payload, detail):
    model = _routing_model(["client", "application"], [(0, 1)], "portal")
    model["external_entities"] = [
        {"id": "ext-person", "kind": "legitimate-role", "name": "Portal operator", "description": "Uses the portal"}
    ]
    model["data_flows"].append(
        {
            "id": "df-002",
            "from": "external",
            "from_entity": "ext-person",
            "to": "portal-0",
            "interaction": True,
            "diagram_label": payload,
            "label": f"{payload} served by the web server",
            "protocol": "HTTPS",
            "direction": "unidirectional",
            "data_classification": "Internal",
            "evidence": [{"file": "server/static.js", "line": 14}],
        }
    )
    model["data_flows"][0]["diagram_label"] = "Account records"
    svg, _ = F._build(model, [], [], detail=detail)
    root = ET.fromstring(svg)
    text = " ".join(root.itertext())
    assert F.INTERACTION_LABEL in text
    # Neither the visible label nor any hover text repeats the authored payload or its description.
    assert payload not in text and "served by" not in svg
    edges = [g for g in root.iter() if g.get("data-flow-ids") == "df-002" and g.get("data-access-mode") is not None]
    hovers = [t.text or "" for g in edges for t in g.findall("{*}title")]
    assert hovers and all(h == f"df-002: {F.INTERACTION_LABEL}; evidence: server/static.js:14" for h in hovers)
    # Technical flows keep the payload their author named.
    assert "Account records" in text


@pytest.mark.parametrize("server_file", ["routes/static.ts", "app/views/assets.py"])
def test_existing_model_with_server_evidenced_interaction_still_exports_and_renders(server_file):
    from validate_intermediate import _check_export_trace_invariants

    model = _routing_model(["client", "application"], [(0, 1)], "shop")
    model["components"][0]["paths"] = ["web/**"]
    model["components"][1]["paths"] = [server_file]
    model["external_entities"] = [
        {"id": "ext-person", "kind": "legitimate-role", "name": "Shopper", "description": "Uses the shop"}
    ]
    model["data_flows"].append(
        {
            "id": "df-002",
            "from": "external",
            "from_entity": "ext-person",
            "to": "shop-0",
            "interaction": True,
            "diagram_label": "Client bundle",
            "label": "Browser loads the client bundle",
            "protocol": "HTTP",
            "evidence": [{"file": server_file, "line": 14}],
        }
    )
    # Models written before the producer rule stay exportable and re-renderable.
    assert _check_export_trace_invariants(model) == []
    svg, problems = F.check_diagram(model, {}, {}, detail=False)
    assert problems == []
    text = " ".join(ET.fromstring(svg).itertext())
    assert F.INTERACTION_LABEL in text and "bundle" not in text


@pytest.mark.parametrize("prefix", ["archive", "ledger"])
def test_assets_appear_at_evidenced_components_without_a_remainder_legend(prefix):
    model = _routing_model(["application", "data", "data"], [(0, 1), (0, 2)], prefix)
    model["assets"] = [
        {
            "id": f"A-{i:03d}",
            "name": name,
            "classification": "Confidential",
            "component_refs": [
                {
                    "component_id": f"{prefix}-{owner}",
                    "relation": relation,
                    "evidence": [{"file": f"src/{prefix}.py", "line": i}],
                }
            ],
        }
        for i, name, owner, relation in [(1, "Orders", 1, "stored"), (2, "Session tokens", 0, "processed")]
    ]
    original = copy.deepcopy(model)
    svg, state = F._build(model, [], [], detail=False)
    root = ET.fromstring(svg)
    assert root.find("{*}g[@data-legend-section='assets']") is None
    for aid, owner, relation in [("A-001", 1, "stored"), ("A-002", 0, "processed")]:
        asset = root.find(f"{{*}}g[@data-asset-id='{aid}']")
        assert asset.get("data-asset-component") == f"{prefix}-{owner}"
        assert asset.get("data-asset-relation") == relation
        assert relation.title() + ":" in " ".join(asset.itertext())
    assert [a["id"] for a in state["nodes"][f"{prefix}-1"]["assets"]] == ["A-001"]
    assert state["nodes"][f"{prefix}-2"]["assets"] == []
    assert "Asset mapping not established" in " ".join(root.itertext())
    assert model == original
    assert F.check_diagram(model, {}, {}, detail=False)[1] == []


def test_payload_layout_selection_respects_geometry_rejection(monkeypatch):
    model = _routing_model(
        ["client", "application", "application", "data"],
        [(1, 2), (1, 3), (2, 3), (0, 1), (2, 1), (2, 0), (0, 2)],
        "dispatch",
    )
    for i, flow in enumerate(model["data_flows"]):
        flow["label"] = ["Credential lookup", "Account authentication", "Record synchronization"][i % 3]
    monkeypatch.setattr(F, "_check_geometry", lambda *args, **kwargs: ["blocked alternative"])
    svg, state = F._build(model, [], [], detail=False)
    assert state["d"].get("_label_notes")
    note = ET.fromstring(svg).find("{*}g[@data-legend-section='flow-notes']")
    text = " ".join(note.itertext())
    assert any("df-007" in ids for ids, _ in state["d"]["_label_notes"])
    assert "Credential lookup" in text
    assert "df-007" not in text
    assert F.check_diagram(model, {}, {}, detail=False)[1] == ["blocked alternative"]


@pytest.mark.parametrize("relation", ["stored", "processed", "transmitted"])
def test_asset_annotations_require_evidence_and_keep_handling_explicit(relation):
    model = _routing_model(["application", "data"], [(0, 1)], "records")
    ref = {"component_id": "records-0", "relation": relation}
    model["assets"] = [{"id": "A-001", "name": "Records", "classification": "Internal", "component_refs": [ref]}]
    _, state = F._build(model, [], [], detail=False)
    assert not any(n["assets"] for n in state["nodes"].values())
    ref["evidence"] = [{"file": "src/records.py", "line": 1}]
    _, state = F._build(model, [], [], detail=False)
    assert state["nodes"]["records-0"]["assets"][0]["_relation"] == relation
    assert state["nodes"]["records-1"]["assets"] == []
    model["assets"][0]["component_refs"].append(
        {"component_id": "records-1", "relation": "stored", "evidence": [{"file": "schema.sql", "line": 1}]}
    )
    _, state = F._build(model, [], [], detail=False)
    assert [a["id"] for a in state["nodes"]["records-1"]["assets"]] == ["A-001"]
    assert bool(state["nodes"]["records-0"]["assets"]) == (relation == "stored")


def test_many_asset_scenarios_badge_the_storing_component_border_not_the_asset():
    model = _routing_model(["data"], [], "archive")
    model["assets"] = [
        {
            "id": "A-001",
            "name": "Records",
            "classification": "Confidential",
            "linked_threats": ["T-001"],
            "component_refs": [
                {"component_id": "archive-0", "relation": "stored", "evidence": [{"file": "schema.sql", "line": 1}]}
            ],
        }
    ]
    scenarios = [{"n": str(n), "fids": [1], "cids": [], "title": "Read records"} for n in range(1, 8)]
    svg, state = F._build(model, scenarios, [], detail=False)
    asset = ET.fromstring(svg).find("{*}g[@data-asset-id='A-001']")
    assert not asset.findall("{*}circle")
    assert [n for n, _ in state["nodes"]["archive-0"]["badges"]] == [str(n) for n in range(1, 8)]
    assert F.check_diagram(model, {}, {}, scenarios=scenarios, actors=[], detail=False)[1] == []


@pytest.mark.parametrize("prefix", ["archive", "ledger"])
@pytest.mark.parametrize("detail", [False, True])
def test_dense_asset_symbols_have_an_exact_legend_and_preserve_small_stores(prefix, detail):
    model = _routing_model(["application", "data", "data"], [(0, 1), (0, 2)], prefix)
    model["assets"] = [
        {
            "id": f"A-{i:03d}",
            "name": f"Record collection {i}",
            "classification": "Confidential",
            "linked_threats": ["T-001"],
            "component_refs": [
                {
                    "component_id": f"{prefix}-{1 if i <= 20 else 2}",
                    "relation": "stored",
                    "evidence": [{"file": f"schema/{prefix}.sql", "line": i}],
                }
            ],
        }
        for i in range(1, 23)
    ]
    # A shared storage location must not create duplicate legend entries.
    model["assets"][0]["component_refs"].append(
        {"component_id": f"{prefix}-2", "relation": "stored", "evidence": [{"file": "schema/replica.sql", "line": 1}]}
    )
    original = copy.deepcopy(model)
    scenarios = [{"n": "1", "fids": [1], "cids": [], "title": "Read records"}]
    svg, state = F._build(model, scenarios, [], detail=detail)
    root = ET.fromstring(svg)
    dense, small = (state["nodes"][f"{prefix}-{i}"] for i in (1, 2))
    assert dense["compact_assets"] and not small["compact_assets"]
    assert dense["h"] < F._asset_inline_height(dense["assets"])
    assert dense["inline_asset_ids"] == ["A-001", "A-002"]
    symbols = root.findall(f"{{*}}g[@data-asset-component='{prefix}-1'][@data-asset-display='symbol']")
    assert len(symbols) == 18
    for symbol in symbols:
        visible = " ".join(t.text or "" for t in symbol.findall("{*}text"))
        assert visible == symbol.get("data-asset-id")
    legend = root.find("{*}g[@data-legend-section='assets']")
    entries = legend.findall("{*}g[@data-asset-legend-id]")
    assert [e.get("data-asset-legend-id") for e in entries] == [f"A-{i:03d}" for i in range(3, 21)]
    for i, entry in enumerate(entries, 3):
        text = " ".join(entry.itertext())
        assert f"A-{i:03d} Record collection {i}" in text
        assert "Confidential · stored in C-02" in text
        assert "Attack scenarios" not in text
    assert dense["badges"] == [("1", None)]
    assert "Record collection 21" in " ".join(root.find("{*}g[@data-asset-id='A-021']").itertext())
    assert model == original
    assert F.check_diagram(model, {}, {}, scenarios=scenarios, actors=[], detail=detail)[1] == []
    assert F._build(model, scenarios, [], detail=detail)[0] == svg


@pytest.mark.parametrize("detail", [False, True])
def test_layer_titles_omit_internal_framework_and_deployment_notes(detail):
    model = _routing_model(["client", "application", "data"], [(0, 1), (1, 2)], "dispatch")
    model["components"][1].update(framework="opaque-framework-label", deployment_zones=["internal-segment-code"])
    svg, errors = F.check_diagram(model, {}, {}, detail=detail)
    assert not errors
    for title in ("Client Layer", "Application Layer", "Data Layer"):
        assert f">{title}<" in svg
    assert "internal-segment-code" not in svg
    # The framework belongs to its component box, never to a layer title.
    root = ET.fromstring(svg)
    shown = [(g.get("data-technology-owner"), g.get("data-framework")) for g in root.iter(f"{_SVG}g")]
    assert [row for row in shown if row[0]] == [(model["components"][1]["id"], "opaque-framework-label")]
    assert _visible_text(root).count("opaque-framework-label") == 1


@pytest.mark.parametrize("tier,relation", [("application", "processed"), ("data", "stored")])
def test_dense_asset_preview_prioritizes_linked_risk_then_classification(tier, relation):
    model = _routing_model([tier], [], "records")
    model["assets"] = [
        {
            "id": f"A-{i:03d}",
            "name": "Critical sounding name" if i == 1 else f"Record collection {i}",
            "classification": "Internal",
            "component_refs": [
                {"component_id": "records-0", "relation": relation, "evidence": [{"file": "src/records.py", "line": i}]}
            ],
        }
        for i in range(1, 13)
    ]
    model["assets"][9]["classification"] = "Restricted"
    model["assets"][10]["linked_threats"] = ["T-001"]
    model["threats"] = [{"id": "T-001", "component": "records-0", "risk": "High", "stride": "Information Disclosure"}]
    svg, state = F._build(model, [], [], detail=False)
    assert state["nodes"]["records-0"]["inline_asset_ids"] == ["A-011", "A-010"]
    root = ET.fromstring(svg)
    assert len(root.findall("{*}g[@data-asset-display='inline']")) == 2
    assert len(root.findall("{*}g[@data-asset-display='symbol']")) == 10
    assert F.check_diagram(model, {}, {}, detail=False)[1] == []


@pytest.mark.parametrize("version", [None, "3.2.1"])
def test_project_identity_prefers_recorded_name_and_never_uses_plugin_version(version):
    model = _routing_model(["application"], [], "checkout")
    model["meta"] = {"project": "working-copy-2", "plugin_version": "9.9.9"}
    model["project"] = {"name": "Order Gateway", "version": version}
    svg, _ = F._build(model, [], [], detail=False)
    assert "Order Gateway" in svg
    assert "working-copy-2" not in svg and "9.9.9" not in svg
    assert ("3.2.1" in svg) == bool(version)


@pytest.mark.parametrize("prefix", ["gateway", "relay"])
@pytest.mark.parametrize("blocked", [False, True])
def test_straight_routes_move_both_ports_only_through_a_free_corridor(prefix, blocked):
    nodes = {
        prefix: {"id": prefix, "x": 0, "y": 220, "w": 100, "h": 120, "tagspace": 0},
        "records": {"id": "records", "x": 300, "y": 20, "w": 100, "h": 280, "tagspace": 0},
    }
    if blocked:
        nodes["obstacle"] = {"id": "obstacle", "x": 150, "y": 210, "w": 100, "h": 100, "tagspace": 0}
    edge = {
        "src": prefix,
        "dst": "records",
        "ids": ["df-001"],
        "kind": "forward",
        "skip": False,
        "tb": [],
        "pts": [(100, 320), (260, 320), (260, 150), (300, 150)],
    }
    original = copy.deepcopy(edge["pts"])
    F._improve_routes(nodes, [edge], [], [], straight_only=True)
    if blocked:
        assert edge["pts"] == original
    else:
        assert len({p[1] for p in edge["pts"]}) == 1
        assert 231 <= edge["pts"][0][1] <= 289
        assert len(F._authentication_endpoint(edge, {})) == 2
    assert F._check_geometry(nodes, [edge], F._Canvas(), []) == []


def test_payload_placement_uses_free_intervals_between_obstacles():
    occupied = [(0, 0, 154, 110), (256, 0, 300, 110)]
    candidates = list(F._label_gaps((0, 100), (300, 100), 80, -6, occupied, []))
    assert candidates
    for _, _, rect, _ in candidates:
        assert 154 < rect[0] < rect[2] < 256


@pytest.mark.parametrize("protocol", ["SQLite in-process", "Custom Repository Protocol"])
def test_short_payload_candidates_never_drop_the_protocol(protocol):
    choices = F._flow_label_candidates(
        [{"id": "df-001", "label": "User and product record lookups", "protocol": protocol}], False
    )
    assert choices and all(protocol in choice for choice in choices)
    assert all("df-001" not in choice for choice in choices)


@pytest.mark.parametrize("protocol", ["WebSocket (Socket.IO)", "SQL (in-process) / HTTPS", "HTTPS", "gRPC / HTTP/2"])
def test_flow_labels_never_nest_parentheses(protocol):
    def depth(text):
        level = deepest = 0
        for char in text:
            level += (char == "(") - (char == ")")
            deepest = max(deepest, level)
        return deepest

    flows = [{"id": "df-001", "diagram_label": "Challenge notifications (live)", "protocol": protocol}]
    choices = F._flow_label_candidates(flows, False)
    assert choices and all(protocol in choice and depth(choice) <= 1 for choice in choices)
    model, paths, taxonomy = _model()
    model["data_flows"][1]["protocol"] = protocol
    model["data_flows"][1]["access_group"] = {"id": "api", "mode": "alternatives", "label": "Public or signed-in"}
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == []
    assert all(depth(t.text or "") <= 1 for t in ET.fromstring(svg).iter(f"{_SVG}text"))


@pytest.mark.parametrize(
    "description",
    [
        "Local inference service for prompts and responses",
        "Blockchain gateway for event subscriptions and transactions",
    ],
)
def test_external_descriptions_wrap_without_cutting_short_sentences(description):
    model = _routing_model(["application"], [], "gateway")
    model["external_entities"] = [
        {
            "id": "ext-service",
            "name": "External processing service",
            "kind": "external-service",
            "description": description,
        }
    ]
    model["data_flows"] = [
        {
            "id": "df-001",
            "from": "gateway-0",
            "to": "external",
            "to_entity": "ext-service",
            "label": "Records",
            "protocol": "HTTPS",
        }
    ]
    original = copy.deepcopy(model)
    svg, state = F._build(model, [], [], detail=False)
    node = ET.fromstring(svg).find("{*}g[@data-external-id='ext-service']")
    lines = [t for t in node.findall("{*}text") if t.get("font-size") == "7.5"]
    assert len(lines) == 2
    assert " ".join(t.text for t in lines) == description
    assert node.find("{*}title").text == description
    assert state["nodes"]["ext-service"]["h"] > F.EXT_H
    assert model == original
    assert F.check_diagram(model, {}, {}, detail=False)[1] == []


def test_attack_paths_use_slightly_heavier_lines_and_descriptive_labels():
    model, paths, taxonomy = _model(xss=True)
    svg, errors = F.check_diagram(model, paths, taxonomy, detail=False)
    assert not errors
    root = ET.fromstring(svg)
    attacks = [p for p in root.iter("{http://www.w3.org/2000/svg}path") if "attacker-" in p.get("marker-end", "")]
    assert attacks and all(float(p.get("stroke-width")) == 1.8 for p in attacks)
    text = [t.text for t in root.iter("{http://www.w3.org/2000/svg}text")]
    assert "Direct attack" in text and "Via user" in text
    # A bare actor code never labels the attacker end; it only marks arrowheads and badge groups.
    _, state = F._build(model, *F.scenarios_from_attack_paths(model, paths, taxonomy), detail=False)
    nodes, attackers = state["nodes"], F._attackers(state["nodes"])
    arrowheads = [track for *_, track in state["canvas"].labels if track.startswith("attack target ")]
    rows = [n["badges"] for n in nodes.values()]
    tags = sum(kind == "tag" for row in rows for kind, *_ in F._badge_tokens(row, attackers, 0, 8))
    assert arrowheads and tags
    assert sum(t in {a["actor_code"] for a in attackers.values()} for t in text) == len(arrowheads) + tags


@pytest.mark.parametrize("port", [12345, 7443])
def test_external_subtitles_keep_the_value_after_a_port_label(port):
    nodes = {
        "external": {
            "kind": "ext",
            "zone": "third-party",
            "name": "Inference endpoint",
            "w": F.EXT_W,
            "h": F.EXT_H,
            "sub": f"Local or remote inference service providing responses on port {port} through a compatible API.",
        }
    }
    F._prepare_external_text(nodes)
    lines = nodes["external"]["sub_lines"]
    assert len(lines) == 3
    assert " ".join(lines) == nodes["external"]["sub"]


def test_multiline_payload_labels_keep_content_and_protocol_outside_notes():
    model = _routing_model(["application", "data"], [(0, 1)], "gateway")
    model["data_flows"][0].update(label="Product queries", protocol="SQLite in-process")
    svg, state = F._build(model, [], [], detail=False)
    assert not state["d"].get("_label_notes")
    root = ET.fromstring(svg)
    for legend in root.findall("{*}g[@data-legend-section]"):
        root.remove(legend)
    text = " ".join(t.text or "" for t in root.iter("{http://www.w3.org/2000/svg}text"))
    assert "Product queries" in text and "SQLite in-process" in text


_SVG = "{http://www.w3.org/2000/svg}"
_INTERNAL = {"surface": "in-process", "transition": [], "kind": "process"}


def _visible_text(root):
    return " ".join(t.text or "" for t in root.iter(f"{_SVG}text"))


def _resolved(source, target, number=1, **extra):
    row = {"id": f"tb-{number}", "from": source, "to": target}
    return {**row, "confidence": "confirmed", "resolution_status": "resolved", **extra}


@pytest.mark.parametrize(
    "rows,expected",
    [
        ([], {}),
        ([("app0", "app2", _INTERNAL)], {}),
        ([("external", "app1", {})], {0: ["tb-1"]}),
        ([("external", "app1", {"confidence": "inferred"})], {0: ["tb-1"]}),
        ([("app0", "db0", {})], {1: ["tb-1"]}),
        ([("app0", "db0", _INTERNAL)], {}),
        ([("external", "spa", {})], {}),
        ([("external", "db0", {})], {0: ["tb-1"], 1: ["tb-1"]}),
        ([("app1", "external", {})], {}),
        ([("app0", "db0", {}), ("external", "app0", _INTERNAL)], {1: ["tb-1"]}),
        ([("app0", "db0", {"resolution_status": "unresolved"})], {}),
    ],
)
@pytest.mark.parametrize("detail", [False, True])
def test_boundary_lines_follow_resolved_crossings_only(rows, expected, detail):
    model, paths, taxonomy = _model()
    model["trust_boundaries"] = [
        _resolved(source, target, i, **extra) for i, (source, target, extra) in enumerate(rows, 1)
    ]
    before = copy.deepcopy(model)
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=detail)
    assert problems == []
    root = ET.fromstring(svg)
    assert _boundary_lines(root) == expected
    assert _visible_text(root).count("TRUST BOUNDARY") == len(expected)
    notation = " ".join(root.find("{*}g[@data-legend-section='notation']").itertext())
    assert ("trust boundary crossed between these columns" in notation) is bool(expected)
    assert model == before


@pytest.mark.parametrize("detail,column", [(False, 2), (True, 0)])
def test_egress_boundary_line_follows_the_drawn_external_participant(detail, column):
    model, paths, taxonomy = _model()
    model["trust_boundaries"] = [_resolved("app0", "external")]
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    svg, state = F._build(model, scenarios, actors, detail=detail)
    assert state["nodes"]["ext:app0"]["col"] == column
    assert _boundary_lines(ET.fromstring(svg)) == {min(column, 1): ["tb-1"]}
    assert F.check_diagram(model, paths, taxonomy, detail=detail)[1] == []


def test_boundary_line_audit_rejects_unbacked_or_missing_lines():
    model, paths, taxonomy = _model()
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    _, state = F._build(model, scenarios, actors, detail=False)
    canvas = state["canvas"]
    args = (state["d"], state["nodes"], state["edges"], state["chips"], state["boundaries"], canvas)
    assert F._audit(*args) == []
    original = list(canvas.o)

    def audit(old, new):
        canvas.o = [line.replace(old, new) for line in original]
        return F._audit(*args)

    assert any("do not match" in p for p in audit('data-boundary-line="1"', 'data-removed-line="1"'))
    unbacked = audit('data-boundary-ids="tb-8"', 'data-boundary-ids="tb-8 tb-77"')
    assert any("tb-77: trust-boundary line without" in p for p in unbacked)
    canvas.o = original
    state["d"]["trust_boundaries"][1].update(_INTERNAL)
    problems = F._audit(*args)
    assert any("do not match" in p for p in problems)
    assert any("tb-8: trust-boundary line without" in p for p in problems)


def test_overview_defers_boundary_inventory_to_the_catalogue():
    model, paths, taxonomy = _model(exposed=("app0", "app1"))
    model["trust_boundaries"][2].update(_INTERNAL)
    model["trust_boundaries"].append(_resolved("app1", "external", 5))
    overview, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    root = ET.fromstring(overview)
    text = _visible_text(root)
    assert not re.search(r"\btb-\d+\b", text)
    assert "not placed" not in text and "internal interface" not in text
    assert root.find(".//{*}g[@data-boundary-marker]") is None
    assert root.find("{*}g[@data-legend-section='boundaries']") is None
    detail, problems = F.check_diagram(model, paths, taxonomy, detail=True)
    assert problems == []
    entries = ET.fromstring(detail).findall("{*}g[@data-legend-section='boundaries']/{*}g[@data-boundary-id]")
    assert {e.get("data-boundary-id") for e in entries} == {t["id"] for t in model["trust_boundaries"]}


@pytest.mark.parametrize(
    "pair,axes,hidden",
    [
        (("app0", "app2"), _INTERNAL, True),
        (("app2", "app0"), {"kind": "process"}, True),
        (("app0", "app2"), {"surface": "in-process", "transition": ["privilege"], "kind": "process"}, False),
        (("app0", "app2"), {"surface": "network", "transition": [], "kind": "network"}, False),
        (("spa", "app0"), _INTERNAL, False),
    ],
)
def test_in_process_calls_between_processes_stay_in_detail_views(pair, axes, hidden):
    model, paths, taxonomy = _model(intra=True)
    model["trust_boundaries"][1].update(_INTERNAL)  # store access stays in the overview
    model["trust_boundaries"].append(_resolved(*pair, 7, **axes))
    before = copy.deepcopy(model)
    overview, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    root = ET.fromstring(overview)
    drawn = " ".join(g.get("data-flow-ids") for g in root.iter(f"{_SVG}g") if g.get("data-flow-ids"))
    moved = {"df-007"} if pair[1] == "app2" or pair[0] == "app2" else {"df-002", "df-003"}
    assert all((fid not in drawn) is hidden for fid in moved)
    assert "df-005" in drawn
    notes = root.find("{*}g[@data-legend-section='notes']")
    notes_text = " ".join(notes.itertext()) if notes is not None else ""
    assert ("in detail views" in notes_text) is hidden
    detail, problems = F.check_diagram(model, paths, taxonomy, detail=True)
    assert problems == []
    assert all(fid in detail for fid in moved)
    assert model == before


def _groups(badges, attackers):
    return [(code, numbers) for code, _, numbers in F._badge_groups(badges, attackers)]


def _shared_number_scenarios():
    def scenario(n, actor, slug, victim, cids, fids):
        title = "Injection" if not victim else "Script injection"
        return dict(n=n, title=title, actor=actor, actor_slug=slug, victim=victim, cids=cids, fids=fids, risk="High")

    scenarios = [
        scenario("1", "Internet Attacker", "internet-anon", False, ["app0", "db0"], [9]),
        scenario("1", "Build Attacker", "build-time", False, ["app0", "db0"], [9]),
        scenario("2", "Internet Attacker", "internet-anon", True, ["spa"], [1]),
        scenario("2", "Build Attacker", "build-time", True, ["spa"], [1]),
        scenario("3", "Internet Attacker", "internet-anon", False, ["app0"], [3]),
    ]
    actors = [
        {"name": "Internet Attacker", "slug": "internet-anon", "sub": "", "attacker": True},
        {"name": "Build Attacker", "slug": "build-time", "sub": "", "attacker": True},
    ]
    return scenarios, actors


@pytest.mark.parametrize("detail", [False, True])
def test_shared_scenario_numbers_render_once_per_attacker_on_node_and_stored_asset_and_once_per_victim(detail):
    model, _, _ = _model()
    model["assets"][0]["component_refs"] = [
        {"component_id": "db0", "relation": "stored", "evidence": [{"file": "src/store.ts", "line": 1}]}
    ]
    scenarios, actors = _shared_number_scenarios()
    svg, state = F._build(model, scenarios, actors, detail=detail)
    nodes = state["nodes"]
    web, build = "Internet Attacker", "Build Attacker"
    assert nodes["app0"]["badges"] == [("1", web), ("1", build), ("3", web)]
    assert nodes["db0"]["badges"] == [("1", web), ("1", build)]
    assert nodes["spa"]["badges"] == [("2", web), ("2", build)]
    assert "_hits" not in nodes["db0"]["assets"][0]  # the stored asset's scenario 1 is already on db0
    assert nodes[F.USER_ID]["sub"].count("②") == 1
    args = (state["nodes"], state["edges"], state["canvas"], state["chips"])
    assert F._check_geometry(*args, boundaries=state["boundaries"]) == []
    assert (
        F._audit(state["d"], state["nodes"], state["edges"], state["chips"], state["boundaries"], state["canvas"]) == []
    )


def test_scenario_legend_lists_each_actor_once():
    model, _, _ = _model()
    scenarios, actors = _shared_number_scenarios()
    svg, _ = F._build(model, scenarios, actors, detail=False)
    groups = ET.fromstring(svg).findall(".//{*}g[@data-scenario-actor]")
    numbers = {
        g.get("data-scenario-actor"): [t.text for t in g.iter(f"{_SVG}text") if (t.text or "").isdigit()]
        for g in groups
    }
    assert [g.get("data-scenario-actor") for g in groups] == list(numbers)
    assert numbers == {
        "Internet Attacker": ["1", "3"],
        "Build Attacker": ["1"],
        "Internet Attacker → User (victim)": ["2"],
        "Build Attacker → User (victim)": ["2"],
    }


def test_several_attackers_mark_badges_arrowheads_and_legend_with_their_code():
    model, _, _ = _model()
    model["assets"][0]["component_refs"] = [
        {"component_id": "db0", "relation": "stored", "evidence": [{"file": "src/store.ts", "line": 1}]}
    ]
    scenarios, actors = _shared_number_scenarios()
    svg, state = F._build(model, scenarios, actors, detail=False)
    nodes, attackers = state["nodes"], F._attackers(state["nodes"])
    assert {a["actor_code"] for a in attackers.values()} == {"A1", "A2"}
    assert _groups(nodes["app0"]["badges"], attackers) == [("A1", ["1", "3"]), ("A2", ["1"])]
    assert _groups(nodes["db0"]["badges"], attackers) == [("A1", ["1"]), ("A2", ["1"])]
    targets = {track.split()[2] for *_, track in state["canvas"].labels if track.startswith("attack target ")}
    assert targets == {"A1", "A2"}
    root = ET.fromstring(svg)
    headings = [next(g.iter(f"{_SVG}text")).text for g in root.findall(".//{*}g[@data-scenario-actor]")]
    assert headings[:2] == ["A1 · Internet Attacker", "A2 · Build Attacker"]
    assert "scenarios of attacker A1" in " ".join(root.find("{*}g[@data-legend-section='notation']").itertext())
    args = (state["nodes"], state["edges"], state["canvas"], state["chips"])
    assert F._check_geometry(*args, boundaries=state["boundaries"]) == []


def test_a_single_attacker_needs_no_code_on_badges_or_arrowheads():
    model, _, _ = _model()
    scenarios, actors = _shared_number_scenarios()
    scenarios = [s for s in scenarios if s["actor"] == "Internet Attacker"]
    svg, state = F._build(model, scenarios, actors[:1], detail=False)
    assert _groups(state["nodes"]["app0"]["badges"], F._attackers(state["nodes"])) == [(None, ["1", "3"])]
    assert not [track for *_, track in state["canvas"].labels if track.startswith("attack target ")]
    root = ET.fromstring(svg)
    headings = [next(g.iter(f"{_SVG}text")).text for g in root.findall(".//{*}g[@data-scenario-actor]")]
    assert headings[0] == "Internet Attacker"
    assert "scenarios of attacker" not in " ".join(root.find("{*}g[@data-legend-section='notation']").itertext())


@pytest.mark.parametrize("shape", ["plain", "elevated", "refuted", "folded-practice", "design-risk"])
def test_figure1_tallies_follow_the_report_basis(shape):
    import collections

    from _severity_rollup import register_severity, register_threats, risk_distribution_counts

    model, paths, taxonomy = _model()
    first = model["threats"][0]
    if shape == "elevated":
        first.update(risk="High", effective_severity="Critical")
    elif shape == "refuted":
        first["evidence_check"] = "refuted"
    elif shape in {"folded-practice", "design-risk"}:
        model["weaknesses"] = [{"id": "W-001", "kind": "implementation", "severity": "High"}]
        first["evidence_tier"] = "insecure-practice"
        if shape == "design-risk":
            model["weaknesses"].append(
                {"id": "W-002", "kind": "design", "severity": "Critical", "severity_basis": "design-risk"}
            )
    before = copy.deepcopy(model)
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    by_number = {int(t["id"].rsplit("-", 1)[1]): t for t in model["threats"]}
    for scenario in scenarios:
        ratings = [register_severity(by_number[f]) for f in scenario["fids"] if f in by_number]
        ratings = [rating for rating in ratings if rating]
        assert scenario["risk"] == (min(ratings, key=F.SEV_RANK.get) if ratings else "")
    svg, state = F._build(model, scenarios, actors, detail=False)
    assert f"· {sum(risk_distribution_counts(model).values())} threats" in svg
    expected = collections.Counter((t["component"], register_severity(t)) for t in register_threats(model))
    for component in model["components"]:
        for severity in ("Critical", "High", "Medium"):
            assert state["nodes"][component["id"]]["sev"].get(severity, 0) == expected[(component["id"], severity)]
    assert model == before
    assert F.check_diagram(model, paths, taxonomy, detail=False)[1] == []


@pytest.mark.parametrize(
    "access,replaces", [("internet-anon", True), ("internet-user", True), ("internet-priv-user", False), (None, False)]
)
def test_single_classified_regular_role_replaces_the_generic_victim(access, replaces):
    model, paths, taxonomy = _model(xss=True)
    entity = {"id": "ext-visitor", "name": "Visitor", "kind": "legitimate-role"}
    if access:
        entity["access"] = access
    model["external_entities"] = [entity]
    model["data_flows"][0]["from_entity"] = model["data_flows"][3]["from_entity"] = "ext-visitor"
    before = copy.deepcopy(model)
    scenarios, actors = F.scenarios_from_attack_paths(model, paths, taxonomy)
    _, state = F._build(model, scenarios, actors, detail=False)
    assert {e["dst"] for e in state["edges"] if e.get("victim")} == {"ext-visitor" if replaces else F.USER_ID}
    assert (F.USER_ID in state["nodes"]) is not replaces
    assert ("victim_label" in state["nodes"]["ext-visitor"]) is replaces
    assert F.legitimate_role_notes(model) == []
    assert model == before
    assert F.check_diagram(model, paths, taxonomy, detail=False)[1] == []
    assert F.check_diagram(model, paths, taxonomy, detail=True)[1] == []


@pytest.mark.parametrize(
    "name,ellipsis",
    [("Challenge Evaluation and Data Infrastructure", False), (" ".join(["Considerably Longer Name"] * 4), True)],
)
def test_component_titles_use_three_lines_before_shortening(name, ellipsis):
    model, paths, taxonomy = _model()
    model["components"][1]["name"] = name
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    lines = [t.text for t in ET.fromstring(svg).find(".//{*}g[@data-component-id='app0']").iter(f"{_SVG}text")]
    assert len(lines) == 3
    assert lines[-1].endswith("…") is ellipsis
    if not ellipsis:
        assert " ".join(lines) == f"C-02 · {name}"


@pytest.mark.parametrize(
    ("name", "items", "shown"),
    [
        ("Chat API", ["llm-calls", "llm-tools"], ["llm-tools"]),
        ("Identity", ["token-issuer", "jwt-issuer", "mfa-verifier"], ["jwt-issuer", "mfa-verifier"]),
        ("Portal", ["oauth-client", "oidc-client"], ["oidc-client"]),
        ("File Upload Service", ["file-upload", "url-fetch"], ["url-fetch"]),
        ("Uploads", ["file-upload"], ["file-upload"]),
        ("Real-time WebSocket Channel", ["websocket-endpoint"], ["websocket-endpoint"]),
        ("LLM Inference Provider (local)", ["llm-inference"], []),
        ("Identity Hub", ["oauth-authorization-server", "oidc-provider"], ["oidc-provider"]),
        ("Ethereum RPC Node", ["blockchain-rpc"], ["blockchain-rpc"]),
    ],
)
def test_capability_labels_do_not_repeat_the_name_or_a_more_specific_label(name, items, shown):
    capabilities, roles = F._capability_vocabulary()
    evidence = [{"file": "src/a.ts", "line": 1}]
    vocabulary = roles if items[0] in roles else capabilities
    key = "role" if vocabulary is roles else "capability"
    rows = F._capability_rows([{key: value, "evidence": evidence} for value in items], vocabulary, key, name)
    assert [row["id"] for row in rows] == shown
    unevidenced = [{key: "llm-tools", "evidence": []}, {key: "llm-calls", "evidence": evidence}]
    if vocabulary is capabilities:
        assert [row["id"] for row in F._capability_rows(unevidenced, vocabulary, key, name)] == ["llm-calls"]


@pytest.mark.parametrize(
    ("authored", "shown", "more"),
    [
        (["background-jobs", "file-upload", "url-fetch"], ["file-upload", "url-fetch", "background-jobs"], []),
        (["admin-functions", "xml-parsing"], ["admin-functions", "xml-parsing"], []),
        (["mfa-verifier", "token-issuer", "file-upload"], ["file-upload", "token-issuer", "mfa-verifier"], []),
        (
            ["email-sending", "admin-functions", "file-upload", "llm-tools", "template-rendering", "url-fetch"],
            # Every tier-1 function stays visible, even beyond the cap of three.
            ["file-upload", "url-fetch", "llm-tools", "admin-functions"],
            ["template-rendering", "email-sending"],
        ),
        (["graphql-endpoint", "websocket-endpoint", "payment-processing", "oauth-client"], None, None),
    ],
)
def test_capability_labels_rank_by_security_relevance_and_keep_the_rest(authored, shown, more):
    capabilities, _ = F._capability_vocabulary()
    evidence = [{"file": "src/a.ts", "line": 1}]
    items = [{"capability": value, "evidence": evidence} for value in authored]
    rows = F._capability_rows(items, capabilities, "capability", "Service")
    ranks = [(capabilities[row["id"]]["tier"], list(capabilities).index(row["id"])) for row in rows]
    assert ranks == sorted(ranks) and {row["id"] for row in rows} == set(authored)
    display = F._capability_display(rows)
    critical = sum(1 for row in rows if capabilities[row["id"]]["tier"] == 1)
    visible = min(max(F.CAPABILITY_CAP, critical), F.CAPABILITY_CRITICAL_MAX)
    assert len([cap for cap in display if not cap.get("more")]) == min(len(rows), visible)
    if shown is not None:
        assert [cap["id"] for cap in display if not cap.get("more")] == shown
        assert [cap["id"] for cap in (display[-1].get("more") or [])] == more
    hidden = display[-1].get("more") or []
    assert display[-1]["label"] == (f"+{len(hidden)}" if hidden else display[-1]["label"])
    assert [cap["id"] for cap in display if not cap.get("more")] + [cap["id"] for cap in hidden] == [
        row["id"] for row in rows
    ]


@pytest.mark.parametrize("vocabulary", [0, 1])
def test_the_vocabulary_keeps_tier_one_within_the_visible_bound(vocabulary):
    # Raising a sixth value to tier 1 must be a deliberate change of this bound.
    entries = F._capability_vocabulary()[vocabulary]
    assert sum(1 for entry in entries.values() if entry.get("tier") == 1) <= F.CAPABILITY_CRITICAL_MAX


@pytest.mark.parametrize("critical", [4, 5, 7, 10])
def test_critical_labels_beyond_the_bound_go_to_the_overflow_label(critical):
    rows = [
        {"id": f"crit-{i}", "label": f"C{i}", "evidence": [{"file": "a", "line": 1}], "tier": 1}
        for i in range(critical)
    ]
    rows.append({"id": "other", "label": "O", "evidence": [{"file": "a", "line": 1}], "tier": 3})
    display = F._capability_display(rows)
    shown = [cap["id"] for cap in display if not cap.get("more")]
    assert shown == [row["id"] for row in rows[: min(critical, F.CAPABILITY_CRITICAL_MAX)]]
    hidden = display[-1].get("more") or []
    assert display[-1]["label"] == f"+{len(hidden)}" and shown + [cap["id"] for cap in hidden] == [
        r["id"] for r in rows
    ]


def test_reported_findings_add_capabilities_only_from_deterministic_rules():
    capabilities, _ = F._capability_vocabulary()
    rule = {"source": "source-scan", "evidence_check": "verified"}
    threats = [
        dict(rule, id="T-001", cwe="CWE-611", component="api", evidence=[{"file": "src/xml.py", "line": 8}]),
        dict(rule, id="T-002", cwe="cwe-611", component="api", evidence=[{"file": "src/xml.py", "line": 8}]),
        dict(
            rule,
            id="T-003",
            cwe="CWE-1336",
            component="api",
            evidence=[{"file": "src/view.py", "line": 3}],
            instances=[{"component_id": "worker", "file": "jobs/render.py", "line": 12}],
        ),
        {
            "id": "T-004",
            "source": "stride",
            "cwe": "CWE-918",
            "component": "api",
            "evidence": [{"file": "a", "line": 1}],
        },
        dict(rule, id="T-005", cwe="CWE-79", component="api", evidence=[{"file": "src/page.py", "line": 2}]),
        dict(rule, id="T-006", cwe="CWE-434", component="api", evidence=[{"file": "src/up.py"}]),
    ]
    derived = F._finding_capabilities(threats, capabilities)
    assert derived == {
        "api": [
            {"capability": "xml-parsing", "evidence": [{"file": "src/xml.py", "line": 8}], "derived": True},
            {"capability": "template-rendering", "evidence": [{"file": "src/view.py", "line": 3}], "derived": True},
        ],
        "worker": [
            {"capability": "template-rendering", "evidence": [{"file": "jobs/render.py", "line": 12}], "derived": True}
        ],
    }
    authored = [{"capability": "xml-parsing", "evidence": [{"file": "src/parser.py", "line": 40}]}]
    rows = F._capability_rows([*authored, *derived["api"]], capabilities, "capability", "API")
    assert [(row["id"], row["derived"], row["evidence"][0]["file"]) for row in rows] == [
        ("xml-parsing", False, "src/parser.py"),
        ("template-rendering", True, "src/view.py"),
    ]
    by_cwe = {}
    for value, entry in capabilities.items():
        for cwe in entry.get("cwes") or []:
            assert cwe not in by_cwe and value not in {"llm-tools", "token-issuer", "jwt-issuer", "admin-functions"}
            by_cwe[cwe] = value

    model, paths, taxonomy = _model()
    model["threats"].append(
        dict(rule, id="T-090", cwe="CWE-611", component="app1", severity="Medium", stride="Information Disclosure")
        | {"evidence": [{"file": "src/import.ts", "line": 7}]}
    )
    model["threats"].append(
        dict(rule, id="T-091", cwe="CWE-918", component="app1", evidence_check="refuted", severity="Medium")
        | {"stride": "Spoofing", "evidence": [{"file": "src/fetch.ts", "line": 9}]}
    )
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    pills = [g for g in ET.fromstring(svg).iter(f"{_SVG}g") if g.get("data-capability")]
    assert [(g.get("data-capability-owner"), g.get("data-capability")) for g in pills] == [("app1", "xml-parsing")]
    assert pills[0].find(f"{_SVG}title").text.endswith("src/import.ts:7 (reported finding)")


def test_capability_labels_rank_tier_before_linked_finding_severity():
    capabilities, _ = F._capability_vocabulary()
    evidence = [{"file": "src/a.ts", "line": 1}]
    threats = [
        {"id": "T-1", "cwe": "CWE-434", "risk": "Critical", "component": "svc"},
        {"id": "T-2", "cwe": "cwe-918", "risk": "High", "component": "svc"},
        {"id": "T-3", "cwe": "CWE-918", "risk": "Medium", "component": "svc"},
        {"id": "T-4", "cwe": "CWE-611", "risk": "Critical", "component": "other"},
        {"id": "T-5", "cwe": "CWE-79", "risk": "Critical", "component": "svc"},
        {"id": "T-6", "cwe": "CWE-1427", "risk": "Medium", "effective_severity": "Critical", "component": "gateway"},
        {
            "id": "T-7",
            "cwe": "CWE-95",
            "risk": "High",
            "component": "gateway",
            "instances": [{"component_id": "jobs", "file": "w.py", "line": 3}, {"component_id": "guess", "line": 4}],
        },
    ]
    severity = F._capability_severity(threats, capabilities, {"svc", "other", "gateway", "jobs"})
    assert severity == {
        "svc": {"file-upload": 0, "url-fetch": 1},
        "other": {"xml-parsing": 0},
        "gateway": {"llm-calls": 2, "llm-tools": 2, "code-evaluation": 1},
        "jobs": {"code-evaluation": 1},
    }
    authored = ["admin-functions", "xml-parsing", "url-fetch", "file-upload"]
    items = [{"capability": value, "evidence": evidence} for value in authored]
    rows = F._capability_rows(items, capabilities, "capability", "Service", severity["svc"])
    assert [row["id"] for row in rows] == ["file-upload", "url-fetch", "admin-functions", "xml-parsing"]
    # Within a tier the most severe linked finding comes first.
    ties = [{"capability": value, "evidence": evidence} for value in ("file-upload", "url-fetch")]
    rows = F._capability_rows(ties, capabilities, "capability", "Service", {"url-fetch": 0})
    assert [(row["id"], row["severity"]) for row in rows] == [("url-fetch", 0), ("file-upload", None)]
    items = [
        {"capability": value, "evidence": evidence}
        for value in ("template-rendering", "llm-tools", "blockchain-client")
    ]
    rows = F._capability_rows(items, capabilities, "capability", "Gateway", severity["gateway"])
    assert [row["id"] for row in rows] == ["llm-tools", "template-rendering", "blockchain-client"]
    # A linked finding never lifts a label above a more critical function type.
    rows = F._capability_rows(items, capabilities, "capability", "Gateway", {"template-rendering": 0})
    assert [row["id"] for row in rows] == ["llm-tools", "template-rendering", "blockchain-client"]

    model, paths, taxonomy = _model()
    model["components"][1]["capabilities"] = [
        {"capability": value, "evidence": [{"file": "src/upload.ts", "line": 4}]}
        for value in ("url-fetch", "xml-parsing", "template-rendering", "background-jobs")
    ]
    model["threats"].append(
        {"id": "T-095", "source": "stride", "cwe": "CWE-1336", "component": "app0", "severity": "Critical"}
        | {"stride": "Tampering", "evidence": [{"file": "src/view.ts", "line": 5}]}
    )
    model["threats"].append(
        {"id": "T-096", "source": "stride", "cwe": "CWE-918", "component": "app0", "severity": "Critical"}
        | {"stride": "Spoofing", "evidence_check": "refuted", "evidence": [{"file": "src/fetch.ts", "line": 9}]}
    )
    svg, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == []
    pills = [g for g in ET.fromstring(svg).iter(f"{_SVG}g") if g.get("data-capability")]
    assert [g.get("data-capability") for g in pills] == ["url-fetch", "template-rendering", "xml-parsing"]
    # Only the label with a reported linked finding carries a dot in its severity colour; borders stay neutral.
    dots = {g.get("data-capability"): [d.get("fill") for d in g.iter(f"{_SVG}circle")] for g in pills}
    assert dots == {"url-fetch": [], "template-rendering": [F.RED], "xml-parsing": []}
    assert {g.find(f"{_SVG}rect").get("stroke") for g in pills} == {"#b6c6d8"}
    for g in pills:
        extra = F.PILL_DOT if g.get("data-capability") == "template-rendering" else 0
        label = F._tw(g.find(f"{_SVG}text").text, F.PILL_SIZE)
        assert float(g.find(f"{_SVG}rect").get("width")) == pytest.approx(label + 12 + extra, abs=0.1)


def test_merged_rule_hits_keep_adding_their_capability():
    capabilities, _ = F._capability_vocabulary()
    rule_hit = {"file": "src/xml.py", "line": 8, "source": "source-scan", "component_id": "backend-guess"}
    threats = [
        {
            "id": "T-001",
            "source": "stride",
            "cwe": "CWE-611",
            "component": "api",
            "evidence": [{"file": "src/xml.py", "line": 8}],
            "instances": [{"file": "src/xml.py", "line": 8, "source": "stride", "component_id": "api"}, rule_hit],
        },
        {
            "id": "T-002",
            "source": "stride",
            "cwe": "CWE-94",
            "component": "jobs",
            "evidence": [{"file": "lib/run.js", "line": 30}],
            "instances": [{"file": "lib/run.js", "line": 31, "source": "source-scan", "component_id": "jobs"}],
        },
        {
            "id": "T-003",
            "source": "stride",
            "cwe": "CWE-918",
            "component": "api",
            "evidence": [{"file": "src/fetch.py", "line": 2}],
            "instances": [{"file": "src/fetch.py", "line": 2, "component_id": "api"}],
        },
        {
            "id": "T-004",
            "source": "source-scan",
            "cwe": "CWE-1336",
            "component": "api",
            "evidence": [{"file": "src/view.py", "line": 3}],
            "instances": [{"file": "src/view.py", "line": 9, "source": "stride", "component_id": "api"}],
        },
    ]
    derived = F._finding_capabilities(threats, capabilities, {"api", "jobs"})
    assert derived == {
        "api": [
            {"capability": "xml-parsing", "evidence": [{"file": "src/xml.py", "line": 8}], "derived": True},
            {"capability": "template-rendering", "evidence": [{"file": "src/view.py", "line": 3}], "derived": True},
        ],
        "jobs": [{"capability": "code-evaluation", "evidence": [{"file": "lib/run.js", "line": 31}], "derived": True}],
    }


def test_capability_labels_require_known_values_and_evidence():
    model, paths, taxonomy = _model()
    unlabelled, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == [] and "data-capability=" not in unlabelled
    assert "Security-relevant capabilities" not in unlabelled
    evidence = [{"file": "src/upload.ts", "line": 4}]
    model["components"][1]["capabilities"] = [
        {"capability": "file-upload", "evidence": evidence},
        {"capability": "file-upload", "evidence": evidence},
        {"capability": "not-a-capability", "evidence": evidence},
        {"capability": "llm-tools", "evidence": []},
        {"capability": "llm-tools", "evidence": evidence},
        {"capability": "token-issuer", "evidence": evidence},
        {"capability": "mfa-verifier", "evidence": evidence},
    ]
    service = {"role": "llm-inference", "evidence": evidence}
    model["external_entities"] = [
        {"id": "ext-model", "name": "Model API", "kind": "external-service", "service_roles": [service]},
        {"id": "ext-reader", "name": "Reader", "kind": "legitimate-role", "service_roles": [service]},
    ]
    model["data_flows"][5]["to_entity"] = "ext-model"
    model["data_flows"][0]["from_entity"] = "ext-reader"
    before = copy.deepcopy(model)
    for detail in (False, True):
        svg, problems = F.check_diagram(model, paths, taxonomy, detail=detail)
        assert problems == []
        root = ET.fromstring(svg)
        pills = [g for g in root.iter(f"{_SVG}g") if g.get("data-capability")]
        assert [(g.get("data-capability-owner"), g.get("data-capability")) for g in pills] == [
            ("app0", "file-upload"),
            ("app0", "llm-tools"),
            ("app0", "token-issuer"),
            ("ext-model", "llm-inference"),
        ]
        assert "src/upload.ts:4" in pills[0].find(f"{_SVG}title").text
        more = [g for g in root.iter(f"{_SVG}g") if g.get("data-capability-more")]
        assert [(g.get("data-capability-owner"), g.get("data-capability-more")) for g in more] == [("app0", "1")]
        assert "".join(more[0].itertext()).strip().endswith("+1")
        assert "MFA verifier" in more[0].find(f"{_SVG}title").text
        notation = " ".join(root.find("{*}g[@data-legend-section='notation']").itertext())
        assert "Security-relevant capabilities / service roles" in notation
        assert "LLM + tools = model calls with executable application tools" in notation
        flat = " ".join(notation.split())
        assert "Most security-critical functions always shown" in flat
        assert "most critical first, then most severe linked finding" in flat
        assert "+N = further labels" in flat
        assert "a missing label does not mean absence" in notation
        further = " ".join(root.find("{*}g[@data-legend-section='capability-notes']").itertext())
        assert "Further capabilities" in further and ": MFA verifier" in further
    assert model == before


@pytest.mark.parametrize(
    ("name", "framework", "language", "shown"),
    [
        ("Order Service", "spring-boot", "Kotlin", {"framework": "spring-boot", "language": "Kotlin"}),
        ("Customer Records", "postgresql", None, {"framework": "postgresql"}),
        ("Report Worker", None, "Go", {"language": "Go"}),
        ("Billing API", "  Ruby  on Rails ", "Ruby", {"framework": "Ruby on Rails"}),
        ("Storefront", "vue", "Vue", {"framework": "vue"}),
        ("Socket.IO Gateway", "socket.io", "TypeScript", {"language": "TypeScript"}),
        ("Python Importer", None, "Python", {}),
        ("PostgreSQL Primary", "PostgreSQL", None, {}),
        ("Worker", "  ", None, {}),
    ],
)
def test_technology_is_left_out_only_when_absent_or_already_said(name, framework, language, shown):
    component = {"id": "worker", "name": name, "framework": framework, "language": language}
    assert F._technology(component) == shown


@pytest.mark.parametrize(
    ("tech", "label"),
    [
        ({"framework": "spring-boot", "language": "Java"}, "[spring-boot · Java]"),
        ({"language": "TypeScript"}, "[TypeScript]"),
        ({"framework": "sequelize-with-custom-dialect", "language": "TypeScript"}, "[sequelize-with… · TypeScript]"),
        ({"framework": "a-very-long-framework-name-beyond-the-line"}, "[a-very-long-framework-name-…]"),
    ],
)
def test_technology_label_shortens_the_framework_before_the_language(tech, label):
    assert F._technology_label(tech) == label


def test_components_show_framework_language_or_engine_apart_from_labels():
    model, paths, taxonomy = _model()
    for comp in model["components"]:
        comp.pop("framework", None)
    bare, problems = F.check_diagram(model, paths, taxonomy, detail=False)
    assert problems == [] and "data-technology-owner" not in bare
    notation = " ".join(ET.fromstring(bare).find("{*}g[@data-legend-section='notation']").itertext())
    assert "data store: engine" not in notation
    by_id = {comp["id"]: comp for comp in model["components"]}
    evidence = [{"file": "src/views.py", "line": 12}]
    by_id["app1"] |= {
        "framework": "fastapi",
        "language": "Python",
        "capabilities": [{"capability": "template-rendering", "evidence": evidence}],
    }
    by_id["app2"] |= {"name": "Gin Gateway", "framework": "gin", "language": "Go"}
    by_id["db0"]["framework"] = "mongodb"
    by_id["ci"]["framework"] = "github-actions"
    before = copy.deepcopy(model)
    for detail in (False, True):
        svg, problems = F.check_diagram(model, paths, taxonomy, detail=detail)
        assert problems == []
        root = ET.fromstring(svg)
        groups = list(root.iter(f"{_SVG}g"))
        shown = {g.get("data-technology-owner"): g for g in groups if g.get("data-technology-owner")}
        assert {owner: (g.get("data-framework"), g.get("data-language")) for owner, g in shown.items()} == {
            "app1": ("fastapi", "Python"),
            "app2": (None, "Go"),
            "db0": ("mongodb", None),
            "ci": ("github-actions", None),
        }
        tech = shown["app1"].find(f"{_SVG}text")
        assert tech.text == "[fastapi · Python]" and tech.get("font-style") == "italic"
        assert shown["app1"].find(f"{_SVG}title").text == "Framework: fastapi · Language: Python"
        assert shown["db0"].find(f"{_SVG}title").text == "Storage engine: mongodb"
        title = next(g for g in groups if g.get("data-component-id") == "app1").find(f"{_SVG}text")
        pill = next(g for g in groups if g.get("data-capability-owner") == "app1").find(f"{_SVG}rect")
        assert float(title.get("y")) < float(tech.get("y")) < float(pill.get("y"))
        assert _visible_text(root).count("github-actions") == 1
        notation = " ".join(root.find("{*}g[@data-legend-section='notation']").itertext())
        assert "framework · language; data store: engine" in notation
    assert model == before


@pytest.mark.parametrize("detail", [False, True])
@pytest.mark.parametrize("zones", [["ci-cd-runtime"], ["build-pipeline", "ci-cd-runtime"], ["release-runner"]])
def test_build_zone_subtitle_is_reader_wording_not_deployment_zone_ids(detail, zones):
    model, paths, taxonomy = _model()
    model["components"][-1]["deployment_zones"] = zones + ["pipeline"]
    svg, _problems = F.check_diagram(model, paths, taxonomy, detail=detail)
    text = [t.text or "" for t in ET.fromstring(svg).iter("{http://www.w3.org/2000/svg}text")]
    assert "CI/CD and release tooling" in text
    assert not any(zone in line for zone in zones for line in text)


@pytest.mark.parametrize(
    "capability,label",
    [
        ("rag-retrieval", "RAG retrieval"),
        ("rag-ingestion", "RAG ingestion"),
        ("agent-memory", "Persistent AI memory"),
        ("agent-delegation", "Agent delegation"),
        ("mcp-client", "MCP client"),
        ("mcp-server", "MCP server"),
    ],
)
def test_ai_capabilities_preserve_topology_and_require_evidence(capability, label):
    model, paths, taxonomy = _model()
    model["components"][1]["capabilities"] = [
        {"capability": capability, "evidence": [{"file": "src/runtime.py", "line": 5}]}
    ]
    before = copy.deepcopy(model)
    for detail in (False, True):
        svg, problems = F.check_diagram(model, paths, taxonomy, detail=detail)
        assert problems == []
        assert f'data-capability="{capability}"' in svg and label in svg
        assert model == before
    model["components"][1]["capabilities"][0]["evidence"] = []
    svg, problems = F.check_diagram(model, paths, taxonomy)
    assert problems == [] and f'data-capability="{capability}"' not in svg
