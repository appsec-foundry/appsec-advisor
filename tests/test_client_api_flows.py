"""A client's requests to its own API become flows grouped by the authentication its routes prove."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from analyzers.client_api_flows import client_calls, flows  # noqa: E402


def route(method, path, line, signal="unresolved", scheme=None, authn="unknown"):
    return {
        "method": method,
        "path": path,
        "handler_file": "server.ts",
        "handler_line": line,
        "authn_signal": authn,
        "authn_handler_signal": signal,
        "authn_handler_scheme": scheme,
        "authn_handler_evidence": [{"file": "lib/guard.ts", "line": 4}],
    }


ROUTES = [
    route("GET", "/api/orders/:id", 10, "verified", "bearer", "middleware_present"),
    route("POST", "/rest/login", 11, "none", "none", "absent"),
    route("GET", "/rest/reports", 12),
    route("GET", "/", 13),
]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("return this.http.get(`${this.host}/api/orders/${id}`)\n", [0]),
        ("return this.http.get(this.host + '/api/orders/' + id)\n", [0]),
        ('this.http.post(environment.api + "/rest/login", creds)\n', [1]),
    ],
)
def test_path_literals_match_their_routes(source, expected):
    assert sorted(client_calls({"web/src/orders.service.ts": source.encode()}, ROUTES)) == expected


@pytest.mark.parametrize(
    ("path", "source"),
    [
        ("web/src/app.html", '<a routerLink="/rest/login">Log in</a>\n'),
        ("web/src/orders.service.spec.ts", "http.get('/api/orders/1')\n"),
        ("web/src/orders.service.ts", "// http.get('/api/orders/1')\n"),
        ("web/src/orders.service.ts", "const page = '/orders/list'\nconst home = '/'\n"),
    ],
    ids=["template", "test-file", "comment", "unmatched"],
)
def test_templates_tests_comments_and_unknown_paths_request_nothing(path, source):
    assert client_calls({path: source.encode()}, ROUTES) == {}


def test_routes_group_by_owner_and_proven_authentication():
    source = (
        "get = (id) => this.http.get(`${base}/api/orders/${id}`)\n"
        "login = (c) => this.http.post(base + '/rest/login', c)\n"
        "reports = () => this.http.get(base + '/rest/reports')\n"
    )
    calls = client_calls({"web/src/api.ts": source.encode()}, ROUTES)
    result = flows("component-web", calls, ROUTES, lambda r: "component-api")
    by_label = {flow["label"]: flow for flow in result}
    assert set(by_label) == {
        "API requests (bearer)",
        "API requests (none)",
        "API requests (unknown authentication)",
    }
    bearer = by_label["API requests (bearer)"]
    assert bearer["route_refs"] == ["GET /api/orders/:id"]
    # The client call and the route registration both stand as evidence, so the route fill can decide it.
    assert bearer["evidence"] == [{"file": "web/src/api.ts", "line": 1}, {"file": "server.ts", "line": 10}]
    assert {flow["access_group"]["mode"] for flow in result} == {"alternatives"}
    assert len({flow["access_group"]["id"] for flow in result}) == 1
    # A route the client itself owns, or no component owns, adds no flow.
    assert flows("component-web", calls, ROUTES, lambda r: None) == []
    assert flows("component-web", calls, ROUTES, lambda r: "component-web") == []


def _filled(client, source, routes, owner):
    """The controller's order: emit, number, apply the route fill, settle the groups."""
    from analyzers.client_api_flows import settle_access_groups
    from analyzers.flow_route_auth import reconcile

    result = flows(client, client_calls({"web/src/api.ts": source.encode()}, routes), routes, lambda r: owner)
    for index, flow in enumerate(result, 1):
        flow["id"] = f"df-{index:03d}"
    document, _filled_ids, _mixed = reconcile({"data_flows": result}, routes)
    settle_access_groups(document["data_flows"])
    return document["data_flows"]


def test_a_flow_left_unknown_by_the_route_fill_leaves_its_access_group():
    from renderers.figure1_security import access_groups

    source = (
        "get = (id) => this.http.get(`${base}/api/orders/${id}`)\n"
        "login = (c) => this.http.post(base + '/rest/login', c)\n"
        "reports = () => this.http.get(base + '/rest/reports')\n"
    )
    result = _filled("component-web", source, ROUTES, "component-api")
    # Before settling, the unknown member made the architecture gate stop the run.
    assert access_groups(result)[1] == []
    grouped = {flow["label"]: (flow.get("access_group") or {}).get("id") for flow in result}
    assert grouped == {
        "API requests (bearer)": "api-component-web-component-api",
        "API requests (none)": "api-component-web-component-api",
        "API requests (unknown authentication)": None,
    }


def test_a_group_with_one_proven_member_dissolves():
    from renderers.figure1_security import access_groups

    routes = [
        route("DELETE", "/v2/items/:key", 30, "verified", "cookie", "middleware_present"),
        route("GET", "/v2/audit", 31),
    ]
    source = "drop = (k) => client.delete(`/v2/items/${k}`)\naudit = () => client.get('/v2/audit')\n"
    result = _filled("component-ui", source, routes, "component-backend")
    assert len(result) == 2
    assert all("access_group" not in flow for flow in result)
    assert access_groups(result)[1] == []


def test_settling_leaves_groups_of_other_producers_to_the_gate():
    from analyzers.client_api_flows import settle_access_groups

    authored = [
        {"id": "df-001", "provenance": "model", "access_group": {"id": "g", "mode": "alternatives", "label": "x"}},
        {"id": "df-002", "provenance": "model", "access_group": {"id": "g", "mode": "alternatives", "label": "x"}},
    ]
    settle_access_groups(authored)
    assert all("access_group" in flow for flow in authored)
