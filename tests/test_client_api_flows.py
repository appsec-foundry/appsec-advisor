"""A client's requests to its own API become flows grouped by the authentication its routes prove."""

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from analyzers.client_api_flows import client_calls, flows, uncovered_calls  # noqa: E402


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


def test_explicit_client_method_does_not_borrow_another_methods_guard():
    routes = [
        route("GET", "/records", 10, "verified", "bearer", "present"),
        route("POST", "/records", 11, "none", "none", "absent"),
        route("OPTIONS", "*", 12, "none", "none", "absent"),
    ]
    calls = client_calls({"ui/api.ts": b"client.get(base + '/records')\n"}, routes)
    assert set(calls) == {0}
    [flow] = flows("web", calls, routes, lambda _: "api")
    assert flow["route_refs"] == ["GET /records"]
    assert flow["authentication"]["scheme"] == "bearer"


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


@pytest.mark.parametrize(
    ("client", "receiver", "prefix"), [("portal", "api", "/orders"), ("console", "engine", "/jobs")]
)
def test_existing_flow_covers_only_its_evidenced_authentication_variant(client, receiver, prefix):
    routes = [
        route("GET", prefix + "/private", 10, "verified", "bearer", "middleware_present"),
        route("POST", prefix + "/session", 11, "verified", "cookie", "present"),
        route("GET", prefix + "/public", 12, "none", "none", "absent"),
        route("GET", prefix + "/dynamic", 13),
    ]
    calls = {i: [{"file": "ui/api.ts", "line": i + 1}] for i in range(4)}

    def owner(_):
        return receiver

    existing = flows(client, {0: calls[0]}, routes, owner)
    before = copy.deepcopy(existing)
    remaining = uncovered_calls(client, calls, routes, owner, existing)
    assert set(remaining) == {1, 2, 3}
    emitted = flows(client, remaining, routes, owner)
    assert {(f.get("authentication") or {}).get("scheme", "unknown") for f in emitted} == {"cookie", "none", "unknown"}
    assert existing == before
    # A repeat does not duplicate these evidenced interfaces.
    assert uncovered_calls(client, calls, routes, owner, existing + emitted) == {}


@pytest.mark.parametrize("kind", ["pair-only", "reference-only", "wrong-receiver", "interaction", "different-auth"])
def test_an_unsubstantiated_or_different_flow_cannot_hide_a_proven_variant(kind):
    calls = {0: [{"file": "ui/api.ts", "line": 1}]}
    existing = {"from": "web", "to": "api", "route_refs": ["GET /api/orders/:id"]}
    if kind not in {"pair-only", "reference-only"}:
        existing["evidence"] = calls[0]
    if kind == "pair-only":
        existing.pop("route_refs")
    elif kind == "wrong-receiver":
        existing["to"] = "other-api"
    elif kind == "interaction":
        existing["interaction"] = True
    elif kind == "different-auth":
        existing["authentication"] = {"scheme": "cookie", "scope": "A session", "evidence": calls[0]}
    assert uncovered_calls("web", calls, ROUTES, lambda _: "api", [existing]) == calls


def test_a_route_fillable_authored_flow_is_not_duplicated():
    calls = {0: [{"file": "ui/api.ts", "line": 1}]}
    existing = {"from": "web", "to": "api", "evidence": [{"file": "server.ts", "line": 10}]}
    assert uncovered_calls("web", calls, ROUTES, lambda _: "api", [existing]) == {}


def test_authentication_considers_every_route_before_bounding_evidence():
    from analyzers.flow_route_auth import reconcile
    from jsonschema import validate
    from renderers.figure1_security import profile_catalog

    routes = [route("GET", f"/records/{i}", i + 10, "none", "none", "absent") for i in range(5)]
    # Both outcomes have scheme none, but decoding a credential is a distinct
    # observation. It used to disappear beyond the four registration samples.
    routes[-1]["authn_handler_signal"] = "decode_only"
    calls = {i: [{"file": "ui/api.ts", "line": i + 1}] for i in range(5)}
    before = copy.deepcopy(routes)
    emitted = flows("web", calls, routes, lambda _: "api")
    assert len(emitted) == 2
    assert len({f["authentication"]["scope"] for f in emitted}) == 2
    for i, flow in enumerate(emitted, 1):
        flow["id"] = f"df-{i:03d}"
    document = {
        "schema_version": 1,
        "component_inventory_fingerprint": "sha256:" + "a" * 64,
        "data_flows": emitted,
    }
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    validate(document, schema)
    enriched, filled, mixed = reconcile(document, routes)
    assert enriched == document and not filled and not mixed
    assert {p["scheme"] for p in profile_catalog(emitted).values()} == {"none"}
    assert routes == before


def test_stable_route_references_keep_covered_guards_after_evidence_is_shortened():
    routes = [route("GET", f"/records/{i}", i + 10, "verified", "bearer", "present") for i in range(8)]
    calls = {i: [{"file": "ui/api.ts", "line": i + 1}] for i in range(8)}
    emitted = flows("web", calls, routes, lambda _: "api")
    assert len(emitted) == 1 and len(emitted[0]["evidence"]) == 8
    assert uncovered_calls("web", calls, routes, lambda _: "api", emitted) == {}
    # Returned evidence must not alias scanner input: the controller qualifies it.
    emitted[0]["authentication"]["evidence"][0]["repository_id"] = "repo-local"
    assert "repository_id" not in routes[0]["authn_handler_evidence"][0]


def test_unresolved_route_does_not_gain_authentication_from_a_finding_on_its_registration_file():
    from analyzers.flow_route_auth import fill_from_verified_findings

    emitted = _filled("web", "client.get('/rest/reports')", ROUTES, "api")
    [flow] = emitted
    assert "authentication" not in flow
    finding = {
        "id": "T-001",
        "component": "api",
        "cwe": "CWE-306",
        "evidence_check": "verified",
        "evidence": [{"file": "server.ts", "line": 200}],
    }
    result, filled = fill_from_verified_findings(emitted, [finding])
    assert result == emitted and filled == []


@pytest.mark.parametrize("prefix", ["/orders", "/v2/jobs"])
@pytest.mark.parametrize("count", [6, 40])
def test_unknown_interfaces_remain_covered_beyond_evidence_and_reference_caps(prefix, count):
    routes = [route("GET", f"{prefix}/{i}", i + 10) for i in range(count)]
    calls = {i: [{"file": "ui/service.ts", "line": i + 1}] for i in range(count)}
    existing = flows("web", calls, routes, lambda _: "api")
    assert sum(len(flow["route_refs"]) for flow in existing) == count
    assert all(len(flow["evidence"]) <= 8 and len(flow["route_refs"]) <= 32 for flow in existing)
    assert all("authentication" not in flow for flow in existing)
    assert uncovered_calls("web", calls, routes, lambda _: "api", existing) == {}


def test_unknown_references_need_a_local_anchor_and_cannot_hide_newly_proven_authentication():
    routes = [route("GET", f"/records/{i}", i + 10) for i in range(6)]
    calls = {i: [{"file": "ui/service.ts", "line": i + 1}] for i in range(6)}
    existing = flows("web", calls, routes, lambda _: "api")
    unanchored = copy.deepcopy(existing)
    unanchored[0]["evidence"] = [{"file": "unrelated.ts", "line": 1}]
    assert uncovered_calls("web", calls, routes, lambda _: "api", unanchored) == calls
    routes[-1].update(authn_signal="present", authn_handler_signal="verified", authn_handler_scheme="cookie")
    assert set(uncovered_calls("web", calls, routes, lambda _: "api", existing)) == {5}


def test_long_interface_names_do_not_collapse_to_the_same_truncated_reference():
    routes = [route("GET", "/" + "segment/" * 20 + str(i), i + 10) for i in range(6)]
    calls = {i: [{"file": "ui/service.ts", "line": i + 1}] for i in range(6)}
    existing = flows("web", calls, routes, lambda _: "api")
    assert len(existing[0]["route_refs"]) == 6
    assert all(len(ref) <= 120 for ref in existing[0]["route_refs"])
    assert uncovered_calls("web", calls, routes, lambda _: "api", existing) == {}


@pytest.mark.parametrize("path", ["/records", "/v2/jobs"])
@pytest.mark.parametrize(
    ("source", "method", "line"),
    [
        ("client.get(\n  '{path}'\n)", "GET", 2),
        ("client.get(base() + '{path}')", "GET", 1),
        ("this.http.post<Result>(\n base() + '{path}', payload)", "POST", 2),
        ("fetch(\n '{path}',\n {{ method: 'POST', body: payload }}\n)", "POST", 2),
        ("fetch('{path}')", "GET", 1),
    ],
)
def test_complete_calls_keep_their_method_and_exact_url_evidence(path, source, method, line):
    routes = [
        route("GET", path, 10, "verified", "bearer", "present"),
        route("POST", path, 11, "none", "none", "absent"),
    ]
    calls = client_calls({"ui/api.ts": source.format(path=path).encode()}, routes)
    index = 0 if method == "GET" else 1
    assert calls == {index: [{"file": "ui/api.ts", "line": line}]}
    [flow] = flows("web", calls, routes, lambda _: "api")
    assert flow["authentication"]["scheme"] == ("bearer" if method == "GET" else "none")


@pytest.mark.parametrize(
    "source",
    [
        "const unused = '/records'",
        "/* client.get('/records') */",
        "const sample = \"client.get('/records')\"",
        "client.post('/elsewhere', { next: '/records' })",
        "fetch('/records', { method: selectedMethod })",
        "fetch('/records', options)",
        "fetch('/records', { method: 'GET', ...options })",
        "fetch('/records', { ['method']: 'POST' })",
        "fetch('/records', { get method() { return selectedMethod } })",
        "fetch('/records', { get ['method']() { return 'POST' } })",
        r"fetch('/records', { '\u006dethod': 'POST' })",
        "fetch('/records', { __proto__: options })",
        "client[method]('/records')",
        "client.get('https://remote.invalid' + '/records')",
        "client.get('/records'",
        "client.get(" + " " * 4096 + "'/records')",
    ],
)
def test_non_requests_and_unresolved_methods_do_not_borrow_route_authentication(source):
    routes = [
        route("GET", "/records", 10, "verified", "bearer", "present"),
        route("POST", "/records", 11, "none", "none", "absent"),
    ]
    assert client_calls({"ui/api.ts": source.encode()}, routes) == {}
