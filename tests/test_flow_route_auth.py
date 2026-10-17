"""A flow's unknown authentication takes the outcome its cited routes' handlers prove."""

import copy
import json
from pathlib import Path

import jsonschema
import pytest
import validators.validate_fragment as validate_fragment
from analyzers.flow_route_auth import fill_from_verified_findings, mixed_route_auth_errors, reconcile
from analyzers.handler_resolver import DECODE_ONLY_SCOPE

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/fragments/data-flows.schema.json").read_text())
UNKNOWN = {"scheme": "unknown", "scope": "Not located", "evidence": [{"file": "app.ts", "line": 9}]}


def _route(line, signal, scheme, authn, path="/x"):
    return {
        "method": "POST",
        "path": path,
        "handler_file": "app.ts",
        "handler_line": line,
        "authn_signal": authn,
        "authn_handler_signal": signal,
        "authn_handler_scheme": scheme,
        "authn_handler_evidence": [{"file": f"handlers/h{line}.ts", "line": 3}],
    }


VERIFIED = _route(10, "verified", "cookie", "present", "/a")
NONE = _route(11, "none", "none", "absent", "/b")
DECODED = _route(12, "decode_only", "none", "absent", "/c")
UNRESOLVED = _route(13, "unresolved", None, "unknown", "/d")


def _flow(fid, *lines, **extra):
    return {
        "id": fid,
        "from": "web",
        "to": "api",
        "label": "Request",
        "protocol": "HTTPS",
        "data_classification": "Internal",
        "direction": "request-response",
        "evidence": [{"file": "app.ts", "line": line} for line in lines],
        "provenance": "architecture",
        **extra,
    }


def _doc(*flows):
    return {"schema_version": 1, "component_inventory_fingerprint": "sha256:" + "a" * 64, "data_flows": list(flows)}


@pytest.mark.parametrize(
    ("lines", "scheme", "scope"),
    [
        ((10,), "cookie", "the handler checks a cookie credential and rejects the request without it"),
        ((11,), "none", "no credential check in the resolved handler chain"),
        ((12,), "none", DECODE_ONLY_SCOPE),
        ((11, 12), None, None),
    ],
)
def test_flow_takes_the_shared_outcome_of_its_routes(lines, scheme, scope):
    document = _doc(_flow("df-001", *lines, authentication=UNKNOWN))
    before = copy.deepcopy(document)
    result, filled, mixed = reconcile(document, [VERIFIED, NONE, DECODED, UNRESOLVED])
    assert document == before
    flow = result["data_flows"][0]
    if scheme is None:
        assert (filled, mixed) == ([], ["df-001"]) and flow["authentication"] == UNKNOWN
        assert "split the flow" in mixed_route_auth_errors(result["data_flows"], [NONE, DECODED])[0]
        return
    assert filled == ["df-001"] and mixed == []
    assert flow["authentication"]["scheme"] == scheme and flow["authentication"]["scope"] == scope
    assert flow["authentication"]["evidence"][0]["file"].startswith("handlers/")
    jsonschema.validate(result, SCHEMA)


@pytest.mark.parametrize(
    "flow",
    [
        _flow(
            "df-001",
            10,
            authentication={"scheme": "bearer", "scope": "Authored", "evidence": [{"file": "app.ts", "line": 10}]},
        ),
        _flow("df-001", 13, authentication=UNKNOWN),
        _flow("df-001", 10, 13, authentication=UNKNOWN),
        _flow("df-001", 99, authentication=UNKNOWN),
        _flow("df-001", 10, authentication=UNKNOWN, interaction=True),
    ],
    ids=["authored-scheme", "unresolved-route", "one-unresolved", "no-route", "interaction"],
)
def test_nothing_unproven_or_authored_is_filled(flow):
    result, filled, mixed = reconcile(_doc(flow), [VERIFIED, UNRESOLVED])
    assert (filled, mixed) == ([], []) and result["data_flows"][0] == flow
    assert mixed_route_auth_errors(result["data_flows"], [VERIFIED, UNRESOLVED]) == []


@pytest.mark.parametrize("seen", ["middleware_present", "decorator_present"])
def test_a_registration_guard_the_resolver_verifies_fills_the_flow(seen):
    guarded = _route(14, "verified", "bearer", seen, "/e")
    result, filled, _mixed = reconcile(_doc(_flow("df-001", 14, authentication=UNKNOWN)), [guarded])
    assert filled == ["df-001"] and result["data_flows"][0]["authentication"]["scheme"] == "bearer"
    # Seen at registration but not verified by the chain fills nothing.
    unproven = _route(14, "unresolved", None, seen, "/e")
    assert reconcile(_doc(_flow("df-001", 14, authentication=UNKNOWN)), [unproven])[1] == []


def test_self_check_reports_a_flow_whose_routes_differ(tmp_path):
    (tmp_path / ".route-inventory.json").write_text(json.dumps({"routes": [VERIFIED, NONE]}))
    flows = {"data_flows": [_flow("df-004", 10, 11, authentication=UNKNOWN)]}
    errors = validate_fragment._route_split_errors(flows, tmp_path / ".route-inventory.json")
    assert len(errors) == 1 and errors[0].startswith("df-004:") and "cookie" in errors[0]
    assert validate_fragment._route_split_errors(flows, tmp_path / "missing.json") == []


def _socket_flow(**auth):
    authentication = {
        "scheme": "unknown",
        "scope": "token in handshake not confirmed",
        "evidence": [{"file": "lib/ws.ts", "line": 20}],
        **auth,
    }
    return {"id": "df-6", "from": "spa", "to": "realtime", "authentication": authentication}


def _missing_auth(**over):
    return {
        "id": "T-027",
        "component": "realtime",
        "cwe": "CWE-306",
        "evidence_check": "verified",
        "evidence": [{"file": "lib/ws.ts", "line": 23}],
        **over,
    }


def test_a_verified_missing_authentication_finding_fills_the_flow_it_cites():
    """A channel the route inventory cannot see (a WebSocket, a queue consumer)
    stayed `unknown` beside a confirmed CWE-306 at the very file the flow cites
    (juice-shop2 2026-09-27, df-006)."""
    flows, filled = fill_from_verified_findings([_socket_flow()], [_missing_auth()])
    assert filled == ["df-6"]
    auth = flows[0]["authentication"]
    assert auth["scheme"] == "none"
    assert "T-027" in auth["scope"]
    assert auth["evidence"] == [{"file": "lib/ws.ts", "line": 23}]


@pytest.mark.parametrize(
    "finding",
    [
        _missing_auth(evidence_check="refuted"),
        _missing_auth(evidence_check="ambiguous"),
        _missing_auth(cwe="CWE-287"),  # broken authentication is still authentication
        _missing_auth(component="api"),  # another component's gap says nothing about this flow
        _missing_auth(evidence=[{"file": "lib/other.ts", "line": 1}]),  # not the code the flow rests on
    ],
)
def test_only_a_verified_missing_authentication_at_the_cited_code_fills(finding):
    flows, filled = fill_from_verified_findings([_socket_flow()], [finding])
    assert filled == []
    assert flows[0]["authentication"]["scheme"] == "unknown"


def test_a_known_scheme_is_never_overwritten():
    flow = _socket_flow(scheme="bearer")
    flows, filled = fill_from_verified_findings([flow], [_missing_auth()])
    assert filled == []
    assert flows[0]["authentication"]["scheme"] == "bearer"
