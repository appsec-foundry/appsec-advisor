"""A flow's unknown authentication takes the outcome its cited routes' handlers prove."""

import copy
import json
from pathlib import Path

import jsonschema
import orchestration_controller as controller
import pytest
import route_inventory as ri
import validate_fragment
from flow_route_auth import mixed_route_auth_errors, reconcile
from handler_resolver import DECODE_ONLY_SCOPE

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


def test_self_check_reports_a_flow_whose_routes_differ(tmp_path):
    (tmp_path / ".route-inventory.json").write_text(json.dumps({"routes": [VERIFIED, NONE]}))
    flows = {"data_flows": [_flow("df-004", 10, 11, authentication=UNKNOWN)]}
    errors = validate_fragment._route_split_errors(flows, tmp_path / ".route-inventory.json")
    assert len(errors) == 1 and errors[0].startswith("df-004:") and "cookie" in errors[0]
    assert validate_fragment._route_split_errors(flows, tmp_path / "missing.json") == []


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_controller_handoff_fills_flow_authentication_from_the_route_inventory(tmp_path):
    repo, out = tmp_path / "repo", tmp_path / "out"
    out.mkdir()
    _write(
        repo,
        "server/app.ts",
        "import express from 'express'\n"
        "import { upload } from './upload'\n"
        "import { profile } from './profile'\n"
        "const app = express()\n"
        "app.post('/upload', upload())\n"
        "app.post('/profile', profile())\n",
    )
    _write(repo, "server/upload.ts", "export function upload () {\n  return (req, res) => res.json(req.body)\n}\n")
    _write(
        repo,
        "server/profile.ts",
        "export function profile () {\n  return (req, res, next) => {\n"
        "    const who = store.get(req.cookies.sid)\n    if (!who) { res.status(401).end(); return }\n"
        "    res.json(who)\n  }\n}\n",
    )
    _write(repo, "web/main.ts", "fetch('/upload')\n")
    (out / ".route-inventory.json").write_text(json.dumps(ri.build_inventory(repo)))
    components = [
        {"id": "web", "tier": "client", "paths": ["web/**"]},
        {"id": "api", "tier": "application", "paths": ["server/**"]},
    ]
    receipt = {"component_inventory_fingerprint": "sha256:" + "a" * 64, "component_ids": ["web", "api"]}
    (out / ".components.json").write_text(json.dumps({"components": components}))
    (out / ".component-inventory-finalization.json").write_text(json.dumps(receipt))

    def unknown_at(line):
        cited = [{"file": "server/app.ts", "line": line}]
        return {"evidence": cited, "authentication": {"scheme": "unknown", "scope": "Not located", "evidence": cited}}

    flows = [{**_flow("df-001"), **unknown_at(5)}, {**_flow("df-002"), **unknown_at(6)}]
    (out / ".data-flows.json").write_text(json.dumps(_doc(*flows)))
    controller._bind_finalized_component_fingerprint(out, repo)
    result = {f["id"]: f["authentication"] for f in json.loads((out / ".data-flows.json").read_text())["data_flows"]}
    assert result["df-001"]["scheme"] == "none"
    assert result["df-002"]["scheme"] == "cookie"
    assert result["df-002"]["evidence"] == [{"file": "server/profile.ts", "line": 3}]
    assert "FLOW_AUTH_RECONCILED" in (out / ".agent-run.log").read_text()
