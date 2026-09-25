"""A legitimate role keeps an authenticated access class only where its request path authenticates."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from reconcile_role_access import (  # noqa: E402
    apply_declared,
    declared_roles,
    reconcile,
    system_proven_anonymous,
)

COMPONENTS = [
    {"id": "gateway", "tier": "application"},
    {"id": "spa", "tier": "client"},
    {"id": "backend", "tier": "application"},
    {"id": "db", "tier": "data"},
]


def flow(fid, src, dst, scheme=None, *, entity=None, interaction=False):
    row = {"id": fid, "from": src, "to": dst}
    if entity:
        row["from_entity"] = entity
    if interaction:
        row["interaction"] = True
    if scheme:
        row["authentication"] = {"scheme": scheme}
    return row


def document(flows, access="internet-user", entity="ext-role"):
    return {
        "external_entities": [{"id": entity, "name": "Role", "kind": "legitimate-role", "access": access}],
        "data_flows": flows,
    }


def access_after(flows, access="internet-user"):
    result, changes = reconcile(document(flows, access), COMPONENTS)
    return result["external_entities"][0]["access"], changes


@pytest.mark.parametrize("access", ["internet-user", "internet-priv-user"])
def test_role_reaching_an_unauthenticated_system_is_anonymous(access):
    flows = [
        flow("df-001", "external", "backend", "none", entity="ext-role"),
        flow("df-002", "external", "backend", "unknown", entity="ext-role"),
    ]
    assert access_after(flows, access) == (
        "internet-anon",
        [{"entity_id": "ext-role", "from": access, "to": "internet-anon"}],
    )


def test_authentication_behind_a_pass_through_gateway_keeps_the_class():
    flows = [
        flow("df-001", "external", "gateway", "none", entity="ext-role"),
        flow("df-002", "gateway", "backend", "bearer"),
    ]
    assert access_after(flows) == ("internet-user", [])


def test_client_interaction_with_an_authenticated_backend_keeps_the_class():
    flows = [
        flow("df-001", "external", "spa", entity="ext-role", interaction=True),
        flow("df-002", "spa", "backend", "cookie"),
    ]
    assert access_after(flows) == ("internet-user", [])


def test_unknown_authentication_proves_nothing():
    flows = [flow("df-001", "external", "backend", "unknown", entity="ext-role")]
    assert access_after(flows) == ("internet-user", [])


def test_role_without_flows_is_left_as_authored():
    assert access_after([]) == ("internet-user", [])


@pytest.mark.parametrize(
    "service_hop",
    [flow("df-002", "backend", "db", "password"), flow("df-002", "backend", "external", "api-key")],
)
def test_service_credentials_behind_the_application_are_not_caller_authentication(service_hop):
    flows = [flow("df-001", "external", "backend", "none", entity="ext-role"), service_hop]
    assert access_after(flows)[0] == "internet-anon"


def test_anonymous_role_and_input_document_are_untouched():
    doc = document([flow("df-001", "external", "backend", "none", entity="ext-role")], access="internet-anon")
    result, changes = reconcile(doc, COMPONENTS)
    assert changes == [] and result == doc
    withdrawn = document([flow("df-001", "external", "backend", "none", entity="ext-role")])
    reconcile(withdrawn, COMPONENTS)
    assert withdrawn["external_entities"][0]["access"] == "internet-user"


def test_system_is_proven_anonymous_only_without_any_authenticated_request_hop():
    anonymous = document([flow("df-001", "external", "backend", "none", entity="ext-role")])
    assert system_proven_anonymous(anonymous, COMPONENTS)
    anonymous["data_flows"].append(flow("df-002", "external", "backend", "oidc", entity="ext-other"))
    assert not system_proven_anonymous(anonymous, COMPONENTS)
    only_unknown = document([flow("df-001", "external", "backend", "unknown", entity="ext-role")])
    assert not system_proven_anonymous(only_unknown, COMPONENTS)
    client_only = document([flow("df-001", "external", "spa", entity="ext-role", interaction=True)])
    assert not system_proven_anonymous(client_only, COMPONENTS)


DECLARATION = """\
discovery:
  enabled: true
legitimate_roles:
  - id: ext-employee
    name: Employee
    access: internet-user
    description: Staff member using the portal.
    authentication: SSO via oauth2-proxy at the ingress
  - id: ext-role
    name: Operator
    access: internet-priv-user
    description: Operates the admin console.
    authentication: VPN plus ingress basic auth
"""


def declare(tmp_path, text=DECLARATION):
    (tmp_path / ".appsec").mkdir()
    (tmp_path / ".appsec/actors.yaml").write_text(text)
    return declared_roles(tmp_path)


def test_declared_roles_cite_their_declaration_line(tmp_path):
    roles = declare(tmp_path)
    assert [(r["id"], r["access"], r["evidence"]) for r in roles] == [
        ("ext-employee", "internet-user", [{"file": ".appsec/actors.yaml", "line": 4}]),
        ("ext-role", "internet-priv-user", [{"file": ".appsec/actors.yaml", "line": 9}]),
    ]
    assert roles[0]["declared"] == {
        "source": ".appsec/actors.yaml",
        "authentication": "SSO via oauth2-proxy at the ingress",
    }


def test_no_declaration_file_declares_nothing(tmp_path):
    assert declared_roles(tmp_path) == []


@pytest.mark.parametrize(
    "role",
    [
        "  - id: ext-employee\n    name: Employee\n    access: internet-user\n    description: Staff.\n",
        "  - id: ext-x\n    name: X\n    access: superuser\n    description: X.\n",
        "  - id: Employee\n    name: X\n    access: internet-anon\n    description: X.\n",
    ],
)
def test_an_authenticated_declaration_must_say_where_the_login_happens(tmp_path, role):
    with pytest.raises(ValueError, match="invalid .appsec/actors.yaml"):
        declare(tmp_path, "legitimate_roles:\n" + role)


def test_a_declared_role_replaces_its_modelled_namesake_and_is_never_withdrawn(tmp_path):
    flows = [flow("df-001", "external", "backend", "none", entity="ext-role")]
    doc = document(flows, access="internet-anon")
    doc["external_entities"][0]["evidence"] = [{"file": "srv/app.py", "line": 3}]
    result, receipts = apply_declared(doc, declare(tmp_path))
    assert receipts == [
        {"entity_id": "ext-employee", "action": "added", "access": "internet-user"},
        {"entity_id": "ext-role", "action": "replaced", "access": "internet-priv-user"},
    ]
    role = next(e for e in result["external_entities"] if e["id"] == "ext-role")
    assert role["name"] == "Operator" and role["access"] == "internet-priv-user"
    assert role["evidence"] == [{"file": ".appsec/actors.yaml", "line": 9}, {"file": "srv/app.py", "line": 3}]
    assert doc["external_entities"][0]["access"] == "internet-anon"
    reconciled, changes = reconcile(result, COMPONENTS)
    assert changes == [] and reconciled == result
    assert not system_proven_anonymous(result, COMPONENTS)


def test_a_declared_id_cannot_take_over_a_modelled_service(tmp_path):
    doc = {"external_entities": [{"id": "ext-role", "name": "IdP", "kind": "identity-provider"}], "data_flows": []}
    with pytest.raises(ValueError, match="names a modelled identity-provider"):
        apply_declared(doc, declare(tmp_path))


def test_a_declared_anonymous_role_leaves_the_system_proven_anonymous(tmp_path):
    roles = declare(
        tmp_path,
        "legitimate_roles:\n  - id: ext-guest\n    name: Guest\n    access: internet-anon\n    description: Anyone.\n",
    )
    doc = document([flow("df-001", "external", "backend", "none", entity="ext-role")])
    result, _ = apply_declared(doc, roles)
    assert system_proven_anonymous(result, COMPONENTS)


def _handoff(tmp_path, declaration=None):
    import json

    import orchestration_controller as controller

    repo, out = tmp_path / "repo", tmp_path / "out"
    (repo / "server").mkdir(parents=True)
    out.mkdir()
    (repo / "server/app.py").write_text("app = App()\n@app.get('/items')\ndef items():\n    return load()\n")
    if declaration:
        (repo / ".appsec").mkdir()
        (repo / ".appsec/actors.yaml").write_text(declaration)
    cited = [{"file": "server/app.py", "line": 2}]
    components = [
        {"id": "api", "tier": "application", "paths": ["server/**"]},
        {"id": "db", "tier": "data", "paths": ["db/**"]},
    ]
    fingerprint = "sha256:" + "a" * 64
    (out / ".components.json").write_text(json.dumps({"components": components}))
    (out / ".component-inventory-finalization.json").write_text(
        json.dumps({"component_inventory_fingerprint": fingerprint, "component_ids": ["api", "db"]})
    )
    flows = {
        "schema_version": 1,
        "component_inventory_fingerprint": fingerprint,
        "external_entities": [
            {
                "id": "ext-visitor",
                "name": "Visitor",
                "kind": "legitimate-role",
                "access": "internet-user",
                "description": "Uses the API.",
                "evidence": cited,
            }
        ],
        "data_flows": [
            {
                "id": "df-001",
                "from": "external",
                "from_entity": "ext-visitor",
                "to": "api",
                "label": "Lists items",
                "protocol": "HTTPS",
                "data_classification": "Internal",
                "direction": "request-response",
                "evidence": cited,
                "authentication": {"scheme": "none", "scope": "The handler checks no credential", "evidence": cited},
                "provenance": "architecture",
            }
        ],
    }
    (out / ".data-flows.json").write_text(json.dumps(flows))
    controller._bind_finalized_component_fingerprint(out, repo)
    result = json.loads((out / ".data-flows.json").read_text())
    return {e["id"]: e for e in result["external_entities"]}, (out / ".agent-run.log").read_text()


def test_controller_withdraws_an_undeclared_authenticated_class_the_flows_disprove(tmp_path):
    roles, log = _handoff(tmp_path)
    assert roles["ext-visitor"]["access"] == "internet-anon" and "declared" not in roles["ext-visitor"]
    assert "ROLE_ACCESS_WITHDRAWN" in log and "entity=ext-visitor" in log


def test_controller_keeps_a_declared_login_outside_the_repository(tmp_path):
    declaration = (
        "legitimate_roles:\n"
        "  - id: ext-visitor\n"
        "    name: Employee\n"
        "    access: internet-user\n"
        "    description: Staff behind the corporate SSO proxy.\n"
        "    authentication: SSO via oauth2-proxy at the ingress\n"
    )
    roles, log = _handoff(tmp_path, declaration)
    role = roles["ext-visitor"]
    assert role["access"] == "internet-user" and role["name"] == "Employee"
    assert role["declared"]["authentication"] == "SSO via oauth2-proxy at the ingress"
    assert role["evidence"][0] == {"file": ".appsec/actors.yaml", "line": 2}
    assert "ROLE_DECLARED" in log and "ROLE_ACCESS_WITHDRAWN" not in log
