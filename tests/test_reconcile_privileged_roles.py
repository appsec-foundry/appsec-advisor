"""A confirmed privileged actor keeps its own legitimate role in the architecture model."""

import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from reconcile_privileged_roles import reconcile  # noqa: E402
from validate_fragment import (  # noqa: E402
    architecture_reference_errors,
    interaction_evidence_errors,
    repository_path_errors,
)

SCHEMA = json.loads((ROOT / "schemas/fragments/data-flows.schema.json").read_text())


def repo(tmp_path, guard):
    path = tmp_path / guard
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("export class Guard {\n  canActivate() {\n    return role === 'admin'\n  }\n}\n")
    (tmp_path / "web/index.ts").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "web/index.ts").write_text("bootstrap()\n")
    return tmp_path


def model(client="storefront", role="ext-shopper"):
    components = [
        {"id": client, "name": "Client", "tier": "client", "paths": ["web/**", "portal/**", "app/**"]},
        {"id": "backend", "name": "Backend", "tier": "application", "paths": ["srv/**"]},
    ]
    flows = {
        "schema_version": 1,
        "component_inventory_fingerprint": "sha256:" + "0" * 64,
        "external_entities": [
            {
                "id": role,
                "name": "Browser User",
                "kind": "legitimate-role",
                "access": "internet-anon",
                "description": "Anyone using the client.",
                "evidence": [{"file": "web/index.ts", "line": 1}],
            }
        ],
        "data_flows": [
            {
                "id": "df-001",
                "from": "external",
                "from_entity": role,
                "to": client,
                "label": "Uses the client",
                "protocol": "HTTPS",
                "data_classification": "Internal",
                "direction": "request-response",
                "interaction": True,
                "evidence": [{"file": "web/index.ts", "line": 1}],
                "provenance": "architecture",
            }
        ],
    }
    return components, flows


def resolved(evidence, *, confidence="high", active=True, slug="internet-priv-user"):
    return {
        "resolved_actors": [
            {"id": "ACT-D-03", "access": ["internet"], "heatmap_slug": slug, "_provenance": {"active": active}}
        ],
        "confirmed_relevant": [
            {"id": "ACT-D-03", "label": "priv", "relevance_evidence": evidence, "confidence": confidence}
        ],
    }


@pytest.mark.parametrize(
    ("guard", "client", "role"),
    [("web/guards/admin.guard.ts", "storefront", "ext-shopper"), ("portal/auth/staff_only.ts", "portal", "ext-member")],
)
def test_confirmed_privileged_actor_gains_its_own_role_and_client_interaction(tmp_path, guard, client, role):
    root = repo(tmp_path, guard)
    components, flows = model(client, role)
    result, receipt = reconcile(root, components, flows, resolved(f"section 7.2: RoleGuard at {guard}:3; see docs"))
    added = next(e for e in result["external_entities"] if e["access"] == "internet-priv-user")
    assert added["kind"] == "legitimate-role" and added["evidence"] == [{"file": guard, "line": 3}]
    use = next(f for f in result["data_flows"] if f.get("from_entity") == added["id"])
    assert use["to"] == client and use["interaction"] is True and use["id"] == "df-002"
    assert receipt == {"actor_id": "ACT-D-03", "entity_id": added["id"], "flow_id": "df-002"}
    assert not list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(result))
    assert not architecture_reference_errors({**result, "components": components})
    assert not repository_path_errors("data-flows", result, root)
    assert flows["external_entities"][0]["id"] == role and len(flows["external_entities"]) == 1


@pytest.mark.parametrize(
    ("guard", "client", "role", "on_client"),
    [
        ("srv/middleware/require_admin.ts", "storefront", "ext-shopper", False),
        ("srv/policies/staff_only.py", "portal", "ext-member", False),
        ("web/guards/admin.guard.ts", "storefront", "ext-shopper", True),
    ],
)
def test_added_interaction_cites_client_code_even_when_the_access_check_is_server_side(
    tmp_path, guard, client, role, on_client
):
    root = repo(tmp_path, guard)
    components, flows = model(client, role)
    result, _ = reconcile(root, components, flows, resolved(f"AdminCheck at {guard}:3"))
    added = next(e for e in result["external_entities"] if e["access"] == "internet-priv-user")
    use = next(f for f in result["data_flows"] if f.get("from_entity") == added["id"])
    assert added["evidence"] == [{"file": guard, "line": 3}]
    expected = [{"file": guard, "line": 3}] if on_client else flows["data_flows"][0]["evidence"]
    assert use["evidence"] == expected
    assert not interaction_evidence_errors(result["data_flows"], components)


@pytest.mark.parametrize(
    "variant",
    ["existing-role", "low-confidence", "inactive", "regular-slug", "missing-line", "no-location"],
)
def test_privileged_role_is_added_only_for_a_confirmed_evidenced_actor_without_a_role(tmp_path, variant):
    root = repo(tmp_path, "web/guards/admin.guard.ts")
    components, flows = model()
    evidence = "RoleGuard at web/guards/admin.guard.ts:3"
    kwargs = {}
    if variant == "existing-role":
        flows["external_entities"].append(
            {**flows["external_entities"][0], "id": "ext-ops", "access": "internet-priv-user"}
        )
    elif variant == "low-confidence":
        kwargs["confidence"] = "low"
    elif variant == "inactive":
        kwargs["active"] = False
    elif variant == "regular-slug":
        kwargs["slug"] = "internet-user"
    elif variant == "missing-line":
        evidence = "RoleGuard at web/guards/admin.guard.ts:99"
    else:
        evidence = "an admin area exists"
    result, receipt = reconcile(root, components, flows, resolved(evidence, **kwargs))
    assert receipt is None
    assert result == flows


def test_without_a_regular_client_interaction_only_the_role_is_added(tmp_path):
    root = repo(tmp_path, "web/guards/admin.guard.ts")
    components, flows = model()
    flows["data_flows"][0]["interaction"] = False
    result, receipt = reconcile(root, components, flows, resolved("RoleGuard at web/guards/admin.guard.ts:3"))
    assert receipt["flow_id"] is None
    assert [f["id"] for f in result["data_flows"]] == ["df-001"]
