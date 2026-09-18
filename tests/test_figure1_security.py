"""Repository-neutral authentication evidence and overview projection checks."""

import copy
import json
from pathlib import Path

import pytest
import yaml
from figure1_security import authentication_profile, flow_bundle_key, profile_catalog
from jsonschema import Draft202012Validator


def auth(scheme, **kwargs):
    return {
        "scheme": scheme,
        "scope": "This access only",
        "evidence": [{"file": "src/access.cfg", "line": 3}],
        **kwargs,
    }


@pytest.mark.parametrize("name", ["catalog-service", "sensor-hub"])
def test_missing_authentication_never_becomes_none(name):
    flow = {"to": name, "label": "Public OAuth JWT database", "protocol": "HTTPS"}
    assert authentication_profile(flow)["scheme"] == "unknown"
    flow["authentication"] = {"scheme": "none"}
    assert authentication_profile(flow)["scheme"] == "unknown"
    # Readers see a plain statement of what the analysis could not determine.
    assert authentication_profile(flow)["title"] == "Unknown"
    assert authentication_profile(flow)["description"] == "Authentication could not be determined from the code."


def test_catalog_reuses_method_not_component_name_or_evidence():
    flows = [{"authentication": auth("bearer")}, {"authentication": auth("bearer", scope="Administrative endpoint")}]
    before = copy.deepcopy(flows)
    catalog = profile_catalog(flows)
    assert len(catalog) == 1
    assert next(iter(catalog.values()))["number"] == "1"
    assert flows == before
    assert next(iter(profile_catalog([{"authentication": auth("none")}]).values()))["number"] == "0"


def test_legend_rows_differ_in_what_they_show():
    from figure1_security import SCHEMES

    flows = [
        {"authentication": auth(scheme, transport=transport, **extras)}
        for scheme in SCHEMES
        for transport in ("protected", "cleartext", "unknown")
        for extras in (
            {"factors": ["password", "totp"]} if scheme == "mfa" else {},
            {"flow": "authorization-code-pkce"} if scheme in {"oauth2", "oidc"} else {"scope": "Another method"},
        )
    ]
    shown = [(p["title"], p["description"], p["color"]) for p in profile_catalog(flows).values()]
    assert len(shown) == len(set(shown))
    only_transport_differs = [
        {"authentication": auth("bearer", transport="protected")},
        {"authentication": auth("bearer")},
    ]
    assert len(profile_catalog(only_transport_differs)) == 1


@pytest.mark.parametrize(
    "scheme,extras,color",
    [
        ("none", {}, "red"),
        ("basic", {"transport": "cleartext"}, "red"),
        ("basic", {"transport": "protected"}, "yellow"),
        ("bearer", {}, "yellow"),
        ("oauth2", {"flow": "implicit", "transport": "protected"}, "yellow"),
        ("oidc", {"flow": "authorization-code-pkce", "transport": "protected"}, "green"),
        ("mfa", {"factors": ["password", "totp"], "transport": "protected"}, "green"),
        ("private-key", {"transport": "protected"}, "green"),
        ("other", {}, "yellow"),
    ],
)
def test_strength_is_qualified_not_inferred_from_oauth_or_key_name(scheme, extras, color):
    assert authentication_profile({"authentication": auth(scheme, **extras)})["color"] == color


def test_distinct_protocols_authentication_and_interfaces_are_not_bundled():
    flow = {"from": "device", "to": "gateway", "protocol": "CustomWire-v42", "authentication": auth("bearer")}
    key = flow_bundle_key(flow)
    for change in [
        {"protocol": "gRPC"},
        {"authentication": auth("none")},
        {"interface_refs": ["management"]},
        {"direction": "bidirectional"},
    ]:
        assert flow_bundle_key({**flow, **change}) != key
    assert flow_bundle_key({**flow, "id": "df-999", "label": "Other payload"}) == key


def test_authentication_schema_matches_across_handoffs_and_rejects_false_claims():
    root = Path(__file__).resolve().parents[1]
    fragment = json.loads((root / "schemas/fragments/data-flows.schema.json").read_text())["$defs"]["data_flow"][
        "properties"
    ]
    boundary = json.loads((root / "schemas/trust-boundary-assessment-input.schema.json").read_text())["$defs"][
        "data_flow"
    ]["properties"]
    output = yaml.safe_load((root / "schemas/threat-model.output.schema.yaml").read_text())["properties"]["data_flows"][
        "items"
    ]["properties"]
    assert fragment["authentication"] == boundary["authentication"] == output["authentication"]
    assert fragment["access_group"] == boundary["access_group"] == output["access_group"]
    group_validator = Draft202012Validator(fragment["access_group"])
    assert group_validator.is_valid({"id": "login", "mode": "sequence", "label": "Sign-in", "step": 1})
    assert group_validator.is_valid({"id": "api", "mode": "alternatives", "label": "Requests"})
    assert not group_validator.is_valid({"id": "api", "mode": "sequence", "label": "Requests"})
    assert not group_validator.is_valid({"id": "api", "mode": "alternatives", "label": "Requests", "step": 1})
    validator = Draft202012Validator(fragment["authentication"])
    assert validator.is_valid(auth("mfa", factors=["password", "totp"]))
    assert validator.is_valid(auth("mfa", factors=["biometric", "webauthn"]))
    assert not validator.is_valid(auth("mfa", factors=["totp", "push"]))
    assert authentication_profile({"authentication": auth("mfa", factors=["totp", "push"])})["scheme"] == "unknown"
    for invalid in [
        auth("mfa"),
        auth("mfa", factors=["password", "password"]),
        auth("bearer", flow="implicit"),
        auth("none", evidence=[]),
        auth("basic", evidence=[{"file": "../outside", "line": 1}]),
    ]:
        assert not validator.is_valid(invalid)


def test_authentication_evidence_is_checked_against_repository(tmp_path):
    from validate_fragment import repository_path_errors

    flow = {"id": "df-001", "authentication": auth("none")}
    errors = repository_path_errors("data-flows", {"data_flows": [flow]}, tmp_path)
    assert errors and any("authentication" in error for error in errors)


@pytest.mark.parametrize("receiver", ["catalog-gateway", "sensor-controller"])
def test_access_groups_reject_ambiguous_or_unevidenced_relationships(receiver):
    from figure1_security import access_groups
    from validate_fragment import architecture_reference_errors

    flows = [
        {
            "id": f"df-{i:03d}",
            "from": "console",
            "to": receiver,
            "protocol": "CustomWire",
            "authentication": auth(
                "password" if i == 1 else "mfa", **({"factors": ["password", "totp"]} if i == 2 else {})
            ),
            "access_group": {"id": "login", "mode": "sequence", "label": "Sign-in (MFA if enrolled)", "step": i},
        }
        for i in (1, 2)
    ]
    before = copy.deepcopy(flows)
    assert access_groups(flows)[1] == []
    assert architecture_reference_errors({"data_flows": flows}) == []
    for change in [
        {"from": "different-console"},
        {"to": "different-receiver"},
        {"protocol": "OtherWire"},
        {"direction": "bidirectional"},
        {"authentication": auth("mfa", factors=["totp", "push"])},
        {"authentication": auth("password", evidence=[])},
        {"interaction": True},
        {"protocol_group": "SSO"},
        {"access_group": {"id": "login", "mode": "sequence", "label": "Other", "step": 2}},
        {"access_group": {"id": "login", "mode": "sequence", "label": "Sign-in (MFA if enrolled)", "step": 1}},
    ]:
        changed = [flows[0], {**flows[1], **change}]
        assert not access_groups(changed)[0]
        assert any("access_group" in err for err in architecture_reference_errors({"data_flows": changed}))
    assert access_groups(flows[:1])[1]
    assert flows == before


@pytest.mark.parametrize("client", ["operator-console", "handheld-ui"])
def test_human_interaction_is_not_an_api_or_provider_exchange(client):
    from validate_fragment import architecture_reference_errors

    flow = {"id": "df-001", "from": "external", "from_entity": "ext-reader", "to": client, "interaction": True}
    model = {
        "components": [{"id": client, "tier": "client"}, {"id": "service", "tier": "application"}],
        "external_entities": [
            {"id": "ext-reader", "kind": "legitimate-role"},
            {"id": "ext-provider", "kind": "identity-provider"},
        ],
        "data_flows": [flow],
    }
    assert architecture_reference_errors(model) == []
    assert profile_catalog([flow]) == {}
    for change in [
        {"from_entity": "ext-provider"},
        {"from_entity": None},
        {"to": "service"},
        {"authentication": auth("bearer")},
        {"from": "service"},
    ]:
        assert architecture_reference_errors({**model, "data_flows": [{**flow, **change}]})
    # Actual authenticated service access must retain its authentication marker.
    api = {**flow, "interaction": False, "to": "service", "authentication": auth("bearer")}
    assert architecture_reference_errors({**model, "data_flows": [api]}) == []
    assert next(iter(profile_catalog([api]).values()))["scheme"] == "bearer"


@pytest.mark.parametrize(
    "client_paths,client_file,server_file",
    [
        (["console/**"], "console/src/app.tsx", "gateway/static.js"),
        (["mobile/app/"], "mobile/app/main.dart", "server/serve.py"),
    ],
)
def test_human_interaction_cites_the_client_it_uses(client_paths, client_file, server_file):
    from validate_fragment import fragment_invariant_errors, interaction_evidence_errors

    components = [
        {"id": "ui", "tier": "client", "paths": client_paths},
        {"id": "service", "tier": "application", "paths": [server_file]},
    ]
    entities = [{"id": "ext-reader", "kind": "legitimate-role"}]
    flow = {"id": "df-001", "from": "external", "from_entity": "ext-reader", "to": "ui", "interaction": True}
    used = {**flow, "evidence": [{"file": client_file, "line": 3}]}
    assert interaction_evidence_errors([used], components) == []
    # Serving the client's bundle is the server's flow to the client, not the person's use of it.
    served = {**flow, "evidence": [{"file": server_file, "line": 14}]}
    errors = interaction_evidence_errors([served], components)
    assert errors and server_file in errors[0] and "its own flow" in errors[0]
    # The architecture self-check reports the same rule when it holds the component inventory.
    fragment = {"external_entities": entities, "data_flows": [served]}
    assert errors[0] in fragment_invariant_errors("data-flows", fragment, context={"components": components})
    delivery = {"id": "df-002", "from": "service", "to": "ui", "evidence": [{"file": server_file, "line": 14}]}
    assert interaction_evidence_errors([used, delivery], components) == []
    # A client that declares no paths cannot be checked, so its evidence is not rejected.
    assert interaction_evidence_errors([served], [{"id": "ui", "tier": "client"}, components[1]]) == []


@pytest.mark.parametrize("group", ["federation-session", "device-handshake"])
def test_reference_selection_keeps_security_relevant_connections(group):
    from figure1_security import select_references

    nodes = {
        "browser": {"zone": "client", "h": 100},
        "identity": {"zone": "third-party", "h": 50},
        "archive": {"zone": "data", "h": 100},
    }
    model = {"data_flows": [{"id": "df-001", "protocol_group": group}, {"id": "df-002", "protocol_group": group}]}
    profile = authentication_profile({})
    edges = [
        {"src": "browser", "dst": "identity", "ids": [f"df-{i:03d}"], "tb": [], "authentication": profile}
        for i in (1, 2)
    ]
    drawn, refs = select_references(model, copy.deepcopy(nodes), edges, {})
    assert drawn == [] and refs[0]["ids"] == ["df-001", "df-002"]
    model["data_flows"][0]["threats"] = ["T-001"]
    assert select_references(model, copy.deepcopy(nodes), edges, {})[0] == edges
    model["data_flows"][0].pop("threats")
    edges[0]["tb"] = ["tb-1"]
    assert select_references(model, copy.deepcopy(nodes), edges, {"tb-1": 1})[0] == edges
    edges[0]["tb"] = []
    for edge in edges:
        edge["dst"] = "archive"
    assert select_references(model, copy.deepcopy(nodes), edges, {})[0] == edges


@pytest.mark.parametrize("bidirectional", [False, True])
def test_reference_directions_preserve_exchange_without_spreading_receiving_auth(bidirectional):
    from figure1_security import select_references

    nodes = {"console": {"zone": "client"}, "identity": {"zone": "third-party"}}
    model = {"data_flows": [{"id": f"df-{i:03d}", "protocol_group": "Login exchange"} for i in (1, 2)]}
    key = authentication_profile({"authentication": auth("bearer")})
    edges = [
        {
            "src": "console",
            "dst": "identity",
            "ids": [f"df-{i:03d}"],
            "tb": [],
            "bidi": bidirectional,
            "authentication": key,
        }
        for i in (1, 2)
    ]
    retained, refs = select_references(model, nodes, edges, {})
    assert retained == [] and len(refs) == 1
    client, provider = nodes["console"]["references"][0], nodes["identity"]["references"][0]
    assert client["peer"] == "identity" and provider["peer"] == "console"
    assert client["direction"] == ("↔" if bidirectional else "→")
    assert provider["direction"] == ("↔" if bidirectional else "←")
    assert client["profiles"] == []
    assert provider["profiles"] == [key["key"]]
