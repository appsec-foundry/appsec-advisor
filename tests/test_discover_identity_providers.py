"""Source-to-diagram coverage for generic external identity integrations."""

import copy
import json
from pathlib import Path

import discover_identity_providers as discovery
import figure1_dfd
import jsonschema
import orchestration_controller as controller
import pytest
from build_trust_boundary_assessment_input import _semantic_flow_validation
from validate_fragment import repository_path_errors


def _write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _components():
    return [
        {
            "id": "client",
            "name": "Web client",
            "tier": "client",
            "paths": ["src/**", "config/**"],
            "deployment_zones": ["client-device"],
        }
    ]


def _flows():
    return {"schema_version": 1, "component_inventory_fingerprint": "sha256:" + "a" * 64, "data_flows": []}


@pytest.mark.parametrize(
    "rel,source,role",
    [
        (
            "src/login.ts",
            'const issuerUrl = "https://id.example/oauth2/authorize";\nwindow.location.assign(`${issuerUrl}?client_id=${clientId}`);',
            "OAuth authorization",
        ),
        ("src/login.js", 'fetch("https://identity.example/oauth/token", {method:"POST"});', "OAuth token exchange"),
        ("src/profile.py", 'requests.get("https://identity.example/oidc/userinfo")', "OAuth profile request"),
        ("src/client.ts", 'new UserManager({authority: "https://login.example/realms/staff"});', "OIDC discovery"),
        (
            "src/client.py",
            'oauth.register(server_metadata_url="https://identity.example/.well-known/openid-configuration")',
            "OIDC discovery",
        ),
        ("src/client.ts", 'Issuer.discover("https://identity.example")', "OIDC discovery"),
        ("src/sso.js", 'new SAMLStrategy({entryPoint: "https://sso.example/signin"});', "SAML sign-in"),
        ("config/sso.yaml", "saml:\n  enabled: true\n  entryPoint: https://sso.example/signin\n", "SAML sign-in"),
        ("config/auth.json", '{"oidc":{"authority":"https://id.example"}}', "OIDC discovery"),
        (
            "config/application.yaml",
            "spring:\n  security:\n    oauth2:\n      client:\n        provider:\n          staff:\n            issuer-uri: https://sso.example/realms/staff\n",
            "OIDC discovery",
        ),
        (
            "config/application.properties",
            "spring.security.oauth2.client.provider.staff.issuer-uri=https://sso.example/realms/staff",
            "OIDC discovery",
        ),
        (
            "config/application.properties",
            "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://sso.example/realms/staff",
            "OIDC discovery",
        ),
        (
            "config/application.yaml",
            "spring.security.oauth2.resourceserver.jwt.issuer-uri: https://sso.example/realms/staff\n",
            "OIDC discovery",
        ),
    ],
)
def test_client_integrations_are_generic_and_evidenced(tmp_path, rel, source, role):
    _write(tmp_path, rel, source)
    candidates = discovery.discover(tmp_path)
    assert len(candidates) == 1
    assert candidates[0].role == role
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert len(result["external_entities"]) == len(result["data_flows"]) == 1
    assert result["data_flows"][0]["from"] == "client"
    assert result["data_flows"][0]["to"] == "external"
    assert repository_path_errors("data-flows", result, tmp_path) == []
    schema = json.loads((Path(__file__).parents[1] / "schemas/fragments/data-flows.schema.json").read_text())
    jsonschema.validate(result, schema)
    assert discovery.reconcile(tmp_path, _components(), result) == result


@pytest.mark.parametrize(
    "rel,source",
    [
        ("docs/oauth.md", 'fetch("https://id.example/oauth/token")'),
        ("src/login.spec.ts", 'fetch("https://id.example/oauth/token")'),
        ("examples/login.ts", 'fetch("https://id.example/oauth/token")'),
        ("src/login.ts", '// fetch("https://id.example/oauth/token")'),
        ("src/login.py", '# requests.get("https://id.example/oauth/token")'),
        ("src/login.py", '"""requests.get("https://id.example/oauth/token")"""'),
        ("src/login.ts", "const docs = 'fetch(\"https://id.example/oauth/token\")';"),
        ("src/login.ts", 'const unused = "https://id.example/oauth/token"; console.log(unused);'),
        ("src/login.ts", 'import OAuth2 from "oauth2";'),
        ("src/login.ts", 'const url = "https://id.example/oauth/token"; url = localUrl; fetch(url);'),
        ("src/login.ts", 'const value = mapping.get("https://id.example/oauth/token");'),
        ("src/login.ts", 'text.replace("https://id.example/oauth/token", "");'),
        ("src/server.ts", 'app.get("/oauth/authorize", handler);'),
        ("config/server.yaml", "oauth:\n  server:\n    issuer: https://our-server.example\n"),
        ("config/client.yaml", "oidc:\n  enabled: false\n  authority: https://id.example\n"),
        ("config/client.yaml", "application:\n  url: https://id.example/oauth/token\n"),
        ("config/client.json", '{"dependencies":{"openid-client":"1"}}'),
        ("src/login.ts", "fetch(process.env.OIDC_ENDPOINT);"),
        ("src/login.ts", 'fetch("https://user:password@id.example/oauth/token");'),
    ],
)
def test_non_integrations_are_not_promoted(tmp_path, rel, source):
    _write(tmp_path, rel, source)
    assert discovery.discover(tmp_path) == []
    assert discovery.reconcile(tmp_path, _components(), _flows()) == _flows()


def test_multiple_providers_and_realms_are_not_merged(tmp_path):
    _write(
        tmp_path,
        "config/clients.json",
        json.dumps(
            {
                "oidc": {
                    "first": {"issuer": "https://id.example/realms/first"},
                    "second": {"issuer": "https://id.example/realms/second"},
                    "third": {"issuer": "https://other.example"},
                }
            }
        ),
    )
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert len(result["external_entities"]) == 3
    assert len(result["data_flows"]) == 3
    assert len({f["to_entity"] for f in result["data_flows"]}) == 3


def test_arbitrary_oidc_issuer_paths_are_distinct(tmp_path):
    _write(
        tmp_path,
        "config/clients.json",
        json.dumps(
            {
                "oidc": {
                    "first": {"issuer": "https://id.example/organization-a"},
                    "second": {"issuer": "https://id.example/organization-b"},
                }
            }
        ),
    )
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert len(result["external_entities"]) == 2
    assert discovery.reconcile(tmp_path, _components(), result) == result


def test_saml_nested_endpoint_and_metadata_are_not_called_oidc(tmp_path):
    _write(
        tmp_path,
        "config/sso.json",
        json.dumps(
            {
                "saml": {
                    "idp": {
                        "metadataUrl": "https://sso.example/metadata",
                        "singleSignOnService": {"url": "https://sso.example/signin"},
                    }
                }
            }
        ),
    )
    assert {c.role for c in discovery.discover(tmp_path)} == {"SAML sign-in", "SAML metadata"}
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert len(result["external_entities"]) == 1
    assert {f["label"] for f in result["data_flows"]} == {"Configured SAML sign-in", "Configured SAML metadata"}
    assert discovery.reconcile(tmp_path, _components(), result) == result


def test_reuses_authored_provider_with_unique_source_evidence(tmp_path):
    _write(tmp_path, "src/login.ts", 'fetch("https://id.example/oauth/token");')
    doc = _flows()
    doc["external_entities"] = [
        {
            "id": "ext-staff",
            "kind": "identity-provider",
            "name": "Staff sign-in",
            "description": "Company identity service",
            "evidence": [{"file": "src/login.ts", "line": 1}],
        }
    ]
    result = discovery.reconcile(tmp_path, _components(), doc)
    assert result["external_entities"] == doc["external_entities"]
    assert result["data_flows"][0]["to_entity"] == "ext-staff"


def test_ambiguous_owner_is_not_arbitrarily_chosen(tmp_path):
    _write(tmp_path, "src/auth.ts", 'fetch("https://id.example/oauth/token");')
    with pytest.raises(ValueError, match="unique component owner"):
        discovery.reconcile(tmp_path, _components() + [{"id": "other", "paths": ["src/**"]}], _flows())


def test_browser_navigation_uses_client_despite_narrower_functional_auth_paths(tmp_path):
    _write(tmp_path, "src/login.ts", 'window.location.assign("https://id.example/oauth/authorize");')
    components = _components() + [{"id": "auth-service", "tier": "application", "paths": ["src/login.ts"]}]
    result = discovery.reconcile(tmp_path, components, _flows())
    assert result["data_flows"][0]["from"] == "client"
    assert discovery.reconcile(tmp_path, components, result) == result


def test_browser_navigation_without_matching_client_fails_instead_of_inventing_server_flow(tmp_path):
    _write(tmp_path, "src/login.ts", 'window.location.assign("https://id.example/oauth/authorize");')
    with pytest.raises(ValueError, match="unique component owner"):
        discovery.reconcile(tmp_path, [{"id": "backend", "tier": "application", "paths": ["src/**"]}], _flows())


def test_saml_sdk_metadata_is_not_oidc_discovery(tmp_path):
    _write(tmp_path, "src/sso.ts", 'new SAMLStrategy({metadataUrl: "https://sso.example/metadata"});')
    assert discovery.discover(tmp_path)[0].role == "SAML metadata"


def test_entity_id_collision_does_not_reclassify_a_user_role(tmp_path):
    _write(tmp_path, "src/auth.ts", 'fetch("https://id.example/oauth/token");')
    result = discovery.reconcile(tmp_path, _components(), _flows())
    result["external_entities"][0]["kind"] = "legitimate-role"
    with pytest.raises(ValueError, match="collides"):
        discovery.reconcile(tmp_path, _components(), result)


def test_reconciles_existing_generic_flow_without_duplicate(tmp_path):
    _write(tmp_path, "src/login.ts", 'fetch("https://id.example/oauth/token");')
    doc = _flows()
    doc["data_flows"] = [
        {"id": "df-009", "from": "client", "to": "external", "evidence": [{"file": "src/login.ts", "line": 1}]}
    ]
    result = discovery.reconcile(tmp_path, _components(), doc)
    assert len(result["data_flows"]) == 1
    assert result["data_flows"][0]["id"] == "df-009"
    assert result["data_flows"][0]["to_entity"] == result["external_entities"][0]["id"]


def test_respects_evidenced_internal_identity_server(tmp_path):
    _write(tmp_path, "src/login.ts", 'fetch("https://id.example/oauth/token");')
    doc = _flows()
    doc["data_flows"] = [
        {"id": "df-009", "from": "client", "to": "identity-server", "evidence": [{"file": "src/login.ts", "line": 1}]}
    ]
    result = discovery.reconcile(tmp_path, _components() + [{"id": "identity-server", "paths": ["identity/**"]}], doc)
    assert result.get("external_entities", []) == []
    assert result["data_flows"] == doc["data_flows"]


def test_unowned_integration_fails_without_mutating_input(tmp_path):
    _write(tmp_path, "elsewhere/auth.ts", 'fetch("https://id.example/oauth/token");')
    original = _flows()
    with pytest.raises(ValueError, match="unique component owner"):
        discovery.reconcile(tmp_path, _components(), original)
    assert original == _flows()


def test_specific_component_path_wins_over_broad_application_path(tmp_path):
    _write(tmp_path, "src/client/auth.ts", 'fetch("https://id.example/oauth/token");')
    components = _components() + [{"id": "browser", "paths": ["src/client/**"]}]
    result = discovery.reconcile(tmp_path, components, _flows())
    assert result["data_flows"][0]["from"] == "browser"


def test_does_not_read_escaping_symlinks_or_oversize_files(tmp_path, monkeypatch):
    outside = _write(tmp_path, "outside.ts", 'fetch("https://id.example/oauth/token");')
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src/link.ts").symlink_to(outside)
    monkeypatch.setattr(discovery, "MAX_FILE_BYTES", 30)
    _write(repo, "src/large.ts", outside.read_text())
    assert discovery.discover(repo) == []


def test_scan_budget_fails_explicitly(tmp_path, monkeypatch):
    _write(tmp_path, "src/auth.ts", 'fetch("https://id.example/oauth/token");')
    monkeypatch.setattr(discovery, "MAX_BYTES", 1)
    with pytest.raises(ValueError, match="source budget"):
        discovery.discover(tmp_path)


def test_query_credentials_are_not_copied_to_model(tmp_path):
    _write(tmp_path, "src/auth.ts", 'fetch("https://id.example/oauth/token?client_secret=must-not-leak");')
    result = discovery.reconcile(tmp_path, _components(), _flows())
    assert "must-not-leak" not in json.dumps(result)


def test_controller_handoff_reaches_boundary_input_and_svg(tmp_path):
    repo, out = tmp_path / "repo", tmp_path / "out"
    _write(
        repo, "src/login.ts", 'const endpoint="https://id.example/oauth2/authorize";\nwindow.location.assign(endpoint);'
    )
    out.mkdir()
    components = _components()
    receipt = {"component_inventory_fingerprint": "sha256:" + "a" * 64, "component_ids": ["client"]}
    (out / ".components.json").write_text(json.dumps({"components": components}))
    (out / ".component-inventory-finalization.json").write_text(json.dumps(receipt))
    (out / ".data-flows.json").write_text(json.dumps(_flows()))
    controller._bind_finalized_component_fingerprint(out, repo)
    doc = json.loads((out / ".data-flows.json").read_text())
    _semantic_flow_validation(doc, receipt)
    model = {**doc, "components": components}
    svg, state = figure1_dfd._build(model, [], [])
    assert "id.example" in svg
    entity = doc["external_entities"][0]["id"]
    assert state["nodes"][entity]["col"] == 0
    assert any(edge["src"] == "client" and edge["dst"] == entity for edge in state["edges"])
    assert not any(edge["src"] == "identity-server" for edge in state["edges"])


def test_controller_does_not_publish_invalid_enrichment(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    for name, value in [
        (".components.json", {"components": _components()}),
        (".component-inventory-finalization.json", {"component_inventory_fingerprint": "sha256:" + "a" * 64}),
        (".data-flows.json", _flows()),
    ]:
        (out / name).write_text(json.dumps(value))
    previous = (out / ".data-flows.json").read_bytes()
    invalid = copy.deepcopy(_flows())
    invalid["external_entities"] = [{"id": "ext-invalid"}]
    monkeypatch.setattr(discovery, "reconcile", lambda *_: invalid)
    with pytest.raises(controller.ControllerError, match="schema validation"):
        controller._bind_finalized_component_fingerprint(out, tmp_path)
    assert (out / ".data-flows.json").read_bytes() == previous
