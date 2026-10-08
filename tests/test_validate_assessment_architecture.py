"""Qualified component handoffs retain existing reconciliation and source gates."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from model.finalize_component_inventory import finalize_assessment
from runtime.multi_repo_scope import ScopeError, admit
from validators import validate_assessment_architecture as validation


def fixture(tmp_path, *, names=("north", "south"), store=False, source="value = 1\n"):
    roots = []
    for index, name in enumerate(names):
        root = tmp_path / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "initial",
            ],
            check=True,
        )
        text = source
        if index == 1 and store:
            # Exercise an existing reconciliation detector, without installing
            # or executing the fixture's declared dependency.
            (root / "package.json").write_text(json.dumps({"dependencies": {"nedb": "1.8.0"}}))
            (root / "src").mkdir()
            (root / "src/store.js").write_text("const Cache = require('nedb')\nconst records = new Cache()\n")
        (root / "app.py").write_text(text)
        roots.append(str(root))
    scope = admit(roots, str(tmp_path / "out"))
    documents = [
        {
            "schema_version": 1,
            "repository_id": r.repository_id,
            "components": [
                {
                    "id": "application",
                    "name": "Application",
                    "description": "Application process",
                    "paths": ["app.py"],
                    "tier": "application",
                }
            ],
            "interfaces": [],
        }
        for r in scope.repositories
    ]
    return scope, documents


@pytest.mark.parametrize("names", [("north", "south"), ("service-red", "service-blue")])
def test_existing_finalization_namespaces_identical_local_ids_and_paths(tmp_path, names):
    scope, documents = fixture(tmp_path, names=names)
    result, receipt = finalize_assessment(scope, documents)
    validation.validate_finalization(scope, result, receipt)
    assert len(result["components"]) == 2
    assert len(set(receipt["component_ids"])) == 2
    assert {c["paths"][0]["repository_id"] for c in result["components"]} == {
        r.repository_id for r in scope.repositories
    }
    assert all(c["language"] == "Python" for c in result["components"])
    assert (result, receipt) == finalize_assessment(scope, list(reversed(documents)))
    assert not scope.output.exists()
    assert str(tmp_path) not in json.dumps(result)


def test_reconciled_embedded_store_stays_with_its_own_repository(tmp_path):
    scope, documents = fixture(tmp_path, store=True)
    result, receipt = finalize_assessment(scope, documents)
    validation.validate_finalization(scope, result, receipt)
    stores = [c for c in result["components"] if c["tier"] == "data"]
    assert len(stores) == 1 and stores[0]["framework"] == "nedb"
    assert stores[0]["repository_ids"] == [scope.repositories[1].repository_id]
    assert receipt["injected_component_ids"] == [stores[0]["id"]]


@pytest.mark.parametrize("kind", ["scope", "hash", "repository", "escape", "ownership", "missing-repo", "duplicate"])
def test_invalid_combined_inventory_fails_before_consumption(tmp_path, kind):
    scope, documents = fixture(tmp_path)
    result, receipt = finalize_assessment(scope, documents)
    source = result["components"][0]["paths"][0]
    if kind == "scope":
        result["source_scope_sha256"] = "0" * 64
    elif kind == "hash":
        source["sha256"] = "0" * 64
    elif kind == "repository":
        source["repository_id"] = "repo-ffffffffffffffff"
    elif kind == "escape":
        source["path"] = "../app.py"
    elif kind == "ownership":
        result["components"][0]["repository_ids"] = ["repo-ffffffffffffffff"]
    elif kind == "missing-repo":
        result["components"].pop()
    else:
        result["components"].append(copy.deepcopy(result["components"][0]))
    with pytest.raises(validation.AssessmentArchitectureError):
        validation.validate_finalization(scope, result, receipt)


def test_changed_source_prevents_finalization_and_legacy_readers_reject_v2(tmp_path):
    scope, documents = fixture(tmp_path)
    result, receipt = finalize_assessment(scope, documents)
    for path, document in [
        ("fragments/components.schema.json", result),
        ("component-inventory-finalization.schema.json", receipt),
    ]:
        schema = json.loads((validation.ROOT / "schemas" / path).read_text())
        assert not Draft202012Validator(schema).is_valid(document)
    (scope.repositories[-1].root / "app.py").write_text("changed = True\n")
    with pytest.raises(ScopeError, match="changed"):
        finalize_assessment(scope, documents)


def test_receipt_detects_path_ownership_change_even_when_file_bytes_match(tmp_path):
    scope, documents = fixture(tmp_path)
    result, receipt = finalize_assessment(scope, documents)
    # Both repositories contain app.py with identical bytes. Swapping only the
    # ownership is nevertheless a changed component identity binding.
    a, b = result["components"]
    a["paths"], b["paths"] = b["paths"], a["paths"]
    a["repository_ids"], b["repository_ids"] = b["repository_ids"], a["repository_ids"]
    with pytest.raises(validation.AssessmentArchitectureError, match="changed after"):
        validation.validate_finalization(scope, result, receipt)


def test_source_reference_budget_applies_across_repositories(tmp_path, monkeypatch):
    scope, discoveries = fixture(tmp_path)
    monkeypatch.setattr(validation, "MAX_SOURCE_REFERENCES", 1)
    with pytest.raises(ValueError, match="source-reference limit"):
        finalize_assessment(scope, discoveries)
    assert not scope.output.exists()


def test_fragment_entry_point_requires_admitted_scope_and_preserves_input(tmp_path):
    from validators.validate_fragment import validate

    scope, discoveries = fixture(tmp_path)
    components, receipt = finalize_assessment(scope, discoveries)
    path = tmp_path / "components.json"
    path.write_text(json.dumps(components))
    original = path.read_bytes()
    assert validate("components-v2", path) == 1
    assert validate("components-v2", path, assessment_scope=scope.inventory()) == 1
    assert validate("components-v2", path, assessment_scope=scope, repo_root=tmp_path) == 1
    assert validate("components-v2", path, assessment_scope=scope) == 0
    assert validate("components", path) == 1
    assert path.read_bytes() == original

    flows = tmp_path / "flows.json"
    flows.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "source_scope_sha256": components["source_scope_sha256"],
                "component_inventory_fingerprint": receipt["component_inventory_fingerprint"],
                "data_flows": [],
            }
        )
    )
    assert validate("data-flows-v2", flows, assessment_scope=scope) == 1
    assert (
        validate("data-flows-v2", flows, assessment_scope=scope, context_path=path, finalization_receipt=receipt) == 0
    )
    (scope.repositories[0].root / "app.py").write_text("changed = True\n")
    assert validate("components-v2", path, assessment_scope=scope) == 1


@pytest.mark.parametrize("endpoint,denied", [("oidc/userinfo", True), ("public/info", False)])
def test_qualified_flows_preserve_provider_authentication_guard(tmp_path, endpoint, denied):
    scope, discoveries = fixture(tmp_path, source=f'requests.get("https://identity.example/{endpoint}")\n')
    components, receipt = finalize_assessment(scope, discoveries)
    component = components["components"][0]
    source = component["paths"][0]
    evidence = [
        {"repository_id": source["repository_id"], "file": source["path"], "sha256": source["sha256"], "line": 1}
    ]
    flows = {
        "schema_version": 2,
        "source_scope_sha256": components["source_scope_sha256"],
        "component_inventory_fingerprint": receipt["component_inventory_fingerprint"],
        "external_entities": [
            {
                "id": "ext-provider",
                "name": "Provider",
                "kind": "external-service",
                "description": "Remote provider",
                "evidence": evidence,
            }
        ],
        "data_flows": [
            {
                "id": "df-001",
                "from": component["id"],
                "to": "external",
                "to_entity": "ext-provider",
                "label": "Provider request",
                "protocol": "HTTPS",
                "data_classification": "unknown",
                "direction": "unidirectional",
                "provenance": "architecture",
                "evidence": evidence,
                "authentication": {"scheme": "none", "scope": "Provider request", "evidence": evidence},
            }
        ],
    }
    if denied:
        with pytest.raises(validation.AssessmentArchitectureError, match="repository evidence"):
            validation.validate_flows(scope, components, receipt, flows)
    else:
        validation.validate_flows(scope, components, receipt, flows)
