"""Neutral candidate matching and source-provenance rejection cases."""

from __future__ import annotations

import copy
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from contexts import reconcile_multi_repo_architecture as architecture
from runtime.multi_repo_scope import AssessmentScope, RepositoryView


def fixture(tmp_path, *, protocol="HTTP", operation="POST /records", address="http://api:8080", names=("one", "two")):
    views, discoveries = [], []
    for index, name in enumerate(names):
        rid = f"repo-{index + 1:016x}"
        text = f"deployment=system-one address={address} operation={operation}"
        view = RepositoryView(rid, tmp_path / name, "a" * 40, "b" * 64, {"config.txt": (text + "\n").encode()})
        views.append(view)
        role = (
            ("publish" if index == 0 else "consume") if protocol == "Kafka" else ("request" if index == 0 else "serve")
        )
        discoveries.append(
            {
                "schema_version": 1,
                "repository_id": rid,
                "components": [
                    {
                        "id": "service",
                        "name": name,
                        "description": "Service",
                        "tier": "application",
                        "paths": ["config.txt"],
                    }
                ],
                "interfaces": [
                    {
                        "id": "operation",
                        "component_id": "service",
                        "role": role,
                        "protocol": protocol,
                        "address": address,
                        "deployment": "system-one",
                        "operation": operation,
                        "evidence": [{"file": "config.txt", "line": 1, "quote": text}],
                    }
                ],
            }
        )
    return AssessmentScope(tuple(views), tmp_path / "out"), discoveries


@pytest.mark.parametrize(
    "names,operation,address",
    [
        (("one", "two"), "POST /records", "http://api:8080"),
        (("edge-client", "ledger-service"), "PUT /ledger", "https://ledger:8443"),
    ],
)
def test_exact_matches_are_review_candidates_with_distinct_component_ownership(tmp_path, names, operation, address):
    scope, documents = fixture(tmp_path, names=names, operation=operation, address=address)
    result = architecture.reconcile(scope, documents)
    assert result == architecture.reconcile(scope, list(reversed(documents)))
    assert len(result["components"]) == 2 and len({c["id"] for c in result["components"]}) == 2
    assert len(result["candidates"]) == 1 and result["unresolved"] == []
    assert result["candidates"][0]["status"] == "requires-architecture-review"
    assert "data_flows" not in result


def test_a_topic_match_preserves_the_broker_requirement(tmp_path):
    scope, documents = fixture(tmp_path, protocol="Kafka", address="broker:9092", operation="record.created")
    result = architecture.reconcile(scope, documents)
    assert result["candidates"][0]["via"] == "message-broker"


def test_same_endpoint_in_different_deployments_does_not_join(tmp_path):
    scope, documents = fixture(tmp_path)
    doc = documents[1]
    doc["interfaces"][0]["deployment"] = "system-two"
    doc["interfaces"][0]["evidence"][0]["quote"] = doc["interfaces"][0]["evidence"][0]["quote"].replace(
        "system-one", "system-two"
    )
    changed = replace(
        scope.repositories[1], files={"config.txt": (doc["interfaces"][0]["evidence"][0]["quote"] + "\n").encode()}
    )
    scope = replace(scope, repositories=(scope.repositories[0], changed))
    result = architecture.reconcile(scope, documents)
    assert result["candidates"] == [] and len(result["unresolved"]) == 2


def test_missing_deployment_identity_and_ambiguous_peers_remain_unresolved(tmp_path):
    scope, documents = fixture(tmp_path)
    documents[0]["interfaces"][0]["deployment"] = None
    assert architecture.reconcile(scope, documents)["candidates"] == []
    documents[0]["interfaces"][0]["deployment"] = "system-one"
    duplicate = copy.deepcopy(documents[1]["interfaces"][0])
    duplicate["id"] = "second-operation"
    documents[1]["interfaces"].append(duplicate)
    result = architecture.reconcile(scope, documents)
    assert result["candidates"] == []
    assert any(r["reason"] == "ambiguous-peer" for r in result["unresolved"])


@pytest.mark.parametrize("kind", ["quote", "path", "repository", "component", "invented-identity", "duplicate"])
def test_forged_or_ambiguous_discovery_is_rejected(tmp_path, kind):
    scope, documents = fixture(tmp_path)
    row = documents[0]["interfaces"][0]
    if kind == "quote":
        row["evidence"][0]["quote"] = "this is not in the source"
    elif kind == "path":
        row["evidence"][0]["file"] = "../outside"
    elif kind == "repository":
        documents[0]["repository_id"] = "repo-ffffffffffffffff"
    elif kind == "component":
        row["component_id"] = "unknown"
    elif kind == "invented-identity":
        row["address"] = "https://invented"
    else:
        documents[0]["components"].append(copy.deepcopy(documents[0]["components"][0]))
    with pytest.raises(architecture.ArchitectureError):
        architecture.reconcile(scope, documents)


def test_missing_repository_discovery_cannot_be_published_as_complete(tmp_path):
    scope, documents = fixture(tmp_path)
    with pytest.raises(architecture.ArchitectureError, match="every selected"):
        architecture.reconcile(scope, documents[:1])
