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
    # A second method of the same component names the same peer.
    duplicate = copy.deepcopy(documents[1]["interfaces"][0])
    duplicate["id"] = "second-operation"
    documents[1]["interfaces"].append(duplicate)
    assert len(architecture.reconcile(scope, documents)["candidates"]) == 1
    # The same endpoint served by a second component is an ambiguity.
    other = copy.deepcopy(documents[1]["components"][0])
    other["id"] = "second-service"
    documents[1]["components"].append(other)
    duplicate["component_id"] = "second-service"
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


@pytest.mark.parametrize(
    ("client", "server"),
    [
        # A cluster-local client address names the service a server deployment declares.
        (("http://orders.shop.svc.cluster.local:8080", None), (None, "orders")),
        # A compose service name binds both sides.
        (("http://ledger:9000", None), ("ledger:9000", None)),
    ],
)
def test_a_service_binding_joins_a_client_address_to_its_server(tmp_path, client, server):
    scope, documents = fixture(tmp_path)
    for document, (address, deployment) in zip(documents, (client, server), strict=True):
        row = document["interfaces"][0]
        row["address"], row["deployment"] = address, deployment
        quote = " ".join(value for value in (address, deployment, row["operation"]) if value)
        row["evidence"][0]["quote"] = quote
    files = [
        {row["evidence"][0]["file"]: (row["evidence"][0]["quote"] + "\n").encode()}
        for row in (d["interfaces"][0] for d in documents)
    ]
    scope = replace(
        scope, repositories=tuple(replace(r, files=f) for r, f in zip(scope.repositories, files, strict=True))
    )
    result = architecture.reconcile(scope, documents)
    assert len(result["candidates"]) == 1


def test_a_public_address_alone_is_not_a_deployment_binding(tmp_path):
    scope, documents = fixture(tmp_path)
    files = []
    for document in documents:
        row = document["interfaces"][0]
        row["address"], row["deployment"] = "https://api.example.invalid", None
        row["evidence"][0]["quote"] = f"{row['address']} {row['operation']}"
        files.append({row["evidence"][0]["file"]: (row["evidence"][0]["quote"] + "\n").encode()})
    scope = replace(
        scope, repositories=tuple(replace(r, files=f) for r, f in zip(scope.repositories, files, strict=True))
    )
    result = architecture.reconcile(scope, documents)
    assert result["candidates"] == []
    assert {r["reason"] for r in result["unresolved"]} == {"identity-not-established"}


SERVICE = "apiVersion: v1\nkind: Service\nmetadata:\n  name: {name}\n  namespace: shop\n"


@pytest.mark.parametrize(
    ("manifests", "joined"),
    [
        ({"deploy/service.yaml": SERVICE.format(name="ledger")}, True),
        ({"deploy/a.yaml": SERVICE.format(name="ledger"), "deploy/b.yaml": SERVICE.format(name="other")}, False),
        ({"deploy/service.yaml": "!!python/object/apply:os.system ['true']\n"}, False),
    ],
)
def test_a_single_declared_service_binds_the_server_route(tmp_path, manifests, joined):
    scope, documents = fixture(tmp_path)
    client, server = (d["interfaces"][0] for d in documents)
    client["address"], client["deployment"] = "http://ledger.shop.svc.cluster.local:9000", None
    server["address"], server["deployment"] = None, None
    files = []
    for row, extra in ((client, {}), (server, manifests)):
        row["evidence"][0]["quote"] = " ".join(v for v in (row["address"], row["operation"]) if v)
        files.append(
            {row["evidence"][0]["file"]: (row["evidence"][0]["quote"] + "\n").encode()}
            | {path: text.encode() for path, text in extra.items()}
        )
    scope = replace(
        scope, repositories=tuple(replace(r, files=f) for r, f in zip(scope.repositories, files, strict=True))
    )
    candidates = architecture.reconcile(scope, documents)["candidates"]
    assert bool(candidates) == joined
    if joined:
        assert candidates[0]["deployment"] == "ledger"


def _rewrite(tmp_path, documents, rows, extra=({}, {})):
    """Set (address, deployment, operation) per side and capture matching source."""
    files = []
    for document, (address, deployment, operation), more in zip(documents, rows, extra, strict=True):
        row = document["interfaces"][0]
        row["address"], row["deployment"], row["operation"] = address, deployment, operation
        row["evidence"][0]["quote"] = " ".join(v for v in (address, deployment, operation) if v) or "call"
        files.append({"config.txt": (row["evidence"][0]["quote"] + "\n").encode()} | more)
    return AssessmentScope(
        tuple(
            RepositoryView(r.repository_id, r.root, r.head, r.state_sha256, f)
            for r, f in zip(fixture(tmp_path)[0].repositories, files, strict=True)
        ),
        tmp_path / "out",
    )


@pytest.mark.parametrize("listen", ["0.0.0.0", "http://127.0.0.1:8080", "[::]:8080", "localhost"])
def test_a_listen_address_does_not_hide_the_declared_service(tmp_path, listen):
    _, documents = fixture(tmp_path)
    service = {"deploy/service.yaml": SERVICE.format(name="ledger").encode()}
    scope = _rewrite(
        tmp_path,
        documents,
        [("http://ledger:9000", None, "POST /records"), (listen, None, "POST /records")],
        ({}, service),
    )
    candidates = architecture.reconcile(scope, documents)["candidates"]
    assert [c["binding_basis"] for c in candidates] == ["service"]


def test_a_named_server_host_still_separates_peers(tmp_path):
    _, documents = fixture(tmp_path)
    service = {"deploy/service.yaml": SERVICE.format(name="ledger").encode()}
    scope = _rewrite(
        tmp_path,
        documents,
        [("http://ledger:9000", None, "POST /records"), ("http://other-host:9000", None, "POST /records")],
        ({}, service),
    )
    assert architecture.reconcile(scope, documents)["candidates"] == []


@pytest.mark.parametrize(
    ("names", "client", "dockerfile", "joined"),
    [
        (("one", "two"), "http://two:8080", "EXPOSE 8080\n", True),
        (("edge", "ledger-api"), "https://ledger-api", "EXPOSE 443/tcp\n", True),
        # Same name, another port: a coincidental host stays apart.
        (("one", "two"), "http://two:9090", "EXPOSE 8080\n", False),
        # A label without any evidenced port binds nothing.
        (("one", "two"), "http://two:8080", "", False),
        # Another selected name never binds this repository.
        (("one", "two"), "http://three:8080", "EXPOSE 8080\n", False),
    ],
)
def test_the_repository_label_binds_only_at_an_evidenced_port(tmp_path, names, client, dockerfile, joined):
    _, documents = fixture(tmp_path, names=names)
    scope = _rewrite(
        tmp_path,
        documents,
        [(client, None, "POST /records"), (None, None, "POST /records")],
        ({}, {"Dockerfile": dockerfile.encode()} if dockerfile else {}),
    )
    scope = AssessmentScope(
        tuple(replace(r, root=tmp_path / name) for r, name in zip(scope.repositories, names, strict=True)),
        scope.output,
    )
    result = architecture.reconcile(scope, documents)
    assert bool(result["candidates"]) == joined
    if joined:
        assert result["candidates"][0]["binding_basis"] == "repository-label"
        assert result["candidates"][0]["binding_evidence"]["file"] == "Dockerfile"


@pytest.mark.parametrize(
    ("compose_owner", "compose", "joined"),
    [
        # An infrastructure file in the client repository builds the peer.
        (0, "services:\n  books:\n    build: ../two\n", True),
        # The peer's own compose file builds itself.
        (1, "services:\n  books:\n    build:\n      context: .\n", True),
        # A build context outside the selection binds nothing.
        (0, "services:\n  books:\n    build: ../elsewhere\n", False),
        (0, "services:\n  books:\n    image: books:1\n", False),
    ],
)
def test_a_compose_service_binds_the_repository_it_builds(tmp_path, compose_owner, compose, joined):
    _, documents = fixture(tmp_path)
    extra = [{}, {}]
    extra[compose_owner] = {"docker-compose.yml": compose.encode()}
    scope = _rewrite(
        tmp_path, documents, [("http://books:7000", None, "POST /records"), (None, None, "POST /records")], extra
    )
    result = architecture.reconcile(scope, documents)
    assert bool(result["candidates"]) == joined
    if joined:
        assert result["candidates"][0]["binding_basis"] == "compose"


def test_a_catch_all_forwarder_reaches_its_one_bound_peer(tmp_path):
    _, documents = fixture(tmp_path)
    service = {"deploy/service.yaml": SERVICE.format(name="ledger").encode()}
    scope = _rewrite(
        tmp_path, documents, [("http://ledger:9000", None, None), (None, None, "GET /records/<id>")], ({}, service)
    )
    (candidate,) = architecture.reconcile(scope, documents)["candidates"]
    assert (candidate["operation"], candidate["operation_match"]) == ("*", "catch-all")
    # A second receiving component behind the same binding is ambiguous.
    other = copy.deepcopy(documents[1]["components"][0])
    other["id"] = "second-service"
    documents[1]["components"].append(other)
    second = copy.deepcopy(documents[1]["interfaces"][0])
    second.update(id="second-operation", component_id="second-service")
    documents[1]["interfaces"].append(second)
    result = architecture.reconcile(scope, documents)
    assert result["candidates"] == []
    assert "ambiguous-peer" in {r["reason"] for r in result["unresolved"]}


def test_only_a_forwarding_request_may_omit_its_operation(tmp_path):
    _, documents = fixture(tmp_path)
    scope = _rewrite(tmp_path, documents, [("http://ledger:9000", None, "POST /records"), (None, None, None)])
    with pytest.raises(architecture.ArchitectureError, match="forwarding"):
        architecture.reconcile(scope, documents)
