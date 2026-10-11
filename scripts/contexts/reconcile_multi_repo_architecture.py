"""Validate repository-local observations and identify candidate connections.

This is a candidate producer, not an architecture publication gate. Exact
source quotations establish provenance, not the truth of an observation's
semantics. A matched candidate still needs architecture review before it can
become a canonical data flow or contribute to a confirmed attack route.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from runtime.multi_repo_scope import AssessmentScope, ScopeError

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "multi-repo-discovery.schema.json"
OUTPUT_SCHEMA = SCHEMA.with_name("multi-repo-connections.schema.json")


class ArchitectureError(ValueError):
    """Observations cannot be reconciled without losing scope or evidence."""


def _id(kind: str, *parts: str) -> str:
    return kind + "-" + hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()[:16]


def validate_discovery(scope: AssessmentScope, expected_repository: str, document: dict) -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    if not Draft202012Validator(schema).is_valid(document):
        raise ArchitectureError("Discovery violates its schema")
    if document["repository_id"] != expected_repository:
        raise ArchitectureError("Discovery cannot select another repository")
    repository = next((r for r in scope.repositories if r.repository_id == expected_repository), None)
    if repository is None:
        raise ArchitectureError("Discovery repository is outside the admitted scope")
    components = {row["id"]: row for row in document["components"]}
    if len(components) != len(document["components"]):
        raise ArchitectureError("Duplicate local component identity")
    for component in components.values():
        if not set(component["paths"]) <= repository.files.keys():
            raise ArchitectureError("Component refers to uncaptured source")
    interface_ids: set[str] = set()
    for interface in document["interfaces"]:
        if interface["id"] in interface_ids or interface["component_id"] not in components:
            raise ArchitectureError("Duplicate interface or unknown component")
        interface_ids.add(interface["id"])
        if (interface["role"] in {"publish", "consume"}) != (interface["protocol"] in {"AMQP", "Kafka"}):
            raise ArchitectureError("Interface role and protocol disagree")
        quotes = []
        for reference in interface["evidence"]:
            try:
                piece = scope.read(expected_repository, reference["file"], reference["line"], reference["line"])
            except ScopeError:
                raise ArchitectureError("Interface cites uncaptured source") from None
            if reference["quote"] not in piece["lines"][0]:
                raise ArchitectureError("Interface quotation does not match its source")
            quotes.append(reference["quote"])
        # Identity strings without source support cannot manufacture a match.
        for key in ("address", "deployment", "operation"):
            value = interface[key]
            if value is not None and not any(value in quote for quote in quotes):
                raise ArchitectureError("Interface identity is not present in cited evidence")


_PROTOCOL_FAMILY = {"HTTPS": "HTTP", "HTTP": "HTTP", "gRPC": "gRPC", "AMQP": "AMQP", "Kafka": "Kafka"}
_MESSAGING = {"AMQP", "Kafka"}


def _operation(value: str) -> str:
    """Compare operations without a query string or trailing separator."""
    return value.split("?", 1)[0].rstrip("/") or value


def _endpoint(row: dict) -> tuple[str | None, str | None]:
    """The deployment binding and host an interface's cited identity establishes.

    The host is the address without scheme, credentials, path or virtual host.
    The binding is the declared deployment, else the service a cluster-local
    (``<service>.<namespace>.svc``) or single-label host names. A public host
    alone is not a binding: equal addresses in separate deployments stay apart.
    """
    host = None
    binding = row["deployment"].lower() if row.get("deployment") else None
    if row.get("address"):
        rest = row["address"].split("://", 1)[-1].rsplit("@", 1)[-1]
        host = rest.split("/", 1)[0].lower() or None
        name = host.split(":", 1)[0] if host else ""
        labels = name.split(".")
        if binding is None and name and (len(labels) == 1 or (len(labels) >= 3 and labels[2] == "svc")):
            binding = labels[0]
    return binding, host


_MANIFEST_SUFFIXES = (".yaml", ".yml")
_MAX_MANIFEST_BYTES = 262_144


def deployment_binding(scope: AssessmentScope, repository_id: str) -> dict | None:
    """The one Kubernetes Service a repository declares, as a deployment binding.

    Manifests are parsed as data from the captured bytes; executable YAML tags
    are rejected by the safe loader. Zero or several Services bind nothing.
    """
    import yaml

    repo = next(r for r in scope.repositories if r.repository_id == repository_id)
    found = []
    for path, data in sorted(repo.files.items()):
        if not path.endswith(_MANIFEST_SUFFIXES) or len(data) > _MAX_MANIFEST_BYTES:
            continue
        try:
            documents = list(yaml.safe_load_all(data.decode("utf-8")))
        except (UnicodeDecodeError, yaml.YAMLError):
            continue
        for document in documents:
            if isinstance(document, dict) and document.get("kind") == "Service":
                name = (document.get("metadata") or {}).get("name")
                if isinstance(name, str) and name.strip():
                    text = data.decode("utf-8").splitlines()
                    line = next((n for n, value in enumerate(text, 1) if "name:" in value and name in value), 1)
                    found.append({"repository_id": repository_id, "file": path, "line": line, "service": name.lower()})
    return found[0] if len(found) == 1 else None


def reconcile(scope: AssessmentScope, discoveries: list[dict]) -> dict:
    """Namespace components and expose matches without promoting them to flows."""
    expected = {r.repository_id for r in scope.repositories}
    supplied = [d.get("repository_id") for d in discoveries if isinstance(d, dict)]
    if any(not isinstance(rid, str) for rid in supplied):
        raise ArchitectureError("Discovery contains an invalid repository identity")
    if len(supplied) != len(discoveries) or len(set(supplied)) != len(supplied) or set(supplied) != expected:
        raise ArchitectureError("Discovery must cover every selected repository exactly once")
    components = []
    interfaces = []
    for document in sorted(discoveries, key=lambda d: d["repository_id"]):
        rid = document["repository_id"]
        validate_discovery(scope, rid, document)
        for row in sorted(document["components"], key=lambda r: r["id"]):
            components.append(
                {**row, "id": _id("component", rid, row["id"]), "repository_id": rid, "local_id": row["id"]}
            )
        for row in sorted(document["interfaces"], key=lambda r: r["id"]):
            interfaces.append(
                {
                    **row,
                    "id": _id("interface", rid, row["id"]),
                    "repository_id": rid,
                    "component_id": _id("component", rid, row["component_id"]),
                }
            )
    unresolved = []
    identified = []
    bindings = {r.repository_id: deployment_binding(scope, r.repository_id) for r in scope.repositories}
    for row in interfaces:
        binding, host = _endpoint(row)
        declared = bindings[row["repository_id"]]
        # A receiving interface without its own binding is bound by the one
        # Service its repository declares (Kubernetes service selection).
        if binding is None and declared and row["role"] in {"serve", "consume"}:
            binding = declared["service"]
        if binding is None:
            unresolved.append({"interface_id": row["id"], "reason": "identity-not-established"})
            continue
        identified.append((row, binding, host))
    candidates = []
    used: set[str] = set()
    seen: set[tuple] = set()
    for sender, binding, host in sorted(identified, key=lambda item: item[0]["id"]):
        if sender["role"] not in {"request", "publish"}:
            continue
        family = _PROTOCOL_FAMILY.get(sender["protocol"], sender["protocol"])
        receiving = "consume" if family in _MESSAGING else "serve"
        operation = _operation(sender["operation"])
        # A peer shares the protocol family, the operation and the deployment
        # binding, and its host when both cite one. This only narrows the
        # review; the architecture analyst decides each candidate from both
        # sides' evidence.
        peers = [
            (receiver, peer_host)
            for receiver, peer_binding, peer_host in identified
            if receiver["role"] == receiving
            and receiver["repository_id"] != sender["repository_id"]
            and _PROTOCOL_FAMILY.get(receiver["protocol"], receiver["protocol"]) == family
            and _operation(receiver["operation"]) == operation
            and peer_binding == binding
            and (host is None or peer_host is None or host == peer_host)
        ]
        # Several interfaces of one receiving component (for example two
        # methods on one route) name one peer; only distinct components are
        # an ambiguity.
        if len({receiver["component_id"] for receiver, _ in peers}) != 1:
            unresolved.append(
                {"interface_id": sender["id"], "reason": "ambiguous-peer" if peers else "no-matching-peer"}
            )
            used.add(sender["id"])
            continue
        receiver, peer_host = min(peers, key=lambda pair: pair[0]["id"])
        used.update([sender["id"], *(row["id"] for row, _ in peers)])
        key = (sender["component_id"], receiver["component_id"], receiver["protocol"], operation)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "id": _id("connection", sender["id"], receiver["id"]),
                "sender_interface": sender["id"],
                "receiver_interface": receiver["id"],
                "from": sender["component_id"],
                "to": receiver["component_id"],
                "protocol": receiver["protocol"],
                "operation": operation,
                "address": (host or peer_host or binding)[:240],
                "deployment": binding[:120],
                "status": "requires-architecture-review",
                "via": "message-broker" if family in _MESSAGING else None,
            }
        )
    unresolved.extend(
        {"interface_id": row["id"], "reason": "no-matching-peer"} for row, _, _ in identified if row["id"] not in used
    )
    result = {
        "schema_version": 1,
        "scope_sha256": scope.inventory()["scope_sha256"],
        "components": components,
        "interfaces": interfaces,
        "candidates": sorted(candidates, key=lambda r: r["id"]),
        "unresolved": sorted(unresolved, key=lambda r: r["interface_id"]),
    }
    if not Draft202012Validator(json.loads(OUTPUT_SCHEMA.read_text(encoding="utf-8"))).is_valid(result):
        raise ArchitectureError("Reconciled connection candidates violate their schema")
    return result
