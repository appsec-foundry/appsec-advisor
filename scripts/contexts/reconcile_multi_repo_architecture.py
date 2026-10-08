"""Validate repository-local observations and identify candidate connections.

This is a candidate producer, not an architecture publication gate. Exact
source quotations establish provenance, not the truth of an observation's
semantics. A matched candidate still needs architecture review before it can
become a canonical data flow or contribute to a confirmed attack route.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
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
    indexed = defaultdict(list)
    unresolved = []
    for row in interfaces:
        if row["address"] is None or row["deployment"] is None:
            unresolved.append({"interface_id": row["id"], "reason": "identity-not-established"})
            continue
        indexed[(row["deployment"], row["address"], row["protocol"], row["operation"])].append(row)
    candidates = []
    for key, rows in sorted(indexed.items()):
        role = "consume" if key[2] in {"AMQP", "Kafka"} else "serve"
        receivers = [r for r in rows if r["role"] == role]
        senders = [r for r in rows if r["role"] in {"request", "publish"}]
        used: set[str] = set()
        for sender in senders:
            peers = [r for r in receivers if r["repository_id"] != sender["repository_id"]]
            # Multiple messaging consumers may be legitimate fan-out, but the
            # consumer-group semantics require review rather than a guess.
            if len(peers) != 1:
                unresolved.append(
                    {"interface_id": sender["id"], "reason": "ambiguous-peer" if peers else "no-matching-peer"}
                )
                used.add(sender["id"])
                continue
            receiver = peers[0]
            used.update((sender["id"], receiver["id"]))
            candidates.append(
                {
                    "id": _id("connection", sender["id"], receiver["id"]),
                    "sender_interface": sender["id"],
                    "receiver_interface": receiver["id"],
                    "from": sender["component_id"],
                    "to": receiver["component_id"],
                    "protocol": key[2],
                    "operation": key[3],
                    "address": key[1],
                    "deployment": key[0],
                    "status": "requires-architecture-review",
                    "via": "message-broker" if role == "consume" else None,
                }
            )
        unresolved.extend({"interface_id": r["id"], "reason": "no-matching-peer"} for r in rows if r["id"] not in used)
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
