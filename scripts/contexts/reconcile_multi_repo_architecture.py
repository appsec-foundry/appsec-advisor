"""Validate repository-local observations and identify candidate connections.

This is a candidate producer, not an architecture publication gate. Exact
source quotations establish provenance, not the truth of an observation's
semantics. A matched candidate still needs architecture review before it can
become a canonical data flow or contribute to a confirmed attack route.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
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
        # A forwarder passes on whatever path it receives and a listener
        # serves no single route, so both may leave the operation open. A
        # message always names its topic.
        if interface["operation"] is None and interface["role"] in {"publish", "consume"}:
            raise ArchitectureError("A published or consumed message must name its topic")
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


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _split_host(host: str) -> tuple[str, int | None]:
    """A host's name and explicit port, keeping a bracketed IPv6 literal whole."""
    if host.startswith("["):
        name, _, rest = host.partition("]")
        name, port = name + "]", rest[1:] if rest.startswith(":") else ""
    elif host.count(":") == 1:
        name, port = host.split(":")
    else:
        name, port = host, ""
    return name, int(port) if port.isdigit() else None


def _is_listen_address(name: str) -> bool:
    """A wildcard or loopback address only says where a server listens."""
    return name in {"0.0.0.0", "*", "::", "[::]", "::1", "[::1]", "localhost"} or name.startswith("127.")


def _address_parts(address: str | None) -> tuple[str | None, str | None, int | None]:
    """Host, host name and port of an address, or nothing for a listen address.

    The host is the address without scheme, credentials, path or virtual host.
    The port is the explicit one, else the scheme's default.
    """
    if not address:
        return None, None, None
    scheme, _, rest = address.rpartition("://")
    host = rest.rsplit("@", 1)[-1].split("/", 1)[0].lower()
    name, port = _split_host(host)
    if not name or _is_listen_address(name):
        return None, None, None
    return host, name, port if port is not None else _DEFAULT_PORTS.get(scheme.lower())


def _endpoint(row: dict) -> tuple[str | None, str | None]:
    """The deployment binding and host an interface's cited identity establishes.

    The binding is the declared deployment, else the service a cluster-local
    (``<service>.<namespace>.svc``) or single-label host names. A public host
    alone is not a binding: equal addresses in separate deployments stay apart.
    A listen address such as ``0.0.0.0`` names no peer and binds nothing.
    """
    binding = row["deployment"].lower() if row.get("deployment") else None
    host, name, _port = _address_parts(row.get("address"))
    labels = name.split(".") if name else []
    if binding is None and labels and (len(labels) == 1 or (len(labels) >= 3 and labels[2] == "svc")):
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


_COMPOSE_FILE = re.compile(r"(?:docker-)?compose(?:\.[a-z0-9_-]+)?\.ya?ml")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_EXPOSE = re.compile(r"\s*EXPOSE\s+(.+)", re.IGNORECASE)


def _line_of(text: str, wanted: str) -> int:
    return next((n for n, value in enumerate(text.splitlines(), 1) if value.strip() == wanted), 1)


def compose_bindings(scope: AssessmentScope) -> dict[str, list[dict]]:
    """Compose service names whose build context is a selected repository.

    A compose file in any selected repository may name the service another
    selected repository builds. The context is resolved against the admitted
    roots only to compare paths; nothing outside the captured bytes is read.
    """
    import yaml

    roots = {r.repository_id: os.path.normpath(str(r.root)) for r in scope.repositories}
    found: dict[str, list[dict]] = {}
    for repo in scope.repositories:
        for path, data in sorted(repo.files.items()):
            if not _COMPOSE_FILE.fullmatch(posixpath.basename(path).lower()) or len(data) > _MAX_MANIFEST_BYTES:
                continue
            try:
                text = data.decode("utf-8")
                document = yaml.safe_load(text)
            except (UnicodeDecodeError, yaml.YAMLError):
                continue
            services = document.get("services") if isinstance(document, dict) else None
            for name, spec in sorted((services or {}).items(), key=lambda item: str(item[0])):
                build = spec.get("build") if isinstance(spec, dict) else None
                context = build.get("context", ".") if isinstance(build, dict) else build
                if not isinstance(name, str) or not isinstance(context, str) or "://" in context:
                    continue
                target = os.path.normpath(os.path.join(roots[repo.repository_id], posixpath.dirname(path), context))
                for rid, root in roots.items():
                    if target == root and _DNS_LABEL.fullmatch(name.lower()):
                        line = _line_of(text, name + ":")
                        evidence = {"repository_id": repo.repository_id, "file": path, "line": line}
                        found.setdefault(rid, []).append(
                            {"name": name.lower(), "basis": "compose", "evidence": evidence}
                        )
    return found


def repository_binding(scope: AssessmentScope, repository_id: str, label: str, interfaces: list[dict]) -> dict | None:
    """The repository label as a service name, valid only at an evidenced port.

    The selection of repositories as one system makes a client address naming
    a selected repository a candidate peer. A matching port the receiver
    exposes or listens on must corroborate it, so a coincidental name with
    another port stays apart. A deduplicated label never forms a host name.
    """
    name = label.lower()
    if not _DNS_LABEL.fullmatch(name):
        return None
    repo = next(r for r in scope.repositories if r.repository_id == repository_id)
    ports, evidence = set(), None
    for path, data in sorted(repo.files.items()):
        base = posixpath.basename(path).lower()
        if not (base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile")):
            continue
        for number, value in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            match = _EXPOSE.fullmatch(value)
            exposed = (
                [int(p.split("/", 1)[0]) for p in match.group(1).split() if p.split("/", 1)[0].isdigit()]
                if match
                else []
            )
            if exposed:
                ports.update(exposed)
                evidence = evidence or {"repository_id": repository_id, "file": path, "line": number}
    for row in interfaces:
        if row["repository_id"] == repository_id and row["role"] == "serve" and row.get("address"):
            host = row["address"].rpartition("://")[2].rsplit("@", 1)[-1].split("/", 1)[0]
            port = _split_host(host)[1]
            if port is not None:
                ports.add(port)
                reference = row["evidence"][0]
                evidence = evidence or {
                    "repository_id": repository_id,
                    "file": reference["file"],
                    "line": reference["line"],
                }
    if not ports:
        return None
    return {"name": name, "basis": "repository-label", "evidence": evidence, "ports": frozenset(ports)}


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
    services = {r.repository_id: deployment_binding(scope, r.repository_id) for r in scope.repositories}
    composed = compose_bindings(scope)
    labels = {r["repository_id"]: r["label"] for r in scope.inventory()["repositories"]}
    for row in interfaces:
        binding, host = _endpoint(row)
        rid = row["repository_id"]
        if binding is not None:
            basis = "declared" if row.get("deployment") else "address"
            identities = [{"name": binding, "basis": basis, "evidence": None}]
        else:
            # A receiving interface without its own binding is bound by the
            # deployment that builds or selects its repository: the one
            # Kubernetes Service it declares or a compose service of the
            # selection. Without either, its repository label binds it at an
            # evidenced port only.
            identities = []
            if row["role"] in {"serve", "consume"} and services[rid]:
                service = services[rid]
                evidence = {k: service[k] for k in ("repository_id", "file", "line")}
                identities.append({"name": service["service"], "basis": "service", "evidence": evidence})
            if row["role"] == "serve":
                identities.extend(composed.get(rid, []))
                if not identities:
                    label = repository_binding(scope, rid, labels[rid], interfaces)
                    identities.extend([label] if label else [])
        if not identities:
            unresolved.append({"interface_id": row["id"], "reason": "identity-not-established"})
            continue
        identified.append((row, identities, host))
    candidates = []
    used: set[str] = set()
    seen: set[tuple] = set()
    for sender, (identity,), host in sorted(
        ((row, ids, host) for row, ids, host in identified if row["role"] in {"request", "publish"}),
        key=lambda item: item[0]["id"],
    ):
        binding = identity["name"]
        family = _PROTOCOL_FAMILY.get(sender["protocol"], sender["protocol"])
        receiving = "consume" if family in _MESSAGING else "serve"
        # A forwarder without its own operation reaches any route of its peer;
        # a fixed operation needs a receiver that names the same route.
        operation = None if sender["operation"] is None else _operation(sender["operation"])
        port = _address_parts(sender.get("address"))[2]
        # A peer shares the protocol family, the operation and the deployment
        # binding, and its host when both cite one. A port-corroborated label
        # also needs the client's port. This only narrows the review; the
        # architecture analyst decides each candidate from both sides' evidence.
        peers = []
        for receiver, identities, peer_host in identified:
            match = next(
                (i for i in identities if i["name"] == binding and ("ports" not in i or port in i["ports"])),
                None,
            )
            if (
                match
                and receiver["role"] == receiving
                and receiver["repository_id"] != sender["repository_id"]
                and _PROTOCOL_FAMILY.get(receiver["protocol"], receiver["protocol"]) == family
                and (
                    operation is None
                    or (receiver["operation"] is not None and _operation(receiver["operation"]) == operation)
                )
                and (host is None or peer_host is None or host == peer_host)
            ):
                peers.append((receiver, peer_host, match))
        # Several interfaces of one receiving component (for example two
        # methods on one route) name one peer; only distinct components are
        # an ambiguity.
        if len({receiver["component_id"] for receiver, _, _ in peers}) != 1:
            unresolved.append(
                {"interface_id": sender["id"], "reason": "ambiguous-peer" if peers else "no-matching-peer"}
            )
            used.add(sender["id"])
            continue
        receiver, peer_host, match = min(peers, key=lambda item: item[0]["id"])
        used.update([sender["id"], *(row["id"] for row, _, _ in peers)])
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
                "operation": operation or "*",
                "operation_match": "exact" if operation is not None else "catch-all",
                "address": (host or peer_host or binding)[:240],
                "deployment": binding[:120],
                "binding_basis": match["basis"],
                "binding_evidence": match["evidence"],
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
