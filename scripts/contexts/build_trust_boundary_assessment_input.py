#!/usr/bin/env python3
"""Build the bounded, deterministic input for the trust-boundary agent."""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema
import validators.validate_intermediate as intermediate_contract
import yaml
from model.finalize_component_inventory import validate_receipt
from shared._atomic_io import atomic_write_json
from validators.validate_fragment import (
    architecture_reference_errors,
    data_flow_endpoint_errors,
    repository_path_errors,
)

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
INPUT_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundary-assessment-input.schema.json"
FLOW_SCHEMA = PLUGIN_ROOT / "schemas" / "fragments" / "data-flows.schema.json"
ROUTE_SCHEMA = PLUGIN_ROOT / "schemas" / "route-inventory.schema.json"
ATTACK_SURFACE_SCHEMA = PLUGIN_ROOT / "schemas" / "fragments" / "attack-surface-overrides.schema.json"
CROSS_REPO_SCHEMA = PLUGIN_ROOT / "schemas" / "cross-repo-register.schema.json"
RECON_SIGNALS_SCHEMA = PLUGIN_ROOT / "schemas" / "recon-signals.schema.json"
DECLARATION_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundaries-repo.schema.yaml"
_SAFE_RELATIVE = re.compile(r"^(?!/)(?![A-Za-z]:[\\/])(?!.*(?:^|/)\.\.(?:/|$))(?!.*://).+$")
_IDENTITY_WORDS = re.compile(
    r"\b(auth(?:entication|orization)?|oauth|oidc|admin|tenant|impersonat|privilege|service identity)\b", re.I
)
_ISOLATION_WORDS = re.compile(
    r"\b(sandbox|plugin|template|parser|worker|child process|deseriali[sz]|file origin)\b", re.I
)
_BUILD_ZONES = {"ci-cd-runtime", "ci-cd-secrets", "build-pipeline", "deployment-pipeline"}


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed JSON input {path}: {exc}") from exc


def _validate(document: Any, schema_path: Path) -> None:
    schema = _read_json(schema_path)
    jsonschema.Draft202012Validator(schema).validate(document)


def _validate_yaml_schema(document: Any, schema_path: Path) -> None:
    schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)


def _bounded_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _safe_evidence(values: Any, repo_root: Path, *, limit: int = 12) -> list[dict[str, Any]]:
    root = repo_root.resolve()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    line_counts: dict[Path, int] = {}
    for value in values if isinstance(values, list) else []:
        if not isinstance(value, dict) or not isinstance(value.get("file"), str):
            continue
        rel = value["file"].replace("\\", "/").strip()
        if not rel or len(rel) > 512 or not _SAFE_RELATIVE.match(rel):
            continue
        try:
            candidate = (root / rel).resolve()
            canonical = candidate.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        try:
            if not candidate.is_file():
                continue
        except OSError:
            continue
        line = value.get("line")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
            continue
        if line is not None:
            if candidate not in line_counts:
                try:
                    with candidate.open("r", encoding="utf-8", errors="ignore") as handle:
                        line_counts[candidate] = sum(1 for _ in handle)
                except OSError:
                    continue
            if line > line_counts[candidate]:
                continue
        key = (canonical, line)
        if key in seen:
            continue
        seen.add(key)
        row: dict[str, Any] = {"file": canonical}
        if line is not None:
            row["line"] = line
        out.append(row)
        if len(out) >= limit:
            break
    return out


def _component_cards(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards = []
    for row in components:
        safe_paths = [
            path.replace("\\", "/")
            for path in row.get("paths", [])[:40]
            if isinstance(path, str) and _SAFE_RELATIVE.match(path.replace("\\", "/"))
        ]
        card = {
            "id": row["id"],
            "name": str(row["name"])[:80],
            "tier": row["tier"],
            "deployment_zones": [
                str(zone)[:80] for zone in row.get("deployment_zones", [])[:20] if isinstance(zone, str)
            ],
            "handles_sensitive_data": bool(row.get("handles_sensitive_data", False)),
            "paths": safe_paths,
        }
        workload_zones = [str(zone)[:140] for zone in row.get("workload_zones") or [] if isinstance(zone, str)]
        if workload_zones:
            card["workload_zones"] = workload_zones[:64]
        cards.append(card)
    return cards


def _material_zones(component: dict[str, Any]) -> set[str]:
    ignored = {"unknown", "runtime", "docker", "docker-container", "prod-env"}
    return {str(value) for value in component.get("deployment_zones", []) if str(value) not in ignored}


def _network_zone_crossing(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Both endpoints run on one deployment platform but on different network zones there.

    Zones are compared per platform, so a component known only from compose and
    one known only from Kubernetes are not a crossing. Differing zone sets count,
    not only disjoint ones: a workload that bridges two zones is exactly where a
    peer from one of them reaches the other.
    """

    def by_platform(component: dict[str, Any]) -> dict[str, set[str]]:
        zones: dict[str, set[str]] = {}
        for value in component.get("workload_zones") or []:
            platform, _, zone = str(value).partition(":")
            if zone:
                zones.setdefault(platform, set()).add(zone)
        return zones

    left_zones, right_zones = by_platform(left), by_platform(right)
    return any(left_zones[platform] != right_zones[platform] for platform in left_zones.keys() & right_zones.keys())


def _signal_id(signal_class: str, source: str, target: str) -> str:
    return f"signal-{signal_class}-{source}-to-{target}"


def _crossing_connections(flows: list[dict[str, Any]], components: dict[str, dict[str, Any]]) -> set[str]:
    """Reviewed connections whose sending and receiving sources share no repository.

    A broker holds evidence from both sides, so the comparison uses the
    connection's outer endpoints rather than each hop's endpoints.
    """
    if not any(flow.get("connection_id") for flow in flows):
        return set()
    from contexts.multi_repo_analysis import connection_relays

    relays = connection_relays(flows)
    sides: dict[str, tuple[set[str], set[str]]] = {}
    for flow in flows:
        key = flow.get("connection_id")
        if not key:
            continue
        senders, receivers = sides.setdefault(key, (set(), set()))
        if flow["from"] not in relays[key]:
            senders.update((components.get(flow["from"]) or {}).get("repository_ids") or [])
        if flow["to"] not in relays[key]:
            receivers.update((components.get(flow["to"]) or {}).get("repository_ids") or [])
    return {
        key for key, (senders, receivers) in sides.items() if senders and receivers and senders.isdisjoint(receivers)
    }


def _signal_specs(
    flow: dict[str, Any],
    components: dict[str, dict[str, Any]],
    crossing_connections: frozenset[str] | set[str] = frozenset(),
) -> list[tuple[str, str, list[str]]]:
    source, target = flow["from"], flow["to"]
    left, right = components.get(source), components.get(target)
    text = f"{flow.get('label', '')} {flow.get('protocol', '')}"
    result: list[tuple[str, str, list[str]]] = []
    if source == "external" and target in components:
        result.append(
            (
                "external-ingress",
                "runtime flow enters a registered component from external",
                ["test/documentation-only route", "development-only listener"],
            )
        )
    if left and right and left.get("tier") == "client" and right.get("tier") == "application":
        result.append(
            (
                "browser-to-server",
                "client-tier runtime flow reaches an application-tier component",
                ["server-side rendering without client runtime", "static asset copy"],
            )
        )
    if (
        left
        and right
        and _material_zones(left)
        and _material_zones(right)
        and _material_zones(left) != _material_zones(right)
    ):
        result.append(
            (
                "cross-zone-flow",
                "resolved flow endpoints have materially different deployment zones",
                ["runtime-only placement labels", "duplicate protocol view"],
            )
        )
    elif left and right and _network_zone_crossing(left, right):
        result.append(
            (
                "cross-zone-flow",
                "resolved flow endpoints run on different network zones of the deployment configuration",
                ["network declared but unused by either workload", "duplicate protocol view"],
            )
        )
    if left and right and left.get("tier") == "application" and right.get("tier") == "data":
        result.append(
            (
                "application-to-data-tier",
                "application-tier component reaches a data-tier component",
                ["in-memory collection", "test-only database"],
            )
        )
    if "external" in {source, target} and not (source == "external" and target in components):
        result.append(
            (
                "third-party-or-cross-repository",
                "runtime flow crosses between a registered component and an external dependency",
                ["development tooling", "build-only dependency unless kind is build"],
            )
        )
    if flow.get("connection_id") in crossing_connections:
        # Review the evidenced communication, not repository membership. The
        # analyst may establish same-trust or leave the crossing unresolved.
        result.append(
            (
                "third-party-or-cross-repository",
                "reviewed runtime communication connects separately owned source implementations",
                ["same process or trust domain established by deployment evidence", "connection does not change trust"],
            )
        )
    if _IDENTITY_WORDS.search(text):
        result.append(
            (
                "identity-or-privilege-transition",
                "flow metadata names an authentication, authorization, tenant, or privilege transition",
                ["display-only role", "documentation claim without enforcement code"],
            )
        )
    if _ISOLATION_WORDS.search(text):
        result.append(
            (
                "in-process-isolation",
                "flow metadata names a parser, sandbox, worker, plugin, or deserialization transition",
                ["ordinary function call with no trust or privilege change"],
            )
        )
    zones = _material_zones(left or {}) | _material_zones(right or {})
    if zones & _BUILD_ZONES or "build" in text.casefold() or "deploy" in text.casefold():
        result.append(
            (
                "build-and-deployment",
                "flow reaches a build, CI/CD, artifact, or deployment surface",
                ["local script unused by automation", "documentation-only workflow"],
            )
        )
    return result


def _signals(
    flows: list[dict[str, Any]],
    components: list[dict[str, Any]],
    source_context: dict[str, Any],
) -> list[dict[str, Any]]:
    by_id = {row["id"]: row for row in components}
    crossings = _crossing_connections(flows, by_id)
    merged: dict[str, dict[str, Any]] = {}
    for flow in flows:
        for signal_class, trigger, exclusions in _signal_specs(flow, by_id, crossings):
            sid = _signal_id(signal_class, flow["from"], flow["to"])
            row = merged.setdefault(
                sid,
                {
                    "id": sid,
                    "class": signal_class,
                    "from": flow["from"],
                    "to": flow["to"],
                    "mandatory": True,
                    "trigger": trigger,
                    "false_positive_exclusions": exclusions,
                    "evidence": [],
                    "provenance": [],
                    "flow_ids": [],
                },
            )
            row["flow_ids"].append(flow["id"])
            row["provenance"].append(flow["provenance"])
            for evidence in flow.get("evidence", []):
                if evidence not in row["evidence"]:
                    row["evidence"].append(evidence)

    # Placement is itself a mandatory external-ingress signal only for
    # application components explicitly marked internet-facing. The analyst
    # must confirm or reject it; the builder never invents a route.
    for component in components:
        if component.get("tier") != "application" or "internet" not in component.get("deployment_zones", []):
            continue
        sid = _signal_id("external-ingress", "external", component["id"])
        merged.setdefault(
            sid,
            {
                "id": sid,
                "class": "external-ingress",
                "from": "external",
                "to": component["id"],
                "mandatory": True,
                "trigger": "application component is explicitly placed on the internet",
                "false_positive_exclusions": ["development-only listener", "documentation-only placement"],
                "evidence": [],
                "provenance": ["component-inventory"],
                "flow_ids": [],
            },
        )
    for component in components:
        if not (_material_zones(component) & _BUILD_ZONES):
            continue
        sid = _signal_id("build-and-deployment", "external", component["id"])
        merged.setdefault(
            sid,
            {
                "id": sid,
                "class": "build-and-deployment",
                "from": "external",
                "to": component["id"],
                "mandatory": True,
                "trigger": "component inventory places this unit in a build or deployment zone",
                "false_positive_exclusions": ["local-only script", "inactive example workflow"],
                "evidence": [],
                "provenance": ["component-inventory"],
                "flow_ids": [],
            },
        )

    recon = source_context["recon_signals"]
    if recon["values"].get("has_auth_surface") or recon["values"].get("has_role_concept"):
        identity_components = [
            component
            for component in components
            if re.search(
                r"\b(auth|identity|admin|tenant|gateway)\b",
                f"{component['id']} {component['name']}".replace("-", " "),
                re.I,
            )
        ]
        for component in identity_components:
            sid = _signal_id("identity-or-privilege-transition", "external", component["id"])
            merged.setdefault(
                sid,
                {
                    "id": sid,
                    "class": "identity-or-privilege-transition",
                    "from": "external",
                    "to": component["id"],
                    "mandatory": True,
                    "trigger": "deterministic recon signals identify an authentication or authorization surface",
                    "false_positive_exclusions": ["role words only in documentation", "outbound credential use only"],
                    "evidence": recon["evidence"],
                    "provenance": ["recon-signals"],
                    "flow_ids": [],
                },
            )
    for row in merged.values():
        row["flow_ids"] = sorted(set(row["flow_ids"]))
        row["provenance"] = sorted(set(row["provenance"]))
        row["evidence"] = row["evidence"][:12]
    return sorted(merged.values(), key=lambda item: item["id"])


_RECON_SIGNAL_KEYS = (
    "has_public_routes",
    "has_auth_surface",
    "has_role_concept",
    "has_ci_pipeline",
    "has_external_apis",
    "has_client_storage",
    "has_multi_tenancy_signal",
)


def _signal_evidence(document: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    raw = document.get("signal_evidence")
    candidates: list[dict[str, Any]] = []
    for key in _RECON_SIGNAL_KEYS:
        value = raw.get(key) if isinstance(raw, dict) else None
        if not isinstance(value, dict):
            continue
        locations = value.get("locations")
        if isinstance(locations, list):
            candidates.extend(locations)
    return _safe_evidence(candidates, repo_root)


def _source_context(repo_root: Path, output_dir: Path) -> dict[str, Any]:
    attack = _read_json(output_dir / ".attack-surface-overrides.json", None)
    if attack is None:
        attack = {"schema_version": 1, "curations": {}, "additions": []}
    _validate(attack, ATTACK_SURFACE_SCHEMA)

    route_doc = _read_json(output_dir / ".route-inventory.json", None)
    route_status = "missing"
    route_cards: list[dict[str, Any]] = []
    if route_doc is not None:
        _validate(route_doc, ROUTE_SCHEMA)
        route_status = "present"
        include_ids = set((attack.get("curations") or {}).get("include_route_ids") or [])
        routes = sorted(route_doc["routes"], key=lambda row: row["route_id"])
        if include_ids:
            routes = [row for row in routes if row["route_id"] in include_ids]
        for row in routes[:100]:
            evidence = _safe_evidence(
                [{"file": row["handler_file"], "line": row["handler_line"]}],
                repo_root,
                limit=1,
            )
            if not evidence:
                raise ValueError(f"route {row['route_id']} has invalid repository evidence")
            route_cards.append(
                {
                    "route_id": row["route_id"],
                    "method": row["method"],
                    "path": _bounded_text(row["path"], 180),
                    "authn_signal": row["authn_signal"],
                    "authz_signal": row["authz_signal"],
                    "management_surface": row["management_surface"],
                    "evidence": evidence,
                }
            )

    additions = [
        {
            "entry_point": _bounded_text(row.get("entry_point"), 180),
            "protocol": _bounded_text(row.get("protocol"), 80),
            "auth_required": row.get("auth_required"),
        }
        for row in (attack.get("additions") or [])[:40]
        if isinstance(row, dict) and row.get("entry_point") and row.get("protocol")
    ]

    cross_repo = _read_json(output_dir / ".cross-repo-register.json", None)
    cross_status = "missing"
    cross_cards: list[dict[str, Any]] = []
    if cross_repo is not None:
        _validate(cross_repo, CROSS_REPO_SCHEMA)
        cross_status = "present"
        for row in cross_repo["entries"][:20]:
            threat_model = row.get("threat_model") or {}
            cross_cards.append(
                {
                    "name": _bounded_text(row["name"], 100),
                    "source": row["source"],
                    "interface": _bounded_text(row.get("interface"), 160),
                    "type": _bounded_text(row.get("type"), 40),
                    "threat_model_status": _bounded_text(threat_model.get("status"), 20),
                }
            )

    recon = _read_json(output_dir / ".recon-signals.json", {}) or {}
    if recon:
        _validate(recon, RECON_SIGNALS_SCHEMA)
        valid, errors = intermediate_contract.validate_recon_signals(recon, repo_root=repo_root)
        if not valid:
            raise ValueError("invalid recon signal evidence: " + "; ".join(errors))
    raw_signals = recon.get("signals") if isinstance(recon, dict) else {}
    values = {
        key: bool(raw_signals.get(key, False)) if isinstance(raw_signals, dict) else False for key in _RECON_SIGNAL_KEYS
    }

    declaration_path = repo_root / ".appsec" / "trust-boundaries.yaml"
    declaration_status = "missing"
    declaration_fingerprint = None
    declaration_keys: list[str] = []
    if declaration_path.is_file():
        try:
            declaration = yaml.safe_load(declaration_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"malformed repository trust-boundary declaration: {exc}") from exc
        _validate_yaml_schema(declaration, DECLARATION_SCHEMA)
        declaration_status = "present"
        encoded = json.dumps(declaration, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        declaration_fingerprint = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        declaration_keys = [row["key"] for row in declaration["boundaries"][:200]]

    config = _read_json(output_dir / ".skill-config.json", {}) or {}
    return {
        "route_inventory": {"status": route_status, "routes": route_cards},
        "attack_surface_additions": additions,
        "cross_repository": {"status": cross_status, "entries": cross_cards},
        "recon_signals": {
            "values": values,
            "evidence": _signal_evidence(recon if isinstance(recon, dict) else {}, repo_root),
        },
        "boundary_declarations": {
            "status": declaration_status,
            "fingerprint": declaration_fingerprint,
            "keys": declaration_keys,
        },
        "incremental": bool(config.get("incremental", False)),
    }


def _prior_identity_hints(output_dir: Path) -> list[dict[str, Any]]:
    prior = _read_json(output_dir / ".trust-boundaries.json", {}) or {}
    rows = prior.get("trust_boundaries", [])
    hints = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not re.fullmatch(r"tb-[0-9]+", str(row.get("id", ""))):
            continue
        hint = {"id": row["id"], "name": str(row.get("name") or "Unnamed boundary")[:100]}
        for key in ("from", "to", "declaration_key"):
            if isinstance(row.get(key), str):
                hint[key] = row[key]
        hints.append(hint)
    return hints[:400]


def _semantic_flow_validation(flows: dict[str, Any], receipt: dict[str, Any]) -> None:
    _validate(flows, FLOW_SCHEMA)
    errors = architecture_reference_errors(flows)
    if errors:
        raise ValueError("; ".join(errors))
    if flows["component_inventory_fingerprint"] != receipt["component_inventory_fingerprint"]:
        raise ValueError("data-flow sidecar carries a stale component inventory fingerprint")
    errors = data_flow_endpoint_errors(flows["data_flows"], receipt["component_ids"])
    if errors:
        raise ValueError("; ".join(errors))


def _flow_identity(row: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(row.get("from") or ""),
        str(row.get("to") or ""),
        str(row.get("from_entity") or ""),
        str(row.get("to_entity") or ""),
        _bounded_text(row.get("protocol"), 80).casefold(),
        _bounded_text(row.get("label"), 120).casefold(),
    )


def _preserve_incremental_flow_ids(output_dir: Path, flow_doc: dict[str, Any]) -> dict[str, Any]:
    config = _read_json(output_dir / ".skill-config.json", {}) or {}
    if not config.get("incremental"):
        return flow_doc
    prior_path = output_dir / "threat-model.yaml"
    if not prior_path.is_file():
        return flow_doc
    try:
        prior = yaml.safe_load(prior_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return flow_doc
    prior_rows = prior.get("data_flows") if isinstance(prior, dict) else None
    if not isinstance(prior_rows, list):
        return flow_doc
    prior_by_identity = {
        _flow_identity(row): row["id"]
        for row in prior_rows
        if isinstance(row, dict) and re.fullmatch(r"df-[0-9]{3,}", str(row.get("id", "")))
    }
    current_rows = flow_doc["data_flows"]
    desired = [prior_by_identity.get(_flow_identity(row), row["id"]) for row in current_rows]
    if len(desired) != len(set(desired)):
        return flow_doc
    if desired == [row["id"] for row in current_rows]:
        return flow_doc
    stabilized = dict(flow_doc)
    stabilized["data_flows"] = [dict(row, id=flow_id) for row, flow_id in zip(current_rows, desired, strict=True)]
    _validate(stabilized, FLOW_SCHEMA)
    atomic_write_json(output_dir / ".data-flows.json", stabilized, sort_keys=False)
    return stabilized


def build(repo_root: Path, output_dir: Path, depth: str) -> dict[str, Any]:
    repo_root, output_dir = repo_root.resolve(), output_dir.resolve()
    receipt = validate_receipt(output_dir, repo_root)
    component_doc = _read_json(output_dir / ".components.json")
    flow_doc = _read_json(output_dir / ".data-flows.json")
    if not isinstance(flow_doc, dict):
        raise ValueError("missing required Stage-1a artifact .data-flows.json")
    flow_doc = _preserve_incremental_flow_ids(output_dir, flow_doc)
    _semantic_flow_validation(flow_doc, receipt)
    evidence_errors = repository_path_errors("data-flows", flow_doc, repo_root)
    if evidence_errors:
        raise ValueError("invalid data-flow repository evidence: " + "; ".join(evidence_errors))
    components = _component_cards(component_doc["components"])
    flows = []
    for row in flow_doc["data_flows"]:
        item = dict(row)
        item["evidence"] = _safe_evidence(row.get("evidence"), repo_root)
        flows.append(item)
    source_context = _source_context(repo_root, output_dir)
    body: dict[str, Any] = {
        "schema_version": 1,
        "component_inventory_fingerprint": receipt["component_inventory_fingerprint"],
        "assessment_input_fingerprint": "sha256:" + "0" * 64,
        "assessment_depth": depth,
        "components": components,
        "data_flows": flows,
        "external_entities": flow_doc.get("external_entities") or [],
        "signals": _signals(flows, components, source_context),
        "prior_boundary_identity_hints": _prior_identity_hints(output_dir),
        "source_context": source_context,
    }
    fingerprint_body = dict(body)
    fingerprint_body.pop("assessment_input_fingerprint")
    encoded = json.dumps(fingerprint_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    body["assessment_input_fingerprint"] = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    _validate(body, INPUT_SCHEMA)
    atomic_write_json(output_dir / ".trust-boundary-assessment-input.json", body, sort_keys=False)
    return body


def build_assessment(scope, components, receipt, flow_doc, source_context, depth) -> dict[str, Any]:
    """Build the controller-held crossing inventory from admitted v2 topology.

    The controller supplies measured, qualified source context. This function
    cannot invent a primary root or interpret missing measurements as false.
    Model jobs receive a single-signal projection of the returned inventory.
    """
    from shared.assessment_sources import source_rows
    from validators.validate_assessment_architecture import validate_flows, validate_source

    from contexts.multi_repo_analysis import contract

    validate_flows(scope, components, receipt, flow_doc)
    schema = contract("trust-boundary-assessment-input-v2.schema.json")
    context = copy.deepcopy(source_context)
    jsonschema.Draft202012Validator(schema["properties"]["source_context"]).validate(context)
    for evidence in source_rows(context):
        validate_source(scope, evidence, path_key="file")
    cards = []
    for component in components["components"]:
        card = {
            "id": component["id"],
            "name": component["name"][:80],
            "tier": component["tier"],
            "deployment_zones": copy.deepcopy(component.get("deployment_zones", [])),
            "handles_sensitive_data": component.get("handles_sensitive_data", False),
            "repository_ids": list(component["repository_ids"]),
            "paths": copy.deepcopy(component["paths"]),
        }
        if component.get("workload_zones"):
            card["workload_zones"] = copy.deepcopy(component["workload_zones"])
        cards.append(card)
    # Connection receipts establish review signals, not trust. Keep them in
    # the canonical topology; the bounded boundary contract carries only its
    # declared flow fields after the signals have been derived.
    flow_fields = set(schema["properties"]["data_flows"]["items"]["properties"])
    flows = [
        {key: copy.deepcopy(value) for key, value in flow.items() if key in flow_fields}
        for flow in flow_doc["data_flows"]
    ]
    body = {
        "schema_version": 2,
        "source_scope_sha256": scope.inventory()["scope_sha256"],
        "component_inventory_fingerprint": receipt["component_inventory_fingerprint"],
        "assessment_input_fingerprint": "sha256:" + "0" * 64,
        "assessment_depth": depth,
        "components": cards,
        "data_flows": flows,
        "external_entities": copy.deepcopy(flow_doc.get("external_entities", [])),
        "signals": _signals(flow_doc["data_flows"], cards, context),
        "prior_boundary_identity_hints": [],
        "source_context": context,
    }
    _assessment_input_fingerprint(body)
    jsonschema.Draft202012Validator(schema).validate(body)
    scope.verify_unchanged()
    return body


def _assessment_input_fingerprint(body):
    fingerprint_body = {key: value for key, value in body.items() if key != "assessment_input_fingerprint"}
    encoded = json.dumps(fingerprint_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    body["assessment_input_fingerprint"] = "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


def project_assessment_signal(assessment, signal_id, topology):
    """Admit only the crossing endpoints and their cited context to one job.

    ``topology`` is the canonical flow list with its connection identities;
    the bounded assessment input omits them.
    """
    from contexts.multi_repo_analysis import contract, scope_relays, source_selection

    signal = next((row for row in assessment["signals"] if row["id"] == signal_id), None)
    if signal is None:
        raise ValueError("Boundary job requires a controller-selected crossing signal")
    if {row["id"] for row in topology} != {row["id"] for row in assessment["data_flows"]}:
        raise ValueError("Boundary job topology does not match its assessment input")
    result = copy.deepcopy(assessment)
    ids = {signal["from"], signal["to"]} - {"external"}
    connections = {
        row["connection_id"] for row in topology if row["id"] in signal["flow_ids"] and row.get("connection_id")
    }
    result["components"] = scope_relays(
        [row for row in result["components"] if row["id"] in ids], topology, connections
    )
    result["data_flows"] = [row for row in result["data_flows"] if row["id"] in signal["flow_ids"]]
    result["signals"] = [copy.deepcopy(signal)]
    external_ids = {row[key] for row in result["data_flows"] for key in ("from_entity", "to_entity") if key in row}
    result["external_entities"] = [row for row in result["external_entities"] if row["id"] in external_ids]
    allowed = source_selection(result["components"])
    context = result["source_context"]
    context["route_inventory"]["routes"] = [
        row
        for row in context["route_inventory"]["routes"]
        if any((ev["repository_id"], ev["file"]) in allowed for ev in row["evidence"])
    ]
    context["recon_signals"]["evidence"] = [
        row for row in context["recon_signals"]["evidence"] if (row["repository_id"], row["file"]) in allowed
    ]
    _assessment_input_fingerprint(result)
    jsonschema.Draft202012Validator(contract("trust-boundary-assessment-input-v2.schema.json")).validate(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--depth", choices=["quick", "standard", "thorough"], default="standard")
    args = parser.parse_args(argv)
    try:
        result = build(args.repo_root, args.output_dir, args.depth)
    except (ValueError, jsonschema.ValidationError, yaml.YAMLError) as exc:
        print(f"TRUST_BOUNDARY_INPUT_FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        "TRUST_BOUNDARY_INPUT_OK: "
        f"{len(result['components'])} components, {len(result['data_flows'])} flows, "
        f"{len(result['signals'])} mandatory signals"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
