#!/usr/bin/env python3
"""Build bounded, exact-source-bound inputs for semantic architecture work."""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from shared._atomic_io import atomic_write_json

# Every projection below is total: for any source it either raises
# ContextProjectionError or returns output its schema accepts. The schemas are
# the only source of the limits, so a cap changed on one side cannot drift from
# the other; an item the schema rejects is omitted and counted, never passed on.
_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
RECON_SCHEMA = "recon-summary-context.schema.json"
ROUTE_SCHEMA = "architecture-route-context.schema.json"
ROLE_UNITS_SCHEMA = "architecture-role-units.schema.json"
TOPOLOGY_SCHEMA = "architecture-topology-context.schema.json"
_VALIDATORS = {
    name: Draft202012Validator(json.loads((_SCHEMA_DIR / name).read_text(encoding="utf-8")))
    for name in (RECON_SCHEMA, ROUTE_SCHEMA, ROLE_UNITS_SCHEMA, TOPOLOGY_SCHEMA)
}


def _schema_at(name: str, *keys: str) -> Any:
    node: Any = _VALIDATORS[name].schema
    for key in keys:
        node = node[key]
    return node


def _item_check(name: str, *keys: str) -> Any:
    """``is_valid`` of the subschema at ``keys``, resolving ``$ref`` against its root."""
    return _VALIDATORS[name].evolve(schema=_schema_at(name, *keys)).is_valid


_RECON_SECTION = ("properties", "sections", "items")
MAX_RECON_SECTIONS = _schema_at(RECON_SCHEMA, "properties", "limits", "properties", "max_sections", "const")
MAX_RECON_RETAINED_LINES = _schema_at(RECON_SCHEMA, "properties", "limits", "properties", "max_retained_lines", "const")
MAX_RECON_LINE_CHARS = _schema_at(RECON_SCHEMA, "properties", "limits", "properties", "max_line_chars", "const")
MAX_RECON_HEADING_CHARS = _schema_at(RECON_SCHEMA, *_RECON_SECTION, "properties", "heading", "maxLength")
MAX_SECTION_LINES = _schema_at(RECON_SCHEMA, *_RECON_SECTION, "else", "properties", "lines", "maxItems")
# The recon template's component table carries one hint per row; the generic
# level-2 cap kept its intro and header plus five hints.
COMPONENT_HINTS_HEADING = _schema_at(
    RECON_SCHEMA, *_RECON_SECTION, "if", "properties", "heading", "pattern"
).removesuffix("$")
MAX_COMPONENT_HINT_LINES = _schema_at(RECON_SCHEMA, *_RECON_SECTION, "then", "properties", "lines", "maxItems")
MAX_ROUTES = _schema_at(ROUTE_SCHEMA, "properties", "limits", "properties", "max_routes", "const")
MAX_UNSUPPORTED_ROUTE_FILES = _schema_at(
    ROUTE_SCHEMA, "properties", "limits", "properties", "max_unsupported_route_files", "const"
)
MAX_FRAMEWORKS_DETECTED = _schema_at(
    ROUTE_SCHEMA, "properties", "coverage", "properties", "frameworks_detected", "maxItems"
)
MAX_ROLE_UNITS = _schema_at(ROLE_UNITS_SCHEMA, "properties", "limits", "properties", "max_units", "const")
MAX_ROLE_UNIT_PATHS = _schema_at(ROLE_UNITS_SCHEMA, "properties", "limits", "properties", "max_paths", "const")
_WORKLOAD = ("properties", "workloads", "items")
MAX_TOPOLOGY_WORKLOADS = _schema_at(TOPOLOGY_SCHEMA, "properties", "limits", "properties", "max_workloads", "const")
MAX_WORKLOAD_DEFINITIONS = _schema_at(TOPOLOGY_SCHEMA, "properties", "limits", "properties", "max_definitions", "const")
MAX_WORKLOAD_ZONES = _schema_at(TOPOLOGY_SCHEMA, *_WORKLOAD, "properties", "zones", "maxItems")
TOPOLOGY_CONTEXT = ".dispatch-context/architecture/topology.json"

# The projection carries only the route fields its own schema declares; a field
# the inventory gains stays out until that schema opts in, never aborts the run.
_PROJECTED_ROUTE_FIELDS = frozenset(_schema_at(ROUTE_SCHEMA, "$defs", "route", "properties"))
_valid_route = _item_check(ROUTE_SCHEMA, "$defs", "route")
_valid_framework = _item_check(ROUTE_SCHEMA, "properties", "coverage", "properties", "frameworks_detected", "items")
_valid_unsupported_file = _item_check(
    ROUTE_SCHEMA, "properties", "coverage", "properties", "unsupported_route_files", "items"
)
_valid_role_unit = _item_check(ROLE_UNITS_SCHEMA, "properties", "units", "items")
_valid_role_unit_path = _item_check(ROLE_UNITS_SCHEMA, "properties", "units", "items", "properties", "paths", "items")
_valid_workload = _item_check(TOPOLOGY_SCHEMA, *_WORKLOAD)
_valid_zone = _item_check(TOPOLOGY_SCHEMA, *_WORKLOAD, "properties", "zones", "items")
_valid_definition = _item_check(TOPOLOGY_SCHEMA, *_WORKLOAD, "properties", "definitions", "items")

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# A recon line naming a concrete file — optionally with a line number — is the
# kind the downstream analyst can act on and verify. Everything else is prose
# that merely describes the same ground.
_SOURCE_REFERENCE_RE = re.compile(
    r"[A-Za-z0-9_./-]+\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|java|kt|rb|php|cs|rs|swift|scala|sql|sh|"
    r"yml|yaml|json|toml|ini|conf|tf|env|xml|gradle|properties|dockerfile)(?::\d+)?",
    re.IGNORECASE,
)


class ContextProjectionError(ValueError):
    """Raised when a source artifact cannot produce a safe bounded projection."""


def _checked(schema: str, projected: dict[str, Any]) -> dict[str, Any]:
    errors = sorted(_VALIDATORS[schema].iter_errors(projected), key=lambda error: list(error.absolute_path))
    if errors:
        detail = "; ".join(
            f"/{'/'.join(str(part) for part in error.absolute_path)}: {error.message[:160]}" for error in errors[:3]
        )
        raise ContextProjectionError(f"projection violates {schema}: {detail}")
    return projected


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _bounded_line(value: str, limit: int = MAX_RECON_LINE_CHARS) -> str:
    compact = value.strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def _select_body_lines(body_lines: list[str], budget: int) -> list[str]:
    """Keep the ``budget`` most informative lines, in their original order.

    The cap used to take the first N lines, so whether a concrete finding
    survived depended only on where the scanner happened to write it. Measured
    on a full run, that discarded half of the lines naming a real file — the
    ones the architecture analyst can actually act on — while keeping prose
    that merely restates the section heading. Prefer lines carrying a source
    reference, then fill the rest in document order, so the same budget carries
    materially more evidence and the kept text still reads in sequence.
    """
    if budget <= 0:
        return []
    if len(body_lines) <= budget:
        return list(body_lines)
    indexed = list(enumerate(body_lines))
    ranked = sorted(indexed, key=lambda pair: (0 if _SOURCE_REFERENCE_RE.search(pair[1]) else 1, pair[0]))
    chosen = sorted(index for index, _ in ranked[:budget])
    return [body_lines[index] for index in chosen]


def project_recon_summary(payload: bytes) -> dict[str, Any]:
    """Project canonical Markdown headings and bounded non-empty body lines."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContextProjectionError("recon summary is not UTF-8") from exc
    source_lines = text.splitlines()
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in source_lines:
        heading = _HEADING_RE.match(raw_line)
        if heading:
            if len(sections) >= MAX_RECON_SECTIONS:
                raise ContextProjectionError(f"recon summary exceeds {MAX_RECON_SECTIONS} headings")
            current = {
                "heading": _bounded_line(heading.group(2), MAX_RECON_HEADING_CHARS),
                "level": len(heading.group(1)),
                "source_body_lines": [],
            }
            sections.append(current)
            continue
        if current is not None and raw_line.strip():
            current["source_body_lines"].append(raw_line)
    if not sections:
        raise ContextProjectionError("recon summary has no Markdown headings")

    retained_total = len(sections)
    projected: list[dict[str, Any]] = []
    for section in sections:
        level = section["level"]
        per_section_cap = 4 if level == 1 else (MAX_SECTION_LINES if level == 2 else 3)
        if level == 2 and section["heading"].endswith(COMPONENT_HINTS_HEADING):
            per_section_cap = MAX_COMPONENT_HINT_LINES
        available = max(0, MAX_RECON_RETAINED_LINES - retained_total)
        kept = _select_body_lines(section["source_body_lines"], min(per_section_cap, available))
        retained_total += len(kept)
        projected.append(
            {
                "heading": section["heading"],
                "level": level,
                "lines": [_bounded_line(line) for line in kept],
                "original_body_lines": len(section["source_body_lines"]),
                "omitted_body_lines": len(section["source_body_lines"]) - len(kept),
            }
        )

    return _checked(
        RECON_SCHEMA,
        {
            "schema_version": 1,
            "source": {
                "artifact_path": ".recon-summary.md",
                "sha256": _sha256(payload),
                "line_count": len(source_lines),
            },
            "limits": {
                "max_sections": MAX_RECON_SECTIONS,
                "max_retained_lines": MAX_RECON_RETAINED_LINES,
                "max_line_chars": MAX_RECON_LINE_CHARS,
                "retained_lines": retained_total,
                "omitted_body_lines": sum(row["omitted_body_lines"] for row in projected),
                "ordering_key": "source heading and line order",
            },
            "sections": projected,
        },
    )


def _route_order_key(route: dict[str, Any]) -> tuple[Any, ...]:
    method = str(route.get("method") or "")
    tags = route.get("relevance_tags") or []
    return (
        0 if route.get("management_surface") is True else 1,
        0 if route.get("missing_auth_suspect") is True else 1,
        0 if route.get("missing_authz_suspect") is True else 1,
        # An LLM endpoint is a trust boundary the architect cannot infer from
        # anything else in this projection: drop it and the model surface is
        # invisible for the rest of the run. Juice Shop's single `/rest/chat`
        # lost the cut at 96 of 247 routes on 2026-08-15, and with it every
        # prompt-injection, excessive-agency, and system-prompt-leak finding.
        0 if "llm" in tags else 1,
        0 if tags else 1,
        0 if method in _STATE_CHANGING else 1,
        0 if route.get("confidence") == "high" else (1 if route.get("confidence") == "medium" else 2),
        str(route.get("framework") or ""),
        str(route.get("handler_file") or ""),
        int(route.get("handler_line") or 0),
        str(route.get("route_id") or ""),
    )


def _route_group(route: dict[str, Any]) -> tuple[str, str]:
    path = Path(str(route.get("handler_file") or ""))
    first = path.parts[0] if path.parts else ""
    return str(route.get("framework") or "unknown"), first


def project_routes(payload: bytes) -> dict[str, Any]:
    """Retain risk-shaped routes plus framework/source-root diversity."""
    try:
        source = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContextProjectionError("route inventory is not valid JSON") from exc
    if not isinstance(source, dict) or source.get("version") != 1 or not isinstance(source.get("routes"), list):
        raise ContextProjectionError("route inventory does not match version 1")
    routes = source["routes"]
    if any(not isinstance(route, dict) for route in routes):
        raise ContextProjectionError("route inventory contains a non-object route")
    projectable = [route for route in routes if _valid_route(_projected_route(route))]
    ranked = sorted(projectable, key=_route_order_key)

    selected: list[dict[str, Any]] = ranked[: min(len(ranked), MAX_ROUTES // 2)]
    selected_ids = {id(route) for route in selected}
    seen_groups = {_route_group(route) for route in selected}
    for route in ranked:
        group = _route_group(route)
        if len(selected) >= MAX_ROUTES:
            break
        if group not in seen_groups:
            selected.append(route)
            selected_ids.add(id(route))
            seen_groups.add(group)
    for route in ranked:
        if len(selected) >= MAX_ROUTES:
            break
        if id(route) not in selected_ids:
            selected.append(route)
            selected_ids.add(id(route))
    selected.sort(key=_route_order_key)

    coverage = source.get("coverage") if isinstance(source.get("coverage"), dict) else {}
    unsupported_source = _list(coverage.get("unsupported_route_files"))
    unsupported = sorted({value for value in unsupported_source if _valid_unsupported_file(value)})
    frameworks = sorted({value for value in _list(coverage.get("frameworks_detected")) if _valid_framework(value)})
    return _checked(
        ROUTE_SCHEMA,
        {
            "schema_version": 1,
            "source": {
                "artifact_path": ".route-inventory.json",
                "sha256": _sha256(payload),
                "route_count": len(routes),
            },
            "limits": {
                "max_routes": MAX_ROUTES,
                "original_routes": len(routes),
                "retained_routes": len(selected),
                "omitted_routes": len(routes) - len(selected),
                "max_unsupported_route_files": MAX_UNSUPPORTED_ROUTE_FILES,
                "omitted_unsupported_route_files": len(unsupported_source)
                - len(unsupported[:MAX_UNSUPPORTED_ROUTE_FILES]),
                "ordering_key": "management,missing-auth,missing-authz,llm,relevance,state-change,confidence,framework,file,line,id",
                "diversity_key": "framework,top-level-handler-directory",
            },
            "coverage": {
                "frameworks_detected": frameworks[:MAX_FRAMEWORKS_DETECTED],
                "unsupported_route_files": unsupported[:MAX_UNSUPPORTED_ROUTE_FILES],
            },
            "routes": [_projected_route(route) for route in selected],
        },
    )


def _projected_route(route: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in route.items() if key in _PROJECTED_ROUTE_FIELDS}


def project_role_units(repo_root: Path) -> dict[str, Any]:
    """Bound the role-bearing units finalization requires as components."""
    from orchestrator.build_stride_dispatch_manifest import role_unit_candidates  # noqa: PLC0415

    candidates = role_unit_candidates(repo_root)
    units: list[dict[str, Any]] = []
    for card in candidates:
        if len(units) >= MAX_ROLE_UNITS:
            break
        paths = [path for path in dict.fromkeys(_list(card.get("paths"))) if _valid_role_unit_path(path)]
        unit = {
            "id": card.get("id"),
            "name": card.get("name"),
            "role": card.get("role"),
            "tier": card.get("tier"),
            "framework": card.get("framework"),
            "paths": paths[:MAX_ROLE_UNIT_PATHS],
            "omitted_paths": len(_list(card.get("paths"))) - len(paths[:MAX_ROLE_UNIT_PATHS]),
        }
        if _valid_role_unit(unit):
            units.append(unit)
    return _checked(
        ROLE_UNITS_SCHEMA,
        {
            "schema_version": 1,
            "limits": {
                "max_units": MAX_ROLE_UNITS,
                "max_paths": MAX_ROLE_UNIT_PATHS,
                "omitted_units": len(candidates) - len(units),
            },
            "units": units,
        },
    )


def build_role_units(output_dir: Path, repo_root: Path) -> Path:
    target = output_dir / ".dispatch-context" / "architecture" / "role-units.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(target, project_role_units(repo_root), sort_keys=False)
    return target


def topology_workloads(inventory: Any) -> list[dict[str, Any]]:
    """One row per workload name with platform-qualified zones, in name order.

    A name deployed on several platforms is one workload; its zones stay
    qualified by platform so a compose network and a namespace of the same
    name are not mistaken for one zone.
    """
    topology = inventory.get("topology") if isinstance(inventory, dict) else None
    rows = topology.get("workloads") if isinstance(topology, dict) else None
    bridging = {
        (row.get("name"), row.get("platform"))
        for row in (topology or {}).get("zone_bridging") or []
        if isinstance(row, dict)
    }
    by_name: dict[str, dict[str, Any]] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not row["name"]:
            continue
        platform = str(row.get("platform") or "")
        entry = by_name.setdefault(
            row["name"], {"name": row["name"], "zones": [], "zone_bridging": False, "definitions": []}
        )
        for zone in row.get("zones") or []:
            qualified = f"{platform}:{zone}"
            if isinstance(zone, str) and qualified not in entry["zones"]:
                entry["zones"].append(qualified)
        entry["zone_bridging"] = entry["zone_bridging"] or (row["name"], platform) in bridging
        definition = {"platform": platform, "source": row.get("source"), "line": row.get("line")}
        if isinstance(row.get("kind"), str):
            definition["kind"] = row["kind"]
        entry["definitions"].append(definition)
    for entry in by_name.values():
        entry["zones"].sort()
    return [by_name[name] for name in sorted(by_name)]


def project_topology(payload: bytes) -> dict[str, Any] | None:
    """Bound the deployable workloads, or ``None`` when the inventory has no topology."""
    try:
        inventory = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContextProjectionError("deployment inventory is not valid JSON") from exc
    workloads = topology_workloads(inventory)
    if not workloads:
        return None
    # A workload is never renamed to fit: the analyst cites names verbatim and
    # coverage compares them exactly, so an unprojectable one is omitted whole.
    kept: list[dict[str, Any]] = []
    for row in workloads:
        if len(kept) >= MAX_TOPOLOGY_WORKLOADS:
            break
        workload = {
            **row,
            "zones": [zone for zone in row["zones"] if _valid_zone(zone)][:MAX_WORKLOAD_ZONES],
            "definitions": [item for item in row["definitions"] if _valid_definition(item)][:MAX_WORKLOAD_DEFINITIONS],
        }
        if _valid_workload(workload):
            kept.append(workload)
    return _checked(
        TOPOLOGY_SCHEMA,
        {
            "schema_version": 1,
            "source": {"artifact_path": ".deployment-inventory.json", "sha256": _sha256(payload)},
            "limits": {
                "max_workloads": MAX_TOPOLOGY_WORKLOADS,
                "max_definitions": MAX_WORKLOAD_DEFINITIONS,
                "original_workloads": len(workloads),
                "omitted_workloads": len(workloads) - len(kept),
            },
            "workloads": kept,
        },
    )


def build_topology(output_dir: Path) -> Path | None:
    """Write the topology projection; remove a stale one when the run has none."""
    target = output_dir / TOPOLOGY_CONTEXT
    source = output_dir / ".deployment-inventory.json"
    projected = project_topology(source.read_bytes()) if source.is_file() else None
    if projected is None:
        target.unlink(missing_ok=True)
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(target, projected, sort_keys=False)
    return target


def build(output_dir: Path) -> tuple[Path, Path]:
    recon_path = output_dir / ".recon-summary.md"
    routes_path = output_dir / ".route-inventory.json"
    try:
        recon_payload = recon_path.read_bytes()
        routes_payload = routes_path.read_bytes()
    except OSError as exc:
        raise ContextProjectionError(f"cannot read architecture context source: {exc}") from exc
    target_dir = output_dir / ".dispatch-context" / "architecture"
    target_dir.mkdir(parents=True, exist_ok=True)
    recon_target = target_dir / "recon-summary-context.json"
    routes_target = target_dir / "route-context.json"
    atomic_write_json(recon_target, project_recon_summary(recon_payload), sort_keys=False)
    atomic_write_json(routes_target, project_routes(routes_payload), sort_keys=False)
    return recon_target, routes_target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, help="also project the role-bearing units of this repository")
    args = parser.parse_args(argv)
    try:
        recon, routes = build(args.output_dir.resolve())
    except ContextProjectionError as exc:
        print(f"build_architecture_analysis_context: {exc}", file=sys.stderr)
        return 1
    result = {"recon_context": str(recon), "route_context": str(routes)}
    try:
        topology = build_topology(args.output_dir.resolve())
    except ContextProjectionError as exc:
        print(f"build_architecture_analysis_context: {exc}", file=sys.stderr)
        return 1
    if topology is not None:
        result["topology_context"] = str(topology)
    if args.repo_root is not None:
        result["role_units"] = str(build_role_units(args.output_dir.resolve(), args.repo_root.resolve()))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
