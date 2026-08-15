#!/usr/bin/env python3
"""Build bounded, exact-source-bound inputs for semantic architecture work."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from _atomic_io import atomic_write_json

MAX_RECON_SECTIONS = 64
MAX_RECON_RETAINED_LINES = 200
MAX_RECON_LINE_CHARS = 500
MAX_ROUTES = 96
MAX_UNSUPPORTED_ROUTE_FILES = 64

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class ContextProjectionError(ValueError):
    """Raised when a source artifact cannot produce a safe bounded projection."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _bounded_line(value: str) -> str:
    compact = value.strip()
    if len(compact) <= MAX_RECON_LINE_CHARS:
        return compact
    return compact[: MAX_RECON_LINE_CHARS - 1].rstrip() + "…"


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
                "heading": heading.group(2),
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
        per_section_cap = 4 if level == 1 else (8 if level == 2 else 3)
        available = max(0, MAX_RECON_RETAINED_LINES - retained_total)
        kept = section["source_body_lines"][: min(per_section_cap, available)]
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

    return {
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
    }


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
    ranked = sorted(routes, key=_route_order_key)

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
    unsupported = sorted(
        value for value in coverage.get("unsupported_route_files", []) if isinstance(value, str) and value
    )
    return {
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
            "omitted_unsupported_route_files": max(0, len(unsupported) - MAX_UNSUPPORTED_ROUTE_FILES),
            "ordering_key": "management,missing-auth,missing-authz,llm,relevance,state-change,confidence,framework,file,line,id",
            "diversity_key": "framework,top-level-handler-directory",
        },
        "coverage": {
            "frameworks_detected": sorted(
                value for value in coverage.get("frameworks_detected", []) if isinstance(value, str) and value
            )[:32],
            "unsupported_route_files": unsupported[:MAX_UNSUPPORTED_ROUTE_FILES],
        },
        "routes": selected,
    }


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
    args = parser.parse_args(argv)
    try:
        recon, routes = build(args.output_dir.resolve())
    except ContextProjectionError as exc:
        print(f"build_architecture_analysis_context: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"recon_context": str(recon), "route_context": str(routes)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
