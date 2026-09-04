#!/usr/bin/env python3
"""Write the per-component requirements slice the STRIDE analyzers read.

`build_stride_dispatch_manifest.py` already looks for
`.dispatch-context/<cid>/requirements-violations.json` and
`build_stride_evidence_bundles.py` already projects it as the
`requirements.component_context` security context — but nothing ever wrote the
file, so the analyzers were told about a requirements input they never received
and could not populate `violated_requirements`.

This producer closes that gap. Requirements stay optional: with no
`.requirements.yaml` the script writes nothing and exits 0, leaving every
component index at "none" exactly as before.

Rows are grouped one per catalog category rather than one per requirement.
A category row carries its requirements whole, so all of them reach the
analyzer under the projection's 32-row cap instead of being truncated to the
first 32 requirements — and no applicability heuristic has to guess which
categories matter for a component. The analyzer judges applicability from each
category's own `applies_when` text.

A requirement also carries the blueprint section that prescribes how to
implement it, when the catalog declares one. Without it the blueprints reached
only the renderer, which appended them beside remediation steps written in
ignorance of them — the report then had to state that the two might differ and
that the blueprint won. The analyst that writes the steps is the place the
prescribed implementation has to arrive.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import requirements_trace
import yaml

# Mirrors MAX_VALUE_CHARS in build_stride_evidence_bundles.py. A row above it is
# truncated mid-JSON by the projection, which would corrupt requirement text, so
# oversized categories are split into several rows instead.
MAX_ROW_CHARS = 4096

# One prescribing section per requirement. The analyst needs the prescribed
# approach, not the whole blueprint, and this slice is charged per component.
MAX_GUIDANCE_PER_REQUIREMENT = 1


def _row_chars(row: dict[str, Any]) -> int:
    return len(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def _category_rows(
    category: dict[str, Any],
    guidance: dict[str, list[requirements_trace.BlueprintSection]] | None = None,
) -> list[dict[str, Any]]:
    """One row per category, split into parts when it would exceed the row cap."""
    guidance = guidance or {}
    requirements = []
    for r in category.get("requirements") or []:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").strip()
        if not rid:
            continue
        item: dict[str, Any] = {
            "id": rid,
            "priority": str(r.get("priority") or "").strip().upper(),
            "text": str(r.get("text") or "").strip(),
        }
        prescribed = [
            {"blueprint": s.blueprint_id, "section": s.title, "guidance": s.content}
            for s in guidance.get(rid, [])[:MAX_GUIDANCE_PER_REQUIREMENT]
            if s.content
        ]
        if prescribed:
            item["blueprint_guidance"] = prescribed
        requirements.append(item)
    if not requirements:
        return []

    def _build(items: list[dict[str, Any]], part: int, parts: int) -> dict[str, Any]:
        row = {
            "category_id": str(category.get("id") or "").strip(),
            "title": str(category.get("title") or "").strip(),
            "applies_when": str(category.get("context") or "").strip(),
            "requirements": items,
        }
        if parts > 1:
            row["part"] = f"{part} of {parts}"
        return row

    if _row_chars(_build(requirements, 1, 1)) <= MAX_ROW_CHARS:
        return [_build(requirements, 1, 1)]

    # Split into the fewest equal parts that fit.
    for parts in range(2, len(requirements) + 1):
        size = -(-len(requirements) // parts)
        chunks = [requirements[i : i + size] for i in range(0, len(requirements), size)]
        rows = [_build(chunk, n + 1, len(chunks)) for n, chunk in enumerate(chunks)]
        if all(_row_chars(row) <= MAX_ROW_CHARS for row in rows):
            return rows
    # One requirement per row is the finest split available; emit it even if a
    # single requirement's own text still exceeds the cap (the projection then
    # truncates that one value and records it).
    return [_build([item], n + 1, len(requirements)) for n, item in enumerate(requirements)]


def build_rows(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    guidance = requirements_trace.sections_by_requirement(catalog, limit=requirements_trace.MAX_ANALYST_SECTION_CHARS)
    rows: list[dict[str, Any]] = []
    for category in catalog.get("categories") or []:
        if isinstance(category, dict):
            rows.extend(_category_rows(category, guidance))
    return rows


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args(argv)

    output_dir = Path(args.output_dir).resolve()
    catalog_path = output_dir / ".requirements.yaml"
    components_path = output_dir / ".components.json"

    if not catalog_path.is_file():
        print("requirements-contexts: no .requirements.yaml — skipped (requirements are optional)")
        return 0
    if not components_path.is_file():
        print("requirements-contexts: no .components.json — skipped", file=sys.stderr)
        return 0

    try:
        catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"requirements-contexts: unreadable catalog: {exc}", file=sys.stderr)
        return 0
    try:
        components_doc = json.loads(components_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"requirements-contexts: unreadable components: {exc}", file=sys.stderr)
        return 0

    rows = build_rows(catalog)
    if not rows:
        print("requirements-contexts: catalog declares no requirements — skipped")
        return 0

    components = components_doc.get("components") if isinstance(components_doc, dict) else components_doc
    total = sum(len(row["requirements"]) for row in rows)
    written = 0
    for component in components or []:
        cid = str((component or {}).get("id") or "").strip()
        if not cid:
            continue
        target_dir = output_dir / ".dispatch-context" / cid
        target_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "component_id": cid,
            "description": (
                "Requirements the configured catalog holds this component to. "
                "Cite an id in violated_requirements only when the component's own "
                "evidence shows the requirement is broken. Where a requirement "
                "carries blueprint_guidance, that is the implementation the "
                "organisation prescribes: base remediation.steps on it and name "
                "the blueprint in remediation.blueprint."
            ),
            "items": rows,
        }
        (target_dir / "requirements-violations.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        written += 1

    guided = sum(1 for row in rows for r in row["requirements"] if r.get("blueprint_guidance"))
    print(
        f"requirements-contexts: {total} requirement(s) in {len(rows)} category row(s) "
        f"({guided} with blueprint guidance) → {written} component(s)"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
