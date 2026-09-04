#!/usr/bin/env python3
"""Render the requirements-audit startup banner deterministically.

The audit skill must tell the user WHICH catalog is in effect and WHICH
requirements it is about to grade before it starts grading — that pass takes
minutes, and a silent wait leaves the user guessing what is being tested
(user 2026-08-27). Deriving the banner from JSON in the prompt made it
skippable; this module owns it, so the skill only prints what it emits.

Inputs, all produced earlier in the same run:
  * ``.requirements-resolution.json`` — source, disposition, freshness
  * ``.requirements.yaml``            — the loaded catalog
Reads nothing from the network and never fails the run: missing or malformed
inputs degrade to the lines that can be derived.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

RULE = "━" * 65
_MAX_CATEGORY_ROWS = 12
_PRIORITY_ORDER = ("MUST", "SHOULD", "MAY")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_catalog(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _age_days(stamp: str | None) -> int | None:
    """Whole days between an ISO 8601 stamp and now, or None when unusable."""
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - parsed).days)


def _date_only(stamp: str | None) -> str:
    return str(stamp).split("T", 1)[0] if stamp else ""


def _categories(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for cat in catalog.get("categories") or []:
        if not isinstance(cat, dict):
            continue
        reqs = [r for r in (cat.get("requirements") or []) if isinstance(r, dict)]
        out.append(
            {"id": (cat.get("id") or "").strip(), "title": (cat.get("title") or "").strip(), "requirements": reqs}
        )
    return out


def _matches_filter(cat: dict[str, Any], req: dict[str, Any], needle: str) -> bool:
    """The audit's category filter: a substring of the requirement or category ID."""
    if not needle:
        return True
    lowered = needle.lower()
    return lowered in (req.get("id") or "").lower() or lowered in cat["id"].lower()


def _priority_breakdown(reqs: list[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for req in reqs:
        counts[(req.get("priority") or "").strip().upper()] = (
            counts.get((req.get("priority") or "").strip().upper(), 0) + 1
        )
    parts = [f"{counts[p]} {p}" for p in _PRIORITY_ORDER if counts.get(p)]
    return " · ".join(parts)


def _loaded_line(resolution: dict[str, Any]) -> str:
    """Name the file the catalog bytes were actually read from this run."""
    disposition = (resolution.get("disposition") or "").strip()
    cache = resolution.get("cache_path") or ""
    url = resolution.get("url") or ""
    if disposition in {"cache", "cache_only", "cache_after_fetch_fail", "status", "skipped"}:
        return f"plugin cache {cache}" if cache else "plugin cache"
    if disposition == "fetched":
        return f"freshly fetched from {url} → cached at {cache}" if cache else f"freshly fetched from {url}"
    if resolution.get("demo"):
        return f"packaged example {url}"
    if (resolution.get("source_kind") or "") in {"local", "cli"} and url:
        return f"local file {url}"
    return url or "unknown"


def _freshness_line(resolution: dict[str, Any]) -> str:
    fresh = resolution.get("freshness") if isinstance(resolution.get("freshness"), dict) else {}
    if not fresh:
        return ""
    if fresh.get("stale"):
        return "🟡 STALE (cache ≥ 30 days) — refresh with --update"
    return "🟢 fresh (cache < 30 days)"


def build_banner(
    resolution: dict[str, Any],
    catalog: dict[str, Any],
    *,
    category_filter: str = "",
    gate_line: str = "",
) -> str:
    cats = _categories(catalog)
    graded = [(c, r) for c in cats for r in c["requirements"] if _matches_filter(c, r, category_filter)]
    total = sum(len(c["requirements"]) for c in cats) or int(resolution.get("count") or 0)

    lines = [RULE, " AppSec Requirements Audit", RULE, "Requirements Source"]
    catalog_name = (resolution.get("description") or resolution.get("label") or "").strip() or "requirements catalog"
    if resolution.get("demo"):
        catalog_name += "  ⚠ DEMO — not your organization's requirements"
    lines.append(f"  Catalog  : {catalog_name}")

    kind = (resolution.get("source_kind") or "").strip()
    url = (resolution.get("url") or "").strip()
    lines.append(f"  Source   : {' · '.join(x for x in (kind, url) if x) or 'unknown'}")
    lines.append(f"  Loaded   : {_loaded_line(resolution)}")

    fetched = _date_only(resolution.get("fetched_at"))
    if fetched:
        age = _age_days(resolution.get("fetched_at"))
        stamp = f"{fetched} ({age} days ago)" if age is not None else fetched
        generated = _date_only(resolution.get("generated"))
        lines.append(f"  Fetched  : {stamp}" + (f" · catalog generated {generated}" if generated else ""))

    count_line = f"{total} requirements"
    if cats:
        count_line += f" in {len(cats)} categories"
    lines.append(f"  Count    : {count_line}")

    freshness = _freshness_line(resolution)
    if freshness:
        lines.append(f"  Freshness: {freshness}")
    if resolution.get("surfaced"):
        lines.append("  Note     : using local repo catalog (overrides org profile)")
    if (resolution.get("disposition") or "") == "cache_after_fetch_fail":
        lines.append("  Note     : source unreachable this run — served the cached copy")
    if gate_line:
        lines.append(f"  Gate     : {gate_line}")
    lines.append(
        "  Override : --update (refresh) · --cache-only · --demo · "
        "--requirements <url> · --status · --clear-requirements"
    )

    if not cats:
        return "\n".join(lines)

    graded_ids = {id(r) for _c, r in graded}
    lines.append("")
    scope = f"Scope (grading {len(graded)} of {total} requirements"
    scope += f", filter '{category_filter}')" if category_filter else ")"
    lines.append(scope)
    shown = 0
    skipped = 0
    for cat in cats:
        in_scope = [r for r in cat["requirements"] if id(r) in graded_ids]
        if not in_scope:
            continue
        if shown >= _MAX_CATEGORY_ROWS:
            skipped += 1
            continue
        label = cat["title"] or cat["id"] or "(unnamed)"
        breakdown = _priority_breakdown(in_scope)
        row = f"  {label[:38]:<38} {len(in_scope):>3}"
        lines.append(f"{row}  ({breakdown})" if breakdown else row)
        shown += 1
    if skipped:
        lines.append(f"  … and {skipped} further categor{'y' if skipped == 1 else 'ies'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="render_requirements_banner.py",
        description="Print the requirements-audit startup banner from the resolved run state.",
    )
    p.add_argument(
        "--output-dir", required=True, help="directory holding .requirements-resolution.json / .requirements.yaml"
    )
    p.add_argument(
        "--filter", default="", help="category filter applied to this run (substring of requirement/category ID)"
    )
    p.add_argument("--gate-line", default="", help="effective gate policy, rendered as the Gate line when given")
    args = p.parse_args(argv)

    out = Path(args.output_dir)
    resolution = _load_json(out / ".requirements-resolution.json")
    catalog = _load_catalog(out / ".requirements.yaml")
    if not resolution and not catalog:
        print(f"error: no requirements state in {out}", file=sys.stderr)
        return 1
    print(build_banner(resolution, catalog, category_filter=args.filter, gate_line=args.gate_line))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
