#!/usr/bin/env python3
"""Build the Full-M1 STRIDE dispatch manifest from on-disk Stage-1 artifacts.

Hybrid handoff: this script assembles every per-component dispatch parameter
that IS deterministically derivable from disk (identity, paths, complexity,
max_turns, the per-component trust-boundary subset, the index/slice paths), and
merges the small set of CONTEXTUAL fields that only the analyst can supply
(interfaces, controls, known_*) from an optional analyst-context JSON. The
result, ``$OUTPUT_DIR/.stride-dispatch-manifest.json``, is validated by
``validate_dispatch_manifest.py`` and consumed by the skill's parallel
``appsec-stride-analyzer`` fan-out (Full-M1).

This minimises the LLM-authored surface to the contextual fields only — the
load-bearing identity/budget/path fields are deterministic and testable.

Usage:
    build_stride_dispatch_manifest.py <output_dir> --depth {quick,standard,thorough}
        [--analyst-context <path.json>] [--plugin-root <dir>]

The analyst-context JSON (optional) maps component_id → a dict of any of:
``interfaces``, ``controls``, ``known_secrets``, ``known_vulns``,
``known_llm_patterns``, ``supply_chain_findings``, ``estimated_threat_count``,
``focus_paths``, ``exclude_paths``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# max_turns per (depth, complexity) — single source of truth is
# resolve_config.DEPTH_PARAMS; imported when available, else a synced fallback
# (kept identical by tests/test_dispatch_manifest.py::test_depth_params_in_sync).
_FALLBACK_DEPTH_PARAMS = {
    "quick":    {"simple": 10, "moderate": 15, "complex": 20},
    "standard": {"simple": 15, "moderate": 22, "complex": 31},
    "thorough": {"simple": 20, "moderate": 28, "complex": 35},
}


def _depth_params() -> dict:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from resolve_config import DEPTH_PARAMS  # type: ignore

        return DEPTH_PARAMS
    except Exception:
        return _FALLBACK_DEPTH_PARAMS


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _trust_boundaries_for(component_id: str, all_boundaries: list) -> str:
    """Deterministic per-component trust-boundary summary string."""
    hits = []
    for b in all_boundaries:
        if not isinstance(b, dict):
            continue
        touches = (
            component_id == b.get("from")
            or component_id == b.get("to")
            or component_id in (b.get("components") or [])
        )
        if touches:
            name = b.get("name", b.get("id", "boundary"))
            enf = b.get("crossing_enforcement", "")
            hits.append(f"{name}: {enf}".strip().rstrip(":").strip())
    return " | ".join(hits) if hits else "No trust boundary directly tied to this component."


def build(output_dir: Path, depth: str, analyst_context: dict, plugin_root: Path) -> dict:
    import datetime as _dt

    dp = _depth_params()
    turns = dp.get(depth, dp.get("standard"))

    cj = _read_json(output_dir / ".components.json", {})
    components = cj.get("components", cj) if isinstance(cj, dict) else cj
    boundaries = (_read_json(output_dir / ".trust-boundaries.json", {}) or {}).get("trust_boundaries", [])

    out_components = []
    for c in components:
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        if not cid:
            continue
        ctx = analyst_context.get(cid, {}) if isinstance(analyst_context, dict) else {}
        complexity = (c.get("complexity") or "moderate").lower()

        def _idx(rel: str) -> str:
            p = output_dir / rel
            return str(p) if p.is_file() else "none"

        tax = output_dir / ".taxonomy-slices" / cid
        comp = {
            "component_id": cid,
            "component_name": c.get("name", cid),
            "component_description": c.get("description", ""),
            "component_paths": c.get("paths", []),
            "component_complexity": complexity if complexity in ("simple", "moderate", "complex") else "moderate",
            "max_turns": int(turns.get(complexity, turns.get("moderate", 22))),
            "trust_boundaries": _trust_boundaries_for(cid, boundaries),
            "taxonomy_slice_dir": str(tax) if tax.is_dir() else str(plugin_root / "data"),
            "index_paths": {
                "prior_findings": _idx(f".dispatch-context/{cid}/prior-findings.json"),
                "known_threats": _idx(f".dispatch-context/{cid}/known-threats.json"),
                "cross_repo": _idx(f".dispatch-context/{cid}/cross-repo.json"),
                "requirements_violations": _idx(f".dispatch-context/{cid}/requirements-violations.json"),
                "relevant_actors": _idx(f".actors-for-{cid}.json"),
            },
        }
        # Merge contextual (analyst-supplied) fields when present. The analyst
        # is an LLM and sometimes emits a richer dict shape (e.g. controls as a
        # {control: description} map) where the manifest schema + the STRIDE
        # analyzer expect a flat text string. Normalize dict-shaped text fields
        # to "key: value; ..." here at the deterministic LLM→schema boundary so
        # validate_dispatch_manifest.py does not reject the manifest.
        for k in ("interfaces", "controls", "known_secrets", "known_vulns",
                  "known_llm_patterns", "supply_chain_findings",
                  "estimated_threat_count", "focus_paths", "exclude_paths"):
            if k in ctx and ctx[k] not in (None, "", []):
                v = ctx[k]
                if isinstance(v, dict):
                    v = "; ".join(f"{kk}: {vv}" for kk, vv in v.items())
                comp[k] = v
        out_components.append(comp)

    return {
        "schema_version": 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stride_profile": analyst_context.get("_stride_profile", "full") if isinstance(analyst_context, dict) else "full",
        "components": out_components,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="build_stride_dispatch_manifest.py")
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--depth", default="standard", choices=["quick", "standard", "thorough"])
    ap.add_argument("--analyst-context", type=Path, default=None)
    ap.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    ns = ap.parse_args(argv)

    ctx = _read_json(ns.analyst_context, {}) if ns.analyst_context else {}
    manifest = build(ns.output_dir, ns.depth, ctx, ns.plugin_root)
    if not manifest["components"]:
        print("ERROR: no components found in .components.json — nothing to dispatch.", file=sys.stderr)
        return 1
    out = ns.output_dir / ".stride-dispatch-manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"OK: wrote {out} ({len(manifest['components'])} components, depth={ns.depth})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
