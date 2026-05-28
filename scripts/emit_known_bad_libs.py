#!/usr/bin/env python3
"""Proposal 2 — emit known-bad-libs architectural meta-findings.

Walks manifests via scripts._lib_manifest and matches against
data/known-bad-libs.yaml. Each hit becomes an MF-NNN routed to §7.11
as an architectural-choice finding (not a CVE scan — see sca.md §6.2).

Severity is the per-entry `severity` field from the data file, capped
by asset_tier via data/sca-practice-severity.yaml ordering.

Output: $OUTPUT_DIR/.known-bad-libs-findings.json. Aggregator
(build_threat_model_yaml.py) merges with other meta-finding sidecars
into the final meta_findings[] list with deterministic MF-NNN ids.

Manifest-only (no lockfile walk) — the architectural choice is the
direct dep, not the transitive surface (sca.md §11).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

# Local sibling import — works when run as a script via the same scripts/ dir.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib_manifest import enumerate_deps  # noqa: E402


SEVERITY_ORDER = ("Informational", "Low", "Medium", "High", "Critical")


def _load_db(plugin_root: Path) -> dict:
    path = plugin_root / "data" / "known-bad-libs.yaml"
    if not path.is_file():
        return {"known_bad": []}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {"known_bad": []}
    except (yaml.YAMLError, OSError):
        return {"known_bad": []}


def _build_index(db: dict) -> dict[tuple[str, str], dict]:
    """Index `(ecosystem, package)` → entry. Names collide across
    ecosystems (npm `request` vs pip `requests`); the tuple key keeps
    matches strict."""
    out: dict[tuple[str, str], dict] = {}
    for entry in (db.get("known_bad") or []):
        if not isinstance(entry, dict):
            continue
        eco = (entry.get("ecosystem") or "").strip()
        pkg = (entry.get("package") or "").strip()
        if not eco or not pkg:
            continue
        out[(eco, pkg)] = entry
    return out


def _cap_by_tier(severity: str, tier: str) -> str:
    """Lower-tier assets get capped severity. Tier-4 caps at Medium; T3 at
    High; T1/T2 do not cap."""
    if tier == "T4":
        cap = "Medium"
    elif tier == "T3":
        cap = "High"
    else:
        return severity
    if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(cap):
        return cap
    return severity


def _normalize_tier(raw: str | None) -> str:
    import re
    if not raw:
        return "T2"
    m = re.search(r"\bT(?:ier\s*)?([1-4])\b", raw, re.IGNORECASE)
    return f"T{m.group(1)}" if m else "T2"


def run(repo_root: Path, output_dir: Path, asset_tier_raw: str | None, plugin_root: Path) -> int:
    tier = _normalize_tier(asset_tier_raw)
    db = _load_db(plugin_root)
    index = _build_index(db)
    if not index:
        # No DB loaded — write empty sidecar and exit zero (graceful).
        (output_dir / ".known-bad-libs-findings.json").write_text(
            json.dumps({"schema_version": 1, "findings": []}, indent=2), encoding="utf-8"
        )
        print("emit_known_bad_libs: known-bad-libs.yaml empty or unreadable — emitted 0 findings")
        return 0

    seen: set[tuple[str, str]] = set()
    findings: list[dict] = []
    for dep in enumerate_deps(repo_root):
        key = (dep.ecosystem, dep.package)
        if key in seen:
            continue
        entry = index.get(key)
        if not entry:
            continue
        seen.add(key)
        sev = _cap_by_tier(entry.get("severity", "Medium"), tier)
        findings.append(
            {
                "title": f"Library {dep.package} ({dep.ecosystem}) has known track record: {entry.get('category', 'unknown')}",
                "category": "Insufficient Patch Management",
                "summary": (
                    f"{entry.get('reason', '').strip()} "
                    f"The architectural choice to depend on this package warrants review "
                    f"regardless of which specific CVE is currently outstanding."
                ).strip(),
                "evidence": [{"file": dep.manifest, "line": dep.line}],
                "severity": sev,
                "control": "Library track-record review",
                "effectiveness": "Weak",
                "source": "known-bad-libs",
                "derived_from": [],
                "asset_tier": tier,
                "track_record_category": entry.get("category"),
            }
        )

    out_path = output_dir / ".known-bad-libs-findings.json"
    out_path.write_text(
        json.dumps({"schema_version": 1, "findings": findings}, indent=2, sort_keys=False),
        encoding="utf-8",
    )
    print(f"emit_known_bad_libs: tier={tier} → {len(findings)} architectural-choice finding(s) across {len(seen)} matched dep(s)")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Emit known-bad-libs architectural meta-findings")
    p.add_argument("--repo-root", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--asset-tier", default=None)
    p.add_argument("--plugin-root", default=None, type=Path)
    args = p.parse_args(argv)

    plugin_root = args.plugin_root or Path(__file__).resolve().parent.parent
    if not args.repo_root.is_dir():
        print(f"emit_known_bad_libs: repo-root not a directory: {args.repo_root}", file=sys.stderr)
        return 2
    if not args.output_dir.is_dir():
        print(f"emit_known_bad_libs: output-dir not a directory: {args.output_dir}", file=sys.stderr)
        return 2
    return run(args.repo_root, args.output_dir, args.asset_tier, plugin_root)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
