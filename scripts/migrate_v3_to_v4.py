#!/usr/bin/env python3
"""migrate_v3_to_v4.py — convert a flat v1 threat-model.yaml (analysis_version=1)
to the two-level v2 schema (analysis_version=2, threat_categories[] + findings[]).

Rules:
  - Every `threats[N]` entry becomes a `findings[N]` entry with the same scenario,
    evidence, risk, and CWE, plus a new `threat_category_id` derived from the
    CWE via threat-category-taxonomy.yaml.
  - `T-NNN` IDs are preserved as `legacy_id` on each finding; new `F-NNN` IDs
    are assigned by zero-padded sequence (1:1 in simple migrations, with
    consolidation gaps when two T-IDs mapped to one canonical finding).
  - `threat_categories[]` is built by aggregating findings per TH-NN: max_risk,
    max_cvss, finding_count, stride_present, mitigation_ids (union of child
    mitigation refs).
  - `meta.analysis_version` bumps 1 → 2 and `meta.legacy_id_map` is written.
  - Non-migrating fields (components[], mitigations[], security_controls[],
    changelog[], assets[], attack_surface[], trust_boundaries[], etc.) are
    copied unchanged.

Usage:
    migrate_v3_to_v4.py <input-yaml> <output-yaml>

Exit codes:
    0 — success
    2 — malformed input
    3 — already v2 (nothing to do; script is idempotent-safe)
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml  # noqa: F401  (kept for explicit ImportError message)
except ImportError:
    sys.exit("migrate_v3_to_v4: PyYAML required")

import _yaml_io

PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", "")).resolve() or None
if not PLUGIN_ROOT or not PLUGIN_ROOT.is_dir():
    # Fallback: relative to this script
    PLUGIN_ROOT = Path(__file__).resolve().parent.parent

TAX_PATH = PLUGIN_ROOT / "data" / "threat-category-taxonomy.yaml"
CWE_PATH = PLUGIN_ROOT / "data" / "cwe-taxonomy.yaml"


def load_yaml(p: Path):
    return _yaml_io.load_yaml(p)


def assign_category(
    primary_cwe: str | None, scenario: str, stride: str, cwe_to_th: dict, categories: list[dict]
) -> tuple[str, list[str]]:
    """Return (primary_th_id, additional_categories)."""
    if primary_cwe and primary_cwe in cwe_to_th:
        ths = cwe_to_th[primary_cwe]
        return ths[0], ths[1:]
    # Keyword fallback
    s = scenario.lower()
    for cat in categories:
        for kw in cat.get("typical_findings", []) or []:
            if kw.lower() in s:
                return cat["id"], []
    # STRIDE fallback
    stride_norm = stride.strip()
    for cat in categories:
        if stride_norm in (cat.get("stride") or []):
            return cat["id"], []
    # Last resort
    return "TH-UNCLASSIFIED", []


def aggregate_categories(findings: list[dict], taxonomy: dict, cwe_tax: dict, mitigations: list[dict]) -> list[dict]:
    """Build threat_categories[] entries for every TH with ≥1 primary finding."""
    categories_map = {c["id"]: c for c in taxonomy["categories"]}
    # Primary-only lookup
    primary_by_th = defaultdict(list)
    for f in findings:
        primary_by_th[f["threat_category_id"]].append(f)

    risk_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    result = []
    for th_id, th_findings in sorted(primary_by_th.items()):
        cat_tax = categories_map.get(th_id, {})
        max_risk = max((f["risk"] for f in th_findings), key=lambda r: risk_rank.get(r, 0))
        cvss_list = [(f.get("cvss_v3_1") or {}).get("score") for f in th_findings]
        cvss_list = [c for c in cvss_list if isinstance(c, (int, float))]
        max_cvss = max(cvss_list) if cvss_list else None
        stride_present = sorted({f["stride"] for f in th_findings})
        # Mitigations — union of finding mitigation_ids (primary only)
        mit_ids = sorted({mid for f in th_findings for mid in (f.get("mitigation_ids") or [])})
        # Risk distribution (primary only — matches finding_count)
        risk_dist = defaultdict(int)
        for f in th_findings:
            risk_dist[f["risk"]] += 1
        # Find pillar info + OWASP
        owasp_a = cat_tax.get("owasp_top10_2025")
        pillar = cat_tax.get("cwe_pillar")
        canonical = cat_tax.get("cwe_canonical")
        top25_members = cat_tax.get("cwe_top25_members", []) or []
        # Presence-of-top25 in actual findings
        top25_in_findings = [f["id"] for f in th_findings if any(c in top25_members for c in (f.get("cwe") or []))]

        # Also collect findings that touch this category via additional_categories (secondary)
        secondary_ids = sorted(
            [
                f["id"]
                for f in findings
                if th_id in (f.get("additional_categories") or []) and f["threat_category_id"] != th_id
            ]
        )
        entry = {
            "id": th_id,
            "title": cat_tax.get("title", th_id),
            "description": cat_tax.get("description", ""),
            "stride_present": stride_present,
            "cwe_pillar": pillar,
            "cwe_canonical": canonical,
            "cwe_top25_members_present": top25_members
            and any(c in top25_members for f in th_findings for c in (f.get("cwe") or [])),
            "owasp_top10_2025": owasp_a,
            "owasp_asvs": cat_tax.get("owasp_asvs"),
            "aggregated": {
                "max_risk": max_risk,
                "max_cvss": max_cvss,
                "finding_count": len(th_findings),
                "risk_distribution": dict(risk_dist),
                "stride_present": stride_present,
            },
            "mitigation_ids": mit_ids,
            "finding_ids": sorted([f["id"] for f in th_findings]),
            "secondary_finding_ids": secondary_ids,
        }
        if top25_in_findings:
            entry["cwe_top25_finding_ids"] = sorted(set(top25_in_findings))
        result.append(entry)

    # Sort by max_cvss desc → finding_count desc → TH-ID asc
    def sort_key(c):
        mc = c["aggregated"]["max_cvss"] or 0
        return (-mc, -c["aggregated"]["finding_count"], c["id"])

    result.sort(key=sort_key)
    return result


def migrate(doc: dict) -> dict:
    meta = doc.get("meta") or {}
    current_version = meta.get("analysis_version", 1)
    if current_version >= 2 and "findings" in doc and "threat_categories" in doc:
        print("migrate_v3_to_v4: input already analysis_version=2 — nothing to do", file=sys.stderr)
        sys.exit(3)

    taxonomy = load_yaml(TAX_PATH)
    cwe_to_th = taxonomy["cwe_to_th"]
    cwe_tax = load_yaml(CWE_PATH)

    # -- Build findings[] from threats[]
    threats = doc.get("threats") or []
    if not threats:
        print("migrate_v3_to_v4: input has no threats[] — nothing to migrate", file=sys.stderr)
        sys.exit(2)

    findings = []
    legacy_map = {}
    for i, t in enumerate(threats, start=1):
        t_id = t["id"]  # e.g. T-009
        f_id = f"F-{t_id.split('-')[1]}"  # F-009
        legacy_map[t_id] = f_id
        cwes = t.get("cwe") or []
        primary_cwe = cwes[0] if cwes else None
        stride = t.get("stride", "")
        scenario = t.get("scenario", "")
        th_id, additional = assign_category(primary_cwe, scenario, stride, cwe_to_th, taxonomy["categories"])
        finding = {
            "id": f_id,
            "legacy_id": t_id,
            "threat_category_id": th_id,
            "component": t.get("component"),
            "stride": stride,
            "scenario": scenario,
            "likelihood": t.get("likelihood"),
            "impact": t.get("impact"),
            "risk": t.get("risk"),
            "cvss_v3_1": t.get("cvss_v3_1"),
            "cwe": cwes,
            "controls_in_place": t.get("controls_in_place"),
            "mitigation_ids": t.get("mitigation_ids") or [],
            "classification": t.get("classification"),
        }
        # Add CWE Top 25 rank when available
        if primary_cwe:
            cwe_entry = cwe_tax["cwes"].get(primary_cwe)
            if cwe_entry and cwe_entry.get("cwe_top25_2024"):
                finding["cwe_top25_rank"] = cwe_entry["cwe_top25_2024"]
        if additional:
            finding["additional_categories"] = additional
        findings.append(finding)

    # -- Build threat_categories[] aggregates
    threat_categories = aggregate_categories(findings, taxonomy, cwe_tax, doc.get("mitigations") or [])

    # -- Update mitigations[] to reference categories (primary) + evidence findings
    for m in doc.get("mitigations") or []:
        addresses = m.get("addresses") or []
        # Convert addresses = [T-NNN, ...] to addresses_findings = [F-NNN, ...]
        m["addresses_findings"] = sorted({legacy_map.get(t, t) for t in addresses})
        # Collect category set
        categories_for_m = sorted({f["threat_category_id"] for f in findings if f["id"] in m["addresses_findings"]})
        m["addresses_categories"] = categories_for_m
        # Keep legacy `addresses` for traceability but mark it
        m["legacy_addresses_t_ids"] = addresses

    # -- Update security_controls[] similarly
    for sc in doc.get("security_controls") or []:
        legacy_threats = sc.get("mitigates_findings") or []  # Phase-2 field name
        converted = [legacy_map.get(t, t) if t.startswith("T-") else t for t in legacy_threats]
        sc["mitigates_findings"] = converted

    # -- Bump analysis_version + write legacy_id_map
    meta["analysis_version"] = 2
    meta["legacy_id_map"] = legacy_map
    meta["schema_notes"] = (
        "Migrated from analysis_version=1 flat threats[] to v2 "
        "threat_categories[] + findings[]. F-IDs are the canonical identifiers; "
        "T-IDs retained as findings[].legacy_id and in meta.legacy_id_map for "
        "backward compatibility with v1-era integrations."
    )
    doc["meta"] = meta

    # -- Replace threats[] with findings[] + threat_categories[]
    doc["findings"] = findings
    doc["threat_categories"] = threat_categories
    doc["threats_legacy"] = threats  # keep for one cycle; remove in a future version
    del doc["threats"]

    return doc


def main():
    p = argparse.ArgumentParser(description="Migrate threat-model.yaml v1 → v2")
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    args = p.parse_args()

    doc = load_yaml(args.input)
    migrated = migrate(doc)

    args.output.write_text(
        yaml.safe_dump(migrated, sort_keys=False, allow_unicode=True, default_flow_style=False, width=10_000)
    )
    print(f"migrate_v3_to_v4: wrote {args.output}")
    print(f"  findings:           {len(migrated['findings'])}")
    print(f"  threat_categories:  {len(migrated['threat_categories'])}")
    unclass = sum(1 for f in migrated["findings"] if f["threat_category_id"] == "TH-UNCLASSIFIED")
    if unclass:
        print(
            f"  WARN: {unclass} findings remain TH-UNCLASSIFIED — extend threat-category-taxonomy.yaml", file=sys.stderr
        )


if __name__ == "__main__":
    main()
