#!/usr/bin/env python3
"""M-4: Emit cross-cutting architectural meta-findings (MF-NNN).

Reads `$OUTPUT_DIR/threat-model.yaml`, aggregates threats by `source`, and
injects a `meta_findings[]` block when the aggregated count crosses a
threshold:

  ≥2 source=dep-scan threats           → "Insufficient Patch Management"
  ≥2 source=configuration-defect       → "Insufficient Secret Management"

Each meta-finding has its own MF-NNN id (separate ID space from T-NNN, so
the contiguity invariant in validate_intermediate._check_t_id_sequence is
unaffected), and links back to the underlying T-NNN list via
`derived_from`.

Idempotent — re-running rewrites the meta_findings list from current
threats[]. Hand-authored entries with `manual: true` are preserved verbatim.

Usage:
    python3 emit_meta_findings.py <output_dir>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

META_CATEGORIES: list[dict] = [
    {
        "source_match": "dep-scan",
        "min_count": 2,
        "title": "Insufficient Patch Management",
        "category": "Insufficient Patch Management",
        "summary_template": (
            "{count} {finding_word} trace to outdated dependencies with published "
            "CVEs. The architectural concern is not the individual libraries — "
            "they can be upgraded — but the absence of a dependency-update "
            "process: no SLA on advisory-to-upgrade time, no scheduled SCA "
            "scan in CI, no documented owner. Patching individual libraries "
            "addresses symptoms; instituting the process addresses the gap."
        ),
        "severity": "High",
    },
    {
        "source_match": "configuration-defect",
        "min_count": 2,
        "title": "Insufficient Secret Management",
        "category": "Insufficient Secret Management",
        "summary_template": (
            "{count} {finding_word} trace to secrets, keys, or tokens stored "
            "directly in source code. The architectural concern is not the "
            "individual values — they can be rotated — but the absence of a "
            "secret-management substrate: no env-var convention, no vault/KMS "
            "integration, no pre-commit scan. Rotating individual secrets "
            "addresses symptoms; instituting the substrate addresses the gap."
        ),
        "severity": "High",
    },
]


_MF_ID_RE = re.compile(r"^MF-(\d{3,})$")


def _next_counter_after_manual(manual: list[dict]) -> int:
    highest = 0
    for entry in manual:
        mid = (entry.get("id") or "").strip()
        match = _MF_ID_RE.fullmatch(mid)
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def _emit_meta_findings(yaml_data: dict) -> list[dict]:
    """Compute the meta_findings[] list from the current threats[] population.

    Preserves any hand-authored entries (entries with `manual: true`) at the
    head of the list so operators can pin additional process gaps.
    """
    threats = yaml_data.get("threats") or []
    if not isinstance(threats, list):
        threats = []

    # Group T-NNNs by source.
    by_source: dict[str, list[str]] = {}
    for t in threats:
        if not isinstance(t, dict):
            continue
        src = (t.get("source") or "").strip()
        tid = (t.get("id") or "").strip()
        if src and tid.startswith("T-"):
            by_source.setdefault(src, []).append(tid)

    # Preserve hand-authored entries (if any).
    existing = yaml_data.get("meta_findings") or []
    if not isinstance(existing, list):
        existing = []
    manual = [m for m in existing if isinstance(m, dict) and m.get("manual")]

    out: list[dict] = list(manual)
    counter = _next_counter_after_manual(manual)
    for spec in META_CATEGORIES:
        src = spec["source_match"]
        tids = sorted(by_source.get(src, []))
        if len(tids) < spec["min_count"]:
            continue
        mf_id = f"MF-{counter:03d}"
        counter += 1
        out.append(
            {
                "id": mf_id,
                "title": spec["title"],
                "category": spec["category"],
                "summary": spec["summary_template"].format(
                    count=len(tids),
                    finding_word="finding" if len(tids) == 1 else "findings",
                ),
                "derived_from": tids,
                "severity": spec["severity"],
                "recommended_mitigation_id": None,
            }
        )
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: emit_meta_findings.py <output_dir>", file=sys.stderr)
        return 2
    output_dir = Path(argv[0])
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"emit_meta_findings: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"emit_meta_findings: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"emit_meta_findings: {yaml_path} did not parse to a mapping", file=sys.stderr)
        return 1

    meta_findings = _emit_meta_findings(data)
    if meta_findings:
        data["meta_findings"] = meta_findings
    else:
        # Drop empty list to keep the YAML clean.
        data.pop("meta_findings", None)

    yaml_path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
        encoding="utf-8",
    )
    print(f"emit_meta_findings: wrote {len(meta_findings)} meta-finding(s) to {yaml_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
