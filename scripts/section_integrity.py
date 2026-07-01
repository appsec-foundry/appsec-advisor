#!/usr/bin/env python3
"""Per-section integrity matrix for a rendered threat model.

Goes through EVERY section of the rendered report and classifies it, so the
pipeline can guarantee two things at once:

  1. Every section that SHOULD be present (given the run's depth, conditional
     gates, and any deeper prior content that must be carried forward) actually
     IS present and substantive — not heading-only boilerplate.
  2. No section that a prior DEEPER run produced is silently dropped by a
     shallower re-run; if it was not re-analysed it must be CARRIED, not removed.

This unifies three previously-separate concerns — section condition gates,
completeness/substance, and depth-downgrade preservation — into one
deterministic per-section verdict.

Substrate: the composer already writes a per-section render manifest to
``.render-integrity.json`` (id, in_scope, outcome ∈ rendered|fallback|empty|
degraded|skipped_conditional). This script cross-references that manifest with
the contract's ``preserve_on_downgrade`` block and the run-start snapshot
manifest to decide, per section, whether its presence/absence is CORRECT.

Verdicts per section:
  ok-present     in-scope and rendered with substance
  ok-omitted     correctly absent (its condition gate is off and it is not a
                 deeper-prior section that needed carrying)
  ok-carried     a deep-only section carried forward from a deeper prior run
  FAIL-empty     in-scope but rendered only boilerplate / degraded
  FAIL-dropped   a deeper prior produced it and the current shallower run
                 dropped it instead of carrying it forward
  FAIL-missing   expected present but absent entirely

Exit 2 if any FAIL-* verdict is present, else 0. Writes the full matrix to
``.section-integrity.json`` and prints a human-readable table.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _atomic_io import atomic_write_json  # noqa: E402
from preserve_lib import depth_rank, preservable_sections  # noqa: E402

# Outcomes the composer emits that mean "present with real content".
_PRESENT_OK = {"rendered", "fallback"}
# Outcomes that mean "in scope but no substance" (a real gap).
_PRESENT_BAD = {"empty", "degraded"}


def _current_depth(output_dir: Path) -> str:
    """Read meta.assessment_depth from threat-model.yaml (root-aligned)."""
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        return ""
    import re

    try:
        text = yaml_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    m = re.search(r"(?m)^\s{2}assessment_depth:\s*[\"']?(\w+)", text)
    return m.group(1).strip().lower() if m else ""


def _snapshot_state(output_dir: Path) -> tuple[str, set[str]]:
    """Return (origin_depth, {section_ids captured in the snapshot})."""
    man_path = output_dir / ".appsec-cache" / "preserved-sections" / "manifest.json"
    if not man_path.is_file():
        return "", set()
    try:
        man = json.loads(man_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return "", set()
    origin = (man.get("origin_depth") or "").strip().lower()
    captured = {s.get("id") for s in (man.get("sections") or []) if s.get("captured")}
    # v1 manifest back-compat: AI captured flagged via has_ai_exposure.
    if not captured and man.get("has_ai_exposure"):
        captured = {"ai_exposure_ms"}
    return origin, captured


def _expected_section_ids(plugin_root: Path) -> list[str] | None:
    """Load the exact document-order IDs the composer must manifest."""
    try:
        import yaml

        contract = yaml.safe_load((plugin_root / "data" / "sections-contract.yaml").read_text(encoding="utf-8"))
        order = ((contract or {}).get("document") or {}).get("order")
        if not isinstance(order, list) or not order:
            return None
        ids = []
        for item in order:
            if isinstance(item, str):
                ids.append(item)
            elif isinstance(item, dict):
                ids.append(item.get("id"))
            else:
                return None
        if not all(isinstance(sid, str) and sid for sid in ids):
            return None
        return ids
    except (OSError, yaml.YAMLError, TypeError):
        return None


def _certificate_error(integrity: dict, sections: list[dict]) -> str:
    """Return a reason when aggregate certificate fields disagree with rows."""
    allowed_outcomes = {
        "rendered",
        "fallback",
        "empty",
        "degraded",
        "skipped_conditional",
    }
    for index, section in enumerate(sections):
        if not isinstance(section, dict):
            return f"section manifest entry {index} is not a mapping"
        if not isinstance(section.get("id"), str) or not section["id"]:
            return f"section manifest entry {index} has no valid id"
        if not isinstance(section.get("in_scope"), bool):
            return f"section manifest entry {index} has non-boolean in_scope"
        outcome = section.get("outcome")
        if outcome not in allowed_outcomes:
            return f"section manifest entry {index} has invalid outcome: {outcome!r}"
        for field in ("expected_fragments", "present_fragments"):
            value = section.get(field)
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                return f"section manifest entry {index} has invalid {field}"
        if section["in_scope"] == (outcome == "skipped_conditional"):
            return (
                f"section manifest entry {index} has inconsistent in_scope/outcome: {section['in_scope']!r}/{outcome!r}"
            )

    in_scope = [section for section in sections if section["in_scope"]]

    def count(outcome: str) -> int:
        return sum(section["outcome"] == outcome for section in in_scope)

    expected = {
        "sections_in_scope": len(in_scope),
        "sections_rendered": count("rendered"),
        "sections_fallback": count("fallback"),
        "sections_degraded": count("degraded"),
        "sections_empty": count("empty"),
        "sections_skipped_conditional": len(sections) - len(in_scope),
        "fragments_expected": sum(len(section.get("expected_fragments") or []) for section in in_scope),
        "fragments_wired": sum(len(section.get("present_fragments") or []) for section in in_scope),
    }
    expected["report_integrity_ok"] = expected["sections_degraded"] == 0 and expected["sections_empty"] == 0
    clean = expected["sections_rendered"] + expected["sections_fallback"]
    expected["integrity_pct"] = 100 if not in_scope else round(100 * clean / len(in_scope))
    expected["broken_sections"] = [section["id"] for section in in_scope if section["outcome"] in _PRESENT_BAD]

    for key, value in expected.items():
        if integrity.get(key) != value:
            return (
                f"render-integrity aggregate {key!r} is inconsistent "
                f"(expected={value!r}, actual={integrity.get(key)!r})"
            )
    return ""


def build_matrix(output_dir: Path, plugin_root: Path) -> dict:
    md_path = output_dir / "threat-model.md"
    if not md_path.is_file():
        return {"error": "threat-model.md missing or empty", "rows": []}
    try:
        if not md_path.read_text(encoding="utf-8").strip():
            return {"error": "threat-model.md missing or empty", "rows": []}
    except OSError:
        return {"error": "threat-model.md unreadable", "rows": []}
    integrity_path = output_dir / ".render-integrity.json"
    if not integrity_path.is_file():
        return {"error": "no .render-integrity.json — compose must run first", "rows": []}
    try:
        integrity = json.loads(integrity_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {"error": "unreadable .render-integrity.json", "rows": []}
    if not isinstance(integrity, dict) or integrity.get("schema_version") != 1:
        return {"error": "invalid .render-integrity.json schema/version", "rows": []}
    sections = integrity.get("sections")
    if not isinstance(sections, list) or not sections:
        return {"error": "empty .render-integrity.json section manifest", "rows": []}
    certificate_error = _certificate_error(integrity, sections)
    if certificate_error:
        return {"error": certificate_error, "rows": []}
    expected_ids = _expected_section_ids(plugin_root)
    if expected_ids is None:
        return {"error": "sections-contract.yaml missing or unreadable", "rows": []}
    actual_ids = [sec["id"] for sec in sections]
    if actual_ids != expected_ids:
        return {
            "error": (
                "render-integrity section manifest does not match document.order "
                f"(expected={expected_ids}, actual={actual_ids})"
            ),
            "rows": [],
        }
    cur_depth = _current_depth(output_dir)
    origin_depth, snap_captured = _snapshot_state(output_dir)
    # A deeper snapshot exists when the current run is strictly shallower than it.
    downgrade = origin_depth and depth_rank(origin_depth) > depth_rank(cur_depth)
    preservable = {s["id"] for s in preservable_sections(plugin_root)}

    rows = []
    for sec in sections:
        sid = sec.get("id")
        outcome = sec.get("outcome")
        in_scope = bool(sec.get("in_scope"))

        # Is this a deep-only section that THIS shallower run should have carried?
        should_carry = bool(downgrade and sid in preservable and sid in snap_captured)

        if in_scope:
            if outcome in _PRESENT_OK:
                verdict = "ok-carried" if should_carry else "ok-present"
            else:  # empty / degraded
                verdict = "FAIL-empty"
        else:
            # Skipped by a condition gate. Correct ONLY if it wasn't a deeper
            # prior section that needed carrying.
            verdict = "FAIL-dropped" if should_carry else "ok-omitted"

        rows.append(
            {
                "id": sid,
                "in_scope": in_scope,
                "outcome": outcome,
                "preservable": sid in preservable,
                "should_carry": should_carry,
                "verdict": verdict,
            }
        )

    failures = [r for r in rows if r["verdict"].startswith("FAIL")]
    return {
        "schema_version": 1,
        "current_depth": cur_depth,
        "snapshot_origin_depth": origin_depth,
        "downgrade": bool(downgrade),
        "ok": not failures,
        "failures": [r["id"] for r in failures],
        "rows": rows,
    }


def _print_matrix(m: dict) -> None:
    if m.get("error"):
        sys.stderr.write(f"section-integrity: {m['error']}\n")
        return
    hdr = f"  section-integrity matrix (depth={m['current_depth']}"
    if m["downgrade"]:
        hdr += f", downgrade from {m['snapshot_origin_depth']}"
    hdr += ")"
    sys.stdout.write(hdr + "\n")
    sys.stdout.write(f"  {'section':<28} {'scope':<6} {'outcome':<20} verdict\n")
    for r in m["rows"]:
        scope = "in" if r["in_scope"] else "out"
        mark = "✗" if r["verdict"].startswith("FAIL") else " "
        sys.stdout.write(f"  {mark} {r['id']:<26} {scope:<6} {str(r['outcome']):<20} {r['verdict']}\n")


def run(output_dir: Path, plugin_root: Path) -> int:
    m = build_matrix(output_dir, plugin_root)
    try:
        atomic_write_json(
            output_dir / ".section-integrity.json",
            m,
            indent=2,
            sort_keys=False,
        )
    except OSError:
        pass
    _print_matrix(m)
    if m.get("error"):
        return 2
    if not m["ok"]:
        sys.stderr.write(
            "section-integrity: FAIL — "
            + ", ".join(f"{r['id']}={r['verdict']}" for r in m["rows"] if r["verdict"].startswith("FAIL"))
            + "\n"
        )
        return 2
    sys.stdout.write(f"section-integrity: OK ({len(m['rows'])} sections, 0 failures)\n")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = p.parse_args()
    if not args.output_dir.is_dir():
        sys.stderr.write(f"section-integrity: output dir not found: {args.output_dir}\n")
        return 2
    return run(args.output_dir, args.plugin_root)


if __name__ == "__main__":
    raise SystemExit(main())
