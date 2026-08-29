#!/usr/bin/env python3
"""Carry the report's requirement and blueprint trace back into ``threat-model.yaml``.

``mitigations[].fulfills_requirements`` is derived at Stage 1 from what the
threats declare. The §10 mitigation register adds one source the structured
model cannot have yet: the §7b compliance assessment's own evidence citations,
which only exist once Stage 2 has authored
``.fragments/requirements-compliance.md``.

Without this step the two artifacts of one run name different requirement sets
for the same mitigation — in a measured run, 22 of 55 mitigations diverged and
several pairs were disjoint, so a consumer reading the YAML (SARIF export,
``review-threat-model``, ``ask-threat-model``) got a different answer from a
reader of the report. This emitter makes the YAML the superset: the rendered
block stays a filtered view of it, showing only requirements the §7b table
marked FAIL / PARTIAL / ANTI-PATTERN, never a requirement the model lacks.

``mitigations[].blueprint`` is recomputed from the completed requirement list
for the same reason: a blueprint chosen from a partial list is not the one the
report shows.

Runs AFTER ``compose_threat_model.py``: the composer is read-only for
``threat-model.yaml`` (``test_analysis_version_upgrade`` pins that a render
never rewrites the model), and the §7b fragment is only guaranteed present and
schema-valid once compose has accepted it. Must run BEFORE cleanup reaps
``.fragments/``.

The same post-compose pass also persists the complete §7b assessment as
``requirements_compliance``. A configured catalog therefore fails closed when
the fragment is missing, malformed, or incomplete; otherwise the Markdown and
machine-readable contracts could disagree after a successful run.

Idempotent — a second run against unchanged inputs rewrites nothing.

Usage:
    python3 emit_requirement_trace_to_model.py <output_dir>
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import requirements_trace
import yaml
from _atomic_io import atomic_write_text
from build_threat_model_yaml import (
    RequirementsComplianceError,
    build_requirements_compliance,
)
from validate_intermediate import validate_threat_model_output


def build_trace(output_dir: Path, doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Mitigation ID → the fields this emitter would write.

    Returns ``{}`` when no requirements catalog is configured, so a run without
    requirements is untouched.
    """
    catalog = requirements_trace.load_catalog(output_dir)
    if not catalog:
        return {}

    import compose_threat_model as compose

    ctx = compose.RenderContext(
        output_dir=Path(output_dir),
        contract={},
        yaml_data=doc,
        triage={},
        fragments_dir=Path(output_dir) / ".fragments",
    )
    # The composer owns the derivation; reuse it rather than re-deriving, so
    # the persisted list and the rendered block cannot disagree.
    known_ids = compose._known_requirement_ids(ctx)
    evidence_reqs = compose._findings_evidence_requirements_map(ctx)
    threats = doc.get("threats") or []
    threats_by_id = {(t.get("t_id") or t.get("id") or "").strip().upper(): t for t in threats}
    by_requirement = requirements_trace.sections_by_requirement(catalog)

    out: dict[str, dict[str, Any]] = {}
    for m in doc.get("mitigations") or []:
        mid = str(m.get("id") or "").strip()
        if not mid:
            continue
        fulfills = compose.mitigation_requirement_ids(m, threats_by_id, known_ids, evidence_reqs)
        entry: dict[str, Any] = {}
        if fulfills:
            entry["fulfills_requirements"] = fulfills
        addressed = [
            threats_by_id.get((tid or "").strip().upper()) or {}
            for tid in (m.get("addresses") or m.get("threat_ids") or [])
        ]
        selected = requirements_trace.select_blueprint(
            by_requirement,
            fulfills,
            requirements_trace.RankContext(
                primary=str(m.get("title") or ""),
                secondary=" ".join(f"{t.get('title') or ''} {t.get('scenario') or ''}" for t in addressed),
            ),
        )
        if selected is not None:
            top = selected.sections[0] if selected.sections else None
            entry["blueprint"] = {
                "id": selected.blueprint_id,
                "title": selected.blueprint_title,
                "url": selected.blueprint_url,
                "section": top.title if top else "",
                "section_url": top.url if top else "",
                "guidance": top.content if top else "",
                "prescribed_by": list(selected.requirement_ids),
                "grounded": selected.is_grounded,
            }
        if entry:
            out[mid] = entry
    return out


def emit(output_dir: Path) -> str:
    """Merge the trace into the model. Returns a short status for the log line."""
    yaml_path = Path(output_dir) / "threat-model.yaml"
    try:
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RequirementsComplianceError(f"cannot read threat-model.yaml: {exc}") from exc
    if not isinstance(doc, dict):
        raise RequirementsComplianceError("threat-model.yaml is not a mapping")

    catalog_path = Path(output_dir) / ".requirements.yaml"
    if not catalog_path.is_file():
        return "no requirements catalog — nothing to do"

    trace = build_trace(Path(output_dir), doc)
    compliance = build_requirements_compliance(Path(output_dir), strict=True)
    if compliance is None:  # strict mode guarantees a value or raises
        raise RequirementsComplianceError("configured requirements compliance was not produced")

    changed = 0
    for m in doc.get("mitigations") or []:
        entry = trace.get(str(m.get("id") or "").strip())
        if not entry:
            continue
        for key, value in entry.items():
            if m.get(key) != value:
                m[key] = value
                changed += 1
    if doc.get("requirements_compliance") != compliance:
        doc["requirements_compliance"] = compliance
        changed += 1
    if not changed:
        return "unchanged"
    ok, errors = validate_threat_model_output(doc)
    if not ok:
        raise RequirementsComplianceError("updated threat-model.yaml is invalid: " + "; ".join(errors[:5]))
    atomic_write_text(
        yaml_path,
        # Same dump options as build_threat_model_yaml.py so re-serialising
        # here does not reformat the whole file.
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120),
    )
    return f"written ({changed} field(s) across {len(trace)} mitigation(s))"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: emit_requirement_trace_to_model.py <output_dir>", file=sys.stderr)
        return 2
    try:
        status = emit(Path(argv[0]))
    except (OSError, yaml.YAMLError, RequirementsComplianceError) as exc:
        print(f"emit_requirement_trace_to_model: failed — {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"emit_requirement_trace_to_model: {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
