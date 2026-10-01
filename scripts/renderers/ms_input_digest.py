#!/usr/bin/env python3
"""Bounded input digest for the Management-Summary renderer.

The renderer used to assemble its inputs itself: paged reads of a
half-megabyte ``threat-model.yaml`` plus greps for titles, CWEs and risk
fields, each turn re-reading a growing context. This writes the fields its
owned fragments need once, deterministically, to
``.dispatch-context/stage2/ms-input.json``.

Every rule is delegated, never re-implemented: concern colour, citable basis
and the Critical floor come from ``renderers._severity_rollup`` (the rules the
compactness gate checks), the attack class from the composer's fallback
classifier, and the LLM surface from the deterministic AI-exposure generator.
The digest never carries a decision the renderer must not change; it is a
read-only index of the model.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

import renderers._severity_rollup as rollup
import renderers.compose_threat_model as compose
import renderers.pregenerate_fragments as pregen

DIGEST_RELPATH = Path(".dispatch-context") / "stage2" / "ms-input.json"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "ms-input-digest.schema.json"
#: Byte ceiling: a twentieth of the model it replaces on a large run, and small
#: enough to stay one Read. Over it, the least severe rows go first.
MAX_BYTES = 48_000
_DETAILED = ("Critical", "High")
_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_TITLE_MAX = 120
_IMPACT_MAX = 240


def _text(value: Any, limit: int) -> str:
    s = " ".join(str(value or "").split())
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def _ids(value: Any) -> list[str]:
    return [str(v) for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _sparse(row: dict) -> dict:
    """Drop empty optional values; ``ref``, ``severity`` and ``title`` always stay."""
    keep = {"ref", "severity", "title"}
    return {k: v for k, v in row.items() if k in keep or v not in ("", [], 0, False, None)}


def build_digest(yaml_data: dict, triage: dict | None = None) -> dict:
    """Return the digest for one model; deterministic for identical input."""
    components = [c for c in yaml_data.get("components") or [] if isinstance(c, dict)]
    cref = {c.get("id"): "C-%02d" % (i + 1) for i, c in enumerate(components) if c.get("id")}
    llm_components = {c.get("id") for c in components if pregen._is_llm_component(c)}
    taxonomy = compose._load_attack_class_taxonomy()
    tiers = {c.get("id"): c.get("default_target_tier") for c in taxonomy.get("classes") or [] if isinstance(c, dict)}

    ranked = rollup.verdict_ranked_ids(triage)
    rank = {rollup.display_id(str(tid)): i + 1 for i, tid in enumerate(ranked)}
    threats = [t for t in rollup.register_threats(yaml_data) if t.get("id")]

    def order(t: dict) -> tuple:
        ref = rollup.display_id(str(t["id"]))
        return (_SEV_ORDER.get(rollup.priority_severity(t), 4), rank.get(ref, len(rank) + 1), ref)

    detailed: list[dict] = []
    brief: list[dict] = []
    for t in sorted(threats, key=order):
        ref = rollup.display_id(str(t["id"]))
        severity = rollup.priority_severity(t)
        row = {
            "ref": ref,
            "severity": severity,
            "title": _text(t.get("title"), _TITLE_MAX),
            "cwe": str(t.get("cwe") or ""),
            "component": cref.get(t.get("component"), ""),
        }
        if severity not in _DETAILED:
            brief.append(_sparse(row))
            continue
        blob = " ".join(str(t.get(f) or "") for f in ("title", "evidence_summary", "impact_description")).lower()
        attack_class = compose._classify_finding_class(t, taxonomy, yaml_data)
        row.update(
            {
                "rank": rank.get(ref, 0),
                "register_severity": rollup.register_severity(t),
                "stride": str(t.get("stride") or ""),
                "component_name": str(t.get("component_name") or ""),
                "attack_class": attack_class or "",
                "default_target_tier": tiers.get(attack_class) or "",
                "primary_actor": str(t.get("primary_actor") or ""),
                "actor_ids": _ids(t.get("actor_ids")),
                "evidence_tier": str(t.get("evidence_tier") or ""),
                "chain_role": str(t.get("chain_role") or ""),
                "compound_chain_ids": _ids(t.get("compound_chain_ids")),
                "verified_chain_ids": _ids(t.get("verified_chain_ids")),
                "owasp_llm_ids": _ids(t.get("owasp_llm_ids")),
                "owasp_asi_ids": _ids(t.get("owasp_asi_ids")),
                # The finding's own tags or prose, never its component alone: a
                # component that hosts a chatbot also hosts unrelated findings.
                "llm_surface": bool(t.get("owasp_llm_ids") or t.get("owasp_asi_ids"))
                or bool(pregen._LLM_SURFACE_RE.search(blob)),
                "mitigations": _ids(t.get("mitigation_ids")),
                "impact": _text(t.get("impact_description") or t.get("scenario"), _IMPACT_MAX),
            }
        )
        detailed.append(_sparse(row))

    basis = rollup.verdict_basis(yaml_data)
    weaknesses = [
        {
            "ref": str(w["id"]),
            "severity": rollup.register_severity(w),
            "kind": str(w.get("kind") or ""),
            "design_risk": w.get("severity_basis") == "design-risk",
            "title": _text(w.get("title"), _TITLE_MAX),
            "components": [cref.get(c, str(c)) for c in w.get("affected_components") or [] if isinstance(c, str)],
        }
        for w in yaml_data.get("weaknesses") or []
        if isinstance(w, dict) and w.get("id")
    ]
    p1 = [
        {
            "ref": str(m["id"]),
            "title": _text(m.get("title"), _TITLE_MAX),
            "finding_refs": [rollup.display_id(str(tid)) for tid in m.get("threat_ids") or []],
        }
        for m in yaml_data.get("mitigations") or []
        if isinstance(m, dict) and m.get("id") and str(m.get("priority") or "").upper() == "P1"
    ]
    trace = yaml_data.get("business_context_trace") or {}
    no_harm = [
        cref.get(row.get("component_id"), str(row.get("component_id") or ""))
        for row in trace.get("component_coverage") or []
        if isinstance(row, dict) and row.get("impact_is_material") is False
    ]
    return {
        "schema_version": 1,
        "source_sha256": hashlib.sha256(json.dumps(yaml_data, sort_keys=True, default=str).encode()).hexdigest(),
        "verdict": {
            "severity": rollup.verdict_severity(yaml_data),
            "floor_refs": rollup.verdict_floor_ids(yaml_data, ranked),
            "design_risk_refs": sorted(ref for ref in basis if ref.startswith("W-")),
        },
        "counts": rollup.risk_distribution_counts(yaml_data),
        "register_floor": rollup.register_floor(yaml_data),
        "no_material_harm_components": [c for c in no_harm if c],
        "components": [
            {
                "ref": cref[c["id"]],
                "name": str(c.get("name") or ""),
                "tier": str(c.get("tier") or ""),
                "framework": str(c.get("framework") or ""),
                "llm_surface": c.get("id") in llm_components,
            }
            for c in components
            if c.get("id") in cref
        ],
        "findings": detailed,
        "other_findings": brief,
        "p1_mitigations": p1,
        "weaknesses": weaknesses,
        "omitted": {"other_findings": 0, "findings": 0},
    }


def _dumps(digest: dict) -> str:
    return json.dumps(digest, ensure_ascii=False, separators=(",", ":"))


def _size(digest: dict) -> int:
    return len(_dumps(digest).encode("utf-8"))


def fit_budget(digest: dict, max_bytes: int = MAX_BYTES) -> dict:
    """Drop the least severe rows until the digest fits; the floor always stays."""
    floor = set(digest["verdict"]["floor_refs"])
    while _size(digest) > max_bytes and digest["other_findings"]:
        digest["other_findings"].pop()
        digest["omitted"]["other_findings"] += 1
    droppable = [i for i, row in enumerate(digest["findings"]) if row["ref"] not in floor]
    while _size(digest) > max_bytes and droppable:
        digest["findings"].pop(droppable.pop())
        digest["omitted"]["findings"] += 1
    return digest


def validate(digest: dict) -> list[str]:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return [f"{list(e.absolute_path)}: {e.message}" for e in Draft202012Validator(schema).iter_errors(digest)]


def write_digest(output_dir: Path) -> Path | None:
    """Write the digest; ``None`` without a model. A schema defect raises, never writes."""
    # A digest of an earlier model must not outlive a failed rebuild: without
    # the file the renderer falls back to the model itself.
    (output_dir / DIGEST_RELPATH).unlink(missing_ok=True)
    model_path = output_dir / "threat-model.yaml"
    if not model_path.is_file():
        return None
    yaml_data = yaml.safe_load(model_path.read_text(encoding="utf-8"))
    if not isinstance(yaml_data, dict):
        return None
    triage_path = output_dir / ".triage-flags.json"
    triage = json.loads(triage_path.read_text(encoding="utf-8")) if triage_path.is_file() else None
    digest = fit_budget(build_digest(yaml_data, triage))
    errors = validate(digest)
    if errors:
        raise ValueError("ms-input digest violates its schema: " + "; ".join(errors[:3]))
    path = output_dir / DIGEST_RELPATH
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(_dumps(digest) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        path = write_digest(args.output_dir)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ms-input digest not written: {exc}", file=sys.stderr)
        return 1
    print(f"ms-input digest: {path}" if path else "ms-input digest: no threat-model.yaml")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
