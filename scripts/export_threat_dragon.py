#!/usr/bin/env python3
"""
export_threat_dragon.py — ALPHA. Generate `threat-model.threatdragon.json`
(OWASP Threat Dragon v2 JSON) deterministically from a `threat-model.yaml`
export.

The file opens in OWASP Threat Dragon and imports into OWASP ThreatAtlas
(Diagram → Import, which accepts `.json` and detects the Threat Dragon shape).
ThreatAtlas' own diagram/product exports carry geometry only — the Threat
Dragon path is the one file format that also creates its threats and
mitigations.

ALPHA — the mapping may change between releases. Threat Dragon's schema is
much narrower than ours, so this export is lossy by construction: CWE,
structured evidence, mitigation priority/effort, requirements traceability,
abuse-case links, business-context use, and referenced trust-boundary crossings
have no field of their own and are folded into bounded text. Actors and boundary
geometry still have no counterpart. Every threat keeps its `F-NNN` anchor in the
title so a reader can walk back to `threat-model.md`.

Best-effort by design: a thin or legacy-shaped yaml still produces a usable
diagram. Missing components, unresolved references and absent data flows
degrade to warnings on stderr, never to a failed export.

CLI:

    python3 export_threat_dragon.py \
        --threat-model $OUTPUT_DIR/threat-model.yaml \
        --output       $OUTPUT_DIR/threat-model.threatdragon.json

Exit codes: 0 success, 1 yaml not found, 2 unparsable yaml, 3 write error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _boundary_criticality import facts_of as _boundary_facts  # noqa: E402

TD_VERSION = "2.4.0"
DIAGRAM_TYPE = "STRIDE"

# `data_flows[].from`/`.to` are component ids, except for this one reserved
# value the output schema allows: `^(?:external|[a-z][a-z0-9-]+)$`.
EXTERNAL_REF = "external"

# `data_flows[].direction` enum. `request-response` travels both ways, so it is
# bidirectional for diagramming purposes.
BIDIRECTIONAL_DIRECTIONS = {"bidirectional", "request-response", "both"}

# Threat Dragon's own STRIDE labels (`td.vue/src/i18n/en.json`,
# `threats.model.stride`) are sentence case where ours are title case. Map onto
# theirs so the editor's type dropdown offers one spelling instead of two — it
# appends an unrecognised type to the option list rather than rejecting it.
# Anything not STRIDE passes through so a foreign category stays readable.
STRIDE_TO_TD = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information disclosure": "Information disclosure",
    "denial of service": "Denial of service",
    "elevation of privilege": "Elevation of privilege",
}

# Node geometry. Fixed columns keep the output byte-stable — no layout engine,
# no randomness, so a golden fixture stays valid.
COLUMN_X = {"actor": 80, "process": 440, "store": 800}
ROW_Y0 = 80
ROW_STEP = 140
NODE_W = 160
NODE_H = 80

# `components[].tier` is the canonical field.
TIER_TO_SHAPE = {
    "client": ("actor", "tm.Actor"),
    "application": ("process", "tm.Process"),
    "data": ("store", "tm.Store"),
}

# `components[].kind` is a legacy/lean inventory field some producers still
# emit. Only used when `tier` is absent.
KIND_TO_TIER = {
    "browser": "client",
    "cli": "client",
    "client": "client",
    "frontend": "client",
    "mobile": "client",
    "spa": "client",
    "ui": "client",
    "external": "client",
    "third-party": "client",
    "bucket": "data",
    "cache": "data",
    "database": "data",
    "datastore": "data",
    "db": "data",
    "queue": "data",
    "storage": "data",
    "store": "data",
}

# Threat Dragon severity vocabulary. ThreatAtlas lowercases before mapping
# these onto likelihood/impact 2..5, so title case works in both tools.
# `Informational` has no counterpart — it must degrade to `Low`, otherwise
# ThreatAtlas imports the finding unscored.
RISK_TO_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Low",
}

# Threat Dragon's severity control is a radio group over TBD/Low/Medium/High/
# Critical, so an unrated threat has a value; omitting the field would leave
# the control blank. ThreatAtlas' map misses `TBD` and an absent severity
# alike, importing either unscored.
SEVERITY_UNRATED = "TBD"

# `threatStatus` in `td.vue/src/service/threats/status.js`. Our mitigations are
# proposed, not verified as implemented, so a threat stays Open — except where
# the only proposal is to accept the risk, which is a decision already taken.
# ThreatAtlas maps `accepted` onto its own accepted state.
STATUS_OPEN = "Open"
STATUS_ACCEPTED = "Accepted"

# New traceability text is deliberately bounded even though Threat Dragon's
# schema does not cap these free-text fields. This prevents an imported catalog
# or model from inflating a single diagram cell without hiding the omission.
TRACE_ITEM_LIMIT = 12
TRACE_CASE_LIMIT = 8
TRACE_VALUE_LIMIT = 300


def _default_tool_version() -> str:
    """Read the packaged plugin version; avoid a second release-version copy."""
    try:
        manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        version = manifest.get("version")
        if isinstance(version, str) and version:
            return version
    except (OSError, json.JSONDecodeError):
        pass
    return "unknown"


DEFAULT_TOOL_VERSION = _default_tool_version()


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _trace_text(value: Any, limit: int = TRACE_VALUE_LIMIT) -> str:
    """Collapse untrusted trace prose to one bounded line."""
    compact = " ".join(_text(value).split())
    if len(compact) <= limit:
        return compact
    return compact[: max(0, limit - 1)].rstrip() + "…"


def _display_id(raw: str) -> str:
    """The id the reader sees in the rendered report. The composer maps the
    yaml's ``T-NNN`` to ``F-NNN`` by prefix swap; mirror that so a Threat
    Dragon title cites the same anchor as `threat-model.md`. Non ``T-`` ids
    pass through unchanged."""
    if len(raw) > 2 and raw[0] in "Tt" and raw[1] == "-":
        return "F-" + raw[2:]
    return raw


def _threat_id(threat: dict) -> str:
    """Canonical field is `id`; legacy fixtures use `t_id`."""
    for key in ("id", "t_id"):
        value = _text(threat.get(key))
        if value:
            return value
    return ""


def _mitigation_id(mitigation: dict) -> str:
    for key in ("id", "m_id"):
        value = _text(mitigation.get(key))
        if value:
            return value
    return ""


def _component_ref(threat: dict) -> str:
    """The component a threat belongs to. `component_id` is the canonical
    field and `component` the alternative — the composer reads them in that
    order, and either may hold an id or a display name."""
    for key in ("component_id", "component"):
        value = _text(threat.get(key))
        if value:
            return value
    return ""


def _shape_for(component: dict) -> tuple[str, str]:
    """Resolve a component to a (shape, tm-type) pair. Unknown or missing
    classification defaults to a process — the neutral DFD element."""
    tier = _text(component.get("tier")).lower()
    if tier not in TIER_TO_SHAPE:
        tier = KIND_TO_TIER.get(_text(component.get("kind")).lower(), "application")
    return TIER_TO_SHAPE.get(tier, TIER_TO_SHAPE["application"])


def _severity_for(threat: dict) -> str:
    for key in ("risk", "severity", "impact"):
        mapped = RISK_TO_SEVERITY.get(_text(threat.get(key)).lower())
        if mapped:
            return mapped
    return SEVERITY_UNRATED


def _status_for(mitigations: list[dict]) -> str:
    """`accept_risk` is the one mitigation kind that records a decision rather
    than a proposal. A threat whose every linked mitigation accepts the risk is
    Accepted; one with any actionable mitigation, or none at all, stays Open."""
    if mitigations and all(_text(m.get("kind")) == "accept_risk" for m in mitigations):
        return STATUS_ACCEPTED
    return STATUS_OPEN


def _cvss_score(threat: dict) -> str:
    """Threat Dragon's free-text `score` field is the one place a numeric
    rating fits — the editor labels it "custom score/risk"."""
    cvss = threat.get("cvss_v4")
    if isinstance(cvss, dict) and isinstance(cvss.get("base_score"), (int, float)):
        return str(cvss["base_score"])
    return ""


def _evidence_entries(threat: dict) -> list[dict]:
    """Normalise `evidence` to a list. The canonical schema declares
    `array[object]`; legacy producers emit a single dict."""
    ev = threat.get("evidence")
    if isinstance(ev, list):
        return [e for e in ev if isinstance(e, dict) and e.get("file")]
    if isinstance(ev, dict) and ev.get("file"):
        return [ev]
    return []


def _linked_mitigations(threat: dict, mitigations: list[dict]) -> list[dict]:
    """Mitigations are linked from either side and under either vocabulary:
    the threat's `mitigation_ids`/`mitigations`, or the mitigation's
    `threat_ids`/`addresses`. Take the union, preserve yaml order."""
    tid = _threat_id(threat)
    wanted = {m for m in (threat.get("mitigation_ids") or threat.get("mitigations") or []) if isinstance(m, str)}
    out: list[dict] = []
    for mitigation in mitigations:
        mid = _mitigation_id(mitigation)
        covered = [t for t in (mitigation.get("threat_ids") or mitigation.get("addresses") or []) if isinstance(t, str)]
        if (mid and mid in wanted) or (tid and tid in covered):
            out.append(mitigation)
    return out


def _boundary_lines(threat: dict, boundary_facts: dict[str, dict]) -> list[str]:
    """`- tb-3 external → C-01 (internet-facing): <rationale>` per reference.

    Threat Dragon has no field for a boundary reference, so it folds into the
    description like CWE and evidence do. Resolved, not as a bare `tb-3`: the id
    is renumbered per run and means nothing once the finding leaves this
    repository.
    """
    lines: list[str] = []
    seen: set[str] = set()
    for ref in threat.get("boundary_refs") or []:
        if not isinstance(ref, dict):
            continue
        boundary_id = _text(ref.get("boundary_id"))
        if not boundary_id or boundary_id in seen:
            continue
        seen.add(boundary_id)
        facts = boundary_facts.get(boundary_id) or {}
        head = boundary_id
        if facts.get("crossing"):
            head += f" {facts['crossing']} ({facts['exposure']})"
        rationale = _text(ref.get("rationale"))
        lines.append(f"- {head}: {rationale}" if rationale else f"- {head}")
    return lines


def _trace_context(data: dict) -> dict[str, Any]:
    """Index the canonical trace sections once for deterministic text folding."""
    compliance = data.get("requirements_compliance")
    requirement_rows = (
        [row for row in (compliance.get("requirements") or []) if isinstance(row, dict)]
        if isinstance(compliance, dict)
        else []
    )
    requirements = {str(row.get("id") or "").strip(): row for row in requirement_rows if row.get("id")}
    requirements_by_finding: dict[str, list[str]] = {}
    for req_id, row in requirements.items():
        for fid in row.get("finding_ids") or []:
            if isinstance(fid, str):
                requirements_by_finding.setdefault(fid, []).append(req_id)

    analysis = data.get("abuse_case_analysis")
    cases = (
        [row for row in (analysis.get("cases") or []) if isinstance(row, dict)] if isinstance(analysis, dict) else []
    )
    cases_by_finding: dict[str, list[dict]] = {}
    for case in cases:
        for fid in case.get("matched_finding_ids") or []:
            if isinstance(fid, str):
                cases_by_finding.setdefault(fid, []).append(case)

    business = data.get("business_context_trace")
    if not isinstance(business, dict):
        business = {}
    provenance = data.get("requirements_provenance")
    if not isinstance(provenance, dict):
        provenance = {}
    return {
        "requirements": requirements,
        "requirements_by_finding": requirements_by_finding,
        "requirements_total": compliance.get("total", len(requirement_rows)) if isinstance(compliance, dict) else 0,
        "requirements_statuses": {
            status: sum(row.get("status") == status for row in requirement_rows)
            for status in ("PASS", "FAIL", "PARTIAL", "UNVERIFIABLE", "N/A")
        },
        "requirements_provenance": provenance,
        "cases": cases,
        "cases_by_finding": cases_by_finding,
        "abuse_status": analysis.get("status") if isinstance(analysis, dict) else None,
        "catalog_evaluated_count": len(analysis.get("catalog_evaluated") or []) if isinstance(analysis, dict) else 0,
        "business": business,
    }


def _bounded_rows(rows: list[str], limit: int, noun: str) -> list[str]:
    """Keep a bounded prefix and name the canonical location of omitted rows."""
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [f"- +{len(rows) - limit} more {noun} in threat-model.yaml"]


def _requirement_ids_for_threat(threat: dict, trace: dict[str, Any]) -> list[str]:
    fid = _display_id(_threat_id(threat))
    req_ids: list[str] = []
    for raw in list(threat.get("violated_requirements") or []) + list(trace["requirements_by_finding"].get(fid, [])):
        req_id = str(raw).strip()
        if req_id and req_id not in req_ids:
            req_ids.append(req_id)
    return req_ids


def _requirement_trace_lines(threat: dict, trace: dict[str, Any]) -> list[str]:
    req_ids = _requirement_ids_for_threat(threat, trace)
    rows: list[str] = []
    for req_id in req_ids:
        requirement = trace["requirements"].get(req_id) or {}
        display_id = _trace_text(req_id, 64)
        status = _trace_text(requirement.get("status"), 32)
        title = _trace_text(requirement.get("title"))
        head = f"{display_id} [{status}]" if status else display_id
        rows.append(f"- {head} — {title}" if title else f"- {head}")
    return _bounded_rows(rows, TRACE_ITEM_LIMIT, "requirement links")


def _abuse_case_trace_lines(threat: dict, trace: dict[str, Any]) -> list[str]:
    fid = _display_id(_threat_id(threat))
    rows: list[str] = []
    for case in trace["cases_by_finding"].get(fid, []):
        case_id = _trace_text(case.get("id"), 64)
        title = _trace_text(case.get("title"))
        verdict = _trace_text(case.get("chain_verdict"), 64).replace("_", " ")
        complete = "verification complete" if case.get("verification_complete") else "verification incomplete"
        matching_steps = [
            f"{step.get('step')} ({_trace_text(step.get('verdict'), 32)})"
            for step in case.get("steps") or []
            if isinstance(step, dict) and step.get("finding_id") == fid
        ]
        qualifiers = ", ".join(part for part in (verdict, complete) if part)
        line = f"- {case_id} [{qualifiers}]" if qualifiers else f"- {case_id}"
        if title:
            line += f" — {title}"
        if matching_steps:
            line += f"; matching steps {', '.join(matching_steps[:TRACE_ITEM_LIMIT])}"
        rows.append(line)
    return _bounded_rows(rows, TRACE_CASE_LIMIT, "abuse-case links")


def _business_context_line(threat: dict, trace: dict[str, Any]) -> str:
    basis = [str(field).replace("_", " ") for field in (threat.get("business_context_basis") or [])]
    if not basis:
        return ""
    business = trace["business"]
    parts = [f"applied fields: {', '.join(basis[:TRACE_ITEM_LIMIT])}"]
    source = _trace_text(business.get("source"), 256)
    if source:
        parts.append(f"source: {source}")
    digest = _text(business.get("sha256"))
    if digest:
        parts.append(f"sha256: {digest}")
    return "; ".join(parts)


def _threat_description(threat: dict, boundary_facts: dict[str, dict], trace: dict[str, Any]) -> str:
    """Fold everything Threat Dragon has no field for into the description.
    This is the only place the dropped detail survives, so keep it structured
    and greppable rather than prose."""
    fid = _display_id(_threat_id(threat))
    blocks: list[str] = []

    scenario = _text(threat.get("scenario")) or _text(threat.get("title"))
    if scenario:
        blocks.append(scenario)

    impact = _text(threat.get("impact_description")) or _text(threat.get("impact_summary"))
    if impact:
        blocks.append(f"Impact: {impact}")

    facts: list[str] = []
    risk = _text(threat.get("risk")) or _text(threat.get("severity"))
    likelihood = _text(threat.get("likelihood"))
    impact_rating = _text(threat.get("impact"))
    if risk:
        rating = f"Risk: {risk}"
        if likelihood and impact_rating:
            rating += f" (likelihood {likelihood}, impact {impact_rating})"
        facts.append(rating)
    cwe = _text(threat.get("cwe"))
    if cwe:
        facts.append(f"CWE: {cwe}")
    cvss = threat.get("cvss_v4")
    if isinstance(cvss, dict):
        score = cvss.get("base_score")
        vector = _text(cvss.get("vector"))
        if score is not None and vector:
            facts.append(f"CVSS v4: {score} ({vector})")
        elif score is not None:
            facts.append(f"CVSS v4: {score}")
        elif vector:
            facts.append(f"CVSS v4: {vector}")
    tier = _text(threat.get("evidence_tier"))
    if tier:
        facts.append(f"Evidence tier: {tier}")
    source = _text(threat.get("source"))
    if source:
        facts.append(f"Source: {source}")
    if facts:
        blocks.append("\n".join(facts))

    evidence_lines: list[str] = []
    summary = _text(threat.get("evidence_summary"))
    if summary:
        evidence_lines.append(summary)
    for entry in _evidence_entries(threat):
        line = entry.get("line")
        file_ref = _text(entry.get("file"))
        evidence_lines.append(f"- {file_ref}:{line}" if isinstance(line, int) and line > 0 else f"- {file_ref}")
    if evidence_lines:
        blocks.append("Evidence:\n" + "\n".join(evidence_lines))

    boundary_lines = _boundary_lines(threat, boundary_facts)
    if boundary_lines:
        blocks.append("Trust boundary crossings:\n" + "\n".join(boundary_lines))

    requirement_lines = _requirement_trace_lines(threat, trace)
    if requirement_lines:
        blocks.append("Requirements trace:\n" + "\n".join(requirement_lines))

    abuse_lines = _abuse_case_trace_lines(threat, trace)
    if abuse_lines:
        blocks.append("Abuse-case trace:\n" + "\n".join(abuse_lines))

    business_line = _business_context_line(threat, trace)
    if business_line:
        blocks.append("Business-context trace:\n" + business_line)

    if fid:
        blocks.append(f"Full finding: threat-model.md#{fid.lower()} ({fid})")

    return "\n\n".join(blocks)


def _mitigation_text(mitigations: list[dict], trace: dict[str, Any]) -> str:
    """Render linked mitigations into the single free-text field Threat Dragon
    offers. ThreatAtlas turns this into a Mitigation record verbatim."""
    blocks: list[str] = []
    for mitigation in mitigations:
        mid = _mitigation_id(mitigation)
        title = _text(mitigation.get("title"))
        head = f"{mid} — {title}" if mid and title else (title or mid)

        qualifiers = [
            f"{label} {_text(mitigation.get(key))}"
            for key, label in (("priority", "priority"), ("effort", "effort"))
            if _text(mitigation.get(key))
        ]
        if qualifiers:
            head = f"{head} ({', '.join(qualifiers)})" if head else f"({', '.join(qualifiers)})"

        lines = [head] if head else []
        steps = [s for s in (mitigation.get("steps") or []) if isinstance(s, str) and s.strip()]
        if steps:
            lines.extend(f"{i}. {s.strip()}" for i, s in enumerate(steps, start=1))
        else:
            # Legacy shape: prose in `why` / `how` instead of numbered steps.
            for key, label in (("why", "Why"), ("how", "How")):
                value = _text(mitigation.get(key))
                if value:
                    lines.append(f"{label}: {value}")
        for key, label in (("verification", "Verification"), ("reference", "Reference")):
            value = _text(mitigation.get(key))
            if value:
                lines.append(f"{label}: {value}")
        fulfilled = [str(req_id).strip() for req_id in (mitigation.get("fulfills_requirements") or []) if req_id]
        if fulfilled:
            req_rows = []
            for req_id in fulfilled:
                requirement = trace["requirements"].get(req_id) or {}
                display_id = _trace_text(req_id, 64)
                status = _trace_text(requirement.get("status"), 32)
                title = _trace_text(requirement.get("title"))
                head = f"{display_id} [{status}]" if status else display_id
                req_rows.append(f"- {head} — {title}" if title else f"- {head}")
            lines.append(
                "Requirements fulfilled:\n" + "\n".join(_bounded_rows(req_rows, TRACE_ITEM_LIMIT, "requirements"))
            )
        blueprint = mitigation.get("blueprint")
        if isinstance(blueprint, dict):
            blueprint_head = " — ".join(
                part
                for part in (
                    _trace_text(blueprint.get("id"), 64),
                    _trace_text(blueprint.get("title")),
                )
                if part
            )
            grounded = blueprint.get("grounded")
            if grounded is False:
                blueprint_head += " [candidate; not grounded]"
            blueprint_lines = [blueprint_head] if blueprint_head else []
            section = _trace_text(blueprint.get("section"))
            section_url = _trace_text(blueprint.get("section_url") or blueprint.get("url"), 512)
            guidance = _trace_text(blueprint.get("guidance"))
            if section:
                blueprint_lines.append(f"Section: {section}")
            if section_url:
                blueprint_lines.append(f"Reference: {section_url}")
            if guidance:
                blueprint_lines.append(f"Guidance: {guidance}")
            if blueprint_lines:
                lines.append("Implementation blueprint:\n" + "\n".join(blueprint_lines))
        if lines:
            blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _build_threat_cell(
    threat: dict,
    number: int,
    mitigations: list[dict],
    boundary_facts: dict[str, dict],
    trace: dict[str, Any],
) -> dict:
    tid = _threat_id(threat)
    fid = _display_id(tid)
    title = _text(threat.get("title")) or fid or "Untitled threat"
    stride = _text(threat.get("stride")) or _text(threat.get("stride_category"))

    cell: dict[str, Any] = {
        "id": fid or f"threat-{number}",
        "title": f"[{fid}] {title}" if fid else title,
        "type": STRIDE_TO_TD.get(stride.lower(), stride or "Other"),
        "status": _status_for(mitigations),
        "severity": _severity_for(threat),
        "description": _threat_description(threat, boundary_facts, trace),
        "mitigation": _mitigation_text(mitigations, trace),
        "modelType": DIAGRAM_TYPE,
        "number": number,
    }
    score = _cvss_score(threat)
    if score:
        cell["score"] = score
    return cell


def _build_node(cid: str, name: str, description: str, shape: str, tm_type: str, index: int) -> dict:
    x = COLUMN_X.get(shape, COLUMN_X["process"])
    return {
        # `cells[].id` carries minLength 2 in the Threat Dragon v2 schema, and a
        # one-character component id would put the whole file outside it. Every
        # lookup keys off the source reference, so padding the emitted id here
        # stays local to the cell.
        "id": cid if len(cid) > 1 else f"td-{cid}",
        "shape": shape,
        "zIndex": 1,
        "visible": True,
        "position": {"x": x, "y": ROW_Y0 + ROW_STEP * index},
        "size": {"width": NODE_W, "height": NODE_H},
        "attrs": {"text": {"text": name}},
        "data": {
            "type": tm_type,
            "name": name,
            "description": description,
            "outOfScope": False,
            "reasonOutOfScope": "",
            "hasOpenThreats": False,
            "threats": [],
        },
    }


def build_threat_dragon(
    data: dict,
    tool_version: str = DEFAULT_TOOL_VERSION,
    diagram_title: str | None = None,
) -> tuple[dict, list[str]]:
    """Return (threat-dragon document, warnings). Never raises on thin input."""
    warnings: list[str] = []
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}

    project = _text(meta.get("project")) or _text(data.get("project")) or "Threat model"
    owner = _text(meta.get("team_owner"))

    components = [c for c in (data.get("components") or []) if isinstance(c, dict)]
    threats = [t for t in (data.get("threats") or []) if isinstance(t, dict)]
    mitigations = [m for m in (data.get("mitigations") or []) if isinstance(m, dict)]
    boundary_facts = _boundary_facts(data)
    trace = _trace_context(data)

    # ── Nodes ──────────────────────────────────────────────────────────────
    nodes: list[dict] = []
    by_id: dict[str, dict] = {}
    by_name: dict[str, dict] = {}
    per_shape_index: dict[str, int] = {}

    for component in components:
        name = _text(component.get("name")) or _text(component.get("id"))
        cid = _text(component.get("id")) or name
        if not cid:
            warnings.append("component without id or name — skipped")
            continue
        if cid in by_id:
            warnings.append(f"duplicate component id {cid!r} — later occurrence skipped")
            continue
        shape, tm_type = _shape_for(component)
        index = per_shape_index.get(shape, 0)
        per_shape_index[shape] = index + 1
        node = _build_node(cid, name or cid, _text(component.get("description")), shape, tm_type, index)
        nodes.append(node)
        by_id[cid] = node
        if name:
            by_name.setdefault(name.lower(), node)

    # A diagram with no elements is rejected by both importers. Recover from
    # the component references the threats themselves carry.
    if not nodes and threats:
        for threat in threats:
            ref = _component_ref(threat)
            if not ref or ref.lower() in by_name:
                continue
            index = per_shape_index.get("process", 0)
            per_shape_index["process"] = index + 1
            node = _build_node(ref, ref, "", "process", "tm.Process", index)
            nodes.append(node)
            by_id.setdefault(ref, node)
            by_name[ref.lower()] = node
        if nodes:
            warnings.append(
                f"no components[] in the yaml — synthesised {len(nodes)} node(s) from threat component references"
            )

    # The placeholder is itself a catch-all, so unresolved threats land on it
    # instead of on a second element drawn at the same coordinates.
    unassigned: dict | None = None
    if not nodes:
        per_shape_index["process"] = 1
        unassigned = _build_node("C-SYSTEM", project, "", "process", "tm.Process", 0)
        nodes.append(unassigned)
        by_id["C-SYSTEM"] = unassigned
        by_name[project.lower()] = unassigned
        warnings.append("no components and no threat component references — emitted a single placeholder node")

    # ── Threats ────────────────────────────────────────────────────────────
    number = 0
    for threat in threats:
        number += 1
        ref = _component_ref(threat)
        node = by_id.get(ref) or by_name.get(ref.lower())
        if node is None:
            if unassigned is None:
                index = per_shape_index.get("process", 0)
                per_shape_index["process"] = index + 1
                unassigned = _build_node(
                    "C-UNASSIGNED",
                    "Unassigned",
                    "Findings whose component reference did not resolve to a diagram element.",
                    "process",
                    "tm.Process",
                    index,
                )
                nodes.append(unassigned)
            node = unassigned
            warnings.append(
                f"threat {_display_id(_threat_id(threat)) or '(no id)'} references unknown component "
                f"{ref!r} — attached to the {node['data']['name']!r} element"
            )
        cell = _build_threat_cell(
            threat,
            number,
            _linked_mitigations(threat, mitigations),
            boundary_facts,
            trace,
        )
        node["data"]["threats"].append(cell)
        node["data"]["hasOpenThreats"] = True

    # ── Data flows ─────────────────────────────────────────────────────────
    flows: list[dict] = []
    external: dict | None = None

    def _endpoint(ref: str) -> dict | None:
        """Resolve a flow endpoint. `external` is a reserved value in
        `data_flows[].from`/`.to` (see the output schema) meaning the world
        outside the system — Threat Dragon models exactly that as an actor, so
        materialise one on first use instead of dropping the flow."""
        nonlocal external
        node = by_id.get(ref) or by_name.get(ref.lower())
        if node is not None:
            return node
        if ref.lower() != EXTERNAL_REF:
            return None
        if external is None:
            index = per_shape_index.get("actor", 0)
            per_shape_index["actor"] = index + 1
            external = _build_node(
                EXTERNAL_REF,
                "External",
                "The world outside the system, as referenced by data_flows[].",
                "actor",
                "tm.Actor",
                index,
            )
            nodes.append(external)
            by_id[EXTERNAL_REF] = external
        return external

    # Threat Dragon's own flag for a flow that leaves the machine. A confirmed
    # `external ↔ component` crossing is exactly that, in either direction —
    # inbound is where an unauthenticated attacker starts, outbound still
    # traverses the public network. Only `internet-facing` / `outbound` qualify,
    # and both already imply a resolved row with confirmed endpoints, so an
    # inferred or unresolved boundary never sets the flag.
    public_pairs = {
        frozenset((row.get("from"), row.get("to")))
        for row in (data.get("trust_boundaries") or [])
        if isinstance(row, dict)
        and (boundary_facts.get(row.get("id"), {}).get("exposure") in {"internet-facing", "outbound"})
    }

    for index, flow in enumerate(data.get("data_flows") or [], start=1):
        if not isinstance(flow, dict):
            continue
        # The §2.2 diagram renderer tolerates the same legacy aliases; match it.
        src_ref = _text(flow.get("from") or flow.get("src") or flow.get("source"))
        dst_ref = _text(flow.get("to") or flow.get("dst") or flow.get("destination"))
        src, dst = _endpoint(src_ref), _endpoint(dst_ref)
        if src is None or dst is None:
            warnings.append(f"data flow {src_ref!r} → {dst_ref!r} has an unresolved endpoint — dropped")
            continue
        label = _text(flow.get("label")) or _text(flow.get("name")) or "Data flow"
        protocol = _text(flow.get("protocol"))
        # Threat Dragon stores the on-canvas label in `labels[0]` as an object,
        # but ThreatAtlas' importer only reads `labels[0]` when it is a plain
        # string and does NOT fall through to `data.name`. Emitting the object
        # would label every flow "Data Flow" there, so the label lives in
        # `data.name` only — visible in both tools' property panels, absent
        # from the Threat Dragon canvas until the user opens the flow.
        flows.append(
            {
                "id": _text(flow.get("id")) or f"DF-{index:02d}",
                "shape": "flow",
                "zIndex": 10,
                "visible": True,
                "source": {"cell": src["id"]},
                "target": {"cell": dst["id"]},
                "data": {
                    "type": "tm.Flow",
                    "name": f"{label} ({protocol})" if protocol else label,
                    "description": _text(flow.get("data_classification")),
                    "outOfScope": False,
                    "reasonOutOfScope": "",
                    "hasOpenThreats": False,
                    "isBidirectional": _text(flow.get("direction")).lower() in BIDIRECTIONAL_DIRECTIONS,
                    "protocol": protocol,
                    "isEncrypted": protocol.lower() in {"https", "tls", "wss", "mtls", "ssh", "sftp"},
                    "isPublicNetwork": frozenset((src["id"], dst["id"])) in public_pairs,
                    "threats": [],
                },
            }
        )

    boundaries = [b for b in (data.get("trust_boundaries") or []) if isinstance(b, dict)]
    if boundaries:
        warnings.append(
            f"{len(boundaries)} trust boundary/boundaries are not drawn — our from/to model has no "
            "geometry, and Threat Dragon needs a boundary box or curve; a crossing a finding "
            "references still travels in that threat's description"
        )

    requirement_finding_links = sum(len(_requirement_ids_for_threat(threat, trace)) for threat in threats)
    requirement_mitigation_links = sum(len(mitigation.get("fulfills_requirements") or []) for mitigation in mitigations)
    abuse_finding_links = sum(len(cases) for cases in trace["cases_by_finding"].values())
    business_finding_links = sum(bool(threat.get("business_context_basis")) for threat in threats)
    if (
        trace["requirements_total"]
        or requirement_finding_links
        or requirement_mitigation_links
        or trace["requirements_provenance"]
    ):
        warnings.append(
            "Threat Dragon has no native requirement fields — folded "
            f"{requirement_finding_links} finding link(s) and {requirement_mitigation_links} mitigation link(s) "
            f"into text; summarized {trace['requirements_total']} assessed requirement(s) and bounded provenance "
            "at document level"
        )
    if trace["cases"] or trace["abuse_status"]:
        warnings.append(
            "Threat Dragon has no native abuse-case objects — folded "
            f"{abuse_finding_links} finding link(s) from {len(trace['cases'])} case(s) into text; "
            f"{trace['catalog_evaluated_count']} catalog evaluation row(s) and the complete step analysis remain "
            "in threat-model.yaml and threat-model.md"
        )
    if business_finding_links or (trace["business"] and trace["business"].get("status") != "not_configured"):
        warnings.append(
            "Threat Dragon has no native business-context fields — folded "
            f"{business_finding_links} finding trace(s) and bounded provenance into text; raw context prose is excluded"
        )

    requirement_status = (
        ", ".join(f"{status} {count}" for status, count in trace["requirements_statuses"].items() if count) or "none"
    )
    provenance = trace["requirements_provenance"]
    requirement_source = _trace_text(provenance.get("source_label") or provenance.get("source_kind"), 256)
    requirement_hash = _text(provenance.get("catalog_sha256"))
    requirement_provenance = ""
    if requirement_source:
        requirement_provenance += f", source {requirement_source}"
    if requirement_hash:
        requirement_provenance += f", sha256 {requirement_hash}"
    business = trace["business"]
    business_status = _trace_text(business.get("status"), 32) or "absent"
    business_provenance = ""
    business_source = _trace_text(business.get("source"), 256)
    business_hash = _text(business.get("sha256"))
    if business_source:
        business_provenance += f", source {business_source}"
    if business_hash:
        business_provenance += f", sha256 {business_hash}"
    trace_summary = (
        f"Traceability retained in bounded text: requirements {trace['requirements_total']} "
        f"({requirement_status}{requirement_provenance}); abuse cases {len(trace['cases'])} "
        f"({trace['abuse_status'] or 'absent'}, {trace['catalog_evaluated_count']} catalog-only); "
        f"business context {business_status}{business_provenance}. "
    )

    title = diagram_title or project
    doc = {
        "version": TD_VERSION,
        "summary": {
            "title": project,
            "owner": owner,
            "description": (
                f"Generated by appsec-advisor {tool_version} — ALPHA Threat Dragon export. "
                "Lossy by design: CWE, evidence locations, referenced trust-boundary "
                "crossings, mitigation detail, requirements, abuse-case links and business-context use "
                "are folded into text; actors and boundary geometry have no counterpart. "
                f"{trace_summary}"
                "See threat-model.md for the authoritative report."
            ),
            "id": 0,
        },
        "detail": {
            "contributors": [],
            "diagrams": [
                {
                    "id": 0,
                    "title": title,
                    "diagramType": DIAGRAM_TYPE,
                    "placeholder": "",
                    "thumbnail": "./public/content/images/thumbnail.stride.jpg",
                    "version": TD_VERSION,
                    "cells": nodes + flows,
                }
            ],
            "diagramTop": 1,
            "reviewer": "",
            "threatTop": number,
        },
    }
    return doc, warnings


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--threat-model", required=True, help="Path to threat-model.yaml")
    p.add_argument("--output", required=True, help="Destination threat-model.threatdragon.json")
    p.add_argument("--diagram-title", default=None, help="Diagram title (default: the project name)")
    p.add_argument(
        "--tool-version",
        default=None,
        help=f"Tool version string (default: {DEFAULT_TOOL_VERSION} or meta.plugin_version when present in yaml)",
    )
    args = p.parse_args()

    yaml_path = Path(args.threat_model)
    if not yaml_path.is_file():
        print(f"ERROR: threat-model.yaml not found: {yaml_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with yaml_path.open() as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"ERROR: cannot parse threat-model.yaml: {e}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(data, dict):
        print("ERROR: threat-model.yaml root is not a mapping", file=sys.stderr)
        sys.exit(2)

    tool_version = args.tool_version
    if not tool_version:
        meta = data.get("meta") or {}
        tool_version = (meta.get("plugin_version") if isinstance(meta, dict) else None) or DEFAULT_TOOL_VERSION

    doc, warnings = build_threat_dragon(data, tool_version=tool_version, diagram_title=args.diagram_title)

    out_path = Path(args.output)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError as e:
        print(f"ERROR: cannot write Threat Dragon output: {e}", file=sys.stderr)
        sys.exit(3)

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    print(
        "NOTE: Threat Dragon export is ALPHA — the mapping may change between releases.",
        file=sys.stderr,
    )

    cells = doc["detail"]["diagrams"][0]["cells"]
    n_nodes = sum(1 for c in cells if c["shape"] != "flow")
    n_flows = len(cells) - n_nodes
    print(
        f"VALID: wrote Threat Dragon v{TD_VERSION} with {n_nodes} elements, "
        f"{n_flows} flows and {doc['detail']['threatTop']} threats → {out_path}"
    )


if __name__ == "__main__":
    main()
