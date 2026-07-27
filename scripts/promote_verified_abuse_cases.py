#!/usr/bin/env python3
"""Promote confirmed source-probe abuse-case steps into canonical findings.

The abuse-case matcher may discover a candidate directly in source when no
earlier scanner or STRIDE pass emitted a finding for it.  A source hit is only
a dispatch signal.  This script runs *after* the verifier fan-out and creates
a normal merged threat only when that verifier confirmed the specific step.

The case author supplies the classification and remediation in
``chain[].finding``.  Keeping that metadata declarative prevents this script
from guessing a CWE, severity, or fix from a regex match.  It updates both
abuse sidecars with the assigned T-ID, so triage, mitigation synthesis, and
the §9 renderer consume the same binding.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml
from reclassify_components import (  # canonical registry resolver — see _component_for
    _build_matcher as _rc_build_matcher,
)
from reclassify_components import (
    _component_for as _rc_component_for,
)
from reclassify_components import (
    _most_specific_candidate as _rc_most_specific_candidate,
)
from reclassify_components import (
    _primary_component_id as _rc_primary_component_id,
)

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
_VALID_STRIDE = {
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
}


def _load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _next_t_id(threats: list[dict]) -> str:
    numbers = []
    for threat in threats:
        match = re.fullmatch(r"T-(\d+)", str(threat.get("t_id") or ""))
        if match:
            numbers.append(int(match.group(1)))
    return f"T-{max(numbers, default=0) + 1:03d}"


def _metadata(step: dict) -> dict | None:
    """Return validated materialisation metadata, or None when absent/unsafe."""
    finding = step.get("finding")
    if not isinstance(finding, dict):
        return None
    cwe = str(finding.get("cwe") or "").upper().strip()
    stride = str(finding.get("stride") or "").strip()
    severity = str(finding.get("severity") or "Medium").strip().capitalize()
    mitigation_title = str(finding.get("mitigation_title") or "").strip()
    if not re.fullmatch(r"CWE-\d+", cwe) or stride not in _VALID_STRIDE:
        return None
    if severity not in _VALID_SEVERITIES or not mitigation_title:
        return None
    return {
        "cwe": cwe,
        "stride": stride,
        "severity": severity,
        "title": str(finding.get("title") or step.get("label") or "Confirmed abuse-case weakness").strip(),
        "mitigation_title": mitigation_title,
        "remediation": str(finding.get("remediation") or "").strip(),
    }


def _component_for(file_path: str, components: list) -> tuple[str, str]:
    """Resolve an evidence file to a **registered** component id/name.

    A promoted threat's ``component_id`` must name a component that exists in
    ``components[]``.  This used to be a hardcoded three-value grouping
    (``frontend`` / ``data-layer`` / ``backend-api``) that never consulted the
    registry, so it invented ids for any model whose components are not named
    exactly that — juice-shop 2026-07-27 promoted an ``AC-T-001`` step under
    ``frontend/`` as ``frontend`` while the registered id was ``frontend-spa``.
    A phantom is expensive: it dangles the §8 Component link, and because
    promotion runs *after* the curing ``reclassify_components`` pass nothing
    fixes it — the read-only pre-export gate then aborts the whole run.

    Matching goes through the same glob resolver ``reclassify_components``
    uses, so promotion and curing agree by construction.  An evidence file
    matching no glob falls back to the primary component (still registered)
    rather than to an invented id.
    """
    registered = [c for c in components if isinstance(c, dict) and (c.get("id") or "").strip()]
    if not registered:
        # No registry to resolve against (yaml absent). Nothing here can be
        # "registered" yet; keep the historical default and let the later
        # reclassify_components pass bind it once the yaml exists.
        return "backend-api", "Backend API"

    primary = _rc_primary_component_id(registered)
    hits = _rc_component_for(file_path, [_rc_build_matcher(c) for c in registered])
    if not hits:
        cid = primary
    elif len(hits) == 1:
        cid = hits[0]
    else:
        glob_index = {
            (c.get("id") or "").strip(): [g for g in (c.get("paths") or []) if isinstance(g, str)] for c in registered
        }
        cid = _rc_most_specific_candidate([file_path], hits, glob_index, primary)

    for component in registered:
        if (component.get("id") or "").strip() == cid:
            return cid, str(component.get("name") or cid)
    return cid, cid


def _registered_components(output_dir: Path) -> list:
    """Component registry from the composed model; empty when it is not there."""
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        return []
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError):
        return []
    if not isinstance(data, dict):
        return []
    components = data.get("components")
    return components if isinstance(components, list) else []


def _find_step(case_match: dict, step_number: object) -> dict | None:
    case = case_match.get("case")
    if not isinstance(case, dict):
        return None
    for step in case.get("chain") or []:
        if isinstance(step, dict) and step.get("step") == step_number:
            return step
    return None


def promote(output_dir: Path) -> tuple[int, list[str]]:
    merged_path = output_dir / ".threats-merged.json"
    matches_path = output_dir / ".abuse-case-matches.json"
    verdicts_path = output_dir / ".abuse-case-verdicts.json"
    required = (merged_path, matches_path, verdicts_path)
    absent = [path.name for path in required if not path.is_file()]
    if absent:
        return 0, [f"skipped: required sidecar(s) absent: {', '.join(absent)}"]

    merged = _load(merged_path)
    matches_doc = _load(matches_path)
    verdicts_doc = _load(verdicts_path)
    threats = merged.get("threats")
    matches = matches_doc.get("matches")
    verdicts = verdicts_doc.get("verdicts")
    if not isinstance(threats, list) or not isinstance(matches, list) or not isinstance(verdicts, list):
        raise ValueError("abuse-case promotion sidecars have an unexpected shape")

    components = _registered_components(output_dir)
    verdict_by_case = {v.get("abuse_case_id"): v for v in verdicts if isinstance(v, dict)}
    existing = {
        (
            str(t.get("abuse_case_id") or ""),
            t.get("abuse_case_step"),
            str(t["evidence"].get("file") or ""),
            t["evidence"].get("line"),
        ): t.get("t_id")
        for t in threats
        if isinstance(t, dict) and t.get("abuse_case_id") and isinstance(t.get("evidence"), dict)
    }
    promoted: list[str] = []
    skipped_metadata: list[str] = []
    bindings_changed = False

    for case_match in matches:
        if not isinstance(case_match, dict):
            continue
        case_id = str(case_match.get("abuse_case_id") or "")
        verdict = verdict_by_case.get(case_id)
        if not case_id or not isinstance(verdict, dict):
            continue
        verdict_steps = {v.get("step"): v for v in verdict.get("step_verdicts") or [] if isinstance(v, dict)}
        for step_match in case_match.get("step_matches") or []:
            if not isinstance(step_match, dict) or step_match.get("match_basis") != "source_probe":
                continue
            step_no = step_match.get("step")
            step_verdict = verdict_steps.get(step_no)
            if not isinstance(step_verdict, dict) or step_verdict.get("verdict") != "confirmed":
                continue
            verifier_evidence = step_verdict.get("evidence")
            evidence = (
                verifier_evidence
                if isinstance(verifier_evidence, dict) and verifier_evidence.get("file")
                else step_match.get("evidence") or {}
            )
            if not isinstance(evidence, dict) or not evidence.get("file"):
                continue
            step = _find_step(case_match, step_no)
            meta = _metadata(step or {})
            if meta is None:
                skipped_metadata.append(f"{case_id} step {step_no}")
                continue
            key = (case_id, step_no, str(evidence.get("file")), evidence.get("line"))
            t_id = existing.get(key)
            if not t_id:
                t_id = _next_t_id(threats)
                component_id, component_name = _component_for(str(evidence["file"]), components)
                threat = {
                    "t_id": t_id,
                    "title": meta["title"],
                    "scenario": str((step or {}).get("description") or (step or {}).get("label") or meta["title"]),
                    "stride": meta["stride"],
                    "risk": meta["severity"],
                    "likelihood": meta["severity"],
                    "impact": meta["severity"],
                    "cwe": meta["cwe"],
                    "evidence": {"file": str(evidence["file"]), "line": evidence.get("line")},
                    "source": "source-scan",
                    "architectural_violation": False,
                    "component_id": component_id,
                    "component_name": component_name,
                    "evidence_check": "verified",
                    "evidence_tier": "confirmed-exploitable",
                    "abuse_case_id": case_id,
                    "abuse_case_step": step_no,
                    "source_scan_ref": f"{case_id}:{step_no}",
                    "mitigation_title": meta["mitigation_title"],
                }
                if meta["remediation"]:
                    threat["remediation"] = {"how": meta["remediation"], "effort": "Medium"}
                threats.append(threat)
                existing[key] = t_id
                promoted.append(t_id)
            step_match["matched_finding_id"] = t_id
            step_match["match_basis"] = "promoted_source_probe"
            step_verdict["matched_finding_id"] = t_id
            bindings_changed = True

        case_match["matched_finding_ids"] = [
            step.get("matched_finding_id")
            for step in case_match.get("step_matches") or []
            if isinstance(step, dict) and step.get("matched_finding_id")
        ]

    if promoted or bindings_changed:
        _write(merged_path, merged)
        _write(matches_path, matches_doc)
        _write(verdicts_path, verdicts_doc)
    notes = [f"promoted {len(promoted)} confirmed source-probe finding(s)"]
    if promoted and not components:
        notes.append(
            "component registry unavailable (no threat-model.yaml) — promoted finding(s) "
            "carry the default component until reclassify_components binds them"
        )
    if skipped_metadata:
        notes.append("not promoted (missing finding metadata): " + ", ".join(sorted(skipped_metadata)))
    return len(promoted), notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Promote confirmed source-probe abuse-case steps into merged findings."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        count, notes = promote(args.output_dir)
    except ValueError as exc:
        print(f"PROMOTE_ABUSE_CASES: ERROR: {exc}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"PROMOTE_ABUSE_CASES: {note}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
