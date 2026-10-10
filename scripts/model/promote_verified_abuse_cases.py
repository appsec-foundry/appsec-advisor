#!/usr/bin/env python3
"""Promote confirmed source-probe abuse-case steps into canonical findings.

The abuse-case matcher may discover a candidate directly in source when no
earlier scanner or STRIDE pass emitted a finding for it.  A source hit is only
a dispatch signal.  This script runs *after* the verifier fan-out and creates
a normal merged threat only when that verifier confirmed the specific step.

The case author supplies the classification and remediation in
``chain[].finding``.  Keeping that metadata declarative prevents this script
from guessing a CWE, severity, or fix from a regex match.

A business (descriptive) case is promoted at its cited step when the chain is
fully viable, or as an unproven finding when it is inconclusive, no step was
blocked or refuted, and a decided step cites admitted code with no control
found.  Its classification comes from the case's optional ``finding`` block.  It updates both
abuse sidecars with the assigned T-ID, so triage, mitigation synthesis, and
the §9 renderer consume the same binding.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import re
import sys
from pathlib import Path

import yaml
from shared._finding_state import is_refuted, record_evidence
from shared._register_titles import HEADING_SOFT_MAX, clamp_mitigation_title, clamp_title

from model.finding_intake import apply_intake
from model.match_abuse_cases import _configured_repo_root, _evidence_problem, _finding_file
from model.merge_threats import _evidence_identity_key
from model.reclassify_components import resolve_owner  # canonical registry resolver

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


# A business case states no classification unless its author adds one.
_DESCRIPTIVE_DEFAULTS = {
    "cwe": "CWE-840",
    "stride": "Elevation of Privilege",
    "severity": "Medium",
}
_UNPROVEN_TIER = "insecure-practice"
_CONFIRMED_TIER = "confirmed-exploitable"


def _descriptive_promotion(case_match: dict, verdict: dict, live_ids: set) -> tuple[dict, str] | None:
    """The step verdict a business case is promoted at and its tier, or None.

    A fully viable case is confirmed at its first confirmed step. An
    inconclusive case without a blocked or refuted step is an indication when
    a decided step cites code that ``finalize`` admitted and names no control.
    A case the verifier bound to a live finding is not promoted.
    """
    steps = [step for step in verdict.get("step_verdicts") or [] if isinstance(step, dict)]
    # The verifier already bound the case to a live finding it cited; that
    # finding carries the result, whatever weakness family the case defaults to.
    if any(step.get("matched_finding_id") in live_ids for step in steps):
        return None
    chain = verdict.get("chain_verdict")
    if chain == "fully_viable":
        wanted, tier = "confirmed", _CONFIRMED_TIER
    elif chain == "inconclusive" and not any(step.get("verdict") in {"blocked", "refuted"} for step in steps):
        wanted, tier = "inconclusive", _UNPROVEN_TIER
    else:
        return None
    for step in steps:
        evidence = step.get("evidence")
        if (
            step.get("verdict") == wanted
            and step.get("state") != "pending"
            and (tier == _CONFIRMED_TIER or not step.get("controls_found"))
            and isinstance(evidence, dict)
            and evidence.get("file")
        ):
            return step, tier
    return None


def _descriptive_metadata(case: dict) -> dict:
    declared = case.get("finding") if isinstance(case.get("finding"), dict) else {}
    meta = {key: declared.get(key) or default for key, default in _DESCRIPTIVE_DEFAULTS.items()}
    meta["title"] = clamp_title(str(case.get("title") or "Business abuse case"), HEADING_SOFT_MAX)
    # Mitigations group by title, so a default names this case's rule rather
    # than folding unrelated business findings into one mitigation.
    meta["mitigation_title"] = clamp_mitigation_title(
        str(declared.get("mitigation_title") or f"Prevent: {case.get('title') or case.get('id')}")
    )
    meta["remediation"] = ""
    return meta


_UNSETTLED_EVIDENCE = {None, "", "ambiguous", "unchecked"}


def _verify_bound_findings(matches: list, verdict_by_case: dict, threats: list, repo_root: Path | None) -> list[str]:
    """Verify findings whose bound step the abuse-case verifier confirmed (AC-11).

    The cited excerpt must pass the same gate that admits descriptive
    evidence, at the finding's own file. Only ambiguous or unchecked evidence
    changes; the exploitability tier is left alone.
    """
    by_id: dict[str, dict] = {}
    for threat in threats:
        if isinstance(threat, dict):
            for key in ("t_id", "f_id", "id"):
                if threat.get(key):
                    by_id.setdefault(str(threat[key]), threat)
    verified: list[str] = []
    for case_match in matches:
        if not isinstance(case_match, dict):
            continue
        verdict = verdict_by_case.get(case_match.get("abuse_case_id"))
        if not isinstance(verdict, dict):
            continue
        steps = {v.get("step"): v for v in verdict.get("step_verdicts") or [] if isinstance(v, dict)}
        for step_match in case_match.get("step_matches") or []:
            if not isinstance(step_match, dict):
                continue
            finding = by_id.get(str(step_match.get("matched_finding_id") or ""))
            step_verdict = steps.get(step_match.get("step")) or {}
            evidence = step_verdict.get("evidence")
            if (
                finding is None
                or step_verdict.get("verdict") != "confirmed"
                or finding.get("evidence_check") not in _UNSETTLED_EVIDENCE
                or not isinstance(evidence, dict)
                or evidence.get("file") != _finding_file(finding)
                or _evidence_problem(evidence, repo_root)
            ):
                continue
            record_evidence(finding, "verified", "llm-verified")
            verified.append(str(finding.get("t_id") or finding.get("id")))
    return verified


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
    owner = resolve_owner(file_path, components)
    if owner is None:
        # No registry to resolve against (yaml absent). Nothing here can be
        # "registered" yet; keep the historical default and let the later
        # reclassify_components pass bind it once the yaml exists.
        return "backend-api", "Backend API"
    return owner


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


def _same_object_finding(threats: list[dict], candidate: dict) -> str | None:
    """T-ID of a live finding with the candidate's evidence identity, if any.

    Uses the merge pass's identity (file, positive line, CWE family) so
    promotion and merging agree on what "the same finding" is. A refuted
    finding never absorbs a confirmed step.
    """
    key = _evidence_identity_key(candidate)
    if key is None:
        return None
    for threat in threats:
        if isinstance(threat, dict) and not is_refuted(threat) and _evidence_identity_key(threat) == key:
            return threat.get("t_id")
    return None


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
    live_ids = {t.get("t_id") for t in threats if isinstance(t, dict) and t.get("t_id") and not is_refuted(t)}
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
        # (step match, step verdict, evidence, metadata, tier, scenario) per promotable step.
        candidates: list[tuple[dict, dict, dict, dict, str, str]] = []
        if case_match.get("kind") == "descriptive":
            # The verifier binds a business case to the findings it cites; the
            # match sidecar carries that binding to triage and the report, as
            # the matcher's binding does for a technical case.
            for step_match in case_match.get("step_matches") or []:
                cited = (verdict_steps.get(step_match.get("step")) or {}).get("matched_finding_id")
                if isinstance(step_match, dict) and cited in live_ids and step_match.get("matched_finding_id") != cited:
                    step_match["matched_finding_id"] = cited
                    step_match["match_basis"] = "finding"
                    bindings_changed = True
            promotion = _descriptive_promotion(case_match, verdict, live_ids)
            step_match = (
                next(
                    (
                        s
                        for s in case_match.get("step_matches") or []
                        if isinstance(s, dict) and s.get("step") == promotion[0].get("step")
                    ),
                    None,
                )
                if promotion
                else None
            )
            if promotion and step_match is not None:
                step_verdict, tier = promotion
                case = case_match.get("case") if isinstance(case_match.get("case"), dict) else {}
                # The verifier's reason names the code behavior; the check is the fallback.
                scenario = str(step_verdict.get("reason") or step_match.get("label") or case.get("title") or "")
                candidates.append(
                    (step_match, step_verdict, step_verdict["evidence"], _descriptive_metadata(case), tier, scenario)
                )
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
            scenario = str((step or {}).get("description") or (step or {}).get("label") or meta["title"])
            candidates.append((step_match, step_verdict, evidence, meta, _CONFIRMED_TIER, scenario))

        for step_match, step_verdict, evidence, meta, tier, scenario in candidates:
            step_no = step_match.get("step")
            key = (case_id, step_no, str(evidence.get("file")), evidence.get("line"))
            t_id = existing.get(key)
            basis = "promoted_source_probe" if step_match.get("match_basis") == "source_probe" else "promoted"
            if not t_id:
                # A finding already at the same code location and weakness family
                # is the same finding: bind the step to it instead of promoting a
                # duplicate the merge pass, which already ran, can no longer fold.
                t_id = _same_object_finding(
                    threats,
                    {"evidence": {"file": str(evidence["file"]), "line": evidence.get("line")}, "cwe": meta["cwe"]},
                )
                if t_id:
                    basis = "finding"
                    existing[key] = t_id
            if not t_id:
                t_id = _next_t_id(threats)
                component_id, component_name = _component_for(str(evidence["file"]), components)
                threat = {
                    "t_id": t_id,
                    "title": meta["title"],
                    "scenario": scenario,
                    "stride": meta["stride"],
                    "risk": meta["severity"],
                    "likelihood": meta["severity"],
                    "impact": meta["severity"],
                    "cwe": meta["cwe"],
                    "evidence": {"file": str(evidence["file"]), "line": evidence.get("line")},
                    "source": "source-scan",
                    "architectural_violation": False,
                    # The abuse-case verifier read this location; an indication
                    # stays ambiguous like every other unproven finding.
                    "evidence_check": "verified" if tier == _CONFIRMED_TIER else "ambiguous",
                    "evidence_basis": "llm-verified" if tier == _CONFIRMED_TIER else "ambiguous",
                    "abuse_case_id": case_id,
                    "abuse_case_step": step_no,
                    "source_scan_ref": f"{case_id}:{step_no}",
                    "mitigation_title": meta["mitigation_title"],
                }
                # A confirmed step claims a proven sink; an indication stays unproven.
                apply_intake(
                    threat,
                    dispatch_component=component_id,
                    component_name=component_name,
                    claimed_tier=tier,
                )
                if meta["remediation"]:
                    threat["remediation"] = {"how": meta["remediation"], "effort": "Medium"}
                threats.append(threat)
                existing[key] = t_id
                promoted.append(t_id)
            step_match["matched_finding_id"] = t_id
            step_match["match_basis"] = basis
            step_verdict["matched_finding_id"] = t_id
            bindings_changed = True

        case_match["matched_finding_ids"] = [
            step.get("matched_finding_id")
            for step in case_match.get("step_matches") or []
            if isinstance(step, dict) and step.get("matched_finding_id")
        ]

    verified = _verify_bound_findings(matches, verdict_by_case, threats, _configured_repo_root(output_dir))
    if promoted or bindings_changed or verified:
        _write(merged_path, merged)
        _write(matches_path, matches_doc)
        _write(verdicts_path, verdicts_doc)
    notes = [f"promoted {len(promoted)} abuse-case finding(s); verified {len(verified)} bound finding(s)"]
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
