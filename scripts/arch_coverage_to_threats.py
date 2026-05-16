#!/usr/bin/env python3
"""
arch_coverage_to_threats.py — Phase-9 bridge.

Converts $OUTPUT_DIR/.architecture-coverage.json into threat-shaped
candidates ready to merge into $OUTPUT_DIR/.threats-merged.json.

Selection policy (arch.md §Pipeline-Integration Punkt 5):
  * anti_pattern_candidates                          → source=architecture-coverage
  * threat_hypotheses with proof_state=confirmed     → source=threat-hypothesis
  * threat_hypotheses with proof_state in
    {control-derived, evidence-backed}               → NOT merged. They stay
                                                       in .architecture-coverage.json
                                                       and are persisted in
                                                       threat-model.yaml#threat_hypotheses[]
                                                       by Phase 11.

Output (.arch-coverage-threats.json):
  {
    "version": 1,
    "generated_at": "...",
    "threats": [...],       # ready to merge; t_id assigned by --merge-into
    "skipped":  [...]       # hypotheses NOT exported, with reason
  }

Modes:
  emit          — write .arch-coverage-threats.json (default).
  merge-into    — append entries to an existing .threats-merged.json,
                  re-assigning contiguous T-NNN ids.

Severity policy: risk / likelihood / impact default to the rule's
severity_cap; never Critical individually (arch.md §Severity-Policy).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


_HERE = Path(__file__).resolve().parent


_STRIDE_NO_SPACE_TO_SPACED = {
    "Spoofing": "Spoofing",
    "Tampering": "Tampering",
    "Repudiation": "Repudiation",
    "InformationDisclosure": "Information Disclosure",
    "DenialOfService": "Denial of Service",
    "ElevationOfPrivilege": "Elevation of Privilege",
}


def _component_for_evidence(evidence: list[dict] | None) -> tuple[str, str]:
    """Pick a coarse component for the threat record from the first
    evidence entry. The bridge does not run component discovery — the
    orchestrator's merger may re-attribute later."""
    if not evidence:
        return ("architecture", "Architecture")
    first = evidence[0]
    file = (first.get("file") or "").strip()
    if not file:
        return ("architecture", "Architecture")
    parts = file.replace("\\", "/").split("/")
    top = parts[0] if parts else "architecture"
    pretty = top.replace("_", " ").replace("-", " ").strip().title() or "Architecture"
    return (top, pretty)


def _evidence_for_threat(evidence: list[dict] | None) -> dict | None:
    if not evidence:
        return None
    e = evidence[0]
    line = e.get("line")
    try:
        line = int(line) if line is not None else None
    except (TypeError, ValueError):
        line = None
    file = (e.get("file") or "").strip()
    if not file:
        return None
    return {"file": file, "line": line}


def _build_threat(
    *,
    source: str,
    rule_id: str,
    title: str,
    cwe: str,
    stride: str,
    risk: str,
    evidence: list[dict],
    hypothesis_id: str | None = None,
) -> dict:
    component_id, component_name = _component_for_evidence(evidence)
    spaced_stride = _STRIDE_NO_SPACE_TO_SPACED.get(stride, stride)
    safe_risk = risk if risk in {"High", "Medium", "Low"} else "Medium"
    threat: dict[str, Any] = {
        "t_id": None,            # assigned by --merge-into; left None on emit
        "component_id": component_id,
        "component_name": component_name,
        "stride": spaced_stride,
        "risk": safe_risk,
        "likelihood": "Medium",
        "impact": safe_risk,
        "title": title,
        "cwe": cwe,
        "evidence": _evidence_for_threat(evidence),
        "source": source,
        "architectural_violation": True,
        "rule_id": rule_id,
    }
    if hypothesis_id:
        threat["hypothesis_id"] = hypothesis_id
    return threat


def select_and_build(coverage: dict) -> tuple[list[dict], list[dict]]:
    threats: list[dict] = []
    skipped: list[dict] = []

    for cand in coverage.get("anti_pattern_candidates", []) or []:
        if cand.get("confidence") != "high":
            skipped.append({
                "rule_id": cand.get("rule_id"),
                "reason": f"confidence={cand.get('confidence')} — bridge requires high",
            })
            continue
        if cand.get("severity_cap") == "Critical":
            skipped.append({
                "rule_id": cand.get("rule_id"),
                "reason": "severity_cap=Critical not permitted for architecture-coverage",
            })
            continue
        rule_id = cand.get("rule_id") or ""
        evidence = cand.get("evidence") or []
        threats.append(_build_threat(
            source="architecture-coverage",
            rule_id=rule_id,
            title=cand.get("title") or rule_id,
            cwe=cand.get("cwe") or "CWE-693",
            stride=_stride_for_rule(rule_id),
            risk=cand.get("severity_cap") or "Medium",
            evidence=evidence,
        ))

    for hyp in coverage.get("threat_hypotheses", []) or []:
        proof = hyp.get("proof_state")
        if proof != "confirmed":
            skipped.append({
                "hypothesis_id": hyp.get("hypothesis_id"),
                "rule_id": hyp.get("rule_id"),
                "reason": f"proof_state={proof} — only 'confirmed' is merged to threats[]",
            })
            continue
        if hyp.get("confidence") != "high":
            skipped.append({
                "hypothesis_id": hyp.get("hypothesis_id"),
                "rule_id": hyp.get("rule_id"),
                "reason": f"confidence={hyp.get('confidence')} — promotion requires high",
            })
            continue
        threats.append(_build_threat(
            source="threat-hypothesis",
            rule_id=hyp.get("rule_id") or "",
            title=hyp.get("title") or "Architecture-derived threat",
            cwe=hyp.get("cwe") or "CWE-693",
            stride=hyp.get("stride") or "Tampering",
            risk="High",
            evidence=hyp.get("positive_signals") or [],
            hypothesis_id=hyp.get("hypothesis_id"),
        ))

    return threats, skipped


_DOMAIN_TO_STRIDE = {
    "ARCH-COOKIE-001": "InformationDisclosure",
    "ARCH-CORS-001": "Tampering",
    "ARCH-JWT-001": "Spoofing",
    "ARCH-TLS-001": "InformationDisclosure",
    "ARCH-MGMT-001": "ElevationOfPrivilege",
}


def _stride_for_rule(rule_id: str) -> str:
    return _DOMAIN_TO_STRIDE.get(rule_id, "Tampering")


# ---------------------------------------------------------------------------
# Merge-into mode
# ---------------------------------------------------------------------------


_T_ID_RE = re.compile(r"^T-(\d{3,})$")


def _next_t_id(existing: list[dict]) -> int:
    max_id = 0
    for t in existing:
        m = _T_ID_RE.match(t.get("t_id", "") or "")
        if m:
            max_id = max(max_id, int(m.group(1)))
    return max_id + 1


def merge_into(merged_path: Path, new_threats: list[dict]) -> dict:
    """Append `new_threats` to an existing .threats-merged.json with
    contiguous T-NNN ids. Writes in place. Returns the resulting object.
    """
    data = json.loads(merged_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{merged_path}: root must be a JSON object")
    threats = data.setdefault("threats", [])
    next_id = _next_t_id(threats)
    appended = []
    for t in new_threats:
        new_id = f"T-{next_id:03d}"
        next_id += 1
        entry = dict(t)
        entry["t_id"] = new_id
        threats.append(entry)
        appended.append(new_id)
    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    merged_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {"appended": appended, "total": len(threats)}


# ---------------------------------------------------------------------------
# persist-hypotheses mode (Phase 11)
# ---------------------------------------------------------------------------


_HYP_ID_RE = re.compile(r"^HYP-(\d{3,})$")


def _next_hyp_id(existing: list[dict]) -> int:
    max_id = 0
    for h in existing:
        m = _HYP_ID_RE.match(str(h.get("id", "")) or "")
        if m:
            max_id = max(max_id, int(m.group(1)))
    return max_id + 1


def _domain_for_rule(rule_id: str) -> str | None:
    return {
        "ARCH-XSS-001": "FrontendSec",
        "ARCH-SQLI-001": "InputVal",
        "ARCH-AUTHZ-001": "AuthZ",
        "ARCH-INPUT-001": "InputVal",
    }.get(rule_id)


def _build_yaml_hypothesis(
    hyp: dict,
    hyp_id: str,
    promoted_threat_id: str | None,
) -> dict:
    """Map .architecture-coverage.json hypothesis → threat-model.yaml shape
    per schemas/threat-model.output.schema.yaml threat_hypotheses[]."""
    rule_id = hyp.get("rule_id") or ""
    out: dict[str, Any] = {
        "id": hyp_id,
        "source_hypothesis_id": hyp.get("hypothesis_id"),
        "rule_id": rule_id,
        "title": hyp.get("title") or rule_id,
        "threat_category_id": hyp.get("threat_category_id"),
        "stride": hyp.get("stride"),
        "cwe": hyp.get("cwe"),
        "component_id": hyp.get("component_id"),
        "domain": _domain_for_rule(rule_id),
        "surface": hyp.get("surface"),
        "proof_state": hyp.get("proof_state") or "control-derived",
        "confidence": hyp.get("confidence") or "medium",
        "linked_control_ids": [],
        "linked_threat_ids": [],
        "promoted_threat_id": promoted_threat_id,
        "evidence": [],
        "validation_objective": _default_validation_objective(hyp),
    }
    for sig in hyp.get("positive_signals") or []:
        if not isinstance(sig, dict):
            continue
        file = sig.get("file")
        line = sig.get("line")
        signal = sig.get("signal") or ""
        if not file:
            continue
        try:
            line_int = int(line) if line is not None else 0
        except (TypeError, ValueError):
            line_int = 0
        out["evidence"].append({
            "file": str(file),
            "line": line_int,
            "signal": str(signal),
        })
    return out


_DEFAULT_VALIDATION_BY_RULE = {
    "ARCH-XSS-001": (
        "Confirm that user-controlled input reaches a browser-rendered "
        "sink (innerHTML / dangerouslySetInnerHTML / v-html / "
        "bypassSecurityTrustHtml) without sanitisation."
    ),
    "ARCH-SQLI-001": (
        "Validate whether attacker-controlled parameters reach a raw SQL "
        "construction (concatenation, template literal, f-string) without "
        "parameter binding."
    ),
    "ARCH-AUTHZ-001": (
        "Probe destructive routes (DELETE/PUT/PATCH) for cross-user / "
        "cross-tenant access using a low-privilege test account."
    ),
    "ARCH-INPUT-001": (
        "Confirm whether an external payload reaches a sensitive sink "
        "without schema or allowlist validation."
    ),
}


def _default_validation_objective(hyp: dict) -> str:
    rule_id = hyp.get("rule_id") or ""
    return _DEFAULT_VALIDATION_BY_RULE.get(
        rule_id,
        f"Validate or refute the hypothesis via a targeted probe (see {rule_id}).",
    )


def persist_hypotheses(
    coverage: dict,
    yaml_path: Path,
    threats_merged: dict | None = None,
) -> dict:
    """Merge unpromoted hypotheses from .architecture-coverage.json into
    threat-model.yaml#threat_hypotheses[]. Idempotent on
    source_hypothesis_id — repeated runs do not duplicate.

    Promotion linkage: if .threats-merged.json contains a threat with
    source=threat-hypothesis and a matching hypothesis_id, the resulting
    yaml entry carries promoted_threat_id pointing at that T-NNN.
    """
    if yaml is None:  # pragma: no cover
        raise RuntimeError("PyYAML required for persist-hypotheses mode")

    promoted_map: dict[str, str] = {}
    if isinstance(threats_merged, dict):
        for t in threats_merged.get("threats") or []:
            if not isinstance(t, dict):
                continue
            if t.get("source") != "threat-hypothesis":
                continue
            sid = t.get("hypothesis_id")
            tid = t.get("t_id")
            if isinstance(sid, str) and isinstance(tid, str):
                promoted_map[sid] = tid

    if yaml_path.is_file():
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        if not isinstance(doc, dict):
            raise ValueError(f"{yaml_path}: root must be a mapping")
    else:
        doc = {}

    existing = doc.setdefault("threat_hypotheses", []) or []
    if not isinstance(existing, list):
        raise ValueError(f"{yaml_path}: threat_hypotheses must be a list")
    doc["threat_hypotheses"] = existing

    by_source: dict[str, dict] = {
        h.get("source_hypothesis_id"): h
        for h in existing
        if isinstance(h, dict) and h.get("source_hypothesis_id")
    }

    next_id = _next_hyp_id(existing)
    appended: list[str] = []
    updated: list[str] = []
    skipped: list[dict] = []

    for hyp in coverage.get("threat_hypotheses") or []:
        if not isinstance(hyp, dict):
            continue
        source_id = hyp.get("hypothesis_id")
        if not source_id:
            skipped.append({"reason": "missing hypothesis_id", "rule_id": hyp.get("rule_id")})
            continue
        promoted_threat_id = promoted_map.get(source_id)

        if source_id in by_source:
            target = by_source[source_id]
            if promoted_threat_id and not target.get("promoted_threat_id"):
                target["promoted_threat_id"] = promoted_threat_id
                updated.append(target.get("id") or source_id)
            continue

        new_id = f"HYP-{next_id:03d}"
        next_id += 1
        target = _build_yaml_hypothesis(hyp, new_id, promoted_threat_id)
        existing.append(target)
        by_source[source_id] = target
        appended.append(new_id)

    if appended or updated or not yaml_path.is_file():
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        yaml_path.write_text(
            yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

    return {"appended": appended, "updated": updated, "skipped": skipped,
            "total_hypotheses": len(existing)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="arch_coverage_to_threats.py", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s_emit = sub.add_parser("emit", help="Write .arch-coverage-threats.json")
    s_emit.add_argument("--input", required=True,
                        help="Path to .architecture-coverage.json")
    s_emit.add_argument("--output-dir", required=True)

    s_merge = sub.add_parser("merge-into", help="Append candidates to .threats-merged.json")
    s_merge.add_argument("--input", required=True,
                         help="Path to .architecture-coverage.json")
    s_merge.add_argument("--threats-merged", required=True,
                         help="Path to .threats-merged.json (in-place update).")

    s_persist = sub.add_parser(
        "persist-hypotheses",
        help="Merge unpromoted hypotheses into threat-model.yaml#threat_hypotheses[]")
    s_persist.add_argument("--input", required=True,
                           help="Path to .architecture-coverage.json")
    s_persist.add_argument("--threat-model", required=True,
                           help="Path to threat-model.yaml (in-place update; created if absent)")
    s_persist.add_argument("--threats-merged",
                           help="Optional .threats-merged.json — used to link promoted_threat_id")

    args = p.parse_args(argv)

    coverage_path = Path(args.input)
    if not coverage_path.is_file():
        print(f"arch_coverage_to_threats.py: input not found: {coverage_path}", file=sys.stderr)
        return 1
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))

    threats, skipped = select_and_build(coverage)

    if args.cmd == "emit":
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / ".arch-coverage-threats.json"
        target.write_text(json.dumps({
            "version": 1,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "threats": threats,
            "skipped": skipped,
        }, indent=2) + "\n", encoding="utf-8")
        print(str(target))
        return 0

    if args.cmd == "merge-into":
        merged_path = Path(args.threats_merged)
        if not merged_path.is_file():
            print(f"arch_coverage_to_threats.py: threats-merged not found: {merged_path}", file=sys.stderr)
            return 1
        result = merge_into(merged_path, threats)
        json.dump({"merged": result, "skipped": skipped}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    if args.cmd == "persist-hypotheses":
        yaml_path = Path(args.threat_model)
        merged_data: dict | None = None
        if args.threats_merged:
            mp = Path(args.threats_merged)
            if mp.is_file():
                merged_data = json.loads(mp.read_text(encoding="utf-8"))
        try:
            result = persist_hypotheses(coverage, yaml_path, merged_data)
        except RuntimeError as e:
            print(f"arch_coverage_to_threats.py: {e}", file=sys.stderr)
            return 1
        json.dump({"persisted": result}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
