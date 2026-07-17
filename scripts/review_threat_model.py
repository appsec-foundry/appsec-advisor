#!/usr/bin/env python3
"""Consumer-side triage of an existing ``threat-model.yaml``.

Powers ``/appsec-advisor:review-threat-model`` — a user-facing skill run
*after* a threat model exists, completely independent of the generation
pipeline. This module is the deterministic half:

  * ``reconcile`` reads the committed ``threat-model.yaml`` and the user's
    triage sidecar, joins them by a stable finding key, and emits a ranked
    JSON view (consumed by the skill to drive the interactive triage loop).
  * ``render`` turns the sidecar + model into a ``remediation-plan.md``.

Design boundaries (why this is a Consumer, never a Producer):
  * Severity and remediation text are READ from the model, never computed
    or authored here.
  * The triage decisions live ONLY in the sidecar (default
    ``<repo>/.appsec-triage/triage.yaml``) — never written back into
    ``threat-model.yaml`` (which the pipeline overwrites on re-scan).
  * The sidecar lives outside ``OUTPUT_DIR`` so runtime cleanup, the
    diagnostic bundle, and ``show``/``health`` never touch it.

Reconciliation is keyed on ``local_id`` (component-scoped, more stable than
the global ``T-NNN`` id, which ``_assign_t_ids`` renumbers across scans),
falling back to ``id`` when a finding has no ``local_id``. Triage entries
whose key no longer exists in the model are surfaced as ``stale`` — never
silently dropped, never a hard error.

Output is byte-stable for a given (model, sidecar) pair: no wall-clock, no
network, no LLM.

Usage:
    review_threat_model.py reconcile --output-dir PATH --triage PATH
    review_threat_model.py render    --output-dir PATH --triage PATH --plan PATH

Exit codes:
    0  ok
    1  no threat model found at <output-dir>/threat-model.yaml
    2  error (unreadable / unparseable input, bad args)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

# Triage decisions the sidecar may carry. Anything else is coerced to
# "untriaged" so a hand-edited sidecar can never route a finding into a
# bucket the renderer doesn't know about.
_DECISIONS = ("fix", "defer", "accept-risk", "untriaged")
_DECISION_TITLES = {
    "fix": "To Fix",
    "defer": "Deferred",
    "accept-risk": "Accepted Risk",
    "untriaged": "Untriaged — decision still needed",
}


# ---------------------------------------------------------------------------
# Field extraction (defensive — shapes vary across schema/fixture versions)
# ---------------------------------------------------------------------------


def _sev_label(threat: dict) -> str:
    """Effective severity for ranking; falls back to risk, then severity."""
    raw = (threat.get("effective_severity") or threat.get("risk") or threat.get("severity") or "").strip()
    label = raw[:1].upper() + raw[1:].lower() if raw else ""
    return label if label in _SEVERITY_ORDER else ""


def _finding_key(threat: dict) -> str:
    """Stable-ish join key. Prefer component-scoped local_id over T-NNN."""
    return str(threat.get("local_id") or threat.get("id") or "").strip()


def _title(threat: dict) -> str:
    title = (threat.get("title") or threat.get("name") or "").strip()
    if title:
        return title
    return (threat.get("scenario") or threat.get("description") or "").strip()[:80].rstrip()


def _effort(threat: dict) -> str:
    rem = threat.get("remediation")
    if isinstance(rem, dict):
        return str(rem.get("effort") or "").strip()
    return ""


def _remediation_steps(threat: dict) -> list[str]:
    rem = threat.get("remediation")
    if isinstance(rem, dict):
        steps = rem.get("steps")
        if isinstance(steps, list):
            return [str(s).strip() for s in steps if str(s).strip()]
    return []


def _norm_decision(value: object) -> str:
    v = str(value or "").strip().lower()
    return v if v in _DECISIONS else "untriaged"


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------


def _load_model(output_dir: Path) -> dict:
    model_path = output_dir / "threat-model.yaml"
    if not model_path.is_file():
        print(f"No threat model found at {model_path}", file=sys.stderr)
        raise SystemExit(1)
    try:
        data = yaml.safe_load(model_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        print(f"Could not parse {model_path}: {e}", file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(data, dict):
        print(f"Unexpected threat-model.yaml shape in {model_path}", file=sys.stderr)
        raise SystemExit(2)
    return data


def _load_sidecar(sidecar_path: Path) -> dict:
    """Return {key: {decision, rationale, owner, target_sprint}} — never raises
    on a missing file; a corrupt sidecar is a hard error (don't silently lose
    user decisions)."""
    if not sidecar_path.is_file():
        return {}
    try:
        doc = yaml.safe_load(sidecar_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        print(f"Could not parse triage sidecar {sidecar_path}: {e}", file=sys.stderr)
        raise SystemExit(2)
    findings = doc.get("findings") if isinstance(doc, dict) else None
    return findings if isinstance(findings, dict) else {}


# ---------------------------------------------------------------------------
# Reconcile
# ---------------------------------------------------------------------------


def reconcile(output_dir: Path, sidecar_path: Path) -> dict:
    model = _load_model(output_dir)
    threats = model.get("threats") or []
    triage = _load_sidecar(sidecar_path)

    seen_keys: set[str] = set()
    findings: list[dict] = []
    for t in threats:
        if not isinstance(t, dict):
            continue
        key = _finding_key(t)
        if not key:
            continue
        seen_keys.add(key)
        entry = triage.get(key) if isinstance(triage.get(key), dict) else {}
        findings.append(
            {
                "key": key,
                "id": str(t.get("id") or "").strip(),
                "title": _title(t),
                "component": str(t.get("component") or t.get("component_name") or "").strip(),
                "severity": _sev_label(t),
                "effort": _effort(t),
                "has_mitigation": bool(t.get("mitigation_ids")),
                "decision": _norm_decision(entry.get("decision")),
                "rationale": str(entry.get("rationale") or "").strip(),
                "owner": str(entry.get("owner") or "").strip(),
                "target_sprint": str(entry.get("target_sprint") or "").strip(),
            }
        )

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["id"]))

    # Triage entries whose finding is gone from the model — surface, never drop.
    stale = []
    for key, entry in triage.items():
        if key in seen_keys:
            continue
        e = entry if isinstance(entry, dict) else {}
        stale.append(
            {
                "key": key,
                "decision": _norm_decision(e.get("decision")),
                "rationale": str(e.get("rationale") or "").strip(),
            }
        )
    stale.sort(key=lambda s: s["key"])

    by_decision: dict[str, int] = {d: 0 for d in _DECISIONS}
    for f in findings:
        by_decision[f["decision"]] += 1

    meta = model.get("meta") if isinstance(model.get("meta"), dict) else {}
    return {
        "project": str(meta.get("project") or "").strip(),
        "generated": str(meta.get("generated") or "").strip(),
        "total": len(findings),
        "by_decision": by_decision,
        "findings": findings,
        "stale": stale,
    }


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------


def _render_finding_block(f: dict) -> list[str]:
    tag = f"[{f['id']}] " if f["id"] else ""
    meta_bits = [b for b in (f["severity"], f["component"], f["effort"] and f"Effort: {f['effort']}") if b]
    lines = [f"### {tag}{f['title']}".rstrip(), ""]
    if meta_bits:
        lines.append("_" + " · ".join(meta_bits) + "_")
        lines.append("")
    ownership = [
        b
        for b in (f["owner"] and f"**Owner:** {f['owner']}", f["target_sprint"] and f"**Target:** {f['target_sprint']}")
        if b
    ]
    if ownership:
        lines.append(" · ".join(ownership))
        lines.append("")
    if f["rationale"]:
        lines.append(f"**Rationale:** {f['rationale']}")
        lines.append("")
    return lines


def render(output_dir: Path, sidecar_path: Path, plan_path: Path) -> Path:
    view = reconcile(output_dir, sidecar_path)
    # Remediation steps are read straight from the model, keyed by finding key.
    model = _load_model(output_dir)
    steps_by_key = {
        _finding_key(t): _remediation_steps(t)
        for t in (model.get("threats") or [])
        if isinstance(t, dict) and _finding_key(t)
    }

    project = view["project"] or "(unnamed)"
    lines: list[str] = [
        f"# Remediation Plan — {project}",
        "",
        "> Generated by `/appsec-advisor:review-threat-model` from the committed "
        "`threat-model.yaml`. Triage decisions are the analyst's; severity and "
        "remediation steps are read verbatim from the model.",
        "",
    ]
    if view["generated"]:
        lines += [f"Source model generated: `{view['generated']}` · {view['total']} findings", ""]

    # Triage summary table.
    lines += ["## Triage summary", "", "| Decision | Count |", "|---|---|"]
    for d in _DECISIONS:
        lines.append(f"| {_DECISION_TITLES[d].split(' — ')[0]} | {view['by_decision'][d]} |")
    lines.append("")

    # One section per decision bucket, findings already severity-ranked.
    for d in _DECISIONS:
        bucket = [f for f in view["findings"] if f["decision"] == d]
        if not bucket:
            continue
        lines += [f"## {_DECISION_TITLES[d]}", ""]
        for f in bucket:
            lines += _render_finding_block(f)
            steps = steps_by_key.get(f["key"]) or []
            if d in ("fix", "defer") and steps:
                lines.append("Remediation:")
                lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
                lines.append("")

    if view["stale"]:
        lines += [
            "## Stale — triaged but no longer in the model",
            "",
            "These findings had a triage decision but are absent from the current "
            "`threat-model.yaml` (fixed, merged, or renumbered). Review before discarding.",
            "",
        ]
        for s in view["stale"]:
            lines.append(f"- `{s['key']}` — was _{s['decision']}_" + (f": {s['rationale']}" if s["rationale"] else ""))
        lines.append("")

    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return plan_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Consumer-side triage of an existing threat model.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("reconcile", help="Emit a ranked, triage-merged JSON view of the findings.")
    r.add_argument("--output-dir", type=Path, required=True, help="Directory holding threat-model.yaml.")
    r.add_argument("--triage", type=Path, required=True, help="Path to the triage sidecar (may not exist yet).")

    p = sub.add_parser("render", help="Render remediation-plan.md from the sidecar + model.")
    p.add_argument("--output-dir", type=Path, required=True, help="Directory holding threat-model.yaml.")
    p.add_argument("--triage", type=Path, required=True, help="Path to the triage sidecar.")
    p.add_argument("--plan", type=Path, required=True, help="Path to write remediation-plan.md.")

    ns = ap.parse_args(argv)

    if ns.cmd == "reconcile":
        view = reconcile(ns.output_dir, ns.triage)
        print(json.dumps(view, indent=2))
        return 0

    if ns.cmd == "render":
        out = render(ns.output_dir, ns.triage, ns.plan)
        print(str(out))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
