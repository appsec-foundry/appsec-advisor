#!/usr/bin/env python3
"""Consumer-side triage of an existing ``threat-model.yaml``.

Powers ``/appsec-advisor:review-threat-model`` — a user-facing skill run
*after* a threat model exists, completely independent of the generation
pipeline. This module is the deterministic half:

  * ``reconcile`` reads the committed ``threat-model.yaml`` and the user's
    triage sidecar, joins them by a stable finding key, and emits a ranked
    JSON view (consumed by the skill to drive the interactive triage loop).
  * ``console`` extends that view with a posture verdict, priority-ranked
    mitigations (with the findings each covers), and findings grouped by
    security domain — one payload that powers the skill's triage console.
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
    review_threat_model.py console   --output-dir PATH --triage PATH
    review_threat_model.py render    --output-dir PATH --triage PATH --plan PATH

Exit codes:
    0  ok
    1  no threat model found at <output-dir>/threat-model.yaml
    2  error (unreadable / unparseable input, bad args)
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

import yaml

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
_PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}
# Within a priority band, actionable fixes rank above items still needing a look
# (investigate/review) so the backlog surfaces do-now work first.
_KIND_ORDER = {"fix": 0, "investigate": 1, "review": 2}
# Security-control effectiveness, worst-first — drives the posture-by-domain rank.
_EFFECTIVENESS_ORDER = {"Missing": 0, "Weak": 1, "Partial": 2, "Adequate": 3}

# Human-readable threat-domain names ("Broken Authentication", "Injection", …)
# live in the generation pipeline's taxonomy. Read-only lookup; the console view
# uses it to group findings by area. Falls back gracefully if absent.
_TAXONOMY_PATH = Path(__file__).resolve().parent.parent / "data" / "threat-category-taxonomy.yaml"

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


def _primary_location(threat: dict) -> str:
    """Best available source location for a finding, as ``file:line`` (or just
    ``file``). Prefers the first ``evidence[].file`` (populated far more often
    than ``affected_files``), then ``affected_files[0]``, then the logical
    ``component`` as a last resort so a row is never location-less."""
    ev = threat.get("evidence")
    if isinstance(ev, list):
        for e in ev:
            if isinstance(e, dict) and str(e.get("file") or "").strip():
                f = str(e["file"]).strip()
                line = e.get("line")
                return f"{f}:{line}" if line not in (None, "", 0) else f
    af = threat.get("affected_files")
    if isinstance(af, list) and af and str(af[0]).strip():
        return str(af[0]).strip()
    return str(threat.get("component") or threat.get("component_name") or "").strip()


def _norm_decision(value: object) -> str:
    v = str(value or "").strip().lower()
    return v if v in _DECISIONS else "untriaged"


def _violated_requirements(threat: dict) -> list[str]:
    """Requirement IDs a threat evidences — the canonical ``violated_requirements``
    array plus a single ``requirement_id``, order-preserving + de-duplicated.

    Deliberately mirrors ONLY the threat-forward source used by the report's
    traceability table, NOT the ``mitigation.fulfills_requirements`` reverse link
    (``_build_requirements_mapping_rows`` in the pipeline). A triage badge needs
    "does this finding break a custom requirement", not the authoritative
    requirement→finding→mitigation mapping (which stays in the rendered report).
    Filtering against the declared custom IDs happens in ``console``."""
    out: list[str] = []
    seen: set[str] = set()
    for rid in threat.get("violated_requirements") or []:
        r = str(rid).strip()
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    single = str(threat.get("requirement_id") or "").strip()
    if single and single not in seen:
        out.append(single)
    return out


def _load_category_names(path: Path | None = None) -> dict[str, str]:
    """Map ``threat_category_id`` (TH-NN) -> human domain name. Read-only, best
    effort: a missing or malformed taxonomy yields an empty map (the console
    then shows the raw code), never an error."""
    p = path or _TAXONOMY_PATH
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    cats = doc.get("categories") if isinstance(doc, dict) else None
    out: dict[str, str] = {}
    if isinstance(cats, list):
        for c in cats:
            if not isinstance(c, dict):
                continue
            cid = str(c.get("id") or "").strip()
            name = str(c.get("name") or c.get("title") or "").strip()
            if cid:
                out[cid] = name or cid
    return out


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


def _load_requirements(output_dir: Path, meta: dict) -> dict:
    """Gate + declared custom requirement IDs for the requirements badge/lens.

    The badge is shown ONLY for *explicit* custom requirements a team integrated
    — never the bundled OWASP best-practices baseline, never a skipped stub, and
    never when the requirements check was off for the run. Signals (all read-only):

      * ``meta.check_requirements`` — the run activated the check.
      * ``<output-dir>/.requirements.yaml`` ``source`` — ``skipped`` (stub) and
        ``bundled-bestpractices`` (zero-config OWASP fallback) are both excluded;
        anything else (company catalog / cache / URL) is a real custom source.
      * non-empty ``categories`` — a source that actually declares requirements.

    Returns ``{integrated, ids, url_by_id}``; ``integrated`` is False (and ids
    empty) whenever any signal fails, so the caller shows no requirement signal."""
    empty = {"integrated": False, "ids": set(), "url_by_id": {}}
    if not bool(meta.get("check_requirements")):
        return empty
    path = output_dir / ".requirements.yaml"
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return empty
    if not isinstance(doc, dict):
        return empty
    source = str(doc.get("source") or "").strip().lower()
    cats = doc.get("categories") or []
    if source in ("skipped", "bundled-bestpractices") or not isinstance(cats, list) or not cats:
        return empty
    ids: set[str] = set()
    url_by_id: dict[str, str] = {}
    for cat in cats:
        if not isinstance(cat, dict):
            continue
        for req in cat.get("requirements") or []:
            if not isinstance(req, dict):
                continue
            rid = str(req.get("id") or "").strip()
            if rid:
                ids.add(rid)
                url_by_id.setdefault(rid, str(req.get("url") or "").strip())
    return {"integrated": bool(ids), "ids": ids, "url_by_id": url_by_id} if ids else empty


# ---------------------------------------------------------------------------
# Reconcile
# ---------------------------------------------------------------------------


def reconcile(output_dir: Path, sidecar_path: Path, category_names: dict[str, str] | None = None) -> dict:
    model = _load_model(output_dir)
    threats = model.get("threats") or []
    triage = _load_sidecar(sidecar_path)
    cat_names = category_names or {}

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
        cid = str(t.get("threat_category_id") or "").strip()
        findings.append(
            {
                "key": key,
                "id": str(t.get("id") or "").strip(),
                "title": _title(t),
                "component": str(t.get("component") or t.get("component_name") or "").strip(),
                "severity": _sev_label(t),
                "effort": _effort(t),
                "cwe": str(t.get("cwe") or "").strip(),
                "location": _primary_location(t),
                "category_id": cid,
                "category_name": cat_names.get(cid, "") if cid else "",
                "has_mitigation": bool(t.get("mitigation_ids")),
                "violated_requirements": _violated_requirements(t),
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
# Console view (verdict + top findings + top mitigations + areas)
#
# Everything below is a deterministic *read* of the model, joined with the
# reconcile view. It powers the interactive triage console in the skill: one
# JSON payload the skill formats into a briefing and drill-down menus. No
# severity or remediation text is computed here — only rolled up.
# ---------------------------------------------------------------------------


def build_mitigations(model: dict, key_by_tid: dict[str, str]) -> list[dict]:
    """Mitigations ranked by priority then leverage (how many findings each
    covers). ``covered_keys`` fans a mitigation's ``threat_ids`` (global T-NNN)
    back to finding keys (local_id) so acting on a mitigation can triage every
    finding it resolves in one shot."""
    out: list[dict] = []
    for m in model.get("mitigations") or []:
        if not isinstance(m, dict):
            continue
        mid = str(m.get("id") or "").strip()
        if not mid:
            continue
        tids = [str(x).strip() for x in (m.get("threat_ids") or []) if str(x).strip()]
        covered = [key_by_tid[t] for t in tids if t in key_by_tid]
        rem = m.get("remediation")
        effort = (rem.get("effort") if isinstance(rem, dict) else None) or m.get("effort")
        out.append(
            {
                "id": mid,
                "title": str(m.get("title") or "").strip(),
                "priority": str(m.get("priority") or "").strip(),
                "severity": _sev_label(m) or str(m.get("severity") or "").strip(),
                "kind": str(m.get("kind") or "").strip(),
                "effort": str(effort or "").strip(),
                "threat_ids": tids,
                "covered_keys": covered,
                "coverage": len(covered),
            }
        )
    out.sort(
        key=lambda x: (
            _PRIORITY_ORDER.get(x["priority"], 9),
            _KIND_ORDER.get(x["kind"], 3),
            -x["coverage"],
            x["id"],
        )
    )
    return out


def build_areas(findings: list[dict]) -> list[dict]:
    """Group findings by threat domain (``category_name``). Ranked by blast:
    Critical count, then High, then total. Uncategorized findings collapse into
    a trailing bucket."""
    groups: dict[str, dict] = {}
    for f in findings:
        cid = f.get("category_id") or ""
        gkey = cid or "__uncat__"
        g = groups.get(gkey)
        if g is None:
            g = groups[gkey] = {
                "category_id": cid,
                "category_name": f.get("category_name") or (cid if cid else "Uncategorized"),
                "keys": [],
                "by_severity": collections.Counter(),
            }
        g["keys"].append(f["key"])
        g["by_severity"][f["severity"] or "Unrated"] += 1
    areas: list[dict] = []
    for g in groups.values():
        sev = g["by_severity"]
        areas.append(
            {
                "category_id": g["category_id"],
                "category_name": g["category_name"],
                "keys": g["keys"],
                "total": len(g["keys"]),
                "critical": sev.get("Critical", 0),
                "high": sev.get("High", 0),
                "by_severity": dict(sev),
            }
        )
    areas.sort(key=lambda a: (-a["critical"], -a["high"], -a["total"], a["category_name"]))
    return areas


def build_verdict(model: dict, findings: list[dict], mitigations: list[dict]) -> dict:
    """Deterministic posture roll-up of the analyst's own numbers — never a
    re-score. Severity mix, hottest areas/components, mitigation coverage,
    design-weakness count, and triage progress."""
    sev = collections.Counter(f["severity"] or "Unrated" for f in findings)
    comps = collections.Counter(f["component"] for f in findings if f["component"])
    area_ct = collections.Counter((f["category_name"] or f["category_id"]) for f in findings if f.get("category_id"))
    with_mit = sum(1 for f in findings if f["has_mitigation"])
    triaged = sum(1 for f in findings if f["decision"] != "untriaged")
    prio = collections.Counter(m["priority"] for m in mitigations if m["priority"])
    return {
        "by_severity": {s: sev.get(s, 0) for s in ("Critical", "High", "Medium", "Low", "Informational") if sev.get(s)},
        "unrated": sev.get("Unrated", 0),
        "components": len(comps),
        "top_components": comps.most_common(3),
        "top_areas": area_ct.most_common(3),
        "weaknesses": len(model.get("weaknesses") or []),
        "with_mitigation": with_mit,
        # Remediation backlog by mitigation priority — the console's primary spine.
        "by_priority": {p: prio.get(p, 0) for p in ("P1", "P2", "P3") if prio.get(p)},
        "p1_mitigations": prio.get("P1", 0),
        # Findings the model proposes no mitigation for — a distinct triage bucket
        # (they cannot be reached by walking mitigations, so never let them vanish).
        "uncovered": len(findings) - with_mit,
        "triaged": triaged,
    }


def build_requirement_groups(findings: list[dict], url_by_id: dict[str, str] | None = None) -> list[dict]:
    """Group findings by each custom requirement they violate (a finding may
    appear under several). Ranked by blast (Critical, then High, then total).
    Only meaningful when explicit custom requirements were integrated — the
    caller passes findings already tagged with gate-filtered ``requirements``."""
    url_by_id = url_by_id or {}
    groups: dict[str, dict] = {}
    for f in findings:
        for rid in f.get("requirements") or []:
            g = groups.get(rid)
            if g is None:
                g = groups[rid] = {"requirement_id": rid, "keys": [], "by_severity": collections.Counter()}
            g["keys"].append(f["key"])
            g["by_severity"][f["severity"] or "Unrated"] += 1
    out: list[dict] = []
    for g in groups.values():
        sev = g["by_severity"]
        out.append(
            {
                "requirement_id": g["requirement_id"],
                "url": url_by_id.get(g["requirement_id"], ""),
                "keys": g["keys"],
                "total": len(g["keys"]),
                "critical": sev.get("Critical", 0),
                "high": sev.get("High", 0),
                "by_severity": dict(sev),
            }
        )
    out.sort(key=lambda a: (-a["critical"], -a["high"], -a["total"], a["requirement_id"]))
    return out


def build_worst_case(model: dict, findings: list[dict], mitigations: list[dict], limit: int = 3) -> list[dict]:
    """The few concrete "if you do nothing" scenarios, read verbatim from the
    model's own ``critical_findings[]`` (producer-curated: ``threat_id`` +
    one-line ``summary`` + covering ``mitigation_id``). Joined to severity /
    component / mitigation priority, severity-ranked, capped. Falls back to the
    top Critical/High findings' titles when the model curated none. Never
    authors text — ``summary`` is the producer's."""
    find_by_id = {f["id"]: f for f in findings if f.get("id")}
    mit_by_id = {m["id"]: m for m in mitigations if m.get("id")}
    out: list[dict] = []
    for c in model.get("critical_findings") or []:
        if not isinstance(c, dict):
            continue
        tid = str(c.get("threat_id") or "").strip()
        f = find_by_id.get(tid)
        if not f:
            continue
        mid = str(c.get("mitigation_id") or "").strip()
        m = mit_by_id.get(mid)
        out.append(
            {
                "id": tid,
                "severity": f["severity"],
                "component": f["component"],
                "summary": str(c.get("summary") or "").strip() or f["title"],
                "mitigation_id": mid if m else "",
                "priority": (m.get("priority") if m else "") or "",
            }
        )
    if not out:  # no curated worst-case — degrade to the top Critical/High findings
        for f in findings:
            if _SEVERITY_ORDER.get(f["severity"], 9) > 1:
                continue
            out.append(
                {
                    "id": f["id"],
                    "severity": f["severity"],
                    "component": f["component"],
                    "summary": f["title"],
                    "mitigation_id": "",
                    "priority": "",
                }
            )
    out.sort(key=lambda w: (_SEVERITY_ORDER.get(w["severity"], 9), w["id"]))
    return out[:limit]


def build_quick_wins(mitigations: list[dict]) -> list[dict]:
    """Low-effort mitigations that resolve at least one Critical/High finding —
    the value/effort sweet spot. Ranked by leverage (coverage), then priority.
    Expects mitigations already enriched with ``covered_severities`` (console
    does this). Mitigations with no ``effort`` are excluded — unknown ≠ quick."""
    out = [
        m
        for m in mitigations
        if str(m.get("effort") or "").strip().lower() == "low"
        and (m.get("covered_severities", {}).get("Critical") or m.get("covered_severities", {}).get("High"))
    ]
    out.sort(key=lambda m: (-m["coverage"], _PRIORITY_ORDER.get(m["priority"], 9), m["id"]))
    return out


def _normalize_domain(raw: str) -> str:
    """Clean display name for a control domain. Targeted normalisation so the
    security aspects a reviewer expects — above all Authentication and
    Authorization — appear under stable canonical names and their label variants
    ("Identity and Authentication", "Identity and Authentication Controls") fold
    into one domain. A display alias only: it never invents a domain, only
    renames/merges the model's own ``security_controls[].domain`` strings; other
    domains just lose a trailing " Controls" for brevity."""
    r = raw.strip()
    low = r.lower()
    if "authorization" in low or "access control" in low:
        return "Authorization"
    if "authentication" in low or "identity" in low:
        return "Authentication"
    return r[: -len(" Controls")].strip() if low.endswith("controls") else r


def build_recommended(mitigations: list[dict], limit: int = 5) -> list[dict]:
    """The proactive "fix first" recommendation — what the tool leads with so a
    developer is told where to start instead of scanning the whole backlog.

    A recommended fix is: actionable now (``kind == fix`` — a concrete change, not
    an investigate/review that needs analysis first = low implementation risk),
    cheap (``effort == Low``), and worth it (covers a Critical or High finding).
    Ranked by the worst severity it removes, then leverage, then priority; capped.
    Expects mitigations enriched with ``covered_severities`` (console does it)."""

    def _worst_rank(m: dict) -> int:
        cs = m.get("covered_severities") or {}
        return min((_SEVERITY_ORDER.get(s, 9) for s in cs), default=9)

    out = [
        m
        for m in mitigations
        if str(m.get("kind") or "").strip().lower() == "fix"
        and str(m.get("effort") or "").strip().lower() == "low"
        and ((m.get("covered_severities") or {}).get("Critical") or (m.get("covered_severities") or {}).get("High"))
    ]
    out.sort(key=lambda m: (_worst_rank(m), -m["coverage"], _PRIORITY_ORDER.get(m["priority"], 9), m["id"]))
    return out[:limit]


def build_control_posture(model: dict) -> list[dict]:
    """Security controls grouped by (normalised) domain with their effectiveness
    rating and assessment — read from ``security_controls[]``. Ranked worst-first
    (Missing → Weak → Partial → Adequate) by the weakest control in each domain.
    Domains carry canonical display names (``_normalize_domain``) so Authentication
    and Authorization are always shown as such. A read-only posture roll-up,
    never a re-score."""
    groups: dict[str, dict] = {}
    for c in model.get("security_controls") or []:
        if not isinstance(c, dict):
            continue
        raw_domain = str(c.get("domain") or "").strip()
        if not raw_domain:
            continue
        domain = _normalize_domain(raw_domain)
        g = groups.get(domain)
        if g is None:
            g = groups[domain] = {"domain": domain, "controls": [], "by_effectiveness": collections.Counter()}
        eff = str(c.get("effectiveness") or "").strip()
        g["controls"].append(
            {
                "control": str(c.get("control") or "").strip(),
                "effectiveness": eff,
                "kind": str(c.get("kind") or "").strip(),
                "assessment": str(c.get("assessment") or "").strip(),
            }
        )
        g["by_effectiveness"][eff or "Unknown"] += 1
    out: list[dict] = []
    for g in groups.values():
        worst = min((_EFFECTIVENESS_ORDER.get(c["effectiveness"], 9) for c in g["controls"]), default=9)
        # Label the domain by its weakest control (the rating the user acts on).
        worst_label = next((k for k, v in _EFFECTIVENESS_ORDER.items() if v == worst), "Unknown")
        out.append(
            {
                "domain": g["domain"],
                "controls": g["controls"],
                "total": len(g["controls"]),
                "by_effectiveness": dict(g["by_effectiveness"]),
                "worst_effectiveness": worst_label,
                "_worst_rank": worst,
            }
        )
    out.sort(key=lambda d: (d["_worst_rank"], -d["total"], d["domain"]))
    return out


def console(output_dir: Path, sidecar_path: Path, taxonomy_path: Path | None = None) -> dict:
    """One payload for the interactive console: the reconcile view plus ranked
    mitigations, area groupings, worst-case scenarios, the requirements lens
    (custom requirements only), and the posture verdict."""
    cat_names = _load_category_names(taxonomy_path)
    view = reconcile(output_dir, sidecar_path, category_names=cat_names)
    model = _load_model(output_dir)
    meta = model.get("meta") if isinstance(model.get("meta"), dict) else {}
    reqs = _load_requirements(output_dir, meta)

    # Tag each finding with the *custom* requirements it violates (gate-filtered);
    # empty for every finding unless explicit custom requirements were integrated.
    for f in view["findings"]:
        f["requirements"] = (
            [r for r in f.get("violated_requirements") or [] if r in reqs["ids"]] if reqs["integrated"] else []
        )

    key_by_tid: dict[str, str] = {}
    for t in model.get("threats") or []:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("id") or "").strip()
        key = _finding_key(t)
        if tid and key:
            key_by_tid[tid] = key
    mitigations = build_mitigations(model, key_by_tid)

    # Fan each mitigation's covered findings back to a severity mix for the backlog display.
    sev_by_key = {f["key"]: f["severity"] for f in view["findings"]}
    for m in mitigations:
        counts = collections.Counter(sev_by_key.get(k, "") for k in m["covered_keys"])
        counts.pop("", None)
        m["covered_severities"] = dict(counts)

    areas = build_areas(view["findings"])
    requirement_groups = build_requirement_groups(view["findings"], reqs["url_by_id"]) if reqs["integrated"] else []
    worst_case = build_worst_case(model, view["findings"], mitigations)
    quick_wins = build_quick_wins(mitigations)
    recommended = build_recommended(mitigations)
    control_posture = build_control_posture(model)
    verdict = build_verdict(model, view["findings"], mitigations)
    verdict["requirements"] = {
        "integrated": reqs["integrated"],
        "findings_violating": sum(1 for f in view["findings"] if f.get("requirements")),
        "requirement_count": len({r for f in view["findings"] for r in f.get("requirements") or []}),
    }
    verdict["quick_wins"] = len(quick_wins)
    verdict["recommended"] = len(recommended)
    return {
        **view,
        "mitigations": mitigations,
        "areas": areas,
        "requirements": requirement_groups,
        "worst_case": worst_case,
        "quick_wins": quick_wins,
        "recommended": recommended,
        "control_posture": control_posture,
        "verdict": verdict,
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

    c = sub.add_parser("console", help="Emit the full console payload: verdict + findings + mitigations + areas.")
    c.add_argument("--output-dir", type=Path, required=True, help="Directory holding threat-model.yaml.")
    c.add_argument("--triage", type=Path, required=True, help="Path to the triage sidecar (may not exist yet).")

    p = sub.add_parser("render", help="Render remediation-plan.md from the sidecar + model.")
    p.add_argument("--output-dir", type=Path, required=True, help="Directory holding threat-model.yaml.")
    p.add_argument("--triage", type=Path, required=True, help="Path to the triage sidecar.")
    p.add_argument("--plan", type=Path, required=True, help="Path to write remediation-plan.md.")

    ns = ap.parse_args(argv)

    if ns.cmd == "reconcile":
        view = reconcile(ns.output_dir, ns.triage)
        print(json.dumps(view, indent=2))
        return 0

    if ns.cmd == "console":
        view = console(ns.output_dir, ns.triage)
        print(json.dumps(view, indent=2))
        return 0

    if ns.cmd == "render":
        out = render(ns.output_dir, ns.triage, ns.plan)
        print(str(out))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
