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

# CSafeLoader (libyaml) parses a large threat-model.yaml (~360 KB) in ~70 ms vs
# ~800 ms for the pure-Python SafeLoader — an ~11× win on the dominant cost of
# loading the console payload. Falls back to SafeLoader where libyaml is absent.
# Same convention as compose_threat_model.py / qa_checks.py.
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
_PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}
# Within a priority band, actionable fixes rank above items still needing a look
# (investigate/review) so the backlog surfaces do-now work first.
_KIND_ORDER = {"fix": 0, "investigate": 1, "review": 2}
# Security-control effectiveness, worst-first — drives the posture-by-domain rank.
_EFFECTIVENESS_ORDER = {"Missing": 0, "Weak": 1, "Partial": 2, "Adequate": 3}
# Valid STRIDE categories for a docs/known-threats.yaml entry (mirrors
# known-threats.schema.yaml). Used when promoting an accept-risk decision: a
# threat whose `stride` is not one of these can't form a schema-valid entry.
_STRIDE_ENUM = frozenset(
    {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
)

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
        doc = yaml.load(p.read_text(encoding="utf-8"), Loader=_YAML_LOADER) or {}
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
        data = yaml.load(model_path.read_text(encoding="utf-8"), Loader=_YAML_LOADER) or {}
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
        doc = yaml.load(sidecar_path.read_text(encoding="utf-8"), Loader=_YAML_LOADER) or {}
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
        doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_YAML_LOADER) or {}
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
    for g in out:
        g.pop("_worst_rank", None)  # internal sort key — never part of the payload
    return out


# ---------------------------------------------------------------------------
# Pre-rendered console screens (deterministic display blocks)
#
# The skill prints these verbatim instead of re-composing each menu from the
# structured arrays. Moving the formatting here keeps the glyph contract, the
# category grouping and the continuous numbering deterministic (no LLM drift),
# and turns the per-screen latency the user feels into an echo rather than a
# fresh compose. The structured arrays stay in the payload — the skill still
# uses them to resolve id/number/range picks and free-text intents; these
# screens are DISPLAY ONLY and never author severity/priority (they read the
# same rolled-up numbers as every other view).
# ---------------------------------------------------------------------------

# Two distinct axes, mirroring threat-model.md (see the skill's "Glyph
# conventions"): a finding carries a severity COLOUR dot; a measure carries a
# monochrome priority fill-RAMP. Never colour a measure, never ramp a finding.
_SEV_DOT = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
_PRIO_RAMP = {"P1": "●", "P2": "◕", "P3": "◑", "P4": "○"}
_RAMP_LEGEND = "(● P1 · ◕ P2 · ◑ P3 · ○ P4)"


def _sev_dot(sev: str) -> str:
    return _SEV_DOT.get(sev, "⚪")  # unrated / Informational / unknown -> hollow


def _ramp(prio: str) -> str:
    return _PRIO_RAMP.get(prio, "○")


def _short(title: str, width: int = 64) -> str:
    t = " ".join((title or "").split())
    return t if len(t) <= width else t[: width - 1].rstrip() + "…"


def _mit_rows(mitigations: list[dict], find_by_key: dict[str, dict]) -> list[dict]:
    """Attach each mitigation's representative covered finding (its worst-severity
    one) plus the display category, for the grouped fix views. Skips mitigations
    covering no finding present in the model — there is nothing to show or act on."""
    rows: list[dict] = []
    for m in mitigations:
        covered = [find_by_key[k] for k in m["covered_keys"] if k in find_by_key]
        if not covered:
            continue
        rep = min(covered, key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))
        rows.append(
            {
                "mit": m,
                "rep": rep,
                "extra": len(covered) - 1,
                "category": rep.get("category_name") or "Uncategorized",
                "worst_rank": _SEVERITY_ORDER.get(rep["severity"], 9),
            }
        )
    return rows


def _group_fix_rows(rows: list[dict]) -> list[tuple[str, list[dict]]]:
    """Bucket fix rows by the category they harden, worst-severity-first both
    within a group and across groups (mirrors the skill's Fix views)."""
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(r["category"], []).append(r)
    for rs in groups.values():
        rs.sort(key=lambda r: (r["worst_rank"], _PRIORITY_ORDER.get(r["mit"]["priority"], 9), r["mit"]["id"]))
    return sorted(groups.items(), key=lambda kv: (min(r["worst_rank"] for r in kv[1]), -len(kv[1]), kv[0]))


def _fix_subline(r: dict) -> str:
    rep = r["rep"]
    extra = f" +{r['extra']}" if r["extra"] else ""
    return f"        └ {_sev_dot(rep['severity'])} {rep['id']} · {rep['location']}{extra}"


def _screen_fix_start(recommended: list[dict], find_by_key: dict[str, dict]) -> str:
    """The 'Recommended to fix first' view — recommended[] grouped by what each
    fix hardens. Empty string when nothing is both cheap and low-risk (the skill
    then falls back to Fix — pick specific; it never invents a recommendation)."""
    rows = _mit_rows(recommended, find_by_key)
    if not rows:
        return ""
    out = [f"🛠 **Recommended to fix first** — cheap, low-risk, high-impact   {_RAMP_LEGEND}", ""]
    for cat, rs in _group_fix_rows(rows):
        out.append(f"**Fix {cat}** — {len(rs)}")
        for r in rs:
            m = r["mit"]
            out.append(f"  {_ramp(m['priority'])} {m['id']} ({m['priority']}) {_short(m['title'])}")
            out.append(_fix_subline(r))
        out.append("")
    return "\n".join(out).rstrip()


def _screen_fix_list(
    mitigations: list[dict], find_by_key: dict[str, dict], recommended_ids: set[str], include_p3: bool
) -> str:
    """The 'Fix — pick specific' view: the same category groups, numbered
    CONTINUOUSLY across groups so a pick like `3` is unambiguous. Defaults to
    P1+P2 with a trailing hint for the hidden P3s; ``include_p3`` renders all."""
    rows = _mit_rows(mitigations, find_by_key)
    shown = rows if include_p3 else [r for r in rows if r["mit"]["priority"] != "P3"]
    hidden_p3 = 0 if include_p3 else sum(1 for r in rows if r["mit"]["priority"] == "P3")
    if not shown:
        return ""
    out = [_RAMP_LEGEND]
    n = 0
    for cat, rs in _group_fix_rows(shown):
        out.append(f"**{cat}**")
        for r in rs:
            n += 1
            m = r["mit"]
            star = " ★" if m["id"] in recommended_ids else ""
            out.append(f"  {n}. {_ramp(m['priority'])} {m['id']} ({m['priority']}) {_short(m['title'])}{star}")
            out.append(_fix_subline(r))
    if hidden_p3:
        out.append(f" … (+{hidden_p3} P3 — type `show P3` to include)")
    return "\n".join(out)


def _screen_browse_severity(findings: list[dict], integrated: bool) -> str:
    """The By-severity finding table: untriaged-first, then severity-ranked."""
    ordered = sorted(
        findings, key=lambda f: (f["decision"] != "untriaged", _SEVERITY_ORDER.get(f["severity"], 9), f["id"])
    )
    lines: list[str] = []
    for f in ordered:
        typ = f.get("category_name") or f.get("cwe") or "—"
        req = f" [req: {', '.join(f['requirements'])}]" if integrated and f.get("requirements") else ""
        dec = f" [{f['decision']}]" if f["decision"] != "untriaged" else ""
        lines.append(
            f"{_sev_dot(f['severity'])} {f['id']} · {f['severity'] or 'unrated'} · {typ} · "
            f"{f['location']} · {_short(f['title'], 80)}{req}{dec}"
        )
    return "\n".join(lines)


def _screen_group_table(groups: list[dict], id_field: str) -> str:
    """Numbered blast-ranked group table shared by By-type and By-requirement."""
    return "\n".join(
        f"{i}. {g[id_field]} — {g['total']} findings (🔴 {g['critical']} · 🟠 {g['high']})"
        for i, g in enumerate(groups, 1)
    )


def _screen_posture(control_posture: list[dict]) -> str:
    """The read-only Security-posture lens: one row per domain, worst-first."""
    if not control_posture:
        return ""
    order = ["Missing", "Weak", "Partial", "Adequate"]
    lines: list[str] = []
    for d in control_posture:
        be = d["by_effectiveness"]
        bits = [f"{be[k]} {k}" for k in order if be.get(k)]
        bits += [f"{v} {k}" for k, v in be.items() if k not in order and v]  # any non-standard label
        lines.append(f"{d['domain']} — {d['worst_effectiveness']} ({d['total']} controls: {', '.join(bits)})")
    return "\n".join(lines)


def _screen_landing(payload: dict) -> str:
    """The landing screen: verdict stat rows + the worst-case block, glyphs baked
    in. Shown on invocation before any menu (skill Step 4)."""
    v = payload["verdict"]
    total, triaged = payload["total"], v["triaged"]
    project = payload["project"] or "(unnamed)"
    generated = payload["generated"] or "unknown"
    lines = [f"**{project}** · generated {generated} · **{total} findings** · {triaged}/{total} triaged", ""]

    bp = v.get("by_priority", {})
    backlog = " · ".join(f"{bp.get(p, 0)}× {p}" for p in ("P1", "P2", "P3"))
    lines.append(f"  **Backlog**    {backlog}   ·   {v['uncovered']} without a fix")

    bs = v.get("by_severity", {})
    sev_bits = [f"{_sev_dot(s)} {bs[s]} {s}" for s in ("Critical", "High", "Medium", "Low") if bs.get(s)]
    if v.get("unrated"):
        sev_bits.append(f"⚪ {v['unrated']} unrated")
    if v.get("weaknesses"):
        sev_bits.append(f"🧩 {v['weaknesses']} design weaknesses")
    if sev_bits:
        lines.append("  **Severity**   " + " · ".join(sev_bits))

    reqs = v.get("requirements", {})
    if reqs.get("integrated"):
        lines.append(
            f"  **Requirements**  {reqs['findings_violating']} findings violate "
            f"{reqs['requirement_count']} custom requirements"
        )

    top_areas = v.get("top_areas") or []
    if top_areas:
        lines.append("  **Hot areas**  " + " · ".join(f"{name} ({n})" for name, n in top_areas))

    worst = payload.get("worst_case") or []
    if worst:
        lines += ["", "**⚠ Worst case if nothing changes**", ""]
        for w in worst:
            tail = f"   → fix with {_ramp(w['priority'])} {w['mitigation_id']}" if w.get("mitigation_id") else ""
            lines.append(f"  {_sev_dot(w['severity'])} **[{w['id']}]** {w['component']} — {w['summary']}{tail}")
    return "\n".join(lines)


def build_screens(payload: dict) -> dict:
    """Ready-to-print text blocks for every heavy console screen. The skill echoes
    these verbatim; it keeps the structured arrays only for pick-resolution and
    free-text intents. Empty string means "nothing to show" (the skill decides
    whether to offer the screen at all — e.g. posture only when non-empty)."""
    find_by_key = {f["key"]: f for f in payload["findings"]}
    recommended = payload["recommended"]
    recommended_ids = {m["id"] for m in recommended}
    integrated = bool(payload["verdict"].get("requirements", {}).get("integrated"))
    return {
        "landing": _screen_landing(payload),
        "fix_start": _screen_fix_start(recommended, find_by_key),
        "fix_list": _screen_fix_list(payload["mitigations"], find_by_key, recommended_ids, include_p3=False),
        "fix_list_full": _screen_fix_list(payload["mitigations"], find_by_key, recommended_ids, include_p3=True),
        "browse_severity": _screen_browse_severity(payload["findings"], integrated),
        "browse_type": _screen_group_table(payload["areas"], "category_name"),
        "browse_requirement": _screen_group_table(payload["requirements"], "requirement_id")
        if payload["requirements"]
        else "",
        "posture": _screen_posture(payload["control_posture"]),
    }


def console(output_dir: Path, sidecar_path: Path, taxonomy_path: Path | None = None) -> dict:
    """One payload for the interactive console: the reconcile view plus ranked
    mitigations, area groupings, worst-case scenarios, the requirements lens
    (custom requirements only), the posture verdict, and pre-rendered display
    ``screens`` the skill prints verbatim (see ``build_screens``)."""
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
    payload = {
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
    payload["screens"] = build_screens(payload)
    return payload


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
# Promote accepted risks into docs/known-threats.yaml
#
# The ONE place this consumer writes outside its own .appsec-triage/ namespace,
# and only on the skill's explicit, opt-in request. It never touches the
# generated threat-model.yaml — it writes the create-threat-model *input* channel
# (docs/known-threats.yaml). A `status: accepted` entry there is re-read on every
# scan: the STRIDE analyzer skips it (not re-raised) and the orchestrator surfaces
# it in meta.accepted_risks[] (verified in appsec-stride-analyzer.md / build_*).
# ---------------------------------------------------------------------------


def _known_threat_description(threat: dict) -> str:
    """Best available prose for a known-threats `description` (required, non-empty)."""
    for k in ("scenario", "impact_description", "evidence_summary", "impact"):
        v = str(threat.get(k) or "").strip()
        if v:
            return v
    return _title(threat) or "(no description recorded)"


def _build_known_threat_entry(threat: dict, rationale: str) -> dict | None:
    """Synthesize a schema-valid ``docs/known-threats.yaml`` entry
    (``status: accepted``) from a generated threat the user accepted the risk on.
    Returns ``None`` when the threat lacks a mappable STRIDE category or a stable
    key — i.e. cannot form a valid entry (skip, never emit invalid input)."""
    key = _finding_key(threat)
    stride = str(threat.get("stride") or "").strip()
    if not key or stride not in _STRIDE_ENUM:
        return None
    entry: dict = {
        "id": key,  # component-scoped local_id — stable across re-scans
        "title": _title(threat) or key,
        "stride": stride,
        "component": str(threat.get("component") or threat.get("component_name") or "").strip() or "unknown",
        "severity": _sev_label(threat) or "Medium",
        "status": "accepted",
        "description": _known_threat_description(threat),
        "accepted_risk": (rationale or "").strip() or "Risk accepted during triage.",
    }
    loc = _primary_location(threat)
    if loc:
        entry["evidence"] = loc
    mit = str(threat.get("mitigation_title") or "").strip()
    if mit:
        entry["mitigation_ref"] = mit
    return entry


def _validate_known_threats_doc(doc: dict) -> tuple[bool, list[str]]:
    """Validate a known-threats document with the pipeline's own validator so
    promoted entries clear the same bar as team-authored input. Best-effort: if
    the validator can't be imported in this environment, don't block the write
    (entries are schema-valid by construction)."""
    try:
        import validate_intermediate as _vi
    except Exception:  # pragma: no cover - environment guard
        return True, []
    return _vi.validate_known_threats(doc)


def promote_accepted(output_dir: Path, sidecar_path: Path, known_threats_path: Path) -> dict:
    """Merge every ``accept-risk`` triage decision into ``known_threats_path`` as a
    ``status: accepted`` entry. Preserves team-authored entries and any extra keys,
    dedups by entry ``id`` (updates an existing entry in place rather than
    duplicating). Validates before writing and fails loudly on invalid output.
    Never writes ``threat-model.yaml``. Returns a summary dict."""
    model = _load_model(output_dir)
    sidecar = _load_sidecar(sidecar_path)
    threats_by_key = {
        _finding_key(t): t for t in (model.get("threats") or []) if isinstance(t, dict) and _finding_key(t)
    }

    new_entries: list[dict] = []
    skipped: list[str] = []  # accepted but stale (gone from model) or unmappable
    for key, dec in sidecar.items():
        if not isinstance(dec, dict) or _norm_decision(dec.get("decision")) != "accept-risk":
            continue
        threat = threats_by_key.get(key)
        entry = _build_known_threat_entry(threat, str(dec.get("rationale") or "")) if threat else None
        if entry is None:
            skipped.append(str(key))
            continue
        new_entries.append(entry)

    # Nothing to promote and no file to preserve — don't litter an empty file.
    if not new_entries and not known_threats_path.is_file():
        return {"path": str(known_threats_path), "added": 0, "updated": 0, "skipped": skipped, "total": 0}

    # Load + merge, preserving existing content.
    if known_threats_path.is_file():
        doc = yaml.load(known_threats_path.read_text(encoding="utf-8"), Loader=_YAML_LOADER) or {}
        if not isinstance(doc, dict):
            print(f"Existing {known_threats_path} is not a mapping — refusing to overwrite.", file=sys.stderr)
            raise SystemExit(2)
    else:
        doc = {}
    existing = doc.get("threats")
    threats_list = list(existing) if isinstance(existing, list) else []
    by_id = {str(e.get("id")): i for i, e in enumerate(threats_list) if isinstance(e, dict) and e.get("id")}

    added = updated = 0
    for entry in new_entries:
        idx = by_id.get(entry["id"])
        if idx is None:
            threats_list.append(entry)
            by_id[entry["id"]] = len(threats_list) - 1
            added += 1
        else:  # flip to accepted + refresh, but keep any extra team keys on the entry
            threats_list[idx] = {**threats_list[idx], **entry}
            updated += 1
    doc["threats"] = threats_list

    ok, errors = _validate_known_threats_doc(doc)
    if not ok:
        print("Refusing to write invalid known-threats.yaml:", file=sys.stderr)
        for e in errors[:10]:
            print(f"  - {e}", file=sys.stderr)
        raise SystemExit(2)

    known_threats_path.parent.mkdir(parents=True, exist_ok=True)
    known_threats_path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100), encoding="utf-8")
    return {
        "path": str(known_threats_path),
        "added": added,
        "updated": updated,
        "skipped": skipped,
        "total": len(threats_list),
    }


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

    pa = sub.add_parser(
        "promote-accepted",
        help="Merge accept-risk decisions into docs/known-threats.yaml as status: accepted entries.",
    )
    pa.add_argument("--output-dir", type=Path, required=True, help="Directory holding threat-model.yaml.")
    pa.add_argument("--triage", type=Path, required=True, help="Path to the triage sidecar.")
    pa.add_argument("--known-threats", type=Path, required=True, help="Path to write/merge docs/known-threats.yaml.")

    ns = ap.parse_args(argv)

    if ns.cmd == "reconcile":
        view = reconcile(ns.output_dir, ns.triage)
        print(json.dumps(view, indent=2))
        return 0

    if ns.cmd == "console":
        view = console(ns.output_dir, ns.triage)
        # Compact: the console payload is machine data the skill parses and keeps
        # in context for every view — indent-whitespace is pure token overhead.
        print(json.dumps(view, separators=(",", ":")))
        return 0

    if ns.cmd == "render":
        out = render(ns.output_dir, ns.triage, ns.plan)
        print(str(out))
        return 0

    if ns.cmd == "promote-accepted":
        summary = promote_accepted(ns.output_dir, ns.triage, ns.known_threats)
        print(json.dumps(summary))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
