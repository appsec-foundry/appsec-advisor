#!/usr/bin/env python3
"""
architect_structural_checks.py — deterministic architect-reviewer helpers
(Sprint 2 Item #4).

Replaces three structural checks that the LLM-driven appsec-architect-reviewer
used to perform by reading files and comparing fields. Those checks are pure
data-matching and do not benefit from LLM judgement:

  Check 1  Architecture ↔ Recon Consistency
           - components[] in threat-model.yaml ↔ services named in
             .recon-summary.md (tech-stack + structure sections)
           - flag invented components (in model, not in recon)
           - flag missing components (in recon, not in model)

  Check 3  Management Summary Verdict Plausibility
           - parse the Verdict text and the Risk Distribution counters from
             threat-model.md
           - cross-check against actual severity counts in .threats-merged.json
           - flag rhetorical / numerical mismatches

  Check 6  CVSS ↔ Likelihood×Impact Alignment
           - iterate threats[] in .threats-merged.json
           - apply the canonical CVSS-band → qualitative-risk table
           - flag out-of-band combinations, skipping threats already flagged
             by the triage-validator

Sprint-3 extension — the detection halves of five more checks that were
likewise pure data-matching (the LLM judgment residue moves to the
`REVIEW_SCOPE=judgment` pass):

  Check 5  Mitigation Realism — CWE-family → wrong-mitigation-type rules +
           Critical/High-without-mitigation. (Judgment residue: "claims
           framework-handled but bypasses defaults".)
  Check 12 Remediation ROI — high_plus/effort formula, top-5 not-prioritized.
  Check 13 Config/IaC coverage — config-scan findings must map to a
           configuration-defect threat (set-membership; skip when absent).
  Check 14 §7 quality bar — mechanical rules from sec7-quality-bar-rules.md
           (heading set, H4 labels/status, no-legacy-flows, overview table,
           floskeln, generic openers). (Judgment residue: Unsafe-vs-Missing
           control classification.)
  Check 15 Actor Coverage — attribution counts + disabled-rationale presence
           (skip when no .actors-resolved.json).

The agent consumes the JSON this script emits instead of rereading files and
re-implementing the comparisons in natural language.

Exit codes:
  0 — success (JSON on stdout), regardless of whether findings were produced
  1 — hard error (missing output dir, invalid JSON input, etc.)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # noqa: F401  (kept for explicit ImportError message)
except ImportError:
    print("architect_structural_checks.py: PyYAML is required", file=sys.stderr)
    sys.exit(1)

import _yaml_io

# ---------------------------------------------------------------------------
# Shared loading
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return _yaml_io.load_yaml(path, default=None)


def _load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.is_file() else ""


# ---------------------------------------------------------------------------
# Check 1 — Architecture ↔ Recon Consistency
# ---------------------------------------------------------------------------


# Match a bullet/row/heading that names a likely service. Heuristic — the
# recon-summary is prose, but it follows stable conventions. We pick up
# names from three sources:
#   - Lines under "## Structure" or "Directory Structure" headings (paths)
#   - Bulleted entries in "Components" / "Services" / "Deployments"
#   - Backtick-wrapped identifiers in tech-stack bullets
_SERVICE_SECTION_HEADINGS = re.compile(
    r"^##+\s*(?:\d+\.?\s*)?(?:Tech\s*Stack|Technology\s*Stack|Structure|"
    r"Directory\s*Structure|Components|Services|Deployment|Deployments|"
    r"Architecture|Applications?)\b",
    re.IGNORECASE | re.MULTILINE,
)

_SERVICE_LINE_RE = re.compile(
    r"(?:^|[\s\-*])`([a-zA-Z][\w\-.]{1,60})`",
    re.MULTILINE,
)
_SERVICE_PATH_RE = re.compile(
    r"(?:^|\s)(services/|apps/|packages/|cmd/|internal/|modules/|workers/)"
    r"([a-zA-Z][\w\-.]{0,60})/?",
    re.MULTILINE,
)


def _extract_recon_services(recon_text: str) -> set[str]:
    """Heuristically collect likely service/component identifiers from the
    recon summary. Casts a wide net; Check 1 only flags mismatches for items
    that appear as entities in BOTH sides.
    """
    if not recon_text:
        return set()

    # Clip to the top half of the file — service names cluster in the
    # tech-stack/structure/components sections, which are near the top.
    # This keeps us away from the per-category finding bodies where any
    # random word can appear in backticks. Keep at least 2000 chars so
    # short recon files (smoke tests, thin repos) do not get truncated.
    cutoff = max(int(len(recon_text) * 0.6), 2000)
    head = recon_text[:cutoff]

    names: set[str] = set()
    for m in _SERVICE_LINE_RE.finditer(head):
        token = m.group(1).strip()
        if len(token) < 3:
            continue
        # Drop tokens that look like file extensions / pure versions
        if re.fullmatch(r"v?\d+(?:\.\d+)*", token):
            continue
        names.add(token.lower())
    for m in _SERVICE_PATH_RE.finditer(head):
        names.add(m.group(2).lower())
    return names


def _extract_model_components(tm_yaml: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not tm_yaml or not isinstance(tm_yaml.get("components"), list):
        return []
    out: list[dict[str, Any]] = []
    for c in tm_yaml["components"]:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id", "")).strip()
        name = str(c.get("name", "")).strip()
        if not cid and not name:
            continue
        out.append(
            {
                "id": cid,
                "name": name,
                "kind": c.get("kind"),
                "paths": c.get("paths", []),
            }
        )
    return out


def check_arch_recon(tm_yaml_path: Path, recon_md_path: Path) -> dict[str, Any]:
    tm = _load_yaml(tm_yaml_path)
    recon = _read_text(recon_md_path)

    components = _extract_model_components(tm)
    recon_services = _extract_recon_services(recon)

    # A model component counts as "grep-able in recon" when ANY of its
    # identifiers (id, name, or any path glob prefix) appears in the
    # collected recon service set OR anywhere in the recon text.
    findings: list[dict[str, Any]] = []
    matched_recon_tokens: set[str] = set()

    recon_lower = recon.lower()
    for c in components:
        # High-confidence candidates: the component's id and full name, plus
        # the first segment of its path globs. These are distinctive enough
        # to match as substrings. We deliberately exclude single words
        # parsed out of the name (e.g. "Ghost" from "Ghost Service") to
        # avoid false positives where the unrelated word happens to appear
        # in the recon prose.
        candidates: list[str] = []
        if c["id"]:
            candidates.append(c["id"].lower())
        if c["name"]:
            candidates.append(c["name"].lower())
        for p in c.get("paths", []):
            seg = re.split(r"[/*]", str(p).lstrip("./"))[0]
            if seg and seg.lower() not in {"src", "lib", "app", "core"}:
                candidates.append(seg.lower())

        def _contained(tok: str) -> bool:
            if tok in recon_services:
                return True
            # Word-boundary check against the prose — stops "ghost" inside
            # "ghostwriter" from matching while still allowing
            # "auth-service" to match "uses `auth-service`".
            return re.search(r"(?<![\w-])" + re.escape(tok) + r"(?![\w])", recon_lower) is not None

        hit_recon = any(_contained(t) for t in candidates)
        if hit_recon:
            for t in candidates:
                if t in recon_services:
                    matched_recon_tokens.add(t)
        else:
            findings.append(
                {
                    "check": "arch-recon",
                    "severity": "warning",
                    "kind": "invented_component",
                    "component_id": c["id"],
                    "component_name": c["name"],
                    "message": (
                        f"Component {c['id'] or c['name']!r} has no grep-able "
                        f"evidence in .recon-summary.md. Either the recon scan missed "
                        f"it (add evidence) or the component is invented."
                    ),
                }
            )

    # Inverse: recon services that do NOT appear anywhere in the model
    # component list. Ignore very short tokens and obvious non-services.
    model_haystack = " ".join((c["id"] + " " + c["name"]).lower() for c in components)
    for svc in sorted(recon_services):
        if len(svc) < 4:
            continue
        if svc in matched_recon_tokens:
            continue
        # Many false-positives: common words that happen to appear in
        # recon backticks. Only flag tokens that clearly look like a
        # deployable: contains a hyphen, ends in -service/-api/-svc, or
        # matches a services/ path prefix.
        looks_like_service = bool(
            re.search(r"(-|_)(service|api|svc|worker|daemon|job|queue|gateway)$", svc)
            or re.search(r"^(services|apps|cmd)/", svc)
        )
        if not looks_like_service:
            continue
        findings.append(
            {
                "check": "arch-recon",
                "severity": "warning",
                "kind": "missing_component",
                "recon_token": svc,
                "message": (
                    f"Recon summary references {svc!r} but no matching component "
                    f"exists in threat-model.yaml. Add it to components[] or "
                    f"confirm it is out of scope."
                ),
            }
        )

    return {
        "check": "arch-recon",
        "tm_yaml_present": tm is not None,
        "recon_md_present": bool(recon),
        "model_component_count": len(components),
        "recon_service_tokens": sorted(recon_services),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Check 3 — Management Summary Verdict Plausibility
# ---------------------------------------------------------------------------


# Rhetorical signals in the Verdict prose
_VERDICT_ACCEPTABLE_SIGNALS = (
    "acceptable risk posture",
    "acceptable posture",
    "secure by default",
    "no significant gaps",
    "no critical gaps",
    "production-ready",
    "ready for production",
)

_VERDICT_ALARMING_SIGNALS = (
    "needs immediate remediation",
    "not fit for production",
    "high-risk posture",
    "critical posture",
    "require urgent",
)

_RISK_DIST_RE = re.compile(
    # Match either "Risk Distribution:", "**Risk Distribution**:" or
    # "**Risk Distribution:**" — colon position inside/outside the bold
    # markers varies across renderers. [^*\n]* is forgiving of extra
    # punctuation ("**Risk Distribution (20 threats):**").
    r"Risk\s*Distribution[^*\n]*?\s*[:\*]+\s*"
    r"(?:\*\*)?\s*Critical\s*[:\*]*\s*(?P<critical>\d+)\s*(?:·|\|)\s*"
    r"(?:\*\*)?\s*High\s*[:\*]*\s*(?P<high>\d+)\s*(?:·|\|)\s*"
    r"(?:\*\*)?\s*Medium\s*[:\*]*\s*(?P<medium>\d+)\s*(?:·|\|)\s*"
    r"(?:\*\*)?\s*Low\s*[:\*]*\s*(?P<low>\d+)",
    re.IGNORECASE,
)


def _find_verdict_text(tm_md: str) -> str:
    """Locate the Verdict / Overall Security Rating passage in the
    Management Summary. Returns up to ~800 chars centred on the match."""
    if not tm_md:
        return ""
    patterns = [
        r"##\s*Overall\s*Security\s*Rating",
        r"###?\s*Verdict",
        r"\*\*Verdict\*\*",
        r"\*\*Overall\s*Rating\*\*",
        r">\s*\*\*Verdict\*\*",
    ]
    for pat in patterns:
        m = re.search(pat, tm_md, re.IGNORECASE)
        if m:
            start = m.start()
            return tm_md[start : start + 800]
    # Fallback: first Management Summary block
    m = re.search(r"##\s*Management\s*Summary", tm_md, re.IGNORECASE)
    if m:
        return tm_md[m.start() : m.start() + 1500]
    return ""


def _parse_risk_distribution(tm_md: str) -> dict[str, int] | None:
    m = _RISK_DIST_RE.search(tm_md)
    if not m:
        return None
    return {
        "Critical": int(m.group("critical")),
        "High": int(m.group("high")),
        "Medium": int(m.group("medium")),
        "Low": int(m.group("low")),
    }


def _count_threats_by_severity(threats: list[dict[str, Any]]) -> dict[str, int]:
    buckets = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for t in threats:
        risk = str(t.get("risk", "")).strip()
        if risk in buckets:
            buckets[risk] += 1
    return buckets


def check_ms_verdict(tm_md_path: Path, threats_merged_path: Path) -> dict[str, Any]:
    tm_md = _read_text(tm_md_path)
    merged = _load_json(threats_merged_path) or {}
    threats = merged.get("threats", []) if isinstance(merged, dict) else []
    actual = _count_threats_by_severity(threats)

    findings: list[dict[str, Any]] = []

    verdict = _find_verdict_text(tm_md).lower()
    if not verdict:
        return {
            "check": "ms-verdict",
            "tm_md_present": bool(tm_md),
            "verdict_found": False,
            "actual_counts": actual,
            "reported_counts": None,
            "findings": [],
        }

    # Rhetoric vs. reality
    says_acceptable = any(sig in verdict for sig in _VERDICT_ACCEPTABLE_SIGNALS)
    says_alarming = any(sig in verdict for sig in _VERDICT_ALARMING_SIGNALS)

    if says_acceptable and actual["Critical"] >= 1:
        findings.append(
            {
                "check": "ms-verdict",
                "severity": "warning",
                "kind": "verdict_understates_critical",
                "message": (
                    f"Verdict text conveys an acceptable posture, but "
                    f"{actual['Critical']} Critical threat(s) exist. The "
                    f"Verdict must acknowledge Critical findings."
                ),
            }
        )
    if says_alarming and actual["Critical"] == 0 and actual["High"] < 3:
        findings.append(
            {
                "check": "ms-verdict",
                "severity": "warning",
                "kind": "verdict_overstates_risk",
                "message": (
                    f"Verdict text conveys an alarming posture (immediate "
                    f"remediation / high-risk / not fit for production), but "
                    f"there are 0 Critical and only {actual['High']} High threat(s). "
                    f"Soften the language or produce supporting evidence."
                ),
            }
        )

    # Numerical mismatch between the MS Risk Distribution line and the
    # actual .threats-merged.json counts.
    reported = _parse_risk_distribution(tm_md)
    if reported is not None:
        mismatches = {k: (reported[k], actual[k]) for k in actual if reported[k] != actual[k]}
        if mismatches:
            findings.append(
                {
                    "check": "ms-verdict",
                    "severity": "warning",
                    "kind": "risk_distribution_mismatch",
                    "reported": reported,
                    "actual": actual,
                    "deltas": mismatches,
                    "message": (
                        f"Risk Distribution counts in the Management Summary do "
                        f"not match .threats-merged.json: reported={reported}, "
                        f"actual={actual}."
                    ),
                }
            )

    return {
        "check": "ms-verdict",
        "tm_md_present": bool(tm_md),
        "verdict_found": True,
        "actual_counts": actual,
        "reported_counts": reported,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Check 6 — CVSS ↔ Likelihood × Impact Alignment
# ---------------------------------------------------------------------------


# Expected qualitative bands per CVSS numeric score.
#   base ≥ 9.0  → Critical or High
#   7.0 – 8.9   → Critical, High, or Medium
#   4.0 – 6.9   → High, Medium, or Low
#   < 4.0       → Medium or Low
def _expected_risk_bands(base: float) -> set[str]:
    if base >= 9.0:
        return {"Critical", "High"}
    if base >= 7.0:
        return {"Critical", "High", "Medium"}
    if base >= 4.0:
        return {"High", "Medium", "Low"}
    return {"Medium", "Low"}


def _already_triage_flagged(threat: dict[str, Any]) -> bool:
    flags = threat.get("triage_flags") or []
    if not isinstance(flags, list):
        return False
    relevant = ("cvss_misalignment", "cvss_out_of_band", "risk_band_mismatch")
    return any(isinstance(f, dict) and f.get("kind") in relevant for f in flags)


def check_cvss_risk(threats_merged_path: Path) -> dict[str, Any]:
    merged = _load_json(threats_merged_path) or {}
    threats = merged.get("threats", []) if isinstance(merged, dict) else []

    findings: list[dict[str, Any]] = []
    evaluated = 0

    for t in threats:
        risk = str(t.get("risk", "")).strip()
        source = str(t.get("source", "")).strip()
        arch_violation = bool(t.get("architectural_violation", False))
        cvss = t.get("cvss_v4")
        base: float | None = None
        if isinstance(cvss, dict):
            bs = cvss.get("base_score")
            if isinstance(bs, (int, float)):
                base = float(bs)

        # Dimension D4.a: CVSS present, check band alignment.
        if base is not None:
            evaluated += 1
            if _already_triage_flagged(t):
                continue
            expected = _expected_risk_bands(base)
            if risk and risk not in expected:
                sev = "warning"
                # Boundary cases (6.9/7.0 and 8.9/9.0) are softened to info
                if abs(base - 7.0) < 0.05 or abs(base - 9.0) < 0.05:
                    sev = "info"
                findings.append(
                    {
                        "check": "cvss-risk",
                        "severity": sev,
                        "kind": "cvss_out_of_band",
                        "t_id": t.get("t_id"),
                        "cvss_base_score": base,
                        "qualitative_risk": risk,
                        "expected_bands": sorted(expected),
                        "message": (
                            f"Threat {t.get('t_id', '?')}: CVSS base {base} "
                            f"expects risk in {sorted(expected)}, but qualitative "
                            f"risk is {risk!r}."
                        ),
                    }
                )
            continue

        # Dimension D4.b: Qualitative Critical with no CVSS and not an
        # architectural_violation, sourced from stride → flag.
        if risk == "Critical" and source == "stride" and not arch_violation:
            if _already_triage_flagged(t):
                continue
            findings.append(
                {
                    "check": "cvss-risk",
                    "severity": "warning",
                    "kind": "critical_without_cvss",
                    "t_id": t.get("t_id"),
                    "message": (
                        f"Threat {t.get('t_id', '?')}: qualitative Critical risk "
                        f"with no CVSS vector and no architectural_violation "
                        f"flag. Either attach a CVSS vector, mark the threat as "
                        f"architectural, or revisit the rating."
                    ),
                }
            )

    return {
        "check": "cvss-risk",
        "threats_total": len(threats),
        "threats_with_cvss": evaluated,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
_WEAK_CONTROL_RANK = {"Missing": 4, "Weak": 3, "Partial": 2}


def _ref_id(item: Any) -> str:
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        return str(item.get("ref") or item.get("id") or item.get("t_id") or "").strip()
    return ""


def _label(item: Any, fallback: str = "") -> str:
    if isinstance(item, dict):
        return str(item.get("label") or item.get("title") or item.get("name") or fallback).strip()
    return fallback


def _build_architecture_input_pack(tm_yaml_path: Path) -> dict[str, Any]:
    """Compact deterministic facts for the LLM architect reviewer.

    The pack is advisory input only. It highlights likely review targets so the
    reviewer spends model budget judging architecture quality instead of
    rediscovering obvious counts and joins.
    """
    tm = _load_yaml(tm_yaml_path) or {}
    if not isinstance(tm, dict):
        tm = {}

    findings_raw = tm.get("findings") or tm.get("threats") or []
    findings: list[dict[str, Any]] = [f for f in findings_raw if isinstance(f, dict)]
    findings_by_id = {_ref_id(f): f for f in findings if _ref_id(f)}

    controls_raw = tm.get("security_controls") or []
    controls = [c for c in controls_raw if isinstance(c, dict)]
    weak_controls: list[dict[str, Any]] = []
    for c in controls:
        effectiveness = str(c.get("effectiveness") or "").strip().title()
        if effectiveness not in _WEAK_CONTROL_RANK:
            continue
        linked = c.get("mitigates_findings") or c.get("linked_threats") or []
        if isinstance(linked, str):
            linked = [linked]
        refs = [_ref_id(x) for x in linked if _ref_id(x)]
        max_sev = "Low"
        for ref in refs:
            f = findings_by_id.get(ref) or {}
            sev = str(f.get("effective_severity") or f.get("risk") or f.get("severity") or "").strip()
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(max_sev, 0):
                max_sev = sev
        weak_controls.append(
            {
                "id": c.get("id"),
                "domain": c.get("domain"),
                "control": c.get("architectural_control") or c.get("control"),
                "effectiveness": effectiveness,
                "linked_findings": refs[:8],
                "max_linked_severity": max_sev if refs else None,
                "gaps": (c.get("gaps") or [])[:3] if isinstance(c.get("gaps"), list) else [],
            }
        )
    weak_controls.sort(
        key=lambda c: (
            _WEAK_CONTROL_RANK.get(str(c.get("effectiveness")), 0),
            _SEVERITY_RANK.get(str(c.get("max_linked_severity")), 0),
            len(c.get("linked_findings") or []),
        ),
        reverse=True,
    )

    architecture_theme_clusters: dict[str, list[str]] = {}
    for f in findings:
        theme = (f.get("architectural_theme") or "").strip()
        fid = _ref_id(f)
        if theme and fid:
            architecture_theme_clusters.setdefault(theme, []).append(fid)

    clusters_top: list[dict[str, Any]] = [
        {
            "theme": theme,
            "finding_count": len(fids),
            "findings": sorted(fids)[:8],
        }
        for theme, fids in sorted(
            architecture_theme_clusters.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
    ]

    high_findings_top: list[dict[str, Any]] = []
    for f in findings:
        fid = _ref_id(f)
        sev = str(f.get("effective_severity") or f.get("risk") or f.get("severity") or "").strip()
        if fid and _SEVERITY_RANK.get(sev, 0) >= _SEVERITY_RANK["High"]:
            high_findings_top.append(
                {
                    "id": fid,
                    "title": _label(f),
                    "severity": sev,
                    "component": f.get("component"),
                    "cwe": f.get("cwe") or f.get("primary_cwe"),
                    "finding_type_id": f.get("finding_type_id"),
                    "architectural_theme": f.get("architectural_theme"),
                }
            )
    high_findings_top.sort(
        key=lambda f: _SEVERITY_RANK.get(str(f.get("severity")), 0),
        reverse=True,
    )

    return {
        "check": "architecture-input-pack",
        "controls_total": len(controls),
        "weak_or_missing_controls_top": weak_controls[:10],
        "architecture_theme_clusters_top": clusters_top[:8],
        "high_findings_top": high_findings_top[:12],
        "trust_boundaries_total": len(tm.get("trust_boundaries") or []),
        "note": (
            "Advisory input for architect-reviewer only; the LLM still judges "
            "architecture coherence, missing clusters, and mitigation realism."
        ),
    }


# ---------------------------------------------------------------------------
# Check 5 — Mitigation Realism (deterministic CWE-family rules)
# ---------------------------------------------------------------------------
# The agent's Check 5 enumerates fixed CWE-family → wrong-mitigation-type rules
# plus a "Critical/High finding with zero mitigations" rule. All of these are
# mechanical. The one genuinely judgemental rule ("claims handled by framework
# but the code bypasses framework defaults") stays in the LLM judgment pass.

_CWE_INJECTION = {78, 89, 94, 502}       # command / SQL / code / deserialization
_CWE_AUTHN = {287, 306}                   # auth bypass / missing auth
_CWE_AUTHZ = {285, 639, 732}              # broken access control / IDOR
_CWE_TLS_INEFFECTIVE = _CWE_INJECTION | _CWE_AUTHN | _CWE_AUTHZ

_MIT_TRANSPORT_RE = re.compile(r"\b(tls|https|ssl|transport[- ]layer|in transit)\b", re.I)
_MIT_RATELIMIT_RE = re.compile(r"\b(rate[- ]?limit\w*|throttl\w*|waf|web application firewall)\b", re.I)
_MIT_INPUTVAL_RE = re.compile(r"\b(input validation|validate input|sanitiz\w+|schema validation)\b", re.I)
_MIT_LOGGING_RE = re.compile(r"\b(logging|log event|monitor\w*|audit log\w*|siem|alerting)\b", re.I)
# Root-cause / preventive mitigation signals. When present on a threat, a
# co-listed transport/rate-limit/logging mitigation is legitimate
# defence-in-depth and must NOT be flagged — this keeps false positives down.
_MIT_ROOTCAUSE_RE = re.compile(
    r"\b(parameteri|prepared statement|\borm\b|bind variable|output encod|escap\w+|"
    r"context-aware|access control|authoriz\w+|ownership check|object-level|"
    r"csrf token|anti-csrf|signature verif|algorithm allowlist|safe.?load|"
    r"failsafe_schema|allowlist|deny by default|least privilege)\b",
    re.I,
)


def _cwe_int(threat: dict[str, Any]) -> int | None:
    m = re.search(r"(\d+)", str(threat.get("cwe") or ""))
    return int(m.group(1)) if m else None


def _threat_severity(t: dict[str, Any]) -> str:
    return str(t.get("effective_severity") or t.get("risk") or t.get("severity") or "").strip()


def _mitigation_blob(t: dict[str, Any], mitigations: dict[str, dict[str, Any]]) -> str:
    texts: list[str] = [str(t.get("mitigation_title") or "")]
    for mid in (t.get("mitigation_ids") or []):
        m = mitigations.get(str(mid)) or {}
        texts.append(str(m.get("title") or ""))
        rem = m.get("remediation")
        if isinstance(rem, dict):
            texts.extend(str(s) for s in (rem.get("steps") or []))
    return " ".join(texts)


def check_mitigation_realism(tm_yaml_path: Path) -> dict[str, Any]:
    tm = _load_yaml(tm_yaml_path) or {}
    threats = [t for t in (tm.get("threats") or tm.get("findings") or []) if isinstance(t, dict)]
    mitigations = {str(m.get("id")): m for m in (tm.get("mitigations") or []) if isinstance(m, dict)}
    findings: list[dict[str, Any]] = []

    for t in threats:
        tid = str(t.get("id") or "")
        sev = _threat_severity(t)
        mids = [str(x) for x in (t.get("mitigation_ids") or []) if x]

        if _SEVERITY_RANK.get(sev, 0) >= _SEVERITY_RANK["High"] and not mids:
            findings.append({
                "check": "mitigation-realism", "severity": "warning",
                "kind": "missing_mitigation", "threat_id": tid,
                "message": f"{tid} ({sev}) has no linked mitigation — every "
                           f"Critical/High threat needs at least one preventive control.",
            })
            continue
        if not mids:
            continue

        blob = _mitigation_blob(t, mitigations)
        if _MIT_ROOTCAUSE_RE.search(blob):
            continue  # a real root-cause fix is present; co-listed controls are DiD
        cwe = _cwe_int(t)
        stride = str(t.get("stride") or "")
        transport = bool(_MIT_TRANSPORT_RE.search(blob))
        ratelimit = bool(_MIT_RATELIMIT_RE.search(blob))
        inputval = bool(_MIT_INPUTVAL_RE.search(blob))
        logging_only = bool(_MIT_LOGGING_RE.search(blob)) and not (transport or ratelimit or inputval)

        if cwe is not None and transport and cwe in _CWE_TLS_INEFFECTIVE:
            findings.append({
                "check": "mitigation-realism", "severity": "warning",
                "kind": "mitigation_type_mismatch", "threat_id": tid, "cwe": cwe,
                "message": f"{tid} (CWE-{cwe}) is mitigated only by transport security "
                           f"(TLS/HTTPS) — that does not address injection / auth / "
                           f"authorization root causes.",
            })
        elif cwe is not None and ratelimit and cwe in _CWE_INJECTION:
            findings.append({
                "check": "mitigation-realism", "severity": "info",
                "kind": "defensive_only", "threat_id": tid, "cwe": cwe,
                "message": f"{tid} (CWE-{cwe}) lists rate-limiting / WAF only — "
                           f"defence-in-depth for injection, never a root-cause fix; "
                           f"pair with parameterization / safe parsing.",
            })
        elif cwe is not None and inputval and cwe in _CWE_AUTHZ:
            findings.append({
                "check": "mitigation-realism", "severity": "warning",
                "kind": "mitigation_type_mismatch", "threat_id": tid, "cwe": cwe,
                "message": f"{tid} (CWE-{cwe}) is an access-control flaw mitigated by "
                           f"input validation — authorization needs an authorization fix.",
            })
        elif logging_only and stride in {"Spoofing", "Elevation of Privilege"}:
            findings.append({
                "check": "mitigation-realism", "severity": "info",
                "kind": "detective_only", "threat_id": tid, "stride": stride,
                "message": f"{tid} ({stride}) is mitigated only by logging / monitoring — "
                           f"detective, not preventive; pair with a preventive control.",
            })

    return {"check": "mitigation-realism", "threat_count": len(threats), "findings": findings}


# ---------------------------------------------------------------------------
# Check 12 — Remediation Synergy & ROI (deterministic formula)
# ---------------------------------------------------------------------------
# roi = (#linked threats with effective_severity >= High) / effort_rank.
# Top-5 mitigations by ROI that are not P1/P2 → warning; P1 with roi < 1.0 → info.

_EFFORT_RANK = {"Low": 1, "Medium": 2, "High": 3}


def check_remediation_roi(tm_yaml_path: Path) -> dict[str, Any]:
    tm = _load_yaml(tm_yaml_path) or {}
    threats = [t for t in (tm.get("threats") or tm.get("findings") or []) if isinstance(t, dict)]
    sev_by_id = {str(t.get("id")): _threat_severity(t) for t in threats}
    mitigations = [m for m in (tm.get("mitigations") or []) if isinstance(m, dict)]

    scored: list[dict[str, Any]] = []
    for m in mitigations:
        effort = str(m.get("effort") or (m.get("remediation") or {}).get("effort") or "Medium").title()
        effort_rank = _EFFORT_RANK.get(effort, 2)
        tids = [str(x) for x in (m.get("threat_ids") or []) if x]
        high_plus = sum(
            1 for tid in tids
            if _SEVERITY_RANK.get(sev_by_id.get(tid, ""), 0) >= _SEVERITY_RANK["High"]
        )
        roi = round(high_plus / effort_rank, 2)
        scored.append({
            "id": str(m.get("id") or ""), "title": str(m.get("title") or ""),
            "priority": str(m.get("priority") or ""), "effort": effort,
            "high_plus": high_plus, "roi": roi,
        })

    scored.sort(key=lambda s: (s["roi"], s["high_plus"]), reverse=True)
    findings: list[dict[str, Any]] = []

    for s in scored[:5]:
        if s["high_plus"] >= 1 and s["priority"] not in {"P1", "P2"}:
            findings.append({
                "check": "remediation-roi", "severity": "warning",
                "kind": "high_roi_mitigation_not_prioritized", "mitigation_id": s["id"],
                "roi": s["roi"], "priority": s["priority"] or "(none)",
                "message": f"{s['id']} has ROI {s['roi']} (closes {s['high_plus']} ≥High at "
                           f"{s['effort']} effort) but is {s['priority'] or 'unprioritized'} — "
                           f"consider promoting to P1/P2.",
            })
    for s in scored:
        if s["priority"] == "P1" and s["roi"] < 1.0:
            findings.append({
                "check": "remediation-roi", "severity": "info",
                "kind": "p1_low_roi", "mitigation_id": s["id"], "roi": s["roi"],
                "message": f"{s['id']} is P1 but ROI {s['roi']} (< 1.0) — "
                           f"high effort for low ≥High coverage; verify the prioritization.",
            })

    return {"check": "remediation-roi", "top5": scored[:5], "findings": findings}


# ---------------------------------------------------------------------------
# Check 13 — Config/IaC coverage (conditional set-membership)
# ---------------------------------------------------------------------------


def check_config_iac(output_dir: Path) -> dict[str, Any]:
    cfg = _load_json(output_dir / ".config-scan-findings.json")
    items = cfg if isinstance(cfg, list) else (cfg or {}).get("findings") if isinstance(cfg, dict) else None
    if not items:
        return {"check": "config-iac", "skipped": True, "reason": "no config-scan findings", "findings": []}

    tm = _load_yaml(output_dir / "threat-model.yaml") or {}
    threats = [t for t in (tm.get("threats") or tm.get("findings") or []) if isinstance(t, dict)]
    config_sourced = [
        t for t in threats
        if str(t.get("source") or "") in {"configuration-defect", "config-scan", "config-defect"}
    ]
    findings: list[dict[str, Any]] = []
    if not config_sourced:
        findings.append({
            "check": "config-iac", "severity": "warning",
            "kind": "config_findings_orphan", "config_finding_count": len(items),
            "message": f"{len(items)} config-scan finding(s) exist but no "
                       f"configuration-defect threat is present in the register — "
                       f"the config scan results were not folded into the threat model.",
        })
    return {
        "check": "config-iac", "skipped": False,
        "config_finding_count": len(items),
        "config_sourced_threats": len(config_sourced),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Check 15 — Actor Coverage (conditional counts; skip when no actor layer)
# ---------------------------------------------------------------------------


def check_actor_coverage(output_dir: Path) -> dict[str, Any]:
    resolved = _load_json(output_dir / ".actors-resolved.json")
    if not resolved:
        return {"check": "actor-coverage", "skipped": True, "reason": "no .actors-resolved.json", "findings": []}

    actors = resolved.get("actors") if isinstance(resolved, dict) else resolved
    actors = [a for a in (actors or []) if isinstance(a, dict)]
    tm = _load_yaml(output_dir / "threat-model.yaml") or {}
    threats = [t for t in (tm.get("threats") or tm.get("findings") or []) if isinstance(t, dict)]

    used_actor_ids: set[str] = set()
    findings_with_actor = 0
    for t in threats:
        ids = [str(x) for x in (t.get("actor_ids") or []) if x]
        if ids:
            findings_with_actor += 1
            used_actor_ids.update(ids)

    findings: list[dict[str, Any]] = []
    total = len(threats)

    # 15.3b — whole-model attribution gap (defect-level).
    if total > 0 and findings_with_actor == 0:
        findings.append({
            "check": "actor-coverage", "severity": "warning",
            "kind": "whole_model_no_actor_attribution",
            "message": "No finding carries actor_ids — the §8 Actor column would render "
                       "a placeholder for every row. Drop the column or re-run STRIDE "
                       "with an explicit actor_ids requirement.",
        })
    elif total > 0 and findings_with_actor / total < 0.25:
        findings.append({
            "check": "actor-coverage", "severity": "info",
            "kind": "pervasive_actor_attribution_gap",
            "message": f"Only {findings_with_actor}/{total} findings carry actor_ids "
                       f"(<25%) — the Actor column is misleading.",
        })

    for a in actors:
        aid = str(a.get("id") or "")
        prov = a.get("_provenance") or {}
        # 15.2 — disabled without rationale (defect).
        if prov.get("disabled_by") and not str(prov.get("disable_reason") or "").strip():
            findings.append({
                "check": "actor-coverage", "severity": "warning",
                "kind": "actor_disabled_without_rationale", "actor_id": aid,
                "message": f"Actor {aid} was disabled by {prov.get('disabled_by')} "
                           f"with no disable_reason recorded.",
            })
        # 15.1 — activated (non-discovery) but unused.
        elif (str(prov.get("layer") or "") != "discovery"
              and aid and aid not in used_actor_ids):
            findings.append({
                "check": "actor-coverage", "severity": "info",
                "kind": "actor_activated_no_findings", "actor_id": aid,
                "message": f"Actor {aid} is activated but no finding references it.",
            })

    return {
        "check": "actor-coverage", "skipped": False,
        "actor_count": len(actors),
        "findings_with_actor_ids": findings_with_actor,
        "total_findings": total,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Check 14 — §7 Security Architecture quality bar (mechanical rules)
# ---------------------------------------------------------------------------
# Implements the deterministic rules from shared/sec7-quality-bar-rules.md.
# The one judgement rule (is a present-but-broken control mislabelled "Missing"
# vs "Unsafe"?) stays in the LLM judgment pass.

_SEC7_FLOSKELN = (
    "leverages", "robust", "comprehensive", "in essence", "seamless",
    "security posture", "with the intention that", "with the expectation that",
)
_SEC7_OPENER_RE = re.compile(r"^\s*The (application|system|server)\b", re.I)


def _extract_sec7_body(tm_md: str) -> str:
    """Return the §7 body: from the first '### 7.1' to the next H2 ('## ')."""
    m = re.search(r"^###\s*7\.1\b", tm_md, re.MULTILINE)
    if not m:
        return ""
    rest = tm_md[m.start():]
    nxt = re.search(r"^##\s+[^#]", rest, re.MULTILINE)
    return rest[: nxt.start()] if nxt else rest


def check_sec7_quality_bar(tm_md_path: Path) -> dict[str, Any]:
    tm_md = _read_text(tm_md_path)
    body = _extract_sec7_body(tm_md)
    if not body:
        return {"check": "sec7-quality-bar", "skipped": True, "reason": "no §7 body (pre-render)", "findings": []}

    findings: list[dict[str, Any]] = []

    # sec7_v2_heading_set — H3 7.1..7.13 all present.
    h3_nums = {int(n) for n in re.findall(r"^###\s*7\.(\d+)\b", body, re.MULTILINE)}
    missing = [n for n in range(1, 14) if n not in h3_nums]
    if missing:
        findings.append({
            "check": "sec7-quality-bar", "severity": "warning", "kind": "sec7_v2_heading_set",
            "message": f"§7 is missing H3 subsection(s): {', '.join('7.'+str(n) for n in missing)}.",
        })

    # sec7_v2_no_legacy_flows — no legacy flow headings / trailers.
    if re.search(r"^####\s*7\.\d+\.\d+\b.*\bFlow\b", body, re.MULTILINE) or "Findings in this flow" in body:
        findings.append({
            "check": "sec7-quality-bar", "severity": "warning", "kind": "sec7_v2_no_legacy_flows",
            "message": "§7 contains legacy flow headings / 'Findings in this flow' trailers — "
                       "v2 layout forbids them.",
        })

    # sec7_v2_overview_table — §7.1 has the 3-column overview header.
    m71 = re.search(r"^###\s*7\.1\b", body, re.MULTILINE)
    m72 = re.search(r"^###\s*7\.2\b", body, re.MULTILINE)
    sec71 = body[m71.start(): m72.start()] if (m71 and m72) else ""
    if not re.search(r"Control category", sec71, re.I):
        findings.append({
            "check": "sec7-quality-bar", "severity": "warning", "kind": "sec7_v2_overview_table",
            "message": "§7.1 is missing the 'Control category | Verdict | Main reason' overview table.",
        })

    # Per-H4 checks: each #### subcontrol needs Status + Security assessment + Relevant findings.
    h4_iter = list(re.finditer(r"^####\s*(7\.\d+\.\d+)\s+(.+)$", body, re.MULTILINE))
    h4_no_status: list[str] = []
    h4_no_labels: list[str] = []
    h4_generic_opener = 0
    for i, h in enumerate(h4_iter):
        start = h.end()
        end = h4_iter[i + 1].start() if i + 1 < len(h4_iter) else len(body)
        block = body[start:end]
        num = h.group(1)
        if "**Status:**" not in block:
            h4_no_status.append(num)
        if "**Security assessment**" not in block or "**Relevant findings**" not in block:
            h4_no_labels.append(num)
        # concrete-opener heuristic: first non-empty prose line after the Status badge.
        after_status = re.split(r"\*\*Status:\*\*[^\n]*\n", block, maxsplit=1)
        intro = after_status[1] if len(after_status) > 1 else block
        first_line = next((ln for ln in intro.splitlines() if ln.strip() and not ln.startswith(("```", "**", "<a"))), "")
        if _SEC7_OPENER_RE.match(first_line):
            h4_generic_opener += 1

    if h4_no_status:
        findings.append({
            "check": "sec7-quality-bar", "severity": "warning", "kind": "section7_h4_status",
            "message": f"H4 subcontrol(s) without a **Status:** badge: {', '.join(h4_no_status)}.",
        })
    if h4_no_labels:
        findings.append({
            "check": "sec7-quality-bar", "severity": "warning", "kind": "sec7_v2_h4_labels",
            "message": f"H4 subcontrol(s) missing **Security assessment** / **Relevant findings**: "
                       f"{', '.join(h4_no_labels)}.",
        })
    if h4_generic_opener >= 3:
        findings.append({
            "check": "sec7-quality-bar", "severity": "info", "kind": "qb7_concrete_openers",
            "message": f"{h4_generic_opener} H4 intros open with the generic 'The "
                       f"application/system/server …' stem — lead with the concrete route/file/library.",
        })

    # qb7_no_floskeln — templated filler.
    floskel_hits = sum(len(re.findall(r"\b" + re.escape(w) + r"\b", body, re.I)) for w in _SEC7_FLOSKELN)
    if floskel_hits >= 3:
        findings.append({
            "check": "sec7-quality-bar", "severity": "info", "kind": "qb7_no_floskeln",
            "message": f"§7 prose contains {floskel_hits} templated-filler token(s) "
                       f"(leverages / robust / comprehensive / …) — tighten to concrete claims.",
        })

    return {"check": "sec7-quality-bar", "skipped": False, "h4_count": len(h4_iter), "findings": findings}


def run_all(output_dir: Path) -> dict[str, Any]:
    tm_yaml = output_dir / "threat-model.yaml"
    tm_md = output_dir / "threat-model.md"
    recon = output_dir / ".recon-summary.md"
    threats_merged = output_dir / ".threats-merged.json"

    a = check_arch_recon(tm_yaml, recon)
    b = check_ms_verdict(tm_md, threats_merged)
    c = check_cvss_risk(threats_merged)
    d = _build_architecture_input_pack(tm_yaml)
    e = check_mitigation_realism(tm_yaml)
    f = check_remediation_roi(tm_yaml)
    g = check_config_iac(output_dir)
    h = check_actor_coverage(output_dir)
    i = check_sec7_quality_bar(tm_md)

    findings = (
        list(a["findings"]) + list(b["findings"]) + list(c["findings"])
        + list(e["findings"]) + list(f["findings"]) + list(g["findings"])
        + list(h["findings"]) + list(i["findings"])
    )

    return {
        "version": 2,
        "arch_recon": a,
        "ms_verdict": b,
        "cvss_risk": c,
        "architecture_input_pack": d,
        "mitigation_realism": e,
        "remediation_roi": f,
        "config_iac": g,
        "actor_coverage": h,
        "sec7_quality_bar": i,
        "findings": findings,
        "findings_total": len(findings),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="architect_structural_checks.py", description=__doc__)
    p.add_argument(
        "command",
        choices=[
            "arch-recon", "ms-verdict", "cvss-risk",
            "mitigation-realism", "remediation-roi", "config-iac",
            "actor-coverage", "sec7-quality-bar", "all",
        ],
    )
    p.add_argument("--output-dir", required=True)
    args = p.parse_args(argv)

    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(f"architect_structural_checks.py: output dir not found: {output_dir}", file=sys.stderr)
        return 1

    if args.command == "arch-recon":
        out: dict[str, Any] = check_arch_recon(output_dir / "threat-model.yaml", output_dir / ".recon-summary.md")
    elif args.command == "ms-verdict":
        out = check_ms_verdict(output_dir / "threat-model.md", output_dir / ".threats-merged.json")
    elif args.command == "cvss-risk":
        out = check_cvss_risk(output_dir / ".threats-merged.json")
    elif args.command == "mitigation-realism":
        out = check_mitigation_realism(output_dir / "threat-model.yaml")
    elif args.command == "remediation-roi":
        out = check_remediation_roi(output_dir / "threat-model.yaml")
    elif args.command == "config-iac":
        out = check_config_iac(output_dir)
    elif args.command == "actor-coverage":
        out = check_actor_coverage(output_dir)
    elif args.command == "sec7-quality-bar":
        out = check_sec7_quality_bar(output_dir / "threat-model.md")
    else:
        out = run_all(output_dir)

    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
