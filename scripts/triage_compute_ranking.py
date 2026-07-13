#!/usr/bin/env python3
"""triage_compute_ranking.py — deterministic Phase-10b Step 6.

Replaces the LLM-driven Step 6 of ``appsec-triage-validator`` with a Python
script. The agent's spec for Step 6 (sub-steps 6a–6g) is fully deterministic
rule application against YAML configs (breach-distance-patterns,
compound-chain-patterns, severity-caps, critical-criteria, cwe-taxonomy).
LLM reasoning is not required, and the LLM consistently mis-emits the ranking
schema (the 2026-04-26 juice-shop run wrote ``version: 1`` with no ranking
block after 6 minutes of work).

Inputs (in $OUTPUT_DIR unless absolute):
    threat-model.yaml         — augmented in-place with per-finding/category
                                effective_severity, breach_distance, chain_role
    .threats-merged.json      — read-only per-finding flat list
    .triage-flags.json (v1)   — preserved; we add the ``ranking`` block + bump
                                ``version`` to 2

Plugin data files ($CLAUDE_PLUGIN_ROOT/data/):
    breach-distance-patterns.yaml
    compound-chain-patterns.yaml
    severity-caps.yaml
    critical-criteria.yaml
    cwe-taxonomy.yaml

Exit codes:
    0 — ranking computed and written
    1 — input file missing or malformed
    2 — usage error
    3 — IO error

Feature flag: set ``APPSEC_TRIAGE_DETERMINISTIC=1`` to enable. Without the
flag the script exits 0 without writing anything (the agent will fall back
to its LLM Step 6 path). This lets us ship the script alongside the agent
prompt change and gate the cutover.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import _yaml_io
import plugin_meta
import yaml  # noqa: F401  (kept for downstream callers writing yaml)

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PLUGIN_ROOT / "data"


# ---------------------------------------------------------------------------
# Severity / impact ordinals
# ---------------------------------------------------------------------------

_SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SEV_LABEL = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}


def _sev_rank(s: str) -> int:
    return _SEV_ORDER.get((s or "").strip().lower(), 0)


def _sev_label(rank: int) -> str:
    return _SEV_LABEL.get(max(0, min(3, rank)), "Low")


def _max_sev(*sevs: str) -> str:
    return _sev_label(max((_sev_rank(s) for s in sevs), default=0))


def _impact_rank(impact: str) -> int:
    return _sev_rank(impact)


def _likelihood_rank_inverse(lik: str) -> int:
    """High → 0, Medium → 1, Low → 2 (low-likelihood deprioritized)."""
    m = {"high": 0, "medium": 1, "low": 2}
    return m.get((lik or "").strip().lower(), 1)


# ---------------------------------------------------------------------------
# YAML loaders (with graceful degradation)
# ---------------------------------------------------------------------------


def _load_yaml(path: Path, default: Any) -> Any:
    data = _yaml_io.load_yaml(path, default=default)
    return data if data else default


def _load_json(path: Path) -> Any:
    """Best-effort JSON load; returns None on any error (non-fatal). Used for
    the abuse-case sidecars, which may be absent when the feature is disabled
    or skipped under budget-critical."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Finding access helpers
# ---------------------------------------------------------------------------


def _finding_id(t: dict) -> str:
    return (t.get("t_id") or t.get("id") or t.get("finding_id") or "").strip()


def _finding_cwe(t: dict) -> str:
    """Return the primary CWE id (e.g. ``CWE-89``)."""
    pc = t.get("primary_cwe") or t.get("cwe")
    if isinstance(pc, str) and pc.strip():
        return pc.strip().upper()
    cwe_list = t.get("cwes") or []
    if isinstance(cwe_list, list) and cwe_list:
        first = cwe_list[0]
        if isinstance(first, dict):
            return (first.get("id") or "").strip().upper()
        if isinstance(first, str):
            return first.strip().upper()
    # Fallback: extract a bare CWE-NNN from remediation.reference when the
    # STRIDE analyzer omitted the top-level cwe field (pre-schema-fix runs).
    ref = ((t.get("remediation") or {}).get("reference") or "").strip()
    m = re.match(r"^(CWE-\d+)$", ref, re.I)
    if m:
        return m.group(1).upper()
    return ""


def _finding_severity(t: dict) -> str:
    return (t.get("risk") or t.get("severity") or "Medium").strip()


def _finding_impact(t: dict) -> str:
    return (t.get("impact") or "").strip()


def _finding_likelihood(t: dict) -> str:
    return (t.get("likelihood") or "").strip()


def _finding_title(t: dict) -> str:
    return (t.get("title") or t.get("name") or "").strip()


def _finding_scenario(t: dict) -> str:
    return (t.get("scenario") or "").lower()


def _finding_evidence_path(t: dict) -> str:
    ev = t.get("evidence")
    if isinstance(ev, dict):
        p = ev.get("file") or ev.get("path") or ""
        return str(p)
    if isinstance(ev, list) and ev and isinstance(ev[0], dict):
        return str(ev[0].get("file") or ev[0].get("path") or "")
    return ""


def _finding_cvss(t: dict) -> float:
    cvss = t.get("cvss_v3_1") or t.get("cvss")
    if isinstance(cvss, dict):
        try:
            return float(cvss.get("score") or 0)
        except (TypeError, ValueError):
            return 0.0
    return 0.0


# ---------------------------------------------------------------------------
# Step 6a — breach distance
# ---------------------------------------------------------------------------


def _compute_breach_distance(t: dict, patterns: dict) -> tuple[int, str]:
    """Return (distance, reason)."""
    title = _finding_title(t)
    scenario = _finding_scenario(t)
    evidence = _finding_evidence_path(t).lower()
    cwe = _finding_cwe(t)

    # Stage 1: title overrides
    for ov in patterns.get("overrides", []) or []:
        pat = ov.get("title_pattern") or ""
        if pat and re.search(pat, title, flags=re.I):
            return int(ov.get("distance", 2)), f"override:{pat}"

    # Stage 2: CWE default
    cwe_defaults = patterns.get("cwe_default_distance", {}) or {}
    distance = int(cwe_defaults.get(cwe, 2))
    reason = f"cwe_default:{cwe or 'unmapped'}"

    # Stage 3: route guard hints (lower distance to 1 if unauthenticated route)
    rg = (patterns.get("route_guard_indicators") or {}).get("frameworks") or {}
    for fw, rules in rg.items():
        if not isinstance(rules, dict):
            continue
        unauth_hints = rules.get("unauthenticated_route_hints") or []
        for hint in unauth_hints:
            if hint and (hint in scenario or hint in evidence):
                distance = min(distance, 1)
                reason = f"unauth_hint:{hint}"
                break
        auth_hints = rules.get("authenticated_route_hints") or []
        for hint in auth_hints:
            if hint and hint in evidence and distance < 2:
                distance = max(distance, 2)
                reason = f"auth_hint:{hint}"

    # Stage 4: amplifiers / deamplifiers (substring or CWE match)
    for amp in patterns.get("amplifiers", []) or []:
        keys = amp.get("if_any_match") or []
        if any(k.lower() in scenario for k in keys):
            distance = max(1, distance - int(amp.get("distance_delta", 0)))
            reason = f"amplifier:{amp.get('name', '?')}"
            break
    for deamp in patterns.get("deamplifiers", []) or []:
        keys = deamp.get("if_any_match") or []
        if any(k.lower() in scenario for k in keys):
            distance = min(3, distance + int(deamp.get("distance_delta", 0)))
            reason = f"deamplifier:{deamp.get('name', '?')}"
            break

    return max(1, min(3, distance)), reason


# ---------------------------------------------------------------------------
# Step 6b — compound-chain detection
# ---------------------------------------------------------------------------


def _match_chain_role(t: dict, role_spec: dict) -> bool:
    if not isinstance(role_spec, dict):
        return False
    cwe_any = role_spec.get("cwe_any") or []
    if cwe_any and _finding_cwe(t) in {c.strip().upper() for c in cwe_any if isinstance(c, str)}:
        return True
    title_any = role_spec.get("title_any") or []
    title = _finding_title(t).lower()
    if title_any and any(p.lower() in title for p in title_any if isinstance(p, str)):
        return True
    return False


def _detect_chains(findings: list[dict], chain_specs: list[dict]) -> list[dict]:
    """For each chain spec, identify members + roles. Return list of active chains."""
    active = []
    for chain in chain_specs:
        keystones, contributors, members = [], [], []
        for t in findings:
            tid = _finding_id(t)
            if not tid:
                continue
            roles = chain.get("roles") or {}
            is_keystone = _match_chain_role(t, roles.get("keystone") or {})
            is_contributor = _match_chain_role(t, roles.get("contributor") or {})
            if is_keystone:
                keystones.append(tid)
                members.append(tid)
            elif is_contributor:
                contributors.append(tid)
                members.append(tid)

        # Active when ≥ 2 members AND (at least one keystone OR no keystone section)
        keystone_required = bool((chain.get("roles") or {}).get("keystone"))
        if len(members) >= 2 and (keystones or not keystone_required):
            active.append(
                {
                    "id": chain.get("id"),
                    "name": chain.get("name"),
                    "severity": chain.get("severity", "High"),
                    "severity_justification": (chain.get("severity_justification") or "").strip(),
                    "breach_distance": int(chain.get("breach_distance", 2)),
                    "keystones": keystones,
                    "contributors": contributors,
                    "members": members,
                    "narrative": (chain.get("narrative_template") or "").strip(),
                }
            )
    return active


def _detect_verified_abuse_chains(findings: list[dict], verdicts_doc: Any, matches_doc: Any) -> list[dict]:
    """Build chain entries (same shape as ``_detect_chains``) from CODE-VERIFIED
    abuse-case verdicts, so the existing effective-severity elevation
    (keystone/contributor + caps + no-downgrade) drives the finding ratings.

    Only ``fully_viable`` chains elevate — ``partially_blocked`` /
    ``inconclusive`` do not (guardrail against inflation). A finding bound to a
    ``required`` step is a keystone; a non-required step is a contributor. The
    chain severity is one notch above the highest member raw severity — the
    "combined exceeds individual" semantics that justify an abuse case — capped
    at Critical. Returns [] when the sidecars are absent (non-fatal)."""
    if not isinstance(verdicts_doc, dict) or not isinstance(matches_doc, dict):
        return []
    verdict_by_id = {v.get("abuse_case_id"): v for v in (verdicts_doc.get("verdicts") or []) if isinstance(v, dict)}

    # The abuse-case matcher binds ``matched_finding_id`` from
    # ``.threats-merged.json`` using ``f_id|t_id|id`` — which need NOT be the
    # same key the triage uses (``t_id|id|finding_id``). Resolve a matched id
    # against EVERY id key of each finding, then store the triage-canonical
    # ``_finding_id`` so membership lines up with the per-finding loop below.
    finding_by_any_id: dict[str, dict] = {}
    for t in findings:
        for key in ("f_id", "t_id", "id", "finding_id"):
            val = (t.get(key) or "").strip()
            if val:
                finding_by_any_id.setdefault(val, t)

    out: list[dict] = []
    for m in matches_doc.get("matches") or []:
        if not isinstance(m, dict):
            continue
        cid = m.get("abuse_case_id")
        v = verdict_by_id.get(cid)
        if not v or v.get("chain_verdict") != "fully_viable":
            continue

        keystones, contributors, members, member_sevs = [], [], [], []
        for sm in m.get("step_matches") or []:
            raw = (sm.get("matched_finding_id") or "").strip()
            finding = finding_by_any_id.get(raw)
            if not finding:
                continue
            tid = _finding_id(finding)
            if not tid:
                continue
            members.append(tid)
            member_sevs.append(_finding_severity(finding))
            if sm.get("required", True):
                keystones.append(tid)
            else:
                contributors.append(tid)
        if not members:
            continue

        base = max((_sev_rank(s) for s in member_sevs), default=_sev_rank("High"))
        combined_rank = min(base + 1, _sev_rank("Critical"))
        out.append(
            {
                "id": cid,
                "name": m.get("title") or cid,
                "severity": _sev_label(combined_rank),
                "severity_justification": f"code-verified fully-viable abuse chain {cid}",
                "breach_distance": 1,
                "keystones": keystones,
                "contributors": contributors,
                "members": members,
                "narrative": "",
            }
        )
    return out


# ---------------------------------------------------------------------------
# Step 6c — effective severity with caps + critical-criteria gate
# ---------------------------------------------------------------------------


def _apply_severity_caps(eff_rank: int, cwe: str, caps: dict) -> tuple[int, str]:
    cap = (caps.get("severity_caps") or {}).get(cwe)
    if not cap:
        return eff_rank, ""
    cap_rank = _sev_rank(cap.get("max", "Critical"))
    if eff_rank > cap_rank:
        return cap_rank, f"capped:{cwe}<={cap.get('max')}"
    return eff_rank, ""


def _apply_critical_criteria(
    t: dict, eff_rank: int, role: str, criteria: dict, breach_distance: int
) -> tuple[int, str]:
    """Final gatekeeper for effective_severity == Critical.

    Two directions:
      • ``always_critical_cwes`` — when the required context holds (breach
        distance + impact floor), the CWE is Critical BY DEFINITION, so this
        PROMOTES a finding the auditor under-rated (e.g. a CWE-915 mass
        assignment that reaches ``role=admin`` on an unauthenticated endpoint
        but was scored High×High=High). When the context fails it caps at High.
      • ``never_individual_critical`` — de-escalates a Critical that is not a
        keystone in a Critical chain.

    Pre-2026-05-31 this function only *kept or de-escalated* an already-Critical
    finding and returned early for anything below Critical — so the
    always-critical CWEs could never actually promote, defeating their stated
    intent (juice-shop T-012 register-as-admin stayed High).
    """
    cwe = _finding_cwe(t)
    impact = _finding_impact(t)
    bd = breach_distance if isinstance(breach_distance, int) else 3

    # Always-critical CWEs: promote (or keep) when context holds, cap at High
    # when it fails. Runs regardless of the incoming rank so an under-scored
    # primary-breach finding is lifted to Critical.
    for entry in criteria.get("always_critical_cwes", []) or []:
        if cwe == (entry.get("cwe") or "").upper():
            req = entry.get("required") or {}
            bd_max = int(req.get("breach_distance_max", 3))
            imp_min = req.get("impact_min", "Low")
            context_ok = bd <= bd_max and _sev_rank(impact) >= _sev_rank(imp_min)
            if not context_ok:
                if eff_rank >= _sev_rank("Critical"):
                    return _sev_rank("High"), f"always_crit_failed:{cwe}"
                return eff_rank, ""
            if eff_rank < _sev_rank("Critical"):
                return _sev_rank("Critical"), f"always_crit_promoted:{cwe}"
            return eff_rank, ""

    # Don't elevate by default — only de-escalate Critical (non-always CWEs).
    if eff_rank < _sev_rank("Critical"):
        return eff_rank, ""

    # never_individual_critical CWEs drop unless they're a keystone in a Critical chain
    never_ind = criteria.get("never_individual_critical") or []
    if cwe in {c.strip().upper() for c in never_ind if isinstance(c, str)} and role != "keystone":
        return _sev_rank(criteria.get("max_severity_individual", "High")), f"never_individual:{cwe}"

    return eff_rank, ""


def _compute_effective(
    t: dict, chain_role: str | None, chain_severity: int, caps: dict, criteria: dict, breach_distance: int
) -> tuple[str, list[str]]:
    """Returns (effective_severity_label, reasons[])."""
    raw_rank = _sev_rank(_finding_severity(t))
    eff = raw_rank
    reasons: list[str] = []

    # M2: refuted findings are not chain-elevated. The auditor's raw risk
    # is preserved (we never downgrade), but the chain cannot pull this
    # finding's effective severity above raw. Suppression is opt-in via
    # the evidence-verifier's verdict; absent/unchecked findings behave
    # identically to pre-M2.
    # RC.P2a (2026-07): an *ambiguous* verdict — the evidence pointer could not
    # be confirmed against real code (e.g. it lands on a package/import line, is
    # out of range, or is an unverified inferred anchor) — is treated like
    # refuted for chain elevation: an unverifiable finding must not be pulled up
    # to Critical/High by a chain it only nominally belongs to. Consistent with
    # the "never downgrade raw auditor risk" policy above — raw severity is still
    # preserved; only the chain-elevation is suppressed.
    evidence_state = t.get("evidence_check")
    evidence_unverified = evidence_state in ("refuted", "ambiguous")

    # Chain elevation by role
    if chain_role == "keystone" and chain_severity > eff and not evidence_unverified:
        eff = chain_severity
        reasons.append(f"elevated:keystone({_sev_label(chain_severity)})")
    elif chain_role == "keystone" and chain_severity > eff and evidence_unverified:
        reasons.append(f"suppressed:evidence_{evidence_state}(keystone)")
    elif chain_role == "contributor" and not evidence_unverified:
        contributor_cap = _sev_rank((caps.get("contributor_cap") or {}).get("default", "High"))
        target = max(eff, min(chain_severity, contributor_cap))
        if target > eff:
            eff = target
            reasons.append(f"elevated:contributor_cap({_sev_label(target)})")
    elif chain_role == "contributor" and evidence_unverified:
        reasons.append(f"suppressed:evidence_{evidence_state}(contributor)")

    # Per-CWE cap
    cwe = _finding_cwe(t)
    eff, cap_reason = _apply_severity_caps(eff, cwe, caps)
    if cap_reason:
        reasons.append(cap_reason)

    # Critical criteria
    eff, crit_reason = _apply_critical_criteria(t, eff, chain_role or "", criteria, breach_distance)
    if crit_reason:
        reasons.append(crit_reason)

    # Invariant: effective never below raw
    if eff < raw_rank:
        eff = raw_rank
        reasons.append("invariant:no_downgrade_below_raw")

    return _sev_label(eff), reasons


# ---------------------------------------------------------------------------
# Step 6e/6f — scoring
# ---------------------------------------------------------------------------


def _cwe_top25_rank(cwe: str, taxonomy: dict) -> int:
    top25 = taxonomy.get("top25") or []
    for i, entry in enumerate(top25, start=1):
        if isinstance(entry, dict) and (entry.get("id") or "").upper() == cwe:
            return i
        if isinstance(entry, str) and entry.upper() == cwe:
            return i
    return 0


def _is_ranking_capped(cwe: str, caps: dict) -> bool:
    rcap = (caps.get("ranking_caps") or {}).get(cwe)
    if rcap and int(rcap.get("max_rank_tier", 1)) >= 2:
        return True
    return False


def _finding_score(t: dict, eff: str, breach_distance: int, chain_role: str | None, caps: dict, taxonomy: dict) -> int:
    cwe = _finding_cwe(t)
    score = (
        150 * _sev_rank(eff)
        + 40 * _impact_rank(_finding_impact(t))
        + 15 * (4 - breach_distance)
        + 3 * _likelihood_rank_inverse(_finding_likelihood(t))
    )
    rank = _cwe_top25_rank(cwe, taxonomy)
    if rank:
        score += 5 * (26 - rank)
    score += int(_finding_cvss(t))
    if chain_role == "contributor":
        score -= 50
    if _is_ranking_capped(cwe, caps):
        score -= 100
    return score


def _category_score(
    category: dict,
    members: list[dict],
    member_eff: dict[str, str],
    member_bd: dict[str, int],
    member_role: dict[str, str],
    caps: dict,
    taxonomy: dict,
) -> tuple[int, str, int]:
    """Return (score, max_eff_severity, min_bd)."""
    if not members:
        return 0, "Low", 3
    effs = [_sev_rank(member_eff.get(_finding_id(m), _finding_severity(m))) for m in members]
    bds = [member_bd.get(_finding_id(m), 3) for m in members]
    max_eff = max(effs)
    min_bd = min(bds) if bds else 3
    impacts = [_impact_rank(_finding_impact(m)) for m in members]
    likelihoods = [_likelihood_rank_inverse(_finding_likelihood(m)) for m in members]
    cvss_max = max((_finding_cvss(m) for m in members), default=0)

    cwe_top25 = sum(1 for m in members if _cwe_top25_rank(_finding_cwe(m), taxonomy))

    score = (
        150 * max_eff
        + 40 * (max(impacts) if impacts else 0)
        + 15 * (4 - min_bd)
        + 10 * len(members)
        + 5 * cwe_top25
        + 3 * (4 - (min(likelihoods) if likelihoods else 1))
        + int(cvss_max)
    )

    if any(_is_ranking_capped(_finding_cwe(m), caps) for m in members):
        score -= 100

    return score, _sev_label(max_eff), min_bd


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def compute_ranking(output_dir: Path, repo_root: Path | None = None) -> dict:
    """Run Steps 6a-6g. Returns the v2 ``ranking`` block."""
    yaml_path = output_dir / "threat-model.yaml"
    flags_path = output_dir / ".triage-flags.json"

    yaml_data = _load_yaml(yaml_path, {})
    if not isinstance(yaml_data, dict):
        raise SystemExit("ERROR: threat-model.yaml is not a mapping")

    findings: list[dict] = [t for t in (yaml_data.get("threats") or []) if isinstance(t, dict)]
    if not findings:
        # Nothing to rank; emit empty v2 block.
        return _empty_ranking_block()

    # Load reference data
    bd_patterns = _load_yaml(DATA_DIR / "breach-distance-patterns.yaml", {})
    chains_yaml = _load_yaml(DATA_DIR / "compound-chain-patterns.yaml", {})
    caps = _load_yaml(DATA_DIR / "severity-caps.yaml", {})
    criteria = _load_yaml(DATA_DIR / "critical-criteria.yaml", {})
    taxonomy = _load_yaml(DATA_DIR / "cwe-taxonomy.yaml", {})

    # 6a — breach distance per finding
    bd_by_id: dict[str, int] = {}
    bd_reason: dict[str, str] = {}
    for t in findings:
        tid = _finding_id(t)
        if not tid:
            continue
        d, r = _compute_breach_distance(t, bd_patterns)
        bd_by_id[tid] = d
        bd_reason[tid] = r
        # Augment yaml in-place (additive)
        if "breach_distance" not in t:
            t["breach_distance"] = d
            t["breach_distance_reason"] = r

    # 6b — chains (keyword compound-chains + code-verified abuse-case chains)
    active_chains = _detect_chains(findings, chains_yaml.get("chains") or [])
    verified_chains = _detect_verified_abuse_chains(
        findings,
        _load_json(output_dir / ".abuse-case-verdicts.json"),
        _load_json(output_dir / ".abuse-case-matches.json"),
    )
    all_chains = active_chains + verified_chains
    role_by_id: dict[str, str] = {}
    chain_membership: dict[str, list[str]] = {}  # compound-chain ids (CC-*)
    verified_membership: dict[str, list[str]] = {}  # verified abuse-case ids (AC-*)
    for ch in active_chains:
        for k in ch.get("keystones") or []:
            role_by_id[k] = "keystone"
            chain_membership.setdefault(k, []).append(ch["id"])
        for c in ch.get("contributors") or []:
            role_by_id.setdefault(c, "contributor")
            chain_membership.setdefault(c, []).append(ch["id"])
    for ch in verified_chains:
        for k in ch.get("keystones") or []:
            role_by_id[k] = "keystone"  # a code-verified chain is ≥ a keyword one
            verified_membership.setdefault(k, []).append(ch["id"])
        for c in ch.get("contributors") or []:
            role_by_id.setdefault(c, "contributor")
            verified_membership.setdefault(c, []).append(ch["id"])

    # 6c — effective severity per finding
    eff_by_id: dict[str, str] = {}
    eff_reasons_by_id: dict[str, list[str]] = {}
    for t in findings:
        tid = _finding_id(t)
        if not tid:
            continue
        role = role_by_id.get(tid)
        chain_sev_rank = 0
        for ch in all_chains:
            if tid in (ch["keystones"] + ch["contributors"]):
                chain_sev_rank = max(chain_sev_rank, _sev_rank(ch["severity"]))
        eff, reasons = _compute_effective(t, role, chain_sev_rank, caps, criteria, bd_by_id.get(tid, 2))
        eff_by_id[tid] = eff
        eff_reasons_by_id[tid] = reasons
        if "effective_severity" not in t:
            t["effective_severity"] = eff
            t["chain_role"] = role or "none"
            t["compound_chain_ids"] = chain_membership.get(tid, [])
            t["verified_chain_ids"] = verified_membership.get(tid, [])

    # 6e — categories
    categories: list[dict] = yaml_data.get("threat_categories") or []
    cat_scored: list[dict] = []
    for cat in categories:
        if not isinstance(cat, dict):
            continue
        member_ids = cat.get("findings") or cat.get("threat_ids") or []
        members = [t for t in findings if _finding_id(t) in member_ids]
        score, max_eff, min_bd = _category_score(cat, members, eff_by_id, bd_by_id, role_by_id, caps, taxonomy)
        cat_scored.append(
            {
                "rank": 0,  # filled below
                "id": cat.get("id") or cat.get("th_id") or "",
                "title": cat.get("title") or cat.get("name") or "",
                "effective_severity": max_eff,
                "raw_severity": cat.get("severity", max_eff),
                "min_breach_distance": min_bd,
                "finding_count": len(members),
                "top_finding_id": (
                    max(
                        members,
                        key=lambda m: _finding_score(
                            m,
                            eff_by_id.get(_finding_id(m), _finding_severity(m)),
                            bd_by_id.get(_finding_id(m), 2),
                            role_by_id.get(_finding_id(m)),
                            caps,
                            taxonomy,
                        ),
                    )[_threat_id_key(members[0])]
                    if members
                    else None
                ),
                "score": score,
                "reasons": _category_reasons(members, eff_by_id, bd_by_id, role_by_id, taxonomy),
            }
        )

    cat_scored.sort(key=lambda x: (-x["score"], x["id"]))
    for i, c in enumerate(cat_scored, start=1):
        c["rank"] = i
    top_threats = [c for c in cat_scored if _sev_rank(c["effective_severity"]) >= _sev_rank("High")]

    # 6f — finding scores
    fnd_scored: list[dict] = []
    for t in findings:
        tid = _finding_id(t)
        if not tid:
            continue
        eff = eff_by_id.get(tid, _finding_severity(t))
        bd = bd_by_id.get(tid, 2)
        role = role_by_id.get(tid)
        s = _finding_score(t, eff, bd, role, caps, taxonomy)
        fnd_scored.append(
            {
                "rank": 0,
                "id": tid,
                "effective_severity": eff,
                "raw_severity": _finding_severity(t),
                "chain_role": role or "none",
                "breach_distance": bd,
                "score": s,
                "compound_chain_ids": chain_membership.get(tid, []),
                "verified_chain_ids": verified_membership.get(tid, []),
            }
        )
    # 6f-bis — design-risk weaknesses (P1.4 / proposal §9.3). A pervasive design
    # weakness with ZERO confirmed instances is not in threats[], yet may be the
    # report's #1 risk. Fold each such weakness into findings_ranked as a
    # W-NNN entry so it competes for the top slot. `confirmed`-basis weaknesses
    # are already represented by their instances and are skipped here. Score
    # mirrors _finding_score's severity/impact weighting plus a pervasiveness
    # bonus; carries `severity_basis: design-risk` so the renderer tags it
    # distinctly and never implies a proven exploit. No-op when the register is
    # empty → legacy ranking is byte-identical.
    for w in yaml_data.get("weaknesses") or []:
        if not isinstance(w, dict) or (w.get("severity_basis") or "") != "design-risk":
            continue
        wid = (w.get("id") or "").strip()
        if not wid:
            continue
        sev = w.get("severity") or "Medium"
        spread = len(w.get("affected_components") or [])
        score = 150 * _sev_rank(sev) + 40 * _impact_rank(sev) + 10 * spread + 5
        fnd_scored.append(
            {
                "rank": 0,
                "id": wid,
                "effective_severity": sev,
                "raw_severity": sev,
                "severity_basis": "design-risk",
                "kind": w.get("kind"),
                "weakness_class": w.get("weakness_class"),
                "chain_role": "none",
                "breach_distance": 3,
                "score": score,
                "compound_chain_ids": [],
                "verified_chain_ids": [],
            }
        )

    fnd_scored.sort(key=lambda x: (-x["score"], x["id"]))
    for i, f in enumerate(fnd_scored, start=1):
        f["rank"] = i

    # 6g — mitigations ranked by addressed severity
    mits_ranked = _rank_mitigations(yaml_data.get("mitigations") or [], eff_by_id)

    chains_ranked = sorted(
        active_chains,
        key=lambda c: (-_sev_rank(c.get("severity", "Low")), -len(c.get("members") or []), c.get("id") or ""),
    )

    # Reconciliation summary
    elevated = sum(1 for tid, reasons in eff_reasons_by_id.items() if any(r.startswith("elevated:") for r in reasons))
    capped = sum(1 for tid, reasons in eff_reasons_by_id.items() if any(r.startswith("capped:") for r in reasons))
    contrib_capped = sum(
        1
        for tid, role in role_by_id.items()
        if role == "contributor" and _sev_rank(eff_by_id.get(tid, "")) <= _sev_rank("High")
    )

    return {
        "method": "impact-weighted-v2",
        "ranked_at": _now_iso(),
        "computed_by": "triage_compute_ranking.py (deterministic)",
        "views": {
            "top_threats": {
                "sort_key": "category_score_impact_weighted",
                "threshold": "effective_severity >= High",
                "categories_ranked": top_threats,
            },
            "top_findings": {
                "sort_key": "finding_score_impact_weighted",
                "threshold": "effective_severity == Critical",
                "max_rows": min(5, len(fnd_scored)),
                "findings_ranked": fnd_scored[:50],  # cap to avoid bloat
            },
            "prioritized_mitigations": {
                "sort_key": "addressed_severity_desc_then_effort_asc",
                "mitigations_ranked": mits_ranked,
            },
            "chains": {
                "sort_key": "severity_desc_then_member_count_desc",
                "chains_ranked": chains_ranked,
            },
        },
        "reconciliation_summary": {
            "findings_elevated_via_chain": elevated,
            "findings_capped_by_cwe": capped,
            "contributors_capped_at_high": contrib_capped,
            "chains_active": len(active_chains),
        },
    }


def _empty_ranking_block() -> dict:
    return {
        "method": "impact-weighted-v2",
        "ranked_at": _now_iso(),
        "computed_by": "triage_compute_ranking.py (deterministic)",
        "views": {
            "top_threats": {
                "sort_key": "category_score_impact_weighted",
                "threshold": "effective_severity >= High",
                "categories_ranked": [],
            },
            "top_findings": {
                "sort_key": "finding_score_impact_weighted",
                "threshold": "effective_severity == Critical",
                "max_rows": 0,
                "findings_ranked": [],
            },
            "prioritized_mitigations": {
                "sort_key": "addressed_severity_desc_then_effort_asc",
                "mitigations_ranked": [],
            },
            "chains": {"sort_key": "severity_desc_then_member_count_desc", "chains_ranked": []},
        },
        "reconciliation_summary": {
            "findings_elevated_via_chain": 0,
            "findings_capped_by_cwe": 0,
            "contributors_capped_at_high": 0,
            "chains_active": 0,
        },
    }


def _threat_id_key(t: dict) -> str:
    return _finding_id(t)


def _category_reasons(members, eff_by_id, bd_by_id, role_by_id, taxonomy) -> list[str]:
    out = []
    for m in members[:3]:  # cap at 3 reasons
        tid = _finding_id(m)
        eff = eff_by_id.get(tid, _finding_severity(m))
        bd = bd_by_id.get(tid, 2)
        cwe = _finding_cwe(m)
        bits = [eff]
        if bd == 1:
            bits.append("internet-reachable")
        rank = _cwe_top25_rank(cwe, taxonomy)
        if rank and rank <= 10:
            bits.append(f"CWE Top-25 #{rank}")
        out.append(": ".join(bits))
    return out


def _rank_mitigations(mits: list, eff_by_id: dict[str, str]) -> list[dict]:
    if not mits:
        return []
    effort_order = {"low": 0, "medium": 1, "high": 2}
    scored = []
    for m in mits:
        if not isinstance(m, dict):
            continue
        addressed = m.get("addresses") or m.get("addresses_findings") or m.get("addresses_threats") or []
        if not isinstance(addressed, list):
            addressed = []
        max_addressed_rank = 0
        for tid in addressed:
            r = _sev_rank(eff_by_id.get(str(tid), ""))
            max_addressed_rank = max(max_addressed_rank, r)
        scored.append(
            {
                "id": m.get("m_id") or m.get("id") or "",
                "addresses_findings": addressed,
                "effort": m.get("effort", "Medium"),
                "score": 1000 * max_addressed_rank - 10 * effort_order.get((m.get("effort") or "Medium").lower(), 1),
                "_max_eff_rank": max_addressed_rank,
            }
        )
    scored.sort(key=lambda x: (-x["score"], x["id"]))
    for i, e in enumerate(scored, start=1):
        e["rank"] = i
        e.pop("_max_eff_rank", None)
    return scored


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Persistence — write yaml + triage-flags.json (v2)
# ---------------------------------------------------------------------------


def write_outputs(output_dir: Path, ranking: dict) -> None:
    yaml_path = output_dir / "threat-model.yaml"
    flags_path = output_dir / ".triage-flags.json"

    # The yaml has been augmented in-place inside compute_ranking; persist.
    with yaml_path.open(encoding="utf-8") as fh:
        yaml_data = yaml.safe_load(fh)
    # Re-apply augmented fields from ranking views back onto yaml.threats
    findings_by_id = {_finding_id(t): t for t in (yaml_data.get("threats") or []) if isinstance(t, dict)}
    for f in ranking.get("views", {}).get("top_findings", {}).get("findings_ranked", []):
        t = findings_by_id.get(f["id"])
        if t is not None:
            t["effective_severity"] = f["effective_severity"]
            t["breach_distance"] = f["breach_distance"]
            t["chain_role"] = f["chain_role"]
            t["compound_chain_ids"] = f.get("compound_chain_ids", [])
            t["verified_chain_ids"] = f.get("verified_chain_ids", [])
    # Write yaml back
    yaml_path.write_text(
        yaml.safe_dump(yaml_data, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )

    # Update triage-flags.json
    if flags_path.is_file():
        with flags_path.open(encoding="utf-8") as fh:
            flags = json.load(fh)
    else:
        flags = {"version": 1, "flags": [], "summary": {}}
    flags["version"] = 2
    # When compute_ranking is the create-owner (the pre-flight writer
    # triage_validate_ratings.py did not run), the stub above lacks the
    # schema-required root `generated_at` and the populated `summary` block.
    # Backfill them so the file is ALWAYS schema-valid (schemas/triage-flags.
    # schema.yaml requires generated_at + summary.{total_flags,warnings,info,
    # threats_reviewed}). setdefault preserves real pre-flight values when the
    # file already existed — only the create-fallback path is filled in.
    flags.setdefault("generated_at", _now_iso())
    flags_list = flags.get("flags") or []
    summary = flags.setdefault("summary", {})
    summary.setdefault("total_flags", len(flags_list))
    summary.setdefault(
        "warnings",
        sum(1 for f in flags_list if isinstance(f, dict) and f.get("severity") == "warning"),
    )
    summary.setdefault(
        "info",
        sum(1 for f in flags_list if isinstance(f, dict) and f.get("severity") == "info"),
    )
    summary.setdefault("threats_reviewed", len(yaml_data.get("threats") or []))
    flags["ranking"] = ranking
    flags_path.write_text(json.dumps(flags, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _bootstrap_yaml_from_merged(output_dir: Path) -> bool:
    """Write a minimal threat-model.yaml from .threats-merged.json.

    Called when --bootstrap-yaml is set and threat-model.yaml is missing.
    The stub contains only the fields triage_compute_ranking needs: threats[]
    with t_id, risk, likelihood, impact, title, component_id, stride, scenario.
    Phase 11 (compose) will overwrite this with the full canonical yaml later.
    Returns True on success, False on failure.
    """
    merged_path = output_dir / ".threats-merged.json"
    yaml_path = output_dir / "threat-model.yaml"
    if not merged_path.is_file():
        print("ERROR: .threats-merged.json missing — cannot bootstrap threat-model.yaml", file=sys.stderr)
        return False
    try:
        with merged_path.open(encoding="utf-8") as fh:
            merged = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"ERROR reading .threats-merged.json: {exc}", file=sys.stderr)
        return False

    threats_raw: list[dict] = merged.get("threats") or []
    threats_stub = []
    for t in threats_raw:
        threats_stub.append(
            {
                "t_id": t.get("t_id") or t.get("id") or "",
                "title": t.get("title") or "",
                "risk": t.get("risk") or t.get("severity") or "Medium",
                "likelihood": t.get("likelihood") or "Medium",
                "impact": t.get("impact") or "Medium",
                # Mirror merge_threats.py:135-139 normalization — config-scan
                # and other non-STRIDE-source threats may set only
                # `stride_category`; fall back to it so the bootstrap stub
                # carries a valid STRIDE enum string instead of an empty list.
                "stride": t.get("stride") or t.get("stride_category") or "",
                "scenario": t.get("scenario") or "",
                "component_id": t.get("component_id") or "",
            }
        )

    analysis_version = plugin_meta.load_meta()["analysis_version"]
    stub: dict = {
        "meta": {"analysis_version": analysis_version, "_bootstrap": True},
        "threat_categories": [],
        "threats": threats_stub,
        "mitigations": [],
        "components": [],
    }
    try:
        yaml_path.write_text(
            yaml.safe_dump(stub, sort_keys=False, allow_unicode=True, width=120),
            encoding="utf-8",
        )
        print(
            f"triage_compute_ranking: bootstrapped threat-model.yaml from .threats-merged.json ({len(threats_stub)} threats)"
        )
        return True
    except OSError as exc:
        print(f"ERROR writing bootstrapped threat-model.yaml: {exc}", file=sys.stderr)
        return False


def _is_deterministic_ranking_owner(output_dir: Path) -> bool:
    """True when a prior deterministic Step 6 run owns the ranking block.

    The marker is ``ranking.computed_by`` in ``.triage-flags.json`` — written
    only by this script (see the ranking dicts in ``compute_ranking``). The
    LLM-driven Step 6 fallback writes its own ranking block without this
    value, so the Stage 1c fold (``--if-deterministic-owner``) stays a no-op
    there and never clobbers LLM-refined rankings.
    """
    flags_path = output_dir / ".triage-flags.json"
    try:
        with flags_path.open(encoding="utf-8") as fh:
            flags = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return False
    computed_by = ((flags.get("ranking") or {}).get("computed_by")) or ""
    return computed_by.startswith("triage_compute_ranking.py")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("output_dir", type=Path, help="$OUTPUT_DIR with threat-model.yaml and .triage-flags.json")
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--force", action="store_true", help="Bypass the APPSEC_TRIAGE_DETERMINISTIC=1 feature flag")
    parser.add_argument(
        "--if-deterministic-owner",
        action="store_true",
        help="Run only when .triage-flags.json shows this script as the "
        "ranking owner (ranking.computed_by from a prior deterministic Step "
        "6 run); exit cleanly otherwise. Bypasses the env feature flag — "
        "for skill-level re-runs (Stage 1c fold) where env vars don't reach "
        "the orchestrator Bash and the LLM-ranking fallback must not be "
        "clobbered.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Compute the ranking but don't write back to disk")
    parser.add_argument(
        "--bootstrap-yaml",
        action="store_true",
        help="If threat-model.yaml is missing, bootstrap a minimal stub from "
        ".threats-merged.json so ranking can proceed. Phase 11 overwrites "
        "the stub with the canonical yaml. Fixes the Phase-10b sequencing "
        "bug where triage_compute_ranking ran before Phase 11 yaml write.",
    )
    args = parser.parse_args(argv)

    if args.if_deterministic_owner:
        if not _is_deterministic_ranking_owner(args.output_dir.resolve()):
            print(
                "triage_compute_ranking: .triage-flags.json carries no deterministic "
                "ranking marker (ranking.computed_by) — not the ranking owner, exiting cleanly"
            )
            return 0
    elif not args.force and os.environ.get("APPSEC_TRIAGE_DETERMINISTIC", "") not in ("1", "true", "yes"):
        print("triage_compute_ranking: feature flag APPSEC_TRIAGE_DETERMINISTIC=1 not set — exiting cleanly")
        return 0

    output_dir = args.output_dir.resolve()
    if not output_dir.is_dir():
        print(f"ERROR: {output_dir} is not a directory", file=sys.stderr)
        return 1

    if not (output_dir / "threat-model.yaml").is_file():
        if args.bootstrap_yaml:
            if not _bootstrap_yaml_from_merged(output_dir):
                return 1
        else:
            print("ERROR: threat-model.yaml missing — Phase 10b prerequisite", file=sys.stderr)
            return 1

    try:
        ranking = compute_ranking(output_dir, args.repo_root)
    except Exception as exc:  # pragma: no cover — surface unexpected errors
        print(f"ERROR computing ranking: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(json.dumps(ranking, indent=2)[:2000])
        return 0

    try:
        write_outputs(output_dir, ranking)
    except OSError as exc:
        print(f"ERROR writing outputs: {exc}", file=sys.stderr)
        return 3

    summary = ranking["reconciliation_summary"]
    print(
        f"triage_compute_ranking: ranking written. "
        f"chains_active={summary['chains_active']} "
        f"elevated={summary['findings_elevated_via_chain']} "
        f"capped={summary['findings_capped_by_cwe']} "
        f"contrib_capped={summary['contributors_capped_at_high']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
