"""Auto-emit `kind: fix` mitigations for code findings the LLM left uncovered.

Background. `scripts/build_threat_model_yaml.py:build_mitigations` only emits
an M-NNN card for a threat that ALREADY carries `mitigation_ids[]`. Those IDs
are assigned by the threat-analyst during the LLM-driven Phase 11 yaml write.
When that step under-produces — observed on the 2026-06-02 juice-shop run,
where all 13 Critical code findings (SQLi, RCE, hardcoded key, stored XSS, …)
came back with `mitigation_ids: []` — `build_mitigations` sees no IDs and emits
no cards. The Mitigation Register then ships with `_No P1 mitigations._` even
though every one of those threats already carries a fully-populated
`remediation` block and `mitigation_title`.

`emit_config_scan_mitigations.py` closes this gap for `source: config-scan`
threats. This emitter is its sibling for *code* findings: it backfills a fix
card for any threat that has remediation content but no mitigation link.

Pipeline:

1. Scan `threat-model.yaml → threats[]` for rows that:
   - carry NO `mitigation_ids`, AND
   - are NOT `source: config-scan` (handled by the sibling emitter), AND
   - carry a usable `remediation` block (or at least a `mitigation_title`).
2. Group threats by their normalised `mitigation_title` so genuine duplicates
   (e.g. two SQL-injection sinks both fixed by "Parameterize raw queries")
   collapse into ONE card addressing both threat IDs — matching the
   build_mitigations "one M-ID, many threat_ids" model.
3. Resolve rollout priority from severity + effort using the P1–P4 algorithm
   in `phase-group-threats.md` (Critical + tractable effort → P1; high-effort
   Critical slips to P2; High → P2/P3; Medium → P3; Low → P4).
4. Allocate the next free `M-NNN`, append a card with `kind: fix`,
   `auto_emitted: true`, `auto_source: "finding-fix"`, and link it back via
   `threat.mitigation_ids`.

Idempotent — prior `auto_source: "finding-fix"` cards and their back-references
are stripped before re-computing, so re-runs are stable.

Usage:
    python3 emit_finding_fix_mitigations.py <output_dir>

Exit codes: 0 always (best-effort emitter; failures are warnings on stderr).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

_M_ID_RE = re.compile(r"\bM-(\d{3,})\b")

# Severity → baseline priority (mirrors build_threat_model_yaml.build_mitigations
# and emit_config_scan_mitigations._SEV_TO_PRI).
_SEV_TO_PRI = {
    "Critical": "P1",
    "High": "P2",
    "Medium": "P3",
    "Low": "P4",
    "Informational": "P4",
}

# Vektors that mean "reachable without authenticating" — keep a Critical at P1
# even when the fix is high effort (the doc's "unauthenticated exploit" rule).
_UNAUTH_VEKTORS = {"internet-anon", "internet-user", "repo-read"}


def _resolve_priority(severity: str, effort: str, vektor: str) -> str:
    """P1–P4 per phase-group-threats.md, severity + effort + reachability.

    Severity says *how bad*, priority says *how soon*. A Critical with a
    tractable (Low/Medium) fix, or one reachable without auth, is P1; a
    Critical whose only fix is high-effort/architectural slips to P2. High
    severity is P2 when the fix is Low/Medium effort, else P3.
    """
    sev = severity or "Medium"
    eff = (effort or "Medium").capitalize()
    if sev == "Critical":
        if eff != "High" or vektor in _UNAUTH_VEKTORS:
            return "P1"
        return "P2"
    if sev == "High":
        return "P2" if eff in ("Low", "Medium") else "P3"
    return _SEV_TO_PRI.get(sev, "P3")


def _norm_title(title: str) -> str:
    """Normalise a mitigation title for grouping (case/space-insensitive)."""
    return re.sub(r"\s+", " ", (title or "").strip().lower())


def _remediation_how(threat: dict) -> str:
    """Build the `how` prose from the threat's remediation — prose-only.

    When `remediation.steps` is a structured list, this returns "" instead of
    joining the steps into one paragraph: compose's render-time fallback
    already harvests `remediation.steps` from the addressed threat and renders
    it as an ordered list, so joining it here too would duplicate the same
    content twice under one mitigation card — once as a paragraph, once as a
    numbered list (juice-shop 2026-07-02 / M-038).
    """
    rem = threat.get("remediation") or {}
    steps = rem.get("steps") if isinstance(rem, dict) else None
    if isinstance(steps, list) and steps and any(str(s).strip() for s in steps):
        return ""
    # Fall back to a single remediation string or the mitigation title.
    if isinstance(rem, str) and rem.strip():
        return rem.strip()
    return threat.get("mitigation_title") or ""


def _scan_max_m_id(data: dict) -> int:
    max_n = 0
    for m in data.get("mitigations") or []:
        if not isinstance(m, dict):
            continue
        mt = _M_ID_RE.fullmatch((m.get("id") or "").strip())
        if mt:
            max_n = max(max_n, int(mt.group(1)))
    return max_n


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
        encoding="utf-8",
    )


def _clear_prior_auto_mitigations(data: dict) -> set[str]:
    items = data.get("mitigations") or []
    if not isinstance(items, list):
        return set()
    stale = {
        m.get("id")
        for m in items
        if isinstance(m, dict)
        and m.get("auto_emitted") is True
        and m.get("auto_source") == "finding-fix"
        and m.get("id")
    }
    if stale:
        data["mitigations"] = [m for m in items if not (isinstance(m, dict) and m.get("id") in stale)]
    return stale


def _clear_stale_threat_refs(data: dict, stale_ids: set[str]) -> None:
    if not stale_ids:
        return
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        existing = t.get("mitigation_ids") or []
        if not existing:
            continue
        kept = [mid for mid in existing if mid not in stale_ids]
        if kept != existing:
            t["mitigation_ids"] = kept


_RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

# G3 (2026-07-05) — kinds that are evidence-confidence NOTES, not remediations.
# A finding covered only by one of these still needs its real fix mitigation.
_NON_REMEDIATION_KINDS = {"review", "investigate"}


def _threat_ids_with_real_mitigation(data: dict) -> set[str]:
    """Threat IDs already covered by a genuine (non-review) mitigation.

    A ``kind:review`` / ``kind:investigate`` card is an evidence-confidence note
    ("have a human re-check this line") — NOT a code fix. Before this guard, a
    single review card set ``threats[].mitigation_ids`` and suppressed the real
    ``kind:fix`` mitigation here (2026-07-05 juice-shop: a degenerate all-
    ambiguous verifier produced 51 review cards, collapsing the Mitigation
    Register to all-P3 with zero P1). Only a real mitigation counts as coverage.
    """
    by_id = {m.get("id"): m for m in (data.get("mitigations") or []) if isinstance(m, dict) and m.get("id")}
    covered: set[str] = set()
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("id") or "").strip()
        if not tid:
            continue
        mids = t.get("mitigation_ids") or []
        if not mids:
            continue
        # A threat is genuinely covered UNLESS every *resolvable* link is a
        # review/investigate note. Dangling links (no matching M-NNN in
        # mitigations[]) are conservatively treated as pre-existing real
        # coverage — only a fully review-only link set uncovers the finding so
        # its real fix card gets synthesised.
        resolvable = [by_id[mid] for mid in mids if mid in by_id]
        if resolvable and all((m.get("kind") or "").strip().lower() in _NON_REMEDIATION_KINDS for m in resolvable):
            continue
        covered.add(tid)
    return covered


def _synthesize(data: dict, state: dict) -> list[dict]:
    """Group uncovered code findings by fix title and emit one card each."""
    covered = _threat_ids_with_real_mitigation(data)
    groups: dict[str, dict] = {}
    order: list[str] = []
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        tid = (t.get("id") or "").strip()
        # G3 — skip only when a real (non-review) mitigation already covers the
        # finding; a lone review/investigate card must NOT block the fix card.
        if tid in covered:
            continue
        if (t.get("source") or "") == "config-scan":
            continue
        if not tid:
            continue
        how = _remediation_how(t)
        title = (t.get("mitigation_title") or "").strip()
        rem = t.get("remediation") or {}
        has_steps = isinstance(rem, dict) and any(str(s).strip() for s in (rem.get("steps") or []))
        if not title and not how and not has_steps:
            # No remediation content at all — nothing to synthesise. (`how`
            # is deliberately "" when `remediation.steps` exists — see
            # _remediation_how — so `has_steps` covers that case here.)
            continue
        if not title:
            title = f"Remediate {t.get('title', tid)}"
        key = _norm_title(title)
        if key not in groups:
            groups[key] = {
                "title": title,
                "threats": [],
                "how": how,
            }
            order.append(key)
        groups[key]["threats"].append(t)

    new_cards: list[dict] = []
    for key in order:
        g = groups[key]
        members = g["threats"]
        # Worst severity across the group drives priority.
        sev = min(
            (m.get("risk") or "Medium" for m in members),
            key=lambda s: _RISK_ORDER.get(s, 4),
        )
        # Lowest effort across the group (a Low-effort path keeps it P1).
        efforts = [
            ((m.get("remediation") or {}).get("effort") or "Medium")
            if isinstance(m.get("remediation"), dict)
            else "Medium"
            for m in members
        ]
        effort = min(efforts, key=lambda e: {"Low": 0, "Medium": 1, "High": 2}.get(e.capitalize(), 1))
        # Any unauth-reachable member keeps a Critical at P1.
        vektor = ""
        for m in members:
            if (m.get("vektor") or "") in _UNAUTH_VEKTORS:
                vektor = m.get("vektor")
                break
        cwes = []
        for m in members:
            c = m.get("cwe")
            if c and c not in cwes:
                cwes.append(c)
        mid = f"M-{state['counter'] + 1:03d}"
        state["counter"] += 1
        card = {
            "id": mid,
            "title": g["title"],
            "kind": "fix",
            "priority": _resolve_priority(sev, effort, vektor),
            "severity": sev,
            "effort": effort.capitalize(),
            "threat_ids": [m["id"] for m in members],
            "auto_emitted": True,
            "auto_source": "finding-fix",
        }
        if g["how"]:
            card["how"] = g["how"]
        if cwes:
            card["prevents"] = cwes
        new_cards.append(card)
        for m in members:
            m.setdefault("mitigation_ids", []).append(mid)
    return new_cards


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: emit_finding_fix_mitigations.py <output_dir>", file=sys.stderr)
        return 0
    out_dir = Path(sys.argv[1])
    yaml_path = out_dir / "threat-model.yaml"
    if not yaml_path.exists():
        print(f"emit_finding_fix_mitigations: no {yaml_path} — skipping", file=sys.stderr)
        return 0
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"emit_finding_fix_mitigations: failed to load yaml: {exc}", file=sys.stderr)
        return 0
    if not isinstance(data, dict):
        print("emit_finding_fix_mitigations: yaml root is not a mapping — skipping", file=sys.stderr)
        return 0

    stale = _clear_prior_auto_mitigations(data)
    _clear_stale_threat_refs(data, stale)

    state = {"counter": _scan_max_m_id(data)}
    new_cards = _synthesize(data, state)
    if not new_cards:
        if stale:
            _write_yaml(yaml_path, data)
        print("emit_finding_fix_mitigations: no uncovered code findings — nothing to emit", file=sys.stderr)
        return 0

    existing = data.get("mitigations") or []
    existing.extend(new_cards)

    def _sort_key(m: dict) -> tuple[int, str]:
        mid = (m.get("id") or "") if isinstance(m, dict) else ""
        mt = _M_ID_RE.fullmatch(mid)
        return (int(mt.group(1)) if mt else 99999, mid)

    data["mitigations"] = sorted(existing, key=_sort_key)
    _write_yaml(yaml_path, data)

    from collections import Counter

    pri = Counter(c["priority"] for c in new_cards)
    print(
        f"emit_finding_fix_mitigations: appended {len(new_cards)} fix card(s) "
        f"({' · '.join(f'{k}={v}' for k, v in sorted(pri.items()))}); "
        f"cleared {len(stale)} stale auto-card(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
