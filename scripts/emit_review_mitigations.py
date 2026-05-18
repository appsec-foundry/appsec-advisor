#!/usr/bin/env python3
"""M-15 / M-16 / M-17 / M-20: Synthesize review/investigate mitigations.

Reads `$OUTPUT_DIR/threat-model.yaml` (post-Phase-11) and appends auto-
generated mitigations for findings that warrant a human-review step rather
than a concrete code fix:

  M-15: evidence_check == "ambiguous" → kind=review, "Manual review:
        verify <weakness> at <file:line>" (P3).
  M-16: evidence_check == "refuted"   → kind=review, "Confirm fix coverage
        at <file:line>" (P3).
  M-17: source ∈ {architectural-anti-pattern, coverage-gap}
        → kind=investigate, ONE card per architectural_theme cluster
        (volume control per verification report) (P2).
  M-20: affected_parameter set + cwe ∈ injection-classes + no M-NNN already
        linked → append PoC hint to the synthesized review/investigate
        card OR a new one when no other auto-card applies.

The script is idempotent — it strips any prior `auto_emitted: true`
mitigations from `mitigations[]` before re-computing, so re-running
produces the same output regardless of run history.

M-NNN ID allocation: uses `baseline_state._scan_max_id` semantics — finds
the highest existing M-NNN in the yaml and starts numbering above it. This
avoids collision with the next run's `baseline_state` counter (which also
re-scans the yaml at L255-256).

Idempotency note: synthesized mitigations carry `auto_emitted: true` and
an `auto_source` discriminator so a re-run can clear and regenerate them.

Usage:
    python3 emit_review_mitigations.py <output_dir>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# CWE → injection-class allowlist for M-20 PoC hints.
# ---------------------------------------------------------------------------

_INJECTION_CWES = frozenset({
    "CWE-89",   # SQL injection
    "CWE-90",   # LDAP injection
    "CWE-78",   # OS command injection
    "CWE-79",   # XSS
    "CWE-91",   # XML injection
    "CWE-94",   # Code injection / eval
    "CWE-95",   # Server-side template injection
    "CWE-611", # XXE
    "CWE-639", # IDOR (BOLA)
    "CWE-918", # SSRF
    "CWE-601", # Open redirect
    "CWE-943", # NoSQL injection
})


_M_ID_RE = re.compile(r"\bM-(\d{3,})\b")


def _scan_max_m_id(data: dict) -> int:
    """Highest M-NNN already in use across mitigations[]. Used to allocate
    fresh IDs above that ceiling so baseline_state's next-run rescan picks
    up the new IDs naturally."""
    max_n = 0
    for m in data.get("mitigations") or []:
        if not isinstance(m, dict):
            continue
        mid = (m.get("id") or "").strip()
        mt = _M_ID_RE.fullmatch(mid)
        if mt:
            max_n = max(max_n, int(mt.group(1)))
    return max_n


def _evidence_file(threat: dict) -> tuple[str, int | None]:
    ev = threat.get("evidence") or []
    first: dict[str, Any] = {}
    if isinstance(ev, list) and ev:
        first = ev[0] if isinstance(ev[0], dict) else {}
    elif isinstance(ev, dict):
        first = ev
    f = (first.get("file") or "").strip()
    ln = first.get("line") if isinstance(first.get("line"), int) else None
    return f, ln


def _short_weakness(title: str) -> str:
    """Strip the trailing `(path)` or em-dash file suffix to recover the
    weakness-class noun phrase only — used in synthesized review titles."""
    t = (title or "").strip()
    if not t:
        return "the finding"
    # Drop `(path...)` suffix.
    t = re.sub(r"\s*\([^)]*\)$", "", t).strip()
    # Drop trailing em-dash + remainder (legacy format).
    t = t.split(" — ")[0].strip()
    return t or "the finding"


def _clear_prior_auto_mitigations(data: dict) -> None:
    """Drop any prior auto_emitted mitigation so re-runs are idempotent."""
    items = data.get("mitigations") or []
    if not isinstance(items, list):
        return
    surviving = [
        m for m in items
        if not (isinstance(m, dict) and m.get("auto_emitted") is True)
    ]
    # Also unlink dropped M-NNNs from threats[].mitigations[].
    dropped_ids = {
        (m.get("id") or "").strip()
        for m in items
        if isinstance(m, dict) and m.get("auto_emitted") is True
    }
    if dropped_ids:
        for t in data.get("threats") or []:
            if isinstance(t, dict) and isinstance(t.get("mitigations"), list):
                t["mitigations"] = [
                    mid for mid in t["mitigations"] if mid not in dropped_ids
                ]
    data["mitigations"] = surviving


def _allocate_next_m_id(state: dict) -> str:
    """Mint the next M-NNN and bump the counter in ``state``."""
    state["counter"] += 1
    return f"M-{state['counter']:03d}"


def _link_threat_to_mitigation(threats_by_id: dict, tid: str, mid: str) -> None:
    """Append `mid` to `threats[tid].mitigations[]` if not already there."""
    t = threats_by_id.get(tid)
    if t is None:
        return
    mitigations = t.get("mitigations")
    if not isinstance(mitigations, list):
        mitigations = []
        t["mitigations"] = mitigations
    if mid not in mitigations:
        mitigations.append(mid)


# ---------------------------------------------------------------------------
# M-15 / M-16: evidence_check ∈ {ambiguous, refuted}
# ---------------------------------------------------------------------------

def _synthesize_evidence_review(
    data: dict, state: dict, threats_by_id: dict
) -> list[dict]:
    """One review card per threat with evidence_check ∈ {ambiguous, refuted}."""
    new_cards: list[dict] = []
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        ec = (t.get("evidence_check") or "").strip().lower()
        if ec not in ("ambiguous", "refuted"):
            continue
        tid = (t.get("id") or "").strip()
        if not tid:
            continue
        f, ln = _evidence_file(t)
        target = f"{f}:{ln}" if (f and ln) else (f or "the cited location")
        weakness = _short_weakness(t.get("title") or "")
        mid = _allocate_next_m_id(state)
        if ec == "ambiguous":
            title = f"Manual review: verify {weakness} at {target}"
            how = (
                "The evidence-verifier sample could not confirm or refute "
                "the claim from the cited snippet alone. Have a developer "
                "familiar with this code path read ±20 lines around the "
                f"cited location ({target}) and decide whether to keep, "
                "downgrade, or remove this finding."
            )
            reason = "evidence-verifier returned ambiguous"
        else:  # refuted
            title = f"Confirm fix coverage at {target}"
            how = (
                "The evidence-verifier sample disagrees with the original "
                "claim — the cited line does not show the weakness as stated. "
                "Confirm the fix has fully landed, that no sibling code path "
                "reintroduces the defect, and that the finding can be closed."
            )
            reason = "evidence-verifier returned refuted"
        new_cards.append({
            "id": mid,
            "title": title,
            "kind": "review",
            "priority": "P3",
            "threat_ids": [tid],
            "how": how,
            "review_target": target,
            "review_reason": reason,
            "auto_emitted": True,
            "auto_source": f"evidence-check-{ec}",
        })
        _link_threat_to_mitigation(threats_by_id, tid, mid)
    return new_cards


# ---------------------------------------------------------------------------
# M-17: architectural-anti-pattern / coverage-gap — clustered investigate
# ---------------------------------------------------------------------------

_ARCH_SOURCES = frozenset({"architectural-anti-pattern", "coverage-gap"})


def _arch_theme_key(threat: dict) -> str:
    """Bucket key for clustering architectural findings into ONE
    investigate card per theme. Prefer explicit `architectural_theme` /
    `rule_id` when present; fall back to (cwe, component) so unknown
    themes still cluster reasonably."""
    for k in ("architectural_theme", "rule_id"):
        v = (threat.get(k) or "").strip()
        if v:
            return v
    cwe = (threat.get("cwe") or "").strip() or "UNKNOWN-CWE"
    comp = (threat.get("component") or threat.get("component_id") or "").strip() or "any"
    return f"{cwe}@{comp}"


def _synthesize_architectural_investigate(
    data: dict, state: dict, threats_by_id: dict
) -> list[dict]:
    """ONE investigate card per architectural_theme cluster (volume control).
    Each card aggregates all T-NNNs in the cluster into its threat_ids."""
    clusters: dict[str, list[dict]] = {}
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        src = (t.get("source") or "").strip()
        if src not in _ARCH_SOURCES:
            continue
        # Skip if the threat already has an LLM-authored mitigation
        # (architectural findings sometimes come with a domain-level
        # recommendation already; we only auto-emit when none exists).
        if t.get("mitigations"):
            continue
        clusters.setdefault(_arch_theme_key(t), []).append(t)

    new_cards: list[dict] = []
    for theme, members in clusters.items():
        if not members:
            continue
        # Title: use the first member's title as the descriptor, prefixed
        # with the architectural marker. Strip the (file) suffix so the
        # title reads as a class.
        descriptor = _short_weakness(members[0].get("title") or theme)
        component = (
            members[0].get("component")
            or members[0].get("component_id")
            or "the affected component"
        )
        mid = _allocate_next_m_id(state)
        tids = sorted({(t.get("id") or "").strip() for t in members if t.get("id")})
        how = (
            f"This is an architectural / coverage-gap finding — the analyser "
            f"inferred {descriptor!r} from architectural reasoning, not from "
            f"a confirmed source-to-sink path. Schedule a focused review of "
            f"{component} to validate the assumption: read the relevant "
            f"control implementation, sample 2–3 representative call paths, "
            f"and decide whether to convert the finding into a concrete "
            f"defect (with file:line evidence) or accept the residual risk. "
            f"This single review card covers {len(members)} clustered "
            f"finding(s) under the same theme to avoid §9 inflation."
        )
        new_cards.append({
            "id": mid,
            "title": f"Architecture review: validate {descriptor} in {component}",
            "kind": "investigate",
            "priority": "P2",
            "threat_ids": tids,
            "how": how,
            "review_target": component,
            "review_reason": f"source ∈ {{architectural-anti-pattern, coverage-gap}}; theme={theme}",
            "auto_emitted": True,
            "auto_source": "architectural-theme-cluster",
        })
        for tid in tids:
            _link_threat_to_mitigation(threats_by_id, tid, mid)
    return new_cards


# ---------------------------------------------------------------------------
# M-20: affected_parameter PoC hint
# ---------------------------------------------------------------------------

_CWE_TO_POC_TEMPLATE: dict[str, str] = {
    "CWE-89": "{method} {route} with {{{param}: \"' OR 1=1--\"}}  (SQL injection)",
    "CWE-90": "{method} {route} with {{{param}: \"*)(uid=*)\"}}  (LDAP injection)",
    "CWE-78": "{method} {route} with {{{param}: \"; id\"}}  (OS command injection)",
    "CWE-79": "{method} {route} with {{{param}: \"<svg onload=alert(1)>\"}}  (XSS payload)",
    "CWE-91": "{method} {route} with {{{param}: \"<![CDATA[<script>...</script>]]>\"}}  (XML injection)",
    "CWE-94": "{method} {route} with {{{param}: \"require('child_process').exec('id')\"}}  (code injection)",
    "CWE-95": "{method} {route} with {{{param}: \"{{constructor.constructor('return process')()}}\"}}  (template injection)",
    "CWE-611": "{method} {route} with body containing <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\"]>  (XXE)",
    "CWE-639": "{method} {route} with {{{param}: <other-user-id>}}  (IDOR)",
    "CWE-918": "{method} {route} with {{{param}: \"http://169.254.169.254/latest/meta-data/\"}}  (SSRF)",
    "CWE-601": "{method} {route} with {{{param}: \"//evil.example.com\"}}  (open redirect)",
    "CWE-943": "{method} {route} with {{{param}: {{\"$gt\": \"\"}}}}  (NoSQL injection)",
}


def _synthesize_poc_hints(data: dict, threats_by_id: dict) -> int:
    """Append a `poc_hint` field to threats whose affected_parameter is set
    AND whose CWE is in the injection allowlist. Does NOT create new M-NNN
    cards — the hint is appended to the threat itself so the composer can
    render it under §8 Threat Register without inflating §9.

    Returns the number of threats annotated.
    """
    count = 0
    for t in data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        param = (t.get("affected_parameter") or "").strip()
        if not param:
            continue
        cwe = (t.get("cwe") or "").strip()
        if cwe not in _INJECTION_CWES:
            continue
        # Skip when the threat already carries a manual PoC hint.
        if (t.get("poc_hint") or "").strip():
            continue
        # Synthesize PoC from CWE template + extracted route.
        route = _extract_route_for_threat(t)
        method = _extract_method_for_threat(t)
        template = _CWE_TO_POC_TEMPLATE.get(cwe, "{method} {route} with {{{param}: <payload>}}")
        hint = template.format(method=method, route=route, param=param)
        t["poc_hint"] = hint
        count += 1
    return count


def _extract_route_for_threat(threat: dict) -> str:
    """Best-effort route extraction from evidence.file or attack_surface
    cross-reference. Falls back to the file path itself."""
    f, _ = _evidence_file(threat)
    if "/" in f:
        # `routes/login.ts` → `/<inferred>` (heuristic; users will refine)
        base = f.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        return f"/{base.lower()}"
    return f"/<endpoint>"


def _extract_method_for_threat(threat: dict) -> str:
    """Heuristic: derive HTTP method from common keywords in title/scenario."""
    text = f"{threat.get('title','')} {threat.get('scenario','')}".lower()
    for verb in ("POST", "PUT", "DELETE", "PATCH", "GET"):
        if verb.lower() in text:
            return verb
    return "POST"


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: emit_review_mitigations.py <output_dir>", file=sys.stderr)
        return 2
    output_dir = Path(argv[0])
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"emit_review_mitigations: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(
            f"emit_review_mitigations: could not parse {yaml_path}: {exc}",
            file=sys.stderr,
        )
        return 1
    if not isinstance(data, dict):
        print("emit_review_mitigations: yaml did not parse to a mapping", file=sys.stderr)
        return 1

    # Idempotent re-run: drop prior auto_emitted entries first.
    _clear_prior_auto_mitigations(data)

    threats_by_id = {
        (t.get("id") or "").strip(): t
        for t in (data.get("threats") or [])
        if isinstance(t, dict) and t.get("id")
    }

    state = {"counter": _scan_max_m_id(data)}

    new_cards: list[dict] = []
    new_cards.extend(_synthesize_evidence_review(data, state, threats_by_id))
    new_cards.extend(_synthesize_architectural_investigate(data, state, threats_by_id))
    poc_count = _synthesize_poc_hints(data, threats_by_id)

    if new_cards:
        existing = data.get("mitigations") or []
        if not isinstance(existing, list):
            existing = []
        data["mitigations"] = existing + new_cards

    yaml_path.write_text(
        yaml.safe_dump(
            data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False
        ),
        encoding="utf-8",
    )

    print(
        f"emit_review_mitigations: appended {len(new_cards)} auto-mitigation(s) "
        f"({sum(1 for c in new_cards if c['kind'] == 'review')} review · "
        f"{sum(1 for c in new_cards if c['kind'] == 'investigate')} investigate); "
        f"annotated {poc_count} threat(s) with poc_hint"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
