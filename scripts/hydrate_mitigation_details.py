#!/usr/bin/env python3
"""Promote actionable remediation detail from findings onto mitigation cards.

The Stage-1 analyzer owns code-aware remediation.  A mitigation can address one
or more findings, but the merger historically retained only its title and IDs;
the Markdown renderer then performed a report-only fallback.  This helper makes
the canonical YAML useful to every downstream consumer by filling a fix card's
    missing steps, code example, verification, reference, and source location
    from its addressed findings. Authored mitigation fields always win.

Linkage is resolved in BOTH directions (2026-07-15). A card's addressed threats
are the union of its own forward link (``threat_ids``/``addresses``) and every
threat that references the card via the canonical reverse link
``threats[].mitigation_ids``. ``prune_dangling_mitigation_threat_ids`` can empty
a card's forward link when the LLM authored a dangling ``threat_ids`` (the
``M-901→T-034`` hallucination class) while a real threat still points at the
card in reverse; forward-only hydration stranded that card with zero steps and
tripped the P1/P2 quality gate. Reverse-link rescue re-attaches the real
remediation.

A ``kind: fix`` card left with NO resolvable link in either direction AND no
authored steps/code is content-free noise that can never satisfy the gate. Such
orphans are dropped here so the gate only
ever sees fix cards that address a real threat or already carry steps — matching
the gate's "repair the producer, never ship a vague recommendation" contract.
Both this reverse-link rescue and the orphan drop run on the normal skill path
and the thin-runtime recovery path, since both invoke this helper before the
gate.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

_NON_FIX_KINDS = {"review", "investigate", "accept_risk"}
_DETAIL_FIELDS = ("code_example", "verification", "reference")
# Fields that, if present, keep an unlinked fix card actionable enough to survive
# the orphan drop (mirrors the P1/P2 gate's own code/step signals).
_CONTENT_FIELDS = ("how", "how_code", "code_example")


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _mid(mitigation: dict) -> str:
    return _text(mitigation.get("id") or mitigation.get("m_id")).upper()


def _is_fix(mitigation: dict) -> bool:
    return _text(mitigation.get("kind")).lower() not in _NON_FIX_KINDS


def _reverse_index(data: dict, threats: dict) -> dict[str, list[dict]]:
    """Map card-id → threats that reference it via ``threats[].mitigation_ids``."""
    reverse: dict[str, list[dict]] = {}
    for threat in threats.values():
        for mid in threat.get("mitigation_ids") or []:
            key = _text(mid).upper()
            if key:
                reverse.setdefault(key, []).append(threat)
    return reverse


def _addressed_threats(mitigation: dict, threats: dict, reverse: dict[str, list[dict]]) -> list[dict]:
    """Threats a card addresses: forward link ∪ reverse referrers, deduped by id."""
    resolved: list[dict] = []
    seen: set[int] = set()
    forward = mitigation.get("threat_ids") or mitigation.get("addresses") or []
    for threat_id in forward:
        threat = threats.get(_text(threat_id).upper())
        if isinstance(threat, dict) and id(threat) not in seen:
            resolved.append(threat)
            seen.add(id(threat))
    for threat in reverse.get(_mid(mitigation), []):
        if id(threat) not in seen:
            resolved.append(threat)
            seen.add(id(threat))
    return resolved


def hydrate(data: dict) -> int:
    """Fill missing fix-card detail from addressed threats; return cards changed."""
    threats = {
        _text(threat.get("id") or threat.get("t_id")).upper(): threat
        for threat in data.get("threats") or []
        if isinstance(threat, dict) and _text(threat.get("id") or threat.get("t_id"))
    }
    reverse = _reverse_index(data, threats)
    changed = 0
    for mitigation in data.get("mitigations") or []:
        if not isinstance(mitigation, dict) or not _is_fix(mitigation):
            continue
        source_threats = _addressed_threats(mitigation, threats, reverse)
        source_rems = [
            threat["remediation"] for threat in source_threats if isinstance(threat.get("remediation"), dict)
        ]
        if not source_rems:
            continue

        card_changed = False
        # Backfill the forward link when prune emptied it but a real threat still
        # points at the card in reverse — so §8/§10 cross-references (compose
        # reads threat_ids/addresses) show the addressed threats, not nothing.
        if not (mitigation.get("threat_ids") or mitigation.get("addresses")):
            recovered = [_text(t.get("id") or t.get("t_id")) for t in source_threats]
            recovered = [tid for tid in recovered if tid]
            if recovered:
                mitigation["threat_ids"] = recovered
                mitigation.pop("addresses", None)
                card_changed = True
        existing_steps = mitigation.get("steps")
        if not isinstance(existing_steps, list):
            existing_steps = []
        merged_steps = [step.strip() for step in existing_steps if _text(step)]
        seen_steps = set(merged_steps)
        for remediation in source_rems:
            for step in remediation.get("steps") or []:
                clean = _text(step)
                if clean and clean not in seen_steps:
                    merged_steps.append(clean)
                    seen_steps.add(clean)
        if merged_steps != existing_steps and merged_steps:
            mitigation["steps"] = merged_steps
            card_changed = True

        for field in _DETAIL_FIELDS:
            if _text(mitigation.get(field)):
                continue
            value = next(
                (_text(remediation.get(field)) for remediation in source_rems if _text(remediation.get(field))), ""
            )
            if value:
                mitigation[field] = value
                card_changed = True
        if not _text(mitigation.get("file") or mitigation.get("location")):
            for threat in source_threats:
                evidence = threat.get("evidence") or []
                if isinstance(evidence, dict):
                    evidence = [evidence]
                if not isinstance(evidence, list) or not evidence or not isinstance(evidence[0], dict):
                    continue
                source_file = _text(evidence[0].get("file"))
                source_line = evidence[0].get("line")
                if source_file:
                    mitigation["file"] = f"{source_file}:{source_line}" if source_line is not None else source_file
                    card_changed = True
                    break
        if card_changed:
            changed += 1

    changed += _drop_orphan_fix_cards(data, threats, reverse)
    return changed


def _drop_orphan_fix_cards(data: dict, threats: dict, reverse: dict[str, list[dict]]) -> int:
    """Remove content-free ``kind: fix`` cards that address no threat at all.

    A fix card with no forward link, no reverse referrer, and no authored
    steps/code instructs nothing and covers nothing — it can never satisfy the
    P1/P2 quality gate and hydration has no source to draw from. Dropping it keeps
    the gate honest without hand-patching a vague card into the report. (No
    back-reference cleanup is needed: an orphan has no reverse referrer by
    definition, so no ``threats[].mitigation_ids`` points at it.) Review/
    investigate/accept-risk cards are notes and are left untouched.
    """
    mitigations = data.get("mitigations")
    if not isinstance(mitigations, list):
        return 0
    survivors: list = []
    dropped = 0
    for mitigation in mitigations:
        if not isinstance(mitigation, dict) or not _is_fix(mitigation):
            survivors.append(mitigation)
            continue
        has_link = bool(_addressed_threats(mitigation, threats, reverse))
        has_steps = isinstance(mitigation.get("steps"), list) and any(_text(step) for step in mitigation["steps"])
        has_content = any(_text(mitigation.get(field)) for field in _CONTENT_FIELDS)
        if not has_link and not has_steps and not has_content and _mid(mitigation):
            dropped += 1
            continue
        survivors.append(mitigation)
    if dropped:
        data["mitigations"] = survivors
    return dropped


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: hydrate_mitigation_details.py <output-dir>", file=sys.stderr)
        return 2
    yaml_path = Path(args[0]) / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"hydrate_mitigation_details: no {yaml_path} — skipping", file=sys.stderr)
        return 0
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"hydrate_mitigation_details: failed to load yaml: {exc}", file=sys.stderr)
        return 0
    if not isinstance(data, dict):
        print("hydrate_mitigation_details: yaml root is not a mapping — skipping", file=sys.stderr)
        return 0
    count = hydrate(data)
    if count:
        yaml_path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096), encoding="utf-8")
    print(f"hydrate_mitigation_details: hydrated {count} mitigation card(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
