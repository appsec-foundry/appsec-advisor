#!/usr/bin/env python3
"""Promote actionable remediation detail from findings onto mitigation cards.

The Stage-1 analyzer owns code-aware remediation.  A mitigation can address one
or more findings, but the merger historically retained only its title and IDs;
the Markdown renderer then performed a report-only fallback.  This helper makes
the canonical YAML useful to every downstream consumer by filling a fix card's
    missing steps, code example, verification, reference, and source location
    from its addressed findings. Authored mitigation fields always win.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

_NON_FIX_KINDS = {"review", "investigate", "accept_risk"}
_DETAIL_FIELDS = ("code_example", "verification", "reference")


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _is_fix(mitigation: dict) -> bool:
    return _text(mitigation.get("kind")).lower() not in _NON_FIX_KINDS


def hydrate(data: dict) -> int:
    """Fill missing fix-card detail from addressed threats; return cards changed."""
    threats = {
        _text(threat.get("id") or threat.get("t_id")).upper(): threat
        for threat in data.get("threats") or []
        if isinstance(threat, dict) and _text(threat.get("id") or threat.get("t_id"))
    }
    changed = 0
    for mitigation in data.get("mitigations") or []:
        if not isinstance(mitigation, dict) or not _is_fix(mitigation):
            continue
        addressed = mitigation.get("threat_ids") or mitigation.get("addresses") or []
        source_threats = []
        source_rems = []
        for threat_id in addressed:
            threat = threats.get(_text(threat_id).upper())
            if isinstance(threat, dict):
                source_threats.append(threat)
            remediation = threat.get("remediation") if isinstance(threat, dict) else None
            if isinstance(remediation, dict):
                source_rems.append(remediation)
        if not source_rems:
            continue

        card_changed = False
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
    return changed


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
