#!/usr/bin/env python3
"""Validate the minimum developer-actionability bar for P1/P2 fix cards.

This runs after mitigation-detail hydration, immediately before rendering.
Every code example must identify its source file. For urgent implementation
work, a valid P1/P2 fix also has at least two ordered steps and a concrete
post-change verification instruction. Review/investigate cards are notes, not
implementation plans.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

_URGENT = {"P1", "P2"}
_NON_FIX_KINDS = {"review", "investigate", "accept_risk"}


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def validate(data: dict) -> list[str]:
    """Return human-actionable errors for P1/P2 fix-card gaps."""
    errors: list[str] = []
    for mitigation in data.get("mitigations") or []:
        if not isinstance(mitigation, dict):
            continue
        priority = _text(mitigation.get("priority")).upper()
        kind = _text(mitigation.get("kind")).lower()
        if kind in _NON_FIX_KINDS:
            continue
        mid = _text(mitigation.get("id") or mitigation.get("m_id")) or "<unknown mitigation>"
        has_code = bool(_text(mitigation.get("how_code")) or _text(mitigation.get("code_example")))
        has_location = bool(_text(mitigation.get("file") or mitigation.get("location")))
        if has_code and not has_location:
            errors.append(f"{mid}: fix with a code example needs a source file location for the example introduction")
        if priority not in _URGENT:
            continue
        steps = mitigation.get("steps")
        step_count = sum(1 for step in steps if _text(step)) if isinstance(steps, list) else 0
        if step_count < 2:
            errors.append(f"{mid}: {priority} fix needs at least two concrete remediation steps (found {step_count})")
        verification = _text(mitigation.get("verification"))
        if not verification:
            errors.append(
                f"{mid}: {priority} fix needs a concrete verification (test, request + expected response, CI assertion, or config check)"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: validate_mitigation_quality.py <output-dir>", file=sys.stderr)
        return 2
    yaml_path = Path(args[0]) / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"INVALID: no threat-model.yaml in {args[0]}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"INVALID: unreadable threat-model.yaml: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print("INVALID: threat-model.yaml root must be a mapping", file=sys.stderr)
        return 1
    errors = validate(data)
    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    print("VALID: P1/P2 mitigation cards include steps and verification")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
