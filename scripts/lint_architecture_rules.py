#!/usr/bin/env python3
"""lint_architecture_rules.py — bugs2 Bug 7 — CI guard on
``data/architecture-coverage-rules.yaml``.

Every architecture-coverage rule (hard or hypothesis) MUST carry six
reviewer-facing fields so a human can reason about its semantics:

  * ``review_intent``      — what security problem the rule detects
  * ``finding_when``       — 1–3 concrete conditions that mean a T-NNN
  * ``not_a_finding_when`` — false-positive carve-outs
  * ``required_evidence``  — what file:line / signal must be visible
  * ``severity_reason``    — why the cap is set where it is
  * ``reviewer_note``      — pre-default-activation human check

This script:

  1. Parses the YAML.
  2. For each rule under ``hard_rules`` and ``hypothesis_rules``, checks
     all six fields are present AND non-empty.
  3. Exits 0 when every rule complies, 1 on any violation.

Usage:
    python3 lint_architecture_rules.py
    python3 lint_architecture_rules.py --rules-yaml <path>

CI: wire as a pre-commit or a job in the test workflow.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("lint_architecture_rules: PyYAML is required", file=sys.stderr)
    sys.exit(2)


_REQUIRED_FIELDS = (
    "review_intent",
    "finding_when",
    "not_a_finding_when",
    "required_evidence",
    "severity_reason",
    "reviewer_note",
)

_HERE = Path(__file__).resolve().parent
_DEFAULT_RULES_YAML = _HERE.parent / "data" / "architecture-coverage-rules.yaml"


def _check_rule(rule: dict, family: str) -> list[str]:
    rule_id = rule.get("id") or "<no-id>"
    errors: list[str] = []
    for field in _REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"{rule_id} ({family}): missing reviewer field `{field}`")
            continue
        value = rule[field]
        # finding_when / not_a_finding_when are lists; the others are scalars.
        if field in ("finding_when", "not_a_finding_when"):
            if not isinstance(value, list) or not value:
                errors.append(f"{rule_id} ({family}): `{field}` must be a non-empty list")
            else:
                for i, entry in enumerate(value):
                    if not isinstance(entry, str) or not entry.strip():
                        errors.append(f"{rule_id} ({family}): `{field}[{i}]` must be a non-empty string")
        else:
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{rule_id} ({family}): `{field}` must be a non-empty string")
    return errors


def lint(rules_yaml: Path) -> tuple[int, list[str]]:
    if not rules_yaml.is_file():
        return 2, [f"rules-yaml not found: {rules_yaml}"]
    try:
        data = yaml.safe_load(rules_yaml.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return 2, [f"yaml parse error: {exc}"]

    errors: list[str] = []
    hard = data.get("hard_rules") or []
    hyp = data.get("hypothesis_rules") or []
    if not isinstance(hard, list):
        errors.append("hard_rules: must be a list")
        hard = []
    if not isinstance(hyp, list):
        errors.append("hypothesis_rules: must be a list")
        hyp = []
    for r in hard:
        if isinstance(r, dict):
            errors.extend(_check_rule(r, "hard"))
    for r in hyp:
        if isinstance(r, dict):
            errors.extend(_check_rule(r, "hypothesis"))

    return (0 if not errors else 1), errors


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="lint_architecture_rules",
                                description="Enforce reviewer-field contract on ARCH rules.")
    p.add_argument("--rules-yaml", default=str(_DEFAULT_RULES_YAML),
                   help=f"Path to architecture-coverage-rules.yaml "
                        f"(default: {_DEFAULT_RULES_YAML}).")
    args = p.parse_args(argv)
    rc, errors = lint(Path(args.rules_yaml))
    if rc == 0:
        print(f"lint_architecture_rules: OK ({Path(args.rules_yaml).name})")
        return 0
    for e in errors:
        print(f"  ✗ {e}")
    print(f"lint_architecture_rules: {len(errors)} violation(s)", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
