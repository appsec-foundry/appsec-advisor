#!/usr/bin/env python3
"""
qa_arch_coverage.py — completeness gate for architecture-coverage delivery.

Per arch.md §Pipeline-Integration Punkt 7: an applicable rule with status
{partial, weak, missing, anti_pattern} in .architecture-coverage.json MUST
be visible in at least one of:

  * threat-model.yaml#security_controls[]                — Section 7 control row
  * threat-model.yaml#threat_hypotheses[]                — Section 7.2 hypothesis
  * .threats-merged.json#threats[] with source in
    {architecture-coverage, threat-hypothesis} and matching rule_id
                                                         — Section 8 register

`present` and `not_applicable` rules are audit-only — they may render but
are not required to.

Also enforces honest semantics:

  * Threats with source in {architecture-coverage, threat-hypothesis}
    MUST NOT carry a CVSS vector.
  * Such threats MUST NOT have effective_severity / risk == "Critical".
  * Hypothesis entries (Section 7.2) MUST NOT carry CVSS or Critical risk.

CLI:
    python3 scripts/qa_arch_coverage.py <output-dir>
    python3 scripts/qa_arch_coverage.py <output-dir> --json

Exit codes:
  0 — no issues found
  1 — completeness or semantic violations
  2 — input artifacts missing or unparseable
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("qa_arch_coverage.py: PyYAML is required", file=sys.stderr)
    sys.exit(2)


_REQUIRES_DOWNSTREAM = {"partial", "weak", "missing", "anti_pattern"}
_ARCH_SOURCES = {"architecture-coverage", "threat-hypothesis"}


# ---------------------------------------------------------------------------
# Visibility check
# ---------------------------------------------------------------------------


def _rule_ids_in_security_controls(threat_model: dict) -> set[str]:
    """A control assessment is wired into security_controls[] via the
    bridge in Phase 8 (pregenerate_fragments). The control may carry the
    rule_id directly or reference it via notes/architectural_control.

    We accept any of: explicit rule_id field, references to ARCH-* in
    notes/architectural_control/control/gap text. A precise wiring is
    preferred and is checked first.
    """
    ids: set[str] = set()
    for c in threat_model.get("security_controls") or []:
        if not isinstance(c, dict):
            continue
        for key in ("rule_id", "architectural_control"):
            v = c.get(key)
            if isinstance(v, str) and v.startswith("ARCH-"):
                ids.add(v)
        for key in ("notes", "control", "gap", "implementation"):
            v = c.get(key)
            if isinstance(v, str):
                for token in v.split():
                    token = token.strip(",.;:()[]")
                    if token.startswith("ARCH-") and token.count("-") >= 2:
                        ids.add(token)
    return ids


def _rule_ids_in_threat_hypotheses(threat_model: dict) -> set[str]:
    ids: set[str] = set()
    for h in threat_model.get("threat_hypotheses") or []:
        if not isinstance(h, dict):
            continue
        v = h.get("rule_id")
        if isinstance(v, str) and v.startswith("ARCH-"):
            ids.add(v)
    return ids


def _rule_ids_in_threats_merged(threats_merged: dict) -> set[str]:
    ids: set[str] = set()
    for t in threats_merged.get("threats") or []:
        if not isinstance(t, dict):
            continue
        if t.get("source") not in _ARCH_SOURCES:
            continue
        v = t.get("rule_id")
        if isinstance(v, str) and v.startswith("ARCH-"):
            ids.add(v)
    return ids


def check_completeness(
    coverage: dict,
    threat_model: dict | None,
    threats_merged: dict | None,
) -> list[dict]:
    """Returns a list of {rule_id, status, reason} issues."""
    issues: list[dict] = []
    tm = threat_model or {}
    tm_merged = threats_merged or {}

    visible = (
        _rule_ids_in_security_controls(tm)
        | _rule_ids_in_threat_hypotheses(tm)
        | _rule_ids_in_threats_merged(tm_merged)
    )

    for rule in coverage.get("rules_evaluated") or []:
        if not isinstance(rule, dict):
            continue
        if not rule.get("applies"):
            continue
        status = rule.get("status")
        if status not in _REQUIRES_DOWNSTREAM:
            continue
        rule_id = rule.get("rule_id")
        if not isinstance(rule_id, str):
            continue
        if rule_id in visible:
            continue
        issues.append({
            "rule_id": rule_id,
            "status": status,
            "kind": "invisible_downstream",
            "reason": (
                f"rule {rule_id} (status={status}) is applicable in "
                f".architecture-coverage.json but appears in none of "
                f"security_controls[], threat_hypotheses[], or threats[]"
            ),
        })
    return issues


# ---------------------------------------------------------------------------
# Semantic guards (CVSS / Critical)
# ---------------------------------------------------------------------------


def check_semantics(
    threat_model: dict | None,
    threats_merged: dict | None,
) -> list[dict]:
    issues: list[dict] = []
    tm = threat_model or {}
    tm_merged = threats_merged or {}

    for i, t in enumerate(tm_merged.get("threats") or []):
        if not isinstance(t, dict):
            continue
        if t.get("source") not in _ARCH_SOURCES:
            continue
        if t.get("cvss_v4"):
            issues.append({
                "kind": "cvss_on_arch_source",
                "where": f"threats[{i}]",
                "reason": f"threat with source={t.get('source')} carries CVSS",
            })
        for fld in ("risk", "effective_severity", "severity"):
            if t.get(fld) == "Critical":
                issues.append({
                    "kind": "critical_on_arch_source",
                    "where": f"threats[{i}].{fld}",
                    "reason": (
                        f"threat with source={t.get('source')} is Critical "
                        f"(severity cap applies — promote via compound chain)"
                    ),
                })

    for i, h in enumerate(tm.get("threat_hypotheses") or []):
        if not isinstance(h, dict):
            continue
        if h.get("cvss_v4"):
            issues.append({
                "kind": "cvss_on_hypothesis",
                "where": f"threat_hypotheses[{i}]",
                "reason": "hypothesis carries CVSS (forbidden — design gap)",
            })
        for fld in ("risk", "effective_severity", "severity"):
            if h.get(fld) == "Critical":
                issues.append({
                    "kind": "critical_on_hypothesis",
                    "where": f"threat_hypotheses[{i}].{fld}",
                    "reason": "hypothesis is Critical (forbidden — unproven)",
                })
    return issues


# ---------------------------------------------------------------------------
# IO + CLI
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_yaml(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None


def run(output_dir: Path) -> tuple[list[dict], list[dict]]:
    coverage = _load_json(output_dir / ".architecture-coverage.json") or {}
    threat_model = _load_yaml(output_dir / "threat-model.yaml")
    threats_merged = _load_json(output_dir / ".threats-merged.json")
    completeness = check_completeness(coverage, threat_model, threats_merged)
    semantics = check_semantics(threat_model, threats_merged)
    return completeness, semantics


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="qa_arch_coverage.py", description=__doc__)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = p.parse_args(argv)

    if not args.output_dir.is_dir():
        print(f"qa_arch_coverage.py: output-dir not found: {args.output_dir}", file=sys.stderr)
        return 2

    coverage_path = args.output_dir / ".architecture-coverage.json"
    if not coverage_path.is_file():
        if args.json:
            json.dump({"skipped": True, "reason": "no .architecture-coverage.json"}, sys.stdout)
            sys.stdout.write("\n")
        else:
            print(f"qa_arch_coverage.py: SKIP (no .architecture-coverage.json at {coverage_path})")
        return 0

    completeness, semantics = run(args.output_dir)
    payload = {
        "completeness_issues": completeness,
        "semantic_issues": semantics,
        "total": len(completeness) + len(semantics),
    }
    if args.json:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        if not completeness and not semantics:
            print("qa_arch_coverage.py: OK (no completeness or semantic violations)")
        else:
            print(f"qa_arch_coverage.py: FAIL — {len(completeness)} completeness, {len(semantics)} semantic issues")
            for issue in completeness:
                print(f"  [{issue['kind']}] {issue['reason']}")
            for issue in semantics:
                print(f"  [{issue['kind']}] {issue['reason']}")
    return 0 if payload["total"] == 0 else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
