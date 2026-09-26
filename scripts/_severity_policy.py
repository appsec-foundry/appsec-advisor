"""Shared policy ceilings for individual risk and effective severity.

Merge and YAML construction normalize individual risk before consumers derive
registers, counts and exports. Triage alone adds contextual elevation. Validation
checks the same ceilings without repairing its input.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@lru_cache(maxsize=1)
def load_policy() -> tuple[dict, dict]:
    """Required plugin policy must be readable; never silently drop ceilings."""
    documents = []
    for filename, key in (
        ("severity-caps.yaml", "severity_caps"),
        ("critical-criteria.yaml", "never_individual_critical"),
    ):
        document = yaml.safe_load((DATA_DIR / filename).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or key not in document:
            raise ValueError(f"Invalid severity policy: {filename}")
        documents.append(document)
    return documents[0], documents[1]


def finding_cwe(finding: dict) -> str:
    value = finding.get("primary_cwe") or finding.get("cwe")
    if not value:
        values = finding.get("cwes") or []
        value = values[0] if values else ""
        if isinstance(value, dict):
            value = value.get("id")
    return str(value or "").strip().upper()


def companion_cwes(finding: dict, findings: list[dict]) -> set[str]:
    """Only other, non-refuted findings in the same explicit category count."""
    category = finding.get("threat_category_id")
    if not category:
        return set()
    return {
        finding_cwe(other)
        for other in findings
        if other is not finding
        and other.get("threat_category_id") == category
        and other.get("evidence_check") not in ("refuted", "ambiguous")
    }


def cwe_ceiling(cwe: str, caps: dict, companions: set[str] | None = None) -> str:
    ceiling = (caps.get("severity_caps") or {}).get(cwe, {}).get("max", "Critical")
    for exception in (caps.get("cap_exceptions") or {}).get(cwe, []):
        required = set(exception.get("requires_compound_with") or [])
        if required and required <= (companions or set()):
            ceiling = max((ceiling, exception["elevated_cap"]), key=RANK.__getitem__)
    return ceiling


def individual_critical_ceiling(cwe: str, criteria: dict) -> str:
    for entry in criteria.get("never_individual_critical") or []:
        # Historical callers supplied bare CWEs; shipped policy uses objects.
        if isinstance(entry, str) and entry.upper() == cwe:
            return criteria.get("max_severity_individual", "High")
        if isinstance(entry, dict) and entry.get("cwe", "").upper() == cwe:
            return entry["max_severity_individual"]
    return "Critical"


def individual_risk(finding: dict, caps: dict, criteria: dict, companions: set[str] | None = None) -> str:
    risk = finding.get("risk") or finding.get("severity") or ""
    if not isinstance(risk, str) or risk not in RANK:
        return risk
    cwe = finding_cwe(finding)
    ceilings = [risk, cwe_ceiling(cwe, caps, companions), individual_critical_ceiling(cwe, criteria)]
    return min(ceilings, key=RANK.__getitem__)


def normalize_risks(findings: list[dict]) -> None:
    """Apply ceilings in place, retaining the original judgement for audit."""
    caps, criteria = load_policy()
    for finding in findings:
        risk = finding.get("risk") or finding.get("severity") or ""
        corrected = individual_risk(finding, caps, criteria, companion_cwes(finding, findings))
        if corrected != risk:
            finding.setdefault("risk_before_policy", risk)
            finding["risk"] = corrected


def abuse_case_priority(findings: list[dict]) -> tuple[int, int, int, int]:
    """Order scenarios by their strongest policy-rated finding, without a bonus.

    Lower keys come first. Equal risks use that finding's assessed breach
    distance, impact and likelihood. Missing assessments sort last; template
    titles, case IDs and previously elevated effective severity do not rate a
    scenario. Callers supply only the findings bound to the case, with risk
    already normalized against the complete register. Reapplying ceilings to
    this subset could lose a valid companion-CWE exception.
    """
    ranks = {"Informational": -1, **RANK}
    keys = []
    for finding in findings:
        if finding.get("evidence_check") == "refuted":
            continue
        risk = finding.get("risk") or finding.get("severity")
        if risk not in ranks:
            continue
        distance = finding.get("breach_distance")
        if type(distance) is not int or not 0 <= distance <= 4:
            distance = 5
        keys.append(
            (
                -ranks[risk],
                distance,
                -ranks.get(finding.get("impact"), -2),
                -ranks.get(finding.get("likelihood"), -2),
            )
        )
    return min(keys, default=(2, 5, 2, 2))


def abuse_case_risk(findings: list[dict], *, fallback: str = "High") -> str:
    """Use the highest individual risk; verifying a path adds no severity."""
    labels = {-1: "Informational", **{rank: label for label, rank in RANK.items()}}
    return labels.get(-abuse_case_priority(findings)[0], fallback)


def policy_errors(findings: list[dict]) -> list[str]:
    """Reject policy violations at artifact gates; never mutate findings."""
    caps, criteria = load_policy()
    errors = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        companions = companion_cwes(finding, [item for item in findings if isinstance(item, dict)])
        expected = individual_risk(finding, caps, criteria, companions)
        risk = finding.get("risk") or finding.get("severity") or ""
        if expected != risk:
            errors.append(f"threats[{index}].risk exceeds policy ceiling {expected}")
        original = finding.get("risk_before_policy")
        if isinstance(original, str) and original in RANK:
            corrected = individual_risk(dict(finding, risk=original), caps, criteria, companions)
            if corrected != risk or original == risk:
                errors.append(f"threats[{index}].risk_before_policy does not explain a policy correction")
        effective = finding.get("effective_severity")
        ceiling = cwe_ceiling(finding_cwe(finding), caps, companions)
        if isinstance(effective, str) and effective in RANK and RANK[effective] > RANK[ceiling]:
            errors.append(f"threats[{index}].effective_severity exceeds policy ceiling {ceiling}")
    return errors
