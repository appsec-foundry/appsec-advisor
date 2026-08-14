"""Compatibility reads for canonical and legacy threat-model finding fields.

The final output contract uses ``risk``, optional ``_status``, and an evidence
array. Older related repositories used ``severity``, ``status``, and a single
evidence object. Cross-repository consumers share these reads so compatibility
cannot drift independently from the current producer.
"""

from __future__ import annotations

from typing import Any


def extract_threats(model: dict[str, Any]) -> list[dict[str, Any]]:
    """Return findings from the current flat shape or the legacy category shape."""
    if isinstance(model.get("threats"), list):
        return [row for row in model["threats"] if isinstance(row, dict)]
    findings: list[dict[str, Any]] = []
    for category in model.get("threat_categories", []) or []:
        if not isinstance(category, dict):
            continue
        findings.extend(row for row in category.get("findings", []) or [] if isinstance(row, dict))
    return findings


def severity_of(threat: dict[str, Any]) -> str:
    """Return the canonical title-cased effective severity, with legacy fallback."""
    value = threat.get("effective_severity") or threat.get("risk") or threat.get("severity") or ""
    return str(value).strip().title()


def is_active(threat: dict[str, Any]) -> bool:
    """Interpret current lifecycle state first, then the legacy status field."""
    if "_status" in threat:
        return threat.get("_status") in (None, "active")
    legacy = str(threat.get("status", "open")).strip().lower()
    return legacy in ("", "open", "active")


def evidence_file_of(threat: dict[str, Any]) -> str | None:
    """Return the first evidence file from current or legacy evidence shapes."""
    evidence = threat.get("evidence")
    if isinstance(evidence, list):
        for row in evidence:
            if isinstance(row, dict) and isinstance(row.get("file"), str):
                return row["file"]
    elif isinstance(evidence, dict) and isinstance(evidence.get("file"), str):
        return evidence["file"]
    legacy = threat.get("evidence_file")
    return legacy if isinstance(legacy, str) else None
