#!/usr/bin/env python3
"""Single source for the finding-severity tally and the finding display id.

Two surfaces present the same model to the same reader and must agree:

* ``compose_threat_model.py`` renders the Management-Summary
  ``**Risk distribution:**`` line and the §8 Findings Register.
* ``summarize_threat_model.py`` prints the ``show-threat-model`` overview.

They did not agree. The overview ranked findings by ``effective_severity`` —
the post-triage rating that carries abuse-chain elevation — while the report
buckets its finding inventory on ``risk``. On a 2026-07 juice-shop run the
overview reported 27 Critical against 15 in §8 and 14 in the Management
Summary, and promoted a Medium CI/CD finding into "Top Critical". The rules
therefore live here, in one place, and both callers use them.

Three tallies exist in the model and they are deliberately different:

``risk``
    Per-finding severity as rated. The §8 Findings Register buckets on this.

``effective_severity``
    ``risk`` plus abuse-chain elevation. Drives §9 and the mitigation
    ranking. It is NOT a finding-inventory basis — using it double-counts the
    chain view into the per-finding view.

Management-Summary basis
    ``risk``, minus ``insecure-practice`` sites folded into the weakness
    register, plus each ``design-risk`` weakness once at its heading severity
    (it has no confirmed instance in ``threats[]`` and would otherwise be
    invisible). This is what :func:`risk_distribution_counts` computes and
    what the report leads with.
"""

from __future__ import annotations

# Display order for the canonical severity labels.
SEVERITY_ORDER: dict[str, int] = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

# Keys of the Management-Summary risk distribution, in display order.
DISTRIBUTION_KEYS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Design-level sources carry no evidence tier and are represented by their
# `design` weakness heading, so they must not inflate the confirmed tally.
# Keep in sync with _shared_sources.DESIGN_LEVEL_SOURCES.
_DESIGN_LEVEL_SOURCES = frozenset(
    {
        "requirements-compliance",
        "known-threats",
        "architecture-coverage",
        "threat-hypothesis",
        "architectural-anti-pattern",
        "coverage-gap",
    }
)


def display_id(raw: str) -> str:
    """The id the reader actually sees in ``threat-model.md``.

    The composer rewrites the visible label of a yaml ``T-NNN`` to ``F-NNN``
    (``compose_threat_model._normalize_finding_label``); ``T-NNN`` survives
    only as a hidden HTML anchor. The one visible ``T-`` family in the report
    is ``AC-T-NNN`` — abuse cases, a different namespace — so a raw ``T-NNN``
    citation sends the reader either nowhere or to the wrong record. Other id
    classes (``M-``, ``C-``, ``W-``, ``AF-``, ``TH-``) pass through unchanged.
    """
    s = (raw or "").strip()
    if len(s) > 2 and s[0] in "Tt" and s[1] == "-" and s[2:].isdigit():
        return "F-" + s[2:]
    return s


def register_severity(threat: dict | None) -> str:
    """Canonical severity for one finding, on the §8 Findings Register basis.

    ``risk`` first, ``severity`` as the legacy fallback — deliberately NOT
    ``effective_severity``. Returns the title-cased canonical label, or the
    raw string when it is not one the model recognises.
    """
    if not threat:
        return ""
    raw = (threat.get("risk") or threat.get("severity") or "").strip()
    if not raw:
        return ""
    label = raw[:1].upper() + raw[1:].lower()
    return label if label in SEVERITY_ORDER else raw


def is_refuted(threat: dict | None) -> bool:
    """True when evidence verification refuted the finding.

    The §8 register drops these; they are not part of the delivered
    inventory.
    """
    if not threat:
        return False
    return (threat.get("evidence_check") or "").strip().lower() == "refuted"


def is_folded_practice(threat: dict | None) -> bool:
    """True when the finding is an ``insecure-practice`` site.

    Only meaningful together with :func:`practice_fold_active`: when the
    weakness register is populated these sites live under a weakness's
    ``practice_evidence`` and are not standalone findings.
    """
    if not threat:
        return False
    return (threat.get("evidence_tier") or "") == "insecure-practice"


def practice_fold_active(yaml_data: dict) -> bool:
    """True when the weakness register is populated, so practice sites fold."""
    return weakness_basis_breakdown(yaml_data) is not None


def weakness_basis_breakdown(yaml_data: dict) -> tuple[int, int, int, int] | None:
    """``(combined, confirmed, implementation, design)`` or ``None``.

    ``None`` when the model carries no weakness register — the fold rules do
    not apply then. ``confirmed`` counts evidence-backed findings only:
    folded practice sites, design-level sources and ambiguous/refuted
    evidence are excluded. ``implementation`` / ``design`` count W-records.
    The combined total is retained for callers that need an assessment count;
    it must never be labelled a finding count.
    """
    weaknesses = yaml_data.get("weaknesses") or []
    if not weaknesses:
        return None
    confirmed = sum(
        1
        for t in (yaml_data.get("threats") or [])
        if (t.get("evidence_tier") or "confirmed-exploitable") != "insecure-practice"
        and (t.get("source") or "").strip() not in _DESIGN_LEVEL_SOURCES
        # RC.P2a: unverifiable/refuted evidence is not "confirmed-exploitable".
        and (t.get("evidence_check") or "").strip() not in ("ambiguous", "refuted")
    )
    implementation = sum(1 for w in weaknesses if w.get("kind") == "implementation")
    design = sum(1 for w in weaknesses if w.get("kind") == "design")
    return (confirmed + implementation + design, confirmed, implementation, design)


def risk_distribution_counts(yaml_data: dict) -> dict[str, int]:
    """Severity tally for the Management-Summary Risk-distribution line.

    Folded insecure-practice sites are excluded (they live under a weakness's
    ``practice_evidence``, not as standalone findings). A ``design-risk``
    weakness is added once at its heading severity: it has NO confirmed
    instance in ``threats[]``, so a design-risk Critical (which may rank #1
    per §9.3) would otherwise be invisible here. ``confirmed`` weaknesses are
    already represented by their instances in ``threats[]`` and are NOT
    re-added (no double-count).
    """
    fold_practice = practice_fold_active(yaml_data)
    counts = {k: 0 for k in DISTRIBUTION_KEYS}
    for t in yaml_data.get("threats") or []:
        if fold_practice and is_folded_practice(t):
            continue
        sev = (t.get("risk") or t.get("severity") or "").strip().lower()
        if sev in counts:
            counts[sev] += 1
        elif sev in ("informational", "information"):
            counts["info"] += 1
    if fold_practice:
        for w in yaml_data.get("weaknesses") or []:
            if (w.get("severity_basis") or "") != "design-risk":
                continue
            sev = (w.get("severity") or "").strip().lower()
            if sev in counts:
                counts[sev] += 1
    return counts


def register_threats(yaml_data: dict) -> list[dict]:
    """The findings the §8 Findings Register lists, in yaml order.

    Every non-refuted threat, including folded insecure-practice sites: the
    Management Summary leaves those out of its headline tally, but §8 still
    renders a card for each, so anything listed from here is something the
    reader can look up. Deliberately NOT the risk-distribution membership —
    filtering practice sites out of the list would silently drop real
    findings (a 2026-07 juice-shop run would have lost the Critical
    weak-password-hashing finding from "Top Critical").
    """
    return [t for t in (yaml_data.get("threats") or []) if isinstance(t, dict) and not is_refuted(t)]
