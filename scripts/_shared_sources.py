"""_shared_sources.py — single source of truth for ``threats[].source`` enums.

Before this module existed, the same source strings were hard-coded in nine
different scripts, and two inconsistent sets drifted in production
(bugs2 Bug 2 + plan3 RC.C):

  ``_ARCH_SOURCES`` in ``emit_review_mitigations.py`` and
  ``triage_validate_ratings.py`` held only the "legacy" pair
  ``{"architectural-anti-pattern", "coverage-gap"}``, while
  ``arch_coverage_to_threats.py`` (the bridge) emits the "bridge" pair
  ``{"architecture-coverage", "threat-hypothesis"}``. Result: M-17
  investigate-cluster cards never fired for any threat coming through the
  Phase-2.6 architecture-coverage engine, and triage flags missed the
  same set.

The fix is *not* to collapse the two pairs — they are intentionally
distinct per ``arch.md`` §"Threat-Hypothesis-Regeln":

  * ``architectural-anti-pattern`` / ``coverage-gap``
    Requirements/blueprint anti-patterns and recon coverage gaps,
    produced by ``phase-group-architecture.md`` (LLM path) and
    ``coverage_checks.py``.

  * ``architecture-coverage`` / ``threat-hypothesis``
    Phase-2.6 deterministic architecture-coverage engine output:
    heuristic anti-pattern candidates and confirmed threat hypotheses
    produced by ``architecture_coverage_checks.py`` +
    ``arch_coverage_to_threats.py``.

  * ``ARCH_ALL_SOURCES``
    Union — used by consumers that treat architectural findings uniformly
    regardless of provenance (e.g. the M-17 investigate-cluster in
    ``emit_review_mitigations.py``).

Kept in lock-step with ``schemas/threats-merged.schema.yaml`` and
``schemas/threat-model.output.schema.yaml``. When adding a new source
value, update this module first; consumers import these constants
rather than redeclaring them.
"""
from __future__ import annotations


# --- Architectural source families ------------------------------------------

ARCH_DESIGN_SOURCES: frozenset[str] = frozenset({
    "architectural-anti-pattern",
    "coverage-gap",
})
"""Requirements/blueprint anti-patterns + recon coverage gaps."""


ARCH_COVERAGE_SOURCES: frozenset[str] = frozenset({
    "architecture-coverage",
    "threat-hypothesis",
})
"""Phase-2.6 architecture-coverage engine + threat-hypothesis bridge output."""


ARCH_ALL_SOURCES: frozenset[str] = ARCH_DESIGN_SOURCES | ARCH_COVERAGE_SOURCES
"""Union — every architectural-design / coverage source. Use this in
consumers that treat architectural findings uniformly (e.g. M-17 clusters,
triage architectural-violation flags, §9 investigate-card grouping)."""


# --- Source families by exploitation level ----------------------------------

CODE_LEVEL_SOURCES: frozenset[str] = frozenset({
    "stride",
    "dep-scan",
    "known-vuln",
})
"""Sources tied to a concrete code-level finding with file/line evidence.
Eligible for CVSS, SARIF, and pentest-tasks emission."""


CONFIG_DEFECT_SOURCES: frozenset[str] = frozenset({
    "configuration-defect",
})
"""Configuration scanner output. Treated as code-level for CVSS but
distinguished from STRIDE for clustering."""


DESIGN_LEVEL_SOURCES: frozenset[str] = frozenset({
    "requirements-compliance",
    "known-threats",
}) | ARCH_ALL_SOURCES
"""Design / architecture / policy findings. NOT eligible for CVSS.
Pentest-tasks generator filters these out; SARIF emitter handles them
under the rule-id family."""


ALL_SOURCES: frozenset[str] = (
    CODE_LEVEL_SOURCES | CONFIG_DEFECT_SOURCES | DESIGN_LEVEL_SOURCES
)
"""Every recognised ``threats[].source`` value."""


# --- Bridge / engine producer constants -------------------------------------

BRIDGE_ANTI_PATTERN_SOURCE: str = "architecture-coverage"
"""Value the arch_coverage_to_threats bridge writes for anti-pattern
candidates promoted to threats."""

BRIDGE_HYPOTHESIS_SOURCE: str = "threat-hypothesis"
"""Value the arch_coverage_to_threats bridge writes for confirmed
hypotheses promoted to threats."""


__all__ = [
    "ARCH_DESIGN_SOURCES",
    "ARCH_COVERAGE_SOURCES",
    "ARCH_ALL_SOURCES",
    "CODE_LEVEL_SOURCES",
    "CONFIG_DEFECT_SOURCES",
    "DESIGN_LEVEL_SOURCES",
    "ALL_SOURCES",
    "BRIDGE_ANTI_PATTERN_SOURCE",
    "BRIDGE_HYPOTHESIS_SOURCE",
]
