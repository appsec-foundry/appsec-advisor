"""Tests for scripts/shared/_finding_state.py — the one evidence-state authority."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from model.build_posture_verdict import build_posture_verdict
from renderers._severity_rollup import weakness_basis_breakdown
from shared._finding_state import (
    evidence_established,
    in_report_scope,
    is_confirmed,
    is_discredited,
    is_refuted,
)
from shared._severity_policy import companion_cwes

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _legacy(tier: str | None, check: str | None) -> dict:
    threat: dict = {"id": "T-001"}
    if tier is not None:
        threat["evidence_tier"] = tier
    if check is not None:
        threat["evidence_check"] = check
    return threat


@pytest.mark.parametrize(
    ("tier", "check", "confirmed", "refuted", "discredited", "established"),
    [
        ("confirmed-exploitable", "verified", True, False, False, True),
        ("confirmed-exploitable", "verified-prior", True, False, False, True),
        ("confirmed-exploitable", "unchecked", False, False, False, False),
        ("confirmed-exploitable", None, False, False, False, False),
        ("confirmed-exploitable", "ambiguous", False, False, True, False),
        ("confirmed-exploitable", "refuted", False, True, True, False),
        ("confirmed-exploitable", " Refuted ", False, True, True, False),
        ("insecure-practice", "verified", False, False, False, True),
        # merge stamps a tier on every threat; a tier-less row is a design signal
        # or legacy data and follows the lenient default (not a practice site).
        (None, "verified", True, False, False, True),
        (None, None, False, False, False, False),
    ],
)
def test_legacy_fields(tier, check, confirmed, refuted, discredited, established) -> None:
    threat = _legacy(tier, check)
    assert is_confirmed(threat) is confirmed
    assert is_refuted(threat) is refuted
    assert is_discredited(threat) is discredited
    assert evidence_established(threat) is established
    assert in_report_scope(threat) is (not refuted)


@pytest.mark.parametrize(
    ("basis", "confirmed", "refuted", "discredited"),
    [
        ("llm-verified", True, False, False),
        ("absence-verified", True, False, False),
        ("verified-prior", True, False, False),
        ("pointer-resolved", False, False, False),
        ("unchecked", False, False, False),
        ("ambiguous", False, False, True),
        ("refuted", False, True, True),
    ],
)
def test_finalized_basis_wins_over_legacy_check(basis, confirmed, refuted, discredited) -> None:
    # The legacy check says "verified"; the finalized basis must decide.
    threat = {"evidence_tier": "confirmed-exploitable", "evidence_check": "verified", "evidence_basis": basis}
    assert is_confirmed(threat) is confirmed
    assert is_refuted(threat) is refuted
    assert is_discredited(threat) is discredited


def test_practice_tier_is_never_confirmed_even_on_established_basis() -> None:
    threat = {"evidence_tier": "insecure-practice", "evidence_basis": "llm-verified"}
    assert is_confirmed(threat) is False
    assert evidence_established(threat) is True


def test_finalized_booleans_win() -> None:
    threat = {
        "evidence_tier": "confirmed-exploitable",
        "evidence_check": "refuted",
        "confirmed": True,
        "in_report_scope": True,
    }
    assert is_confirmed(threat) is True
    assert in_report_scope(threat) is True
    assert in_report_scope({"evidence_check": "verified", "in_report_scope": False}) is False


@pytest.mark.parametrize("value", [None, {}, "T-001", []])
def test_missing_or_malformed_threat(value) -> None:
    assert is_confirmed(value) is False
    assert is_refuted(value) is False
    assert is_discredited(value) is False
    assert evidence_established(value) is False


def _register(*threats: dict) -> dict:
    return {"threats": list(threats), "weaknesses": [{"id": "W-001", "kind": "implementation"}]}


def _finding(tid: str, check: str, cwe: str = "CWE-89") -> dict:
    return {
        "id": tid,
        "cwe": cwe,
        "risk": "High",
        "source": "stride",
        "evidence_tier": "confirmed-exploitable",
        "evidence_check": check,
        "threat_category_id": "TH-01",
    }


def test_unchecked_findings_are_not_counted_confirmed_anywhere() -> None:
    model = _register(_finding("T-001", "verified"), _finding("T-002", "unchecked"), _finding("T-003", "ambiguous"))
    assert weakness_basis_breakdown(model)[1] == 1
    instances = sum(row.get("confirmed_instances") or 0 for row in build_posture_verdict(model))
    assert instances == sum(is_confirmed(t) for t in model["threats"])


def test_unchecked_companion_still_lifts_a_severity_cap() -> None:
    # Companion CWEs need usable evidence, not confirmed evidence.
    target = _finding("T-001", "verified", "CWE-89")
    unchecked = _finding("T-002", "unchecked", "CWE-943")
    ambiguous = _finding("T-003", "ambiguous", "CWE-564")
    assert companion_cwes(target, [target, unchecked, ambiguous]) == {"CWE-943"}


# Evidence-state rules live in shared/_finding_state.py. A new literal
# comparison of evidence_check/evidence_basis elsewhere is a second copy of the
# rule. Each allowed hit is a deliberate exception documented in that module.
_STATE_LITERAL = re.compile(
    r"""evidence_(?:check|basis)\b[^\n]{0,80}?(['"])(refuted|ambiguous|verified|verified-prior)\1"""
)
_ALLOWED = {
    "shared/_finding_state.py": 2,
    "analyzers/flow_route_auth.py": 1,  # needs a fresh verifier receipt
    "validators/qa_checks.py": 1,  # needs a fresh verifier receipt
    "contexts/build_architect_context.py": 1,  # ordering: ambiguous last
    "contexts/build_post_stride_contexts.py": 1,  # sampling skips verified-prior
    "model/emit_review_mitigations.py": 1,  # docstring of the ambiguous review rule
    "model/promote_verified_abuse_cases.py": 1,  # producer writes the state
    "validators/guard_evidence_verification.py": 1,  # verifier-state guard
}


def test_no_ad_hoc_evidence_state_checks() -> None:
    hits: dict[str, int] = {}
    for path in SCRIPTS.rglob("*.py"):
        if "node_modules" in path.parts:
            continue
        n = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if _STATE_LITERAL.search(line))
        if n:
            hits[path.relative_to(SCRIPTS).as_posix()] = n
    assert hits == _ALLOWED, f"use shared._finding_state predicates instead: {hits}"
