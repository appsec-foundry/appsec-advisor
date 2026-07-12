"""P4 — Layer-2 systemic posture verdict (build_posture_verdict.py)."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import build_posture_verdict as bpv  # noqa: E402


def _weakness(wclass, kind="design", basis="design-risk", severity="High",
              strategy=None, components=None, instances=None):
    w = {"id": "W-001", "weakness_class": wclass, "kind": kind, "severity": severity,
         "severity_basis": basis, "affected_components": components or []}
    if strategy:
        w["implementation_strategy"] = strategy
    if instances:
        w["instances"] = instances
    return w


def test_empty_yields_no_rows() -> None:
    assert bpv.build_posture_verdict({"threats": [], "weaknesses": []}) == []


def test_confirmed_instance_is_violated() -> None:
    yd = {"weaknesses": [_weakness("injection", basis="confirmed",
                                   instances=[{"id": "T-001"}], components=["a"])]}
    rows = {r["theme"]: r for r in bpv.build_posture_verdict(yd)}
    assert rows["InputValidation"]["verdict"] == "VIOLATED"


def test_pervasive_home_grown_design_is_violated() -> None:
    yd = {"weaknesses": [_weakness("weak_crypto", kind="design", strategy="home-grown",
                                   components=["a", "b", "c"])]}
    rows = {r["theme"]: r for r in bpv.build_posture_verdict(yd)}
    assert rows["DataProtection"]["verdict"] == "VIOLATED"


def test_isolated_weakness_is_weak() -> None:
    yd = {"weaknesses": [_weakness("broken_auth", kind="implementation", components=["a"])]}
    rows = {r["theme"]: r for r in bpv.build_posture_verdict(yd)}
    assert rows["Authentication"]["verdict"] == "WEAK"


def test_standard_vetted_no_confirmed_is_adequate() -> None:
    yd = {"weaknesses": [_weakness("weak_crypto", kind="design", strategy="standard-vetted",
                                   components=["a"])]}
    rows = {r["theme"]: r for r in bpv.build_posture_verdict(yd)}
    assert rows["DataProtection"]["verdict"] == "ADEQUATE"


def test_unfolded_confirmed_threat_counts_but_folded_not_double() -> None:
    # A confirmed threat that is ALSO a weakness instance is counted once.
    yd = {
        "weaknesses": [_weakness("injection", basis="confirmed",
                                 instances=[{"id": "T-001"}], components=["a"])],
        "threats": [
            {"id": "T-001", "cwe": "CWE-89", "evidence_tier": "confirmed-exploitable"},  # folded
            {"id": "T-050", "cwe": "CWE-89", "evidence_tier": "confirmed-exploitable"},  # unfolded
        ],
    }
    rows = {r["theme"]: r for r in bpv.build_posture_verdict(yd)}
    # 1 folded instance + 1 unfolded confirmed threat = 2, not 3.
    assert rows["InputValidation"]["confirmed_instances"] == 2


def test_rows_sorted_worst_first() -> None:
    yd = {"weaknesses": [
        _weakness("broken_auth", kind="implementation", components=["a"]),           # WEAK
        {"id": "W-2", "weakness_class": "injection", "kind": "design", "severity": "Critical",
         "severity_basis": "confirmed", "instances": [{"id": "T-001"}], "affected_components": ["a"]},  # VIOLATED
    ]}
    rows = bpv.build_posture_verdict(yd)
    assert rows[0]["verdict"] == "VIOLATED"
