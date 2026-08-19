"""Tests for scripts/_severity_rollup.py — the shared finding-severity rules.

The module exists because two surfaces disagreed about the same model: the
report bucketed findings on `risk` while the show-threat-model overview ranked
them by `effective_severity`. These tests pin the rules that resolved it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import _severity_rollup as sr  # noqa: E402,I001


# ---------------------------------------------------------------------------
# display_id
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("T-001", "F-001"),
        ("t-042", "F-042"),
        ("T-1234", "F-1234"),
        ("F-007", "F-007"),
        ("M-003", "M-003"),
        ("W-002", "W-002"),
        ("AC-T-001", "AC-T-001"),
        ("", ""),
    ],
)
def test_display_id_maps_only_the_yaml_threat_id(raw, expected):
    assert sr.display_id(raw) == expected


def test_display_id_leaves_non_numeric_t_prefix_alone():
    # `TB-` (trust boundary) starts with T- but is not a finding id.
    assert sr.display_id("TB-01") == "TB-01"


# ---------------------------------------------------------------------------
# register_severity
# ---------------------------------------------------------------------------


def test_register_severity_ignores_effective_severity():
    """The abuse-chain elevated rating must not leak into the finding
    inventory — that is exactly the bug this module was extracted to fix."""
    threat = {"risk": "High", "effective_severity": "Critical"}
    assert sr.register_severity(threat) == "High"


def test_register_severity_falls_back_to_legacy_severity_field():
    assert sr.register_severity({"severity": "medium"}) == "Medium"


def test_register_severity_normalizes_case():
    assert sr.register_severity({"risk": "cRITICAL"}) == "Critical"


def test_register_severity_passes_through_unknown_label():
    assert sr.register_severity({"risk": "Catastrophic"}) == "Catastrophic"


def test_register_severity_empty_inputs():
    assert sr.register_severity(None) == ""
    assert sr.register_severity({}) == ""


# ---------------------------------------------------------------------------
# risk_distribution_counts
# ---------------------------------------------------------------------------


def _model(threats, weaknesses=None):
    doc = {"threats": threats}
    if weaknesses is not None:
        doc["weaknesses"] = weaknesses
    return doc


def test_risk_distribution_without_weakness_register_counts_every_threat():
    data = _model(
        [
            {"risk": "Critical", "evidence_tier": "insecure-practice"},
            {"risk": "High"},
            {"risk": "Medium"},
        ]
    )
    assert sr.risk_distribution_counts(data) == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "info": 0,
    }


def test_risk_distribution_folds_practice_sites_when_weaknesses_exist():
    data = _model(
        [
            {"risk": "Critical", "evidence_tier": "insecure-practice"},
            {"risk": "Critical"},
        ],
        weaknesses=[{"kind": "implementation", "severity_basis": "confirmed", "severity": "High"}],
    )
    counts = sr.risk_distribution_counts(data)
    assert counts["critical"] == 1


def test_risk_distribution_adds_design_risk_weakness_once():
    """A design-risk weakness has no instance in threats[] — without this it
    would be invisible in the tally despite ranking in the report."""
    data = _model(
        [{"risk": "High"}],
        weaknesses=[{"kind": "design", "severity_basis": "design-risk", "severity": "Critical"}],
    )
    counts = sr.risk_distribution_counts(data)
    assert counts["critical"] == 1
    assert counts["high"] == 1


def test_risk_distribution_does_not_re_add_confirmed_weaknesses():
    data = _model(
        [{"risk": "High"}],
        weaknesses=[{"kind": "implementation", "severity_basis": "confirmed", "severity": "High"}],
    )
    assert sr.risk_distribution_counts(data)["high"] == 1


def test_risk_distribution_maps_informational_spellings():
    data = _model([{"risk": "informational"}, {"risk": "information"}, {"risk": "info"}])
    assert sr.risk_distribution_counts(data)["info"] == 3


# ---------------------------------------------------------------------------
# register_threats / weakness_basis_breakdown
# ---------------------------------------------------------------------------


def test_register_threats_keeps_folded_practice_sites():
    """§8 still renders a card for a practice site, so the overview must be
    able to list it — dropping it would lose a real Critical finding."""
    data = _model(
        [
            {"id": "T-011", "risk": "Critical", "evidence_tier": "insecure-practice"},
            {"id": "T-001", "risk": "Critical"},
        ],
        weaknesses=[{"kind": "implementation", "severity_basis": "confirmed", "severity": "High"}],
    )
    assert [t["id"] for t in sr.register_threats(data)] == ["T-011", "T-001"]


def test_register_threats_drops_refuted():
    data = _model(
        [
            {"id": "T-001", "risk": "High"},
            {"id": "T-002", "risk": "High", "evidence_check": "refuted"},
        ]
    )
    assert [t["id"] for t in sr.register_threats(data)] == ["T-001"]


def test_weakness_basis_breakdown_none_without_register():
    assert sr.weakness_basis_breakdown(_model([{"risk": "High"}])) is None
    assert sr.practice_fold_active(_model([{"risk": "High"}])) is False


def test_weakness_basis_breakdown_excludes_design_sources_and_bad_evidence():
    data = _model(
        [
            {"risk": "High"},
            {"risk": "High", "source": "coverage-gap"},
            {"risk": "High", "evidence_check": "refuted"},
            {"risk": "High", "evidence_tier": "insecure-practice"},
        ],
        weaknesses=[
            {"kind": "implementation"},
            {"kind": "design"},
            {"kind": "design"},
        ],
    )
    combined, confirmed, implementation, design = sr.weakness_basis_breakdown(data)
    assert (confirmed, implementation, design) == (1, 1, 2)
    assert combined == 4


def test_composer_delegates_to_this_module():
    """The composer's Management-Summary tally and this module must not drift
    apart again — they are the same function."""
    import compose_threat_model as compose

    data = _model(
        [{"risk": "Critical"}, {"risk": "High", "evidence_tier": "insecure-practice"}],
        weaknesses=[{"kind": "design", "severity_basis": "design-risk", "severity": "Medium"}],
    )
    assert compose._risk_distribution_counts(data) == sr.risk_distribution_counts(data)
    assert compose._weakness_basis_breakdown(data) == sr.weakness_basis_breakdown(data)


# ---------------------------------------------------------------------------
# register floor / low cell
# ---------------------------------------------------------------------------


def test_register_floor_defaults_to_medium_when_meta_is_silent():
    """A model written before the floor was persisted ran under the resolver's
    default, so reading it as `medium` matches what actually happened."""
    assert sr.register_floor({}) == "medium"
    assert sr.register_floor({"meta": {}}) == "medium"
    assert sr.register_floor({"meta": {"register_severity_floor": "bogus"}}) == "medium"


def test_register_floor_reads_meta():
    assert sr.register_floor({"meta": {"register_severity_floor": "LOW"}}) == "low"
    assert sr.register_floor({"meta": {"register_severity_floor": "high"}}) == "high"


def test_low_is_suppressed_above_a_low_floor():
    assert sr.low_suppressed({"meta": {"register_severity_floor": "medium"}}) is True
    assert sr.low_suppressed({"meta": {"register_severity_floor": "high"}}) is True
    assert sr.low_suppressed({"meta": {"register_severity_floor": "low"}}) is False
    assert sr.low_suppressed({"meta": {"register_severity_floor": "informational"}}) is False


def test_low_cell_reports_na_only_when_nothing_could_be_counted():
    counts = {"low": 0}
    assert sr.low_cell({"meta": {"register_severity_floor": "medium"}}, counts) == "n/a"
    assert sr.low_cell({"meta": {"register_severity_floor": "low"}}, counts) == "0"
    assert sr.low_cell({"meta": {"register_severity_floor": "low"}}, {"low": 3}) == "3"
