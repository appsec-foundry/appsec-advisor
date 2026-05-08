"""
Tests for the newly added validators: triage-flags, threat-model output,
and user-supplied known-threats.

Covers happy-path, schema-level violations, and the Python post-checks
that JSONSchema Draft 2020-12 cannot express (sequential TF-NNN, counter
consistency, unique known-threat IDs).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

import pytest
import yaml

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from validate_intermediate import (  # noqa: E402
    validate_known_threats,
    validate_threat_model_output,
    validate_triage_flags,
)


# ---------------------------------------------------------------------------
# Fixture builders — each returns a FRESH dict so parametrized mutations
# cannot bleed between cases
# ---------------------------------------------------------------------------

def _ranking(findings: list[dict] | None = None) -> dict:
    return {
        "method": "impact-weighted-v2",
        "ranked_at": "2026-04-15T12:00:01Z",
        "computed_by": "triage_compute_ranking.py (deterministic)",
        "views": {
            "top_threats": {
                "sort_key": "category_score_impact_weighted",
                "threshold": "effective_severity >= High",
                "categories_ranked": [],
            },
            "top_findings": {
                "sort_key": "finding_score_impact_weighted",
                "threshold": "effective_severity == Critical",
                "max_rows": 4,
                "findings_ranked": findings or [],
            },
            "prioritized_mitigations": {
                "sort_key": "addressed_severity_desc_then_effort_asc",
                "mitigations_ranked": [],
            },
            "chains": {
                "sort_key": "severity_desc_then_member_count_desc",
                "chains_ranked": [],
            },
        },
        "reconciliation_summary": {
            "findings_elevated_via_chain": 0,
            "findings_capped_by_cwe": 0,
            "contributors_capped_at_high": 0,
            "chains_active": 0,
        },
    }


def _valid_triage() -> dict:
    return {
        "version": 2,
        "generated_at": "2026-04-15T12:00:00Z",
        "flags": [
            {
                "flag_id": "TF-001",
                "type": "consistency",
                "severity": "warning",
                "threat_ids": ["T-001"],
                "message": "Rating drift across similar components",
            },
            {
                "flag_id": "TF-002",
                "type": "cvss_band_mismatch",
                "severity": "info",
                "threat_ids": ["T-003"],
                "message": "CVSS severity differs from risk band",
            },
        ],
        "summary": {
            "total_flags": 2,
            "warnings": 1,
            "info": 1,
            "threats_reviewed": 2,
        },
        "ranking": _ranking([
            {
                "rank": 1,
                "id": "T-001",
                "effective_severity": "High",
                "raw_severity": "High",
                "chain_role": "none",
                "breach_distance": 2,
                "score": 410,
                "compound_chain_ids": [],
            }
        ]),
    }


def _empty_triage() -> dict:
    return {
        "version": 2,
        "generated_at": "2026-04-15T12:00:00Z",
        "flags": [],
        "summary": {"total_flags": 0, "warnings": 0, "info": 0, "threats_reviewed": 0},
        "ranking": _ranking(),
    }


def _valid_known_threats() -> dict:
    return {
        "threats": [
            {
                "id": "PT-2025-001",
                "title": "Example",
                "stride": "Spoofing",
                "component": "auth",
                "severity": "High",
                "status": "open",
                "description": "A real finding.",
            }
        ]
    }


# ---------------------------------------------------------------------------
# triage-flags — parametrized positive and negative cases
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("builder", [_valid_triage, _empty_triage],
                         ids=["valid-with-flags", "valid-empty-flags"])
def test_triage_flags_valid_inputs_pass(builder: Callable[[], dict]) -> None:
    ok, errors = validate_triage_flags(builder())
    assert ok, errors


def _mutate(setter: Callable[[dict], None]) -> Callable[[dict], None]:
    """Tiny helper to let the table below stay readable."""
    return setter


# (case_id, mutate_fn, required_error_substrings)
_TRIAGE_NEG: list[tuple[str, Callable[[dict], None], list | None]] = [
    ("nonsequential-tf-id",
     _mutate(lambda d: d["flags"].__setitem__(1, {**d["flags"][1], "flag_id": "TF-005"})),
     ["breaks sequential order"]),
    ("duplicate-tf-id",
     _mutate(lambda d: d["flags"].__setitem__(1, {**d["flags"][1], "flag_id": "TF-001"})),
     ["duplicated"]),
    ("summary-total-flags-mismatch",
     _mutate(lambda d: d["summary"].__setitem__("total_flags", 99)),
     ["total_flags"]),
    ("summary-warnings-info-sum-mismatch",
     _mutate(lambda d: (d["summary"].update({"warnings": 2, "info": 2, "total_flags": 2}))),
     None),
    ("invalid-type-enum",
     _mutate(lambda d: d["flags"][0].__setitem__("type", "not-a-real-type")),
     None),
]


@pytest.mark.parametrize(
    "mutate,required",
    [(m, r) for _, m, r in _TRIAGE_NEG],
    ids=[cid for cid, _, _ in _TRIAGE_NEG],
)
def test_triage_flags_invalid_inputs_rejected(
    mutate: Callable[[dict], None], required: list | None
) -> None:
    data = _valid_triage()
    mutate(data)
    ok, errors = validate_triage_flags(data)
    assert not ok, f"invalid input was accepted (errors={errors})"
    if required:
        for sub in required:
            assert any(sub in e for e in errors), (
                f"no error mentions {sub!r}; got errors={errors}"
            )


# ---------------------------------------------------------------------------
# threat-model.output — only 3 cases, keep them as separate tests for clarity
# ---------------------------------------------------------------------------

def test_threat_model_output_canonical_example_validates() -> None:
    path = ROOT / "tests" / "fixtures" / "schema" / "threat-model.valid.yaml"
    data = yaml.safe_load(path.read_text())
    ok, errors = validate_threat_model_output(data)
    assert ok, errors


def _threat_model_skeleton_no_components() -> dict:
    return {
        "meta": {
            "schema_version": 1, "project": "x",
            "generated": "2026-04-15T00:00:00Z", "mode": "full", "model": "sonnet",
        },
    }


def _threat_model_skeleton_with_bad_id() -> dict:
    return {
        "meta": {
            "schema_version": 1, "project": "x",
            "generated": "2026-04-15T00:00:00Z", "mode": "full", "model": "sonnet",
        },
        "components": [], "assets": [], "attack_surface": [],
        "trust_boundaries": [], "security_controls": [], "mitigations": [],
        "threats": [
            {"id": "BAD-1", "component": "x", "stride": "Spoofing",
             "scenario": "a scenario long enough", "likelihood": "Low",
             "impact": "Low", "risk": "Low"},
        ],
    }


@pytest.mark.parametrize("builder,required", [
    (_threat_model_skeleton_no_components, ["components"]),
    (_threat_model_skeleton_with_bad_id, None),
], ids=["missing-components", "bad-threat-id-pattern"])
def test_threat_model_output_invalid_inputs_rejected(
    builder: Callable[[], dict], required: list | None
) -> None:
    ok, errors = validate_threat_model_output(builder())
    assert not ok
    if required:
        for sub in required:
            assert any(sub in e for e in errors), (
                f"no error mentions {sub!r}; got errors={errors}"
            )


# ---------------------------------------------------------------------------
# known-threats
# ---------------------------------------------------------------------------

def test_known_threats_valid() -> None:
    ok, errors = validate_known_threats(_valid_known_threats())
    assert ok, errors


def test_known_threats_example_file_validates() -> None:
    path = ROOT / "examples" / "known-threats.yaml"
    if not path.exists():
        pytest.skip("example known-threats.yaml not present")
    data = yaml.safe_load(path.read_text())
    ok, errors = validate_known_threats(data)
    assert ok, errors


_KNOWN_THREATS_NEG: list[tuple[str, Callable[[dict], dict], list | None]] = [
    ("duplicate-ids-rejected",
     lambda: (lambda d: (d["threats"].append(dict(d["threats"][0])), d)[-1])(_valid_known_threats()),
     ["duplicated"]),
    ("bad-status-enum",
     lambda: (lambda d: (d["threats"][0].__setitem__("status", "someday-maybe"), d)[-1])(_valid_known_threats()),
     None),
    ("missing-required-field",
     lambda: {"threats": [{"id": "X-1", "title": "t"}]},
     None),
]


@pytest.mark.parametrize(
    "builder,required",
    [(b, r) for _, b, r in _KNOWN_THREATS_NEG],
    ids=[cid for cid, _, _ in _KNOWN_THREATS_NEG],
)
def test_known_threats_invalid_inputs_rejected(
    builder: Callable[[], dict], required: list | None
) -> None:
    ok, errors = validate_known_threats(builder())
    assert not ok
    if required:
        for sub in required:
            assert any(sub in e for e in errors), (
                f"no error mentions {sub!r}; got errors={errors}"
            )
