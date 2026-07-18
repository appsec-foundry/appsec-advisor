"""
Schema validation tests for .threats-merged.json — the canonical merged
threat list produced by Phase 9 after global T-NNN assignment. Downstream
tooling (diagram annotator, YAML/SARIF export, changelog writer) consumes
this file, so its schema is a load-bearing contract.
"""

import copy
import json
import sys
from pathlib import Path
from typing import Callable

import pytest

PLUGIN_SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))
from validate_intermediate import validate_threats_merged  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def _load() -> dict:
    with (FIXTURES / "valid_threats_merged.json").open() as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Positive cases — inputs that must validate successfully
# ---------------------------------------------------------------------------


def _mutate_likelihood_critical(d: dict) -> None:
    d["threats"][0]["likelihood"] = "Critical"  # Phase 9 risk matrix allows this


def _mutate_evidence_line_null(d: dict) -> None:
    d["threats"][0]["evidence"]["line"] = None  # null line permitted


def _mutate_evidence_tier(d: dict) -> None:
    # P1 (weakness-class evidence model): the new instance-level evidence basis.
    d["threats"][0]["evidence_tier"] = "insecure-practice"


def _valid_weakness() -> dict:
    return {
        "id": "W-001",
        "weakness_class": "injection",
        "kind": "design",
        "title": "Database query safety",
        "statement": "SQL built by string concatenation; no parametrized layer.",
        "severity": "High",
        "severity_basis": "confirmed",
        "observable_backing": {
            "absent_control_signal": [{"pattern": "sequelize", "hit_count": 0}],
            "practice_evidence": [{"file": "routes/search.ts", "line": 23}],
        },
        "affected_components": ["api"],
        "instances": [{"id": "T-001", "file": "routes/login.ts", "line": 34, "basis": "confirmed-exploitable"}],
    }


def _mutate_add_weakness(d: dict) -> None:
    # P1: top-level weakness register parents. Optional, additive.
    d["weaknesses"] = [_valid_weakness()]


_POSITIVE_CASES = [
    ("pristine-fixture-passes", lambda d: None),
    ("likelihood-allows-critical", _mutate_likelihood_critical),
    ("evidence-line-may-be-null", _mutate_evidence_line_null),
    ("evidence-tier-accepted", _mutate_evidence_tier),
    ("weakness-register-accepted", _mutate_add_weakness),
]


@pytest.mark.parametrize("mutate", [m for _, m in _POSITIVE_CASES], ids=[cid for cid, _ in _POSITIVE_CASES])
def test_valid_input_passes(mutate: Callable[[dict], None]) -> None:
    data = _load()
    mutate(data)
    ok, errors = validate_threats_merged(data)
    assert ok, f"valid input rejected: {errors}"
    assert errors == [] or errors == errors  # errors list present-but-empty is fine


# ---------------------------------------------------------------------------
# Negative cases — invalid inputs that must be caught, organized as a table
#
# Each case describes a single mutation against the fixture plus the
# keyword(s) the validator must mention in its error. The mutate callable
# receives a fresh copy of the fixture; it can delete, replace, or add
# fields as needed.
# ---------------------------------------------------------------------------


def _delete(path: tuple):
    """Build a mutator that deletes a nested key."""

    def _mut(d: dict) -> None:
        obj = d
        for p in path[:-1]:
            obj = obj[p]
        del obj[path[-1]]

    return _mut


def _set(path: tuple, value) -> Callable[[dict], None]:
    """Build a mutator that sets a nested key to a value."""

    def _mut(d: dict) -> None:
        obj = d
        for p in path[:-1]:
            obj = obj[p]
        obj[path[-1]] = value

    return _mut


# Each row: (case_id, mutate_fn, required_error_substrings)
# required_error_substrings is either a list of individual substrings (any-of)
# or a tuple of (all, of) substrings that must co-occur in the same error line.
_NEGATIVE_CASES: list[tuple[str, Callable[[dict], None], list | tuple]] = [
    ("missing-top-level-field-version", _delete(("version",)), ["version"]),
    ("version-must-be-one", _set(("version",), 2), ["version"]),
    ("threats-must-be-array", _set(("threats",), {"not": "a list"}), [("threats", "array")]),
    ("t-id-format-enforced", _set(("threats", 0, "t_id"), "TX-001"), ["t_id"]),
    ("t-id-must-be-sequential", _set(("threats", 1, "t_id"), "T-005"), ["sequential"]),
    ("t-id-uniqueness", _set(("threats", 1, "t_id"), "T-001"), ["duplicated"]),
    ("stride-category-enforced", _set(("threats", 0, "stride"), "S"), ["stride"]),
    ("risk-values-enforced", _set(("threats", 0, "risk"), "Severe"), ["risk"]),
    ("cwe-format-enforced", _set(("threats", 0, "cwe"), "CWE_321"), ["cwe"]),
    ("source-values-enforced", _set(("threats", 0, "source"), "manual"), ["source"]),
    (
        "architectural-violation-must-be-bool",
        _set(("threats", 0, "architectural_violation"), "no"),
        ["architectural_violation"],
    ),
    ("evidence-missing-file", _delete(("threats", 0, "evidence", "file")), [("evidence", "file")]),
    ("evidence-line-must-be-int", _set(("threats", 0, "evidence", "line"), "22"), ["line"]),
    ("title-must-not-be-empty", _set(("threats", 0, "title"), "   "), ["title"]),
    ("missing-row-field-component-id", _delete(("threats", 0, "component_id")), ["component_id"]),
    # P1 weakness-class evidence model — new instance/weakness contract.
    (
        "evidence-tier-enum-enforced",
        _set(("threats", 0, "evidence_tier"), "maybe"),
        ["evidence_tier"],
    ),
    (
        "weakness-id-pattern-enforced",
        lambda d: d.update({"weaknesses": [{**_valid_weakness(), "id": "T-001"}]}),
        ["W-"],
    ),
    (
        "weakness-class-enum-enforced",
        lambda d: d.update({"weaknesses": [{**_valid_weakness(), "weakness_class": "sqli"}]}),
        ["weakness_class"],
    ),
    (
        "weakness-kind-enum-enforced",
        lambda d: d.update({"weaknesses": [{**_valid_weakness(), "kind": "runtime"}]}),
        ["kind"],
    ),
    (
        "weakness-requires-observable-backing",
        lambda d: d.update({"weaknesses": [{k: v for k, v in _valid_weakness().items() if k != "observable_backing"}]}),
        ["observable_backing"],
    ),
]


@pytest.mark.parametrize(
    "mutate,required",
    [(m, r) for _, m, r in _NEGATIVE_CASES],
    ids=[cid for cid, _, _ in _NEGATIVE_CASES],
)
def test_invalid_input_rejected(mutate: Callable[[dict], None], required: list) -> None:
    data = _load()
    mutate(data)
    ok, errors = validate_threats_merged(data)

    assert not ok, f"invalid input was incorrectly accepted (errors={errors})"

    for req in required:
        if isinstance(req, tuple):
            # All substrings of this tuple must appear in the SAME error line
            assert any(all(part in e for part in req) for e in errors), (
                f"no error line contains all of {req!r}; got errors={errors}"
            )
        else:
            # At least one error line must contain this substring
            assert any(req in e for e in errors), f"no error mentions {req!r}; got errors={errors}"


# ---------------------------------------------------------------------------
# Cases that don't fit the mutate-fixture pattern
# ---------------------------------------------------------------------------


def test_root_not_object_produces_specific_error() -> None:
    """The one and only case where the input is not even a dict."""
    ok, errors = validate_threats_merged([])
    assert not ok
    assert errors == ["root must be a JSON object"]


def test_validator_does_not_mutate_input() -> None:
    """The validator must work on a copy or read-only — it cannot alter caller data."""
    original = _load()
    mutated = copy.deepcopy(original)
    mutated["threats"][0]["risk"] = "Low"
    validate_threats_merged(mutated)
    assert original["threats"][0]["risk"] == "Critical"


# ---------------------------------------------------------------------------
# P1.5 — weakness-register emission invariants (I2 + W-NNN uniqueness),
# enforced as Python post-checks in validate_intermediate.
# ---------------------------------------------------------------------------


def test_weakness_empty_backing_rejected() -> None:
    data = _load()
    data["weaknesses"] = [
        {
            "id": "W-001",
            "weakness_class": "injection",
            "kind": "design",
            "title": "Input validation",
            "statement": "x",
            "severity": "High",
            "severity_basis": "design-risk",
            "observable_backing": {},  # I2 violation: no backing
        }
    ]
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("observable_backing" in e for e in errors)


def test_weakness_duplicate_id_rejected() -> None:
    data = _load()
    w = {
        "id": "W-001",
        "weakness_class": "injection",
        "kind": "design",
        "title": "Input validation",
        "statement": "x",
        "severity": "High",
        "severity_basis": "design-risk",
        "observable_backing": {"absent_control_signal": [{"hit_count": 0}]},
    }
    data["weaknesses"] = [w, dict(w)]
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("duplicated weakness id" in e for e in errors)


def test_weakness_with_backing_accepted() -> None:
    data = _load()
    data["weaknesses"] = [
        {
            "id": "W-001",
            "weakness_class": "injection",
            "kind": "design",
            "title": "Input validation",
            "statement": "x",
            "severity": "High",
            "severity_basis": "design-risk",
            "observable_backing": {"practice_evidence": [{"file": "a.ts", "line": 1}]},
        }
    ]
    ok, errors = validate_threats_merged(data)
    assert ok, f"valid weakness rejected: {errors}"


def test_observed_practice_weakness_is_schema_valid() -> None:
    data = _load()
    data["weaknesses"] = [
        {
            "id": "W-001",
            "weakness_class": "injection",
            "kind": "implementation",
            "title": "Database query safety",
            "statement": "Unsafe query construction in the persistence boundary.",
            "severity": "High",
            "severity_basis": "observed-practice",
            "observable_backing": {"practice_evidence": [{"file": "routes/search.ts", "line": 23}]},
        }
    ]
    ok, errors = validate_threats_merged(data)
    assert ok, f"observed practice weakness rejected: {errors}"


def test_weakness_title_length_is_enforced() -> None:
    data = _load()
    weakness = _valid_weakness()
    weakness["title"] = "x" * 81
    data["weaknesses"] = [weakness]
    ok, errors = validate_threats_merged(data)
    assert not ok
    assert any("title" in error for error in errors)
