from __future__ import annotations

from jsonschema import Draft202012Validator
from schema_canonicalize import canonicalize_lossless

SCHEMA = {
    "type": "object",
    "required": ["id", "kind"],
    "properties": {
        "id": {"type": "string"},
        "kind": {"enum": ["business_impact", "consistency"]},
        "note": {"type": "string"},
        "trace": {"type": "object"},
        "either": {"anyOf": [{"type": "integer"}, {"type": "string"}]},
        "clash": {"enum": ["a_b", "A-B"]},
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["level"],
                "properties": {"level": {"enum": ["High", "Low"]}, "why": {"type": "string"}},
            },
        },
    },
    "additionalProperties": False,
}
VALIDATOR = Draft202012Validator(SCHEMA)


def _run(document: dict) -> list[str]:
    return [str(change) for change in canonicalize_lossless(document, VALIDATOR)]


def test_null_on_optional_fields_is_removed_at_any_depth():
    doc = {"id": "x", "kind": "consistency", "trace": None, "items": [{"level": "Low", "why": None}]}

    assert _run(doc) == ["trace: null removed", "items[0].why: null removed"]
    assert doc == {"id": "x", "kind": "consistency", "items": [{"level": "Low"}]}
    assert VALIDATOR.is_valid(doc)


def test_null_on_a_required_field_stays_for_the_gate():
    doc = {"id": None, "kind": "consistency"}

    assert _run(doc) == []
    assert doc["id"] is None


def test_enum_spelling_drift_maps_to_the_single_declared_member():
    doc = {"id": "x", "kind": "Business-Impact", "items": [{"level": "high"}]}

    assert _run(doc) == ["kind: Business-Impact -> business_impact", "items[0].level: high -> High"]
    assert VALIDATOR.is_valid(doc)


def test_ambiguous_or_undeclared_enum_values_are_never_guessed():
    doc = {"id": "x", "kind": "severity", "clash": "a b"}

    assert _run(doc) == []
    assert doc == {"id": "x", "kind": "severity", "clash": "a b"}


def test_null_inside_a_combinator_is_removed_when_optional():
    doc = {"id": "x", "kind": "consistency", "either": None}

    assert _run(doc) == ["either: null removed"]
    assert VALIDATOR.is_valid(doc)


def test_valid_documents_are_untouched():
    doc = {"id": "x", "kind": "consistency", "note": "n"}

    assert _run(doc) == []
