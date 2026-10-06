"""The dialog-confirmed use case is the one business statement the report repeats."""

from __future__ import annotations

import pytest
from contexts import business_use_case as uc

QUESTION = (
    "**Question:** I understand this application as an intentionally vulnerable web application for "
    "security training. Is that the use case to assess? If not, describe your intended use in the free-text answer."
)


def _purpose(answer: str, question: str = QUESTION) -> str:
    return f"## Business purpose\n\n{question}\n\n**Answer:** {answer}\n\n## Impact if compromised\n\n**Answer:** x\n"


@pytest.mark.parametrize(
    ("choice", "answer", "expected"),
    [
        ("confirmed", "Yes, assess this use case", "an intentionally vulnerable web application for security training"),
        (
            "corrected",
            "No, a different use case — An internal payroll portal for HR staff",
            "An internal payroll portal for HR staff",
        ),
        # A bare "No" rejects the proposal without naming a use case.
        ("corrected", "No, a different use case", ""),
        # A choice that contradicts the answer records nothing.
        ("confirmed", "No, a different use case — something else", ""),
        ("corrected", "Yes, assess this use case", ""),
    ],
)
def test_only_a_marked_confirmation_or_replacement_yields_a_use_case(choice, answer, expected):
    text = _purpose(answer)
    annotated = uc.annotate(text, choice)
    assert uc.confirmed_use_case(annotated) == expected
    assert (annotated != text) == bool(expected)


def test_unmarked_or_missing_sections_yield_nothing():
    assert uc.confirmed_use_case(_purpose("Yes, assess this use case")) == ""
    assert uc.confirmed_use_case("Free-form context without dialog sections.") == ""
    assert uc.annotate("no purpose heading\n", "confirmed") == "no purpose heading\n"


def test_unknown_choice_is_rejected():
    with pytest.raises(ValueError):
        uc.annotate(_purpose("Yes, assess this use case"), "maybe")


def test_use_case_is_reduced_to_plain_capped_words():
    answer = (
        "No, a different use case — An [HR](http://evil.example) <script>x</script> portal `rm -rf` "
        "see https://evil.example/path " + "very long text " * 30
    )
    use_case = uc.confirmed_use_case(uc.annotate(_purpose(answer), "corrected"))
    assert use_case.startswith("An HR")
    assert not any(ch in use_case for ch in "[]()<>`*_|#")
    assert "http" not in use_case and "evil.example" not in use_case
    assert len(use_case) <= uc.MAX_USE_CASE_CHARS
