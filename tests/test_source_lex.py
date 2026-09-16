"""Offset-preserving lexical contracts used by passive scanners."""

import pytest
from _source_lex import call_end, rejecting_check, without_comments


@pytest.mark.parametrize("marker", ["// guard(x)", "/* guard(x) */"])
def test_comments_are_blank_but_locations_survive(marker):
    text = 'const url = "https://example.invalid";\n' + marker + "\nuse(url);"
    cleaned = without_comments(text)
    assert len(cleaned) == len(text)
    assert cleaned.count("\n") == text.count("\n")
    assert "https://example.invalid" in cleaned
    assert "guard" not in cleaned


def test_python_string_is_not_a_comment():
    assert without_comments('value = "#keep" #drop', python=True).strip() == 'value = "#keep"'


@pytest.mark.parametrize("prefix", ["", " ", "x; "])
def test_unterminated_comment_is_blanked(prefix):
    assert without_comments(prefix + "/* unfinished") == prefix + " " * len("/* unfinished")


def test_call_does_not_end_at_parenthesis_in_string():
    text = 'check(" ) ", nested(x)); unrelated();'
    assert text[: call_end(text, text.index("("))] == 'check(" ) ", nested(x))'


def test_ignored_predicate_is_not_rejection():
    assert not rejecting_check("allowed.has(value);")
    assert rejecting_check('if (!allowed.has(value)) throw new Error("no");')
