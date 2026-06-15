"""Tests for scripts/_slug.py — canonical GitHub-flavoured Markdown slugs."""

from __future__ import annotations

import _slug
from _slug import github_slug, slugify, v2_slug


def test_heading_with_hashes_and_numbers():
    assert github_slug("## 1. System Overview") == "1-system-overview"


def test_markdown_link_reduced_to_label():
    assert github_slug("### 3.2 Foo ([T-001](#t-001))") == "32-foo-t-001"


def test_ampersand_dropped():
    assert github_slug("Authentication & Authorization") == "authentication-authorization"


def test_lowercasing():
    assert github_slug("HELLO World") == "hello-world"


def test_special_chars_stripped():
    # @ = + ; < > ~ ! ? all dropped (not in word/space/hyphen class)
    assert github_slug("a@b=c+d;e<f>g~h!i?j") == "abcdefghij"


def test_repeated_hyphens_collapse():
    assert github_slug("foo --- bar") == "foo-bar"


def test_leading_trailing_hyphens_stripped():
    assert github_slug("-- foo --") == "foo"


def test_non_string_returns_empty():
    assert github_slug(None) == ""
    assert github_slug(123) == ""


def test_empty_string():
    assert github_slug("") == ""


def test_only_punctuation_yields_empty():
    assert github_slug("!!!") == ""


def test_slugify_unbounded_is_github_slug():
    text = "Some Long Heading Title Here"
    assert slugify(text) == github_slug(text)


def test_slugify_truncates_and_rstrips_hyphen():
    # 'foo-bar-baz' truncated at 8 -> 'foo-bar-' -> rstrip -> 'foo-bar'
    assert slugify("foo bar baz", max_len=8) == "foo-bar"


def test_slugify_no_truncation_when_under_cap():
    assert slugify("foo bar", max_len=100) == "foo-bar"


def test_v2_slug_is_github_slug_alias():
    assert v2_slug is github_slug
    assert v2_slug("My Heading") == "my-heading"


def test_all_exports():
    assert _slug.__all__ == ["github_slug", "slugify", "v2_slug"]
