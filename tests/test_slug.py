"""Tests for scripts/_slug.py — canonical GitHub-flavoured Markdown slugs."""

from __future__ import annotations

import _slug
from _slug import github_render_slug, github_slug, slugify, v2_slug


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
    assert _slug.__all__ == ["github_slug", "github_render_slug", "slugify", "v2_slug"]


# ---------------------------------------------------------------------------
# github_render_slug — the anchor github.com ACTUALLY renders. Values below
# were captured from the real `github-slugger` package (the one github.com
# uses). The defining difference from github_slug: NO hyphen collapse, NO
# leading/trailing trim. These pin the closure check against drift back into
# the tautology that hid the 2026-06 §3 ToC breakage.
# ---------------------------------------------------------------------------


def test_render_slug_emdash_yields_double_hyphen():
    # ` — ` (space em-dash space) → em-dash removed → two spaces → '--'.
    assert (
        github_render_slug("3.7 Insecure Direct Object Reference — routes/address.ts:11")
        == "37-insecure-direct-object-reference--routesaddressts11"
    )


def test_render_slug_ampersand_yields_double_hyphen():
    assert github_render_slug("Authentication & Authorization") == "authentication--authorization"


def test_render_slug_keeps_literal_spaced_hyphen_run():
    # "foo - bar" → spaces both sides of the kept hyphen → 'foo---bar'.
    assert github_render_slug("foo - bar") == "foo---bar"


def test_render_slug_does_not_trim_leading_hyphen():
    # Leading emoji is stripped but the space it left becomes a leading hyphen.
    assert github_render_slug("🔴 Critical (29)") == "-critical-29"


def test_render_slug_clean_heading_matches_generator():
    # The whole point of stripping the §3 ` — file:line` tail: a punctuation-
    # free heading slugs IDENTICALLY under the generator and the renderer, so
    # the composer-built link target resolves on github.com.
    clean = "Insecure Direct Object Reference"
    assert github_render_slug(clean) == github_slug(clean) == "insecure-direct-object-reference"


def test_render_slug_diverges_from_generator_only_on_spaced_punctuation():
    # Documents the invariant the closure check relies on: the two functions
    # agree unless a heading carries punctuation surrounded by whitespace.
    assert github_render_slug("Simple Heading 12") == github_slug("Simple Heading 12")
    assert github_render_slug("A & B") != github_slug("A & B")


def test_render_slug_non_string_and_empty():
    assert github_render_slug(None) == ""
    assert github_render_slug("") == ""
