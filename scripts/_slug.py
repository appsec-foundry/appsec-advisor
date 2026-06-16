"""_slug.py — single source of truth for GitHub-flavoured Markdown anchor slugs.

Before this module existed, four near-identical slug functions lived in:
  * `scripts/compose_threat_model.py::_anchor_from_heading`
  * `scripts/qa_checks.py::_github_slug`
  * `scripts/pregenerate_fragments.py::_v2_slug`
  * `scripts/export_sarif.py::_slugify`

Each handled edge cases slightly differently. The visible symptom was the
2026-05 juice-shop run that produced 26 unresolved `#h4-*` anchors in §7
because the LLM-emitted Markdown used one variant while the pregenerator
emitted another. The TOC-closure check then false-positive-flagged the
divergence.

This module exposes ONE function — `github_slug` — that all callers must
import. It encodes the canonical GitHub slug rule (also matched by MkDocs,
GitLab, and VS Code preview):

  1. lower-case the heading text
  2. reduce `[label](url)` link syntax to just `label`
  3. drop everything that is not word-char, whitespace, or hyphen
     (the explicit-allow-list variant in earlier code missed
     `@`, `=`, `+`, `;`, `<`, `>`, `~`, `!`, `?`, etc.)
  4. collapse whitespace to hyphens
  5. collapse repeated hyphens to one
  6. strip leading and trailing hyphens

For backward compatibility, two thin aliases are provided:
  * `slugify` — `github_slug` with an optional length cap (legacy callers)
  * `v2_slug` — `github_slug` (pregenerator use case)

Out of scope: `scripts/export_sarif.py::_slugify` builds SARIF rule IDs
(bounded length, governed by the SARIF spec — not Markdown anchors).
That helper intentionally stays separate and is NOT a Markdown anchor
generator.
"""

from __future__ import annotations

import re

__all__ = ["github_slug", "github_render_slug", "slugify", "v2_slug"]


def github_slug(heading_text: str) -> str:
    """Canonical GitHub-flavoured Markdown heading slug.

    Examples:
        >>> github_slug("## 1. System Overview")
        '1-system-overview'
        >>> github_slug("### 3.2 Foo ([T-001](#t-001))")
        '32-foo-t-001'
        >>> github_slug("Authentication & Authorization")
        'authentication-authorization'
    """
    if not isinstance(heading_text, str):
        return ""
    h = heading_text.lstrip("#").strip().lower()
    # Reduce markdown links `[text](url)` to just `text` before stripping
    # punctuation — otherwise the URL's `#id` would leak as a literal `#`.
    h = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", h)
    # Drop everything except word-char, whitespace, hyphen.
    h = re.sub(r"[^\w\s-]", "", h)
    # Collapse whitespace to single hyphen, then collapse repeated hyphens.
    h = re.sub(r"\s+", "-", h).strip("-")
    h = re.sub(r"-+", "-", h).strip("-")
    return h


def github_render_slug(heading_text: str) -> str:
    """The anchor GitHub (and pandoc) ACTUALLY render for a heading.

    Differs from `github_slug` in ONE way that matters: it does NOT collapse
    repeated hyphens and does NOT strip leading/trailing hyphens. This mirrors
    `github-slugger` (the library github.com uses) exactly, which removes
    punctuation and then maps each remaining space to a single hyphen with no
    post-collapse:

        >>> github_render_slug("3.7 IDOR — routes/address.ts:11")
        '37-idor--routesaddressts11'
        >>> github_render_slug("Authentication & Authorization")
        'authentication--authorization'

    `github_slug` is the right function for GENERATING anchor link targets —
    it produces clean single-hyphen slugs, and for headings free of
    punctuation-surrounded-by-whitespace the two functions agree, so the link
    resolves. This function is the right one for VERIFYING closure: a link
    whose target was built by `github_slug` resolves on github.com only if the
    heading's `github_render_slug` equals it. They diverge exactly when a
    heading carries ` — `, ` & `, ` / ` and friends — the renderer-unstable
    case the closure check must FLAG, not silently bless (the 2026-06 §3 ToC
    breakage was invisible because the check slugged both sides with
    `github_slug`).
    """
    if not isinstance(heading_text, str):
        return ""
    h = heading_text.lstrip("#").strip().lower()
    h = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", h)
    h = re.sub(r"[^\w\s-]", "", h)
    h = re.sub(r"\s", "-", h)
    return h


def slugify(text: str, max_len: int = 0) -> str:
    """`github_slug` with an optional length cap.

    Used by `export_sarif.py` where SARIF rule IDs benefit from a bounded
    length. `max_len=0` (default) is unbounded — identical to `github_slug`.
    """
    s = github_slug(text)
    if max_len and len(s) > max_len:
        s = s[:max_len].rstrip("-")
    return s


# Alias for backward-compat with the pregenerator's old function name.
v2_slug = github_slug
