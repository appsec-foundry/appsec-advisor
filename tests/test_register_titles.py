"""Register titles stay within the heading limit that QA enforces."""

from __future__ import annotations

import model.emit_review_mitigations as erm
from shared._register_titles import (
    HEADING_HARD_MAX,
    MITIGATION_TITLE_MAX,
    clamp_heading_title,
    clamp_mitigation_title,
    clamp_title,
)

_LONG_REVIEW_WEAKNESS = "Browser-side navigation checks provide no server-enforced authorization for admin views"


def test_review_title_fallback_fits_the_register_heading() -> None:
    threat = {"title": _LONG_REVIEW_WEAKNESS, "evidence": [{"file": "web/src/guards/nav.guard.ts", "line": 12}]}
    title = erm._review_title("verify", threat)
    assert len(f"M-004 — {title}") <= HEADING_HARD_MAX
    assert title.endswith("…")
    assert title.startswith("Manual review: verify Browser-side navigation checks")


def test_variant_wide_id_and_trailing_locator_are_kept() -> None:
    title = "Rotate the signing key that is embedded in the service configuration and loaded at startup cfg/app.yml:7"
    clamped = clamp_heading_title("M-1234", title)
    assert len(f"M-1234 — {clamped}") <= HEADING_HARD_MAX
    assert clamped.endswith("… cfg/app.yml:7")


def test_cut_never_ends_on_a_dangling_word() -> None:
    clamped = clamp_title("Validate the redirect target against the allow-list of the gateway", 52)
    assert clamped == "Validate the redirect target against the allow-list…"
    assert clamp_title("Encrypt data with a managed key in the storage layer", 30) == "Encrypt data with a managed…"


def test_short_titles_are_unchanged() -> None:
    assert clamp_mitigation_title("Use parameterized database queries") == "Use parameterized database queries"
    assert len("M-0000 — ") + MITIGATION_TITLE_MAX == HEADING_HARD_MAX
