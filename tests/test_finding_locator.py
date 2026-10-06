"""The one locator-stripping rule every reader-facing title passes through (RA-4)."""

from __future__ import annotations

import pytest
from shared._finding_locator import is_code_locator, strip_trailing_locator, title_without_locator


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("SQL injection in login query (routes/login.ts:34)", "SQL injection in login query"),
        ("SQL injection (`routes/login.ts:34`)", "SQL injection"),
        ("Missing auth on users route (routes/api/Users)", "Missing auth on users route"),
        ("Hard-coded key — lib/insecurity.ts:21", "Hard-coded key"),
        ("Container Runs as Root — Dockerfile:1", "Container Runs as Root"),
        ("Unpinned base image — docker/Dockerfile:3", "Unpinned base image"),
        ("JWT decode without signature check lib/insecurity.ts:56", "JWT decode without signature check"),
        ("Range read (a/b.ts:20-25)", "Range read"),
        ("Doubled tail (a.ts:3) — a.ts:3", "Doubled tail"),
        ("Weak hash in lib/x.ts", "Weak hash"),
        ("Admin access (/rest/admin)", "Admin access"),
        ("Windows path (C:\\src\\app.ts:3)", "Windows path"),
        ("Rust panic (src/lib.rs:12)", "Rust panic"),
    ],
)
def test_every_locator_shape_is_removed(title: str, expected: str) -> None:
    assert strip_trailing_locator(title) == expected


@pytest.mark.parametrize(
    "title",
    [
        "Insecure Direct Object Reference (IDOR)",
        "Tampering with orders (S·E)",
        "Unpinned base image in Dockerfile",
        "Missing Container Image Signing",
        "Insecure Socket.IO",
        "Upgrade Node.js",
        "Prototype pollution in lodash.merge",
        "Outdated Express v4.17",
        "Missing auth — Socket.IO",
        "Note (e.g.)",
        "Version (1.2.3)",
        "(routes/x.ts:1)",
        "",
    ],
)
def test_prose_and_pure_locators_are_kept(title: str) -> None:
    assert strip_trailing_locator(title) == title


def test_a_pure_locator_has_no_display_title() -> None:
    assert title_without_locator("(routes/x.ts:1)") == ""
    assert title_without_locator("IDOR (routes/x.ts:1)") == "IDOR"


def test_stripping_is_idempotent() -> None:
    once = strip_trailing_locator("Doubled tail (a.ts:3) — a.ts:3")
    assert strip_trailing_locator(once) == once


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("routes/login.ts:34", True),
        ("routes/api/Users", True),
        ("Dockerfile", True),
        ("IDOR", False),
        ("S·E", False),
        ("two words.ts", False),
        ("Socket.IO", False),
        ("1.2.3", False),
        ("/rest/admin", True),
    ],
)
def test_code_locator_recognition(token: str, expected: bool) -> None:
    assert is_code_locator(token) is expected
