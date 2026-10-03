"""Tests for scripts/shared/_paths.py — the one ``./``-prefix strip rule."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from shared._paths import strip_dot_slash

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("./a.ts", "a.ts"),
        ("././a.ts", "a.ts"),
        (".github/workflows/ci.yml", ".github/workflows/ci.yml"),
        ("./.github/workflows/ci.yml", ".github/workflows/ci.yml"),
        ("../x.ts", "../x.ts"),
        (".a", ".a"),
        ("a", "a"),
        ("", ""),
        ("/abs/a", "/abs/a"),
    ],
)
def test_strips_only_the_dot_slash_prefix(raw: str, expected: str) -> None:
    assert strip_dot_slash(raw) == expected


def test_hidden_directory_never_collides_with_plain_one() -> None:
    assert strip_dot_slash(".github/x") != strip_dot_slash("github/x")


# lstrip("./") / lstrip("/.") strip a character set and eat the dot of hidden
# directories. The only permitted occurrence reproduces the version-1 changelog
# match keys so a diff against an entry persisted before the fix stays stable.
_CHARSET_STRIP = re.compile(r"""\.lstrip\(\s*(['"])(\./|/\.)\1\s*\)""")
_ALLOWED = {"model/build_threat_model_yaml.py": 1}


def test_no_path_code_strips_a_dot_slash_character_set() -> None:
    hits: dict[str, int] = {}
    for path in SCRIPTS.rglob("*.py"):
        if "node_modules" in path.parts:
            continue
        n = len(_CHARSET_STRIP.findall(path.read_text(encoding="utf-8")))
        if n:
            hits[path.relative_to(SCRIPTS).as_posix()] = n
    assert hits == _ALLOWED, f"use shared._paths.strip_dot_slash instead: {hits}"
