"""Tests for data/config-iac-checks.yaml.

The checks are evaluated by the appsec-config-scanner agent (LLM), so there is
no deterministic runtime that exercises them. These tests guard the two things
a data-only change can still break: every regex must compile, and the specific
`expect: absent` / `expect: present` semantics must match the intended
target-vs-noise behaviour.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

CHECKS_PATH = Path(__file__).parent.parent / "data" / "config-iac-checks.yaml"


def _load_checks() -> list[dict]:
    data = yaml.safe_load(CHECKS_PATH.read_text(encoding="utf-8"))
    return data["checks"]


def _check(check_id: str) -> dict:
    for c in _load_checks():
        if c.get("id") == check_id:
            return c
    raise AssertionError(f"check {check_id} not found")


def test_every_check_regex_compiles():
    for c in _load_checks():
        pat = c.get("pattern")
        if not isinstance(pat, str):
            continue
        try:
            re.compile(pat)
        except re.error as e:  # pragma: no cover - failure path
            raise AssertionError(f"{c.get('id')} pattern does not compile: {e}")


def test_iac005_npm_ignore_scripts_only_fires_on_actual_js_install():
    """Regression for the insecure-spring-app T-054 false positive: the npm
    --ignore-scripts check must not fire on a Dockerfile that uses no JS
    package manager at all. It flags the BAD pattern (a JS install missing
    --ignore-scripts) via `expect: absent`, not the good flag's global absence."""
    c = _check("IAC-005")
    assert c["expect"] == "absent", "IAC-005 must flag the bad pattern, not require the good one globally"
    rx = re.compile(c["pattern"])

    # A Maven/Java image with no npm/pnpm/yarn — must NOT match (no finding).
    java_dockerfile = "FROM openjdk:17-slim\nRUN apt-get install -y curl\nCOPY . /app\n"
    assert not rx.search(java_dockerfile)

    # A Node image whose install is hardened — must NOT match (no finding).
    good_node = "FROM node:20\nRUN npm ci --ignore-scripts\n"
    assert not rx.search(good_node)

    # A Node image whose install is unhardened — MUST match (finding fires).
    assert rx.search("FROM node:20\nRUN npm ci --production\n")
    assert rx.search("RUN yarn install --frozen-lockfile\n")
