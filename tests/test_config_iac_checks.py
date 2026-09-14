"""Focused rule semantics for the deterministic Config/IaC catalog."""

from __future__ import annotations

import re
from pathlib import Path

import build_threat_model_yaml as b
import merge_threats as mt
import yaml

CHECKS_PATH = Path(__file__).parent.parent / "data" / "config-iac-checks.yaml"
SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "threat-model.output.schema.yaml"


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


def test_every_check_titles_its_violation_not_its_desired_state():
    """A config finding is titled with the defect. The check `name` states the
    desired state ("... present and committed") and reads as a pass."""
    schema = yaml.safe_load(SCHEMA_PATH.read_text(encoding="utf-8"))
    rule = schema["properties"]["threats"]["items"]["properties"]["title"]
    pattern = re.compile(rule["pattern"])
    for c in _load_checks():
        title = c.get("violation_title")
        assert isinstance(title, str) and title.strip(), f"{c['id']} has no violation_title"
        assert title != c["name"], f"{c['id']} repeats its desired-state name"
        assert pattern.match(title), f"{c['id']}: {title!r} breaks the threat title pattern"
        assert rule["minLength"] <= len(title) <= rule["maxLength"], f"{c['id']}: {title!r} length"
        assert b._clean_title(title) == title, f"{c['id']}: {title!r} is rewritten by the title cleaner"


def test_violation_title_joins_the_same_consolidation_group_as_the_check_name():
    """Consolidation groups select config findings partly by title pattern,
    written against the check names. Titling a finding with its violation must
    not move its check into, out of, or between groups."""
    groups = mt._load_consolidation_groups()
    for c in _load_checks():

        def group(title: str, check: dict = c) -> str | None:
            threat = {
                "cwe": check["cwe"],
                "title": title,
                "evidence": {"file": check["file_pattern"], "line": 1},
                "config_check_id": check["id"],
                "source": "config-scan",
            }
            match = mt._match_consolidation_group(threat, groups)
            return match["id"] if match else None

        assert group(c["violation_title"]) == group(c["name"]), c["id"]


def test_category_inventory_covers_surface_alternatives():
    data = yaml.safe_load(CHECKS_PATH.read_text(encoding="utf-8"))
    patterns = data["file_patterns_by_type"]
    assert "**/.github/workflows/*.yaml" in patterns["github_workflow"]
    assert "**/compose*.yaml" in patterns["docker_compose"]
    assert "**/.github/dependabot.yaml" in patterns["dependabot"]
    assert "**/Dockerfile" in patterns["Dockerfile"]


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
