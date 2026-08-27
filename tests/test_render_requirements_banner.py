"""Tests for the deterministic requirements-audit startup banner.

The banner is the only place the audit tells the user which catalog is in
effect and which requirements it is about to grade, so it must render from the
run state alone and degrade instead of failing when part of that state is
missing.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_requirements_banner.py"

spec = importlib.util.spec_from_file_location("render_requirements_banner", SCRIPT_PATH)
banner = importlib.util.module_from_spec(spec)
sys.modules["render_requirements_banner"] = banner
assert spec.loader is not None
spec.loader.exec_module(banner)


CATALOG = """
generated: '2026-04-09'
description: Acme Application Security Requirements
categories:
  - id: SEC-AUTH
    title: Authentication
    requirements:
      - id: SEC-AUTH-1
        priority: MUST
        text: Authenticate every protected route.
      - id: SEC-AUTH-2
        priority: SHOULD
        text: Rotate the session id on login.
  - id: SEC-LOG
    title: Logging
    requirements:
      - id: SEC-LOG-1
        priority: MAY
        text: Log authentication failures.
"""


def _write_state(tmp_path: Path, resolution: dict, catalog: str = CATALOG) -> Path:
    out = tmp_path / "security"
    out.mkdir()
    (out / ".requirements-resolution.json").write_text(json.dumps(resolution), encoding="utf-8")
    if catalog:
        (out / ".requirements.yaml").write_text(catalog, encoding="utf-8")
    return out


def test_banner_names_the_catalog_and_the_requirements_in_scope(tmp_path: Path) -> None:
    out = _write_state(
        tmp_path,
        {
            "source_kind": "remembered",
            "url": "https://acme.example/appsec.yaml",
            "description": "Acme Application Security Requirements",
            "disposition": "cache",
            "cache_path": "/plugin/.cache/requirements.yaml",
            "fetched_at": "2026-04-10T08:00:00Z",
            "generated": "2026-04-09",
            "count": 3,
            "freshness": {"stale": False},
        },
    )

    text = banner.build_banner(
        banner._load_json(out / ".requirements-resolution.json"),
        banner._load_catalog(out / ".requirements.yaml"),
    )

    assert "Acme Application Security Requirements" in text
    assert "Source   : remembered · https://acme.example/appsec.yaml" in text
    assert "Loaded   : plugin cache /plugin/.cache/requirements.yaml" in text
    assert "Count    : 3 requirements in 2 categories" in text
    assert "Scope (grading 3 of 3 requirements)" in text
    assert "Authentication" in text and "(1 MUST · 1 SHOULD)" in text
    assert "Logging" in text and "(1 MAY)" in text


def test_filter_narrows_the_scope_block(tmp_path: Path) -> None:
    out = _write_state(tmp_path, {"description": "Acme", "disposition": "cache", "cache_path": "/c.yaml"})

    text = banner.build_banner(
        banner._load_json(out / ".requirements-resolution.json"),
        banner._load_catalog(out / ".requirements.yaml"),
        category_filter="AUTH",
    )

    assert "Scope (grading 2 of 3 requirements, filter 'AUTH')" in text
    assert "Authentication" in text
    assert "Logging" not in text


def test_demo_and_stale_state_are_flagged(tmp_path: Path) -> None:
    out = _write_state(
        tmp_path,
        {
            "description": "Bundled example",
            "demo": True,
            "surfaced": True,
            "disposition": "cache_after_fetch_fail",
            "cache_path": "/c.yaml",
            "freshness": {"stale": True},
        },
    )

    text = banner.build_banner(
        banner._load_json(out / ".requirements-resolution.json"),
        banner._load_catalog(out / ".requirements.yaml"),
        gate_line="enforce · gate-on=fail · floor=MUST (from preset acme)",
    )

    assert "⚠ DEMO" in text
    assert "🟡 STALE" in text
    assert "using local repo catalog" in text
    assert "source unreachable this run" in text
    assert "Gate     : enforce · gate-on=fail · floor=MUST (from preset acme)" in text


def test_banner_degrades_without_a_catalog(tmp_path: Path) -> None:
    out = _write_state(tmp_path, {"description": "Acme", "count": 42, "disposition": "cache"}, catalog="")

    text = banner.build_banner(banner._load_json(out / ".requirements-resolution.json"), {})

    assert "Count    : 42 requirements" in text
    assert "Scope" not in text  # no catalog on disk → no invented scope block


def test_cli_reports_missing_state(tmp_path: Path, capsys) -> None:
    assert banner.main(["--output-dir", str(tmp_path)]) == 1
    assert "no requirements state" in capsys.readouterr().err


def test_cli_prints_the_banner(tmp_path: Path, capsys) -> None:
    out = _write_state(tmp_path, {"description": "Acme", "disposition": "cache", "cache_path": "/c.yaml"})

    assert banner.main(["--output-dir", str(out), "--filter", "LOG"]) == 0
    printed = capsys.readouterr().out
    assert "AppSec Requirements Audit" in printed
    assert "Scope (grading 1 of 3 requirements, filter 'LOG')" in printed
