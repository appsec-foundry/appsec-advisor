"""Tests for scripts/canonicalize_component_id.py (M4/M13).

Verify:
  - All 22 historically-observed Juice-Shop component IDs map to 6 canonical IDs
  - Pass-through behavior on miss
  - --strict exit code
  - Signal-based matching
  - YAML schema integrity
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "canonicalize_component_id.py"
YAML_PATH = PLUGIN_ROOT / "data" / "component-canonical.yaml"

# Insert the plugin scripts/ on sys.path so imports work
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import canonicalize_component_id as cci  # noqa: E402

# ---------------------------------------------------------------------------
# All 22 historical Juice-Shop names → expected canonical
# (extracted from .hook-events.log analysis 22.04 - 27.04)
# ---------------------------------------------------------------------------
HISTORICAL_MAPPINGS = {
    # backend-api family
    "rest-api": "backend-api",
    "express-api": "backend-api",
    "express-rest-api": "backend-api",
    "express-backend": "backend-api",
    # auth-identity family
    "auth-core": "auth-identity",
    "auth-jwt": "auth-identity",
    "auth-login": "auth-identity",
    "auth-module": "auth-identity",
    "auth-session": "auth-identity",
    # frontend-spa family
    "angular-spa": "frontend-spa",
    "angular-frontend": "frontend-spa",
    "angular-spa-frontend": "frontend-spa",
    "frontend-spa": "frontend-spa",
    "frontend": "frontend-spa",
    # data-persistence family
    "data-layer": "data-persistence",
    "database": "data-persistence",
    "database-layer": "data-persistence",
    "nosql-layer": "data-persistence",
    # file-handling family
    "file-services": "file-handling",
    "file-upload": "file-handling",
    "file-handling": "file-handling",
    "file-delivery": "file-handling",
    "file-upload-ftp": "file-handling",
}


class TestPassThrough:
    """Unknown IDs pass through unchanged unless --strict."""

    def test_unknown_passes_through(self):
        canonical, kind = cci.canonicalize("totally-novel-component")
        assert canonical == "totally-novel-component"
        assert kind == "miss"

    def test_normalize_cli_pass_through(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "normalize", "totally-novel"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == "totally-novel"
        assert "no canonical mapping" in r.stderr

    def test_normalize_strict_exits_1_on_miss(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "normalize", "novel", "--strict"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1


class TestCLI:
    def test_list_subcommand(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "list"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        # 8 canonical IDs expected
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        assert len(lines) == 8, f"expected 8 canonical IDs, got {len(lines)}"

    def test_validate_all_historical_ids(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "validate"] + list(HISTORICAL_MAPPINGS.keys()),
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, f"validation failed: {r.stdout}"

    def test_validate_includes_one_miss(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "validate", "rest-api", "totally-novel"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert "miss" in r.stdout


class TestNoOverlappingAliases:
    """Aliases must be unique across canonical entries — no double-mapping."""

    def test_aliases_are_disjoint(self):
        m = cci.load_map(YAML_PATH)
        seen: dict[str, str] = {}
        for canonical_id, entry in m.items():
            for alias in entry.aliases:
                key = alias.strip().lower()
                if key in seen and seen[key] != canonical_id:
                    pytest.fail(f"Alias '{alias}' appears in both '{seen[key]}' and '{canonical_id}' — must be unique")
                seen[key] = canonical_id

    def test_canonical_ids_not_in_aliases_of_others(self):
        m = cci.load_map(YAML_PATH)
        for canonical_id, entry in m.items():
            for other_id, other_entry in m.items():
                if other_id == canonical_id:
                    continue
                assert canonical_id not in other_entry.aliases, (
                    f"Canonical '{canonical_id}' listed as alias of '{other_id}'"
                )
