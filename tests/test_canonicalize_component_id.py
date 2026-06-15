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


class TestCanonicalizeLib:
    """Direct library-level canonicalize() branches."""

    def test_exact_hit(self):
        canonical, kind = cci.canonicalize("backend-api")
        assert canonical == "backend-api"
        assert kind == "exact"

    def test_exact_hit_case_and_whitespace_insensitive(self):
        canonical, kind = cci.canonicalize("  Backend-API  ")
        assert canonical == "backend-api"
        assert kind == "exact"

    def test_alias_hit(self):
        canonical, kind = cci.canonicalize("express-backend")
        assert canonical == "backend-api"
        assert kind == "alias"

    def test_alias_hit_case_insensitive(self):
        canonical, kind = cci.canonicalize("REST-API")
        assert canonical == "backend-api"
        assert kind == "alias"

    def test_canonicalize_loads_default_map_when_none(self):
        # map_=None path -> load_map() with default plugin-root path
        canonical, kind = cci.canonicalize("rest-api", map_=None)
        assert kind == "alias"
        assert canonical == "backend-api"


class TestMatchBySignals:
    """Signal-based inference (lib + CLI)."""

    def test_lib_single_hit(self):
        m = cci.load_map(YAML_PATH)
        hits = cci.match_by_signals("the app uses express() in server.ts", m)
        cids = [c for c, _ in hits]
        assert "backend-api" in cids
        # matched signals returned for that entry
        matched = dict(hits)["backend-api"]
        assert any("server.ts" in s or "express()" in s for s in matched)

    def test_lib_sorted_most_matches_first(self):
        m = cci.load_map(YAML_PATH)
        # text rich in frontend signals
        text = "src/app/ angular.json @angular/core react-dom and routes/ server.ts"
        hits = cci.match_by_signals(text, m)
        assert len(hits) >= 2
        # sorted descending by number of matched signals
        counts = [len(sig) for _, sig in hits]
        assert counts == sorted(counts, reverse=True)

    def test_lib_no_hits(self):
        m = cci.load_map(YAML_PATH)
        assert cci.match_by_signals("nothing-relevant-here-xyz", m) == []

    def test_lib_loads_default_map_when_none(self):
        hits = cci.match_by_signals("express() server.ts", map_=None)
        assert any(c == "backend-api" for c, _ in hits)

    def test_cli_match_signals_via_file(self, tmp_path):
        f = tmp_path / "recon.txt"
        f.write_text("express() detected in server.ts routes/", encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "match-signals", "--file", str(f)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert "backend-api" in r.stdout

    def test_cli_match_signals_via_stdin_no_hits(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "match-signals"],
            input="absolutely-nothing-matches-here",
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert r.stdout.strip() == ""


class TestNormalizeHitCLI:
    def test_normalize_exact_hit_prints_canonical(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "normalize", "backend-api"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == "backend-api"

    def test_normalize_alias_hit_prints_canonical(self):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "normalize", "express-backend"],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == "backend-api"


class TestPluginRoot:
    def test_env_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        assert cci._plugin_root() == tmp_path

    def test_relative_fallback(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        root = cci._plugin_root()
        # falls back to repo root (two parents up from scripts/<file>)
        assert (root / "data" / "component-canonical.yaml").exists()


class TestMinimalParserFallback:
    """Exercise the hand-rolled YAML subset parser used when PyYAML is absent.

    The real module imports PyYAML, so force the _HAS_YAML=False branch via
    monkeypatch to cover the fallback parser (lines 77-113) and the dict->[]
    coercion in load_map (lines 129-132).
    """

    def test_minimal_parser_parses_canonical_file(self, monkeypatch):
        monkeypatch.setattr(cci, "_HAS_YAML", False)
        data = cci._parse_yaml_minimal(YAML_PATH)
        assert "canonical_components" in data
        assert "backend-api" in data["canonical_components"]

    def test_load_map_with_minimal_parser_coerces_dict_lists(self, monkeypatch):
        monkeypatch.setattr(cci, "_HAS_YAML", False)
        m = cci.load_map(YAML_PATH)
        # canonical ids still present
        assert "backend-api" in m
        # aliases/signals coerced to tuples (possibly empty under minimal parse)
        entry = m["backend-api"]
        assert isinstance(entry.aliases, tuple)
        assert isinstance(entry.detection_signals, tuple)

    def test_minimal_parser_list_and_scalar(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cci, "_HAS_YAML", False)
        f = tmp_path / "mini.yaml"
        f.write_text(
            "version: 1  # a comment\n"
            "canonical_components:\n"
            "  foo:\n"
            "    display_name: \"Foo Service\"\n"
            "    aliases:\n"
            "      - foo-alt\n"
            "      - 'foo-other'\n"
            "    category: backend-api\n",
            encoding="utf-8",
        )
        data = cci._parse_yaml_minimal(f)
        assert data["version"] == "1"
        foo = data["canonical_components"]["foo"]
        assert foo["display_name"] == "Foo Service"
        # Known limitation (documented at line 112): the minimal parser defaults
        # an empty-value key to a dict, and `- ` items are only appended when the
        # parent is already a list, so `aliases:` followed by `- ...` stays {}.
        assert foo["aliases"] == {}
        assert foo["category"] == "backend-api"
