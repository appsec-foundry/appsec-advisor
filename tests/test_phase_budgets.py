"""Unit tests for scripts/phase_budgets.py — shared phase budget loader."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "phase_budgets.py"


def _load():
    spec = importlib.util.spec_from_file_location("phase_budgets", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["phase_budgets"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _reset_module_cache():
    """Each test starts with a fresh cache so YAML re-loads are honoured."""
    pb = _load()
    pb.reset_cache()
    yield
    pb.reset_cache()


# ---------------------------------------------------------------------------
# Budget table integrity (drift guard against hard-coded fallback values)
# ---------------------------------------------------------------------------


def test_three_depths_present():
    pb = _load()
    cfg = pb._load()  # noqa: SLF001
    assert set(cfg["budgets"].keys()) >= {"quick", "standard", "thorough"}


def test_known_phase_quick_budget():
    pb = _load()
    # Phase 9 quick = 180s in the YAML; multiplier 1.5 → 270s.
    assert pb.threshold_for_phase("9", "quick") == 270


def test_known_phase_thorough_budget():
    pb = _load()
    # Phase 11 thorough = 900s; × 1.5 = 1350s.
    assert pb.threshold_for_phase("11", "thorough") == 1350


def test_unlisted_phase_uses_unlisted_fallback():
    pb = _load()
    # Phases 4-8 have no entry → unlisted_phase_fallback (180) × 1.5 = 270.
    for ph in ("4", "5", "6", "7", "8"):
        assert pb.threshold_for_phase(ph, "standard") == 270, ph


def test_no_phase_uses_heartbeat_default():
    pb = _load()
    # No phase context at all → depth-agnostic default (300 s).
    assert pb.threshold_for_phase(None, "standard") == 300
    assert pb.threshold_for_phase("", "standard") == 300


def test_explicit_multiplier_overrides_default():
    pb = _load()
    # Phase 9 quick = 180; × 1.0 = 180.
    assert pb.threshold_for_phase("9", "quick", multiplier=1.0) == 180
    # × 3.0 = 540.
    assert pb.threshold_for_phase("9", "quick", multiplier=3.0) == 540


def test_hard_ceiling_is_enforced():
    pb = _load()
    # Phase 11 thorough × 5.0 = 4500 → clamped to ceiling (1800).
    assert pb.threshold_for_phase("11", "thorough", multiplier=5.0) == 1800


def test_unknown_depth_falls_back_to_standard():
    pb = _load()
    # 'lightning' is not a real depth; should mirror standard.
    assert pb.threshold_for_phase("9", "lightning") == pb.threshold_for_phase("9", "standard")


def test_default_helpers_return_documented_values():
    pb = _load()
    assert pb.default_heartbeat_stale_seconds() == 300
    assert pb.unlisted_phase_fallback_seconds() == 180
    assert pb.hard_ceiling_seconds() == 1800
    assert pb.default_stall_multiplier() == 1.5


# ---------------------------------------------------------------------------
# Fallback parser — runs when PyYAML is absent on the host.
# ---------------------------------------------------------------------------


def test_minimal_yaml_parser_round_trip():
    pb = _load()
    text = """
phase_budgets_seconds:
  quick:
    "1": 100
    "9": 200
defaults:
  heartbeat_stale_seconds: 250
"""
    parsed = pb._minimal_yaml_parse(text)  # noqa: SLF001
    assert parsed["phase_budgets_seconds"]["quick"]["1"] == 100
    assert parsed["phase_budgets_seconds"]["quick"]["9"] == 200
    assert parsed["defaults"]["heartbeat_stale_seconds"] == 250


def test_minimal_yaml_parser_handles_inline_comments():
    pb = _load()
    text = """
phase_budgets_seconds:  # top-level
  standard:
    "9": 360  # production budget
"""
    parsed = pb._minimal_yaml_parse(text)  # noqa: SLF001
    assert parsed["phase_budgets_seconds"]["standard"]["9"] == 360


# ---------------------------------------------------------------------------
# Fallback when YAML is missing (drift guard against silent regression)
# ---------------------------------------------------------------------------


def test_fallback_table_matches_legacy_constants(monkeypatch):
    """When data/phase-budgets.yaml is unreachable, the loader must serve the
    historical hard-coded values so v1 callers (acquire_lock + check_state
    pre-M3.6) keep behaving identically."""
    pb = _load()

    def _missing():
        return Path("/nonexistent/phase-budgets.yaml")

    monkeypatch.setattr(pb, "_yaml_path", _missing)
    pb.reset_cache()

    cfg = pb._load()  # noqa: SLF001
    assert cfg["budgets"]["quick"]["9"] == 180
    assert cfg["budgets"]["standard"]["10b"] == 120
    assert cfg["defaults"]["heartbeat_stale_seconds"] == 300


# ---------------------------------------------------------------------------
# _yaml_path resolution — env var vs __file__ relative.
# ---------------------------------------------------------------------------


def test_yaml_path_uses_plugin_root_env(monkeypatch):
    pb = _load()
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", "/some/plugin")
    p = pb._yaml_path()  # noqa: SLF001
    assert p == Path("/some/plugin") / "data" / "phase-budgets.yaml"


def test_yaml_path_falls_back_to_file_relative(monkeypatch):
    pb = _load()
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
    p = pb._yaml_path()  # noqa: SLF001
    # Resolves relative to the script's parent.parent/data.
    assert p.name == "phase-budgets.yaml"
    assert p.parent.name == "data"


# ---------------------------------------------------------------------------
# _try_pyyaml branches.
# ---------------------------------------------------------------------------


def test_try_pyyaml_non_dict_returns_none():
    pb = _load()
    # A bare scalar / list is valid YAML but not a mapping → None.
    assert pb._try_pyyaml("- a\n- b\n") is None  # noqa: SLF001
    assert pb._try_pyyaml("just a string") is None  # noqa: SLF001


def test_try_pyyaml_parses_mapping():
    pb = _load()
    out = pb._try_pyyaml("a: 1\nb: 2\n")  # noqa: SLF001
    assert out == {"a": 1, "b": 2}


def test_try_pyyaml_invalid_returns_none():
    pb = _load()
    # Malformed YAML triggers the except branch.
    assert pb._try_pyyaml("a: [1, 2\n  bad") is None  # noqa: SLF001


# ---------------------------------------------------------------------------
# _minimal_yaml_parse edge cases (comment-only lines, float coercion,
# valueless keys, single-quote stripping).
# ---------------------------------------------------------------------------


def test_minimal_yaml_parse_float_and_comment_only_lines():
    pb = _load()
    text = """
# pure comment line
defaults:
  stall_multiplier: 1.5
  # nested comment
  name: 'quoted'
  novalue:   # a key with only a trailing comment becomes a scope
"""
    parsed = pb._minimal_yaml_parse(text)  # noqa: SLF001
    assert parsed["defaults"]["stall_multiplier"] == 1.5
    assert parsed["defaults"]["name"] == "quoted"
    # `novalue:` followed by nothing → opens a (empty) nested scope.
    assert parsed["defaults"]["novalue"] == {}


def test_minimal_yaml_parse_line_with_no_colon_ignored():
    pb = _load()
    text = "defaults:\n  bareword\n  k: 1\n"
    parsed = pb._minimal_yaml_parse(text)  # noqa: SLF001
    assert parsed["defaults"]["k"] == 1
    assert "bareword" not in parsed["defaults"]


def test_minimal_yaml_parse_comment_strips_to_empty_skips():
    pb = _load()
    # A line that is whitespace + inline comment after a value-bearing key.
    text = "defaults:\n  k: 5  # trailing\n  # full comment\n"
    parsed = pb._minimal_yaml_parse(text)  # noqa: SLF001
    assert parsed["defaults"]["k"] == 5


# ---------------------------------------------------------------------------
# _load fallback when parse yields no usable budgets/defaults.
# ---------------------------------------------------------------------------


def test_load_falls_back_when_pyyaml_and_minimal_both_fail(monkeypatch, tmp_path):
    pb = _load()
    bad = tmp_path / "phase-budgets.yaml"
    bad.write_text("phase_budgets_seconds:\n  quick:\n    '9': 180\n")
    monkeypatch.setattr(pb, "_yaml_path", lambda: bad)
    # Force both parsers to fail so the `parsed = None` path runs.
    monkeypatch.setattr(pb, "_try_pyyaml", lambda _t: None)

    def _boom(_t):
        raise RuntimeError("parser blew up")

    monkeypatch.setattr(pb, "_minimal_yaml_parse", _boom)
    pb.reset_cache()
    cfg = pb._load()  # noqa: SLF001
    # Both parsers failed → fall back to hard-coded budgets.
    assert cfg["budgets"]["standard"]["9"] == 360


def test_load_uses_fallback_when_budgets_not_a_dict(monkeypatch, tmp_path):
    pb = _load()
    f = tmp_path / "phase-budgets.yaml"
    f.write_text("x")
    monkeypatch.setattr(pb, "_yaml_path", lambda: f)
    # parsed dict has wrong-typed budgets + non-dict defaults.
    monkeypatch.setattr(pb, "_try_pyyaml", lambda _t: {"phase_budgets_seconds": [], "defaults": 7})
    pb.reset_cache()
    cfg = pb._load()  # noqa: SLF001
    assert cfg["budgets"]["quick"]["9"] == 180  # fallback budgets
    # Non-dict defaults replaced by {} then merged with fallback defaults.
    assert cfg["defaults"]["heartbeat_stale_seconds"] == 300


# ---------------------------------------------------------------------------
# budgets_for_depth copy semantics.
# ---------------------------------------------------------------------------


def test_budgets_for_depth_returns_fresh_copy():
    pb = _load()
    a = pb.budgets_for_depth("standard")
    a["9"] = -1
    b = pb.budgets_for_depth("standard")
    assert b["9"] != -1  # mutation did not leak into the cache


# ---------------------------------------------------------------------------
# CLI / main() — covers lines 250-279.
# ---------------------------------------------------------------------------


def test_main_no_args_prints_full_json(capsys):
    pb = _load()
    rc = pb.main(["phase_budgets.py"])
    assert rc == 0
    out = capsys.readouterr().out
    import json as _json

    data = _json.loads(out)
    assert "budgets" in data and "defaults" in data


def test_main_phase_arg_prints_bare_threshold(capsys):
    pb = _load()
    rc = pb.main(["phase_budgets.py", "9", "--depth", "quick"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == "270"  # 180 * 1.5


def test_main_phase_arg_json_flag(capsys):
    pb = _load()
    rc = pb.main(["phase_budgets.py", "9", "--depth", "quick", "--multiplier", "1.0", "--json"])
    assert rc == 0
    import json as _json

    data = _json.loads(capsys.readouterr().out)
    assert data["phase"] == "9"
    assert data["depth"] == "quick"
    assert data["multiplier"] == 1.0
    assert data["threshold_seconds"] == 180
