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
