"""Drift-guard tests for the Quick-mode STRIDE depth profile.

Pins the A-F depth-reduction values so future edits to
``scripts/resolve_config.py → QUICK_STRIDE_PROFILE`` cannot silently
drift away from the documented Quick-mode contract.

Profile (A-F, applies only when reasoning_mode=sonnet-economy AND
depth=quick):
  A. skip_verification_greps = True
  B. max_threats_per_category = 1   (Critical-safe: Criticals never dropped)
  C. skip_code_examples = False     (R9 — flipped 2026-05, kept actionable)
  D. skip_evidence_excerpt = False  (P3 — kept, restores §8 evidence)
  E. skip_cvss_scoring = True
  F. turn_budget_hard_cap = 25
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _load_resolver():
    spec = importlib.util.spec_from_file_location(
        "_rc",
        Path(__file__).parent.parent / "scripts" / "resolve_config.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Profile values — one assertion per A-F flag
# ---------------------------------------------------------------------------


def test_profile_active_quick_haiku_economy():
    rc = _load_resolver()
    out = rc.resolve_stride_profile("sonnet-economy", "quick")
    p = out["stride_profile"]

    assert p["skip_verification_greps"] is True, "A: verification greps must be off in Quick"
    assert p["max_threats_per_category"] == 1, "B: cap is 1 (Critical-safe quick triage)"
    assert p["skip_code_examples"] is False, "C: code_example KEPT at quick (R9 — flipped 2026-05)"
    # P3 (A6) re-balance — evidence excerpt is CHEAP to keep at quick (it's a
    # yaml-side string trim, not new prose) and dropping it stripped the §8
    # Findings Register Finding column and Linked Threats columns of every
    # descriptive substring. Flag flipped from True to False; the other A-F
    # reductions stay in place.
    assert p["skip_evidence_excerpt"] is False, "D: evidence excerpt KEPT at quick (P3 — A6 re-balance)"
    assert p["skip_cvss_scoring"] is True, "E: CVSS scoring forced-off"
    assert p["turn_budget_hard_cap"] == 25, "F: TURN_BUDGET cap 25 (was 40)"
    assert "depth-reduced" in p["stride_profile_label"]


# ---------------------------------------------------------------------------
# Opt-in semantics — profile only active for sonnet-economy + quick
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode,depth",
    [
        ("sonnet", "quick"),  # quick alone is NOT enough — opt-in via tier required
        ("sonnet", "standard"),
        ("sonnet", "thorough"),
        ("opus-cheap", "quick"),
        ("opus-cheap", "standard"),
        ("opus-cheap", "thorough"),
        ("opus", "quick"),
        ("opus", "standard"),
        ("opus", "thorough"),
        ("sonnet-economy", "standard"),  # sonnet-economy at non-quick: full STRIDE
        ("sonnet-economy", "thorough"),
    ],
)
def test_profile_full_outside_quick_haiku_economy(mode, depth):
    rc = _load_resolver()
    out = rc.resolve_stride_profile(mode, depth)
    p = out["stride_profile"]
    assert p["stride_profile_label"] == "full", f"{mode}+{depth} must keep full STRIDE depth — opt-in only"
    # No depth-reduction flags present
    for key in (
        "skip_verification_greps",
        "max_threats_per_category",
        "skip_code_examples",
        "skip_evidence_excerpt",
        "skip_cvss_scoring",
        "turn_budget_hard_cap",
    ):
        assert key not in p, f"{mode}+{depth} leaked {key!r} into full profile"


# ---------------------------------------------------------------------------
# Hard invariants — what MUST NOT be reduced (verifies that risky skips
# we explicitly rejected are not accidentally introduced)
# ---------------------------------------------------------------------------


def test_profile_does_not_skip_owasp_llm():
    """OWASP LLM Top 10 block stays conditional on KNOWN_LLM_PATTERNS,
    NOT forced-off. LLM-Threats can be Critical."""
    rc = _load_resolver()
    out = rc.resolve_stride_profile("sonnet-economy", "quick")
    p = out["stride_profile"]
    assert "skip_owasp_llm" not in p
    assert "skip_llm_top10" not in p


def test_profile_does_not_skip_supply_chain():
    """Supply-Chain block stays conditional on SUPPLY_CHAIN_FINDINGS."""
    rc = _load_resolver()
    out = rc.resolve_stride_profile("sonnet-economy", "quick")
    p = out["stride_profile"]
    assert "skip_supply_chain" not in p


def test_profile_does_not_skip_client_side():
    """Client-Side / SPA block stays active for frontend components."""
    rc = _load_resolver()
    out = rc.resolve_stride_profile("sonnet-economy", "quick")
    p = out["stride_profile"]
    assert "skip_client_side" not in p
    assert "skip_spa_analysis" not in p


def test_profile_does_not_skip_stride_categories():
    """All 6 STRIDE categories must always be enumerated.
    Output-Contract requires all 6 markers."""
    rc = _load_resolver()
    out = rc.resolve_stride_profile("sonnet-economy", "quick")
    p = out["stride_profile"]
    assert "skip_categories" not in p
    assert "stride_categories" not in p


# ---------------------------------------------------------------------------
# Opt-in --stride-cap N — a per-category threat cap that is ORTHOGONAL to the
# quick A-F profile and preserves full STRIDE depth at standard/thorough.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("depth", ["standard", "thorough"])
def test_stride_cap_injects_cap_at_full_depth(depth):
    """--stride-cap N at standard/thorough emits ONLY the per-category cap; the
    rest of full depth (no skip_cvss / skip_greps / evidence drop) is preserved."""
    rc = _load_resolver()
    out = rc.resolve_stride_profile("opus", depth, stride_cap=2)
    p = out["stride_profile"]
    assert p["max_threats_per_category"] == 2
    assert p["stride_profile_label"] == "full (per-category cap 2)"
    # No other A-F reduction leaked — full depth otherwise intact.
    for key in (
        "skip_verification_greps",
        "skip_code_examples",
        "skip_evidence_excerpt",
        "skip_cvss_scoring",
        "turn_budget_hard_cap",
    ):
        assert key not in p, f"{key!r} must not leak into a --stride-cap full profile"


def test_stride_cap_none_preserves_full_invariant():
    """No flag (None) keeps the documented 'standard = full, opt-in only' rule."""
    rc = _load_resolver()
    out = rc.resolve_stride_profile("opus", "standard", stride_cap=None)
    assert out["stride_profile"] == {"stride_profile_label": "full"}


@pytest.mark.parametrize("bad", [0, -1])
def test_stride_cap_non_positive_ignored(bad):
    """A non-positive cap is treated as 'no cap' (defensive)."""
    rc = _load_resolver()
    out = rc.resolve_stride_profile("opus", "standard", stride_cap=bad)
    assert out["stride_profile"] == {"stride_profile_label": "full"}


def test_stride_cap_overrides_quick_profile_value():
    """At quick+economy the A-F profile still applies, but --stride-cap overrides
    the cap VALUE (and is reflected in the label)."""
    rc = _load_resolver()
    out = rc.resolve_stride_profile("sonnet-economy", "quick", stride_cap=3)
    p = out["stride_profile"]
    assert p["max_threats_per_category"] == 3
    assert p["skip_cvss_scoring"] is True  # quick reductions still present
    assert "per-category cap 3" in p["stride_profile_label"]


def test_stride_cap_flag_parses_and_flows_through_resolver():
    """End-to-end: --stride-cap on the parser reaches the emitted profile."""
    rc = _load_resolver()
    ns = rc.build_parser().parse_args(["--stride-cap", "2"])
    assert ns.stride_cap == 2
    # default (no flag) parses to None
    ns0 = rc.build_parser().parse_args([])
    assert ns0.stride_cap is None
