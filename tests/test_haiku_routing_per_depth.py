"""Drift-guard tests for the haiku-economy routing tier.

Pins the per-depth × per-agent model assignment so future edits to
``scripts/resolve_config.py → EXTENDED_MODEL_MATRIX`` cannot silently
drift away from the documented routing policy.

Routing policy (verified against agent specs):

| Agent              | Quick  | Standard | Thorough |
|--------------------|--------|----------|----------|
| context-resolver   | Haiku  | Haiku    | Haiku    |
| recon-scanner      | Haiku  | Haiku    | Haiku    |
| qa-routine         | Haiku  | Haiku    | Sonnet   |
| qa-content         | Sonnet | Sonnet   | Sonnet   |
| config-scanner     | Haiku  | Haiku    | Haiku    |
| orchestrator       | Sonnet | Sonnet   | Sonnet   |
| stride/triage/merger | Sonnet | Sonnet | Sonnet   | (via MODEL_MATRIX)

Default tier (sonnet / opus-cheap / opus) routes the three pure-extraction
agents (context-resolver, recon-scanner, config-scanner) to Haiku as well —
their workload is deterministic regardless of which reasoning tier the user
picked for STRIDE / triage / merger. Override per-agent via env var:
APPSEC_<AGENT>_MODEL.
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


# Version-less aliases — the resolver emits these short names so the run
# always binds to the latest model of each tier. Tests pin the alias, never
# a pinned version, so a model bump never breaks the routing drift-guard.
HAIKU = "haiku"
SONNET = "sonnet"


# ---------------------------------------------------------------------------
# Per-depth routing assertions — one row per (depth × agent)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "depth,agent,expected",
    [
        # Quick — pure-extraction agents on Haiku, qa_content + orchestrator on Sonnet.
        ("quick", "context_resolver", HAIKU),
        ("quick", "recon_scanner", HAIKU),
        ("quick", "qa_routine", HAIKU),
        ("quick", "qa_content", SONNET),
        ("quick", "config_scanner", HAIKU),
        ("quick", "orchestrator", SONNET),
        # Standard — same as quick. Recon stays on Haiku because the agent's
        # workload (28 grep categories + lookup-table verdicts) is structured
        # enough for Haiku regardless of repo size.
        ("standard", "context_resolver", HAIKU),
        ("standard", "recon_scanner", HAIKU),
        ("standard", "qa_routine", HAIKU),
        ("standard", "qa_content", SONNET),
        ("standard", "config_scanner", HAIKU),
        ("standard", "orchestrator", SONNET),
        # Thorough — qa_routine moves to Sonnet (denser cross-refs in bigger
        # documents); the three pure-extraction agents stay on Haiku.
        ("thorough", "context_resolver", HAIKU),
        ("thorough", "recon_scanner", HAIKU),
        ("thorough", "qa_routine", SONNET),
        ("thorough", "qa_content", SONNET),
        ("thorough", "config_scanner", HAIKU),
        ("thorough", "orchestrator", SONNET),
    ],
)
def test_haiku_economy_routing(depth, agent, expected):
    rc = _load_resolver()
    out = rc.resolve_extended_models("haiku-economy", depth)
    assert out[f"{agent}_model"] == expected, (
        f"haiku-economy + {depth} → {agent} expected {expected!r}, got {out[f'{agent}_model']!r}"
    )


# ---------------------------------------------------------------------------
# Default tier (sonnet/opus-cheap/opus) — must be unchanged from today
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tier", ["sonnet", "opus-cheap", "opus"])
@pytest.mark.parametrize("depth", ["quick", "standard", "thorough"])
def test_default_tier_extraction_agents_on_haiku(tier, depth):
    """sonnet/opus-cheap/opus tiers route pure-extraction agents
    (context-resolver, recon-scanner, config-scanner) to Haiku — the
    workload is deterministic so the reasoning tier is irrelevant.
    The remaining agents follow the tier's quality floor."""
    rc = _load_resolver()
    out = rc.resolve_extended_models(tier, depth)
    # Pure-extraction → Haiku regardless of tier
    assert out["context_resolver_model"] == HAIKU
    assert out["recon_scanner_model"] == HAIKU
    assert out["config_scanner_model"] == HAIKU
    # Reasoning-bearing → Sonnet at default tier (quality floor)
    assert out["qa_routine_model"] == SONNET
    assert out["qa_content_model"] == SONNET
    assert out["orchestrator_model"] == SONNET


# ---------------------------------------------------------------------------
# Invariants — the entire point of haiku-economy is preserved
# ---------------------------------------------------------------------------


def test_qa_content_never_haiku():
    """QA content fixes (invariants/ms_structure/contract) must always
    use Sonnet — the split-mode design protects content reasoning."""
    rc = _load_resolver()
    for depth in ("quick", "standard", "thorough"):
        out = rc.resolve_extended_models("haiku-economy", depth)
        assert out["qa_content_model"] == SONNET


def test_orchestrator_never_haiku():
    """Orchestrator handles Phase 3-7 architectural content + Phase 11
    fragments — never on Haiku."""
    rc = _load_resolver()
    for depth in ("quick", "standard", "thorough"):
        out = rc.resolve_extended_models("haiku-economy", depth)
        assert out["orchestrator_model"] == SONNET


def test_context_resolver_always_haiku_in_haiku_economy():
    """File-IO + structured-summary task — Haiku in every depth."""
    rc = _load_resolver()
    for depth in ("quick", "standard", "thorough"):
        out = rc.resolve_extended_models("haiku-economy", depth)
        assert out["context_resolver_model"] == HAIKU


def test_config_scanner_always_haiku_in_haiku_economy():
    """Pattern-matching against YAML rule list — Haiku in every depth."""
    rc = _load_resolver()
    for depth in ("quick", "standard", "thorough"):
        out = rc.resolve_extended_models("haiku-economy", depth)
        assert out["config_scanner_model"] == HAIKU


def test_recon_scanner_always_haiku_in_haiku_economy():
    """28 grep categories + lookup-table verdicts (severity by ecosystem,
    repo-visibility-conditional severity for self-hosted runners, etc.)
    — all decision-table-driven, Haiku-suitable in every depth."""
    rc = _load_resolver()
    for depth in ("quick", "standard", "thorough"):
        out = rc.resolve_extended_models("haiku-economy", depth)
        assert out["recon_scanner_model"] == HAIKU


def test_extraction_trio_always_haiku_in_default_tiers():
    """The pure-extraction agents stay on Haiku even at the default
    sonnet/opus-cheap/opus tiers — the user's tier choice expresses
    a preference about STRIDE/triage/merger reasoning quality, not
    about deterministic preprocessing."""
    rc = _load_resolver()
    for tier in ("sonnet", "opus-cheap", "opus"):
        for depth in ("quick", "standard", "thorough"):
            out = rc.resolve_extended_models(tier, depth)
            assert out["context_resolver_model"] == HAIKU
            assert out["recon_scanner_model"] == HAIKU
            assert out["config_scanner_model"] == HAIKU


# ---------------------------------------------------------------------------
# Env-var overrides — finest-grained control for debugging
# ---------------------------------------------------------------------------


def test_env_override_per_agent(monkeypatch):
    rc = _load_resolver()
    monkeypatch.setenv("APPSEC_CONTEXT_RESOLVER_MODEL", "opus")
    out = rc.resolve_extended_models("haiku-economy", "quick")
    assert out["context_resolver_model"] == "opus"
    # Other agents still follow the routing
    assert out["recon_scanner_model"] == HAIKU


# ---------------------------------------------------------------------------
# Configuration-summary rendering — pin the Reasoning + STRIDE Profile lines
# ---------------------------------------------------------------------------


def _minimal_cfg(reasoning_mode="sonnet", stride_label="full", reasoning_label=None):
    """Build a minimum cfg dict that satisfies render_configuration_summary."""
    if reasoning_label is None:
        reasoning_label = (
            f"{reasoning_mode} (STRIDE: sonnet, triage: sonnet, merger: sonnet)"
        )
    return {
        "repo_root": "/repo",
        "output_dir": "/repo/docs/security",
        "plugin_version": "0.4.0-beta",
        "analysis_version": 2,
        "mode_label": "full",
        "mode": "full",
        "depth_label": "quick",
        "requirements_label": "disabled",
        "reasoning_model": reasoning_mode,
        "reasoning_label": reasoning_label,
        "stride_profile": {"stride_profile_label": stride_label},
    }


def test_summary_shows_reasoning_line_for_haiku_economy():
    rc = _load_resolver()
    cfg = _minimal_cfg(reasoning_mode="haiku-economy", stride_label="quick (depth-reduced via haiku-economy)")
    out = rc.render_configuration_summary(cfg)
    assert "Reasoning : haiku-economy" in out
    assert "STRIDE    : quick (depth-reduced via haiku-economy)" in out


def test_summary_shows_reasoning_line_for_sonnet_default():
    """Reasoning is now always rendered — users see the resolved STRIDE /
    triage / merger model trio even at the silent default tier."""
    rc = _load_resolver()
    cfg = _minimal_cfg(reasoning_mode="sonnet")
    out = rc.render_configuration_summary(cfg)
    assert "Reasoning : sonnet" in out
    # STRIDE Prof. line is gated on a non-"full" profile label.
    assert "STRIDE    :" not in out


def test_summary_shows_reasoning_line_for_opus_cheap():
    rc = _load_resolver()
    cfg = _minimal_cfg(reasoning_mode="opus-cheap")
    out = rc.render_configuration_summary(cfg)
    assert "Reasoning : opus-cheap" in out
