"""Drift-guard tests for the haiku-economy routing tier.

Pins the per-depth × per-agent model assignment so future edits to
``scripts/resolve_config.py → EXTENDED_MODEL_MATRIX`` cannot silently
drift away from the documented routing policy.

Routing policy (mirrors CLAUDE.md §2.3):

| Agent              | Quick  | Standard | Thorough |
|--------------------|--------|----------|----------|
| context-resolver   | Haiku  | Haiku    | Haiku    |
| recon-scanner      | Haiku  | Sonnet   | Sonnet   |
| qa-routine         | Haiku  | Haiku    | Sonnet   |
| qa-content         | Sonnet | Sonnet   | Sonnet   |
| config-scanner     | Haiku  | Haiku    | Haiku    |
| orchestrator       | Sonnet | Sonnet   | Sonnet   |
| stride/triage/merger | Sonnet | Sonnet | Sonnet   | (via MODEL_MATRIX)
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


HAIKU = "claude-haiku-4-5"
SONNET = "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# Per-depth routing assertions — one row per (depth × agent)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("depth,agent,expected", [
    # Quick — broadest Haiku surface
    ("quick",    "context_resolver", HAIKU),
    ("quick",    "recon_scanner",    HAIKU),
    ("quick",    "qa_routine",       HAIKU),
    ("quick",    "qa_content",       SONNET),
    ("quick",    "config_scanner",   HAIKU),
    ("quick",    "orchestrator",     SONNET),
    # Standard — recon back to Sonnet (24+ Cats deep)
    ("standard", "context_resolver", HAIKU),
    ("standard", "recon_scanner",    SONNET),
    ("standard", "qa_routine",       HAIKU),
    ("standard", "qa_content",       SONNET),
    ("standard", "config_scanner",   HAIKU),
    ("standard", "orchestrator",     SONNET),
    # Thorough — only context-resolver + config-scanner stay Haiku
    ("thorough", "context_resolver", HAIKU),
    ("thorough", "recon_scanner",    SONNET),
    ("thorough", "qa_routine",       SONNET),
    ("thorough", "qa_content",       SONNET),
    ("thorough", "config_scanner",   HAIKU),
    ("thorough", "orchestrator",     SONNET),
])
def test_haiku_economy_routing(depth, agent, expected):
    rc = _load_resolver()
    out = rc.resolve_extended_models("haiku-economy", depth)
    assert out[f"{agent}_model"] == expected, (
        f"haiku-economy + {depth} → {agent} expected {expected!r}, "
        f"got {out[f'{agent}_model']!r}"
    )


# ---------------------------------------------------------------------------
# Default tier (sonnet/opus-cheap/opus) — must be unchanged from today
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tier", ["sonnet", "opus-cheap", "opus"])
@pytest.mark.parametrize("depth", ["quick", "standard", "thorough"])
def test_default_tiers_keep_sonnet_for_extended_agents(tier, depth):
    """sonnet/opus-cheap/opus tiers route extended agents to Sonnet
    (= pre-haiku-economy behaviour). Haiku is reached via the
    haiku-economy tier — the default at quick depth, opt-in elsewhere."""
    rc = _load_resolver()
    out = rc.resolve_extended_models(tier, depth)
    for key in [
        "context_resolver_model",
        "recon_scanner_model",
        "qa_routine_model",
        "qa_content_model",
        "config_scanner_model",
        "orchestrator_model",
    ]:
        assert out[key] == SONNET, (
            f"{tier} + {depth}: {key} must be Sonnet for backward compat"
        )


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


# ---------------------------------------------------------------------------
# Env-var overrides — finest-grained control for debugging
# ---------------------------------------------------------------------------


def test_env_override_per_agent(monkeypatch):
    rc = _load_resolver()
    monkeypatch.setenv("APPSEC_CONTEXT_RESOLVER_MODEL", "claude-opus-4-7")
    out = rc.resolve_extended_models("haiku-economy", "quick")
    assert out["context_resolver_model"] == "claude-opus-4-7"
    # Other agents still follow the routing
    assert out["recon_scanner_model"] == HAIKU


# ---------------------------------------------------------------------------
# Configuration-summary rendering — pin the Reasoning + STRIDE Profile lines
# ---------------------------------------------------------------------------


def _minimal_cfg(reasoning_mode="sonnet", stride_label="full",
                 reasoning_label=None):
    """Build a minimum cfg dict that satisfies render_configuration_summary."""
    if reasoning_label is None:
        reasoning_label = (
            f"{reasoning_mode} (STRIDE: claude-sonnet-4-6, "
            f"triage: claude-sonnet-4-6, merger: claude-sonnet-4-6)"
        )
    return {
        "repo_root": "/repo",
        "output_dir": "/repo/docs/security",
        "plugin_version": "0.9.0-beta",
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
    cfg = _minimal_cfg(reasoning_mode="haiku-economy",
                       stride_label="quick (depth-reduced via haiku-economy)")
    out = rc.render_configuration_summary(cfg)
    assert "Reasoning    : haiku-economy" in out
    assert "STRIDE Prof. : quick (depth-reduced via haiku-economy)" in out


def test_summary_shows_reasoning_line_for_sonnet_default():
    """Reasoning is now always rendered — users see the resolved STRIDE /
    triage / merger model trio even at the silent default tier."""
    rc = _load_resolver()
    cfg = _minimal_cfg(reasoning_mode="sonnet")
    out = rc.render_configuration_summary(cfg)
    assert "Reasoning    : sonnet" in out
    # STRIDE Prof. line is gated on a non-"full" profile label.
    assert "STRIDE Prof" not in out


def test_summary_shows_reasoning_line_for_opus_cheap():
    rc = _load_resolver()
    cfg = _minimal_cfg(reasoning_mode="opus-cheap")
    out = rc.render_configuration_summary(cfg)
    assert "Reasoning    : opus-cheap" in out
