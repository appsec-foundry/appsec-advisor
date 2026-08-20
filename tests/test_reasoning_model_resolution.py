"""Tests for the --reasoning-model flag resolution matrix.

Since M3.2 the actual resolver lives in ``scripts/resolve_config.py`` and is
covered in depth by ``tests/test_resolve_config.py``. The tests here guard
against drift between the resolver (Python) and the downstream consumers
that still reference the resolved env-vars by name — i.e. the agent
definitions and compact runtimes that dispatch sub-agents with these model
parameters. Touching any of:

    * scripts/resolve_config.py                  (source of truth)
    * skills/create-threat-model/SKILL.md        (must mention the flag + delegate)
    * scripts/orchestration_controller.py        (must own role routing)
    * docs/model-selection.md                    (user-facing model choices)

without updating the others will surface here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SKILL_MD = ROOT / "skills" / "create-threat-model" / "SKILL.md"
SKILL_FULL_RUNTIME_MD = ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md"
SKILL_RERENDER_RUNTIME_MD = ROOT / "skills" / "create-threat-model" / "SKILL-rerender-runtime.md"
HELP_TXT = ROOT / "skills" / "create-threat-model" / "HELP.txt"
MODEL_SELECTION_MD = ROOT / "docs" / "model-selection.md"
RESOLVE_CONFIG_PY = ROOT / "scripts" / "resolve_config.py"
CONTROLLER_PY = ROOT / "scripts" / "orchestration_controller.py"


def _load_resolver():
    if "resolve_config" in sys.modules:
        return sys.modules["resolve_config"]
    spec = importlib.util.spec_from_file_location("resolve_config", RESOLVE_CONFIG_PY)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["resolve_config"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def skill_text() -> str:
    """Concatenated live routing, runtime, and help surfaces."""
    return "\n".join(
        path.read_text() for path in (SKILL_MD, SKILL_FULL_RUNTIME_MD, SKILL_RERENDER_RUNTIME_MD, HELP_TXT)
    )


@pytest.fixture(scope="module")
def skill_router_text() -> str:
    """SKILL.md alone — for tests that specifically target the router stub."""
    return SKILL_MD.read_text()


# ---------------------------------------------------------------------------
# Flag is documented + skill delegates to resolve_config.py
# ---------------------------------------------------------------------------


class TestFlagDocumented:
    def test_flag_appears_in_skill_md(self, skill_text):
        assert "--reasoning-model" in skill_text, "SKILL.md must document --reasoning-model"

    def test_controller_delegates_to_resolve_config(self):
        assert "import resolve_config" in CONTROLLER_PY.read_text()


# ---------------------------------------------------------------------------
# Resolver matrix — three modes, three variables per mode
# ---------------------------------------------------------------------------


class TestResolverMatrix:
    def test_modes_present(self):
        rc = _load_resolver()
        assert set(rc.MODEL_MATRIX.keys()) == {
            "sonnet",
            "opus-cheap",
            "opus",
            "sonnet-economy",
        }

    @pytest.mark.parametrize("key", ["stride", "triage", "merger"])
    def test_every_mode_has_three_slots(self, key):
        rc = _load_resolver()
        for mode, models in rc.MODEL_MATRIX.items():
            assert key in models, f"{mode!r} mode missing {key!r} slot"

    def test_opus_cheap_differentiator(self):
        """opus-cheap's raison d'être: STRIDE + triage on Sonnet, merger on Opus.

        Triage stays on Sonnet because scripts/triage_validate_ratings.py is
        the deterministic floor — the agent only does judgment validation on
        top of structured input. Opus reasoning here is overkill.
        """
        rc = _load_resolver()
        m = rc.MODEL_MATRIX["opus-cheap"]
        assert "sonnet" in m["stride"]
        assert "sonnet" in m["triage"]
        assert "opus" in m["merger"]

    def test_haiku_economy_keeps_stride_on_sonnet(self):
        """sonnet-economy MUST NOT downgrade STRIDE/triage/merger.
        Threat-Reasoning is the tool's primary value contribution."""
        rc = _load_resolver()
        m = rc.MODEL_MATRIX["sonnet-economy"]
        assert "sonnet" in m["stride"]
        assert "sonnet" in m["triage"]
        assert "sonnet" in m["merger"]


# ---------------------------------------------------------------------------
# Backward-compat: deprecated ``haiku-economy`` alias → ``sonnet-economy``
# ---------------------------------------------------------------------------


class TestHaikuEconomyAlias:
    """The tier was renamed haiku-economy → sonnet-economy. Old CLI flags,
    stored .skill-config.json values, and recorded fixtures still carry the
    alias and MUST resolve identically to the canonical name."""

    def test_canonical_normaliser_maps_alias(self):
        rc = _load_resolver()
        assert rc.canonical_reasoning_model("haiku-economy") == "sonnet-economy"
        assert rc.canonical_reasoning_model("sonnet-economy") == "sonnet-economy"
        assert rc.canonical_reasoning_model("opus-cheap") == "opus-cheap"
        assert rc.canonical_reasoning_model(None) is None

    def test_cli_flag_alias_resolves_to_canonical(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--reasoning-model", "haiku-economy"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["reasoning_model"] == "sonnet-economy"
        assert out["stride_model"] == "claude-sonnet-4-6"

    def test_extended_models_alias_matches_canonical(self):
        rc = _load_resolver()
        for depth in ("quick", "standard", "thorough"):
            assert rc.resolve_extended_models("haiku-economy", depth) == rc.resolve_extended_models(
                "sonnet-economy", depth
            )

    def test_stride_profile_alias_matches_canonical(self):
        rc = _load_resolver()
        assert rc.resolve_stride_profile("haiku-economy", "quick") == rc.resolve_stride_profile(
            "sonnet-economy", "quick"
        )


# ---------------------------------------------------------------------------
# Default coupling to --assessment-depth
# ---------------------------------------------------------------------------


class TestDefaultCoupling:
    def test_quick_defaults_to_haiku_economy(self):
        """Quick depth promises 'fast + cheap' — the default tier routes
        deterministic-leaning agents to Haiku 4.5. STRIDE/triage/merger
        still stay on the Sonnet tier via the sonnet-economy MODEL_MATRIX
        entry, cost-pinned to the concrete Sonnet 4.6."""
        rc = _load_resolver()
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "quick")
        assert out["reasoning_model"] == "sonnet-economy"
        assert out["stride_model"] == "claude-sonnet-4-6"
        assert out["triage_model"] == "claude-sonnet-4-6"
        assert out["merger_model"] == "claude-sonnet-4-6"

    def test_quick_explicit_sonnet_override(self):
        """Users who want pre-2026-05 behaviour pass --reasoning-model sonnet."""
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--reasoning-model", "sonnet"])
        out = rc.resolve_reasoning_model(ns, "quick")
        assert out["reasoning_model"] == "sonnet"

    def test_standard_defaults_to_sonnet_economy(self):
        # 2026-06-23: standard reverted to sonnet-economy. A clean A/B showed
        # Opus reasoning was ~+$10.77 with no measurable quality gain; standard
        # is the everyday default, so it favours cost. Opus stays opt-in
        # (--reasoning-model opus) and remains the thorough default.
        rc = _load_resolver()
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["reasoning_model"] == "sonnet-economy"
        # STRIDE stays cost-pinned to Sonnet 4.6 (Sonnet 5 REGRESSED discovery
        # recall). The `standard` quality buy-back (2026-07-05) upgrades the
        # aggregation/judgment stages triage + merger to Sonnet 5.
        assert out["stride_model"] == "claude-sonnet-4-6"
        assert out["triage_model"] == "claude-sonnet-5"
        assert out["merger_model"] == "claude-sonnet-5"

    def test_standard_opus_still_opt_in(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["reasoning_model"] == "opus"
        assert out["stride_model"] == "opus"

    def test_thorough_defaults_to_opus(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "thorough")
        assert out["reasoning_model"] == "opus"


# ---------------------------------------------------------------------------
# Env-var escape hatches
# ---------------------------------------------------------------------------


class TestEnvVarOverrides:
    @pytest.mark.parametrize(
        "env",
        [
            "APPSEC_STRIDE_MODEL",
            "APPSEC_TRIAGE_MODEL",
            "APPSEC_MERGER_MODEL",
        ],
    )
    def test_env_var_referenced_in_resolver(self, env):
        assert env in RESOLVE_CONFIG_PY.read_text(), f"{env} must appear as an escape hatch in resolve_config.py"

    def test_env_var_beats_tier(self, monkeypatch):
        rc = _load_resolver()
        monkeypatch.setenv("APPSEC_STRIDE_MODEL", "claude-override")
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        # opus tier would set STRIDE to opus, but the env override wins.
        assert out["stride_model"] == "claude-override"


# ---------------------------------------------------------------------------
# Per-stage CLI flags (--stride-model / --triage-model / --merger-model)
# ---------------------------------------------------------------------------


class TestPerStageModelFlags:
    def test_triage_flag_overrides_tier(self):
        """--triage-model opus on a sonnet-economy run = the middle config:
        Sonnet STRIDE/merger, Opus triage (calibrated severities, cheap)."""
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--reasoning-model", "sonnet-economy", "--triage-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        # stride stays cost-pinned to Sonnet 4.6; merger takes the standard
        # buy-back (Sonnet 5); only triage is overridden to Opus by the
        # per-stage flag (the flag wins over the buy-back).
        assert out["stride_model"] == "claude-sonnet-4-6"
        assert out["triage_model"] == "opus"
        assert out["merger_model"] == "claude-sonnet-5"

    def test_all_three_flags_independent(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(
            ["--stride-model", "opus", "--triage-model", "sonnet", "--merger-model", "opus"]
        )
        out = rc.resolve_reasoning_model(ns, "standard")
        assert (out["stride_model"], out["triage_model"], out["merger_model"]) == (
            "opus",
            "sonnet",
            "opus",
        )

    def test_cli_flag_beats_env(self, monkeypatch):
        """The explicit per-run flag wins over the env escape hatch."""
        rc = _load_resolver()
        monkeypatch.setenv("APPSEC_TRIAGE_MODEL", "sonnet")
        ns = rc.build_parser().parse_args(["--triage-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["triage_model"] == "opus"

    def test_no_flag_keeps_tier_default(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--reasoning-model", "sonnet-economy"])
        out = rc.resolve_reasoning_model(ns, "standard")
        # standard buy-back: triage upgraded to Sonnet 5 (STRIDE stays 4.6).
        assert out["triage_model"] == "claude-sonnet-5"

    def test_triage_flag_label_reflects_override(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--reasoning-model", "sonnet-economy", "--triage-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert "triage: opus" in out["reasoning_label"]


# ---------------------------------------------------------------------------
# Orchestrator handoff + sub-agent dispatch threading (agent markdown checks)
# ---------------------------------------------------------------------------


class TestOrchestratorHandoff:
    def test_skill_passes_all_three_vars_to_orchestrator(self, skill_text):
        """The live runtime must bind all three centrally resolved model values."""
        for var in ("STRIDE_MODEL", "TRIAGE_MODEL", "MERGER_MODEL"):
            assert var in skill_text, f"SKILL Stage 1 handoff must pass {var} to the orchestrator"

    def test_controller_accepts_all_three_config_keys(self):
        text = CONTROLLER_PY.read_text()
        for key in ("stride_model", "triage_model", "merger_model"):
            assert f'"{key}"' in text


class TestDispatchThreading:
    def test_stride_dispatch_uses_stride_model(self):
        text = CONTROLLER_PY.read_text()
        assert '"stride_analyzer": "stride_model"' in text

    def test_triage_dispatch_uses_triage_model(self):
        text = CONTROLLER_PY.read_text()
        assert '"triage_validator": "triage_model"' in text

    def test_merger_dispatch_uses_merger_model(self):
        text = CONTROLLER_PY.read_text()
        assert '"threat_merger": "merger_model"' in text


class TestModelSelectionDocumentsFlag:
    def test_flag_mentioned(self):
        assert "--reasoning-model" in MODEL_SELECTION_MD.read_text()

    def test_opus_cheap_mode_described(self):
        assert "opus-cheap" in MODEL_SELECTION_MD.read_text()
