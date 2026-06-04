"""Tests for the --reasoning-model flag resolution matrix.

Since M3.2 the actual resolver lives in ``scripts/resolve_config.py`` and is
covered in depth by ``tests/test_resolve_config.py``. The tests here guard
against drift between the resolver (Python) and the downstream consumers
that still reference the resolved env-vars by name — i.e. the agent
definitions and phase-group markdown that dispatch sub-agents with these
model parameters. Touching any of:

    * scripts/resolve_config.py                  (source of truth)
    * skills/create-threat-model/SKILL.md        (must mention the flag + delegate)
    * agents/appsec-threat-analyst.md            (must accept the three vars)
    * agents/phases/phase-group-threats.md       (must thread the vars to dispatches)
    * AGENTS.md                                  (must describe flag + opus-cheap)

without updating the others will surface here.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SKILL_MD = ROOT / "skills" / "create-threat-model" / "SKILL.md"
SKILL_IMPL_MD = ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
AGENTS_MD = ROOT / "AGENTS.md"
THREAT_ANALYST_MD = ROOT / "agents" / "appsec-threat-analyst.md"
PHASE_GROUP_THREATS_MD = ROOT / "agents" / "phases" / "phase-group-threats.md"
RESOLVE_CONFIG_PY = ROOT / "scripts" / "resolve_config.py"


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
    """Concatenated text of SKILL.md (router stub) + SKILL-impl.md
    (authoritative implementation). The skill's actual flag handling,
    env-var extraction, and orchestrator handoff live in SKILL-impl.md
    since the M2.x split — SKILL.md is a thin Case 1/Case 2 router."""
    return SKILL_MD.read_text() + "\n" + SKILL_IMPL_MD.read_text()


@pytest.fixture(scope="module")
def skill_router_text() -> str:
    """SKILL.md alone — for tests that specifically target the router stub."""
    return SKILL_MD.read_text()


# ---------------------------------------------------------------------------
# Flag is documented + skill delegates to resolve_config.py
# ---------------------------------------------------------------------------


class TestFlagDocumented:
    def test_flag_appears_in_skill_md(self, skill_text):
        assert "--reasoning-model" in skill_text, "SKILL.md / SKILL-impl.md must document --reasoning-model"

    def test_skill_delegates_to_resolve_config(self, skill_text):
        assert "resolve_config.py" in skill_text, (
            "SKILL must delegate flag resolution to resolve_config.py (check SKILL-impl.md for the actual delegation)"
        )


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
        assert out["stride_model"] == "sonnet"

    def test_extended_models_alias_matches_canonical(self):
        rc = _load_resolver()
        for depth in ("quick", "standard", "thorough"):
            assert (rc.resolve_extended_models("haiku-economy", depth)
                    == rc.resolve_extended_models("sonnet-economy", depth))

    def test_stride_profile_alias_matches_canonical(self):
        rc = _load_resolver()
        assert (rc.resolve_stride_profile("haiku-economy", "quick")
                == rc.resolve_stride_profile("sonnet-economy", "quick"))


# ---------------------------------------------------------------------------
# Default coupling to --assessment-depth
# ---------------------------------------------------------------------------


class TestDefaultCoupling:
    def test_quick_defaults_to_haiku_economy(self):
        """Quick depth promises 'fast + cheap' — the default tier routes
        deterministic-leaning agents to Haiku 4.5. STRIDE/triage/merger
        still stay on Sonnet via the sonnet-economy MODEL_MATRIX entry."""
        rc = _load_resolver()
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "quick")
        assert out["reasoning_model"] == "sonnet-economy"
        assert out["stride_model"] == "sonnet"
        assert out["triage_model"] == "sonnet"
        assert out["merger_model"] == "sonnet"

    def test_quick_explicit_sonnet_override(self):
        """Users who want pre-2026-05 behaviour pass --reasoning-model sonnet."""
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--reasoning-model", "sonnet"])
        out = rc.resolve_reasoning_model(ns, "quick")
        assert out["reasoning_model"] == "sonnet"

    def test_standard_defaults_to_opus_cheap(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["reasoning_model"] == "opus-cheap"

    def test_thorough_defaults_to_opus_cheap(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "thorough")
        assert out["reasoning_model"] == "opus-cheap"


# ---------------------------------------------------------------------------
# --stride-model punctual override (deprecated alias)
# ---------------------------------------------------------------------------


class TestStrideModelDeprecation:
    def test_stride_model_still_parsable(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--stride-model", "claude-custom"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "claude-custom"

    def test_stride_model_does_not_affect_triage_or_merger(self):
        """Deprecation property: --stride-model only touches STRIDE_MODEL."""
        rc = _load_resolver()
        ns = rc.build_parser().parse_args(["--stride-model", "claude-custom"])
        out = rc.resolve_reasoning_model(ns, "standard")
        # opus-cheap default → triage stays on Sonnet, merger stays on Opus.
        assert out["triage_model"] == "sonnet"
        assert out["merger_model"] == "opus"


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

    def test_env_var_beats_flags(self, monkeypatch):
        rc = _load_resolver()
        monkeypatch.setenv("APPSEC_STRIDE_MODEL", "claude-override")
        ns = rc.build_parser().parse_args(["--reasoning-model", "sonnet", "--stride-model", "claude-cli"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "claude-override"


# ---------------------------------------------------------------------------
# Orchestrator handoff + sub-agent dispatch threading (agent markdown checks)
# ---------------------------------------------------------------------------


class TestOrchestratorHandoff:
    def test_skill_passes_all_three_vars_to_orchestrator(self, skill_text):
        """The Stage 1 invocation must pass all three model variables to the
        orchestrator so it can thread them through Agent dispatches.
        The handoff lives in SKILL-impl.md (M2.x split) — the fixture
        concatenates both router + impl, so this test catches the var in
        either file."""
        for var in ("STRIDE_MODEL", "TRIAGE_MODEL", "MERGER_MODEL"):
            assert var in skill_text, f"SKILL Stage 1 handoff must pass {var} to the orchestrator"

    def test_orchestrator_accepts_all_three_vars(self):
        text = THREAT_ANALYST_MD.read_text()
        for var in ("STRIDE_MODEL", "TRIAGE_MODEL", "MERGER_MODEL"):
            assert var in text, f"appsec-threat-analyst.md must reference {var} as an input variable"


class TestDispatchThreading:
    def test_stride_dispatch_uses_stride_model(self):
        text = PHASE_GROUP_THREATS_MD.read_text()
        assert "$STRIDE_MODEL" in text, (
            "phase-group-threats.md STRIDE dispatch must pass $STRIDE_MODEL as Agent model parameter"
        )

    def test_triage_dispatch_uses_triage_model(self):
        text = PHASE_GROUP_THREATS_MD.read_text()
        m = re.search(
            r"subagent_type:\s*\"appsec-advisor:appsec-triage-validator\".*?(?=\n###|\n##)",
            text,
            re.DOTALL,
        )
        assert m, "Triage-validator dispatch block not found"
        assert "$TRIAGE_MODEL" in m.group(0) or "TRIAGE_MODEL" in m.group(0), (
            "Triage-validator dispatch must pass $TRIAGE_MODEL"
        )

    def test_merger_dispatch_uses_merger_model(self):
        text = PHASE_GROUP_THREATS_MD.read_text()
        m = re.search(
            r"subagent_type:\s*\"appsec-advisor:appsec-threat-merger\".*?(?=\n###|\n##)",
            text,
            re.DOTALL,
        )
        assert m, "Threat-merger dispatch block not found"
        assert "$MERGER_MODEL" in m.group(0), "Threat-merger dispatch must pass $MERGER_MODEL"


class TestAgentsMdDocumentsFlag:
    def test_flag_mentioned(self):
        assert "--reasoning-model" in AGENTS_MD.read_text(), "AGENTS.md must document the --reasoning-model flag"

    def test_opus_cheap_mode_described(self):
        text = AGENTS_MD.read_text()
        assert "opus-cheap" in text, "AGENTS.md must describe the opus-cheap mode"

    def test_stride_model_deprecation_noted(self):
        text = AGENTS_MD.read_text()
        m = re.search(
            r"^-\s+`--stride-model[^\n]+(?:\n\s+[^\n-][^\n]*)*",
            text,
            re.MULTILINE,
        )
        assert m, "AGENTS.md must document --stride-model as a flag bullet"
        assert "deprecated" in m.group(0).lower(), "AGENTS.md flag bullet for --stride-model must mark it deprecated"
