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
    * CLAUDE.md                                  (must describe flag + opus-cheap)

without updating the others will surface here.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT                   = Path(__file__).parent.parent
SKILL_MD               = ROOT / "skills" / "create-threat-model" / "SKILL.md"
CLAUDE_MD              = ROOT / "CLAUDE.md"
THREAT_ANALYST_MD      = ROOT / "agents" / "appsec-threat-analyst.md"
PHASE_GROUP_THREATS_MD = ROOT / "agents" / "phases" / "phase-group-threats.md"
RESOLVE_CONFIG_PY      = ROOT / "scripts" / "resolve_config.py"


def _load_resolver():
    if "resolve_config" in sys.modules:
        return sys.modules["resolve_config"]
    spec = importlib.util.spec_from_file_location("resolve_config", RESOLVE_CONFIG_PY)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules["resolve_config"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def skill_text() -> str:
    return SKILL_MD.read_text()


# ---------------------------------------------------------------------------
# Flag is documented + skill delegates to resolve_config.py
# ---------------------------------------------------------------------------


class TestFlagDocumented:
    def test_flag_appears_in_skill_md(self, skill_text):
        assert "--reasoning-model" in skill_text, (
            "SKILL.md flag-parsing table must document --reasoning-model"
        )

    def test_skill_delegates_to_resolve_config(self, skill_text):
        assert "resolve_config.py" in skill_text, (
            "SKILL.md must delegate flag resolution to resolve_config.py"
        )


# ---------------------------------------------------------------------------
# Resolver matrix — three modes, three variables per mode
# ---------------------------------------------------------------------------


class TestResolverMatrix:
    def test_three_modes_present(self):
        rc = _load_resolver()
        assert set(rc.MODEL_MATRIX.keys()) == {"sonnet", "opus-cheap", "opus"}

    @pytest.mark.parametrize("key", ["stride", "triage", "merger"])
    def test_every_mode_has_three_slots(self, key):
        rc = _load_resolver()
        for mode, models in rc.MODEL_MATRIX.items():
            assert key in models, f"{mode!r} mode missing {key!r} slot"

    def test_opus_cheap_differentiator(self):
        """opus-cheap's raison d'être: STRIDE on Sonnet, triage+merger on Opus."""
        rc = _load_resolver()
        m = rc.MODEL_MATRIX["opus-cheap"]
        assert "sonnet" in m["stride"]
        assert "opus"   in m["triage"]
        assert "opus"   in m["merger"]


# ---------------------------------------------------------------------------
# Default coupling to --assessment-depth
# ---------------------------------------------------------------------------


class TestDefaultCoupling:
    def test_quick_defaults_to_sonnet(self):
        rc = _load_resolver()
        ns = rc.build_parser().parse_args([])
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
        # opus-cheap default → triage+merger stay on Opus regardless.
        assert out["triage_model"] == "claude-opus-4-7"
        assert out["merger_model"] == "claude-opus-4-7"


# ---------------------------------------------------------------------------
# Env-var escape hatches
# ---------------------------------------------------------------------------


class TestEnvVarOverrides:
    @pytest.mark.parametrize("env", [
        "APPSEC_STRIDE_MODEL",
        "APPSEC_TRIAGE_MODEL",
        "APPSEC_MERGER_MODEL",
    ])
    def test_env_var_referenced_in_resolver(self, env):
        assert env in RESOLVE_CONFIG_PY.read_text(), (
            f"{env} must appear as an escape hatch in resolve_config.py"
        )

    def test_env_var_beats_flags(self, monkeypatch):
        rc = _load_resolver()
        monkeypatch.setenv("APPSEC_STRIDE_MODEL", "claude-override")
        ns = rc.build_parser().parse_args(["--reasoning-model", "sonnet",
                                           "--stride-model",    "claude-cli"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "claude-override"


# ---------------------------------------------------------------------------
# Orchestrator handoff + sub-agent dispatch threading (agent markdown checks)
# ---------------------------------------------------------------------------


class TestOrchestratorHandoff:
    def test_skill_passes_all_three_vars_to_orchestrator(self, skill_text):
        """The Stage 1 invocation must pass all three model variables to the
        orchestrator so it can thread them through Agent dispatches."""
        for var in ("STRIDE_MODEL", "TRIAGE_MODEL", "MERGER_MODEL"):
            assert var in skill_text, (
                f"SKILL.md Stage 1 handoff must pass {var} to the orchestrator"
            )

    def test_orchestrator_accepts_all_three_vars(self):
        text = THREAT_ANALYST_MD.read_text()
        for var in ("STRIDE_MODEL", "TRIAGE_MODEL", "MERGER_MODEL"):
            assert var in text, (
                f"appsec-threat-analyst.md must reference {var} as an input variable"
            )


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
        assert "$MERGER_MODEL" in m.group(0), (
            "Threat-merger dispatch must pass $MERGER_MODEL"
        )


class TestClaudeMdDocumentsFlag:
    def test_flag_mentioned(self):
        assert "--reasoning-model" in CLAUDE_MD.read_text(), (
            "CLAUDE.md must document the --reasoning-model flag"
        )

    def test_opus_cheap_mode_described(self):
        text = CLAUDE_MD.read_text()
        assert "opus-cheap" in text, (
            "CLAUDE.md must describe the opus-cheap mode"
        )

    def test_stride_model_deprecation_noted(self):
        text = CLAUDE_MD.read_text()
        m = re.search(
            r"^-\s+`--stride-model[^\n]+(?:\n\s+[^\n-][^\n]*)*",
            text,
            re.MULTILINE,
        )
        assert m, "CLAUDE.md must document --stride-model as a flag bullet"
        assert "deprecated" in m.group(0).lower(), (
            "CLAUDE.md flag bullet for --stride-model must mark it deprecated"
        )
