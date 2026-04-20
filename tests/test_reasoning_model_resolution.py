"""Tests for the --reasoning-model flag resolution matrix.

Validates that claude-plugin/skills/create-threat-model/SKILL.md documents:
  * The 3 modes (sonnet / opus-cheap / opus)
  * Their per-variable resolutions
  * Default coupling to --assessment-depth
  * --stride-model as a deprecated punctual override
  * Env-var escape hatches

Because SKILL.md is a prose/markdown spec (no executable resolver module),
these tests parse the documentation text rather than calling Python logic.
They guard against *doc* drift — which is where real bugs enter the pipeline
when the orchestrator reads SKILL.md-derived env vars but the flag no longer
resolves them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SKILL_MD = (
    Path(__file__).parent.parent
    / "claude-plugin" / "skills" / "create-threat-model" / "SKILL.md"
)
CLAUDE_MD = Path(__file__).parent.parent / "claude-plugin" / "CLAUDE.md"
THREAT_ANALYST_MD = (
    Path(__file__).parent.parent / "claude-plugin" / "agents" / "appsec-threat-analyst.md"
)
PHASE_GROUP_THREATS_MD = (
    Path(__file__).parent.parent
    / "claude-plugin" / "agents" / "phases" / "phase-group-threats.md"
)


@pytest.fixture(scope="module")
def skill_text() -> str:
    return SKILL_MD.read_text()


@pytest.fixture(scope="module")
def reasoning_section(skill_text) -> str:
    """Extract the 'Reasoning Model Resolution' section up to the next ## heading."""
    m = re.search(
        r"##\s+Reasoning Model Resolution\s*\n(.*?)(?=\n##\s)",
        skill_text,
        re.DOTALL,
    )
    assert m, "SKILL.md is missing the 'Reasoning Model Resolution' section"
    return m.group(1)


# ---------------------------------------------------------------------------
# Flag is documented
# ---------------------------------------------------------------------------

class TestFlagDocumented:
    def test_flag_appears_in_flag_table(self, skill_text):
        assert "--reasoning-model" in skill_text, (
            "SKILL.md flag-parsing table must document --reasoning-model"
        )

    def test_reasoning_section_exists(self, reasoning_section):
        assert reasoning_section.strip(), "Reasoning Model Resolution section is empty"


# ---------------------------------------------------------------------------
# Mode matrix
# ---------------------------------------------------------------------------

class TestModeMatrix:
    @pytest.mark.parametrize("mode", ["sonnet", "opus-cheap", "opus"])
    def test_mode_listed_in_matrix(self, reasoning_section, mode):
        assert f"`{mode}`" in reasoning_section, (
            f"Mode '{mode}' missing from Reasoning Model Resolution matrix"
        )

    @pytest.mark.parametrize("var", ["STRIDE_MODEL", "TRIAGE_MODEL", "MERGER_MODEL"])
    def test_variable_resolved_in_matrix(self, reasoning_section, var):
        assert var in reasoning_section, (
            f"Variable {var} must appear in the Reasoning Model Resolution matrix"
        )

    def test_opus_cheap_leaves_stride_on_sonnet(self, reasoning_section):
        """The opus-cheap mode's defining property: STRIDE stays on Sonnet
        while triage + merger go to Opus. The mode name is worthless if this
        differentiator is lost — guard it explicitly.
        """
        # Find the opus-cheap row — expect sonnet in STRIDE column, opus in others
        m = re.search(
            r"`opus-cheap`[^\n]*",
            reasoning_section,
        )
        assert m, "opus-cheap row missing from matrix"
        row = m.group(0)
        assert "sonnet" in row.lower(), (
            "opus-cheap row must include sonnet (for STRIDE) — found: " + row
        )
        assert "opus" in row.lower(), (
            "opus-cheap row must include opus (for triage+merger) — found: " + row
        )


# ---------------------------------------------------------------------------
# Default coupling to --assessment-depth
# ---------------------------------------------------------------------------

class TestDefaultCoupling:
    def test_thorough_defaults_to_opus_cheap(self, reasoning_section):
        assert re.search(
            r"thorough[^\n]*opus-cheap",
            reasoning_section,
        ), "--assessment-depth thorough must default to --reasoning-model opus-cheap"

    def test_quick_standard_default_to_sonnet(self, reasoning_section):
        assert re.search(
            r"(quick|standard)[^\n]*sonnet",
            reasoning_section,
        ), "--assessment-depth quick/standard must default to --reasoning-model sonnet"


# ---------------------------------------------------------------------------
# Backward compatibility — --stride-model
# ---------------------------------------------------------------------------

class TestStrideModelDeprecation:
    def test_stride_model_still_documented(self, skill_text):
        """--stride-model must remain parsable for CI pipelines."""
        assert "--stride-model" in skill_text

    def test_stride_model_marked_deprecated(self, reasoning_section):
        assert "deprecated" in reasoning_section.lower(), (
            "SKILL.md Reasoning Model Resolution must mark --stride-model deprecated"
        )

    def test_stride_model_override_ordering(self, reasoning_section):
        """--stride-model must be applied after --reasoning-model resolution so
        that it scopes to STRIDE only, not to triage/merger."""
        assert re.search(
            r"after.*resolution|applied.*after|after.*matrix",
            reasoning_section,
            re.IGNORECASE,
        ), "SKILL.md must document that --stride-model is applied AFTER --reasoning-model"


# ---------------------------------------------------------------------------
# Env-var escape hatch
# ---------------------------------------------------------------------------

class TestEnvVarOverrides:
    @pytest.mark.parametrize(
        "var",
        ["APPSEC_STRIDE_MODEL", "APPSEC_TRIAGE_MODEL", "APPSEC_MERGER_MODEL"],
    )
    def test_env_var_documented(self, reasoning_section, var):
        assert var in reasoning_section, (
            f"Env-var override {var} must be documented as an escape hatch"
        )

    def test_env_vars_have_highest_precedence(self, reasoning_section):
        assert "highest precedence" in reasoning_section.lower() or \
               "overriding" in reasoning_section.lower(), (
            "Env vars must be documented as having highest precedence over flags"
        )


# ---------------------------------------------------------------------------
# Variables passed to orchestrator
# ---------------------------------------------------------------------------

class TestOrchestratorHandoff:
    def test_skill_passes_all_three_vars(self, skill_text):
        """The Stage 1 invocation must pass all three model variables to
        the orchestrator so it can thread them through Agent dispatches."""
        for var in ("STRIDE_MODEL", "TRIAGE_MODEL", "MERGER_MODEL"):
            assert var in skill_text, (
                f"SKILL.md Stage 1 handoff must pass {var} to the orchestrator"
            )

    def test_orchestrator_accepts_all_three_vars(self):
        """threat-analyst.md must document receiving the three model vars."""
        text = THREAT_ANALYST_MD.read_text()
        for var in ("STRIDE_MODEL", "TRIAGE_MODEL", "MERGER_MODEL"):
            assert var in text, (
                f"appsec-threat-analyst.md must reference {var} as an input variable"
            )


# ---------------------------------------------------------------------------
# Dispatch threading — sub-agents receive the right model parameter
# ---------------------------------------------------------------------------

class TestDispatchThreading:
    def test_stride_dispatch_uses_stride_model(self):
        text = PHASE_GROUP_THREATS_MD.read_text()
        assert "$STRIDE_MODEL" in text, (
            "phase-group-threats.md STRIDE dispatch must pass $STRIDE_MODEL as Agent model parameter"
        )

    def test_triage_dispatch_uses_triage_model(self):
        text = PHASE_GROUP_THREATS_MD.read_text()
        # Find the triage-validator dispatch block
        m = re.search(
            r"subagent_type:\s*\"appsec-plugin:appsec-triage-validator\".*?(?=\n###|\n##)",
            text,
            re.DOTALL,
        )
        assert m, "Triage-validator dispatch block not found"
        assert "$TRIAGE_MODEL" in m.group(0) or "TRIAGE_MODEL" in m.group(0), (
            "Triage-validator dispatch must pass $TRIAGE_MODEL as Agent model parameter"
        )

    def test_merger_dispatch_uses_merger_model(self):
        text = PHASE_GROUP_THREATS_MD.read_text()
        # Find the threat-merger dispatch block (optional / hybrid section)
        m = re.search(
            r"subagent_type:\s*\"appsec-plugin:appsec-threat-merger\".*?(?=\n###|\n##)",
            text,
            re.DOTALL,
        )
        assert m, "Threat-merger dispatch block not found"
        assert "$MERGER_MODEL" in m.group(0), (
            "Threat-merger dispatch must pass $MERGER_MODEL as Agent model parameter"
        )


# ---------------------------------------------------------------------------
# CLAUDE.md documents the flag
# ---------------------------------------------------------------------------

class TestClaudeMdDocumentsFlag:
    def test_flag_mentioned(self):
        assert "--reasoning-model" in CLAUDE_MD.read_text(), (
            "claude-plugin/CLAUDE.md must document the --reasoning-model flag"
        )

    def test_opus_cheap_mode_described(self):
        text = CLAUDE_MD.read_text()
        assert "opus-cheap" in text, (
            "claude-plugin/CLAUDE.md must describe the opus-cheap mode"
        )

    def test_stride_model_deprecation_noted(self):
        text = CLAUDE_MD.read_text()
        # Find the bullet-style flag documentation (lines starting with "- `--stride-model")
        m = re.search(
            r"^-\s+`--stride-model[^\n]+(?:\n\s+[^\n-][^\n]*)*",
            text,
            re.MULTILINE,
        )
        assert m, "claude-plugin/CLAUDE.md must document --stride-model as a flag bullet"
        assert "deprecated" in m.group(0).lower(), (
            "claude-plugin/CLAUDE.md flag bullet for --stride-model must mark it deprecated"
        )
