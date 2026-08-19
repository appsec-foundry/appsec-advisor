"""
Tests for deterministic QA dispatch policy:

- E.2: QA Check 11 depth matrix — core skips entirely; full runs 11a+11d only;
  extended runs the full 11a/b/c/d set. Prevents regression to the prior
  "always run 11a" wasteful baseline.
- QA Check 2 Pass 2c remains retired.
"""

import re
from pathlib import Path

PLUGIN_ROOT = Path(__file__).parent.parent
QA_REVIEWER = PLUGIN_ROOT / "agents" / "appsec-qa-reviewer.md"
SKILL_MD = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# E.2 — deterministic ownership / dispatch policy
# ---------------------------------------------------------------------------


class TestDeterministicQaOwnership:
    def test_mitigation_shape_is_not_rechecked_by_agent(self):
        text = _read(QA_REVIEWER)
        assert "mitigation schema and P1–P4 grouping" in text
        assert "Do not run `qa_checks.py all`" in text

    def test_extended_depth_does_not_dispatch_clean_agent(self):
        skill = _read(PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md")
        reviewer = _read(QA_REVIEWER)
        assert "regardless of assessment depth" in reviewer
        assert "Extended depth adds deterministic coverage" in skill
        assert "- `QA_DEPTH=extended`" not in skill

    def test_forced_review_bypasses_clean_fast_exit(self):
        text = _read(QA_REVIEWER)
        assert "APPSEC_FORCE_QA_AGENT != 1" in text
        assert "explicit force exception" in text


# ---------------------------------------------------------------------------
# Retired Pass 2c
# ---------------------------------------------------------------------------


class TestPass2cRetired:
    def test_qa_reviewer_pass_2c_section_removed(self):
        """As of 2026-04 the Pass 2c proactive repo-scan was removed
        entirely because the traversal cost was disproportionate to the
        marginal coverage it added.

        This test guards against accidental reintroduction: neither the
        section heading nor the gating env var should reappear in the
        agent prompt. If a future iteration brings it back, change this
        test to assert the new contract.
        """
        text = _read(QA_REVIEWER)
        assert "### Pass 2c — Proactive repo scan" not in text, (
            "qa-reviewer.md should not reintroduce Pass 2c — see the 2026-04 removal note inline in the agent file."
        )
        assert not re.search(r"combined total from Passes 2a and 2b is fewer than 5", text), (
            "qa-reviewer.md must not reintroduce the old 'fewer than 5' auto-trigger for Pass 2c."
        )


class TestDeterministicFirstQa:
    def test_skill_documents_clean_fast_path_skip(self):
        text = _read(PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md")
        assert "deterministic-pre-agent" in text
        assert "skip the QA agent" in text
        assert "qa_checks.py all" in text
        assert "QA_AGENT_DISPATCHED=false" in text
        assert "do **not** execute any later instruction that invokes `appsec-qa-reviewer`" in text

    def test_repair_loop_respects_deterministic_qa_gate(self):
        text = _read(PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md")
        assert "run Stage 3 QA gate" in text
        assert "The Stage 3 gate may be deterministic-only" in text
        assert "Do not dispatch\n  # qa-reviewer unless QA_AGENT_DISPATCHED=true" in text

    def test_total_stage_count_includes_stage_1_and_2(self):
        text = _read(PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md")
        assert "start with `2` for Stage 1 (orchestrator) + Stage 2 (composition)" in text
        assert "normal quick runs without architect review show `2`" in text
        assert "standard runs with QA and no architect review show `3`" in text
        assert "▶ Stage 4/<total_stages> — Architect Review starting" in text
        assert "▶ Stage 4/4 — Architect Review starting" not in text

    def test_qa_reviewer_reads_prepass_before_markdown(self):
        text = _read(QA_REVIEWER)
        assert "Deterministic-first scope" in text
        assert "PRE_PASS_JSON_PATH" in text
        assert "Do not read the full `threat-model.md` on the normal plan-triage path" in text
