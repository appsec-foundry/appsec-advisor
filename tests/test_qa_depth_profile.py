"""
Tests for Sprint 1 Item E.2 + E.3:

- E.2: QA Check 11 depth matrix — core skips entirely; full runs 11a+11d only;
  extended runs the full 11a/b/c/d set. Prevents regression to the prior
  "always run 11a" wasteful baseline.
- E.3: QA Check 2 Pass 2c must be opt-in via --qa-scan-repo / QA_SCAN_REPO=true.
  The old 5-ref threshold auto-trigger is gone.
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
# E.3 — Pass 2c opt-in via --qa-scan-repo
# ---------------------------------------------------------------------------


class TestPass2cOptIn:
    def test_skill_documents_qa_scan_repo_flag(self):
        text = _read(PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md")
        assert "--qa-scan-repo" in text, "SKILL.md must document the --qa-scan-repo flag in the Argument Parsing table"
        assert "QA_SCAN_REPO=true" in text, "SKILL.md must bind --qa-scan-repo to QA_SCAN_REPO=true"

    def test_qa_reviewer_pass_2c_section_removed(self):
        """As of 2026-04 the Pass 2c proactive repo-scan was removed
        entirely — the `QA_SCAN_REPO` env var was never set in
        production and the `find`-traversal cost was disproportionate
        to the marginal coverage it added.

        This test guards against accidental reintroduction: neither the
        section heading nor the gating env var should reappear in the
        agent prompt. If a future iteration brings it back, change this
        test to assert the new contract.
        """
        text = _read(QA_REVIEWER)
        assert "### Pass 2c — Proactive repo scan" not in text, (
            "qa-reviewer.md should not reintroduce Pass 2c — see the 2026-04 removal note inline in the agent file."
        )
        assert "QA_SCAN_REPO=true" not in text, "qa-reviewer.md must not reference QA_SCAN_REPO — Pass 2c was retired."
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
