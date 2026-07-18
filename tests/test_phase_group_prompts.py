"""Content tests for the phase-group-*.md orchestrator prompts.

These tests protect a small number of structural guidance blocks from silent
erosion. They do not validate every paragraph — just the markers that are
mirrored by deterministic contract checks in `sections-contract.yaml` and
enforced by `scripts/qa_checks.py`. If a marker is removed from the prompt,
the QA rule loses its author-side counterpart and starts failing on freshly
generated threat models; this test catches that at plugin-unit-test time
instead of at full-run time.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
FINALIZATION_PROMPT = REPO_ROOT / "agents" / "phases" / "phase-group-finalization.md"
RECON_PROMPT = REPO_ROOT / "agents" / "phases" / "phase-group-recon.md"


@pytest.fixture(scope="module")
def finalization_text() -> str:
    assert FINALIZATION_PROMPT.is_file(), f"expected phase-group prompt at {FINALIZATION_PROMPT}"
    return FINALIZATION_PROMPT.read_text(encoding="utf-8")


class TestSecurityArchitectureV2Guidance:
    """Verify that the §6 v2 control-category guidance is still present."""

    def test_mentions_v2_13_section_layout(self, finalization_text):
        assert "v2 13-section control-category layout" in finalization_text
        assert "### 6.1 Security Control Overview" in finalization_text
        assert "### 6.13 Defense-in-Depth Summary" in finalization_text

    def test_mentions_section_level_labels(self, finalization_text):
        for marker in (
            "**Verdict:**",
            "**Controls covered:**",
            "**Implemented controls:**",
            "**Assessment:**",
        ):
            assert marker in finalization_text

    def test_mentions_h4_subcontrol_labels(self, finalization_text):
        assert "**Security assessment**" in finalization_text
        assert "**Relevant findings**" in finalization_text

    def test_mentions_controls_covered_link_contract(self, finalization_text):
        assert "visible text of each `**Controls covered:**` link must exactly match an H4 heading" in finalization_text

    def test_mentions_new_gate_and_legacy_retirement(self, finalization_text):
        assert "control_subsection_coverage" in finalization_text
        assert "Do not emit legacy §6.3.N auth-flow structure" in finalization_text


class TestActorPhaseRuntimeContract:
    @pytest.fixture(scope="class")
    def recon_text(self) -> str:
        return RECON_PROMPT.read_text(encoding="utf-8")

    def test_quick_skips_discovery_not_static_resolution(self, recon_text):
        assert "**Never skip the static resolver.**" in recon_text
        assert '$( [ "$ASSESSMENT_DEPTH" = "quick" ] && echo "--quick" )' in recon_text
        assert "**Skip when:** `ASSESSMENT_DEPTH = quick`." not in recon_text

    def test_cache_uses_deterministic_helper_without_environment_lookup(self, recon_text):
        assert "scripts/actor_discovery_cache.py" in recon_text
        assert 'os.environ.get("DISCOVERY_CACHE_KEY"' not in recon_text
        assert '--expected-key "$DISCOVERY_CACHE_KEY"' in recon_text

    def test_resolved_actor_output_is_hard_validated(self, recon_text):
        assert recon_text.count('actors_resolved "$OUTPUT_DIR/.actors-resolved.json"') == 2
        assert "discovery_enabled=false" in recon_text
