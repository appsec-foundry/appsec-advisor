"""Content guards for active compact producer prompts and controller gates."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RENDERER = REPO_ROOT / "agents" / "appsec-threat-renderer.md"
SEC6_CONTRACT = REPO_ROOT / "agents" / "shared" / "sec6-authoring.md"
CONTROLLER = REPO_ROOT / "scripts" / "orchestrator/orchestration_controller.py"
POSTURE = REPO_ROOT / "scripts" / "model/assessment_posture.py"


def test_security_architecture_v2_authoring_contract_is_active():
    assert "agents/shared/sec6-authoring.md" in RENDERER.read_text(encoding="utf-8")
    text = SEC6_CONTRACT.read_text(encoding="utf-8")
    assert "13-section" in text
    assert "**Controls covered:**" in text
    assert "**Security assessment**" in text
    assert "**Relevant findings**" in text
    assert "control_subsection_coverage" in text
    assert "legacy" in text and "remains retired" in text


def test_actor_discovery_output_is_validated_at_both_boundaries():
    text = POSTURE.read_text(encoding="utf-8")
    assert 'validate_actors_resolved(_read(workspace / ".actors-resolved.json"))' in text
    assert "validate_actors_discovered(discovered)" in text
    assert "assessment_posture.discover_actors(" in CONTROLLER.read_text(encoding="utf-8")
