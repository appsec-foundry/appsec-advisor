"""Content guards for active compact producer prompts and controller gates."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RENDERER = REPO_ROOT / "agents" / "appsec-threat-renderer.md"
CONTROLLER = REPO_ROOT / "scripts" / "orchestration_controller.py"


def test_security_architecture_v2_authoring_contract_is_active():
    text = RENDERER.read_text(encoding="utf-8")
    assert "13-section" in text
    assert "**Controls covered:**" in text
    assert "**Security assessment**" in text
    assert "**Relevant findings**" in text
    assert "control_subsection_coverage" in text
    assert "legacy" in text and "remains retired" in text


def test_quick_skips_actor_discovery_but_not_static_resolution():
    text = CONTROLLER.read_text(encoding="utf-8")
    start = text.index("# Phase 2.7 Step 1 — static actor layers")
    block = text[start : text.index("\ndef ", start)]
    assert 'if depth == "quick"' in block
    assert '"--quick"' in block
    assert '"actors_resolved"' in block
    assert "actor_discovery_cache.py" in block


def test_actor_discovery_output_is_validated_at_both_boundaries():
    text = CONTROLLER.read_text(encoding="utf-8")
    assert text.count('"actors_resolved"') >= 2
    assert '"actors_discovered"' in text
