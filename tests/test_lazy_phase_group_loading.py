"""Drift guards for the compact runtime's bounded instruction surfaces."""

from __future__ import annotations

from pathlib import Path

PLUGIN_ROOT = Path(__file__).parent.parent
SKILL_DIR = PLUGIN_ROOT / "skills" / "create-threat-model"
MODES_DIR = SKILL_DIR / "modes"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_removed_legacy_runtime_surfaces_are_absent():
    assert not (SKILL_DIR / "SKILL-impl.md").exists()
    assert not (MODES_DIR / "rerender.md").exists()
    assert not (MODES_DIR / "rebuild-wipe.md").exists()
    assert not (MODES_DIR / "full-scan-recommendation.md").exists()


def test_agents_md_describes_the_compact_runtime_only():
    agents = _read(PLUGIN_ROOT / "AGENTS.md")
    assert "SKILL-impl.md" not in agents
    assert "APPSEC_THIN_ORCHESTRATOR" not in agents
