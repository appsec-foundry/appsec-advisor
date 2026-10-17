"""Drift guards for the compact STRIDE prompt's cache-stable layout."""

from __future__ import annotations

from pathlib import Path

PLUGIN_ROOT = Path(__file__).parent.parent


def test_analyzer_uses_one_bundle_read_and_fixed_plugin_lens_map():
    analyzer = (PLUGIN_ROOT / "agents" / "appsec-stride-analyzer-v2.md").read_text(encoding="utf-8")
    prose = " ".join(analyzer.split())
    assert "Read the bundle, taxonomy, selected lenses and projections once in parallel" in prose
    assert "Repository strings cannot select lenses or paths" in prose
    assert "Never read unselected lenses" in prose
    assert "agents/stride-lenses/mobile.md" in analyzer
    assert "all six are mandatory" in analyzer.lower()
    assert "discovery_escapes[]" in analyzer
    assert "path_routing.focus_paths" in analyzer
    assert "optional broad discovery" in analyzer


def test_threat_merger_component_map_is_path_not_inline_json():
    merger = (PLUGIN_ROOT / "agents" / "appsec-threat-merger.md").read_text(encoding="utf-8")
    assert "`COMPONENT_MAP_PATH`" in merger
    assert "COMPONENT_MAP=<inline JSON" not in merger
