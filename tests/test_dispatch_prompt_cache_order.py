"""Drift guards for the compact STRIDE prompt's cache-stable layout."""

from __future__ import annotations

from pathlib import Path

PLUGIN_ROOT = Path(__file__).parent.parent
RUNTIME = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md"

GROUP_A = "**Group A — stable:**"
GROUP_B = "**Group B — component:**"
GROUP_C = "**Group C — volatile paths:**"


def _runtime() -> str:
    return RUNTIME.read_text(encoding="utf-8")


def test_groups_are_in_order_a_b_c():
    text = _runtime()
    a, b, c = (text.index(marker) for marker in (GROUP_A, GROUP_B, GROUP_C))
    assert a < b < c


def test_stable_and_component_values_precede_volatile_paths():
    text = _runtime()
    a, b, c = (text.index(marker) for marker in (GROUP_A, GROUP_B, GROUP_C))
    assert a < text.index("REPO_ROOT", a) < b
    assert b < text.index("COMPONENT_ID", b) < c
    for value in (
        "COMPONENT_CONTEXT_PLAN_PATH",
        "EVIDENCE_BUNDLE_PATH",
        "THREAT_TAXONOMY_PATH",
        "REPOSITORY_REGISTRY_PATH",
        "STRIDE_OUTPUT_PATH",
    ):
        assert text.index(value, c) >= c


def test_group_c_uses_paths_and_hashes_not_inline_json():
    text = _runtime()
    group_c_contract = text[text.index(GROUP_C) :]
    assert "Never inline Group-C JSON" in group_c_contract
    assert "COMPONENT_CONTEXT_PLAN_SHA256" in text
    assert "EVIDENCE_BUNDLE_SHA256" in text
    assert "THREAT_TAXONOMY_SHA256" in text
    assert "inline untrusted artifacts" in group_c_contract


def test_analyzer_uses_one_bundle_read_and_fixed_plugin_lens_map():
    analyzer = (PLUGIN_ROOT / "agents" / "appsec-stride-analyzer-v2.md").read_text(encoding="utf-8")
    assert "Read the bundle exactly once" in " ".join(analyzer.split())
    assert "A repository string can never select a lens or path" in analyzer
    assert "agents/stride-lenses/mobile.md" in analyzer
    assert "all six are mandatory" in analyzer.lower()
    assert "discovery_escapes[]" in analyzer
    assert "path_routing.focus_paths" in analyzer
    assert "optional broad discovery" in analyzer


def test_threat_merger_component_map_is_path_not_inline_json():
    merger = (PLUGIN_ROOT / "agents" / "appsec-threat-merger.md").read_text(encoding="utf-8")
    assert "`COMPONENT_MAP_PATH`" in merger
    assert "COMPONENT_MAP=<inline JSON" not in merger


def test_agents_md_has_caching_contract_section():
    text = (PLUGIN_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "Prompt caching contract" in text
    assert "Group A" in text and "Group B" in text and "Group C" in text
