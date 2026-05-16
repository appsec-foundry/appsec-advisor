"""
Drift guard for Sprint 3 Item #2 — prompt-caching-friendly dispatch layout.

The orchestrator's STRIDE-analyzer Dispatch block in
`agents/phases/phase-group-threats.md` must emit parameters in three
groups, ordered by how cache-stable they are across component dispatches:

  Group A — stable across every STRIDE dispatch (REPO_ROOT, OUTPUT_DIR, …)
  Group B — component-specific scalars and short lists
  Group C — volatile context file paths (PRIOR_FINDINGS_INDEX_PATH, …)

Emitting Group C first would invalidate the prompt cache for every
dispatch — this test fails loudly if someone reorders the groups or
drops the group structure.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
PHASE_GROUP_THREATS = PLUGIN_ROOT / "agents" / "phases" / "phase-group-threats.md"
AGENTS_MD = PLUGIN_ROOT / "AGENTS.md"


def _dispatch_block() -> str:
    """Return the Dispatch section of phase-group-threats.md (stops at the
    next ### heading)."""
    text = PHASE_GROUP_THREATS.read_text(encoding="utf-8")
    start = text.find("### Dispatch")
    assert start != -1, "### Dispatch section not found"
    rest = text[start:]
    next_heading = re.search(r"^###\s", rest[4:], re.MULTILINE)
    if next_heading:
        return rest[: 4 + next_heading.start()]
    return rest


# ---------------------------------------------------------------------------
# Three named groups are present
# ---------------------------------------------------------------------------


GROUP_A_MARKER = "**Group A — stable across every STRIDE dispatch"
GROUP_B_MARKER = "**Group B — component-specific scalars"
GROUP_C_MARKER = "**Group C — volatile context file paths"


def test_dispatch_block_has_all_three_groups():
    block = _dispatch_block()
    assert GROUP_A_MARKER in block, "Dispatch block must contain Group A marker"
    assert GROUP_B_MARKER in block, "Dispatch block must contain Group B marker"
    assert GROUP_C_MARKER in block, "Dispatch block must contain Group C marker"


def test_groups_are_in_order_a_b_c():
    """Group C listed before Group A would undo the cache optimisation."""
    block = _dispatch_block()
    a = block.find(GROUP_A_MARKER)
    b = block.find(GROUP_B_MARKER)
    c = block.find(GROUP_C_MARKER)
    assert 0 < a < b < c, f"Groups must appear in A→B→C order; got positions A={a}, B={b}, C={c}"


# ---------------------------------------------------------------------------
# Volatile context paths are in Group C
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "param",
    [
        "PRIOR_FINDINGS_INDEX_PATH",
        "KNOWN_THREATS_INDEX_PATH",
        "CROSS_REPO_CONTEXT_PATH",
        "PHASE_8B_VIOLATIONS_INDEX_PATH",
    ],
)
def test_volatile_paths_listed_in_group_c(param):
    """Every volatile context path must be listed under Group C —
    listing it in Group A/B would break caching across dispatches."""
    block = _dispatch_block()
    c_start = block.find(GROUP_C_MARKER)
    assert c_start != -1
    # Search for the parameter name only after Group C's header. First
    # occurrence in the block must be inside Group C.
    first_occurrence = block.find(param)
    assert first_occurrence >= c_start, (
        f"{param} appears before Group C at position {first_occurrence} "
        f"(Group C starts at {c_start}). Volatile blobs must be last."
    )


def test_group_c_uses_paths_not_inline_json_contract():
    block = _dispatch_block()
    c_start = block.find(GROUP_C_MARKER)
    assert c_start != -1
    group_c = block[c_start:]
    assert "Do **not** inline the JSON arrays" in group_c
    assert ".dispatch-context/<COMPONENT_ID>/" in group_c


def test_threat_merger_component_map_is_path_not_inline_json():
    text = PHASE_GROUP_THREATS.read_text(encoding="utf-8")
    assert "COMPONENT_MAP_PATH=<OUTPUT_DIR>/.merge-context/component-map.json" in text
    assert "COMPONENT_MAP=<inline JSON" not in text


# ---------------------------------------------------------------------------
# Stable prefix parameters are in Group A
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "param",
    [
        "REPO_ROOT",
        "OUTPUT_DIR",
        "COMPLIANCE_SCOPE",
        "ASSET_TIER",
    ],
)
def test_stable_params_in_group_a(param):
    """Parameters that do not change between dispatches of the same agent
    type must be in Group A (the cacheable prefix)."""
    block = _dispatch_block()
    a_start = block.find(GROUP_A_MARKER)
    b_start = block.find(GROUP_B_MARKER)
    # First occurrence of the parameter must fall between Group A's header
    # and Group B's header (i.e. inside Group A).
    first = block.find(param)
    assert a_start <= first < b_start, (
        f"{param} must be listed inside Group A (positions {a_start}–{b_start}); first occurrence at {first}"
    )


# ---------------------------------------------------------------------------
# AGENTS.md documents the contract
# ---------------------------------------------------------------------------


def test_agents_md_has_caching_contract_section():
    text = AGENTS_MD.read_text(encoding="utf-8")
    assert "Prompt caching contract" in text, (
        "AGENTS.md must include a 'Prompt caching contract' section documenting the three-group dispatch layout"
    )
    # Must name all three groups
    for group_letter in ("Group A", "Group B", "Group C"):
        assert group_letter in text, f"AGENTS.md caching contract section must explain {group_letter}"


def test_claude_md_references_drift_guard():
    """The caching section must point at this very test file so future
    readers know how the contract is enforced."""
    text = AGENTS_MD.read_text(encoding="utf-8")
    assert "test_dispatch_prompt_cache_order" in text, (
        "AGENTS.md must reference tests/test_dispatch_prompt_cache_order.py"
    )
