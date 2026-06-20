"""
Tests for Sprint 4 Item #9 — lazy loading of phase-group files.

Invariant: `appsec-threat-analyst.md` MUST read
  - phase-group-recon.md         at startup (Pre-Phase checklist step 10)
  - phase-group-architecture.md  just before Phase 3
  - phase-group-threats.md       just before Phase 9
  - phase-group-finalization.md  just before Phase 11

It MUST NOT instruct the model to read all four files in one batched call at
startup — that was the pre-Sprint-4 behaviour and carries ~108k tokens of
wasted startup context.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
ANALYST_MD = PLUGIN_ROOT / "agents" / "appsec-threat-analyst.md"
AGENTS_MD = PLUGIN_ROOT / "AGENTS.md"


def _text() -> str:
    return ANALYST_MD.read_text(encoding="utf-8")


def _slice_between(text: str, start_marker: str, end_marker: str) -> str:
    """Return the substring starting at the first occurrence of start_marker
    and ending at the next occurrence of end_marker. Empty string if the
    markers are not found in order."""
    s = text.find(start_marker)
    if s == -1:
        return ""
    e = text.find(end_marker, s + len(start_marker))
    return text[s:e] if e != -1 else text[s:]


# ---------------------------------------------------------------------------
# Startup: only phase-group-recon.md
# ---------------------------------------------------------------------------


class TestStartupReadsReconOnly:
    def test_pre_phase_block_mentions_recon(self):
        """The Pre-Phase checklist must load phase-group-recon.md."""
        text = _text()
        # The Pre-Phase-checklist Step 10 section
        block = _slice_between(text, "10. **Read the FIRST phase-group file", "11.")
        if not block:
            block = _slice_between(text, "Pre-Phase checklist", "Post-assessment cleanup")
        assert "phase-group-recon.md" in block, "Pre-Phase checklist Step 10 must read phase-group-recon.md at startup"

    def test_pre_phase_block_does_not_instruct_all_four_upfront(self):
        """Regression: the prior instruction 'Read all four phase-group
        files in parallel' must be gone from the Pre-Phase checklist.
        Explanatory references to that pattern (e.g. 'instead of reading
        all four…') are permitted — we only guard against the imperative
        form returning."""
        text = _text()
        block = _slice_between(text, "**Pre-Phase checklist", "Only then proceed")
        assert block, "Pre-Phase checklist block not found"
        # The exact former instruction. Any variant that imperatively tells
        # the model to read all four in one batch must not survive.
        forbidden = [
            "read all four phase-group files in parallel",
            "issue four read tool calls simultaneously",
            "read all four in parallel",
        ]
        low = block.lower()
        for phrase in forbidden:
            assert phrase not in low, (
                f"Pre-Phase checklist contains the imperative phrase "
                f"{phrase!r} — Sprint 4 Item #9 replaced that with lazy loading"
            )

    def test_pre_phase_block_lists_deferred_loads_in_a_table(self):
        """The checklist should explicitly name which phase-group files are
        loaded later, at which phase boundary — prevents ambiguity."""
        text = _text()
        block = _slice_between(text, "**Pre-Phase checklist", "Only then proceed")
        for name in ("phase-group-architecture.md", "phase-group-threats.md", "phase-group-finalization.md"):
            assert name in block, (
                f"Pre-Phase checklist must mention {name} in the lazy-load "
                f"schedule table so the reader knows when it gets loaded"
            )


# ---------------------------------------------------------------------------
# Phase 3 / 9 / 11 boundary reads
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "heading,phase_group_file",
    [
        ("### Phases 3–7: Architecture & Analysis", "phase-group-architecture.md"),
        ("### Phase 9: Threat Enumeration", "phase-group-threats.md"),
        ("### Phases 10–11: Synthesis, Triage & Finalization", "phase-group-finalization.md"),
    ],
)
def test_phase_boundary_has_lazy_load_instruction(heading, phase_group_file):
    """Each of the three downstream phase-group files must be read at the
    boundary of the phase(s) it governs, NOT earlier. The instruction must
    include a Read() tool call with the file path."""
    text = _text()
    block_start = text.find(heading)
    assert block_start != -1, f"phase heading not found: {heading}"
    # Inspect only the next ~1500 chars after the heading — the lazy-load
    # instruction should sit at the top of the section.
    block = text[block_start : block_start + 1500]
    assert f"Read($CLAUDE_PLUGIN_ROOT/agents/phases/{phase_group_file})" in block, (
        f"Phase section '{heading}' must contain a Read() instruction for {phase_group_file}"
    )
    # Positive corroborating signal: the text mentions "Lazy-load"
    assert "Lazy-load" in block or "lazy-load" in block, (
        f"Phase section '{heading}' must explicitly name this as a lazy-load "
        f"step so future readers do not collapse it back into the startup batch"
    )


def test_phase_boundary_reads_are_unique():
    """Each downstream phase-group file must only be loaded once — at its
    boundary. Duplicate Read() instructions would undo the benefit of lazy
    loading (and potentially re-parse the file)."""
    text = _text()
    for f in ("phase-group-architecture.md", "phase-group-threats.md", "phase-group-finalization.md"):
        read_call = f"Read($CLAUDE_PLUGIN_ROOT/agents/phases/{f})"
        count = text.count(read_call)
        assert count == 1, (
            f"{f} Read() instruction appears {count}× — must be exactly 1 (the lazy-load call at its phase boundary)"
        )


# ---------------------------------------------------------------------------
# AGENTS.md documents the protocol
# ---------------------------------------------------------------------------


def test_agents_md_documents_lazy_loading():
    """The orchestrator protocol change must be called out in AGENTS.md so
    future contributors understand it is intentional."""
    text = AGENTS_MD.read_text(encoding="utf-8")
    # Must mention 'lazy-load' (or 'lazy loading') specifically in the
    # phase-group-files paragraph.
    assert re.search(r"lazy[- ]load", text, re.IGNORECASE), (
        "AGENTS.md must document the lazy-loading protocol (Sprint 4 Item #9)"
    )


# ---------------------------------------------------------------------------
# P8 — mode-specific sections lazy-loaded out of SKILL-impl.md (modes/*.md)
# ---------------------------------------------------------------------------

SKILL_IMPL_MD = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
MODES_DIR = PLUGIN_ROOT / "skills" / "create-threat-model" / "modes"


def test_rerender_mode_lazy_loaded_not_inline():
    """P8: the rerender branch body must live in modes/rerender.md and be loaded
    just-in-time, not sit inline in SKILL-impl.md's resident full-run context.
    SKILL-impl.md keeps exactly one lazy-load pointer; the operative bash gate
    moved verbatim into the mode file."""
    impl = SKILL_IMPL_MD.read_text(encoding="utf-8")
    mode = (MODES_DIR / "rerender.md").read_text(encoding="utf-8")

    gate = "rerender needs an existing assessment"
    assert gate not in impl, "rerender precondition gate must NOT be inline in SKILL-impl.md (lazy-load it)"
    assert gate in mode, "rerender precondition gate must live verbatim in modes/rerender.md"

    assert impl.count("modes/rerender.md") == 1, (
        "SKILL-impl.md must reference modes/rerender.md exactly once (single lazy-load pointer)"
    )
    assert "only when `MODE=rerender`" in impl, "the modes/rerender.md load must be explicitly gated on rerender mode"
