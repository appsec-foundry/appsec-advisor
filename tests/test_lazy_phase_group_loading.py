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


def test_full_scan_recommendation_lazy_loaded_not_inline():
    """Context-budget fix (2026-06-23): the auto-incremental full-scan recommendation
    prompt body must live in modes/full-scan-recommendation.md and load just-in-time,
    not sit inline in SKILL-impl.md's resident full-run context. A standard/full scan
    never runs this branch, so carrying it in context is pure dead weight. SKILL-impl.md
    keeps exactly one gated lazy-load pointer; the operative bash moved verbatim into the
    mode file."""
    impl = SKILL_IMPL_MD.read_text(encoding="utf-8")
    mode = (MODES_DIR / "full-scan-recommendation.md").read_text(encoding="utf-8")

    gate = "Incremental run not recommended"
    assert gate not in impl, "full-scan recommendation prompt body must NOT be inline in SKILL-impl.md (lazy-load it)"
    assert gate in mode, "full-scan recommendation prompt must live verbatim in modes/full-scan-recommendation.md"

    assert impl.count("modes/full-scan-recommendation.md") == 1, (
        "SKILL-impl.md must reference modes/full-scan-recommendation.md exactly once (single lazy-load pointer)"
    )
    assert "only when `MODE=incremental`" in impl, (
        "the modes/full-scan-recommendation.md load must be explicitly gated on auto-incremental mode"
    )


def test_rebuild_wipe_lazy_loaded_not_inline():
    """Context-budget fix (2026-06-23): the rebuild pre-flight wipe body must live in
    modes/rebuild-wipe.md and load just-in-time, not sit inline in SKILL-impl.md's
    resident full-run context. A full / standard / thorough scan without --rebuild never
    runs this branch. SKILL-impl.md keeps exactly one gated lazy-load pointer; the
    operative bash moved verbatim into the mode file."""
    impl = SKILL_IMPL_MD.read_text(encoding="utf-8")
    mode = (MODES_DIR / "rebuild-wipe.md").read_text(encoding="utf-8")

    gate = "discarding prior threat model and all cached state"
    assert gate not in impl, "rebuild wipe body must NOT be inline in SKILL-impl.md (lazy-load it)"
    assert gate in mode, "rebuild wipe body must live verbatim in modes/rebuild-wipe.md"

    assert impl.count("modes/rebuild-wipe.md") == 1, (
        "SKILL-impl.md must reference modes/rebuild-wipe.md exactly once (single lazy-load pointer)"
    )
    assert "only when `REBUILD=true`" in impl, "the modes/rebuild-wipe.md load must be explicitly gated on rebuild mode"


def test_skill_impl_stage2_tail_lazy_loaded():
    """Context-budget fix (2026-06-23): the orchestrator must read SKILL-impl.md only
    through the LAZY-LOAD BOUNDARY during initial load (Stage 1 core), deferring the
    Stage 2/3/4/Completion tail until its individual stage boundaries. This keeps the
    pre-flight resident context below the auto-compaction threshold that otherwise fires
    just before STRIDE dispatch. Content stays in SKILL-impl.md (no test churn) — only the
    *read schedule* changes."""
    skill = (PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL.md").read_text(encoding="utf-8")
    impl = SKILL_IMPL_MD.read_text(encoding="utf-8")

    # SKILL.md no longer reads the whole file upfront; it stops at the boundary.
    assert "read `<base-dir>/SKILL-impl.md` in full" not in skill, (
        "SKILL.md must NOT instruct reading SKILL-impl.md in full (defeats the lazy tail)"
    )
    assert "LAZY-LOAD BOUNDARY" in skill, "SKILL.md must point the initial read at the LAZY-LOAD BOUNDARY"

    # Exactly one boundary marker, and it defers Stage 1c plus later stages.
    assert impl.count("<!-- LAZY-LOAD BOUNDARY") == 1, (
        "SKILL-impl.md must contain exactly one LAZY-LOAD BOUNDARY marker"
    )
    boundary_pos = impl.find("<!-- LAZY-LOAD BOUNDARY")
    stage1c_pos = impl.find("## Stage 1c — Abuse Case Verification")
    stage2_pos = impl.find("## Stage 2 - Report Rendering")
    assert 0 < boundary_pos < stage1c_pos < stage2_pos, (
        "the LAZY-LOAD BOUNDARY marker must defer Stage 1c and every later stage"
    )

    # The bounded resume instruction must sit above the marker, and neither the
    # router nor the prefix may tell legacy mode to ingest the complete tail.
    resume_pos = impl.find("Follow the bounded schedule")
    assert 0 < resume_pos < boundary_pos
    bounded_instruction = " ".join(impl[resume_pos:boundary_pos].split())
    assert "Do not read from this marker to EOF" in bounded_instruction
    assert "do not read the whole tail" in skill
    for heading in (
        "## Stage 2 - Report Rendering",
        "## Stage 3 - QA Review",
        "## Stage 4 - Architect Review",
        "## Completion Summary",
        "## Error Handling",
    ):
        assert heading in skill
    assert "skip it for rerender and Stage-2-only recovery paths" in skill
    prefix = impl[:boundary_pos]
    assert "rerender and Stage-2-only recovery go directly to\nStage 2" in prefix


def test_thin_runtime_loads_stage1c_only_when_enabled():
    runtime = (PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(
        encoding="utf-8"
    )
    assert "stop before\n`## Stage 1c — Abuse Case Verification`" in runtime
    assert "Only when\n`SKIP_ABUSE_CASE_VERIFICATION=false`" in runtime
    assert "Verification` to `## Stage 2 - Report Rendering`" in runtime
    assert "Otherwise do not load the Stage-1c slice" in runtime


def test_non_dry_stage3_safety_slice_cannot_be_bypassed_by_controller_action():
    """Quick/no-QA paths may return stage4/complete from the controller, but
    the depth-independent secret gate still has to run before either action."""
    router = (PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL.md").read_text(encoding="utf-8")
    full = (PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(
        encoding="utf-8"
    )
    rerender = (PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-rerender-runtime.md").read_text(
        encoding="utf-8"
    )

    for text in (router, full, rerender):
        normalized = " ".join(text.split())
        assert "Stage-3 safety slice" in normalized
        assert "secret-leak gate" in normalized
        assert "stage4" in normalized and "complete" in normalized


def test_completion_slice_owns_cross_path_release_gates():
    """Final integrity gates must not live in optional Stage 4: standard runs
    without architect review jump directly to the Completion slice."""
    impl = SKILL_IMPL_MD.read_text(encoding="utf-8")
    completion = impl.find("## Completion Summary")
    hard_link_gate = impl.find("### Hard broken-link gate")
    error_handling = impl.find("## Error Handling")

    assert 0 < completion < hard_link_gate < error_handling
    completion_slice = impl[completion:error_handling]
    assert "reclassify_components.py" in completion_slice
    assert "qa_checks.py\" toc_closure" in completion_slice


def test_stage4_lazy_loads_repair_contract_only_when_required():
    """A clean Stage-3 fast path must not make architect repair instructions
    unreachable, while a passing architect review should not pay for them."""
    impl = SKILL_IMPL_MD.read_text(encoding="utf-8")
    stage4 = impl.find("## Stage 4 - Architect Review")
    completion = impl.find("## Completion Summary")
    block = impl[stage4:completion]

    assert ".architect-status.json" in block
    assert "repair_required" in block
    assert "Re-Render Loop — enforce strict contract" in block
    assert "Do not load the repair block when the status is `pass`" in block


def test_agents_md_does_not_claim_full_impl_is_resident():
    agents = AGENTS_MD.read_text(encoding="utf-8")
    assert "`SKILL-impl.md` is read in full into the orchestrator's resident context" not in agents
    assert "`SKILL-impl.md` is large and is read in bounded slices" in agents
