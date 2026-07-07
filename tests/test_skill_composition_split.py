"""Doc-drift tests for the M2.12 Stage-2 render split (formerly "Stage 1b").

These tests verify the contract documented in SKILL-impl.md and
agents/appsec-threat-analyst.md is internally consistent:

  * Skill dispatches Stage 1 via analyst and Stage 2 via renderer
  * The Stage 1 dispatch passes STAGE1_PHASE_LIMIT=10b
  * The Stage 2 (Composition) dispatch uses appsec-threat-renderer
  * The Stage 2 task is in the bootstrap table
  * The phase-10b precondition gate is documented
  * The pre-generator is wired in before/after Stage 2 dispatch
  * The orchestrator agent documents both branches with required substeps
  * Mutual-exclusivity is documented in both directions

Behavioural execution of the dispatch is out of scope for unit tests —
that is covered by the end-to-end run against juice-shop.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
SKILL_IMPL = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
ORCHESTRATOR = PLUGIN_ROOT / "agents" / "appsec-threat-analyst.md"
RENDERER = PLUGIN_ROOT / "agents" / "appsec-threat-renderer.md"


@pytest.fixture(scope="module")
def skill_impl_text() -> str:
    return SKILL_IMPL.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def orchestrator_text() -> str:
    return ORCHESTRATOR.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def renderer_text() -> str:
    return RENDERER.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# SKILL-impl.md — bootstrap table includes Stage 2 (Report Rendering)
# ---------------------------------------------------------------------------


def test_bootstrap_table_includes_composition_stage_always(skill_impl_text):
    assert "Stage 2 - Report Rendering" in skill_impl_text, (
        "Bootstrap table must list Stage 2 (Report Rendering) as an always-created task (M2.12)"
    )


def test_stage_1_split_into_lettered_subrows(skill_impl_text):
    # Stage 1 is exposed as three lettered sub-rows (2026-06): 1a/1b run
    # inside the single analyst dispatch, 1c is the separate abuse-case
    # verifier fan-out. Subjects use hyphen-minus (`-`), not em-dash (`—`),
    # because the TodoWrite renderer mis-handles multi-byte em-dash widths
    # and bleeds adjacent task labels into each other. The `&`/em-dash
    # canonical names may still appear in headings/prose/stats where the
    # rendering path is unaffected.
    assert "`Stage 1a - Threat Analysis`" in skill_impl_text
    assert "`Stage 1b - Triage`" in skill_impl_text
    assert "`Stage 1c - Abuse Case Verification`" in skill_impl_text


# ---------------------------------------------------------------------------
# SKILL-impl.md — Phase-10b precondition gate
# ---------------------------------------------------------------------------


def test_phase10b_precondition_gate_documented(skill_impl_text):
    assert "Phase-10b precondition gate" in skill_impl_text
    # The four mandatory artifacts must be enumerated
    assert ".threats-merged.json" in skill_impl_text
    assert ".triage-flags.json" in skill_impl_text
    assert "threat-model.yaml" in skill_impl_text


def test_deterministic_phase10b_ranking_wired_at_skill_level(skill_impl_text):
    """The deterministic Phase-10b Step 6 ranking must run at skill level with
    --force (env vars do not reach skill/agent Bash, so the in-agent
    APPSEC_TRIAGE_DETERMINISTIC gate never flips and the LLM fallback emits a
    v1 .triage-flags.json with no ranking block). Regression guard for the
    2026-06-18 e2e failure."""
    assert "Deterministic Phase-10b ranking (skill-level)" in skill_impl_text
    # The skill-level invocation must use --force to bypass the env feature flag.
    assert re.search(
        r"triage_compute_ranking\.py[^\n]*\n[^\n]*--force",
        skill_impl_text,
    ), "skill-level triage_compute_ranking.py must be invoked with --force"


# ---------------------------------------------------------------------------
# SKILL-impl.md — Stage 1 dispatch passes STAGE1_PHASE_LIMIT=10b
# ---------------------------------------------------------------------------


def test_stage1_dispatch_sets_phase_limit(skill_impl_text):
    assert "STAGE1_PHASE_LIMIT=10b" in skill_impl_text, (
        "Stage 1 dispatch must explicitly set STAGE1_PHASE_LIMIT=10b so the orchestrator stops cleanly after Phase 10b"
    )


# ---------------------------------------------------------------------------
# SKILL-impl.md — Stage 2 (Report Rendering) dispatch uses renderer
# ---------------------------------------------------------------------------


def test_composition_dispatch_uses_renderer(skill_impl_text):
    assert "appsec-advisor:appsec-threat-renderer" in skill_impl_text
    assert "Threat Model Renderer (Stage 2)" in skill_impl_text


def test_composition_documents_pre_generator_call(skill_impl_text):
    # Pre-dispatch pre-generation step must be documented
    assert "pregenerate_fragments.py" in skill_impl_text
    # Idempotent claim must be present so future maintainers don't try to
    # gate it behind "only-if-empty" logic
    assert "idempotent" in skill_impl_text.lower()


def test_composition_handoff_banner_documented(skill_impl_text):
    assert "Stage 2 - Report Rendering starting" in skill_impl_text
    assert "renderer budget" in skill_impl_text


def test_stage2_conditional_qa_gate_documented(skill_impl_text, renderer_text):
    assert "conditional QA" in skill_impl_text
    assert "SKIP_QA=true" in skill_impl_text
    assert "DRY_RUN=true" in skill_impl_text
    assert "PR_MODE=true" in skill_impl_text
    assert 'qa_checks.py" all' in renderer_text
    assert 'qa_checks.py" contract' in renderer_text
    assert "SKIP_QA" in renderer_text
    assert "DRY_RUN" in renderer_text
    assert "PR_MODE" in renderer_text


# ---------------------------------------------------------------------------
# SKILL-impl.md — env-var documentation in "Passing configuration"
# ---------------------------------------------------------------------------


def test_env_vars_documented_in_passing_config(skill_impl_text):
    # Stage 1 limit remains the source of truth for stopping before render.
    # RENDER_ONLY remains documented only as a legacy compatibility signal.
    assert "STAGE1_PHASE_LIMIT=10b" in skill_impl_text
    assert "RENDER_ONLY=true" in skill_impl_text
    # Mutual-exclusivity must be documented on at least one of them
    assert "Mutually exclusive" in skill_impl_text


# ---------------------------------------------------------------------------
# Orchestrator agent — STAGE1_PHASE_LIMIT branch documented
# ---------------------------------------------------------------------------


def test_orchestrator_documents_phase_limit_branch(orchestrator_text):
    assert "STAGE1_PHASE_LIMIT" in orchestrator_text
    assert "stops cleanly" in orchestrator_text or "stop cleanly" in orchestrator_text
    # Behaviour contract must include the checkpoint write
    assert "phase=10b status=completed" in orchestrator_text
    assert "need_render=true" in orchestrator_text


def test_renderer_documents_render_scope(orchestrator_text, renderer_text):
    assert "RENDER_ONLY=true" in orchestrator_text
    # Stage 2 (Composition) must explicitly skip Phases 1-10b
    assert "Skip Phases 1–10b" in renderer_text or "skip Phases 1–10b" in renderer_text
    # The LLM fragment must be named
    assert "ms-verdict.json" in renderer_text
    # The 7 structural ones must be named as pre-generated
    assert "system-overview.md" in renderer_text
    assert "architecture-diagrams.md" in renderer_text
    assert "security-architecture.md" in renderer_text


def test_orchestrator_branches_are_mutually_exclusive(orchestrator_text):
    # Both ends document the mutual-exclusivity invariant
    assert "Mutual exclusivity" in orchestrator_text or "mutually exclusive" in orchestrator_text


# ---------------------------------------------------------------------------
# Cross-file consistency — both files agree on the names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("env_var", ["STAGE1_PHASE_LIMIT"])
def test_env_vars_appear_in_skill_and_orchestrator(skill_impl_text, orchestrator_text, env_var):
    assert env_var in skill_impl_text, f"{env_var} not in SKILL-impl.md"
    assert env_var in orchestrator_text, f"{env_var} not in orchestrator agent"


def test_max_turns_120_documented_in_orchestrator(orchestrator_text):
    # The orchestrator turn budget was bumped past the legacy 75 (M2.9 →
    # 75 → 120 → 250 → 300). The frontmatter must carry the current ceiling
    # and the M2.9 guidance header documenting why.
    assert "maxTurns: 300" in orchestrator_text
    # And referenced in the M2.9 header guidance
    assert "M2.9" in orchestrator_text or "120 turns" in orchestrator_text


@pytest.mark.parametrize("heading", ["Verbose Mode — Marker File Lifecycle", "Tracing Mode — Marker File Lifecycle"])
def test_marker_lifecycle_section_is_single_source(skill_impl_text, heading):
    """P4 (2026-06-20): the verbose/tracing marker-file lifecycle had a divergent
    duplicate — an early `$VERBOSE_REPORT`/`$TRACING`-gated copy plus the canonical
    `RESOLVED_JSON`-gated one with the EXIT trap. Consolidated to one authoritative
    section each; guard against the duplicate creeping back."""
    assert skill_impl_text.count(f"### {heading}") == 1, (
        f"'{heading}' must appear exactly once — the divergent duplicate was removed"
    )


def test_display_renumber_is_wired_and_persists_section6(skill_impl_text):
    """The ONE sanctioned last-mile mutator is `renumber_sections_display.py`:
    it relabels §7→§6 so the persisted `threat-model.md` (and every derived
    deliverable) shows contiguous §1–§10. The §7 document is preserved as a
    mirror at `.appsec-cache/threat-model.canonical7.md` for the next run's §7
    carry-forward + qa_checks contract matching — but the primary
    `threat-model.md` is NOT restored to §7 (it stays §6, the reader-facing form).

    No OTHER post-QA report mutator may be wired (they would silently change the
    QA-clean report content), and the gray-ramp presentation remains owned by
    `qa_checks.py autofix`."""
    # The display renumber IS wired, and the §7 mirror is kept under .appsec-cache/.
    assert "renumber_sections_display.py" in skill_impl_text
    assert ".appsec-cache/threat-model.canonical7.md" in skill_impl_text
    # The persisted threat-model.md must NOT be restored back to §7 (the old
    # design). If a restore reappears, the reader-facing file would revert to §7.
    assert 'mv -f "$OUTPUT_DIR/.threat-model.canonical7.md" "$OUTPUT_DIR/threat-model.md"' not in skill_impl_text
    # No other content-mutating post-QA passes.
    assert "style_priority_circles.py" not in skill_impl_text
    assert "`qa_checks.py autofix` owns the final presentation-only gray ramp" in skill_impl_text


def test_final_structure_gate_runs_after_last_mutation_before_exports(skill_impl_text):
    completion_idx = skill_impl_text.find("### Normal Completion (DRY_RUN=false)")
    patch_idx = skill_impl_text.find("--patch-placeholders \\", completion_idx)
    no_print_idx = skill_impl_text.find("--no-print", patch_idx)
    final_idx = skill_impl_text.find("final_structure", patch_idx)
    completeness_idx = skill_impl_text.find("--phase render", final_idx)
    integrity_idx = skill_impl_text.find("section_integrity.py", completeness_idx)
    summary_idx = skill_impl_text.find(
        'python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_completion_summary.py"',
        integrity_idx,
    )
    pdf_idx = skill_impl_text.find("export_pdf.py", integrity_idx)
    html_idx = skill_impl_text.find("export_html.py", integrity_idx)

    assert -1 not in {
        completion_idx,
        patch_idx,
        no_print_idx,
        final_idx,
        completeness_idx,
        integrity_idx,
        summary_idx,
        pdf_idx,
        html_idx,
    }
    assert patch_idx < no_print_idx < final_idx < completeness_idx < integrity_idx
    assert integrity_idx < summary_idx < pdf_idx
    assert integrity_idx < summary_idx < html_idx
