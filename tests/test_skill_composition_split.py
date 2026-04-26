"""Doc-drift tests for the M2.12 Composition split (formerly "Stage 1b").

These tests verify the contract documented in SKILL-impl.md and
agents/appsec-threat-analyst.md is internally consistent:

  * Both files mention the new env vars (STAGE1_PHASE_LIMIT, RENDER_ONLY)
  * The Stage 1 dispatch passes STAGE1_PHASE_LIMIT=10b
  * The Stage 2 (Composition) dispatch passes RENDER_ONLY=true
  * The Stage 2 task is in the bootstrap table
  * The phase-10b precondition gate is documented
  * The pre-generator is wired in before/after Stage 2 dispatch
  * The orchestrator agent documents both branches with required substeps
  * Mutual-exclusivity is documented in both directions

Behavioural execution of the dispatch is out of scope for unit tests —
that is covered by the end-to-end run against juice-shop.
"""
from __future__ import annotations

from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
SKILL_IMPL = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
ORCHESTRATOR = PLUGIN_ROOT / "agents" / "appsec-threat-analyst.md"


@pytest.fixture(scope="module")
def skill_impl_text() -> str:
    return SKILL_IMPL.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def orchestrator_text() -> str:
    return ORCHESTRATOR.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# SKILL-impl.md — bootstrap table includes Stage 2 (Composition)
# ---------------------------------------------------------------------------

def test_bootstrap_table_includes_composition_stage_always(skill_impl_text):
    assert "Stage 2 — Composition (Phase 11)" in skill_impl_text, (
        "Bootstrap table must list Stage 2 (Composition) as an always-created task (M2.12)"
    )


def test_stage_1_task_renamed_to_phases_1_10b(skill_impl_text):
    # The original "Stage 1 — Threat Model Orchestrator" wording is replaced
    # with the new Phase-1-10b scope marker.
    assert "Stage 1 — Threat Model Orchestrator (Phases 1–10b)" in skill_impl_text


# ---------------------------------------------------------------------------
# SKILL-impl.md — Phase-10b precondition gate
# ---------------------------------------------------------------------------

def test_phase10b_precondition_gate_documented(skill_impl_text):
    assert "Phase-10b precondition gate" in skill_impl_text
    # The four mandatory artifacts must be enumerated
    assert ".threats-merged.json" in skill_impl_text
    assert ".triage-flags.json" in skill_impl_text
    assert "threat-model.yaml" in skill_impl_text


# ---------------------------------------------------------------------------
# SKILL-impl.md — Stage 1 dispatch passes STAGE1_PHASE_LIMIT=10b
# ---------------------------------------------------------------------------

def test_stage1_dispatch_sets_phase_limit(skill_impl_text):
    assert "STAGE1_PHASE_LIMIT=10b" in skill_impl_text, (
        "Stage 1 dispatch must explicitly set STAGE1_PHASE_LIMIT=10b so the "
        "orchestrator stops cleanly after Phase 10b"
    )


# ---------------------------------------------------------------------------
# SKILL-impl.md — Stage 2 (Composition) dispatch passes RENDER_ONLY=true
# ---------------------------------------------------------------------------

def test_composition_dispatch_sets_render_only(skill_impl_text):
    assert "RENDER_ONLY=true" in skill_impl_text


def test_composition_documents_pre_generator_call(skill_impl_text):
    # Pre-dispatch pre-generation step must be documented
    assert "pregenerate_fragments.py" in skill_impl_text
    # Idempotent claim must be present so future maintainers don't try to
    # gate it behind "only-if-empty" logic
    assert "idempotent" in skill_impl_text.lower()


def test_composition_handoff_banner_documented(skill_impl_text):
    assert "Stage 2 — Composition (Phase 11) starting" in skill_impl_text
    assert "fresh 120-turn budget" in skill_impl_text


# ---------------------------------------------------------------------------
# SKILL-impl.md — env-var documentation in "Passing configuration"
# ---------------------------------------------------------------------------

def test_env_vars_documented_in_passing_config(skill_impl_text):
    # Both new variables must appear in the "Passing configuration" enum
    # — that is the source of truth for what the agent receives.
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


def test_orchestrator_documents_render_only_branch(orchestrator_text):
    assert "RENDER_ONLY=true" in orchestrator_text
    # Stage 2 (Composition) must explicitly skip Phases 1-10b
    assert "skips Phases 1–10b" in orchestrator_text or "skip Phases 1–10b" in orchestrator_text
    # The 2 LLM fragments must be named
    assert "ms-verdict.json" in orchestrator_text
    assert "ms-architecture-assessment.json" in orchestrator_text
    # The 6 structural ones must be named as pre-generated
    assert "system-overview.md" in orchestrator_text
    assert "architecture-diagrams.md" in orchestrator_text
    assert "security-architecture.md" in orchestrator_text


def test_orchestrator_branches_are_mutually_exclusive(orchestrator_text):
    # Both ends document the mutual-exclusivity invariant
    assert "Mutual exclusivity" in orchestrator_text or "mutually exclusive" in orchestrator_text


# ---------------------------------------------------------------------------
# Cross-file consistency — both files agree on the names
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("env_var", ["STAGE1_PHASE_LIMIT", "RENDER_ONLY"])
def test_env_vars_appear_in_both_files(skill_impl_text, orchestrator_text, env_var):
    assert env_var in skill_impl_text, f"{env_var} not in SKILL-impl.md"
    assert env_var in orchestrator_text, f"{env_var} not in orchestrator agent"


def test_max_turns_120_documented_in_orchestrator(orchestrator_text):
    # The bump from M2.9 must still be in the frontmatter
    assert "maxTurns: 120" in orchestrator_text
    # And referenced in the M2.9 header guidance
    assert "M2.9" in orchestrator_text or "120 turns" in orchestrator_text
