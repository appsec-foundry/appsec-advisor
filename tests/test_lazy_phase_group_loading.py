"""Drift guards for the compact runtime's bounded instruction surfaces."""

from __future__ import annotations

from pathlib import Path

PLUGIN_ROOT = Path(__file__).parent.parent
SKILL_DIR = PLUGIN_ROOT / "skills" / "create-threat-model"
MODES_DIR = SKILL_DIR / "modes"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_business_context_reaches_the_default_full_runtime():
    runtime = _read(SKILL_DIR / "SKILL-full-runtime.md")
    router = _read(SKILL_DIR / "SKILL.md")
    mode = _read(MODES_DIR / "business-context.md")

    assert "BUSINESS_CONTEXT_SOURCE = business_context_source" in runtime
    assert runtime.count("modes/business-context.md") == 1
    assert "APPSEC_HEADLESS=1" in runtime
    assert "SKIP_BUSINESS_CONTEXT = skip_business_context" in runtime
    assert "skip_business_context` is true" in runtime
    assert runtime.index("modes/business-context.md") < runtime.index("## 3. Bind compact state")
    assert "Step 0 — A source was supplied" in mode
    assert "load_business_context.py" in mode
    assert "business-context question" in router


def test_full_runtime_loads_only_controller_returned_stage_surfaces():
    runtime = " ".join(_read(SKILL_DIR / "SKILL-full-runtime.md").split())

    assert "Read `ACTION.instruction_file` in full and follow it" in runtime
    assert "SKILL-thin-stage1-v2.md" in runtime
    assert "Do not substitute another file" in runtime
    assert "Only when `SKIP_ABUSE_CASE_VERIFICATION=false`" in runtime
    assert "SKILL-thin-stage1d.md" in runtime
    for name in (
        "SKILL-thin-stage2.md",
        "SKILL-thin-stage3.md",
        "SKILL-thin-stage4.md",
        "SKILL-thin-completion.md",
    ):
        assert name in runtime
    assert "There is no legacy range or fallback" in runtime


def test_rerender_runtime_uses_the_same_release_tail():
    runtime = _read(SKILL_DIR / "SKILL-rerender-runtime.md")

    assert "SKILL-thin-stage2.md" in runtime
    assert "SKILL-thin-stage3.md" in runtime
    assert "SKILL-thin-stage4.md" in runtime
    assert "SKILL-thin-completion.md" in runtime
    assert "secret gate is never optional" in runtime
    assert "There is no legacy slice" in runtime


def test_stage3_preserves_the_secret_gate_and_canonical_mutation_order():
    stage3 = _read(SKILL_DIR / "SKILL-thin-stage3.md")

    assert "unmasked_secrets" in stage3
    assert "Never skip this" in stage3 and "Quick" in stage3
    assert "SKIP_QA=true" in stage3
    assert "compose --strict → apply_prose_fixes → qa_checks.py gate" in stage3
    assert "MAX_REPAIR_ITERATIONS" in stage3
    assert "appsec-advisor:appsec-fragment-fixer" in stage3
    assert stage3.rindex("unmasked_secrets") > stage3.index('qa_checks.py" gate')


def test_completion_owns_cross_path_release_gates_in_order():
    completion = _read(SKILL_DIR / "SKILL-thin-completion.md")

    patch = completion.index("--patch-placeholders --no-print")
    final_structure = completion.index('qa_checks.py" final_structure')
    completeness = completion.index("assert_completeness.py")
    integrity = completion.index("section_integrity.py")
    exports = completion.index("## 2. Exports and summary")
    assert patch < final_structure < completeness < integrity < exports
    assert "reclassify_components.py" in completion
    assert "toc_closure" in completion
    assert "runtime_cleanup.py" in completion


def test_stage4_repairs_return_through_stage3():
    stage4 = _read(SKILL_DIR / "SKILL-thin-stage4.md")

    assert ".architect-status.json" in stage4
    assert "repair_required" in stage4
    assert "MAX_REPAIR_ITERATIONS" in stage4
    assert "SKILL-thin-stage3.md" in stage4
    assert "secret gate" in stage4


def test_removed_legacy_runtime_surfaces_are_absent():
    assert not (SKILL_DIR / "SKILL-impl.md").exists()
    assert not (MODES_DIR / "rerender.md").exists()
    assert not (MODES_DIR / "rebuild-wipe.md").exists()
    assert not (MODES_DIR / "full-scan-recommendation.md").exists()


def test_agents_md_describes_the_compact_runtime_only():
    agents = _read(PLUGIN_ROOT / "AGENTS.md")
    assert "SKILL-impl.md" not in agents
    assert "APPSEC_THIN_ORCHESTRATOR" not in agents
