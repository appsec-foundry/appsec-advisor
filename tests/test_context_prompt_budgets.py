from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BUDGETS = yaml.safe_load((ROOT / "data" / "context-budgets.yaml").read_text(encoding="utf-8"))

# Review ratchet: a larger ceiling must change this test as well as the data
# file, so budget growth cannot hide inside a prompt edit. Lower ceilings pass
# without updating the ratchet; new surfaces must be admitted explicitly.
SURFACE_MAX_BYTES_RATCHET = {
    "contributor_instruction_loader": 256,
    "contributor_instructions": 18500,
    "skill_router": 8500,
    "thin_full_runtime": 13250,
    "thin_rerender_runtime": 10000,
    "thin_stage1_v2_runtime": 6400,
    "thin_stage1d_runtime": 3400,
    "thin_stage2_runtime": 3600,
    "thin_stage3_runtime": 8000,
    "thin_stage4_runtime": 3600,
    "thin_completion_runtime": 6000,
    "shared_threat_analysis_kernel": 16000,
    "architecture_analyst_role": 12000,
    "control_analyst_role": 12000,
    "post_stride_synthesizer_role": 12000,
    "stride_analyzer_role": 12000,
    "stride_lens_llm": 7000,
    "stride_lens_agentic": 8000,
    "stride_lens_spa": 3500,
    "stride_lens_mobile": 2500,
    "stride_lens_supply_chain": 14000,
}


def test_context_budget_contract_shape():
    assert BUDGETS["version"] == 1
    assert BUDGETS["surfaces"]
    for name, spec in BUDGETS["surfaces"].items():
        assert (ROOT / spec["path"]).is_file(), name
        assert isinstance(spec["max_bytes"], int) and spec["max_bytes"] > 0
    admission = BUDGETS["admission"]
    assert admission == {
        "shared_kernel_max_tokens": 4000,
        "role_contract_max_tokens": 3000,
        "dispatch_task_max_tokens": 1500,
        "state_manifest_max_tokens": 500,
        "plugin_selected_startup_max_tokens": 10000,
        "initial_resident_max_tokens": 30000,
        "enforce_startup_totals": False,
    }


def test_surface_budget_increases_require_an_explicit_ratchet_change():
    surfaces = BUDGETS["surfaces"]
    assert set(surfaces) == set(SURFACE_MAX_BYTES_RATCHET)
    increased = {
        name: (spec["max_bytes"], SURFACE_MAX_BYTES_RATCHET[name])
        for name, spec in surfaces.items()
        if spec["max_bytes"] > SURFACE_MAX_BYTES_RATCHET[name]
    }
    assert not increased, f"surface budget increase requires ratchet review: {increased}"


def _slice_bytes(spec: dict) -> int:
    raw = (ROOT / spec["path"]).read_bytes()
    start = spec.get("start")
    end = spec.get("end")
    if start and start != "BOF":
        marker = start.encode()
        assert raw.count(marker) == 1, f"{spec['path']}: start marker must be unique"
        raw = raw[raw.index(marker) :]
    if end and end != "EOF":
        marker = end.encode()
        assert raw.count(marker) == 1, f"{spec['path']}: end marker must be unique"
        raw = raw[: raw.index(marker)]
    return len(raw)


def test_each_live_prompt_surface_stays_within_budget():
    failures = []
    for name, spec in BUDGETS["surfaces"].items():
        actual = _slice_bytes(spec)
        if actual > spec["max_bytes"]:
            failures.append(f"{name}: {actual} > {spec['max_bytes']} bytes")
    assert not failures, "\n".join(failures)


def test_shared_kernel_stays_within_token_admission_budget():
    spec = BUDGETS["surfaces"]["shared_threat_analysis_kernel"]
    text = (ROOT / spec["path"]).read_text(encoding="utf-8")
    assert len(text) // 4 <= BUDGETS["admission"]["shared_kernel_max_tokens"]
    assert BUDGETS["admission"]["enforce_startup_totals"] is False


def test_thin_full_initial_context_is_bounded():
    surfaces = BUDGETS["surfaces"]
    thin = sum(
        _slice_bytes(surfaces[name])
        for name in (
            "skill_router",
            "thin_full_runtime",
            "thin_stage1_v2_runtime",
            "thin_stage1d_runtime",
        )
    )
    aggregate = BUDGETS["aggregate"]
    assert thin <= aggregate["thin_full_pre_stage2_max_bytes"]


def test_thin_full_without_abuse_verification_omits_stage1d_budget():
    surfaces = BUDGETS["surfaces"]
    thin = sum(_slice_bytes(surfaces[name]) for name in ("skill_router", "thin_full_runtime", "thin_stage1_v2_runtime"))
    assert thin <= BUDGETS["aggregate"]["thin_full_without_stage1d_max_bytes"]


def test_thin_rerender_initial_context_is_bounded():
    surfaces = BUDGETS["surfaces"]
    rerender = sum(_slice_bytes(surfaces[name]) for name in ("skill_router", "thin_rerender_runtime"))
    assert rerender <= BUDGETS["aggregate"]["thin_rerender_pre_stage2_max_bytes"]


def test_thin_runtime_uses_bounded_stage_reads():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    assert "SKILL-thin-stage1-v2.md" in text
    assert "SKILL-thin-stage1d.md" in text
    assert "SKILL-thin-stage2.md" in text
    assert "SKIP_ABUSE_CASE_VERIFICATION=false" in text
    assert "do not load any Stage-1d instructions" in text
    assert "SKILL-thin-stage3.md" in text
    assert "SKILL-thin-stage4.md" in text
    assert "SKILL-thin-completion.md" in text
    assert "ORG_PROFILE_PATH = org_profile_path" in text
    assert "▶ Stage 1a/<TOTAL_STAGES>" in text
    assert "secret gate is never optional" in text
    assert "There is no legacy range or fallback" in text


def test_thin_full_cumulative_stage2_context_is_bounded():
    surfaces = BUDGETS["surfaces"]
    thin = sum(
        _slice_bytes(surfaces[name])
        for name in (
            "skill_router",
            "thin_full_runtime",
            "thin_stage1_v2_runtime",
            "thin_stage1d_runtime",
            "thin_stage2_runtime",
        )
    )
    assert thin <= BUDGETS["aggregate"]["thin_full_through_stage2_max_bytes"]


def test_compact_stage_contracts_preserve_level0_dispatch_and_gates():
    base = ROOT / "skills" / "create-threat-model"
    stage1 = (base / "SKILL-thin-stage1-v2.md").read_text(encoding="utf-8")
    stage1d = (base / "SKILL-thin-stage1d.md").read_text(encoding="utf-8")
    stage2 = (base / "SKILL-thin-stage2.md").read_text(encoding="utf-8")

    assert "in ONE assistant message" in stage1
    assert "context-v2-begin" in stage1
    assert "context-v2-finalize" in stage1
    assert "filesystem is authoritative" in stage1
    assert "verify-receipts" in stage1

    assert "prepare-abuse --output-dir" in stage1d
    assert "finalize-abuse --output-dir" in stage1d
    # The Agent tool has no background flag; the wave is concurrent because it
    # is issued in one message. Instructing the removed parameter voided every
    # dispatch in the wave.
    assert "Pass no `run_in_background`" in stage1d
    assert "launching the wave" in stage1d and "in ONE message" in stage1d
    assert "wait_abuse_progress.py" in stage1d
    assert "model alias" in stage1d
    assert "without reproducing evidence or artifact content" in stage1d
    assert "must not silently drop candidates" in stage1d
    assert "deterministic match + per-candidate" in stage1d

    assert "prepare-stage2 --output-dir" in stage2
    assert "appsec-secarch-renderer" in stage2
    assert "appsec-ms-renderer" in stage2
    assert "appsec-threat-renderer" in stage2
    assert "next --output-dir" in stage2
    assert "Never infer completion" in stage2
    assert "never reproduce report bodies" in stage2
    assert "Stage-3 secret gate" in stage2
    assert "Authoring required LLM fragments" in stage2


def test_thin_rerender_runtime_starts_at_stage2():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-rerender-runtime.md").read_text(encoding="utf-8")
    assert "ACTION.mode=rerender" in text
    assert "SKILL-thin-stage2.md" in text
    assert "RENDERER_MODEL = renderer_model" in text
    assert "SKILL-thin-stage3.md" in text
    assert "SKILL-thin-stage4.md" in text
    assert "SKILL-thin-completion.md" in text
    assert "There is no legacy slice" in text


def test_context_v2_stage1_runtime_is_bounded():
    base = ROOT / "skills" / "create-threat-model"
    v2 = (base / "SKILL-thin-stage1-v2.md").read_bytes()
    assert len(v2) <= BUDGETS["surfaces"]["thin_stage1_v2_runtime"]["max_bytes"]


def test_context_v2_stage1_runtime_preserves_dispatch_and_boundary_contract():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md").read_text(encoding="utf-8")
    flat = " ".join(text.split())

    # OR-5: a STRIDE wave is concurrent because it is issued in one message,
    # plus a deterministic waiter, so one-call-per-message drift cannot
    # serialize it. The Agent tool has no background flag — instructing the
    # removed parameter voided every dispatch in the wave.
    assert "in ONE assistant message" in flat
    assert "Pass no `run_in_background`" in text
    assert "wait_stride_progress.py" in text
    assert "Never wait for one STRIDE job before launching the next" in flat
    assert "Do not end your turn after dispatching" in text
    assert "Never re-dispatch an agent that already returned" in text
    assert "filesystem is authoritative" in flat
    assert "Before the first boundary command" in text
    assert "fixed heartbeat watchdog from the parent runtime" in flat
    assert "run_in_background: true" in text
    # The watchdog task id is held for TaskStop, not announced: an all-caps
    # variable token made the runtime echo `HEARTBEAT_TASK_ID=<id>` to the
    # console, which the no-meta-narration rule above already forbids.
    assert "retain its task id, never printed" in flat
    assert "HEARTBEAT_TASK_ID" not in text

    # Per-role measurement must be executable, not a prose suggestion. R9
    # recorded only abuse verification and rendering despite dispatching all
    # Stage-1 roles.
    assert "WAVE_START_ISO" in text
    assert "group the returned jobs by `semantic_role`, `agent_type`, and `model`" in flat
    assert "`total_tokens`, `tool_uses`, and `duration_ms`" in text
    assert '--variant "<semantic_role>"' in text
    assert '--subagent-type "<agent_type>" --since-iso "$WAVE_START_ISO"' in flat

    # The skill must never select a producer itself.
    assert "semantic_role" in text
    assert "Never substitute an agent, model, instruction file, tool, or write path" in flat
    assert "subagent_type=dispatch_jobs[].agent_type" in text
    assert "model=dispatch_jobs[].model" in text
    assert "untrusted data" in text
    assert "Resolve every output-relative input and output path under absolute `OUTPUT_DIR`" in flat
    assert "Resolve every path under absolute `OUTPUT_DIR`" in flat
    assert "resolve any output artifact against `REPO_ROOT`" in flat
    assert "taxonomy_slice_path`/`taxonomy_slice_sha256" in text
    assert "The component plan owns depth" in flat
    assert "Never pass the shared effective plan" in flat
    assert "`COMPONENT_CONTEXT_PLAN_PATH`" in text
    assert "`COMPONENT_CONTEXT_PLAN_SHA256`" in text
    assert "`THREAT_TAXONOMY_PATH`" in text
    assert "`THREAT_TAXONOMY_SHA256`" in text

    # The runtime names the chain's two ends and the STRIDE join it owns. It must
    # not enumerate the boundaries in between: the controller returns the
    # successor in `next_boundary`, and a static sequence here is what let a
    # quick-depth run call `context-v2-post-actors` after the architecture
    # dispatch that skipped actor discovery (2026-08-15 juice-shop abort).
    for command in ("context-v2-begin", "context-v2-post-stride", "context-v2-finalize"):
        assert command in text, command
    assert "`next_boundary`" in text
    for derived in ("context-v2-post-recon", "context-v2-post-actors", "context-v2-post-architecture"):
        assert derived not in text, derived

    # The boundary names are the runtime's own vocabulary. A run printed
    # "calling context-v2-post-evidence" and labelled a dispatch
    # "Evidence verifier - phase10a-evidence", so the ban has to name every
    # surface the reader sees, not narration alone.
    assert "a command, boundary, or id never reaches console text, an Agent description, or a task row" in flat

    # Naming the banned vocabulary was not enough: a run still printed "Waiter
    # exited with code 1", "Controller returned another STRIDE wave" and
    # "4/5 STRIDE done", which name nothing on that list. The ban is positive —
    # no console text from this runtime, abort excepted.
    assert "This runtime emits no console text at all" in flat
    assert "Only an abort speaks" in flat

    # It must not carry the removed generation's stage machinery.
    assert "SKILL-thin-stage1.md" not in text
    assert "STAGE1_PHASE_LIMIT" not in text
    assert "RESUME_FROM_PHASE" not in text


def test_compact_full_runtime_loads_the_controller_selected_stage1_runtime():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    stage_section = text.split("## 5. Stages 1a–1d", 1)[1].split("## 6. Stage 2 onward", 1)[0]

    assert "Read `ACTION.instruction_file` in full" in stage_section
    assert "Read `SKILL-thin-stage1.md` in full" not in stage_section
    assert "SKILL-thin-stage1-v2.md" in stage_section
