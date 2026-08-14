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
    "thin_stage1_runtime": 11000,
    "thin_stage1_v2_runtime": 6400,
    "thin_stage1b_runtime": 4300,
    "thin_stage1d_runtime": 3400,
    "thin_stage2_runtime": 3600,
    "legacy_initial_slice": 230000,
    "full_stage1_slice": 57500,
    "full_stage1d_slice": 15000,
    "stage2_runtime_dispatch_slice": 20000,
    "stage3_runtime_gate_slice": 25000,
    "threat_analyst": 155000,
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
    "phase_group_recon": 40000,
    "phase_group_architecture": 190000,
    "phase_group_threats": 160000,
    "phase_group_finalization": 155000,
}


def test_context_budget_contract_shape():
    assert BUDGETS["version"] == 1
    assert BUDGETS["surfaces"]
    for name, spec in BUDGETS["surfaces"].items():
        assert (ROOT / spec["path"]).is_file(), name
        assert isinstance(spec["max_bytes"], int) and spec["max_bytes"] > 0
    assert 0 < BUDGETS["aggregate"]["thin_to_legacy_max_ratio"] < 1
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


def test_thin_full_initial_context_is_materially_smaller_than_legacy():
    surfaces = BUDGETS["surfaces"]
    thin = sum(
        _slice_bytes(surfaces[name])
        for name in (
            "skill_router",
            "thin_full_runtime",
            "thin_stage1_runtime",
            "thin_stage1b_runtime",
            "thin_stage1d_runtime",
        )
    )
    legacy = _slice_bytes(surfaces["legacy_initial_slice"])
    aggregate = BUDGETS["aggregate"]
    assert thin <= aggregate["thin_full_pre_stage2_max_bytes"]
    assert thin / legacy <= aggregate["thin_to_legacy_max_ratio"]


def test_thin_full_without_abuse_verification_omits_stage1d_budget():
    surfaces = BUDGETS["surfaces"]
    thin = sum(
        _slice_bytes(surfaces[name])
        for name in ("skill_router", "thin_full_runtime", "thin_stage1_runtime", "thin_stage1b_runtime")
    )
    assert thin <= BUDGETS["aggregate"]["thin_full_without_stage1d_max_bytes"]


def test_thin_rerender_initial_context_is_bounded():
    surfaces = BUDGETS["surfaces"]
    rerender = sum(_slice_bytes(surfaces[name]) for name in ("skill_router", "thin_rerender_runtime"))
    assert rerender <= BUDGETS["aggregate"]["thin_rerender_pre_stage2_max_bytes"]


def test_thin_runtime_uses_bounded_stage_reads():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    assert "SKILL-thin-stage1.md" in text
    assert "SKILL-thin-stage1d.md" in text
    assert "SKILL-thin-stage2.md" in text
    assert "SKIP_ABUSE_CASE_VERIFICATION=false" in text
    assert "do not load any Stage-1d instructions" in text
    assert "Do not load the Stage-2 slice" in text
    assert "### Stage-1 dispatch contract" in text
    assert "APPSEC_TRIAGE_DETERMINISTIC=1" in text
    assert "STAGE1_PHASE_LIMIT=8" in text
    assert "RESUME_FROM_PHASE=9-merge" in text
    assert "ORG_PROFILE_PATH = org_profile_path" in text
    assert "▶ Stage 1a/<TOTAL_STAGES>" in text
    assert "## Stage 3 - QA Review` to `### Stage 3 handoff banner" in text
    assert "Load this safety slice on every non-dry path" in text
    assert "run the Stage-3 safety slice first" in text
    assert "marker to EOF" not in text


def test_thin_full_cumulative_stage2_context_is_bounded():
    surfaces = BUDGETS["surfaces"]
    thin = sum(
        _slice_bytes(surfaces[name])
        for name in (
            "skill_router",
            "thin_full_runtime",
            "thin_stage1_runtime",
            "thin_stage1b_runtime",
            "thin_stage1d_runtime",
            "thin_stage2_runtime",
        )
    )
    assert thin <= BUDGETS["aggregate"]["thin_full_through_stage2_max_bytes"]


def test_compact_stage_contracts_preserve_level0_dispatch_and_gates():
    base = ROOT / "skills" / "create-threat-model"
    stage1 = (base / "SKILL-thin-stage1.md").read_text(encoding="utf-8")
    stage1b = (base / "SKILL-thin-stage1b.md").read_text(encoding="utf-8")
    stage1d = (base / "SKILL-thin-stage1d.md").read_text(encoding="utf-8")
    stage2 = (base / "SKILL-thin-stage2.md").read_text(encoding="utf-8")

    assert "SKILL-impl.md" in stage1 and "do not read" in stage1.lower()
    assert "STAGE1_PHASE_LIMIT=8" in stage1
    assert "RESUME_FROM_PHASE=9-merge" in stage1
    assert "one assistant message" in stage1
    assert "post-stage1a --output-dir" in stage1
    assert "post-stage1c --output-dir" in stage1
    assert "filesystem is authoritative" in stage1
    assert "must not reproduce artifact bodies" in stage1
    assert "MD_PRE_STAGE1" in stage1
    assert ".stage1-resume-count" in stage1
    assert "completion checkpoint" in stage1
    assert "stall result does not override a successful post-gate" in stage1

    assert "appsec-trust-boundary-analyst" in stage1b
    assert "finalize-stage1b --output-dir" in stage1b
    assert "Retry once" in stage1b

    assert "prepare-abuse --output-dir" in stage1d
    assert "finalize-abuse --output-dir" in stage1d
    assert "run_in_background:true" in stage1d
    assert "launch the whole wave before waiting" in stage1d
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
    assert "must not reproduce fragment or" in stage2
    assert "Authoring 2 LLM fragments" in stage2


def test_thin_rerender_runtime_starts_at_stage2():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-rerender-runtime.md").read_text(encoding="utf-8")
    assert "ACTION.mode=rerender" in text
    assert "Stage-1 prefix" in text
    assert "## Stage 2 - Report Rendering" in text
    assert "rerender mode file, or Stages 1a–1d" in text
    assert "RENDERER_MODEL = renderer_model" in text
    assert "always run the non-dry Stage-3 safety" in text
    assert "including its final release gates" in text


def test_context_v2_stage1_runtime_is_bounded_and_smaller_than_legacy():
    base = ROOT / "skills" / "create-threat-model"
    v2 = (base / "SKILL-thin-stage1-v2.md").read_bytes()
    legacy = (base / "SKILL-thin-stage1.md").read_bytes()
    assert len(v2) <= BUDGETS["surfaces"]["thin_stage1_v2_runtime"]["max_bytes"]
    # The point of the split is a thinner Stage-1 prompt, not a second copy.
    assert len(v2) < len(legacy)


def test_context_v2_stage1_runtime_preserves_dispatch_and_boundary_contract():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md").read_text(encoding="utf-8")
    flat = " ".join(text.split())

    # OR-5: STRIDE waves use non-blocking fan-out plus a deterministic waiter so
    # one-call-per-message drift cannot serialize the wave. Other semantic
    # boundaries remain foreground and blocking.
    assert "run_in_background: true" in text
    assert "wait_stride_progress.py" in text
    assert "Never wait for one STRIDE job before launching the next" in flat
    assert "run_in_background: false" in text
    assert "Do not end your turn after dispatching" in text
    assert "Never re-dispatch an agent that already returned" in text
    assert "filesystem is authoritative" in flat
    assert "Before the first boundary command" in text
    assert "fixed heartbeat watchdog from the parent runtime" in flat
    assert "run_in_background: true" in text
    assert "HEARTBEAT_TASK_ID" in text

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
    assert "paths resolved under absolute `OUTPUT_DIR`" in flat
    assert "resolve any output artifact against `REPO_ROOT`" in flat
    assert "taxonomy_slice_path`/`taxonomy_slice_sha256" in text
    assert "The component plan is authoritative for analysis depth" in flat
    assert "Never pass the shared effective plan" in flat
    assert "`COMPONENT_CONTEXT_PLAN_PATH`" in text
    assert "`COMPONENT_CONTEXT_PLAN_SHA256`" in text
    assert "`THREAT_TAXONOMY_PATH`" in text
    assert "`THREAT_TAXONOMY_SHA256`" in text

    # Every landed boundary command must be reachable from this runtime.
    for command in (
        "context-v2-begin",
        "context-v2-post-recon",
        "context-v2-post-actors",
        "context-v2-post-architecture",
        "context-v2-post-boundary",
        "context-v2-prepare-stride",
        "context-v2-post-stride",
        "context-v2-post-merge",
        "context-v2-post-evidence",
        "context-v2-post-triage",
        "context-v2-finalize",
    ):
        assert command in text, command

    # It must not carry the legacy generation's stage machinery.
    assert "SKILL-thin-stage1.md" in text  # names it only to forbid mixing
    assert "STAGE1_PHASE_LIMIT" not in text
    assert "RESUME_FROM_PHASE" not in text


def test_compact_full_runtime_loads_the_controller_selected_stage1_runtime():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    stage_section = text.split("## 5. Stages 1a–1d", 1)[1].split("## 6. Stage 2 onward", 1)[0]

    assert "Read `ACTION.instruction_file` in full" in stage_section
    assert "Read `SKILL-thin-stage1.md` in full" not in stage_section
    assert "SKILL-thin-stage1-v2.md" in stage_section
