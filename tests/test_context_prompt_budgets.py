from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BUDGETS = yaml.safe_load((ROOT / "data" / "context-budgets.yaml").read_text(encoding="utf-8"))


def test_context_budget_contract_shape():
    assert BUDGETS["version"] == 1
    assert BUDGETS["surfaces"]
    for name, spec in BUDGETS["surfaces"].items():
        assert (ROOT / spec["path"]).is_file(), name
        assert isinstance(spec["max_bytes"], int) and spec["max_bytes"] > 0
    assert 0 < BUDGETS["aggregate"]["thin_to_legacy_max_ratio"] < 1


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


def test_thin_full_initial_context_is_materially_smaller_than_legacy():
    surfaces = BUDGETS["surfaces"]
    thin = sum(
        _slice_bytes(surfaces[name])
        for name in ("skill_router", "thin_full_runtime", "thin_stage1_runtime", "thin_stage1c_runtime")
    )
    legacy = _slice_bytes(surfaces["legacy_initial_slice"])
    aggregate = BUDGETS["aggregate"]
    assert thin <= aggregate["thin_full_pre_stage2_max_bytes"]
    assert thin / legacy <= aggregate["thin_to_legacy_max_ratio"]


def test_thin_full_without_abuse_verification_omits_stage1c_budget():
    surfaces = BUDGETS["surfaces"]
    thin = sum(_slice_bytes(surfaces[name]) for name in ("skill_router", "thin_full_runtime", "thin_stage1_runtime"))
    assert thin <= BUDGETS["aggregate"]["thin_full_without_stage1c_max_bytes"]


def test_thin_rerender_initial_context_is_bounded():
    surfaces = BUDGETS["surfaces"]
    rerender = sum(_slice_bytes(surfaces[name]) for name in ("skill_router", "thin_rerender_runtime"))
    assert rerender <= BUDGETS["aggregate"]["thin_rerender_pre_stage2_max_bytes"]


def test_thin_runtime_uses_bounded_stage_reads():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    assert "SKILL-thin-stage1.md" in text
    assert "SKILL-thin-stage1c.md" in text
    assert "SKILL-thin-stage2.md" in text
    assert "SKIP_ABUSE_CASE_VERIFICATION=false" in text
    assert "do not load any\nStage-1c instructions" in text
    assert "Do not load the Stage-2 slice" in text
    assert "### Stage-1 dispatch contract" in text
    assert "APPSEC_TRIAGE_DETERMINISTIC=1" in text
    assert "STAGE1_PHASE_LIMIT=8" in text
    assert "RESUME_FROM_PHASE=9-merge" in text
    assert "ORG_PROFILE_PATH = org_profile_path" in text
    assert "▶ Stage 1/<TOTAL_STAGES>" in text
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
            "thin_stage1c_runtime",
            "thin_stage2_runtime",
        )
    )
    assert thin <= BUDGETS["aggregate"]["thin_full_through_stage2_max_bytes"]


def test_compact_stage_contracts_preserve_level0_dispatch_and_gates():
    base = ROOT / "skills" / "create-threat-model"
    stage1 = (base / "SKILL-thin-stage1.md").read_text(encoding="utf-8")
    stage1c = (base / "SKILL-thin-stage1c.md").read_text(encoding="utf-8")
    stage2 = (base / "SKILL-thin-stage2.md").read_text(encoding="utf-8")

    assert "SKILL-impl.md" in stage1 and "do not read" in stage1.lower()
    assert "STAGE1_PHASE_LIMIT=8" in stage1
    assert "RESUME_FROM_PHASE=9-merge" in stage1
    assert "one assistant message" in stage1
    assert "post-stage1 --output-dir" in stage1
    assert "filesystem is authoritative" in stage1
    assert "must not reproduce artifact bodies" in stage1
    assert "MD_PRE_STAGE1" in stage1
    assert ".stage1-resume-count" in stage1
    assert "completion checkpoint" in stage1
    assert "stall result does not override a successful post-gate" in stage1

    assert "prepare-abuse --output-dir" in stage1c
    assert "finalize-abuse --output-dir" in stage1c
    assert "single assistant message" in stage1c
    assert "model alias" in stage1c
    assert "without reproducing evidence or artifact content" in stage1c
    assert "must not silently drop candidates" in stage1c
    assert "deterministic match + per-candidate" in stage1c

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
    assert "rerender mode file, Stage 1, or Stage 1c" in text
    assert "RENDERER_MODEL = renderer_model" in text
    assert "always run the non-dry Stage-3 safety" in text
    assert "including its final release gates" in text
