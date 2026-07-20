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
        for name in ("skill_router", "thin_full_runtime", "full_stage1_slice", "full_stage1c_slice")
    )
    legacy = _slice_bytes(surfaces["legacy_initial_slice"])
    aggregate = BUDGETS["aggregate"]
    assert thin <= aggregate["thin_full_pre_stage2_max_bytes"]
    assert thin / legacy <= aggregate["thin_to_legacy_max_ratio"]


def test_thin_full_without_abuse_verification_omits_stage1c_budget():
    surfaces = BUDGETS["surfaces"]
    thin = sum(
        _slice_bytes(surfaces[name])
        for name in ("skill_router", "thin_full_runtime", "full_stage1_slice")
    )
    assert thin <= BUDGETS["aggregate"]["thin_full_without_stage1c_max_bytes"]


def test_thin_rerender_initial_context_is_bounded():
    surfaces = BUDGETS["surfaces"]
    rerender = sum(_slice_bytes(surfaces[name]) for name in ("skill_router", "thin_rerender_runtime"))
    assert rerender <= BUDGETS["aggregate"]["thin_rerender_pre_stage2_max_bytes"]


def test_thin_runtime_uses_bounded_stage_reads():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    assert "## Stage 1 — Threat Analysis & Triage" in text
    assert "## Stage 1c — Abuse Case Verification" in text
    assert "SKIP_ABUSE_CASE_VERIFICATION=false" in text
    assert "Otherwise do not load the Stage-1c slice" in text
    assert "## Stage 2 - Report Rendering" in text
    assert "Do not read any earlier part" in text
    assert "### Stage-1 dispatch contract" in text
    assert "APPSEC_TRIAGE_DETERMINISTIC=1" in text
    assert "STAGE1_PHASE_LIMIT=8" in text
    assert "RESUME_FROM_PHASE=9-merge" in text
    assert "ORG_PROFILE_PATH = org_profile_path" in text
    assert "▶ Stage 1/<TOTAL_STAGES>" in text
    assert "## Stage 2 - Report Rendering` to `### Handling turn-budget cut-offs" in text
    assert "## Stage 3 - QA Review` to `### Stage 3 handoff banner" in text
    assert "Load this safety slice on every non-dry path" in text
    assert "run the Stage-3 safety slice first" in text
    assert "marker to EOF" not in text


def test_thin_rerender_runtime_starts_at_stage2():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-rerender-runtime.md").read_text(encoding="utf-8")
    assert "ACTION.mode=rerender" in text
    assert "Stage-1 prefix" in text
    assert "## Stage 2 - Report Rendering" in text
    assert "rerender mode file, Stage 1, or Stage 1c" in text
    assert "RENDERER_MODEL = renderer_model" in text
    assert "always run the non-dry Stage-3 safety" in text
    assert "including its final release gates" in text
