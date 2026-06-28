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
    thin = sum(_slice_bytes(surfaces[name]) for name in ("skill_router", "thin_full_runtime", "full_stage1_slice"))
    legacy = _slice_bytes(surfaces["legacy_initial_slice"])
    aggregate = BUDGETS["aggregate"]
    assert thin <= aggregate["thin_full_pre_stage2_max_bytes"]
    assert thin / legacy <= aggregate["thin_to_legacy_max_ratio"]


def test_thin_runtime_uses_bounded_stage_reads():
    text = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    assert "## Stage 1 — Threat Analysis & Triage" in text
    assert "<!-- LAZY-LOAD BOUNDARY" in text
    assert "Do not read any earlier part" in text
    assert "### Stage-1 dispatch contract" in text
    assert "APPSEC_TRIAGE_DETERMINISTIC=1" in text
    assert "STAGE1_PHASE_LIMIT=8" in text
    assert "RESUME_FROM_PHASE=9-merge" in text
    assert "ORG_PROFILE_PATH = org_profile_path" in text
    assert "▶ Stage 1/<TOTAL_STAGES>" in text
