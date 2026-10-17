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
    # 8500 -> 12000 (2026-10-17): the router is now the appsec-analyzer skill,
    # which carries the launch, trust and progress steps the legacy router
    # delegated to its runtime files.
    "skill_router": 12000,
    "shared_threat_analysis_kernel": 16000,
    # 12000 -> 13000 (2026-09-17): role units, capability labels, and concrete
    # access-group and `none` rules. See the note in data/context-budgets.yaml.
    "architecture_analyst_role": 13000,
    "control_analyst_role": 12000,
    "post_stride_synthesizer_role": 12000,
    # 12000 -> 14500 (2026-08-30): requirements and blueprint provenance grew
    # the role to 12764 bytes, past the hard budget and inside the headroom
    # band. See the note in data/context-budgets.yaml.
    # 14500 -> 17500 (2026-09-24): gate-enforced mechanism_trace contract and
    # the retry repair brief. See the note in data/context-budgets.yaml.
    "stride_analyzer_role": 17500,
    "stride_lens_llm": 7000,
    "stride_lens_agentic": 8000,
    "stride_lens_rag": 2600,
    "stride_lens_mcp": 3300,
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
