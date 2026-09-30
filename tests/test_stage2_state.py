"""Check the persisted Stage-2 state contract after its internal move."""

from __future__ import annotations

import json

from orchestrator.stage2_state import (
    _STAGE2_DISPATCH_MARKER,
    _clear_stage2_recovery_state,
    _fragment_repair_is_actionable,
    _stage2_attempt_counts,
)


def test_fragment_repair_requires_a_valid_actionable_plan(tmp_path):
    plan = tmp_path / ".pre-render-repair-plan.json"
    assert not _fragment_repair_is_actionable(tmp_path)
    plan.write_text("{", encoding="utf-8")
    assert not _fragment_repair_is_actionable(tmp_path)
    plan.write_text(json.dumps({"actionable": False, "actions": ["repair"]}), encoding="utf-8")
    assert not _fragment_repair_is_actionable(tmp_path)
    plan.write_text(json.dumps({"actionable": True, "actions": []}), encoding="utf-8")
    assert not _fragment_repair_is_actionable(tmp_path)
    plan.write_text(json.dumps({"actionable": True, "actions": ["repair"]}), encoding="utf-8")
    assert _fragment_repair_is_actionable(tmp_path)


def test_attempt_ledger_keeps_legacy_budget_and_ignores_invalid_state(tmp_path):
    ledger = tmp_path / ".inline-shortcut-retry-count"
    assert _stage2_attempt_counts(ledger) == {}
    ledger.write_text("2", encoding="utf-8")
    assert _stage2_attempt_counts(ledger) == {"unknown": 2}
    ledger.write_text(json.dumps({"fragments": 2, "compose": 1, "unused": 0, "bad": "2"}), encoding="utf-8")
    assert _stage2_attempt_counts(ledger) == {"fragments": 2, "compose": 1}
    ledger.write_text("{", encoding="utf-8")
    assert _stage2_attempt_counts(ledger) == {}


def test_recovery_cleanup_removes_only_stage2_markers(tmp_path):
    markers = (
        ".inline-shortcut-retry-count",
        ".inline-shortcut-repair-plan.json",
        ".compose-blocked.json",
        _STAGE2_DISPATCH_MARKER,
    )
    for name in (*markers, "threat-model.yaml"):
        (tmp_path / name).write_text("keep or remove", encoding="utf-8")

    _clear_stage2_recovery_state(tmp_path)
    _clear_stage2_recovery_state(tmp_path)

    assert all(not (tmp_path / name).exists() for name in markers)
    assert (tmp_path / "threat-model.yaml").read_text(encoding="utf-8") == "keep or remove"
