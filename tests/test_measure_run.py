"""Smoke test for scripts/measure_run.py against a frozen example."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "measure_run.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("measure_run", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    sys.modules["measure_run"] = m
    spec.loader.exec_module(m)
    return m


def _seed_fixture(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / ".stage-stats.jsonl").write_text(
        "\n".join(
            [
                json.dumps({"stage": 1, "name": "Stage A", "agent": "agent-1", "tokens": 1000, "duration_ms": 5000}),
                json.dumps({"stage": 2, "name": "Stage B", "agent": "agent-2", "tokens": 2000, "duration_ms": 7000}),
                # malformed line — must be dropped silently
                "{not json",
                # duplicate stage-2 — last write wins
                json.dumps({"stage": 2, "name": "Stage B", "agent": "agent-2", "tokens": 2500, "duration_ms": 8000}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (d / ".hook-events.log").write_text(
        "\n".join(
            [
                "2026-05-15 12:00:00 SESSION_STOP reason=end_turn cost=0.01",
                "2026-05-15 12:01:00 SESSION_STOP reason=max_turns cost=0.05",
                "2026-05-15 12:02:00 REPAIR_MODE attempt=1",
            ]
        ),
        encoding="utf-8",
    )


def test_stage_summary_aggregates_and_dedupes(mod, tmp_path):
    _seed_fixture(tmp_path)
    metrics = mod.measure(tmp_path)
    s = metrics["stages"]
    assert s["stage_count"] == 2, s
    # last-write-wins for duplicate stage 2 → 1000 + 2500 = 3500
    assert s["tokens_total"] == 3500, s
    assert s["duration_ms_total"] == 13000, s
    assert [r["stage"] for r in s["stages"]] == [1, 2]


def test_hook_events_signal_extraction(mod, tmp_path):
    _seed_fixture(tmp_path)
    metrics = mod.measure(tmp_path)
    h = metrics["hook_events"]
    assert h["present"] is True
    assert h["stop_reasons"] == {"end_turn": 1, "max_turns": 1}
    assert h["retry_hints"] == 1


def test_missing_files_produce_empty_buckets(mod, tmp_path):
    metrics = mod.measure(tmp_path)
    assert metrics["stages"]["stage_count"] == 0
    assert metrics["hook_events"] == {"present": False}
    assert metrics["compose_stats"] is None


def test_compose_stats_passthrough(mod, tmp_path):
    payload = {"render_count": 3, "elapsed_ms": 1200}
    (tmp_path / ".compose-stats.json").write_text(json.dumps(payload), encoding="utf-8")
    metrics = mod.measure(tmp_path)
    assert metrics["compose_stats"] == payload
