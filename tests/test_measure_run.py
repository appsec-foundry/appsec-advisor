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
                # Real emitter format (agent_logger.py): "stop_reason=" with a
                # timestamped "[sid] INFO" prefix — NOT a bare "reason=". The
                # parser must match this or the stop-reason metric is silently
                # empty on every real run.
                "2026-05-15T12:00:00Z [abc12345] INFO  SESSION_STOP stop_reason=end_turn  in=1,000  out=500  cost=$0.0100",
                "2026-05-15T12:01:00Z [abc12345] INFO  SESSION_STOP stop_reason=max_turns  in=2,000  out=800  cost=$0.0500",
                # Non-SESSION_STOP line must not be counted as a stop reason.
                "2026-05-15T12:01:00Z [abc12345] ERROR MAX_TURNS Agent terminated — maxTurns limit reached.",
                "2026-05-15T12:02:00Z [abc12345] INFO  REPAIR_MODE attempt=1",
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
    assert metrics["role_telemetry_coverage"] == {"complete": False, "roles": []}
    assert metrics["headless_usage"] is None
    assert metrics["attribution"]["role_cost"] == "unavailable"
    assert metrics["hook_events"] == {"present": False}
    assert metrics["compose_stats"] is None


def test_compose_stats_passthrough(mod, tmp_path):
    payload = {"render_count": 3, "elapsed_ms": 1200}
    (tmp_path / ".compose-stats.json").write_text(json.dumps(payload), encoding="utf-8")
    metrics = mod.measure(tmp_path)
    assert metrics["compose_stats"] == payload


def test_stage_summary_preserves_role_variants(mod):
    records = [
        {"stage": 1, "variant": "recon_scanner", "tokens": 10},
        {"stage": 1, "variant": "architecture_analyst", "tokens": 20},
        {"stage": 1, "variant": "recon_scanner", "tokens": 30},
    ]

    summary = mod._stage_summary(records)

    assert summary["stage_count"] == 2
    assert summary["tokens_total"] == 50
    assert [row["variant"] for row in summary["stages"]] == [
        "architecture_analyst",
        "recon_scanner",
    ]


def test_role_telemetry_coverage_detects_missing_dispatched_role(mod, tmp_path):
    (tmp_path / ".hook-events.log").write_text(
        "\n".join(
            [
                "2026-08-09T10:00:00Z [sid] INFO AGENT_SPAWN appsec-advisor:appsec-recon-scanner model=sonnet",
                "2026-08-09T10:01:00Z [sid] INFO AGENT_SPAWN appsec-advisor:appsec-stride-analyzer-v2 model=sonnet",
                "2026-08-09T10:01:01Z [sid] INFO AGENT_SPAWN appsec-advisor:appsec-stride-analyzer-v2 model=sonnet",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    stages = [
        {
            "stage": 1,
            "variant": "stride_analyzer",
            "agent": "appsec-advisor:appsec-stride-analyzer-v2",
        }
    ]

    coverage = mod._role_telemetry_coverage(tmp_path, stages)

    assert coverage == {
        "complete": False,
        "roles": [
            {"role": "recon-scanner", "dispatched": 1, "stats_records": 0, "covered": False},
            {"role": "stride-analyzer-v2", "dispatched": 2, "stats_records": 1, "covered": True},
        ],
    }


def test_headless_usage_is_exact_run_level_telemetry(mod, tmp_path):
    (tmp_path / ".headless-result.json").write_text(
        json.dumps(
            {
                "type": "result",
                "total_cost_usd": 1.25,
                "num_turns": 7,
                "duration_ms": 9000,
                "modelUsage": {
                    "model-id": {
                        "canonicalModel": "model",
                        "inputTokens": 2,
                        "outputTokens": 3,
                        "cacheReadInputTokens": 5,
                        "cacheCreationInputTokens": 7,
                        "costUSD": 1.25,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    metrics = mod.measure(tmp_path)

    assert metrics["headless_usage"]["num_turns"] == 7
    assert metrics["headless_usage"]["models"][0]["total_tokens"] == 17
    assert metrics["attribution"]["run_cost_by_model"] == "exact"
    assert metrics["attribution"]["role_turns"] == "unavailable"
