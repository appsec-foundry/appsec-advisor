"""The log grammar is a contract between producers and every consumer.

`event_log.format_line` is the single writer. `event_log.parse_line` is the
single reader. Consumers that re-derive the grammar with their own regex drift
away from it silently and fail *open* — they return "nothing found", which is
indistinguishable from a healthy run.

Two such drifts shipped and neither test suite noticed, because every fixture
invented the shape it wanted to see:

  * `check_stride_dispatch` matched `COMPONENT_ID=` while the hook writes
    `component_id=`, so the serial-dispatch guard (decision OR-5) read an empty
    set on every real run and could never report a serial wave.
  * `record_component_durations` required `PHASE_START [Phase 9/…]`, a bracket
    the context-v2 runtime does not emit, so it recorded nothing at all.

`fixtures/logs/context-v2-run.log` is a trimmed corpus of real lines from the
2026-08-16 run. A consumer that cannot read it is broken against production,
whatever its own fixtures say.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import aggregate_run_issues  # noqa: E402
import check_stride_dispatch  # noqa: E402
import event_log  # noqa: E402
import record_component_durations  # noqa: E402

CORPUS = Path(__file__).parent / "fixtures" / "logs" / "context-v2-run.log"

STRIDE_COMPONENTS = {"web-frontend", "api-server", "ci-cd-pipeline"}


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """A run directory carrying the production corpus under both log names."""
    out = tmp_path / "security"
    out.mkdir()
    for name in (".agent-run.log", ".hook-events.log"):
        shutil.copyfile(CORPUS, out / name)
    (out / ".stride-dispatch-manifest.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-08-16T06:59:08Z",
                "components": [{"component_id": cid} for cid in sorted(STRIDE_COMPONENTS)],
            }
        ),
        encoding="utf-8",
    )
    return out


def _corpus_lines() -> list[str]:
    return [line for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_the_canonical_reader_reads_every_production_line():
    unparsed = [line for line in _corpus_lines() if event_log.parse_line(line) is None]
    assert unparsed == [], "the shared reader must cover every shape production emits"


def test_the_corpus_carries_the_events_consumers_key_on():
    events = {parsed.event for line in _corpus_lines() if (parsed := event_log.parse_line(line))}
    # A guard is only as good as the corpus behind it; keep these present so a
    # producer that stops emitting one is caught here rather than in a run.
    assert {"AGENT_SPAWN", "AGENT_USAGE", "PHASE_START", "PHASE_END", "SESSION_STOP"} <= events


def test_serial_dispatch_detection_sees_the_wave(run_dir: Path):
    """OR-5 — a detector that reads nothing can never report a defect."""
    starts = check_stride_dispatch._context_v2_dispatch_starts(run_dir, None)

    assert set(starts) == STRIDE_COMPONENTS
    # This corpus is a real parallel wave, so the verdict is "no finding" — but
    # now on evidence rather than on an empty read.
    assert check_stride_dispatch.detect_serial_dispatch(run_dir) == []


def test_component_durations_are_recorded_from_the_corpus(run_dir: Path):
    assert record_component_durations.main([str(run_dir)]) == 0

    baseline = json.loads((run_dir / ".appsec-cache" / "baseline.json").read_text(encoding="utf-8"))
    assert baseline["component_durations"] == {
        "web-frontend": 801,
        "api-server": 623,
        "ci-cd-pipeline": 359,
    }


def test_stride_model_drift_is_visible_on_a_context_v2_run(run_dir: Path):
    """`--reasoning-model opus` silently ignored is exactly what this advisory exists for."""
    (run_dir / ".skill-config.json").write_text(json.dumps({"stride_model": "claude-opus-4-8"}), encoding="utf-8")
    log = [(index, line) for index, line in enumerate(_corpus_lines(), start=1)]

    issues = aggregate_run_issues._extract_stride_model_mismatch(run_dir, log, [])

    assert issues, "the corpus dispatches sonnet against an opus setting and must be reported"


def test_phase_nine_is_anchored_without_a_bracketed_boundary(run_dir: Path):
    """The context-v2 runtime logs `PHASE_START <label>`, with no [Phase N/M]."""
    log = run_dir / ".agent-run.log"
    assert "[Phase 9/" not in log.read_text(encoding="utf-8")

    assert record_component_durations._read_phase_9_start(log) is not None


def test_watchdog_events_never_lose_the_agent_that_emitted_them():
    """The agent identity must survive to the consumer, in either line shape.

    `budget_watchdog.format_detail` flattens a structured payload into display
    text. When the emitter also left the component column empty, every consumer
    keyed on that column read `""` — which degraded the fix recommender that
    needs the agent to locate its definition, and folded distinct agents into a
    single `?` bucket. Both shapes appear in the corpus: the historical 5-field
    line that carries the name only in the detail, and the 6-field line the
    fixed emitter writes.
    """
    watchdog = {"MAX_TURNS", "BUDGET_WARN", "BUDGET_CRITICAL"}
    seen = {}
    for line in _corpus_lines():
        parsed = aggregate_run_issues._parse_event_line(line)
        if parsed and parsed["event"] in watchdog:
            seen[parsed["event"]] = aggregate_run_issues._emitting_agent(parsed)

    assert watchdog <= set(seen), "the corpus must exercise every watchdog event"
    assert all(seen.values()), f"an unattributed watchdog event reaches the consumer: {seen}"
    assert seen["MAX_TURNS"] == "ms-renderer"


def test_the_emitted_component_column_round_trips_through_both_readers():
    """A component longer than COMPONENT_WIDTH overflows its column; the fixed
    offsets then miss and only the whitespace-split fallback recovers it. Agent
    names on both sides of that boundary must parse identically in the canonical
    reader and in the aggregator's own."""
    for agent in ("ms-renderer", "stride-analyzer-v2", "abuse-case-verifier"):
        line = event_log.format_line(
            "MAX_TURNS", f"agent={agent}  turns=1/1  pct=100%", level="WARN", component=agent, sid="aa40ceb8"
        )
        canonical = event_log.parse_line(line)
        aggregated = aggregate_run_issues._parse_event_line(line)

        assert canonical is not None and canonical.component == agent
        assert aggregated is not None and aggregate_run_issues._emitting_agent(aggregated) == agent
        assert canonical.event == aggregated["event"] == "MAX_TURNS"
