"""Unit tests for the M3.3 Appendix: Run Statistics enhancements:

• _read_stage_stats reads JSONL written by record_stage_stats.py
• _read_skill_config falls back when meta lacks paths
• _fmt_ms / _fmt_seconds duration formatting
• _scrape_phase_durations now handles seconds-only [Xs] suffix and
  timestamp-pairing fallback for PHASE_END lines without duration
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"

# compose_threat_model imports `from _atomic_io import …` (sibling module
# in scripts/), so make scripts/ resolvable on sys.path before exec.
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load():
    spec = importlib.util.spec_from_file_location("compose_threat_model", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["compose_threat_model"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load()


# ---------------------------------------------------------------------------
# _read_stage_stats
# ---------------------------------------------------------------------------


def test_read_stage_stats_returns_empty_when_file_absent(tmp_path):
    assert compose._read_stage_stats(tmp_path) == []


def test_read_stage_stats_parses_valid_jsonl(tmp_path):
    (tmp_path / ".stage-stats.jsonl").write_text(
        json.dumps(
            {
                "stage": 1,
                "duration_ms": 1000,
                "tool_uses": 5,
                "tokens": 100,
                "name": "Stage 1",
                "agent": "ag",
                "model": "m",
            }
        )
        + "\n"
        + json.dumps(
            {
                "stage": 2,
                "duration_ms": 2000,
                "tool_uses": 10,
                "tokens": 200,
                "name": "Stage 2",
                "agent": "ag",
                "model": "m",
            }
        )
        + "\n"
    )
    rows = compose._read_stage_stats(tmp_path)
    assert len(rows) == 2
    assert rows[0]["stage"] == 1
    assert rows[1]["stage"] == 2


def test_read_stage_stats_drops_malformed_lines(tmp_path):
    (tmp_path / ".stage-stats.jsonl").write_text(
        json.dumps(
            {"stage": 1, "duration_ms": 1, "tool_uses": 1, "tokens": 1, "name": "ok", "agent": "x", "model": "y"}
        )
        + "\n"
        + "this is not json\n"
        + ""
        + "\n"
        + json.dumps(
            {"stage": 2, "duration_ms": 2, "tool_uses": 1, "tokens": 1, "name": "ok2", "agent": "x", "model": "y"}
        )
        + "\n"
    )
    rows = compose._read_stage_stats(tmp_path)
    assert len(rows) == 2  # malformed and empty silently dropped
    assert [r["stage"] for r in rows] == [1, 2]


# ---------------------------------------------------------------------------
# _read_skill_config
# ---------------------------------------------------------------------------


def test_read_skill_config_returns_empty_when_absent(tmp_path):
    assert compose._read_skill_config(tmp_path) == {}


def test_read_skill_config_parses_valid_json(tmp_path):
    (tmp_path / ".skill-config.json").write_text(
        json.dumps({"repo_root": "/home/x", "output_dir": "/home/x/docs/security"})
    )
    cfg = compose._read_skill_config(tmp_path)
    assert cfg["repo_root"] == "/home/x"
    assert cfg["output_dir"] == "/home/x/docs/security"


def test_read_skill_config_returns_empty_on_malformed(tmp_path):
    (tmp_path / ".skill-config.json").write_text("{invalid json")
    assert compose._read_skill_config(tmp_path) == {}


# ---------------------------------------------------------------------------
# _fmt_ms / _fmt_seconds
# ---------------------------------------------------------------------------


def test_fmt_ms_zero_returns_em_dash():
    assert compose._fmt_ms(0) == "—"
    assert compose._fmt_ms(None) == "—"
    assert compose._fmt_ms(-1) == "—"


def test_fmt_ms_below_minute():
    assert compose._fmt_ms(30_000) == "0m 30s"


def test_fmt_ms_full_minutes():
    assert compose._fmt_ms(1_503_583) == "25m 03s"


def test_fmt_seconds_zero_is_inline():
    assert compose._fmt_seconds(0) == "(inline)"


def test_fmt_seconds_below_minute():
    assert compose._fmt_seconds(45) == "45s"


def test_fmt_seconds_above_minute():
    assert compose._fmt_seconds(226) == "3m 46s"
    assert compose._fmt_seconds(500) == "8m 20s"


# ---------------------------------------------------------------------------
# _scrape_phase_durations — seconds-only suffix + timestamp pairing
# ---------------------------------------------------------------------------


def _line(ts: str, event: str, detail: str) -> str:
    return f"{ts}  [--------]  INFO   threat-analyst  {event}   {detail}"


def test_scrape_picks_up_seconds_only_suffix(tmp_path):
    """[226s] form must now match (was previously dropped)."""
    log = tmp_path / ".agent-run.log"
    log.write_text(
        _line("2026-04-26T18:00:00Z", "PHASE_START", "[Phase 2/11] ▶ Reconnaissance")
        + "\n"
        + _line("2026-04-26T18:03:46Z", "PHASE_END", "[Phase 2/11] ✓ Reconnaissance complete [226s]")
        + "\n"
    )
    rows = compose._scrape_phase_durations(tmp_path)
    assert len(rows) == 1
    assert rows[0]["phase"] == "Phase 2"
    assert rows[0]["duration"] == "226s"


def test_scrape_pairs_phase_start_end_when_suffix_missing(tmp_path):
    """Phase 1 has no [duration] suffix; renderer derives it from timestamps."""
    log = tmp_path / ".agent-run.log"
    log.write_text(
        _line("2026-04-26T18:00:00Z", "PHASE_START", "[Phase 1/11] Context Resolution")
        + "\n"
        + _line("2026-04-26T18:02:36Z", "PHASE_END", "[Phase 1/11] ✓ Context Resolution complete")
        + "\n"
    )
    rows = compose._scrape_phase_durations(tmp_path)
    assert len(rows) == 1
    assert rows[0]["phase"] == "Phase 1"
    assert rows[0]["duration"] == "2m 36s"


def test_scrape_handles_full_minutes_seconds_suffix(tmp_path):
    """[6m 36s] (canonical agent_logger format) still matches."""
    log = tmp_path / ".agent-run.log"
    log.write_text(
        _line("2026-04-26T18:00:00Z", "PHASE_START", "[Phase 9/11] STRIDE Enumeration")
        + "\n"
        + _line("2026-04-26T18:06:36Z", "PHASE_END", "[Phase 9/11] ✓ STRIDE Enumeration — 32 threats [6m 36s]")
        + "\n"
    )
    rows = compose._scrape_phase_durations(tmp_path)
    assert len(rows) == 1
    assert rows[0]["duration"] == "6m 36s"


def test_scrape_handles_phase_10b_special_id(tmp_path):
    """The 'b' suffix on Phase 10b must be preserved."""
    log = tmp_path / ".agent-run.log"
    log.write_text(
        _line("2026-04-26T18:00:00Z", "PHASE_START", "[Phase 10b/11] Triage Validation")
        + "\n"
        + _line("2026-04-26T18:08:20Z", "PHASE_END", "[Phase 10b/11] Triage Validation — 33 flags [500s]")
        + "\n"
    )
    rows = compose._scrape_phase_durations(tmp_path)
    assert len(rows) == 1
    assert rows[0]["phase"] == "Phase 10b"


def test_scrape_returns_empty_when_log_missing(tmp_path):
    assert compose._scrape_phase_durations(tmp_path) == []


def test_scrape_full_run_all_12_phases(tmp_path):
    """End-to-end: a full agent-run.log with mixed inline + bare PHASE_END
    must surface durations for every phase that had a START + END pair."""
    log = tmp_path / ".agent-run.log"
    lines = []
    # Phase 1 — bare END (timestamp pairing)
    lines.append(_line("2026-04-26T18:00:00Z", "PHASE_START", "[Phase 1/11] Context Resolution"))
    lines.append(_line("2026-04-26T18:02:36Z", "PHASE_END", "[Phase 1/11] ✓ Context Resolution complete"))
    # Phase 2 — seconds-only suffix
    lines.append(_line("2026-04-26T18:03:00Z", "PHASE_START", "[Phase 2/11] Reconnaissance"))
    lines.append(_line("2026-04-26T18:06:46Z", "PHASE_END", "[Phase 2/11] ✓ Reconnaissance complete [226s]"))
    # Phase 9 — m/s suffix
    lines.append(_line("2026-04-26T18:07:00Z", "PHASE_START", "[Phase 9/11] STRIDE"))
    lines.append(_line("2026-04-26T18:13:36Z", "PHASE_END", "[Phase 9/11] ✓ STRIDE complete [6m 36s]"))
    # Phase 10b — seconds-only
    lines.append(_line("2026-04-26T18:14:00Z", "PHASE_START", "[Phase 10b/11] Triage"))
    lines.append(_line("2026-04-26T18:22:20Z", "PHASE_END", "[Phase 10b/11] Triage — 33 flags [500s]"))
    log.write_text("\n".join(lines) + "\n")

    rows = compose._scrape_phase_durations(tmp_path)
    durations = {r["phase"]: r["duration"] for r in rows}
    assert durations == {
        "Phase 1": "2m 36s",
        "Phase 2": "226s",
        "Phase 9": "6m 36s",
        "Phase 10b": "500s",
    }
