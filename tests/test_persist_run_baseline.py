"""Tests for scripts/persist_run_baseline.py — the run-end baseline writer.

Context: the writer used to be inline bash in SKILL-impl.md that the
orchestrator reproduced by hand, including four exact JSON key names. On
2026-07-27 it resumed after a context compaction, read the descriptive
paragraph but not the bash block below it, and wrote `last_wall_seconds` /
`last_mode` / `last_depth`. `estimate_duration.py` reads only
`last_run_seconds`, so the estimator silently fell back to the parametric
formula. `test_written_cache_is_consumed_by_estimator` is the guard that would
have caught it.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "persist_run_baseline.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load():
    if "persist_run_baseline" in sys.modules:
        return sys.modules["persist_run_baseline"]
    spec = importlib.util.spec_from_file_location("persist_run_baseline", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["persist_run_baseline"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


prb = _load()


def _read_cache(out: Path) -> dict:
    return json.loads((out / ".appsec-cache" / "baseline.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The regression that motivated this script
# ---------------------------------------------------------------------------


def test_written_cache_is_consumed_by_estimator(tmp_path: Path):
    """End-to-end contract: what the writer writes, the reader must consume.

    This is the test whose absence let the 2026-07-27 key-name drift through —
    writer and reader agreed on nothing and neither side complained.
    """
    import estimate_duration

    (tmp_path / ".scan-start-epoch").write_text("1000", encoding="utf-8")
    prb.persist(tmp_path, "full", "standard", now_epoch=1000 + 6000)

    # `parametric_total` is the formula estimate, used only as a hang guard.
    hit = estimate_duration._last_run_cache(tmp_path, "full", "standard", 90.0)
    assert hit is not None, "estimator did not accept the cache the writer produced"
    stages, source = hit
    assert source == "last_run_cache"
    assert abs(stages["total"] - 100.0) < 1.0


def test_field_names_match_what_the_estimator_reads(tmp_path: Path):
    """Pin the four canonical names against the reader's literals."""
    src = (REPO_ROOT / "scripts" / "estimate_duration.py").read_text(encoding="utf-8")
    for key in (prb.KEY_SECONDS, prb.KEY_MODE, prb.KEY_DEPTH):
        assert f'"{key}"' in src, f"{key} is not read by estimate_duration.py"
    assert prb.KEY_SECONDS == "last_run_seconds"
    assert prb.KEY_MODE == "last_run_mode"
    assert prb.KEY_DEPTH == "last_run_depth"
    assert prb.KEY_ISO == "last_run_iso"


def test_field_names_match_baseline_state_carry_forward():
    """`baseline_state.py` carries these forward on rewrite; a name that drifts
    apart from that list gets silently wiped by the next baseline write."""
    src = (REPO_ROOT / "scripts" / "baseline_state.py").read_text(encoding="utf-8")
    for key in (prb.KEY_SECONDS, prb.KEY_MODE, prb.KEY_DEPTH, prb.KEY_ISO):
        assert f'"{key}"' in src, f"{key} missing from baseline_state carry-forward"


# ---------------------------------------------------------------------------
# Start-epoch precedence
# ---------------------------------------------------------------------------


def test_log_assessment_start_wins_over_marker(tmp_path: Path):
    """The log excludes permission-prompt wait time and must take precedence."""
    (tmp_path / ".agent-run.log").write_text(
        "2026-07-27T05:00:00Z  [--------]  INFO   skill  ASSESSMENT_START  mode=full\n",
        encoding="utf-8",
    )
    (tmp_path / ".scan-start-epoch").write_text("1", encoding="utf-8")
    epoch, source = prb.resolve_start_epoch(tmp_path, None)
    assert source == "agent-run.log:ASSESSMENT_START"
    assert epoch == 1785128400


def test_marker_file_used_when_log_has_no_assessment_start(tmp_path: Path):
    (tmp_path / ".agent-run.log").write_text("2026-07-27T05:00:00Z INFO nothing here\n", encoding="utf-8")
    (tmp_path / ".scan-start-epoch").write_text("4242", encoding="utf-8")
    epoch, source = prb.resolve_start_epoch(tmp_path, None)
    assert (epoch, source) == (4242, ".scan-start-epoch")


def test_fallback_epoch_is_last_resort(tmp_path: Path):
    epoch, source = prb.resolve_start_epoch(tmp_path, 999)
    assert (epoch, source) == (999, "--fallback-epoch")


def test_no_signal_skips_write_without_raising(tmp_path: Path):
    assert prb.persist(tmp_path, "full", "standard") is None
    assert not (tmp_path / ".appsec-cache" / "baseline.json").exists()


def test_cli_never_fails_the_run_when_skipping(tmp_path: Path):
    rc = prb.main(["--output-dir", str(tmp_path), "--mode", "full"])
    assert rc == 0  # best-effort by contract


# ---------------------------------------------------------------------------
# Duration semantics
# ---------------------------------------------------------------------------


def test_net_wall_wins_when_smaller(tmp_path: Path, monkeypatch):
    """An idle run must not teach the estimator that it takes that long."""
    (tmp_path / ".scan-start-epoch").write_text("1000", encoding="utf-8")
    monkeypatch.setattr(prb, "_net_wall_seconds", lambda *a, **k: 600)
    written = prb.persist(tmp_path, "full", "standard", now_epoch=1000 + 6000)
    assert written[prb.KEY_SECONDS] == 600


def test_net_wall_ignored_when_larger(tmp_path: Path, monkeypatch):
    (tmp_path / ".scan-start-epoch").write_text("1000", encoding="utf-8")
    monkeypatch.setattr(prb, "_net_wall_seconds", lambda *a, **k: 99999)
    written = prb.persist(tmp_path, "full", "standard", now_epoch=1000 + 6000)
    assert written[prb.KEY_SECONDS] == 6000


def test_non_positive_duration_is_not_persisted(tmp_path: Path):
    (tmp_path / ".scan-start-epoch").write_text("5000", encoding="utf-8")
    assert prb.persist(tmp_path, "full", "standard", now_epoch=5000) is None


# ---------------------------------------------------------------------------
# Cache merge behaviour
# ---------------------------------------------------------------------------


def test_existing_cache_keys_are_preserved(tmp_path: Path, monkeypatch):
    """The writer owns four fields and must not disturb anything else —
    component_durations and id_counters live in the same file."""
    cache_dir = tmp_path / ".appsec-cache"
    cache_dir.mkdir()
    (cache_dir / "baseline.json").write_text(
        json.dumps({"id_counters": {"T": 70}, "component_durations": {"backend-api": 120}}),
        encoding="utf-8",
    )
    (tmp_path / ".scan-start-epoch").write_text("1000", encoding="utf-8")
    monkeypatch.setattr(prb, "_net_wall_seconds", lambda *a, **k: None)
    prb.persist(tmp_path, "full", "standard", now_epoch=1000 + 300)

    data = _read_cache(tmp_path)
    assert data["id_counters"] == {"T": 70}
    assert data["component_durations"] == {"backend-api": 120}
    assert data[prb.KEY_SECONDS] == 300


def test_corrupt_cache_does_not_block_the_write(tmp_path: Path, monkeypatch):
    cache_dir = tmp_path / ".appsec-cache"
    cache_dir.mkdir()
    (cache_dir / "baseline.json").write_text("{not json", encoding="utf-8")
    (tmp_path / ".scan-start-epoch").write_text("1000", encoding="utf-8")
    monkeypatch.setattr(prb, "_net_wall_seconds", lambda *a, **k: None)
    prb.persist(tmp_path, "full", "standard", now_epoch=1000 + 300)
    assert _read_cache(tmp_path)[prb.KEY_SECONDS] == 300


def test_rerun_overwrites_only_the_owned_fields(tmp_path: Path, monkeypatch):
    (tmp_path / ".scan-start-epoch").write_text("1000", encoding="utf-8")
    monkeypatch.setattr(prb, "_net_wall_seconds", lambda *a, **k: None)
    prb.persist(tmp_path, "full", "standard", now_epoch=1000 + 300)
    prb.persist(tmp_path, "incremental", "quick", now_epoch=1000 + 60)
    data = _read_cache(tmp_path)
    assert data[prb.KEY_SECONDS] == 60
    assert data[prb.KEY_MODE] == "incremental"
    assert data[prb.KEY_DEPTH] == "quick"


def test_no_temp_file_left_behind(tmp_path: Path, monkeypatch):
    (tmp_path / ".scan-start-epoch").write_text("1000", encoding="utf-8")
    monkeypatch.setattr(prb, "_net_wall_seconds", lambda *a, **k: None)
    prb.persist(tmp_path, "full", "standard", now_epoch=1000 + 300)
    assert list((tmp_path / ".appsec-cache").glob("*.tmp")) == []
