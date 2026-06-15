"""Unit tests for scripts/watch_run.py.

watch() streams in an infinite loop in follow mode, but in --once mode it is
deadline-bounded. Tests drive --once with a stubbed time source so the loop
terminates deterministically; pure helpers are tested directly.
"""

from __future__ import annotations

import json

import pytest
import watch_run as wr


# ---------------------------------------------------------------------------
# Module-level budget tables
# ---------------------------------------------------------------------------
def test_budget_tables_have_all_depths():
    for depth in ("quick", "standard", "thorough"):
        assert depth in wr.PHASE_DURATION_LIMITS_SECONDS
    assert wr.DEFAULT_PHASE_FALLBACK_SECONDS > 0
    assert wr.ABSOLUTE_HARD_CEILING_SECONDS > 0


# ---------------------------------------------------------------------------
# _now_local_short
# ---------------------------------------------------------------------------
def test_now_local_short_shape():
    s = wr._now_local_short()
    assert len(s) == 8 and s.count(":") == 2


# ---------------------------------------------------------------------------
# _read_phase_from_checkpoint
# ---------------------------------------------------------------------------
def test_read_phase_missing_checkpoint(tmp_path):
    assert wr._read_phase_from_checkpoint(tmp_path) == ("?", "?")


def test_read_phase_parses_tokens(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text("phase=10b status=running other=x\nsecond line\n")
    assert wr._read_phase_from_checkpoint(tmp_path) == ("10b", "running")


def test_read_phase_empty_values_become_qmark(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text("phase= status=\n")
    assert wr._read_phase_from_checkpoint(tmp_path) == ("?", "?")


def test_read_phase_empty_file_indexerror(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text("")
    assert wr._read_phase_from_checkpoint(tmp_path) == ("?", "?")


# ---------------------------------------------------------------------------
# _threshold_for_phase
# ---------------------------------------------------------------------------
def test_threshold_known_phase():
    # standard phase "1" budget * multiplier
    base = wr.PHASE_DURATION_LIMITS_SECONDS["standard"]["1"]
    assert wr._threshold_for_phase("1", "standard", 1.0) == base
    assert wr._threshold_for_phase("1", "standard", 2.0) == base * 2


def test_threshold_unknown_phase_uses_fallback():
    val = wr._threshold_for_phase("zzz", "standard", 1.0)
    assert val == wr.DEFAULT_PHASE_FALLBACK_SECONDS


def test_threshold_unknown_depth_falls_back_to_standard():
    assert wr._threshold_for_phase("1", "nonsense-depth", 1.0) == wr.PHASE_DURATION_LIMITS_SECONDS["standard"]["1"]


def test_threshold_capped_at_hard_ceiling():
    assert wr._threshold_for_phase("1", "standard", 100000.0) == wr.ABSOLUTE_HARD_CEILING_SECONDS


# ---------------------------------------------------------------------------
# _parse_event_name
# ---------------------------------------------------------------------------
def test_parse_event_name_valid():
    line = "2026-06-14T10:00:00Z  [sid12345]  INFO  PHASE_START  detail here"
    assert wr._parse_event_name(line) == "PHASE_START"


def test_parse_event_name_too_few_parts():
    assert wr._parse_event_name("ts [sid] INFO") is None


# ---------------------------------------------------------------------------
# _parse_ts
# ---------------------------------------------------------------------------
def test_parse_ts_valid():
    ts = wr._parse_ts("2026-06-14T10:00:00Z  rest of line")
    assert isinstance(ts, int) and ts > 0


def test_parse_ts_invalid():
    assert wr._parse_ts("not-a-timestamp rest") is None
    assert wr._parse_ts("") is None


# ---------------------------------------------------------------------------
# _read_progress_state
# ---------------------------------------------------------------------------
def test_read_progress_state_missing(tmp_path):
    assert wr._read_progress_state(tmp_path) is None


def test_read_progress_state_bad_json(tmp_path):
    (tmp_path / ".appsec-progress.json").write_text("{not json")
    assert wr._read_progress_state(tmp_path) is None


def test_read_progress_state_full(tmp_path):
    payload = {
        "phase": "9",
        "phase_total": 12,
        "step": 2,
        "step_total": 4,
        "agent": "stride-analyzer",
        "label": "scanning",
    }
    (tmp_path / ".appsec-progress.json").write_text(json.dumps(payload))
    mtime, detail = wr._read_progress_state(tmp_path)
    assert isinstance(mtime, int)
    assert "phase=9/12" in detail
    assert "step=2/4" in detail
    assert "agent=stride-analyzer" in detail
    assert "label=scanning" in detail


def test_read_progress_state_detail_fallback(tmp_path):
    payload = {"phase": "1", "detail": "fallback-detail"}
    (tmp_path / ".appsec-progress.json").write_text(json.dumps(payload))
    _mtime, detail = wr._read_progress_state(tmp_path)
    assert "label=fallback-detail" in detail
    assert "phase=1" in detail  # no phase_total -> no /N suffix


# ---------------------------------------------------------------------------
# _print_budgets
# ---------------------------------------------------------------------------
def test_print_budgets_all(capsys):
    rc = wr._print_budgets(None)
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "standard" in data and "_meta" in data


def test_print_budgets_single_depth(capsys):
    rc = wr._print_budgets("quick")
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"quick", "_meta"}


def test_print_budgets_unknown_depth(capsys):
    rc = wr._print_budgets("bogus")
    assert rc == 2
    assert "unknown depth" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# watch — error / snapshot paths
# ---------------------------------------------------------------------------
def test_watch_missing_output_dir(tmp_path, capsys):
    missing = tmp_path / "nope"
    rc = wr.watch(missing, "standard", 1.5, once=True, poll_seconds=2.0)
    assert rc == 1
    assert "output_dir not found" in capsys.readouterr().err


def _bounded_time(monkeypatch, ticks):
    """Make time.time() walk through `ticks` then stay at the last value."""
    seq = list(ticks)
    state = {"i": 0}

    def fake_time():
        i = state["i"]
        if i < len(seq):
            state["i"] += 1
            return seq[i]
        return seq[-1]

    monkeypatch.setattr(wr.time, "time", fake_time)
    monkeypatch.setattr(wr.time, "sleep", lambda s: None)


def test_watch_once_empty_dir_snapshot(tmp_path, monkeypatch, capsys):
    out = tmp_path / "out"
    out.mkdir()
    # deadline = time()+poll. First call (deadline calc)=0, loop check >= 1000
    _bounded_time(monkeypatch, [0, 1000])
    rc = wr.watch(out, "standard", 1.5, once=True, poll_seconds=5.0)
    assert rc == 0
    o = capsys.readouterr().out
    assert "WATCH_START" in o
    assert "WATCH_END" in o
    assert "events=0" in o


def test_watch_once_tracks_phase_and_progress(tmp_path, monkeypatch, capsys):
    # NOTE: the log read-and-relay block (lines ~245-259 of watch_run.py) is
    # effectively dead because `fh.tell()` inside `for raw in fh` raises
    # OSError("telling position disabled by next() call"), which the
    # surrounding `except OSError: pass` swallows. So we cannot assert on
    # relayed PHASE_START events here; we assert on the reachable PHASE_TRACK
    # and PROGRESS synthetic events instead. (Reported as a real bug.)
    out = tmp_path / "out"
    out.mkdir()
    (out / ".hook-events.log").write_text("x")  # non-empty so is_file branch taken
    (out / ".appsec-checkpoint").write_text("phase=1 status=running\n")
    (out / ".appsec-progress.json").write_text(json.dumps({"phase": "1", "step": 1, "step_total": 3}))

    _bounded_time(monkeypatch, [0, 1000])
    rc = wr.watch(out, "standard", 1.5, once=True, poll_seconds=5.0)
    assert rc == 0
    o = capsys.readouterr().out
    assert "PHASE_TRACK" in o
    assert "phase=?→1" in o
    assert "PROGRESS" in o
    assert "phase=1" in o
    assert "WATCH_END" in o


def test_watch_log_rotation_resets_pos(tmp_path, monkeypatch, capsys):
    # Exercise the `size < pos` rotation branch (pos reset to 0). The relay
    # itself is dead (see note above), so we only assert the loop survives a
    # shrink without raising and still completes the snapshot.
    out = tmp_path / "out"
    out.mkdir()
    log = out / ".hook-events.log"
    log.write_text("x" * 500)  # initial size 500 -> pos=500 at start

    appended = {"done": False}

    def fake_time():
        if not appended["done"]:
            appended["done"] = True
            # rotate: shrink below pos
            log.write_text("short\n")
            return 0
        return 1000

    monkeypatch.setattr(wr.time, "time", fake_time)
    monkeypatch.setattr(wr.time, "sleep", lambda s: None)

    rc = wr.watch(out, "standard", 1.5, once=True, poll_seconds=5.0)
    assert rc == 0
    assert "WATCH_END" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def test_main_print_budgets(capsys):
    rc = wr.main(["prog", "--print-budgets"])
    assert rc == 0
    assert "_meta" in capsys.readouterr().out


def test_main_print_budgets_with_depth(capsys):
    rc = wr.main(["prog", "--print-budgets", "--depth", "quick"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"quick", "_meta"}


def test_main_requires_output_dir(monkeypatch, capsys):
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    with pytest.raises(SystemExit):
        wr.main(["prog"])


def test_main_dispatches_to_watch(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    captured = {}

    def fake_watch(*, output_dir, depth, stall_multiplier, once, poll_seconds):
        captured.update(
            output_dir=output_dir, depth=depth, stall_multiplier=stall_multiplier, once=once, poll_seconds=poll_seconds
        )
        return 7

    monkeypatch.setattr(wr, "watch", fake_watch)
    rc = wr.main(["prog", str(out), "--depth", "thorough", "--stall-multiplier", "2.0", "--once", "--poll-seconds", "1"])
    assert rc == 7
    assert captured["depth"] == "thorough"
    assert captured["stall_multiplier"] == 2.0
    assert captured["once"] is True
    assert captured["poll_seconds"] == 1.0


def test_main_output_dir_from_env(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setenv("OUTPUT_DIR", str(out))
    monkeypatch.setattr(wr, "watch", lambda **k: 0)
    # argparse default reads os.environ at module-call time via default=...,
    # which is evaluated at parser construction inside main -> picks up env.
    rc = wr.main(["prog"])
    assert rc == 0
