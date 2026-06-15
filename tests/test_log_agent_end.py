"""Unit tests for scripts/log_agent_end.py."""

from __future__ import annotations

import log_agent_end as mod

# --- fmt_duration ----------------------------------------------------------


def test_fmt_duration():
    assert mod.fmt_duration(0) == "0 min 00 s"
    assert mod.fmt_duration(5) == "0 min 05 s"
    assert mod.fmt_duration(65) == "1 min 05 s"
    assert mod.fmt_duration(600) == "10 min 00 s"


# --- main ------------------------------------------------------------------


def test_main_wrong_arg_count(capsys):
    rc = mod.main(["log_agent_end.py", "only", "three", "args"])
    assert rc == 2
    assert "usage:" in capsys.readouterr().err


def test_main_appends_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(mod.time, "time", lambda: 1000.0)
    rc = mod.main(["log_agent_end.py", str(tmp_path), "threat-analyst", "sonnet", "940"])
    assert rc == 0
    log = (tmp_path / ".agent-run.log").read_text()
    assert "AGENT_END" in log
    assert "threat-analyst" in log
    assert "model: sonnet" in log
    assert "1 min 00 s" in log  # 1000 - 940 = 60s


def test_main_non_integer_start_epoch(tmp_path, monkeypatch):
    monkeypatch.setattr(mod.time, "time", lambda: 500.0)
    rc = mod.main(["log_agent_end.py", str(tmp_path), "stride-analyzer", "opus", "not-a-number"])
    assert rc == 0
    # start_epoch defaults to 0 → elapsed = 500s = 8 min 20 s
    log = (tmp_path / ".agent-run.log").read_text()
    assert "8 min 20 s" in log


def test_main_negative_elapsed_clamped(tmp_path, monkeypatch):
    monkeypatch.setattr(mod.time, "time", lambda: 100.0)
    rc = mod.main(["log_agent_end.py", str(tmp_path), "a", "m", "999"])
    assert rc == 0
    log = (tmp_path / ".agent-run.log").read_text()
    assert "0 min 00 s" in log  # max(0, 100-999) == 0


def test_main_appends_not_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(mod.time, "time", lambda: 1000.0)
    mod.main(["log_agent_end.py", str(tmp_path), "first", "m", "1000"])
    mod.main(["log_agent_end.py", str(tmp_path), "second", "m", "1000"])
    log = (tmp_path / ".agent-run.log").read_text()
    assert "first" in log and "second" in log
    assert log.count("AGENT_END") == 2


def test_main_non_writable_dir_ignored(tmp_path):
    # output_dir points at a path whose parent is a file → open('a') raises OSError
    nonfile = tmp_path / "afile"
    nonfile.write_text("x", encoding="utf-8")
    bad_dir = nonfile / "subdir"  # parent is a file, not a dir
    rc = mod.main(["log_agent_end.py", str(bad_dir), "a", "m", "1"])
    assert rc == 0  # OSError swallowed
