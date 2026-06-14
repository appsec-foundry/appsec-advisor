from __future__ import annotations

import json
import subprocess
from pathlib import Path

import batch_checkpoint
import phase_elapsed
import pytest
import qa_release_gate
import record_component_durations as rcd


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run_batch_checkpoint(monkeypatch, *args: object) -> int:
    monkeypatch.setattr(batch_checkpoint.sys, "argv", ["batch_checkpoint.py", *[str(a) for a in args]])
    with pytest.raises(SystemExit) as exc:
        batch_checkpoint.main()
    return int(exc.value.code or 0)


def test_phase_elapsed_usage_valid_epoch_and_fallback(monkeypatch, tmp_path: Path, capsys) -> None:
    assert phase_elapsed.main(["phase_elapsed.py"]) == 2
    assert "usage:" in capsys.readouterr().err

    out = tmp_path / "out"
    out.mkdir()
    _write(out / ".phase-epoch", "873\n")
    monkeypatch.setattr(phase_elapsed.time, "time", lambda: 1000)

    assert phase_elapsed.main(["phase_elapsed.py", str(out)]) == 0
    assert capsys.readouterr().out == "127 2m07s\n"

    _write(out / ".phase-epoch", "not an int\n")
    assert phase_elapsed.main(["phase_elapsed.py", str(out)]) == 0
    assert capsys.readouterr().out == "0 0m00s\n"


def test_batch_checkpoint_writes_checkpoint_and_skips_missing_heartbeat(monkeypatch, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(batch_checkpoint.os.path, "isfile", lambda path: False)

    rc = _run_batch_checkpoint(
        monkeypatch,
        out,
        "--phase",
        "11",
        "--step",
        "2",
        "--status",
        "yaml_written",
    )

    assert rc == 0
    checkpoint = (out / ".appsec-checkpoint").read_text(encoding="utf-8")
    assert checkpoint.startswith("phase=11 step=2 status=yaml_written timestamp=")
    assert "heartbeat skipped" in capsys.readouterr().err


def test_batch_checkpoint_reports_nonfatal_heartbeat_failure(monkeypatch, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(batch_checkpoint.os.path, "isfile", lambda path: True)

    def fake_run(cmd, capture_output):
        assert "--heartbeat" in cmd
        assert "--phase=9" in cmd
        assert "--step=fanout" in cmd
        assert capture_output is True
        return subprocess.CompletedProcess(cmd, 7, stderr=b"lock stale")

    monkeypatch.setattr(subprocess, "run", fake_run)

    rc = _run_batch_checkpoint(
        monkeypatch,
        out,
        "--phase",
        "9",
        "--step",
        "fanout",
        "--status",
        "started",
        "--lock",
        out / ".custom-lock",
    )

    assert rc == 0
    assert "heartbeat failed" in capsys.readouterr().err


def test_qa_release_gate_scan_missing_unreadable_ok_and_blocked(tmp_path: Path) -> None:
    missing_rc, missing = qa_release_gate.scan(tmp_path / "missing.json")
    assert missing_rc == 1
    assert missing["status"] == "missing"

    bad = tmp_path / "bad.json"
    _write(bad, "{bad json")
    unreadable_rc, unreadable = qa_release_gate.scan(bad)
    assert unreadable_rc == 1
    assert unreadable["status"] == "unreadable"

    ok = tmp_path / "ok.json"
    _write(ok, json.dumps({"manual_review_items": [{"issue": "cosmetic heading", "description": "false positive"}]}))
    ok_rc, ok_payload = qa_release_gate.scan(ok)
    assert ok_rc == 0
    assert ok_payload["status"] == "ok"
    assert ok_payload["items_total"] == 1

    blocked = tmp_path / "blocked.json"
    _write(
        blocked,
        json.dumps(
            {
                "manual_review_items": [
                    {"issue": "Mitigation column empty", "description": "must abort"},
                    {"issue": "ignored scalar"},
                    "bad item",
                ]
            }
        ),
    )
    blocked_rc, blocked_payload = qa_release_gate.scan(blocked)
    assert blocked_rc == 2
    assert blocked_payload["status"] == "blocked"
    assert blocked_payload["items_total"] == 3
    assert blocked_payload["blockers"][0]["matched_pattern"] == "mitigation column empty"


def test_qa_release_gate_main_usage_and_blocker_output(tmp_path: Path, capsys) -> None:
    assert qa_release_gate.main(["qa_release_gate.py"]) == 1
    assert "Usage:" in capsys.readouterr().err

    status = tmp_path / ".qa-status.json"
    _write(status, json.dumps({"manual_review_items": [{"issue": "Broken anchor in report"}]}))

    assert qa_release_gate.main(["qa_release_gate.py", str(status)]) == 2

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["blockers_count"] == 1
    assert "RELEASE-BLOCKER" in captured.err
    assert "[broken anchor]" in captured.err


def test_record_component_duration_timestamp_helpers(tmp_path: Path) -> None:
    log = tmp_path / ".agent-run.log"
    _write(
        log,
        "\n".join(
            [
                "2026-01-01T00:00:00Z  [--------]  PHASE_START  [Phase 9/11] old",
                "2026-01-01T00:05:00Z  [--------]  PHASE_START  [Phase 9/11] new",
                "not-a-date  [--------]  PHASE_START  [Phase 9/11] bad",
            ]
        ),
    )

    assert rcd._parse_ts("2026-01-01T00:05:00Z") == 1767225900
    assert rcd._parse_ts("bad") is None
    assert rcd._read_phase_9_start(log) is None

    _write(log, "2026-01-01T00:05:00Z  [--------]  PHASE_START  [Phase 9/11] ok\n")
    assert rcd._read_phase_9_start(log) == 1767225900
    assert rcd._read_phase_9_start(tmp_path / "missing.log") is None


def test_record_component_durations_prefers_self_reported_then_log_then_mtime(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(
        out / ".stride-api.json",
        json.dumps({"started_at": "2026-01-01T00:00:00Z", "analyzed_at": "2026-01-01T00:01:10Z"}),
    )
    _write(out / ".stride-bad.json", json.dumps({"started_at": "bad", "analyzed_at": "2026-01-01T00:00:00Z"}))
    _write(out / ".stride-list.json", "[]")
    _write(out / ".stride-missing-ts.json", "{}")
    _write(
        out / ".stride-too-long.json",
        json.dumps({"started_at": "2026-01-01T00:00:00Z", "analyzed_at": "2026-01-01T03:00:00Z"}),
    )

    assert rcd._self_reported_durations(out) == {"api": 70}
    assert rcd._stride_durations(out, phase_9_start=1767225600) == {"api": 70}

    for path in out.glob(".stride-*.json"):
        path.unlink()
    _write(
        out / ".agent-run.log",
        "\n".join(
            [
                "2026-01-01T00:00:00Z  [--------]  stride-analyzer  AGENT_INVOKE  STRIDE analysis: api",
                "2026-01-01T00:00:45Z  [--------]  stride-analyzer  AGENT_DONE  STRIDE analysis: api complete",
                "2026-01-01T00:02:00Z  [--------]  stride-analyzer  AGENT_INVOKE  STRIDE analysis: bad",
                "2026-01-01T00:01:00Z  [--------]  stride-analyzer  AGENT_DONE  STRIDE analysis: bad complete",
            ]
        ),
    )

    assert rcd._per_component_marker_pairs(out / ".agent-run.log") == {"api": 45}
    assert rcd._stride_durations(out, phase_9_start=1767225600) == {"api": 45}
    assert rcd._per_component_marker_pairs(tmp_path / "missing.log") == {}

    (out / ".agent-run.log").unlink()
    stride = out / ".stride-worker.json"
    _write(stride, "{}")
    old = out / ".stride-old.json"
    _write(old, "{}")
    outlier = out / ".stride-outlier.json"
    _write(outlier, "{}")
    mtime = 1767225660
    stride.touch()
    import os

    os.utime(stride, (mtime, mtime))
    os.utime(old, (1767225590, 1767225590))
    os.utime(outlier, (1767234001, 1767234001))
    assert rcd._stride_durations(out, phase_9_start=1767225600) == {"worker": 60}


def test_record_component_durations_merge_and_main(tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    cache = out / ".appsec-cache" / "baseline.json"
    _write(cache, json.dumps({"existing": True}))

    assert rcd._merge_into_baseline(cache, {"api": 12}, phase_9_start=1767225600) is True
    merged = json.loads(cache.read_text(encoding="utf-8"))
    assert merged["existing"] is True
    assert merged["component_durations"] == {"api": 12}
    assert merged["component_durations_phase_9_start"] == 1767225600

    _write(cache, "{bad json")
    assert rcd._merge_into_baseline(cache, {"api": 13}, phase_9_start=1767225601) is True
    assert json.loads(cache.read_text(encoding="utf-8"))["component_durations"] == {"api": 13}

    assert rcd.main([str(tmp_path / "missing")]) == 2
    assert "not a directory" in capsys.readouterr().err

    empty = tmp_path / "empty"
    empty.mkdir()
    assert rcd.main([str(empty)]) == 0
    assert "no Phase 9" in capsys.readouterr().err
    assert rcd.main([str(empty), "--phase-9-start", "1767225600"]) == 0
    assert "no .stride-*.json" in capsys.readouterr().err

    _write(
        out / ".stride-api.json",
        json.dumps({"started_at": "2026-01-01T00:00:00Z", "analyzed_at": "2026-01-01T00:00:20Z"}),
    )
    assert rcd.main([str(out), "--phase-9-start", "1767225600"]) == 0
    assert "api" in capsys.readouterr().err
    assert json.loads(cache.read_text(encoding="utf-8"))["component_durations"] == {"api": 20}


def test_record_component_durations_main_reports_merge_failure(monkeypatch, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(
        out / ".stride-api.json",
        json.dumps({"started_at": "2026-01-01T00:00:00Z", "analyzed_at": "2026-01-01T00:00:20Z"}),
    )
    monkeypatch.setattr(rcd, "_merge_into_baseline", lambda *args, **kwargs: False)

    assert rcd.main([str(out), "--phase-9-start", "1767225600"]) == 1
    assert "failed to write baseline" in capsys.readouterr().err
