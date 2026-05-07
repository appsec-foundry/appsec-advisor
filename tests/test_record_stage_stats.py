"""Tests for scripts/record_stage_stats.py — JSONL append + idempotency."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "record_stage_stats.py"


def _load():
    spec = importlib.util.spec_from_file_location("record_stage_stats", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["record_stage_stats"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


rec = _load()


def _argv(output_dir: Path, **overrides) -> list[str]:
    base = {
        "--stage": "1",
        "--name": "Analysis & Triage",
        "--agent": "appsec-advisor:appsec-threat-analyst",
        "--model": "claude-sonnet-4-6",
        "--duration-ms": "1503583",
        "--tool-uses": "113",
        "--tokens": "93066",
    }
    base.update({k: str(v) for k, v in overrides.items()})
    args = ["record_stage_stats.py", str(output_dir)]
    for k, v in base.items():
        args.extend([k, v])
    return args


def test_append_creates_jsonl(tmp_path):
    rc = rec.main(_argv(tmp_path))
    assert rc == 0
    jsonl = tmp_path / ".stage-stats.jsonl"
    assert jsonl.is_file()
    record = json.loads(jsonl.read_text().strip())
    assert record["stage"] == 1
    assert record["duration_ms"] == 1503583
    assert record["tool_uses"] == 113
    assert record["tokens"] == 93066


def test_idempotent_on_duplicate_stage(tmp_path):
    rc1 = rec.main(_argv(tmp_path, **{"--stage": "1", "--tokens": "100"}))
    rc2 = rec.main(_argv(tmp_path, **{"--stage": "1", "--tokens": "999999"}))
    assert rc1 == 0
    assert rc2 == 0  # no-op exit
    jsonl = tmp_path / ".stage-stats.jsonl"
    lines = [l for l in jsonl.read_text().splitlines() if l.strip()]
    assert len(lines) == 1, "duplicate stage must not append a second record"
    record = json.loads(lines[0])
    assert record["tokens"] == 100, "first write wins"


def test_allow_duplicates_overrides_idempotency(tmp_path):
    rec.main(_argv(tmp_path, **{"--stage": "1", "--tokens": "100"}))
    argv = _argv(tmp_path, **{"--stage": "1", "--tokens": "999"})
    argv.append("--allow-duplicates")
    rc = rec.main(argv)
    assert rc == 0
    jsonl = tmp_path / ".stage-stats.jsonl"
    lines = [l for l in jsonl.read_text().splitlines() if l.strip()]
    assert len(lines) == 2


def test_multiple_stages_append_in_order(tmp_path):
    rec.main(_argv(tmp_path, **{"--stage": "1"}))
    rec.main(_argv(tmp_path, **{"--stage": "2", "--name": "Report Rendering", "--tokens": "108296"}))
    rec.main(_argv(tmp_path, **{"--stage": "3", "--name": "QA Review", "--tokens": "153087"}))
    jsonl = tmp_path / ".stage-stats.jsonl"
    records = [json.loads(l) for l in jsonl.read_text().splitlines() if l.strip()]
    assert [r["stage"] for r in records] == [1, 2, 3]


def test_missing_output_dir_errors(tmp_path):
    """Required positional arg + no env fallback → exit 2 from argparse."""
    argv = ["record_stage_stats.py",
            "--stage", "1", "--name", "x",
            "--agent", "y", "--duration-ms", "1",
            "--tool-uses", "1", "--tokens", "1"]
    with pytest.raises(SystemExit) as exc:
        rec.main(argv)
    assert exc.value.code == 2


def test_output_dir_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    argv = ["record_stage_stats.py",
            "--stage", "1", "--name", "x",
            "--agent", "y", "--model", "m", "--duration-ms", "1",
            "--tool-uses", "1", "--tokens", "1"]
    rc = rec.main(argv)
    assert rc == 0
    assert (tmp_path / ".stage-stats.jsonl").is_file()
