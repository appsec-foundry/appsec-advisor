"""Tests for scripts/record_stage_stats.py — JSONL append + idempotency."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
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
        "--name": "Threat Analysis & Triage",
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
    argv = [
        "record_stage_stats.py",
        "--stage",
        "1",
        "--name",
        "x",
        "--agent",
        "y",
        "--duration-ms",
        "1",
        "--tool-uses",
        "1",
        "--tokens",
        "1",
    ]
    with pytest.raises(SystemExit) as exc:
        rec.main(argv)
    assert exc.value.code == 2


def test_output_dir_via_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    argv = [
        "record_stage_stats.py",
        "--stage",
        "1",
        "--name",
        "x",
        "--agent",
        "y",
        "--model",
        "m",
        "--duration-ms",
        "1",
        "--tool-uses",
        "1",
        "--tokens",
        "1",
    ]
    rc = rec.main(argv)
    assert rc == 0
    assert (tmp_path / ".stage-stats.jsonl").is_file()


# ---------------------------------------------------------------------------
# Dispatch-wall derivation tests (--subagent-type + --since-iso)
# ---------------------------------------------------------------------------

# Synthetic hook log mirroring the 2026-05-23 juice-shop Stage 2 multi-dispatch
# (two AGENT_SPAWN, one AGENT_INVOKE — earlier Spawn 1 never returned).
_MULTI_DISPATCH_LOG = """\
2026-05-23T17:32:13Z  [f13a4710]  INFO   AGENT_SPAWN         appsec-advisor:appsec-threat-analyst         model=sonnet  Threat Analysis & Triage  [REPO_ROOT=/x]
2026-05-23T18:26:53Z  [f13a4710]  INFO   AGENT_INVOKE        appsec-advisor:appsec-threat-analyst         model=sonnet  Threat Analysis & Triage  [REPO_ROOT=/x]
2026-05-23T18:28:15Z  [f13a4710]  INFO   AGENT_SPAWN         appsec-advisor:appsec-threat-renderer        model=sonnet  Threat Model Renderer (Stage 2)  [REPO_ROOT=/x]
2026-05-23T18:36:07Z  [f13a4710]  INFO   AGENT_SPAWN         appsec-advisor:appsec-threat-renderer        model=sonnet  Threat Model Renderer (Stage 2)  [REPO_ROOT=/x]
2026-05-23T18:44:17Z  [f13a4710]  INFO   AGENT_INVOKE        appsec-advisor:appsec-threat-renderer        model=sonnet  Threat Model Renderer (Stage 2)  [REPO_ROOT=/x]
"""


def _write_hook_log(output_dir: Path, body: str = _MULTI_DISPATCH_LOG) -> None:
    (output_dir / ".hook-events.log").write_text(body, encoding="utf-8")


def test_dispatch_derivation_multi_spawn(tmp_path):
    """Stage 2 with 2 spawns + 1 clean return → wall covers both spawns."""
    _write_hook_log(tmp_path)
    argv = _argv(
        tmp_path,
        **{
            "--stage": "2",
            "--name": "Report Rendering",
            "--agent": "appsec-advisor:appsec-threat-renderer",
            "--duration-ms": "486210",
            "--subagent-type": "appsec-advisor:appsec-threat-renderer",
            "--since-iso": "2026-05-23T18:27:00Z",
        },
    )
    rc = rec.main(argv)
    assert rc == 0
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    # 2 AGENT_SPAWN for the renderer after the since cutoff.
    assert record["dispatch_count"] == 2
    # First spawn 18:28:15 → last invoke 18:44:17 = 962 s.
    assert record["wall_secs_observed"] == 962
    # Original duration_ms preserved alongside the derived wall.
    assert record["duration_ms"] == 486210


def test_dispatch_derivation_single_spawn(tmp_path):
    """Stage 1 with 1 spawn + 1 clean return → dispatch_count == 1."""
    _write_hook_log(tmp_path)
    argv = _argv(
        tmp_path,
        **{
            "--stage": "1",
            "--subagent-type": "appsec-advisor:appsec-threat-analyst",
            "--since-iso": "2026-05-23T17:00:00Z",
        },
    )
    rc = rec.main(argv)
    assert rc == 0
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert record["dispatch_count"] == 1
    # 17:32:13 → 18:26:53 = 3280 s.
    assert record["wall_secs_observed"] == 3280


def test_dispatch_derivation_since_filter_excludes_earlier_spawns(tmp_path):
    """Events earlier than --since-iso are not counted."""
    _write_hook_log(tmp_path)
    argv = _argv(
        tmp_path,
        **{
            "--stage": "2",
            "--name": "Report Rendering",
            "--agent": "appsec-advisor:appsec-threat-renderer",
            "--subagent-type": "appsec-advisor:appsec-threat-renderer",
            # since-iso AFTER the first renderer spawn — only Spawn 2 counts.
            "--since-iso": "2026-05-23T18:30:00Z",
        },
    )
    rc = rec.main(argv)
    assert rc == 0
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert record["dispatch_count"] == 1
    # 18:36:07 → 18:44:17 = 490 s.
    assert record["wall_secs_observed"] == 490


def test_dispatch_derivation_missing_log(tmp_path):
    """Missing .hook-events.log → derived fields omitted, record still written."""
    argv = _argv(
        tmp_path,
        **{
            "--subagent-type": "appsec-advisor:appsec-threat-analyst",
            "--since-iso": "2026-05-23T17:00:00Z",
        },
    )
    rc = rec.main(argv)
    assert rc == 0
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert "dispatch_count" not in record
    assert "wall_secs_observed" not in record


def test_dispatch_derivation_back_compat_no_args(tmp_path):
    """Without --subagent-type/--since-iso the record matches pre-existing shape."""
    _write_hook_log(tmp_path)  # log present, args missing — derivation skipped
    argv = _argv(tmp_path)
    rc = rec.main(argv)
    assert rc == 0
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert "dispatch_count" not in record
    assert "wall_secs_observed" not in record


def test_dispatch_derivation_partial_args_warn_and_skip(tmp_path, capsys):
    """Passing only one of the pair surfaces a stderr warning and is otherwise a no-op."""
    _write_hook_log(tmp_path)
    argv = _argv(tmp_path, **{"--subagent-type": "appsec-advisor:appsec-threat-analyst"})
    rc = rec.main(argv)
    assert rc == 0
    err = capsys.readouterr().err
    assert "--subagent-type and --since-iso must be passed together" in err
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert "dispatch_count" not in record
    assert "wall_secs_observed" not in record


def test_dispatch_derivation_unknown_subagent_omits_fields(tmp_path):
    """No matching subagent events → derivation returns None, fields omitted."""
    _write_hook_log(tmp_path)
    argv = _argv(
        tmp_path,
        **{
            "--subagent-type": "appsec-advisor:nonexistent-agent",
            "--since-iso": "2026-05-23T17:00:00Z",
        },
    )
    rc = rec.main(argv)
    assert rc == 0
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert "dispatch_count" not in record
    assert "wall_secs_observed" not in record
