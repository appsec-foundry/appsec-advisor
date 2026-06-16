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


# ---------------------------------------------------------------------------
# Fix B (2026-05-25) — hybrid-record sanity gate. A record that claims a
# deterministic agent/model but carries non-zero token/tool counts is
# impossible by construction and indicates the skill conflated two stages
# (e.g. QA fast-path label + Re-Render-Loop REPAIR_MODE token counts).
# ---------------------------------------------------------------------------


def test_hybrid_record_flagged_when_deterministic_label_carries_llm_tokens(tmp_path, capsys):
    """Reproduces the juice-shop 2026-05-25 Stage-3 record shape."""
    argv = _argv(
        tmp_path,
        **{
            "--stage": "3",
            "--name": "QA Review",
            "--agent": "deterministic:qa_checks.py",
            "--model": "none",
            "--duration-ms": "545553",
            "--tool-uses": "95",
            "--tokens": "119662",
        },
    )
    rc = rec.main(argv)
    assert rc == 0  # non-fatal, record still written
    err = capsys.readouterr().err
    assert "claims deterministic" in err
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert "_inconsistency" in record, "record must carry structured inconsistency annotation"
    assert "tokens=119662" in record["_inconsistency"]


def test_hybrid_record_clean_when_deterministic_and_zero_tokens(tmp_path, capsys):
    """The canonical deterministic-skip path (tokens=0, tool_uses=0) must NOT trip."""
    argv = _argv(
        tmp_path,
        **{
            "--stage": "3",
            "--agent": "deterministic:qa_checks.py",
            "--model": "none",
            "--duration-ms": "5000",
            "--tool-uses": "0",
            "--tokens": "0",
        },
    )
    rc = rec.main(argv)
    assert rc == 0
    err = capsys.readouterr().err
    assert "claims deterministic" not in err
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert "_inconsistency" not in record


def test_hybrid_record_clean_when_llm_agent_with_tokens(tmp_path, capsys):
    """The canonical LLM-dispatch path (model=sonnet, tokens=N) must NOT trip."""
    argv = _argv(
        tmp_path,
        **{
            "--stage": "2",
            "--agent": "appsec-advisor:appsec-threat-renderer",
            "--model": "claude-sonnet-4-6",
            "--duration-ms": "481000",
            "--tool-uses": "47",
            "--tokens": "93240",
        },
    )
    rc = rec.main(argv)
    assert rc == 0
    err = capsys.readouterr().err
    assert "claims deterministic" not in err
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert "_inconsistency" not in record


# ---------------------------------------------------------------------------
# Fix C (2026-05-25) — --variant lets multiple records per stage coexist
# without --allow-duplicates (e.g. Stage 3 = QA fast-path + repair-mode).
# ---------------------------------------------------------------------------


def test_variant_allows_second_record_for_same_stage(tmp_path):
    """Two records for stage=3 differentiated by --variant are both written."""
    rec.main(
        _argv(
            tmp_path,
            **{
                "--stage": "3",
                "--name": "QA Review",
                "--tokens": "0",
                "--tool-uses": "0",
                "--agent": "deterministic:qa_checks.py",
                "--model": "none",
                "--duration-ms": "5000",
            },
        )
    )
    rc2 = rec.main(
        _argv(
            tmp_path,
            **{
                "--stage": "3",
                "--variant": "repair",
                "--name": "Re-Render Loop",
                "--agent": "appsec-advisor:appsec-threat-analyst",
                "--model": "claude-sonnet-4-6",
                "--duration-ms": "545553",
                "--tool-uses": "95",
                "--tokens": "119662",
            },
        )
    )
    assert rc2 == 0
    records = [json.loads(l) for l in (tmp_path / ".stage-stats.jsonl").read_text().splitlines() if l.strip()]
    assert len(records) == 2, "variant must coexist with default record without --allow-duplicates"
    assert records[0].get("variant", "") == ""
    assert records[1].get("variant") == "repair"


def test_variant_same_key_still_idempotent(tmp_path, capsys):
    """Two records with same (stage, variant) → still no-op on duplicate."""
    rec.main(_argv(tmp_path, **{"--stage": "3", "--variant": "repair"}))
    rc = rec.main(_argv(tmp_path, **{"--stage": "3", "--variant": "repair", "--tokens": "999"}))
    assert rc == 0
    records = [json.loads(l) for l in (tmp_path / ".stage-stats.jsonl").read_text().splitlines() if l.strip()]
    assert len(records) == 1
    err = capsys.readouterr().err
    assert "variant='repair'" in err


# ---------------------------------------------------------------------------
# Fix D (2026-05-25) — _HOOK_EVENT_RE matches SCAN_START + SCAN_COMPLETE
# (subagent after `agent=`), not only AGENT_SPAWN/AGENT_INVOKE (positional).
# Without this, wall_secs_observed=0 on hooks that emit only SCAN_* events.
# ---------------------------------------------------------------------------


_SCAN_EVENT_LOG = """\
2026-05-25T06:46:14Z  [1b5162a8]  INFO   AGENT_SPAWN         appsec-advisor:appsec-threat-analyst         model=sonnet  Threat Analysis & Triage (repair-mode)  [REPO_ROOT=/x]
2026-05-25T06:46:14Z  [1b5162a8]  INFO   SCAN_START          repo=/x  agent=appsec-advisor:appsec-threat-analyst  model=sonnet
2026-05-25T06:55:22Z  [1b5162a8]  INFO   SCAN_COMPLETE       repo=/x  agent=appsec-advisor:appsec-threat-analyst  model=sonnet
"""


def test_match_hook_event_handles_scan_complete(tmp_path):
    """SCAN_COMPLETE has subagent after `agent=`; the matcher must capture it."""
    m = rec._match_hook_event(
        "2026-05-25T06:55:22Z  [1b5162a8]  INFO   SCAN_COMPLETE  "
        "repo=/x  agent=appsec-advisor:appsec-threat-analyst  model=sonnet\n"
    )
    assert m is not None
    assert m.group("event") == "SCAN_COMPLETE"
    assert m.group("subagent") == "appsec-advisor:appsec-threat-analyst"


def test_match_hook_event_handles_scan_start(tmp_path):
    m = rec._match_hook_event(
        "2026-05-25T06:46:14Z  [x]  INFO   SCAN_START  repo=/x  "
        "agent=appsec-advisor:appsec-threat-analyst  model=sonnet\n"
    )
    assert m is not None
    assert m.group("event") == "SCAN_START"
    assert m.group("subagent") == "appsec-advisor:appsec-threat-analyst"


def test_match_hook_event_agent_spawn_unchanged(tmp_path):
    """AGENT_SPAWN regex path (positional subagent) must keep its semantics."""
    m = rec._match_hook_event(
        "2026-05-25T06:46:14Z  [x]  INFO   AGENT_SPAWN  appsec-advisor:appsec-threat-analyst  model=sonnet  desc\n"
    )
    assert m is not None
    assert m.group("event") == "AGENT_SPAWN"
    assert m.group("subagent") == "appsec-advisor:appsec-threat-analyst"


def test_dispatch_derivation_with_only_scan_events_now_yields_wall(tmp_path):
    """Hook log with AGENT_SPAWN + SCAN_COMPLETE (no AGENT_INVOKE) — pre-fix
    would have returned wall_secs_observed=0 because SCAN_COMPLETE wasn't
    matched. Post-fix the spread reflects the full SPAWN→SCAN_COMPLETE
    interval (~9 min for the juice-shop repair-mode dispatch)."""
    _write_hook_log(tmp_path, body=_SCAN_EVENT_LOG)
    argv = _argv(
        tmp_path,
        **{
            "--stage": "3",
            "--variant": "repair",
            "--agent": "appsec-advisor:appsec-threat-analyst",
            "--subagent-type": "appsec-advisor:appsec-threat-analyst",
            "--since-iso": "2026-05-25T06:45:00Z",
            "--duration-ms": "545553",
            "--tool-uses": "95",
            "--tokens": "119662",
        },
    )
    rc = rec.main(argv)
    assert rc == 0
    record = json.loads((tmp_path / ".stage-stats.jsonl").read_text().strip())
    assert record["dispatch_count"] == 1
    # 06:46:14 → 06:55:22 = 548 seconds
    assert record["wall_secs_observed"] == 548


# ---------------------------------------------------------------------------
# Coverage extensions: error/edge branches not exercised above.
# ---------------------------------------------------------------------------


def test_derive_dispatch_oserror_returns_none(tmp_path, monkeypatch):
    """An OSError while reading the log → None (lines 164-165)."""
    log = tmp_path / ".hook-events.log"
    log.write_text(_MULTI_DISPATCH_LOG, encoding="utf-8")

    def boom_open(*_a, **_k):
        raise OSError("read fail")

    monkeypatch.setattr(Path, "open", boom_open)
    assert (
        rec._derive_dispatch_stats(log, "appsec-advisor:appsec-threat-analyst", "2026-05-23T17:00:00Z") is None
    )


def test_derive_dispatch_bad_timestamp_returns_none(tmp_path, monkeypatch):
    """A ValueError parsing the timestamp → None (lines 171-172).

    Patch strptime to raise so the well-formed log still reaches the parse
    block but fails there.
    """
    log = tmp_path / ".hook-events.log"
    log.write_text(_MULTI_DISPATCH_LOG, encoding="utf-8")

    real_strptime = rec.datetime.strptime

    class _DT(rec.datetime):  # type: ignore[misc,valid-type]
        @classmethod
        def strptime(cls, *a, **k):
            raise ValueError("bad ts")

    monkeypatch.setattr(rec, "datetime", _DT)
    assert (
        rec._derive_dispatch_stats(log, "appsec-advisor:appsec-threat-analyst", "2026-05-23T17:00:00Z") is None
    )
    # sanity: real strptime still parses (not globally broken)
    assert real_strptime("2026-05-23T17:32:13Z", "%Y-%m-%dT%H:%M:%SZ")


def test_derive_dispatch_skips_nonmatching_lines(tmp_path):
    """Lines that don't match either regex are skipped (line 148 continue)."""
    log = tmp_path / ".hook-events.log"
    log.write_text(
        "garbage line that matches nothing\n"
        "another non-event line\n" + _MULTI_DISPATCH_LOG,
        encoding="utf-8",
    )
    out = rec._derive_dispatch_stats(
        log, "appsec-advisor:appsec-threat-analyst", "2026-05-23T17:00:00Z"
    )
    assert out is not None
    assert out["dispatch_count"] == 1


def test_existing_stage_keys_skips_blank_and_malformed(tmp_path):
    """Blank lines (line 194) and JSONDecodeError lines (197-198) are skipped."""
    jsonl = tmp_path / ".stage-stats.jsonl"
    jsonl.write_text(
        '\n'  # blank
        '   \n'  # whitespace-only blank
        '{ not json\n'  # malformed → JSONDecodeError
        '{"stage": 5}\n'  # valid int stage
        '{"stage": "x"}\n',  # stage not int → not added
        encoding="utf-8",
    )
    keys = rec._existing_stage_keys(jsonl)
    assert keys == {(5, "")}


def test_existing_stage_keys_oserror_returns_partial(tmp_path, monkeypatch):
    """OSError during read_text → returns the (empty) accumulator (lines 203-204)."""
    jsonl = tmp_path / ".stage-stats.jsonl"
    jsonl.write_text('{"stage": 1}\n', encoding="utf-8")

    def boom_read(*_a, **_k):
        raise OSError("read fail")

    monkeypatch.setattr(Path, "read_text", boom_read)
    assert rec._existing_stage_keys(jsonl) == set()


def test_existing_stage_numbers_alias(tmp_path):
    """Back-compat alias _existing_stage_numbers returns just the stage ints (line 210)."""
    jsonl = tmp_path / ".stage-stats.jsonl"
    jsonl.write_text('{"stage": 1}\n{"stage": 2, "variant": "repair"}\n', encoding="utf-8")
    assert rec._existing_stage_numbers(jsonl) == {1, 2}


def test_output_dir_not_a_directory_returns_2(tmp_path, capsys):
    """output_dir points at a file → exit 2 (lines 279-280)."""
    afile = tmp_path / "afile"
    afile.write_text("x")
    argv = _argv(afile)  # positional output_dir is a file, not dir
    rc = rec.main(argv)
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err


def test_rebuild_truncates_on_stage_1(tmp_path):
    """--rebuild + --stage 1 unlinks the existing jsonl before appending (286-289)."""
    jsonl = tmp_path / ".stage-stats.jsonl"
    jsonl.write_text('{"stage": 9, "stale": true}\n', encoding="utf-8")
    argv = _argv(tmp_path, **{"--stage": "1"})
    argv.append("--rebuild")
    rc = rec.main(argv)
    assert rc == 0
    records = [json.loads(l) for l in jsonl.read_text().splitlines() if l.strip()]
    assert len(records) == 1
    assert records[0]["stage"] == 1  # stale stage-9 record gone


def test_rebuild_unlink_oserror_warns_but_continues(tmp_path, monkeypatch, capsys):
    """If unlink fails the helper warns and still writes (line 288-289 except)."""
    jsonl = tmp_path / ".stage-stats.jsonl"
    jsonl.write_text('{"stage": 9}\n', encoding="utf-8")

    real_unlink = Path.unlink

    def boom_unlink(self, *a, **k):
        if self.name == ".stage-stats.jsonl":
            raise OSError("cannot unlink")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", boom_unlink)
    argv = _argv(tmp_path, **{"--stage": "1"})
    argv.append("--rebuild")
    rc = rec.main(argv)
    assert rc == 0
    assert "could not unlink" in capsys.readouterr().err


def test_append_oserror_returns_2(tmp_path, monkeypatch, capsys):
    """An OSError opening the jsonl for append → exit 2 (lines 361-363)."""

    real_open = Path.open

    def boom_open(self, *a, **k):
        if self.name == ".stage-stats.jsonl" and a and "a" in str(a[0]):
            raise OSError("disk full")
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "open", boom_open)
    rc = rec.main(_argv(tmp_path))
    assert rc == 2
    assert "failed to append" in capsys.readouterr().err


def test_script_main_entrypoint(tmp_path):
    """Run the module as __main__ via subprocess to cover line 370."""
    import subprocess as _sp

    out = _sp.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            str(tmp_path),
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
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0
    assert (tmp_path / ".stage-stats.jsonl").is_file()
