"""Additional coverage tests for scripts/agent_logger.py.

Targets the helper functions and handler branches that the existing
test_agent_logger.py / test_agent_logger_checkpoint_abort.py suites do not
reach: tool-call markers, path redaction, session-agent map, log rotation,
trace summary, transcript usage parsing, substep/activity emitters, and the
Read/Grep/Glob/MultiEdit PostToolUse branches.

The module runs ``main()`` at import (reading stdin), so it is loaded via an
isolated importlib spec with stdin/stderr neutralised — same pattern as
test_agent_logger_checkpoint_abort.py.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "agent_logger.py"


@pytest.fixture
def al(tmp_path, monkeypatch):
    """Import agent_logger fresh with OUTPUT_DIR -> tmp_path."""
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    spec = importlib.util.spec_from_file_location("agent_logger", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_logger"] = module
    assert spec.loader is not None
    with contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# _summarise_tool_input
# ---------------------------------------------------------------------------
class TestSummariseToolInput:
    def test_non_dict_returns_empty(self, al):
        assert al._summarise_tool_input("Bash", "not a dict") == ""

    def test_bash_command_summary(self, al):
        out = al._summarise_tool_input("Bash", {"command": "ls -la /tmp"})
        assert "ls -la" in out

    def test_bash_masks_secret(self, al):
        out = al._summarise_tool_input("Bash", {"command": "echo password='supersecret'"})
        assert "supersecret" not in out
        assert "****" in out

    def test_read_path_summary(self, al):
        out = al._summarise_tool_input("Read", {"file_path": "/tmp/foo.py"})
        assert out == "/tmp/foo.py"

    def test_read_path_redacted_when_enabled(self, al, monkeypatch):
        monkeypatch.setenv("APPSEC_LOG_REDACT_PATHS", "1")
        out = al._summarise_tool_input("Read", {"file_path": "/secret/secrets.ts"})
        assert "secrets.ts" in out
        assert out.startswith("<redacted:")
        assert "/secret/" not in out

    def test_agent_summary(self, al):
        out = al._summarise_tool_input(
            "Agent", {"subagent_type": "appsec-stride-analyzer", "description": "STRIDE run"}
        )
        assert "appsec-stride-analyzer" in out
        assert "STRIDE run" in out

    def test_grep_summary(self, al):
        out = al._summarise_tool_input("Grep", {"pattern": "TODO"})
        assert "TODO" in out

    def test_glob_summary(self, al):
        out = al._summarise_tool_input("Glob", {"pattern": "**/*.py"})
        assert "*.py" in out

    def test_unknown_tool_empty(self, al):
        assert al._summarise_tool_input("WeirdTool", {"x": 1}) == ""


# ---------------------------------------------------------------------------
# _path_redact_enabled / _redact_path
# ---------------------------------------------------------------------------
class TestPathRedaction:
    def test_disabled_by_default(self, al, monkeypatch):
        monkeypatch.delenv("APPSEC_LOG_REDACT_PATHS", raising=False)
        assert al._path_redact_enabled() is False

    def test_enabled_truthy_values(self, al, monkeypatch):
        for v in ("1", "true", "yes", "on", "ON", "True"):
            monkeypatch.setenv("APPSEC_LOG_REDACT_PATHS", v)
            assert al._path_redact_enabled() is True

    def test_redact_empty_passthrough(self, al):
        assert al._redact_path("") == ""

    def test_redact_format(self, al):
        out = al._redact_path("/home/u/project/secrets.ts")
        assert out.startswith("<redacted:secrets.ts:")
        assert out.endswith(">")
        # 8-char hex digest
        digest = out.rsplit(":", 1)[1].rstrip(">")
        assert len(digest) == 8

    def test_redact_trailing_slash(self, al):
        out = al._redact_path("/home/u/dir/")
        assert "dir" in out

    def test_redact_deterministic(self, al):
        a = al._redact_path("/x/y/z.txt")
        b = al._redact_path("/x/y/z.txt")
        assert a == b


# ---------------------------------------------------------------------------
# _record_tool_start / _record_tool_end / _dur_suffix
# ---------------------------------------------------------------------------
class TestActiveToolMarkers:
    def test_start_no_tool_use_id_noop(self, al, tmp_path):
        al._record_tool_start({"tool_name": "Bash", "tool_input": {}}, "sid12345")
        assert not (tmp_path / ".active-tool-calls").exists()

    def test_start_creates_marker(self, al, tmp_path):
        data = {
            "tool_use_id": "tu_abc123",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/x"},
        }
        al._record_tool_start(data, "sid98765")
        marker = tmp_path / ".active-tool-calls" / "tu_abc123.json"
        assert marker.exists()
        rec = json.loads(marker.read_text())
        assert rec["tool"] == "Read"
        assert rec["tool_use_id"] == "tu_abc123"
        assert rec["session_id"] == "sid98765"

    def test_end_returns_started_at_and_removes(self, al, tmp_path):
        data = {"tool_use_id": "tu_xyz", "tool_name": "Bash", "tool_input": {"command": "ls"}}
        al._record_tool_start(data, "sid00000")
        marker = tmp_path / ".active-tool-calls" / "tu_xyz.json"
        assert marker.exists()
        started = al._record_tool_end({"tool_use_id": "tu_xyz"})
        assert started > 0
        assert not marker.exists()

    def test_end_no_id_returns_zero(self, al):
        assert al._record_tool_end({}) == 0

    def test_end_missing_marker_returns_zero(self, al):
        assert al._record_tool_end({"tool_use_id": "never_written"}) == 0

    def test_active_tool_path_sanitizes(self, al):
        p = al._active_tool_path("../../etc/passwd")
        assert "/" in p  # dir join, but the filename component is sanitized
        assert Path(p).name == "etcpasswd.json"

    def test_active_tool_path_anon_for_empty(self, al):
        assert Path(al._active_tool_path("")).name == "anon.json"

    def test_dur_suffix_zero(self, al):
        assert al._dur_suffix(0) == ""

    def test_dur_suffix_nonzero(self, al):
        out = al._dur_suffix(int(time.time()) - 5)
        assert "dur=" in out and out.endswith("s")


# ---------------------------------------------------------------------------
# _save_session_agent / _lookup_session_agent
# ---------------------------------------------------------------------------
class TestSessionAgentMap:
    def test_save_and_lookup(self, al):
        al._save_session_agent("sess1234", "stride-analyzer")
        assert al._lookup_session_agent("sess1234") == "stride-analyzer"

    def test_lookup_missing_file(self, al):
        assert al._lookup_session_agent("nope") == ""

    def test_lookup_unknown_session(self, al):
        al._save_session_agent("known123", "recon-scanner")
        assert al._lookup_session_agent("other999") == ""

    def test_save_keeps_last_20(self, al, tmp_path):
        for i in range(30):
            al._save_session_agent(f"sid{i:05d}", f"agent{i}")
        lines = (tmp_path / ".session-agent-map").read_text().splitlines()
        assert len(lines) <= 20
        # most recent retained
        assert al._lookup_session_agent("sid00029") == "agent29"


# ---------------------------------------------------------------------------
# _rotate_if_needed
# ---------------------------------------------------------------------------
class TestRotation:
    def test_no_file_noop(self, al, tmp_path):
        al._rotate_if_needed(str(tmp_path / "missing.log"))  # no raise

    def test_small_file_not_rotated(self, al, tmp_path):
        f = tmp_path / "small.log"
        f.write_text("tiny")
        al._rotate_if_needed(str(f))
        assert f.exists()
        assert not (tmp_path / "small.log.1").exists()

    def test_large_file_rotates(self, al, tmp_path, monkeypatch):
        # Force a tiny max so a small file triggers rotation.
        monkeypatch.setattr(al, "_load_max_log_bytes", lambda: 10)
        f = tmp_path / "big.log"
        f.write_text("x" * 100)
        al._rotate_if_needed(str(f))
        assert (tmp_path / "big.log.1").exists()
        assert not f.exists()

    def test_rotation_shifts_existing_copies(self, al, tmp_path, monkeypatch):
        monkeypatch.setattr(al, "_load_max_log_bytes", lambda: 10)
        f = tmp_path / "r.log"
        f.write_text("x" * 100)
        (tmp_path / "r.log.1").write_text("old1")
        (tmp_path / "r.log.2").write_text("old2")
        al._rotate_if_needed(str(f))
        # .1 now holds the rotated current; .2 holds prior .1 content
        assert (tmp_path / "r.log.2").read_text() == "old1"


# ---------------------------------------------------------------------------
# _calc_cost
# ---------------------------------------------------------------------------
class TestCalcCost:
    def test_zero_usage(self, al):
        assert al._calc_cost({}) == 0.0

    def test_known_cost(self, al):
        # 1M input @ $3 + 1M output @ $15 = $18
        cost = al._calc_cost({"input_tokens": 1_000_000, "output_tokens": 1_000_000})
        assert abs(cost - 18.0) < 0.001


# ---------------------------------------------------------------------------
# _usage_from_transcript
# ---------------------------------------------------------------------------
class TestUsageFromTranscript:
    def test_missing_path(self, al):
        assert al._usage_from_transcript("") == {}
        assert al._usage_from_transcript("/no/such/file.jsonl") == {}

    def test_sums_assistant_usage(self, al, tmp_path):
        t = tmp_path / "transcript.jsonl"
        t.write_text(
            "\n".join(
                [
                    json.dumps({"message": {"role": "assistant", "usage": {"input_tokens": 100, "output_tokens": 10}}}),
                    json.dumps({"message": {"role": "assistant", "usage": {"input_tokens": 50, "output_tokens": 5}}}),
                    "not json line",
                    "",
                ]
            )
        )
        out = al._usage_from_transcript(str(t))
        assert out["input_tokens"] == 150
        assert out["output_tokens"] == 15

    def test_nested_usage_under_content(self, al, tmp_path):
        t = tmp_path / "t2.jsonl"
        t.write_text(json.dumps({"message": {"content": {"usage": {"input_tokens": 7, "output_tokens": 3}}}}) + "\n")
        out = al._usage_from_transcript(str(t))
        assert out["input_tokens"] == 7

    def test_no_usage_returns_empty(self, al, tmp_path):
        t = tmp_path / "t3.jsonl"
        t.write_text(json.dumps({"message": {"role": "user", "content": "hi"}}) + "\n")
        assert al._usage_from_transcript(str(t)) == {}


# ---------------------------------------------------------------------------
# _emit_substep_progress
# ---------------------------------------------------------------------------
class TestEmitSubstepProgress:
    def test_no_progress_event_noop(self, al, capsys):
        al._emit_substep_progress('echo "hello" >> ".agent-run.log"')
        assert capsys.readouterr().err == ""

    def test_phase_start_emits_arrow(self, al, capsys):
        cmd = 'echo "ts INFO threat-analyst PHASE_START [Phase 3/11] Architecture" >> ".agent-run.log"'
        al._emit_substep_progress(cmd)
        err = capsys.readouterr().err
        assert "▶" in err
        assert "Architecture" in err

    def test_phase_end_emits_check(self, al, capsys):
        cmd = 'echo "ts INFO threat-analyst PHASE_END [Phase 3/11] done" >> ".agent-run.log"'
        al._emit_substep_progress(cmd)
        assert "✓" in capsys.readouterr().err

    def test_agent_done_check(self, al, capsys):
        cmd = 'echo "ts INFO orch AGENT_DONE stride finished" >> ".agent-run.log"'
        al._emit_substep_progress(cmd)
        assert "✓" in capsys.readouterr().err

    def test_empty_message_noop(self, al, capsys):
        cmd = 'echo "PHASE_START" >> ".agent-run.log"'
        al._emit_substep_progress(cmd)
        # message after keyword is empty -> no emission
        assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# _should_emit_activity / _emit_activity
# ---------------------------------------------------------------------------
class TestActivityThrottle:
    def test_first_call_emits(self, al):
        assert al._should_emit_activity("sid111") is True

    def test_second_call_throttled(self, al):
        assert al._should_emit_activity("sid222") is True
        assert al._should_emit_activity("sid222") is False

    def test_emit_activity_no_agent_silent(self, al, capsys):
        # No session-agent mapping -> outermost session -> no activity line
        al._emit_activity("Read", {"file_path": "/x/y.py"}, "unmapped")
        assert capsys.readouterr().err == ""

    def test_emit_activity_with_agent(self, al, capsys):
        al._save_session_agent("sidA1234", "stride-analyzer")
        al._emit_activity("Read", {"file_path": "/repo/auth.py"}, "sidA1234")
        err = capsys.readouterr().err
        assert "stride-analyzer" in err
        assert "reading" in err
        assert "auth.py" in err

    def test_emit_activity_grep_hint(self, al, capsys):
        al._save_session_agent("sidB1234", "recon-scanner")
        al._emit_activity("Grep", {"pattern": "secret_token"}, "sidB1234")
        err = capsys.readouterr().err
        assert "searching" in err
        assert "secret_token" in err

    def test_emit_activity_bash_hint(self, al, capsys):
        al._save_session_agent("sidC1234", "dep-scanner")
        al._emit_activity("Bash", {"command": "npm audit"}, "sidC1234")
        err = capsys.readouterr().err
        assert "executing" in err
        assert "npm audit" in err


# ---------------------------------------------------------------------------
# _agent_params
# ---------------------------------------------------------------------------
class TestAgentParams:
    def test_extracts_known_keys(self, al):
        p = al._agent_params("REPO_ROOT=/r COMPONENT_ID=c MANIFESTS=pkg.json CONTEXT_FILE=ctx.md")
        assert p == {
            "REPO_ROOT": "/r",
            "COMPONENT_ID": "c",
            "MANIFESTS": "pkg.json",
            "CONTEXT_FILE": "ctx.md",
        }

    def test_empty_prompt(self, al):
        assert al._agent_params("") == {}


# ---------------------------------------------------------------------------
# _write_trace_summary
# ---------------------------------------------------------------------------
class TestWriteTraceSummary:
    def test_missing_trace_file_noop(self, al):
        al._write_trace_summary("sid")  # no raise, no file

    def test_no_completes_noop(self, al, tmp_path):
        trace = tmp_path / ".appsec-trace.log"
        trace.write_text("some unrelated line\n")
        al._write_trace_summary("sid")
        assert "ASSESSMENT_TRACE" not in trace.read_text()

    def test_builds_table_from_pairs(self, al, tmp_path):
        trace = tmp_path / ".appsec-trace.log"
        trace.write_text(
            "TRACE AGENT_DISPATCH agent=stride-analyzer model=sonnet context_ktok=12.3 max_turns=40\n"
            "TRACE AGENT_COMPLETE agent=stride-analyzer in=10,000 out=2,000 cost=$0.06 turns=20 wall_secs=125 stop=end_turn\n"
        )
        al._write_trace_summary("sid")
        out = trace.read_text()
        assert "ASSESSMENT_TRACE" in out
        assert "stride-analyzer" in out
        assert "2m05s" in out  # 125 seconds formatted


# ---------------------------------------------------------------------------
# _is_verbose / _is_tracing markers
# ---------------------------------------------------------------------------
class TestModeDetection:
    def test_verbose_marker_file(self, al, tmp_path, monkeypatch):
        monkeypatch.delenv("APPSEC_VERBOSE", raising=False)
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        uid = al.os.getuid() if hasattr(al.os, "getuid") else 0
        (tmp_path / f".appsec-verbose-{uid}").write_text("")
        assert al._is_verbose() is True

    def test_tracing_env(self, al, monkeypatch):
        monkeypatch.setenv("APPSEC_TRACING", "1")
        assert al._is_tracing() is True

    def test_tracing_marker_file(self, al, tmp_path, monkeypatch):
        monkeypatch.delenv("APPSEC_TRACING", raising=False)
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        uid = al.os.getuid() if hasattr(al.os, "getuid") else 0
        (tmp_path / f".appsec-tracing-{uid}").write_text("")
        assert al._is_tracing() is True

    def test_tracing_false_value(self, al, tmp_path, monkeypatch):
        monkeypatch.setenv("APPSEC_TRACING", "0")
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        assert al._is_tracing() is False


# ---------------------------------------------------------------------------
# _output_dir resolution branches
# ---------------------------------------------------------------------------
class TestOutputDir:
    def test_env_wins(self, al, monkeypatch):
        monkeypatch.setenv("OUTPUT_DIR", "/custom/out")
        assert al._output_dir() == "/custom/out"

    def test_cwd_already_in_docs_security(self, al, monkeypatch, tmp_path):
        monkeypatch.delenv("OUTPUT_DIR", raising=False)
        ds = tmp_path / "docs" / "security"
        ds.mkdir(parents=True)
        monkeypatch.chdir(ds)
        assert al._output_dir() == str(ds)

    def test_cwd_default_appends(self, al, monkeypatch, tmp_path):
        monkeypatch.delenv("OUTPUT_DIR", raising=False)
        monkeypatch.chdir(tmp_path)
        out = al._output_dir()
        assert out.endswith("docs/security") or out.endswith("docs\\security")


# ---------------------------------------------------------------------------
# PostToolUse handler branches — Read / Grep / Glob / MultiEdit / Bash OK
# Exercised directly via handle_post_tool_use against an OUTPUT_DIR log.
# ---------------------------------------------------------------------------
class TestPostToolBranches:
    def _read_log(self, tmp_path: Path) -> str:
        f = tmp_path / ".hook-events.log"
        return f.read_text() if f.exists() else ""

    def test_read_tool_logs_file_read(self, al, tmp_path):
        al.handle_post_tool_use(
            {"tool_name": "Read", "tool_input": {"file_path": "/repo/x.py"}, "tool_response": "ok"},
            "sid",
        )
        log = self._read_log(tmp_path)
        assert "FILE_READ" in log and "/repo/x.py" in log

    def test_read_tool_with_range(self, al, tmp_path):
        al.handle_post_tool_use(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/repo/x.py", "offset": 100, "limit": 50},
                "tool_response": "ok",
            },
            "sid",
        )
        log = self._read_log(tmp_path)
        assert "range=offset=100,limit=50" in log

    def test_grep_tool_logs_grep_run(self, al, tmp_path):
        al.handle_post_tool_use(
            {
                "tool_name": "Grep",
                "tool_input": {"pattern": "TODO", "path": "/repo"},
                "tool_response": "ok",
            },
            "sid",
        )
        log = self._read_log(tmp_path)
        assert "GREP_RUN" in log and "pattern=TODO" in log and "path=/repo" in log

    def test_grep_tool_with_glob_scope(self, al, tmp_path):
        al.handle_post_tool_use(
            {
                "tool_name": "Grep",
                "tool_input": {"pattern": "x", "glob": "*.ts"},
                "tool_response": "ok",
            },
            "sid",
        )
        assert "glob=*.ts" in self._read_log(tmp_path)

    def test_glob_tool_logs_glob_run(self, al, tmp_path):
        al.handle_post_tool_use(
            {
                "tool_name": "Glob",
                "tool_input": {"pattern": "**/*.py", "path": "/repo"},
                "tool_response": "ok",
            },
            "sid",
        )
        log = self._read_log(tmp_path)
        assert "GLOB_RUN" in log and "path=/repo" in log

    def test_multiedit_logs_file_edit(self, al, tmp_path):
        al.handle_post_tool_use(
            {
                "tool_name": "MultiEdit",
                "tool_input": {"file_path": "/repo/x.py", "edits": [{}, {}, {}]},
                "tool_response": "ok",
            },
            "sid",
        )
        log = self._read_log(tmp_path)
        assert "FILE_EDIT" in log and "multi_edits=3" in log

    def test_bash_ok_logged(self, al, tmp_path):
        al.handle_post_tool_use(
            {"tool_name": "Bash", "tool_input": {"command": "echo hi"}, "tool_response": "hi"},
            "sid",
        )
        assert "BASH_OK" in self._read_log(tmp_path)

    def test_bash_help_call_not_warned(self, al, tmp_path):
        al.handle_post_tool_use(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "tool.py --help"},
                "tool_response": "usage: tool.py [-h]",
            },
            "sid",
        )
        log = self._read_log(tmp_path)
        assert "BASH_WARN" not in log
        assert "BASH_OK" in log

    def test_bash_usage_triggers_warn(self, al, tmp_path):
        al.handle_post_tool_use(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "tool.py --bogus"},
                "tool_response": "usage: tool.py [-h]",
            },
            "sid",
        )
        assert "BASH_WARN" in self._read_log(tmp_path)

    def test_bash_agent_run_log_echo_suppressed(self, al, tmp_path, capsys):
        # Writes to .agent-run.log are not double-logged as BASH_OK.
        al.handle_post_tool_use(
            {
                "tool_name": "Bash",
                "tool_input": {
                    "command": 'echo "ts INFO threat-analyst PHASE_START [Phase 2/11] Recon" >> "$OUTPUT_DIR/.agent-run.log"'
                },
                "tool_response": "",
            },
            "sid",
        )
        log = self._read_log(tmp_path)
        assert "BASH_OK" not in log
        # PHASE_START mirrored into the hook log
        assert "PHASE_START" in log

    def test_tool_error_branch(self, al, tmp_path):
        al.handle_post_tool_use(
            {
                "tool_name": "Read",
                "tool_input": {"file_path": "/x"},
                "tool_response": "boom",
                "is_error": True,
            },
            "sid",
        )
        assert "TOOL_ERROR" in self._read_log(tmp_path)


# ---------------------------------------------------------------------------
# handle_stop — transcript usage + agent mirror + max_turns mirror
# ---------------------------------------------------------------------------
class TestHandleStop:
    def _read_log(self, tmp_path: Path) -> str:
        f = tmp_path / ".hook-events.log"
        return f.read_text() if f.exists() else ""

    def _agent_run(self, tmp_path: Path) -> str:
        f = tmp_path / ".agent-run.log"
        return f.read_text() if f.exists() else ""

    def test_transcript_usage_summed(self, al, tmp_path):
        t = tmp_path / "tr.jsonl"
        t.write_text(
            json.dumps({"message": {"role": "assistant", "usage": {"input_tokens": 999, "output_tokens": 11}}}) + "\n"
        )
        al.handle_stop({"stop_reason": "end_turn", "transcript_path": str(t)}, "sid12345", "SubagentStop")
        log = self._read_log(tmp_path)
        assert "in=999" in log and "out=11" in log

    def test_agent_mirror_on_stop(self, al, tmp_path):
        al._save_session_agent("sid98765", "stride-analyzer")
        (tmp_path / ".agent-run.log").write_text("seed\n")
        al.handle_stop({"stop_reason": "end_turn"}, "sid98765", "Stop")
        assert "SESSION_STOP" in self._agent_run(tmp_path)

    def test_subagentstop_suppresses_agent_run_mirror(self, al, tmp_path):
        al._save_session_agent("sidsub12", "recon-scanner")
        # .agent-run.log must exist for _write_agent_run to append
        (tmp_path / ".agent-run.log").write_text("seed\n")
        al.handle_stop({"stop_reason": "end_turn"}, "sidsub12", "SubagentStop")
        assert "SESSION_STOP" not in self._agent_run(tmp_path)

    def test_max_turns_mirrored_to_agent_run(self, al, tmp_path):
        al._save_session_agent("sidmt123", "stride-analyzer")
        (tmp_path / ".agent-run.log").write_text("seed\n")
        al.handle_stop({"stop_reason": "max_turns"}, "sidmt123", "Stop")
        ar = self._agent_run(tmp_path)
        assert "MAX_TURNS" in ar

    def test_payload_usage_fallback(self, al, tmp_path):
        al.handle_stop(
            {"stop_reason": "end_turn", "usage": {"input_tokens": 42, "output_tokens": 7}},
            "sidpay12",
            "Stop",
        )
        log = self._read_log(tmp_path)
        assert "in=42" in log
        assert "src=payload-last-turn" in log


# ---------------------------------------------------------------------------
# _write_assessment_summary — phase-duration + yaml threat counting paths
# ---------------------------------------------------------------------------
class TestAssessmentSummaryInternals:
    def test_phase_durations_emitted(self, al, tmp_path):
        # hook-events.log with a SCAN_START boundary + SESSION_STOP for tokens
        (tmp_path / ".hook-events.log").write_text(
            "2026-06-14T10:00:00Z  [sidmain1]  INFO   SCAN_START  repo=/r\n"
            "2026-06-14T10:05:00Z  [sidmain1]  INFO   SESSION_STOP  stop_reason=end_turn  in=1,000  out=100  cost=$0.01\n"
        )
        # agent-run.log with PHASE_START/PHASE_END pairs that yield real durations
        (tmp_path / ".agent-run.log").write_text(
            "2026-06-14T10:00:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START   mode=incremental\n"
            "2026-06-14T10:00:00Z  [--------]  INFO   threat-analyst  PHASE_START   [Phase 2/11] Recon\n"
            "2026-06-14T10:02:00Z  [--------]  INFO   threat-analyst  PHASE_END     [Phase 2/11] Recon complete\n"
        )
        al._write_assessment_summary("sidmain1")
        log = (tmp_path / ".hook-events.log").read_text()
        assert "ASSESSMENT_PHASES" in log
        assert "mode=incremental" in log
        assert "Phase 2/11" in log

    def test_idle_accounting_in_summary(self, al, tmp_path):
        (tmp_path / ".hook-events.log").write_text(
            "2026-06-14T10:00:00Z  [sididle1]  INFO   SCAN_START  repo=/r\n"
            "2026-06-14T10:10:00Z  [sididle1]  INFO   SESSION_STOP  stop_reason=end_turn  in=1,000  out=100  cost=$0.01\n"
        )
        (tmp_path / ".agent-run.log").write_text(
            "2026-06-14T10:00:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START   mode=full\n"
            "2026-06-14T10:05:00Z  [--------]  WARN   watchdog  RUN_IDLE   no run activity for 120s\n"
            "2026-06-14T10:06:00Z  [--------]  INFO   watchdog  RUN_RESUMED   resumed after 120s idle\n"
        )
        al._write_assessment_summary("sididle1")
        log = (tmp_path / ".hook-events.log").read_text()
        assert "idle≈" in log

    def test_yaml_threat_counting(self, al, tmp_path):
        (tmp_path / ".hook-events.log").write_text("2026-06-14T10:00:00Z  [sidyaml1]  INFO   SCAN_START  repo=/r\n")
        (tmp_path / "threat-model.yaml").write_text(
            "threats:\n"
            "  - id: T-001\n    severity: Critical\n"
            "  - id: T-002\n    severity: High\n"
            "  - id: T-003\n    severity: High\n"
        )
        al._write_assessment_summary("sidyaml1")
        log = (tmp_path / ".hook-events.log").read_text()
        assert "threats=3" in log
        assert "Critical=1" in log
        assert "High=2" in log

    def test_ghost_summary_suppressed_by_owner_sid(self, al, tmp_path):
        (tmp_path / ".hook-events.log").write_text("2026-06-14T10:00:00Z  [owner123]  INFO   SCAN_START  repo=/r\n")
        (tmp_path / ".assessment-owner-sid").write_text("owner123")
        # Different sid -> must bail without writing a summary
        al._write_assessment_summary("ghost999")
        log = (tmp_path / ".hook-events.log").read_text()
        assert "ASSESSMENT_SUMMARY" not in log

    def test_no_log_file_noop(self, al, tmp_path):
        # No hook-events.log present
        al._write_assessment_summary("sid")
        assert not (tmp_path / ".hook-events.log").exists()


# ---------------------------------------------------------------------------
# _write_agent_run — only appends when the file already exists
# ---------------------------------------------------------------------------
class TestWriteAgentRun:
    def test_no_append_when_missing(self, al, tmp_path):
        al._write_agent_run("INFO", "agent", "EVT", "detail")
        assert not (tmp_path / ".agent-run.log").exists()

    def test_appends_when_present(self, al, tmp_path):
        (tmp_path / ".agent-run.log").write_text("seed\n")
        al._write_agent_run("INFO", "stride", "EVT", "detail")
        assert "EVT" in (tmp_path / ".agent-run.log").read_text()


# ---------------------------------------------------------------------------
# Tracing-enabled paths — AGENT_DISPATCH at pre, AGENT_COMPLETE at stop
# ---------------------------------------------------------------------------
@pytest.fixture
def al_trace(tmp_path, monkeypatch):
    """Import agent_logger with tracing enabled (module-level _TRACING=True)."""
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("APPSEC_TRACING", "1")
    spec = importlib.util.spec_from_file_location("agent_logger_trace", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_logger_trace"] = module
    assert spec.loader is not None
    with contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
    return module


class TestTracingPaths:
    def test_write_trace_appends(self, al_trace, tmp_path):
        al_trace._write_trace("AGENT_DISPATCH", "agent=stride model=sonnet", "sid")
        assert (tmp_path / ".appsec-trace.log").exists()
        assert "AGENT_DISPATCH" in (tmp_path / ".appsec-trace.log").read_text()

    def test_pre_tool_emits_agent_dispatch(self, al_trace, tmp_path):
        al_trace.handle_pre_tool_use(
            {
                "tool_name": "Agent",
                "tool_input": {
                    "subagent_type": "appsec-advisor:appsec-stride-analyzer",
                    "description": "STRIDE",
                    "prompt": "REPO_ROOT=/r MAX_TURNS=40",
                },
            },
            "sidtrace1",
        )
        trace = (tmp_path / ".appsec-trace.log").read_text()
        assert "AGENT_DISPATCH" in trace
        assert "agent=stride-analyzer" in trace

    def test_stop_emits_agent_complete(self, al_trace, tmp_path):
        al_trace._save_session_agent("trace2ab", "stride-analyzer")
        t = tmp_path / "tr.jsonl"
        t.write_text(
            json.dumps({"message": {"role": "assistant", "usage": {"input_tokens": 100, "output_tokens": 5}}}) + "\n"
        )
        al_trace.handle_stop({"stop_reason": "end_turn", "transcript_path": str(t)}, "trace2ab", "SubagentStop")
        trace = (tmp_path / ".appsec-trace.log").read_text()
        assert "AGENT_COMPLETE" in trace
        assert "turns=1" in trace


# ---------------------------------------------------------------------------
# Phase-duration smear — batched same-second phases get a non-zero estimate
# ---------------------------------------------------------------------------
class TestPhaseSmear:
    def test_batched_zero_phases_smeared(self, al, tmp_path):
        (tmp_path / ".hook-events.log").write_text("2026-06-14T10:00:00Z  [sidsmear1]  INFO   SCAN_START  repo=/r\n")
        # Phases 5 and 6 start+end on the same second (batched -> 0s each),
        # Phase 7 starts 30s later providing the downstream anchor for the smear.
        (tmp_path / ".agent-run.log").write_text(
            "2026-06-14T10:00:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START   mode=full\n"
            "2026-06-14T10:01:00Z  [--------]  INFO   threat-analyst  PHASE_START   [Phase 5/11] A\n"
            "2026-06-14T10:01:00Z  [--------]  INFO   threat-analyst  PHASE_END     [Phase 5/11] A done\n"
            "2026-06-14T10:01:00Z  [--------]  INFO   threat-analyst  PHASE_START   [Phase 6/11] B\n"
            "2026-06-14T10:01:00Z  [--------]  INFO   threat-analyst  PHASE_END     [Phase 6/11] B done\n"
            "2026-06-14T10:01:30Z  [--------]  INFO   threat-analyst  PHASE_START   [Phase 7/11] C\n"
            "2026-06-14T10:02:00Z  [--------]  INFO   threat-analyst  PHASE_END     [Phase 7/11] C done\n"
        )
        al._write_assessment_summary("sidsmear1")
        log = (tmp_path / ".hook-events.log").read_text()
        phases_line = [l for l in log.splitlines() if "ASSESSMENT_PHASES" in l][-1]
        # The two batched phases must NOT both read 0s after the smear.
        assert "Phase 5/11" in phases_line and "Phase 6/11" in phases_line
        assert "=0s  Phase 6/11 B=0s" not in phases_line
