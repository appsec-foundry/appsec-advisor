"""Branch/error coverage for scripts/agent_logger.py.

Targets the error paths, config-driven branches, and handler edges that the
existing in-process suites (test_agent_logger_cov.py /
test_agent_logger_checkpoint_abort.py) leave uncovered. All tests run the
module in-process via an importlib spec with stdin/stderr neutralised, since
agent_logger.py calls main() at import time.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "agent_logger.py"


def _load(monkeypatch, tmp_path, *, env=None, name="agent_logger"):
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    for k, v in (env or {}).items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    with contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
    return module


@pytest.fixture
def al(tmp_path, monkeypatch):
    return _load(monkeypatch, tmp_path)


# ---------------------------------------------------------------------------
# _load_config / _load_pricing — plugin-root config branches
# ---------------------------------------------------------------------------
class TestConfigLoading:
    def test_loads_config_json(self, tmp_path, monkeypatch):
        plugin = tmp_path / "plugin"
        plugin.mkdir()
        (plugin / "config.json").write_text(
            json.dumps({"pricing": {"input_per_1m": 1.0, "output_per_1m": 2.0}, "logging": {"verbose": False}})
        )
        al = _load(monkeypatch, tmp_path, env={"CLAUDE_PLUGIN_ROOT": str(plugin)}, name="al_cfg")
        cfg = al._load_config()
        assert cfg["pricing"]["input_per_1m"] == 1.0
        # Pricing derived from config (line 111 branch).
        pricing = al._load_pricing()
        assert pricing["input"] == 1.0
        assert pricing["output"] == 2.0

    def test_local_overrides_base(self, tmp_path, monkeypatch):
        plugin = tmp_path / "plugin2"
        plugin.mkdir()
        (plugin / "config.json").write_text(json.dumps({"pricing": {"input_per_1m": 9.9}}))
        (plugin / "config.local.json").write_text(json.dumps({"pricing": {"input_per_1m": 0.5}}))
        al = _load(monkeypatch, tmp_path, env={"CLAUDE_PLUGIN_ROOT": str(plugin)}, name="al_cfg_local")
        assert al._load_pricing()["input"] == 0.5

    def test_bad_json_falls_back_to_empty(self, tmp_path, monkeypatch):
        plugin = tmp_path / "plugin3"
        plugin.mkdir()
        (plugin / "config.json").write_text("{not valid json")
        al = _load(monkeypatch, tmp_path, env={"CLAUDE_PLUGIN_ROOT": str(plugin)}, name="al_cfg_bad")
        assert al._load_config() == {}
        # Pricing falls back to defaults.
        assert al._load_pricing()["input"] == 3.00


# ---------------------------------------------------------------------------
# _is_verbose / _is_tracing env-truthy + getuid AttributeError fallback
# ---------------------------------------------------------------------------
class TestModeDetectionBranches:
    def test_verbose_env_truthy(self, al, monkeypatch):
        monkeypatch.setenv("APPSEC_VERBOSE", "1")
        assert al._is_verbose() is True

    def test_verbose_config_true(self, tmp_path, monkeypatch):
        plugin = tmp_path / "pv"
        plugin.mkdir()
        (plugin / "config.json").write_text(json.dumps({"logging": {"verbose": True}}))
        al = _load(
            monkeypatch, tmp_path, env={"CLAUDE_PLUGIN_ROOT": str(plugin), "APPSEC_VERBOSE": None}, name="al_verbose_cfg"
        )
        assert al._is_verbose() is True

    def test_verbose_getuid_attribute_error(self, al, monkeypatch, tmp_path):
        monkeypatch.delenv("APPSEC_VERBOSE", raising=False)
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        monkeypatch.delattr(al.os, "getuid", raising=False)
        # uid falls back to 0; no marker file -> False
        assert al._is_verbose() is False

    def test_tracing_getuid_attribute_error(self, al, monkeypatch, tmp_path):
        monkeypatch.delenv("APPSEC_TRACING", raising=False)
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        monkeypatch.delattr(al.os, "getuid", raising=False)
        (tmp_path / ".appsec-tracing-0").write_text("")
        assert al._is_tracing() is True


# ---------------------------------------------------------------------------
# _agent_model branches
# ---------------------------------------------------------------------------
class TestAgentModel:
    def test_override_wins(self, al):
        assert al._agent_model("appsec-stride-analyzer", {"model": "opus"}) == "opus"

    def test_reads_frontmatter(self, tmp_path, monkeypatch):
        plugin = tmp_path / "p"
        (plugin / "agents").mkdir(parents=True)
        (plugin / "agents" / "appsec-stride-analyzer.md").write_text("---\nmodel: sonnet\n---\nbody\n")
        al = _load(monkeypatch, tmp_path, env={"CLAUDE_PLUGIN_ROOT": str(plugin)}, name="al_model")
        assert al._agent_model("appsec-advisor:appsec-stride-analyzer", {}) == "sonnet"

    def test_missing_file_returns_question(self, tmp_path, monkeypatch):
        plugin = tmp_path / "p2"
        (plugin / "agents").mkdir(parents=True)
        al = _load(monkeypatch, tmp_path, env={"CLAUDE_PLUGIN_ROOT": str(plugin)}, name="al_model2")
        assert al._agent_model("nope", {}) == "?"

    def test_no_plugin_root_returns_question(self, al, monkeypatch):
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        assert al._agent_model("x", {}) == "?"


# ---------------------------------------------------------------------------
# _mask_secrets — 3-group (jdbc) redaction path
# ---------------------------------------------------------------------------
class TestMaskSecrets:
    def test_jdbc_password_masked(self, al):
        out = al._mask_secrets("jdbc:mysql://user:supersecretpw@host:3306/db")
        assert "supersecretpw" not in out
        assert "supe****" in out

    def test_jdbc_short_password_masked(self, al):
        out = al._mask_secrets("jdbc:mysql://u:ab@host")
        assert "****" in out

    def test_bearer_token_masked(self, al):
        out = al._mask_secrets("Authorization: Bearer abcdefgh12345")
        assert "abcdefgh12345" not in out


# ---------------------------------------------------------------------------
# _redact_path — hashlib failure fallback
# ---------------------------------------------------------------------------
class TestRedactPathFallback:
    def test_hashlib_failure_uses_placeholder(self, al, monkeypatch):
        import hashlib as _h

        monkeypatch.setattr(_h, "sha256", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        out = al._redact_path("/a/b/secret.txt")
        assert "????????" in out


# ---------------------------------------------------------------------------
# _write / _write_trace / rotation / _write_agent_run error paths
# ---------------------------------------------------------------------------
class TestWriteErrorPaths:
    def test_write_oserror_swallowed(self, al, monkeypatch):
        monkeypatch.setattr(al, "_log_path", lambda: (_ for _ in ()).throw(OSError("nope")))
        al._write("INFO ", "EVT", "detail", "sid")  # no raise

    def test_write_stderr_oserror_swallowed(self, al, monkeypatch):
        # force_mirror path (high-signal event) + stderr.write fails
        monkeypatch.setattr(sys.stderr, "write", lambda *a, **k: (_ for _ in ()).throw(OSError("pipe")))
        al._write("INFO ", "SCAN_START", "detail", "sid")  # no raise

    def test_write_trace_skips_when_not_tracing(self, al):
        # _TRACING is False in the default fixture -> early return, no file.
        al._write_trace("EVT", "d", "sid")
        assert not (Path(al._output_dir()) / ".appsec-trace.log").exists()

    def test_rotation_exception_swallowed(self, al, monkeypatch):
        monkeypatch.setattr(al.os.path, "getsize", lambda p: (_ for _ in ()).throw(OSError("boom")))
        f = Path(al._output_dir()) / "x.log"
        f.write_text("data")
        al._rotate_if_needed(str(f))  # no raise

    def test_write_agent_run_exception_swallowed(self, al, tmp_path, monkeypatch):
        (tmp_path / ".agent-run.log").write_text("seed\n")
        monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError("ro")))
        al._write_agent_run("INFO", "agent", "EVT", "d")  # no raise


# ---------------------------------------------------------------------------
# _save_session_agent / _lookup_session_agent error paths
# ---------------------------------------------------------------------------
class TestSessionMapErrors:
    def test_save_cleanup_on_replace_failure(self, al, monkeypatch, tmp_path):
        # os.replace fails -> tmp file cleanup branch + outer swallow.
        monkeypatch.setattr(al.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
        al._save_session_agent("sid12345", "agent")  # no raise
        # No stray temp files left in the dir.
        leftovers = list(tmp_path.glob(".session-map-tmp-*"))
        assert leftovers == []

    def test_lookup_exception_returns_empty(self, al, monkeypatch):
        monkeypatch.setattr(al, "_session_map_path", lambda: (_ for _ in ()).throw(OSError("x")))
        assert al._lookup_session_agent("sid") == ""


# ---------------------------------------------------------------------------
# _record_tool_start / _record_tool_end outer exception
# ---------------------------------------------------------------------------
class TestRecordToolExceptions:
    def test_record_start_outer_exception(self, al, monkeypatch):
        monkeypatch.setattr(al, "_active_tools_dir", lambda: (_ for _ in ()).throw(OSError("x")))
        al._record_tool_start({"tool_use_id": "abc", "tool_name": "Bash"}, "sid")  # no raise

    def test_record_end_outer_exception(self, al, monkeypatch):
        monkeypatch.setattr(al, "_active_tool_path", lambda *a: (_ for _ in ()).throw(OSError("x")))
        assert al._record_tool_end({"tool_use_id": "abc"}) == 0


# ---------------------------------------------------------------------------
# _mark_checkpoint_aborted_if_dirty — atomic-write fallback to direct write
# ---------------------------------------------------------------------------
class TestCheckpointAbortFallback:
    def test_atomic_write_failure_falls_back_to_direct(self, al, tmp_path, monkeypatch):
        cp = tmp_path / ".appsec-checkpoint"
        cp.write_text("phase=5 status=started\n")
        # Make the deferred atomic_write_text import raise so the fallback
        # direct-write branch executes.
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **k):
            if name == "_atomic_io":
                raise ImportError("no atomic io")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        al._mark_checkpoint_aborted_if_dirty("error")
        assert "status=aborted" in cp.read_text()


# ---------------------------------------------------------------------------
# _usage_from_transcript — malformed lines + nested delta + outer exception
# ---------------------------------------------------------------------------
class TestUsageTranscriptBranches:
    def test_invalid_json_line_skipped(self, al, tmp_path):
        t = tmp_path / "t.jsonl"
        t.write_text("{bad json\n" + json.dumps({"message": {"usage": {"input_tokens": 5}}}) + "\n")
        out = al._usage_from_transcript(str(t))
        assert out["input_tokens"] == 5

    def test_usage_under_delta(self, al, tmp_path):
        t = tmp_path / "t2.jsonl"
        t.write_text(json.dumps({"message": {"delta": {"usage": {"output_tokens": 9}}}}) + "\n")
        out = al._usage_from_transcript(str(t))
        assert out["output_tokens"] == 9

    def test_outer_exception_returns_empty(self, al, monkeypatch, tmp_path):
        t = tmp_path / "t3.jsonl"
        t.write_text("{}\n")
        monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
        assert al._usage_from_transcript(str(t)) == {}


# ---------------------------------------------------------------------------
# handle_stop — cache fields, no-usage, max_turns, checkpoint mark on empty agent
# ---------------------------------------------------------------------------
class TestHandleStopBranches:
    def _log(self, al):
        f = Path(al._output_dir()) / ".hook-events.log"
        return f.read_text() if f.exists() else ""

    def test_cache_fields_emitted(self, al, tmp_path):
        al.handle_stop(
            {
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 2,
                    "cache_creation_input_tokens": 3,
                    "cache_read_input_tokens": 4,
                },
            },
            "sid",
            "Stop",
        )
        log = self._log(al)
        assert "cache_write=3" in log
        assert "cache_read=4" in log

    def test_no_usage_data(self, al):
        al.handle_stop({"stop_reason": "end_turn"}, "sid", "SubagentStop")
        assert "cost=n/a" in self._log(al)

    def test_max_turns_emits_max_turns_event(self, al):
        al.handle_stop({"stop_reason": "max_turns"}, "sid", "Stop")
        log = self._log(al)
        assert "MAX_TURNS" in log

    def test_analyst_marks_checkpoint_aborted(self, al, tmp_path):
        al._save_session_agent("sidanaly", "threat-analyst")
        (tmp_path / ".agent-run.log").write_text("seed\n")
        cp = tmp_path / ".appsec-checkpoint"
        cp.write_text("phase=3 status=started\n")
        # threat-analyst owner + unclean stop -> checkpoint stamped aborted.
        al.handle_stop({"stop_reason": "error"}, "sidanaly", "Stop")
        assert "status=aborted" in cp.read_text()

    def test_stop_sentinel_claimed_runs_summary_once(self, al, tmp_path):
        (tmp_path / ".hook-events.log").write_text(
            "2026-06-14T10:00:00Z  [sidone12]  INFO   SCAN_START  repo=/r\n"
        )
        al.handle_stop({"stop_reason": "end_turn"}, "sidone12", "Stop")
        assert (tmp_path / ".assessment-summary-emitted").exists()
        # Second Stop with same sentinel present -> FileExistsError branch, no crash.
        al.handle_stop({"stop_reason": "end_turn"}, "sidone12", "Stop")


# ---------------------------------------------------------------------------
# handle_post_tool_use — Agent / Write+CONTEXT_READY / Edit / watchdog
# ---------------------------------------------------------------------------
class TestPostToolAgentBranches:
    def _log(self, al):
        f = Path(al._output_dir()) / ".hook-events.log"
        return f.read_text() if f.exists() else ""

    def test_agent_invoke_non_analyst(self, al):
        al.handle_post_tool_use(
            {
                "tool_name": "Agent",
                "tool_input": {"subagent_type": "appsec-recon-scanner", "description": "recon"},
                "tool_response": "",
            },
            "sid",
        )
        assert "AGENT_INVOKE" in self._log(al)

    def test_agent_scan_complete_for_analyst(self, al):
        al.handle_post_tool_use(
            {
                "tool_name": "Agent",
                "tool_input": {
                    "subagent_type": "appsec-threat-analyst",
                    "description": "scan",
                    "prompt": "REPO_ROOT=/repo",
                },
                "tool_response": "",
            },
            "sid",
        )
        log = self._log(al)
        assert "SCAN_COMPLETE" in log
        assert "repo=/repo" in log

    def test_write_emits_context_ready(self, al):
        al.handle_post_tool_use(
            {
                "tool_name": "Write",
                "tool_input": {"file_path": "/out/.threat-modeling-context.md", "content": "x" * 50},
                "tool_response": "",
            },
            "sid",
        )
        log = self._log(al)
        assert "FILE_WRITE" in log
        assert "CONTEXT_READY" in log

    def test_edit_with_replace_all(self, al):
        al.handle_post_tool_use(
            {
                "tool_name": "Edit",
                "tool_input": {"file_path": "/f", "old_string": "a", "new_string": "abc", "replace_all": True},
                "tool_response": "",
            },
            "sid",
        )
        log = self._log(al)
        assert "FILE_EDIT" in log
        assert "replace_all" in log

    def test_watchdog_crossing_logged(self, al, monkeypatch):
        # Force a budget crossing so the WARN event is written (lines 2130-2131).
        import budget_watchdog

        monkeypatch.setattr(
            budget_watchdog, "tally_and_check", lambda *a, **k: {"event": "BUDGET_WARN", "agent": "x"}
        )
        monkeypatch.setattr(budget_watchdog, "format_detail", lambda c: "detail")
        al.handle_post_tool_use(
            {"tool_name": "Read", "tool_input": {"file_path": "/f"}, "tool_response": "ok"}, "sid"
        )
        assert "BUDGET_WARN" in self._log(al)


# ---------------------------------------------------------------------------
# handle_pre_tool_use — OUTPUT_DIR recovery, direct-write guard, verbose activity
# ---------------------------------------------------------------------------
class TestPreToolUseBranches:
    def test_output_dir_recovery_from_prompt(self, al, monkeypatch, tmp_path):
        monkeypatch.delenv("OUTPUT_DIR", raising=False)
        recovered = tmp_path / "recovered"
        al.handle_pre_tool_use(
            {
                "tool_name": "Agent",
                "tool_input": {
                    "subagent_type": "appsec-recon-scanner",
                    "description": "d",
                    "prompt": f"OUTPUT_DIR={recovered}",
                },
            },
            "sid",
        )
        assert al.os.environ.get("OUTPUT_DIR") == str(recovered)

    def test_direct_write_guard_denies_threat_model_md(self, al, capsys):
        al.handle_pre_tool_use(
            {"tool_name": "Write", "tool_input": {"file_path": "/out/threat-model.md"}},
            "sid",
        )
        out = capsys.readouterr().out
        assert "permissionDecision" in out
        assert "deny" in out

    def test_non_agent_verbose_activity(self, tmp_path, monkeypatch):
        al = _load(monkeypatch, tmp_path, env={"APPSEC_VERBOSE": "1"}, name="al_pre_verbose")
        al._save_session_agent("sidv1234", "stride-analyzer")
        al.handle_pre_tool_use(
            {"tool_name": "Read", "tool_input": {"file_path": "/repo/a.py"}}, "sidv1234"
        )  # exercises _emit_activity path; no assertion needed beyond no-raise

    def test_threat_analyst_spawn_emits_scan_start(self, al, tmp_path):
        al.handle_pre_tool_use(
            {
                "tool_name": "Agent",
                "tool_input": {
                    "subagent_type": "appsec-threat-analyst",
                    "description": "scan",
                    "prompt": "REPO_ROOT=/repo",
                },
            },
            "sidanalyst",
        )
        log = (tmp_path / ".hook-events.log").read_text()
        assert "SCAN_START" in log
        assert "AGENT_SPAWN" in log
        # owner-sid recorded
        assert (tmp_path / ".assessment-owner-sid").exists()


# ---------------------------------------------------------------------------
# _emit_activity hint branches (Write/Edit) + stderr exception
# ---------------------------------------------------------------------------
class TestEmitActivityHints:
    def test_write_hint(self, tmp_path, monkeypatch, capsys):
        al = _load(monkeypatch, tmp_path, env={"APPSEC_VERBOSE": "1"}, name="al_emit_w")
        al._save_session_agent("sidw1234", "stride-analyzer")
        al._emit_activity("Write", {"file_path": "/repo/out.md"}, "sidw1234")
        assert "writing" in capsys.readouterr().err

    def test_stderr_exception_swallowed(self, tmp_path, monkeypatch):
        al = _load(monkeypatch, tmp_path, env={"APPSEC_VERBOSE": "1"}, name="al_emit_err")
        al._save_session_agent("side1234", "recon-scanner")
        monkeypatch.setattr(sys.stderr, "write", lambda *a, **k: (_ for _ in ()).throw(OSError("pipe")))
        al._emit_activity("Read", {"file_path": "/r/x"}, "side1234")  # no raise


# ---------------------------------------------------------------------------
# _emit_substep_progress stderr exception + info prefix
# ---------------------------------------------------------------------------
class TestSubstepProgress:
    def test_info_prefix_dot(self, al, capsys):
        # ASSESSMENT_END is not in start/end lists? It IS end. Use AGENT_DISPATCH
        # (▶). For the · branch we need an event not matched by either list but
        # still matched by _PROGRESS_EVENTS — there is none, so verify the
        # dispatch ▶ branch instead which covers _emit_substep_progress fully.
        al._emit_substep_progress('echo "x AGENT_DISPATCH stride dispatched" >> ".agent-run.log"')
        assert "▶" in capsys.readouterr().err

    def test_stderr_exception_swallowed(self, al, monkeypatch):
        monkeypatch.setattr(sys.stderr, "write", lambda *a, **k: (_ for _ in ()).throw(OSError("pipe")))
        al._emit_substep_progress('echo "x PHASE_START [Phase 1/2] go" >> ".agent-run.log"')  # no raise


# ---------------------------------------------------------------------------
# _mirror_phase_events_to_hook_log — no match + empty detail
# ---------------------------------------------------------------------------
class TestMirrorPhaseEvents:
    def test_no_phase_boundary_noop(self, al):
        al._mirror_phase_events_to_hook_log('echo "STEP_START something" >> ".agent-run.log"', "sid")
        log_file = Path(al._output_dir()) / ".hook-events.log"
        # No PHASE event written.
        assert not log_file.exists() or "PHASE_START" not in log_file.read_text()

    def test_empty_detail_noop(self, al):
        al._mirror_phase_events_to_hook_log('echo "PHASE_START" >> ".agent-run.log"', "sid")
        log_file = Path(al._output_dir()) / ".hook-events.log"
        assert not log_file.exists() or "PHASE_START" not in log_file.read_text()

    def test_refresh_snapshot_exception_swallowed(self, al, monkeypatch):
        # Make the deferred log_event import raise inside _refresh_progress_snapshot.
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **k):
            if name == "log_event":
                raise ImportError("no")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        al._refresh_progress_snapshot("PHASE_START", "[Phase 1/2] go", "sid")  # no raise


# ---------------------------------------------------------------------------
# main() routing — invalid stdin JSON + event dispatch
# ---------------------------------------------------------------------------
class TestMainRouting:
    def test_invalid_stdin_json(self, al, monkeypatch):
        monkeypatch.setattr(sys, "stdin", io.StringIO("{not json"))
        al.main()  # no raise, returns None

    def test_routes_pretooluse(self, al, monkeypatch, tmp_path):
        payload = json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "session_id": "sidmain",
                "tool_name": "Agent",
                "tool_input": {"subagent_type": "appsec-recon-scanner", "description": "d"},
            }
        )
        monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
        al.main()
        assert "AGENT_SPAWN" in (tmp_path / ".hook-events.log").read_text()

    def test_routes_stop(self, al, monkeypatch, tmp_path):
        payload = json.dumps({"hook_event_name": "Stop", "session_id": "s", "stop_reason": "end_turn"})
        monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
        al.main()
        assert "SESSION_STOP" in (tmp_path / ".hook-events.log").read_text()

    def test_routes_posttooluse_default(self, al, monkeypatch, tmp_path):
        payload = json.dumps(
            {
                "hook_event_name": "PostToolUse",
                "session_id": "s",
                "tool_name": "Read",
                "tool_input": {"file_path": "/x"},
                "tool_response": "ok",
            }
        )
        monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
        al.main()
        assert "FILE_READ" in (tmp_path / ".hook-events.log").read_text()


# ---------------------------------------------------------------------------
# _write_assessment_summary — dry-run mode, md-heuristic, files, owner-read err
# ---------------------------------------------------------------------------
class TestAssessmentSummaryExtra:
    def test_dry_run_mode_and_md_heuristic(self, al, tmp_path):
        (tmp_path / ".hook-events.log").write_text(
            "2026-06-14T10:00:00Z  [siddry12]  INFO   SCAN_START  repo=/r\n"
            "2026-06-14T10:01:00Z  [siddry12]  INFO   FILE_WRITE  "
            f"{tmp_path}/threat-model.md  (10 chars)\n"
            "2026-06-14T10:02:00Z  [siddry12]  INFO   AGENT_SPAWN  appsec-advisor:appsec-stride-analyzer  model=sonnet\n"
            "2026-06-14T10:05:00Z  [siddry12]  INFO   SESSION_STOP  stop_reason=end_turn  in=1,000  out=100  cache_write=5  cache_read=2  cost=$0.01\n"
        )
        (tmp_path / ".agent-run.log").write_text(
            "2026-06-14T10:00:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START   mode=dry-run\n"
        )
        # No yaml -> md heuristic fallback. Emoji-badge table rows.
        (tmp_path / "threat-model.md").write_text(
            "| 🔴 Critical | T-001 | foo |\n| 🟠 High | T-002 | bar |\n"
        )
        al._write_assessment_summary("siddry12")
        log = (tmp_path / ".hook-events.log").read_text()
        assert "mode=dry-run" in log
        assert "ASSESSMENT_MODELS" in log
        assert "stride-analyzer=sonnet" in log
        # ASSESSMENT_FILES emitted for the FILE_WRITE path.
        assert "ASSESSMENT_FILES" in log

    def test_owner_read_exception_continues(self, al, tmp_path, monkeypatch):
        (tmp_path / ".hook-events.log").write_text(
            "2026-06-14T10:00:00Z  [sidown12]  INFO   SCAN_START  repo=/r\n"
        )
        owner = tmp_path / ".assessment-owner-sid"
        owner.write_text("sidown12")
        # Make reading the owner file raise -> except branch (lines 869-870),
        # then proceeds to write the summary.
        real_open = open

        def flaky(path, *a, **k):
            if str(path).endswith(".assessment-owner-sid"):
                raise OSError("x")
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", flaky)
        al._write_assessment_summary("sidown12")
