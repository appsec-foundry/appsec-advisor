"""
Tests for plugin/scripts/agent_logger.py

The logger reads a hook event JSON from stdin and appends a line to
docs/security/.agent-run.log in the current working directory.
We run it as a subprocess and inspect both exit code and log output.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "plugin" / "scripts" / "agent_logger.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_logger(event: dict, cwd: Path) -> tuple[int, str]:
    """Run the logger with the given event dict. Returns (returncode, log_content)."""
    log_dir = cwd / "docs" / "security"
    log_file = log_dir / ".agent-run.log"

    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )
    content = log_file.read_text() if log_file.exists() else ""
    return result.returncode, content


def last_line(log: str) -> str:
    lines = [l for l in log.splitlines() if l.strip()]
    return lines[-1] if lines else ""


def make_post_tool_event(tool: str, inp: dict, resp: str = "", is_error: bool = False,
                         session_id: str = "testsid1") -> dict:
    return {
        "hook_event_name": "PostToolUse",
        "session_id": session_id,
        "tool_name": tool,
        "tool_input": inp,
        "tool_response": resp,
        "is_error": is_error,
    }


# ===========================================================================
# PostToolUse — Agent tool
# ===========================================================================

class TestAgentInvoke:
    def test_stride_analyzer_logs_agent_invoke(self, tmp_path):
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-stride-analyzer",
            "description": "STRIDE analysis for REST API",
            "prompt": "COMPONENT_ID=rest-api REPO_ROOT=/tmp/repo",
            "run_in_background": True,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "AGENT_INVOKE" in log
        assert "appsec-stride-analyzer" in log

    def test_background_flag_annotated(self, tmp_path):
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-dep-scanner",
            "description": "Scan dependencies",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": True,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "[bg]" in log

    def test_foreground_agent_no_bg_tag(self, tmp_path):
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-qa-reviewer",
            "description": "QA review",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        line = last_line(log)
        assert "[bg]" not in line

    def test_threat_analyst_logs_scan_start(self, tmp_path):
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-threat-analyst",
            "description": "Threat Model Orchestrator",
            "prompt": "FORCE_FULL=false REPO_ROOT=/tmp/repo",
            "run_in_background": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "SCAN_START" in log
        assert "INCREMENTAL" in log

    def test_threat_analyst_full_mode(self, tmp_path):
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-threat-analyst",
            "description": "Threat Model Orchestrator",
            "prompt": "FORCE_FULL=true REPO_ROOT=/tmp/repo",
            "run_in_background": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert "SCAN_START" in log
        assert "FULL" in log

    def test_component_id_extracted_from_prompt(self, tmp_path):
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-stride-analyzer",
            "description": "STRIDE analysis",
            "prompt": "COMPONENT_ID=auth-service REPO_ROOT=/tmp/repo CONTEXT_FILE=docs/security/threat-modeling-context.md",
            "run_in_background": True,
        })
        rc, log = run_logger(event, tmp_path)
        assert "auth-service" in log


# ===========================================================================
# PostToolUse — Write tool
# ===========================================================================

class TestFileWrite:
    def test_write_tool_logs_file_write(self, tmp_path):
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/repo/docs/security/threat-model.md",
            "content": "x" * 500,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "FILE_WRITE" in log
        assert "threat-model.md" in log

    def test_write_tool_logs_char_count(self, tmp_path):
        content = "a" * 1234
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/repo/out.md",
            "content": content,
        })
        rc, log = run_logger(event, tmp_path)
        assert "1,234" in log


# ===========================================================================
# PostToolUse — Bash tool
# ===========================================================================

class TestBashWarn:
    @pytest.mark.parametrize("error_text", [
        "permission denied",
        "No such file or directory",
        "command not found",
        "exit status 1",
        "Traceback",
        "SyntaxError",
    ])
    def test_bash_error_keywords_produce_warn(self, tmp_path, error_text):
        event = make_post_tool_event("Bash",
            inp={"command": "cat /etc/shadow"},
            resp=f"cat: /etc/shadow: {error_text}",
        )
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "BASH_WARN" in log

    def test_bash_clean_output_not_logged(self, tmp_path):
        event = make_post_tool_event("Bash",
            inp={"command": "echo hello"},
            resp="hello",
        )
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "BASH_WARN" not in log
        assert "FILE_WRITE" not in log


# ===========================================================================
# PostToolUse — is_error flag
# ===========================================================================

class TestToolError:
    def test_is_error_true_logs_tool_error(self, tmp_path):
        event = make_post_tool_event("Read",
            inp={"file_path": "/nonexistent"},
            resp="File not found",
            is_error=True,
        )
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "TOOL_ERROR" in log
        assert "ERROR" in log

    def test_is_error_takes_priority_over_bash_warn(self, tmp_path):
        """When is_error=True on a Bash call, TOOL_ERROR is logged, not BASH_WARN."""
        event = make_post_tool_event("Bash",
            inp={"command": "cat /etc/shadow"},
            resp="permission denied",
            is_error=True,
        )
        rc, log = run_logger(event, tmp_path)
        assert "TOOL_ERROR" in log
        assert "BASH_WARN" not in log


# ===========================================================================
# Stop event
# ===========================================================================

class TestStopEvent:
    def test_end_turn_logs_info(self, tmp_path):
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
        }
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "SESSION_STOP" in log
        assert "end_turn" in log

    def test_max_turns_logs_error_level(self, tmp_path):
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "max_turns",
        }
        rc, log = run_logger(event, tmp_path)
        assert "SESSION_STOP" in log
        assert "ERROR" in log

    def test_subagentstop_treated_as_stop(self, tmp_path):
        event = {
            "hook_event_name": "SubagentStop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
        }
        rc, log = run_logger(event, tmp_path)
        assert "SESSION_STOP" in log


# ===========================================================================
# Robustness
# ===========================================================================

class TestRobustness:
    def test_malformed_json_stdin_does_not_crash(self, tmp_path):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input="this is not json {{{",
            capture_output=True, text=True,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0

    def test_empty_stdin_does_not_crash(self, tmp_path):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input="",
            capture_output=True, text=True,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0

    def test_log_directory_created_automatically(self, tmp_path):
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/out.md",
            "content": "hello",
        })
        # docs/security/ does NOT exist yet in tmp_path
        assert not (tmp_path / "docs").exists()
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert (tmp_path / "docs" / "security" / ".agent-run.log").exists()

    def test_multiple_events_appended_to_same_log(self, tmp_path):
        for i in range(3):
            event = make_post_tool_event("Write", {
                "file_path": f"/tmp/out{i}.md",
                "content": "data",
            }, session_id=f"session{i}")
            run_logger(event, tmp_path)

        log = (tmp_path / "docs" / "security" / ".agent-run.log").read_text()
        assert log.count("FILE_WRITE") == 3

    def test_session_id_truncated_to_8_chars(self, tmp_path):
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/x.md",
            "content": "y",
        }, session_id="abcdefghijklmnop")
        rc, log = run_logger(event, tmp_path)
        # session id in log must be at most 8 chars
        line = last_line(log)
        # Format: "<ts>  [<sid8>]  ..."
        import re
        m = re.search(r'\[([^\]]+)\]', line)
        assert m and len(m.group(1).strip()) <= 8

    def test_unknown_tool_does_not_crash(self, tmp_path):
        event = make_post_tool_event("UnknownTool", {"x": 1})
        rc, log = run_logger(event, tmp_path)
        assert rc == 0

    def test_log_line_format_has_timestamp_and_level(self, tmp_path):
        event = make_post_tool_event("Write", {"file_path": "/x", "content": "y"})
        rc, log = run_logger(event, tmp_path)
        line = last_line(log)
        # Must start with an ISO timestamp
        import re
        assert re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', line), (
            f"Log line missing ISO timestamp: {line!r}"
        )
