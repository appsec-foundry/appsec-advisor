"""
Tests for plugin/scripts/agent_logger.py

The logger reads a hook event JSON from stdin and appends a line to
docs/security/.hook-events.log in the current working directory.
We run it as a subprocess and inspect both exit code and log output.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "plugin" / "scripts" / "agent_logger.py"
PLUGIN_ROOT = Path(__file__).parent.parent / "plugin"

# Import internals for direct unit testing
PLUGIN_SCRIPTS = Path(__file__).parent.parent / "plugin" / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))
from agent_logger import _mask_secrets, _clip, _extract_param, _agent_model  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_logger(event: dict, cwd: Path, plugin_root: Path = PLUGIN_ROOT) -> tuple[int, str]:
    """Run the logger with the given event dict. Returns (returncode, log_content)."""
    log_dir = cwd / "docs" / "security"
    log_file = log_dir / ".hook-events.log"

    env = os.environ.copy()
    env["CLAUDE_PLUGIN_ROOT"] = str(plugin_root)

    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=env,
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


def make_pre_tool_event(tool: str, inp: dict, session_id: str = "testsid1") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": session_id,
        "tool_name": tool,
        "tool_input": inp,
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
        """SCAN_START is emitted at PreToolUse for the orchestrator dispatch."""
        event = make_pre_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-threat-analyst",
            "description": "Threat Model Orchestrator",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "SCAN_START" in log
        assert "/tmp/repo" in log

    def test_component_id_extracted_from_prompt(self, tmp_path):
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-stride-analyzer",
            "description": "STRIDE analysis",
            "prompt": "COMPONENT_ID=auth-service REPO_ROOT=/tmp/repo CONTEXT_FILE=docs/security/.threat-modeling-context.md",
            "run_in_background": True,
        })
        rc, log = run_logger(event, tmp_path)
        assert "auth-service" in log

    def test_model_from_agent_definition_logged(self, tmp_path):
        """AGENT_INVOKE must include model= read from the agent frontmatter file."""
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-qa-reviewer",
            "description": "QA review",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "model=sonnet" in log

    def test_model_override_in_tool_input_takes_priority(self, tmp_path):
        """Explicit model= in tool_input overrides the frontmatter default."""
        event = make_post_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-qa-reviewer",
            "description": "QA review with opus override",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": False,
            "model": "opus",
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "model=opus" in log

    def test_scan_start_includes_model(self, tmp_path):
        """SCAN_START must include model= for the orchestrator."""
        event = make_pre_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-threat-analyst",
            "description": "Threat Model Orchestrator",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "SCAN_START" in log
        assert "model=sonnet" in log


# ===========================================================================
# PreToolUse — AGENT_SPAWN
# ===========================================================================

class TestAgentSpawn:
    def test_pre_tool_use_agent_logs_agent_spawn(self, tmp_path):
        """PreToolUse for Agent tool must produce an AGENT_SPAWN entry."""
        event = make_pre_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-context-resolver",
            "description": "Resolve context",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "AGENT_SPAWN" in log
        assert "appsec-context-resolver" in log

    def test_agent_spawn_includes_model(self, tmp_path):
        """AGENT_SPAWN must include model= from agent definition."""
        event = make_pre_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-recon-scanner",
            "description": "Recon scan",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "model=sonnet" in log

    def test_agent_spawn_background_flag(self, tmp_path):
        """AGENT_SPAWN must include [bg] tag for background agents."""
        event = make_pre_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-dep-scanner",
            "description": "Dep scan",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": True,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "[bg]" in log

    def test_pre_tool_use_non_agent_tool_not_logged(self, tmp_path):
        """PreToolUse for non-Agent tools must produce no log entry."""
        event = make_pre_tool_event("Bash", {"command": "ls"})
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert log == ""

    def test_agent_spawn_model_override(self, tmp_path):
        """Explicit model in tool_input overrides frontmatter in AGENT_SPAWN too."""
        event = make_pre_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-dep-scanner",
            "description": "Dep scan with opus",
            "prompt": "REPO_ROOT=/tmp/repo",
            "run_in_background": False,
            "model": "opus",
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "model=opus" in log

    def test_agent_spawn_params_extracted(self, tmp_path):
        """AGENT_SPAWN must include COMPONENT_ID and REPO_ROOT from prompt."""
        event = make_pre_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-stride-analyzer",
            "description": "STRIDE analysis",
            "prompt": "COMPONENT_ID=api-gw REPO_ROOT=/tmp/repo",
            "run_in_background": True,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "api-gw" in log
        assert "REPO_ROOT" in log


# ===========================================================================
# _agent_model — unit tests
# ===========================================================================

class TestAgentModel:
    def test_explicit_override_takes_priority(self):
        """Explicit model in tool_input overrides everything."""
        result = _agent_model("appsec-plugin:appsec-qa-reviewer", {"model": "opus"})
        assert result == "opus"

    def test_reads_model_from_agent_definition(self, monkeypatch):
        """Without override, model is read from agents/<name>.md frontmatter."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(PLUGIN_ROOT))
        result = _agent_model("appsec-plugin:appsec-qa-reviewer", {})
        assert result == "sonnet"

    def test_reads_model_for_all_known_agents(self, monkeypatch):
        """All plugin agents must resolve to 'sonnet' from their frontmatter.

        Discovered from the filesystem rather than hardcoded — new agents are
        covered automatically without having to remember to add them here.
        """
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(PLUGIN_ROOT))
        agents_dir = PLUGIN_ROOT / "agents"
        agents = [f"appsec-plugin:{p.stem}" for p in sorted(agents_dir.glob("appsec-*.md"))]
        assert agents, f"No agent .md files found under {agents_dir}"
        offenders = [a for a in agents if _agent_model(a, {}) != "sonnet"]
        assert not offenders, f"Agents not resolving to 'sonnet': {offenders}"

    def test_unknown_agent_returns_question_mark(self, monkeypatch):
        """An unrecognised agent name must return '?' gracefully."""
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(PLUGIN_ROOT))
        result = _agent_model("appsec-plugin:appsec-nonexistent", {})
        assert result == "?"

    def test_missing_plugin_root_returns_question_mark(self, monkeypatch):
        """Without CLAUDE_PLUGIN_ROOT set, return '?' without crashing."""
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        result = _agent_model("appsec-plugin:appsec-qa-reviewer", {})
        assert result == "?"


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

    def test_context_ready_emitted_for_context_file(self, tmp_path):
        """Writing .threat-modeling-context.md must emit both FILE_WRITE and CONTEXT_READY."""
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/repo/docs/security/.threat-modeling-context.md",
            "content": "# Context\n" + "x" * 400,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "FILE_WRITE" in log
        assert "CONTEXT_READY" in log
        assert ".threat-modeling-context.md" in log

    def test_context_ready_not_emitted_for_other_files(self, tmp_path):
        """CONTEXT_READY must only fire for the context file, not other writes."""
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/repo/docs/security/threat-model.md",
            "content": "# Threat Model",
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "CONTEXT_READY" not in log


# ===========================================================================
# PostToolUse — Bash tool
# ===========================================================================

class TestBashWarn:
    def test_bash_error_keywords_produce_warn(self, tmp_path):
        """All known bash-error keywords must trigger a BASH_WARN log entry.

        Consolidated from a 6-way parametrize into a single test that exercises
        every keyword and reports any failures at once.
        """
        keywords = [
            "permission denied",
            "No such file or directory",
            "command not found",
            "exit status 1",
            "Traceback",
            "SyntaxError",
        ]
        failures: list[str] = []
        for kw in keywords:
            event = make_post_tool_event("Bash",
                inp={"command": "cat /etc/shadow"},
                resp=f"cat: /etc/shadow: {kw}",
            )
            rc, log = run_logger(event, tmp_path)
            if rc != 0 or "BASH_WARN" not in log:
                failures.append(f"{kw!r} (rc={rc}, BASH_WARN in log: {'BASH_WARN' in log})")
        assert not failures, (
            "Keywords that failed to produce BASH_WARN:\n  - " + "\n  - ".join(failures)
        )

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

    def test_token_usage_logged_on_stop(self, tmp_path):
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 12000,
                "output_tokens": 3000,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
        }
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "in=12,000" in log
        assert "out=3,000" in log

    def test_cost_estimate_logged_on_stop(self, tmp_path):
        # 10k input ($0.03) + 2k output ($0.03) = $0.0600
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 10_000,
                "output_tokens": 2_000,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
        }
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "cost=$" in log
        assert "0.0600" in log

    def test_cache_tokens_logged_when_present(self, tmp_path):
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 5_000,
                "output_tokens": 1_000,
                "cache_creation_input_tokens": 8_000,
                "cache_read_input_tokens": 20_000,
            },
        }
        rc, log = run_logger(event, tmp_path)
        assert "cache_write=8,000" in log
        assert "cache_read=20,000" in log

    def test_cache_tokens_omitted_when_zero(self, tmp_path):
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 5_000,
                "output_tokens": 1_000,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
        }
        rc, log = run_logger(event, tmp_path)
        stop_line = [l for l in log.splitlines() if "SESSION_STOP" in l][0]
        assert "cache_write" not in stop_line
        assert "cache_read" not in stop_line

    def test_no_usage_field_still_logs_stop_reason(self, tmp_path):
        """Stop events without usage field must not crash."""
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
        }
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "SESSION_STOP" in log
        assert "end_turn" in log


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
        assert (tmp_path / "docs" / "security" / ".hook-events.log").exists()

    def test_multiple_events_appended_to_same_log(self, tmp_path):
        for i in range(3):
            event = make_post_tool_event("Write", {
                "file_path": f"/tmp/out{i}.md",
                "content": "data",
            }, session_id=f"session{i}")
            run_logger(event, tmp_path)

        log = (tmp_path / "docs" / "security" / ".hook-events.log").read_text()
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


# ===========================================================================
# _mask_secrets — unit tests for secret redaction
# ===========================================================================

class TestMaskSecrets:
    def test_password_equals_masked(self):
        assert "password='abcd****'" in _mask_secrets("password='abcdefgh'")

    def test_api_key_masked(self):
        result = _mask_secrets('api_key="AIzaSyDk1234567890"')
        assert "AIza****" in result
        assert "AIzaSyDk1234567890" not in result

    def test_token_masked(self):
        result = _mask_secrets("token='ghp_abc123def456'")
        assert "ghp_****" in result
        assert "ghp_abc123def456" not in result

    def test_secret_masked(self):
        result = _mask_secrets("secret=mysecretvalue123")
        assert "myse****" in result
        assert "mysecretvalue123" not in result

    def test_aws_access_key_masked(self):
        result = _mask_secrets("aws_access_key_id='AKIAIOSFODNN7EXAMPLE'")
        assert "AKIA****" in result
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_aws_secret_key_masked(self):
        result = _mask_secrets("aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")
        assert "wJal****" in result
        assert "wJalrXUtnFEMI" not in result

    def test_client_secret_masked(self):
        result = _mask_secrets("client_secret='longclientsecretvalue'")
        assert "long****" in result
        assert "longclientsecretvalue" not in result

    def test_auth_token_masked(self):
        result = _mask_secrets("auth_token='tok_1234567890abcdef'")
        assert "tok_****" in result
        assert "tok_1234567890abcdef" not in result

    def test_jdbc_connection_string_masked(self):
        result = _mask_secrets("jdbc:postgresql://user:SuperSecret123@db.host:5432/mydb")
        assert "Supe****" in result
        assert "SuperSecret123" not in result

    def test_bearer_token_masked(self):
        result = _mask_secrets("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig")
        assert "eyJh****" in result
        assert "eyJhbGciOiJSUzI1NiJ9" not in result

    def test_pem_private_key_masked(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALong...\n-----END RSA PRIVATE KEY-----"
        result = _mask_secrets(pem)
        assert "-----BEGIN RSA PRIVATE KEY-----" in result
        assert "MIIBogIBAAJBALong" not in result

    def test_short_secret_fully_masked(self):
        """Secrets with ≤4 characters get fully masked to just ****."""
        result = _mask_secrets("password='abcd'")
        assert "****" in result
        assert "abcd" not in result

    def test_no_secret_passthrough(self):
        text = "This is a normal log line with no secrets at all."
        assert _mask_secrets(text) == text

    def test_multiple_secrets_all_masked(self):
        text = "password='hunter2abc' api_key='AIzaSyDk12345'"
        result = _mask_secrets(text)
        assert "hunter2abc" not in result
        assert "AIzaSyDk12345" not in result
        assert result.count("****") == 2

    def test_case_insensitive_keyword(self):
        result = _mask_secrets("PASSWORD='SensitiveValue'")
        assert "Sens****" in result
        assert "SensitiveValue" not in result

    def test_colon_separator_masked(self):
        """key: value format (not just key=value)."""
        result = _mask_secrets("secret: 'longersecrethere'")
        assert "long****" in result
        assert "longersecrethere" not in result


# ===========================================================================
# _clip — unit tests for string truncation
# ===========================================================================

class TestClip:
    def test_short_string_unchanged(self):
        assert _clip("hello world") == "hello world"

    def test_long_string_truncated(self):
        long = "x" * 200
        result = _clip(long, 120)
        assert len(result) == 121  # 120 chars + "…"
        assert result.endswith("…")

    def test_exact_length_not_truncated(self):
        exact = "x" * 120
        assert _clip(exact, 120) == exact

    def test_newlines_replaced(self):
        result = _clip("line1\nline2\nline3")
        assert "\n" not in result
        assert "line1 line2 line3" == result

    def test_whitespace_stripped(self):
        assert _clip("  hello  ") == "hello"


# ===========================================================================
# _extract_param — unit tests for KEY=value extraction
# ===========================================================================

class TestExtractParam:
    def test_extracts_repo_root(self):
        text = "REPO_ROOT=/tmp/repo MANIFESTS=package.json"
        assert _extract_param(text, "REPO_ROOT") == "/tmp/repo"

    def test_extracts_component_id(self):
        text = "COMPONENT_ID=auth-service REPO_ROOT=/tmp/repo"
        assert _extract_param(text, "COMPONENT_ID") == "auth-service"

    def test_missing_key_returns_empty(self):
        assert _extract_param("REPO_ROOT=/tmp", "MISSING_KEY") == ""

    def test_truncates_long_value(self):
        long_val = "x" * 200
        text = f"KEY={long_val}"
        result = _extract_param(text, "KEY", max_len=80)
        assert len(result) == 80

    def test_value_at_end_of_string(self):
        text = "REPO_ROOT=/home/user/project"
        assert _extract_param(text, "REPO_ROOT") == "/home/user/project"


# ===========================================================================
# Secret masking in TOOL_ERROR and BASH_WARN output
# ===========================================================================

class TestSecretMaskingInLogOutput:
    def test_tool_error_masks_secret_in_response(self, tmp_path):
        """Secrets in tool error responses must be masked in the log."""
        event = make_post_tool_event("Grep",
            inp={"pattern": "password"},
            resp="src/config.py:5: password='SuperSecretValue123'",
            is_error=True,
        )
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "TOOL_ERROR" in log
        assert "SuperSecretValue123" not in log
        assert "****" in log

    def test_bash_warn_masks_secret_in_command(self, tmp_path):
        """Secrets in bash commands must be masked in BASH_WARN log entries."""
        event = make_post_tool_event("Bash",
            inp={"command": "echo password='RealSecret123'"},
            resp="error: permission denied",
        )
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "BASH_WARN" in log
        assert "RealSecret123" not in log

    def test_bash_warn_masks_secret_in_response(self, tmp_path):
        """Secrets in bash error responses must be masked in BASH_WARN log entries."""
        event = make_post_tool_event("Bash",
            inp={"command": "cat config.env"},
            resp="api_key='AIzaSyDk1234567890'\nPermission denied",
        )
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "BASH_WARN" in log
        assert "AIzaSyDk1234567890" not in log
        assert "****" in log


# ===========================================================================
# PostToolUse — Edit tool
# ===========================================================================

class TestFileEdit:
    def test_edit_tool_logs_file_edit(self, tmp_path):
        event = make_post_tool_event("Edit", {
            "file_path": "/tmp/repo/docs/security/threat-model.md",
            "old_string": "old text",
            "new_string": "new longer text here",
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "FILE_EDIT" in log
        assert "threat-model.md" in log

    def test_edit_tool_logs_char_delta(self, tmp_path):
        event = make_post_tool_event("Edit", {
            "file_path": "/tmp/repo/out.md",
            "old_string": "short",
            "new_string": "much longer replacement text",
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "delta=" in log

    def test_edit_tool_replace_all_annotated(self, tmp_path):
        event = make_post_tool_event("Edit", {
            "file_path": "/tmp/repo/out.md",
            "old_string": "foo",
            "new_string": "bar",
            "replace_all": True,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "(replace_all)" in log

    def test_edit_tool_no_replace_all_tag(self, tmp_path):
        event = make_post_tool_event("Edit", {
            "file_path": "/tmp/repo/out.md",
            "old_string": "foo",
            "new_string": "bar",
            "replace_all": False,
        })
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "(replace_all)" not in log


# ===========================================================================
# Stop event — MAX_TURNS dedicated error
# ===========================================================================

class TestMaxTurnsEvent:
    def test_max_turns_emits_dedicated_error(self, tmp_path):
        """max_turns stop must emit both SESSION_STOP and MAX_TURNS entries."""
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "max_turns",
        }
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "SESSION_STOP" in log
        assert "MAX_TURNS" in log
        assert log.count("ERROR") >= 2  # both SESSION_STOP and MAX_TURNS lines

    def test_end_turn_does_not_emit_max_turns(self, tmp_path):
        """Normal end_turn must not emit MAX_TURNS."""
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
        }
        rc, log = run_logger(event, tmp_path)
        assert rc == 0
        assert "MAX_TURNS" not in log


# ===========================================================================
# Verbose mode — stderr output
# ===========================================================================

def run_logger_verbose(event: dict, cwd: Path, verbose: bool = True,
                       plugin_root: Path = PLUGIN_ROOT) -> tuple[int, str, str]:
    """Run the logger with APPSEC_VERBOSE. Returns (returncode, log_content, stderr)."""
    log_dir = cwd / "docs" / "security"
    log_file = log_dir / ".hook-events.log"

    env = os.environ.copy()
    env["CLAUDE_PLUGIN_ROOT"] = str(plugin_root)
    if verbose:
        env["APPSEC_VERBOSE"] = "1"
    else:
        env.pop("APPSEC_VERBOSE", None)

    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=env,
    )
    content = log_file.read_text() if log_file.exists() else ""
    return result.returncode, content, result.stderr


class TestVerboseMode:
    def test_verbose_env_writes_to_stderr(self, tmp_path):
        """When APPSEC_VERBOSE=1, log lines appear on stderr."""
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/out.md",
            "content": "hello",
        })
        rc, log, stderr = run_logger_verbose(event, tmp_path, verbose=True)
        assert rc == 0
        assert "FILE_WRITE" in log       # file still written
        assert "[appsec]" in stderr       # stderr prefix present
        assert "FILE_WRITE" in stderr     # event appears on stderr

    def test_no_verbose_no_stderr(self, tmp_path):
        """Without APPSEC_VERBOSE, stderr must be empty."""
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/out.md",
            "content": "hello",
        })
        rc, log, stderr = run_logger_verbose(event, tmp_path, verbose=False)
        assert rc == 0
        assert "FILE_WRITE" in log       # file still written
        assert stderr.strip() == ""      # no stderr output

    def test_verbose_agent_spawn_on_stderr(self, tmp_path):
        event = make_pre_tool_event("Agent", {
            "subagent_type": "appsec-plugin:appsec-stride-analyzer",
            "description": "STRIDE for auth",
            "prompt": "COMPONENT_ID=auth-svc REPO_ROOT=/tmp/repo",
        })
        rc, log, stderr = run_logger_verbose(event, tmp_path, verbose=True)
        assert rc == 0
        assert "AGENT_SPAWN" in stderr
        assert "stride-analyzer" in stderr

    def test_verbose_stop_event_on_stderr(self, tmp_path):
        event = {
            "hook_event_name": "Stop",
            "session_id": "abc12345",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 5_000,
                "output_tokens": 1_000,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
        }
        rc, log, stderr = run_logger_verbose(event, tmp_path, verbose=True)
        assert rc == 0
        assert "SESSION_STOP" in stderr
        assert "cost=$" in stderr

    def test_verbose_false_values_do_not_activate(self, tmp_path):
        """APPSEC_VERBOSE=0, false, no should not activate verbose."""
        event = make_post_tool_event("Write", {
            "file_path": "/tmp/out.md",
            "content": "hello",
        })
        for val in ("0", "false", "no"):
            env = os.environ.copy()
            env["CLAUDE_PLUGIN_ROOT"] = str(PLUGIN_ROOT)
            env["APPSEC_VERBOSE"] = val
            result = subprocess.run(
                [sys.executable, str(SCRIPT)],
                input=json.dumps(event),
                capture_output=True,
                text=True,
                cwd=str(tmp_path),
                env=env,
            )
            assert result.stderr.strip() == "", (
                f"APPSEC_VERBOSE={val!r} should not produce stderr, got: {result.stderr!r}"
            )

    def test_verbose_config_activates_stderr(self, tmp_path):
        """logging.verbose: true in config.json activates stderr output."""
        # Create a temporary plugin root with verbose config
        fake_plugin = tmp_path / "fake_plugin"
        fake_plugin.mkdir()
        config = {
            "external_context": {"enabled": False, "rest_url": None},
            "logging": {"max_log_bytes": 5242880, "verbose": True},
        }
        (fake_plugin / "config.json").write_text(json.dumps(config))

        event = make_post_tool_event("Write", {
            "file_path": "/tmp/out.md",
            "content": "hello",
        })

        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(fake_plugin)
        env.pop("APPSEC_VERBOSE", None)  # no env var

        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env=env,
        )
        assert "[appsec]" in result.stderr
        assert "FILE_WRITE" in result.stderr


# ===========================================================================
# Assessment Summary — aggregated on outermost Stop event
# ===========================================================================

class TestAssessmentSummary:
    """Test the ASSESSMENT_SUMMARY event written on the outermost Stop."""

    def _seed_log(self, cwd: Path, lines: list[str]) -> None:
        """Pre-populate .hook-events.log with lines."""
        log_dir = cwd / "docs" / "security"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / ".hook-events.log").write_text("\n".join(lines) + "\n")

    def _seed_agent_run_log(self, cwd: Path, content: str) -> None:
        """Pre-populate .agent-run.log."""
        log_dir = cwd / "docs" / "security"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / ".agent-run.log").write_text(content)

    def _seed_threat_model(self, cwd: Path) -> None:
        """Create a minimal threat-model.md with known severity badges.

        The parser in `_write_assessment_summary` counts table rows (lines
        starting with `|`) whose Risk cell contains the emoji + severity
        word (e.g. `| T-001 | Foo | ... | 🔴 Critical | ...`). Each rendered
        line here mimics one such table row.
        """
        out_dir = cwd / "docs" / "security"
        out_dir.mkdir(parents=True, exist_ok=True)
        rows = []
        for _ in range(2):
            rows.append("| T-001 | Title | Foo | 🔴 Critical | M-001 |")
        for _ in range(5):
            rows.append("| T-002 | Title | Foo | 🟠 High | M-002 |")
        for _ in range(3):
            rows.append("| T-003 | Title | Foo | 🟡 Medium | M-003 |")
        (out_dir / "threat-model.md").write_text("\n".join(rows))

    def test_stop_event_emits_summary(self, tmp_path):
        """Outermost Stop event (hook_event_name=Stop) emits ASSESSMENT_SUMMARY."""
        # Seed a log with one SESSION_STOP entry
        self._seed_log(tmp_path, [
            '2026-04-08T10:00:00Z  [abc12345]  INFO   SESSION_STOP        stop_reason=end_turn  in=10,000  out=2,000  cost=$0.0600',
            '2026-04-08T10:00:00Z  [abc12345]  INFO   AGENT_SPAWN         appsec-threat-analyst            model=sonnet  Threat Model',
        ])
        self._seed_agent_run_log(tmp_path,
            '2026-04-08T10:00:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START   mode=full\n')

        event = {
            "hook_event_name": "Stop",
            "session_id": "mainsid1",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5000, "output_tokens": 1000},
        }
        rc, log = run_logger(event, tmp_path)
        assert "ASSESSMENT_SUMMARY" in log
        assert "ASSESSMENT_TOKENS" in log
        assert "ASSESSMENT_MODELS" in log
        assert "mode=full" in log

    def test_subagentstop_does_not_emit_summary(self, tmp_path):
        """SubagentStop must NOT emit ASSESSMENT_SUMMARY."""
        self._seed_log(tmp_path, [
            '2026-04-08T10:00:00Z  [abc12345]  INFO   SESSION_STOP        stop_reason=end_turn  in=1,000  out=500  cost=$0.0100',
        ])
        event = {
            "hook_event_name": "SubagentStop",
            "session_id": "subsid01",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1000, "output_tokens": 500},
        }
        rc, log = run_logger(event, tmp_path)
        assert "SESSION_STOP" in log
        assert "ASSESSMENT_SUMMARY" not in log

    def test_summary_aggregates_tokens(self, tmp_path):
        """Token counts from multiple SESSION_STOP entries are summed."""
        self._seed_log(tmp_path, [
            '2026-04-08T10:00:00Z  [aaaaaaaa]  INFO   SESSION_STOP        stop_reason=end_turn  in=10,000  out=2,000  cache_write=500  cache_read=1,000  cost=$0.0600',
            '2026-04-08T10:01:00Z  [bbbbbbbb]  INFO   SESSION_STOP        stop_reason=end_turn  in=5,000  out=1,000  cost=$0.0200',
        ])
        event = {
            "hook_event_name": "Stop",
            "session_id": "mainsid2",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 3000, "output_tokens": 800},
        }
        rc, log = run_logger(event, tmp_path)
        # Seeded + main session totals:
        #   fresh in     : 10,000 + 5,000 + 3,000 = 18,000
        #   output       :  2,000 + 1,000 +   800 =  3,800
        #   cache_write  :    500 +     0 +     0 =    500
        #   cache_read   :  1,000 +     0 +     0 =  1,000
        #   input total  : 18,000 + 500 + 1,000 = 19,500
        #   throughput   : 19,500 + 3,800 = 23,300
        assert "ASSESSMENT_TOKENS" in log
        tokens_line = [l for l in log.splitlines() if "ASSESSMENT_TOKENS" in l][-1]
        assert "throughput=23,300" in tokens_line
        assert "input=19,500" in tokens_line
        assert "output=3,800" in tokens_line
        assert "fresh=18,000" in tokens_line
        assert "cache_write=500" in tokens_line
        assert "cache_read=1,000" in tokens_line

    def test_summary_parses_threat_counts(self, tmp_path):
        """Threat counts are extracted from threat-model.md badges."""
        # Seed a FILE_WRITE entry pointing to the threat model path
        tm_path = str(tmp_path / "docs" / "security" / "threat-model.md")
        self._seed_log(tmp_path, [
            f'2026-04-08T10:00:00Z  [aaaaaaaa]  INFO   FILE_WRITE          {tm_path}  (5000 chars)',
        ])
        self._seed_threat_model(tmp_path)
        event = {
            "hook_event_name": "Stop",
            "session_id": "mainsid3",
            "stop_reason": "end_turn",
            "usage": {},
        }
        rc, log = run_logger(event, tmp_path)
        summary_line = [l for l in log.splitlines() if "ASSESSMENT_SUMMARY" in l][-1]
        assert "Critical=2" in summary_line
        assert "High=5" in summary_line
        assert "Medium=3" in summary_line
        assert "Low=0" in summary_line
        assert "threats=10" in summary_line

    def test_summary_detects_incremental_mode(self, tmp_path):
        """Mode is extracted from ASSESSMENT_START in .agent-run.log."""
        self._seed_log(tmp_path, [])
        self._seed_agent_run_log(tmp_path,
            '2026-04-08T10:00:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START   mode=incremental\n')
        event = {
            "hook_event_name": "Stop",
            "session_id": "mainsid4",
            "stop_reason": "end_turn",
            "usage": {},
        }
        rc, log = run_logger(event, tmp_path)
        summary_line = [l for l in log.splitlines() if "ASSESSMENT_SUMMARY" in l][-1]
        assert "mode=incremental" in summary_line

    def test_summary_collects_agent_models(self, tmp_path):
        """Agent models are collected from AGENT_SPAWN entries."""
        self._seed_log(tmp_path, [
            '2026-04-08T10:00:00Z  [aaaaaaaa]  INFO   AGENT_SPAWN         appsec-threat-analyst            model=sonnet  Threat Model',
            '2026-04-08T10:00:10Z  [bbbbbbbb]  INFO   AGENT_SPAWN         appsec-stride-analyzer           model=sonnet  STRIDE analysis',
            '2026-04-08T10:00:20Z  [cccccccc]  INFO   AGENT_SPAWN         appsec-qa-reviewer               model=sonnet  QA review',
        ])
        event = {
            "hook_event_name": "Stop",
            "session_id": "mainsid5",
            "stop_reason": "end_turn",
            "usage": {},
        }
        rc, log = run_logger(event, tmp_path)
        models_line = [l for l in log.splitlines() if "ASSESSMENT_MODELS" in l][-1]
        assert "threat-analyst=sonnet" in models_line
        assert "stride-analyzer=sonnet" in models_line
        assert "qa-reviewer=sonnet" in models_line

    def test_summary_subscription_billing(self, tmp_path):
        """When ANTHROPIC_API_KEY is not set, billing=subscription is shown."""
        self._seed_log(tmp_path, [])
        env = os.environ.copy()
        env["CLAUDE_PLUGIN_ROOT"] = str(PLUGIN_ROOT)
        env.pop("ANTHROPIC_API_KEY", None)
        log_dir = tmp_path / "docs" / "security"
        log_dir.mkdir(parents=True, exist_ok=True)
        event = {
            "hook_event_name": "Stop",
            "session_id": "mainsid6",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1000, "output_tokens": 500},
        }
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
            env=env,
        )
        log = (log_dir / ".hook-events.log").read_text()
        tokens_line = [l for l in log.splitlines() if "ASSESSMENT_TOKENS" in l][-1]
        assert "billing=subscription" in tokens_line

    def test_summary_mirrored_to_agent_run_log(self, tmp_path):
        """ASSESSMENT_SUMMARY is also written to .agent-run.log."""
        self._seed_log(tmp_path, [])
        self._seed_agent_run_log(tmp_path,
            '2026-04-08T10:00:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START   mode=full\n')
        event = {
            "hook_event_name": "Stop",
            "session_id": "mainsid7",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1000, "output_tokens": 500},
        }
        rc, log = run_logger(event, tmp_path)
        agent_run = (tmp_path / "docs" / "security" / ".agent-run.log").read_text()
        assert "ASSESSMENT_SUMMARY" in agent_run
        assert "ASSESSMENT_TOKENS" in agent_run
        assert "ASSESSMENT_MODELS" in agent_run
