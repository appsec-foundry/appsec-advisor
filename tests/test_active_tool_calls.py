"""Unit tests for the M3.6 #2 active-tool-call markers in agent_logger."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "agent_logger.py"


@pytest.fixture
def agent_logger(tmp_path, monkeypatch):
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    spec = importlib.util.spec_from_file_location("agent_logger", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_logger"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _read_active(tmp_path: Path) -> list[dict]:
    d = tmp_path / ".active-tool-calls"
    if not d.is_dir():
        return []
    return [json.loads(f.read_text()) for f in sorted(d.glob("*.json"))]


# ---------------------------------------------------------------------------
# Pre / Post lifecycle
# ---------------------------------------------------------------------------


def test_pre_creates_per_call_marker(tmp_path, agent_logger):
    al = agent_logger
    al._record_tool_start(
        {
            "tool_use_id": "toolu_xyz",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
        },
        sid="abc12345",
    )
    entries = _read_active(tmp_path)
    assert len(entries) == 1
    e = entries[0]
    assert e["tool_use_id"] == "toolu_xyz"
    assert e["tool"] == "Bash"
    assert e["session_id"] == "abc12345"
    assert "echo hello" in e["input_summary"]
    assert isinstance(e["started_at"], int)


def test_post_removes_marker(tmp_path, agent_logger):
    al = agent_logger
    al._record_tool_start(
        {
            "tool_use_id": "toolu_xyz",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        },
        sid="abc12345",
    )
    assert _read_active(tmp_path)
    al._record_tool_end({"tool_use_id": "toolu_xyz"})
    assert _read_active(tmp_path) == []


def test_post_is_idempotent_when_marker_missing(tmp_path, agent_logger):
    al = agent_logger
    # Should not raise even when nothing has been recorded.
    al._record_tool_end({"tool_use_id": "missing"})
    assert _read_active(tmp_path) == []


def test_pre_skips_when_tool_use_id_absent(tmp_path, agent_logger):
    al = agent_logger
    al._record_tool_start(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        },
        sid="abc12345",
    )
    assert _read_active(tmp_path) == []


# ---------------------------------------------------------------------------
# Input summarisation — must redact secrets and clip overlong payloads
# ---------------------------------------------------------------------------


def test_summary_clips_long_command(tmp_path, agent_logger):
    al = agent_logger
    long_cmd = "echo " + ("X" * 500)
    al._record_tool_start(
        {
            "tool_use_id": "toolu_long",
            "tool_name": "Bash",
            "tool_input": {"command": long_cmd},
        },
        sid="abc12345",
    )
    e = _read_active(tmp_path)[0]
    assert len(e["input_summary"]) <= 165  # 160 budget + ellipsis allowance


def test_summary_redacts_bearer_token(tmp_path, agent_logger):
    al = agent_logger
    al._record_tool_start(
        {
            "tool_use_id": "toolu_secret",
            "tool_name": "Bash",
            "tool_input": {"command": "curl -H 'Authorization: Bearer abcdefghijklmnopqr1234567890' https://x"},
        },
        sid="abc12345",
    )
    e = _read_active(tmp_path)[0]
    assert "abcdefghij" not in e["input_summary"]


def test_summary_for_read_uses_file_path(tmp_path, agent_logger):
    al = agent_logger
    al._record_tool_start(
        {
            "tool_use_id": "toolu_read",
            "tool_name": "Read",
            "tool_input": {"file_path": "/etc/hosts"},
        },
        sid="abc12345",
    )
    e = _read_active(tmp_path)[0]
    assert e["input_summary"] == "/etc/hosts"


def test_summary_for_agent_includes_subtype(tmp_path, agent_logger):
    al = agent_logger
    al._record_tool_start(
        {
            "tool_use_id": "toolu_agent",
            "tool_name": "Agent",
            "tool_input": {"subagent_type": "stride-analyzer", "description": "Auth Service"},
        },
        sid="abc12345",
    )
    e = _read_active(tmp_path)[0]
    assert "stride-analyzer" in e["input_summary"]
    assert "Auth Service" in e["input_summary"]


def test_per_call_files_have_distinct_paths(tmp_path, agent_logger):
    al = agent_logger
    for tid in ("toolu_a", "toolu_b", "toolu_c"):
        al._record_tool_start(
            {
                "tool_use_id": tid,
                "tool_name": "Bash",
                "tool_input": {"command": "true"},
            },
            sid="abc12345",
        )
    entries = _read_active(tmp_path)
    assert {e["tool_use_id"] for e in entries} == {"toolu_a", "toolu_b", "toolu_c"}


def test_unsafe_tool_use_id_chars_are_stripped(tmp_path, agent_logger):
    al = agent_logger
    al._record_tool_start(
        {
            "tool_use_id": "../../../etc/passwd",
            "tool_name": "Bash",
            "tool_input": {"command": "true"},
        },
        sid="abc12345",
    )
    # The marker must land inside .active-tool-calls/ — never escape it.
    assert (tmp_path / ".active-tool-calls").is_dir()
    files = list((tmp_path / ".active-tool-calls").glob("*.json"))
    assert len(files) == 1
    # Sanitised name should contain no path separators.
    assert "/" not in files[0].name
    assert files[0].name != "passwd.json"  # must not write outside dir
