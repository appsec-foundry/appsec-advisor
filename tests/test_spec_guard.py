"""End-to-end checks for the development-only specification guard."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts" / "spec_guard.py"
SPECS = ROOT / "specs"


def invoke(
    payload: object, args: list[str] | None = None, *, project_dir: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["CLAUDE_PROJECT_DIR"] = project_dir or str(ROOT)
    return subprocess.run(
        [
            sys.executable,
            str(GUARD),
            *(args if args is not None else ["--protected-dir", str(SPECS)]),
        ],
        input=json.dumps(payload) if not isinstance(payload, str) else payload,
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
        check=False,
    )


def decision(tool_name: str, tool_input: dict, *, cwd: Path = ROOT) -> dict | None:
    proc = invoke({"hook_event_name": "PreToolUse", "cwd": str(cwd), "tool_name": tool_name, "tool_input": tool_input})
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout else None


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Write", {"file_path": "specs/requirements.md", "content": "x"}),
        ("Edit", {"file_path": "specs/changes/guard/tasks.md", "new_string": "x"}),
        ("Bash", {"command": "echo x > specs/requirements.md"}),
        ("Bash", {"command": "sed -i 's/a/b/' specs/requirements.md"}),
        ("Bash", {"command": "find specs -type f -delete"}),
        ("Bash", {"command": "curl -o specs/download.md https://example.invalid/file"}),
        ("PowerShell", {"command": "Set-Content -Path specs/x.md -Value x"}),
        ("mcp__filesystem__write_file", {"path": "specs/x.md", "content": "x"}),
        ("mcp__filesystem__update_file", {"nested": {"target_path": "specs/x.md"}}),
    ],
)
def test_identifiable_spec_mutations_require_approval(tool_name, tool_input):
    result = decision(tool_name, tool_input)
    assert result is not None
    output = result["hookSpecificOutput"]
    assert output["permissionDecision"] == "ask"
    assert str(SPECS) in output["permissionDecisionReason"]


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Write", {"file_path": "tests/result.txt", "content": "x"}),
        ("Bash", {"command": "cat specs/requirements.md"}),
        ("Bash", {"command": "git diff -- specs/"}),
        ("Bash", {"command": "echo x > tests/result.txt"}),
        ("PowerShell", {"command": "Get-Content specs/requirements.md"}),
        ("mcp__filesystem__read_file", {"path": "specs/requirements.md"}),
        ("mcp__filesystem__write_file", {"path": "tests/result.txt", "content": "x"}),
    ],
)
def test_non_mutating_or_out_of_scope_calls_are_unaffected(tool_name, tool_input):
    assert decision(tool_name, tool_input) is None


def test_relative_write_from_a_specs_working_directory_requires_approval():
    result = decision("Bash", {"command": "touch changes/x.md"}, cwd=SPECS)
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "ask"


@pytest.mark.parametrize(
    "spelling",
    [
        "${CLAUDE_PROJECT_DIR}",
        "$CLAUDE_PROJECT_DIR",
        "%CLAUDE_PROJECT_DIR%",
        "${env:CLAUDE_PROJECT_DIR}",
        "$env:CLAUDE_PROJECT_DIR",
    ],
)
def test_project_root_spellings_are_resolved(spelling):
    result = decision("Bash", {"command": f'echo x > "{spelling}/specs/x.md"'})
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "ask"


@pytest.mark.parametrize(
    ("payload", "args"),
    [
        ("{", None),
        ([], None),
        ({"hook_event_name": "PreToolUse", "cwd": str(ROOT), "tool_name": "Bash", "tool_input": {}}, None),
        (
            {"hook_event_name": "PreToolUse", "cwd": str(ROOT), "tool_name": "Write", "tool_input": {"content": "x"}},
            None,
        ),
        (
            {
                "hook_event_name": "PreToolUse",
                "cwd": str(ROOT),
                "tool_name": "Write",
                "tool_input": {"file_path": "specs/x.md"},
            },
            [],
        ),
        (
            {
                "hook_event_name": "PreToolUse",
                "cwd": str(ROOT),
                "tool_name": "Write",
                "tool_input": {"file_path": "specs/x.md"},
            },
            ["--protected-dir", "specs"],
        ),
        (
            {
                "hook_event_name": "PreToolUse",
                "cwd": str(ROOT),
                "tool_name": "Write",
                "tool_input": {"file_path": "specs/x.md"},
            },
            ["--protected-dir", "/"],
        ),
    ],
)
def test_invalid_input_and_configuration_fail_closed(payload, args):
    proc = invoke(payload, args)
    assert proc.returncode == 2
    assert "blocking" in proc.stderr


def test_spec_guard_registration_and_decisions():
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
    assert settings["permissions"] == {"ask": ["Edit(/specs/**)"]}
    groups = settings["hooks"]["PreToolUse"]
    spec_groups = [
        group
        for group in groups
        if "scripts/spec_guard.py"
        in " ".join(" ".join([hook.get("command", ""), *hook.get("args", [])]) for hook in group.get("hooks", []))
    ]
    assert len(spec_groups) == 1
    group = spec_groups[0]
    assert set(group["matcher"].split("|")) == {
        "Bash",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "PowerShell",
        "Write",
        "mcp__.*",
    }
    handler = group["hooks"][0]
    assert handler["args"] == [
        "${CLAUDE_PROJECT_DIR}/scripts/spec_guard.py",
        "--protected-dir",
        "${CLAUDE_PROJECT_DIR}/specs",
    ]
    assert handler["timeout"] == 10
