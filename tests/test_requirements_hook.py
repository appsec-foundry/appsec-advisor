"""Guards for `scripts/requirements_hook.py`.

The hook acts before a direct implementation edit. These tests pin both halves:
the decision register requires explicit user approval, and every governed file
arrives with the product requirement and external guard coverage attached. The
separate specification guard owns catalog approval.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import requirements_hook  # noqa: E402


def payload(tool: str = "Edit", path: str = "scripts/merge_threats.py") -> dict:
    field = "notebook_path" if tool == "NotebookEdit" else "file_path"
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {field: path},
    }


def output(response: dict | None) -> dict:
    assert response is not None
    return response["hookSpecificOutput"]


@pytest.mark.parametrize("tool", ["Edit", "Write", "MultiEdit", "NotebookEdit"])
def test_decision_register_requires_user_approval(tool):
    held = "docs/internal/decisions.md"
    decision = output(requirements_hook.decide(payload(tool=tool, path=held)))
    assert decision["permissionDecision"] == "ask"
    assert held in decision["permissionDecisionReason"]


def test_decision_register_requires_approval_through_an_absolute_path():
    absolute = str(ROOT / "docs" / "internal" / "decisions.md")
    assert output(requirements_hook.decide(payload(path=absolute)))["permissionDecision"] == "ask"


def test_catalog_approval_is_left_to_the_specification_guard():
    assert requirements_hook.decide(payload(path="specs/requirements.md")) is None


def test_governed_file_carries_its_requirements():
    context = output(requirements_hook.decide(payload()))["additionalContext"]
    assert "scripts/merge_threats.py" in context
    assert "REQ-MOD-001" in context
    assert "Guard coverage: partial" in context


def test_ungoverned_file_is_left_alone():
    assert requirements_hook.decide(payload(path="CHANGELOG.md")) is None


def test_path_outside_the_repository_is_left_alone():
    assert requirements_hook.decide(payload(path="/etc/passwd")) is None


@pytest.mark.parametrize(
    "broken",
    [
        {},
        {"hook_event_name": "PostToolUse", "tool_name": "Edit"},
        {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
        {"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {}},
        {"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": {"file_path": 7}},
    ],
)
def test_unusable_payload_allows(broken):
    assert requirements_hook.decide(broken) is None


def test_main_prints_nothing_when_it_allows(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO('{"hook_event_name": "Stop"}'))
    assert requirements_hook.main() == 0
    assert capsys.readouterr().out == ""


def bash(command: str) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


@pytest.mark.parametrize(
    "command",
    [
        "echo x >> docs/internal/decisions.md",
        "rm docs/internal/decisions.md",
        "python3 - <<'EOF'\nPath('docs/internal/decisions.md').write_text('')\nEOF",
        "git checkout other -- docs/internal/decisions.md",
    ],
)
def test_a_shell_write_to_a_held_file_requires_user_approval(command):
    assert output(requirements_hook.decide(bash(command)))["permissionDecision"] == "ask"


@pytest.mark.parametrize(
    "command",
    [
        "grep REQ- specs/requirements.md",
        "cat > specs/requirements.md",
        "wc -l docs/internal/decisions.md",
        "python3 scripts/check_specs.py",
        "echo hello > /tmp/note.txt",
    ],
)
def test_a_harmless_command_is_allowed(command):
    assert requirements_hook.decide(bash(command)) is None


def test_project_settings_wire_every_write_surface_to_the_hook():
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
    groups = settings["hooks"]["PreToolUse"]
    matches = [
        group
        for group in groups
        if group.get("matcher") == "Edit|Write|MultiEdit|NotebookEdit|Bash"
        and any(
            "requirements_hook.py" in " ".join([hook.get("command", ""), *hook.get("args", [])])
            for hook in group.get("hooks", [])
        )
    ]
    assert len(matches) == 1
