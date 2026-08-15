"""Guards for `scripts/requirements_hook.py`.

The hook is the only part of the specs mechanism that acts before an edit
rather than after it. These tests pin both halves: the catalog and the decision
register are held, and every other governed file arrives with its requirements
attached.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import requirements_hook  # noqa: E402


def payload(tool: str = "Edit", path: str = "scripts/merge_threats.py") -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": path},
    }


def output(response: dict | None) -> dict:
    assert response is not None
    return response["hookSpecificOutput"]


@pytest.mark.parametrize("held", ["specs/requirements.md", "docs/internal/decisions.md"])
def test_held_files_are_denied(held, monkeypatch):
    monkeypatch.delenv("APPSEC_SPEC_EDIT", raising=False)
    decision = output(requirements_hook.decide(payload(path=held)))
    assert decision["permissionDecision"] == "deny"
    assert held in decision["permissionDecisionReason"]


def test_held_file_is_denied_through_an_absolute_path(monkeypatch):
    monkeypatch.delenv("APPSEC_SPEC_EDIT", raising=False)
    absolute = str(ROOT / "specs" / "requirements.md")
    assert output(requirements_hook.decide(payload(path=absolute)))["permissionDecision"] == "deny"


def test_operator_can_hand_the_edit_over(monkeypatch):
    monkeypatch.setenv("APPSEC_SPEC_EDIT", "1")
    assert requirements_hook.decide(payload(path="specs/requirements.md")) is None


def test_governed_file_carries_its_requirements(monkeypatch):
    monkeypatch.delenv("APPSEC_SPEC_EDIT", raising=False)
    context = output(requirements_hook.decide(payload()))["additionalContext"]
    assert "scripts/merge_threats.py" in context
    assert "REQ-" in context


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
        "cat > specs/requirements.md",
        "echo x >> docs/internal/decisions.md",
        "sed -i 's/a/b/' specs/requirements.md",
        "python3 - <<'EOF'\nPath('specs/requirements.md').write_text('')\nEOF",
        "rm docs/internal/decisions.md",
        "git checkout other -- specs/requirements.md",
    ],
)
def test_a_shell_write_to_a_held_file_is_denied(command, monkeypatch):
    monkeypatch.delenv("APPSEC_SPEC_EDIT", raising=False)
    assert output(requirements_hook.decide(bash(command)))["permissionDecision"] == "deny"


@pytest.mark.parametrize(
    "command",
    [
        "grep REQ- specs/requirements.md",
        "wc -l docs/internal/decisions.md",
        "python3 scripts/check_specs.py",
        "echo hello > /tmp/note.txt",
    ],
)
def test_a_harmless_command_is_allowed(command, monkeypatch):
    monkeypatch.delenv("APPSEC_SPEC_EDIT", raising=False)
    assert requirements_hook.decide(bash(command)) is None


def test_the_operator_override_also_covers_the_shell(monkeypatch):
    monkeypatch.setenv("APPSEC_SPEC_EDIT", "1")
    assert requirements_hook.decide(bash("cat > specs/requirements.md")) is None
