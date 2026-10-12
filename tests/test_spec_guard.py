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
REQUIREMENTS = ROOT / "requirements.md"


def invoke(
    payload: object, args: list[str] | None = None, *, project_dir: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["CLAUDE_PROJECT_DIR"] = project_dir or str(ROOT)
    return subprocess.run(
        [
            sys.executable,
            str(GUARD),
            *(args if args is not None else ["--protected-path", str(REQUIREMENTS)]),
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
        ("Write", {"file_path": "requirements.md", "content": "x"}),
        ("Edit", {"file_path": "requirements.md", "new_string": "x"}),
        ("Bash", {"command": "echo x > requirements.md"}),
        ("Bash", {"command": "sed -i 's/a/b/' requirements.md"}),
        ("Bash", {"command": "find . -type f -delete"}),
        ("Bash", {"command": "curl -o requirements.md https://example.invalid/file"}),
        ("PowerShell", {"command": "Set-Content -Path requirements.md -Value x"}),
        ("mcp__filesystem__write_file", {"path": "requirements.md", "content": "x"}),
        ("mcp__filesystem__remove", {"path": "."}),
    ],
)
def test_identifiable_spec_mutations_require_approval(tool_name, tool_input):
    result = decision(tool_name, tool_input)
    assert result is not None
    output = result["hookSpecificOutput"]
    assert output["permissionDecision"] == "ask"
    assert str(REQUIREMENTS) in output["permissionDecisionReason"]


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Write", {"file_path": "tests/result.txt", "content": "x"}),
        ("Edit", {"file_path": "specs/changes/guard/tasks.md", "new_string": "x"}),
        ("Edit", {"file_path": "specs/requirements.md", "new_string": "historical path"}),
        ("Bash", {"command": "cat requirements.md"}),
        ("Bash", {"command": "git diff -- specs/"}),
        ("Bash", {"command": "echo x > specs/changes/note.md"}),
        ("Bash", {"command": "echo x > tests/result.txt"}),
        ("PowerShell", {"command": "Get-Content requirements.md"}),
        ("mcp__filesystem__read_file", {"path": "requirements.md"}),
        ("mcp__filesystem__write_file", {"path": "tests/result.txt", "content": "x"}),
        ("Bash", {"command": f"cd {ROOT}\npython3 - <<'PY'\nprint(1)\nPY"}),
        ("Bash", {"command": "cp tests/result.txt ."}),
        ("Bash", {"command": f"cd {ROOT} && rm -rf .cache"}),
        # The catalog is named as data here, not as an argument of the writer.
        ("Bash", {"command": 'echo "commits that touch requirements.md: 3"'}),
        ("Bash", {"command": "awk '{ if (length($0)>100) c++ }' requirements.md"}),
        ("Bash", {"command": "cat > note.txt <<'PY'\nsee requirements.md\nPY"}),
        # A removal in one simple command does not reach a path named in another.
        ("Bash", {"command": f"grep -rn foo {ROOT} && rm -rf .cache"}),
    ],
)
def test_non_mutating_or_out_of_scope_calls_are_unaffected(tool_name, tool_input):
    assert decision(tool_name, tool_input) is None


@pytest.mark.parametrize(
    "command",
    [
        f"rm -rf {ROOT}",
        "rm -rf .",
        "git checkout -- .",
        'echo x > "requirements.md"',
        "cat draft.md | tee requirements.md",
        "grep -rn foo . ; rm -rf .",
    ],
)
def test_writers_reaching_the_catalog_indirectly_require_approval(command):
    result = decision("Bash", {"command": command})
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_relative_write_from_specs_to_catalog_requires_approval():
    result = decision("Bash", {"command": "touch ../requirements.md"}, cwd=SPECS)
    assert result is not None
    assert result["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_relative_write_inside_specs_does_not_target_root_catalog():
    assert decision("Bash", {"command": "touch requirements.md"}, cwd=SPECS) is None


def test_relative_write_to_change_record_does_not_require_specification_approval():
    assert decision("Bash", {"command": "touch changes/x.md"}, cwd=SPECS) is None


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
    result = decision("Bash", {"command": f'echo x > "{spelling}/requirements.md"'})
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
                "tool_input": {"file_path": "requirements.md"},
            },
            [],
        ),
        (
            {
                "hook_event_name": "PreToolUse",
                "cwd": str(ROOT),
                "tool_name": "Write",
                "tool_input": {"file_path": "requirements.md"},
            },
            ["--protected-path", "requirements.md"],
        ),
        (
            {
                "hook_event_name": "PreToolUse",
                "cwd": str(ROOT),
                "tool_name": "Write",
                "tool_input": {"file_path": "requirements.md"},
            },
            ["--protected-path", "/"],
        ),
    ],
)
def test_invalid_input_and_configuration_fail_closed(payload, args):
    proc = invoke(payload, args)
    assert proc.returncode == 2
    assert "blocking" in proc.stderr


def test_spec_guard_registration_and_decisions():
    settings = json.loads((ROOT / ".claude" / "settings.json").read_text())
    assert settings["permissions"] == {
        "ask": [
            "Edit(requirements.md)",
        ],
        # The guard cannot hold a rule an agent may rewrite. These files carry
        # the rule itself, so they are denied rather than merely asked about.
        # Only Edit(...) rules take part in file permission checks; they cover
        # every file-editing tool and also reach shell writes through the
        # sandbox, so a Write(...) twin would be inert.
        "deny": [
            "Edit(.claude/settings.json)",
            "Edit(scripts/spec_guard.py)",
            "Edit(scripts/requirements/requirements_hook.py)",
        ],
    }
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
        "--protected-path",
        "${CLAUDE_PROJECT_DIR}/requirements.md",
    ]
    assert handler["timeout"] == 10
