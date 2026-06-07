"""Tests for scripts/smoke_test_package.py (packaged-plugin contract check)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SMOKE = REPO_ROOT / "scripts" / "smoke_test_package.py"

NAME = "acme-appsec"


def _make_valid(root: Path, name: str = NAME) -> None:
    """Write a minimal plugin tree that satisfies every smoke assertion."""
    plugin = root / ".claude-plugin" / "plugin.json"
    plugin.parent.mkdir(parents=True, exist_ok=True)
    plugin.write_text(json.dumps({"name": name, "version": "0.4.0-dev"}))

    (root / "config.json").write_text(
        json.dumps(
            {
                "organization_profile": {
                    "enabled": True,
                    "path": "org-profile/org-profile.yaml",
                }
            }
        )
    )

    profile = root / "org-profile" / "org-profile.yaml"
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_text("organization: { id: acme }\n")

    skill = root / "skills" / "create-threat-model" / "SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text(f"Run /{name}:create-threat-model.\n")


def _run(root: Path, name: str = NAME) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SMOKE), str(root), "--name", name],
        capture_output=True,
        text=True,
    )


def test_passes_on_valid_tree(tmp_path: Path) -> None:
    _make_valid(tmp_path)
    result = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "Smoke test passed" in result.stdout


def test_fails_on_wrong_name(tmp_path: Path) -> None:
    _make_valid(tmp_path)
    result = _run(tmp_path, name="wrong-name")
    assert result.returncode == 1
    assert "name" in result.stderr


def test_fails_when_org_profile_disabled(tmp_path: Path) -> None:
    _make_valid(tmp_path)
    config = tmp_path / "config.json"
    data = json.loads(config.read_text())
    data["organization_profile"]["enabled"] = False
    config.write_text(json.dumps(data))
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "organization_profile" in result.stderr


def test_fails_on_namespace_leak(tmp_path: Path) -> None:
    _make_valid(tmp_path)
    leak = tmp_path / "skills" / "leak.md"
    leak.write_text("dispatch appsec-advisor:worker\n")
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "appsec-advisor:" in result.stderr


def test_fails_when_entry_command_missing(tmp_path: Path) -> None:
    _make_valid(tmp_path)
    skill = tmp_path / "skills" / "create-threat-model" / "SKILL.md"
    skill.write_text("No entry command here.\n")
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "entry command" in result.stderr


def test_passes_with_matching_surface_manifest(tmp_path: Path) -> None:
    _make_valid(tmp_path)
    hooks = tmp_path / "hooks" / "hooks.json"
    hooks.parent.mkdir(parents=True, exist_ok=True)
    hooks.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": (
                                        "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/"
                                        "agent_logger.py"
                                    ),
                                }
                            ]
                        }
                    ]
                }
            }
        )
    )
    manifest = tmp_path / ".claude-plugin" / "package-surface.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "skills": {
                    "included": ["create-threat-model"],
                    "removed": ["publish-threat-model"],
                },
                "hooks": {
                    "included": ["agent-logger"],
                    "removed": ["security-coach"],
                },
            }
        )
    )
    result = _run(tmp_path)
    assert result.returncode == 0, result.stderr


def test_fails_when_removed_skill_is_present(tmp_path: Path) -> None:
    _make_valid(tmp_path)
    skill = tmp_path / "skills" / "publish-threat-model" / "SKILL.md"
    skill.parent.mkdir(parents=True, exist_ok=True)
    skill.write_text("Publish.\n")
    manifest = tmp_path / ".claude-plugin" / "package-surface.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "skills": {
                    "included": ["create-threat-model"],
                    "removed": ["publish-threat-model"],
                },
                "hooks": {"included": [], "removed": []},
            }
        )
    )
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "removed" in result.stderr


def test_fails_when_removed_hook_is_registered(tmp_path: Path) -> None:
    _make_valid(tmp_path)
    hooks = tmp_path / "hooks" / "hooks.json"
    hooks.parent.mkdir(parents=True, exist_ok=True)
    hooks.write_text(
        json.dumps(
            {
                "hooks": {
                    "UserPromptSubmit": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": (
                                        "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/"
                                        "security_steering.py"
                                    ),
                                }
                            ]
                        }
                    ]
                }
            }
        )
    )
    manifest = tmp_path / ".claude-plugin" / "package-surface.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "skills": {"included": ["create-threat-model"], "removed": []},
                "hooks": {"included": [], "removed": ["security-coach"]},
            }
        )
    )
    result = _run(tmp_path)
    assert result.returncode == 1
    assert "security-coach" in result.stderr
