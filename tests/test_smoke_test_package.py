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
                                    "command": ("python3 ${CLAUDE_PLUGIN_ROOT}/scripts/agent_logger.py"),
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
                                    "command": ("python3 ${CLAUDE_PLUGIN_ROOT}/scripts/security_steering.py"),
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


# ---------------------------------------------------------------------------
# In-process tests (import the module) so coverage is collected and the
# fine-grained _die error branches are exercised directly.
# ---------------------------------------------------------------------------

import pytest  # noqa: E402
import smoke_test_package as smk  # noqa: E402


def test_main_passes_in_process(tmp_path, capsys):
    _make_valid(tmp_path)
    assert smk.main([str(tmp_path), "--name", NAME]) == 0
    assert "Smoke test passed" in capsys.readouterr().out


def test_main_not_a_directory(tmp_path):
    with pytest.raises(SystemExit) as exc:
        smk.main([str(tmp_path / "ghost"), "--name", NAME])
    assert exc.value.code == 1


# --- _hook_id --------------------------------------------------------------


def test_hook_id_no_scripts_returns_none():
    assert smk._hook_id("python3 /opt/other/tool.py") is None


def test_hook_id_known_mapping():
    assert smk._hook_id("python3 /x/scripts/agent_logger.py --flag") == "agent-logger"


def test_hook_id_windows_path_and_stem_fallback():
    assert smk._hook_id("python C:\\x\\scripts\\my_custom_hook.py") == "my-custom-hook"


# --- _registered_hook_ids --------------------------------------------------


def test_registered_hook_ids_no_file(tmp_path):
    assert smk._registered_hook_ids(tmp_path) == set()


def test_registered_hook_ids_skips_non_dict_and_non_list(tmp_path):
    hooks = tmp_path / "hooks" / "hooks.json"
    hooks.parent.mkdir(parents=True, exist_ok=True)
    hooks.write_text(
        json.dumps(
            {
                "hooks": {
                    "BadEvent": "not-a-list",
                    "Mixed": [
                        "not-a-dict",
                        {"hooks": ["not-a-dict", {"command": 123}, {"no_command": "x"}]},
                        {"hooks": [{"command": "python3 /a/scripts/agent_logger.py"}]},
                    ],
                }
            }
        )
    )
    assert smk._registered_hook_ids(tmp_path) == {"agent-logger"}


# --- check_plugin_identity -------------------------------------------------


def test_check_plugin_identity_missing(tmp_path):
    with pytest.raises(SystemExit):
        smk.check_plugin_identity(tmp_path, NAME)


def test_check_plugin_identity_empty_version(tmp_path):
    p = tmp_path / ".claude-plugin" / "plugin.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"name": NAME, "version": ""}))
    with pytest.raises(SystemExit):
        smk.check_plugin_identity(tmp_path, NAME)


# --- check_org_profile_wired -----------------------------------------------


def test_check_org_profile_missing_config(tmp_path):
    with pytest.raises(SystemExit):
        smk.check_org_profile_wired(tmp_path)


def test_check_org_profile_empty_path(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"organization_profile": {"enabled": True, "path": ""}}))
    with pytest.raises(SystemExit):
        smk.check_org_profile_wired(tmp_path)


def test_check_org_profile_bundled_missing(tmp_path):
    (tmp_path / "config.json").write_text(
        json.dumps({"organization_profile": {"enabled": True, "path": "org-profile/org-profile.yaml"}})
    )
    with pytest.raises(SystemExit):
        smk.check_org_profile_wired(tmp_path)


def test_check_org_profile_bundled_empty(tmp_path):
    (tmp_path / "config.json").write_text(
        json.dumps({"organization_profile": {"enabled": True, "path": "org-profile/org-profile.yaml"}})
    )
    bundled = tmp_path / "org-profile" / "org-profile.yaml"
    bundled.parent.mkdir(parents=True, exist_ok=True)
    bundled.write_text("   \n")
    with pytest.raises(SystemExit):
        smk.check_org_profile_wired(tmp_path)


# --- check_namespace_rewritten ---------------------------------------------


def test_check_namespace_no_skills_dir(tmp_path):
    # no leaks, no skills dir -> the entry-command check is skipped, no error
    smk.check_namespace_rewritten(tmp_path, NAME)


# --- check_surface_manifest ------------------------------------------------


def test_check_surface_manifest_absent_is_noop(tmp_path):
    smk.check_surface_manifest(tmp_path)


def test_check_surface_manifest_included_skill_missing(tmp_path):
    manifest = tmp_path / ".claude-plugin" / "package-surface.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"skills": {"included": ["create-threat-model"]}}))
    with pytest.raises(SystemExit):
        smk.check_surface_manifest(tmp_path)


def test_check_surface_manifest_removed_hook_still_registered(tmp_path):
    # security-coach registered but manifest says removed
    hooks = tmp_path / "hooks" / "hooks.json"
    hooks.parent.mkdir(parents=True, exist_ok=True)
    hooks.write_text(
        json.dumps(
            {"hooks": {"UserPromptSubmit": [{"hooks": [{"command": "python3 /a/scripts/security_steering.py"}]}]}}
        )
    )
    manifest = tmp_path / ".claude-plugin" / "package-surface.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"hooks": {"removed": ["security-coach"]}}))
    with pytest.raises(SystemExit):
        smk.check_surface_manifest(tmp_path)


def test_check_surface_manifest_included_hook_not_registered(tmp_path):
    manifest = tmp_path / ".claude-plugin" / "package-surface.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"hooks": {"included": ["agent-logger"]}}))
    with pytest.raises(SystemExit):
        smk.check_surface_manifest(tmp_path)


def test_check_surface_manifest_steering_keywords_leftover(tmp_path):
    manifest = tmp_path / ".claude-plugin" / "package-surface.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps({"hooks": {"removed": ["security-coach"]}}))
    kw = tmp_path / "hooks" / "steering_keywords.json"
    kw.parent.mkdir(parents=True, exist_ok=True)
    kw.write_text("{}")
    with pytest.raises(SystemExit):
        smk.check_surface_manifest(tmp_path)
