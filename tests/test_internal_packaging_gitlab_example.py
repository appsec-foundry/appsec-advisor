"""Regression tests for the GitLab internal-packaging example."""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_ROOT = REPO_ROOT / "examples" / "internal-packaging-gitlab"
PACKAGER = REPO_ROOT / "scripts" / "package_internal_plugin.py"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_upstream_packager_excludes_vcs_and_local_outputs(tmp_path: Path) -> None:
    shutil.copytree(EXAMPLE_ROOT / "org-profile", tmp_path / "org-profile")

    upstream = tmp_path / "upstream" / "appsec-advisor"
    _write(
        upstream / ".claude-plugin" / "plugin.json",
        json.dumps(
            {
                "name": "appsec-advisor",
                "version": "0.0.0",
                "description": "Upstream plugin",
            }
        ),
    )
    _write(upstream / "config.json", "{}")
    (upstream / "schemas").mkdir(parents=True)
    _write(
        upstream / "skills" / "create-threat-model" / "SKILL.md",
        "Run /appsec-advisor:create-threat-model.\nSchema appsec-advisor.org-profile/v2 must stay unchanged.\n",
    )
    _write(upstream / "agents" / "dispatch.yaml", "agent: appsec-advisor:worker\n")
    _write(
        upstream / ".git" / "config",
        '[remote "origin"]\nurl = https://token@gitlab.internal/appsec.git\n',
    )
    _write(upstream / ".agents" / "local.txt", "local")
    _write(upstream / ".codex" / "local.txt", "local")
    _write(upstream / ".pytest_cache" / "README.md", "cache")
    _write(upstream / "build" / "old.txt", "local build")
    _write(upstream / "dist" / "old.tgz", "local dist")
    _write(upstream / "docs" / "security" / "threat-model.md", "sensitive")
    _write(upstream / "scripts" / "docs" / "security" / "threat-model.md", "sensitive")
    _write(upstream / "tests" / "fixtures" / "e2e" / "_last-run" / "threat-model.md", "sensitive")
    _write(upstream / "scripts" / "__pycache__" / "x.pyc", "cache")

    subprocess.run(
        [
            "python3",
            str(PACKAGER),
            "--source",
            str(upstream),
            "--org-profile",
            str(tmp_path / "org-profile"),
            "--name",
            "acme-appsec",
            "--version",
            "1.2.3-test",
            "--skip-validation",
        ],
        cwd=tmp_path,
        check=True,
    )

    build = tmp_path / "build" / "acme-appsec"
    plugin = json.loads((build / ".claude-plugin" / "plugin.json").read_text())
    config = json.loads((build / "config.json").read_text())

    assert plugin["name"] == "acme-appsec"
    assert plugin["version"] == "1.2.3-test"
    assert config["organization_profile"] == {
        "enabled": True,
        "path": "org-profile/org-profile.yaml",
    }
    assert not (build / ".git").exists()
    assert not (build / ".agents").exists()
    assert not (build / ".codex").exists()
    assert not (build / ".pytest_cache").exists()
    assert not (build / "build").exists()
    assert not (build / "dist").exists()
    assert not (build / "docs" / "security").exists()
    assert not (build / "scripts" / "docs").exists()
    assert not (build / "tests" / "fixtures" / "e2e" / "_last-run").exists()
    assert not (build / "scripts" / "__pycache__").exists()
    assert (build / "org-profile" / "org-profile.yaml").exists()

    skill_text = (build / "skills" / "create-threat-model" / "SKILL.md").read_text()
    agent_text = (build / "agents" / "dispatch.yaml").read_text()
    assert "/acme-appsec:create-threat-model" in skill_text
    assert "appsec-advisor:" not in skill_text
    assert "appsec-advisor.org-profile/v2" in skill_text
    assert "agent: acme-appsec:worker" in agent_text

    artifact = tmp_path / "dist" / "acme-appsec-1.2.3-test.tgz"
    checksum = tmp_path / "dist" / "acme-appsec-1.2.3-test.tgz.sha256"
    assert artifact.exists()
    assert checksum.exists()
    with tarfile.open(artifact) as archive:
        names = archive.getnames()
    forbidden = [
        name
        for name in names
        if name == "acme-appsec/.git"
        or name.startswith("acme-appsec/.git/")
        or name == "acme-appsec/.agents"
        or name.startswith("acme-appsec/.agents/")
        or name == "acme-appsec/.codex"
        or name.startswith("acme-appsec/.codex/")
        or name == "acme-appsec/.pytest_cache"
        or name.startswith("acme-appsec/.pytest_cache/")
        or name == "acme-appsec/build"
        or name.startswith("acme-appsec/build/")
        or name == "acme-appsec/dist"
        or name.startswith("acme-appsec/dist/")
        or name == "acme-appsec/docs/security"
        or name.startswith("acme-appsec/docs/security/")
        or name == "acme-appsec/scripts/docs"
        or name.startswith("acme-appsec/scripts/docs/")
        or name == "acme-appsec/tests/fixtures/e2e/_last-run"
        or name.startswith("acme-appsec/tests/fixtures/e2e/_last-run/")
        or "/__pycache__/" in name
    ]
    assert forbidden == []


def test_upstream_packager_rejects_slashes_in_version(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python3",
            str(PACKAGER),
            "--source",
            str(tmp_path / "missing-source"),
            "--org-profile",
            str(EXAMPLE_ROOT / "org-profile"),
            "--name",
            "acme-appsec",
            "--version",
            "feature/example",
        ],
        cwd=tmp_path,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 2
    assert "VERSION must not contain '/'" in result.stderr


def test_package_policy_prunes_skills_and_hooks(tmp_path: Path) -> None:
    shutil.copytree(EXAMPLE_ROOT / "org-profile", tmp_path / "org-profile")
    _write(
        tmp_path / "org-profile" / "package-policy.yaml",
        """
plugin_surface:
  skills:
    exclude:
      - audit-security-requirements
      - publish-threat-model
  hooks:
    exclude:
      - security-coach
""".lstrip(),
    )

    upstream = tmp_path / "upstream" / "appsec-advisor"
    _write(
        upstream / ".claude-plugin" / "plugin.json",
        json.dumps({"name": "appsec-advisor", "version": "0.0.0"}),
    )
    _write(
        upstream / "config.json",
        json.dumps({"external_context": {"enabled": False, "rest_url": None}}),
    )
    (upstream / "schemas").mkdir(parents=True)
    (upstream / "scripts").mkdir(parents=True)
    _write(
        upstream / "skills" / "create-threat-model" / "SKILL.md",
        "Run /appsec-advisor:create-threat-model.\n",
    )
    _write(
        upstream / "skills" / "status" / "SKILL.md",
        "Run /appsec-advisor:status.\n",
    )
    _write(
        upstream / "skills" / "audit-security-requirements" / "SKILL.md",
        "Run /appsec-advisor:audit-security-requirements.\n",
    )
    _write(
        upstream / "skills" / "audit-security-requirements" / "config.json",
        json.dumps({"requirements_source": {"enabled": False, "requirements_yaml_url": None}}),
    )
    _write(
        upstream / "skills" / "publish-threat-model" / "SKILL.md",
        "Run /appsec-advisor:publish-threat-model.\n",
    )
    _write(upstream / "agents" / "dispatch.yaml", "agent: appsec-advisor:worker\n")
    _write(
        upstream / "hooks" / "hooks.json",
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
                    ],
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": ("python3 ${CLAUDE_PLUGIN_ROOT}/scripts/agent_logger.py"),
                                }
                            ]
                        }
                    ],
                }
            }
        ),
    )
    _write(upstream / "hooks" / "steering_keywords.json", json.dumps({"topics": {}}))

    subprocess.run(
        [
            "python3",
            str(PACKAGER),
            "--source",
            str(upstream),
            "--org-profile",
            str(tmp_path / "org-profile"),
            "--name",
            "acme-appsec",
            "--version",
            "1.2.3-test",
            "--skip-validation",
            "--skip-archive",
        ],
        cwd=tmp_path,
        check=True,
    )

    build = tmp_path / "build" / "acme-appsec"
    assert (build / "skills" / "create-threat-model" / "SKILL.md").exists()
    assert (build / "skills" / "status" / "SKILL.md").exists()
    assert not (build / "skills" / "audit-security-requirements").exists()
    assert not (build / "skills" / "publish-threat-model").exists()
    assert not (build / "hooks" / "steering_keywords.json").exists()

    hooks = json.loads((build / "hooks" / "hooks.json").read_text())
    assert "UserPromptSubmit" not in hooks["hooks"]
    assert "PreToolUse" in hooks["hooks"]

    manifest = json.loads((build / ".claude-plugin" / "package-surface.json").read_text())
    assert manifest["policy"] == "org-profile/package-policy.yaml"
    assert manifest["skills"]["removed"] == [
        "audit-security-requirements",
        "publish-threat-model",
    ]
    assert manifest["hooks"]["removed"] == ["security-coach"]


def test_gitlab_ci_pins_ref_with_single_clone_then_smoke_tests() -> None:
    pipeline = yaml.safe_load((EXAMPLE_ROOT / ".gitlab-ci.yml").read_text())
    script_lines = pipeline["package"]["script"]
    script = "\n".join(script_lines)

    assert not (EXAMPLE_ROOT / "scripts" / "package.sh").exists()
    assert pipeline["stages"] == ["package"]
    assert pipeline["variables"]["VERSION"] == "0.4.0-internal.${CI_COMMIT_SHORT_SHA}"
    assert "apt-get install -y -qq --no-install-recommends git" in "\n".join(pipeline["default"]["before_script"])
    assert "rsync" not in script
    assert "ripgrep" not in script
    assert "tar -czf" not in script
    # A single clone pins the ref via --branch; no separate fetch/checkout dance.
    assert 'git clone --depth 1 --branch "$APPSEC_ADVISOR_REF" "$APPSEC_ADVISOR_URL" upstream/appsec-advisor' in script
    assert "fetch --depth 1 origin" not in script
    assert "checkout --detach FETCH_HEAD" not in script
    assert "scripts/package_internal_plugin.py" in script
    # The build is smoke-tested before publishing.
    assert "scripts/smoke_test_package.py" in script
