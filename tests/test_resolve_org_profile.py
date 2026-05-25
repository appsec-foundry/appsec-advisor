"""Tests for scripts/resolve_org_profile.py.

Covers discovery (CLI > env > config.json), preset resolution, target.repo
rules, output_dir template expansion, fingerprint stability, and the
``--no-org-profile`` short-circuit.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "resolve_org_profile.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "org-profiles" / "acme"
FIXTURE_PATH = FIXTURE_DIR / "org-profile.yaml"


def _load_module():
    if "resolve_org_profile" in sys.modules:
        return sys.modules["resolve_org_profile"]
    spec = importlib.util.spec_from_file_location("resolve_org_profile", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["resolve_org_profile"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rop = _load_module()


@pytest.fixture
def isolated_root(tmp_path: Path) -> Path:
    """Plugin root with only ``schemas/`` + ``scripts/`` symlinked through.

    Each test sees its own ``config.json`` and lives in its own dir so
    ``CLAUDE_PLUGIN_ROOT`` can be set without leaking between tests.
    """
    root = tmp_path / "plugin"
    root.mkdir()
    (root / "schemas").symlink_to(REPO_ROOT / "schemas")
    (root / "scripts").symlink_to(REPO_ROOT / "scripts")
    (root / ".claude-plugin").mkdir()
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"version": "0.4.0-beta"})
    )
    return root


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discovery_no_profile_returns_none(isolated_root):
    path, source = rop.discover_active_profile(
        cli_path=None, cli_no_profile=False, plugin_root=isolated_root, env={}
    )
    assert path is None
    assert source == "none"


def test_discovery_cli_beats_env_beats_config(isolated_root):
    path, source = rop.discover_active_profile(
        cli_path=str(FIXTURE_PATH),
        cli_no_profile=False,
        plugin_root=isolated_root,
        env={"APPSEC_ADVISOR_ORG_PROFILE": "/tmp/other.yaml"},
    )
    assert source == "cli"
    assert path == FIXTURE_PATH


def test_discovery_env_beats_config(isolated_root):
    (isolated_root / "config.json").write_text(
        json.dumps({
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {
                "enabled": True,
                "path": "../some/where.yaml",
                "default_preset": None,
            },
        })
    )
    path, source = rop.discover_active_profile(
        cli_path=None,
        cli_no_profile=False,
        plugin_root=isolated_root,
        env={"APPSEC_ADVISOR_ORG_PROFILE": str(FIXTURE_PATH)},
    )
    assert source == "env"
    assert path == FIXTURE_PATH


def test_discovery_no_org_profile_flag_disables(isolated_root):
    path, source = rop.discover_active_profile(
        cli_path=str(FIXTURE_PATH),
        cli_no_profile=True,
        plugin_root=isolated_root,
        env={},
    )
    assert path is None
    assert source == "disabled"


def test_discovery_env_kill_switch(isolated_root):
    path, source = rop.discover_active_profile(
        cli_path=None,
        cli_no_profile=False,
        plugin_root=isolated_root,
        env={
            "APPSEC_ADVISOR_ORG_PROFILE": str(FIXTURE_PATH),
            "APPSEC_ADVISOR_NO_ORG_PROFILE": "1",
        },
    )
    assert path is None
    assert source == "disabled"


def test_discovery_config_pointer_is_relative_to_plugin_root(isolated_root):
    # Stage a profile copy under the plugin root and reference it relatively.
    target_dir = isolated_root / "org-profile"
    shutil.copytree(FIXTURE_DIR, target_dir)
    (isolated_root / "config.json").write_text(
        json.dumps({
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {
                "enabled": True,
                "path": "org-profile/org-profile.yaml",
                "default_preset": None,
            },
        })
    )
    path, source = rop.discover_active_profile(
        cli_path=None, cli_no_profile=False, plugin_root=isolated_root, env={}
    )
    assert source == "config"
    assert path == (target_dir / "org-profile.yaml").resolve()


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def test_resolve_default_preset(isolated_root):
    effective, errors = rop.resolve(
        str(FIXTURE_PATH), None, False, None, isolated_root, env={}
    )
    assert errors == []
    assert effective["org_profile"]["active"] is True
    assert effective["preset"]["name"] == "ci-standard"
    assert effective["defaults"]["assessment_depth"] == "standard"
    assert effective["defaults"]["write_sarif"] is True
    assert effective["defaults"]["write_pdf"] is False
    assert effective["requirements_source"]["enabled"] is True
    assert effective["skill_toggles"]["publish-threat-model"]["enabled"] is False
    assert effective["skill_toggles"]["publish-threat-model"]["reason"]


def test_resolve_explicit_preset_overrides_default(isolated_root):
    effective, errors = rop.resolve(
        str(FIXTURE_PATH), "release-review", False, None, isolated_root, env={}
    )
    assert errors == []
    assert effective["preset"]["name"] == "release-review"
    assert effective["defaults"]["write_pdf"] is True
    assert effective["defaults"]["write_pentest_tasks"] is True


def test_resolve_unknown_preset_fails(isolated_root):
    effective, errors = rop.resolve(
        str(FIXTURE_PATH), "ghost", False, None, isolated_root, env={}
    )
    assert errors
    assert any("ghost" in e for e in errors)


def test_org_profile_required_preset_without_repo_fails(isolated_root):
    effective, errors = rop.resolve(
        str(FIXTURE_PATH), "appsec-verification", False, None, isolated_root, env={}
    )
    assert any("--repo" in e for e in errors), errors


def test_cli_required_preset_with_repo_resolves_output_template(isolated_root, tmp_path):
    repo = tmp_path / "payments-api"
    repo.mkdir()
    effective, errors = rop.resolve(
        str(FIXTURE_PATH),
        "appsec-verification",
        False,
        str(repo),
        isolated_root,
        env={},
    )
    assert errors == []
    output_dir = effective["defaults"]["output_dir"]
    assert output_dir is not None
    assert "payments-api" in output_dir
    assert "appsec-verification" in output_dir


def test_no_org_profile_returns_inactive(isolated_root):
    effective, errors = rop.resolve(
        str(FIXTURE_PATH), None, True, None, isolated_root, env={}
    )
    assert errors == []
    assert effective["org_profile"]["active"] is False
    assert effective["preset"] is None
    assert effective["defaults"] == {}


def test_fingerprint_changes_when_context_changes(isolated_root, tmp_path):
    staged = tmp_path / "profile"
    shutil.copytree(FIXTURE_DIR, staged)
    profile = staged / "org-profile.yaml"
    eff1, errs1 = rop.resolve(
        str(profile), None, False, None, isolated_root, env={}
    )
    assert errs1 == []
    fp1 = eff1["org_profile"]["profile_fingerprint"]

    (staged / "context" / "sso.md").write_text("# changed content\n")
    eff2, errs2 = rop.resolve(
        str(profile), None, False, None, isolated_root, env={}
    )
    assert errs2 == []
    fp2 = eff2["org_profile"]["profile_fingerprint"]
    assert fp1 != fp2


def test_emit_file_writes_effective_json(isolated_root, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    rc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--org-profile",
            str(FIXTURE_PATH),
            "--output-dir",
            str(out),
            "--emit-file",
            "--plugin-root",
            str(isolated_root),
        ],
        capture_output=True,
        text=True,
    )
    assert rc.returncode == 0, rc.stderr
    emitted = out / ".org-profile-effective.json"
    assert emitted.exists()
    data = json.loads(emitted.read_text())
    assert data["org_profile"]["active"] is True
    assert data["preset"]["name"] == "ci-standard"
