"""Tests for the org-profile slice of scripts/resolve_config.py.

Asserts that:
  * legacy invocations without an org profile keep their existing output
  * --org-profile activates the resolver and emits org_profile blocks
  * preset defaults apply only where the CLI did not toggle the flag
  * --no-sarif / --no-pdf / --no-pentest-tasks / --no-sca override
    preset-enabled outputs
  * --org-profile + --no-org-profile cancel out
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "resolve_config.py"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "org-profiles" / "acme" / "org-profile.yaml"


def _load_module():
    if "resolve_config" in sys.modules:
        return sys.modules["resolve_config"]
    spec = importlib.util.spec_from_file_location("resolve_config", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["resolve_config"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rc = _load_module()


def _resolve(argv: list[str]) -> dict:
    return rc.resolve(argv, REPO_ROOT)


def test_resolve_without_org_profile_keeps_inactive_block():
    cfg = _resolve(["--output", "/tmp/null", "auth"])
    assert cfg["org_profile"]["active"] is False
    assert cfg["preset"] is None
    assert cfg["org_profile_defaults"] == {}


def test_org_profile_activation_via_cli(tmp_path):
    cfg = _resolve(["--org-profile", str(FIXTURE), "--output", str(tmp_path), "auth"])
    assert cfg["org_profile"]["active"] is True
    assert cfg["preset"]["name"] == "ci-standard"
    # ci-standard preset enables sarif by default; CLI didn't pass --sarif
    # so the preset default applies.
    assert cfg["write_sarif"] is True


def test_no_sarif_overrides_preset(tmp_path):
    cfg = _resolve([
        "--org-profile", str(FIXTURE),
        "--preset", "release-review",
        "--no-sarif",
        "--output", str(tmp_path),
        "auth",
    ])
    assert cfg["org_profile"]["active"] is True
    assert cfg["preset"]["name"] == "release-review"
    # release-review enables sarif/pdf/pentest_tasks; --no-sarif still wins.
    assert cfg["write_sarif"] is False


def test_no_pentest_tasks_overrides_preset(tmp_path):
    cfg = _resolve([
        "--org-profile", str(FIXTURE),
        "--preset", "release-review",
        "--no-pentest-tasks",
        "--output", str(tmp_path),
        "auth",
    ])
    assert cfg["write_pentest_tasks"] is False


def test_no_org_profile_disables_active_profile(tmp_path):
    cfg = _resolve([
        "--org-profile", str(FIXTURE),
        "--no-org-profile",
        "--output", str(tmp_path),
        "auth",
    ])
    assert cfg["org_profile"]["active"] is False


def test_cli_required_preset_without_repo_fails(tmp_path):
    with pytest.raises(SystemExit):
        _resolve([
            "--org-profile", str(FIXTURE),
            "--preset", "appsec-verification",
            "--output", str(tmp_path),
            "auth",
        ])


def test_unknown_preset_fails(tmp_path):
    with pytest.raises(SystemExit):
        _resolve([
            "--org-profile", str(FIXTURE),
            "--preset", "ghost-preset",
            "--output", str(tmp_path),
            "auth",
        ])


def test_emit_file_writes_org_profile_effective(tmp_path):
    rc_code = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--org-profile",
            str(FIXTURE),
            "--output",
            str(tmp_path),
            "--emit-file",
            "auth",
        ],
        capture_output=True,
        text=True,
    )
    assert rc_code.returncode == 0, rc_code.stderr
    emitted = tmp_path / ".org-profile-effective.json"
    assert emitted.exists()
    data = json.loads(emitted.read_text())
    assert data["org_profile"]["active"] is True
    assert data["preset"]["name"] == "ci-standard"


def test_validate_only_accepts_documented_skill_flags(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--validate-only",
            "--pdf",
            "--max-resumes",
            "2",
            "--clean-cache",
            "--no-sarif",
            "--no-pdf",
            "--no-pentest-tasks",
            "--no-sca",
            "--no-org-profile",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
