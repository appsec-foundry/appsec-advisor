"""Tests for scripts/validate_org_profile.py.

Validates the bundled fixture profile, then exercises each semantic rule
through tiny mutations on a deep-copied dict instead of writing many YAML
fixtures by hand.
"""
from __future__ import annotations

import copy
import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_org_profile.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "org-profiles" / "acme"
FIXTURE_PATH = FIXTURE_DIR / "org-profile.yaml"


def _load_module():
    if "validate_org_profile" in sys.modules:
        return sys.modules["validate_org_profile"]
    spec = importlib.util.spec_from_file_location("validate_org_profile", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["validate_org_profile"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


vop = _load_module()


@pytest.fixture
def acme_profile() -> dict:
    return vop._load_yaml(FIXTURE_PATH)


def test_valid_org_profile_fixture_passes(acme_profile):
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert errors == [], errors


def test_default_preset_must_exist(acme_profile):
    acme_profile["default_preset"] = "no-such-preset"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("default_preset" in e for e in errors), errors


def test_unknown_top_level_key_fails(acme_profile):
    acme_profile["surprise_block"] = {"any": "value"}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("surprise_block" in e for e in errors), errors


def test_unknown_preset_key_fails(acme_profile):
    acme_profile["presets"]["ci-standard"]["mystery"] = True
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("mystery" in e for e in errors), errors


def test_context_path_must_stay_under_profile_dir(acme_profile):
    acme_profile["llm_context"]["documents"][0]["path"] = "../../../etc/passwd"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("outside" in e for e in errors), errors


def test_context_absolute_path_rejected(acme_profile):
    acme_profile["llm_context"]["documents"][0]["path"] = "/etc/passwd"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("relative" in e for e in errors), errors


def test_context_symlink_escape_fails(tmp_path, acme_profile):
    # Copy fixture into a tmp dir, then plant a symlink that points
    # outside it and reference it from llm_context.documents.
    profile_dir = tmp_path / "profile"
    (profile_dir / "context").mkdir(parents=True)
    (profile_dir / "context" / "leak.md").symlink_to("/etc/hostname")
    acme_profile["llm_context"]["documents"].append(
        {"id": "leak", "path": "context/leak.md", "purpose": "other"}
    )
    errors = vop.validate(acme_profile, profile_dir)
    assert any("symlink" in e or "outside" in e for e in errors), errors


def test_preset_context_document_ids_must_exist(acme_profile):
    acme_profile["presets"]["appsec-verification"]["context"]["document_ids"].append(
        "ghost"
    )
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("ghost" in e for e in errors), errors


def test_target_profile_default_requires_repo_path(acme_profile):
    acme_profile["presets"]["release-review"]["target"] = {"repo": "profile_default"}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("profile_default" in e for e in errors), errors


def test_output_dir_unknown_token_rejected(acme_profile):
    acme_profile["presets"]["appsec-verification"]["target"]["output_dir"] = (
        "../{secret_token}"
    )
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("secret_token" in e for e in errors), errors


def test_output_dir_with_git_component_rejected(acme_profile):
    acme_profile["presets"]["release-review"]["target"]["output_dir"] = (
        ".git/something"
    )
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any(".git" in e for e in errors), errors


def test_requirements_url_with_credentials_rejected(acme_profile):
    acme_profile["requirements"]["source"]["requirements_yaml_url"] = (
        "https://user:secret@example.test/x.yaml"
    )
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("credentials" in e for e in errors), errors


def test_skill_toggle_unknown_skill_rejected(acme_profile):
    acme_profile["skill_toggles"]["not-a-skill"] = True
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("not-a-skill" in e for e in errors), errors


def test_skill_toggle_disabled_requires_reason(acme_profile):
    acme_profile["skill_toggles"]["export-threat-model"] = {"enabled": False}
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("reason" in e for e in errors), errors


def test_compatibility_accepts_current_plugin_version(acme_profile):
    # Fixture uses ">=0.0 <999.0" which always accepts the local plugin.
    errors = vop.validate(acme_profile, FIXTURE_DIR, plugin_version="0.9.0-beta")
    assert errors == [], errors


def test_compatibility_rejects_unsupported_core(acme_profile):
    acme_profile["compatibility"]["core"] = ">=99.0"
    errors = vop.validate(acme_profile, FIXTURE_DIR, plugin_version="0.9.0-beta")
    assert any("compatibility" in e for e in errors), errors


def test_api_version_const_enforced(acme_profile):
    acme_profile["api_version"] = "appsec-advisor.org-profile/v2"
    errors = vop.validate(acme_profile, FIXTURE_DIR)
    assert any("api_version" in e for e in errors), errors


def test_validator_returns_nonzero_on_errors(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("api_version: wrong\n")
    rc = vop.main([str(bad)])
    assert rc == 1


def test_validator_returns_zero_on_success():
    rc = vop.main([str(FIXTURE_PATH), "--plugin-version", "0.9.0-beta"])
    assert rc == 0
