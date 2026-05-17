"""Tests for scripts/resolve_requirements_source.py."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "resolve_requirements_source.py"


def _load_module():
    if "resolve_requirements_source" in sys.modules:
        return sys.modules["resolve_requirements_source"]
    spec = importlib.util.spec_from_file_location(
        "resolve_requirements_source", SCRIPT_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["resolve_requirements_source"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rrs = _load_module()


PROFILE_RS = {
    "requirements_yaml_url": "https://security.example.test/x.yaml",
    "label": "Acme",
    "human_source_url": "https://wiki.example.test/x",
    "fail_mode": "cache_fallback",
    "cache": True,
    "create_threat_model": {"default_active": True, "quick_default_active": False},
    "standalone_audit": {"enabled": True},
}
EFFECTIVE = {"requirements_source": PROFILE_RS}
LEGACY = {"requirements_source": {"enabled": False, "requirements_yaml_url": None}}


def test_cli_url_wins():
    result = rrs.resolve(
        "https://cli.example.test/y.yaml",
        False,
        "standard",
        "create-threat-model",
        EFFECTIVE,
        LEGACY,
    )
    assert result["enabled"] is True
    assert result["url"] == "https://cli.example.test/y.yaml"
    assert result["source"] == "cli"


def test_no_requirements_wins_over_profile():
    result = rrs.resolve(
        None, True, "standard", "create-threat-model", EFFECTIVE, LEGACY
    )
    assert result["enabled"] is False
    assert result["source"] == "disabled"


def test_profile_used_when_no_cli_override():
    result = rrs.resolve(
        None, False, "standard", "create-threat-model", EFFECTIVE, LEGACY
    )
    assert result["enabled"] is True
    assert result["source"] == "org-profile"
    assert result["url"] == PROFILE_RS["requirements_yaml_url"]


def test_quick_default_inactive_disables_for_quick_mode():
    result = rrs.resolve(
        None, False, "quick", "create-threat-model", EFFECTIVE, LEGACY
    )
    assert result["enabled"] is False
    assert result["source"] == "org-profile"
    # URL stays present so status output can still show where it would
    # have come from; only enabled is gated.
    assert result["url"] == PROFILE_RS["requirements_yaml_url"]


def test_quick_default_active_enables_when_profile_allows():
    effective = {
        "requirements_source": {
            **PROFILE_RS,
            "create_threat_model": {"default_active": True, "quick_default_active": True},
        }
    }
    result = rrs.resolve(
        None, False, "quick", "create-threat-model", effective, LEGACY
    )
    assert result["enabled"] is True


def test_standalone_audit_respects_toggle():
    effective = {
        "requirements_source": {**PROFILE_RS, "standalone_audit": {"enabled": False}}
    }
    result = rrs.resolve(
        None, False, None, "check-appsec-requirements", effective, LEGACY
    )
    assert result["enabled"] is False


def test_legacy_fallback_when_no_profile_active():
    result = rrs.resolve(None, False, "standard", "create-threat-model", None, LEGACY)
    assert result["source"] == "legacy"
    assert result["enabled"] is False
