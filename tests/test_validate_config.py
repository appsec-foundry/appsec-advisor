"""Unit tests for scripts/validate_config.py.

The validator is exercised by the integration test suite end-to-end, but the
schema rules themselves were never directly tested. These cases lock in the
contract for future config schema changes.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

VALIDATE_CONFIG_PATH = Path(__file__).parent.parent / "scripts" / "validate_config.py"


@pytest.fixture(scope="module")
def validate_config():
    """Import scripts/validate_config.py as a module."""
    spec = importlib.util.spec_from_file_location("validate_config", VALIDATE_CONFIG_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_config"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Main plugin config (config.json)
# ---------------------------------------------------------------------------


class TestMainConfig:
    def test_minimal_valid(self, validate_config):
        data = {"external_context": {"enabled": False, "rest_url": None}}
        assert validate_config._validate_main_config(data, "test") == []

    def test_full_valid(self, validate_config):
        data = {
            "external_context": {
                "enabled": True,
                "rest_url": "https://ctx.example.com/api",
            },
            "pricing": {
                "input_per_1m": 3.0,
                "output_per_1m": 15.0,
                "cache_write_per_1m": 3.75,
                "cache_read_per_1m": 0.30,
            },
            "logging": {"max_log_bytes": 5_000_000, "verbose": False},
        }
        assert validate_config._validate_main_config(data, "test") == []

    def test_root_must_be_object(self, validate_config):
        errors = validate_config._validate_main_config([], "test")
        assert any("root must be a JSON object" in e for e in errors)

    def test_external_context_required(self, validate_config):
        errors = validate_config._validate_main_config({}, "test")
        assert any("missing required key 'external_context'" in e for e in errors)

    def test_enabled_must_be_bool(self, validate_config):
        data = {"external_context": {"enabled": "yes", "rest_url": None}}
        errors = validate_config._validate_main_config(data, "test")
        assert any("'external_context.enabled' must be a boolean" in e for e in errors)

    def test_rest_url_must_be_http(self, validate_config):
        data = {"external_context": {"enabled": True, "rest_url": "ftp://x.invalid"}}
        errors = validate_config._validate_main_config(data, "test")
        assert any("must be a valid http:// or https:// URL" in e for e in errors)

    def test_rest_url_null_ok_when_disabled(self, validate_config):
        data = {"external_context": {"enabled": False, "rest_url": None}}
        assert validate_config._validate_main_config(data, "test") == []

    def test_pricing_must_be_numeric(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "pricing": {"input_per_1m": "free"},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'pricing.input_per_1m' must be a number" in e for e in errors)

    def test_pricing_must_be_non_negative(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "pricing": {"output_per_1m": -1.0},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("must be non-negative" in e for e in errors)

    def test_logging_max_bytes_too_small(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "logging": {"max_log_bytes": 100},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("must be at least 1024" in e for e in errors)

    def test_unknown_top_level_key_rejected(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "totally_made_up": {},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("unknown top-level keys" in e for e in errors)

    def test_organization_profile_disabled_ok(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {
                "enabled": False,
                "path": None,
                "default_preset": None,
            },
        }
        assert validate_config._validate_main_config(data, "test") == []

    def test_organization_profile_enabled_requires_path(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {"enabled": True, "path": None},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'path' is null" in e for e in errors), errors

    def test_organization_profile_enabled_must_be_bool(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {"enabled": "yes", "path": "x"},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("enabled' must be a boolean" in e for e in errors), errors

    def test_organization_profile_unknown_subkey_rejected(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {
                "enabled": False,
                "path": None,
                "default_preset": None,
                "extra_field": "?",
            },
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("unknown keys in 'organization_profile'" in e for e in errors), errors


# ---------------------------------------------------------------------------
# Requirements skill config
# ---------------------------------------------------------------------------


class TestRequirementsConfig:
    def test_minimal_valid_disabled(self, validate_config):
        data = {"requirements_source": {"enabled": False, "requirements_yaml_url": None}}
        assert validate_config._validate_requirements_config(data, "test") == []

    def test_valid_with_url(self, validate_config):
        data = {
            "requirements_source": {
                "enabled": True,
                "requirements_yaml_url": "https://req.example.com/r.yaml",
            }
        }
        assert validate_config._validate_requirements_config(data, "test") == []

    def test_requirements_source_required(self, validate_config):
        errors = validate_config._validate_requirements_config({}, "test")
        assert any("missing required key 'requirements_source'" in e for e in errors)

    def test_enabled_true_without_url_warns(self, validate_config):
        data = {"requirements_source": {"enabled": True, "requirements_yaml_url": None}}
        errors = validate_config._validate_requirements_config(data, "test")
        assert any("enabled' is true but" in e for e in errors)

    def test_invalid_url_scheme(self, validate_config):
        data = {
            "requirements_source": {
                "enabled": True,
                "requirements_yaml_url": "file:///etc/passwd",
            }
        }
        errors = validate_config._validate_requirements_config(data, "test")
        assert any("must be a valid http:// or https:// URL" in e for e in errors)

    def test_plugin_root_skips_requirements_config_when_skill_removed(
        self, validate_config, tmp_path: Path
    ):
        (tmp_path / "config.json").write_text(
            '{"external_context": {"enabled": false, "rest_url": null}}\n'
        )
        errors = validate_config.validate_plugin_root(tmp_path)
        assert errors == []


# ---------------------------------------------------------------------------
# Real-world: the actual plugin configs must validate cleanly
# ---------------------------------------------------------------------------


class TestRealWorldConfigs:
    def test_actual_plugin_config_passes(self, validate_config):
        plugin_config = Path(__file__).parent.parent / "config.json"
        if not plugin_config.exists():
            pytest.skip("config.json not present in this checkout")
        import json

        with plugin_config.open() as fh:
            data = json.load(fh)
        errors = validate_config._validate_main_config(data, str(plugin_config))
        assert errors == [], f"Real config.json failed validation: {errors}"

    def test_actual_requirements_config_passes(self, validate_config):
        req_config = Path(__file__).parent.parent / "skills" / "audit-security-requirements" / "config.json"
        if not req_config.exists():
            pytest.skip("requirements skill config not present in this checkout")
        import json

        with req_config.open() as fh:
            data = json.load(fh)
        errors = validate_config._validate_requirements_config(data, str(req_config))
        assert errors == [], f"Real requirements config failed validation: {errors}"
