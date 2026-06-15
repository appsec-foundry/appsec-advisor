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

    def test_plugin_root_skips_requirements_config_when_skill_removed(self, validate_config, tmp_path: Path):
        (tmp_path / "config.json").write_text('{"external_context": {"enabled": false, "rest_url": null}}\n')
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


# ---------------------------------------------------------------------------
# Extra main-config branch coverage
# ---------------------------------------------------------------------------


class TestMainConfigExtraBranches:
    def test_external_context_not_object(self, validate_config):
        errors = validate_config._validate_main_config({"external_context": "x"}, "test")
        assert any("'external_context' must be an object" in e for e in errors)

    def test_external_context_missing_enabled_and_rest_url(self, validate_config):
        errors = validate_config._validate_main_config({"external_context": {}}, "test")
        assert any("'external_context.enabled' is required" in e for e in errors)
        assert any("'external_context.rest_url' is required" in e for e in errors)

    def test_rest_url_wrong_type(self, validate_config):
        data = {"external_context": {"enabled": True, "rest_url": 123}}
        errors = validate_config._validate_main_config(data, "test")
        assert any("'external_context.rest_url' must be a string or null" in e for e in errors)

    def test_pricing_not_object(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "pricing": "x",
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'pricing' must be an object" in e for e in errors)

    def test_logging_not_object(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "logging": "x",
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'logging' must be an object" in e for e in errors)

    def test_logging_max_bytes_not_int(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "logging": {"max_log_bytes": "big"},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'logging.max_log_bytes' must be an integer" in e for e in errors)

    def test_logging_verbose_not_bool(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "logging": {"verbose": "yes"},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'logging.verbose' must be a boolean" in e for e in errors)

    def test_organization_profile_not_object(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": "x",
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'organization_profile' must be an object" in e for e in errors)

    def test_organization_profile_missing_enabled(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {"path": None},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'organization_profile.enabled' is required" in e for e in errors)

    def test_organization_profile_path_wrong_type(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {"enabled": False, "path": 5},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'organization_profile.path' must be a string or null" in e for e in errors)

    def test_organization_profile_default_preset_wrong_type(self, validate_config):
        data = {
            "external_context": {"enabled": False, "rest_url": None},
            "organization_profile": {"enabled": False, "path": None, "default_preset": 9},
        }
        errors = validate_config._validate_main_config(data, "test")
        assert any("'organization_profile.default_preset' must be a string or null" in e for e in errors)


class TestRequirementsConfigExtraBranches:
    def test_requirements_source_not_object(self, validate_config):
        errors = validate_config._validate_requirements_config({"requirements_source": "x"}, "test")
        assert any("'requirements_source' must be an object" in e for e in errors)

    def test_enabled_missing(self, validate_config):
        data = {"requirements_source": {"requirements_yaml_url": None}}
        errors = validate_config._validate_requirements_config(data, "test")
        assert any("'requirements_source.enabled' is required" in e for e in errors)

    def test_enabled_not_bool(self, validate_config):
        data = {"requirements_source": {"enabled": "yes", "requirements_yaml_url": None}}
        errors = validate_config._validate_requirements_config(data, "test")
        assert any("'requirements_source.enabled' must be a boolean" in e for e in errors)

    def test_url_key_missing(self, validate_config):
        data = {"requirements_source": {"enabled": False}}
        errors = validate_config._validate_requirements_config(data, "test")
        assert any("requirements_yaml_url' is required" in e for e in errors)

    def test_url_wrong_type(self, validate_config):
        data = {"requirements_source": {"enabled": False, "requirements_yaml_url": 5}}
        errors = validate_config._validate_requirements_config(data, "test")
        assert any("requirements_yaml_url' must be a string or null" in e for e in errors)


# ---------------------------------------------------------------------------
# validate_plugin_root — file IO / JSON-error branches
# ---------------------------------------------------------------------------


class TestValidatePluginRoot:
    def test_missing_main_config(self, validate_config, tmp_path: Path):
        errors = validate_config.validate_plugin_root(tmp_path)
        assert any("config.json" in e and "file not found" in e for e in errors)

    def test_main_config_invalid_json(self, validate_config, tmp_path: Path):
        (tmp_path / "config.json").write_text("{not json", encoding="utf-8")
        errors = validate_config.validate_plugin_root(tmp_path)
        assert any("invalid JSON" in e for e in errors)

    def test_requirements_skill_present_config_missing(self, validate_config, tmp_path: Path):
        (tmp_path / "config.json").write_text(
            '{"external_context": {"enabled": false, "rest_url": null}}', encoding="utf-8"
        )
        skill_dir = tmp_path / "skills" / "audit-security-requirements"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# skill", encoding="utf-8")
        errors = validate_config.validate_plugin_root(tmp_path)
        assert any("config.json" in e and "file not found" in e for e in errors)

    def test_requirements_config_invalid_json(self, validate_config, tmp_path: Path):
        (tmp_path / "config.json").write_text(
            '{"external_context": {"enabled": false, "rest_url": null}}', encoding="utf-8"
        )
        skill_dir = tmp_path / "skills" / "audit-security-requirements"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# skill", encoding="utf-8")
        (skill_dir / "config.json").write_text("{bad", encoding="utf-8")
        errors = validate_config.validate_plugin_root(tmp_path)
        assert any("invalid JSON" in e for e in errors)

    def test_valid_full_plugin_root(self, validate_config, tmp_path: Path):
        (tmp_path / "config.json").write_text(
            '{"external_context": {"enabled": false, "rest_url": null}}', encoding="utf-8"
        )
        skill_dir = tmp_path / "skills" / "audit-security-requirements"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# skill", encoding="utf-8")
        (skill_dir / "config.json").write_text(
            '{"requirements_source": {"enabled": false, "requirements_yaml_url": null}}',
            encoding="utf-8",
        )
        assert validate_config.validate_plugin_root(tmp_path) == []


# ---------------------------------------------------------------------------
# _validate_yaml_against_schema
# ---------------------------------------------------------------------------


class TestValidateYamlAgainstSchema:
    def test_data_file_not_found(self, validate_config, tmp_path: Path):
        errors = validate_config._validate_yaml_against_schema(
            tmp_path / "data.yaml", tmp_path / "schema.yaml"
        )
        assert any("file not found" in e for e in errors)

    def test_schema_file_not_found(self, validate_config, tmp_path: Path):
        data = tmp_path / "data.yaml"
        data.write_text("a: 1\n", encoding="utf-8")
        errors = validate_config._validate_yaml_against_schema(data, tmp_path / "schema.yaml")
        assert any("schema file not found" in e for e in errors)

    def test_valid_yaml_passes_schema(self, validate_config, tmp_path: Path):
        data = tmp_path / "data.yaml"
        schema = tmp_path / "schema.yaml"
        data.write_text("name: hi\ncount: 3\n", encoding="utf-8")
        schema.write_text(
            "type: object\n"
            "properties:\n"
            "  name: {type: string}\n"
            "  count: {type: integer}\n"
            "required: [name, count]\n",
            encoding="utf-8",
        )
        assert validate_config._validate_yaml_against_schema(data, schema) == []

    def test_yaml_violates_schema(self, validate_config, tmp_path: Path):
        data = tmp_path / "data.yaml"
        schema = tmp_path / "schema.yaml"
        # count should be integer, give a string
        data.write_text("name: hi\ncount: not-a-number\n", encoding="utf-8")
        schema.write_text(
            "type: object\n"
            "properties:\n"
            "  count: {type: integer}\n"
            "required: [count]\n",
            encoding="utf-8",
        )
        errors = validate_config._validate_yaml_against_schema(data, schema)
        assert errors
        assert any("count" in e for e in errors)

    def test_invalid_data_yaml(self, validate_config, tmp_path: Path):
        data = tmp_path / "data.yaml"
        schema = tmp_path / "schema.yaml"
        data.write_text("a: [unterminated\n", encoding="utf-8")
        schema.write_text("type: object\n", encoding="utf-8")
        errors = validate_config._validate_yaml_against_schema(data, schema)
        assert any("invalid YAML" in e for e in errors)

    def test_invalid_schema_yaml(self, validate_config, tmp_path: Path):
        data = tmp_path / "data.yaml"
        schema = tmp_path / "schema.yaml"
        data.write_text("a: 1\n", encoding="utf-8")
        schema.write_text("type: [unterminated\n", encoding="utf-8")
        errors = validate_config._validate_yaml_against_schema(data, schema)
        assert any("invalid YAML schema" in e for e in errors)

    def test_invalid_json_schema_itself(self, validate_config, tmp_path: Path):
        data = tmp_path / "data.yaml"
        schema = tmp_path / "schema.yaml"
        data.write_text("a: 1\n", encoding="utf-8")
        # 'type' must be a string/array of strings, not an integer
        schema.write_text("type: 12345\n", encoding="utf-8")
        errors = validate_config._validate_yaml_against_schema(data, schema)
        assert any("invalid JSON Schema" in e for e in errors)


# ---------------------------------------------------------------------------
# main() — CLI entry point
# ---------------------------------------------------------------------------


class TestMainCli:
    def test_main_valid_exits_0(self, run_plugin_script, tmp_path: Path):
        (tmp_path / "config.json").write_text(
            '{"external_context": {"enabled": false, "rest_url": null}}', encoding="utf-8"
        )
        result = run_plugin_script("validate_config.py", str(tmp_path), check=False)
        assert result.returncode == 0
        assert "VALID:" in result.stdout

    def test_main_invalid_exits_1(self, run_plugin_script, tmp_path: Path):
        # missing config.json → file not found error → exit 1
        result = run_plugin_script("validate_config.py", str(tmp_path), check=False)
        assert result.returncode == 1
        assert "INVALID:" in result.stdout

    def test_main_uses_env_var(self, run_plugin_script, tmp_path: Path):
        (tmp_path / "config.json").write_text(
            '{"external_context": {"enabled": false, "rest_url": null}}', encoding="utf-8"
        )
        result = run_plugin_script(
            "validate_config.py", env={"CLAUDE_PLUGIN_ROOT": str(tmp_path)}, check=False
        )
        assert result.returncode == 0
        assert "VALID:" in result.stdout
