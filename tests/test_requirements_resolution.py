"""
Tests for requirements flag resolution logic.

Validates all combinations of config (enabled, requirements_yaml_url)
and CLI flags (--with-requirements, --ignore-requirements, --requirements-url)
as defined in skills/create-threat-model/SKILL.md and
skills/check-appsec-requirements/SKILL.md.

Uses examples/appsec-requirements-example.yaml as a fixture for URL-based tests.
"""

from __future__ import annotations

import json
import shutil
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from threading import Thread
from typing import Any

import pytest
import yaml

PLUGIN_DIR = Path(__file__).parent.parent / "plugin"
EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
REQUIREMENTS_EXAMPLE = EXAMPLES_DIR / "appsec-requirements-example.yaml"
REQUIREMENTS_CONFIG = PLUGIN_DIR / "skills" / "check-appsec-requirements" / "config.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_config() -> dict[str, Any]:
    """Load the requirements skill config."""
    return json.loads(REQUIREMENTS_CONFIG.read_text())


def resolve_check_requirements(
    *,
    config_enabled: bool,
    flag_with_requirements: bool = False,
    flag_ignore_requirements: bool = False,
    flag_requirements_url: str | None = None,
    flag_requirements_deprecated: bool = False,
) -> tuple[bool, str | None, str | None]:
    """
    Pure-logic implementation of the CHECK_REQUIREMENTS resolution
    as specified in create-threat-model/SKILL.md.

    Returns:
        (CHECK_REQUIREMENTS, REQUIREMENTS_URL_OVERRIDE, error_message)
    """
    # Conflict detection
    ignore = flag_ignore_requirements
    enable = flag_with_requirements or flag_requirements_deprecated

    if ignore and enable:
        return False, None, "Conflicting flags: --with-requirements and --ignore-requirements cannot be used together."

    if ignore and flag_requirements_url:
        return False, None, "Conflicting flags: --requirements-url and --ignore-requirements cannot be used together."

    # Resolution order (first match wins)
    if flag_ignore_requirements:
        return False, None, None

    if flag_with_requirements or flag_requirements_deprecated:
        return True, flag_requirements_url, None

    if flag_requirements_url:
        return True, flag_requirements_url, None

    if config_enabled:
        return True, None, None

    return False, None, None


# ---------------------------------------------------------------------------
# Config defaults
# ---------------------------------------------------------------------------

class TestConfigDefaults:
    """Verify the shipped config has the expected defaults."""

    def test_config_exists(self):
        assert REQUIREMENTS_CONFIG.exists()

    def test_enabled_defaults_to_false(self):
        cfg = load_config()
        assert cfg["requirements_source"]["enabled"] is False, (
            "Default 'enabled' must be false — threat models should not "
            "include requirements checks unless explicitly configured."
        )

    def test_url_defaults_to_null(self):
        cfg = load_config()
        assert cfg["requirements_source"]["requirements_yaml_url"] is None


# ---------------------------------------------------------------------------
# Flag resolution: enabled=false (default)
# ---------------------------------------------------------------------------

class TestResolutionEnabledFalse:
    """Config enabled=false — requirements off by default."""

    def test_no_flags(self):
        check, url, err = resolve_check_requirements(config_enabled=False)
        assert check is False
        assert url is None
        assert err is None

    def test_with_requirements_flag(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False, flag_with_requirements=True
        )
        assert check is True
        assert url is None
        assert err is None

    def test_ignore_requirements_flag_is_redundant_no_error(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False, flag_ignore_requirements=True
        )
        assert check is False
        assert err is None

    def test_requirements_url_implies_check(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements_url="http://localhost:8000/req.yaml",
        )
        assert check is True
        assert url == "http://localhost:8000/req.yaml"
        assert err is None

    def test_deprecated_requirements_flag(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False, flag_requirements_deprecated=True
        )
        assert check is True
        assert err is None


# ---------------------------------------------------------------------------
# Flag resolution: enabled=true
# ---------------------------------------------------------------------------

class TestResolutionEnabledTrue:
    """Config enabled=true — requirements on by default."""

    def test_no_flags_enables_check(self):
        check, url, err = resolve_check_requirements(config_enabled=True)
        assert check is True
        assert url is None
        assert err is None

    def test_ignore_requirements_overrides_config(self):
        check, url, err = resolve_check_requirements(
            config_enabled=True, flag_ignore_requirements=True
        )
        assert check is False
        assert err is None

    def test_with_requirements_is_redundant_no_error(self):
        check, url, err = resolve_check_requirements(
            config_enabled=True, flag_with_requirements=True
        )
        assert check is True
        assert err is None

    def test_requirements_url_overrides_config_url(self):
        check, url, err = resolve_check_requirements(
            config_enabled=True,
            flag_requirements_url="http://custom:9000/req.yaml",
        )
        assert check is True
        assert url == "http://custom:9000/req.yaml"
        assert err is None

    def test_with_requirements_and_url_together(self):
        check, url, err = resolve_check_requirements(
            config_enabled=True,
            flag_with_requirements=True,
            flag_requirements_url="http://custom:9000/req.yaml",
        )
        assert check is True
        assert url == "http://custom:9000/req.yaml"
        assert err is None


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------

class TestConflicts:
    """Conflicting flag combinations must produce errors."""

    def test_with_and_ignore_conflict(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_with_requirements=True,
            flag_ignore_requirements=True,
        )
        assert err is not None
        assert "Conflicting" in err

    def test_url_and_ignore_conflict(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements_url="http://localhost/r.yaml",
            flag_ignore_requirements=True,
        )
        assert err is not None
        assert "Conflicting" in err

    def test_deprecated_and_ignore_conflict(self):
        check, url, err = resolve_check_requirements(
            config_enabled=True,
            flag_requirements_deprecated=True,
            flag_ignore_requirements=True,
        )
        assert err is not None
        assert "Conflicting" in err

    def test_with_requirements_and_url_is_not_a_conflict(self):
        """Both say 'check' — they differ only in source."""
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_with_requirements=True,
            flag_requirements_url="http://localhost/r.yaml",
        )
        assert err is None
        assert check is True
        assert url == "http://localhost/r.yaml"


# ---------------------------------------------------------------------------
# Requirements YAML fixture validity
# ---------------------------------------------------------------------------

class TestRequirementsFixture:
    """Verify the example requirements file is usable as a test fixture."""

    def test_example_file_exists(self):
        assert REQUIREMENTS_EXAMPLE.exists(), (
            f"Example requirements file not found: {REQUIREMENTS_EXAMPLE}"
        )

    def test_example_is_valid_yaml(self):
        data = yaml.safe_load(REQUIREMENTS_EXAMPLE.read_text())
        assert isinstance(data, dict)

    def test_example_has_categories_with_requirements(self):
        data = yaml.safe_load(REQUIREMENTS_EXAMPLE.read_text())
        cats = data.get("categories", [])
        assert len(cats) > 0, "Example must have at least one category"
        for cat in cats:
            reqs = cat.get("requirements", [])
            assert len(reqs) > 0, f"Category {cat.get('id')} has no requirements"

    def test_example_requirements_have_required_fields(self):
        data = yaml.safe_load(REQUIREMENTS_EXAMPLE.read_text())
        for cat in data["categories"]:
            for req in cat["requirements"]:
                assert "id" in req, f"Requirement missing 'id' in {cat['id']}"
                assert "text" in req, f"Requirement {req.get('id')} missing 'text'"
                assert "priority" in req, f"Requirement {req.get('id')} missing 'priority'"
                assert req["priority"] in {"MUST", "SHOULD", "MAY"}, (
                    f"Requirement {req['id']} has invalid priority: {req['priority']}"
                )


# ---------------------------------------------------------------------------
# Config validation: enabled=true + url=null warning
# ---------------------------------------------------------------------------

class TestConfigValidation:
    """validate_config.py must flag enabled=true with no URL."""

    def test_enabled_true_without_url_produces_error(self):
        """Import and call the validator directly."""
        import sys
        sys.path.insert(0, str(PLUGIN_DIR / "scripts"))
        from validate_config import _validate_requirements_config

        config = {
            "requirements_source": {
                "enabled": True,
                "requirements_yaml_url": None,
            }
        }
        errors = _validate_requirements_config(config, "test")
        assert any("enabled" in e and "null" in e for e in errors), (
            f"Expected warning about enabled=true + url=null, got: {errors}"
        )

    def test_enabled_false_without_url_is_valid(self):
        import sys
        sys.path.insert(0, str(PLUGIN_DIR / "scripts"))
        from validate_config import _validate_requirements_config

        config = {
            "requirements_source": {
                "enabled": False,
                "requirements_yaml_url": None,
            }
        }
        errors = _validate_requirements_config(config, "test")
        assert len(errors) == 0, f"Unexpected errors: {errors}"

    def test_enabled_true_with_url_is_valid(self):
        import sys
        sys.path.insert(0, str(PLUGIN_DIR / "scripts"))
        from validate_config import _validate_requirements_config

        config = {
            "requirements_source": {
                "enabled": True,
                "requirements_yaml_url": "http://localhost:8000/req.yaml",
            }
        }
        errors = _validate_requirements_config(config, "test")
        assert len(errors) == 0, f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# Loading path behavior (documented contracts)
# ---------------------------------------------------------------------------

class TestLoadingPathContracts:
    """
    These tests verify the documented loading-path contracts
    without actually fetching URLs. They test the DECISION logic,
    not the network behavior.
    """

    def test_url_override_means_no_cache_fallback(self):
        """When --requirements-url is set, cache fallback is not allowed."""
        # The contract: REQUIREMENTS_URL_OVERRIDE set → fetch or abort.
        # We test the resolution produces a URL override.
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements_url="http://example.com/custom.yaml",
        )
        assert check is True
        assert url == "http://example.com/custom.yaml"
        # The presence of url means the context-resolver must use Path A
        # (no cache fallback). This is a structural guarantee.

    def test_config_url_allows_cache_fallback(self):
        """When enabled=true without URL override, cache fallback is allowed."""
        check, url, err = resolve_check_requirements(
            config_enabled=True,
        )
        assert check is True
        assert url is None
        # url=None means the context-resolver uses Path B
        # (config URL → cache → abort). Cache fallback is allowed.

    def test_with_requirements_flag_allows_cache_fallback(self):
        """--with-requirements without --requirements-url allows cache fallback."""
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_with_requirements=True,
        )
        assert check is True
        assert url is None
        # Same as above: Path B with cache fallback.


# ---------------------------------------------------------------------------
# Skill applicability
# ---------------------------------------------------------------------------

class TestSkillApplicability:
    """
    --ignore-requirements and --with-requirements are only for
    create-threat-model. The check-appsec-requirements skill always
    loads requirements (it IS a requirements check).
    """

    def test_check_skill_has_no_ignore_flag(self):
        """Verify SKILL.md does not define --ignore-requirements."""
        skill_md = PLUGIN_DIR / "skills" / "check-appsec-requirements" / "SKILL.md"
        content = skill_md.read_text()
        assert "--ignore-requirements" not in content, (
            "check-appsec-requirements must not support --ignore-requirements"
        )

    def test_check_skill_has_no_with_requirements_flag(self):
        """Verify SKILL.md does not define --with-requirements."""
        skill_md = PLUGIN_DIR / "skills" / "check-appsec-requirements" / "SKILL.md"
        content = skill_md.read_text()
        assert "--with-requirements" not in content, (
            "check-appsec-requirements must not support --with-requirements"
        )

    def test_check_skill_supports_requirements_url(self):
        """Verify SKILL.md defines --requirements-url."""
        skill_md = PLUGIN_DIR / "skills" / "check-appsec-requirements" / "SKILL.md"
        content = skill_md.read_text()
        assert "--requirements-url" in content

    def test_create_skill_supports_all_three_flags(self):
        """Verify create-threat-model SKILL.md defines all requirement flags."""
        skill_md = PLUGIN_DIR / "skills" / "create-threat-model" / "SKILL.md"
        content = skill_md.read_text()
        assert "--with-requirements" in content
        assert "--ignore-requirements" in content
        assert "--requirements-url" in content


# ---------------------------------------------------------------------------
# Context-resolver contract
# ---------------------------------------------------------------------------

class TestContextResolverContract:
    """
    Verify the context-resolver agent definition documents
    the correct loading paths.
    """

    def test_context_resolver_has_path_a_and_b(self):
        agent_md = PLUGIN_DIR / "agents" / "appsec-context-resolver.md"
        content = agent_md.read_text()
        assert "Path A" in content, "Context-resolver must document Path A (URL override)"
        assert "Path B" in content, "Context-resolver must document Path B (config URL)"

    def test_context_resolver_accepts_requirements_url_override(self):
        agent_md = PLUGIN_DIR / "agents" / "appsec-context-resolver.md"
        content = agent_md.read_text()
        assert "REQUIREMENTS_URL_OVERRIDE" in content

    def test_context_resolver_skip_when_check_false(self):
        agent_md = PLUGIN_DIR / "agents" / "appsec-context-resolver.md"
        content = agent_md.read_text()
        assert "CHECK_REQUIREMENTS=false" in content.lower() or "skipped" in content.lower()

    def test_orchestrator_passes_url_override(self):
        agent_md = PLUGIN_DIR / "agents" / "appsec-threat-analyst.md"
        content = agent_md.read_text()
        assert "REQUIREMENTS_URL_OVERRIDE" in content


# ---------------------------------------------------------------------------
# Deprecated --requirements alias
# ---------------------------------------------------------------------------

class TestDeprecatedAlias:
    """The old --requirements flag should be documented as deprecated."""

    def test_deprecated_alias_documented(self):
        skill_md = PLUGIN_DIR / "skills" / "create-threat-model" / "SKILL.md"
        content = skill_md.read_text()
        assert "--requirements" in content, "Deprecated alias must still be mentioned"
        assert "deprecated" in content.lower() or "Deprecated" in content
