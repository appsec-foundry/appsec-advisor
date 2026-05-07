"""
Tests for requirements flag resolution logic.

Validates all combinations of config (enabled, requirements_yaml_url)
and CLI flags (--requirements [<url>], --no-requirements)
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

PLUGIN_DIR = Path(__file__).parent.parent
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
    flag_requirements: bool = False,
    flag_requirements_url: str | None = None,
    flag_no_requirements: bool = False,
    assessment_depth: str = "standard",
) -> tuple[bool, str | None, str | None]:
    """
    Pure-logic implementation of the CHECK_REQUIREMENTS resolution
    as specified in create-threat-model/SKILL.md.

    --requirements           → flag_requirements=True
    --requirements <url>     → flag_requirements=True, flag_requirements_url=<url>
    --no-requirements        → flag_no_requirements=True

    `assessment_depth` triggers the Sprint 1 Item E.1 post-depth override:
    at depth=quick, CHECK_REQUIREMENTS is forced off unless the user passed
    an explicit --requirements flag.

    Returns:
        (CHECK_REQUIREMENTS, REQUIREMENTS_URL_OVERRIDE, error_message)
    """
    # Conflict detection
    if flag_no_requirements and (flag_requirements or flag_requirements_url):
        return False, None, "Conflicting flags: --requirements and --no-requirements cannot be used together."

    # Resolution order (first match wins)
    if flag_no_requirements:
        return False, None, None

    if flag_requirements or flag_requirements_url:
        # Explicit opt-in always wins — even at quick depth.
        return True, flag_requirements_url, None

    if config_enabled:
        # Post-depth override: config-enabled auto-on is suppressed at quick depth.
        if assessment_depth == "quick":
            return False, None, None
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

    def test_requirements_flag(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False, flag_requirements=True
        )
        assert check is True
        assert url is None
        assert err is None

    def test_no_requirements_flag_is_redundant_no_error(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False, flag_no_requirements=True
        )
        assert check is False
        assert err is None

    def test_requirements_url_implies_check(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements=True,
            flag_requirements_url="http://localhost:8000/req.yaml",
        )
        assert check is True
        assert url == "http://localhost:8000/req.yaml"
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

    def test_no_requirements_overrides_config(self):
        check, url, err = resolve_check_requirements(
            config_enabled=True, flag_no_requirements=True
        )
        assert check is False
        assert err is None

    def test_requirements_flag_is_redundant_no_error(self):
        check, url, err = resolve_check_requirements(
            config_enabled=True, flag_requirements=True
        )
        assert check is True
        assert err is None

    def test_requirements_url_overrides_config_url(self):
        check, url, err = resolve_check_requirements(
            config_enabled=True,
            flag_requirements=True,
            flag_requirements_url="http://custom:9000/req.yaml",
        )
        assert check is True
        assert url == "http://custom:9000/req.yaml"
        assert err is None


# ---------------------------------------------------------------------------
# Depth-aware post-resolution override (Sprint 1 Item E.1)
# ---------------------------------------------------------------------------

class TestDepthOverride:
    """At --assessment-depth quick, config-enabled auto-on is suppressed.
    Explicit --requirements still wins. Explicit --no-requirements always wins."""

    def test_quick_depth_suppresses_config_auto_on(self):
        """Config enabled, no flags, quick depth → check must be off."""
        check, url, err = resolve_check_requirements(
            config_enabled=True, assessment_depth="quick"
        )
        assert check is False, (
            "quick depth should suppress config auto-on to avoid 53-requirement "
            "noise on ≤3-component scopes"
        )
        assert err is None

    def test_quick_depth_does_not_affect_explicit_opt_in(self):
        """--requirements explicitly passed → check is on even at quick depth."""
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements=True,
            assessment_depth="quick",
        )
        assert check is True
        assert err is None

    def test_quick_depth_does_not_affect_explicit_opt_in_with_config_enabled(self):
        """Even when config is enabled, explicit --requirements wins at quick."""
        check, url, err = resolve_check_requirements(
            config_enabled=True,
            flag_requirements=True,
            assessment_depth="quick",
        )
        assert check is True
        assert err is None

    def test_quick_depth_respects_explicit_opt_out(self):
        """--no-requirements at quick depth is still false (no-op)."""
        check, url, err = resolve_check_requirements(
            config_enabled=True,
            flag_no_requirements=True,
            assessment_depth="quick",
        )
        assert check is False
        assert err is None

    def test_standard_depth_does_not_suppress(self):
        """Override only fires at quick — standard still honors config."""
        check, url, err = resolve_check_requirements(
            config_enabled=True, assessment_depth="standard"
        )
        assert check is True
        assert err is None

    def test_thorough_depth_does_not_suppress(self):
        """Thorough also honors config."""
        check, url, err = resolve_check_requirements(
            config_enabled=True, assessment_depth="thorough"
        )
        assert check is True
        assert err is None


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------

class TestConflicts:
    """Conflicting flag combinations must produce errors."""

    def test_requirements_and_no_requirements_conflict(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements=True,
            flag_no_requirements=True,
        )
        assert err is not None
        assert "Conflicting" in err

    def test_url_and_no_requirements_conflict(self):
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements=True,
            flag_requirements_url="http://localhost/r.yaml",
            flag_no_requirements=True,
        )
        assert err is not None
        assert "Conflicting" in err


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
        """When --requirements <url> is set, cache fallback is not allowed."""
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements=True,
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

    def test_requirements_flag_allows_cache_fallback(self):
        """--requirements without URL allows cache fallback."""
        check, url, err = resolve_check_requirements(
            config_enabled=False,
            flag_requirements=True,
        )
        assert check is True
        assert url is None
        # Same as above: Path B with cache fallback.


# ---------------------------------------------------------------------------
# Skill applicability
# ---------------------------------------------------------------------------

class TestSkillApplicability:
    """
    --no-requirements and --requirements are only for
    create-threat-model. The check-appsec-requirements skill always
    loads requirements (it IS a requirements check).
    """

    def test_check_skill_has_no_no_requirements_flag(self):
        """Verify SKILL.md does not define --no-requirements."""
        skill_md = PLUGIN_DIR / "skills" / "check-appsec-requirements" / "SKILL.md"
        content = skill_md.read_text()
        assert "--no-requirements" not in content, (
            "check-appsec-requirements must not support --no-requirements"
        )

    def test_check_skill_supports_requirements_url(self):
        """Verify SKILL.md defines --requirements <url>."""
        skill_md = PLUGIN_DIR / "skills" / "check-appsec-requirements" / "SKILL.md"
        content = skill_md.read_text()
        assert "--requirements" in content

    def test_check_skill_links_to_final_finding_ids(self):
        """Requirements audit links must target rendered F-NNN anchors, not
        internal T-NNN ids."""
        skill_md = PLUGIN_DIR / "skills" / "check-appsec-requirements" / "SKILL.md"
        content = skill_md.read_text()
        assert "[F-NNN · Risk](docs/security/threat-model.md#f-nnn)" in content
        assert "[T-NNN · Risk](docs/security/threat-model.md#t-nnn)" not in content

    def test_create_skill_supports_both_flags(self):
        """Verify create-threat-model implementation defines --requirements and --no-requirements."""
        skill_md = PLUGIN_DIR / "skills" / "create-threat-model" / "SKILL-impl.md"
        content = skill_md.read_text()
        assert "--requirements" in content
        assert "--no-requirements" in content


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

    def test_qa_reviewer_treats_skipped_requirements_as_disabled(self):
        agent_md = PLUGIN_DIR / "agents" / "appsec-qa-reviewer.md"
        content = agent_md.read_text()
        assert '"skipped"' in content
        assert 'source:` is not `"disabled"`, `"skipped"`, or `"unavailable"`' in content

    def test_orchestrator_passes_url_override(self):
        agent_md = PLUGIN_DIR / "agents" / "appsec-threat-analyst.md"
        content = agent_md.read_text()
        assert "REQUIREMENTS_URL_OVERRIDE" in content

    def test_phase8b_uses_canonical_requirements_fragment_name(self):
        phase_md = PLUGIN_DIR / "agents" / "phases" / "phase-group-architecture.md"
        content = phase_md.read_text()
        assert ".fragments/requirements-compliance.md" in content
        assert ".fragments/requirements_compliance.md" not in content


# ---------------------------------------------------------------------------
# Deprecated flag aliases (backward compatibility)
# ---------------------------------------------------------------------------

class TestDeprecatedAliases:
    """The old flags should be documented as deprecated in the skill implementation."""

    def test_deprecated_aliases_documented(self):
        skill_md = PLUGIN_DIR / "skills" / "create-threat-model" / "SKILL-impl.md"
        content = skill_md.read_text()
        assert "Deprecated" in content or "deprecated" in content
        assert "--with-requirements" in content
        assert "--ignore-requirements" in content
