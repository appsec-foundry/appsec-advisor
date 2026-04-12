"""
Integration tests for the appsec-plugin.

These tests validate the structural integrity of the plugin as a whole:
- All components referenced in plugin.json exist
- Hook scripts are executable and handle edge cases
- Config files pass schema validation
- Phase-group reference files exist and are reachable
- Skill definitions reference valid agents
- The .gitignore-template covers all intermediate files mentioned in agents
- Steering keywords config is consistent with the steering script defaults
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).parent.parent / "plugin"
AGENTS_DIR = PLUGIN_DIR / "agents"
SKILLS_DIR = PLUGIN_DIR / "skills"
SCRIPTS_DIR = PLUGIN_DIR / "scripts"
HOOKS_DIR = PLUGIN_DIR / "hooks"
PHASES_DIR = AGENTS_DIR / "phases"


# ---------------------------------------------------------------------------
# Plugin manifest integrity
# ---------------------------------------------------------------------------

class TestPluginManifest:
    def test_plugin_json_exists(self):
        manifest = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
        assert manifest.exists(), "plugin.json not found"

    def test_plugin_json_valid(self):
        manifest = PLUGIN_DIR / ".claude-plugin" / "plugin.json"
        data = json.loads(manifest.read_text())
        assert "name" in data
        assert "version" in data
        assert "description" in data

    def test_agents_directory_discoverable(self):
        agents_dir = PLUGIN_DIR / "agents"
        assert agents_dir.is_dir(), "agents/ directory missing — required for auto-discovery"
        agent_files = list(agents_dir.glob("*.md"))
        assert agent_files, "no agent .md files found in agents/"

    def test_skills_directory_discoverable(self):
        skills_dir = PLUGIN_DIR / "skills"
        assert skills_dir.is_dir(), "skills/ directory missing — required for auto-discovery"
        skill_files = list(skills_dir.glob("*/SKILL.md"))
        assert skill_files, "no SKILL.md files found under skills/"


# ---------------------------------------------------------------------------
# Hook system integrity
# ---------------------------------------------------------------------------

class TestHookSystem:
    def test_hooks_json_exists(self):
        assert (HOOKS_DIR / "hooks.json").exists()

    def test_hooks_json_valid(self):
        data = json.loads((HOOKS_DIR / "hooks.json").read_text())
        assert "hooks" in data

    def test_all_hook_scripts_exist(self):
        data = json.loads((HOOKS_DIR / "hooks.json").read_text())
        for event_name, hook_list in data["hooks"].items():
            for entry in hook_list:
                for hook in entry.get("hooks", []):
                    cmd = hook.get("command", "")
                    # Extract script path from command like "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/foo.py"
                    if "scripts/" in cmd:
                        script_name = cmd.split("scripts/")[-1].strip()
                        script_path = SCRIPTS_DIR / script_name
                        assert script_path.exists(), (
                            f"Hook script not found: {script_name} (referenced by {event_name})"
                        )

    def test_steering_script_handles_empty_json(self):
        """Steering script must not crash on empty JSON."""
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "security_steering.py")],
            input="{}",
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_logger_script_handles_empty_json(self):
        """Logger script must not crash on empty JSON."""
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "agent_logger.py")],
            input="{}",
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_logger_script_handles_malformed_input(self):
        """Logger script must not crash on non-JSON input."""
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "agent_logger.py")],
            input="not json at all",
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Config schema validation
# ---------------------------------------------------------------------------

class TestConfigValidation:
    def test_main_config_exists(self):
        assert (PLUGIN_DIR / "config.json").exists()

    def test_main_config_valid_json(self):
        data = json.loads((PLUGIN_DIR / "config.json").read_text())
        assert isinstance(data, dict)
        assert "external_context" in data

    def test_main_config_has_pricing(self):
        data = json.loads((PLUGIN_DIR / "config.json").read_text())
        assert "pricing" in data
        pricing = data["pricing"]
        for key in ("input_per_1m", "output_per_1m", "cache_write_per_1m", "cache_read_per_1m"):
            assert key in pricing, f"Missing pricing key: {key}"
            assert isinstance(pricing[key], (int, float))
            assert pricing[key] >= 0

    def test_main_config_has_logging(self):
        data = json.loads((PLUGIN_DIR / "config.json").read_text())
        assert "logging" in data
        assert "max_log_bytes" in data["logging"]
        assert isinstance(data["logging"]["max_log_bytes"], int)
        assert data["logging"]["max_log_bytes"] >= 1024

    def test_requirements_config_exists(self):
        cfg = SKILLS_DIR / "check-appsec-requirements" / "config.json"
        assert cfg.exists()

    def test_requirements_config_valid(self):
        cfg = SKILLS_DIR / "check-appsec-requirements" / "config.json"
        data = json.loads(cfg.read_text())
        assert "requirements_source" in data
        rs = data["requirements_source"]
        assert "enabled" in rs
        assert isinstance(rs["enabled"], bool)

    def test_validate_config_script_passes(self):
        """Run the config validator script and ensure it passes."""
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "validate_config.py"), str(PLUGIN_DIR)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Config validation failed:\n{result.stdout}"
        assert "VALID" in result.stdout


# ---------------------------------------------------------------------------
# Phase-group reference files
# ---------------------------------------------------------------------------

EXPECTED_PHASE_FILES = [
    "phase-group-recon.md",
    "phase-group-architecture.md",
    "phase-group-threats.md",
    "phase-group-finalization.md",
]


class TestPhaseGroups:
    def test_phases_directory_exists(self):
        assert PHASES_DIR.exists(), "phases/ directory not found under agents/"

    @pytest.mark.parametrize("filename", EXPECTED_PHASE_FILES)
    def test_phase_file_exists(self, filename):
        assert (PHASES_DIR / filename).exists(), f"Phase group file missing: {filename}"

    @pytest.mark.parametrize("filename", EXPECTED_PHASE_FILES)
    def test_phase_file_not_empty(self, filename):
        content = (PHASES_DIR / filename).read_text()
        assert len(content) > 100, f"Phase group file {filename} appears too short"

    def test_orchestrator_references_phase_files(self):
        """The orchestrator must reference phase-group files."""
        orchestrator = AGENTS_DIR / "appsec-threat-analyst.md"
        content = orchestrator.read_text()
        for filename in EXPECTED_PHASE_FILES:
            assert filename in content, (
                f"Orchestrator does not reference {filename}"
            )


# ---------------------------------------------------------------------------
# Skill definitions reference valid agents
# ---------------------------------------------------------------------------

class TestSkillAgentReferences:
    def test_create_threat_model_references_orchestrator(self):
        skill = SKILLS_DIR / "create-threat-model" / "SKILL.md"
        content = skill.read_text()
        assert "appsec-threat-analyst" in content

    def test_create_threat_model_references_qa_reviewer(self):
        skill = SKILLS_DIR / "create-threat-model" / "SKILL.md"
        content = skill.read_text()
        assert "appsec-qa-reviewer" in content

    def test_create_threat_model_supports_dry_run(self):
        skill = SKILLS_DIR / "create-threat-model" / "SKILL.md"
        content = skill.read_text()
        assert "--dry-run" in content
        assert "DRY_RUN" in content

    def test_create_threat_model_supports_resume(self):
        skill = SKILLS_DIR / "create-threat-model" / "SKILL.md"
        content = skill.read_text()
        assert "--resume" in content
        assert "checkpoint" in content.lower()

    def test_create_threat_model_supports_incremental(self):
        skill = SKILLS_DIR / "create-threat-model" / "SKILL.md"
        content = skill.read_text()
        assert "--incremental" in content
        assert "INCREMENTAL" in content

    def test_create_threat_model_supports_with_sca(self):
        skill = SKILLS_DIR / "create-threat-model" / "SKILL.md"
        content = skill.read_text()
        assert "--with-sca" in content
        assert "WITH_SCA" in content


# ---------------------------------------------------------------------------
# Steering keywords config consistency
# ---------------------------------------------------------------------------

class TestSteeringKeywordsConfig:
    def test_config_exists(self):
        assert (HOOKS_DIR / "steering_keywords.json").exists()

    def test_config_valid_json(self):
        data = json.loads((HOOKS_DIR / "steering_keywords.json").read_text())
        assert "strong" in data
        assert "code" in data
        assert "action" in data
        assert "thresholds" in data

    def test_keyword_lists_non_empty(self):
        data = json.loads((HOOKS_DIR / "steering_keywords.json").read_text())
        assert len(data["strong"]) >= 10
        assert len(data["code"]) >= 10
        assert len(data["action"]) >= 5

    def test_thresholds_valid(self):
        data = json.loads((HOOKS_DIR / "steering_keywords.json").read_text())
        t = data["thresholds"]
        assert t["strong_min"] >= 1
        assert t["code_min"] >= 1
        assert t["code_action_code_min"] >= 1
        assert t["code_action_action_min"] >= 1

    def test_no_duplicate_keywords_across_tiers(self):
        """Keywords should not appear in multiple tiers."""
        data = json.loads((HOOKS_DIR / "steering_keywords.json").read_text())
        strong = set(data["strong"])
        code = set(data["code"])
        action = set(data["action"])
        assert not (strong & code), f"Keywords in both strong and code: {strong & code}"
        assert not (strong & action), f"Keywords in both strong and action: {strong & action}"
        assert not (code & action), f"Keywords in both code and action: {code & action}"


# ---------------------------------------------------------------------------
# Intermediate file coverage
# ---------------------------------------------------------------------------

class TestIntermediateFileCoverage:
    """Verify that .gitignore-template covers all intermediate files mentioned in agents."""

    INTERMEDIATE_PATTERNS = [
        ".recon-summary.md",
        ".dep-scan.json",
        ".stride-",       # stride-*.json
        ".threat-modeling-context.md",
        ".appsec-lock",
        ".agent-run.log",
        ".hook-events.log",
        ".appsec-checkpoint",
    ]

    def test_gitignore_template_exists(self):
        template = SCRIPTS_DIR / ".gitignore-template"
        assert template.exists()

    @pytest.mark.parametrize("pattern", INTERMEDIATE_PATTERNS[:-1])  # checkpoint is new
    def test_pattern_in_gitignore(self, pattern):
        content = (SCRIPTS_DIR / ".gitignore-template").read_text()
        assert pattern in content, f"Pattern '{pattern}' not in .gitignore-template"
