"""
Integration tests for the appsec-advisor.

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

PLUGIN_DIR = Path(__file__).parent.parent
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

# Each entry declares a capability that the SKILL.md MUST document. A failure
# means either the skill was refactored without updating this list (expected —
# update the list) or a capability was silently dropped (unexpected —
# investigate). Using lowercase=True performs case-insensitive matching; some
# capabilities want to find both a flag (--x) and an env-var (X) so the
# `phrases` list can hold multiple required substrings.
_CREATE_THREAT_MODEL_INVARIANTS = [
    # (test-id,              phrases that must all be present,            case-insensitive?)
    ("references-orchestrator", ["appsec-threat-analyst"],                False),
    ("references-qa-reviewer",  ["appsec-qa-reviewer"],                   False),
    ("supports-dry-run",        ["--dry-run", "DRY_RUN"],                 False),
    ("supports-resume",         ["--resume", "checkpoint"],               True),
    ("supports-incremental",    ["--incremental", "INCREMENTAL"],         False),
    ("supports-with-sca",       ["--with-sca", "WITH_SCA"],               False),
]


class TestSkillAgentReferences:
    @pytest.mark.parametrize(
        "phrases,case_insensitive",
        [(p, ci) for _, p, ci in _CREATE_THREAT_MODEL_INVARIANTS],
        ids=[tid for tid, _, _ in _CREATE_THREAT_MODEL_INVARIANTS],
    )
    def test_create_threat_model_documents(self, phrases, case_insensitive):
        """SKILL.md must mention every capability the skill supports.

        Collapsed from six individual tests (test_create_threat_model_*) into
        a single parametrized test. Each phrase list maps to one pytest case;
        the failure message shows which phrase was missing.
        """
        skill_dir = SKILLS_DIR / "create-threat-model"
        content = (skill_dir / "SKILL.md").read_text()
        impl = skill_dir / "SKILL-impl.md"
        if impl.exists():
            content += "\n" + impl.read_text()
        haystack = content.lower() if case_insensitive else content
        missing = [p for p in phrases if (p.lower() if case_insensitive else p) not in haystack]
        assert not missing, (
            f"SKILL.md is missing required phrase(s): {missing!r}"
        )


# ---------------------------------------------------------------------------
# Steering keywords config consistency
# ---------------------------------------------------------------------------

class TestSteeringKeywordsConfig:
    @pytest.fixture(scope="class")
    def data(self):
        path = HOOKS_DIR / "steering_keywords.json"
        assert path.exists(), f"steering_keywords.json not found at {path}"
        return json.loads(path.read_text())

    def test_has_required_top_level_keys(self, data):
        required = {"baseline", "code_keywords", "action_keywords", "thresholds", "topics"}
        missing = required - set(data)
        assert not missing, f"missing top-level keys: {sorted(missing)}"

    @pytest.mark.parametrize("tier,min_size", [
        ("code_keywords", 10),
        ("action_keywords", 5),
    ])
    def test_keyword_list_has_minimum_size(self, data, tier, min_size):
        assert len(data[tier]) >= min_size, (
            f"keyword tier '{tier}' has {len(data[tier])} entries, expected >= {min_size}"
        )

    @pytest.mark.parametrize("key", [
        "code_min", "code_action_code_min", "code_action_action_min",
    ])
    def test_threshold_is_positive(self, data, key):
        assert data["thresholds"][key] >= 1, (
            f"thresholds.{key} = {data['thresholds'][key]!r}, expected >= 1"
        )

    def test_topics_cover_core_domains(self, data):
        """Core AppSec domains must each have a topic so repo-specific overrides
        can attach guidance and requirements to them."""
        required_topics = {"general", "auth", "injection", "crypto", "xss_csrf", "secrets", "iac"}
        missing = required_topics - set(data["topics"])
        assert not missing, f"topics missing core domains: {sorted(missing)}"

    def test_topic_triggers_have_minimum_size(self, data):
        """Every declared topic must have at least one trigger keyword."""
        for name, spec in data["topics"].items():
            triggers = spec.get("triggers", [])
            assert triggers, f"topic '{name}' has no triggers"

    def test_flat_groups_do_not_overlap_with_topic_triggers(self, data):
        """A word in code_keywords/action_keywords should not also be a topic
        trigger — that would double-count it and confuse the threshold logic."""
        flat = set(data["code_keywords"]) | set(data["action_keywords"])
        for name, spec in data["topics"].items():
            conflicts = flat & set(spec.get("triggers", []))
            assert not conflicts, (
                f"triggers in topic '{name}' also appear in code_keywords/action_keywords: {sorted(conflicts)}"
            )


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
