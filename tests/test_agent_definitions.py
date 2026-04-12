"""
Tests for agent .md frontmatter definitions.

Validates that every agent file has the correct metadata fields,
uses the mandated model, and respects turn-count ceilings.
All constraints are derived from plugin/CLAUDE.md policy.
"""

import re
from pathlib import Path

import pytest
import yaml

AGENTS_DIR = Path(__file__).parent.parent / "plugin" / "agents"

# Required frontmatter keys for every agent
REQUIRED_KEYS = ["name", "description", "tools", "model", "maxTurns"]

# Per CLAUDE.md: all agents must use sonnet
REQUIRED_MODEL = "sonnet"

# Known agents and their maxTurns ceiling.
# Orchestrator ceiling is 80 to allow room for future increases
# without triggering tests (current value: 60).
EXPECTED_MAX_TURNS = {
    "appsec-threat-analyst":  80,
    "appsec-context-resolver": 25,
    "appsec-recon-scanner":   25,
    "appsec-dep-scanner":     15,
    "appsec-stride-analyzer": 31,
    "appsec-qa-reviewer":     80,
}

# Agents that must NOT be user-invocable (must carry INTERNAL marker in body)
INTERNAL_AGENTS = {
    "appsec-context-resolver",
    "appsec-recon-scanner",
    "appsec-dep-scanner",
    "appsec-stride-analyzer",
    "appsec-qa-reviewer",
}

# The orchestrator is the only user-facing agent
ORCHESTRATOR = "appsec-threat-analyst"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def agent_files() -> list[Path]:
    return sorted(AGENTS_DIR.glob("*.md"))


def parse_frontmatter(path: Path) -> tuple[dict, str]:
    """Parse YAML frontmatter between --- delimiters. Returns (meta, body)."""
    text = path.read_text()
    m = re.match(r"^---\n(.*?)\n---\n(.*)", text, re.DOTALL)
    if not m:
        return {}, text
    meta = yaml.safe_load(m.group(1)) or {}
    body = m.group(2)
    return meta, body


def agent_ids() -> list[str]:
    return [f.stem for f in agent_files()]


# ---------------------------------------------------------------------------
# Parametrized per-file tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("agent_file", agent_files(), ids=lambda f: f.stem)
class TestAgentFrontmatter:
    def test_frontmatter_is_parseable(self, agent_file):
        meta, _ = parse_frontmatter(agent_file)
        assert isinstance(meta, dict), f"{agent_file.name}: frontmatter could not be parsed as YAML dict"

    @pytest.mark.parametrize("key", REQUIRED_KEYS)
    def test_required_key_present(self, agent_file, key):
        meta, _ = parse_frontmatter(agent_file)
        assert key in meta, f"{agent_file.name}: missing required frontmatter key '{key}'"

    def test_model_is_sonnet(self, agent_file):
        meta, _ = parse_frontmatter(agent_file)
        assert meta.get("model") == REQUIRED_MODEL, (
            f"{agent_file.name}: model must be '{REQUIRED_MODEL}', "
            f"got '{meta.get('model')}'"
        )

    def test_max_turns_is_positive_integer(self, agent_file):
        meta, _ = parse_frontmatter(agent_file)
        mt = meta.get("maxTurns")
        assert isinstance(mt, int) and mt > 0, (
            f"{agent_file.name}: maxTurns must be a positive integer, got {mt!r}"
        )

    def test_name_matches_filename(self, agent_file):
        meta, _ = parse_frontmatter(agent_file)
        assert meta.get("name") == agent_file.stem, (
            f"name '{meta.get('name')}' does not match filename '{agent_file.stem}'"
        )

    def test_description_is_non_empty_string(self, agent_file):
        meta, _ = parse_frontmatter(agent_file)
        desc = meta.get("description", "")
        assert isinstance(desc, str) and len(desc.strip()) > 10, (
            f"{agent_file.name}: description is missing or too short"
        )

    def test_tools_is_non_empty_string(self, agent_file):
        meta, _ = parse_frontmatter(agent_file)
        tools = meta.get("tools", "")
        assert isinstance(tools, str) and len(tools.strip()) > 0, (
            f"{agent_file.name}: tools must be a non-empty string"
        )


# ---------------------------------------------------------------------------
# maxTurns ceiling checks
# ---------------------------------------------------------------------------

class TestMaxTurnsCeilings:
    @pytest.mark.parametrize("agent_name,ceiling", EXPECTED_MAX_TURNS.items())
    def test_max_turns_does_not_exceed_ceiling(self, agent_name, ceiling):
        path = AGENTS_DIR / f"{agent_name}.md"
        assert path.exists(), f"Agent file not found: {path}"
        meta, _ = parse_frontmatter(path)
        mt = meta.get("maxTurns", 0)
        assert mt <= ceiling, (
            f"{agent_name}: maxTurns {mt} exceeds ceiling {ceiling}"
        )

    def test_orchestrator_has_highest_turns(self):
        """The orchestrator must have the highest maxTurns of all sub-agents.

        The QA reviewer is excluded because it runs at SKILL level (Stage 2),
        not as a sub-agent of the orchestrator — it has its own independent
        turn budget invoked by the skill after the orchestrator finishes.
        """
        skill_level_agents = {"appsec-qa-reviewer"}
        all_turns = {}
        for f in agent_files():
            meta, _ = parse_frontmatter(f)
            all_turns[f.stem] = meta.get("maxTurns", 0)
        orchestrator_turns = all_turns.get(ORCHESTRATOR, 0)
        for name, turns in all_turns.items():
            if name != ORCHESTRATOR and name not in skill_level_agents:
                assert orchestrator_turns >= turns, (
                    f"Orchestrator ({orchestrator_turns}) has fewer turns than {name} ({turns})"
                )


# ---------------------------------------------------------------------------
# INTERNAL agent marker
# ---------------------------------------------------------------------------

class TestInternalMarkers:
    @pytest.mark.parametrize("agent_name", sorted(INTERNAL_AGENTS))
    def test_internal_agents_have_internal_marker(self, agent_name):
        path = AGENTS_DIR / f"{agent_name}.md"
        _, body = parse_frontmatter(path)
        assert "INTERNAL" in body, (
            f"{agent_name}: body must contain 'INTERNAL' to prevent direct invocation"
        )

    def test_orchestrator_is_not_marked_internal(self):
        path = AGENTS_DIR / f"{ORCHESTRATOR}.md"
        _, body = parse_frontmatter(path)
        # The orchestrator body should NOT start with "INTERNAL AGENT"
        assert not body.strip().startswith("INTERNAL AGENT"), (
            f"{ORCHESTRATOR} must not be marked as INTERNAL — it is user-facing"
        )


# ---------------------------------------------------------------------------
# All expected agents are present
# ---------------------------------------------------------------------------

class TestAgentInventory:
    def test_all_expected_agents_present(self):
        found = {f.stem for f in agent_files()}
        expected = set(EXPECTED_MAX_TURNS.keys())
        missing = expected - found
        assert not missing, f"Missing agent files: {missing}"

    def test_no_unexpected_agents(self):
        """Fail loudly if a new agent is added without updating this test suite."""
        found = {f.stem for f in agent_files()}
        expected = set(EXPECTED_MAX_TURNS.keys())
        extra = found - expected
        assert not extra, (
            f"Unexpected agent files found: {extra}\n"
            "Add them to EXPECTED_MAX_TURNS in test_agent_definitions.py"
        )


# ---------------------------------------------------------------------------
# Model ID consistency — agents must print their actual model in progress lines
# ---------------------------------------------------------------------------

class TestModelIdConsistency:
    @pytest.mark.parametrize("agent_name", sorted(INTERNAL_AGENTS))
    def test_internal_agent_references_model_id(self, agent_name):
        """Internal agents must reference MODEL_ID in their progress output instructions."""
        path = AGENTS_DIR / f"{agent_name}.md"
        _, body = parse_frontmatter(path)
        assert "MODEL_ID" in body, (
            f"{agent_name}: must use MODEL_ID variable in progress format "
            "so the running model is visible in output"
        )


# ---------------------------------------------------------------------------
# Body content cross-references — naming consistency
# ---------------------------------------------------------------------------

# Agents that reference the context file (all except context-resolver which writes it)
_CONTEXT_FILE_AGENTS = {
    "appsec-threat-analyst",
    "appsec-stride-analyzer",
    "appsec-context-resolver",
}


class TestBodyContentConsistency:
    @pytest.mark.parametrize("agent_file", agent_files(), ids=lambda f: f.stem)
    def test_no_old_context_filename(self, agent_file):
        """No agent may reference the old non-dot-prefix context filename."""
        _, body = parse_frontmatter(agent_file)
        # The old name without dot-prefix — should not appear except inside
        # the dot-prefixed version. Remove all occurrences of the new name
        # first, then check for the old name.
        cleaned = body.replace(".threat-modeling-context.md", "")
        assert "threat-modeling-context.md" not in cleaned, (
            f"{agent_file.name}: references old filename 'threat-modeling-context.md' "
            "— must use '.threat-modeling-context.md' (dot-prefix)"
        )

    @pytest.mark.parametrize("agent_name", sorted(_CONTEXT_FILE_AGENTS))
    def test_dot_prefix_context_file_referenced(self, agent_name):
        """Agents that use the context file must reference the dot-prefixed name."""
        path = AGENTS_DIR / f"{agent_name}.md"
        _, body = parse_frontmatter(path)
        assert ".threat-modeling-context.md" in body, (
            f"{agent_name}: must reference '.threat-modeling-context.md'"
        )

    @pytest.mark.parametrize("agent_file", agent_files(), ids=lambda f: f.stem)
    def test_agent_run_log_referenced(self, agent_file):
        """Every agent must reference .agent-run.log for logging."""
        _, body = parse_frontmatter(agent_file)
        assert ".agent-run.log" in body, (
            f"{agent_file.name}: must reference '.agent-run.log' for structured logging"
        )

    def test_orchestrator_references_model_id_string(self):
        """The orchestrator must contain the literal model ID string 'claude-sonnet-4-6'."""
        path = AGENTS_DIR / f"{ORCHESTRATOR}.md"
        _, body = parse_frontmatter(path)
        assert "claude-sonnet-4-6" in body, (
            f"{ORCHESTRATOR}: must contain 'claude-sonnet-4-6' as MODEL_ID value"
        )


# ---------------------------------------------------------------------------
# .gitignore-template — must cover all intermediate dot-files
# ---------------------------------------------------------------------------

GITIGNORE_TEMPLATE = Path(__file__).parent.parent / "plugin" / "scripts" / ".gitignore-template"

# Every intermediate dot-file that agents write to docs/security/
# Keep this list in sync with CLAUDE.md "Intermediate Files" table and agent definitions.
EXPECTED_GITIGNORE_ENTRIES = [
    ".recon-summary.md",
    ".dep-scan.json",
    ".stride-*.json",
    ".threat-modeling-context.md",
    ".appsec-lock",
    ".agent-run.log",
    ".hook-events.log",
]


class TestGitignoreTemplate:
    def test_template_exists(self):
        assert GITIGNORE_TEMPLATE.exists(), ".gitignore-template not found"

    @pytest.mark.parametrize("entry", EXPECTED_GITIGNORE_ENTRIES)
    def test_intermediate_file_covered(self, entry):
        """Every known intermediate dot-file must appear in the .gitignore template."""
        content = GITIGNORE_TEMPLATE.read_text()
        assert entry in content, (
            f".gitignore-template is missing entry for '{entry}'"
        )

    def test_no_non_dot_intermediate_files(self):
        """All entries in the template under docs/security/ should be dot-files."""
        content = GITIGNORE_TEMPLATE.read_text()
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            # Extract filename part after the last /
            filename = line.rsplit("/", 1)[-1]
            assert filename.startswith("."), (
                f"Intermediate file '{filename}' in .gitignore-template "
                "is not a dot-file — all intermediate files should be hidden"
            )
