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
    "appsec-dep-scanner":     20,
    "appsec-stride-analyzer": 31,
    "appsec-qa-reviewer":     25,
}

# Agents that must NOT be user-invocable (must carry INTERNAL marker in body)
INTERNAL_AGENTS = {
    "appsec-context-resolver",
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
        """The orchestrator must have the highest maxTurns of all agents."""
        all_turns = {}
        for f in agent_files():
            meta, _ = parse_frontmatter(f)
            all_turns[f.stem] = meta.get("maxTurns", 0)
        orchestrator_turns = all_turns.get(ORCHESTRATOR, 0)
        for name, turns in all_turns.items():
            if name != ORCHESTRATOR:
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
