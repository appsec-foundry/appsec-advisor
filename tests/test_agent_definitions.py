"""
Tests for agent .md frontmatter definitions.

Validates that every agent file has the correct metadata fields,
uses the mandated model, and respects turn-count ceilings.
All constraints are derived from AGENTS.md policy.
"""

import re
from pathlib import Path

import pytest
import yaml

AGENTS_DIR = Path(__file__).parent.parent / "agents"

# Required frontmatter keys for every agent
REQUIRED_KEYS = ["name", "description", "tools", "model", "maxTurns"]

# Per AGENTS.md: all agents must use sonnet
REQUIRED_MODEL = "sonnet"

# Known agents and their maxTurns ceiling.
# Orchestrator ceiling bumped 80→120 in M2.9 (2026-04-25) — same rationale
# as the QA-reviewer 80→120 bump in M2.8: Phase 11 (Finalization) routinely
# touched the previous 75-turn budget when writing 12 fragments + compose +
# qa_checks + placeholder-patch, causing Sonnet to take the inline-shortcut
# bypass and hand-author threat-model.md instead of running the renderer.
EXPECTED_MAX_TURNS = {
    "appsec-threat-analyst": 120,
    "appsec-context-resolver": 25,
    "appsec-recon-scanner": 25,
    "appsec-stride-analyzer": 40,  # B2a fix: bumped from 31 to cover thorough/complex (35 + 5 buffer)
    "appsec-triage-validator": 20,
    "appsec-threat-merger": 12,
    "appsec-threat-renderer": 45,
    "appsec-qa-reviewer": 120,
    "appsec-architect-reviewer": 40,
    "appsec-config-scanner": 15,  # Phase 2.5 dispatch (M3.5)
    "appsec-evidence-verifier": 30,  # M2: Phase 10a evidence re-check
}

# Agents that must NOT be user-invocable (must carry INTERNAL marker in body)
INTERNAL_AGENTS = {
    "appsec-context-resolver",
    "appsec-recon-scanner",
    "appsec-stride-analyzer",
    "appsec-triage-validator",
    "appsec-threat-merger",
    "appsec-threat-renderer",
    "appsec-qa-reviewer",
    "appsec-architect-reviewer",
    "appsec-config-scanner",
    "appsec-evidence-verifier",
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
def test_agent_frontmatter_valid(agent_file):
    """Validate every required frontmatter rule in one pass per agent.

    Consolidates the previous 7-method parametrize matrix (63 tests for 9 agents)
    into 1 test per agent (9 tests). Failure messages list all problems at once
    so you see the full picture instead of one assertion at a time.
    """
    meta, _ = parse_frontmatter(agent_file)
    problems: list[str] = []

    if not isinstance(meta, dict):
        pytest.fail(f"{agent_file.name}: frontmatter could not be parsed as YAML dict")

    for key in REQUIRED_KEYS:
        if key not in meta:
            problems.append(f"missing required frontmatter key '{key}'")

    if meta.get("model") != REQUIRED_MODEL:
        problems.append(f"model must be '{REQUIRED_MODEL}', got '{meta.get('model')}'")

    mt = meta.get("maxTurns")
    if not (isinstance(mt, int) and mt > 0):
        problems.append(f"maxTurns must be a positive integer, got {mt!r}")

    if meta.get("name") != agent_file.stem:
        problems.append(f"name '{meta.get('name')}' does not match filename '{agent_file.stem}'")

    desc = meta.get("description", "")
    if not (isinstance(desc, str) and len(desc.strip()) > 10):
        problems.append("description is missing or too short")

    tools = meta.get("tools", "")
    if not (isinstance(tools, str) and len(tools.strip()) > 0):
        problems.append("tools must be a non-empty string")

    if problems:
        pytest.fail(f"{agent_file.name} frontmatter issues:\n  - " + "\n  - ".join(problems))


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
        assert mt <= ceiling, f"{agent_name}: maxTurns {mt} exceeds ceiling {ceiling}"

    def test_orchestrator_has_highest_turns(self):
        """The orchestrator must have the highest maxTurns of all sub-agents.

        The QA reviewer is excluded because it runs at SKILL level (Stage 3),
        not as a sub-agent of the orchestrator — it has its own independent
        turn budget invoked by the skill after the orchestrator finishes.
        """
        skill_level_agents = {"appsec-qa-reviewer", "appsec-architect-reviewer", "appsec-threat-renderer"}
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
        assert "INTERNAL" in body, f"{agent_name}: body must contain 'INTERNAL' to prevent direct invocation"

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
            f"Unexpected agent files found: {extra}\nAdd them to EXPECTED_MAX_TURNS in test_agent_definitions.py"
        )


# ---------------------------------------------------------------------------
# Model ID consistency — agents must print their actual model in progress lines
# ---------------------------------------------------------------------------


class TestModelIdConsistency:
    def test_all_internal_agents_reference_model_id(self):
        """Internal agents must reference MODEL_ID in their progress output instructions.

        Checks all internal agents in one pass and reports every offender at once,
        rather than producing one failure per agent.
        """
        offenders: list[str] = []
        for agent_name in sorted(INTERNAL_AGENTS):
            path = AGENTS_DIR / f"{agent_name}.md"
            _, body = parse_frontmatter(path)
            if "MODEL_ID" not in body:
                offenders.append(agent_name)
        assert not offenders, (
            "The following internal agents do not reference MODEL_ID "
            "(required so the running model is visible in progress output):\n  - " + "\n  - ".join(offenders)
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
        assert ".threat-modeling-context.md" in body, f"{agent_name}: must reference '.threat-modeling-context.md'"

    @pytest.mark.parametrize("agent_file", agent_files(), ids=lambda f: f.stem)
    def test_agent_run_log_referenced(self, agent_file):
        """Every agent must reference .agent-run.log for logging."""
        _, body = parse_frontmatter(agent_file)
        assert ".agent-run.log" in body, f"{agent_file.name}: must reference '.agent-run.log' for structured logging"

    def test_orchestrator_references_model_id_string(self):
        """The orchestrator must contain the literal model ID string 'claude-sonnet-4-6'."""
        path = AGENTS_DIR / f"{ORCHESTRATOR}.md"
        _, body = parse_frontmatter(path)
        assert "claude-sonnet-4-6" in body, f"{ORCHESTRATOR}: must contain 'claude-sonnet-4-6' as MODEL_ID value"


# ---------------------------------------------------------------------------
# .gitignore-template — must cover all intermediate dot-files
# ---------------------------------------------------------------------------

GITIGNORE_TEMPLATE = Path(__file__).parent.parent / "scripts" / ".gitignore-template"

# Every intermediate dot-file that agents write to docs/security/
# Keep this list in sync with AGENTS.md "Intermediate Files" table and agent definitions.
EXPECTED_GITIGNORE_ENTRIES = [
    ".recon-summary.md",
    ".dep-scan.json",
    ".stride-*.json",
    ".triage-flags.json",
    ".threat-modeling-context.md",
    ".appsec-lock",
    ".agent-run.log",
    ".hook-events.log",
]


class TestGitignoreTemplate:
    def test_template_exists(self):
        assert GITIGNORE_TEMPLATE.exists(), ".gitignore-template not found"

    def test_all_intermediate_files_covered(self):
        """Every known intermediate dot-file must appear in the .gitignore template.

        Reports every missing entry at once instead of one failure per entry.
        """
        content = GITIGNORE_TEMPLATE.read_text()
        missing = [entry for entry in EXPECTED_GITIGNORE_ENTRIES if entry not in content]
        assert not missing, ".gitignore-template is missing entries:\n  - " + "\n  - ".join(missing)

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


# ---------------------------------------------------------------------------
# Doc-drift: AGENTS.md describes each agent. Catch the case where the
# documented maxTurns drifts away from the agent frontmatter (this exact bug
# happened: AGENTS.md said "40 max turns" while the agent had maxTurns: 80).
# ---------------------------------------------------------------------------

PLUGIN_AGENTS_MD = Path(__file__).parent.parent / "AGENTS.md"

# Regex matches lines like:
#   `agents/appsec-qa-reviewer.md` — Sonnet, 80 max turns
_AGENT_TURN_DOC_RE = re.compile(
    r"`agents/(?P<name>appsec-[a-z-]+)\.md`\s*[—-]\s*Sonnet,\s*(?P<turns>\d+)\s*max\s*turns",
    re.IGNORECASE,
)


class TestAgentsMdDocDrift:
    # Note: existence is implicitly asserted by the drift/inventory tests below
    # (they call read_text() and regex-match; a missing file fails loudly).

    def test_documented_max_turns_matches_frontmatter(self):
        """Every agent referenced in AGENTS.md with a 'N max turns'
        annotation must match the agent's actual frontmatter value.
        """
        text = PLUGIN_AGENTS_MD.read_text()
        documented = {m.group("name"): int(m.group("turns")) for m in _AGENT_TURN_DOC_RE.finditer(text)}
        assert documented, "No agent maxTurns annotations found in AGENTS.md — the doc-drift regex may need updating"
        mismatches = []
        for name, doc_turns in documented.items():
            path = AGENTS_DIR / f"{name}.md"
            if not path.exists():
                mismatches.append(f"{name}: documented in AGENTS.md but agent file not found")
                continue
            meta, _ = parse_frontmatter(path)
            actual = meta.get("maxTurns")
            if actual != doc_turns:
                mismatches.append(f"{name}: AGENTS.md says {doc_turns} max turns, frontmatter has maxTurns: {actual}")
        assert not mismatches, "Doc-drift detected:\n  " + "\n  ".join(mismatches)

    def test_all_agents_documented_in_claude_md(self):
        """Every agent file must be documented in AGENTS.md."""
        text = PLUGIN_AGENTS_MD.read_text()
        documented = {m.group("name") for m in _AGENT_TURN_DOC_RE.finditer(text)}
        present = set(EXPECTED_MAX_TURNS.keys())
        missing = present - documented
        assert not missing, f"Agents missing from AGENTS.md (or missing 'N max turns' annotation): {missing}"


# ---------------------------------------------------------------------------
# Logging template centralization (Sprint 1 Item D)
#
# The shared/logging-standard.md file is the single source of truth for the
# echo-template format. Agent prompts and phase-group files must reference it
# rather than re-inlining full templates. The check below counts fully-formed
# `.agent-run.log` echo templates per file and flags any file that exceeds a
# drift ceiling. Files with genuinely phase-specific wrappers (the Phase 11
# start block; the Phase 5-8 auto-repair loop) are exempted with a budget.
# ---------------------------------------------------------------------------

# Matches a full logging echo template: must have the structured format prefix
# (date -u) AND the .agent-run.log append target. Ignores partial / contextual
# log-line examples that don't form a complete ready-to-use template.
_LOG_TEMPLATE_RE = re.compile(
    r'echo\s+"[^"]*\$\(date -u[^"]*\.agent-run\.log"',
    re.DOTALL,
)

# Per-file budget for inline logging templates. Justified exceptions only —
# adding to this dict requires a one-line rationale in the test.
INLINE_LOG_TEMPLATE_BUDGET = {
    # Authoritative source — templates live here.
    "agents/shared/logging-standard.md": 20,
    # Phase 11 has a unique 3-call-batch (phase-epoch + checkpoint + PHASE_START)
    # that is not expressible through the standard templates alone. The
    # log-completeness auto-repair loop also emits synthetic PHASE_START/END
    # entries. Keep finalization and architecture phase-groups close to the
    # standard but allow these justified cases.
    "agents/phases/phase-group-finalization.md": 10,
    "agents/phases/phase-group-architecture.md": 5,
    # Phase 9 STRIDE dispatch loop emits AGENT_INVOKE / AGENT_DONE per-component
    # plus BASH_WARN entries that legitimately inline format strings.
    "agents/phases/phase-group-threats.md": 12,
    # Orchestrator owns ASSESSMENT_START/END, CACHE_HIT, and a handful of
    # context-specific phase-logging call sites. Templates themselves now
    # delegate to shared/logging-standard.md; budget covers the contextual
    # call sites.
    "agents/appsec-threat-analyst.md": 8,
    # Renderer owns a minimal Phase-11 start/end pair so Stage 2 telemetry is
    # present without loading the full finalization prompt just for logging.
    "agents/appsec-threat-renderer.md": 2,
}

# Everything else: zero inline templates. Use shared/logging-standard.md.
AGENT_FILES_WITH_ZERO_BUDGET = [
    AGENTS_DIR / "appsec-qa-reviewer.md",
    AGENTS_DIR / "appsec-stride-analyzer.md",
    AGENTS_DIR / "appsec-context-resolver.md",
    AGENTS_DIR / "appsec-recon-scanner.md",
    AGENTS_DIR / "appsec-triage-validator.md",
    AGENTS_DIR / "appsec-threat-merger.md",
    AGENTS_DIR / "appsec-architect-reviewer.md",
    AGENTS_DIR / "appsec-config-scanner.md",
    AGENTS_DIR / "phases" / "phase-group-recon.md",
]


def _count_inline_log_templates(path: Path) -> int:
    return len(_LOG_TEMPLATE_RE.findall(path.read_text(encoding="utf-8")))


class TestLoggingCentralization:
    """Drift guard: logging templates must live in shared/logging-standard.md,
    not be duplicated across every agent. Item D of Sprint 1 extracted
    ~180 lines of duplicated echo-templates; this test prevents regression."""

    @pytest.mark.parametrize(
        "rel_path,ceiling",
        sorted(INLINE_LOG_TEMPLATE_BUDGET.items()),
    )
    def test_budgeted_files_stay_under_ceiling(self, rel_path, ceiling):
        path = AGENTS_DIR.parent / rel_path
        assert path.exists(), f"budgeted file missing: {rel_path}"
        count = _count_inline_log_templates(path)
        assert count <= ceiling, (
            f"{rel_path} has {count} inline log templates — ceiling is {ceiling}. "
            f"Move templates to shared/logging-standard.md or justify and raise the "
            f"ceiling with a rationale comment."
        )

    @pytest.mark.parametrize(
        "agent_file",
        AGENT_FILES_WITH_ZERO_BUDGET,
        ids=lambda p: str(p.relative_to(AGENTS_DIR.parent)),
    )
    def test_zero_budget_files_have_no_inline_templates(self, agent_file):
        assert agent_file.exists(), f"expected file missing: {agent_file}"
        count = _count_inline_log_templates(agent_file)
        assert count == 0, (
            f"{agent_file.relative_to(AGENTS_DIR.parent)} contains {count} inline "
            f"log templates — reference shared/logging-standard.md instead."
        )


# ---------------------------------------------------------------------------
# Scan-exclude centralization (Sprint 1 Item F)
#
# The two grep-heavy agents must NOT carry a hardcoded exclusion glob. Their
# excludes come from `data/scan-excludes.yaml` via `scripts/scan_excludes.py`.
# ---------------------------------------------------------------------------

# The prior hardcoded glob string — must no longer appear in either agent.
_LEGACY_HARDCODED_GLOB_FRAGMENT = (
    "{node_modules,vendor,dist,build,.git,__pycache__,"
    ".next,.nuxt,coverage,target,out,__tests__,__mocks__,translations,i18n,locales}"
)

AGENT_FILES_USING_EXCLUDE_GLOB = [
    AGENTS_DIR / "appsec-recon-scanner.md",
    AGENTS_DIR / "appsec-stride-analyzer.md",
]


class TestScanExcludesCentralization:
    """Drift guard for Sprint 1 Item F — the recon-scanner and stride-analyzer
    agents must delegate directory exclusions to scripts/scan_excludes.py
    instead of carrying a hardcoded glob string."""

    @pytest.mark.parametrize(
        "agent_file",
        AGENT_FILES_USING_EXCLUDE_GLOB,
        ids=lambda p: str(p.relative_to(AGENTS_DIR.parent)),
    )
    def test_no_legacy_hardcoded_glob(self, agent_file):
        text = agent_file.read_text(encoding="utf-8")
        assert _LEGACY_HARDCODED_GLOB_FRAGMENT not in text, (
            f"{agent_file.relative_to(AGENTS_DIR.parent)} still contains the "
            f"legacy hardcoded exclusion glob. Replace it with the "
            f"`scan_excludes.py glob` call documented in Step 2 / Step 3."
        )

    @pytest.mark.parametrize(
        "agent_file",
        AGENT_FILES_USING_EXCLUDE_GLOB,
        ids=lambda p: str(p.relative_to(AGENTS_DIR.parent)),
    )
    def test_references_scan_excludes_script(self, agent_file):
        text = agent_file.read_text(encoding="utf-8")
        assert "scripts/scan_excludes.py" in text, (
            f"{agent_file.relative_to(AGENTS_DIR.parent)} must instruct the "
            f"agent to call `scripts/scan_excludes.py glob` to obtain "
            f"$EXCLUDE_GLOB at runtime."
        )
        assert "EXCLUDE_GLOB" in text, (
            f"{agent_file.relative_to(AGENTS_DIR.parent)} must define and use "
            f"the $EXCLUDE_GLOB variable name (consumers grep for it)."
        )


# ---------------------------------------------------------------------------
# Prose-style anchor centralization (AGENTS.md Rule 10)
#
# Every agent or phase-group file that authors prose for the rendered report
# (verdict, architecture-assessment, STRIDE scenarios, security-architecture
# domain text, MS template) must reference `agents/shared/prose-style.md` as
# the runtime style anchor. This is the drift guard for the casework — if a
# refactor silently removes the reference, the QA reviewer loses the
# enforcement hook and prose quality drifts back toward generic LLM output.
# ---------------------------------------------------------------------------

PROSE_STYLE_FILE = AGENTS_DIR / "shared" / "prose-style.md"

AGENT_FILES_AUTHORING_PROSE = [
    AGENTS_DIR / "appsec-threat-renderer.md",
    AGENTS_DIR / "appsec-stride-analyzer.md",
    AGENTS_DIR / "phases" / "phase-group-finalization.md",
    AGENTS_DIR / "shared" / "ms-template.md",
]


class TestProseStyleAnchor:
    """Drift guard: prose-authoring agents must reference the prose-style
    anchor so the casework stays loaded at generation time.

    Anchored by AGENTS.md Rule 10. Removing the reference without removing
    the rule produces prose drift that is invisible until the next report
    review — the explicit test fails fast at edit time instead.
    """

    def test_prose_style_file_exists(self):
        assert PROSE_STYLE_FILE.is_file(), (
            f"missing prose-style anchor file: {PROSE_STYLE_FILE.relative_to(AGENTS_DIR.parent)}. "
            f"It is referenced by AGENTS.md Rule 10 and the prose-authoring agents."
        )

    @pytest.mark.parametrize(
        "agent_file",
        AGENT_FILES_AUTHORING_PROSE,
        ids=lambda p: str(p.relative_to(AGENTS_DIR.parent)),
    )
    def test_prose_authoring_files_reference_anchor(self, agent_file):
        assert agent_file.exists(), f"expected file missing: {agent_file}"
        text = agent_file.read_text(encoding="utf-8")
        assert "shared/prose-style.md" in text, (
            f"{agent_file.relative_to(AGENTS_DIR.parent)} authors prose that reaches "
            f"the rendered report but does not reference `agents/shared/prose-style.md`. "
            f"Add a `cat $CLAUDE_PLUGIN_ROOT/agents/shared/prose-style.md` block at the "
            f"prose-authoring step so the style rules load at runtime. See AGENTS.md "
            f"Rule 10 for the policy."
        )
