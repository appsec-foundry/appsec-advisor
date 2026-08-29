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

# Run-path coupling: a Bash block that uses the output directory must also set
# it, because shell state does not survive between Bash calls.
_BASH_BLOCKS = re.compile(r"```bash\n(.*?)```", re.DOTALL)
_RUN_PATH_USE = re.compile(r"\$\{?(?:OUTPUT_DIR|OUT_DIR)\b")
_RUN_PATH_ASSIGN = re.compile(r"^\s*(?:export\s+)?(?:OUTPUT_DIR|OUT_DIR)=", re.MULTILINE)

# Required frontmatter keys for every agent
REQUIRED_KEYS = ["name", "description", "tools", "model", "maxTurns"]

# Per AGENTS.md: all agents must use sonnet
REQUIRED_MODEL = "sonnet"

# Known agents and their maxTurns ceiling. Must match the agent frontmatter.
# History:
#   - QA-reviewer 80→120 (M2.8) and orchestrator 80→120 (M2.9, 2026-04-25):
#     Phase 11 (Finalization) routinely touched the 75-turn budget when
#     writing 12 fragments + compose + qa_checks + placeholder-patch, causing
#     Sonnet to take the inline-shortcut bypass and hand-author
#     threat-model.md instead of running the renderer.
#   - Orchestrator 120→250 + renderer 45→80 (refactor): aligned with the
#     Stage 1/Stage 2 split where the renderer needs more budget to compose
#     fragments and the orchestrator absorbs additional sub-agent dispatches.
#   - Orchestrator 250→300: extra headroom for the added sub-agent dispatches
#     (Phase 2.7 actor discovery + Stage-1d abuse-case fan-out coordination).
#   - QA reviewer 120→200 (2026-08-02): large semantic repair plans repeatedly
#     exhausted 120 turns before emitting the mandatory completion status.
#   - Recon scanner 25→36 (2026-08-07): reserve ten publication calls after a
#     fixed 22-call discovery ceiling; a live run consumed all 25 turns and
#     skipped its required Markdown validator after writing an incomplete
#     heading sequence.
EXPECTED_MAX_TURNS = {
    "appsec-architecture-analyst": 60,
    "appsec-control-analyst": 40,
    "appsec-post-stride-synthesizer": 20,
    "appsec-context-resolver": 25,
    "appsec-recon-scanner": 36,
    "appsec-stride-analyzer-v2": 96,
    "appsec-triage-validator": 20,
    "appsec-threat-merger": 12,
    "appsec-threat-renderer": 80,
    "appsec-secarch-renderer": 60,
    # 32 → 60 (2026-08-27): a standard-depth juice-shop run stopped this agent
    # at 32/32 turns. It authors six fragments (verdict, critical attack tree,
    # attack paths, anti-patterns, AI exposure, requirements compliance) against
    # the secarch-renderer's one, yet carried the tighter of the two Stage-2
    # ceilings. Matched to its sibling.
    "appsec-ms-renderer": 60,
    "appsec-qa-reviewer": 200,
    "appsec-architect-reviewer": 40,
    "appsec-config-scanner": 15,  # Phase 2.5 dispatch (M3.5)
    "appsec-actor-discoverer": 15,  # Phase 2.7 actor discovery
    # 20 → 40 (2026-08-22): 8fbbd534 had taken this from 60 to 20 while
    # routing bounded context, leaving 20 turns for a sample set capped at 30.
    # The 2026-08-21 run was killed at 20/20. See MIN_MAX_TURNS.
    "appsec-evidence-verifier": 40,
    # 28 → 36 (2026-08-22): restores the value 843afab8 set after the
    # 2026-07-24 cut-off, which 022bf115 reverted without a measurement.
    "appsec-abuse-case-verifier": 36,
    "appsec-trust-boundary-analyst": 24,
    # M2b: lean Re-Render-Loop repair executor (replaces heavy analyst REPAIR_MODE).
    # 30 → 45 after the 2026-08-21 insecure-large-spring-app run logged MAX_TURNS
    # at 30/30 and the fixer's closing message was cut mid-sentence; 30 was both
    # its budget and its ceiling, so there was no headroom to absorb a repair
    # plan naming several fragments.
    "appsec-fragment-fixer": 45,
    "appsec-reviewer": 40,  # embeddable diff-scoped security reviewer (requirements or best-practices); skill/CLI/direct
    "appsec-eval-judge": 30,  # dev/test semantic-quality judge for the eval-threat-model skill (JUDGE/VERIFY modes)
    "appsec-run-diagnostician": 45,  # APPSEC_PLUGIN_DEV post-run diagnosis: 12 issues x ~2 grounding reads + startup + write
    "appsec-authnz-analyzer": 28,  # cross-component AuthN/AuthZ: consumes pre-extracted scanner JSON, no source re-read
}

# Floor for the same values. EXPECTED_MAX_TURNS is a cost ceiling — `mt <=
# ceiling` can only notice a budget that grew, never one that shrank. Every
# turn-kill this plugin has shipped was a budget that was too SMALL, and the
# worst of them was introduced by a refactor that lowered one:
#
#   8fbbd534 (2026-08-09, "route bounded post-stride and abuse context") took
#   appsec-evidence-verifier from 60 to 20 without touching
#   evidence_verifier_max_findings, and 022bf115 the same day took
#   appsec-abuse-case-verifier from 36 back to 28 with an empty message body,
#   replacing a comment that cited two measured incidents with an unmeasured
#   claim. Neither test went red: the ceiling assertion is blind downwards.
#   Twelve days later both agents were cut off again on the
#   insecure-large-spring-app run — the evidence verifier at 20/20, which left
#   a budget-critical claim standing that skipped abuse-case verification
#   entirely and shipped four unverified chains as "? Inconclusive".
#
# A floor makes lowering a deliberate, reviewable edit instead of a side effect.
# Raising a budget stays free; only going below a value that a real run needed
# requires touching this table and saying why.
MIN_MAX_TURNS = {
    # Workload is `evidence_verifier_max_findings` (30 at standard depth, 100
    # at thorough, unbounded via --evidence-verifier-cap). The agent pre-seeds
    # once and flushes every five verdicts, so 30 samples need ~6 flush turns
    # on top of reading and judging them. 20 cannot cover that arithmetic; 40
    # is the value the agent held from 2026-06-13 until the 07-21 escalation.
    "appsec-evidence-verifier": 40,
    # 843afab8 (2026-07-25) raised this to 36 after the 2026-07-24 juice-shop
    # run shipped empty-excerpt verdicts from agents still grepping at the
    # ceiling. 022bf115 reverted it; dec415fa (2026-08-21) recorded the next
    # cut-off, where AC-T-003 needed three manual dispatches.
    "appsec-abuse-case-verifier": 36,
    # 743dd1be (2026-08-02): spring-web-app needed 65 turns for 47 files and
    # died twice at 56. This is the one budget in the plugin that also scales
    # per component; the frontmatter value is its hard ceiling.
    "appsec-stride-analyzer-v2": 96,
    # 7cceff0d (2026-08-21): cut off mid-sentence at 30/30 on a repair plan
    # naming several fragments.
    "appsec-fragment-fixer": 45,
    # 240850ee (2026-08-02): large semantic repair plans exhausted 120 turns
    # before the mandatory completion status.
    "appsec-qa-reviewer": 200,
    # 74846143 (2026-08-07): a live run consumed all 25 turns and skipped the
    # required Markdown validator.
    "appsec-recon-scanner": 36,
}

# Agents that must NOT be user-invocable (must carry INTERNAL marker in body)
INTERNAL_AGENTS = {
    "appsec-architecture-analyst",
    "appsec-control-analyst",
    "appsec-post-stride-synthesizer",
    "appsec-context-resolver",
    "appsec-recon-scanner",
    "appsec-stride-analyzer-v2",
    "appsec-triage-validator",
    "appsec-threat-merger",
    "appsec-threat-renderer",
    "appsec-secarch-renderer",
    "appsec-ms-renderer",
    "appsec-qa-reviewer",
    "appsec-architect-reviewer",
    "appsec-config-scanner",
    "appsec-actor-discoverer",  # Phase 2.7 sub-agent — internal (body already carries the marker; set was missing it)
    "appsec-evidence-verifier",
    "appsec-abuse-case-verifier",
    "appsec-trust-boundary-analyst",
    "appsec-fragment-fixer",
    "appsec-run-diagnostician",  # dispatched by the orchestrator at completion, never by the user
}

# The deterministic controller owns all Level-0 dispatch. No pipeline agent may
# recursively dispatch another agent.
AGENT_TOOL_OWNERS = set()
EDIT_TOOL_OWNERS = {"appsec-fragment-fixer", "appsec-qa-reviewer"}

KERNEL_PRELOAD_ROLES = {
    "appsec-architecture-analyst",
    "appsec-control-analyst",
    "appsec-post-stride-synthesizer",
    "appsec-stride-analyzer-v2",
}


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


def _frontmatter_tools(path: Path) -> set[str]:
    meta, _ = parse_frontmatter(path)
    return {tool.strip() for tool in str(meta.get("tools") or "").split(",") if tool.strip()}


# ---------------------------------------------------------------------------
# Semantic drift guards
# ---------------------------------------------------------------------------


def test_single_runtime_forbids_recursive_agents_and_pins_edit_owners():
    agent_owners = {path.stem for path in agent_files() if "Agent" in _frontmatter_tools(path)}
    edit_owners = {path.stem for path in agent_files() if "Edit" in _frontmatter_tools(path)}

    assert agent_owners == AGENT_TOOL_OWNERS
    assert edit_owners == EDIT_TOOL_OWNERS


def test_pipeline_agent_frontmatter_never_admits_mcp_tools():
    violations = {}
    for path in agent_files():
        tools = {tool for tool in _frontmatter_tools(path) if tool.lower() == "mcp" or tool.lower().startswith("mcp__")}
        if tools:
            violations[path.stem] = sorted(tools)
    assert not violations, f"pipeline agent MCP tools are forbidden: {violations}"


def test_cross_repo_mismatch_requires_target_evidence():
    text = (AGENTS_DIR / "appsec-stride-analyzer-v2.md").read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "requires a target-side probe" in flat
    assert "emit only when target source or the probe proves" in flat
    assert "Related context cannot prove a finding or justify CVSS" in flat
    assert "emit a HIGH-likelihood threat" not in flat


def test_actor_discovery_prompt_keeps_actor_identity_boundary():
    """Do not regress to technique-, feature-, or persona-based actor classes."""
    text = (AGENTS_DIR / "appsec-actor-discoverer.md").read_text(encoding="utf-8")
    required_contract = (
        "It is not an attack technique, tool, target feature, or",
        "Different motivation, sophistication, tooling, dwell time, target subsystem,",
        "`prompt-injector`",
        "CTF participant",
        "`compromised-third-party-service`",
        "`trust_positions[]`",
        "`distinct_trust_positions[]`",
    )
    missing = [marker for marker in required_contract if marker not in text]
    assert not missing, f"actor discovery identity-boundary contract drifted; missing: {missing}"
    assert re.search(r"active\s+or dormant static actor", text), (
        "actor discovery must compare proposals with both active and dormant static actors"
    )


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

    @pytest.mark.parametrize("agent_name,floor", MIN_MAX_TURNS.items())
    def test_max_turns_does_not_fall_below_floor(self, agent_name, floor):
        """A budget a real run needed may not be lowered as a side effect.

        See MIN_MAX_TURNS for the incidents. Raising a budget needs no change
        here; lowering one below a measured need must edit that table and say
        why, so it shows up in review instead of in the next run's log.
        """
        path = AGENTS_DIR / f"{agent_name}.md"
        assert path.exists(), f"Agent file not found: {path}"
        meta, _ = parse_frontmatter(path)
        mt = meta.get("maxTurns", 0)
        assert mt >= floor, (
            f"{agent_name}: maxTurns {mt} is below the floor {floor} that a "
            f"measured run needed. If this budget is genuinely no longer "
            f"required, lower MIN_MAX_TURNS in the same commit and record what "
            f"changed to make it sufficient."
        )

    def test_every_floor_has_a_ceiling(self):
        """A floor without a ceiling could be raised past the cost guard."""
        orphans = sorted(set(MIN_MAX_TURNS) - set(EXPECTED_MAX_TURNS))
        assert not orphans, f"floors without a ceiling entry: {orphans}"

    @pytest.mark.parametrize("agent_name,floor", MIN_MAX_TURNS.items())
    def test_floor_does_not_exceed_ceiling(self, agent_name, floor):
        """The two tables must leave a satisfiable range."""
        ceiling = EXPECTED_MAX_TURNS[agent_name]
        assert floor <= ceiling, f"{agent_name}: floor {floor} exceeds ceiling {ceiling} — no value can satisfy both"


# ---------------------------------------------------------------------------
# INTERNAL agent marker
# ---------------------------------------------------------------------------


class TestInternalMarkers:
    @pytest.mark.parametrize("agent_name", sorted(INTERNAL_AGENTS))
    def test_internal_agents_have_internal_marker(self, agent_name):
        path = AGENTS_DIR / f"{agent_name}.md"
        _, body = parse_frontmatter(path)
        assert "INTERNAL" in body, f"{agent_name}: body must contain 'INTERNAL' to prevent direct invocation"


def test_internal_kernel_is_preloaded_only_by_focused_context_v2_roles():
    preloaded = set()
    for path in agent_files():
        meta, _ = parse_frontmatter(path)
        skills = meta.get("skills", [])
        assert isinstance(skills, list), f"{path.name}: skills frontmatter must be a list"
        if "internal-threat-analysis-kernel" in skills:
            preloaded.add(path.stem)
        assert all(skill == "internal-threat-analysis-kernel" for skill in skills), (
            f"{path.name}: repository-selected or unexpected preloaded skill: {skills}"
        )
    assert preloaded == KERNEL_PRELOAD_ROLES


# ---------------------------------------------------------------------------
# All expected agents are present
# ---------------------------------------------------------------------------


class TestAgentInventory:
    def test_all_expected_agents_present(self):
        found = {f.stem for f in agent_files()}
        expected = set(EXPECTED_MAX_TURNS.keys())
        missing = expected - found
        assert not missing, f"Missing agent files: {missing}"


# ---------------------------------------------------------------------------
# Re-Render-Loop finalization tail (AGENTS.md "Critical ordering rule")
# ---------------------------------------------------------------------------


class TestFragmentFixerFinalizationTail:
    """The fragment-fixer recomposes from fragments, which discards the
    autofix-exclusive §4/§5 GFM→HTML fixed-layout table conversion + path
    backticking. The canonical tail `compose --strict → apply_prose_fixes →
    <autofix-bearing command>` MUST run after the recompose, with the autofix
    LAST, else repaired runs ship regressed §4/§5 tables. Recurring regression
    class — see AGENTS.md "Critical ordering rule".

    `qa_checks.py gate` satisfies the autofix half: `cmd_gate` runs
    `_run_autofix` and only then validates the resulting bytes. It is the
    preferred form because it is also the command the thin Stage-3 runtime uses —
    see tests/test_repair_self_verification.py for why the fixer must not
    self-verify with anything narrower."""

    def test_fragment_fixer_reruns_autofix_after_prose_fixes(self):
        body = (AGENTS_DIR / "appsec-fragment-fixer.md").read_text(encoding="utf-8")
        prose_idx = body.find("apply_prose_fixes.py")
        # `gate` = `_run_autofix` + `cmd_repair_plan`; either form re-applies
        # the autofix-exclusive passes. Quoting/line continuations vary.
        autofix_match = re.search(r'qa_checks\.py"?\s*\\?\s*(?:autofix|gate)\b', body)
        compose_idx = body.find("compose_threat_model.py")
        assert prose_idx != -1, "fragment-fixer must re-run apply_prose_fixes after recompose"
        assert autofix_match is not None, (
            "fragment-fixer must re-run `qa_checks.py autofix` (or `gate`, which "
            "subsumes it) after recompose — it owns the §4/§5 GFM→HTML table "
            "conversion that compose drops"
        )
        assert compose_idx < prose_idx < autofix_match.start(), (
            "canonical order must be compose --strict → apply_prose_fixes → "
            "qa_checks autofix/gate (the autofix is the LAST mutation)"
        )

    def test_no_unexpected_agents(self):
        """Fail loudly if a new agent is added without updating this test suite."""
        found = {f.stem for f in agent_files()}
        expected = set(EXPECTED_MAX_TURNS.keys())
        extra = found - expected
        assert not extra, (
            f"Unexpected agent files found: {extra}\nAdd them to EXPECTED_MAX_TURNS in test_agent_definitions.py"
        )


def test_focused_renderer_line_slices_match_their_owned_contracts():
    """The focused agents use bounded line reads from the full producer."""
    renderer_lines = (AGENTS_DIR / "appsec-threat-renderer.md").read_text(encoding="utf-8").splitlines()
    ms = (AGENTS_DIR / "appsec-ms-renderer.md").read_text(encoding="utf-8")
    secarch = (AGENTS_DIR / "appsec-secarch-renderer.md").read_text(encoding="utf-8")

    assert "lines 143–377" in ms
    assert renderer_lines[142].startswith("### MS prose")
    assert renderer_lines[375].startswith("Finding severity does not determine compliance status")
    assert renderer_lines[376] == ""
    assert "lines 378–703" in secarch
    assert renderer_lines[377].startswith("### `security-architecture.md` authoring")
    assert renderer_lines[701] == "```"
    assert renderer_lines[702] == ""
    assert renderer_lines[703].startswith("## Completion")

    # The MS slice must actually carry the ms-verdict rules the MS renderer is
    # sent here for — an edit that lands one outside the bounds ships a rule no
    # agent ever reads (which is what the line numbers above are protecting).
    ms_slice = "\n".join(renderer_lines[142:375])
    assert "`ms-verdict.json` authoring contract" in ms_slice
    assert "must not assert a precondition the bullets do not all share" in ms_slice
    assert "What an attacker can do today, worst first:" in ms_slice


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
    "appsec-stride-analyzer-v2",
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

    def test_step_logging_guidance_forbids_inline_format_line(self):
        """Regression guard (2026-06-20 Sonnet run): step/check logging must route
        through log_event.py, and the shared standard must explicitly forbid calling
        event_log.format_line via `python3 -c`. format_line's level/component/sid are
        keyword-only, so a hand-rolled positional/`event_type=` call TypeErrors and
        leaves LOG_ERR noise in .agent-run.log. The agents that already carried this
        local prohibition (abuse-case-verifier, eval-judge) did not crash; the
        stride-analyzer, which lacked it, did."""
        shared = (AGENTS_DIR / "shared" / "logging-standard.md").read_text(encoding="utf-8")
        assert "log_event.py" in shared, "logging-standard.md must mandate log_event.py for step/check logging"
        assert "format_line" in shared and "python3 -c" in shared, (
            "logging-standard.md must explicitly forbid calling format_line via python3 -c"
        )
        _, stride = parse_frontmatter(AGENTS_DIR / "appsec-stride-analyzer-v2.md")
        assert "log_event.py" in stride

    def test_context_v2_logging_ownership_is_explicit(self):
        shared = (AGENTS_DIR / "shared" / "logging-standard.md").read_text(encoding="utf-8")
        assert "controller and skill emit" in shared
        assert "controller proxy event must never claim" in shared
        for name in KERNEL_PRELOAD_ROLES:
            _, body = parse_frontmatter(AGENTS_DIR / f"{name}.md")
            assert "AGENT_START" in body and "AGENT_END" in body
            assert "AGENT_INVOKE" in body and "AGENT_DONE" in body

    def test_every_agent_that_opens_a_lifecycle_also_closes_it(self):
        """An agent that documents AGENT_START must document how it ends.

        The lifecycle invariant used to be asserted only over
        KERNEL_PRELOAD_ROLES, so any agent outside that set could open a
        lifecycle and never close it without a test noticing. The abuse-case
        verifier did exactly that: 11 dispatches logged AGENT_START and none
        logged AGENT_END, leaving verify_run_costs.py unable to bind their
        usage. Scope this to every agent definition so it cannot rot again for
        the next role added outside the kernel set.

        Closing counts either way — a literal AGENT_END emitted through
        log_event.py, or a delegated call to log_agent_end.py.
        """
        for path in sorted(AGENTS_DIR.glob("appsec-*.md")):
            _, body = parse_frontmatter(path)
            if "AGENT_START" not in body:
                continue
            assert "AGENT_END" in body or "log_agent_end" in body, (
                f"{path.name} documents AGENT_START but never closes the lifecycle — "
                "add an AGENT_END emission (or a log_agent_end.py call)"
            )

    def test_context_v2_control_analyst_does_not_author_stride_profile(self):
        _, body = parse_frontmatter(AGENTS_DIR / "appsec-control-analyst.md")
        assert "top-level keys" in body
        assert "must be final component\nIDs" in body
        assert "Omit a component when it has no semantic value" in body
        assert "Never write `_stride_profile`" in body
        flat = " ".join(body.split())
        assert "controller derives that reserved routing value from `.skill-config.json`" in flat

    def test_context_v2_semantic_roles_preserve_component_path_ownership(self):
        _, architecture = parse_frontmatter(AGENTS_DIR / "appsec-architecture-analyst.md")
        _, controls = parse_frontmatter(AGENTS_DIR / "appsec-control-analyst.md")
        architecture_flat = " ".join(architecture.split())
        controls_flat = " ".join(controls.split())

        assert "including handlers, middleware, and delegated initialization code" in architecture_flat
        assert "Shared files may belong to multiple co-located security components" in architecture_flat
        assert "retain the fact in the applicable semantic field but omit the routing hint" in controls_flat
        assert '--repo-root "$REPO_ROOT"' in controls

    def test_recon_scanner_self_check_uses_canonical_oauth_heading(self):
        meta, body = parse_frontmatter(AGENTS_DIR / "appsec-recon-scanner.md")
        template = (AGENTS_DIR / "shared" / "recon-output-template.md").read_text(encoding="utf-8")
        assert "$CLAUDE_PLUGIN_ROOT/agents/shared/recon-output-template.md` once in full" in body
        assert "sub-sections 7.1–7.32" in body
        assert "6.1–6.32" not in body
        assert "### 6." not in template
        assert "7.1–7.32" in template
        assert "hard cap of **200 lines**" not in template
        assert "The 200-line cap is blocking" not in body
        assert "never omit required headings to meet the target" in body
        assert "scripts/validate_recon_summary.py" in body
        assert "the **next tool call**" in body
        assert "Do not write `.recon-signals.json`" in body
        assert "--normalize-key-files" in body
        assert "relative-file:single-line" in body
        assert "Section 7.28 is Container Runtime Hardening" in body

        discovery_limit = int(re.search(r"`DISCOVERY_TOOL_CALL_LIMIT=(\d+)`", body).group(1))
        publication_reserve = int(re.search(r"`PUBLICATION_TOOL_CALL_RESERVE=(\d+)`", body).group(1))
        assert discovery_limit == 22
        assert publication_reserve >= 10
        assert meta["maxTurns"] - discovery_limit >= publication_reserve
        assert "Read` call without `offset` or `limit`" in " ".join(body.split())
        assert "Do not read the template during Steps 1–3" in body
        assert "`MANIFEST_READ_CAP=8`" in body
        assert "`DEPLOYMENT_READ_CAP=5`" in body
        assert "`CONFIG_READ_CAP=5`" in body
        assert "`GREP_RESULT_CAP_PER_CATEGORY=40`" in body
        assert "disclose the omitted count" in body

    def test_context_resolver_self_validates_before_completion(self):
        meta, body = parse_frontmatter(AGENTS_DIR / "appsec-context-resolver.md")
        assert "scripts/validate_threat_modeling_context.py" in body
        assert "--repair-missing-headings" in body
        assert "the **next tool call**" in body
        assert "Do not log completion or print the final summary before this exits 0" in " ".join(body.split())
        discovery_limit = int(re.search(r"`DISCOVERY_TOOL_CALL_LIMIT=(\d+)`", body).group(1))
        publication_reserve = int(re.search(r"`PUBLICATION_TOOL_CALL_RESERVE=(\d+)`", body).group(1))
        assert discovery_limit == 18
        assert publication_reserve >= 7
        assert meta["maxTurns"] - discovery_limit >= publication_reserve
        assert "Never spend the publication reserve on additional discovery" in body

    def test_context_resolver_never_sources_repository_values_as_shell(self):
        _meta, body = parse_frontmatter(AGENTS_DIR / "appsec-context-resolver.md")
        flat = " ".join(body.split())
        assert "Never write or source a shell environment file" in flat
        assert "never place discovered values into shell assignments" in flat
        assert "multiple paths in JSON" in flat

    @pytest.mark.parametrize(
        ("agent_name", "discovery_limit", "publication_reserve"),
        [
            ("appsec-architecture-analyst", 44, 16),
            ("appsec-trust-boundary-analyst", 14, 10),
            ("appsec-control-analyst", 28, 12),
            ("appsec-post-stride-synthesizer", 12, 8),
        ],
    )
    def test_required_context_v2_producers_reserve_publication_turns(
        self, agent_name, discovery_limit, publication_reserve
    ):
        meta, body = parse_frontmatter(AGENTS_DIR / f"{agent_name}.md")
        assert f"`DISCOVERY_TOOL_CALL_LIMIT={discovery_limit}`" in body
        assert f"`PUBLICATION_TOOL_CALL_RESERVE={publication_reserve}`" in body
        assert meta["maxTurns"] - discovery_limit >= publication_reserve
        assert "Count every tool call" in " ".join(body.split())

    def test_context_v2_producers_gate_outputs_before_controller_handoff(self):
        expected_tokens = {
            "appsec-actor-discoverer.md": ("validate_intermediate.py", "actors_discovered"),
            "appsec-architecture-analyst.md": (
                "validate_fragment.py",
                "components",
                "data-flows",
                "assets",
                "attack-surface-overrides",
            ),
            "appsec-config-scanner.md": (
                "normalize_config_scan.py",
                "validate_intermediate.py",
                "config_scan_findings",
            ),
            "appsec-context-resolver.md": ("validate_threat_modeling_context.py",),
            "appsec-control-analyst.md": (
                "validate_fragment.py",
                "security-controls",
                "validate_intermediate.py",
                "stride_analyst_context",
            ),
            "appsec-evidence-verifier.md": (
                "validate_intermediate.py",
                "evidence_verification",
            ),
            "appsec-post-stride-synthesizer.md": (
                "validate_fragment.py",
                "mitigation-overrides",
                "tier-root-causes",
            ),
            "appsec-recon-scanner.md": (
                "validate_recon_summary.py",
                "validate_intermediate.py",
                "recon_signals",
            ),
            "appsec-threat-merger.md": ("merge_threats.py", "validate-decisions", "$CANDIDATES_FILE"),
            "appsec-triage-validator.md": (
                "validate_intermediate.py",
                "triage_flags",
                "threats_merged",
            ),
            "appsec-trust-boundary-analyst.md": ("validate_fragment.py", "trust-boundary-candidates"),
        }
        for filename, tokens in expected_tokens.items():
            _, body = parse_frontmatter(AGENTS_DIR / filename)
            for token in tokens:
                assert token in body, f"{filename} does not producer-validate with {token}"

        _, stride = parse_frontmatter(AGENTS_DIR / "appsec-stride-analyzer-v2.md")
        assert "post-agent gate validates and may dispatch a semantic repair" in " ".join(stride.split())

    def test_threat_merger_partial_decisions_are_disjoint(self):
        _, body = parse_frontmatter(AGENTS_DIR / "appsec-threat-merger.md")
        assert "Never overlap\nthe `member_indices` of two decisions for the same group" in body
        assert "Each decision subset is disjoint from every other decision subset" in body

    def test_trust_boundary_analyst_uses_absolute_plugin_logging_contract_path(self):
        _, body = parse_frontmatter(AGENTS_DIR / "appsec-trust-boundary-analyst.md")
        assert "$CLAUDE_PLUGIN_ROOT/agents/shared/logging-standard.md" in body

    def test_stride_analyzer_mandates_output_dir_export(self):
        """Regression guard (2026-06-21 juice-shop run): 5/8 parallel stride
        analyzers never wrote .progress/<id>.json because they did not export
        OUTPUT_DIR as their first Bash call, so agent_progress.sh (which exits 0
        silently when $OUTPUT_DIR is unset) no-opped. The agent doc must mandate
        the export as the literal first command."""
        _, stride = parse_frontmatter(AGENTS_DIR / "appsec-stride-analyzer-v2.md")
        assert 'export OUTPUT_DIR="' in stride, (
            "stride-analyzer must mandate `export OUTPUT_DIR=` as its first Bash call "
            "so agent_progress.sh / log_event.py see the path (RC-3)"
        )

    def test_every_log_event_caller_mandates_output_dir_export(self):
        """Generalises the guard above to every agent that logs.

        The 2026-06-21 fix only covered stride-analyzer-v2, so the same defect
        recurred for the abuse-case verifiers on 2026-08-21: their doc handed
        the model a copy-paste `log_event.py "$OUTPUT_DIR" …` block while the
        dispatch supplies OUTPUT_DIR as prompt TEXT, never as a shell variable.
        Nothing in the plugin exports it — agent_logger's mutation lives in the
        hook process — so log_event refused to write and the run silently lost
        AGENT_START/END coverage. An agent that invokes the emitter must carry
        the export next to it, not only a pointer to the shared standard.
        """
        missing = []
        for path in sorted(AGENTS_DIR.glob("appsec-*.md")):
            _, body = parse_frontmatter(path)
            if "log_event.py" not in body:
                continue
            # eval-judge is dispatched with OUT_DIR by its own dev-only skill.
            if 'export OUTPUT_DIR="' in body or 'export OUT_DIR="' in body:
                continue
            missing.append(path.name)
        assert not missing, (
            "these agents invoke log_event.py but never mandate the export, so "
            f"$OUTPUT_DIR is unset in their shell: {missing}"
        )

    def test_run_path_is_assigned_in_every_block_that_uses_it(self):
        """The export must sit in the SAME command as the use, not before it.

        The guard above only asks whether `export OUTPUT_DIR=` appears
        somewhere in the file, and agents/shared/logging-standard.md told
        agents to spend their "very first Bash call" on exactly that export and
        then use `$OUTPUT_DIR` in later blocks. Shell state does not survive
        between Bash calls — agents/shared/validation-routine.md says so in as
        many words — so the variable is empty again by the second block.

        The 2026-08-21 insecure-large-spring-app run shows both halves: the
        export succeeded at 19:13:13 and 19:47:44, and 4s resp. 68s later
        log_event.py refused an empty <output_dir> in the very next block. That
        cost the run its recon-scanner AGENT_START and left AGENT_START/END
        unpaired, which is what makes a dispatch drop out of cost accounting.

        A block that both assigns and uses the path is the only form that
        works, so that is the form this asserts.
        """
        offenders: list[str] = []
        # The shared standards are preloaded into agents, which copy their
        # blocks verbatim — a template that omits the assignment teaches the
        # defect to every agent at once, so they are checked here too.
        docs = sorted(AGENTS_DIR.glob("appsec-*.md")) + sorted((AGENTS_DIR / "shared").glob("*.md"))
        for path in docs:
            body = path.read_text(encoding="utf-8")
            if path.name.startswith("appsec-"):
                _, body = parse_frontmatter(path)
            if "log_event.py" not in body:
                continue
            for block in _BASH_BLOCKS.findall(body):
                if not _RUN_PATH_USE.search(block):
                    continue
                if _RUN_PATH_ASSIGN.search(block):
                    continue
                first = next((ln.strip() for ln in block.splitlines() if ln.strip()), "")
                offenders.append(f"{path.name}: {first[:70]}")
        assert not offenders, (
            "these Bash blocks use the run path but do not assign it in the "
            "same block, so it expands to the empty string:\n  " + "\n  ".join(offenders)
        )

    def test_context_v2_stride_producer_carries_exact_boundary_and_progress_contracts(self):
        _, stride = parse_frontmatter(AGENTS_DIR / "appsec-stride-analyzer-v2.md")
        flat = " ".join(stride.split())
        for field in ("boundary_id", "origin_component_id", "rationale", "evidence_locations"):
            assert f'"{field}"' in stride
        assert "Never emit `id`" in stride
        assert "exactly repeats its evidence" in flat
        assert "Never emit `TH-UNCLASSIFIED`" in stride
        assert 'bash "$CLAUDE_PLUGIN_ROOT/scripts/agent_progress.sh"' in stride
        assert "never invoke that shell script with Python" in stride
        assert "--agent stride-analyzer-v2" in stride
        assert '--component-id "<COMPONENT_ID literal>"' in flat
        assert "never author depth" in flat
        assert "`MODEL_ID` and exact plan `analysis.depth` (`full` or `light`)" in flat
        assert "never infer it from profile, budget, or another component" in flat
        assert "role/permission/identity claims as authorization questions" in flat
        assert "use one `missing-control-proof` escape" in flat
        assert "Never read the shared effective plan or dispatch manifest" in flat
        assert "Its `analysis`, `lens_ids`, and `inputs` own the policy" in flat
        assert "max_threats_per_category" in stride
        assert "read the plugin-owned full\n`data/threat-category-taxonomy.yaml` once" in stride
        thin_runtime = (AGENTS_DIR.parent / "skills" / "create-threat-model" / "SKILL-thin-stage1-v2.md").read_text(
            encoding="utf-8"
        )
        assert "STRIDE (<dispatch_jobs[].analysis_depth>): <dispatch_jobs[].component_id>" in thin_runtime
        assert "`COMPONENT_CONTEXT_PLAN_PATH`" in thin_runtime
        assert "`COMPONENT_CONTEXT_PLAN_SHA256`" in thin_runtime
        assert "`THREAT_TAXONOMY_SHA256`" in thin_runtime
        flat_runtime = " ".join(thin_runtime.split())
        assert "Never recommend resume" in flat_runtime
        assert "a later fresh full run restarts Stage 1" in flat_runtime

        architecture = (AGENTS_DIR / "appsec-architecture-analyst.md").read_text(encoding="utf-8")
        assert "AI/LLM surface separate only when it is a distinct deployable" in architecture
        assert "preserve the LLM evidence\nand lens instead of inventing a second component" in architecture

    def test_context_v2_root_cause_producer_maps_component_tiers_to_schema_keys(self):
        _, body = parse_frontmatter(AGENTS_DIR / "appsec-post-stride-synthesizer.md")
        assert "`client` → `edge`" in body
        assert "`application` → `server`" in body
        assert "Never emit `client` or\n`application` as keys" in body


# ---------------------------------------------------------------------------
# .gitignore-template — must cover all intermediate dot-files
# ---------------------------------------------------------------------------

GITIGNORE_TEMPLATE = Path(__file__).parent.parent / "scripts" / ".gitignore-template"

# Every intermediate dot-file that agents write to docs/security/
# Keep this list in sync with AGENTS.md "Intermediate Files" table and agent definitions.
EXPECTED_GITIGNORE_ENTRIES = [
    ".recon-summary.md",
    ".sca-practice-findings.json",
    ".known-bad-libs-findings.json",
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
# Logging template centralization (Sprint 1 Item D)
#
# The shared/logging-standard.md file is the single source of truth for the
# echo-template format. Agent prompts and compact runtimes must reference it
# rather than re-inlining full templates. The check below counts fully-formed
# `.agent-run.log` echo templates per file and flags any file that exceeds a
# drift ceiling. Files with genuinely stage-specific wrappers are exempted with
# a budget.
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
    # Orchestrator owns ASSESSMENT_START/END, CACHE_HIT, and a handful of
    # context-specific phase-logging call sites. Templates themselves now
    # delegate to shared/logging-standard.md; budget covers the contextual
    # call sites.
    # Renderer owns a minimal Phase-11 start/end pair so Stage 2 telemetry is
    # present without loading the full finalization prompt just for logging.
    "agents/appsec-threat-renderer.md": 2,
}

# Everything else: zero inline templates. Use shared/logging-standard.md.
AGENT_FILES_WITH_ZERO_BUDGET = [
    AGENTS_DIR / "appsec-qa-reviewer.md",
    AGENTS_DIR / "appsec-stride-analyzer-v2.md",
    AGENTS_DIR / "appsec-context-resolver.md",
    AGENTS_DIR / "appsec-recon-scanner.md",
    AGENTS_DIR / "appsec-triage-validator.md",
    AGENTS_DIR / "appsec-threat-merger.md",
    AGENTS_DIR / "appsec-architect-reviewer.md",
    AGENTS_DIR / "appsec-config-scanner.md",
    AGENTS_DIR / "appsec-eval-judge.md",
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
    AGENTS_DIR / "appsec-stride-analyzer-v2.md",
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
# Every agent or shared template that authors prose for the rendered report
# (verdict, STRIDE scenarios, security-architecture
# domain text, MS template) must reference `agents/shared/prose-style.md` as
# the runtime style anchor. This is the drift guard for the casework — if a
# refactor silently removes the reference, the QA reviewer loses the
# enforcement hook and prose quality drifts back toward generic LLM output.
# ---------------------------------------------------------------------------

PROSE_STYLE_FILE = AGENTS_DIR / "shared" / "prose-style.md"
PROSE_SAMPLES_FILE = AGENTS_DIR / "shared" / "prose-samples.md"

AGENT_FILES_AUTHORING_PROSE = [
    AGENTS_DIR / "appsec-threat-renderer.md",
    AGENTS_DIR / "appsec-secarch-renderer.md",
    AGENTS_DIR / "appsec-ms-renderer.md",
    AGENTS_DIR / "appsec-stride-analyzer-v2.md",
    AGENTS_DIR / "shared" / "ms-template.md",
]

# Subset that authors the Management-Summary prose fields (verdict)
# and therefore MUST load the worked Before/After
# pairs in prose-samples.md, not just the rules in prose-style.md. The
# stride-analyzer authors scenario/mitigation strings and the ms-template
# is template prose only — both are covered by prose-style.md alone for now.
AGENT_FILES_AUTHORING_MS_PROSE = [
    AGENTS_DIR / "appsec-threat-renderer.md",
    AGENTS_DIR / "appsec-ms-renderer.md",
]


class TestProseStyleAnchor:
    """Drift guard: prose-authoring agents must reference the prose-style
    anchor AND, for MS-prose authors, the prose-samples worked-examples
    file. The two files load together — examples without rules drift,
    rules without examples drift, both must remain wired at generation
    time.

    Anchored by AGENTS.md Rule 10. Removing the reference without removing
    the rule produces prose drift that is invisible until the next report
    review — the explicit test fails fast at edit time instead.
    """

    def test_prose_style_file_exists(self):
        assert PROSE_STYLE_FILE.is_file(), (
            f"missing prose-style anchor file: {PROSE_STYLE_FILE.relative_to(AGENTS_DIR.parent)}. "
            f"It is referenced by AGENTS.md Rule 10 and the prose-authoring agents."
        )

    def test_prose_samples_file_exists(self):
        assert PROSE_SAMPLES_FILE.is_file(), (
            f"missing prose-samples companion file: {PROSE_SAMPLES_FILE.relative_to(AGENTS_DIR.parent)}. "
            f"It carries the worked Before/After pairs that the MS-prose authoring "
            f"agents embed alongside prose-style.md. "
            f"See prose-style.md → 'Companion file' for the rationale."
        )

    def test_inline_code_semantics_are_owned_at_production(self):
        style = PROSE_STYLE_FILE.read_text(encoding="utf-8")
        stride = (AGENTS_DIR / "appsec-stride-analyzer-v2.md").read_text(encoding="utf-8")
        renderer = (AGENTS_DIR / "appsec-threat-renderer.md").read_text(encoding="utf-8")
        assert "Producer ownership:" in style
        assert "author these backticks in every Markdown-bearing prose field" in style
        assert "Kernel preloads `shared/prose-style.md`" in stride
        assert "$CLAUDE_PLUGIN_ROOT/agents/shared/prose-style.md" in renderer

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

    @pytest.mark.parametrize(
        "agent_file",
        AGENT_FILES_AUTHORING_MS_PROSE,
        ids=lambda p: str(p.relative_to(AGENTS_DIR.parent)),
    )
    def test_ms_prose_authoring_files_reference_samples(self, agent_file):
        assert agent_file.exists(), f"expected file missing: {agent_file}"
        text = agent_file.read_text(encoding="utf-8")
        assert "shared/prose-samples.md" in text, (
            f"{agent_file.relative_to(AGENTS_DIR.parent)} authors Management-Summary "
            f"prose (ms-verdict.json) but does not "
            f"reference `agents/shared/prose-samples.md`. Add a "
            f"`cat $CLAUDE_PLUGIN_ROOT/agents/shared/prose-samples.md` block alongside "
            f"the prose-style.md load so worked Before/After pairs load at runtime. "
            f"Sonnet imitates examples more reliably than it follows abstract rules."
        )


# Agents that read raw, attacker-controlled target-repo content (source,
# comments, configs, the lines around a finding) and therefore MUST carry an
# explicit untrusted-content guard so an injected directive cannot steer them.
# (PI-1/PI-2, audit 2026-06-11.)
REPO_READING_AGENTS = [
    "appsec-recon-scanner",
    "appsec-config-scanner",
    "appsec-evidence-verifier",
    "appsec-abuse-case-verifier",
    "appsec-stride-analyzer-v2",
    "appsec-threat-renderer",
    "appsec-secarch-renderer",
    "appsec-ms-renderer",
    "appsec-context-resolver",
    "appsec-eval-judge",
]


class TestUntrustedContentGuard:
    """Drift guard: every agent that ingests target-repo or external text must
    state that the content is untrusted data, never instructions. Dropping the
    guard re-opens the prompt-injection surface silently."""

    @pytest.mark.parametrize("agent_name", REPO_READING_AGENTS)
    def test_repo_reading_agent_has_untrusted_guard(self, agent_name):
        path = AGENTS_DIR / f"{agent_name}.md"
        assert path.is_file(), f"expected agent file missing: {path}"
        text = path.read_text(encoding="utf-8")
        assert re.search(r"untrusted|not instructions|never as instructions", text, re.I), (
            f"{agent_name}.md reads untrusted target-repo content but has no "
            f"untrusted-content guard. Add the boundary block (see "
            f"appsec-recon-scanner.md or appsec-stride-analyzer-v2.md). PI-1/PI-2."
        )


def test_stride_template_never_offers_null_for_a_string_only_field():
    """The analyzer copies its JSON template verbatim, so the template may not
    offer a value the schema rejects.

    `evidence.file` is typed as a bare `string` in stride.schema.yaml — no
    `"null"` member, unlike its `evidence` parent and its `line` sibling. The
    template nonetheless read `"<path relative to REPO_ROOT or null>"`, and two
    of eight component analysts did exactly that. A single such threat hard-fails
    the WHOLE component fragment, so each cost a full re-dispatch (juice-shop
    2026-08-01). Prose drifts; this pins the two sides together.
    """
    schema = yaml.safe_load((AGENTS_DIR.parent / "schemas" / "stride.schema.yaml").read_text(encoding="utf-8"))
    evidence = schema["$defs"]["normal"]["properties"]["threats"]["items"]["properties"]["evidence"]
    file_type = evidence["properties"]["file"]["type"]

    # Read the schema rather than hard-coding "string": should `file` ever gain a
    # "null" member deliberately, this test relaxes with it instead of failing.
    if "null" in file_type:
        pytest.skip("evidence.file now accepts null — the template may offer it again")

    text = (AGENTS_DIR / "appsec-stride-analyzer-v2.md").read_text(encoding="utf-8")
    line = next((ln for ln in text.splitlines() if '"file":' in ln and "REPO_ROOT" in ln), None)
    assert line is not None, "evidence.file template line not found in appsec-stride-analyzer-v2.md"
    assert "or null" not in line, (
        "the evidence.file template offers `null`, which stride.schema.yaml rejects "
        '(type: string). Say `never null` and point the author at `"evidence": null` '
        "for the whole object."
    )
    assert "never null" in line.lower(), "the template must state that evidence.file is never null"


def test_context_v2_architecture_agent_uses_bounded_data_classification_vocabulary():
    text = (AGENTS_DIR / "appsec-architecture-analyst.md").read_text(encoding="utf-8")
    assert "Use only `Public`, `Internal`, `Confidential`, or" in text
    assert "`Restricted` as the data classification" in text
    assert re.search(r"replaces the\s+provisional fingerprint", text)
    assert "reserve_ids.py asset --count <N> --output-dir" in text


def test_recon_signal_prompt_states_the_coupling_the_validator_enforces():
    """The producer prompt must carry both directions of the signal/status rule.

    `validate_intermediate.py` gained `true => supporting` on 2026-08-09 while
    the prompt kept stating only `supporting => true`. A producer that followed
    the prompt literally could set a boolean true with `status: "none"`, which
    the controller gate then rejected — one aborted run per occurrence, six
    minutes in. Whenever the enforced coupling changes, this test fails until
    the prompt says the same thing.
    """
    validator = (AGENTS_DIR.parent / "scripts" / "validate_intermediate.py").read_text(encoding="utf-8")
    forward = "must be 'supporting' when the signal is true"
    reverse = "cannot be 'supporting' when the signal is false"
    assert forward in validator and reverse in validator, (
        "the enforced recon-signal coupling moved; update this test and the producer prompt together"
    )

    prompt = (AGENTS_DIR / "appsec-recon-scanner.md").read_text(encoding="utf-8")
    rules = prompt.split("**Signal assignment rules:**", 1)[1]
    assert "a `true` boolean requires `supporting`" in rules, (
        "the prompt must state that a true signal requires supporting evidence"
    )
    assert "`supporting` requires the boolean to be `true`" in rules, (
        "the prompt must state that supporting evidence requires a true signal"
    )
    assert "set the boolean `false`" in rules, (
        "the prompt must name the compliant way out when no location was observed"
    )
    assert "never invent a location" in rules, "the way out must not be fabricated evidence"
