"""Pin the Phase 11 runtime-cleanup whitelist.

The plugin's Phase 11 finalization removes a small set of transient files
after a successful run. The whitelist is documented in
`agents/phases/phase-group-finalization.md` and additionally summarized
in `CLAUDE.md`. This test pins both copies of the list and the safety
gates so that:

  * adding a new transient artifact (e.g. a future `.merger.stderr`) forces
    an update here — that is the drift guard;
  * shrinking or moving the list is a deliberate test edit, not an accident;
  * the safety gates (KEEP_RUNTIME_FILES, threat-model.md presence,
    AGENT_ERROR check) cannot silently disappear.

The test does not run the cleanup script itself — Phase 11 cleanup is a
Bash block emitted by the orchestrator at runtime, not a standalone script.
What we can check from a pure Python test is the documentation contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
FINALIZATION_MD = PLUGIN_ROOT / "agents" / "phases" / "phase-group-finalization.md"
CLAUDE_MD = PLUGIN_ROOT / "CLAUDE.md"
SKILL_MD = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL.md"
RUNTIME_CLEANUP_PY = PLUGIN_ROOT / "scripts" / "runtime_cleanup.py"

# ---------------------------------------------------------------------------
# Whitelist — pinned. To add a new transient artifact:
#   1) add it to the cleanup Bash block in phase-group-finalization.md
#   2) add it to CLAUDE.md "Runtime artifact cleanup" section
#   3) add it here
# All three live-fire failures (cleanup, doc, doc) become test failures
# until the lists are in sync.
# ---------------------------------------------------------------------------
# "Always" wave — removed regardless of QA / architect stage. These map 1:1
# to ``runtime_cleanup.ALWAYS_FILES`` / ``ALWAYS_DIRS`` and are also listed in
# the Phase-11 doc table.
EXPECTED_WHITELIST_FILES = {
    ".dep-scan.pid",
    ".dep-scan.stdout",
    ".merge-candidates.json",
    ".merge-decisions.json",
    ".management-summary-draft.md",
    ".phase-epoch",
    ".session-agent-map",
    ".assessment-summary-emitted",
    ".prior-findings-index.json",
    ".stage1-resume-count",
}
EXPECTED_WHITELIST_DIRS = {
    ".progress",
    ".taxonomy-slices",
}

# Post-QA wave — removed by ``runtime_cleanup.py --stage post-qa`` once the
# QA reviewer has written ``.qa-status.json`` with ``status=pass`` and an
# empty (or absent) ``.qa-repair-plan.json``. Pinned here so shrinking the
# list is a deliberate edit.
EXPECTED_POST_QA_FILES_IF_PASS = {
    ".qa-status.json",
    ".qa-repair-plan.json",
    ".pre-render-report.json",
    ".pre-render-repair-plan.json",
    # M2.13 — Sprint 4 auto-retry-loop bookkeeping. Reaped on successful
    # completion (this branch only runs when QA passed). On exit 2 /
    # exhausted-retries the skill bypasses this cleanup entirely, so the
    # user's exhausted-retries banner can still point at these files.
    ".inline-shortcut-retry-count",
    ".inline-shortcut-repair-plan.json",
}
EXPECTED_POST_QA_DIRS = {
    ".fragments",
}
# Post-architect wave — analogous.
EXPECTED_POST_ARCH_FILES_IF_PASS = {
    ".architect-status.json",
    ".architect-repair-plan.json",
}

# Files that MUST NOT appear in the cleanup whitelist. These are audit
# trail or carry-forward state — losing them would break incremental mode
# or leave the user without evidence for the report.
NEVER_CLEANUP = {
    ".threat-modeling-context.md",
    ".recon-summary.md",
    ".dep-scan.json",
    ".threats-merged.json",
    ".triage-flags.json",
    ".architect-review.md",
    ".requirements.yaml",
    ".appsec-cache",
    ".appsec-checkpoint",
    ".agent-run.log",
    ".hook-events.log",
    "threat-model.md",
    "threat-model.yaml",
    "threat-model.sarif.json",
    "pentest-tasks.yaml",
    "analysis-model.md",
}


@pytest.fixture(scope="module")
def finalization_text() -> str:
    return FINALIZATION_MD.read_text()


@pytest.fixture(scope="module")
def claude_text() -> str:
    return CLAUDE_MD.read_text()


@pytest.fixture(scope="module")
def skill_text() -> str:
    return SKILL_MD.read_text()


@pytest.fixture(scope="module")
def cleanup_py_text() -> str:
    return RUNTIME_CLEANUP_PY.read_text()


# ---------------------------------------------------------------------------
# Whitelist coverage in the orchestrator's Bash block
# ---------------------------------------------------------------------------

class TestFinalizationWhitelist:
    @pytest.mark.parametrize("filename", sorted(EXPECTED_WHITELIST_FILES))
    def test_file_in_cleanup_table(self, finalization_text, filename):
        """Every whitelisted file must appear in the Phase-11 doc table so
        readers of the architecture doc see the same list the script uses."""
        token = f'`$OUTPUT_DIR/{filename}`'
        assert token in finalization_text, (
            f"phase-group-finalization.md cleanup table is missing entry for {filename!r}. "
            f"Add the path to the Runtime Cleanup section's table."
        )

    @pytest.mark.parametrize("dirname", sorted(EXPECTED_WHITELIST_DIRS))
    def test_directory_in_cleanup_table(self, finalization_text, dirname):
        token = f'`$OUTPUT_DIR/{dirname}/`'
        assert token in finalization_text, (
            f"phase-group-finalization.md cleanup table is missing directory entry for {dirname!r}."
        )

    @pytest.mark.parametrize("never", sorted(NEVER_CLEANUP))
    def test_audit_artifact_not_in_script_whitelist(self, cleanup_py_text, never):
        """Audit artifacts must not appear in any of runtime_cleanup.py's
        removal lists. The script defines them as ``ALWAYS_FILES``,
        ``ALWAYS_DIRS``, ``POST_QA_FILES_IF_PASS``, ``POST_QA_DIRS``, and
        ``POST_ARCH_FILES_IF_PASS`` — grep every list for each NEVER path."""
        import re as _re
        list_names = (
            "ALWAYS_FILES", "ALWAYS_DIRS",
            "POST_QA_FILES_IF_PASS", "POST_QA_DIRS",
            "POST_ARCH_FILES_IF_PASS",
        )
        for name in list_names:
            m = _re.search(
                rf"^{name}\s*=\s*\[(.*?)\]",
                cleanup_py_text, _re.DOTALL | _re.MULTILINE,
            )
            assert m, f"{name} list not found in runtime_cleanup.py"
            body = m.group(1)
            assert f'"{never}"' not in body, (
                f"Audit artifact {never!r} must NOT appear in runtime_cleanup.py → {name}"
            )


# ---------------------------------------------------------------------------
# Safety gates — verified in the standalone script
# ---------------------------------------------------------------------------

class TestCleanupGates:
    def test_keep_runtime_files_gate(self, cleanup_py_text):
        assert "KEEP_RUNTIME_FILES" in cleanup_py_text, (
            "runtime_cleanup.py must honor the KEEP_RUNTIME_FILES env var"
        )
        assert "keep_runtime_files" in cleanup_py_text, (
            "runtime_cleanup.py must accept --keep-runtime-files"
        )

    def test_threat_model_md_existence_gate(self, cleanup_py_text):
        assert 'threat-model.md' in cleanup_py_text, (
            "runtime_cleanup.py gate must require threat-model.md to exist before deleting"
        )

    def test_agent_error_grep_gate(self, cleanup_py_text):
        assert 'AGENT_ERROR' in cleanup_py_text, (
            "runtime_cleanup.py gate must scan .agent-run.log for AGENT_ERROR"
        )

    def test_cleanup_logs_outcome(self, cleanup_py_text):
        assert 'RUNTIME_CLEANUP' in cleanup_py_text, (
            "runtime_cleanup.py must append a RUNTIME_CLEANUP line to .agent-run.log "
            "so the user can audit what was removed"
        )


# ---------------------------------------------------------------------------
# Whitelist pinning — the script's Python constants must match the pinned
# expected sets. This is the drift guard: editing ``ALWAYS_FILES`` etc.
# without also updating the expected set here causes a test failure.
# ---------------------------------------------------------------------------

class TestScriptWhitelist:
    def _extract_list(self, text: str, name: str) -> set[str]:
        import re as _re
        m = _re.search(rf"^{name}\s*=\s*\[(.*?)\]", text, _re.DOTALL | _re.MULTILINE)
        if not m:
            return set()
        return set(_re.findall(r'"([^"]+)"', m.group(1)))

    def test_always_files_match(self, cleanup_py_text):
        assert self._extract_list(cleanup_py_text, "ALWAYS_FILES") == EXPECTED_WHITELIST_FILES

    def test_always_dirs_match(self, cleanup_py_text):
        assert self._extract_list(cleanup_py_text, "ALWAYS_DIRS") == EXPECTED_WHITELIST_DIRS

    def test_post_qa_files_match(self, cleanup_py_text):
        assert self._extract_list(cleanup_py_text, "POST_QA_FILES_IF_PASS") \
            == EXPECTED_POST_QA_FILES_IF_PASS

    def test_post_qa_dirs_match(self, cleanup_py_text):
        assert self._extract_list(cleanup_py_text, "POST_QA_DIRS") \
            == EXPECTED_POST_QA_DIRS

    def test_post_arch_files_match(self, cleanup_py_text):
        assert self._extract_list(cleanup_py_text, "POST_ARCH_FILES_IF_PASS") \
            == EXPECTED_POST_ARCH_FILES_IF_PASS


# ---------------------------------------------------------------------------
# Documentation in CLAUDE.md
# ---------------------------------------------------------------------------

class TestClaudeMdDocsClean:
    def test_section_exists(self, claude_text):
        assert "Runtime artifact cleanup" in claude_text, (
            "CLAUDE.md must document the Runtime artifact cleanup behavior"
        )

    @pytest.mark.parametrize(
        "filename",
        sorted(
            EXPECTED_WHITELIST_FILES | EXPECTED_WHITELIST_DIRS
        ),
    )
    def test_filename_mentioned_in_docs(self, claude_text, filename):
        # Both `.progress/` (with trailing slash) and `.progress` should match.
        assert filename in claude_text, (
            f"CLAUDE.md cleanup section should mention {filename!r} so users "
            f"know what gets removed."
        )

    def test_keep_runtime_files_flag_mentioned(self, claude_text):
        assert "--keep-runtime-files" in claude_text, (
            "CLAUDE.md must reference the --keep-runtime-files opt-out flag"
        )


# ---------------------------------------------------------------------------
# SKILL.md flag wiring
# ---------------------------------------------------------------------------

class TestSkillMdFlag:
    def test_flag_in_argument_table(self, skill_text):
        assert "--keep-runtime-files" in skill_text, (
            "SKILL.md flag-parsing table must document --keep-runtime-files"
        )

    def test_env_var_passed_to_orchestrator(self, skill_text):
        assert "KEEP_RUNTIME_FILES" in skill_text, (
            "SKILL.md must pass KEEP_RUNTIME_FILES env to the orchestrator (Stage 1 handoff)"
        )

    def test_skill_invokes_cleanup_script(self, skill_text):
        """The skill layer MUST call the deterministic cleanup at the end of
        Completion Summary — this is the fallback that runs even when the
        orchestrator skipped its own Phase 11 cleanup due to turn-budget
        pressure."""
        assert "runtime_cleanup.py" in skill_text, (
            "SKILL.md Completion Summary must invoke scripts/runtime_cleanup.py "
            "so cleanup runs deterministically at the end of every successful run"
        )

    def test_skill_invokes_post_qa_stage(self, skill_text):
        assert "runtime_cleanup.py" in skill_text and "post-qa" in skill_text, (
            "SKILL.md must invoke runtime_cleanup.py with --stage post-qa after "
            "Stage 2 (QA reviewer) completes"
        )

    def test_skill_invokes_post_architect_stage(self, skill_text):
        assert "post-architect" in skill_text, (
            "SKILL.md must invoke runtime_cleanup.py with --stage post-architect "
            "when ARCHITECT_REVIEW=true"
        )
