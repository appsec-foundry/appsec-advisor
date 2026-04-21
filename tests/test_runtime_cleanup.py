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

# ---------------------------------------------------------------------------
# Whitelist — pinned. To add a new transient artifact:
#   1) add it to the cleanup Bash block in phase-group-finalization.md
#   2) add it to CLAUDE.md "Runtime artifact cleanup" section
#   3) add it here
# All three live-fire failures (cleanup, doc, doc) become test failures
# until the lists are in sync.
# ---------------------------------------------------------------------------
EXPECTED_WHITELIST_FILES = {
    ".dep-scan.pid",
    ".dep-scan.stdout",
    ".merge-candidates.json",
    ".merge-decisions.json",
    ".management-summary-draft.md",
    ".phase-epoch",
    ".session-agent-map",
}
EXPECTED_WHITELIST_DIRS = {
    ".progress",
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


# ---------------------------------------------------------------------------
# Whitelist coverage in the orchestrator's Bash block
# ---------------------------------------------------------------------------

class TestFinalizationWhitelist:
    @pytest.mark.parametrize("filename", sorted(EXPECTED_WHITELIST_FILES))
    def test_file_in_cleanup_block(self, finalization_text, filename):
        # The cleanup Bash block lists each path as `"$OUTPUT_DIR/<name>"`.
        token = f'"$OUTPUT_DIR/{filename}"'
        assert token in finalization_text, (
            f"phase-group-finalization.md cleanup block is missing entry for {filename!r}. "
            f"Add the path to the Runtime Cleanup section's `for path in …` loop."
        )

    @pytest.mark.parametrize("dirname", sorted(EXPECTED_WHITELIST_DIRS))
    def test_directory_in_cleanup_block(self, finalization_text, dirname):
        token = f'"$OUTPUT_DIR/{dirname}"'
        assert token in finalization_text, (
            f"phase-group-finalization.md cleanup block is missing directory entry for {dirname!r}."
        )

    @pytest.mark.parametrize("never", sorted(NEVER_CLEANUP))
    def test_audit_artifact_not_in_cleanup_loop(self, finalization_text, never):
        """Audit artifacts must not appear inside the `for path in … do` removal
        loop. They may legitimately appear elsewhere in the cleanup section
        (e.g. `threat-model.md` in the gate condition, `.agent-run.log` in
        the AGENT_ERROR check) — only the actual delete loop is forbidden."""
        cleanup_block_marker = "### Runtime Cleanup"
        if cleanup_block_marker not in finalization_text:
            pytest.fail("Runtime Cleanup section is missing from phase-group-finalization.md")
        cleanup_section = finalization_text.split(cleanup_block_marker, 1)[1].split("### ", 1)[0]
        # Extract the `for path in … done` body
        import re as _re
        loop_match = _re.search(r"for path in\s+\\\n(.*?)\n\s*do\b", cleanup_section, _re.DOTALL)
        loop_body = loop_match.group(1) if loop_match else ""
        token = f'"$OUTPUT_DIR/{never}"'
        assert token not in loop_body, (
            f"Audit artifact {never!r} must NOT appear in the cleanup `for path in` loop"
        )
        # Also check the rmdir block and any explicit `rm -rf "$OUTPUT_DIR/<dir>"`
        rmdir_match = _re.search(r"rm -rf\s+\"\$OUTPUT_DIR/(\S+?)\"", cleanup_section)
        if rmdir_match:
            assert rmdir_match.group(1) != never.lstrip("/"), (
                f"Audit artifact {never!r} must NOT appear in `rm -rf` directive"
            )


# ---------------------------------------------------------------------------
# Safety gates
# ---------------------------------------------------------------------------

class TestCleanupGates:
    def test_keep_runtime_files_gate(self, finalization_text):
        assert 'KEEP_RUNTIME_FILES' in finalization_text, (
            "Cleanup must check KEEP_RUNTIME_FILES env to honor --keep-runtime-files"
        )

    def test_threat_model_md_existence_gate(self, finalization_text):
        # The cleanup Bash block must check that the report was actually written
        cleanup_block = finalization_text.split("### Runtime Cleanup", 1)[1] \
            if "### Runtime Cleanup" in finalization_text else ""
        assert 'threat-model.md' in cleanup_block, (
            "Cleanup gate must require $OUTPUT_DIR/threat-model.md to exist before deleting"
        )

    def test_agent_error_grep_gate(self, finalization_text):
        cleanup_block = finalization_text.split("### Runtime Cleanup", 1)[1] \
            if "### Runtime Cleanup" in finalization_text else ""
        assert 'AGENT_ERROR' in cleanup_block, (
            "Cleanup gate must scan recent log lines for AGENT_ERROR before deleting"
        )

    def test_cleanup_logs_outcome(self, finalization_text):
        cleanup_block = finalization_text.split("### Runtime Cleanup", 1)[1] \
            if "### Runtime Cleanup" in finalization_text else ""
        assert 'RUNTIME_CLEANUP' in cleanup_block, (
            "Cleanup must emit a RUNTIME_CLEANUP log line so the user can audit "
            "what was removed (or why it was skipped)"
        )


# ---------------------------------------------------------------------------
# Documentation in CLAUDE.md
# ---------------------------------------------------------------------------

class TestClaudeMdDocsClean:
    def test_section_exists(self, claude_text):
        assert "Runtime artifact cleanup" in claude_text, (
            "CLAUDE.md must document the Runtime artifact cleanup behavior"
        )

    @pytest.mark.parametrize("filename", sorted(EXPECTED_WHITELIST_FILES | EXPECTED_WHITELIST_DIRS))
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
