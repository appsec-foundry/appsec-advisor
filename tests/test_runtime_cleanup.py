"""Pin the Phase 11 runtime-cleanup whitelist.

The plugin's Phase 11 finalization removes a small set of transient files
after a successful run. The whitelist is documented in
`agents/phases/phase-group-finalization.md` and additionally summarized
in `AGENTS.md`. This test pins both copies of the list and the safety
gates so that:

  * adding a new transient artifact (e.g. a future `.merger.stderr`) forces
    an update here — that is the drift guard;
  * shrinking or moving the list is a deliberate test edit, not an accident;
  * the safety gates (KEEP_RUNTIME_FILES, threat-model.md presence,
    AGENT_ERROR check) cannot silently disappear.

The suite pins the documentation contract and also executes the standalone
runtime_cleanup.py behavior directly. The behavior tests cover the safety
gates and stage-specific cleanup waves so the text guards do not drift away
from the script's actual deletion decisions.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import runtime_cleanup as rc

PLUGIN_ROOT = Path(__file__).parent.parent
FINALIZATION_MD = PLUGIN_ROOT / "agents" / "phases" / "phase-group-finalization.md"
AGENTS_MD = PLUGIN_ROOT / "AGENTS.md"
CLEANUP_WHITELIST_MD = PLUGIN_ROOT / "docs" / "internal" / "contracts" / "cleanup-whitelist.md"
SKILL_MD = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL.md"
SKILL_IMPL_MD = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md"
RUNTIME_CLEANUP_PY = PLUGIN_ROOT / "scripts" / "runtime_cleanup.py"

# ---------------------------------------------------------------------------
# Whitelist — pinned. To add a new transient artifact:
#   1) add it to the cleanup Bash block in phase-group-finalization.md
#   2) add it to AGENTS.md "Runtime artifact cleanup" section
#   3) add it here
# All three live-fire failures (cleanup, doc, doc) become test failures
# until the lists are in sync.
# ---------------------------------------------------------------------------
# "Always" wave — removed regardless of QA / architect stage. These map 1:1
# to ``runtime_cleanup.ALWAYS_FILES`` / ``ALWAYS_DIRS`` and are also listed in
# the Phase-11 doc table.
EXPECTED_WHITELIST_FILES = {
    ".merge-candidates.json",
    ".merge-decisions.json",
    ".management-summary-draft.md",
    ".phase-epoch",
    ".session-agent-map",
    ".assessment-summary-emitted",
    ".assessment-owner-sid",
    ".prior-findings-index.json",
    ".stage1-resume-count",
    # M3.3: added to clean up state files left behind by crashed runs.
    ".skill-config.json",
    ".recon-patterns.json",
    # Pre-existing additions visible in scripts/runtime_cleanup.py:
    ".context-resolver.stdout",
    ".ctx-resolver.pid",
    ".recon-scanner.pid",
    ".recon-scanner.stdout",
    ".coverage-gaps.json",
    ".scan-manifest.txt",
    ".triage-ranking.json",
    ".qa-prepass.json",
    # Latest live-progress snapshot; .agent-run.log is the durable audit trail.
    ".appsec-progress.json",
    # M3.6 — self-liveness counter from skill_watchdog.py.
    ".skill-watchdog.tick",
    # Architecture-coverage delivery (arch.md) — deterministic intermediates.
    ".route-inventory.json",
    ".architecture-coverage.json",
    ".arch-coverage-threats.json",
}
EXPECTED_WHITELIST_DIRS = {
    ".progress",
    ".taxonomy-slices",
    ".dispatch-context",
    ".merge-context",
    # M3.6 — per-tool-call markers; sub-agent calls without a propagating
    # PostToolUse may leave stale entries that the post-run cleanup wipes.
    ".active-tool-calls",
}

# Post-QA wave — removed by ``runtime_cleanup.py --stage post-qa`` once the
# QA reviewer has written ``.qa-status.json`` with ``status=pass`` and an
# empty (or absent) ``.qa-repair-plan.json``. Pinned here so shrinking the
# list is a deliberate edit.
EXPECTED_POST_QA_FILES_IF_PASS = {
    ".qa-status.json",
    ".qa-repair-plan.json",
    # Sprint 3A (M3.5) — content-repair plan from QA reviewer; reaped on
    # clean QA, preserved otherwise so the user can inspect the applier's
    # input.
    ".qa-content-repair-plan.json",
    ".pre-render-report.json",
    ".pre-render-repair-plan.json",
    # M2.13 — Sprint 4 auto-retry-loop bookkeeping. Reaped on successful
    # completion (this branch only runs when QA passed). On exit 2 /
    # exhausted-retries the skill bypasses this cleanup entirely, so the
    # user's exhausted-retries banner can still point at these files.
    ".inline-shortcut-retry-count",
    ".inline-shortcut-repair-plan.json",
    # M2.14 — Sprint 6 observability. Reaped on success; canonical
    # persistence is the §Composition Notes appendix in threat-model.md.
    ".compose-stats.json",
    # Report-integrity manifest. Reaped on clean pass; preserved on a
    # non-clean run for inspection.
    ".render-integrity.json",
    # M2.15 — Sprint 7 observability. Reaped on success; canonical
    # persistence is the §Run Issues appendix in threat-model.md.
    ".run-issues.json",
    ".run-issues-fixes.json",
    # Wall-clock timing markers — rendered figure lives in §Run Statistics.
    ".scan-start-epoch",
    ".scan-wall-seconds",
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
    ".sca-practice-findings.json",
    ".known-bad-libs-findings.json",
    ".dep-update-activity.json",
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
    "threat-model.pdf",
    "threat-model.html",
    "pentest-tasks.yaml",
    "analysis-model.md",
}


@pytest.fixture(scope="module")
def finalization_text() -> str:
    return FINALIZATION_MD.read_text()


@pytest.fixture(scope="module")
def agents_text() -> str:
    return AGENTS_MD.read_text()


@pytest.fixture(scope="module")
def whitelist_text() -> str:
    return CLEANUP_WHITELIST_MD.read_text()


@pytest.fixture(scope="module")
def skill_text() -> str:
    return SKILL_MD.read_text() + "\n" + SKILL_IMPL_MD.read_text()


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
        token = f"`$OUTPUT_DIR/{filename}`"
        assert token in finalization_text, (
            f"phase-group-finalization.md cleanup table is missing entry for {filename!r}. "
            f"Add the path to the Runtime Cleanup section's table."
        )

    @pytest.mark.parametrize("dirname", sorted(EXPECTED_WHITELIST_DIRS))
    def test_directory_in_cleanup_table(self, finalization_text, dirname):
        token = f"`$OUTPUT_DIR/{dirname}/`"
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
            "ALWAYS_FILES",
            "ALWAYS_DIRS",
            "POST_QA_FILES_IF_PASS",
            "POST_QA_DIRS",
            "POST_ARCH_FILES_IF_PASS",
        )
        for name in list_names:
            m = _re.search(
                rf"^{name}\s*=\s*\[(.*?)\]",
                cleanup_py_text,
                _re.DOTALL | _re.MULTILINE,
            )
            assert m, f"{name} list not found in runtime_cleanup.py"
            body = m.group(1)
            assert f'"{never}"' not in body, f"Audit artifact {never!r} must NOT appear in runtime_cleanup.py → {name}"


# ---------------------------------------------------------------------------
# Safety gates — verified in the standalone script
# ---------------------------------------------------------------------------


class TestCleanupGates:
    def test_keep_runtime_files_gate(self, cleanup_py_text):
        assert "KEEP_RUNTIME_FILES" in cleanup_py_text, "runtime_cleanup.py must honor the KEEP_RUNTIME_FILES env var"
        assert "keep_runtime_files" in cleanup_py_text, "runtime_cleanup.py must accept --keep-runtime-files"

    def test_threat_model_md_existence_gate(self, cleanup_py_text):
        assert "threat-model.md" in cleanup_py_text, (
            "runtime_cleanup.py gate must require threat-model.md to exist before deleting"
        )

    def test_agent_error_grep_gate(self, cleanup_py_text):
        assert "AGENT_ERROR" in cleanup_py_text, "runtime_cleanup.py gate must scan .agent-run.log for AGENT_ERROR"

    def test_cleanup_logs_outcome(self, cleanup_py_text):
        assert "RUNTIME_CLEANUP" in cleanup_py_text, (
            "runtime_cleanup.py must append a RUNTIME_CLEANUP line to .agent-run.log "
            "so the user can audit what was removed"
        )


# ---------------------------------------------------------------------------
# Runtime behavior — execute the cleanup logic, not just text drift guards.
# ---------------------------------------------------------------------------


def _completed_output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    (out / "threat-model.md").write_text("# completed\n", encoding="utf-8")
    return out


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


class TestRuntimeCleanupBehavior:
    def test_keep_runtime_files_flag_skips_and_logs(self, tmp_path):
        out = _completed_output_dir(tmp_path)
        transient = out / ".merge-candidates.json"
        transient.write_text("{}", encoding="utf-8")

        report = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=True, force=False)

        assert report["skipped"] is True
        assert "opt-out" in report["skip_reason"]
        assert transient.exists()
        log_text = (out / ".agent-run.log").read_text(encoding="utf-8")
        assert "RUNTIME_CLEANUP" in log_text and "skipped" in log_text

    def test_keep_runtime_files_env_skips(self, tmp_path, monkeypatch):
        out = _completed_output_dir(tmp_path)
        transient = out / ".merge-candidates.json"
        transient.write_text("{}", encoding="utf-8")
        monkeypatch.setenv("KEEP_RUNTIME_FILES", "true")

        report = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=False, force=False)

        assert report["skipped"] is True
        assert transient.exists()

    def test_missing_threat_model_skips_unless_forced(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        transient = out / ".merge-candidates.json"
        transient.write_text("{}", encoding="utf-8")

        skipped = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=False, force=False)
        forced = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=False, force=True)

        assert skipped["skipped"] is True
        assert "threat-model.md missing" in skipped["skip_reason"]
        assert forced["skipped"] is False
        assert ".merge-candidates.json" in forced["removed"]
        assert not transient.exists()

    def test_agent_error_skips_without_self_poisoning_log(self, tmp_path):
        out = _completed_output_dir(tmp_path)
        transient = out / ".merge-candidates.json"
        transient.write_text("{}", encoding="utf-8")
        (out / ".agent-run.log").write_text("2026-06-13T00:00:00Z [s] ERROR AGENT_ERROR worker failed\n")

        report = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=False, force=False)

        assert report["skipped"] is True
        assert transient.exists()
        # The cleanup skip line must not create another uppercase AGENT_ERROR
        # token that would keep future cleanup runs stuck on their own audit log.
        log_lines = (out / ".agent-run.log").read_text(encoding="utf-8").splitlines()
        assert sum("AGENT_ERROR" in line for line in log_lines) == 1

    def test_post_architect_removes_status_and_plan_after_pass(self, tmp_path):
        out = _completed_output_dir(tmp_path)
        _write_json(out / ".architect-status.json", {"status": "pass"})
        _write_json(out / ".architect-repair-plan.json", {"issue_count": 0})
        (out / ".architect-review.md").write_text("# review\n", encoding="utf-8")

        report = rc.run_cleanup(out, stage="post-architect", keep_runtime_files=False, force=False)

        assert report["skipped"] is False
        assert ".architect-status.json" in report["removed"]
        assert ".architect-repair-plan.json" in report["removed"]
        assert not (out / ".architect-status.json").exists()
        assert not (out / ".architect-repair-plan.json").exists()
        assert (out / ".architect-review.md").exists()

    def test_post_architect_preserves_files_when_review_not_clean(self, tmp_path):
        out = _completed_output_dir(tmp_path)
        _write_json(out / ".architect-status.json", {"status": "repair_required"})
        _write_json(out / ".architect-repair-plan.json", {"issue_count": 1})

        report = rc.run_cleanup(out, stage="post-architect", keep_runtime_files=False, force=False)

        assert report["skipped"] is False
        assert not report["removed"]
        assert ".architect-status.json / .architect-repair-plan.json" in report["preserved"][0]
        assert (out / ".architect-status.json").exists()
        assert (out / ".architect-repair-plan.json").exists()

    def test_never_artifacts_survive_all_stage_cleanup(self, tmp_path):
        out = _completed_output_dir(tmp_path)
        (out / ".merge-candidates.json").write_text("{}", encoding="utf-8")
        for name in (".sca-practice-findings.json", ".known-bad-libs-findings.json", "threat-model.yaml"):
            (out / name).write_text("{}\n", encoding="utf-8")

        report = rc.run_cleanup(out, stage="all", keep_runtime_files=False, force=False)

        assert ".merge-candidates.json" in report["removed"]
        assert not (out / ".merge-candidates.json").exists()
        assert (out / ".sca-practice-findings.json").exists()
        assert (out / ".known-bad-libs-findings.json").exists()
        assert (out / "threat-model.yaml").exists()

    def test_cli_json_report_is_machine_readable(self, tmp_path):
        out = _completed_output_dir(tmp_path)
        (out / ".merge-candidates.json").write_text("{}", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(RUNTIME_CLEANUP_PY), str(out), "--stage", "pre-qa", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
        )

        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["skipped"] is False
        assert report["removed"] == [".merge-candidates.json"]


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
        assert self._extract_list(cleanup_py_text, "POST_QA_FILES_IF_PASS") == EXPECTED_POST_QA_FILES_IF_PASS

    def test_post_qa_dirs_match(self, cleanup_py_text):
        assert self._extract_list(cleanup_py_text, "POST_QA_DIRS") == EXPECTED_POST_QA_DIRS

    def test_post_arch_files_match(self, cleanup_py_text):
        assert self._extract_list(cleanup_py_text, "POST_ARCH_FILES_IF_PASS") == EXPECTED_POST_ARCH_FILES_IF_PASS


# ---------------------------------------------------------------------------
# Documentation in AGENTS.md
# ---------------------------------------------------------------------------


class TestCleanupWhitelistDoc:
    """The cleanup whitelist is documented in `docs/internal/contracts/cleanup-whitelist.md`
    (single human-readable mirror of the constants in
    `scripts/runtime_cleanup.py`). AGENTS.md retains the policy paragraphs
    and a pointer.
    """

    def test_agents_md_section_exists(self, agents_text):
        assert "Runtime artifact cleanup" in agents_text, (
            "AGENTS.md must keep the 'Runtime artifact cleanup' section as the policy anchor."
        )

    def test_agents_md_points_at_whitelist_doc(self, agents_text):
        assert "docs/internal/contracts/cleanup-whitelist.md" in agents_text, (
            "AGENTS.md cleanup section must reference docs/internal/contracts/cleanup-whitelist.md so readers can find the full list."
        )

    @pytest.mark.parametrize(
        "filename",
        sorted(EXPECTED_WHITELIST_FILES | EXPECTED_WHITELIST_DIRS),
    )
    def test_filename_mentioned_in_docs(self, whitelist_text, filename):
        # Both `.progress/` (with trailing slash) and `.progress` should match.
        assert filename in whitelist_text, (
            f"docs/internal/contracts/cleanup-whitelist.md must mention {filename!r} so the doc stays in sync with the script."
        )

    def test_keep_runtime_files_flag_mentioned(self, agents_text):
        assert "--keep-runtime-files" in agents_text, "AGENTS.md must reference the --keep-runtime-files opt-out flag"


# ---------------------------------------------------------------------------
# SKILL.md flag wiring
# ---------------------------------------------------------------------------


class TestSkillMdFlag:
    def test_flag_in_argument_table(self, skill_text):
        assert "--keep-runtime-files" in skill_text, "SKILL.md flag-parsing table must document --keep-runtime-files"

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
            "SKILL.md must invoke runtime_cleanup.py with --stage post-qa after Stage 3 (QA reviewer) completes"
        )

    def test_skill_invokes_post_architect_stage(self, skill_text):
        assert "post-architect" in skill_text, (
            "SKILL.md must invoke runtime_cleanup.py with --stage post-architect when ARCHITECT_REVIEW=true"
        )


# ---------------------------------------------------------------------------
# Helper-level branch coverage: status/repair-plan parsing and log/error paths.
# ---------------------------------------------------------------------------


class TestStatusHelpers:
    def test_status_missing_counts_as_pass(self, tmp_path):
        assert rc._status_file_is_pass(tmp_path / "nope.json") is True

    def test_status_bad_json_is_not_pass(self, tmp_path):
        p = tmp_path / ".qa-status.json"
        p.write_text("{broken", encoding="utf-8")
        assert rc._status_file_is_pass(p) is False

    @pytest.mark.parametrize("status", ["pass", "ok", "clean", "PASS"])
    def test_status_pass_synonyms(self, tmp_path, status):
        p = tmp_path / ".qa-status.json"
        p.write_text(json.dumps({"status": status}), encoding="utf-8")
        assert rc._status_file_is_pass(p) is True

    def test_status_fail_value(self, tmp_path):
        p = tmp_path / ".qa-status.json"
        p.write_text(json.dumps({"status": "fail"}), encoding="utf-8")
        assert rc._status_file_is_pass(p) is False

    def test_repair_plan_missing_is_empty(self, tmp_path):
        assert rc._repair_plan_is_empty(tmp_path / "nope.json") is True

    def test_repair_plan_bad_json_not_empty(self, tmp_path):
        p = tmp_path / ".qa-repair-plan.json"
        p.write_text("{broken", encoding="utf-8")
        assert rc._repair_plan_is_empty(p) is False

    def test_repair_plan_nonzero_count(self, tmp_path):
        p = tmp_path / ".qa-repair-plan.json"
        p.write_text(json.dumps({"issue_count": 3}), encoding="utf-8")
        assert rc._repair_plan_is_empty(p) is False

    def test_repair_plan_cosmetic_advisory_counts_as_clean(self, tmp_path):
        """Regression (2026-07-18 juice-shop): a `cosmetic_advisory` plan
        (repair_plan exit 4) is explicitly non-blocking and is deliberately left
        on disk, but its non-zero issue_count made the whole post-QA branch
        preserve everything — one readability nit stopped `.fragments/` and all
        QA bookkeeping from being reaped on an otherwise successful run."""
        p = tmp_path / ".qa-repair-plan.json"
        p.write_text(
            json.dumps({"status": "cosmetic_advisory", "actionable": False, "issue_count": 1}),
            encoding="utf-8",
        )
        assert rc._repair_plan_is_empty(p) is True

    def test_repair_plan_manual_review_still_not_clean(self, tmp_path):
        """Negative control — `manual_review` describes a real defect needing a
        human, so its artefacts must still be preserved."""
        p = tmp_path / ".qa-repair-plan.json"
        p.write_text(
            json.dumps({"status": "manual_review", "actionable": False, "issue_count": 2}),
            encoding="utf-8",
        )
        assert rc._repair_plan_is_empty(p) is False

    def test_has_agent_error_missing_log(self, tmp_path):
        assert rc._has_agent_error(tmp_path / "no.log") is False

    def test_has_agent_error_long_tail(self, tmp_path):
        log = tmp_path / ".agent-run.log"
        # >100 lines, AGENT_ERROR in the tail
        lines = [f"line {i}\n" for i in range(150)] + ["AGENT_ERROR boom\n"]
        log.write_text("".join(lines), encoding="utf-8")
        assert rc._has_agent_error(log) is True

    def test_has_agent_error_old_error_beyond_tail(self, tmp_path):
        log = tmp_path / ".agent-run.log"
        lines = ["AGENT_ERROR old\n"] + [f"line {i}\n" for i in range(200)]
        log.write_text("".join(lines), encoding="utf-8")
        # Error is only in the first line, far outside the 100-line tail.
        assert rc._has_agent_error(log) is False


# ---------------------------------------------------------------------------
# run_cleanup edge branches: not-a-dir skip, QA-not-clean preserve, unlink
# OSError, directory removal, and log-write OSError tolerance.
# ---------------------------------------------------------------------------


class TestRunCleanupEdges:
    def test_output_dir_not_a_directory_skips(self, tmp_path):
        missing = tmp_path / "ghost"
        report = rc.run_cleanup(missing, stage="all", keep_runtime_files=False, force=False)
        assert report["skipped"] is True
        assert "not a directory" in report["skip_reason"]

    def test_post_qa_preserves_when_qa_not_clean(self, tmp_path):
        out = _completed_output_dir(tmp_path)
        _write_json(out / ".qa-status.json", {"status": "fail"})
        _write_json(out / ".qa-repair-plan.json", {"issue_count": 2})
        report = rc.run_cleanup(out, stage="post-qa", keep_runtime_files=False, force=False)
        assert report["skipped"] is False
        assert any("QA not clean" in note for note in report["preserved"])
        assert (out / ".qa-status.json").exists()

    def test_post_qa_reaps_on_pass_with_cosmetic_advisory(self, tmp_path):
        """End-to-end counterpart: status=pass + cosmetic_advisory plan is the
        `GATE_EXIT == 4` fast path and must run the post-QA wave normally."""
        out = _completed_output_dir(tmp_path)
        _write_json(out / ".qa-status.json", {"status": "pass"})
        _write_json(
            out / ".qa-repair-plan.json",
            {"status": "cosmetic_advisory", "actionable": False, "issue_count": 1},
        )
        report = rc.run_cleanup(out, stage="post-qa", keep_runtime_files=False, force=False)
        assert report["skipped"] is False
        assert not any("QA not clean" in note for note in report["preserved"])
        assert not (out / ".qa-status.json").exists()

    def test_directory_removed_and_not_present(self, tmp_path):
        out = _completed_output_dir(tmp_path)
        prog = out / ".progress"
        prog.mkdir()
        (prog / "x.json").write_text("{}", encoding="utf-8")
        report = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=False, force=False)
        assert ".progress/" in report["removed"]
        assert not prog.exists()
        # A dir from the whitelist that wasn't present is reported not_present.
        assert ".taxonomy-slices/" in report["not_present"]

    def test_file_unlink_oserror_preserved(self, tmp_path, monkeypatch):
        out = _completed_output_dir(tmp_path)
        (out / ".merge-candidates.json").write_text("{}", encoding="utf-8")

        real_unlink = Path.unlink

        def boom(self, *a, **k):
            if self.name == ".merge-candidates.json":
                raise OSError("permission denied")
            return real_unlink(self, *a, **k)

        monkeypatch.setattr(Path, "unlink", boom)
        report = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=False, force=False)
        assert any(".merge-candidates.json" in note for note in report["preserved"])

    def test_dir_rmtree_oserror_preserved(self, tmp_path, monkeypatch):
        out = _completed_output_dir(tmp_path)
        (out / ".progress").mkdir()

        def boom(path, *a, **k):
            raise OSError("busy")

        monkeypatch.setattr(rc.shutil, "rmtree", boom)
        report = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=False, force=False)
        assert any(".progress/" in note for note in report["preserved"])

    def test_log_write_oserror_is_nonfatal(self, tmp_path, monkeypatch):
        out = _completed_output_dir(tmp_path)
        (out / ".merge-candidates.json").write_text("{}", encoding="utf-8")

        def boom(self, *a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "open", boom)
        # Must not raise despite log write failing.
        report = rc.run_cleanup(out, stage="pre-qa", keep_runtime_files=False, force=False)
        assert report["skipped"] is False


# ---------------------------------------------------------------------------
# main() in-process: arg parsing, not-a-dir exit code 2, text report branches.
# ---------------------------------------------------------------------------


class TestMainInProcess:
    def test_main_not_a_directory_returns_2(self, tmp_path, capsys):
        rc_code = rc.main([str(tmp_path / "ghost")])
        assert rc_code == 2
        assert "not a directory" in capsys.readouterr().err

    def test_main_text_report_lists_removed(self, tmp_path, capsys):
        out = _completed_output_dir(tmp_path)
        (out / ".merge-candidates.json").write_text("{}", encoding="utf-8")
        code = rc.main([str(out), "--stage", "pre-qa"])
        assert code == 0
        printed = capsys.readouterr().out
        assert "runtime-cleanup: stage=pre-qa" in printed
        assert "removed   .merge-candidates.json" in printed

    def test_main_text_report_skipped(self, tmp_path, capsys):
        out = _completed_output_dir(tmp_path)
        code = rc.main([str(out), "--stage", "pre-qa", "--keep-runtime-files"])
        assert code == 1
        assert "skipped" in capsys.readouterr().out

    def test_main_json_report(self, tmp_path, capsys):
        out = _completed_output_dir(tmp_path)
        code = rc.main([str(out), "--stage", "pre-qa", "--json"])
        assert code == 0
        report = json.loads(capsys.readouterr().out)
        assert report["stage"] == "pre-qa"

    def test_main_preserved_note_printed(self, tmp_path, capsys):
        out = _completed_output_dir(tmp_path)
        _write_json(out / ".architect-status.json", {"status": "fail"})
        _write_json(out / ".architect-repair-plan.json", {"issue_count": 1})
        code = rc.main([str(out), "--stage", "post-architect"])
        assert code == 0
        printed = capsys.readouterr().out
        assert "preserved" in printed
