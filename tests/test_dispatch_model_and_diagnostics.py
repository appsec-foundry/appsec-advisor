"""Regressions from the run-a2a0e355 diagnosis.

Three defects that survive any single repository, each verified against the
artefacts of the run that exposed them:

  • The resolver pins ``claude-sonnet-5`` on stages the interactive Agent tool
    cannot name. The tool rejects the value outright, so the thin runtimes told
    the orchestrator to convert it in prose — a step skipped at Stage 2 of that
    run, costing a rejected dispatch. The reduction is now emitted as data.

  • ``BASH_WARN`` clipped ``str(resp)``, spending its budget on the ``{'stdout':``
    wrapper and cutting the message off. Three "cannot validate STRIDE logging
    depth" warnings were left permanently undiagnosable by their own log line.

  • Evidence-coverage shortfall was computed only by the completion aggregator,
    after the report it describes was already written.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import runtime.agent_logger as agent_logger

REPO_ROOT = Path(__file__).parent.parent


def _load_aggregator():
    path = REPO_ROOT / "scripts" / "runtime/aggregate_run_issues.py"
    spec = importlib.util.spec_from_file_location("runtime.aggregate_run_issues", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["runtime.aggregate_run_issues"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


agg = _load_aggregator()


# ---------------------------------------------------------------------------
# Model alias contract
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# BASH_WARN diagnostic excerpt
# ---------------------------------------------------------------------------

ERROR_KW = ("traceback", "error:", "exit status 1", "no such file or directory")


class TestDiagnosticExcerpt:
    def test_the_reason_survives_instead_of_the_dict_wrapper(self):
        # Verbatim from run a2a0e355, whose truncated form ended at "…depth: p…"
        # and left the defect unattributable.
        stdout = (
            "/home/mrohr/appsec-advisor/scripts/runtime/log_event.py: cannot validate STRIDE "
            "logging depth: precondition failed because the wave claim was already released"
        )
        out = agent_logger._diagnostic_excerpt("", stdout, {"stdout": stdout}, ERROR_KW)
        assert out.startswith("/home/mrohr/appsec-advisor/scripts/runtime/log_event.py:")
        assert "already released" in out
        assert "{'stdout'" not in out

    def test_a_rejected_kind_keeps_the_vocabulary_it_names(self):
        stdout = "/plugin/scripts/runtime/log_event.py: unknown kind 'STEP' (expected one of ['info', 'step-start'])"
        out = agent_logger._diagnostic_excerpt("", stdout, {"stdout": stdout}, ERROR_KW)
        assert "step-start" in out

    def test_a_traceback_yields_the_exception_not_the_header(self):
        stderr = 'Traceback (most recent call last):\n  File "x.py", line 3\nValueError: boom'
        out = agent_logger._diagnostic_excerpt(stderr, "", {"stderr": stderr}, ERROR_KW)
        assert out == "ValueError: boom"

    def test_stderr_outranks_stdout(self):
        out = agent_logger._diagnostic_excerpt("prog.py: real failure", "usage: prog.py", {}, ERROR_KW)
        assert "real failure" in out

    def test_an_unrecognisable_response_still_reports_something(self):
        out = agent_logger._diagnostic_excerpt("", "", {"weird": 1}, ERROR_KW)
        assert "weird" in out

    def test_the_excerpt_is_bounded(self):
        out = agent_logger._diagnostic_excerpt("", "x" * 5000, {}, ERROR_KW, limit=240)
        assert len(out) <= 241


# ---------------------------------------------------------------------------
# Evidence-coverage shortfall in aggregated run diagnostics
# ---------------------------------------------------------------------------


class TestEvidenceCoverageShortfall:
    def test_the_run_a2a0e355_components_are_all_flagged(self):
        # backend-api, database, frontend-spa as measured on that run.
        assert agg.evidence_coverage_shortfall(85, 4) is not None
        assert agg.evidence_coverage_shortfall(26, 1) is not None
        assert agg.evidence_coverage_shortfall(426, 19) is not None

    def test_adequate_coverage_is_silent(self):
        assert agg.evidence_coverage_shortfall(85, 40) is None

    def test_a_trivially_small_component_is_exempt(self):
        # A low ratio over four files says nothing worth reporting.
        assert agg.evidence_coverage_shortfall(4, 0) is None

    def test_a_non_integer_file_count_is_ignored(self):
        assert agg.evidence_coverage_shortfall(None, 3) is None
        assert agg.evidence_coverage_shortfall("85", 3) is None
        assert agg.evidence_coverage_shortfall(True, 0) is None

    def test_the_ratio_is_the_reported_fraction(self):
        assert agg.evidence_coverage_shortfall(100, 10) == 0.1


# ---------------------------------------------------------------------------
# The kernel SKILL names an enum its roles are forbidden to discover
# ---------------------------------------------------------------------------


class TestKernelLoggingVocabulary:
    def test_the_kernel_skill_lists_every_accepted_log_event_kind(self):
        """A role told not to probe `--help` can only know what the skill says.

        The stride analyzer guessed `STEP` because the skill gave it `<kind>`
        and nothing else. If a kind is ever added to runtime/log_event.py without being
        named here, the next role is back to guessing.
        """
        import runtime.log_event as log_event

        skill = (REPO_ROOT / "skills" / "internal-threat-analysis-kernel" / "SKILL.md").read_text(encoding="utf-8")
        for kind in log_event._CANONICAL_EVENTS:
            assert f"`{kind}`" in skill, (
                f"kind {kind!r} accepted by runtime/log_event.py but absent from the kernel skill"
            )

    def test_the_guessed_stem_is_still_rejected_rather_than_guessed_at(self):
        # `STEP` is ambiguous between step-start and step-end. Inventing a
        # winner would corrupt the timeline, so rejection is correct — the fix
        # belongs in the documentation, not in the normaliser.
        import runtime.log_event as log_event

        assert "step" not in log_event._CANONICAL_EVENTS
        assert log_event._EVENT_NAME_RE.fullmatch("STEP") is None
