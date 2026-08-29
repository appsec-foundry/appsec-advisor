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

import agent_logger
import orchestration_controller as controller

REPO_ROOT = Path(__file__).parent.parent


def _load_aggregator():
    path = REPO_ROOT / "scripts" / "aggregate_run_issues.py"
    spec = importlib.util.spec_from_file_location("aggregate_run_issues", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["aggregate_run_issues"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


agg = _load_aggregator()


# ---------------------------------------------------------------------------
# Model alias contract
# ---------------------------------------------------------------------------

# The Claude Agent tool's closed vocabulary. Anything else is an
# InputValidationError, not a fallback.
AGENT_ALIASES = {"sonnet", "opus", "haiku", "fable"}


class TestBareAgentModel:
    def test_every_configured_model_reduces_into_the_closed_alias_set(self):
        configured = [
            "claude-sonnet-5",
            "claude-sonnet-4-6",
            "claude-haiku-4-5-20251001",
            "claude-opus-5",
            "claude-fable-5",
            "sonnet",
            "haiku",
        ]
        for value in configured:
            assert controller._bare_agent_model(value) in AGENT_ALIASES

    def test_fable_is_recognised_rather_than_coerced_to_sonnet(self):
        # `fable` is a valid Agent alias; before this fix it fell through the
        # alias loop and was silently rewritten to `sonnet`.
        assert controller._bare_agent_model("claude-fable-5") == "fable"
        assert controller._bare_agent_model("fable") == "fable"

    def test_an_unmappable_value_still_yields_a_dispatchable_alias(self):
        # Fail soft, not closed: a typo must not abort a run mid-wave.
        assert controller._bare_agent_model("gpt-4") == "sonnet"
        assert controller._bare_agent_model(None) == "sonnet"

    def test_a_version_pin_is_reported_as_inexpressible(self):
        assert controller._model_pin_is_expressible("sonnet") is True
        assert controller._model_pin_is_expressible("") is True
        assert controller._model_pin_is_expressible("claude-sonnet-5") is False
        assert controller._model_pin_is_expressible("claude-sonnet-4-6") is False


class TestDispatchValueAliases:
    def test_each_directly_dispatched_role_carries_a_ready_alias(self):
        values = {
            "renderer_model": "claude-sonnet-5",
            "abuse_verifier_model": "claude-sonnet-5",
            "qa_content_model": "claude-sonnet-4-6",
            "qa_routine_model": "haiku",
        }
        out = controller._with_model_aliases(values)
        assert out["renderer_model_alias"] == "sonnet"
        assert out["abuse_verifier_model_alias"] == "sonnet"
        assert out["qa_content_model_alias"] == "sonnet"
        assert out["qa_routine_model_alias"] == "haiku"

    def test_operator_intent_survives_beside_the_alias(self):
        # The headless path honours the exact id; rewriting it here would throw
        # that away to serve the interactive caller.
        out = controller._with_model_aliases({"renderer_model": "claude-sonnet-5"})
        assert out["renderer_model"] == "claude-sonnet-5"

    def test_a_tier_label_never_becomes_a_model_alias(self):
        # `reasoning_model` holds `sonnet-economy`, not a model. A `*_model`
        # suffix rule minted an alias for it and broke every action against the
        # dispatch_values property-name enum.
        out = controller._with_model_aliases({"reasoning_model": "sonnet-economy"})
        assert "reasoning_model_alias" not in out

    def test_dropped_pins_are_named_rather_than_silently_ignored(self):
        out = controller._with_model_aliases({"renderer_model": "claude-sonnet-5", "qa_routine_model": "haiku"})
        assert "renderer_model=claude-sonnet-5" in out["model_pins_dropped"]
        assert "qa_routine_model" not in out["model_pins_dropped"]

    def test_a_fully_expressible_config_reports_no_dropped_pin(self):
        out = controller._with_model_aliases({"renderer_model": "sonnet", "qa_routine_model": "haiku"})
        assert out["model_pins_dropped"] == ""

    def test_an_unstaffed_role_yields_a_null_alias_not_a_missing_key(self):
        # The key set stays constant so a consumer can read without probing,
        # and the dispatch-key drift guard can still state an exact set.
        out = controller._with_model_aliases({"architect_model": None})
        assert out["architect_model_alias"] is None

    def test_the_emitted_key_set_does_not_depend_on_the_config(self):
        rich = controller._with_model_aliases(dict.fromkeys(controller._DISPATCH_ALIAS_MODEL_KEYS, "claude-opus-5"))
        bare = controller._with_model_aliases(dict.fromkeys(controller._DISPATCH_ALIAS_MODEL_KEYS))
        assert set(rich) == set(bare)

    def test_emitted_alias_keys_stay_inside_the_action_schema(self):
        import json

        schema = json.loads((REPO_ROOT / "schemas" / "orchestration-action.schema.json").read_text(encoding="utf-8"))
        allowed = set(schema["properties"]["dispatch_values"]["propertyNames"]["enum"])
        emitted = {f"{key}_alias" for key in controller._DISPATCH_ALIAS_MODEL_KEYS}
        assert emitted <= allowed
        assert "model_pins_dropped" in allowed

    def test_a_fully_populated_payload_stays_under_the_property_budget(self):
        """Measure the real payload, do not estimate it.

        A config that sets every model key is the worst case, and it lands two
        properties under the cap. The next key added here fails this test
        rather than a live run's action validation.
        """
        import json

        schema = json.loads((REPO_ROOT / "schemas" / "orchestration-action.schema.json").read_text(encoding="utf-8"))
        budget = schema["properties"]["dispatch_values"]["maxProperties"]
        cfg = {key: "claude-sonnet-5" if key.endswith("_model") else "x" for key in controller._DISPATCH_KEYS}
        cfg["architect_model"] = "claude-opus-5"
        values = controller._dispatch_values(cfg)
        assert len(values) <= budget, f"dispatch_values emits {len(values)} properties, cap is {budget}"


# ---------------------------------------------------------------------------
# BASH_WARN diagnostic excerpt
# ---------------------------------------------------------------------------

ERROR_KW = ("traceback", "error:", "exit status 1", "no such file or directory")


class TestDiagnosticExcerpt:
    def test_the_reason_survives_instead_of_the_dict_wrapper(self):
        # Verbatim from run a2a0e355, whose truncated form ended at "…depth: p…"
        # and left the defect unattributable.
        stdout = (
            "/home/mrohr/appsec-advisor/scripts/log_event.py: cannot validate STRIDE "
            "logging depth: precondition failed because the wave claim was already released"
        )
        out = agent_logger._diagnostic_excerpt("", stdout, {"stdout": stdout}, ERROR_KW)
        assert out.startswith("/home/mrohr/appsec-advisor/scripts/log_event.py:")
        assert "already released" in out
        assert "{'stdout'" not in out

    def test_a_rejected_kind_keeps_the_vocabulary_it_names(self):
        stdout = "/plugin/scripts/log_event.py: unknown kind 'STEP' (expected one of ['info', 'step-start'])"
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
# Evidence-coverage shortfall — one threshold, two callers
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

    def test_the_controller_uses_the_aggregator_threshold(self):
        # Two copies of this rule would drift, and the run would then warn at
        # the end about a shortfall the dispatch gate had already cleared.
        source = (REPO_ROOT / "scripts" / "orchestration_controller.py").read_text(encoding="utf-8")
        assert "from aggregate_run_issues import evidence_coverage_shortfall" in source


# ---------------------------------------------------------------------------
# The kernel SKILL names an enum its roles are forbidden to discover
# ---------------------------------------------------------------------------


class TestKernelLoggingVocabulary:
    def test_the_kernel_skill_lists_every_accepted_log_event_kind(self):
        """A role told not to probe `--help` can only know what the skill says.

        The stride analyzer guessed `STEP` because the skill gave it `<kind>`
        and nothing else. If a kind is ever added to log_event.py without being
        named here, the next role is back to guessing.
        """
        import log_event

        skill = (REPO_ROOT / "skills" / "internal-threat-analysis-kernel" / "SKILL.md").read_text(encoding="utf-8")
        for kind in log_event._CANONICAL_EVENTS:
            assert f"`{kind}`" in skill, f"kind {kind!r} accepted by log_event.py but absent from the kernel skill"

    def test_the_guessed_stem_is_still_rejected_rather_than_guessed_at(self):
        # `STEP` is ambiguous between step-start and step-end. Inventing a
        # winner would corrupt the timeline, so rejection is correct — the fix
        # belongs in the documentation, not in the normaliser.
        import log_event

        assert "step" not in log_event._CANONICAL_EVENTS
        assert log_event._EVENT_NAME_RE.fullmatch("STEP") is None
