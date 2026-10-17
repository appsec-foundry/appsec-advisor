"""Tests for scripts/runtime/resolve_config.py.

Validates each resolver individually plus the end-to-end CLI contract.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "runtime/resolve_config.py"


def _load_module():
    if "runtime.resolve_config" in sys.modules:
        return sys.modules["runtime.resolve_config"]
    spec = importlib.util.spec_from_file_location("runtime.resolve_config", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["runtime.resolve_config"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rc = _load_module()


def _resolve_argv(*argv):
    """Resolve ``argv`` in-process, reporting the outcome like a process run."""
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(stderr):
            cfg = rc.resolve(list(argv), REPO_ROOT)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            stderr.write(exc.code)
            return subprocess.CompletedProcess(argv, 1, "", stderr.getvalue())
        return subprocess.CompletedProcess(argv, exc.code or 0, "", stderr.getvalue())
    return subprocess.CompletedProcess(argv, 0, json.dumps(cfg), stderr.getvalue())


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------


class TestConflicts:
    def _parse(self, *argv):
        return rc.build_parser().parse_args(list(argv))

    def test_yaml_vs_no_yaml(self):
        msg = rc.detect_conflicts(self._parse("--yaml", "--no-yaml"))
        assert msg and "yaml" in msg.lower()

    def test_full_vs_incremental(self):
        msg = rc.detect_conflicts(self._parse("--full", "--incremental"))
        assert msg and "--full" in msg and "--incremental" in msg

    def test_full_vs_resume(self):
        msg = rc.detect_conflicts(self._parse("--full", "--resume"))
        assert msg and "--full" in msg and "--resume" in msg

    def test_rebuild_vs_incremental(self):
        msg = rc.detect_conflicts(self._parse("--rebuild", "--incremental"))
        assert msg and "--rebuild" in msg

    def test_rebuild_vs_resume(self):
        msg = rc.detect_conflicts(self._parse("--rebuild", "--resume"))
        assert msg and "checkpoint" in msg.lower()

    @pytest.mark.parametrize("other", ["--full", "--incremental", "--rebuild", "--resume"])
    def test_rerender_conflicts(self, other):
        msg = rc.detect_conflicts(self._parse("--rerender", other))
        assert msg and "rerender" in msg.lower()

    def test_architect_review_conflict(self):
        msg = rc.detect_conflicts(self._parse("--architect-review", "--no-architect-review"))
        assert msg

    def test_no_conflict_clean_args(self):
        msg = rc.detect_conflicts(self._parse("--full", "--verbose"))
        assert msg is None

    def test_bare_slug_swallowing_its_value_is_refused(self):
        """juice-shop 2026-08-02: `--slug --keep-runtime-files my-label` left
        the label in `scope` and stamped a random slug — discovered ~3h later,
        from the filenames. The ambiguity must fail fast, not be guessed."""
        ns = self._parse("--slug", "--keep-runtime-files", "juice-shop-thorough-v0.5.2")
        assert ns.slug == "__auto__" and ns.scope == ["juice-shop-thorough-v0.5.2"]
        msg = rc.detect_conflicts(ns)
        assert msg and "--slug" in msg and "juice-shop-thorough-v0.5.2" in msg

    def test_explicit_slug_value_with_flags_is_fine(self):
        ns = self._parse("--slug", "my-label", "--keep-runtime-files")
        assert ns.slug == "my-label"
        assert rc.detect_conflicts(ns) is None

    def test_bare_slug_with_prose_scope_is_fine(self):
        """A real scope phrase reads as several words — not a swallowed value."""
        ns = self._parse("--slug", "--keep-runtime-files", "focus", "on", "auth")
        assert rc.detect_conflicts(ns) is None

    def test_bare_slug_without_scope_is_fine(self):
        assert rc.detect_conflicts(self._parse("--slug", "--keep-runtime-files")) is None


# ---------------------------------------------------------------------------
# Per-resolver unit tests
# ---------------------------------------------------------------------------


class TestResolveWriteYaml:
    def test_default_is_enabled(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_write_yaml(ns)
        assert out["write_yaml"] is True
        assert "default" in out["write_yaml_label"]

    def test_explicit_yaml(self):
        ns = rc.build_parser().parse_args(["--yaml"])
        out = rc.resolve_write_yaml(ns)
        assert out["write_yaml"] is True

    def test_no_yaml(self):
        ns = rc.build_parser().parse_args(["--no-yaml"])
        out = rc.resolve_write_yaml(ns)
        assert out["write_yaml"] is False


class TestCheapStride:
    def test_flags_unset_without_arguments(self):
        """The FLAGS default to unset; the depth default is applied in resolve() so
        that --no-cheap-stride can distinguish "user said no" from "user said
        nothing"."""
        ns = rc.build_parser().parse_args([])
        assert ns.cheap_stride is False
        assert ns.no_cheap_stride is False

    def test_flag_sets_true(self):
        ns = rc.build_parser().parse_args(["--cheap-stride"])
        assert ns.cheap_stride is True

    def test_reaches_resolved_config(self, tmp_path):
        """Parser-level is not enough — the manifest builder reads the RESOLVED
        cfg (via .skill-config.json), so the key has to survive resolve()."""
        base = ["--repo", str(tmp_path), "--output", str(tmp_path / "out")]
        assert rc.resolve([*base, "--cheap-stride"], REPO_ROOT)["cheap_stride"] is True
        assert rc.resolve([*base, "--no-cheap-stride"], REPO_ROOT)["cheap_stride"] is False

    def test_default_on_at_quick_and_standard_off_at_thorough(self, tmp_path):
        """Screening only ever reaches components proven to be side-of-the-house
        (build_stride_dispatch_manifest._cheap_stride_target), so quick and standard
        take it by default. Thorough is the mode a user picks when depth outweighs
        cost, so it keeps full depth everywhere."""
        base = ["--repo", str(tmp_path), "--output", str(tmp_path / "out")]
        assert rc.resolve(base, REPO_ROOT)["cheap_stride"] is True
        assert rc.resolve([*base, "--quick"], REPO_ROOT)["cheap_stride"] is True
        assert rc.resolve([*base, "--thorough"], REPO_ROOT)["cheap_stride"] is False

    def test_explicit_flags_beat_the_depth_default(self, tmp_path):
        base = ["--repo", str(tmp_path), "--output", str(tmp_path / "out")]
        forced_on = rc.resolve([*base, "--thorough", "--cheap-stride"], REPO_ROOT)
        assert forced_on["cheap_stride"] is True
        assert forced_on["cheap_stride_label"] == "on (--cheap-stride)"
        forced_off = rc.resolve([*base, "--quick", "--no-cheap-stride"], REPO_ROOT)
        assert forced_off["cheap_stride"] is False
        assert forced_off["cheap_stride_label"] == "off (--no-cheap-stride)"

    def test_label_names_the_source_of_the_decision(self, tmp_path):
        """The pre-flight has to say whether the user asked for screening depth or
        the depth default did — otherwise a surprised user cannot tell."""
        base = ["--repo", str(tmp_path), "--output", str(tmp_path / "out")]
        assert rc.resolve(base, REPO_ROOT)["cheap_stride_label"] == "on (auto - standard depth)"
        assert rc.resolve([*base, "--quick"], REPO_ROOT)["cheap_stride_label"] == "on (auto - quick depth)"
        assert rc.resolve([*base, "--thorough"], REPO_ROOT)["cheap_stride_label"] == "off (auto - thorough depth)"

    def test_conflicting_flags_are_rejected(self):
        ns = rc.build_parser().parse_args(["--cheap-stride", "--no-cheap-stride"])
        assert "cannot be used together" in (rc.detect_conflicts(ns) or "")


class TestResolveRequirements:
    def test_no_requirements_flag(self):
        ns = rc.build_parser().parse_args(["--no-requirements"])
        out = rc.resolve_requirements(ns, config_enabled=True)
        assert out["check_requirements"] is False

    def test_requirements_flag_alone(self):
        ns = rc.build_parser().parse_args(["--requirements"])
        out = rc.resolve_requirements(ns, config_enabled=False)
        assert out["check_requirements"] is True
        assert out["requirements_url_override"] is None

    def test_requirements_flag_with_url(self):
        ns = rc.build_parser().parse_args(["--requirements", "https://ex.com/r.yaml"])
        out = rc.resolve_requirements(ns, config_enabled=False)
        assert out["check_requirements"] is True
        assert out["requirements_url_override"] == "https://ex.com/r.yaml"

    def test_config_enabled_default(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_requirements(ns, config_enabled=True)
        assert out["check_requirements"] is True
        assert "config" in out["requirements_label"]

    def test_config_disabled_default(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_requirements(ns, config_enabled=False)
        assert out["check_requirements"] is False


class TestResolveAssessmentDepth:
    def test_default_is_standard(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_assessment_depth(ns)
        assert out["assessment_depth"] == "standard"
        assert out["register_severity_floor"] == "medium"
        # max_stride_components is now the depth-independent operational ceiling,
        # NOT a per-depth selection count (selection is criteria-derived).
        assert out["max_stride_components"] == rc.STRIDE_COMPONENT_CEILING

    def test_quick(self):
        ns = rc.build_parser().parse_args(["--assessment-depth", "quick"])
        out = rc.resolve_assessment_depth(ns)
        assert out["assessment_depth"] == "quick"
        assert out["max_stride_components"] == rc.STRIDE_COMPONENT_CEILING
        assert out["diagram_depth"] == "minimal"

    def test_thorough(self):
        ns = rc.build_parser().parse_args(["--assessment-depth", "thorough"])
        out = rc.resolve_assessment_depth(ns)
        assert out["max_stride_components"] == rc.STRIDE_COMPONENT_CEILING
        assert out["qa_depth"] == "extended"

    def test_ceiling_is_depth_independent(self):
        """The operational ceiling does not vary by depth — depth changes the
        criteria predicate (and turn budget), not a component count."""
        ceilings = {
            d: rc.resolve_assessment_depth(rc.build_parser().parse_args(["--assessment-depth", d]))[
                "max_stride_components"
            ]
            for d in ("quick", "standard", "thorough")
        }
        assert len(set(ceilings.values())) == 1

    def test_max_repair_iterations_depth_aware(self):
        """Re-Render Loop budget: quick/standard = single quick-fix pass (1),
        thorough keeps the historical budget of 3."""
        got = {
            d: rc.resolve_assessment_depth(rc.build_parser().parse_args(["--assessment-depth", d]))[
                "max_repair_iterations"
            ]
            for d in ("quick", "standard", "thorough")
        }
        assert got == {"quick": 1, "standard": 1, "thorough": 3}

    def test_max_repair_iterations_default_is_one(self):
        """The default depth (standard) caps QA repair at a single pass."""
        out = rc.resolve_assessment_depth(rc.build_parser().parse_args([]))
        assert out["max_repair_iterations"] == 1

    def test_register_severity_floor_override(self):
        ns = rc.build_parser().parse_args(["--register-severity-floor", "low"])
        assert rc.resolve_assessment_depth(ns)["register_severity_floor"] == "low"


class TestResolveStrideConcurrency:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("APPSEC_STRIDE_CONCURRENCY", raising=False)
        assert rc.resolve_stride_concurrency() == {"stride_concurrency": 5}

    def test_override(self, monkeypatch):
        monkeypatch.setenv("APPSEC_STRIDE_CONCURRENCY", "5")
        assert rc.resolve_stride_concurrency() == {"stride_concurrency": 5}

    @pytest.mark.parametrize("value", ["0", "6", "11", "33", "many"])
    def test_invalid_override_fails_closed(self, monkeypatch, value):
        monkeypatch.setenv("APPSEC_STRIDE_CONCURRENCY", value)
        with pytest.raises(SystemExit, match="APPSEC_STRIDE_CONCURRENCY"):
            rc.resolve_stride_concurrency()


class TestEvidenceVerifierCap:
    def test_depth_defaults_bound_non_critical_work(self):
        caps = {
            depth: rc.resolve_evidence_verifier_cap(rc.build_parser().parse_args(["--assessment-depth", depth]), depth)[
                "evidence_verifier_max_findings"
            ]
            for depth in ("quick", "standard", "thorough")
        }
        assert caps == {"quick": 20, "standard": 30, "thorough": 100}

    def test_explicit_cap_overrides_depth_default(self):
        ns = rc.build_parser().parse_args(["--assessment-depth", "standard", "--evidence-verifier-cap", "12"])
        out = rc.resolve_evidence_verifier_cap(ns, "standard")
        assert out["evidence_verifier_max_findings"] == 12
        assert "--evidence-verifier-cap" in out["evidence_verifier_cap_label"]


class TestResolveReasoningModel:
    def test_default_standard_gives_sonnet_economy(self):
        # 2026-06-23: standard default reverted to sonnet-economy. A clean A/B
        # showed Opus reasoning was ~+$10.77 with no measurable quality gain, so
        # the everyday default favours cost. Opus is opt-in; thorough keeps Opus.
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["reasoning_model"] == "sonnet-economy"
        # STRIDE stays cost-pinned to Sonnet 4.6 (Sonnet 5 regressed recall).
        # The standard buy-back (2026-07-05) upgrades triage + merger to Sonnet 5.
        assert out["stride_model"] == "claude-sonnet-4-6"
        assert out["triage_model"] == "claude-sonnet-5-5"
        assert out["merger_model"] == "claude-sonnet-5-5"

    def test_default_thorough_still_opus(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "thorough")
        assert out["reasoning_model"] == "opus"
        assert out["stride_model"] == "opus"

    def test_default_quick_gives_haiku_economy(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "quick")
        assert out["reasoning_model"] == "sonnet-economy"
        # sonnet-economy keeps the Reasoning core on the Sonnet tier,
        # cost-pinned to the concrete Sonnet 4.6.
        assert out["stride_model"] == "claude-sonnet-4-6"
        assert out["triage_model"] == "claude-sonnet-4-6"
        assert out["merger_model"] == "claude-sonnet-4-6"

    def test_explicit_opus(self):
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "opus"

    def test_env_var_highest_precedence(self, monkeypatch):
        monkeypatch.setenv("APPSEC_STRIDE_MODEL", "claude-env-override")
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "claude-env-override"

    def test_explicit_version_id_accepted(self):
        # Group B: per-stage flags accept explicit version ids (no choices=).
        ns = rc.build_parser().parse_args(
            [
                "--triage-model",
                "claude-sonnet-5",
                "--stride-model",
                "claude-sonnet-4-6",
                "--merger-model",
                "claude-opus-4-7",
            ]
        )
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["triage_model"] == "claude-sonnet-5"
        assert out["stride_model"] == "claude-sonnet-4-6"
        assert out["merger_model"] == "claude-opus-4-7"

    def test_version_id_flag_wins_over_tier_and_env(self, monkeypatch):
        # CLI per-stage flag is highest precedence except --no-opus.
        monkeypatch.setenv("APPSEC_TRIAGE_MODEL", "claude-env")
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus", "--triage-model", "claude-sonnet-5"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["triage_model"] == "claude-sonnet-5"

    def test_triage_5_overrides_economy_without_mutating_tier(self, tmp_path, monkeypatch):
        # Group D (item 10): the sanctioned economy buy-back —
        # --triage-model claude-sonnet-5 pins triage to Sonnet-5 while STRIDE +
        # merger stay on the 4.6-cost-pinned reasoning core and the tier NAME
        # stays sonnet-economy (the named tier is NOT redefined). Cheap base +
        # one-stage buy-back that pays on a 4.6 session.
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--triage-model", "claude-sonnet-5"], REPO_ROOT)
        assert cfg["reasoning_model"] == "sonnet-economy"  # tier unmutated
        assert cfg["triage_model"] == "claude-sonnet-5"  # buy-back (flag agrees)
        assert cfg["stride_model"] == "claude-sonnet-4-6"  # STRIDE stays cheap
        # merger now takes the standard buy-back (Sonnet 5) by default too.
        assert cfg["merger_model"] == "claude-sonnet-5-5"


# (Removed 2026-06: TestResolveDefaultTierForCappedRepos — the B2d large-repo
# reasoning-tier auto-downgrade was removed. Large repos now keep the default
# Opus reasoning tier. repo_size_capped is purely informational. See
# docs/analysis/plan-opus-stride-default-2026-06-21.md.)


class TestResolveExtendedModelsRendererAbuse:
    """Group C: renderer + abuse-verifier pin knobs. Outside the standard
    buy-back the default is the `sonnet` alias (host session); at `standard`
    they take the Sonnet-5 buy-back. Pinnable via env vars; opus-banned."""

    def test_quick_pins_renderer_abuse_to_46(self):
        # quick/thorough pin every Sonnet-tier subagent to concrete 4.6.
        out = rc.resolve_extended_models("sonnet-economy", "quick")
        assert out["renderer_model"] == "claude-sonnet-4-6"
        assert out["abuse_verifier_model"] == "claude-sonnet-4-6"

    def test_sonnet_tier_optin_keeps_alias(self):
        # The explicit `sonnet` tier (--reasoning-model sonnet) opts into latest
        # Sonnet → the 4.6 pin is skipped, the alias survives.
        out = rc.resolve_extended_models("sonnet", "quick")
        assert out["renderer_model"] == "sonnet"
        assert out["abuse_verifier_model"] == "sonnet"

    def test_standard_buyback_pins_sonnet5(self):
        # standard buy-back (2026-07-05): renderer + abuse-verifier → Sonnet 5.
        out = rc.resolve_extended_models("sonnet-economy", "standard")
        assert out["renderer_model"] == "claude-sonnet-5-5"
        assert out["abuse_verifier_model"] == "claude-sonnet-5-5"

    def test_thorough_showcase_pins_sonnet5(self):
        # thorough is a quality tier → renderer + abuse-verifier on latest Sonnet 5
        # (NOT 4.6). thorough resolves the extended models via the opus tier.
        out = rc.resolve_extended_models("opus", "thorough")
        assert out["renderer_model"] == "claude-sonnet-5-5"
        assert out["abuse_verifier_model"] == "claude-sonnet-5-5"
        # ...while the mechanical qa stages stay on cheap 4.6.
        assert out["qa_content_model"] == "claude-sonnet-4-6"
        assert out["qa_routine_model"] == "claude-sonnet-4-6"

    def test_defaults_on_non_economy_tier(self):
        out = rc.resolve_extended_models("sonnet", "standard")
        assert out["renderer_model"] == "sonnet"
        assert out["abuse_verifier_model"] == "sonnet"

    def test_env_pins(self, monkeypatch):
        monkeypatch.setenv("APPSEC_RENDERER_MODEL", "claude-sonnet-5")
        monkeypatch.setenv("APPSEC_ABUSE_VERIFIER_MODEL", "claude-sonnet-5")
        out = rc.resolve_extended_models("sonnet-economy", "standard")
        assert out["renderer_model"] == "claude-sonnet-5"
        assert out["abuse_verifier_model"] == "claude-sonnet-5"

    def test_opus_ban_clamps_renderer_and_abuse(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("APPSEC_RENDERER_MODEL", "claude-opus-4-7")
        monkeypatch.setenv("APPSEC_ABUSE_VERIFIER_MODEL", "claude-opus-4-7")
        cfg = rc.resolve(["--no-opus"], REPO_ROOT)
        assert cfg["renderer_model"] == "sonnet"
        assert cfg["abuse_verifier_model"] == "sonnet"


class TestOrchestratorRecommendation:
    """Advisory session-model recommendation from repo size (2026-07-05).
    Recommends Sonnet 5 only for VERY large repos (window safety), else 4.6
    (~half cost). Never binding — the skill surfaces it, the user chooses."""

    def test_normal_repo_recommends_46(self):
        out = rc.recommend_orchestrator_model(641)  # Juice-Shop-sized
        assert out["orchestrator_recommended_model"] == "claude-sonnet-4-6"
        assert out["orchestrator_recommendation_repo_files"] == 641

    def test_threshold_boundary_recommends_5(self):
        out = rc.recommend_orchestrator_model(rc.ORCHESTRATOR_SONNET5_FILE_THRESHOLD)
        assert out["orchestrator_recommended_model"] == "claude-sonnet-5-5"

    def test_just_below_threshold_recommends_46(self):
        out = rc.recommend_orchestrator_model(rc.ORCHESTRATOR_SONNET5_FILE_THRESHOLD - 1)
        assert out["orchestrator_recommended_model"] == "claude-sonnet-4-6"

    def test_threshold_is_above_juice_shop(self):
        # Calibration invariant: a Juice-Shop-sized repo must land on 4.6.
        assert rc.ORCHESTRATOR_SONNET5_FILE_THRESHOLD > 641

    def test_resolve_populates_recommendation(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve([], REPO_ROOT)
        assert "orchestrator_recommended_model" in cfg
        assert cfg["orchestrator_recommendation_repo_files"] >= 0


class TestResolveRepoSizeCap:
    """2026-06: a large repo is flagged (repo_size_capped, informational only
    since the B2d auto-downgrade was removed) but NEVER drops components —
    dropping components created whole-component blind spots, and since 2026-06-07
    the analyzed set is criteria-derived (no count to reduce). The cap patch
    therefore carries NO max_stride_components key."""

    def _cfg(self):
        return {
            "assessment_depth": "standard",
            "max_stride_components": 10,
            "stride_turns_simple": 15,
            "stride_turns_moderate": 22,
            "stride_turns_complex": 31,
            "diagram_depth": "standard",
            "qa_depth": "full",
        }

    def test_large_repo_keeps_all_components_but_marks_capped(self, monkeypatch):
        monkeypatch.setattr(rc, "_count_source_files", lambda p: 600)
        out = rc.resolve_repo_size_cap(self._cfg(), Path("/tmp/x"))
        assert out["repo_size_capped"] is True  # informational flag only
        assert "max_stride_components" not in out  # no count touched
        assert "criteria-selected components" in out["depth_label"]
        assert "capped from" not in out["depth_label"]

    def test_small_repo_is_noop(self, monkeypatch):
        monkeypatch.setattr(rc, "_count_source_files", lambda p: 50)
        out = rc.resolve_repo_size_cap(self._cfg(), Path("/tmp/x"))
        assert out == {}

    def test_only_at_standard_depth(self, monkeypatch):
        monkeypatch.setattr(rc, "_count_source_files", lambda p: 600)
        cfg = self._cfg()
        cfg["assessment_depth"] = "thorough"
        cfg["max_stride_components"] = 8
        out = rc.resolve_repo_size_cap(cfg, Path("/tmp/x"))
        assert out == {}


class TestResolveArchitectReview:
    def test_off_at_standard_by_default(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_architect_review(ns, "standard", dry_run=False)
        assert out["architect_review"] is False

    def test_auto_on_at_thorough(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_architect_review(ns, "thorough", dry_run=False)
        assert out["architect_review"] is True
        # Stage 4 rewrites prose from a bounded projection and judges nothing,
        # so the default came off Opus (2026-08-30).
        assert out["architect_model"] == "sonnet"
        assert "auto-thorough" in out["architect_label"]

    def test_explicit_on(self):
        ns = rc.build_parser().parse_args(["--architect-review"])
        out = rc.resolve_architect_review(ns, "standard", dry_run=False)
        assert out["architect_review"] is True

    def test_explicit_off_wins_over_thorough(self):
        ns = rc.build_parser().parse_args(["--no-architect-review"])
        out = rc.resolve_architect_review(ns, "thorough", dry_run=False)
        assert out["architect_review"] is False

    def test_dry_run_forces_off(self):
        ns = rc.build_parser().parse_args(["--architect-review"])
        out = rc.resolve_architect_review(ns, "thorough", dry_run=True)
        assert out["architect_review"] is False

    def test_model_flag_sonnet(self):
        ns = rc.build_parser().parse_args(["--architect-review", "--architect-model", "sonnet"])
        out = rc.resolve_architect_review(ns, "standard", dry_run=False)
        assert out["architect_model"] == "sonnet"

    def test_model_flag_explicit_version_id(self):
        # Group B: an explicit version id must pass through verbatim, NOT be
        # silently upgraded to the opus default (the pre-B else-branch bug).
        ns = rc.build_parser().parse_args(["--architect-review", "--architect-model", "claude-sonnet-5"])
        out = rc.resolve_architect_review(ns, "standard", dry_run=False)
        assert out["architect_model"] == "claude-sonnet-5"


class TestResolveEnrichArchFragments:
    """M3.3 / D2 — LLM enrichment of architecture-diagrams.md and
    security-architecture.md fragments. Auto-on at thorough, off
    elsewhere; CLI flags override."""

    def test_on_at_standard_by_default(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_enrich_arch_fragments(ns, "standard", dry_run=False)
        assert out["enrich_arch_fragments"] is True
        assert "standard" in out["enrich_arch_label"]

    def test_off_at_quick_by_default(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_enrich_arch_fragments(ns, "quick", dry_run=False)
        assert out["enrich_arch_fragments"] is False

    def test_auto_on_at_thorough(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_enrich_arch_fragments(ns, "thorough", dry_run=False)
        assert out["enrich_arch_fragments"] is True
        assert "auto-thorough" in out["enrich_arch_label"]

    def test_explicit_on_overrides_standard(self):
        ns = rc.build_parser().parse_args(["--enrich-arch"])
        out = rc.resolve_enrich_arch_fragments(ns, "standard", dry_run=False)
        assert out["enrich_arch_fragments"] is True
        assert "--enrich-arch" in out["enrich_arch_label"]

    def test_explicit_off_overrides_thorough(self):
        ns = rc.build_parser().parse_args(["--no-enrich-arch"])
        out = rc.resolve_enrich_arch_fragments(ns, "thorough", dry_run=False)
        assert out["enrich_arch_fragments"] is False
        assert "--no-enrich-arch" in out["enrich_arch_label"]

    def test_dry_run_forces_off(self):
        ns = rc.build_parser().parse_args(["--enrich-arch"])
        out = rc.resolve_enrich_arch_fragments(ns, "thorough", dry_run=True)
        assert out["enrich_arch_fragments"] is False
        assert "dry-run" in out["enrich_arch_label"]

    def test_conflict_pair_rejected(self):
        with pytest.raises(SystemExit):
            self._parse("--enrich-arch", "--no-enrich-arch")

    def _parse(self, *args):
        ns = rc.build_parser().parse_args(list(args))
        msg = rc.detect_conflicts(ns)
        if msg:
            import sys

            sys.exit(msg)
        return ns


# ---------------------------------------------------------------------------
# Incremental mode resolution (baseline-aware)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Whole-argv resolution
# ---------------------------------------------------------------------------


class TestCLI:
    def _run(self, *argv):
        return _resolve_argv(*argv)

    def test_empty_args_default_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run()
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["mode"] == "full"  # first run
        assert cfg["write_yaml"] is True
        assert cfg["assessment_depth"] == "standard"
        assert cfg["reasoning_model"] == "sonnet-economy"  # standard default (2026-06-23)
        assert cfg["architect_review"] is False
        assert cfg["quiet"] is False  # verdict echoed by default
        assert cfg["evidence_verifier_max_findings"] == 30

    def test_evidence_verifier_cap_flows_to_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--evidence-verifier-cap", "12")
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["evidence_verifier_max_findings"] == 12

    def test_evidence_verifier_cap_rejects_zero(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--evidence-verifier-cap", "0")
        assert r.returncode == 1
        assert "must be at least 1" in r.stderr

    def test_quiet_flag_flows_to_cfg(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--quiet")
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["quiet"] is True

    # -- fail-fast argument checks -----------------------------------------

    def test_unknown_flag_is_rejected(self, tmp_path, monkeypatch):
        """argparse must reject a typo like `--qiuck` with exit 2 and produce no JSON."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--qiuck")
        assert r.returncode == 2
        assert "unrecognized arguments: --qiuck" in r.stderr
        assert r.stdout == ""

    def test_lifecycle_conflict_is_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--rebuild", "--incremental")
        assert r.returncode == 1

    # -- depth shortcuts ----------------------------------------------------

    def test_quick_shortcut_maps_to_assessment_depth(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--quick")
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["assessment_depth"] == "quick"
        assert cfg["skip_qa"] is True
        assert cfg["skip_qa_label"] == "skipped (auto - quick depth)"
        assert cfg["skip_attack_walkthroughs"] is True
        assert cfg["skip_attack_walkthroughs_label"] == ("skipped (auto - quick depth)")

    def test_quick_depth_flag_sets_fast_mode_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--assessment-depth", "quick")
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["assessment_depth"] == "quick"
        assert cfg["skip_qa"] is True
        assert cfg["skip_attack_walkthroughs"] is True

    def test_thorough_shortcut_maps_to_assessment_depth(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--thorough")
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["assessment_depth"] == "thorough"

    def test_quick_and_thorough_conflict(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--quick", "--thorough")
        assert r.returncode == 1
        assert "--quick and --thorough" in r.stderr

    def test_quick_disagrees_with_explicit_depth(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--quick", "--assessment-depth", "thorough")
        assert r.returncode == 1
        assert "--quick conflicts with --assessment-depth thorough" in r.stderr

    def test_quick_agrees_with_explicit_depth(self, tmp_path, monkeypatch):
        """`--quick --assessment-depth quick` is redundant but not an error."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--quick", "--assessment-depth", "quick")
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["assessment_depth"] == "quick"

    # -- abuse-case verification gating -------------------------------------

    def test_abuse_cases_enabled_by_default_at_standard(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = json.loads(self._run().stdout)
        assert cfg["skip_abuse_case_verification"] is False
        assert cfg["abuse_case_label"] == "enabled"

    def test_abuse_cases_skipped_by_default_at_quick(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = json.loads(self._run("--quick").stdout)
        assert cfg["skip_abuse_case_verification"] is True
        assert cfg["abuse_case_label"] == "skipped (auto - quick depth)"

    def test_abuse_cases_force_on_at_quick(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = json.loads(self._run("--quick", "--abuse-cases").stdout)
        assert cfg["skip_abuse_case_verification"] is False
        assert cfg["abuse_case_label"] == "enabled (--abuse-cases)"

    def test_abuse_cases_force_off_at_standard(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = json.loads(self._run("--no-abuse-cases").stdout)
        assert cfg["skip_abuse_case_verification"] is True
        assert cfg["abuse_case_label"] == "skipped (--no-abuse-cases)"

    def test_abuse_cases_conflict(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--abuse-cases", "--no-abuse-cases")
        assert r.returncode == 1
        assert "--abuse-cases and --no-abuse-cases" in r.stderr

    def test_per_scan_abuse_case_selection_is_persisted(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = json.loads(
            self._run(
                "--abuse-case-file",
                "security/payments.yaml",
                "--only-abuse-case",
                "REPO-AC-010",
            ).stdout
        )
        assert cfg["abuse_case_files"] == ["security/payments.yaml"]
        assert cfg["only_abuse_case_ids"] == ["REPO-AC-010"]

    def test_per_scan_case_file_enables_verification_at_quick_depth(self, tmp_path, monkeypatch):
        """Naming a case file is a request to verify it — it must not resolve
        into a stage the quick-depth default switched off."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--quick", "--abuse-case-file", "security/payments.yaml")
        cfg = json.loads(r.stdout)
        assert cfg["skip_abuse_case_verification"] is False
        assert cfg["abuse_case_label"] == "enabled (per-scan case selection)"

    def test_per_scan_case_id_enables_verification_at_quick_depth(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = json.loads(self._run("--quick", "--only-abuse-case", "AC-T-001").stdout)
        assert cfg["skip_abuse_case_verification"] is False

    def test_per_scan_case_file_conflicts_with_no_abuse_cases(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--abuse-case-file", "security/payments.yaml", "--no-abuse-cases")
        assert r.returncode == 1
        assert "--abuse-case-file" in r.stderr

    def test_per_scan_case_id_conflicts_with_no_abuse_cases(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--only-abuse-case", "AC-T-001", "--no-abuse-cases")
        assert r.returncode == 1
        assert "--only-abuse-case" in r.stderr

    # -- summary "show only when active" rules ------------------------------

    def test_with_sca_flag_is_rejected(self, tmp_path, monkeypatch):
        """--with-sca / --no-sca were removed in 2026-05. argparse must
        reject them as unknown flags (exit 2). Verifies the hard cutover
        is in place — no deprecation alias, no no-op acceptance."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--with-sca")
        assert r.returncode != 0, "--with-sca must be rejected by argparse"
        assert "unrecognized arguments" in r.stderr or "error" in r.stderr.lower()

    def test_qa_scan_repo_flag_is_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--qa-scan-repo")
        assert r.returncode == 2
        assert "unrecognized arguments: --qa-scan-repo" in r.stderr
        assert r.stdout == ""

    def test_the_deprecated_org_guardrail_key_still_resolves(self, tmp_path, monkeypatch):
        """`max_cost_usd` was published in the org-profile schema. A profile
        that still spells it that way must keep working."""
        monkeypatch.chdir(tmp_path)
        profile = tmp_path / "org-profile" / "org-profile.yaml"
        profile.parent.mkdir()
        profile.write_text(
            "api_version: appsec-advisor.org-profile/v2\n"
            'organization: { id: myorg, name: My Org, profile_version: "1" }\n'
            'compatibility: { core: ">=0.4 <0.7" }\n'
            "default_preset: local-default\n"
            "presets:\n"
            "  local-default:\n"
            "    base_mode: standard\n"
            "    guardrails: { max_cost_usd: 12 }\n"
        )
        r = self._run("--org-profile", str(profile))
        assert r.returncode == 0
        assert json.loads(r.stdout)["soft_budget_usd"] == 12

    def test_conflict_exits_nonzero(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--yaml", "--no-yaml")
        assert r.returncode != 0
        assert "cannot be used together" in r.stderr

    def test_repo_flag_resolves_path(self, tmp_path, monkeypatch):
        # Set up a fake "repo" — just a directory; git fallback is fine.
        monkeypatch.chdir(tmp_path)
        r = self._run("--repo", str(tmp_path))
        cfg = json.loads(r.stdout)
        assert cfg["repo_root"] == str(tmp_path)

    def test_repeated_repo_flag_is_rejected_not_last_wins(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        r = self._run("--repo", str(tmp_path / "a"), "--repo", str(tmp_path / "b"))
        assert r.returncode == 2
        assert "--repo may be given only once" in r.stderr
        r = self._run("--repo", str(tmp_path / "a"))
        assert r.returncode == 0 and json.loads(r.stdout)["repo_root"] == str(tmp_path / "a")

    def test_repo_flag_honours_explicit_subdir_not_git_root(self, tmp_path, monkeypatch):
        # An explicit --repo pointing at a subdir nested inside a larger git repo
        # (no .git of its own) must resolve to the subdir itself, NOT walk up to
        # the enclosing git toplevel. Regression: the e2e fixture nested in the
        # plugin's own tree was silently retargeting the whole parent repo.
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        sub = tmp_path / "nested" / "fixture"
        sub.mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        r = self._run("--repo", str(sub))
        cfg = json.loads(r.stdout)
        assert cfg["repo_root"] == str(sub)


# ---------------------------------------------------------------------------
# Regression scenarios observed in production runs
# ---------------------------------------------------------------------------


class TestIntegrationScenarios:
    """Scenarios that matched the 2026-04-22 juice-shop first-full run."""

    def test_first_run_juiceshop_like(self, tmp_path, monkeypatch):
        """No flags, empty output-dir, repo-like layout."""
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve([], REPO_ROOT)
        assert cfg["mode"] == "full"
        # standard default is sonnet-economy since 2026-06-23 (cost; Opus opt-in).
        # Concrete Sonnet cost-pinned to 4.6 since 2026-07-04.
        assert cfg["reasoning_model"] == "sonnet-economy"
        # STRIDE cost-pinned to 4.6; standard buy-back upgrades triage + merger.
        assert cfg["stride_model"] == "claude-sonnet-4-6"
        assert cfg["triage_model"] == "claude-sonnet-5-5"
        assert cfg["merger_model"] == "claude-sonnet-5-5"
        assert cfg["architect_review"] is False
        assert cfg["check_requirements"] is False

    def test_thorough_auto_enables_architect_review(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--assessment-depth", "thorough"], REPO_ROOT)
        assert cfg["architect_review"] is True
        assert cfg["architect_model"] == "sonnet"

    def test_deprecated_with_requirements_alias(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--with-requirements"], REPO_ROOT)
        assert cfg["check_requirements"] is True

    def test_security_schema_is_v2_only(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve([], REPO_ROOT)
        assert cfg["security_schema"] == "v2"
        assert "13-section" in cfg["security_schema_label"]

        explicit = rc.resolve(["--schema-v2"], REPO_ROOT)
        assert explicit["security_schema"] == "v2"

        with pytest.raises(SystemExit, match="--schema-v1 was removed"):
            rc.resolve(["--schema-v1"], REPO_ROOT)


# ---------------------------------------------------------------------------
# Opus ceiling (--no-opus / APPSEC_DISABLE_OPUS / policy.disable_opus)
# ---------------------------------------------------------------------------


class TestOpusBan:
    """The Opus ceiling downgrades every Opus selection to Sonnet. It is the
    last model step in resolve(), so it overrides env-var per-agent overrides
    and an explicit --reasoning-model opus alike."""

    def test_baseline_unchanged_when_off(self, tmp_path, monkeypatch):
        """No switch → no-op: an explicit Opus tier stays on Opus, flag False.
        (The standard default is now sonnet-economy, so use an explicit opus
        tier to have an Opus selection that the off-state must leave intact.)"""
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--reasoning-model", "opus"], REPO_ROOT)
        assert cfg["opus_disabled"] is False
        assert cfg["merger_model"] == "opus"

    def test_no_opus_clamps_explicit_opus_tier(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--no-opus", "--reasoning-model", "opus"], REPO_ROOT)
        assert cfg["opus_disabled"] is True
        assert cfg["reasoning_model"] == "sonnet"
        assert cfg["stride_model"] == "sonnet"
        assert cfg["triage_model"] == "sonnet"
        assert cfg["merger_model"] == "sonnet"

    def test_no_opus_clamps_explicit_opus_version_id(self, tmp_path, monkeypatch):
        # Group B: a per-stage flag carrying a concrete Opus version id is still
        # caught by the substring clamp (_OPUS_TOKEN='opus' matches claude-opus-*).
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--no-opus", "--merger-model", "claude-opus-4-7"], REPO_ROOT)
        assert cfg["opus_disabled"] is True
        assert cfg["merger_model"] == "sonnet"

    def test_no_opus_leaves_sonnet_version_id_intact(self, tmp_path, monkeypatch):
        # A concrete Sonnet-5 pin survives --no-opus untouched (no opus token).
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--no-opus", "--triage-model", "claude-sonnet-5"], REPO_ROOT)
        assert cfg["triage_model"] == "claude-sonnet-5"

    def test_no_opus_noop_on_sonnet_default(self, tmp_path, monkeypatch):
        """Standard now defaults to sonnet-economy (all Sonnet), so --no-opus has
        nothing to clamp in the reasoning core — it records the flag and leaves
        the already-Sonnet models unchanged. (Clamping of an explicit Opus tier
        is covered by test_no_opus_clamps_explicit_opus_tier.)"""
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--no-opus"], REPO_ROOT)
        assert cfg["opus_disabled"] is True
        assert cfg["reasoning_model"] == "sonnet-economy"
        # already Sonnet (merger on the 5 buy-back) → nothing for --no-opus to clamp.
        assert cfg["merger_model"] == "claude-sonnet-5-5"

    def test_no_opus_clamps_architect_model(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(
            ["--no-opus", "--assessment-depth", "thorough", "--architect-review"],
            REPO_ROOT,
        )
        assert cfg["architect_review"] is True
        assert cfg["architect_model"] == "sonnet"

    def test_env_disable_opus(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("APPSEC_DISABLE_OPUS", "1")
        cfg = rc.resolve(["--reasoning-model", "opus"], REPO_ROOT)
        assert cfg["opus_disabled"] is True
        assert cfg["merger_model"] == "sonnet"

    def test_clamp_runs_after_env_override(self, tmp_path, monkeypatch):
        """Proves ordering: an APPSEC_*_MODEL=opus env override is applied
        inside the resolver, then clamped by the ceiling at the end."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("APPSEC_STRIDE_MODEL", "claude-opus-4-7")
        cfg = rc.resolve(["--no-opus"], REPO_ROOT)
        assert cfg["stride_model"] == "sonnet"

    def test_apply_opus_ban_idempotent_noop(self):
        cfg = {"reasoning_model": "opus-cheap", "merger_model": "opus"}
        patch = rc.apply_opus_ban(cfg, False)
        assert patch == {}
        assert cfg["opus_disabled"] is False
        assert cfg["merger_model"] == "opus"

    def test_apply_opus_ban_matches_full_id(self):
        cfg = {"reasoning_model": "opus", "merger_model": "claude-opus-4-7"}
        patch = rc.apply_opus_ban(cfg, True)
        assert patch["reasoning_model"] == "sonnet"
        assert patch["merger_model"] == "sonnet"


# ---------------------------------------------------------------------------
# Run-plan verdict: full scan over an existing model must explain itself
# ---------------------------------------------------------------------------


class TestEmbedFiguresFlag:
    """`--embed-figures` must be accepted by the validator parser (the user hit
    'unrecognized arguments' / internal-flag rejection) and default to False."""

    def test_flag_is_accepted(self):
        ns = rc.build_parser().parse_args(["--embed-figures"])
        assert ns.embed_figures is True

    def test_flag_defaults_false(self):
        ns = rc.build_parser().parse_args([])
        assert ns.embed_figures is False


class TestThreatDragonFlag:
    """`--threatdragon` must be accepted by the validator parser, default to
    False, and reach cfg as `write_threatdragon`. It is ALPHA and opt-in — no
    depth may turn it on implicitly."""

    def test_flag_is_accepted(self):
        ns = rc.build_parser().parse_args(["--threatdragon"])
        assert ns.threatdragon is True

    def test_flag_defaults_false(self):
        ns = rc.build_parser().parse_args([])
        assert ns.threatdragon is False

    def test_not_enabled_by_any_depth(self, tmp_path):
        base = ["--repo", str(tmp_path), "--output", str(tmp_path / "out")]
        for depth in ("quick", "standard", "thorough"):
            cfg = rc.resolve([*base, "--assessment-depth", depth], REPO_ROOT)
            assert cfg["write_threatdragon"] is False, depth

    def test_flag_reaches_cfg(self, tmp_path):
        base = ["--repo", str(tmp_path), "--output", str(tmp_path / "out")]
        cfg = rc.resolve([*base, "--threatdragon"], REPO_ROOT)
        assert cfg["write_threatdragon"] is True


class TestBrandingFlags:
    """Cover-branding flags (--report-title / --contact-name / --contact-email
    / --logo) flow to cfg, absolutise a relative local logo, and compose with
    an org-profile `branding` block (CLI wins)."""

    def _run(self, *argv):
        return _resolve_argv(*argv)

    def _write_branding_profile(self, tmp_path: Path) -> Path:
        profile = tmp_path / "org-profile" / "org-profile.yaml"
        profile.parent.mkdir()
        profile.write_text(
            "api_version: appsec-advisor.org-profile/v2\n"
            'organization: { id: myorg, name: My Org, profile_version: "1" }\n'
            'compatibility: { core: ">=0.0 <999.0" }\n'
            "branding:\n"
            "  report_title: Profile Title\n"
            "  contact_name: Profile Contact\n"
            "  contact_email: profile@org.test\n"
            "  logo: https://org.test/logo.png\n"
            "default_preset: std\n"
            "presets:\n"
            "  std:\n"
            "    base_mode: standard\n"
        )
        return profile

    def test_cli_flags_flow_to_cfg(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run(
            "--report-title",
            "Security Assessment",
            "--contact-name",
            "Jane Doe",
            "--contact-email",
            "jane@acme.io",
            "--logo",
            "https://acme.io/logo.png",
        )
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["report_title"] == "Security Assessment"
        assert cfg["contact_name"] == "Jane Doe"
        assert cfg["contact_email"] == "jane@acme.io"
        assert cfg["logo"] == "https://acme.io/logo.png"

    def test_branding_defaults_none(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = json.loads(self._run().stdout)
        for key in ("report_title", "contact_name", "contact_email", "logo"):
            assert cfg[key] is None

    def test_relative_local_logo_absolutised_against_cwd(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--logo", "assets/logo.png")
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["logo"] == str((tmp_path / "assets" / "logo.png").resolve())

    def test_org_profile_branding_fills_when_cli_absent(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        profile = self._write_branding_profile(tmp_path)
        cfg = json.loads(self._run("--org-profile", str(profile)).stdout)
        assert cfg["report_title"] == "Profile Title"
        assert cfg["contact_name"] == "Profile Contact"
        assert cfg["contact_email"] == "profile@org.test"
        assert cfg["logo"] == "https://org.test/logo.png"

    def test_cli_overrides_org_profile_branding(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        profile = self._write_branding_profile(tmp_path)
        cfg = json.loads(
            self._run(
                "--org-profile",
                str(profile),
                "--report-title",
                "Local Title",
                "--contact-name",
                "Local Contact",
            ).stdout
        )
        assert cfg["report_title"] == "Local Title"
        assert cfg["contact_name"] == "Local Contact"
        # Untouched fields still come from the profile.
        assert cfg["contact_email"] == "profile@org.test"
        assert cfg["logo"] == "https://org.test/logo.png"


class TestTracingPrecedence:
    """An explicit flag beats an org-profile preset, which beats the default (on)."""

    def _run(self, *argv):
        return _resolve_argv(*argv)

    def _write_profile(self, tmp_path: Path, tracing: bool) -> Path:
        profile = tmp_path / "org-profile" / "org-profile.yaml"
        profile.parent.mkdir()
        profile.write_text(
            "api_version: appsec-advisor.org-profile/v2\n"
            'organization: { id: myorg, name: My Org, profile_version: "1" }\n'
            'compatibility: { core: ">=0.0 <999.0" }\n'
            "default_preset: std\n"
            "presets:\n"
            "  std:\n"
            "    base_mode: standard\n"
            f"    guardrails: {{ tracing: {str(tracing).lower()} }}\n"
        )
        return profile

    @pytest.mark.parametrize(
        ("preset", "flags", "expected"),
        [
            (None, [], True),
            (None, ["--tracing"], True),
            (None, ["--no-tracing"], False),
            (True, [], True),
            (False, [], False),
            (True, ["--no-tracing"], False),
            (False, ["--tracing"], True),
        ],
    )
    def test_resolved_tracing(self, tmp_path, monkeypatch, preset, flags, expected):
        monkeypatch.chdir(tmp_path)
        argv = list(flags)
        if preset is not None:
            argv += ["--org-profile", str(self._write_profile(tmp_path, preset))]
        r = self._run(*argv)
        assert r.returncode == 0, r.stderr
        assert json.loads(r.stdout)["tracing"] is expected


# ---------------------------------------------------------------------------
# Render helpers — coverage of the run-plan / config-summary surface.
# These are pure functions over a resolved cfg dict; we resolve a real cfg
# once and override per-case so every required key is present.
# ---------------------------------------------------------------------------


class TestSummaryActiveOptions:
    def test_parallel_stride_environment_switch_is_absent(self):
        source = Path(rc.__file__).read_text(encoding="utf-8")
        assert "APPSEC_PARALLEL_STRIDE" not in source


class TestRuntimeGeneration:
    def test_runtime_generation_has_no_legacy_selection(self):
        resolved = rc.resolve_runtime_generation()
        assert resolved["runtime_generation"] == "context-v2"
        assert resolved["runtime_generation_label"] == "context-v2 (single runtime)"
        assert resolved["runtime_artifact_schema_versions"] == rc.CONTEXT_V2_ARTIFACT_SCHEMA_VERSIONS

    def test_read_only_resolution_does_not_create_output_directory(self, tmp_path):
        out_dir = tmp_path / "unstarted"
        cfg = rc.resolve(
            ["--full", "--repo", str(tmp_path), "--output", str(out_dir)], REPO_ROOT, create_output_dir=False
        )

        assert cfg["output_dir"] == str(out_dir)
        assert not out_dir.exists()


# ---------------------------------------------------------------------------
# Business context (--context, --skip-context)
# ---------------------------------------------------------------------------


class TestBusinessContext:
    def _ns(self, *argv):
        return rc.build_parser().parse_args(list(argv))

    def test_context_conflicts_with_rerender_and_resume(self):
        assert "--rerender" in (rc.detect_conflicts(self._ns("--context", "x", "--rerender")) or "")
        assert "--resume" in (rc.detect_conflicts(self._ns("--context", "x", "--resume")) or "")

    def test_url_value_is_carried_through(self, tmp_path):
        cfg = {"incremental": False, "repo_root": str(tmp_path), "output_dir": str(tmp_path)}
        out = rc.resolve_business_context(self._ns("--context", "https://ctx.example.test/a.md"), cfg)
        assert out["business_context_source"] == "https://ctx.example.test/a.md"

    def test_file_value_is_resolved_to_an_absolute_path(self, tmp_path, monkeypatch):
        source = tmp_path / "context.md"
        source.write_text("Checkout handles card data.\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        cfg = {"incremental": False, "repo_root": str(tmp_path), "output_dir": str(tmp_path)}

        out = rc.resolve_business_context(self._ns("--context", "context.md"), cfg)

        assert out["business_context_source"] == str(source.resolve())

    def test_skip_context_is_carried_through(self, tmp_path):
        cfg = {"incremental": False, "repo_root": str(tmp_path), "output_dir": str(tmp_path)}

        assert rc.resolve_business_context(self._ns("--skip-context"), cfg)["skip_business_context"] is True
        assert rc.resolve_business_context(self._ns(), cfg)["skip_business_context"] is False

    def test_skip_context_contradicts_context(self, tmp_path):
        cfg = {"incremental": False, "repo_root": str(tmp_path), "output_dir": str(tmp_path)}
        with pytest.raises(SystemExit, match="contradict"):
            rc.resolve_business_context(self._ns("--context", "https://ctx.example.test/a.md", "--skip-context"), cfg)

    def test_context_is_refused_when_the_producer_cannot_read_it(self, tmp_path):
        cfg = {"incremental": False, "repo_root": str(tmp_path), "output_dir": str(tmp_path)}
        with pytest.raises(SystemExit, match="neither an http"):
            rc.resolve_business_context(self._ns("--context", "ftp://host/ctx.md"), cfg)

    def test_context_configuration_never_selects_another_producer(self, tmp_path):
        source = tmp_path / "context.md"
        source.write_text("Checkout handles card data.\n", encoding="utf-8")
        out = tmp_path / "out"
        out.mkdir()
        (out / "threat-model.yaml").write_text("meta:\n  assessment_depth: standard\n", encoding="utf-8")
        base = ["--repo", str(tmp_path), "--output", str(out), "--context", str(source)]

        cfg = rc.resolve([*base, "--incremental"], REPO_ROOT)

        assert cfg["runtime_generation"] == "context-v2"
        assert cfg["business_context_source"] == str(source.resolve())

    def test_context_survives_a_full_run(self, tmp_path):
        source = tmp_path / "context.md"
        source.write_text("Checkout handles card data.\n", encoding="utf-8")
        base = ["--repo", str(tmp_path), "--output", str(tmp_path / "out"), "--context", str(source)]

        cfg = rc.resolve([*base, "--full"], REPO_ROOT)

        assert cfg["runtime_generation"] == "context-v2"
        assert cfg["business_context_source"] == str(source.resolve())
