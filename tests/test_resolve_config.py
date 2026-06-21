"""Tests for scripts/resolve_config.py.

Validates each resolver individually plus the end-to-end CLI contract.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "resolve_config.py"


def _load_module():
    if "resolve_config" in sys.modules:
        return sys.modules["resolve_config"]
    spec = importlib.util.spec_from_file_location("resolve_config", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["resolve_config"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rc = _load_module()


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


class TestRerenderMode:
    def _parse(self, *argv):
        return rc.build_parser().parse_args(list(argv))

    def test_rerender_on_structured_baseline(self, tmp_path):
        (tmp_path / "threat-model.yaml").write_text("meta: {}\n")
        res = rc.resolve_incremental_mode(self._parse("--rerender"), tmp_path, dry_run=False)
        assert res["mode"] == "rerender"
        assert res["rerender"] is True
        assert res["incremental"] is False
        assert res["rebuild"] is False

    def test_rerender_empty_dir_aborts(self, tmp_path):
        with pytest.raises(SystemExit):
            rc.resolve_incremental_mode(self._parse("--rerender"), tmp_path, dry_run=False)


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


class TestResolveReasoningModel:
    def test_default_standard_gives_opus_cheap(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["reasoning_model"] == "opus-cheap"
        assert out["stride_model"] == "sonnet"
        # opus-cheap routes only the merger to Opus; triage stays on Sonnet
        # because triage_validate_ratings.py is the deterministic floor.
        assert out["triage_model"] == "sonnet"
        assert out["merger_model"] == "opus"

    def test_default_quick_gives_haiku_economy(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "quick")
        assert out["reasoning_model"] == "sonnet-economy"
        # sonnet-economy keeps the Reasoning core on Sonnet
        assert out["stride_model"] == "sonnet"
        assert out["triage_model"] == "sonnet"
        assert out["merger_model"] == "sonnet"

    def test_explicit_opus(self):
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "opus"

    def test_env_var_highest_precedence(self, monkeypatch):
        monkeypatch.setenv("APPSEC_STRIDE_MODEL", "claude-env-override")
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "claude-env-override"


class TestResolveDefaultTierForCappedRepos:
    """B2d — auto-switch from opus-cheap to sonnet-economy on capped repos.

    Trigger: repo_size_capped=True AND user did not pass --reasoning-model.
    No-op in every other case.
    """

    def _ns(self, *argv):
        return rc.build_parser().parse_args(list(argv))

    def _capped_cfg(self, reasoning_model="opus-cheap", depth="standard", stride_components=3, capped=True):
        """Build a minimal cfg dict in the post-cap state."""
        return {
            "assessment_depth": depth,
            "reasoning_model": reasoning_model,
            "max_stride_components": stride_components,
            "repo_size_capped": capped,
        }

    def test_triggers_when_capped_and_no_flag(self):
        ns = self._ns()  # no --reasoning-model
        cfg = self._capped_cfg()
        out = rc.resolve_default_tier_for_capped_repos(cfg, ns)
        assert out["reasoning_model"] == "sonnet-economy"
        assert out["reasoning_auto_switched"] is True
        assert "auto" in out["reasoning_label"]
        # 2026-06-02/06-07: large repos keep the economy tier but never DROP
        # components — the analyzed set is criteria-selected, so the label says
        # "economy tier across all criteria-selected components".
        assert "criteria-selected components" in out["reasoning_label"]
        assert "economy tier" in out["reasoning_label"]
        # Dependent fields re-resolved
        assert out["triage_model"] == "sonnet"  # was Opus
        assert out["merger_model"] == "sonnet"  # was Opus
        assert out["recon_scanner_model"] == "haiku"

    def test_explicit_flag_disables_auto_switch(self):
        ns = self._ns("--reasoning-model", "opus-cheap")
        cfg = self._capped_cfg()
        out = rc.resolve_default_tier_for_capped_repos(cfg, ns)
        assert out == {}  # no patch

    def test_no_op_when_not_capped(self):
        ns = self._ns()
        cfg = self._capped_cfg(capped=False)
        out = rc.resolve_default_tier_for_capped_repos(cfg, ns)
        assert out == {}

    def test_no_op_when_already_haiku_economy(self):
        # quick depth defaults to sonnet-economy already → no need to switch.
        ns = self._ns()
        cfg = self._capped_cfg(reasoning_model="sonnet-economy", depth="quick")
        out = rc.resolve_default_tier_for_capped_repos(cfg, ns)
        assert out == {}

    def test_no_op_when_explicit_opus_chosen(self):
        # User explicitly wants Opus → never auto-downgrade.
        ns = self._ns("--reasoning-model", "opus")
        cfg = self._capped_cfg(reasoning_model="opus")
        out = rc.resolve_default_tier_for_capped_repos(cfg, ns)
        assert out == {}

    def test_thorough_capped_also_switches(self):
        # Thorough capped: same logic — capped components mean Opus
        # uneconomical regardless of whether the cap was set at standard
        # or carried into thorough.
        ns = self._ns()
        cfg = self._capped_cfg(depth="thorough")
        out = rc.resolve_default_tier_for_capped_repos(cfg, ns)
        assert out["reasoning_model"] == "sonnet-economy"
        assert out["reasoning_auto_switched"] is True


class TestResolveRepoSizeCap:
    """2026-06-02/06-07: a large repo flips to the economy tier (repo_size_capped)
    but NEVER drops components — dropping components created whole-component blind
    spots, and since 2026-06-07 the analyzed set is criteria-derived (no count to
    reduce). The cap patch therefore carries NO max_stride_components key."""

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
        assert out["repo_size_capped"] is True  # → drives economy tier
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
        assert out["architect_model"] == "opus"
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


class TestResolveIncrementalMode:
    def test_empty_dir_no_flag_is_first_run_full(self, tmp_path):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "full"
        assert "first run" in out["mode_label"]

    def test_empty_dir_plus_incremental_aborts(self, tmp_path):
        ns = rc.build_parser().parse_args(["--incremental"])
        with pytest.raises(SystemExit) as exc:
            rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert "requires an existing threat model" in str(exc.value)

    def test_legacy_baseline_plus_incremental_aborts(self, tmp_path):
        (tmp_path / "threat-model.md").write_text("# legacy\n")
        ns = rc.build_parser().parse_args(["--incremental"])
        with pytest.raises(SystemExit) as exc:
            rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert "structured baseline" in str(exc.value)

    def test_structured_baseline_auto_incremental(self, tmp_path):
        (tmp_path / "threat-model.yaml").write_text("meta: {schema_version: 1}\nthreats: []\n")
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "incremental"
        assert "auto" in out["mode_label"]

    def test_legacy_bootstrap_note(self, tmp_path):
        (tmp_path / "threat-model.md").write_text("# legacy\n")
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "full"
        assert "bootstrap" in out["mode_label"]
        assert "bootstrapping" in out["post_summary_note"].lower()

    def test_rebuild_with_existing_baseline(self, tmp_path):
        (tmp_path / "threat-model.yaml").write_text("meta: {schema_version: 1}\n")
        ns = rc.build_parser().parse_args(["--rebuild"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "rebuild"
        assert "will be deleted" in out["post_summary_note"]

    def test_dry_run_always_full(self, tmp_path):
        (tmp_path / "threat-model.yaml").write_text("meta: {schema_version: 1}\n")
        ns = rc.build_parser().parse_args(["--incremental"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=True)
        assert out["mode"] == "full"
        assert out["incremental"] is False

    # --- Depth-increase override (auto-incremental → full) -------------------

    def _yaml_with_depth(self, tmp_path, depth):
        (tmp_path / "threat-model.yaml").write_text(
            f"meta:\n  schema_version: 1\n  assessment_depth: {depth}\nthreats: []\n"
        )

    def test_depth_increase_quick_to_standard_forces_full(self, tmp_path):
        self._yaml_with_depth(tmp_path, "quick")
        ns = rc.build_parser().parse_args(["--assessment-depth", "standard"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "full"
        assert out["incremental"] is False
        assert "depth increased" in out["mode_label"]
        assert "quick" in out["depth_upgrade_reason"] and "standard" in out["depth_upgrade_reason"]

    def test_depth_increase_standard_to_thorough_forces_full(self, tmp_path):
        self._yaml_with_depth(tmp_path, "standard")
        ns = rc.build_parser().parse_args(["--assessment-depth", "thorough"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "full"
        assert "depth increased: standard → thorough" in out["mode_label"]

    def test_depth_increase_sets_reuse_recon_eligible(self, tmp_path):
        # Auto-upgraded full (depth deepened on an unchanged baseline) is eligible
        # to reuse the prior recon when the tree is git-provably clean.
        self._yaml_with_depth(tmp_path, "standard")
        ns = rc.build_parser().parse_args(["--assessment-depth", "thorough"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["reuse_recon_eligible"] is True

    def test_explicit_full_not_reuse_recon_eligible(self, tmp_path):
        # Explicit --full is the trust-nothing escape hatch: never reuse recon.
        self._yaml_with_depth(tmp_path, "standard")
        ns = rc.build_parser().parse_args(["--full", "--assessment-depth", "thorough"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "full"
        assert out.get("reuse_recon_eligible") is not True

    def test_auto_incremental_not_reuse_recon_eligible(self, tmp_path):
        # Plain auto-incremental skips recon via its own INCREMENTAL=true gate; it
        # does not need (and must not carry) the auto-upgraded-full reuse flag.
        self._yaml_with_depth(tmp_path, "standard")
        ns = rc.build_parser().parse_args(["--assessment-depth", "standard"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "incremental"
        assert out.get("reuse_recon_eligible") is not True

    def test_same_depth_stays_incremental(self, tmp_path):
        self._yaml_with_depth(tmp_path, "standard")
        ns = rc.build_parser().parse_args(["--assessment-depth", "standard"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "incremental"

    def test_shallower_depth_stays_incremental(self, tmp_path):
        self._yaml_with_depth(tmp_path, "thorough")
        ns = rc.build_parser().parse_args(["--assessment-depth", "quick"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "incremental"

    def test_no_depth_flag_defaults_standard_vs_quick_baseline_forces_full(self, tmp_path):
        # No --assessment-depth → effective "standard"; quick baseline is shallower.
        self._yaml_with_depth(tmp_path, "quick")
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "full"

    def test_baseline_without_depth_stays_incremental(self, tmp_path):
        # Pre-depth baseline (no meta.assessment_depth) → unknown → no upgrade.
        (tmp_path / "threat-model.yaml").write_text("meta:\n  schema_version: 1\nthreats: []\n")
        ns = rc.build_parser().parse_args(["--assessment-depth", "thorough"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "incremental"

    def test_explicit_incremental_honored_despite_depth_increase(self, tmp_path):
        # Explicit --incremental is always honored as-is (Rule 2/3 short-circuits
        # before the auto depth-increase override).
        self._yaml_with_depth(tmp_path, "quick")
        ns = rc.build_parser().parse_args(["--incremental", "--assessment-depth", "thorough"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "incremental"

    def test_depth_upgrade_reason_flows_into_run_plan_verdict(self, tmp_path):
        self._yaml_with_depth(tmp_path, "quick")
        ns = rc.build_parser().parse_args(["--assessment-depth", "thorough"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        cfg = {
            "mode": "full",
            "incremental": False,
            "baseline_state": "structured",
            "mode_label": out["mode_label"],
            "depth_upgrade_reason": out["depth_upgrade_reason"],
        }
        v = rc._run_plan_verdict(cfg, None, None, None)
        assert v["verdict"] == "RUN — full assessment (existing model)"
        assert "incremental cannot deepen" in v["reason"]

    # --- Requirements-toggle override (Variante B — final-resolved compare) ---

    def _yaml_with_req(self, tmp_path, check_requirements):
        val = "true" if check_requirements else "false"
        (tmp_path / "threat-model.yaml").write_text(
            f"meta:\n  schema_version: 1\n  check_requirements: {val}\nthreats: []\n"
        )

    def test_requirements_added_off_to_on_forces_full(self, tmp_path):
        self._yaml_with_req(tmp_path, False)
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False, cur_check_requirements=True)
        assert out["mode"] == "full"
        assert out["incremental"] is False
        assert "requirements added" in out["mode_label"]
        assert "without" in out["mode_upgraded_reason"].lower()
        # Auto-upgraded full on an unchanged baseline → eligible to reuse recon.
        assert out["reuse_recon_eligible"] is True

    def test_requirements_dropped_on_to_off_aborts(self, tmp_path):
        self._yaml_with_req(tmp_path, True)
        ns = rc.build_parser().parse_args([])
        with pytest.raises(SystemExit) as exc:
            rc.resolve_incremental_mode(ns, tmp_path, dry_run=False, cur_check_requirements=False)
        msg = str(exc.value)
        assert "requirements disabled" in msg
        assert "--full" in msg

    def test_requirements_unchanged_on_stays_incremental(self, tmp_path):
        self._yaml_with_req(tmp_path, True)
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False, cur_check_requirements=True)
        assert out["mode"] == "incremental"

    def test_requirements_unchanged_off_stays_incremental(self, tmp_path):
        self._yaml_with_req(tmp_path, False)
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False, cur_check_requirements=False)
        assert out["mode"] == "incremental"

    def test_requirements_baseline_without_field_stays_incremental(self, tmp_path):
        # Pre-feature baseline (no meta.check_requirements) → unknown → no gate.
        (tmp_path / "threat-model.yaml").write_text("meta:\n  schema_version: 1\nthreats: []\n")
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False, cur_check_requirements=False)
        assert out["mode"] == "incremental"

    def test_requirements_cur_unknown_skips_gate(self, tmp_path):
        # cur_check_requirements=None (caller did not pass it) → backward-compat no-op.
        self._yaml_with_req(tmp_path, True)
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False)
        assert out["mode"] == "incremental"

    def test_explicit_incremental_bypasses_requirements_drop(self, tmp_path):
        # Explicit --incremental is honored as-is (Rule 2/3 short-circuits),
        # same honor-the-explicit-flag contract as the depth-increase override.
        self._yaml_with_req(tmp_path, True)
        ns = rc.build_parser().parse_args(["--incremental"])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False, cur_check_requirements=False)
        assert out["mode"] == "incremental"

    def test_requirements_added_reason_flows_into_run_plan_verdict(self, tmp_path):
        self._yaml_with_req(tmp_path, False)
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_incremental_mode(ns, tmp_path, dry_run=False, cur_check_requirements=True)
        cfg = {
            "mode": "full",
            "incremental": False,
            "baseline_state": "structured",
            "mode_label": out["mode_label"],
            "mode_upgraded_reason": out["mode_upgraded_reason"],
        }
        v = rc._run_plan_verdict(cfg, None, None, None)
        assert v["verdict"] == "RUN — full assessment (existing model)"
        assert "incremental cannot add requirement coverage" in v["reason"]


# ---------------------------------------------------------------------------
# End-to-end CLI smoke
# ---------------------------------------------------------------------------


class TestCLI:
    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *argv],
            capture_output=True,
            text=True,
        )

    def test_empty_args_default_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run()
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["mode"] == "full"  # first run
        assert cfg["write_yaml"] is True
        assert cfg["assessment_depth"] == "standard"
        assert cfg["reasoning_model"] == "opus-cheap"
        assert cfg["architect_review"] is False
        assert cfg["quiet"] is False  # verdict echoed by default

    def test_quiet_flag_flows_to_cfg(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--quiet")
        assert r.returncode == 0
        cfg = json.loads(r.stdout)
        assert cfg["quiet"] is True

    def test_config_summary_prints_human_readable(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary")
        assert r.returncode == 0
        assert "Configuration resolved." in r.stdout
        assert "Repository" in r.stdout
        assert "Mode" in r.stdout

    # -- --validate-only fail-fast gate -------------------------------------

    def test_validate_only_rejects_unknown_flag(self, tmp_path, monkeypatch):
        """Skill-level fail-fast: argparse must reject a typo like `--qiuck`
        with exit 2 and produce no JSON."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--validate-only", "--qiuck")
        assert r.returncode == 2
        assert "unrecognized arguments: --qiuck" in r.stderr
        assert r.stdout == ""

    def test_validate_only_accepts_clean_args(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--validate-only", "--assessment-depth", "quick")
        assert r.returncode == 0
        assert r.stdout == ""

    def test_validate_only_strips_skill_only_force(self, tmp_path, monkeypatch):
        """`--force` is consumed by the skill layer; validator must not
        reject it."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--validate-only", "--rebuild", "--force")
        assert r.returncode == 0

    def test_validate_only_rejects_conflict(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--validate-only", "--rebuild", "--incremental")
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

    # -- summary "show only when active" rules ------------------------------

    def test_summary_default_quiet_no_optional_rows(self, tmp_path, monkeypatch):
        """A bare invocation must show the boxed run identity without
        default-off Active Options clutter or 'disabled' lines."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary")
        assert r.returncode == 0
        out = r.stdout
        assert "Create Threat Model" in out
        # Always-shown core rows
        for label in ("Repository:", "Output", "Plugin", "Mode", "Depth", "Reasoning"):
            assert label in out, f"missing always-on row: {label}"
        assert "Scope     : full repository" in out
        # Default-off optional rows must be silent
        assert "SCA " not in out
        assert "architect review" not in out
        assert "Outputs " not in out
        assert "Run flags " not in out
        assert "Skips" not in out
        # Requirements is disabled by default at standard → silent (the
        # informational "Tip:" post-line is fine).
        assert "Requirements " not in out

    def test_with_sca_flag_is_rejected(self, tmp_path, monkeypatch):
        """--with-sca / --no-sca were removed in 2026-05. argparse must
        reject them as unknown flags (exit 2). Verifies the hard cutover
        is in place — no deprecation alias, no no-op acceptance."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "--with-sca")
        assert r.returncode != 0, "--with-sca must be rejected by argparse"
        assert "unrecognized arguments" in r.stderr or "error" in r.stderr.lower()

    def test_summary_shows_architect_when_thorough(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "--assessment-depth", "thorough")
        assert "Extras    : architect review" in r.stdout

    def test_summary_shows_run_flags_when_active(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Tracing is the silent default since M3.6, so passing --tracing is
        # a no-op for the flag list. Use --no-tracing as the deviation that
        # surfaces in the Run flags row.
        r = self._run("--config-summary", "--dry-run", "--verbose", "--no-tracing")
        assert "Run flags : dry-run, verbose, no-tracing" in r.stdout

    def test_summary_shows_outputs_when_sarif_or_pentest(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "--sarif", "--pentest-tasks")
        assert "Outputs   :" in r.stdout
        assert "markdown + yaml + sarif" in r.stdout
        assert "pentest-tasks (generic)" in r.stdout

    def test_summary_shows_active_org_profile_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        profile = tmp_path / "org-profile" / "org-profile.yaml"
        profile.parent.mkdir()
        profile.write_text(
            "api_version: appsec-advisor.org-profile/v2\n"
            'organization: { id: myorg, name: My Org, profile_version: "1" }\n'
            'compatibility: { core: ">=0.4 <0.6" }\n'
            "default_preset: local-default\n"
            "presets:\n"
            "  local-default:\n"
            "    base_mode: standard\n"
            "    outputs: { sarif: true }\n"
            "    guardrails: { max_cost_usd: 10 }\n"
        )
        r = self._run("--config-summary", "--org-profile", str(profile))
        assert r.returncode == 0
        assert "Org profile" in r.stdout
        assert "My Org (myorg), preset local-default, source cli" in r.stdout
        assert "Outputs   :" in r.stdout
        assert "markdown + yaml + sarif" in r.stdout
        assert "Limits    : cost $10.00" in r.stdout

    def test_summary_shows_pentest_target_inline(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run(
            "--config-summary", "--pentest-tasks", "--pentest-format", "strix", "--pentest-target", "https://x.test"
        )
        assert "pentest-tasks (strix, target:" in r.stdout
        assert "https://x.test" in r.stdout

    def test_summary_shows_scope_when_present(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "focus", "on", "auth")
        assert "Scope     : focus on auth" in r.stdout

    def test_summary_shows_no_yaml_marker(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "--no-yaml")
        assert "Outputs   :" in r.stdout
        assert "markdown + no yaml" in r.stdout

    def test_summary_shows_qa_skipped(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "--no-qa")
        assert "Skips     : QA skipped (--no-qa)" in r.stdout

    def test_summary_shows_quick_fast_mode_skips(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "--quick")
        assert r.returncode == 0
        assert "QA skipped (auto - quick depth)" in r.stdout
        assert "walkthroughs" in r.stdout
        assert "skipped (auto - quick" in r.stdout
        assert "depth)" in r.stdout
        assert "QA skipped (--no-qa)" not in r.stdout

    def test_summary_shows_walkthroughs_skipped_when_set(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "--no-walkthroughs")
        assert r.returncode == 0
        assert "walkthroughs skipped (--no-walkthroughs)" in r.stdout

    def test_summary_shows_deadline_when_set(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary", "--max-wall-time", "1h", "--max-cost", "15.0")
        assert "Limits    : wall-time 1 h / cost $15.00" in r.stdout

    def test_summary_box_wraps_long_values_without_breaking_border(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        long_out = tmp_path / (
            "this/is/a/very/long/output/path/with/many/segments/that/would/not/fit/in/a/fixed/box/docs/security"
        )
        r = self._run(
            "--config-summary",
            "--output",
            str(long_out),
            "--pentest-tasks",
            "--pentest-format",
            "strix",
            "--pentest-target",
            "https://example.internal.company.test/a/very/long/path?service=auth",
            "focus",
            "on",
            "authentication",
            "admin",
            "privilege",
            "escalation",
            "and",
            "OAuth",
            "callback",
            "handling",
        )
        assert r.returncode == 0
        box_lines = [line for line in r.stdout.splitlines() if line.startswith(("╭", "│", "╰"))]
        assert box_lines
        widths = {len(line) for line in box_lines}
        assert len(widths) == 1
        assert all(line.endswith(("╮", "│", "╯")) for line in box_lines)

    def test_summary_is_incremental_mode_aware(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "docs" / "security"
        out.mkdir(parents=True)
        (out / "threat-model.yaml").write_text("meta:\n")
        r = self._run("--config-summary")
        assert r.returncode == 0
        assert "Mode      : incremental (auto)" in r.stdout
        assert "Scope     : incremental delta from previous threat-model.yaml" in r.stdout
        assert "Pipeline  : change check -> recon -> STRIDE delta" in r.stdout

    def test_summary_silent_for_disabled_options(self, tmp_path, monkeypatch):
        """Verify the disabled-by-default rule: no 'disabled' lines for the
        SCA/QA/Architect toggles when the user did not set them."""
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary")
        out = r.stdout
        for needle in ("SCA          : disabled", "Architect    : disabled", "QA           : enabled"):
            assert needle not in out

    def test_conflict_exits_nonzero(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--yaml", "--no-yaml")
        assert r.returncode != 0
        assert "cannot be used together" in r.stderr

    def test_emit_file_writes_skill_config_json(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        r = self._run("--output", str(out), "--emit-file")
        assert r.returncode == 0
        sc = out / ".skill-config.json"
        assert sc.is_file()
        data = json.loads(sc.read_text())
        assert data["output_dir"] == str(out)

    def test_repo_flag_resolves_path(self, tmp_path, monkeypatch):
        # Set up a fake "repo" — just a directory; git fallback is fine.
        monkeypatch.chdir(tmp_path)
        r = self._run("--repo", str(tmp_path))
        cfg = json.loads(r.stdout)
        assert cfg["repo_root"] == str(tmp_path)

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
        assert cfg["mode_label"] == "full (first run)"
        assert cfg["reasoning_model"] == "opus-cheap"
        assert cfg["stride_model"] == "sonnet"
        assert cfg["triage_model"] == "sonnet"
        assert cfg["merger_model"] == "opus"
        assert cfg["architect_review"] is False
        assert cfg["check_requirements"] is False

    def test_thorough_auto_enables_architect_review(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--assessment-depth", "thorough"], REPO_ROOT)
        assert cfg["architect_review"] is True
        assert cfg["architect_model"] == "opus"

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
        """No switch → no-op: merger stays on Opus, flag records False."""
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve([], REPO_ROOT)
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

    def test_no_opus_clamps_default_merger(self, tmp_path, monkeypatch):
        """Default standard tier is opus-cheap → merger would be Opus."""
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--no-opus"], REPO_ROOT)
        assert cfg["reasoning_model"] == "sonnet"
        assert cfg["merger_model"] == "sonnet"

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


class TestFullOverExistingReason:
    def _cfg(self, **over):
        base = {
            "mode": "full",
            "incremental": False,
            "baseline_state": "structured",
            "mode_label": "full",
            "repo_root": "/r",
            "output_dir": "/o",
            "plugin_version": "0.4.0-beta",
            "analysis_version": 2,
            "skip_qa": False,
            "architect_review": False,
        }
        base.update(over)
        return base

    def test_explicit_full_over_existing_model_names_existing(self):
        v = rc._run_plan_verdict(self._cfg(), None, None, None)
        assert v["verdict"] == "RUN — full assessment (existing model)"
        assert "existing model present" in v["reason"]
        assert "--full requested" in v["reason"]

    def test_first_run_has_no_existing_suffix(self):
        v = rc._run_plan_verdict(self._cfg(baseline_state="empty"), None, None, None)
        assert v["verdict"] == "RUN — full assessment"
        assert "first full assessment" in v["reason"]

    def test_incompatible_schema_reason(self):
        v = rc._run_plan_verdict(self._cfg(), None, None, "incompatible")
        assert "incompatible" in v["reason"]
        assert "full rebuild required" in v["reason"]

    def test_plugin_minor_drift_reason(self):
        pre = {"plugin_version": {"baseline": "0.3.0", "current": "0.4.0", "tier": "minor"}}
        v = rc._run_plan_verdict(self._cfg(), pre, None, None)
        assert "plugin upgraded (minor)" in v["reason"]

    def test_mode_upgrade_reason_passthrough(self):
        cfg = self._cfg(mode_upgraded_reason="existing model present; switched to full — broad delta")
        v = rc._run_plan_verdict(cfg, None, None, None)
        assert v["reason"] == "existing model present; switched to full — broad delta"

    def test_prior_label_appended_when_present(self):
        cfg = self._cfg(baseline_prior_label="v3 (2026-06-10)")
        v = rc._run_plan_verdict(cfg, None, None, None)
        assert "[replaces v3 (2026-06-10)]" in v["reason"]

    def test_rebuild_reason_unchanged(self):
        v = rc._run_plan_verdict(self._cfg(mode="rebuild", mode_label="rebuild"), None, None, None)
        assert v["verdict"] == "REBUILD — wipe + full re-assessment"


class TestEmbedFiguresFlag:
    """`--embed-figures` must be accepted by the validator parser (the user hit
    'unrecognized arguments' / internal-flag rejection) and default to False."""

    def test_flag_is_accepted(self):
        ns = rc.build_parser().parse_args(["--embed-figures"])
        assert ns.embed_figures is True

    def test_flag_defaults_false(self):
        ns = rc.build_parser().parse_args([])
        assert ns.embed_figures is False


class TestBrandingFlags:
    """Cover-branding flags (--report-title / --contact-name / --contact-email
    / --logo) flow to cfg, absolutise a relative local logo, and compose with
    an org-profile `branding` block (CLI wins)."""

    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *argv],
            capture_output=True,
            text=True,
        )

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


# ---------------------------------------------------------------------------
# Render helpers — coverage of the run-plan / config-summary surface.
# These are pure functions over a resolved cfg dict; we resolve a real cfg
# once and override per-case so every required key is present.
# ---------------------------------------------------------------------------


def _base_cfg(**over):
    cfg = rc.resolve([], REPO_ROOT)
    cfg.update(over)
    return cfg


class TestRenderConfigurationSummary:
    def test_basic_box_renders(self):
        out = rc.render_configuration_summary(_base_cfg())
        assert "Configuration resolved." in out
        assert "Create Threat Model" in out
        assert "Repository" in out
        assert "Run Plan" in out

    def test_incremental_scope_line(self):
        out = rc.render_configuration_summary(_base_cfg(incremental=True, scope=["auth", "api"]))
        assert "incremental delta" in out
        assert "user focus: auth api" in out

    def test_incremental_scope_no_focus(self):
        out = rc.render_configuration_summary(_base_cfg(incremental=True, scope=[]))
        assert "incremental delta from previous threat-model.yaml" in out

    def test_full_repository_scope(self):
        out = rc.render_configuration_summary(_base_cfg(scope=[]))
        assert "full repository" in out

    def test_active_options_outputs_and_extras(self):
        out = rc.render_configuration_summary(
            _base_cfg(
                write_yaml=True,
                write_sarif=True,
                check_requirements=True,
                requirements_label="OWASP ASVS",
                architect_review=True,
                architect_label="deep",
            )
        )
        assert "Active Options" in out
        assert "sarif" in out
        assert "requirements" in out
        assert "architect review" in out

    def test_post_summary_note_for_incremental_mode(self):
        out = rc.render_configuration_summary(_base_cfg(mode="incremental"))
        assert "Run with --full periodically" in out

    def test_post_summary_output_outside_repo(self):
        out = rc.render_configuration_summary(_base_cfg(output_outside_repo=True))
        assert "outside the repository" in out

    def test_post_summary_repo_size_capped(self):
        out = rc.render_configuration_summary(_base_cfg(repo_size_capped=True, repo_size_source_files=99999))
        assert "large repository" in out
        assert "99999" in out


class TestFormatDepthSummary:
    def test_full_run_names_criteria_selection(self):
        s = rc._format_depth_summary(_base_cfg(incremental=False))
        assert "criteria-selected components" in s
        assert "STRIDE turns" in s

    def test_incremental_omits_component_count(self):
        s = rc._format_depth_summary(_base_cfg(incremental=True))
        assert "criteria-selected components" not in s


class TestFormatPipelineSummary:
    def test_full_pipeline(self):
        s = rc._format_pipeline_summary(_base_cfg(incremental=False, skip_qa=False))
        assert "recon -> architecture -> STRIDE" in s
        assert "QA" in s

    def test_incremental_pipeline_skip_qa(self):
        s = rc._format_pipeline_summary(_base_cfg(incremental=True, skip_qa=True))
        assert "change check" in s
        assert "STRIDE delta" in s
        assert "QA" not in s

    def test_architect_review_appended(self):
        s = rc._format_pipeline_summary(_base_cfg(architect_review=True))
        assert "architect review" in s


class TestFormatReasoningSummary:
    def test_opus_disabled_ceiling(self):
        s = rc._format_reasoning_summary(_base_cfg(opus_disabled=True))
        assert "no-opus ceiling" in s

    def test_auto_switched_large_repo(self):
        s = rc._format_reasoning_summary(_base_cfg(opus_disabled=False, reasoning_auto_switched=True))
        assert "auto-switched for large repo" in s

    def test_sonnet_economy_special(self):
        s = rc._format_reasoning_summary(
            _base_cfg(
                opus_disabled=False,
                reasoning_auto_switched=False,
                reasoning_model="sonnet-economy",
            )
        )
        assert "cheap phases Haiku" in s

    def test_alias_normalised(self):
        s = rc._format_reasoning_summary(
            _base_cfg(
                opus_disabled=False,
                reasoning_auto_switched=False,
                reasoning_model="haiku-economy",
            )
        )
        # alias maps to sonnet-economy
        assert "sonnet-economy" in s

    def test_per_agent_models_shortened(self):
        s = rc._format_reasoning_summary(
            _base_cfg(
                opus_disabled=False,
                reasoning_auto_switched=False,
                reasoning_model="opus-cheap",
                stride_model="claude-sonnet-4-6",
                triage_model="claude-sonnet-4-6",
                merger_model="claude-opus-4-7",
            )
        )
        assert "STRIDE Sonnet" in s
        assert "merge Opus" in s


class TestSummaryActiveOptions:
    def test_skips_and_flags(self, monkeypatch):
        monkeypatch.delenv("APPSEC_PARALLEL_STRIDE", raising=False)
        monkeypatch.delenv("APPSEC_LIVE_PHASE", raising=False)
        rows = rc._summary_active_options(
            _base_cfg(
                skip_qa=True,
                skip_qa_label="skipped",
                skip_attack_walkthroughs=True,
                dry_run=True,
                verbose=True,
                tracing=False,
                mode="incremental",
            )
        )
        labels = {label for label, _ in rows}
        assert "Skips" in labels
        assert "Run flags" in labels

    def test_parallel_stride_default_on_for_full(self, monkeypatch):
        monkeypatch.delenv("APPSEC_PARALLEL_STRIDE", raising=False)
        monkeypatch.delenv("APPSEC_LIVE_PHASE", raising=False)
        rows = dict(rc._summary_active_options(_base_cfg(mode="full")))
        assert "parallel" in rows["STRIDE disp"]

    def test_parallel_stride_optout(self, monkeypatch):
        monkeypatch.setenv("APPSEC_PARALLEL_STRIDE", "0")
        monkeypatch.delenv("APPSEC_LIVE_PHASE", raising=False)
        rows = dict(rc._summary_active_options(_base_cfg(mode="full")))
        assert "serial inline" in rows["STRIDE disp"]

    def test_live_phase_active(self, monkeypatch):
        monkeypatch.setenv("APPSEC_PARALLEL_STRIDE", "0")
        monkeypatch.setenv("APPSEC_LIVE_PHASE", "1")
        rows = dict(rc._summary_active_options(_base_cfg(mode="incremental")))
        assert "Live phase" in rows
        assert "background dispatch" in rows["Live phase"]

    def test_live_phase_inactive_under_parallel(self, monkeypatch):
        monkeypatch.delenv("APPSEC_PARALLEL_STRIDE", raising=False)
        monkeypatch.setenv("APPSEC_LIVE_PHASE", "1")
        rows = dict(rc._summary_active_options(_base_cfg(mode="full")))
        assert "PARALLEL_STRIDE wins" in rows["Live phase"]

    def test_limits_wall_time_hours_and_cost(self, monkeypatch):
        monkeypatch.delenv("APPSEC_PARALLEL_STRIDE", raising=False)
        monkeypatch.delenv("APPSEC_LIVE_PHASE", raising=False)
        rows = dict(rc._summary_active_options(_base_cfg(max_wall_time_seconds=7800, max_cost_usd=12.5)))
        assert "wall-time 2 h 10 min" in rows["Limits"]
        assert "cost $12.50" in rows["Limits"]

    def test_limits_wall_time_minutes_only(self, monkeypatch):
        monkeypatch.delenv("APPSEC_PARALLEL_STRIDE", raising=False)
        monkeypatch.delenv("APPSEC_LIVE_PHASE", raising=False)
        rows = dict(rc._summary_active_options(_base_cfg(max_wall_time_seconds=1800, max_cost_usd=None)))
        assert "wall-time 30 min" in rows["Limits"]

    def test_stride_profile_non_full(self, monkeypatch):
        monkeypatch.delenv("APPSEC_PARALLEL_STRIDE", raising=False)
        monkeypatch.delenv("APPSEC_LIVE_PHASE", raising=False)
        rows = dict(rc._summary_active_options(_base_cfg(stride_profile={"stride_profile_label": "web-only"})))
        assert rows["STRIDE"] == "web-only"


class TestFormatOrgProfileSummary:
    def test_inactive_returns_empty(self):
        assert rc._format_org_profile_summary(_base_cfg(org_profile={})) == ""

    def test_active_with_preset_and_source(self):
        s = rc._format_org_profile_summary(
            _base_cfg(
                org_profile={
                    "active": True,
                    "name": "Acme",
                    "id": "acme-corp",
                    "source": "url",
                },
                preset={"name": "strict"},
            )
        )
        assert "Acme (acme-corp)" in s
        assert "preset strict" in s
        assert "source url" in s


class TestFormatOutputsSummary:
    def test_default_md_yaml_is_empty(self):
        s = rc._format_outputs_summary(_base_cfg(write_yaml=True, write_sarif=False, write_pentest_tasks=False))
        assert s == ""

    def test_no_yaml(self):
        s = rc._format_outputs_summary(_base_cfg(write_yaml=False))
        assert "no yaml" in s

    def test_pentest_with_target(self):
        s = rc._format_outputs_summary(
            _base_cfg(
                write_pentest_tasks=True,
                pentest_format="burp",
                pentest_target="https://x.test",
            )
        )
        assert "pentest-tasks (burp, target: https://x.test)" in s

    def test_pentest_without_target(self):
        s = rc._format_outputs_summary(
            _base_cfg(
                write_pentest_tasks=True,
                pentest_format=None,
                pentest_target=None,
            )
        )
        assert "pentest-tasks (generic)" in s


class TestFormatOutputs:
    def test_no_yaml_and_sarif_and_pentest_target(self):
        s = rc._format_outputs(
            _base_cfg(
                write_yaml=False,
                write_sarif=True,
                write_pentest_tasks=True,
                pentest_format="md",
                pentest_target="t",
            )
        )
        assert "-yaml (--no-yaml)" in s
        assert "+ sarif" in s
        assert "pentest-tasks (md, target: t)" in s

    def test_pentest_no_target_default_format(self):
        s = rc._format_outputs(
            _base_cfg(
                write_yaml=True,
                write_sarif=False,
                write_pentest_tasks=True,
                pentest_format=None,
                pentest_target=None,
            )
        )
        assert "pentest-tasks (generic)" in s


class TestFormatRunFlags:
    def test_all_deviating_flags(self):
        s = rc._format_run_flags(
            _base_cfg(
                dry_run=True,
                verbose=True,
                tracing=False,
                scan_manifest=True,
                keep_runtime_files=True,
                pr_mode=True,
                qa_scan_repo=True,
            )
        )
        for token in (
            "dry-run",
            "verbose",
            "no-tracing",
            "scan-manifest",
            "keep-runtime-files",
            "pr-mode",
            "qa-scan-repo",
        ):
            assert token in s

    def test_silent_defaults_empty(self):
        s = rc._format_run_flags(
            _base_cfg(
                dry_run=False,
                verbose=False,
                tracing=True,
                scan_manifest=False,
                keep_runtime_files=False,
                pr_mode=False,
                qa_scan_repo=False,
            )
        )
        assert s == ""


class TestRunPlanVerdictIncremental:
    def _icfg(self, **over):
        base = _base_cfg(incremental=True, mode="incremental")
        base.update(over)
        return base

    def test_unchanged_noop(self):
        v = rc._run_plan_verdict(self._icfg(), {"status": "unchanged"}, None, None)
        assert v["will_run"] is False
        assert "NO-OP" in v["verdict"]

    def test_noise_only(self):
        pre = {"status": "noise_only", "noise_only_changes": ["a.md", "b.md"]}
        v = rc._run_plan_verdict(self._icfg(), pre, None, None)
        assert v["will_run"] is False
        assert "NOISE-ONLY" in v["verdict"]
        assert "2 non-security" in v["reason"]

    def test_unchanged_plugin_drift(self):
        pre = {
            "status": "unchanged_plugin_drift",
            "plugin_version": {
                "baseline": "0.3.0",
                "current": "0.4.0",
                "tier": "minor",
                "message": "drifted",
            },
        }
        v = rc._run_plan_verdict(self._icfg(), pre, None, None)
        assert v["will_run"] is False
        assert "PLUGIN-DRIFT" in v["verdict"]
        assert v["reason"] == "drifted"

    def test_changed_noop_global_only(self):
        pre = {"status": "changed"}
        ds = {"decision": "noop_global_only"}
        v = rc._run_plan_verdict(self._icfg(), pre, ds, None)
        assert v["will_run"] is False
        assert "NO-OP" in v["verdict"]

    def test_changed_ambiguous_new_component(self):
        pre = {"status": "changed"}
        ds = {"decision": "ambiguous_potential_new_component"}
        v = rc._run_plan_verdict(self._icfg(), pre, ds, None)
        assert v["will_run"] is True
        assert "AMBIGUOUS" in v["verdict"]

    def test_changed_dirty_components(self):
        pre = {"status": "changed", "plugin_version": {"tier": "minor"}}
        ds = {"decision": "dirty", "dirty_component_ids": ["c1", "c2", "c3", "c4"]}
        v = rc._run_plan_verdict(self._icfg(), pre, ds, None)
        assert v["will_run"] is True
        assert "4 component(s) dirty" in v["verdict"]
        assert "consider --full" in v["verdict"]

    def test_changed_dirty_unresolved_fallthrough(self):
        pre = {"status": "changed"}
        v = rc._run_plan_verdict(self._icfg(), pre, None, None)
        assert v["will_run"] is True
        assert "delta scope unresolved" in v["verdict"]

    def test_no_precheck_default_fallthrough(self):
        v = rc._run_plan_verdict(self._icfg(), None, None, None)
        assert v["will_run"] is True
        assert "full pipeline (default)" in v["verdict"]

    def test_legacy_baseline_full(self):
        cfg = _base_cfg(incremental=False, baseline_state="legacy")
        v = rc._run_plan_verdict(cfg, None, None, None)
        assert "bootstrap full run" in v["reason"]


class TestPipelineString:
    def test_full(self):
        s = rc._pipeline_string(_base_cfg(skip_qa=False), full=True)
        assert s.startswith("recon -> architecture -> STRIDE")
        assert "QA" in s

    def test_incremental_no_dirty(self):
        s = rc._pipeline_string(_base_cfg(skip_qa=True), full=False)
        assert "STRIDE delta" in s
        assert "QA" not in s

    def test_incremental_dirty_scope_truncation(self):
        s = rc._pipeline_string(
            _base_cfg(),
            full=False,
            dirty_components=["a", "b", "c", "d", "e"],
        )
        assert "STRIDE delta (a, b, c, +2)" in s

    def test_architect_review_appended(self):
        s = rc._pipeline_string(_base_cfg(architect_review=True), full=True)
        assert s.endswith("architect review")


class TestRunPlanNotes:
    def test_will_run_incremental_notes(self):
        verdict = {"will_run": True, "mode_line": "incremental — delta"}
        notes = rc._run_plan_notes(verdict, _base_cfg(), None, None, None)
        assert any("Ctrl-C" in n for n in notes)
        assert any("Pass --full to widen" in n for n in notes)

    def test_skipped_notes(self):
        verdict = {"will_run": False, "mode_line": "incremental — fast-abort"}
        notes = rc._run_plan_notes(verdict, _base_cfg(), None, None, None)
        assert any("preserved as-is" in n for n in notes)

    def test_major_plugin_drift_note(self):
        verdict = {"will_run": True, "mode_line": "incremental"}
        pre = {"plugin_version": {"tier": "major"}}
        notes = rc._run_plan_notes(verdict, _base_cfg(), pre, None, None)
        assert any("STRONGLY consider --full" in n for n in notes)

    def test_minor_plugin_drift_note(self):
        verdict = {"will_run": True, "mode_line": "incremental"}
        pre = {"plugin_version": {"tier": "minor"}}
        notes = rc._run_plan_notes(verdict, _base_cfg(), pre, None, None)
        assert any("Consider --full" in n for n in notes)

    def test_older_compatible_note(self):
        verdict = {"will_run": True, "mode_line": "full"}
        notes = rc._run_plan_notes(verdict, _base_cfg(), None, None, "older-compatible")
        assert any("Analysis schema drifted" in n for n in notes)

    def test_repo_size_capped_note(self):
        verdict = {"will_run": True, "mode_line": "full"}
        cfg = _base_cfg(repo_size_capped=True, repo_size_source_files=12345)
        notes = rc._run_plan_notes(verdict, cfg, None, None, None)
        assert any("Large repo (12345" in n for n in notes)


class TestRenderRunPlan:
    def test_full_run_renders_configuration_section(self):
        cfg = _base_cfg(incremental=False, baseline_state="empty")
        out = rc.render_run_plan(cfg, None, None, None)
        assert "Threat Model — Pre-flight" in out
        assert "Configuration" in out
        assert "Verdict" in out

    def test_dirty_incremental_renders_files_and_why(self):
        cfg = _base_cfg(incremental=True, mode="incremental")
        pre = {
            "status": "changed",
            "security_relevant_change_count": 2,
            "noise_only_changes": ["x.md"],
            "excluded_pre_filter_count": 1,
            "security_relevant_changes": ["src/auth.ts", "src/api.ts"],
            "relevance_reasons": {"src/auth.ts": ["authn"], "src/api.ts": []},
            "plugin_version": {},
        }
        ds = {
            "decision": "dirty",
            "dirty_component_ids": ["auth"],
            "all_components_known": ["auth", "api", "ui"],
        }
        out = rc.render_run_plan(cfg, pre, ds, "older-compatible")
        assert "Files" in out
        assert "Why this run is going to launch" in out
        assert "src/auth.ts" in out
        assert "Components" in out
        assert "carried forward" in out

    def test_noop_renders_why_not(self):
        cfg = _base_cfg(incremental=True, mode="incremental")
        pre = {
            "status": "noise_only",
            "noise_only_changes": ["a.md"],
            "security_relevant_changes": ["docs/readme.md"],
            "relevance_reasons": {},
            "security_relevant_change_count": 0,
            "plugin_version": {},
        }
        out = rc.render_run_plan(cfg, pre, None, None)
        assert "Why this run will NOT execute" in out

    def test_plugin_drift_marker_and_schema_line(self):
        cfg = _base_cfg(incremental=True, mode="incremental")
        pre = {
            "status": "changed",
            "plugin_version": {
                "baseline": "0.1.0",
                "current": cfg["plugin_version"],
                "tier": "major",
            },
        }
        out = rc.render_run_plan(cfg, pre, None, "incompatible")
        assert "DRIFT" in out
        assert "analysis_version drift" in out

    def test_ambiguous_unmapped_files_section(self):
        cfg = _base_cfg(incremental=True, mode="incremental")
        pre = {
            "status": "changed",
            "security_relevant_changes": ["new/thing.ts"],
            "relevance_reasons": {},
            "security_relevant_change_count": 1,
            "plugin_version": {},
        }
        ds = {
            "decision": "ambiguous_potential_new_component",
            "unmapped_files": ["new/thing.ts"],
            "all_components_known": ["a"],
            "dirty_component_ids": [],
        }
        out = rc.render_run_plan(cfg, pre, ds, None)
        assert "Unmapped (possible new component)" in out


class TestRunPlanCLI:
    def _run(self, *argv, **kw):
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *argv],
            capture_output=True,
            text=True,
            **kw,
        )

    def test_run_plan_without_skill_config_uses_fresh_resolve(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--run-plan")
        assert r.returncode == 0
        assert "Threat Model — Pre-flight" in r.stdout

    def test_run_plan_reads_skill_config_and_payloads(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # First emit a real .skill-config.json into the output dir.
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        emit = self._run("--emit-file", "--output", str(out_dir))
        assert emit.returncode == 0
        sc = out_dir / ".skill-config.json"
        assert sc.is_file()
        # Flip the persisted cfg to incremental so the verdict engine refines
        # via the pre-check / dirty-set payloads (a fresh first-run resolve is
        # always full and would ignore them).
        cfg = json.loads(sc.read_text())
        cfg["incremental"] = True
        cfg["mode"] = "incremental"
        sc.write_text(json.dumps(cfg))

        pre = out_dir / "pre.json"
        pre.write_text(
            json.dumps(
                {
                    "status": "changed",
                    "security_relevant_changes": ["src/a.ts"],
                    "relevance_reasons": {"src/a.ts": ["authn"]},
                    "security_relevant_change_count": 1,
                    "plugin_version": {},
                }
            )
        )
        ds = out_dir / "ds.json"
        ds.write_text(
            json.dumps(
                {
                    "decision": "dirty",
                    "dirty_component_ids": ["comp-a"],
                    "all_components_known": ["comp-a", "comp-b"],
                }
            )
        )
        r = self._run(
            "--run-plan",
            "--output",
            str(out_dir),
            "--pre-check-file",
            str(pre),
            "--dirty-set-file",
            str(ds),
            "--compat-label",
            "equal",
        )
        assert r.returncode == 0
        assert "comp-a" in r.stdout
        assert "1 component(s) dirty" in r.stdout

    def test_run_plan_pre_check_via_stdin(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        emit = self._run("--emit-file", "--output", str(out_dir))
        assert emit.returncode == 0
        sc = out_dir / ".skill-config.json"
        cfg = json.loads(sc.read_text())
        cfg["incremental"] = True
        cfg["mode"] = "incremental"
        sc.write_text(json.dumps(cfg))

        pre = json.dumps(
            {
                "status": "unchanged",
                "plugin_version": {},
            }
        )
        r = self._run(
            "--run-plan",
            "--output",
            str(out_dir),
            "--pre-check-file",
            "-",
            input=pre,
        )
        assert r.returncode == 0
        assert "NO-OP" in r.stdout

    def test_run_plan_malformed_payload_ignored(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        r = self._run("--run-plan", "--pre-check-file", str(bad))
        assert r.returncode == 0
        # malformed pre-check is swallowed → default fall-through verdict
        assert "Threat Model — Pre-flight" in r.stdout

    def test_emit_file_writes_org_profile_effective(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out_dir = tmp_path / "o"
        out_dir.mkdir()
        r = self._run("--emit-file", "--output", str(out_dir))
        assert r.returncode == 0
        assert (out_dir / ".skill-config.json").is_file()
        assert (out_dir / ".org-profile-effective.json").is_file()
