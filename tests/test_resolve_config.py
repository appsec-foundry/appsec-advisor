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

REPO_ROOT   = Path(__file__).parent.parent
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

    def test_rebuild_vs_incremental(self):
        msg = rc.detect_conflicts(self._parse("--rebuild", "--incremental"))
        assert msg and "--rebuild" in msg

    def test_rebuild_vs_resume(self):
        msg = rc.detect_conflicts(self._parse("--rebuild", "--resume"))
        assert msg and "checkpoint" in msg.lower()

    def test_architect_review_conflict(self):
        msg = rc.detect_conflicts(
            self._parse("--architect-review", "--no-architect-review")
        )
        assert msg

    def test_no_conflict_clean_args(self):
        msg = rc.detect_conflicts(self._parse("--full", "--verbose"))
        assert msg is None


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
        assert out["max_stride_components"] == 5

    def test_quick(self):
        ns = rc.build_parser().parse_args(["--assessment-depth", "quick"])
        out = rc.resolve_assessment_depth(ns)
        assert out["assessment_depth"] == "quick"
        assert out["max_stride_components"] == 3
        assert out["diagram_depth"] == "minimal"

    def test_thorough(self):
        ns = rc.build_parser().parse_args(["--assessment-depth", "thorough"])
        out = rc.resolve_assessment_depth(ns)
        assert out["max_stride_components"] == 8
        assert out["qa_depth"] == "extended"


class TestResolveReasoningModel:
    def test_default_standard_gives_opus_cheap(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["reasoning_model"] == "opus-cheap"
        assert out["stride_model"] == "claude-sonnet-4-6"
        assert out["triage_model"] == "claude-opus-4-7"
        assert out["merger_model"] == "claude-opus-4-7"

    def test_default_quick_gives_haiku_economy(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_reasoning_model(ns, "quick")
        assert out["reasoning_model"] == "haiku-economy"
        # haiku-economy keeps the Reasoning core on Sonnet
        assert out["stride_model"] == "claude-sonnet-4-6"
        assert out["triage_model"] == "claude-sonnet-4-6"
        assert out["merger_model"] == "claude-sonnet-4-6"

    def test_explicit_opus(self):
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "claude-opus-4-7"

    def test_stride_model_override_keeps_triage_opus(self):
        ns = rc.build_parser().parse_args(["--stride-model", "claude-custom-1"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "claude-custom-1"
        assert out["triage_model"] == "claude-opus-4-7"  # unchanged

    def test_env_var_highest_precedence(self, monkeypatch):
        monkeypatch.setenv("APPSEC_STRIDE_MODEL", "claude-env-override")
        ns = rc.build_parser().parse_args(["--reasoning-model", "opus"])
        out = rc.resolve_reasoning_model(ns, "standard")
        assert out["stride_model"] == "claude-env-override"


class TestResolveArchitectReview:
    def test_off_at_standard_by_default(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_architect_review(ns, "standard", dry_run=False)
        assert out["architect_review"] is False

    def test_auto_on_at_thorough(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_architect_review(ns, "thorough", dry_run=False)
        assert out["architect_review"] is True
        assert out["architect_model"] == "claude-opus-4-7"
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
        ns = rc.build_parser().parse_args(
            ["--architect-review", "--architect-model", "sonnet"]
        )
        out = rc.resolve_architect_review(ns, "standard", dry_run=False)
        assert out["architect_model"] == "claude-sonnet-4-6"


class TestResolveEnrichArchFragments:
    """M3.3 / D2 — LLM enrichment of architecture-diagrams.md and
    security-architecture.md fragments. Auto-on at thorough, off
    elsewhere; CLI flags override."""

    def test_off_at_standard_by_default(self):
        ns = rc.build_parser().parse_args([])
        out = rc.resolve_enrich_arch_fragments(ns, "standard", dry_run=False)
        assert out["enrich_arch_fragments"] is False
        assert "depth=standard" in out["enrich_arch_label"]

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
        (tmp_path / "threat-model.yaml").write_text(
            "meta: {schema_version: 1}\nthreats: []\n"
        )
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


# ---------------------------------------------------------------------------
# End-to-end CLI smoke
# ---------------------------------------------------------------------------


class TestCLI:
    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *argv],
            capture_output=True, text=True,
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

    def test_config_summary_prints_human_readable(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = self._run("--config-summary")
        assert r.returncode == 0
        assert "Configuration resolved." in r.stdout
        assert "Repository" in r.stdout
        assert "Mode" in r.stdout

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
        assert cfg["stride_model"] == "claude-sonnet-4-6"
        assert cfg["triage_model"] == "claude-opus-4-7"
        assert cfg["merger_model"] == "claude-opus-4-7"
        assert cfg["architect_review"] is False
        assert cfg["check_requirements"] is False

    def test_thorough_auto_enables_architect_review(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--assessment-depth", "thorough"], REPO_ROOT)
        assert cfg["architect_review"] is True
        assert cfg["architect_model"] == "claude-opus-4-7"

    def test_deprecated_with_requirements_alias(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = rc.resolve(["--with-requirements"], REPO_ROOT)
        assert cfg["check_requirements"] is True
