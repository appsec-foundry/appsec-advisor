"""Tests for scripts/estimate_duration.py — the wall-clock estimator.

Calibration anchors (RECALIBRATED 2026-06-13): fresh juice-shop runs in
/home/mrohr/scans measured ~76 min wall for `standard --full` and ~81 min
for `thorough --full --architect-review`. The 2026-04 anchor (44 min) is
obsolete — the pipeline grew (abuse-case fan-out, more STRIDE components,
heavier composition) and API-tier idle now adds ~25-30 % of wall. The
parametric constants (`_STAGE1_BASE`, `_TRANSITION_BUFFER`) were bumped to
land standard ≈ 66 min / thorough ≈ 82 min on a 1.0× repo. The standard
anchor was resume-contaminated (~76 incl. a re-dispatch), so the
parametric target is set conservatively below it to avoid over-estimating
clean runs.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "estimate_duration.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("estimate_duration", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["estimate_duration"] = module
    spec.loader.exec_module(module)
    return module


est = _load_module()


def _run_cli(*args: str) -> dict:
    """Invoke the script as a subprocess and parse its JSON output."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"non-zero exit: {result.stderr}"
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Parametric fallback — the path used for first-ever runs on a repo.
# ---------------------------------------------------------------------------


class TestParametric:
    def test_thorough_full_opus_cheap_with_architect(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        for i in range(500):
            (repo / f"f{i}.py").touch()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = _run_cli(
            "--depth",
            "thorough",
            "--mode",
            "full",
            "--reasoning-model",
            "opus-cheap",
            "--architect-review",
            "--output-dir",
            str(out_dir),
            "--repo-root",
            str(repo),
        )
        # 40 × 1.0 × 1.05 + 6 (abuse) + 11 + 9 + 6 + 8 (transition) = 82
        assert result["source"] == "parametric"
        assert 75 <= result["total_min"] <= 90, result
        assert result["stage4_min"] >= 5, "architect-review stage 4 must be present"

    def test_quick_skip_qa(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = _run_cli(
            "--depth",
            "quick",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--skip-qa",
            "--output-dir",
            str(out_dir),
            "--repo-root",
            str(repo),
        )
        assert result["stage3_min"] == 0, "QA disabled → stage 3 must be 0"
        # Tiny repo (no source files) → 0.6 size factor.
        # 32 × 0.6 × 1.0 + 0 (abuse off at quick) + 9 + 0 + 8 = 36.
        assert 33 <= result["total_min"] <= 39, result

    def test_standard_includes_stage1c_abuse(self, tmp_path: Path):
        """Standard depth runs the abuse-case fan-out by default → the
        parametric total carries the Stage-1c additive (~5 min)."""
        repo = tmp_path / "repo"
        repo.mkdir()
        for i in range(500):  # 1.0 size factor
            (repo / f"f{i}.py").touch()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out_dir),
            "--repo-root",
            str(repo),
        )
        # 38 + 5 (abuse) + 8 + 7 + 8 (transition) = 66
        assert result["stage1c_min"] == 5, result
        assert result["total_min"] == 66, result

    def test_skip_abuse_cases_zeroes_stage1c(self, tmp_path: Path):
        """--no-abuse-cases (→ --skip-abuse-cases) drops the Stage-1c additive."""
        repo = tmp_path / "repo"
        repo.mkdir()
        for i in range(500):
            (repo / f"f{i}.py").touch()
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--skip-abuse-cases",
            "--output-dir",
            str(out_dir),
            "--repo-root",
            str(repo),
        )
        assert result["stage1c_min"] == 0, result
        assert result["total_min"] == 61, result  # 38 + 0 + 8 + 7 + 8

    def test_size_factor_brackets(self):
        """The _size_factor_from_files brackets are calibrated against the
        juice-shop reality (~1400 files = 1.0×). Pin those numbers."""
        assert est._size_factor_from_files(50) == 0.6
        assert est._size_factor_from_files(199) == 0.6
        assert est._size_factor_from_files(200) == 1.0
        assert est._size_factor_from_files(1399) == 1.0  # juice-shop
        assert est._size_factor_from_files(2499) == 1.0
        assert est._size_factor_from_files(2500) == 1.5
        assert est._size_factor_from_files(9999) == 1.5
        assert est._size_factor_from_files(10000) == 2.0


# ---------------------------------------------------------------------------
# Last-run cache — highest-priority source.
# ---------------------------------------------------------------------------


class TestLastRunCache:
    def _make_cache(self, out_dir: Path, **kwargs) -> Path:
        cache_dir = out_dir / ".appsec-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / "baseline.json"
        path.write_text(json.dumps(kwargs))
        return path

    def test_cache_hit_returns_measured_value(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(
            out,
            last_run_seconds=2670,  # 44m 30s — the juice-shop reality
            last_run_mode="full",
            last_run_depth="standard",
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        assert result["source"] == "last_run_cache"
        assert result["total_min"] == 44  # ROUND(2670/60) == 44.5 → 44 with banker's rounding

    def test_standby_inflated_measurement_rejected(self, tmp_path: Path):
        """A run suspended mid-flight (machine standby) writes an absurd
        last_run_seconds (observed: 13908 s = 232 min for an ~85 min thorough
        run). The standby/hang guard must reject it and fall back to the
        formula rather than replay ~232 min on the next run."""
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(
            out,
            last_run_seconds=13908,  # 232 min — standby-poisoned
            last_run_mode="full",
            last_run_depth="thorough",
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        for i in range(500):  # 1.0 size factor → parametric ≈ 82 min
            (repo / f"f{i}.py").touch()
        result = _run_cli(
            "--depth",
            "thorough",
            "--mode",
            "full",
            "--reasoning-model",
            "opus-cheap",
            "--architect-review",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        # 232 min > 2.5 × 82 ≈ 205 → measurement rejected, parametric wins.
        assert result["source"] == "parametric", result
        assert result["total_min"] < 120, result

    def test_plausible_measurement_still_used(self, tmp_path: Path):
        """A measurement within the sanity ceiling is replayed as before —
        the guard must not reject honest (even somewhat slow) runs."""
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(
            out,
            last_run_seconds=5400,  # 90 min — slow but plausible for thorough
            last_run_mode="full",
            last_run_depth="thorough",
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        for i in range(500):
            (repo / f"f{i}.py").touch()
        result = _run_cli(
            "--depth",
            "thorough",
            "--mode",
            "full",
            "--reasoning-model",
            "opus-cheap",
            "--architect-review",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        # 90 min < 2.5 × 82 → kept.
        assert result["source"] == "last_run_cache", result
        assert result["total_min"] == 90, result

    def test_cache_miss_when_mode_differs(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(
            out,
            last_run_seconds=2670,
            last_run_mode="incremental",  # different mode
            last_run_depth="standard",
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        assert result["source"] == "parametric"

    def test_cache_miss_when_depth_differs(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(
            out,
            last_run_seconds=2670,
            last_run_mode="full",
            last_run_depth="quick",  # different depth
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        result = _run_cli(
            "--depth",
            "thorough",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        assert result["source"] == "parametric"


# ---------------------------------------------------------------------------
# Resume — reads .appsec-checkpoint, sums remaining-phase time.
# ---------------------------------------------------------------------------


class TestResume:
    def test_resume_after_phase_8_drops_long_phases(self, tmp_path: Path):
        """Resume from phase=9 should skip the ~10 min of Phases 1–8 budget."""
        out = tmp_path / "out"
        out.mkdir()
        (out / ".appsec-checkpoint").write_text("phase=9 status=in_progress\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "resume",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        assert result["source"] == "resume_checkpoint"
        # Standard table: phases 9+10+11 = 15 + 0.5 + 1 = 16.5 → +stage2(8)+stage3(7)+buffer(8) ≈ 40
        assert result["total_min"] < 42, result
        assert result["stage1_min"] >= 15

    def test_resume_after_phase_2_keeps_most_phases(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        (out / ".appsec-checkpoint").write_text("phase=2 status=in_progress\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "resume",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        assert result["source"] == "resume_checkpoint"
        # Almost a full run remaining.
        assert result["total_min"] >= 35, result


# ---------------------------------------------------------------------------
# Incremental — dirty-set ratio path.
# ---------------------------------------------------------------------------


class TestIncremental:
    def test_one_dirty_component_is_much_shorter(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "incremental",
            "--reasoning-model",
            "sonnet",
            "--sec-change-count",
            "1",
            "--max-stride-components",
            "5",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        assert result["source"] == "incremental_dirty_set"
        # 1/5 dirty → Phase 9 ≈ 3 min; total ≈ 38 min (vs 66 for full).
        assert result["total_min"] < 42, result
        assert result["total_min"] >= 18, result

    def test_all_dirty_approaches_full_run(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "incremental",
            "--reasoning-model",
            "sonnet",
            "--sec-change-count",
            "5",
            "--max-stride-components",
            "5",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        # All 5/5 dirty → close to the parametric standard estimate.
        assert result["total_min"] >= 35, result


# ---------------------------------------------------------------------------
# Edge cases — malformed input, missing args.
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_missing_repo_root_falls_through_to_parametric(self, tmp_path: Path):
        """Non-existent repo_root → file count is 0 → size_factor 0.6 ×."""
        out = tmp_path / "out"
        out.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(tmp_path / "does-not-exist"),
        )
        assert result["source"] == "parametric"
        # 38 × 0.6 + 5 (Stage-1c abuse) + 8 + 7 + 8 = 51
        assert 45 <= result["total_min"] <= 56, result

    def test_malformed_checkpoint_falls_through(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        (out / ".appsec-checkpoint").write_text("this is not valid format\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "resume",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        # Resume strategy fails, falls through to last-run-cache (also miss),
        # finally parametric.
        assert result["source"] == "parametric"

    def test_opus_increases_total(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        result_sonnet = _run_cli(
            "--depth",
            "thorough",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        result_opus = _run_cli(
            "--depth",
            "thorough",
            "--mode",
            "full",
            "--reasoning-model",
            "opus",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        # Opus must be measurably slower than sonnet on the same repo.
        assert result_opus["total_min"] > result_sonnet["total_min"]
        # 40 × 0.6 (tiny repo) × 1.4 = 33.6 vs 24 → ~10 min spread.
        assert result_opus["total_min"] - result_sonnet["total_min"] >= 8


# ---------------------------------------------------------------------------
# Output schema — caller relies on these keys being present.
# ---------------------------------------------------------------------------


class TestComponentDurations:
    """M5 per-component-duration secondary source (lines 360-380, 583)."""

    def _make_cache(self, out_dir: Path, **kwargs) -> Path:
        cache_dir = out_dir / ".appsec-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_dir / "baseline.json"
        path.write_text(json.dumps(kwargs))
        return path

    def test_component_durations_used_when_no_total_cache(self, tmp_path: Path):
        """No last_run_seconds but component_durations present → that source."""
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(
            out,
            component_durations={"api": 160, "web": 120, "worker": 90},
        )
        result = est._component_durations_estimate(out, "standard", 5)
        assert result is not None
        breakdown, source = result
        assert source == "component_durations"
        # phase9 = max(160) + 30 = 190s; phase_other = 720s standard.
        assert breakdown["stage1"] == (190 + 720) / 60.0
        assert breakdown["stage1c"] == 5.0
        assert breakdown["stage2"] == 8.0
        assert breakdown["total"] > breakdown["stage1"]

    def test_component_durations_via_main(self, tmp_path: Path, capsys, monkeypatch):
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(out, component_durations={"api": 100})
        repo = tmp_path / "repo"
        repo.mkdir()
        rc = est.main(
            [
                "estimate_duration.py",
                "--depth",
                "standard",
                "--mode",
                "full",
                "--output-dir",
                str(out),
                "--repo-root",
                str(repo),
            ]
        )
        assert rc == 0
        result = json.loads(capsys.readouterr().out)
        assert result["source"] == "component_durations"

    def test_no_cache_returns_none(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        assert est._component_durations_estimate(out, "standard", 5) is None

    def test_empty_durations_returns_none(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(out, component_durations={})
        assert est._component_durations_estimate(out, "standard", 5) is None

    def test_non_dict_durations_returns_none(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        self._make_cache(out, component_durations=[1, 2, 3])
        assert est._component_durations_estimate(out, "standard", 5) is None


class TestLowLevelHelpers:
    def test_last_run_seconds_not_numeric_returns_none(self, tmp_path: Path):
        """Line 310: last_run_seconds is a string → reject."""
        out = tmp_path / "out"
        cache_dir = out / ".appsec-cache"
        cache_dir.mkdir(parents=True)
        (cache_dir / "baseline.json").write_text(
            json.dumps({"last_run_seconds": "oops", "last_run_mode": "full", "last_run_depth": "standard"})
        )
        assert est._last_run_cache(out, "full", "standard", 50.0) is None

    def test_last_run_seconds_zero_returns_none(self, tmp_path: Path):
        out = tmp_path / "out"
        cache_dir = out / ".appsec-cache"
        cache_dir.mkdir(parents=True)
        (cache_dir / "baseline.json").write_text(json.dumps({"last_run_seconds": 0}))
        assert est._last_run_cache(out, "full", "standard", 50.0) is None

    def test_resume_json_checkpoint_dict(self, tmp_path: Path):
        """Line 402: .appsec-checkpoint parses as JSON dict with phase."""
        out = tmp_path / "out"
        out.mkdir()
        (out / ".appsec-checkpoint").write_text(json.dumps({"phase": 9, "status": "in_progress"}))
        result = est._resume_remaining(out, "standard")
        assert result is not None
        breakdown, source = result
        assert source == "resume_checkpoint"
        assert breakdown["stage1"] >= 15

    def test_resume_json_checkpoint_bad_phase_type(self, tmp_path: Path):
        """Lines 412-418: JSON dict whose phase is non-int → TypeError path → None."""
        out = tmp_path / "out"
        out.mkdir()
        (out / ".appsec-checkpoint").write_text(json.dumps({"phase": "abc"}))
        assert est._resume_remaining(out, "standard") is None

    def test_resume_phase_out_of_range(self, tmp_path: Path):
        """Line 419-420: phase > 11 → None."""
        out = tmp_path / "out"
        out.mkdir()
        (out / ".appsec-checkpoint").write_text("phase=99 status=x\n")
        assert est._resume_remaining(out, "standard") is None

    def test_resume_text_checkpoint_no_phase_token(self, tmp_path: Path):
        """Text checkpoint lacking a phase= token → None (phase_n stays None)."""
        out = tmp_path / "out"
        out.mkdir()
        (out / ".appsec-checkpoint").write_text("status=in_progress only\n")
        assert est._resume_remaining(out, "standard") is None

    def test_resume_no_checkpoint_file(self, tmp_path: Path):
        out = tmp_path / "out"
        out.mkdir()
        assert est._resume_remaining(out, "standard") is None

    def test_incremental_zero_change_count_returns_none(self):
        """Line 443-444: sec_change_count <= 0 → None."""
        assert est._incremental_dirty_set("standard", 0, 5) is None
        assert est._incremental_dirty_set("standard", 3, 0) is None

    def test_count_repo_files_find_fallback_on_non_git(self, tmp_path: Path, monkeypatch):
        """Lines 238-240 / 274-277: git fails → find fallback path runs."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").touch()
        (repo / "b.py").touch()

        real_run = subprocess.run

        def fake_run(cmd, *a, **k):
            if cmd and cmd[0] == "git":
                raise FileNotFoundError("no git")
            return real_run(cmd, *a, **k)

        monkeypatch.setattr(est.subprocess, "run", fake_run)
        n = est._count_repo_files(repo)
        assert n >= 2

    def test_count_repo_files_all_fail_returns_zero(self, tmp_path: Path, monkeypatch):
        """Both git and find raise → returns 0."""

        def boom(*a, **k):
            raise OSError("blocked")

        monkeypatch.setattr(est.subprocess, "run", boom)
        assert est._count_repo_files(tmp_path) == 0


class TestOutputSchema:
    def test_all_required_keys_present(self, tmp_path: Path):
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        result = _run_cli(
            "--depth",
            "standard",
            "--mode",
            "full",
            "--reasoning-model",
            "sonnet",
            "--output-dir",
            str(out),
            "--repo-root",
            str(repo),
        )
        for key in (
            "source",
            "stage1_min",
            "stage1c_min",
            "stage2_min",
            "stage3_min",
            "stage4_min",
            "transition_min",
            "total_min",
            "total_pretty",
        ):
            assert key in result, f"missing key: {key}"
        assert result["total_pretty"].endswith("min")
