"""Guards for the pre-run cost projection.

The projection decides whether a run starts at all, so its two refusal paths
and, more importantly, the cases where it must NOT refuse are pinned here. A
wrong refusal costs the user a run they could have had.
"""

from __future__ import annotations

import json
from pathlib import Path

import project_run_cost as prc


def _cache(output_dir: Path, **fields: object) -> None:
    cache = output_dir / ".appsec-cache"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "baseline.json").write_text(json.dumps(fields), encoding="utf-8")


def test_no_budget_projects_without_a_verdict(tmp_path):
    result = prc.project(tmp_path, "full", "standard", None)
    assert result["fits"] is True
    assert result["reason"] is None


def test_a_first_run_against_an_unknown_repository_is_admitted(tmp_path):
    """The component count drives the cost and is unknown before recon, so a
    plausible budget must not be refused on a formula."""
    result = prc.project(tmp_path, "full", "standard", 30.0)
    assert result["fits"] is True
    assert result["basis"] == "none"


def test_a_budget_below_the_depth_floor_is_refused(tmp_path):
    result = prc.project(tmp_path, "full", "standard", 3.0)
    assert result["fits"] is False
    assert "before any component is analyzed" in result["reason"]


def test_the_floor_refuses_only_what_is_clearly_below_it(tmp_path):
    """One measured anchor carries the floor, so a budget near it is admitted
    and left to the boundary checkpoints."""
    floor = prc.parametric_floor("standard")
    assert prc.project(tmp_path, "full", "standard", floor * 0.9)["fits"] is True
    assert prc.project(tmp_path, "full", "standard", floor * 0.5)["fits"] is False


def test_a_rerender_is_not_held_against_the_analysis_floor(tmp_path):
    """A rerender rebuilds the report from existing artifacts. Holding it
    against the cost of analyzing source would refuse a run that easily fits."""
    assert prc.project(tmp_path, "rerender", "standard", 5.0)["fits"] is True


def test_a_measured_previous_run_above_the_budget_refuses(tmp_path):
    _cache(tmp_path, last_run_cost_usd=29.59, last_run_mode="full", last_run_depth="standard")
    result = prc.project(tmp_path, "full", "standard", 20.0)
    assert result["fits"] is False
    assert result["basis"] == "last_run_cache"
    assert "$29.59" in result["reason"]


def test_a_measured_previous_run_below_the_budget_admits(tmp_path):
    _cache(tmp_path, last_run_cost_usd=29.59, last_run_mode="full", last_run_depth="standard")
    assert prc.project(tmp_path, "full", "standard", 35.0)["fits"] is True


def test_a_measurement_from_another_shape_is_not_reused(tmp_path):
    """A quick run's cost says nothing about a thorough one, and a rerender's
    says nothing about a full analysis."""
    _cache(tmp_path, last_run_cost_usd=29.59, last_run_mode="full", last_run_depth="quick")
    assert prc.last_run_cost(tmp_path, "full", "thorough") is None
    assert prc.last_run_cost(tmp_path, "rerender", "quick") is None


def test_a_corrupt_or_absent_cache_does_not_refuse(tmp_path):
    (tmp_path / ".appsec-cache").mkdir()
    (tmp_path / ".appsec-cache" / "baseline.json").write_text("{not json", encoding="utf-8")
    assert prc.last_run_cost(tmp_path, "full", "standard") is None
    assert prc.project(tmp_path, "full", "standard", 30.0)["fits"] is True


def test_depth_scales_the_floor_and_the_per_component_term():
    assert prc.parametric_floor("quick") < prc.parametric_floor("standard") < prc.parametric_floor("thorough")
    standard = prc.parametric_total("standard", 7)
    assert prc.parametric_total("standard", 8) > standard
    assert prc.parametric_total("quick", 7) < standard


def test_the_parametric_model_reproduces_its_own_anchor():
    """The constants are anchored on the 2026-08-31 juice-shop run: seven
    components at standard depth, $29.59. A change that moves this materially
    is a change to the model, not a refactor."""
    assert abs(prc.parametric_total("standard", 7) - 29.59) < 1.0
