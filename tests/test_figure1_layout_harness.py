"""Soft layout-quality guard for Figure 1 (Top-Threats architecture diagram).

Renders the Figure-1 generator for a matrix of synthetic models via ``mmdc``
and measures the actual drawn geometry (see ``scripts/figure1_harness.py``).
The intent is *minimise crossings where possible, accept the unavoidable* — so
the crossing assertions are SOFT budgets with headroom, NOT a forced zero. Two
properties ARE hard, because they are always achievable and a violation is a
real defect:

  * tier vertical order  (Actors → Client → Application → Data, top to bottom)
  * no edge runs through an unrelated component box (box_overlaps == 0)

Skips cleanly when mmdc + a launchable Chrome are not present (most CI), since
the metric needs a real SVG render.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import figure1_harness as H  # noqa: E402

pytestmark = pytest.mark.skipif(not H.mmdc_available(), reason="mmdc + Chrome not available — layout render skipped")

# Per-model crossing budget. Current measured values are 0 everywhere except the
# 3-actor model with a shared attack target (2 — an unavoidable interleaving).
# Headroom is deliberate: the guard catches a regression that *meaningfully*
# worsens legibility, it does not force a crossing-free layout.
MAX_CROSSINGS_PER_MODEL = 3
MAX_CROSSINGS_TOTAL = 5
# Width control. The thing the generator actually controls is the per-tier box
# count (the R2 cap); aspect_w_h is a softer backstop confounded by diagram
# height (a short diagram inflates the ratio), so it gets generous headroom.
MAX_ASPECT = 2.1


@pytest.fixture(scope="module")
def report() -> dict:
    return H.run()


def test_tiers_are_ordered_top_down(report: dict) -> None:
    for name, m in report.items():
        if "error" in m:
            pytest.fail(f"{name}: {m['error']}")
        assert m["tier_order_ok"], f"{name}: tiers not ordered Actors→Client→App→Data (centre-y)"


def test_no_edge_runs_through_an_unrelated_box(report: dict) -> None:
    for name, m in report.items():
        if "error" in m:
            continue
        assert m["box_overlaps"] == 0, f"{name}: {m['box_overlaps']} edge(s) cross an unrelated component box"


def test_crossings_stay_within_a_soft_budget(report: dict) -> None:
    total = 0
    for name, m in report.items():
        if "error" in m:
            continue
        total += m["crossings"]
        assert m["crossings"] <= MAX_CROSSINGS_PER_MODEL, (
            f"{name}: {m['crossings']} edge crossings (budget {MAX_CROSSINGS_PER_MODEL}). "
            "Crossings are tolerated when unavoidable, but this exceeds the headroom — "
            "investigate before raising the budget."
        )
    assert total <= MAX_CROSSINGS_TOTAL, f"total crossings {total} across fixtures exceeds {MAX_CROSSINGS_TOTAL}"


def test_figure_does_not_scale_into_a_wide_strip(report: dict) -> None:
    for name, m in report.items():
        if "error" in m:
            continue
        assert m["aspect_w_h"] <= MAX_ASPECT, (
            f"{name}: aspect {m['aspect_w_h']} > {MAX_ASPECT} — tier row too wide; "
            f"app_boxes={m.get('app_boxes')}, the per-tier width cap may need attention"
        )
