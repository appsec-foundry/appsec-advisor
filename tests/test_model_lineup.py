"""Tests for scripts/model_lineup.py and its use in the headless banner.

run-headless.sh printed `Model: <session>`, which reads as "the whole assessment
runs on this". It does not: the session model drives orchestration while STRIDE,
triage, merge, render, abuse and the cheap recon/config phases resolve
separately. The misreading is costly in one direction — the session model is the
dominant cost lever and the smallest contributor to analysis depth.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import model_lineup  # noqa: E402

HEADLESS = ROOT / "scripts" / "run-headless.sh"


def test_lineup_covers_every_pipeline_role() -> None:
    """Every role the run dispatches must appear, or the line under-reports."""
    line = model_lineup.lineup("claude-sonnet-4-6")
    for role in ("session/orchestrator", "STRIDE", "triage", "merge", "render", "recon"):
        assert role in line, f"role {role!r} missing from the model lineup"


def test_lineup_groups_roles_by_model() -> None:
    """Cost is per model, so the grouping must be per model, not per role."""
    line = model_lineup.lineup("claude-sonnet-4-6")
    assert line.count("claude-sonnet-4-6") == 1, "a model must appear once with its roles"
    assert " · " in line


def test_session_model_change_does_not_move_analysis_roles() -> None:
    """The lineup must show what a session-model switch actually buys.

    Switching the session to Opus moves orchestration only — STRIDE stays on
    4.6 and triage/merge stay on Sonnet 5. That is the fact the line exists to
    make visible.
    """
    opus = model_lineup.lineup("claude-opus-4-8")
    assert "claude-opus-4-8 (session/orchestrator" in opus
    assert "claude-sonnet-4-6 (STRIDE" in opus, (
        "STRIDE must still be shown on its own model when the session is Opus"
    )


def test_reasoning_tier_is_reflected() -> None:
    """A different reasoning tier must visibly change the analysis models."""
    economy = model_lineup.lineup("claude-sonnet-4-6", "sonnet-economy", "standard")
    opus_tier = model_lineup.lineup("claude-sonnet-4-6", "opus", "thorough")
    assert economy != opus_tier
    assert "opus (STRIDE" in opus_tier


def test_alias_is_resolved_to_the_session_model() -> None:
    """The `sonnet` alias means 'inherit the session model'.

    Printing it verbatim beside a concrete id would imply a second, different
    model is in play.
    """
    line = model_lineup.lineup("claude-sonnet-4-6")
    assert " sonnet (" not in line, "unresolved alias leaked into the lineup"


def test_lineup_never_raises_on_bad_input() -> None:
    """The banner must not be able to abort a run."""
    assert model_lineup.lineup("claude-sonnet-4-6", "nonsense", "nonsense")
    assert model_lineup.lineup("x", "", "") == "x" or model_lineup.lineup("x", "", "")


def test_cli_prints_a_single_line() -> None:
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "model_lineup.py"), "--session", "claude-sonnet-4-6"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0
    assert len(out.stdout.strip().splitlines()) == 1


# ── headless banner wiring ──────────────────────────────────────────────


def test_headless_banner_shows_the_lineup_not_just_the_session_model() -> None:
    body = HEADLESS.read_text(encoding="utf-8")
    assert "model_lineup.py" in body, "headless banner does not resolve the model lineup"
    assert 'echo "  Model      : $MODEL"' not in body, (
        "the bare session-model banner line is back; it reads as 'everything runs "
        "on this model', which is wrong"
    )


def test_headless_banner_places_models_after_depth() -> None:
    body = HEADLESS.read_text(encoding="utf-8")
    depth_at = body.index('echo "  Depth      : ')
    models_at = body.index('echo "  Models     : ')
    assert depth_at < models_at, "the Models line belongs below Depth"


def test_headless_records_reasoning_tier_for_the_banner() -> None:
    """--reasoning-model must reach the banner, not only the skill prompt."""
    body = HEADLESS.read_text(encoding="utf-8")
    assert 'REASONING_TIER="$2"' in body, (
        "--reasoning-model is forwarded to the skill but never captured for the "
        "banner, so the banner would show the default tier's models"
    )
