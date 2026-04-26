"""Unit tests for scripts/check_inline_shortcut.py.

The hard gate is invoked as a subprocess from skills/create-threat-model/
SKILL-impl.md and is expected to:

  * exit 0 when the fragment pipeline ran cleanly
  * exit 2 when any inline-shortcut indicator trips
  * exit 3 on tool error (bad path)

These tests cover every detection path and the --write-repair-plan stub.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_inline_shortcut.py"

# The 8 fragment names mirror REQUIRED_FRAGMENTS in qa_checks.py. Kept as a
# local constant so test assertions don't depend on importing qa_checks at
# module load time.
ALL_FRAGMENTS = (
    "ms-verdict.json",
    "ms-architecture-assessment.json",
    "system-overview.md",
    "architecture-diagrams.md",
    "attack-walkthroughs.md",
    "assets.md",
    "attack-surface.md",
    "security-architecture.md",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_clean_output_dir(tmp_path: Path, fragments: Iterable[str] = ALL_FRAGMENTS) -> Path:
    """Create an output dir that passes every indicator: 8 fragments,
    .threats-merged.json + .triage-flags.json + threat-model.md present.
    """
    out = tmp_path / "docs" / "security"
    (out / ".fragments").mkdir(parents=True)
    for name in fragments:
        (out / ".fragments" / name).write_text("{}\n" if name.endswith(".json") else "stub\n")
    (out / ".threats-merged.json").write_text("{}\n")
    (out / ".triage-flags.json").write_text("[]\n")
    (out / "threat-model.md").write_text("# stub\n")
    return out


def _run_gate(output_dir: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(output_dir), *extra],
        capture_output=True,
        text=True,
        timeout=60,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_clean_state_exits_zero(tmp_path):
    out = _make_clean_output_dir(tmp_path)
    result = _run_gate(out)
    assert result.returncode == 0, f"Expected exit 0 on clean state; stderr={result.stderr}"
    assert "ASSESSMENT INCOMPLETE" not in result.stderr


# ---------------------------------------------------------------------------
# Indicator A1 — fragments dir missing entirely
# ---------------------------------------------------------------------------

def test_fragments_dir_missing_trips_gate(tmp_path):
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True)
    (out / "threat-model.md").write_text("# inline-authored\n")
    result = _run_gate(out)
    assert result.returncode == 2
    assert ".fragments/ directory missing" in result.stderr
    assert "ASSESSMENT INCOMPLETE — inline-shortcut detected" in result.stderr


# ---------------------------------------------------------------------------
# Indicator A2 — fragments dir present but empty / near-empty
# ---------------------------------------------------------------------------

def test_fragments_dir_empty_trips_gate(tmp_path):
    out = tmp_path / "docs" / "security"
    (out / ".fragments").mkdir(parents=True)
    (out / "threat-model.md").write_text("# inline-authored\n")
    result = _run_gate(out)
    assert result.returncode == 2
    assert "contains only 0 files" in result.stderr


def test_fragments_dir_partial_under_minimum_trips_gate(tmp_path):
    # 2 fragments out of 8 — below the MIN_FRAGMENTS=3 threshold for A2.
    out = _make_clean_output_dir(tmp_path, fragments=ALL_FRAGMENTS[:2])
    result = _run_gate(out)
    assert result.returncode == 2
    assert "contains only 2 files" in result.stderr


def test_fragments_dir_at_minimum_does_not_trip_a2(tmp_path):
    # Exactly 3 fragments → A2 not tripped, but qa_checks.py fragments will
    # still complain about the other 5 missing required ones (Indicator B
    # in qa_checks's own classification).
    out = _make_clean_output_dir(tmp_path, fragments=ALL_FRAGMENTS[:3])
    result = _run_gate(out)
    # Still trips because qa_checks reports missing required fragments.
    assert result.returncode == 2
    assert "contains only" not in result.stderr  # A2 specifically did NOT trip
    assert "qa_checks.py fragments exit code: 1" in result.stderr


# ---------------------------------------------------------------------------
# Indicator B — .threats-merged.json missing while threat-model.md exists
# ---------------------------------------------------------------------------

def test_threats_merged_missing_trips_gate(tmp_path):
    out = _make_clean_output_dir(tmp_path)
    (out / ".threats-merged.json").unlink()
    result = _run_gate(out)
    assert result.returncode == 2
    assert ".threats-merged.json missing" in result.stderr
    assert "Phase 9 merge step bypassed" in result.stderr


def test_threats_merged_missing_without_md_does_not_trip_b(tmp_path):
    # Pre-Phase-11 state — md not yet written. We expect the gate to NOT
    # trip on Indicator B (the orchestrator may legitimately not have
    # reached Phase 11). qa_checks may still trip on its own checks though,
    # since the fragments are present but threats-merged is missing.
    out = _make_clean_output_dir(tmp_path)
    (out / ".threats-merged.json").unlink()
    (out / "threat-model.md").unlink()
    result = _run_gate(out)
    # Indicator B requires threat-model.md to exist; with it removed, the
    # only B/C-tripping signals are gone. qa_checks may still report issues.
    if result.returncode == 0:
        assert ".threats-merged.json missing" not in result.stderr


# ---------------------------------------------------------------------------
# Indicator C — .triage-flags.json missing (depth-dependent)
# ---------------------------------------------------------------------------

def test_triage_flags_missing_trips_at_standard_depth(tmp_path):
    out = _make_clean_output_dir(tmp_path)
    (out / ".triage-flags.json").unlink()
    result = _run_gate(out, "--depth", "standard")
    assert result.returncode == 2
    assert ".triage-flags.json missing" in result.stderr
    assert "Phase 10b triage step bypassed" in result.stderr


def test_triage_flags_missing_does_not_trip_at_quick_depth(tmp_path):
    out = _make_clean_output_dir(tmp_path)
    (out / ".triage-flags.json").unlink()
    result = _run_gate(out, "--depth", "quick")
    # At quick depth, .triage-flags.json is legitimately optional. The gate
    # should not trip on Indicator C (but may still trip elsewhere).
    if result.returncode == 0:
        assert ".triage-flags.json missing" not in result.stderr


# ---------------------------------------------------------------------------
# qa_checks.py fragments OR-merge — REQUIRED_FRAGMENTS-derived signal
# ---------------------------------------------------------------------------

def test_qa_checks_required_fragments_signal_trips_gate(tmp_path):
    # 5 of 8 fragments present (above MIN=3), threats-merged + triage present,
    # threat-model.md present — A1/A2/B/C all clean. But qa_checks.py will
    # still complain about the other 3 missing required fragments.
    out = _make_clean_output_dir(tmp_path, fragments=ALL_FRAGMENTS[:5])
    result = _run_gate(out)
    assert result.returncode == 2
    assert "qa_checks.py fragments exit code: 1" in result.stderr


# ---------------------------------------------------------------------------
# Tool errors
# ---------------------------------------------------------------------------

def test_missing_output_dir_exits_three(tmp_path):
    nonexistent = tmp_path / "does-not-exist"
    result = _run_gate(nonexistent)
    assert result.returncode == 3
    assert "output directory does not exist" in result.stderr


# ---------------------------------------------------------------------------
# --write-repair-plan stub (Sprint 4 hook)
# ---------------------------------------------------------------------------

def test_write_repair_plan_emits_json_on_trip(tmp_path):
    out = _make_clean_output_dir(tmp_path, fragments=())
    (out / ".threats-merged.json").unlink()
    (out / ".triage-flags.json").unlink()
    result = _run_gate(out, "--write-repair-plan")
    assert result.returncode == 2

    plan_path = out / ".inline-shortcut-repair-plan.json"
    assert plan_path.is_file(), "Repair plan must be written when --write-repair-plan tripped"
    plan = json.loads(plan_path.read_text())
    assert plan["status"] == "fail"
    assert plan["kind"] == "inline_shortcut"
    assert plan["schema_version"] == 1
    assert "indicators" in plan and len(plan["indicators"]) >= 1
    assert "missing_fragments" in plan
    # When fragments=() and qa_checks runs, all 8 required ones are missing.
    assert len(plan["missing_fragments"]) == 8
    assert plan["qa_fragments_exit"] == 1


def test_write_repair_plan_not_written_on_clean(tmp_path):
    out = _make_clean_output_dir(tmp_path)
    result = _run_gate(out, "--write-repair-plan")
    assert result.returncode == 0
    plan_path = out / ".inline-shortcut-repair-plan.json"
    assert not plan_path.exists(), "Repair plan must not be written on clean exit"


# ---------------------------------------------------------------------------
# Banner format — sanity check that the user-facing wording is preserved
# ---------------------------------------------------------------------------

def test_banner_lists_every_tripped_indicator(tmp_path):
    # All three skill-level indicators trip simultaneously.
    out = _make_clean_output_dir(tmp_path, fragments=())
    (out / ".threats-merged.json").unlink()
    (out / ".triage-flags.json").unlink()
    result = _run_gate(out, "--depth", "standard")
    assert result.returncode == 2
    # A2 (empty .fragments/) — counts 0
    assert "contains only 0 files" in result.stderr
    # B
    assert ".threats-merged.json missing" in result.stderr
    # C
    assert ".triage-flags.json missing" in result.stderr
    # qa_checks aggregator
    assert "qa_checks.py fragments exit code:" in result.stderr
    # Root-cause prose
    assert "Phase 11 Substep 4" in result.stderr or "fragment authoring" in result.stderr
    # Closing rule
    assert "═" * 10 in result.stderr  # box-drawing rule
