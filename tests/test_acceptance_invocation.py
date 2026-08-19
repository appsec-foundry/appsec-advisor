"""Tests for scripts/acceptance_invocation.py and the cohort manifest.

Four pre-R10 runs were rejected because a retyped command line dropped a flag
and resolution quietly produced a different run. These tests pin that the
shipped manifest still defines the cohort the plan requires, that the emitted
invocation carries every flag, and that a run resolving to something else is
rejected rather than accepted as evidence.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import acceptance_invocation as cohort  # noqa: E402


def _manifest() -> dict:
    return cohort.load_manifest()


def test_the_shipped_manifest_loads_and_defines_the_planned_cohort() -> None:
    members = _manifest()["members"]
    assert set(members) == {"r10"}


def test_r10_pins_the_four_settings_earlier_runs_lost() -> None:
    """Depth, rebuild, abuse cases and runtime preservation are exactly what
    the rejected pre-R10 invocations failed to carry."""
    member = cohort.member_of(_manifest(), "r10")
    line = cohort.invocation(member, "r10", Path("/repo"), Path("/out"))
    for flag in ("--assessment-depth quick", "--rebuild", "--abuse-cases", "--keep-runtime-files"):
        assert flag in line
    assert line.startswith("scripts/run-headless.sh --repo /repo --output /out/r10")
    assert member["expect"]["skip_abuse_case_verification"] is False
    assert member["expect"]["runtime_generation"] == "context-v2"


def test_the_manifest_names_no_machine_specific_path() -> None:
    """A cohort is defined by configuration, not by one machine's paths."""
    raw = (REPO_ROOT / "docs" / "internal" / "acceptance-cohort.yaml").read_text(encoding="utf-8")
    for member in _manifest()["members"].values():
        assert not any(str(flag).startswith("/") for flag in member["flags"])
    assert "--repo /" not in raw
    assert "--output /" not in raw


def test_verify_accepts_a_matching_run_and_names_every_deviation(tmp_path: Path) -> None:
    member = cohort.member_of(_manifest(), "r10")
    resolved = dict(member["expect"])
    (tmp_path / cohort.RESOLVED_CONFIG).write_text(json.dumps(resolved), encoding="utf-8")
    assert cohort.verify(member, tmp_path) == []

    resolved["assessment_depth"] = "standard"
    del resolved["keep_runtime_files"]
    (tmp_path / cohort.RESOLVED_CONFIG).write_text(json.dumps(resolved), encoding="utf-8")
    mismatches = cohort.verify(member, tmp_path)
    assert any("assessment_depth" in line and "'standard'" in line for line in mismatches)
    assert any("keep_runtime_files" in line and "<absent>" in line for line in mismatches)


def test_verify_reports_a_missing_resolved_config(tmp_path: Path) -> None:
    member = cohort.member_of(_manifest(), "r10")
    with pytest.raises(cohort.CohortError):
        cohort.verify(member, tmp_path)


def test_the_cohort_hash_covers_only_the_membership_fields() -> None:
    member = cohort.member_of(_manifest(), "r10")
    baseline = cohort.cohort_hash(member["expect"])
    assert cohort.cohort_hash(dict(reversed(list(member["expect"].items())))) == baseline
    changed = {**member["expect"], "assessment_depth": "thorough"}
    assert cohort.cohort_hash(changed) != baseline


def test_an_unknown_member_lists_what_the_manifest_defines() -> None:
    with pytest.raises(cohort.CohortError) as exc:
        cohort.member_of(_manifest(), "r11")
    assert "r10" in str(exc.value)


@pytest.mark.parametrize(
    "broken",
    [
        {"schema_version": 2, "members": {}},
        {"schema_version": 1, "members": {}},
        {"schema_version": 1, "members": {"x": {"expect": {"a": 1}}}},
        {"schema_version": 1, "members": {"x": {"flags": ["--rebuild"]}}},
        {"schema_version": 1, "members": {"x": {"flags": ["--rebuild"], "expect": {"a": 1}, "env": []}}},
    ],
)
def test_a_malformed_manifest_is_refused(tmp_path: Path, broken: dict) -> None:
    path = tmp_path / "cohort.yaml"
    path.write_text(yaml.safe_dump(broken), encoding="utf-8")
    with pytest.raises(cohort.CohortError):
        cohort.load_manifest(path)


def test_print_refuses_a_target_that_already_holds_a_run(tmp_path: Path, capsys) -> None:
    """A reserved postfix path was overwritten twice before: --rebuild clears
    the preserved artifacts and the appended event logs then mix two runs."""
    target = tmp_path / "r10"
    target.mkdir()
    (target / ".hook-events.log").write_text("prior run\n", encoding="utf-8")

    assert cohort.main(["print", "--member", "r10", "--repo", "/repo", "--output-root", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "already holds a run" in err
    assert ".hook-events.log" in err

    assert (
        cohort.main(["print", "--member", "r10", "--repo", "/repo", "--output-root", str(tmp_path), "--allow-existing"])
        == 0
    )
    assert "run-headless.sh" in capsys.readouterr().out


def test_an_empty_or_absent_target_is_accepted(tmp_path: Path) -> None:
    cohort.assert_clean_target(tmp_path / "absent")
    (tmp_path / "empty").mkdir()
    cohort.assert_clean_target(tmp_path / "empty")


def test_cli_print_and_verify(tmp_path: Path, capsys) -> None:
    assert cohort.main(["print", "--member", "r10", "--repo", "/repo", "--output-root", str(tmp_path)]) == 0
    assert "run-headless.sh" in capsys.readouterr().out

    run_dir = tmp_path / "r10"
    run_dir.mkdir()
    expect = cohort.member_of(_manifest(), "r10")["expect"]
    (run_dir / cohort.RESOLVED_CONFIG).write_text(json.dumps(expect), encoding="utf-8")
    assert cohort.main(["verify", "--member", "r10", "--output-dir", str(run_dir)]) == 0
    assert "matches" in capsys.readouterr().out

    (run_dir / cohort.RESOLVED_CONFIG).write_text(json.dumps({**expect, "rebuild": False}), encoding="utf-8")
    assert cohort.main(["verify", "--member", "r10", "--output-dir", str(run_dir)]) == 1
    assert "not a cohort member" in capsys.readouterr().err
