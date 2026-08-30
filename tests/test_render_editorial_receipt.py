"""
Tests for scripts/render_editorial_receipt.py — the Stage-4 record.

Covers:
  * the outcome reaches `.architect-status.json`, which the controller gate and
    the completion summary already read;
  * a reverted pass reports zero applied edits, whatever the applier counted;
  * rejected actions and the deterministic structural warnings are surfaced;
  * missing or unparseable inputs degrade to a status, never to a crash.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import render_editorial_receipt as receipt  # noqa: E402


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "security"
    (out / receipt.CONTEXT_DIR).mkdir(parents=True)
    return out


def _write(output_dir: Path, name: str, payload: dict) -> None:
    (output_dir / receipt.CONTEXT_DIR / name).write_text(json.dumps(payload), encoding="utf-8")


def _clean_pass(output_dir: Path) -> None:
    _write(output_dir, "blocks.json", {"selection": {"blocks_total": 40}})
    _write(output_dir, "plan.json", {"status": "edits", "actions": [{"file": "threat-model.yaml"}] * 6})
    _write(
        output_dir,
        "apply-report.json",
        {"applied_count": 6, "rejected_count": 0, "files_touched": ["threat-model.yaml"]},
    )
    _write(output_dir, "guard-report.json", {"status": "clean", "violation_count": 0, "restored": []})


def test_the_outcome_lands_in_the_status_file(output_dir: Path) -> None:
    _clean_pass(output_dir)

    assert receipt.main([str(output_dir), "--no-print"]) == 0
    status = json.loads((output_dir / receipt.STATUS_NAME).read_text(encoding="utf-8"))

    assert status["status"] == "pass"
    assert status["source"] == "editorial-pass"
    assert (status["blocks_offered"], status["edits_proposed"], status["edits_applied"]) == (40, 6, 6)
    assert status["files_touched"] == ["threat-model.yaml"]
    assert status["reverted"] is False


def test_a_reverted_pass_reports_no_applied_edits(output_dir: Path) -> None:
    _clean_pass(output_dir)
    _write(
        output_dir,
        "guard-report.json",
        {"status": "violations", "violation_count": 2, "restored": ["threat-model.yaml"]},
    )

    assert receipt.main([str(output_dir), "--no-print"]) == 0
    status = json.loads((output_dir / receipt.STATUS_NAME).read_text(encoding="utf-8"))

    assert status["reverted"] is True
    assert status["edits_applied"] == 0
    assert status["files_touched"] == []
    assert status["status"] == "pass"  # a failed polish is not a failed run


def test_rejected_actions_are_surfaced(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    _clean_pass(output_dir)
    _write(
        output_dir,
        "apply-report.json",
        {"applied_count": 4, "rejected_count": 2, "files_touched": ["threat-model.yaml"]},
    )

    assert receipt.main([str(output_dir)]) == 0
    out = capsys.readouterr().out

    assert "Rewrote 4 of 40 blocks" in out
    assert "Rejected: 2 action(s)" in out


def test_structural_warnings_reach_the_console(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    _clean_pass(output_dir)
    (output_dir / receipt.PRE_PASS_NAME).write_text(
        json.dumps(
            {
                "ms_verdict": {
                    "findings": [
                        {"severity": "warning", "title": "Management Summary counts 59, the register lists 76"},
                        {"severity": "info", "title": "not a warning"},
                    ]
                },
                "cvss_risk": {"findings": [{"severity": "warning", "title": "Two severity axes for one finding"}]},
                "skipped_section": {"skipped": True},
            }
        ),
        encoding="utf-8",
    )

    assert receipt.main([str(output_dir)]) == 0
    out = capsys.readouterr().out
    status = json.loads((output_dir / receipt.STATUS_NAME).read_text(encoding="utf-8"))

    assert len(status["advisory_findings"]) == 2
    assert "Management Summary counts 59" in out
    assert "not a warning" not in out


def test_many_warnings_are_capped_with_a_pointer(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    _clean_pass(output_dir)
    (output_dir / receipt.PRE_PASS_NAME).write_text(
        json.dumps({"checks": {"findings": [{"severity": "warning", "title": f"W{i}"} for i in range(9)]}}),
        encoding="utf-8",
    )

    receipt.main([str(output_dir)])
    out = capsys.readouterr().out

    assert "… 4 more in .architect-pre-pass.json" in out


def test_missing_inputs_still_produce_a_status(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    assert receipt.main([str(output_dir)]) == 0
    status = json.loads((output_dir / receipt.STATUS_NAME).read_text(encoding="utf-8"))

    assert status["status"] == "pass"
    assert status["blocks_offered"] == 0
    assert "No rewrite needed" in capsys.readouterr().out


def test_unparseable_inputs_do_not_crash(output_dir: Path) -> None:
    (output_dir / receipt.CONTEXT_DIR / "plan.json").write_text("{not json", encoding="utf-8")
    (output_dir / receipt.PRE_PASS_NAME).write_text("[]", encoding="utf-8")

    assert receipt.main([str(output_dir), "--no-print"]) == 0


def test_a_missing_output_dir_is_a_usage_error(tmp_path: Path) -> None:
    assert receipt.main([str(tmp_path / "nope")]) == 2


def test_the_counts_survive_in_the_run_log(output_dir: Path) -> None:
    """`.architect-status.json` is reaped on a clean run; the log line is not.

    `runtime_cleanup` removes `POST_ARCH_FILES_IF_PASS` whenever the status is
    `pass`, and the editorial pass is always `pass`. Without this line a
    finished run keeps no record of how the pass performed.
    """
    _clean_pass(output_dir)

    assert receipt.main([str(output_dir), "--no-print"]) == 0
    line = (output_dir / receipt.LOG_NAME).read_text(encoding="utf-8")

    assert "EDITORIAL_PASS" in line
    assert "architect-reviewer" in line
    for field in ("offered=40", "proposed=6", "applied=6", "rejected=0", "guard_violations=0", "reverted=false"):
        assert field in line


def test_the_run_log_records_a_reverted_pass_as_reverted(output_dir: Path) -> None:
    _clean_pass(output_dir)
    _write(output_dir, "guard-report.json", {"status": "violations", "violation_count": 2, "restored": ["a.md"]})

    assert receipt.main([str(output_dir), "--no-print"]) == 0
    line = (output_dir / receipt.LOG_NAME).read_text(encoding="utf-8")

    assert "reverted=true" in line
    assert "applied=0" in line
    assert "guard_violations=2" in line


def test_the_log_line_is_appended_not_overwritten(output_dir: Path) -> None:
    """Stage 4 writes into a log the whole run has been appending to."""
    _clean_pass(output_dir)
    (output_dir / receipt.LOG_NAME).write_text("earlier stage line\n", encoding="utf-8")

    assert receipt.main([str(output_dir), "--no-print"]) == 0

    assert (output_dir / receipt.LOG_NAME).read_text(encoding="utf-8").startswith("earlier stage line\n")


def test_an_unwritable_log_does_not_fail_the_stage(output_dir: Path) -> None:
    _clean_pass(output_dir)
    (output_dir / receipt.LOG_NAME).mkdir()

    assert receipt.main([str(output_dir), "--no-print"]) == 0
    assert (output_dir / receipt.STATUS_NAME).is_file()
