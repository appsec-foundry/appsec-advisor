"""
Tests for scripts/render_qa_receipt.py — the Stage-3 record.

Covers:
  * the deterministic fast path says so, rather than staying silent;
  * a dispatched reviewer, a repair loop, and a residual plan reach the console;
  * a skipped QA path is reported as skipped, not as a clean gate;
  * an unmasked secret is visible in the receipt, not only in the sidecar;
  * the counts survive in `.agent-run.log`, which cleanup never reaps;
  * `.qa-status.json` is read, never rewritten — Stage 3 owns that file;
  * missing or unparseable inputs degrade to a receipt, never to a crash.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import render_qa_receipt as receipt  # noqa: E402


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "security"
    out.mkdir(parents=True)
    return out


def _write(output_dir: Path, name: str, payload: dict) -> None:
    (output_dir / name).write_text(json.dumps(payload), encoding="utf-8")


def _clean_pass(output_dir: Path) -> None:
    _write(output_dir, receipt.STATUS_NAME, {"status": "pass", "source": "deterministic-pre-agent", "qa_skipped": False})
    _write(output_dir, receipt.SECRET_SCAN_NAME, {"check": "unmasked_secrets", "ok": 1, "issue_count": 0})


def test_the_deterministic_fast_path_is_reported(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    _clean_pass(output_dir)

    assert receipt.main([str(output_dir), "--gate-exit", "0"]) == 0
    out = capsys.readouterr().out

    assert "Stage 3 — QA gate" in out
    assert "Passed deterministically" in out
    assert "Secret-leak gate: clean" in out
    assert "Verdict: pass (deterministic-pre-agent)" in out


def test_a_dispatched_reviewer_and_its_repairs_reach_the_console(
    output_dir: Path, capsys: pytest.CaptureFixture
) -> None:
    _write(output_dir, receipt.STATUS_NAME, {"status": "pass", "source": "qa-reviewer", "qa_skipped": False})
    _write(output_dir, receipt.SECRET_SCAN_NAME, {"issue_count": 0})

    assert (
        receipt.main(
            [
                str(output_dir),
                "--gate-exit",
                "1",
                "--repair-iterations",
                "2",
                "--dispatched",
                "appsec-qa-reviewer",
                "--dispatched",
                "appsec-fragment-fixer",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out

    assert "actionable violations" in out
    assert "appsec-qa-reviewer, appsec-fragment-fixer" in out
    assert "Repaired: 2 iteration(s)" in out


def test_a_residual_repair_plan_is_broken_down_by_severity(
    output_dir: Path, capsys: pytest.CaptureFixture
) -> None:
    _clean_pass(output_dir)
    _write(
        output_dir,
        receipt.REPAIR_PLAN_NAME,
        {
            "status": "manual_review",
            "actions": [
                {"severity": "manual_review", "type": "evidence_gap"},
                {"severity": "manual_review", "type": "evidence_gap"},
                {"severity": "cosmetic", "type": "compactness"},
            ],
        },
    )

    assert receipt.main([str(output_dir), "--gate-exit", "3"]) == 0
    out = capsys.readouterr().out

    assert "Open repair plan: 3 action(s) [manual_review]" in out
    assert "1 cosmetic" in out
    assert "2 manual_review" in out


def test_cosmetic_advisories_are_surfaced_and_capped(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    _write(
        output_dir,
        receipt.STATUS_NAME,
        {
            "status": "pass",
            "source": "deterministic-pre-agent",
            "cosmetic_advisories": [f"advisory {i}" for i in range(7)],
        },
    )
    _write(output_dir, receipt.SECRET_SCAN_NAME, {"issue_count": 0})

    assert receipt.main([str(output_dir), "--gate-exit", "4"]) == 0
    out = capsys.readouterr().out

    assert "Cosmetic advisories (7, not re-rendered)" in out
    assert "advisory 0" in out
    assert f"… 2 more in {receipt.STATUS_NAME}" in out


def test_a_skipped_qa_path_is_not_reported_as_a_clean_gate(
    output_dir: Path, capsys: pytest.CaptureFixture
) -> None:
    _write(output_dir, receipt.STATUS_NAME, {"status": "pass", "source": "secret-gate-only", "qa_skipped": True})
    _write(output_dir, receipt.SECRET_SCAN_NAME, {"issue_count": 0})

    assert receipt.main([str(output_dir)]) == 0
    out = capsys.readouterr().out

    assert "QA skipped by configuration" in out
    assert "Passed deterministically" not in out


def test_an_unmasked_secret_is_visible_in_the_receipt(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    _write(output_dir, receipt.STATUS_NAME, {"status": "repair_required", "source": "qa-reviewer"})
    _write(output_dir, receipt.SECRET_SCAN_NAME, {"issue_count": 2, "issues": [{}, {}]})

    assert receipt.main([str(output_dir), "--gate-exit", "1"]) == 0
    out = capsys.readouterr().out

    assert "2 unmasked secret(s) — release blocked" in out
    assert "Verdict: repair_required" in out


def test_the_counts_survive_in_the_run_log(output_dir: Path) -> None:
    """`.qa-status.json` is reaped on a clean run; the log line is not."""
    _clean_pass(output_dir)

    assert receipt.main([str(output_dir), "--gate-exit", "0", "--no-print"]) == 0
    line = (output_dir / receipt.LOG_NAME).read_text(encoding="utf-8")

    assert "QA_GATE" in line
    assert "qa-reviewer" in line
    for field in ("verdict=pass", "source=deterministic-pre-agent", "gate_exit=0", "repairs=0", "secret_issues=0"):
        assert field in line


def test_the_log_line_is_appended_not_overwritten(output_dir: Path) -> None:
    _clean_pass(output_dir)
    (output_dir / receipt.LOG_NAME).write_text("earlier stage line\n", encoding="utf-8")

    assert receipt.main([str(output_dir), "--no-print"]) == 0

    assert (output_dir / receipt.LOG_NAME).read_text(encoding="utf-8").startswith("earlier stage line\n")


def test_the_status_file_is_read_never_rewritten(output_dir: Path) -> None:
    """Stage 3 writes `.qa-status.json` last, on purpose. This script is a reader."""
    _clean_pass(output_dir)
    before = (output_dir / receipt.STATUS_NAME).read_bytes()

    assert receipt.main([str(output_dir), "--gate-exit", "0", "--no-print"]) == 0

    assert (output_dir / receipt.STATUS_NAME).read_bytes() == before


def test_missing_inputs_still_produce_a_receipt(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    assert receipt.main([str(output_dir)]) == 0
    out = capsys.readouterr().out

    assert "Verdict: unknown (unknown)" in out
    assert "Secret-leak gate: no scan on disk" in out


def test_unparseable_inputs_do_not_crash(output_dir: Path) -> None:
    (output_dir / receipt.STATUS_NAME).write_text("{not json", encoding="utf-8")
    (output_dir / receipt.REPAIR_PLAN_NAME).write_text("[]", encoding="utf-8")

    assert receipt.main([str(output_dir), "--no-print"]) == 0


def test_an_unreported_gate_exit_does_not_invent_an_outcome(
    output_dir: Path, capsys: pytest.CaptureFixture
) -> None:
    _write(output_dir, receipt.STATUS_NAME, {"status": "pass", "source": "qa-reviewer"})
    _write(output_dir, receipt.SECRET_SCAN_NAME, {"issue_count": 0})

    assert receipt.main([str(output_dir), "--dispatched", "appsec-qa-reviewer"]) == 0

    assert "outcome not reported by the runtime" in capsys.readouterr().out


def test_a_missing_output_dir_is_a_usage_error(tmp_path: Path) -> None:
    assert receipt.main([str(tmp_path / "nope")]) == 2


def test_an_empty_output_dir_argument_is_refused() -> None:
    """An unset `$OUTPUT_DIR` arrives as `""`, and `Path("")` is the CWD."""
    assert receipt.main([""]) == 2


def test_an_option_in_the_output_dir_slot_is_refused() -> None:
    """Shifted arguments must not make the CWD the write target.

    argparse rejects the unknown option before the in-script guard sees it, so
    this exits rather than returning. Either way nothing is written.
    """
    with pytest.raises(SystemExit) as exc:
        receipt.main(["-x"])
    assert exc.value.code == 2


def test_an_unwritable_log_does_not_fail_the_stage(output_dir: Path) -> None:
    _clean_pass(output_dir)
    (output_dir / receipt.LOG_NAME).mkdir()

    assert receipt.main([str(output_dir), "--no-print"]) == 0
