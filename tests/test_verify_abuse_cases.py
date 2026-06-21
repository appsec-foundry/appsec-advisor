"""Unit tests for scripts/verify_abuse_cases.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import verify_abuse_cases as mod


def _write(p: Path, obj) -> None:
    p.write_text(json.dumps(obj), encoding="utf-8")


# --- _candidates -----------------------------------------------------------


def test_candidates_missing_matches_file(tmp_path):
    assert mod._candidates(tmp_path) == []


def test_candidates_filters_by_structural_verdict(tmp_path):
    _write(
        tmp_path / ".abuse-case-matches.json",
        {
            "matches": [
                {"abuse_case_id": "AC-001", "structural_verdict": "candidate"},
                {"abuse_case_id": "AC-002", "structural_verdict": "partial_candidate"},
                {"abuse_case_id": "AC-003", "structural_verdict": "no_match"},
                {"abuse_case_id": "AC-004"},
            ]
        },
    )
    assert mod._candidates(tmp_path) == ["AC-001", "AC-002"]


# --- _load_verdict_files ---------------------------------------------------


def test_load_verdict_files_empty(tmp_path):
    assert mod._load_verdict_files(tmp_path) == {}


def test_load_verdict_files_normalises_steps_and_keys(tmp_path):
    _write(
        tmp_path / ".abuse-case-verdict-AC-001.json",
        {
            "abuse_case_id": "AC-001",
            "step_verdicts": [
                {"verdict": "confirmed"},
                {"verdict": "weird-unknown"},
            ],
        },
    )
    out = mod._load_verdict_files(tmp_path)
    assert set(out) == {"AC-001"}
    steps = out["AC-001"]["step_verdicts"]
    assert steps[0]["verdict"] == "confirmed"
    assert steps[1]["verdict"] == "inconclusive"  # normalised


def test_load_verdict_files_skips_unreadable(tmp_path, capsys):
    (tmp_path / ".abuse-case-verdict-bad.json").write_text("{ not json", encoding="utf-8")
    _write(tmp_path / ".abuse-case-verdict-AC-009.json", {"abuse_case_id": "AC-009"})
    out = mod._load_verdict_files(tmp_path)
    assert set(out) == {"AC-009"}
    assert "skipping unreadable" in capsys.readouterr().err


def test_load_verdict_files_skips_no_id(tmp_path, capsys):
    _write(tmp_path / ".abuse-case-verdict-AC-noid.json", {"step_verdicts": []})
    out = mod._load_verdict_files(tmp_path)
    assert out == {}
    assert "no abuse_case_id" in capsys.readouterr().err


def test_load_verdict_files_step_verdicts_none(tmp_path):
    # step_verdicts absent → `or []` branch, no crash
    _write(tmp_path / ".abuse-case-verdict-AC-005.json", {"abuse_case_id": "AC-005"})
    out = mod._load_verdict_files(tmp_path)
    assert out["AC-005"] == {"abuse_case_id": "AC-005"}


# --- cmd_merge -------------------------------------------------------------


def _ns(output_dir):
    import argparse

    return argparse.Namespace(output_dir=str(output_dir))


def test_cmd_merge_writes_consolidated(tmp_path, capsys):
    _write(tmp_path / ".abuse-case-verdict-AC-001.json", {"abuse_case_id": "AC-001", "step_verdicts": []})
    rc = mod.cmd_merge(_ns(tmp_path))
    assert rc == 0
    merged = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    assert merged["schema_version"] == 1
    assert {v["abuse_case_id"] for v in merged["verdicts"]} == {"AC-001"}
    assert "merged 1 verdict" in capsys.readouterr().err


def test_cmd_merge_stubs_missing_candidates(tmp_path):
    _write(
        tmp_path / ".abuse-case-matches.json",
        {"matches": [{"abuse_case_id": "AC-100", "structural_verdict": "candidate"}]},
    )
    rc = mod.cmd_merge(_ns(tmp_path))
    assert rc == 0
    merged = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    stub = next(v for v in merged["verdicts"] if v["abuse_case_id"] == "AC-100")
    assert stub["note"] == "no verifier verdict"
    assert stub["step_verdicts"] == []


def test_cmd_merge_budget_critical_note(tmp_path, capsys):
    _write(
        tmp_path / ".abuse-case-matches.json",
        {"matches": [{"abuse_case_id": "AC-200", "structural_verdict": "partial_candidate"}]},
    )
    (tmp_path / ".budget-critical").write_text("", encoding="utf-8")
    rc = mod.cmd_merge(_ns(tmp_path))
    assert rc == 0
    merged = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    stub = next(v for v in merged["verdicts"] if v["abuse_case_id"] == "AC-200")
    assert "budget-critical" in stub["note"]
    assert "[budget-critical]" in capsys.readouterr().err


def test_cmd_merge_existing_verdict_not_stubbed(tmp_path):
    _write(
        tmp_path / ".abuse-case-matches.json",
        {"matches": [{"abuse_case_id": "AC-300", "structural_verdict": "candidate"}]},
    )
    _write(tmp_path / ".abuse-case-verdict-AC-300.json", {"abuse_case_id": "AC-300", "step_verdicts": []})
    mod.cmd_merge(_ns(tmp_path))
    merged = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    v = next(v for v in merged["verdicts"] if v["abuse_case_id"] == "AC-300")
    assert "note" not in v  # real verdict kept verbatim


# --- RC-4: unfinalized pre-seed detection ----------------------------------


def test_is_unfinalized_preseed_all_inconclusive_no_reason():
    v = {
        "abuse_case_id": "AC-T-003",
        "step_verdicts": [
            {"step": 1, "verdict": "inconclusive", "evidence": {"file": "x", "line": 1}},
            {"step": 2, "verdict": "inconclusive", "evidence": {"file": "", "line": 0}},
        ],
    }
    assert mod._is_unfinalized_preseed(v) is True


def test_is_unfinalized_preseed_reasoned_inconclusive_is_genuine():
    # A reasoned inconclusive (per the verifier contract) is NOT a pre-seed.
    v = {
        "step_verdicts": [
            {"step": 1, "verdict": "inconclusive", "reason": "could not resolve handler precedence within budget"},
        ],
    }
    assert mod._is_unfinalized_preseed(v) is False


def test_is_unfinalized_preseed_any_decided_step_is_finalized():
    v = {
        "step_verdicts": [
            {"step": 1, "verdict": "confirmed"},
            {"step": 2, "verdict": "inconclusive"},
        ],
    }
    assert mod._is_unfinalized_preseed(v) is False


def test_is_unfinalized_preseed_empty_steps_is_not_preseed():
    # No steps at all → handled by the missing-candidate stub path, not here.
    assert mod._is_unfinalized_preseed({"step_verdicts": []}) is False


def test_load_verdict_files_flags_unfinalized(tmp_path):
    _write(
        tmp_path / ".abuse-case-verdict-AC-T-003.json",
        {
            "abuse_case_id": "AC-T-003",
            "step_verdicts": [
                {"step": 1, "verdict": "inconclusive"},
                {"step": 2, "verdict": "inconclusive"},
            ],
        },
    )
    out = mod._load_verdict_files(tmp_path)
    assert out["AC-T-003"]["_not_finalized"] is True


def test_cmd_merge_warns_on_unfinalized(tmp_path, capsys):
    _write(
        tmp_path / ".abuse-case-verdict-AC-T-003.json",
        {
            "abuse_case_id": "AC-T-003",
            "step_verdicts": [{"step": 1, "verdict": "inconclusive"}],
        },
    )
    rc = mod.cmd_merge(_ns(tmp_path))
    assert rc == 0
    err = capsys.readouterr().err
    assert "did not finalize" in err and "AC-T-003" in err
    merged = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    v = next(v for v in merged["verdicts"] if v["abuse_case_id"] == "AC-T-003")
    assert v["_not_finalized"] is True


def test_cmd_merge_no_unfinalized_warning_when_reasoned(tmp_path, capsys):
    _write(
        tmp_path / ".abuse-case-verdict-AC-T-009.json",
        {
            "abuse_case_id": "AC-T-009",
            "step_verdicts": [{"step": 1, "verdict": "inconclusive", "reason": "ambiguous middleware order"}],
        },
    )
    mod.cmd_merge(_ns(tmp_path))
    assert "did not finalize" not in capsys.readouterr().err


# --- main / argparse -------------------------------------------------------


def test_main_merge_dispatch(tmp_path):
    _write(tmp_path / ".abuse-case-verdict-AC-001.json", {"abuse_case_id": "AC-001"})
    rc = mod.main(["merge", "--output-dir", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / ".abuse-case-verdicts.json").exists()


def test_main_requires_subcommand():
    with pytest.raises(SystemExit):
        mod.main([])
