"""Tests for the chain-verdict finalizer in scripts/match_abuse_cases.py.

The chain verdict is computed deterministically from per-step verifier verdicts
— never rated by an LLM — so it is fully unit-testable here.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "match_abuse_cases.py"


def _load():
    if "match_abuse_cases" in sys.modules:
        return sys.modules["match_abuse_cases"]
    spec = importlib.util.spec_from_file_location("match_abuse_cases", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["match_abuse_cases"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


mac = _load()


def _case_match(n_required=2):
    return {
        "step_matches": [
            {"step": i + 1, "required": True, "controls_found": []} for i in range(n_required)
        ]
    }


def _sv(step, verdict, controls=None):
    return {"step": step, "verdict": verdict, "controls_found": controls or []}


def test_all_confirmed_no_controls_is_fully_viable():
    cm = _case_match(2)
    sv = [_sv(1, "confirmed"), _sv(2, "confirmed")]
    assert mac.finalize_verdict(cm, sv) == "fully_viable"


def test_confirmed_with_control_is_partially_blocked():
    cm = _case_match(2)
    sv = [_sv(1, "confirmed"), _sv(2, "confirmed", controls=["DomSanitizer"])]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


def test_all_blocked_is_mitigated():
    cm = _case_match(2)
    sv = [_sv(1, "blocked"), _sv(2, "blocked")]
    assert mac.finalize_verdict(cm, sv) == "mitigated"


def test_any_inconclusive_required_is_inconclusive():
    cm = _case_match(2)
    sv = [_sv(1, "confirmed"), _sv(2, "inconclusive")]
    assert mac.finalize_verdict(cm, sv) == "inconclusive"


def test_mix_confirmed_and_blocked_is_partially_blocked():
    cm = _case_match(2)
    sv = [_sv(1, "confirmed"), _sv(2, "blocked")]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


def test_control_on_step_match_counts_even_without_verdict_controls():
    # control observed by the matcher (step_matches), not repeated in step verdict
    cm = {"step_matches": [
        {"step": 1, "required": True, "controls_found": []},
        {"step": 2, "required": True, "controls_found": ["HttpOnly"]},
    ]}
    sv = [_sv(1, "confirmed"), _sv(2, "confirmed")]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


def test_no_required_steps_is_not_applicable():
    cm = {"step_matches": [{"step": 1, "required": False, "controls_found": []}]}
    assert mac.finalize_verdict(cm, []) == "not_applicable"


# ---------------------------------------------------------------------------
# finalize CLI: matches + verdicts → enriched verdicts with chain_verdict
# ---------------------------------------------------------------------------


def test_finalize_cli_writes_chain_verdict(tmp_path: Path):
    matches = {
        "schema_version": 1,
        "matches": [
            {
                "abuse_case_id": "AC-T-001",
                "structural_verdict": "candidate",
                "step_matches": [
                    {"step": 1, "required": True, "controls_found": []},
                    {"step": 2, "required": True, "controls_found": []},
                ],
            }
        ],
    }
    verdicts = {
        "schema_version": 1,
        "verdicts": [
            {
                "abuse_case_id": "AC-T-001",
                "step_verdicts": [_sv(1, "confirmed"), _sv(2, "confirmed")],
            }
        ],
    }
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(matches))
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(verdicts))

    rc = mac.main(["finalize", "--output-dir", str(tmp_path)])
    assert rc == 0
    out = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    assert out["verdicts"][0]["chain_verdict"] == "fully_viable"
