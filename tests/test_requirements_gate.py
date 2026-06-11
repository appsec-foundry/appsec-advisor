"""Exit-code matrix for scripts/requirements_gate.py.

The gate is the single authority on whether a change blocks. It must recompute
the gating set from results[] and NEVER trust the agent's advisory `gating` /
`gating_failures` fields. These tests pin every branch of that contract.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import requirements_gate  # noqa: E402


def _result(rid, priority, status, in_scope=True, gating=None):
    r = {"id": rid, "priority": priority, "status": status, "in_scope": in_scope}
    if gating is not None:
        r["gating"] = gating
    return r


def _write(tmp_path: Path, results: list[dict]) -> Path:
    verdict = {
        "version": 1,
        "generated_at": "2026-06-07T00:00:00Z",
        "base_ref": "origin/main",
        "priority_floor": "MUST",
        "summary": {
            "changed_files": 1,
            "candidates": len(results),
            "in_scope": sum(1 for r in results if r["in_scope"]),
            "pass": 0,
            "partial": 0,
            "fail": 0,
            "unverifiable": 0,
            "not_applicable": 0,
            "gating_failures": 0,
        },
        "results": results,
    }
    p = tmp_path / ".requirements-verification.json"
    p.write_text(json.dumps(verdict), encoding="utf-8")
    return p


def _run(verdict_path, *extra):
    return requirements_gate.main(["--verdict", str(verdict_path), *extra])


# --- advisory mode always exits 0 -------------------------------------------


def test_advisory_must_fail_exits_zero(tmp_path):
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "FAIL")])
    assert _run(p) == 0  # advisory: no --gate


# --- gate mode core ----------------------------------------------------------


def test_gate_must_fail_blocks(tmp_path):
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "FAIL")])
    assert _run(p, "--gate") == 1


def test_gate_all_pass_exits_zero(tmp_path):
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "PASS"), _result("SEC-CSP", "SHOULD", "PASS")])
    assert _run(p, "--gate") == 0


def test_gate_not_in_scope_does_not_block(tmp_path):
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "FAIL", in_scope=False)])
    assert _run(p, "--gate") == 0


def test_not_applicable_never_blocks(tmp_path):
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "NOT_APPLICABLE", in_scope=False)])
    assert _run(p, "--gate") == 0


# --- priority floor ----------------------------------------------------------


def test_gate_should_fail_below_default_floor_passes(tmp_path):
    p = _write(tmp_path, [_result("SEC-CSP", "SHOULD", "FAIL")])
    assert _run(p, "--gate") == 0  # floor MUST → SHOULD does not gate


def test_gate_should_fail_at_should_floor_blocks(tmp_path):
    p = _write(tmp_path, [_result("SEC-CSP", "SHOULD", "FAIL")])
    assert _run(p, "--gate", "--priority-floor", "SHOULD") == 1


def test_gate_may_floor_blocks_everything(tmp_path):
    p = _write(tmp_path, [_result("SEC-X", "MAY", "FAIL")])
    assert _run(p, "--gate", "--priority-floor", "MAY") == 1


# --- gate-on partial ---------------------------------------------------------


def test_partial_does_not_block_by_default(tmp_path):
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "PARTIAL")])
    assert _run(p, "--gate") == 0


def test_partial_blocks_with_gate_on_partial(tmp_path):
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "PARTIAL")])
    assert _run(p, "--gate", "--gate-on", "partial") == 1


# --- agent advisory fields are ignored (authoritative recompute) ------------


def test_agent_gating_true_but_status_pass_does_not_block(tmp_path):
    # Agent mis-set gating:true on a PASS — the gate must ignore it.
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "PASS", gating=True)])
    assert _run(p, "--gate") == 0


def test_agent_gating_false_but_real_fail_still_blocks(tmp_path):
    # Agent under-reported gating:false on a real MUST FAIL — gate must catch it.
    p = _write(tmp_path, [_result("SEC-SQL", "MUST", "FAIL", gating=False)])
    assert _run(p, "--gate") == 1


# --- error handling ----------------------------------------------------------


def test_missing_file_exits_two(tmp_path):
    assert _run(tmp_path / "nope.json", "--gate") == 2


def test_malformed_json_exits_two(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    assert _run(p, "--gate") == 2


def test_missing_results_array_exits_two(tmp_path):
    p = tmp_path / "no-results.json"
    p.write_text(json.dumps({"version": 1}), encoding="utf-8")
    assert _run(p, "--gate") == 2
