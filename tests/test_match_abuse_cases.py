"""Tests for scripts/match_abuse_cases.py — the deterministic matcher.

Covers sink/control matching, scope-qualifier gating, and the structural
verdict (candidate / partial_candidate / not_applicable).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

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


def _finding(fid, text, controls="", file="src/x.ts", line=10):
    return {
        "t_id": fid,
        "title": text,
        "scenario": text,
        "controls_in_place": controls,
        "evidence": {"file": file, "line": line},
    }


def _step(n, sink, *, required=True, controls=None, requires=None, grants="state"):
    probe = {"sink_patterns": [sink]}
    if controls:
        probe["control_patterns"] = controls
    s = {"step": n, "label": f"step{n}", "grants": grants, "required": required, "probe": probe}
    if requires:
        s["requires"] = requires
    return s


def _case(steps, **kw):
    base = {
        "id": kw.get("id", "AC-T-999"),
        "title": "T",
        "source": "mandatory",
        "attacker": {"actor_id": "a", "initial_access": "unauthenticated"},
        "goal": "g",
        "chain": steps,
    }
    if "required_signals" in kw:
        base["scope_qualifier"] = {"required_signals": kw["required_signals"]}
    return base


# ---------------------------------------------------------------------------
# Step matching
# ---------------------------------------------------------------------------


def test_step_matches_finding_by_sink_regex():
    findings = [_finding("T-001", "uses bypassSecurityTrustHtml on input")]
    m = mac.match_step(_step(1, "bypassSecurityTrust"), findings)
    assert m["matched"] and m["matched_finding_id"] == "T-001"
    assert m["evidence"]["file"] == "src/x.ts"


def test_step_no_match_when_sink_absent():
    findings = [_finding("T-001", "totally unrelated finding")]
    m = mac.match_step(_step(1, "bypassSecurityTrust"), findings)
    assert not m["matched"] and m["matched_finding_id"] is None


def test_step_records_controls_found():
    findings = [_finding("T-001", "innerHTML sink", controls="DomSanitizer applied")]
    m = mac.match_step(_step(1, "innerHTML", controls=["DomSanitizer"]), findings)
    assert m["matched"]
    assert m["controls_found"] == ["DomSanitizer"]


def test_invalid_regex_falls_back_to_literal():
    findings = [_finding("T-001", "value is a[b (unbalanced)")]
    m = mac.match_step(_step(1, "a[b ("), findings)  # invalid regex
    assert m["matched"]


# ---------------------------------------------------------------------------
# Case-level structural verdict
# ---------------------------------------------------------------------------


def test_all_required_matched_is_candidate():
    findings = [_finding("T-001", "sql injection"), _finding("T-002", "mass assignment role")]
    case = _case([_step(1, "sql injection"), _step(2, "mass assignment", requires="state")])
    r = mac.match_case(case, findings, None)
    assert r["structural_verdict"] == "candidate"
    assert r["matched_finding_ids"] == ["T-001", "T-002"]


def test_no_required_matched_is_not_applicable():
    findings = [_finding("T-001", "irrelevant")]
    case = _case([_step(1, "sql injection"), _step(2, "mass assignment")])
    r = mac.match_case(case, findings, None)
    assert r["structural_verdict"] == "not_applicable"


def test_partial_match_is_partial_candidate():
    findings = [_finding("T-001", "sql injection")]
    case = _case([_step(1, "sql injection"), _step(2, "mass assignment")])
    r = mac.match_case(case, findings, None)
    assert r["structural_verdict"] == "partial_candidate"


def test_non_required_step_miss_still_candidate():
    findings = [_finding("T-001", "sql injection")]
    case = _case([_step(1, "sql injection"), _step(2, "optional sink", required=False)])
    r = mac.match_case(case, findings, None)
    assert r["structural_verdict"] == "candidate"


# ---------------------------------------------------------------------------
# scope_qualifier
# ---------------------------------------------------------------------------


def test_scope_missing_signal_is_not_applicable():
    findings = [_finding("T-001", "sql injection")]
    case = _case([_step(1, "sql injection")], required_signals=["has_auth_surface"])
    r = mac.match_case(case, findings, signals=set())  # signals known, required absent
    assert r["structural_verdict"] == "not_applicable"
    assert r["applicable"] is False
    # Records WHY (for the §9 'evaluated, not applicable' catalog table).
    assert "has_auth_surface" in (r.get("unmet_signals") or [])
    assert r.get("reason") and "has_auth_surface" in r["reason"]


def test_not_applicable_no_step_match_records_reason():
    findings = [_finding("T-001", "irrelevant")]
    case = _case([_step(1, "sql injection")])
    r = mac.match_case(case, findings, None)
    assert r["structural_verdict"] == "not_applicable"
    assert r.get("reason") and "no finding matched" in r["reason"]


def test_scope_satisfied_when_signal_present():
    findings = [_finding("T-001", "sql injection")]
    case = _case([_step(1, "sql injection")], required_signals=["has_auth_surface"])
    r = mac.match_case(case, findings, signals={"has_auth_surface"})
    assert r["structural_verdict"] == "candidate"


def test_scope_treated_satisfied_when_no_signals_source():
    findings = [_finding("T-001", "sql injection")]
    case = _case([_step(1, "sql injection")], required_signals=["has_auth_surface"])
    r = mac.match_case(case, findings, signals=None)  # no signals file → cannot disprove
    assert r["applicable"] is True
    assert r["structural_verdict"] == "candidate"


# ---------------------------------------------------------------------------
# CLI: match → list-candidates round trip against the shipped library
# ---------------------------------------------------------------------------


def test_cli_match_and_list_candidates(tmp_path: Path, capsys):
    findings = {
        "threats": [
            _finding("T-048", "bypassSecurityTrustHtml renders feedback"),
            _finding("T-046", "refresh token in localStorage.getItem"),
            _finding("T-012", "findById params.id no ownership"),
            _finding("T-019", "update(req.body) persists role"),
        ]
    }
    (tmp_path / ".threats-merged.json").write_text(json.dumps(findings))
    rc = mac.main(["match", "--output-dir", str(tmp_path)])
    assert rc == 0
    doc = json.loads((tmp_path / ".abuse-case-matches.json").read_text())
    ids = {m["abuse_case_id"]: m["structural_verdict"] for m in doc["matches"]}
    # AC-T-001 (XSS+token) and AC-T-002 (IDOR+mass-assignment) should be candidates.
    assert ids.get("AC-T-001") in ("candidate", "partial_candidate")
    assert ids.get("AC-T-002") in ("candidate", "partial_candidate")

    rc = mac.main(["list-candidates", "--output-dir", str(tmp_path)])
    assert rc == 0
    listed = capsys.readouterr().out.split()
    assert "AC-T-001" in listed


# ---------------------------------------------------------------------------
# CLI: list-inconclusive — escalation work-list
# ---------------------------------------------------------------------------


def _write_verdicts(tmp_path: Path, rows: list[tuple[str, str]]) -> None:
    """rows = [(ac_id, chain_verdict), ...]"""
    doc = {
        "schema_version": 1,
        "verdicts": [{"abuse_case_id": cid, "chain_verdict": cv, "step_verdicts": []} for cid, cv in rows],
    }
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(doc))


def _write_matches(tmp_path: Path, rows: list[tuple[str, str]]) -> None:
    """rows = [(ac_id, structural_verdict), ...]"""
    doc = {"schema_version": 1, "matches": [{"abuse_case_id": cid, "structural_verdict": sv} for cid, sv in rows]}
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(doc))


def test_list_inconclusive_lists_only_inconclusive_candidates(tmp_path: Path, capsys):
    _write_verdicts(tmp_path, [("AC-T-001", "fully_viable"), ("AC-T-002", "inconclusive"), ("AC-T-003", "mitigated")])
    _write_matches(tmp_path, [("AC-T-001", "candidate"), ("AC-T-002", "candidate"), ("AC-T-003", "candidate")])
    rc = mac.main(["list-inconclusive", "--output-dir", str(tmp_path)])
    assert rc == 0
    assert capsys.readouterr().out.split() == ["AC-T-002"]


def test_list_inconclusive_skips_non_candidates(tmp_path: Path, capsys):
    _write_verdicts(tmp_path, [("AC-T-002", "inconclusive"), ("AC-T-009", "inconclusive")])
    _write_matches(tmp_path, [("AC-T-002", "candidate"), ("AC-T-009", "not_applicable")])
    mac.main(["list-inconclusive", "--output-dir", str(tmp_path)])
    assert capsys.readouterr().out.split() == ["AC-T-002"]


def test_list_inconclusive_respects_cap(tmp_path: Path, capsys):
    rows = [(f"AC-T-{n:03d}", "inconclusive") for n in range(1, 9)]
    _write_verdicts(tmp_path, rows)
    _write_matches(tmp_path, [(cid, "candidate") for cid, _ in rows])
    mac.main(["list-inconclusive", "--output-dir", str(tmp_path), "--max", "3"])
    out = capsys.readouterr().out.split()
    assert len(out) == 3
    assert out == ["AC-T-001", "AC-T-002", "AC-T-003"]  # deterministic sort


def test_list_inconclusive_no_verdicts_file_is_empty(tmp_path: Path, capsys):
    rc = mac.main(["list-inconclusive", "--output-dir", str(tmp_path)])
    assert rc == 0
    assert capsys.readouterr().out.strip() == ""
