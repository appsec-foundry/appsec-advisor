"""Tests for scripts/match_abuse_cases.py — the deterministic matcher.

Covers sink/control matching, scope-qualifier gating, and the structural
verdict (candidate / partial_candidate / not_applicable).
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


def test_cwe_specific_pattern_outranks_incidental_prose():
    # An IDOR finding (CWE-639) whose scenario also mentions "role escalation"
    # in passing must NOT capture a mass-assignment step (CWE-915) — the CWE-code
    # pattern is more specific than the incidental prose hit. (juice-shop
    # 2026-07-13: AC-T-002 step 2 mis-linked to F-008 IDOR.)
    idor = {
        "t_id": "T-008",
        "title": "Insecure Direct Object Reference",
        "scenario": "attacker can escalate role via enumerated object",
        "cwe": "CWE-639",
        "evidence": {"file": "routes/address.ts", "line": 11},
    }
    massassign = {
        "t_id": "T-009",
        "title": "Mass assignment privileged field",
        "scenario": "role field accepted from request body",
        "cwe": "CWE-915",
        "evidence": {"file": "routes/verify.ts", "line": 53},
    }
    step = _step(2, "CWE-(915|266|269)")
    step["probe"]["sink_patterns"].append("(?i)(role|privilege) escalation")
    step["probe"]["sink_patterns"].append("(?i)mass assignment")
    m = mac.match_step(step, [idor, massassign])
    assert m["matched_finding_id"] == "T-009"


def test_context_dependent_cwe_needs_mechanism_evidence():
    """A broad access-control CWE alone must not create an IDOR candidate."""
    generic_access_control = {
        "t_id": "T-001",
        "title": "CLI configuration trust boundary",
        "scenario": "A command-line option changes the trust mode.",
        "cwe": "CWE-284",
        "evidence": {"file": "scripts/tool.sh", "line": 12},
    }
    idor = {
        "t_id": "T-002",
        "title": "Missing ownership check on object read",
        "scenario": "An authenticated caller can read another user's object.",
        "cwe": "CWE-284",
        "evidence": {"file": "routes/object.ts", "line": 24},
    }
    step = _step(1, "CWE-(639|284|862|863|566)")
    step["probe"]["sink_patterns"].append("(?i)ownership check")

    assert not mac.match_step(step, [generic_access_control])["matched"]
    assert mac.match_step(step, [idor])["matched_finding_id"] == "T-002"


def test_context_dependent_jwt_cwe_needs_jwt_mechanism_evidence():
    """CWE-347 artifact provenance must not be treated as JWT verification."""
    unsigned_artifact = {
        "t_id": "T-001",
        "title": "Unsigned build artifact",
        "scenario": "Release provenance is not verified.",
        "cwe": "CWE-347",
        "evidence": {"file": ".github/workflows/release.yml", "line": 1},
    }
    jwt_verifier = {
        "t_id": "T-002",
        "title": "JWT verification accepts an attacker-controlled algorithm",
        "scenario": "jwt.verify accepts a token without an algorithm allowlist.",
        "cwe": "CWE-347",
        "evidence": {"file": "middleware/auth.ts", "line": 24},
    }
    step = _step(1, "CWE-347")
    step["probe"]["sink_patterns"].append("jwt\\.verify")

    assert not mac.match_step(step, [unsigned_artifact])["matched"]
    assert mac.match_step(step, [jwt_verifier])["matched_finding_id"] == "T-002"


def test_chain_steps_do_not_collapse_to_one_finding():
    # A two-step chain (IDOR read → mass-assignment write) must map to two
    # distinct findings, not the same one twice.
    idor = {
        "t_id": "T-008",
        "title": "IDOR",
        "scenario": "escalate role",
        "cwe": "CWE-639",
        "evidence": {"file": "a.ts", "line": 1},
    }
    massassign = {
        "t_id": "T-009",
        "title": "Mass assignment",
        "scenario": "role field",
        "cwe": "CWE-915",
        "evidence": {"file": "b.ts", "line": 2},
    }
    step1 = _step(1, "CWE-(639|284|862)")
    step2 = _step(2, "CWE-(915|266|269)", requires="state")
    case = _case([step1, step2])
    r = mac.match_case(case, [idor, massassign], None)
    ids = r["matched_finding_ids"]
    assert ids == ["T-008", "T-009"], ids


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


def test_direct_source_probe_makes_case_a_candidate_without_finding(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "template.ts").write_text("render(innerHTML);\n", encoding="utf-8")
    case = _case([_step(1, "innerHTML")])

    result = mac.match_case(case, [], signals=None, repo_root=tmp_path)

    assert result["structural_verdict"] == "candidate"
    step = result["step_matches"][0]
    assert step["match_basis"] == "source_probe"
    assert step["matched_finding_id"] is None
    assert step["evidence"] == {"file": "src/template.ts", "line": 1, "excerpt": "render(innerHTML);"}


def test_scope_path_patterns_gate_case_without_shell_path_expansion(tmp_path: Path):
    (tmp_path / "services").mkdir()
    (tmp_path / "services" / "payments.py").write_text("refund()\n", encoding="utf-8")
    case = _case([_step(1, "refund")])
    case["scope_qualifier"] = {"path_patterns": ["services/**/*.py"]}

    assert mac.match_case(case, [], signals=None, repo_root=tmp_path)["applicable"] is True
    case["scope_qualifier"] = {"path_patterns": ["../outside/**/*.py"]}
    result = mac.match_case(case, [], signals=None, repo_root=tmp_path)
    assert result["structural_verdict"] == "not_applicable"
    assert result["unmet_path_patterns"] == ["../outside/**/*.py"]


def test_load_signals_reads_canonical_recon_sidecar_shape(tmp_path: Path):
    signal_path = tmp_path / ".recon-signals.json"
    signal_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signals": {"has_auth_surface": True, "has_role_concept": False},
                "signal_evidence": {"has_auth_surface": "middleware/auth.ts:12"},
            }
        ),
        encoding="utf-8",
    )

    assert mac._load_signals(str(signal_path)) == {"has_auth_surface"}


def test_load_signals_rejects_non_runtime_evidence_for_surface_signals(tmp_path: Path):
    """Documentation and scanner catalogs cannot activate web abuse cases."""
    signal_path = tmp_path / ".recon-signals.json"
    signal_path.write_text(
        json.dumps(
            {
                "signals": {
                    "has_auth_surface": True,
                    "has_role_concept": True,
                    "has_client_storage": True,
                    "has_ci_pipeline": True,
                },
                "signal_evidence": {
                    "has_auth_surface": "agents/phases/auth.md:12",
                    "has_role_concept": "data/cwe-taxonomy.yaml:4",
                    "has_client_storage": "docs/frontend-guide.md:8",
                    "has_ci_pipeline": ".github/workflows/tests.yml:1",
                },
            }
        ),
        encoding="utf-8",
    )

    assert mac._load_signals(str(signal_path)) == {"has_ci_pipeline"}


def test_load_signals_treats_missing_sidecar_as_unknown_scope(tmp_path: Path):
    assert mac._load_signals(str(tmp_path / ".recon-signals.json")) is None


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


# ---------------------------------------------------------------------------
# load_findings — shape handling
# ---------------------------------------------------------------------------


def test_load_findings_top_level_list(tmp_path: Path):
    p = tmp_path / "merged.json"
    p.write_text(json.dumps([_finding("T-001", "sqli")]))
    out = mac.load_findings(p)
    assert isinstance(out, list) and out[0]["t_id"] == "T-001"


def test_load_findings_dict_findings_key(tmp_path: Path):
    p = tmp_path / "merged.json"
    p.write_text(json.dumps({"findings": [_finding("T-002", "xss")]}))
    out = mac.load_findings(p)
    assert out[0]["t_id"] == "T-002"


def test_load_findings_unexpected_scalar_is_empty(tmp_path: Path):
    p = tmp_path / "merged.json"
    p.write_text(json.dumps("not-a-list-or-dict"))
    assert mac.load_findings(p) == []


# ---------------------------------------------------------------------------
# _load_signals — accepted shapes
# ---------------------------------------------------------------------------


def test_load_signals_none_path():
    assert mac._load_signals(None) is None


def test_load_signals_signals_list(tmp_path: Path):
    p = tmp_path / "sig.json"
    p.write_text(json.dumps({"signals": ["a", "b"]}))
    assert mac._load_signals(str(p)) == {"a", "b"}


def test_load_signals_truthy_dict(tmp_path: Path):
    p = tmp_path / "sig.json"
    p.write_text(json.dumps({"a": True, "b": False, "c": 1}))
    assert mac._load_signals(str(p)) == {"a", "c"}


def test_load_signals_bare_list(tmp_path: Path):
    p = tmp_path / "sig.json"
    p.write_text(json.dumps(["x", "y"]))
    assert mac._load_signals(str(p)) == {"x", "y"}


def test_load_signals_scalar_returns_none(tmp_path: Path):
    p = tmp_path / "sig.json"
    p.write_text(json.dumps(42))
    assert mac._load_signals(str(p)) is None


# ---------------------------------------------------------------------------
# finalize_verdict — chain folding
# ---------------------------------------------------------------------------


def _cm(steps):
    """case_match with the given step_matches rows."""
    return {"step_matches": steps}


def test_finalize_no_required_steps_is_not_applicable():
    cm = _cm([{"step": 1, "required": False}])
    assert mac.finalize_verdict(cm, []) == "not_applicable"


def test_finalize_all_blocked_is_mitigated():
    cm = _cm([{"step": 1, "required": True}, {"step": 2, "required": True}])
    sv = [{"step": 1, "verdict": "blocked"}, {"step": 2, "verdict": "blocked"}]
    assert mac.finalize_verdict(cm, sv) == "mitigated"


def test_finalize_any_inconclusive_is_inconclusive():
    cm = _cm([{"step": 1, "required": True}, {"step": 2, "required": True}])
    sv = [{"step": 1, "verdict": "confirmed"}, {"step": 2, "verdict": "inconclusive"}]
    assert mac.finalize_verdict(cm, sv) == "inconclusive"


def test_finalize_all_confirmed_no_controls_is_fully_viable():
    cm = _cm([{"step": 1, "required": True}])
    sv = [{"step": 1, "verdict": "confirmed"}]
    assert mac.finalize_verdict(cm, sv) == "fully_viable"


def test_finalize_all_confirmed_with_control_is_partially_blocked():
    cm = _cm([{"step": 1, "required": True, "controls_found": ["x"]}])
    sv = [{"step": 1, "verdict": "confirmed"}]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


def test_finalize_control_from_verdict_marks_partially_blocked():
    cm = _cm([{"step": 1, "required": True}])
    sv = [{"step": 1, "verdict": "confirmed", "controls_found": ["wf"]}]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


def test_finalize_non_required_step_control_counts():
    cm = _cm(
        [
            {"step": 1, "required": True},
            {"step": 2, "required": False, "controls_found": ["x"]},
        ]
    )
    sv = [{"step": 1, "verdict": "confirmed"}, {"step": 2, "verdict": "confirmed"}]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


def test_finalize_mixed_confirmed_blocked_is_partially_blocked():
    cm = _cm([{"step": 1, "required": True}, {"step": 2, "required": True}])
    sv = [{"step": 1, "verdict": "confirmed"}, {"step": 2, "verdict": "blocked"}]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


def test_finalize_missing_verdict_defaults_inconclusive():
    cm = _cm([{"step": 1, "required": True}])
    # no step_verdict provided → defaults to inconclusive
    assert mac.finalize_verdict(cm, []) == "inconclusive"


# ---------------------------------------------------------------------------
# cmd_match — org-profile + resolver-error paths
# ---------------------------------------------------------------------------


def test_cmd_match_with_org_profile(tmp_path: Path, capsys):
    findings = {"threats": [_finding("T-001", "sqli")]}
    (tmp_path / ".threats-merged.json").write_text(json.dumps(findings))
    # An empty/minimal org-profile yaml — resolver tolerates an empty profile
    # and still loads the shipped mandatory catalog.
    prof = tmp_path / "org-profile.yaml"
    prof.write_text("name: acme\n")
    rc = mac.main(["match", "--output-dir", str(tmp_path), "--org-profile", str(prof)])
    assert rc == 0
    assert (tmp_path / ".abuse-case-matches.json").is_file()


def test_cmd_match_resolver_errors_returns_1(tmp_path: Path, monkeypatch, capsys):
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": []}))

    def fake_rac():
        class M:
            def resolve_abuse_cases(self, *a, **k):
                return [], ["boom-error"]

        return M()

    monkeypatch.setattr(mac, "_rac", fake_rac)
    rc = mac.main(["match", "--output-dir", str(tmp_path)])
    assert rc == 1
    assert "boom-error" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# cmd_list_candidates — missing file
# ---------------------------------------------------------------------------


def test_list_candidates_no_matches_file(tmp_path: Path, capsys):
    rc = mac.main(["list-candidates", "--output-dir", str(tmp_path)])
    assert rc == 0
    assert capsys.readouterr().out.strip() == ""


# ---------------------------------------------------------------------------
# cmd_list_inconclusive — malformed json branches
# ---------------------------------------------------------------------------


def test_list_inconclusive_malformed_verdicts_json(tmp_path: Path, capsys):
    (tmp_path / ".abuse-case-verdicts.json").write_text("{ not json")
    rc = mac.main(["list-inconclusive", "--output-dir", str(tmp_path)])
    assert rc == 0
    assert capsys.readouterr().out.strip() == ""


def test_list_inconclusive_malformed_matches_json(tmp_path: Path, capsys):
    _write_verdicts(tmp_path, [("AC-T-002", "inconclusive")])
    (tmp_path / ".abuse-case-matches.json").write_text("{ not json")
    rc = mac.main(["list-inconclusive", "--output-dir", str(tmp_path)])
    assert rc == 0
    # malformed matches → candidates set empty → no candidate gate, lists all
    assert capsys.readouterr().out.split() == ["AC-T-002"]


def test_list_inconclusive_verdicts_as_bare_list(tmp_path: Path, capsys):
    # verdicts file is a bare list (not a {"verdicts": [...]} dict)
    (tmp_path / ".abuse-case-verdicts.json").write_text(
        json.dumps([{"abuse_case_id": "AC-T-007", "chain_verdict": "inconclusive"}])
    )
    rc = mac.main(["list-inconclusive", "--output-dir", str(tmp_path)])
    assert rc == 0
    assert capsys.readouterr().out.split() == ["AC-T-007"]


# ---------------------------------------------------------------------------
# cmd_finalize — folds step verdicts into chain verdicts on disk
# ---------------------------------------------------------------------------


def test_cmd_finalize_writes_chain_verdicts(tmp_path: Path):
    matches = {
        "schema_version": 1,
        "matches": [
            {
                "abuse_case_id": "AC-T-001",
                "step_matches": [{"step": 1, "required": True}],
            }
        ],
    }
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(matches))
    verdicts = {
        "schema_version": 1,
        "verdicts": [{"abuse_case_id": "AC-T-001", "step_verdicts": [{"step": 1, "verdict": "confirmed"}]}],
    }
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(verdicts))
    rc = mac.main(["finalize", "--output-dir", str(tmp_path)])
    assert rc == 0
    out = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    assert out["verdicts"][0]["chain_verdict"] == "fully_viable"


def test_cmd_finalize_explicit_paths_and_bare_list(tmp_path: Path):
    mp = tmp_path / "m.json"
    vp = tmp_path / "v.json"
    mp.write_text(
        json.dumps({"matches": [{"abuse_case_id": "AC-T-002", "step_matches": [{"step": 1, "required": True}]}]})
    )
    # verdicts as a bare list
    vp.write_text(json.dumps([{"abuse_case_id": "AC-T-002", "step_verdicts": [{"step": 1, "verdict": "blocked"}]}]))
    rc = mac.main(["finalize", "--matches", str(mp), "--verdicts", str(vp)])
    assert rc == 0
    out = json.loads(vp.read_text())
    assert out["verdicts"][0]["chain_verdict"] == "mitigated"


def test_cmd_finalize_unknown_case_uses_empty_step_matches(tmp_path: Path):
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps({"matches": []}))
    (tmp_path / ".abuse-case-verdicts.json").write_text(
        json.dumps({"verdicts": [{"abuse_case_id": "AC-T-099", "step_verdicts": []}]})
    )
    rc = mac.main(["finalize", "--output-dir", str(tmp_path)])
    assert rc == 0
    out = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    assert out["verdicts"][0]["chain_verdict"] == "not_applicable"
