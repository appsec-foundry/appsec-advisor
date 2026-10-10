"""Tests for scripts/model/match_abuse_cases.py — the deterministic matcher.

Covers sink/control matching, scope-qualifier gating, and the structural
verdict (candidate / partial_candidate / not_applicable).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "model/match_abuse_cases.py"


def _load():
    if "model.match_abuse_cases" in sys.modules:
        return sys.modules["model.match_abuse_cases"]
    spec = importlib.util.spec_from_file_location("model.match_abuse_cases", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["model.match_abuse_cases"] = mod
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


def test_absent_control_evidence_is_not_a_control_found():
    # Regression (2026-07-25): `controls_absent_evidence` documents controls the
    # finding proves are MISSING. Probing it for controls PRESENT inverted the
    # signal — a finding evidencing "no DomSanitizer anywhere" was recorded as
    # having found DomSanitizer, which then downgraded the abuse chain to
    # partially_blocked. Only `controls_in_place` may feed this probe.
    finding = _finding("T-001", "innerHTML sink", controls="")
    finding["controls_absent_evidence"] = [{"pattern": "DomSanitizer", "search_paths": ["src/"], "hit_count": 0}]
    m = mac.match_step(_step(1, "innerHTML", controls=["DomSanitizer"]), [finding])
    assert m["matched"]
    assert m["controls_found"] == []


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


def test_declared_cwe_step_rejects_unrelated_generic_escalation_prose():
    idor = {
        "t_id": "T-008",
        "title": "Insecure Direct Object Reference",
        "scenario": "Attacker-controlled ownership permits horizontal privilege escalation.",
        "cwe": "CWE-639",
        "evidence": {"file": "routes/object.ts", "line": 11},
    }
    step = _step(1, "CWE-(915|266|269)")
    step["finding"] = {"cwe": "CWE-915"}
    step["probe"]["sink_patterns"].append("(?i)(role|privilege|admin) escalation")

    matched = mac.match_step(step, [idor])

    assert matched["matched"] is False
    assert matched["matched_finding_id"] is None


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


@pytest.mark.parametrize(
    "file",
    [".github/workflows/ci.yml", "docs/runbooks/deploy.md", "tests/fixtures/accounts.ts"],
)
def test_step_never_binds_a_finding_outside_the_runtime_surface(file):
    """A privilege CWE on a CI, documentation, or test finding is not the
    application step it names; the same CWE in runtime code still binds."""
    step = _step(1, "CWE-(915|266|269)")
    step["finding"] = {"cwe": "CWE-915"}
    elsewhere = dict(_finding("T-045", "Workflow grants write permissions", file=file, line=1), cwe="CWE-915")
    runtime = dict(_finding("T-070", "Account model persists any request field", file="api/accounts.py"), cwe="CWE-915")

    assert not mac.match_step(step, [elsewhere])["matched"]
    assert mac.match_step(step, [elsewhere, runtime])["matched_finding_id"] == "T-070"


def test_a_lone_family_only_match_is_not_bound():
    """A finding that shares only the declared step CWE's family is not the
    step, even without a competitor; the step's own CWE or a mechanism phrase
    still binds, and so does a family match in a file the chain runs through."""
    step = _step(2, "CWE-(863|862|266|269)")
    step["probe"]["sink_patterns"].append("req\\.user\\.role")
    step["finding"] = {"cwe": "CWE-863"}
    coupon = dict(_finding("T-046", "Tool call lacks a discount ceiling", file="routes/assistant.py"), cwe="CWE-862")
    own_cwe = dict(_finding("T-020", "Admin route trusts the token", file="app/admin.go"), cwe="CWE-863")
    mechanism = dict(
        _finding("T-021", "Handler reads req.user.role from the token", file="app/admin.go"), cwe="CWE-862"
    )

    assert not mac.match_step(step, [coupon])["matched"]
    assert mac.match_step(step, [coupon, own_cwe])["matched_finding_id"] == "T-020"
    assert mac.match_step(step, [coupon, mechanism])["matched_finding_id"] == "T-021"
    assert mac.match_step(step, [coupon], prefer_files=frozenset({"routes/assistant.py"}))["matched"]


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


def test_generic_injection_cwe_needs_code_execution_mechanism_evidence():
    """CWE-74 state injection must not create a server-side RCE candidate."""
    wallet_state_injection = {
        "t_id": "T-016",
        "title": "Unauthenticated wallet injection into challenge state",
        "scenario": "An attacker adds an arbitrary address to an in-memory wallet set.",
        "cwe": "CWE-74",
        "evidence": {"file": "routes/web3Wallet.ts", "line": 16},
    }
    execution_sink = {
        "t_id": "T-017",
        "title": "Server-side template injection permits remote code execution",
        "scenario": "User input reaches an unsafe template interpreter.",
        "cwe": "CWE-74",
        "evidence": {"file": "routes/render.ts", "line": 28},
    }
    step = _step(1, "CWE-(94|95|917|1336|502|74)", grants="code_execution")
    step["finding"] = {"cwe": "CWE-94"}
    step["probe"]["sink_patterns"].append("(?i)(remote code execution|\\bRCE\\b)")
    step["probe"]["sink_patterns"].append("(?i)(template injection|\\bSSTI\\b)")

    assert not mac.match_step(step, [wallet_state_injection])["matched"]
    assert mac.match_step(step, [execution_sink])["matched_finding_id"] == "T-017"


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


@pytest.mark.parametrize(
    ("key_file", "signer_file", "expected"),
    [
        ("lib/insecurity.ts", "lib/insecurity.ts", "T-KEY"),
        ("src/auth/keys.py", "src/auth/keys.py", "T-KEY"),
        ("lib/insecurity.ts", "lib/other.ts", "T-CRED"),
    ],
    ids=["shared-file", "neutral-names", "no-shared-file"],
)
def test_equal_score_step_binds_the_finding_its_chain_runs_through(key_file, signer_file, expected):
    """A declared step CWE names a class; a sibling step's file shows the path."""
    credential = {"t_id": "T-CRED", "title": "Wallet seed in source", "cwe": "CWE-798", "evidence": {"file": "w.ts"}}
    key = {"t_id": "T-KEY", "title": "Signing key in source", "cwe": "CWE-321", "evidence": {"file": key_file}}
    signer = _finding("T-SIGN", "token forgery with the embedded key", file=signer_file)
    step1 = _step(1, "CWE-(798|321)")
    step1["finding"] = {"cwe": "CWE-798"}
    case = _case([step1, _step(2, "token forgery", requires="state")])

    result = mac.match_case(case, [credential, key, signer], None)

    assert result["matched_finding_ids"] == [expected, "T-SIGN"]


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


def test_default_registration_case_uses_canonical_open_registration_signal():
    cases, errors = mac._rac().resolve_abuse_cases(None, None, mac.PLUGIN_ROOT, None)
    assert errors == []
    registration = next(case for case in cases if case["id"] == "AC-T-004")

    assert registration["scope_qualifier"]["required_signals"] == [
        "has_auth_surface",
        "has_open_self_registration",
    ]


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


def test_direct_source_probe_ignores_prior_run_telemetry(tmp_path: Path):
    (tmp_path / ".agent-run.log").write_text("render(innerHTML);\n", encoding="utf-8")
    case = _case([_step(1, "innerHTML")])

    result = mac.match_case(case, [], signals=None, repo_root=tmp_path)

    assert result["structural_verdict"] == "not_applicable"
    assert result["step_matches"][0]["evidence"] is None


def test_refuted_findings_are_not_matchable_abuse_inputs():
    refuted = _finding("T-007", "mass assignment role")
    refuted["evidence_check"] = "refuted"
    verified = _finding("T-008", "ownership bypass")
    verified["evidence_check"] = "verified"

    assert mac.matchable_findings([refuted, verified]) == [verified]


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
    keys = {
        "has_public_routes",
        "has_auth_surface",
        "has_role_concept",
        "has_secrets_in_repo",
        "has_ci_pipeline",
        "has_external_apis",
        "has_client_storage",
        "has_multi_tenancy_signal",
        "has_open_self_registration",
        "has_llm_surface",
    }
    evidence = {key: {"status": "none", "locations": []} for key in keys}
    evidence["has_auth_surface"] = {
        "status": "supporting",
        "locations": [{"file": "middleware/auth.ts", "line": 12}],
    }
    signal_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "signals": {key: key == "has_auth_surface" for key in keys},
                "signal_evidence": evidence,
                "signal_classification": {"has_open_self_registration": "deterministic"},
                "component_hints": [],
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
                "schema_version": 2,
                "signals": {
                    "has_public_routes": False,
                    "has_auth_surface": True,
                    "has_role_concept": True,
                    "has_client_storage": True,
                    "has_ci_pipeline": True,
                    "has_secrets_in_repo": False,
                    "has_external_apis": False,
                    "has_multi_tenancy_signal": False,
                    "has_open_self_registration": False,
                    "has_llm_surface": False,
                },
                "signal_evidence": {
                    "has_public_routes": {"status": "none", "locations": []},
                    "has_auth_surface": {
                        "status": "supporting",
                        "locations": [{"file": "agents/phases/auth.md", "line": 12}],
                    },
                    "has_role_concept": {
                        "status": "supporting",
                        "locations": [{"file": "data/cwe-taxonomy.yaml", "line": 4}],
                    },
                    "has_client_storage": {
                        "status": "supporting",
                        "locations": [{"file": "docs/frontend-guide.md", "line": 8}],
                    },
                    "has_ci_pipeline": {
                        "status": "supporting",
                        "locations": [{"file": ".github/workflows/tests.yml", "line": 1}],
                    },
                    "has_secrets_in_repo": {"status": "none", "locations": []},
                    "has_external_apis": {"status": "none", "locations": []},
                    "has_multi_tenancy_signal": {"status": "none", "locations": []},
                    "has_open_self_registration": {"status": "none", "locations": []},
                    "has_llm_surface": {"status": "none", "locations": []},
                },
                "signal_classification": {"has_open_self_registration": "deterministic"},
                "component_hints": [],
            }
        ),
        encoding="utf-8",
    )

    assert mac._load_signals(str(signal_path)) == {"has_ci_pipeline"}


def test_load_signals_rejects_legacy_free_form_recon_evidence(tmp_path: Path):
    signal_path = tmp_path / ".recon-signals.json"
    signal_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "signals": {"has_auth_surface": True},
                "signal_evidence": {"has_auth_surface": "middleware/auth.ts:12"},
            }
        ),
        encoding="utf-8",
    )

    assert mac._load_signals(str(signal_path)) is None


def test_load_signals_treats_missing_sidecar_as_unknown_scope(tmp_path: Path):
    assert mac._load_signals(str(tmp_path / ".recon-signals.json")) is None


def test_late_registration_true_adds_canonical_signal(tmp_path: Path):
    (tmp_path / "threat-model.yaml").write_text(
        "meta:\n  open_user_registration: true\n",
        encoding="utf-8",
    )

    assert mac._effective_registration_signal({"has_auth_surface"}, tmp_path) == {
        "has_auth_surface",
        "has_open_self_registration",
    }


def test_late_registration_false_removes_stale_recon_signal(tmp_path: Path):
    (tmp_path / "threat-model.yaml").write_text(
        "meta:\n  open_user_registration: false\n",
        encoding="utf-8",
    )

    assert mac._effective_registration_signal(
        {"has_auth_surface", "has_open_self_registration"},
        tmp_path,
    ) == {"has_auth_surface"}


def test_missing_late_registration_verdict_preserves_recon_signal_state(tmp_path: Path):
    assert mac._effective_registration_signal({"has_open_self_registration"}, tmp_path) == {
        "has_open_self_registration"
    }


def test_malformed_late_registration_meta_preserves_recon_signal_state(tmp_path: Path):
    (tmp_path / "threat-model.yaml").write_text("meta: malformed\n", encoding="utf-8")

    assert mac._effective_registration_signal({"has_open_self_registration"}, tmp_path) == {
        "has_open_self_registration"
    }


# ---------------------------------------------------------------------------
# CLI: match → list-candidates round trip against the shipped library
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ids,filename", [((1, 900, 20), "src/records.py"), ((980, 120, 400), "handlers/work.go")])
def test_cli_candidates_prioritize_evidenced_risk_without_dropping_partial_cases(tmp_path, capsys, ids, filename):
    cases = [
        _case([_step(1, "record_lookup")], id=f"ORG-AC-{ids[0]:03d}"),
        _case([_step(1, "run_operation")], id=f"ORG-AC-{ids[1]:03d}"),
        _case([_step(1, "inspect_state"), _step(2, "missing_operation")], id=f"ORG-AC-{ids[2]:03d}"),
    ]
    # A declared template severity cannot override an actual linked finding.
    cases[0]["chain"][0]["finding"] = {
        "cwe": "CWE-89",
        "stride": "Tampering",
        "severity": "Critical",
        "mitigation_title": "Constrain input",
    }
    profile_dir = tmp_path / "profile"
    (profile_dir / "abuse-cases").mkdir(parents=True)
    (profile_dir / "abuse-cases" / "cases.yaml").write_text(yaml.safe_dump({"abuse_cases": cases}))
    profile_path = profile_dir / "org-profile.yaml"
    profile_path.write_text(yaml.safe_dump({"abuse_cases": {"inherit_defaults": False}}))
    findings = [
        {**_finding("T-011", "record_lookup", file=filename), "risk": "High", "cwe": "CWE-89"},
        {**_finding("T-092", "run_operation", file=filename), "risk": "Critical"},
        {**_finding("T-080", "inspect_state", file=filename), "risk": "Medium"},
    ]
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": findings}))
    assert mac.main(["match", "--output-dir", str(tmp_path), "--org-profile", str(profile_path)]) == 0
    assert mac.main(["list-candidates", "--output-dir", str(tmp_path)]) == 0
    assert capsys.readouterr().out.split() == [f"ORG-AC-{ids[i]:03d}" for i in (1, 0, 2)]
    matches = json.loads((tmp_path / ".abuse-case-matches.json").read_text())["matches"]
    assert matches[-1]["structural_verdict"] == "partial_candidate"


def test_source_probe_priority_uses_only_matched_classification():
    case = _case([_step(1, "operation"), _step(2, "other")])
    case["chain"][0]["finding"] = {"severity": "High", "cwe": "CWE-79"}
    case["chain"][1]["finding"] = {"severity": "Critical", "cwe": "CWE-94"}
    match = {
        "abuse_case_id": case["id"],
        "case": case,
        "structural_verdict": "partial_candidate",
        "step_matches": [{"step": 1, "matched": True, "match_basis": "source_probe"}, {"step": 2, "matched": False}],
    }
    assert mac._candidate_priority(match, {})[0] == -2  # High; the Critical step never matched.
    match["step_matches"][0]["matched"] = False
    assert mac._candidate_priority(match, {})[0] > 0


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


def test_list_inconclusive_skips_chains_settled_by_refutation(tmp_path: Path, capsys):
    # AC-6: re-verifying a refuted pairing cannot change it, and that step caps
    # the chain whatever its open steps show. A chain without a refuted step,
    # or with no recorded step verdicts, stays on the work-list.
    steps = {
        "AC-T-001": [{"step": 1, "verdict": "confirmed"}, {"step": 2, "verdict": "refuted"}],
        "AC-T-002": [{"step": 1, "verdict": "refuted"}, {"step": 2, "verdict": "inconclusive"}],
        "AC-T-003": [],
        "AC-T-004": [
            {"step": 1, "verdict": "inconclusive"},
            {"step": 2, "verdict": "confirmed"},
            {"step": 3, "verdict": "refuted"},
        ],
        "AC-T-005": [{"step": 1, "verdict": "confirmed"}, {"step": 2, "verdict": "inconclusive"}],
    }
    doc = {
        "schema_version": 1,
        "verdicts": [
            {"abuse_case_id": cid, "chain_verdict": "inconclusive", "step_verdicts": sv} for cid, sv in steps.items()
        ],
    }
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(doc))
    _write_matches(tmp_path, [(cid, "candidate") for cid in steps])
    mac.main(["list-inconclusive", "--output-dir", str(tmp_path)])
    assert capsys.readouterr().out.split() == ["AC-T-003", "AC-T-005"]


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


def test_finalize_refuted_step_caps_the_chain_like_inconclusive():
    # AC-6: a refuted step folds exactly like an inconclusive one in every chain
    # shape — required leg or non-required payoff, after a confirmed or a
    # blocked setup. A settled mismatch never makes a chain fully viable.
    for required in (True, False):
        cm = _cm([{"step": 1, "required": True}, {"step": 2, "required": required}])
        for setup in ("confirmed", "blocked"):
            refuted = [{"step": 1, "verdict": setup}, {"step": 2, "verdict": "refuted"}]
            open_step = [{"step": 1, "verdict": setup}, {"step": 2, "verdict": "inconclusive"}]
            assert mac.finalize_verdict(cm, refuted) == mac.finalize_verdict(cm, open_step)
        confirmed_setup = [{"step": 1, "verdict": "confirmed"}, {"step": 2, "verdict": "refuted"}]
        assert mac.finalize_verdict(cm, confirmed_setup) == "inconclusive"


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


@pytest.mark.parametrize(
    "verdicts", [("confirmed", "blocked"), ("blocked", "confirmed"), ("confirmed", "blocked", "confirmed")]
)
def test_finalize_business_chain_stopped_at_one_step_is_mitigated(verdicts):
    cm = {"kind": "descriptive", "step_matches": [{"step": n, "required": True} for n in range(1, len(verdicts) + 1)]}
    sv = [{"step": n, "verdict": v} for n, v in enumerate(verdicts, 1)]
    assert mac.finalize_verdict(cm, sv) == "mitigated"
    # A technical chain with the same steps stays partially blocked.
    assert mac.finalize_verdict(_cm(cm["step_matches"]), sv) == "partially_blocked"


@pytest.mark.parametrize("steps", [1, 2])
def test_finalize_confirmed_business_step_ignores_the_insufficient_check_beside_it(steps):
    """A confirmed business step says no control enforces its boundary; a check
    the verifier lists beside it does not turn the case partially blocked."""
    cm = {"kind": "descriptive", "step_matches": [{"step": n, "required": True} for n in range(1, steps + 1)]}
    sv = [{"step": n, "verdict": "confirmed", "controls_found": ["role check only"]} for n in range(1, steps + 1)]
    assert mac.finalize_verdict(cm, sv) == "fully_viable"
    # A technical chain still treats a listed control as impeding it.
    assert mac.finalize_verdict(_cm(cm["step_matches"]), sv) == "partially_blocked"


def test_finalize_business_chain_with_an_open_step_stays_inconclusive():
    cm = {"kind": "descriptive", "step_matches": [{"step": 1, "required": True}, {"step": 2, "required": True}]}
    sv = [{"step": 1, "verdict": "blocked"}, {"step": 2, "verdict": "inconclusive"}]
    assert mac.finalize_verdict(cm, sv) == "inconclusive"


def test_finalize_missing_verdict_defaults_inconclusive():
    cm = _cm([{"step": 1, "required": True}])
    # no step_verdict provided → defaults to inconclusive
    assert mac.finalize_verdict(cm, []) == "inconclusive"


def test_finalize_non_required_untouched_preseed_caps_at_inconclusive():
    # Regression (2026-07-16 juice-shop AC-T-003): a step left as an untouched
    # write-first pre-seed (inconclusive, no reason, no excerpt) on a NON-required
    # leg was silently dropped by the required-only scan, so the chain wrongly
    # finalized fully_viable — while the identical AC-T-002 with a REQUIRED step 2
    # correctly read inconclusive. The verdict must be a pure function of the step
    # verdicts: an unverified step caps the chain at inconclusive regardless of the
    # matcher's `required` flag.
    cm = _cm([{"step": 1, "required": True}, {"step": 2, "required": False}])
    sv = [
        {"step": 1, "verdict": "confirmed", "reason": "no ownership check"},
        {"step": 2, "verdict": "inconclusive"},  # untouched pre-seed: no reason/excerpt
    ]
    assert mac.finalize_verdict(cm, sv) == "inconclusive"


def test_finalize_non_required_reasoned_inconclusive_caps_at_inconclusive():
    # Regression (2026-07-25 insecure-spring-app AC-T-005): a REASONED inconclusive
    # on a non-required leg used to stand as fully_viable, on the theory that the
    # attack is still viable through the required path. Every `required: false`
    # step in data/abuse-cases is the chain's PAYOFF, not an optional side leg, so
    # that theory inverts the risk: AC-T-005 step 1 confirmed (signing key
    # hardcoded in the Dockerfile) + step 2 inconclusive (SignedJwtService uses a
    # random in-memory key, so the exposed secret is not the one the server
    # trusts) shipped as "Fully viable · Critical". fully_viable is a positive
    # end-to-end claim and must not survive an unresolved step anywhere.
    cm = _cm([{"step": 1, "required": True}, {"step": 2, "required": False}])
    sv = [
        {"step": 1, "verdict": "confirmed"},
        {"step": 2, "verdict": "inconclusive", "reason": "control present but bypass unclear"},
    ]
    assert mac.finalize_verdict(cm, sv) == "inconclusive"


def test_finalize_verifier_empty_controls_overrides_matcher_preseed():
    # Regression (2026-07-25 insecure-spring-app AC-T-002): the matcher's static
    # keyword probe pre-seeded controls_found=['ownership'] from finding prose that
    # NEGATED the control ("None on the detail page — edit and delete use
    # loadAllowedOrder() which does enforce ownership"). The verifier read the
    # source, reported controls_found=[] and confirmed both steps, but the OR with
    # the stale guess still downgraded the chain to partially_blocked. An explicit
    # (even empty) verifier list is authoritative for that step.
    cm = _cm(
        [
            {"step": 1, "required": True, "controls_found": ["ownership"]},
            {"step": 2, "required": True, "controls_found": []},
        ]
    )
    sv = [
        {"step": 1, "verdict": "confirmed", "controls_found": []},
        {"step": 2, "verdict": "confirmed", "controls_found": []},
    ]
    assert mac.finalize_verdict(cm, sv) == "fully_viable"


def test_finalize_verifier_control_overrides_empty_matcher_preseed():
    # The override cuts both ways: a control the verifier found but the matcher's
    # probe missed must downgrade the chain, not be lost.
    cm = _cm([{"step": 1, "required": True, "controls_found": []}])
    sv = [{"step": 1, "verdict": "confirmed", "controls_found": ["csrf-token"]}]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


def test_finalize_matcher_preseed_used_when_verifier_silent_on_controls():
    # The matcher hint remains the only signal when the verifier never spoke about
    # controls for that step (key absent, not merely empty) — keep using it.
    cm = _cm([{"step": 1, "required": True, "controls_found": ["ownership"]}])
    sv = [{"step": 1, "verdict": "confirmed"}]
    assert mac.finalize_verdict(cm, sv) == "partially_blocked"


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

    real = mac._rac()

    def fake_rac():
        class M:
            load_limits = staticmethod(real.load_limits)

            def resolve_abuse_case_sources(self, *a, **k):
                return [], ["boom-error"], []

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


def _shipped_case(case_id: str) -> dict:
    import yaml

    library = yaml.safe_load((REPO_ROOT / "data" / "abuse-cases" / "default-library.yaml").read_text(encoding="utf-8"))
    return next(case for case in library["abuse_cases"] if case["id"] == case_id)


def test_the_llm_abuse_case_is_gated_on_the_llm_signal():
    """Without a structured signal the chain could never be selected.

    LLM risk reached the report only through findings on a modelled component,
    so a target whose model surface was never modelled produced no
    prompt-injection chain at all. The signal is what lets the library gate one.
    """
    case = _shipped_case("AC-T-007")
    assert case["scope_qualifier"]["required_signals"] == ["has_llm_surface"]

    findings = [_finding("T-001", "prompt injection reaches the system prompt")]
    blocked = mac.match_case(case, findings, {"has_auth_surface"})
    assert blocked["structural_verdict"] == "not_applicable"
    assert "has_llm_surface" in (blocked.get("unmet_signals") or [])

    allowed = mac.match_case(case, findings, {"has_llm_surface"})
    assert "has_llm_surface" not in (allowed.get("unmet_signals") or [])


def test_the_llm_signal_is_part_of_the_recon_contract():
    """The gate is only real if the producer can set it and the schema knows it."""
    import json

    schema = json.loads((REPO_ROOT / "schemas" / "recon-signals.schema.json").read_text(encoding="utf-8"))
    assert "has_llm_surface" in schema["properties"]["signals"]["required"]
    assert "has_llm_surface" in schema["properties"]["signal_evidence"]["required"]

    prompt = (REPO_ROOT / "agents" / "appsec-recon-scanner.md").read_text(encoding="utf-8")
    assert "has_llm_surface" in prompt
    assert "A declared dependency alone is not enough" in prompt, "the tag needs its false-positive exclusion"


def _prompt_injection_control_patterns():
    import yaml

    library = yaml.safe_load((REPO_ROOT / "data" / "abuse-cases" / "default-library.yaml").read_text(encoding="utf-8"))
    case = next(row for row in library["abuse_cases"] if row["id"] == "AC-T-007")
    return case["chain"][0]["probe"]["control_patterns"]


def test_a_prompt_level_guardrail_is_not_a_control_for_prompt_injection():
    """A rule that exists only as prompt text is not a boundary, so the word
    `guardrail` in a controls description must not mark the step guarded and
    blunt the finding. Controls that live outside the prompt still count."""
    patterns = _prompt_injection_control_patterns()
    step = _step(1, "prompt.*inject", controls=patterns)
    prompt_only = _finding("T-001", "prompt injection sink", controls="System prompt states a guardrail")
    assert mac.match_step(step, [prompt_only])["controls_found"] == []

    for real_control in ("Input is sanitized before assembly", "Instruction hierarchy separates the channels"):
        finding = _finding("T-002", "prompt injection sink", controls=real_control)
        assert mac.match_step(step, [finding])["controls_found"], real_control


# ---------------------------------------------------------------------------
# Descriptive (business) cases: preselection, limits, evidence admission
# ---------------------------------------------------------------------------


def _descriptive(cid="REPO-AC-020", patterns=("**/roles/**",), signals=None):
    qualifier = {"path_patterns": list(patterns)} if patterns else {}
    if signals:
        qualifier["required_signals"] = list(signals)
    return {
        "id": cid,
        "kind": "descriptive",
        "title": "Delegated administrator grants themselves a role",
        "actor": "Delegated administrator",
        "initial_access": "authenticated_high_priv",
        "goal": "Obtain a role outside the delegation.",
        "boundary": "Roles the delegation permits.",
        "steps": ["Assign a role to themselves.", "Choose a role outside the delegation."],
        "expected_controls": ["The assignment checks the delegation."],
        "scope_qualifier": qualifier,
    }


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src" / "roles").mkdir(parents=True)
    (repo / "src" / "roles" / "assign.ts").write_text(
        "export async function assign(req, res) {\n"
        "  const user = await Users.find(req.body.userId);\n"
        "  user.roles.push(req.body.role);\n"
        "  await user.save();\n"
        "}\n"
    )
    (repo / "docs" / "roles").mkdir(parents=True)
    (repo / "docs" / "roles" / "guide.md").write_text("roles guide\n")
    return repo


def test_descriptive_case_is_preselected_from_runtime_paths(tmp_path: Path):
    repo = _repo(tmp_path)
    finding = _finding("F-001", "role update", file="src/roles/assign.ts", line=3)
    m = mac.match_case(_descriptive(), [finding], None, repo_root=repo)
    assert m["structural_verdict"] == "candidate"
    assert m["preselected_sources"] == ["src/roles/assign.ts"]
    assert m["related_finding_ids"] == ["F-001"]
    assert [s["label"] for s in m["step_matches"]] == _descriptive()["steps"]
    assert not any(s["matched"] for s in m["step_matches"])


def test_descriptive_preselection_admits_only_executable_source(tmp_path: Path):
    repo = _repo(tmp_path)
    for name in ("roles.component.scss", "roles.component.html", "roles.md.bak", "roles.component.ts"):
        (repo / "src" / "roles" / name).write_text("x\n")
    m = mac.match_case(_descriptive(), [], None, repo_root=repo)
    assert m["preselected_sources"] == ["src/roles/assign.ts", "src/roles/roles.component.ts"]


def test_descriptive_case_with_only_documentation_hits_is_not_applicable(tmp_path: Path):
    repo = _repo(tmp_path)
    m = mac.match_case(_descriptive(patterns=("docs/**",)), [], None, repo_root=repo)
    assert m["structural_verdict"] == "not_applicable"
    assert "no runtime source path matched" in m["reason"]


def test_descriptive_case_respects_required_signals(tmp_path: Path):
    repo = _repo(tmp_path)
    case = _descriptive(signals=["has_role_concept"])
    assert mac.match_case(case, [], {"has_auth_surface"}, repo_root=repo)["structural_verdict"] == "not_applicable"
    assert mac.match_case(case, [], {"has_role_concept"}, repo_root=repo)["structural_verdict"] == "candidate"


def _located_repo(tmp_path: Path) -> Path:
    """Handlers whose file names carry no case vocabulary, so only routes or detectors can locate them."""
    repo = tmp_path / "repo"
    (repo / "app" / "handlers").mkdir(parents=True)
    for name in ("grants.py", "billing.py"):
        (repo / "app" / "handlers" / name).write_text("def handle(request):\n    return request.json\n")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_grants.py").write_text("def test_x():\n    pass\n")
    return repo


def _route(path: str, handler: str) -> dict:
    return {"path": path, "handler_file": handler, "method": "POST"}


def _locating(**qualifier) -> dict:
    case = _descriptive(patterns=None)
    case["scope_qualifier"] = qualifier
    return case


def test_a_route_pattern_preselects_the_handler_of_a_matching_route(tmp_path: Path):
    repo = _located_repo(tmp_path)
    routes = [
        _route("/api/Members/:id/ROLES", "app/handlers/grants.py"),
        _route("/api/invoices", "app/handlers/billing.py"),
    ]
    m = mac.match_case(_locating(route_patterns=["*/roles*"]), [], None, repo_root=repo, routes=routes)
    assert m["structural_verdict"] == "candidate"
    assert m["preselected_sources"] == ["app/handlers/grants.py"]


def test_a_detector_rule_preselects_the_file_of_its_finding_and_relates_the_finding(tmp_path: Path):
    repo = _located_repo(tmp_path)
    flagged = _finding("F-004", "privileged field bound from request", file="app/handlers/billing.py", line=2)
    flagged["source_check_id"] = "AUTHZ-003"
    other = _finding("F-005", "unrelated", file="app/handlers/grants.py", line=2)
    other["source_check_id"] = "INJ-001"
    m = mac.match_case(_locating(detector_rules=["AUTHZ-003", "AUTHZ-008"]), [flagged, other], None, repo_root=repo)
    assert m["preselected_sources"] == ["app/handlers/billing.py"]
    assert m["related_finding_ids"] == ["F-004"]


def test_locators_never_admit_files_outside_runtime_source(tmp_path: Path):
    repo = _located_repo(tmp_path)
    routes = [_route("/roles", "tests/test_grants.py"), _route("/roles", "../outside/grants.py")]
    flagged = _finding("F-006", "test fixture", file="tests/test_grants.py", line=1)
    flagged["source_check_id"] = "AUTHZ-003"
    case = _locating(route_patterns=["/roles"], detector_rules=["AUTHZ-003"])
    m = mac.match_case(case, [flagged], None, repo_root=repo, routes=routes)
    assert m["structural_verdict"] == "not_applicable"
    assert "no route matched" in m["reason"] and "AUTHZ-003" in m["reason"]


def test_a_route_only_case_without_a_route_inventory_is_not_preselected(tmp_path: Path):
    m = mac.match_case(_locating(route_patterns=["*role*"]), [], None, repo_root=_located_repo(tmp_path), routes=None)
    assert m["structural_verdict"] == "not_applicable"
    assert m["reason"] == "route inventory unavailable"


def test_any_locator_suffices_while_required_signals_still_gate(tmp_path: Path):
    repo = _located_repo(tmp_path)
    routes = [_route("/admin/roles", "app/handlers/grants.py")]
    case = _locating(
        route_patterns=["*role*"], path_patterns=["**/permissions/**"], required_signals=["has_role_concept"]
    )
    assert (
        mac.match_case(case, [], {"has_role_concept"}, repo_root=repo, routes=routes)["structural_verdict"]
        == "candidate"
    )
    assert mac.match_case(case, [], {"has_auth_surface"}, repo_root=repo, routes=routes)["structural_verdict"] == (
        "not_applicable"
    )


def test_cli_reads_routes_from_the_route_inventory(tmp_path: Path):
    (tmp_path / ".route-inventory.json").write_text(
        json.dumps({"routes": [_route("/x/roles", "app/a.py"), {"path": 3}, "bad"]}), encoding="utf-8"
    )
    assert mac.load_routes(tmp_path) == [_route("/x/roles", "app/a.py")]
    assert mac.load_routes(tmp_path / "missing") is None


def _candidates(n: int) -> list[dict]:
    return [
        {
            "abuse_case_id": f"REPO-AC-{100 + i}",
            "kind": "descriptive",
            "structural_verdict": "candidate",
            "related_finding_ids": [],
            "preselected_sources": ["a"] * i,
        }
        for i in range(n)
    ]


def test_descriptive_limits_follow_depth_and_record_omissions():
    limits = {
        "descriptive_candidates_standard": 2,
        "descriptive_candidates_thorough": 4,
        "descriptive_candidates_explicit": 1,
    }
    for depth, expected in (("quick", 0), ("standard", 2), ("thorough", 4)):
        matches = _candidates(5)
        mac.apply_descriptive_limits(matches, set(), depth, limits)
        kept = [m for m in matches if m["structural_verdict"] == "candidate"]
        assert len(kept) == expected, depth
        # Strongest preselection evidence wins.
        assert {m["abuse_case_id"] for m in kept} == {f"REPO-AC-{100 + i}" for i in range(4, 4 - expected, -1)}
        omitted = [m for m in matches if m["structural_verdict"] == "not_performed"]
        assert len(omitted) == 5 - expected and all(m["reason"] for m in omitted)


def test_explicit_request_runs_at_quick_depth_even_without_preselection():
    limits = {
        "descriptive_candidates_standard": 0,
        "descriptive_candidates_thorough": 0,
        "descriptive_candidates_explicit": 1,
    }
    matches = _candidates(1)
    matches[0]["structural_verdict"] = "not_applicable"
    matches[0]["reason"] = "required signal(s) absent: has_role_concept"
    second = dict(_candidates(1)[0], abuse_case_id="REPO-AC-200")
    matches.append(second)
    mac.apply_descriptive_limits(matches, {"REPO-AC-100", "REPO-AC-200"}, "quick", limits)
    verdicts = {m["abuse_case_id"]: m["structural_verdict"] for m in matches}
    assert sorted(verdicts.values()) == ["candidate", "not_performed"]
    assert all(m["requested"] for m in matches)
    assert "explicitly requested" in next(m["reason"] for m in matches if m["abuse_case_id"] == "REPO-AC-100")


def test_probe_cases_are_untouched_by_descriptive_limits():
    probe = {"abuse_case_id": "AC-T-001", "structural_verdict": "candidate"}
    mac.apply_descriptive_limits(
        [probe],
        set(),
        "quick",
        {
            "descriptive_candidates_standard": 0,
            "descriptive_candidates_thorough": 0,
            "descriptive_candidates_explicit": 0,
        },
    )
    assert probe == {"abuse_case_id": "AC-T-001", "structural_verdict": "candidate"}


def _dstep(n, verdict, file="src/roles/assign.ts", line=3, excerpt="user.roles.push(req.body.role);"):
    return {
        "step": n,
        "verdict": verdict,
        "state": "decided",
        "reason": "r",
        "evidence": {"file": file, "line": line, "excerpt": excerpt},
    }


def test_descriptive_evidence_admission(tmp_path: Path):
    repo = _repo(tmp_path)
    verdict = {
        "abuse_case_id": "REPO-AC-020",
        "step_verdicts": [
            _dstep(1, "confirmed"),
            _dstep(2, "blocked", excerpt="checkDelegation(req.user, role)"),
            _dstep(3, "confirmed"),
        ],
    }
    mac.admit_descriptive_evidence(verdict, 2, repo)
    steps = verdict["step_verdicts"]
    assert [s["step"] for s in steps] == [1, 2]
    assert steps[0]["verdict"] == "confirmed"
    assert steps[1]["verdict"] == "inconclusive"
    assert steps[1]["evidence"] is None and steps[1]["rejected_evidence"]["excerpt"].startswith("checkDelegation")
    assert steps[1]["reason"].startswith("evidence not admitted (excerpt does not occur near src/roles/assign.ts:3)")


@pytest.mark.parametrize(
    "evidence",
    [
        {"file": "docs/roles/guide.md", "line": 1, "excerpt": "roles guide"},
        {"file": "../outside.ts", "line": 1, "excerpt": "x"},
        {"file": "/etc/passwd", "line": 1, "excerpt": "root"},
        {"file": "src/roles/assign.ts", "line": 0, "excerpt": "user"},
        {"file": "src/roles/missing.ts", "line": 1, "excerpt": "x"},
        None,
    ],
)
def test_descriptive_evidence_outside_runtime_source_is_not_admitted(tmp_path: Path, evidence):
    repo = _repo(tmp_path)
    verdict = {"step_verdicts": [{"step": 1, "verdict": "refuted", "reason": "r", "evidence": evidence}]}
    mac.admit_descriptive_evidence(verdict, 1, repo)
    assert verdict["step_verdicts"][0]["verdict"] == "inconclusive"


def test_cli_match_reports_rejected_repo_files_and_keeps_the_library(tmp_path: Path, capsys):
    repo = _repo(tmp_path)
    case_dir = repo / ".appsec" / "abuse-cases"
    case_dir.mkdir(parents=True)
    (case_dir / "broken.yaml").write_text("abuse_cases: [1]\n")
    (case_dir / "business.yaml").write_text(yaml.safe_dump({"schema_version": 2, "abuse_cases": [_descriptive()]}))
    out = tmp_path / "out"
    out.mkdir()
    (out / ".threats-merged.json").write_text(json.dumps({"threats": []}))
    assert mac.main(["match", "--output-dir", str(out), "--repo-root", str(repo)]) == 0
    doc = json.loads((out / ".abuse-case-matches.json").read_text())
    assert [r["path"] for r in doc["rejected_case_files"]] == [".appsec/abuse-cases/broken.yaml"]
    by_id = {m["abuse_case_id"]: m for m in doc["matches"]}
    assert "AC-T-001" in by_id
    assert by_id["REPO-AC-020"]["structural_verdict"] == "candidate"
    assert "REJECTED: .appsec/abuse-cases/broken.yaml" in capsys.readouterr().err


def test_cli_finalize_admits_descriptive_evidence_from_configured_repo(tmp_path: Path):
    repo = _repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    (out / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo)}))
    match = mac.match_case(_descriptive(), [], None, repo_root=repo)
    (out / ".abuse-case-matches.json").write_text(json.dumps({"matches": [match]}))
    steps = [_dstep(1, "confirmed"), _dstep(2, "confirmed", excerpt="not in the file")]
    (out / ".abuse-case-verdicts.json").write_text(
        json.dumps({"verdicts": [{"abuse_case_id": "REPO-AC-020", "step_verdicts": steps}]})
    )
    assert mac.main(["finalize", "--output-dir", str(out)]) == 0
    verdict = json.loads((out / ".abuse-case-verdicts.json").read_text())["verdicts"][0]
    assert verdict["step_verdicts"][1]["verdict"] == "inconclusive"
    assert verdict["chain_verdict"] == "inconclusive"


def test_a_router_file_from_the_route_inventory_never_displaces_specific_files(tmp_path: Path):
    repo = _located_repo(tmp_path)
    (repo / "app" / "server.py").write_text("routes = []\n")
    routes = [_route("/roles", "app/server.py")]
    case = _locating(route_patterns=["/roles"], path_patterns=["**/grants.py"])
    m = mac.match_case(case, [], None, repo_root=repo, max_descriptive_files=1, routes=routes)
    assert m["preselected_sources"] == ["app/handlers/grants.py"]
