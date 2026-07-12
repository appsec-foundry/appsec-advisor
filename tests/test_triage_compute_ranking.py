"""Smoke tests for triage_compute_ranking.

Coverage: feature-flag gate, basic ranking computation, edge cases (no
threats, missing categories, schema-drift on security_controls)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "triage_compute_ranking.py"


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _minimal_yaml(threats: list[dict]) -> dict:
    return {
        "meta": {"analysis_version": 2, "plugin_version": "test"},
        "components": [],
        "threats": threats,
        "mitigations": [],
        "security_controls": [],
        "attack_surface": {"unauthenticated": [], "authenticated": []},
        "assets": [],
        "trust_boundaries": [],
        "use_cases": [],
        "critical_findings": [],
        "owasp_coverage": [],
        "triage_summary": {},
        "changelog": [],
    }


def _run(
    output_dir: Path, env_extra: dict | None = None, extra_args: list[str] | None = None
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(env_extra or {})
    cmd = [sys.executable, str(SCRIPT), str(output_dir), *(extra_args or [])]
    return subprocess.run(cmd, env=env, capture_output=True, text=True)


def test_feature_flag_default_off(tmp_path: Path) -> None:
    """Without APPSEC_TRIAGE_DETERMINISTIC=1 the script no-ops cleanly."""
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml([]))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": ""})
    assert res.returncode == 0
    assert "feature flag" in res.stdout.lower()
    assert not (tmp_path / ".triage-flags.json").is_file()


def test_empty_threats_emits_empty_block(tmp_path: Path) -> None:
    """Zero-threat run produces a v2 ranking block but no rankings."""
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml([]))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 0, res.stderr
    flags = json.loads((tmp_path / ".triage-flags.json").read_text())
    assert flags["version"] == 2
    assert "ranking" in flags
    assert flags["ranking"]["reconciliation_summary"]["chains_active"] == 0


def test_create_fallback_is_schema_valid(tmp_path: Path) -> None:
    """When compute_ranking is the create-owner (the pre-flight writer
    triage_validate_ratings.py never ran, so no .triage-flags.json exists), the
    file it writes must still satisfy schemas/triage-flags.schema.yaml — i.e.
    carry root `generated_at` and a populated `summary`. Regression for the
    2026-06-28 e2e failure where the fallback emitted an empty `summary` / no
    `generated_at`, so validate_intermediate.py rejected it."""
    threats = [
        {
            "t_id": "F-001",
            "title": "X",
            "primary_cwe": "CWE-89",
            "risk": "High",
            "impact": "High",
            "likelihood": "Medium",
            "scenario": "s",
            "evidence": {"file": "a.ts", "line": 1},
        },
    ]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    assert not (tmp_path / ".triage-flags.json").is_file()  # create-owner path
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 0, res.stderr
    flags = json.loads((tmp_path / ".triage-flags.json").read_text())
    assert flags.get("generated_at"), "root generated_at missing"
    summary = flags.get("summary") or {}
    for key in ("total_flags", "warnings", "info", "threats_reviewed"):
        assert key in summary, f"summary.{key} missing"
    assert summary["threats_reviewed"] == 1
    assert summary["total_flags"] == len(flags.get("flags") or [])
    # Cross-check against the authoritative schema validator.
    val = subprocess.run(
        [
            sys.executable,
            str(PLUGIN_ROOT / "scripts" / "validate_intermediate.py"),
            "triage_flags",
            str(tmp_path / ".triage-flags.json"),
        ],
        capture_output=True,
        text=True,
    )
    assert val.returncode == 0, f"schema-invalid fallback:\n{val.stdout}\n{val.stderr}"


def test_basic_ranking_with_two_findings(tmp_path: Path) -> None:
    threats = [
        {
            "t_id": "F-001",
            "title": "SQL Injection in /login",
            "primary_cwe": "CWE-89",
            "risk": "Critical",
            "impact": "Critical",
            "likelihood": "High",
            "cvss_v3_1": {"score": 9.8},
            "scenario": "Attacker submits crafted password to /rest/user/login...",
            "evidence": {"file": "routes/login.ts", "line": 34},
        },
        {
            "t_id": "F-002",
            "title": "Verbose error messages",
            "primary_cwe": "CWE-209",
            "risk": "High",
            "impact": "Low",
            "likelihood": "Medium",
            "cvss_v3_1": {"score": 4.3},
            "scenario": "Stack traces leak in 500 responses.",
            "evidence": {"file": "lib/error.ts"},
        },
    ]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 0, res.stderr
    flags = json.loads((tmp_path / ".triage-flags.json").read_text())
    ranked = flags["ranking"]["views"]["top_findings"]["findings_ranked"]
    assert len(ranked) == 2
    # Critical SQLi must outrank Medium info-disclosure
    assert ranked[0]["id"] == "F-001"
    assert ranked[0]["effective_severity"] == "Critical"
    # CWE-209 ranking-cap should NOT prevent High but should limit it
    assert ranked[1]["id"] == "F-002"


def test_yaml_augmented_with_effective_fields(tmp_path: Path) -> None:
    threats = [
        {
            "t_id": "F-001",
            "title": "Test",
            "primary_cwe": "CWE-89",
            "risk": "Critical",
            "impact": "Critical",
            "likelihood": "High",
            "scenario": "test",
        }
    ]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 0
    augmented = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    t = augmented["threats"][0]
    assert "effective_severity" in t
    assert "breach_distance" in t
    assert "chain_role" in t


def test_missing_yaml_returns_error(tmp_path: Path) -> None:
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 1
    assert "missing" in res.stderr.lower()


def test_dry_run_does_not_write(tmp_path: Path) -> None:
    threats = [{"t_id": "F-001", "title": "Test", "primary_cwe": "CWE-89", "risk": "Critical"}]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    env = dict(os.environ)
    env["APPSEC_TRIAGE_DETERMINISTIC"] = "1"
    res = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path), "--dry-run"], env=env, capture_output=True, text=True
    )
    assert res.returncode == 0
    assert not (tmp_path / ".triage-flags.json").is_file()


def test_refuted_keystone_not_elevated() -> None:
    """M2: a finding marked evidence_check=refuted must NOT receive
    chain-elevation. Raw risk is preserved (no downgrade), but the
    keystone semantics that would normally promote High → Critical are
    suppressed because the evidence-verifier could not confirm the
    cited weakness exists.
    """
    sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
    import triage_compute_ranking as tcr  # type: ignore[import-not-found]

    caps = {"contributor_cap": {"default": "High"}}
    criteria = {
        "never_individual_critical": [],
        "always_critical_cwes": [],
        "conditional_critical": {},
    }
    refuted = {"risk": "High", "evidence_check": "refuted", "primary_cwe": "CWE-89"}
    eff, reasons = tcr._compute_effective(refuted, "keystone", 4, caps, criteria, 2)
    assert eff == "High", f"refuted keystone must not elevate; got {eff}"
    assert any("suppressed:evidence_refuted" in r for r in reasons)

    # Control: same shape without refutation does get elevated.
    intact = {"risk": "High", "primary_cwe": "CWE-89"}
    eff2, reasons2 = tcr._compute_effective(intact, "keystone", 4, caps, criteria, 2)
    assert eff2 == "Critical"
    assert any("elevated:keystone" in r for r in reasons2)


def test_always_critical_cwe_promotes_under_context() -> None:
    """always_critical_cwes must PROMOTE an under-scored finding to Critical
    when the required context holds — e.g. a CWE-915 mass assignment reaching
    role=admin on an UNAUTHENTICATED endpoint that the auditor scored
    High×High=High (juice-shop T-012). Pre-2026-05-31 the gate only kept /
    de-escalated an already-Critical finding, so this stayed High forever.
    """
    sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
    import triage_compute_ranking as tcr  # type: ignore[import-not-found]

    caps = {"contributor_cap": {"default": "High"}}
    criteria = {
        "never_individual_critical": [],
        "always_critical_cwes": [
            {"cwe": "CWE-915", "required": {"breach_distance_max": 1, "impact_min": "High"}},
        ],
        "conditional_critical": {},
    }
    # Context holds: unauthenticated (breach_distance 1), impact High → promote.
    mass = {"risk": "High", "impact": "High", "primary_cwe": "CWE-915"}
    eff, reasons = tcr._compute_effective(mass, None, 0, caps, criteria, 1)
    assert eff == "Critical", f"CWE-915 on unauth endpoint must promote; got {eff}"
    assert any("always_crit_promoted:CWE-915" in r for r in reasons)

    # Context fails: deeper / authenticated (breach_distance 3) → stays High.
    mass2 = {"risk": "High", "impact": "High", "primary_cwe": "CWE-915"}
    eff2, reasons2 = tcr._compute_effective(mass2, None, 0, caps, criteria, 3)
    assert eff2 == "High", f"CWE-915 without unauth context must stay High; got {eff2}"
    assert not any("always_crit_promoted" in r for r in reasons2)


def test_mass_assignment_override_pins_distance_1_against_real_config() -> None:
    """Regression for the juice-shop F-009 under-rating: a CWE-915 mass-assignment
    finding whose scenario mentions a 'logged-in user' PUT variant must still get
    breach_distance 1 (the open-registration / REST-bridge POST variant is the
    reachable one). The override short-circuits the Stage-3 authenticated-route-hint
    heuristic that otherwise re-raised it to 2 and defeated the Critical promotion.
    """
    sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
    import triage_compute_ranking as tcr  # type: ignore[import-not-found]

    bd_patterns = tcr._load_yaml(PLUGIN_ROOT / "data" / "breach-distance-patterns.yaml", {})
    crit = tcr._load_yaml(PLUGIN_ROOT / "data" / "critical-criteria.yaml", {})

    finding = {
        "title": "Mass assignment via Sequelize REST — /api/* routes",
        "cwe": "CWE-915",
        "impact": "Critical",
        # Scenario deliberately frames the AUTHENTICATED PUT variant — the exact
        # wording that pushed breach_distance to 2 at Stage-1 triage time.
        "scenario": "a logged-in authenticated user can send PUT /api/Users/:id "
        "with {role: 'admin'} via the finale-rest bridge on routes/basket-like /api/* routes",
        "evidence": {"file": "models/user.ts", "line": 86},
    }
    dist, reason = tcr._compute_breach_distance(finding, bd_patterns)
    assert dist == 1, f"mass-assignment override must pin distance 1; got {dist} ({reason})"

    # And with impact=Critical the always-critical gate promotes to Critical.
    eff = tcr._sev_rank("High")  # Medium likelihood × Critical impact → High
    rank, crit_reason = tcr._apply_critical_criteria(finding, eff, "", crit, dist)
    assert rank == tcr._sev_rank("Critical"), f"must promote to Critical; reason={crit_reason}"
    assert "always_crit_promoted:CWE-915" in crit_reason

    # Guard: a LOW-impact mass-assignment is NOT over-promoted by the distance pin.
    low = dict(finding, impact="Low")
    rank_low, _ = tcr._apply_critical_criteria(low, tcr._sev_rank("Medium"), "", crit, dist)
    assert rank_low < tcr._sev_rank("Critical"), "low-impact mass-assignment must not promote"


def test_refuted_contributor_not_elevated() -> None:
    """Contributor refutation suppression — mirror of the keystone case."""
    sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
    import triage_compute_ranking as tcr  # type: ignore[import-not-found]

    caps = {"contributor_cap": {"default": "High"}}
    criteria = {
        "never_individual_critical": [],
        "always_critical_cwes": [],
        "conditional_critical": {},
    }
    refuted = {"risk": "Medium", "evidence_check": "refuted", "primary_cwe": "CWE-89"}
    eff, reasons = tcr._compute_effective(refuted, "contributor", 4, caps, criteria, 2)
    assert eff == "Medium", f"refuted contributor must not elevate; got {eff}"
    assert any("suppressed:evidence_refuted" in r for r in reasons)


def test_force_flag_overrides_env_gate(tmp_path: Path) -> None:
    """--force runs the ranking even without the feature flag."""
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml([]))
    env = dict(os.environ)
    env["APPSEC_TRIAGE_DETERMINISTIC"] = ""
    res = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path), "--force"], env=env, capture_output=True, text=True
    )
    assert res.returncode == 0
    assert (tmp_path / ".triage-flags.json").is_file()


# ---------------------------------------------------------------------------
# Verified abuse-case chains → effective_severity (P1-B)
# ---------------------------------------------------------------------------


def _tcr():
    sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))
    import triage_compute_ranking as tcr  # type: ignore[import-not-found]

    return tcr


def _ac_docs(chain_verdict: str, *, required: bool = True):
    """Build a matches+verdicts pair for one abuse case AC-T-001 whose single
    matched step binds finding F-1."""
    matches = {
        "matches": [
            {
                "abuse_case_id": "AC-T-001",
                "title": "Account Takeover via Stored XSS + Token Hijacking",
                "step_matches": [
                    {"step": 1, "required": required, "matched_finding_id": "F-1"},
                ],
            }
        ]
    }
    verdicts = {"verdicts": [{"abuse_case_id": "AC-T-001", "chain_verdict": chain_verdict}]}
    return verdicts, matches


def test_verified_fully_viable_chain_elevates_required_finding() -> None:
    """A finding bound to a REQUIRED step of a code-verified fully_viable chain
    is a keystone → its effective severity is pulled up one notch (High→Critical)."""
    tcr = _tcr()
    findings = [{"id": "F-1", "risk": "High", "title": "Stored XSS"}]
    verdicts, matches = _ac_docs("fully_viable")
    chains = tcr._detect_verified_abuse_chains(findings, verdicts, matches)
    assert len(chains) == 1
    ch = chains[0]
    assert ch["id"] == "AC-T-001"
    assert ch["keystones"] == ["F-1"]
    assert ch["severity"] == "Critical"  # one notch above High, capped


def test_matched_id_key_mismatch_resolves_to_triage_id() -> None:
    """REGRESSION: the matcher binds matched_finding_id via f_id, but triage
    keys findings on t_id. The detector must resolve across id keys and store
    the triage-canonical id, else elevation silently no-ops in production."""
    tcr = _tcr()
    # Matcher bound "F-1" (the f_id); triage canonical _finding_id is the t_id "T-1".
    findings = [{"f_id": "F-1", "t_id": "T-1", "risk": "High"}]
    verdicts, matches = _ac_docs("fully_viable")  # binds matched_finding_id "F-1"
    chains = tcr._detect_verified_abuse_chains(findings, verdicts, matches)
    assert chains and chains[0]["keystones"] == ["T-1"]  # stored under triage id


def test_partially_blocked_chain_does_not_elevate() -> None:
    """Only fully_viable elevates; partially_blocked / inconclusive must not."""
    tcr = _tcr()
    findings = [{"id": "F-1", "risk": "High"}]
    for verdict in ("partially_blocked", "inconclusive", "mitigated"):
        verdicts, matches = _ac_docs(verdict)
        assert tcr._detect_verified_abuse_chains(findings, verdicts, matches) == []


def test_non_required_step_is_contributor() -> None:
    """A finding on a non-required step is a contributor (capped), not keystone."""
    tcr = _tcr()
    findings = [{"id": "F-1", "risk": "Medium"}]
    verdicts, matches = _ac_docs("fully_viable", required=False)
    chains = tcr._detect_verified_abuse_chains(findings, verdicts, matches)
    assert chains[0]["contributors"] == ["F-1"]
    assert chains[0]["keystones"] == []


def test_absent_sidecars_are_non_fatal() -> None:
    """Missing/None sidecars → no verified chains, no error (feature off / budget)."""
    tcr = _tcr()
    findings = [{"id": "F-1", "risk": "High"}]
    assert tcr._detect_verified_abuse_chains(findings, None, None) == []
    assert tcr._detect_verified_abuse_chains(findings, {}, {}) == []


def test_combined_severity_capped_at_critical() -> None:
    """Max member already Critical → combined stays Critical (no overflow)."""
    tcr = _tcr()
    findings = [{"id": "F-1", "risk": "Critical"}]
    verdicts, matches = _ac_docs("fully_viable")
    chains = tcr._detect_verified_abuse_chains(findings, verdicts, matches)
    assert chains[0]["severity"] == "Critical"


def test_verified_chain_annotates_finding_end_to_end(tmp_path: Path) -> None:
    """Integration: with sidecars present, compute_ranking elevates the bound
    finding's effective_severity and stamps verified_chain_ids in the ranking."""
    tcr = _tcr()
    threats = [
        {"id": "F-1", "title": "Stored XSS", "risk": "High", "impact": "High", "primary_cwe": "CWE-79"},
    ]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    verdicts, matches = _ac_docs("fully_viable")
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(verdicts), encoding="utf-8")
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(matches), encoding="utf-8")

    ranking = tcr.compute_ranking(tmp_path)
    fnd = ranking["views"]["top_findings"]["findings_ranked"]
    entry = next(f for f in fnd if f["id"] == "F-1")
    assert entry["effective_severity"] == "Critical"
    assert entry["chain_role"] == "keystone"
    assert entry["verified_chain_ids"] == ["AC-T-001"]


def test_rerun_after_abuse_elevates_upward_and_is_idempotent(tmp_path: Path) -> None:
    """Weg 2: first triage pass (no sidecars) fixes effective_severity; a second
    pass after the abuse sidecars appear must re-elevate the chain member upward
    and persist it — and a third identical pass must be a no-op."""
    tcr = _tcr()

    env = dict(os.environ)

    def _persist(out_dir: Path) -> None:
        """Run the real CLI (writes threat-model.yaml + .triage-flags.json back)."""
        res = subprocess.run(
            [sys.executable, str(SCRIPT), str(out_dir), "--force"],
            env=env,
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, res.stderr

    threats = [{"id": "F-1", "title": "Stored XSS", "risk": "High", "primary_cwe": "CWE-79"}]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))

    # Pass 1 — no abuse sidecars: stays High (no chain elevation).
    _persist(tmp_path)
    after1 = yaml.safe_load((tmp_path / "threat-model.yaml").read_text(encoding="utf-8"))
    f1 = next(t for t in after1["threats"] if t["id"] == "F-1")
    assert f1["effective_severity"] == "High"

    # Sidecars now appear (Stage 1c completed) — pass 2 must elevate to Critical.
    verdicts, matches = _ac_docs("fully_viable")
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(verdicts), encoding="utf-8")
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(matches), encoding="utf-8")
    _persist(tmp_path)
    after2 = yaml.safe_load((tmp_path / "threat-model.yaml").read_text(encoding="utf-8"))
    f2 = next(t for t in after2["threats"] if t["id"] == "F-1")
    assert f2["effective_severity"] == "Critical"
    assert f2["verified_chain_ids"] == ["AC-T-001"]

    # Pass 3 — identical inputs: idempotent no-op.
    _persist(tmp_path)
    after3 = yaml.safe_load((tmp_path / "threat-model.yaml").read_text(encoding="utf-8"))
    f3 = next(t for t in after3["threats"] if t["id"] == "F-1")
    assert f3["effective_severity"] == "Critical"


def test_if_deterministic_owner_noop_without_marker(tmp_path: Path) -> None:
    """--if-deterministic-owner exits cleanly when no deterministic ranking marker exists.

    Stage 1c (SKILL-impl step 3b2) re-runs the fold with this flag instead of the
    env feature flag — env vars don't reach skill-level Bash (gotcha 2026-06-10)."""
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml([]))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": ""}, ["--if-deterministic-owner"])
    assert res.returncode == 0
    assert "not the ranking owner" in res.stdout
    assert not (tmp_path / ".triage-flags.json").is_file()


def test_if_deterministic_owner_noop_on_llm_ranking(tmp_path: Path) -> None:
    """An LLM-authored ranking block (different computed_by) must not be clobbered."""
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml([]))
    flags = {
        "version": 2,
        "flags": [],
        "summary": {},
        "ranking": {"computed_by": "appsec-triage-validator (LLM Step 6)"},
    }
    (tmp_path / ".triage-flags.json").write_text(json.dumps(flags), encoding="utf-8")
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": ""}, ["--if-deterministic-owner"])
    assert res.returncode == 0
    assert "not the ranking owner" in res.stdout
    assert json.loads((tmp_path / ".triage-flags.json").read_text(encoding="utf-8")) == flags


def test_if_deterministic_owner_folds_chains_without_env(tmp_path: Path) -> None:
    """End-to-end Stage 1c fold: deterministic marker present → the re-run works
    WITHOUT the env flag and elevates the verified chain keystone."""
    threats = [{"id": "F-1", "title": "Stored XSS", "risk": "High", "primary_cwe": "CWE-79"}]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    # Phase 10b deterministic run writes the owner marker (ranking.computed_by).
    res0 = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res0.returncode == 0, res0.stderr
    # Stage 1c: abuse sidecars appear, fold re-runs with --if-deterministic-owner
    # and the env flag explicitly UNSET (default-run conditions).
    verdicts, matches = _ac_docs("fully_viable")
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(verdicts), encoding="utf-8")
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(matches), encoding="utf-8")
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": ""}, ["--if-deterministic-owner"])
    assert res.returncode == 0, res.stderr
    assert "ranking written" in res.stdout
    after = yaml.safe_load((tmp_path / "threat-model.yaml").read_text(encoding="utf-8"))
    f = next(t for t in after["threats"] if t["id"] == "F-1")
    assert f["effective_severity"] == "Critical"
    assert f["verified_chain_ids"] == ["AC-T-001"]


# ===========================================================================
# Coverage-campaign extension tests (2026-06-14)
# Target the still-uncovered scoring helpers, the category/mitigation
# branches of compute_ranking, and the bootstrap / dir-validation CLI paths.
# ===========================================================================


# ---------------------------------------------------------------------------
# Low-level finding accessors / ordinal helpers
# ---------------------------------------------------------------------------


def test_max_sev_picks_highest():
    tcr = _tcr()
    assert tcr._max_sev("Low", "Critical", "Medium") == "Critical"
    assert tcr._max_sev() == "Low"


def test_finding_cwe_from_cwes_list_of_dicts():
    tcr = _tcr()
    assert tcr._finding_cwe({"cwes": [{"id": "cwe-89"}]}) == "CWE-89"


def test_finding_cwe_from_cwes_list_of_str():
    tcr = _tcr()
    assert tcr._finding_cwe({"cwes": ["cwe-79"]}) == "CWE-79"


def test_finding_cwe_from_remediation_reference():
    tcr = _tcr()
    assert tcr._finding_cwe({"remediation": {"reference": "CWE-502"}}) == "CWE-502"


def test_finding_cwe_empty_when_absent():
    tcr = _tcr()
    assert tcr._finding_cwe({}) == ""


def test_finding_evidence_path_dict_and_list():
    tcr = _tcr()
    assert tcr._finding_evidence_path({"evidence": {"path": "a/b.ts"}}) == "a/b.ts"
    assert tcr._finding_evidence_path({"evidence": [{"file": "c.ts"}]}) == "c.ts"
    assert tcr._finding_evidence_path({"evidence": "nope"}) == ""


def test_finding_cvss_variants():
    tcr = _tcr()
    assert tcr._finding_cvss({"cvss": {"score": 7.5}}) == 7.5
    assert tcr._finding_cvss({"cvss": {"score": "bad"}}) == 0.0
    assert tcr._finding_cvss({}) == 0.0


def test_load_json_missing_returns_none(tmp_path: Path):
    tcr = _tcr()
    assert tcr._load_json(tmp_path / "nope.json") is None


# ---------------------------------------------------------------------------
# Breach distance — amplifier / deamplifier / route-guard branches
# ---------------------------------------------------------------------------


def test_breach_distance_amplifier_and_deamplifier():
    tcr = _tcr()
    patterns = {
        "cwe_default_distance": {"CWE-89": 2},
        "amplifiers": [{"name": "amp", "if_any_match": ["public exploit"], "distance_delta": 1}],
    }
    d, reason = tcr._compute_breach_distance({"cwe": "CWE-89", "scenario": "a public exploit exists"}, patterns)
    assert d == 1 and reason.startswith("amplifier:")

    patterns2 = {
        "cwe_default_distance": {"CWE-89": 1},
        "deamplifiers": [{"name": "deamp", "if_any_match": ["requires admin"], "distance_delta": 1}],
    }
    d2, reason2 = tcr._compute_breach_distance({"cwe": "CWE-89", "scenario": "this requires admin first"}, patterns2)
    assert d2 == 2 and reason2.startswith("deamplifier:")


def test_breach_distance_route_guard_unauth_and_auth():
    tcr = _tcr()
    patterns = {
        "cwe_default_distance": {"CWE-89": 2},
        "route_guard_indicators": {
            "frameworks": {
                "express": {
                    "unauthenticated_route_hints": ["app.get('/public"],
                    "authenticated_route_hints": ["requireauth"],
                }
            }
        },
    }
    d_unauth, r_unauth = tcr._compute_breach_distance(
        {"cwe": "CWE-89", "scenario": "app.get('/public') leaks data"}, patterns
    )
    assert d_unauth == 1 and r_unauth.startswith("unauth_hint:")


# ---------------------------------------------------------------------------
# Severity caps + ranking caps + critical-criteria never_individual
# ---------------------------------------------------------------------------


def test_apply_severity_caps_caps_when_over():
    tcr = _tcr()
    caps = {"severity_caps": {"CWE-209": {"max": "Medium"}}}
    rank, reason = tcr._apply_severity_caps(tcr._sev_rank("Critical"), "CWE-209", caps)
    assert rank == tcr._sev_rank("Medium")
    assert reason.startswith("capped:")


def test_apply_severity_caps_no_cap():
    tcr = _tcr()
    rank, reason = tcr._apply_severity_caps(tcr._sev_rank("High"), "CWE-89", {})
    assert rank == tcr._sev_rank("High") and reason == ""


def test_never_individual_critical_deescalates():
    tcr = _tcr()
    criteria = {
        "always_critical_cwes": [],
        "never_individual_critical": ["CWE-200"],
        "max_severity_individual": "High",
    }
    # Critical, not a keystone, CWE in never-individual → drop to High.
    rank, reason = tcr._apply_critical_criteria({"cwe": "CWE-200"}, tcr._sev_rank("Critical"), "none", criteria, 2)
    assert rank == tcr._sev_rank("High") and reason.startswith("never_individual:")


def test_always_critical_failed_context_caps_critical_to_high():
    tcr = _tcr()
    criteria = {
        "always_critical_cwes": [{"cwe": "CWE-915", "required": {"breach_distance_max": 1, "impact_min": "High"}}],
        "never_individual_critical": [],
    }
    # Already Critical but context fails (breach distance 3) → cap to High.
    rank, reason = tcr._apply_critical_criteria(
        {"cwe": "CWE-915", "impact": "High"}, tcr._sev_rank("Critical"), "", criteria, 3
    )
    assert rank == tcr._sev_rank("High") and "always_crit_failed" in reason


def test_is_ranking_capped():
    tcr = _tcr()
    caps = {"ranking_caps": {"CWE-209": {"max_rank_tier": 2}}}
    assert tcr._is_ranking_capped("CWE-209", caps) is True
    assert tcr._is_ranking_capped("CWE-89", caps) is False


def test_cwe_top25_rank_dict_and_str():
    tcr = _tcr()
    tax = {"top25": [{"id": "CWE-79"}, "CWE-89"]}
    assert tcr._cwe_top25_rank("CWE-79", tax) == 1
    assert tcr._cwe_top25_rank("CWE-89", tax) == 2
    assert tcr._cwe_top25_rank("CWE-1", tax) == 0


def test_finding_score_applies_contributor_and_cap_penalty():
    tcr = _tcr()
    caps = {"ranking_caps": {"CWE-209": {"max_rank_tier": 2}}}
    base = tcr._finding_score(
        {"cwe": "CWE-89", "impact": "High", "likelihood": "High", "cvss": {"score": 5}},
        "High",
        1,
        None,
        {},
        {},
    )
    capped = tcr._finding_score(
        {"cwe": "CWE-209", "impact": "High", "likelihood": "High"},
        "High",
        1,
        "contributor",
        caps,
        {},
    )
    assert base > capped  # contributor -50 and ranking-cap -100 lower the score


# ---------------------------------------------------------------------------
# _category_score + _category_reasons (direct — avoids the top_finding_id bug)
# ---------------------------------------------------------------------------


def test_category_score_empty_members():
    tcr = _tcr()
    score, max_eff, min_bd = tcr._category_score({}, [], {}, {}, {}, {}, {})
    assert (score, max_eff, min_bd) == (0, "Low", 3)


def test_category_score_aggregates_members():
    tcr = _tcr()
    members = [
        {"t_id": "T-1", "risk": "Critical", "impact": "High", "likelihood": "High", "cwe": "CWE-89"},
        {"t_id": "T-2", "risk": "Low", "impact": "Low", "likelihood": "Low", "cwe": "CWE-209"},
    ]
    eff = {"T-1": "Critical", "T-2": "Low"}
    bd = {"T-1": 1, "T-2": 3}
    role = {}
    caps = {"ranking_caps": {"CWE-209": {"max_rank_tier": 2}}}
    tax = {"top25": [{"id": "CWE-89"}]}
    score, max_eff, min_bd = tcr._category_score({}, members, eff, bd, role, caps, tax)
    assert max_eff == "Critical"
    assert min_bd == 1
    assert score > 0


def test_category_reasons_marks_internet_reachable_and_top25():
    tcr = _tcr()
    members = [{"t_id": "T-1", "risk": "Critical", "cwe": "CWE-89"}]
    eff = {"T-1": "Critical"}
    bd = {"T-1": 1}
    tax = {"top25": [{"id": "CWE-89"}]}
    reasons = tcr._category_reasons(members, eff, bd, {}, tax)
    assert reasons
    assert "internet-reachable" in reasons[0]
    assert "Top-25" in reasons[0]


# ---------------------------------------------------------------------------
# _rank_mitigations
# ---------------------------------------------------------------------------


def test_rank_mitigations_orders_by_addressed_severity_then_effort():
    tcr = _tcr()
    eff = {"T-1": "Critical", "T-2": "Low"}
    mits = [
        {"m_id": "M-1", "addresses": ["T-2"], "effort": "Low"},
        {"m_id": "M-2", "addresses": ["T-1"], "effort": "High"},
        "not-a-dict",
    ]
    ranked = tcr._rank_mitigations(mits, eff)
    assert [m["id"] for m in ranked] == ["M-2", "M-1"]
    assert ranked[0]["rank"] == 1
    assert "_max_eff_rank" not in ranked[0]


def test_rank_mitigations_empty():
    tcr = _tcr()
    assert tcr._rank_mitigations([], {}) == []


def test_rank_mitigations_non_list_addressed_coerced():
    tcr = _tcr()
    ranked = tcr._rank_mitigations([{"m_id": "M-1", "addresses": "T-1"}], {"T-1": "High"})
    assert ranked[0]["addresses_findings"] == []  # non-list coerced to empty


# ---------------------------------------------------------------------------
# compute_ranking with categories (members unresolved) + chains + mitigations
# ---------------------------------------------------------------------------


def test_compute_ranking_with_unresolved_category_and_mitigations(tmp_path: Path):
    """Category whose member ids don't resolve takes the `else None` branch for
    top_finding_id — exercising the 6e loop without tripping the top_finding_id
    KeyError bug (which requires resolvable members). Also covers 6g mitigation
    ranking and the chains_ranked sort."""
    tcr = _tcr()
    threats = [
        {
            "t_id": "T-1",
            "title": "SQLi",
            "risk": "Critical",
            "impact": "Critical",
            "likelihood": "High",
            "primary_cwe": "CWE-89",
        },
        {
            "t_id": "T-2",
            "title": "Info leak",
            "risk": "Low",
            "impact": "Low",
            "likelihood": "Low",
            "primary_cwe": "CWE-209",
        },
    ]
    data = _minimal_yaml(threats)
    data["threat_categories"] = [
        {"id": "TH-1", "title": "Injection", "findings": ["DOES-NOT-EXIST"]},
        "not-a-dict",
    ]
    data["mitigations"] = [
        {"m_id": "M-1", "addresses": ["T-1"], "effort": "Low"},
    ]
    _write_yaml(tmp_path / "threat-model.yaml", data)
    ranking = tcr.compute_ranking(tmp_path)
    cats = ranking["views"]["top_threats"]["categories_ranked"]
    # category has no resolvable members → finding_count 0, top_finding_id None.
    th1 = next((c for c in ranking["views"]["top_threats"]["categories_ranked"] if c["id"] == "TH-1"), None)
    # TH-1 (Low effective severity) is filtered out of top_threats (>= High only).
    assert th1 is None or th1["finding_count"] == 0
    mits = ranking["views"]["prioritized_mitigations"]["mitigations_ranked"]
    assert mits and mits[0]["id"] == "M-1"
    assert isinstance(cats, list)


def test_compute_ranking_finding_without_id_skipped(tmp_path: Path):
    """A finding with no resolvable id is skipped across the 6a/6c/6f loops."""
    tcr = _tcr()
    threats = [
        {"t_id": "T-1", "title": "x", "risk": "High", "primary_cwe": "CWE-89"},
        {"title": "no id here", "risk": "High"},  # no t_id/id/finding_id
    ]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    ranking = tcr.compute_ranking(tmp_path)
    ranked = ranking["views"]["top_findings"]["findings_ranked"]
    assert [f["id"] for f in ranked] == ["T-1"]


def test_compute_ranking_non_mapping_yaml_raises(tmp_path: Path):
    tcr = _tcr()
    (tmp_path / "threat-model.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    import pytest

    with pytest.raises(SystemExit):
        tcr.compute_ranking(tmp_path)


# ---------------------------------------------------------------------------
# CLI: directory validation, bootstrap path, error exits
# ---------------------------------------------------------------------------


def test_cli_output_dir_not_a_directory(tmp_path: Path):
    """output_dir pointing at a file → exit 1 (not a directory)."""
    target = tmp_path / "afile"
    target.write_text("x", encoding="utf-8")
    res = _run(target, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 1
    assert "not a directory" in res.stderr.lower()


def test_cli_bootstrap_yaml_from_merged(tmp_path: Path):
    """--bootstrap-yaml builds threat-model.yaml from .threats-merged.json when
    the yaml is missing, then ranks it."""
    merged = {
        "threats": [
            {
                "t_id": "T-1",
                "title": "SQLi",
                "risk": "Critical",
                "likelihood": "High",
                "impact": "Critical",
                "stride": "Tampering",
                "scenario": "x",
                "component_id": "c",
            },
        ]
    }
    (tmp_path / ".threats-merged.json").write_text(json.dumps(merged), encoding="utf-8")
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"}, ["--bootstrap-yaml"])
    assert res.returncode == 0, res.stderr
    assert "bootstrapped threat-model.yaml" in res.stdout
    yaml_data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    plugin_manifest = json.loads((Path(__file__).resolve().parents[1] / ".claude-plugin" / "plugin.json").read_text())
    assert yaml_data["meta"]["_bootstrap"] is True
    assert yaml_data["meta"]["analysis_version"] == plugin_manifest["analysis_version"]
    assert yaml_data["threats"][0]["t_id"] == "T-1"


def test_cli_bootstrap_yaml_missing_merged_errors(tmp_path: Path):
    """--bootstrap-yaml with no .threats-merged.json → exit 1."""
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"}, ["--bootstrap-yaml"])
    assert res.returncode == 1
    assert ".threats-merged.json missing" in res.stderr


def test_cli_missing_yaml_no_bootstrap_errors(tmp_path: Path):
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 1
    assert "threat-model.yaml missing" in res.stderr


def test_bootstrap_falls_back_stride_category(tmp_path: Path):
    """_bootstrap_yaml_from_merged mirrors merge-normalization: stride falls back
    to stride_category when stride is absent/empty."""
    tcr = _tcr()
    merged = {"threats": [{"id": "T-9", "stride_category": "Spoofing", "risk": "High"}]}
    (tmp_path / ".threats-merged.json").write_text(json.dumps(merged), encoding="utf-8")
    assert tcr._bootstrap_yaml_from_merged(tmp_path) is True
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    assert data["threats"][0]["stride"] == "Spoofing"
    assert data["threats"][0]["t_id"] == "T-9"


def test_bootstrap_malformed_merged_returns_false(tmp_path: Path):
    tcr = _tcr()
    (tmp_path / ".threats-merged.json").write_text("{bad json", encoding="utf-8")
    assert tcr._bootstrap_yaml_from_merged(tmp_path) is False


# ---------------------------------------------------------------------------
# write_outputs — flags-file creation when absent
# ---------------------------------------------------------------------------


def test_write_outputs_creates_flags_when_absent(tmp_path: Path):
    tcr = _tcr()
    threats = [{"t_id": "T-1", "title": "x", "risk": "High", "primary_cwe": "CWE-89"}]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    ranking = tcr.compute_ranking(tmp_path)
    # No .triage-flags.json present → write_outputs must create a v2 stub.
    assert not (tmp_path / ".triage-flags.json").is_file()
    tcr.write_outputs(tmp_path, ranking)
    flags = json.loads((tmp_path / ".triage-flags.json").read_text())
    assert flags["version"] == 2
    assert flags["ranking"]["computed_by"].startswith("triage_compute_ranking.py")


def test_design_risk_weakness_enters_findings_ranked(tmp_path: Path) -> None:
    """P1.4 / §9.3 — a design-risk weakness (zero confirmed instances) is folded
    into findings_ranked as a W-NNN entry so it can top the ranking."""
    import triage_compute_ranking as tcr  # type: ignore[import-not-found]

    data = _minimal_yaml(
        [
            {
                "t_id": "T-001",
                "component": "api",
                "stride": "Tampering",
                "title": "SQL Injection (a.ts:1)",
                "scenario": "x" * 12,
                "likelihood": "High",
                "impact": "High",
                "risk": "High",
                "cwe": "CWE-89",
                "evidence": [{"file": "a.ts", "line": 1}],
            },
        ]
    )
    data["weaknesses"] = [
        {
            "id": "W-001",
            "weakness_class": "injection",
            "kind": "design",
            "severity": "Critical",
            "severity_basis": "design-risk",
            "statement": "no central validation",
            "observable_backing": {"absent_control_signal": [{"hit_count": 0}]},
            "affected_components": ["api", "search", "admin"],
        }
    ]
    _write_yaml(tmp_path / "threat-model.yaml", data)
    ranking = tcr.compute_ranking(tmp_path, PLUGIN_ROOT)
    ranked = ranking["views"]["top_findings"]["findings_ranked"]
    w = [r for r in ranked if r["id"] == "W-001"]
    assert w, "design-risk weakness missing from findings_ranked"
    assert w[0]["severity_basis"] == "design-risk"
    assert w[0]["effective_severity"] == "Critical"
    # A design-risk Critical outranks a confirmed High (§9.3 — may be #1).
    assert w[0]["rank"] == 1, f"expected design-risk Critical at #1, got {w[0]['rank']}"


def test_confirmed_weakness_not_double_ranked(tmp_path: Path) -> None:
    """A `confirmed`-basis weakness is represented by its instances already —
    it must NOT be added as a separate W-NNN ranked entry."""
    import triage_compute_ranking as tcr  # type: ignore[import-not-found]

    data = _minimal_yaml(
        [
            {
                "t_id": "T-001",
                "component": "api",
                "stride": "Tampering",
                "title": "SQL Injection (a.ts:1)",
                "scenario": "x" * 12,
                "likelihood": "High",
                "impact": "High",
                "risk": "High",
                "cwe": "CWE-89",
                "evidence": [{"file": "a.ts", "line": 1}],
            },
        ]
    )
    data["weaknesses"] = [
        {
            "id": "W-001",
            "weakness_class": "injection",
            "kind": "design",
            "severity": "High",
            "severity_basis": "confirmed",
            "statement": "folded",
            "observable_backing": {"absent_control_signal": [{"hit_count": 0}]},
            "instances": [{"id": "T-001", "basis": "confirmed-exploitable"}],
        }
    ]
    _write_yaml(tmp_path / "threat-model.yaml", data)
    ranking = tcr.compute_ranking(tmp_path, PLUGIN_ROOT)
    ranked = ranking["views"]["top_findings"]["findings_ranked"]
    assert not any(r["id"] == "W-001" for r in ranked)
