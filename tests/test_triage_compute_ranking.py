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


def _run(output_dir: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(SCRIPT), str(output_dir)], env=env, capture_output=True, text=True)


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
            env=env, capture_output=True, text=True,
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
