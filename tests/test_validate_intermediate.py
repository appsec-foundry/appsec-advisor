"""Unit tests for scripts/validate_intermediate.py.

validate_intermediate.py is the schema + invariant gate for all intermediate
JSON artifacts (stride, threats_merged, triage_flags, …). These tests
exercise the public API and CLI contract directly. The dep_scan validator
was removed in 2026-05 alongside the in-tree SCA producer.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_intermediate.py"
SCHEMAS_DIR = REPO_ROOT / "schemas"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


vi = _load_module("validate_intermediate", SCRIPT_PATH)


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# Schema file registry completeness
# ---------------------------------------------------------------------------


def test_all_registered_schema_files_exist():
    """Every schema referenced in _SCHEMA_FILES must be present on disk."""
    missing = []
    for kind, schema_file in vi._SCHEMA_FILES.items():
        path = SCHEMAS_DIR / schema_file
        if not path.is_file():
            missing.append(f"{kind} → {schema_file}")
    assert not missing, "Missing schema files:\n  " + "\n  ".join(missing)


def test_schema_files_are_valid_yaml():
    """Every registered schema file must parse as valid YAML."""
    invalid = []
    for kind, schema_file in vi._SCHEMA_FILES.items():
        path = SCHEMAS_DIR / schema_file
        if path.is_file():
            try:
                yaml.safe_load(path.read_text())
            except yaml.YAMLError as e:
                invalid.append(f"{kind}: {e}")
    assert not invalid, "Invalid YAML in schema files:\n  " + "\n  ".join(invalid)


# ---------------------------------------------------------------------------
# CLI: unknown artifact type
# ---------------------------------------------------------------------------


def test_unknown_kind_exits_2(tmp_path: Path):
    dummy = tmp_path / "x.json"
    dummy.write_text("{}")
    result = _run(["unknown_kind", str(dummy)])
    assert result.returncode == 2


def test_actor_discovery_contract_accepts_distinct_high_confidence_actor():
    data = {
        "schema_version": 1,
        "discovery_cache_key": "a" * 64,
        "generated_at": "2026-06-30T12:00:00Z",
        "confirmed_relevant": [],
        "proposed_additional": [
            {
                "id": "ACT-X-1",
                "label": "partner-api-credential-holder",
                "access": ["internet"],
                "trust_positions": ["partner-api-credential"],
                "distinct_trust_positions": ["partner-api-credential"],
                "distinct_trust_position_evidence": "Recon section 7.1 identifies a partner-only API credential.",
                "capabilities": {
                    "sophistication": "medium",
                    "tooling": ["off-the-shelf"],
                    "dwell_time": "weeks",
                    "surface_reach": ["internet"],
                },
                "motivation": "financial",
                "rationale": "The credential grants authority unavailable to ordinary application users.",
                "confidence": "high",
                "discovery_method": "heuristic-section-A",
            }
        ],
        "inputs_questioned": [],
        "coverage_rationale": "Static and discovered access positions compared.",
    }
    ok, errors = vi.validate_actors_discovered(data)
    assert ok, errors


def test_actor_discovery_contract_rejects_unqualified_proposal():
    data = {
        "schema_version": 1,
        "discovery_cache_key": "a",
        "generated_at": "now",
        "confirmed_relevant": [],
        "proposed_additional": [
            {
                "id": "ACT-X-1",
                "label": "prompt-injector",
                "access": ["internet"],
                "capabilities": {
                    "sophistication": "low",
                    "tooling": [],
                    "dwell_time": "short",
                    "surface_reach": ["internet"],
                },
                "motivation": "curiosity",
                "rationale": "This is only an attack technique rather than a distinct access position.",
                "confidence": "high",
                "discovery_method": "heuristic-section-A",
            }
        ],
        "inputs_questioned": [],
        "coverage_rationale": "",
    }
    ok, errors = vi.validate_actors_discovered(data)
    assert not ok
    assert any("distinct_trust_positions" in error for error in errors)


def _valid_resolved_actors() -> dict:
    return {
        "schema_version": 1,
        "quick_mode": True,
        "discovery_enabled": True,
        "discovery_skip_reason": "quick-mode",
        "actors_inputs_fingerprint": "a" * 64,
        "alias_map": {},
        "resolved_actors": [
            {
                "id": "ACT-D-1",
                "label": "anonymous-attacker",
                "access": ["internet"],
                "capabilities": {
                    "sophistication": "low",
                    "dwell_time": "short",
                    "surface_reach": ["internet"],
                },
                "motivation": "financial",
                "_provenance": {
                    "layer": "plugin",
                    "active": True,
                    "activation_reason": "always-active (no conditions defined)",
                    "signal_status": "normal",
                },
            }
        ],
        "confirmed_relevant": [],
        "inputs_questioned": [],
        "run_issues": [],
        "discovery_actor_count": 0,
        "rejected_discovery_actors": [],
    }


def test_actor_resolved_contract_accepts_runtime_fields():
    ok, errors = vi.validate_actors_resolved(_valid_resolved_actors())
    assert ok, errors


def test_actor_resolved_contract_rejects_unknown_runtime_field():
    data = _valid_resolved_actors()
    data["resolved_actors"][0]["_provenance"]["invented"] = True
    ok, errors = vi.validate_actors_resolved(data)
    assert not ok
    assert any("invented" in error for error in errors)


def test_actor_repo_contract_rejects_invalid_discovery_config():
    ok, errors = vi.validate_actors_repo({"discovery": {"enabled": "yes", "max_proposed": 99}})
    assert not ok
    assert any("enabled" in error or "max_proposed" in error for error in errors)


def test_actor_contract_rejects_incomplete_new_actor():
    ok, errors = vi.validate_actor({"id": "ACT-R-1", "label": "repo-actor"})
    assert not ok
    assert any("access" in error or "capabilities" in error for error in errors)


# ---------------------------------------------------------------------------
# stride validation
# ---------------------------------------------------------------------------


def test_stride_empty_object_fails():
    ok, errors = vi.validate_stride({})
    assert not ok
    assert errors


def test_stride_minimal_valid():
    minimal = {
        "component_id": "auth-svc",
        "component_name": "Auth Service",
        "analyzed_at": "2026-04-22T10:00:00Z",
        "threats": [],
    }
    ok, errors = vi.validate_stride(minimal)
    assert ok, f"Expected valid stride, got errors: {errors}"


def _stride_threat_with_code_example(code_example):
    return {
        "component_id": "auth-svc",
        "component_name": "Auth Service",
        "analyzed_at": "2026-04-22T10:00:00Z",
        "threats": [
            {
                "local_id": "C-01",
                "stride": "Tampering",
                "threat_category_id": "TH-06",
                "scenario": "Endpoint registered without auth middleware.",
                "likelihood": "Medium",
                "impact": "Medium",
                "risk": "Medium",
                "remediation": {
                    "effort": "Low",
                    "steps": ["Delete the unauthenticated endpoint."],
                    "code_example": code_example,
                    "reference": "CWE-862",
                },
            }
        ],
    }


def test_stride_code_example_null_is_valid():
    """code_example may be null when the fix is purely config/docs
    (appsec-stride-analyzer.md spec); schemas/stride.schema.yaml allows null.
    Regression: a non-null-only type tripped the 2026-06-27 E2E."""
    ok, errors = vi.validate_stride(_stride_threat_with_code_example(None))
    assert ok, f"null code_example must be valid: {errors}"


def test_stride_code_example_non_string_rejected():
    ok, errors = vi.validate_stride(_stride_threat_with_code_example(123))
    assert not ok


def test_stride_verification_string_is_valid():
    data = _stride_threat_with_code_example(None)
    data["threats"][0]["remediation"]["verification"] = "npm test -- auth.spec.ts"
    ok, errors = vi.validate_stride(data)
    assert ok, errors


def test_stride_verification_non_string_rejected():
    data = _stride_threat_with_code_example(None)
    data["threats"][0]["remediation"]["verification"] = ["not a string"]
    ok, errors = vi.validate_stride(data)
    assert not ok


def test_stride_owasp_ai_ids_are_schema_validated():
    data = _stride_threat_with_code_example(None)
    data["threats"][0]["owasp_llm_ids"] = ["LLM06"]
    data["threats"][0]["owasp_asi_ids"] = ["ASI02", "ASI10"]
    ok, errors = vi.validate_stride(data)
    assert ok, errors

    data["threats"][0]["owasp_asi_ids"] = ["ASI99"]
    ok, errors = vi.validate_stride(data)
    assert not ok


def test_write_first_stub_is_schema_valid():
    """The mandatory STRIDE write-first stub (appsec-stride-analyzer.md
    "Write-first guarantee") must satisfy stride.schema.yaml — otherwise a
    budget-cut analyzer leaves a file the orchestrator gate rejects, defeating
    the partial-but-valid degradation (CD-1, audit 2026-06-11)."""
    stub = {
        "component_id": "express-backend",
        "component_name": "Express Backend",
        "analyzed_at": "2026-06-11T00:00:00Z",
        "started_at": "2026-06-11T00:00:00Z",
        "partial": True,
        "skipped_categories": [
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege",
        ],
        "threats": [],
    }
    ok, errors = vi.validate_stride(stub)
    assert ok, f"Write-first stub must be schema-valid, got errors: {errors}"


# ---------------------------------------------------------------------------
# CLI file-not-found
# ---------------------------------------------------------------------------


def test_missing_file_exits_nonzero():
    result = _run(["stride", "/nonexistent/path.json"])
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# Python post-check invariants
# ---------------------------------------------------------------------------


def _make_threat(t_id: str, cwe: str = "CWE-89") -> dict:
    return {
        "t_id": t_id,
        "component_id": "svc",
        "component_name": "Service",
        "stride": "Tampering",
        "risk": "High",
        "likelihood": "High",
        "impact": "High",
        "title": f"Threat {t_id}",
        "cwe": [cwe],
        "evidence": {"file": "app.py", "line": 1},
        "source": "stride",
        "architectural_violation": False,
    }


def test_t_id_must_be_sequential():
    """T-IDs in threats_merged must be sequential — a gap should fail the invariant check."""
    data = {
        "version": 1,
        "generated_at": "2026-04-22T10:00:00Z",
        "threats": [
            _make_threat("T-001"),
            _make_threat("T-003"),  # gap — should be T-002
        ],
    }
    ok, errors = vi.validate_threats_merged(data)
    assert not ok, "Expected validation to fail due to non-sequential T-IDs"


# --- _check_component_path_glob_consistency (M-1 advisory) ---------------


def _model_two_components(threat_component: str, evidence_file: str) -> dict:
    """Minimal model with two components whose globs do not overlap, plus one
    threat whose evidence file lives under the OTHER component's globs."""
    return {
        "components": [
            {"id": "backend-api", "paths": ["server.ts", "routes/**", "lib/**"]},
            {"id": "data-persistence", "paths": ["models/**", "data/**"]},
        ],
        "threats": [
            {
                "id": "T-001",
                "component": threat_component,
                "evidence": [{"file": evidence_file}],
            }
        ],
    }


def test_glob_advisory_suppressed_for_single_sibling_match():
    """The case reclassify_components.py self-heals (evidence matches exactly
    one OTHER component) must NOT emit an advisory — it is pure noise."""
    data = _model_two_components("data-persistence", "routes/search.ts")
    advisories = vi._check_component_path_glob_consistency(data)
    assert advisories == [], advisories


def test_glob_advisory_kept_for_orphan_evidence():
    """No sibling component matches → genuine orphan; advisory stays."""
    data = _model_two_components("data-persistence", "scripts/build.sh")
    advisories = vi._check_component_path_glob_consistency(data)
    assert len(advisories) == 1
    assert "T-001" in advisories[0]
    assert "consider" not in advisories[0]  # no single suggestion


def test_glob_advisory_kept_for_ambiguous_match():
    """Two distinct sibling components match → reclassify won't touch it; the
    advisory stays so an operator can disambiguate."""
    data = {
        "components": [
            {"id": "backend-api", "paths": ["shared/**"]},
            {"id": "frontend-spa", "paths": ["shared/**"]},
            {"id": "data-persistence", "paths": ["models/**"]},
        ],
        "threats": [
            {
                "id": "T-001",
                "component": "data-persistence",
                "evidence": [{"file": "shared/util.ts"}],
            }
        ],
    }
    advisories = vi._check_component_path_glob_consistency(data)
    assert len(advisories) == 1
    assert "consider one of" in advisories[0]


# ===========================================================================
# In-process coverage of helper invariants and validators
# ===========================================================================

import json as _json  # noqa: E402

import pytest  # noqa: E402

# --- _format_error_path -----------------------------------------------------


class _FakeErr:
    def __init__(self, path, message="msg"):
        self.absolute_path = path
        self.message = message


def test_format_error_path_root():
    assert vi._format_error_path(_FakeErr([])) == "root"


def test_format_error_path_mixed_keys_and_indices():
    out = vi._format_error_path(_FakeErr(["threats", 2, "title"]))
    assert out == "threats[2].title"


# --- _eligible_cwes OSError fallback ---------------------------------------


def test_eligible_cwes_missing_file_returns_empty(monkeypatch):
    vi._eligible_cwes.cache_clear()

    def boom(self, *a, **k):
        raise OSError("nope")

    monkeypatch.setattr(vi.Path, "open", boom)
    assert vi._eligible_cwes() == frozenset()
    vi._eligible_cwes.cache_clear()


# --- _check_cvss_eligibility branches --------------------------------------


def test_cvss_required_missing_fails():
    data = {"threats": [{"source": "known-vuln"}]}
    errs = vi._check_cvss_eligibility(data)
    assert any("cvss_v4 is required" in e for e in errs)


def test_cvss_required_missing_waived_when_skip():
    data = {"threats": [{"source": "known-vuln"}]}
    errs = vi._check_cvss_eligibility(data, skip_cvss_required=True)
    assert errs == []


def test_cvss_forbidden_source_with_cvss_fails():
    data = {"threats": [{"source": "requirements-compliance", "cvss_v4": {"severity": "High"}}]}
    errs = vi._check_cvss_eligibility(data)
    assert any("not permitted" in e for e in errs)


def test_cvss_stride_bad_cwe_and_missing_line():
    data = {"threats": [{"source": "stride", "cvss_v4": {"severity": "High"}, "cwe": "not-a-cwe"}]}
    errs = vi._check_cvss_eligibility(data)
    assert any("valid CWE reference" in e for e in errs)
    assert any("requires evidence.line" in e for e in errs)


def test_cvss_stride_cwe_not_eligible(monkeypatch):
    monkeypatch.setattr(vi, "_eligible_cwes", lambda: frozenset())
    data = {
        "threats": [
            {
                "source": "stride",
                "cvss_v4": {"severity": "High"},
                "cwe": "CWE-89",
                "evidence": {"line": 5},
            }
        ]
    }
    errs = vi._check_cvss_eligibility(data)
    assert any("not in cvss-eligible-cwes.yaml" in e for e in errs)


def test_cvss_band_gap_fails():
    data = {"threats": [{"source": "configuration-defect", "cvss_v4": {"severity": "Critical"}, "risk": "Low"}]}
    errs = vi._check_cvss_eligibility(data)
    assert any("more than one band away" in e for e in errs)


def test_cvss_skips_non_dict_threat():
    assert vi._check_cvss_eligibility({"threats": ["notadict"]}) == []


# --- _check_snippet_redaction ----------------------------------------------


def test_snippet_not_redacted():
    data = {"hardcoded_secrets": [{"snippet": "password=hunter2"}]}
    errs = vi._check_snippet_redaction(data)
    assert any("not redacted" in e for e in errs)


def test_snippet_exposes_too_much():
    data = {"hardcoded_secrets": [{"snippet": "abcdef****"}]}
    errs = vi._check_snippet_redaction(data)
    assert any("more than 4 characters" in e for e in errs)


def test_snippet_clean_passes():
    data = {"hardcoded_secrets": [{"snippet": "ab****"}]}
    assert vi._check_snippet_redaction(data) == []


def test_snippet_non_list_returns_empty():
    assert vi._check_snippet_redaction({"hardcoded_secrets": "x"}) == []


def test_snippet_skips_non_dict_and_empty():
    data = {"hardcoded_secrets": ["x", {"snippet": ""}, {"snippet": 5}]}
    assert vi._check_snippet_redaction(data) == []


# --- _check_scenario_stripped_length ---------------------------------------


def test_scenario_too_short():
    errs = vi._check_scenario_stripped_length({"threats": [{"scenario": "  hi  "}]})
    assert any("at least 10 characters" in e for e in errs)


def test_scenario_skips_non_dict():
    assert vi._check_scenario_stripped_length({"threats": ["x"]}) == []


# --- _check_threat_category_id_set / _warning ------------------------------


def test_th_check_env_skip(monkeypatch):
    monkeypatch.setenv("APPSEC_SKIP_TH_CHECK", "1")
    data = {"threats": [{"source": "stride", "threat_category_id": None}]}
    assert vi._check_threat_category_id_set(data) == []


def test_th_check_missing_id_fails(monkeypatch):
    monkeypatch.delenv("APPSEC_SKIP_TH_CHECK", raising=False)
    data = {"threats": [{"source": "stride", "t_id": "T-001", "threat_category_id": None}]}
    errs = vi._check_threat_category_id_set(data)
    assert any("threat_category_id is required" in e for e in errs)


def test_th_check_non_stride_skipped(monkeypatch):
    monkeypatch.delenv("APPSEC_SKIP_TH_CHECK", raising=False)
    data = {"threats": [{"source": "known-vuln"}, "notadict"]}
    assert vi._check_threat_category_id_set(data) == []


def test_th_warning_emits_even_when_env_set():
    data = {"threats": [{"source": "stride", "threat_category_id": None}, "x", {"source": "known-vuln"}]}
    errs = vi._check_threat_category_id_warning(data)
    assert any(e.startswith("WARN:") for e in errs)


# --- _check_stride_remediation_nonempty ------------------------------------


def test_remediation_null_fails():
    errs = vi._check_stride_remediation_nonempty({"threats": [{"remediation": None}]})
    assert any("remediation is null" in e for e in errs)


def test_remediation_empty_steps_fails():
    errs = vi._check_stride_remediation_nonempty({"threats": [{"remediation": {"steps": []}}]})
    assert any("steps is empty" in e for e in errs)


def test_remediation_ok():
    errs = vi._check_stride_remediation_nonempty({"threats": [{"remediation": {"steps": ["do x"]}}, "skip"]})
    assert errs == []


# --- _check_title_not_blank -------------------------------------------------


def test_title_blank_and_truncated():
    errs = vi._check_title_not_blank({"threats": [{"title": "   "}, {"title": "long title..."}, "skip"]})
    assert any("must not be empty" in e for e in errs)
    assert any("truncated" in e for e in errs)


# --- _check_t_id_sequence duplicate ----------------------------------------


def test_t_id_duplicate_detected():
    data = {"threats": [{"t_id": "T-001"}, {"t_id": "T-001"}, {"t_id": 5}, "skip", {"t_id": "bad"}]}
    errs = vi._check_t_id_sequence(data)
    assert any("duplicated" in e for e in errs)


# --- _check_tf_id_sequence + _check_triage_summary -------------------------


def test_tf_id_sequence_dup_and_gap():
    data = {
        "flags": [
            {"flag_id": "TF-001"},
            {"flag_id": "TF-003"},
            {"flag_id": "TF-001"},
            {"flag_id": 5},
            "x",
            {"flag_id": "bad"},
        ]
    }
    errs = vi._check_tf_id_sequence(data)
    assert any("breaks sequential order" in e for e in errs)
    assert any("duplicated" in e for e in errs)


def test_triage_summary_mismatches():
    data = {
        "flags": [
            {"severity": "warning"},
            {"severity": "info"},
        ],
        "summary": {"total_flags": 5, "warnings": 3, "info": 4},
    }
    errs = vi._check_triage_summary(data)
    assert any("does not match flags length" in e for e in errs)
    assert any("does not equal" in e for e in errs)
    assert any("actual warning flag count" in e for e in errs)
    assert any("actual info flag count" in e for e in errs)


def test_triage_summary_non_list_returns_empty():
    assert vi._check_triage_summary({"flags": "x", "summary": {}}) == []


# --- _check_known_threats_unique_ids ---------------------------------------


def test_known_threats_dup_id():
    data = {"threats": [{"id": "K-1"}, {"id": "K-1"}, {"id": 5}, "x"]}
    errs = vi._check_known_threats_unique_ids(data)
    assert any("duplicated" in e for e in errs)


# --- _check_architecture_coverage_invariants -------------------------------


def test_arch_cov_non_rule_source_with_rule_id():
    src = sorted(vi._RULE_ID_SOURCES)[0]
    data = {
        "threats": [
            {"source": "stride", "rule_id": "ARCH-X-001", "hypothesis_id": "y"},
            {"source": src},  # missing rule_id → required error
        ]
    }
    errs = vi._check_architecture_coverage_invariants(data)
    assert any("rule_id is only permitted" in e for e in errs)
    assert any("hypothesis_id is only permitted" in e for e in errs)
    assert any("rule_id is required" in e for e in errs)


def test_arch_cov_requirement_id_forbidden_and_critical():
    src = sorted(vi._RULE_ID_SOURCES)[0]
    data = {
        "threats": [
            {
                "source": src,
                "rule_id": "ARCH-AUTHZ-001",
                "requirement_id": "REQ-1",
                "risk": "Critical",
                "effective_severity": "Critical",
            }
        ]
    }
    errs = vi._check_architecture_coverage_invariants(data)
    assert any("requirement_id MUST NOT be set" in e for e in errs)
    assert any("MUST NOT be Critical" in e for e in errs)


def test_arch_cov_threat_hypothesis_requires_hyp_id():
    if "threat-hypothesis" not in vi._RULE_ID_SOURCES:
        pytest.skip("threat-hypothesis not a rule-id source")
    data = {"threats": [{"source": "threat-hypothesis", "rule_id": "ARCH-X-001"}]}
    errs = vi._check_architecture_coverage_invariants(data)
    assert any("hypothesis_id is required" in e for e in errs)


def test_arch_cov_skips_non_dict():
    assert vi._check_architecture_coverage_invariants({"threats": ["x"]}) == []


# --- _check_threat_hypotheses_invariants -----------------------------------


def test_threat_hypotheses_invariants():
    data = {
        "threats": [{"threat_id": "HYP-002"}],
        "threat_hypotheses": [
            "notadict",
            {"id": "bad"},
            {"id": "HYP-001"},
            {"id": "HYP-001"},  # dup
            {"id": "HYP-002"},  # collides with threats[].threat_id
            {"id": "HYP-003", "promoted_threat_id": "T-1", "proof_state": "evidence-backed"},
        ],
    }
    errs = vi._check_threat_hypotheses_invariants(data)
    assert any("must be an object" in e for e in errs)
    assert any("MUST match ^HYP" in e for e in errs)
    assert any("is duplicated" in e for e in errs)
    assert any("collides" in e for e in errs)
    assert any("promoted_threat_id is set but proof_state" in e for e in errs)


def test_threat_hypotheses_non_list_returns_empty():
    assert vi._check_threat_hypotheses_invariants({"threat_hypotheses": "x"}) == []


# --- _read_stride_profile --------------------------------------------------


def test_read_stride_profile_none():
    assert vi._read_stride_profile(None) == {}


def test_read_stride_profile_missing_file(tmp_path):
    assert vi._read_stride_profile(tmp_path) == {}


def test_read_stride_profile_reads(tmp_path):
    (tmp_path / ".stride-dispatch-manifest.json").write_text(
        _json.dumps({"stride_profile": {"skip_cvss_scoring": True}})
    )
    assert vi._read_stride_profile(tmp_path) == {"skip_cvss_scoring": True}


def test_read_stride_profile_non_dict_doc(tmp_path):
    (tmp_path / ".stride-dispatch-manifest.json").write_text("[]")
    assert vi._read_stride_profile(tmp_path) == {}


def test_read_stride_profile_string_label_in_manifest(tmp_path):
    # The manifest's stride_profile is analyst-authored and may be a bare
    # label string rather than the dict — it must not crash str.get and must
    # infer the CVSS waiver that the quick depth-reduced profile carries.
    (tmp_path / ".stride-dispatch-manifest.json").write_text(
        _json.dumps({"stride_profile": "quick (depth-reduced via sonnet-economy)"})
    )
    assert vi._read_stride_profile(tmp_path) == {
        "stride_profile_label": "quick (depth-reduced via sonnet-economy)",
        "skip_cvss_scoring": True,
    }


def test_read_stride_profile_string_label_full_carries_no_waiver(tmp_path):
    (tmp_path / ".stride-dispatch-manifest.json").write_text(_json.dumps({"stride_profile": "full"}))
    assert vi._read_stride_profile(tmp_path) == {}


def test_read_stride_profile_prefers_skill_config_dict(tmp_path):
    # .skill-config.json is the authoritative resolved-config source and wins
    # over the analyst-authored manifest label.
    (tmp_path / ".skill-config.json").write_text(
        _json.dumps({"stride_profile": {"skip_cvss_scoring": True, "stride_profile_label": "quick"}})
    )
    (tmp_path / ".stride-dispatch-manifest.json").write_text(_json.dumps({"stride_profile": "full"}))
    assert vi._read_stride_profile(tmp_path) == {
        "skip_cvss_scoring": True,
        "stride_profile_label": "quick",
    }


# --- validate_threats_merged with profile waiver ---------------------------


def test_validate_threats_merged_non_dict():
    ok, errs = vi.validate_threats_merged([])
    assert not ok and errs == ["root must be a JSON object"]


# --- _check_security_controls_shape ----------------------------------------


def test_security_controls_string_drift_v2():
    data = {"security_controls": ["bare", "string"], "meta": {"analysis_version": 2}}
    errs = vi._check_security_controls_shape(data)
    assert any("SCHEMA_DRIFT" in e for e in errs)


def test_security_controls_v1_not_flagged():
    data = {"security_controls": ["bare"], "meta": {"analysis_version": "notint"}}
    assert vi._check_security_controls_shape(data) == []


def test_security_controls_non_list():
    assert vi._check_security_controls_shape({"security_controls": {}}) == []


# --- _check_attack_surface_shape -------------------------------------------


def test_attack_surface_dict_bad_path_and_missing_auth():
    data = {
        "attack_surface": {
            "unauthenticated": ["notadict", {"method": "GET"}],
            "authenticated": [{"path": "/x", "auth_required": True}],
        }
    }
    errs = vi._check_attack_surface_shape(data)
    assert any("missing required" in e for e in errs)
    assert any("ADVISORY" in e for e in errs)


def test_attack_surface_list_form():
    data = {"attack_surface": [{"path": "/ok", "auth_required": False}]}
    assert vi._check_attack_surface_shape(data) == []


def test_attack_surface_other_type():
    assert vi._check_attack_surface_shape({"attack_surface": 5}) == []


# --- _check_triage_flags_version (dead returns []) -------------------------


def test_triage_flags_version_dead():
    assert vi._check_triage_flags_version({}) == []


# --- _normalise_mitigation_field_drift -------------------------------------


def test_mitigation_drift_migrates_legacy_fields():
    data = {
        "mitigations": [
            {"mitigation_title": "Fix it", "addresses": ["T-001"]},
            "skip",
        ]
    }
    notes = vi._normalise_mitigation_field_drift(data)
    assert data["mitigations"][0]["title"] == "Fix it"
    assert data["mitigations"][0]["threat_ids"] == ["T-001"]
    assert len(notes) == 2


# --- validate_threat_model_output non-dict ---------------------------------


def test_validate_threat_model_output_non_dict():
    ok, errs = vi.validate_threat_model_output([])
    assert not ok and errs == ["root must be a mapping"]


# --- _check_finding_id_contiguity ------------------------------------------


def test_finding_id_contiguity_gap():
    data = {"threats": [{"id": "F-001"}, {"id": "F-003"}, "x", {"id": "nope"}]}
    adv = vi._check_finding_id_contiguity(data)
    assert any("numbering has" in a for a in adv)


def test_finding_id_contiguity_no_ids():
    assert vi._check_finding_id_contiguity({"threats": [{"id": "nope"}]}) == []


def test_finding_id_contiguity_non_list():
    assert vi._check_finding_id_contiguity({"threats": "x"}) == []


def test_finding_id_contiguity_many_gaps():
    data = {"threats": [{"id": "F-001"}, {"id": "F-010"}]}
    adv = vi._check_finding_id_contiguity(data)
    assert "…" in adv[0]


# --- _check_component_path_glob_consistency non-list paths -----------------


def test_glob_consistency_non_list_components():
    assert vi._check_component_path_glob_consistency({"components": "x"}) == []


def test_glob_consistency_non_list_threats():
    assert vi._check_component_path_glob_consistency({"components": [], "threats": "x"}) == []


def test_glob_consistency_no_evidence_files_tolerated():
    data = {
        "components": [{"id": "c1", "paths": ["a/**"]}],
        "threats": [{"id": "T-1", "component": "c1", "evidence": []}],
    }
    assert vi._check_component_path_glob_consistency(data) == []


# --- _check_mitigations_nonempty -------------------------------------------


def test_mitigations_empty_with_ranked_threats():
    # Unrecoverable: ranked threat carries NO remediation content the backfill
    # could use → hard (non-advisory) error.
    data = {"mitigations": [], "threats": [{"risk": "High"}]}
    errs = vi._check_mitigations_nonempty(data)
    assert any("mitigations[] is empty" in e and not e.startswith("[advisory]") for e in errs)


def test_mitigations_present_returns_empty():
    assert vi._check_mitigations_nonempty({"mitigations": [{"id": "M-1"}]}) == []


def test_mitigations_empty_no_ranked_threats():
    assert vi._check_mitigations_nonempty({"mitigations": [], "threats": [{"risk": "Low"}]}) == []


def test_mitigations_empty_recoverable_with_remediation_is_advisory():
    # Regression (2026-06-16): empty register but ranked threats carry
    # remediation content → the deterministic backfill will populate it before
    # compose, so this is an ADVISORY, not a hard error.
    data = {"mitigations": [], "threats": [{"risk": "Critical", "remediation": {"steps": ["Use bind params"]}}]}
    errs = vi._check_mitigations_nonempty(data)
    assert errs and all(e.startswith("[advisory]") for e in errs)


def test_mitigations_empty_recoverable_config_scan_is_advisory():
    # config-scan threats are backfilled by emit_config_scan_mitigations.
    data = {"mitigations": [], "threats": [{"risk": "High", "source": "config-scan"}]}
    errs = vi._check_mitigations_nonempty(data)
    assert errs and all(e.startswith("[advisory]") for e in errs)


def test_mitigations_empty_mitigation_title_only_is_advisory():
    data = {"mitigations": [], "threats": [{"risk": "Critical", "mitigation_title": "Add ownership check"}]}
    errs = vi._check_mitigations_nonempty(data)
    assert errs and all(e.startswith("[advisory]") for e in errs)


def test_validator_valid_when_empty_register_recoverable():
    # Full validator: a schema-valid model with an empty register but
    # remediation-bearing ranked threats must be is_valid=True (advisory only).
    data = {
        "meta": {"generated": "2026-06-16T00:00:00Z"},
        "threats": [
            {
                "id": "T-001",
                "title": "SQL Injection",
                "risk": "Critical",
                "component": "api",
                "cwe": "CWE-89",
                "remediation": {"steps": ["Use parameterized queries"]},
            },
        ],
        "mitigations": [],
    }
    ok, msgs = vi.validate_threat_model_output(data)
    hard = [m for m in msgs if not m.startswith(("[advisory] ", "[migrated] "))]
    # The empty-register check itself must not contribute a hard error.
    assert not any("mitigations[] is empty" in m and not m.startswith("[advisory]") for m in hard)
    assert any(m.startswith("[advisory]") and "mitigations[] is empty" in m for m in msgs)


# --- _check_pt_id_sequence + validate_pentest_tasks ------------------------


def test_pt_id_sequence_dup_and_gap():
    data = {
        "tasks": [
            {"task_id": "PT-001"},
            {"task_id": "PT-003"},
            {"task_id": "PT-001"},
            {"task_id": 5},
            "x",
            {"task_id": "bad"},
        ]
    }
    errs = vi._check_pt_id_sequence(data)
    assert any("breaks sequential order" in e for e in errs)
    assert any("duplicated" in e for e in errs)


def test_validate_pentest_tasks_non_dict():
    ok, errs = vi.validate_pentest_tasks([])
    assert not ok and errs == ["root must be a mapping"]


# --- validate_known_threats / triage_flags non-dict ------------------------


def test_validate_known_threats_non_dict():
    ok, errs = vi.validate_known_threats([])
    assert not ok


def test_validate_triage_flags_non_dict():
    ok, errs = vi.validate_triage_flags([])
    assert not ok


def test_validate_triage_flags_v1_no_ranking():
    data = {"version": 1, "flags": [], "summary": {"total_flags": 0, "warnings": 0, "info": 0}}
    ok, errs = vi.validate_triage_flags(data)
    assert any("SCHEMA_DRIFT" in e for e in errs)


# --- config / source auth findings -----------------------------------------


def test_validate_config_scan_findings_non_dict():
    ok, errs = vi.validate_config_scan_findings([])
    assert not ok


def test_validate_config_scan_findings_dup_local_id():
    data = {"findings": [{"local_id": "CFG-1"}, {"local_id": "CFG-1"}, {"local_id": 5}, "x"]}
    ok, errs = vi.validate_config_scan_findings(data)
    assert any("duplicated" in e for e in errs)


def test_validate_config_scan_findings_parse_error_skips_invariant():
    data = {"parse_error": "boom"}
    # schema may error but the dup-check is skipped; just ensure callable
    vi.validate_config_scan_findings(data)


def test_validate_source_auth_findings_non_dict():
    ok, errs = vi.validate_source_auth_findings([])
    assert not ok


def test_validate_source_auth_findings_dup_local_id():
    data = {"findings": [{"local_id": "SA-1"}, {"local_id": "SA-1"}, {"local_id": 5}, "x"]}
    ok, errs = vi.validate_source_auth_findings(data)
    assert any("duplicated" in e for e in errs)


# ===========================================================================
# CLI main() via subprocess — exercise dispatch, advisories, yaml/json paths
# ===========================================================================


def test_main_usage_error_no_args():
    result = _run([])
    assert result.returncode == 2


def test_main_invalid_json_file(tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{bad json")
    result = _run(["stride", str(p)])
    assert result.returncode == 1
    assert "INVALID JSON" in result.stdout


def test_main_invalid_yaml_file(tmp_path):
    p = tmp_path / "x.yaml"
    p.write_text("a: b: c: : :\n  - [")
    result = _run(["threat_model_output", str(p)])
    assert result.returncode == 1
    assert "INVALID YAML" in result.stdout or "INVALID" in result.stdout


def test_main_valid_stride_summary(tmp_path):
    p = tmp_path / ".stride-x.json"
    p.write_text(
        _json.dumps(
            {
                "component_id": "svc",
                "component_name": "Svc",
                "analyzed_at": "2026-04-22T10:00:00Z",
                "threats": [],
            }
        )
    )
    result = _run(["stride", str(p)])
    assert result.returncode == 0
    assert "VALID: 0 threats" in result.stdout


def test_main_threat_model_output_with_advisory(tmp_path):
    # F-NNN gap → advisory printed, but otherwise may fail schema; we just
    # assert the ADVISORY line is emitted on stdout.
    p = tmp_path / "threat-model.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "mitigations": [{"mitigation_title": "x", "addresses": ["T-1"]}],
                "threats": [{"id": "F-001"}, {"id": "F-003"}],
            }
        )
    )
    result = _run(["threat_model_output", str(p)])
    assert "ADVISORY:" in result.stdout


# ===========================================================================
# In-process main() coverage (patch argv, catch SystemExit)
# ===========================================================================


def _main_exit(monkeypatch, argv):
    monkeypatch.setattr(vi.sys, "argv", ["validate_intermediate.py", *argv])
    with pytest.raises(SystemExit) as ei:
        vi.main()
    code = ei.value.code
    return code if code is not None else 0


def test_main_inproc_usage(monkeypatch, capsys):
    code = _main_exit(monkeypatch, [])
    assert code == 2
    assert "Usage:" in capsys.readouterr().err


def test_main_inproc_unknown_kind(monkeypatch, tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{}")
    assert _main_exit(monkeypatch, ["nope", str(p)]) == 2


def test_main_inproc_invalid_json(monkeypatch, tmp_path, capsys):
    p = tmp_path / "x.json"
    p.write_text("{bad")
    assert _main_exit(monkeypatch, ["stride", str(p)]) == 1
    assert "INVALID JSON" in capsys.readouterr().out


def test_main_inproc_invalid_yaml(monkeypatch, tmp_path, capsys):
    p = tmp_path / "x.yaml"
    p.write_text("a: b: c:\n  - [\n: :")
    code = _main_exit(monkeypatch, ["known_threats", str(p)])
    assert code == 1
    assert "INVALID" in capsys.readouterr().out


def test_main_inproc_oserror_missing(monkeypatch, tmp_path, capsys):
    code = _main_exit(monkeypatch, ["stride", str(tmp_path / "nope.json")])
    assert code == 1
    assert "cannot read file" in capsys.readouterr().out


def test_main_inproc_valid_stride(monkeypatch, tmp_path, capsys):
    p = tmp_path / ".stride-x.json"
    p.write_text(
        _json.dumps(
            {
                "component_id": "svc",
                "component_name": "Svc",
                "analyzed_at": "2026-04-22T10:00:00Z",
                "threats": [],
            }
        )
    )
    assert _main_exit(monkeypatch, ["stride", str(p)]) == 0
    assert "VALID: 0 threats" in capsys.readouterr().out


def test_main_inproc_invalid_stride_prints_errors(monkeypatch, tmp_path, capsys):
    p = tmp_path / ".stride-x.json"
    p.write_text("{}")
    assert _main_exit(monkeypatch, ["stride", str(p)]) == 1
    assert "INVALID:" in capsys.readouterr().out


def test_main_inproc_triage_flags_summary(monkeypatch, tmp_path, capsys):
    p = tmp_path / ".triage-flags.json"
    # Build a minimally-valid triage flags doc; if schema fails it still
    # exercises the summary branch path. Use empty flags.
    p.write_text(
        _json.dumps(
            {
                "version": 2,
                "generated_at": "2026-04-22T10:00:00Z",
                "flags": [],
                "summary": {"total_flags": 0, "warnings": 0, "info": 0},
                "ranking": {},
            }
        )
    )
    _main_exit(monkeypatch, ["triage_flags", str(p)])
    # whichever branch, output should mention flags or INVALID
    out = capsys.readouterr().out
    assert "flags" in out or "INVALID" in out


def test_main_inproc_pentest_tasks_summary(monkeypatch, tmp_path, capsys):
    p = tmp_path / "pentest-tasks.yaml"
    p.write_text(yaml.safe_dump({"tasks": []}))
    _main_exit(monkeypatch, ["pentest_tasks", str(p)])
    out = capsys.readouterr().out
    assert "tasks" in out or "INVALID" in out


def test_main_inproc_threat_model_output_advisory(monkeypatch, tmp_path, capsys):
    p = tmp_path / "threat-model.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "mitigations": [{"mitigation_title": "x", "addresses": ["T-1"]}],
                "threats": [{"id": "F-001"}, {"id": "F-003"}],
            }
        )
    )
    _main_exit(monkeypatch, ["threat_model_output", str(p)])
    assert "ADVISORY:" in capsys.readouterr().out


# --- validate_threat_model_output direct call (lines 765-786) --------------


def test_validate_threat_model_output_direct_runs_all_checks():
    data = {
        "security_controls": ["bare"],
        "meta": {"analysis_version": 2},
        "attack_surface": [{"method": "GET"}],
        "mitigations": [],
        "threats": [
            {"id": "F-001", "risk": "High", "component": "c1", "evidence": [{"file": "x/y.py"}]},
            {"id": "F-003"},
        ],
        "components": [{"id": "c1", "paths": ["a/**"]}],
        "threat_hypotheses": [{"id": "HYP-001"}],
    }
    ok, errs = vi.validate_threat_model_output(data)
    # Many invariants fire; just confirm structured outputs returned.
    assert isinstance(ok, bool)
    assert any("[advisory]" in e for e in errs) or any("SCHEMA_DRIFT" in e for e in errs)


def test_glob_consistency_suggestion_part_in_advisory():
    # 2+ distinct siblings match → suggestion list rendered (sugg_part path).
    data = {
        "components": [
            {"id": "c1", "paths": ["models/**"]},
            {"id": "c2", "paths": ["shared/**"]},
            {"id": "c3", "paths": ["shared/**"]},
        ],
        "threats": [
            {"id": "T-1", "component": "c1", "evidence": [{"file": "shared/u.ts"}]},
        ],
    }
    adv = vi._check_component_path_glob_consistency(data)
    assert adv and "consider one of" in adv[0]
