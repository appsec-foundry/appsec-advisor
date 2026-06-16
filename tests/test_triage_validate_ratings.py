"""Unit tests for triage_validate_ratings.py — deterministic pre-flight
rating validation (Steps 1–5) for `.threats-merged.json`.

Tests target the step implementations directly (fast, precise coverage) plus
the `main()` CLI path via the import-and-call route with monkeypatched argv,
covering: cross-component consistency, severity plausibility, P1/P2 priority,
rating completeness, CVSS scope, and the file-IO / flag-merge driver."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import triage_validate_ratings as tvr  # noqa: E402  (sys.path set above)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _threat(**over):
    """A field-complete, matrix-coherent base threat that passes Step 4."""
    base = {
        "t_id": "T-001",
        "component_id": "comp-api",
        "stride": "Tampering",
        "risk": "High",
        "likelihood": "High",
        "impact": "Medium",
        "cwe": "CWE-89",
        "evidence": {"file": "routes/login.ts", "line": 34},
        "source": "stride",
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_severity_diff():
    assert tvr._severity_diff("Low", "Critical") == 3
    assert tvr._severity_diff("High", "High") == 0
    assert tvr._severity_diff("bogus", "High") == 3  # unknown → 0


def test_load_cvss_eligible_none_root():
    assert tvr._load_cvss_eligible(None) == frozenset()


def test_load_cvss_eligible_missing_file(tmp_path):
    assert tvr._load_cvss_eligible(tmp_path) == frozenset()


def test_load_cvss_eligible_reads_real_data():
    eligible = tvr._load_cvss_eligible(PLUGIN_ROOT)
    assert "CWE-89" in eligible


def test_load_cvss_eligible_malformed_returns_empty(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "cvss-eligible-cwes.yaml").write_text("{[ not yaml", encoding="utf-8")
    assert tvr._load_cvss_eligible(tmp_path) == frozenset()


def test_resolve_plugin_root_finds_root():
    # output_dir under the real plugin resolves to the plugin root.
    assert tvr._resolve_plugin_root(PLUGIN_ROOT) == PLUGIN_ROOT


def test_resolve_plugin_root_not_found(tmp_path):
    assert tvr._resolve_plugin_root(tmp_path) is None


# ---------------------------------------------------------------------------
# Step 1 — cross-component consistency
# ---------------------------------------------------------------------------


def test_step1_flags_cwe_severity_gap_same_source():
    threats = [
        _threat(t_id="T-001", cwe="CWE-89", risk="Critical", component_id="A"),
        _threat(t_id="T-002", cwe="CWE-89", risk="Low", component_id="B"),
    ]
    flags = tvr._step1_cross_component_consistency(threats, "standard")
    consistency = [f for f in flags if f["type"] == "consistency"]
    assert consistency
    assert consistency[0]["severity"] == "warning"
    assert "T-001" in consistency[0]["threat_ids"]


def test_step1_skips_small_gap():
    threats = [
        _threat(t_id="T-001", cwe="CWE-89", risk="High"),
        _threat(t_id="T-002", cwe="CWE-89", risk="Medium"),
    ]
    flags = tvr._step1_cross_component_consistency(threats, "quick")
    assert flags == []


def test_step1_skips_architectural_violation():
    threats = [
        _threat(t_id="T-001", cwe="CWE-89", risk="Critical", architectural_violation=True),
        _threat(t_id="T-002", cwe="CWE-89", risk="Low"),
    ]
    flags = tvr._step1_cross_component_consistency(threats, "quick")
    assert flags == []


def test_step1_skips_different_source():
    threats = [
        _threat(t_id="T-001", cwe="CWE-89", risk="Critical", source="stride"),
        _threat(t_id="T-002", cwe="CWE-89", risk="Low", source="dep-scan"),
    ]
    flags = tvr._step1_cross_component_consistency(threats, "quick")
    assert flags == []


def test_step1_single_member_group_no_flag():
    threats = [_threat(cwe="CWE-89")]
    assert tvr._step1_cross_component_consistency(threats, "quick") == []


def test_step1_empty_cwe_ignored():
    threats = [_threat(t_id="T-001", cwe="", risk="Critical"), _threat(t_id="T-002", cwe="", risk="Low")]
    assert tvr._step1_cross_component_consistency(threats, "quick") == []


def test_step1_title_pattern_consistency_standard():
    threats = [
        _threat(
            t_id="T-001",
            cwe="CWE-1",
            stride="Spoofing",
            title="Auth bypass on login",
            risk="Critical",
            component_id="A",
        ),
        _threat(
            t_id="T-002", cwe="CWE-2", stride="Spoofing", title="Auth bypass on login", risk="Low", component_id="B"
        ),
    ]
    flags = tvr._step1_cross_component_consistency(threats, "standard")
    # CWEs differ so no cwe-group flag; title+stride match drives the second branch.
    assert any("Similar Spoofing threats" in f["message"] for f in flags)


def test_step1_title_pattern_same_component_skipped():
    threats = [
        _threat(t_id="T-001", cwe="CWE-1", stride="Spoofing", title="Auth bypass", risk="Critical", component_id="A"),
        _threat(t_id="T-002", cwe="CWE-2", stride="Spoofing", title="Auth bypass", risk="Low", component_id="A"),
    ]
    flags = tvr._step1_cross_component_consistency(threats, "thorough")
    assert not any("Similar" in f["message"] for f in flags)


# ---------------------------------------------------------------------------
# Step 2 — severity plausibility
# ---------------------------------------------------------------------------


def test_step2_quick_returns_empty():
    assert tvr._step2_severity_plausibility([_threat()], "quick") == []


def test_step2_must_be_high_flag():
    threats = [_threat(cwe="CWE-89", risk="Medium", evidence={"file": "x.ts"})]
    flags = tvr._step2_severity_plausibility(threats, "standard")
    assert any(f["type"] == "plausibility" and "at least High" in f["message"] for f in flags)


def test_step2_must_be_high_no_flag_when_high():
    threats = [_threat(cwe="CWE-89", risk="High", evidence={"file": "x.ts"})]
    assert tvr._step2_severity_plausibility(threats, "standard") == []


def test_step2_known_vuln_eop_min_high():
    threats = [_threat(source="known-vuln", stride="Elevation of Privilege", risk="Low", cwe="CWE-1", evidence={})]
    flags = tvr._step2_severity_plausibility(threats, "standard")
    assert any("known-vuln threat with Elevation of Privilege" in f["message"] for f in flags)


def test_step2_repudiation_critical_info_flag():
    threats = [_threat(stride="Repudiation", risk="Critical", cwe="CWE-1", evidence={})]
    flags = tvr._step2_severity_plausibility(threats, "thorough")
    assert any(f["severity"] == "info" and "Repudiation" in f["message"] for f in flags)


def test_step2_info_disclosure_admin_path_critical():
    threats = [
        _threat(
            stride="Information Disclosure",
            risk="Critical",
            cwe="CWE-1",
            evidence={"file": "src/admin/panel.ts"},
        )
    ]
    flags = tvr._step2_severity_plausibility(threats, "standard")
    assert any("admin/internal path" in f["message"] for f in flags)


def test_step2_info_disclosure_with_arch_violation_no_flag():
    threats = [
        _threat(
            stride="Information Disclosure",
            risk="Critical",
            cwe="CWE-1",
            architectural_violation=True,
            evidence={"file": "src/admin/panel.ts"},
        )
    ]
    flags = tvr._step2_severity_plausibility(threats, "standard")
    assert not any("admin/internal path" in f["message"] for f in flags)


def test_step2_evidence_not_dict_handled():
    threats = [_threat(cwe="CWE-89", risk="Low", evidence="not-a-dict")]
    # ev_file becomes "" so must-be-high gate doesn't fire; no crash.
    assert tvr._step2_severity_plausibility(threats, "standard") == []


# ---------------------------------------------------------------------------
# Step 3 — priority validation
# ---------------------------------------------------------------------------


def test_step3_quick_returns_empty():
    assert tvr._step3_priority_validation([_threat(risk="Critical")], "quick") == []


def test_step3_known_vuln_critical_info():
    threats = [_threat(risk="Critical", source="known-vuln")]
    flags = tvr._step3_priority_validation(threats, "standard")
    assert any("P1 candidate" in f["message"] for f in flags)


def test_step3_no_criticals_many_highs():
    threats = [_threat(t_id=f"T-00{i}", risk="High") for i in range(3)]
    flags = tvr._step3_priority_validation(threats, "standard")
    assert any("No Critical threats found" in f["message"] for f in flags)


def test_step3_rce_not_highest_ranked_thorough():
    # Non-RCE critical T-001 ranks before RCE critical T-005 → flag.
    threats = [
        _threat(t_id="T-001", risk="Critical", cwe="CWE-200"),
        _threat(t_id="T-005", risk="Critical", cwe="CWE-89"),
        _threat(t_id="T-009", risk="High", cwe="CWE-1"),
    ]
    flags = tvr._step3_priority_validation(threats, "thorough")
    assert any("RCE/injection Critical threats are not the highest" in f["message"] for f in flags)


def test_step3_rce_highest_ranked_no_flag():
    threats = [
        _threat(t_id="T-001", risk="Critical", cwe="CWE-89"),
        _threat(t_id="T-005", risk="Critical", cwe="CWE-200"),
        _threat(t_id="T-009", risk="High", cwe="CWE-1"),
    ]
    flags = tvr._step3_priority_validation(threats, "thorough")
    assert not any("not the highest" in f["message"] for f in flags)


# ---------------------------------------------------------------------------
# Step 4 — rating completeness
# ---------------------------------------------------------------------------


def test_step4_clean_threat_no_flag():
    # High likelihood × Medium impact → High (matches risk).
    assert tvr._step4_rating_completeness([_threat()]) == []


def test_step4_all_fields_invalid():
    bad = {
        "t_id": "BAD",
        "stride": "Nonsense",
        "risk": "Severe",
        "likelihood": "Always",
        "impact": "Huge",
        "cwe": "89",
        "evidence": "string",
        "source": "made-up",
    }
    flags = tvr._step4_rating_completeness([bad])
    assert len(flags) == 1
    msg = flags[0]["message"]
    assert "t_id missing or does not match" in msg
    assert "component_id missing" in msg
    assert "not a valid STRIDE" in msg
    assert "evidence.file missing" in msg
    assert "not a valid source type" in msg


def test_step4_matrix_mismatch_flag():
    # Low likelihood × Low impact → matrix expects Low; we claim Critical.
    bad = _threat(likelihood="Low", impact="Low", risk="Critical")
    flags = tvr._step4_rating_completeness([bad])
    assert any("does not match Likelihood×Impact matrix" in f["message"] for f in flags)


def test_step4_matrix_mismatch_suppressed_by_arch_violation():
    bad = _threat(likelihood="Low", impact="Low", risk="Critical", architectural_violation=True)
    assert tvr._step4_rating_completeness([bad]) == []


def test_step4_critical_likelihood_skips_matrix():
    # likelihood Critical is not a matrix row key → no matrix check, valid otherwise.
    t = _threat(likelihood="Critical", impact="Low", risk="Critical")
    assert tvr._step4_rating_completeness([t]) == []


# ---------------------------------------------------------------------------
# Step 5 — CVSS scope
# ---------------------------------------------------------------------------


def test_step5_cvss_required_missing():
    threats = [_threat(source="dep-scan", cwe="CWE-89")]  # no cvss_v4
    flags = tvr._step5_cvss_scope(threats, frozenset(), "standard")
    assert any(f["type"] == "cvss_missing" for f in flags)


def test_step5_cvss_forbidden_present():
    threats = [_threat(source="requirements-compliance", cvss_v4={"severity": "High"})]
    flags = tvr._step5_cvss_scope(threats, frozenset(), "standard")
    assert any(f["type"] == "cvss_scope_violation" and "not permitted" in f["message"] for f in flags)


def test_step5_stride_cwe_not_eligible():
    threats = [_threat(source="stride", cwe="CWE-999", cvss_v4={"severity": "High"}, evidence={"file": "x", "line": 5})]
    flags = tvr._step5_cvss_scope(threats, frozenset({"CWE-89"}), "standard")
    assert any("not in cvss-eligible-cwes.yaml" in f["message"] for f in flags)


def test_step5_stride_missing_line():
    threats = [_threat(source="stride", cwe="CWE-89", cvss_v4={"severity": "High"}, evidence={"file": "x"})]
    flags = tvr._step5_cvss_scope(threats, frozenset({"CWE-89"}), "standard")
    assert any("evidence.line is null" in f["message"] for f in flags)


def test_step5_band_mismatch_info():
    # cvss severity Critical (band 4) vs risk Low (band 1) → diff 3 ≥ 2 → info flag.
    threats = [
        _threat(
            source="stride",
            cwe="CWE-89",
            risk="Low",
            cvss_v4={"severity": "Critical"},
            evidence={"file": "x", "line": 1},
        )
    ]
    flags = tvr._step5_cvss_scope(threats, frozenset({"CWE-89"}), "thorough")
    assert any(f["type"] == "cvss_band_mismatch" for f in flags)


def test_step5_no_cvss_no_flag_for_optional_source():
    threats = [_threat(source="stride", cvss_v4=None)]
    flags = tvr._step5_cvss_scope(threats, frozenset(), "quick")
    assert flags == []


# ---------------------------------------------------------------------------
# main() driver — via monkeypatched argv
# ---------------------------------------------------------------------------


def _run_main(monkeypatch, output_dir, *extra):
    monkeypatch.setattr(sys, "argv", ["triage_validate_ratings.py", str(output_dir), *extra])
    return tvr.main()


def test_main_missing_input_returns_1(monkeypatch, tmp_path):
    assert _run_main(monkeypatch, tmp_path) == 1


def test_main_malformed_json_returns_1(monkeypatch, tmp_path):
    (tmp_path / ".threats-merged.json").write_text("{ not json", encoding="utf-8")
    assert _run_main(monkeypatch, tmp_path) == 1


def test_main_writes_flags_file(monkeypatch, tmp_path):
    threats = [
        _threat(t_id="T-001", cwe="CWE-89", risk="Critical", component_id="A"),
        _threat(t_id="T-002", cwe="CWE-89", risk="Low", component_id="B"),
    ]
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": threats}), encoding="utf-8")
    rc = _run_main(monkeypatch, tmp_path, "--depth", "standard")
    assert rc == 0
    out = json.loads((tmp_path / ".triage-flags.json").read_text())
    assert out["version"] == 1
    assert out["summary"]["threats_reviewed"] == 2
    assert out["flags"]
    assert all(f["flag_id"].startswith("TF-") for f in out["flags"])
    assert all(f["source"] == "triage-pre-flight" for f in out["flags"])


def test_main_merges_existing_flags_and_continues_ids(monkeypatch, tmp_path):
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps(
            {
                "threats": [
                    _threat(cwe="CWE-89", risk="Critical"),
                    _threat(t_id="T-002", cwe="CWE-89", risk="Low", component_id="B"),
                ]
            }
        ),
        encoding="utf-8",
    )
    existing = {
        "version": 1,
        "flags": [{"flag_id": "TF-005", "severity": "info", "threat_ids": ["T-099"]}],
        "ranking": {"computed_by": "x"},
    }
    (tmp_path / ".triage-flags.json").write_text(json.dumps(existing), encoding="utf-8")
    rc = _run_main(monkeypatch, tmp_path)
    assert rc == 0
    out = json.loads((tmp_path / ".triage-flags.json").read_text())
    # Existing TF-005 preserved; new flags start at TF-006.
    ids = [f["flag_id"] for f in out["flags"]]
    assert "TF-005" in ids
    assert any(i == "TF-006" for i in ids)
    # ranking block preserved.
    assert out["ranking"] == {"computed_by": "x"}


def test_main_corrupt_existing_flags_treated_empty(monkeypatch, tmp_path):
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": []}), encoding="utf-8")
    (tmp_path / ".triage-flags.json").write_text("garbage{", encoding="utf-8")
    rc = _run_main(monkeypatch, tmp_path)
    assert rc == 0
    out = json.loads((tmp_path / ".triage-flags.json").read_text())
    assert out["summary"]["total_flags"] == 0


def test_main_unknown_args_warned_not_fatal(monkeypatch, tmp_path, capsys):
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": []}), encoding="utf-8")
    rc = _run_main(monkeypatch, tmp_path, "--bogus-flag", "value")
    assert rc == 0
    err = capsys.readouterr().err
    assert "Ignoring unrecognised argument" in err


def test_main_falls_back_to_env_output_dir(monkeypatch, tmp_path):
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": []}), encoding="utf-8")
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["triage_validate_ratings.py"])  # no positional
    assert tvr.main() == 0
    assert (tmp_path / ".triage-flags.json").is_file()


def test_main_write_failure_returns_1(monkeypatch, tmp_path):
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": []}), encoding="utf-8")

    def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(tvr, "atomic_write_json", _boom)
    assert _run_main(monkeypatch, tmp_path) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
