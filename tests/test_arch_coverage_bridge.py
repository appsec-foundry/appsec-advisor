"""Tests for the architecture-coverage bridge (arch.md §Phase-9-Bruecke)
and the validator invariants on architecture-coverage / threat-hypothesis
sources."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).parent.parent
BRIDGE = REPO_ROOT / "scripts" / "arch_coverage_to_threats.py"
VALIDATOR = REPO_ROOT / "scripts" / "validate_intermediate.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import validate_intermediate as vi  # noqa: E402
import arch_coverage_to_threats as bridge  # noqa: E402


# ---------------------------------------------------------------------------
# Validator: new sources, CVSS-forbidden, rule_id discipline
# ---------------------------------------------------------------------------


def _merged(threat: dict, hypotheses: list[dict] | None = None) -> dict:
    out = {
        "version": 1,
        "generated_at": "2026-05-16T00:00:00Z",
        "threats": [{
            "t_id": "T-001",
            "component_id": "architecture",
            "component_name": "Architecture",
            "stride": "Tampering",
            "risk": "High",
            "likelihood": "Medium",
            "impact": "High",
            "title": "CORS wildcard with credentials",
            "cwe": "CWE-942",
            "evidence": {"file": "server.ts", "line": 3},
            "source": "stride",
            "architectural_violation": True,
            **threat,
        }],
    }
    if hypotheses is not None:
        out["threat_hypotheses"] = hypotheses
    return out


def test_validator_accepts_architecture_coverage_source_no_cvss() -> None:
    data = _merged({"source": "architecture-coverage", "rule_id": "ARCH-CORS-001"})
    ok, errs = vi.validate_threats_merged(data)
    assert ok, errs


def test_validator_rejects_cvss_on_architecture_coverage() -> None:
    data = _merged({
        "source": "architecture-coverage",
        "rule_id": "ARCH-CORS-001",
        "cvss_v4": {
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "base_score": 9.8, "severity": "Critical", "source": "manual",
        },
    })
    ok, errs = vi.validate_threats_merged(data)
    assert not ok
    assert any("cvss_v4 is not permitted" in e for e in errs)


def test_validator_rejects_arch_source_without_rule_id() -> None:
    data = _merged({"source": "architecture-coverage"})  # missing rule_id
    ok, errs = vi.validate_threats_merged(data)
    assert not ok
    assert any("rule_id is required" in e for e in errs)


def test_validator_rejects_rule_id_on_stride_source() -> None:
    data = _merged({"rule_id": "ARCH-CORS-001"})  # source defaults to stride
    ok, errs = vi.validate_threats_merged(data)
    assert not ok
    assert any("rule_id is only permitted" in e for e in errs)


def test_validator_rejects_requirement_id_on_architecture_coverage() -> None:
    data = _merged({
        "source": "architecture-coverage",
        "rule_id": "ARCH-CORS-001",
        "requirement_id": "REQ-FAKE-1",
    })
    ok, errs = vi.validate_threats_merged(data)
    assert not ok
    assert any("requirement_id MUST NOT be set" in e for e in errs)


def test_validator_rejects_critical_on_architecture_coverage() -> None:
    data = _merged({
        "source": "architecture-coverage",
        "rule_id": "ARCH-CORS-001",
        "risk": "Critical",
        "impact": "Critical",
    })
    ok, errs = vi.validate_threats_merged(data)
    assert not ok
    assert any("MUST NOT be Critical" in e for e in errs)


def test_validator_requires_hypothesis_id_on_threat_hypothesis_source() -> None:
    data = _merged({
        "source": "threat-hypothesis",
        "rule_id": "ARCH-SQLI-001",
    })  # missing hypothesis_id
    ok, errs = vi.validate_threats_merged(data)
    assert not ok
    assert any("hypothesis_id is required" in e for e in errs)


def test_validator_accepts_threat_hypothesis_source_complete() -> None:
    data = _merged({
        "source": "threat-hypothesis",
        "rule_id": "ARCH-SQLI-001",
        "hypothesis_id": "ARCH-HYP-SQLI-001",
        "cwe": "CWE-89",
    })
    ok, errs = vi.validate_threats_merged(data)
    assert ok, errs


def test_validator_rejects_invalid_hyp_id_pattern() -> None:
    """Validator runs on threats-merged; the threat-hypothesis source check
    requires the HYP id matches ARCH-HYP-<TOKEN>-NNN."""
    data = _merged({
        "source": "threat-hypothesis",
        "rule_id": "ARCH-SQLI-001",
        "hypothesis_id": "HYP-001",  # wrong pattern for hypothesis_id on threats[]
    })
    ok, errs = vi.validate_threats_merged(data)
    assert not ok
    assert any("hypothesis_id" in e for e in errs)


# ---------------------------------------------------------------------------
# threat_hypotheses[] invariants (validator on final threat-model.yaml)
# ---------------------------------------------------------------------------


def test_hypotheses_collision_with_t_ids_rejected() -> None:
    """HYP-NNN must not collide with any T-NNN."""
    data = _merged(
        {"source": "stride"},  # T-001 in threats[]
        hypotheses=[{
            "id": "T-001",  # collision (also wrong pattern)
            "source_hypothesis_id": "ARCH-HYP-SQLI-001",
            "rule_id": "ARCH-SQLI-001",
            "title": "x",
            "threat_category_id": "TH-01",
            "cwe": "CWE-89",
            "proof_state": "control-derived",
            "confidence": "medium",
        }],
    )
    errs = vi._check_threat_hypotheses_invariants(data)
    assert any("id MUST match" in e for e in errs) or any("collides" in e for e in errs)


def test_promoted_threat_id_requires_confirmed() -> None:
    data = {
        "threat_hypotheses": [{
            "id": "HYP-001",
            "source_hypothesis_id": "ARCH-HYP-SQLI-001",
            "rule_id": "ARCH-SQLI-001",
            "title": "x",
            "threat_category_id": "TH-01",
            "cwe": "CWE-89",
            "proof_state": "control-derived",  # not confirmed
            "confidence": "medium",
            "promoted_threat_id": "T-007",      # invalid: not confirmed
        }],
    }
    errs = vi._check_threat_hypotheses_invariants(data)
    assert any("promoted_threat_id" in e and "confirmed" in e for e in errs)


def test_promoted_threat_id_accepted_when_confirmed() -> None:
    data = {
        "threat_hypotheses": [{
            "id": "HYP-001",
            "source_hypothesis_id": "ARCH-HYP-SQLI-001",
            "rule_id": "ARCH-SQLI-001",
            "title": "x",
            "threat_category_id": "TH-01",
            "cwe": "CWE-89",
            "proof_state": "confirmed",
            "confidence": "high",
            "promoted_threat_id": "T-007",
        }],
    }
    errs = vi._check_threat_hypotheses_invariants(data)
    assert errs == []


# ---------------------------------------------------------------------------
# Bridge: emit + merge-into
# ---------------------------------------------------------------------------


def _coverage_fixture(
    anti_patterns: list[dict] | None = None,
    hypotheses: list[dict] | None = None,
) -> dict:
    return {
        "version": 1,
        "generated_at": "2026-05-16T00:00:00Z",
        "repo_root": "/tmp/repo",
        "rules_evaluated": [
            {"rule_id": "ARCH-CORS-001", "title": "CORS wildcard combined with credentials",
             "status": "anti_pattern", "applies": True, "confidence": "high",
             "control": "CORS Policy", "domain": "FrontendSec", "evidence": [],
             "decision": "emit_control_and_threat_candidate"},
        ],
        "control_assessments": [],
        "threat_hypotheses": hypotheses or [],
        "anti_pattern_candidates": anti_patterns or [],
        "warnings": [],
    }


def test_bridge_emits_anti_pattern_as_architecture_coverage_source(tmp_path: Path) -> None:
    cov = _coverage_fixture(anti_patterns=[{
        "rule_id": "ARCH-CORS-001",
        "title": "CORS wildcard origin combined with credentials",
        "architectural_theme": "SecureDefaults",
        "generic_threat_title": "Cross-origin request abuse through permissive CORS",
        "cwe": "CWE-942",
        "domain": "FrontendSec",
        "severity_cap": "High",
        "evidence": [{"file": "src/server.ts", "line": 7, "signal": "origin: '*'"}],
        "confidence": "high",
        "must_not_carry_cvss": True,
    }])
    threats, skipped = bridge.select_and_build(cov)
    assert len(threats) == 1
    t = threats[0]
    assert t["source"] == "architecture-coverage"
    assert t["rule_id"] == "ARCH-CORS-001"
    assert t["title"] == "Cross-origin request abuse through permissive CORS"
    assert "weakness_id" not in t
    assert t["architectural_theme"] == "SecureDefaults"
    assert t["generic_threat_title"] == "Cross-origin request abuse through permissive CORS"
    assert t["cwe"] == "CWE-942"
    assert t["risk"] == "High"
    assert t["risk"] != "Critical"
    assert "cvss_v4" not in t
    assert t["evidence"]["file"] == "src/server.ts"
    assert t["evidence"]["line"] == 7
    assert skipped == []


def test_bridge_skips_unconfirmed_hypotheses() -> None:
    cov = _coverage_fixture(hypotheses=[
        {"hypothesis_id": "ARCH-HYP-SQLI-001", "rule_id": "ARCH-SQLI-001",
         "title": "SQLi exposure", "threat_category_id": "TH-01",
         "stride": "Tampering", "cwe": "CWE-89", "proof_state": "control-derived",
         "confidence": "medium", "weak_or_missing_controls": ["Parameterized Queries"],
         "positive_signals": [], "decision": "emit_hypothesis_only"},
        {"hypothesis_id": "ARCH-HYP-XSS-001", "rule_id": "ARCH-XSS-001",
         "title": "XSS exposure", "threat_category_id": "TH-11",
         "stride": "Tampering", "cwe": "CWE-79", "proof_state": "evidence-backed",
         "confidence": "high", "weak_or_missing_controls": ["Output Encoding"],
         "positive_signals": [], "decision": "emit_hypothesis_only"},
    ])
    threats, skipped = bridge.select_and_build(cov)
    assert threats == []
    assert len(skipped) == 2
    assert all("control-derived" in s["reason"] or "evidence-backed" in s["reason"] for s in skipped)


def test_bridge_emits_confirmed_hypothesis_as_threat_hypothesis_source() -> None:
    cov = _coverage_fixture(hypotheses=[{
        "hypothesis_id": "ARCH-HYP-SQLI-001", "rule_id": "ARCH-SQLI-001",
        "title": "SQLi confirmed", "threat_category_id": "TH-01",
        "architectural_theme": "InputValidation",
        "generic_threat_title": "Injection through missing centralized input validation",
        "stride": "Tampering", "cwe": "CWE-89", "proof_state": "confirmed",
        "confidence": "high", "weak_or_missing_controls": ["Parameterized Queries"],
        "positive_signals": [{"file": "src/login.ts", "line": 12, "signal": "raw SQL"}],
        "decision": "promote_to_threat_candidate",
    }])
    threats, skipped = bridge.select_and_build(cov)
    assert len(threats) == 1
    t = threats[0]
    assert t["source"] == "threat-hypothesis"
    assert t["hypothesis_id"] == "ARCH-HYP-SQLI-001"
    assert t["rule_id"] == "ARCH-SQLI-001"
    assert t["title"] == "Injection through missing centralized input validation"
    assert "weakness_id" not in t
    assert t["architectural_theme"] == "InputValidation"
    assert t["cwe"] == "CWE-89"
    assert t["risk"] in {"High", "Medium", "Low"}
    assert skipped == []


def test_bridge_normalises_stride_no_space_to_spaced() -> None:
    cov = _coverage_fixture(anti_patterns=[{
        "rule_id": "ARCH-TLS-001",
        "title": "TLS",
        "cwe": "CWE-319",
        "domain": "DataProt",
        "severity_cap": "High",
        "evidence": [{"file": "db.ts", "line": 1, "signal": "sslmode=disable"}],
        "confidence": "high",
        "must_not_carry_cvss": True,
    }])
    threats, _ = bridge.select_and_build(cov)
    assert threats[0]["stride"] == "Information Disclosure"


def test_bridge_skips_low_confidence_candidates() -> None:
    cov = _coverage_fixture(anti_patterns=[{
        "rule_id": "ARCH-TLS-001", "title": "TLS", "cwe": "CWE-319",
        "domain": "DataProt", "severity_cap": "High",
        "evidence": [{"file": "db.ts", "line": 1, "signal": "x"}],
        "confidence": "medium",
        "must_not_carry_cvss": True,
    }])
    threats, skipped = bridge.select_and_build(cov)
    assert threats == []
    assert len(skipped) == 1


def test_bridge_merge_into_assigns_contiguous_t_ids(tmp_path: Path) -> None:
    merged = tmp_path / ".threats-merged.json"
    merged.write_text(json.dumps({
        "version": 1, "generated_at": "2026-05-16T00:00:00Z",
        "threats": [
            {"t_id": "T-001", "source": "stride", "title": "x", "cwe": "CWE-79",
             "stride": "Tampering", "risk": "High", "likelihood": "High",
             "impact": "High", "component_id": "c", "component_name": "C",
             "evidence": {"file": "a", "line": 1}, "architectural_violation": False,
             # F-10 RC.I — STRIDE-sourced threats MUST carry threat_category_id (v2).
             "threat_category_id": "TH-11"},
        ],
    }))
    new_threats = [{
        "t_id": None, "source": "architecture-coverage", "rule_id": "ARCH-CORS-001",
        "title": "CORS", "cwe": "CWE-942", "stride": "Tampering",
        "risk": "High", "likelihood": "Medium", "impact": "High",
        "component_id": "architecture", "component_name": "Architecture",
        "evidence": {"file": "s.ts", "line": 1}, "architectural_violation": True,
    }]
    result = bridge.merge_into(merged, new_threats)
    assert result["appended"] == ["T-002"]
    data = json.loads(merged.read_text())
    assert data["threats"][-1]["t_id"] == "T-002"
    ok, errs = vi.validate_threats_merged(data)
    assert ok, errs


def test_end_to_end_bridge_via_cli(tmp_path: Path) -> None:
    """Full pipeline: synthetic repo → inventory → engine → bridge → validator."""
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    (repo / "server.ts").write_text(
        "app.use(cors({origin:'*', credentials:true}));\n"
        "const dsn='postgres://u:p@h/db?sslmode=disable';\n"
    )
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "route_inventory.py"),
                    "--repo-root", str(repo), "--output-dir", str(out)],
                   check=True, capture_output=True)
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "architecture_coverage_checks.py"),
                    "--repo-root", str(repo), "--output-dir", str(out)],
                   check=True, capture_output=True)

    (out / ".threats-merged.json").write_text(
        '{"version":1,"generated_at":"2026-05-16T00:00:00Z","threats":[]}\n'
    )
    subprocess.run([sys.executable, str(BRIDGE), "merge-into",
                    "--input", str(out / ".architecture-coverage.json"),
                    "--threats-merged", str(out / ".threats-merged.json")],
                   check=True, capture_output=True)

    merged = json.loads((out / ".threats-merged.json").read_text())
    rule_ids = [t.get("rule_id") for t in merged["threats"]]
    assert "ARCH-CORS-001" in rule_ids
    assert "ARCH-TLS-001" in rule_ids
    for t in merged["threats"]:
        assert t["source"] == "architecture-coverage"
        assert "cvss_v4" not in t
        assert t["risk"] != "Critical"

    ok, errs = vi.validate_threats_merged(merged)
    assert ok, errs


# ---------------------------------------------------------------------------
# persist-hypotheses mode (arch.md gap F — Phase 11 data persistence)
# ---------------------------------------------------------------------------


import yaml as _yaml  # noqa: E402


def _coverage_with_hyps(*hypotheses) -> dict:
    return {
        "version": 1, "rules_evaluated": [],
        "control_assessments": [], "anti_pattern_candidates": [],
        "warnings": [], "threat_hypotheses": list(hypotheses),
    }


def _src_hyp(**overrides) -> dict:
    base = {
        "hypothesis_id": "ARCH-HYP-SQLI-001",
        "rule_id": "ARCH-SQLI-001",
        "title": "SQL injection exposure",
        "threat_category_id": "TH-01",
        "stride": "Tampering",
        "cwe": "CWE-89",
        "proof_state": "control-derived",
        "confidence": "medium",
        "weak_or_missing_controls": ["Parameterized Queries"],
        "positive_signals": [{"file": "routes/login.ts", "line": 34, "signal": "raw SQL"}],
        "decision": "emit_hypothesis_only",
    }
    base.update(overrides)
    return base


def test_persist_creates_yaml_with_hyp_ids(tmp_path: Path) -> None:
    cov = _coverage_with_hyps(_src_hyp(
        architectural_theme="InputValidation",
        generic_threat_title="Injection through missing centralized input validation",
        domain="InputVal",
    ))
    yaml_path = tmp_path / "threat-model.yaml"
    result = bridge.persist_hypotheses(cov, yaml_path)
    assert result["appended"] == ["HYP-001"]
    doc = _yaml.safe_load(yaml_path.read_text())
    hyp = doc["threat_hypotheses"][0]
    assert hyp["id"] == "HYP-001"
    assert hyp["source_hypothesis_id"] == "ARCH-HYP-SQLI-001"
    assert hyp["title"] == "Injection through missing centralized input validation"
    assert "weakness_id" not in hyp
    assert hyp["architectural_theme"] == "InputValidation"
    assert hyp["generic_threat_title"] == "Injection through missing centralized input validation"
    assert hyp["domain"] == "InputVal"
    assert hyp["promoted_threat_id"] is None


def test_persist_is_idempotent_on_source_id(tmp_path: Path) -> None:
    cov = _coverage_with_hyps(_src_hyp())
    yaml_path = tmp_path / "threat-model.yaml"
    bridge.persist_hypotheses(cov, yaml_path)
    result = bridge.persist_hypotheses(cov, yaml_path)
    assert result["appended"] == []
    doc = _yaml.safe_load(yaml_path.read_text())
    assert len(doc["threat_hypotheses"]) == 1


def test_persist_assigns_contiguous_hyp_ids(tmp_path: Path) -> None:
    cov = _coverage_with_hyps(
        _src_hyp(hypothesis_id="ARCH-HYP-SQLI-001"),
        _src_hyp(hypothesis_id="ARCH-HYP-XSS-001", rule_id="ARCH-XSS-001", cwe="CWE-79"),
    )
    yaml_path = tmp_path / "threat-model.yaml"
    result = bridge.persist_hypotheses(cov, yaml_path)
    assert result["appended"] == ["HYP-001", "HYP-002"]


def test_persist_continues_numbering_from_existing(tmp_path: Path) -> None:
    yaml_path = tmp_path / "threat-model.yaml"
    yaml_path.write_text(_yaml.safe_dump({
        "threat_hypotheses": [{
            "id": "HYP-005",
            "source_hypothesis_id": "ARCH-HYP-OLD-001",
            "rule_id": "ARCH-XSS-001",
            "title": "x", "threat_category_id": "TH-11",
            "cwe": "CWE-79", "proof_state": "control-derived",
            "confidence": "low",
        }],
    }))
    cov = _coverage_with_hyps(_src_hyp(hypothesis_id="ARCH-HYP-SQLI-002"))
    result = bridge.persist_hypotheses(cov, yaml_path)
    assert result["appended"] == ["HYP-006"]


def test_persist_links_promoted_threat_id_when_in_merged(tmp_path: Path) -> None:
    yaml_path = tmp_path / "threat-model.yaml"
    cov = _coverage_with_hyps(_src_hyp())
    bridge.persist_hypotheses(cov, yaml_path)
    # Second run with .threats-merged.json carrying a promotion
    merged = {"threats": [{
        "t_id": "T-007",
        "source": "threat-hypothesis",
        "hypothesis_id": "ARCH-HYP-SQLI-001",
        "rule_id": "ARCH-SQLI-001",
    }]}
    result = bridge.persist_hypotheses(cov, yaml_path, merged)
    assert result["updated"] == ["HYP-001"]
    doc = _yaml.safe_load(yaml_path.read_text())
    assert doc["threat_hypotheses"][0]["promoted_threat_id"] == "T-007"


def test_persist_emits_default_validation_objective(tmp_path: Path) -> None:
    cov = _coverage_with_hyps(_src_hyp(rule_id="ARCH-XSS-001", cwe="CWE-79"))
    yaml_path = tmp_path / "threat-model.yaml"
    bridge.persist_hypotheses(cov, yaml_path)
    doc = _yaml.safe_load(yaml_path.read_text())
    objective = doc["threat_hypotheses"][0]["validation_objective"]
    assert "browser-rendered" in objective


def test_persist_skips_hypothesis_without_id(tmp_path: Path) -> None:
    cov = _coverage_with_hyps({
        "rule_id": "ARCH-SQLI-001",
        "title": "broken",
        "threat_category_id": "TH-01",
        "stride": "Tampering", "cwe": "CWE-89",
        "proof_state": "control-derived", "confidence": "medium",
        "weak_or_missing_controls": [],
        "positive_signals": [],
        "decision": "emit_hypothesis_only",
        # no hypothesis_id
    })
    yaml_path = tmp_path / "threat-model.yaml"
    result = bridge.persist_hypotheses(cov, yaml_path)
    assert result["appended"] == []
    assert len(result["skipped"]) == 1


def test_persist_preserves_unrelated_yaml_keys(tmp_path: Path) -> None:
    yaml_path = tmp_path / "threat-model.yaml"
    yaml_path.write_text(_yaml.safe_dump({
        "meta": {"schema_version": 1, "project": "test"},
        "components": [{"id": "C-01", "name": "X"}],
    }))
    cov = _coverage_with_hyps(_src_hyp())
    bridge.persist_hypotheses(cov, yaml_path)
    doc = _yaml.safe_load(yaml_path.read_text())
    assert doc["meta"]["project"] == "test"
    assert doc["components"][0]["id"] == "C-01"
    assert len(doc["threat_hypotheses"]) == 1


def test_persist_cli(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    cov_path = out / ".architecture-coverage.json"
    cov_path.write_text(json.dumps(_coverage_with_hyps(_src_hyp())))
    yaml_path = out / "threat-model.yaml"
    proc = subprocess.run(
        [sys.executable, str(BRIDGE), "persist-hypotheses",
         "--input", str(cov_path), "--threat-model", str(yaml_path)],
        capture_output=True, text=True, check=True,
    )
    assert "HYP-001" in proc.stdout
    doc = _yaml.safe_load(yaml_path.read_text())
    assert doc["threat_hypotheses"][0]["id"] == "HYP-001"
