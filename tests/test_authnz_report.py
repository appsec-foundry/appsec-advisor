"""Tests for scripts/model/authnz_report.py — category counts of the authnz-review
scanner sidecars and validation plus summary of `.authnz-report.json`."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import model.authnz_report as ar  # noqa: E402

SCRIPT = ROOT / "scripts" / "model" / "authnz_report.py"
AGENT = ROOT / "agents" / "appsec-authnz-analyzer.md"


def _write_json(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _scanner_finding(check_id: str, cwe: str) -> dict:
    return {"check_id": check_id, "file": "src/a.x", "line": 3, "cwe": [cwe]}


def _finding(fid: str, **over) -> dict:
    f = {
        "id": fid,
        "title": "Order lookup accepts any order id",
        "severity": "High",
        "category": "idor",
        "cwe": "CWE-639",
        "stride": "Elevation of Privilege",
        "source": "confirmed-instance",
        "component_id": "api",
        "evidence": [{"file": "src/orders.ts", "line": 12}],
        "attack_path": "A user reads another user's order by id.",
        "remediation": {"summary": "Scope the lookup to the caller.", "reference": "CWE-639 — Authorization Bypass"},
        "requirement_id": None,
        "requirement_url": None,
    }
    f.update(over)
    return f


def _report(findings: list[dict], **over) -> dict:
    r = {
        "partial": False,
        "analyzed_at": "2026-10-01T10:00:00Z",
        "findings": findings,
        "chain_findings": [],
        "stride_covered": [],
    }
    r.update(over)
    return r


# --- categories --------------------------------------------------------------


def test_every_authz_check_in_the_catalog_has_a_category():
    """A new language variant of an AuthZ/AuthN check lands in its class through
    its CWE, without a list of check ids to extend."""
    checks = yaml.safe_load((ROOT / "data" / "source-auth-checks.yaml").read_text(encoding="utf-8"))["checks"]
    checks += yaml.safe_load((ROOT / "data" / "credential-lifecycle-checks.yaml").read_text(encoding="utf-8"))["checks"]
    authz = [c for c in checks if re.match(r"AUTH[NZ]-", c["id"])]
    assert authz
    for c in authz:
        assert ar.category_of(c["cwe"]) in ar.CATEGORIES, c["id"]


def test_injection_and_mobile_checks_stay_out_of_scope():
    checks = yaml.safe_load((ROOT / "data" / "source-auth-checks.yaml").read_text(encoding="utf-8"))["checks"]
    for c in checks:
        if c["id"].startswith(("INJ-", "MOBILE-")):
            assert ar.category_of(c["cwe"]) is None, c["id"]


def test_agent_documents_the_same_cwe_table():
    rows = dict(re.findall(r"^\| (CWE-\d+) \| `(\w+)` \|$", AGENT.read_text(encoding="utf-8"), re.M))
    assert rows == ar.CATEGORY_BY_CWE


# --- counts ------------------------------------------------------------------


def test_counts_bucket_language_variants_by_cwe(tmp_path: Path):
    _write_json(
        tmp_path / ".source-auth-findings.json",
        {
            "findings": [
                _scanner_finding("AUTHZ-005", "CWE-347"),
                _scanner_finding("AUTHZ-GO-001", "CWE-345"),
                _scanner_finding("AUTHZ-PHP-002", "CWE-915"),
                _scanner_finding("AUTHZ-001", "CWE-639"),
                _scanner_finding("AUTHN-002", "CWE-521"),
                _scanner_finding("INJ-001", "CWE-89"),
            ]
        },
    )
    out = ar.scan_counts(tmp_path)
    assert out == {
        "scanner": {
            "idor": 1,
            "route_auth": 0,
            "mass_assign": 1,
            "jwt": 2,
            "credential": 1,
            "in_scope": 5,
            "out_of_scope": 1,
        }
    }


def test_counts_report_confirmed_and_unresolved(tmp_path: Path):
    _write_json(
        tmp_path / ".authz-confirm-findings.json",
        {
            "findings": [_scanner_finding("AUTHZ-301", "CWE-639"), _scanner_finding("AUTHZ-302", "CWE-862")],
            "unresolved_suspects": ["R-004", "R-009"],
        },
    )
    assert ar.scan_counts(tmp_path) == {"confirmed": {"idor": 1, "route_auth": 1, "total": 2, "unresolved_suspects": 2}}


def test_counts_cli_fails_closed_on_unreadable_sidecar(tmp_path: Path):
    (tmp_path / ".source-auth-findings.json").write_text("{not json", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "counts", "--output-dir", str(tmp_path)], capture_output=True, text=True
    )
    assert proc.returncode == 2
    assert ".source-auth-findings.json" in proc.stderr


# --- finalize ----------------------------------------------------------------


def test_finalize_computes_the_summary(tmp_path: Path):
    report = _report(
        [
            _finding("AZ-001", severity="Critical", category="jwt", cwe="CWE-347", stride="Spoofing", source="scanner"),
            _finding("AZ-002"),
            _finding("AZ-003", severity="Medium", source="hypothesis"),
            _finding(
                "AZ-004",
                category="mass_assign",
                cwe="CWE-915",
                source="scanner",
                privilege_escalation=True,
                requirement_id="SEC-AUTHZ-2",
            ),
        ],
        chain_findings=[{"root_id": "AZ-001", "root_title": "JWT forgeable", "chain_ids": ["AZ-002"], "impact": "x"}],
        stride_covered=[{"title": "t", "cwe": "CWE-862", "file": "a.ts", "stride_threat": "T-003"}],
    )
    path = _write_json(tmp_path / ".authnz-report.json", report)
    ar.finalize(path)
    summary = json.loads(path.read_text(encoding="utf-8"))["summary"]
    assert summary == {
        "total_findings": 4,
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 0,
        "idor_confirmed": 1,
        "idor_hypotheses": 1,
        "missing_auth": 0,
        "jwt_findings": 1,
        "credential_findings": 0,
        "privilege_escalation": 1,
        "requirements_annotated": 1,
        "stride_deduplicated": 1,
        "chains": 1,
    }


def test_finalize_replaces_a_hand_tallied_summary(tmp_path: Path):
    path = _write_json(tmp_path / ".authnz-report.json", _report([_finding("AZ-001")]))
    ar.finalize(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["summary"]["total_findings"] = 9
    _write_json(path, data)
    assert ar.finalize(path)["summary"]["total_findings"] == 1


def test_write_first_stub_is_valid(tmp_path: Path):
    stub = {
        "partial": True,
        "analyzed_at": "2026-10-01T10:00:00Z",
        "last_step": "start",
        "findings": [],
        "chain_findings": [],
        "stride_covered": [],
    }
    path = _write_json(tmp_path / ".authnz-report.json", stub)
    assert ar.finalize(path)["summary"]["total_findings"] == 0


def test_invalid_reports_are_rejected():
    no_evidence = _finding("AZ-001", evidence=[])
    unknown_source = _finding("AZ-001", source="jwt")
    missing_field = {k: v for k, v in _finding("AZ-001").items() if k != "category"}
    for bad in (no_evidence, unknown_source, missing_field):
        assert ar.report_errors(_report([bad])), bad


def test_duplicate_ids_and_dangling_chain_refs_are_rejected():
    dup = _report([_finding("AZ-001"), _finding("AZ-001")])
    assert any("duplicated" in e for e in ar.report_errors(dup))
    dangling = _report(
        [_finding("AZ-001")],
        chain_findings=[{"root_id": "AZ-001", "root_title": "r", "chain_ids": ["AZ-007"], "impact": "x"}],
    )
    assert any("AZ-007" in e for e in ar.report_errors(dangling))


def test_finalize_cli_fails_closed_and_leaves_the_file(tmp_path: Path):
    bad = _report([_finding("AZ-001", severity="Severe")])
    path = _write_json(tmp_path / ".authnz-report.json", bad)
    before = path.read_text(encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "finalize", "--report", str(path)], capture_output=True, text=True
    )
    assert proc.returncode == 2
    assert "invalid" in proc.stderr
    assert path.read_text(encoding="utf-8") == before


def test_finalize_cli_prints_the_summary(tmp_path: Path):
    path = _write_json(tmp_path / ".authnz-report.json", _report([_finding("AZ-001")]))
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "finalize", "--report", str(path)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["idor_confirmed"] == 1


def _signal_document():
    return {
        "version": 1,
        "generated_at": "2026-10-04T10:00:00Z",
        "checks_run": 1,
        "violations": 1,
        "findings": [
            {
                "local_id": "SAF-001",
                "check_id": "AUTHZ-002",
                "source_type": "nodejs_source",
                "file": "src/items.js",
                "line": 7,
                "title": "Object lookup lacks ownership filter",
                "scenario": "A caller substitutes another object identifier in the lookup.",
                "severity": "High",
                "cwe": ["CWE-639"],
                "evidence_snippet": "Items.findById(req.params.id)",
            }
        ],
    }


def test_finalize_retains_scanner_idor_without_a_route_suspect(tmp_path):
    doc = _signal_document()
    _write_json(tmp_path / ".source-auth-findings.json", doc)
    path = _write_json(tmp_path / ".authnz-report.json", _report([]))
    report = ar.finalize(path)
    assert report["findings"][0]["source"] == "scanner"
    assert report["signal_dispositions"][0]["finding_id"] == report["findings"][0]["id"]
    assert len(ar.finalize(path)["findings"]) == 1


def test_finalize_matches_instances_by_line_not_just_file(tmp_path):
    doc = _signal_document()
    _write_json(tmp_path / ".source-auth-findings.json", doc)
    path = _write_json(
        tmp_path / ".authnz-report.json", _report([_finding("AZ-001", evidence=[{"file": "src/items.js", "line": 30}])])
    )
    assert len(ar.finalize(path)["findings"]) == 2


def test_required_inputs_cannot_silently_disappear(tmp_path):
    import pytest

    path = _write_json(tmp_path / ".authnz-report.json", _report([]))
    with pytest.raises(ar.InputError):
        ar.finalize(path, require_inputs=True)


def test_gate_rejects_partial_empty_report_and_ignores_forged_counts(tmp_path):
    path = _write_json(tmp_path / ".authnz-report.json", _report([], partial=True))
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "gate", "--report", str(path)], capture_output=True, text=True
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["partial"]
    _write_json(path, _report([]))
    assert not ar.gate(path)["failed"]
    forged = _report([_finding("AZ-001")])
    forged["summary"] = ar.recompute_summary(_report([]))
    _write_json(path, forged)
    assert ar.gate(path)["failed"]


def test_unresolved_operation_permission_survives_empty_model_report(tmp_path):
    _write_json(
        tmp_path / ".route-inventory.json",
        {
            "version": 1,
            "coverage": {"frameworks_detected": ["express"], "unsupported_route_files": []},
            "routes": [
                {
                    "route_id": "R-001",
                    "method": "POST",
                    "path": "/records/export",
                    "framework": "express",
                    "handler_file": "api.js",
                    "handler_line": 4,
                    "authn_signal": "present",
                    "authz_signal": "unknown",
                    "management_surface": False,
                    "confidence": "medium",
                    "notes": ["authorization-review-required"],
                }
            ],
        },
    )
    path = _write_json(tmp_path / ".authnz-report.json", _report([]))
    report = ar.finalize(path)
    assert [(f["source"], f["category"], f["severity"]) for f in report["findings"]] == [
        ("hypothesis", "route_auth", "Medium")
    ]
    assert len(ar.finalize(path)["findings"]) == 1


def test_public_probe_inventory_does_not_create_a_missing_auth_finding(tmp_path):
    _write_json(
        tmp_path / ".route-inventory.json",
        {
            "version": 1,
            "coverage": {"frameworks_detected": ["express"], "unsupported_route_files": []},
            "routes": [
                {
                    "route_id": "R-001",
                    "method": "GET",
                    "path": "/health",
                    "framework": "express",
                    "handler_file": "api.js",
                    "handler_line": 4,
                    "authn_signal": "absent",
                    "authz_signal": "unknown",
                    "management_surface": True,
                    "confidence": "medium",
                    "notes": ["public-by-design"],
                }
            ],
        },
    )
    path = _write_json(tmp_path / ".authnz-report.json", _report([]))
    assert ar.finalize(path)["findings"] == []
    assert not ar.gate(path)["failed"]


def test_invalid_signal_cannot_partially_overwrite_a_report(tmp_path):
    import pytest

    doc = _signal_document()
    doc["findings"][0]["line"] = None
    _write_json(tmp_path / ".source-auth-findings.json", doc)
    path = _write_json(tmp_path / ".authnz-report.json", _report([]))
    before = path.read_bytes()
    with pytest.raises(ar.InputError):
        ar.finalize(path)
    assert path.read_bytes() == before
