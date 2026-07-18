"""Regression tests for deterministic scanner-remediation backfill.

Scanner findings (source-auth / crypto / config-iac) carry only a one-line
``mitigation_title``; the P1/P2 quality gate needs >=2 steps + a verification on
the fix card ``build_mitigations`` synthesises for them. This backfill writes a
structured ``remediation`` block so ``hydrate_mitigation_details`` can promote it
and the gate is satisfiable by construction.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "backfill_scanner_remediation.py"


def _load():
    spec = importlib.util.spec_from_file_location("backfill_scanner_remediation", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


bf = _load()
CHECKS = bf._load_check_index(ROOT)


def test_backfill_uses_check_library_and_names_check_in_verification():
    data = {
        "threats": [
            {
                "id": "T-1",
                "source": "source-scan",
                "source_check_id": "AUTHZ-001",
                "cwe": "CWE-639",
                "mitigation_title": "one-line title fallback",
                "evidence": [{"file": "routes/basket.ts", "line": 37}],
            }
        ]
    }
    assert bf.backfill(data, CHECKS) == 1
    rem = data["threats"][0]["remediation"]
    assert len(rem["steps"]) == 2
    # Step 1 is the library remediation (preferred over the mitigation_title).
    assert rem["steps"][0].startswith("Replace req.body.UserId")
    assert "regression test" in rem["steps"][1]
    assert "AUTHZ-001" in rem["verification"]
    assert "routes/basket.ts:37" in rem["verification"]


def test_backfill_config_threat_resolves_by_config_check_id():
    data = {
        "threats": [
            {
                "id": "T-2",
                "source": "config-scan",
                "config_check_id": "IAC-010",
                "mitigation_title": "Add permissions block",
                "evidence": [{"file": ".github/workflows/ci.yml", "line": 1}],
            }
        ]
    }
    assert bf.backfill(data, CHECKS) == 1
    rem = data["threats"][0]["remediation"]
    assert len(rem["steps"]) == 2
    assert "IAC-010" in rem["verification"]


def test_backfill_falls_back_to_mitigation_title_when_check_unknown():
    data = {
        "threats": [
            {
                "id": "T-3",
                "source": "source-scan",
                "source_check_id": "UNKNOWN-999",
                "cwe": "CWE-284",
                "mitigation_title": "Do the concrete fix described here.",
            }
        ]
    }
    assert bf.backfill(data, CHECKS) == 1
    rem = data["threats"][0]["remediation"]
    # Check id not in library → step 1 falls back to the mitigation_title …
    assert rem["steps"][0] == "Do the concrete fix described here."
    # … while the verification still names the scanner's finding id.
    assert "UNKNOWN-999" in rem["verification"]


def test_backfill_verification_uses_cwe_when_no_check_id():
    data = {
        "threats": [
            {
                "id": "T-3b",
                "source": "architecture-coverage",
                "cwe": "CWE-319",
                "mitigation_title": "Enforce TLS on all transport.",
            }
        ]
    }
    assert bf.backfill(data, CHECKS) == 1
    assert "CWE-319" in data["threats"][0]["remediation"]["verification"]


def test_backfill_skips_threat_without_any_instruction():
    data = {"threats": [{"id": "T-4", "source": "source-scan", "mitigation_title": ""}]}
    assert bf.backfill(data, CHECKS) == 0
    assert data["threats"][0].get("remediation") in (None, {})


def test_backfill_preserves_authored_remediation_and_is_idempotent():
    data = {
        "threats": [
            {
                "id": "T-5",
                "source": "source-scan",
                "source_check_id": "AUTHZ-001",
                "remediation": {"steps": ["Authored step one", "Authored step two"], "verification": "authored"},
            }
        ]
    }
    assert bf.backfill(data, CHECKS) == 0
    assert data["threats"][0]["remediation"]["steps"] == ["Authored step one", "Authored step two"]


def test_backfill_second_pass_is_idempotent():
    data = {
        "threats": [
            {
                "id": "T-6",
                "source": "source-scan",
                "source_check_id": "AUTHZ-001",
                "mitigation_title": "t",
                "evidence": [{"file": "a.ts", "line": 1}],
            }
        ]
    }
    assert bf.backfill(data, CHECKS) == 1
    assert bf.backfill(data, CHECKS) == 0
