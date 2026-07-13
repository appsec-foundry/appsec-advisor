"""Regression tests for canonical mitigation-detail hydration."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "hydrate_mitigation_details.py"


def _load():
    spec = importlib.util.spec_from_file_location("hydrate_mitigation_details", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


hydrate = _load()


def test_hydrate_promotes_details_from_addressed_findings():
    data = {
        "threats": [
            {
                "id": "T-001",
                "evidence": {"file": "routes/login.ts", "line": 34},
                "remediation": {
                    "steps": ["Replace interpolation with bound parameters", "Add a regression test"],
                    "code_example": "db.query(sql, { replacements: { email } })",
                    "verification": "Run login-sqli.spec.ts; a quote in email returns HTTP 401.",
                    "reference": "https://example.test/sqli",
                },
            },
            {
                "id": "T-002",
                "remediation": {"steps": ["Audit remaining raw query calls", "Add a regression test"]},
            },
        ],
        "mitigations": [{"id": "M-001", "kind": "fix", "threat_ids": ["T-001", "T-002"]}],
    }

    assert hydrate.hydrate(data) == 1
    card = data["mitigations"][0]
    assert card["steps"] == [
        "Replace interpolation with bound parameters",
        "Add a regression test",
        "Audit remaining raw query calls",
    ]
    assert card["code_example"].startswith("db.query")
    assert card["verification"].startswith("Run login-sqli")
    assert card["reference"] == "https://example.test/sqli"
    assert card["file"] == "routes/login.ts:34"


def test_hydrate_preserves_authored_detail_and_skips_review_cards():
    data = {
        "threats": [
            {
                "id": "T-001",
                "remediation": {
                    "steps": ["Source step"],
                    "verification": "Source verification",
                },
            }
        ],
        "mitigations": [
            {
                "id": "M-001",
                "kind": "fix",
                "threat_ids": ["T-001"],
                "verification": "Authored verification",
            },
            {"id": "M-002", "kind": "review", "threat_ids": ["T-001"]},
        ],
    }

    assert hydrate.hydrate(data) == 1
    assert data["mitigations"][0]["verification"] == "Authored verification"
    assert data["mitigations"][0]["steps"] == ["Source step"]
    assert "steps" not in data["mitigations"][1]
