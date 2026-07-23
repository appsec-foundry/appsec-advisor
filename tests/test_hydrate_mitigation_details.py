"""Regression tests for canonical mitigation-detail hydration."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "hydrate_mitigation_details.py"
GATE_SCRIPT = ROOT / "scripts" / "validate_mitigation_quality.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


hydrate = _load("hydrate_mitigation_details", SCRIPT)
gate = _load("validate_mitigation_quality", GATE_SCRIPT)


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


def test_hydrate_rescues_card_via_reverse_link_when_forward_link_empty():
    """prune_dangling can empty a card's forward threat_ids while a real threat
    still points at it via mitigation_ids; hydration must use the reverse link."""
    data = {
        "threats": [
            {
                "id": "T-001",
                "risk": "Critical",
                "mitigation_ids": ["M-901"],
                "remediation": {
                    "steps": ["Bind parameters", "Add a regression test"],
                    "verification": "A quote in email returns HTTP 401.",
                },
            }
        ],
        # Forward link emptied (dangling T-034 pruned away); reverse link intact.
        "mitigations": [{"id": "M-901", "kind": "fix", "priority": "P1", "threat_ids": []}],
    }

    assert hydrate.hydrate(data) == 1
    card = data["mitigations"][0]
    assert card["steps"] == ["Bind parameters", "Add a regression test"]
    assert card["verification"].startswith("A quote")
    # The emptied forward link is backfilled from the reverse referrer.
    assert card["threat_ids"] == ["T-001"]


def test_hydrate_drops_content_free_orphan_fix_card():
    """A fix card with no link in either direction and no steps/code is noise."""
    data = {
        "threats": [{"id": "T-010", "risk": "High", "mitigation_ids": ["M-500"]}],
        "mitigations": [
            {"id": "M-500", "kind": "fix", "priority": "P1", "threat_ids": ["T-010"]},
            {"id": "M-777", "kind": "fix", "priority": "P1", "addresses": []},
        ],
    }

    assert hydrate.hydrate(data) == 1
    assert [m["id"] for m in data["mitigations"]] == ["M-500"]


def test_hydrate_keeps_orphan_review_card_and_orphan_fix_with_steps():
    """The drop is scoped to content-free fix cards only."""
    data = {
        "threats": [],
        "mitigations": [
            {"id": "M-1", "kind": "review", "priority": "P1", "addresses": []},
            {
                "id": "M-2",
                "kind": "fix",
                "priority": "P1",
                "addresses": [],
                "steps": ["a", "b"],
                "verification": "v",
            },
        ],
    }

    assert hydrate.hydrate(data) == 0
    assert [m["id"] for m in data["mitigations"]] == ["M-1", "M-2"]


def test_hydrate_synthesizes_verification_for_urgent_fix_without_source():
    """An auto-emitted P2 finding-fix card whose addressed threat has steps but no
    verification (and no scanner check for backfill to key off) must get a
    synthesized concrete verification, so the P1/P2 quality gate is satisfiable by
    the producer instead of a downstream hand-patch (M-084/T-088 abort-loop)."""
    data = {
        "threats": [
            {
                "id": "T-088",
                "remediation": {"effort": "Low", "steps": ["Redirect HTTP to HTTPS", "Add HSTS header"]},
            }
        ],
        "mitigations": [
            {
                "id": "M-084",
                "kind": "fix",
                "priority": "P2",
                "threat_ids": ["T-088"],
                "prevents": ["CWE-319"],
            }
        ],
    }

    assert hydrate.hydrate(data) == 1
    card = data["mitigations"][0]
    assert card["steps"] == ["Redirect HTTP to HTTPS", "Add HSTS header"]
    assert "CWE-319" in card["verification"]
    # The whole point: the P1/P2 quality gate now passes for this card.
    assert gate.validate(data) == []


def test_hydrate_does_not_synthesize_verification_for_non_urgent_fix():
    """Synthesis is scoped to P1/P2 — the gate only enforces verification there,
    so a P3 fix must be left untouched (surgical blast radius)."""
    data = {
        "threats": [
            {"id": "T-050", "remediation": {"steps": ["Do the thing", "Add a test"]}},
        ],
        "mitigations": [
            {"id": "M-050", "kind": "fix", "priority": "P3", "threat_ids": ["T-050"], "prevents": ["CWE-200"]},
        ],
    }

    assert hydrate.hydrate(data) == 1  # steps still hydrated
    assert "verification" not in data["mitigations"][0]


def test_hydrate_reverse_linked_stepless_fix_card_is_not_orphan():
    """A stepless fix card referenced by a threat via mitigation_ids has a link
    and must NOT be dropped — the orphan drop is scoped to truly-unlinked cards."""
    data = {
        "threats": [{"id": "T-020", "risk": "Low", "mitigation_ids": ["M-800", "M-801"]}],
        "mitigations": [
            {"id": "M-800", "kind": "fix", "priority": "P3", "addresses": [], "steps": ["x", "y"]},
            {"id": "M-801", "kind": "fix", "priority": "P3", "addresses": []},
        ],
    }

    assert hydrate.hydrate(data) == 0
    assert [m["id"] for m in data["mitigations"]] == ["M-800", "M-801"]
