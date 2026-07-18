"""Tests for the P1/P2 mitigation actionability gate."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "validate_mitigation_quality.py"


def _load():
    spec = importlib.util.spec_from_file_location("validate_mitigation_quality", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


quality = _load()


def test_urgent_fix_requires_steps_and_verification():
    errors = quality.validate(
        {
            "mitigations": [
                {"id": "M-001", "priority": "P1", "kind": "fix", "steps": ["One step"]},
                {"id": "M-002", "priority": "P2", "steps": ["One", "Two"]},
            ]
        }
    )
    assert errors == [
        "M-001: P1 fix needs at least two concrete remediation steps (found 1)",
        "M-001: P1 fix needs a concrete verification (test, request + expected response, CI assertion, or config check)",
        "M-002: P2 fix needs a concrete verification (test, request + expected response, CI assertion, or config check)",
    ]


def test_non_urgent_and_non_fix_cards_are_outside_gate():
    errors = quality.validate(
        {
            "mitigations": [
                {"id": "M-001", "priority": "P3", "kind": "fix"},
                {"id": "M-002", "priority": "P1", "kind": "review"},
                {
                    "id": "M-003",
                    "priority": "P2",
                    "steps": ["Change the handler", "Add the regression test"],
                    "verification": "npm test -- auth.spec.ts",
                },
            ]
        }
    )
    assert errors == []


def test_urgent_code_example_needs_a_source_location():
    errors = quality.validate(
        {
            "mitigations": [
                {
                    "id": "M-004",
                    "priority": "P1",
                    "steps": ["Update the handler", "Add a regression test"],
                    "verification": "npm test -- handler.spec.ts",
                    "code_example": "safeHandler(input)",
                }
            ]
        }
    )
    assert errors == ["M-004: fix with a code example needs a source file location for the example introduction"]


def test_backlog_code_example_also_needs_a_source_location():
    errors = quality.validate(
        {"mitigations": [{"id": "M-005", "priority": "P3", "code_example": "safeHandler(input)"}]}
    )
    assert errors == ["M-005: fix with a code example needs a source file location for the example introduction"]
