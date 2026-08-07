"""Contract tests for the evidence-verifier side-channel artifact."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "evidence-verification.schema.json"


def _valid_artifact() -> dict:
    return {
        "version": 1,
        "generated_at": "2026-08-06T12:00:00Z",
        "model_id": "sonnet",
        "depth": "standard",
        "summary": {
            "total_threats": 8,
            "sampled": 2,
            "verified": 1,
            "refuted": 0,
            "ambiguous": 0,
            "unchecked": 1,
        },
        "flags": [
            {
                "flag_id": "EV-001",
                "t_id": "T-001",
                "verdict": "verified",
                "reason": "The cited line contains the claimed sink.",
                "line_excerpt": "db.query(userInput)",
            }
        ],
    }


def _errors(value: dict) -> list:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return list(Draft202012Validator(schema).iter_errors(value))


def test_representative_evidence_verification_artifact_validates() -> None:
    assert not _errors(_valid_artifact())


def test_guard_annotations_remain_inside_the_contract() -> None:
    artifact = _valid_artifact()
    artifact.update(
        {
            "verification_gate": "fallback_required",
            "verification_gate_reason": "The verifier returned no verdicts.",
            "verification_gate_at": "2026-08-06T12:01:00Z",
            "degenerate_neutralized": True,
            "degenerate_reason": "All sampled outcomes were ambiguous.",
            "degenerate_neutralized_at": "2026-08-06T12:01:01Z",
        }
    )
    assert not _errors(artifact)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("model_id"),
        lambda value: value.__setitem__("depth", "fast"),
        lambda value: value["summary"].__setitem__("sampled", -1),
        lambda value: value["flags"][0].__setitem__("flag_id", "EV-one"),
        lambda value: value["flags"][0].__setitem__("verdict", "unknown"),
        lambda value: value.__setitem__("unexpected", True),
    ],
    ids=["missing-model", "bad-depth", "negative-count", "bad-flag-id", "bad-verdict", "extra-field"],
)
def test_evidence_verification_schema_rejects_invalid_shape(mutate) -> None:
    artifact = _valid_artifact()
    mutate(artifact)
    assert _errors(artifact)
