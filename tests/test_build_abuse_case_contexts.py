from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_abuse_case_contexts as contexts  # noqa: E402
import context_routing as routing  # noqa: E402


def _match(candidate_id: str = "AC-T-001") -> dict:
    case = {
        "id": candidate_id,
        "title": "Stored script to token theft",
        "source": "mandatory",
        "attacker": {"actor_id": "anonymous", "initial_access": "unauthenticated"},
        "goal": "Steal an authenticated session.",
        "chain": [
            {
                "step": 1,
                "label": "Inject script",
                "grants": "script execution",
                "required": True,
                "probe": {
                    "entry_points": {"endpoint_patterns": ["/feedback"], "file_hints": ["routes/"]},
                    "sink_patterns": ["innerHTML"],
                    "control_patterns": ["sanitize"],
                    "control_sufficiency": "any",
                },
            }
        ],
    }
    return {
        "abuse_case_id": candidate_id,
        "title": case["title"],
        "source": "mandatory",
        "applicable": True,
        "structural_verdict": "candidate",
        "reason": None,
        "matched_finding_ids": ["T-001"],
        "step_matches": [
            {
                "step": 1,
                "label": "Inject script",
                "required": True,
                "grants": "script execution",
                "requires": None,
                "matched": True,
                "matched_finding_id": "T-001",
                "evidence": {"file": "routes/feedback.ts", "line": 12},
                "match_basis": "finding",
                "controls_found": [],
            }
        ],
        "case": case,
    }


def _schema_errors(value: dict) -> list:
    schema = json.loads((ROOT / "schemas/abuse-case-verifier-context.schema.json").read_text())
    return list(Draft202012Validator(schema).iter_errors(value))


def test_candidate_projection_is_exact_source_bound_and_schema_valid(tmp_path: Path) -> None:
    source = {"schema_version": 1, "matches": [_match()]}
    source_path = tmp_path / ".abuse-case-matches.json"
    source_path.write_text(json.dumps(source), encoding="utf-8")

    path = contexts.write_candidate(tmp_path, "AC-T-001")
    value = json.loads(path.read_text())

    assert value["source"]["sha256"] == hashlib.sha256(source_path.read_bytes()).hexdigest()
    assert value["candidate"]["chain"][0]["probe"]["sink_patterns"] == ["innerHTML"]
    assert value["candidate"]["step_matches"][0]["matched_finding_id"] == "T-001"
    assert value["limits"]["serialized_bytes"] == path.stat().st_size
    assert not _schema_errors(value)


def test_candidate_projection_rejects_non_candidate(tmp_path: Path) -> None:
    row = _match()
    row["structural_verdict"] = "not_applicable"
    payload = json.dumps({"matches": [row]}).encode()

    with pytest.raises(contexts.AbuseContextError, match="not eligible"):
        contexts.project_candidate(payload, "AC-T-001")


def test_candidate_projection_rejects_duplicate_candidate_ids() -> None:
    row = _match()
    payload = json.dumps({"matches": [row, row]}).encode()

    with pytest.raises(contexts.AbuseContextError, match="exactly one"):
        contexts.project_candidate(payload, "AC-T-001")


def test_candidate_projection_rejects_oversized_pattern_list() -> None:
    row = _match()
    row["case"]["chain"][0]["probe"]["sink_patterns"] = [f"sink-{index}" for index in range(33)]
    payload = json.dumps({"matches": [row]}).encode()

    with pytest.raises(contexts.AbuseContextError, match="exceeds 32"):
        contexts.project_candidate(payload, "AC-T-001")


def test_default_library_candidates_project_without_schema_or_chain_loss(tmp_path: Path) -> None:
    library = yaml.safe_load((ROOT / "data/abuse-cases/default-library.yaml").read_text())
    matches = []
    for case in library["abuse_cases"]:
        matches.append(
            {
                "abuse_case_id": case["id"],
                "title": case["title"],
                "source": case["source"],
                "structural_verdict": "candidate",
                "reason": None,
                "step_matches": [
                    {
                        "step": step["step"],
                        "label": step["label"],
                        "required": step.get("required", True),
                        "grants": step["grants"],
                        "requires": step.get("requires"),
                        "matched": False,
                        "matched_finding_id": None,
                        "evidence": None,
                        "match_basis": None,
                        "controls_found": [],
                    }
                    for step in case["chain"]
                ],
                "case": case,
            }
        )
    (tmp_path / ".abuse-case-matches.json").write_text(
        json.dumps({"schema_version": 1, "matches": matches}), encoding="utf-8"
    )

    for case in library["abuse_cases"]:
        path = contexts.write_candidate(tmp_path, case["id"])
        projected = json.loads(path.read_text())
        assert len(projected["candidate"]["chain"]) == len(case["chain"])
        assert len(projected["candidate"]["step_matches"]) == len(case["chain"])
        assert not _schema_errors(projected)
        profile = json.loads((ROOT / "data" / "context-routing-bindings.json").read_text())["limit_profiles"][
            "abuse_candidate"
        ]
        routing._enforce_limits(  # noqa: SLF001
            "abuse_cases.matches",
            routing._counts(path.read_bytes(), record_count=len(projected["candidate"])),  # noqa: SLF001
            profile,
        )
