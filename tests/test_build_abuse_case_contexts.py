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

import contexts.build_abuse_case_contexts as contexts  # noqa: E402
import contexts.context_routing as routing  # noqa: E402


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


def test_candidate_projection_embeds_bounded_exact_source_window(tmp_path: Path) -> None:
    source = {"schema_version": 1, "matches": [_match()]}
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(source), encoding="utf-8")
    target = tmp_path / "routes" / "feedback.ts"
    target.parent.mkdir()
    target.write_text("\n".join(f"line {number}" for number in range(1, 25)) + "\n", encoding="utf-8")

    path = contexts.write_candidate(tmp_path, "AC-T-001", repo_root=tmp_path)
    value = json.loads(path.read_text())
    window = value["candidate"]["step_matches"][0]["source_window"]

    assert window["file"] == "routes/feedback.ts"
    assert window["start_line"] == 4
    assert window["end_line"] == 20
    assert "line 12" in window["content"]
    assert value["limits"]["source_chars"] == len(window["content"])
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


def _descriptive_match(repo: Path) -> dict:
    sys.path.insert(0, str(ROOT / "scripts"))
    import model.match_abuse_cases as matcher  # noqa: PLC0415

    case = {
        "id": "REPO-AC-020",
        "kind": "descriptive",
        "title": "Delegated administrator grants themselves a role",
        "actor": "Delegated administrator",
        "initial_access": "authenticated_high_priv",
        "goal": "Obtain a role outside the delegation.",
        "boundary": "Roles the delegation permits.",
        "steps": ["Assign a role to themselves.", "Choose a role outside the delegation."],
        "expected_controls": ["The assignment checks the delegation."],
        "exclusions": ["Administrators who may assign every role."],
        "scope_qualifier": {"path_patterns": ["src/roles/*"]},
    }
    finding = {
        "t_id": "F-007",
        "title": "Role field accepted from body",
        "cwe": "CWE-915",
        "evidence": {"file": "src/roles/assign.ts", "line": 3},
    }
    return matcher.match_case(case, [finding], None, repo_root=repo)


def test_descriptive_candidate_projects_prose_sources_and_finding_windows(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "src" / "roles").mkdir(parents=True)
    (repo / "src" / "roles" / "assign.ts").write_text("a\nb\nuser.roles.push(req.body.role)\nc\n")
    payload = json.dumps({"matches": [_descriptive_match(repo)]}).encode()
    value = contexts.project_candidate(payload, "REPO-AC-020", repo_root=repo)
    schema = json.loads((ROOT / "schemas" / "abuse-case-verifier-context.schema.json").read_text())
    value["limits"]["serialized_bytes"] = 1
    Draft202012Validator(schema).validate(value)
    candidate = value["candidate"]
    assert candidate["kind"] == "descriptive"
    assert [s["label"] for s in candidate["steps"]] == [
        "Assign a role to themselves.",
        "Choose a role outside the delegation.",
    ]
    assert candidate["preselected_sources"] == ["src/roles/assign.ts"]
    window = candidate["related_findings"][0]["source_window"]
    assert "user.roles.push" in window["content"]
    assert value["limits"]["source_chars"] == len(window["content"])
    assert "probe" not in json.dumps(candidate)


def _abuse_candidate_limits() -> dict:
    bindings = json.loads((ROOT / "data" / "context-routing-bindings.json").read_text())
    return bindings["limit_profiles"]["abuse_candidate"]


def test_descriptive_candidate_fits_the_dispatch_limits(tmp_path: Path):
    """The controller counts candidate fields against ``max_items``; a
    descriptive candidate over it aborted every abuse case of a run."""
    repo = tmp_path / "repo"
    (repo / "src" / "roles").mkdir(parents=True)
    (repo / "src" / "roles" / "assign.ts").write_text("a\nb\nuser.roles.push(req.body.role)\nc\n")
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps({"matches": [_descriptive_match(repo)]}))
    path = contexts.write_candidate(tmp_path, "REPO-AC-020", repo_root=repo)
    projected = json.loads(path.read_text())
    routing._enforce_limits(  # noqa: SLF001
        "abuse_cases.matches",
        routing._counts(path.read_bytes(), record_count=len(projected["candidate"])),  # noqa: SLF001
        _abuse_candidate_limits(),
    )


def test_every_candidate_shape_fits_the_item_limit():
    """Adding a candidate field must not outgrow the dispatch item limit."""
    schema = json.loads((ROOT / "schemas" / "abuse-case-verifier-context.schema.json").read_text())
    widest = max(len(schema["$defs"][name]["properties"]) for name in ("probe_candidate", "descriptive_candidate"))
    assert widest <= _abuse_candidate_limits()["max_items"]


def test_descriptive_candidate_cannot_smuggle_probe_fields_past_the_schema(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "src" / "roles").mkdir(parents=True)
    (repo / "src" / "roles" / "assign.ts").write_text("x\n")
    payload = json.dumps({"matches": [_descriptive_match(repo)]}).encode()
    value = contexts.project_candidate(payload, "REPO-AC-020", repo_root=repo)
    value["limits"]["serialized_bytes"] = 1
    value["candidate"]["chain"] = []
    schema = json.loads((ROOT / "schemas" / "abuse-case-verifier-context.schema.json").read_text())
    assert list(Draft202012Validator(schema).iter_errors(value))
