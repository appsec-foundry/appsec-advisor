from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest
import yaml
from jsonschema import Draft202012Validator

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import prepare_trust_boundary_context as prep  # noqa: E402


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    out = repo / "docs" / "security"
    (repo / "src").mkdir(parents=True)
    out.mkdir(parents=True)
    (repo / "src" / "auth.py").write_text("def authorize():\n    return True\n", encoding="utf-8")
    _write_json(
        out / ".components.json",
        {
            "schema_version": 1,
            "components": [
                {
                    "id": "web-api",
                    "name": "Web API",
                    "paths": ["src/**"],
                    "handles_sensitive_data": True,
                },
                {"id": "worker", "name": "Worker", "paths": ["worker/**"]},
            ],
        },
    )
    return repo, out


def _row(name: str = "Public API", **overrides) -> dict:
    row = {
        "id": "tb-99",
        "name": name,
        "from": "external",
        "to": "web-api",
        "kind": "network",
        "assumption": "Protected operations require authorization checks.",
        "evidence": [{"file": "src/auth.py", "line": 1}],
        "confidence": "confirmed",
    }
    row.update(overrides)
    return row


def _assessment(component_fp: str, input_fp: str, *, with_signal: bool = True) -> dict:
    signal = {
        "id": "signal-external-ingress-external-to-web-api",
        "class": "external-ingress",
        "from": "external",
        "to": "web-api",
        "mandatory": True,
        "trigger": "runtime flow enters from external",
        "false_positive_exclusions": ["test-only route"],
        "evidence": [{"file": "src/auth.py", "line": 1}],
        "provenance": ["architecture"],
        "flow_ids": ["df-001"],
    }
    return {
        "schema_version": 1,
        "component_inventory_fingerprint": component_fp,
        "assessment_input_fingerprint": input_fp,
        "assessment_depth": "standard",
        "components": [
            {
                "id": "web-api",
                "name": "Web API",
                "tier": "application",
                "deployment_zones": ["internet"],
                "handles_sensitive_data": True,
                "paths": ["src/**"],
            }
        ],
        "data_flows": [{"id": "df-001"}] if with_signal else [],
        "signals": [signal] if with_signal else [],
        "prior_boundary_identity_hints": [],
        "source_context": {
            "route_inventory": {"status": "missing", "routes": []},
            "attack_surface_additions": [],
            "cross_repository": {"status": "missing", "entries": []},
            "recon_signals": {
                "values": {
                    "has_public_routes": False,
                    "has_auth_surface": False,
                    "has_role_concept": False,
                    "has_ci_pipeline": False,
                    "has_external_apis": False,
                    "has_client_storage": False,
                    "has_multi_tenancy_signal": False,
                },
                "evidence": [],
            },
            "boundary_declarations": {"status": "missing", "fingerprint": None, "keys": []},
            "incremental": False,
        },
    }


def _candidate_doc(component_fp: str, input_fp: str, *, with_signal: bool = True) -> dict:
    if not with_signal:
        return {
            "schema_version": 1,
            "component_inventory_fingerprint": component_fp,
            "assessment_input_fingerprint": input_fp,
            "candidates": [],
            "dispositions": [],
        }
    return {
        "schema_version": 1,
        "component_inventory_fingerprint": component_fp,
        "assessment_input_fingerprint": input_fp,
        "candidates": [
            {
                "candidate_key": "candidate-1",
                "name": "Internet to Web API",
                "from": "external",
                "to": "web-api",
                "kind": "network",
                "assumption": "Protected operations require authenticated and authorized requests.",
                "evidence": [{"file": "src/auth.py", "line": 1}],
                "confidence": "confirmed",
                "covered_signal_ids": ["signal-external-ingress-external-to-web-api"],
                "covered_flow_ids": ["df-001"],
            }
        ],
        "dispositions": [
            {
                "signal_id": "signal-external-ingress-external-to-web-api",
                "disposition": "boundary",
                "candidate_keys": ["candidate-1"],
                "rationale": "Requests enter the API process from an untrusted external network.",
            }
        ],
    }


def test_promote_candidates_writes_canonical_and_coverage(tmp_path: Path):
    repo, out = _repo(tmp_path)
    component_fp = "sha256:" + "1" * 64
    input_fp = "sha256:" + "2" * 64
    assessment = out / ".trust-boundary-assessment-input.json"
    candidates = out / ".trust-boundary-candidates.json"
    _write_json(assessment, _assessment(component_fp, input_fp))
    _write_json(candidates, _candidate_doc(component_fp, input_fp))

    canonical, coverage = prep.promote_candidates(
        repo_root=repo,
        output_dir=out,
        candidates_path=candidates,
        assessment_input_path=assessment,
        prior_model=None,
    )

    assert canonical["trust_boundaries"][0]["id"] == "tb-1"
    assert canonical["trust_boundaries"][0]["sources"] == ["detected"]
    assert coverage["status"] == "pass"
    assert coverage["signals"][0]["boundary_ids"] == ["tb-1"]


def test_promote_candidates_rejects_unaccounted_signal(tmp_path: Path):
    repo, out = _repo(tmp_path)
    component_fp = "sha256:" + "1" * 64
    input_fp = "sha256:" + "2" * 64
    assessment = out / ".trust-boundary-assessment-input.json"
    candidates = out / ".trust-boundary-candidates.json"
    document = _candidate_doc(component_fp, input_fp)
    document["dispositions"] = []
    _write_json(assessment, _assessment(component_fp, input_fp))
    _write_json(candidates, document)

    with pytest.raises(ValueError, match="signal disposition mismatch"):
        prep.promote_candidates(
            repo_root=repo,
            output_dir=out,
            candidates_path=candidates,
            assessment_input_path=assessment,
            prior_model=None,
        )


def test_promote_candidates_rejects_confirmed_candidate_without_valid_evidence(tmp_path: Path):
    repo, out = _repo(tmp_path)
    component_fp = "sha256:" + "1" * 64
    input_fp = "sha256:" + "2" * 64
    assessment = out / ".trust-boundary-assessment-input.json"
    candidates = out / ".trust-boundary-candidates.json"
    document = _candidate_doc(component_fp, input_fp)
    document["candidates"][0]["evidence"] = [{"file": "src/missing.py", "line": 1}]
    _write_json(assessment, _assessment(component_fp, input_fp))
    _write_json(candidates, document)

    with pytest.raises(ValueError, match="confirmed confidence without valid repository evidence"):
        prep.promote_candidates(
            repo_root=repo,
            output_dir=out,
            candidates_path=candidates,
            assessment_input_path=assessment,
            prior_model=None,
        )


def test_promote_candidates_preserves_public_id_across_full_refresh(tmp_path: Path):
    repo, out = _repo(tmp_path)
    component_fp = "sha256:" + "1" * 64
    input_fp = "sha256:" + "2" * 64
    assessment = out / ".trust-boundary-assessment-input.json"
    candidates = out / ".trust-boundary-candidates.json"
    _write_json(assessment, _assessment(component_fp, input_fp))
    _write_json(candidates, _candidate_doc(component_fp, input_fp))
    first, _coverage = prep.promote_candidates(
        repo_root=repo,
        output_dir=out,
        candidates_path=candidates,
        assessment_input_path=assessment,
        prior_model=None,
    )
    prior_model = out / "threat-model.yaml"
    prior_model.write_text(yaml.safe_dump({"trust_boundaries": first["trust_boundaries"]}), encoding="utf-8")

    second, _coverage = prep.promote_candidates(
        repo_root=repo,
        output_dir=out,
        candidates_path=candidates,
        assessment_input_path=assessment,
        prior_model=prior_model,
    )

    assert [row["id"] for row in second["trust_boundaries"]] == ["tb-1"]


def test_promote_candidates_accepts_explicit_empty_when_no_signals(tmp_path: Path):
    repo, out = _repo(tmp_path)
    component_fp = "sha256:" + "1" * 64
    input_fp = "sha256:" + "2" * 64
    assessment = out / ".trust-boundary-assessment-input.json"
    candidates = out / ".trust-boundary-candidates.json"
    _write_json(assessment, _assessment(component_fp, input_fp, with_signal=False))
    _write_json(candidates, _candidate_doc(component_fp, input_fp, with_signal=False))

    canonical, coverage = prep.promote_candidates(
        repo_root=repo,
        output_dir=out,
        candidates_path=candidates,
        assessment_input_path=assessment,
        prior_model=None,
    )

    assert canonical["trust_boundaries"] == []
    assert coverage["signals"] == []


def test_promote_candidates_keeps_accounted_unresolved_signal_visible(tmp_path: Path):
    repo, out = _repo(tmp_path)
    component_fp = "sha256:" + "1" * 64
    input_fp = "sha256:" + "2" * 64
    assessment = out / ".trust-boundary-assessment-input.json"
    candidates = out / ".trust-boundary-candidates.json"
    document = _candidate_doc(component_fp, input_fp)
    document["candidates"] = []
    document["dispositions"] = [
        {
            "signal_id": "signal-external-ingress-external-to-web-api",
            "disposition": "unresolved",
            "candidate_keys": [],
            "rationale": "The bounded evidence does not identify the enforcement point.",
        }
    ]
    _write_json(assessment, _assessment(component_fp, input_fp))
    _write_json(candidates, document)

    canonical, coverage = prep.promote_candidates(
        repo_root=repo,
        output_dir=out,
        candidates_path=candidates,
        assessment_input_path=assessment,
        prior_model=None,
    )

    assert canonical["trust_boundaries"] == []
    assert coverage["status"] == "pass"
    assert coverage["signals"][0]["disposition"] == "unresolved"
    assert coverage["issues"][0]["code"] == "unresolved-signal"


def test_normalize_migrates_legacy_without_promoting_absence(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    sidecar = out / ".trust-boundaries.json"
    _write_json(
        sidecar,
        {
            "schema_version": 1,
            "trust_boundaries": [
                {
                    "id": "tb-44",
                    "name": "Legacy edge",
                    "enforcement": "none observed",
                    "controls": ["unknown"],
                }
            ],
        },
    )

    result, warnings = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=None, output_dir=out)

    boundary = result["trust_boundaries"][0]
    assert result["schema_version"] == 2
    assert boundary["id"] == "tb-1"
    assert boundary["assumption"] == prep.NEUTRAL_LEGACY_ASSUMPTION
    assert boundary["confidence"] == "unknown"
    assert boundary["resolution_status"] == "unresolved"
    assert boundary["sources"] == ["legacy"]
    assert "enforcement" not in boundary and "controls" not in boundary
    assert warnings


def test_present_empty_v2_catalogue_is_authoritative(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    sidecar = out / ".trust-boundaries.json"
    _write_json(sidecar, {"schema_version": 2, "trust_boundaries": []})
    result, _ = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=None, output_dir=out)
    assert result == {"schema_version": 2, "trust_boundaries": []}


def test_juice_shop_prose_endpoints_are_resolved_conservatively(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    _write_json(
        out / ".components.json",
        {
            "schema_version": 1,
            "components": [
                {"id": "frontend-spa", "name": "Frontend SPA", "paths": ["frontend/**"]},
                {"id": "backend-api", "name": "Backend API Server", "paths": ["routes/**"]},
                {"id": "database", "name": "SQLite Database", "paths": ["models/**"]},
                {"id": "ci-cd-pipeline", "name": "CI/CD Pipeline", "paths": [".github/**"]},
            ],
        },
    )

    def captured(boundary_id: str, name: str, source: str, target: str, status: str) -> dict:
        return {
            "id": boundary_id,
            "name": name,
            "from": source,
            "to": target,
            "kind": "network",
            "assumption": "The crossing requires a concrete and reviewable trust assumption.",
            "evidence": [],
            "confidence": "inferred",
            "resolution_status": status,
            "sources": ["detected"],
        }

    rows = [
        captured("tb-1", "Internet entry", "Public Internet", "Backend API Server (port 3000)", "resolved"),
        captured("tb-2", "Browser/API", "Angular SPA (browser)", "Backend API Server", "unresolved"),
        captured("tb-3", "API/database", "Backend API Server", "SQLite Database", "resolved"),
        captured(
            "tb-4",
            "LLM provider",
            "Backend API Server (routes/chatbot.ts)",
            "External OpenAI-compatible LLM endpoint",
            "unresolved",
        ),
        captured(
            "tb-5",
            "OAuth provider",
            "Angular SPA (browser)",
            "Google OAuth v2 Authorization Server",
            "unresolved",
        ),
        captured(
            "tb-6",
            "Build registries",
            "GitHub Actions Runner",
            "GitHub, npm Registry, Docker Hub",
            "unresolved",
        ),
        captured(
            "tb-7",
            "Privilege boundary",
            "Authenticated User (user/accounting role)",
            "Admin-protected API endpoints",
            "unresolved",
        ),
    ]
    sidecar = out / ".trust-boundaries.json"
    _write_json(sidecar, {"schema_version": 2, "trust_boundaries": rows})

    result, _warnings = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=None, output_dir=out)
    by_id = {row["id"]: row for row in result["trust_boundaries"]}

    assert (by_id["tb-1"]["from"], by_id["tb-1"]["to"], by_id["tb-1"]["resolution_status"]) == (
        "external",
        "backend-api",
        "resolved",
    )
    assert (by_id["tb-3"]["from"], by_id["tb-3"]["to"], by_id["tb-3"]["resolution_status"]) == (
        "backend-api",
        "database",
        "resolved",
    )
    assert (by_id["tb-4"]["from"], by_id["tb-4"]["to"], by_id["tb-4"]["resolution_status"]) == (
        "backend-api",
        "external",
        "resolved",
    )
    assert {boundary_id for boundary_id, row in by_id.items() if row["resolution_status"] == "unresolved"} == {
        "tb-2",
        "tb-5",
        "tb-6",
        "tb-7",
    }
    assert by_id["tb-2"]["from"] == "Angular SPA (browser)"
    assert by_id["tb-5"]["to"] == "Google OAuth v2 Authorization Server"
    diagnostics = json.loads((out / ".trust-boundary-diagnostics.json").read_text(encoding="utf-8"))
    assert {item["boundary_id"] for item in diagnostics["issues"]} == {"tb-2", "tb-5", "tb-6", "tb-7"}


def test_invalid_resolved_row_is_recomputed_and_diagnosed(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    sidecar = out / ".trust-boundaries.json"
    _write_json(
        sidecar,
        {
            "schema_version": 2,
            "trust_boundaries": [
                {
                    **_row(id="tb-4", from_="Authenticated User", to="web-api"),
                    "from": "Authenticated User",
                    "resolution_status": "resolved",
                    "sources": ["detected"],
                }
            ],
        },
    )

    result, _warnings = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=None, output_dir=out)
    row = result["trust_boundaries"][0]
    assert row["id"] == "tb-4"
    assert row["resolution_status"] == "unresolved"
    diagnostics = json.loads((out / ".trust-boundary-diagnostics.json").read_text(encoding="utf-8"))
    assert diagnostics["issues"][0]["code"] == "invalid_resolved_endpoint"
    assert diagnostics["issues"][0]["side"] == "from"


def test_contexts_defer_and_surface_persisted_invalid_resolved_row(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    row = {
        **_row(id="tb-9"),
        "from": "Public Internet",
        "resolution_status": "resolved",
        "sources": ["detected"],
    }
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": [row]})

    audit = prep.prepare_contexts(
        repo_root=repo,
        output_dir=out,
        component_ids=["web-api"],
        depth="standard",
    )

    component = audit["components"]["web-api"]
    assert component["selected_ids"] == []
    assert component["deferred_ids"] == ["tb-9"]
    assert component["invalid_ids"] == ["tb-9"]
    diagnostics = json.loads((out / ".trust-boundary-diagnostics.json").read_text(encoding="utf-8"))
    assert diagnostics["issues"][0]["code"] == "invalid_resolved_endpoint"


def test_component_audit_satisfies_delivered_output_schema(tmp_path: Path) -> None:
    """The per-component audit must satisfy the schema that gates the delivered yaml.

    `build_threat_model_yaml` copies this mapping verbatim into
    `meta.boundary_selection.components`, where the output schema pins
    `additionalProperties: false`. A key added here but not there therefore
    aborts every full run at the post-Stage-1c gate — which is what `invalid_ids`
    did from 2026-07-27 until 2026-08-01.

    The drift shipped because nothing coupled the two: the e2e fixture predates
    the feature and is git-ignored (so its round-trip test skips), and the
    validator subprocess is mocked wherever the builder is exercised, to protect
    the parallel coverage DB. Checking real producer output against the real
    schema in-process depends on none of that, so it also catches the *next* key.
    """
    repo, out = _repo(tmp_path)
    # The nested component has no crossing of its own and therefore inherits
    # the containing API's row. This is the only branch that emits
    # `inherited_from`; omitting it here let the 2026-08-07 full run reach final
    # YAML validation before the producer/output-schema drift was detected.
    _write_json(
        out / ".components.json",
        {
            "schema_version": 1,
            "components": [
                {
                    "id": "web-api",
                    "name": "Web API",
                    "paths": ["src/**"],
                    "handles_sensitive_data": True,
                },
                {
                    "id": "web3-nft",
                    "name": "Web3 NFT",
                    "paths": ["src/web3/**"],
                    "handles_sensitive_data": False,
                },
            ],
        },
    )
    _write_json(
        out / ".trust-boundaries.json",
        {
            "schema_version": 2,
            "trust_boundaries": [
                {
                    **_row(id="tb-9"),
                    "resolution_status": "resolved",
                    "sources": ["detected"],
                }
            ],
        },
    )

    audit = prep.prepare_contexts(
        repo_root=repo,
        output_dir=out,
        component_ids=["web-api", "web3-nft"],
        depth="standard",
    )
    assert audit["components"]["web3-nft"]["inherited_from"] == "web-api"

    output_schema = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "schemas" / "threat-model.output.schema.yaml").read_text(
            encoding="utf-8"
        )
    )
    selection_schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schemas" / "trust-boundary-selection.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(selection_schema).validate(audit)
    per_component = output_schema["properties"]["meta"]["properties"]["boundary_selection"]["properties"]["components"][
        "additionalProperties"
    ]
    selection_component = selection_schema["$defs"]["component_audit"]
    assert set(per_component["required"]) == set(selection_component["required"])
    assert set(per_component["properties"]) == set(selection_component["properties"])
    validator = Draft202012Validator(per_component)

    assert audit["components"], "audit must carry a component for this to mean anything"
    for cid, entry in audit["components"].items():
        errors = list(validator.iter_errors(entry))
        assert not errors, f"{cid}: " + "; ".join(f"{e.json_path}: {e.message}" for e in errors)


def test_selection_contract_rejects_unknown_inherited_component(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    _write_json(
        out / ".trust-boundaries.json",
        {
            "schema_version": 2,
            "trust_boundaries": [
                {
                    **_row(id="tb-9"),
                    "resolution_status": "resolved",
                    "sources": ["detected"],
                }
            ],
        },
    )
    audit = prep.prepare_contexts(
        repo_root=repo,
        output_dir=out,
        component_ids=["web-api"],
        depth="standard",
    )
    audit["components"]["web-api"]["inherited_from"] = "missing-parent"

    with pytest.raises(jsonschema.ValidationError, match="unknown component 'missing-parent'"):
        prep.validate_trust_boundary_selection(audit, known_component_ids={"web-api", "worker"})


def test_selection_contract_rejects_inherited_component_without_audit(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    _write_json(
        out / ".trust-boundaries.json",
        {
            "schema_version": 2,
            "trust_boundaries": [
                {
                    **_row(id="tb-9"),
                    "resolution_status": "resolved",
                    "sources": ["detected"],
                }
            ],
        },
    )
    audit = prep.prepare_contexts(
        repo_root=repo,
        output_dir=out,
        component_ids=["web-api"],
        depth="standard",
    )
    audit["components"]["web-api"]["inherited_from"] = "worker"

    with pytest.raises(jsonschema.ValidationError, match="without a selection audit"):
        prep.validate_trust_boundary_selection(audit, known_component_ids={"web-api", "worker"})


def test_reorder_and_unambiguous_rename_preserve_ids(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    prior = out / "prior.yaml"
    prior.write_text(
        yaml.safe_dump(
            {
                "components": [{"id": "web-api"}, {"id": "worker"}],
                "trust_boundaries": [
                    {
                        **_row("Public API"),
                        "id": "tb-7",
                        "resolution_status": "resolved",
                        "sources": ["detected"],
                    },
                    {
                        **_row(
                            "Worker handoff",
                            id="tb-8",
                            from_="web-api",
                            to="worker",
                        ),
                        "from": "web-api",
                        "id": "tb-8",
                        "resolution_status": "resolved",
                        "sources": ["detected"],
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    sidecar = out / ".trust-boundaries.json"
    _write_json(
        sidecar,
        {
            "schema_version": 1,
            "trust_boundaries": [
                _row("Renamed public entry"),
                {
                    **_row("Worker handoff", from_="web-api", to="worker"),
                    "from": "web-api",
                    "to": "worker",
                },
            ],
        },
    )
    result, _ = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=prior, output_dir=out)
    assert [row["id"] for row in result["trust_boundaries"]] == ["tb-7", "tb-8"]


def test_retired_highest_id_is_never_reused_on_third_run(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    prior = out / "prior.yaml"
    prior.write_text(
        yaml.safe_dump(
            {
                "components": [{"id": "web-api"}],
                "trust_boundaries": [
                    {
                        **_row(),
                        "id": "tb-3",
                        "resolution_status": "resolved",
                        "sources": ["detected"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    sidecar = out / ".trust-boundaries.json"
    _write_json(sidecar, {"schema_version": 2, "trust_boundaries": []})
    prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=prior, output_dir=out)

    _write_json(
        sidecar,
        {
            "schema_version": 1,
            "trust_boundaries": [_row("New integration", id="tb-3", kind="third-party")],
        },
    )
    result, _ = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=None, output_dir=out)
    assert result["trust_boundaries"][0]["id"] == "tb-4"


def test_repository_declaration_is_additive_and_cannot_self_confirm(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    declaration = repo / ".appsec" / "trust-boundaries.yaml"
    declaration.parent.mkdir()
    declaration.write_text(
        yaml.safe_dump(
            {
                "api_version": "appsec-advisor/trust-boundaries/v1",
                "boundaries": [
                    {
                        "key": "worker-egress",
                        "name": "Worker third-party egress",
                        "from": "worker",
                        "to": "external",
                        "kind": "third-party",
                        "assumption": "Outbound payloads contain only approved data.",
                        "evidence": [{"file": "src/auth.py", "line": 1}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    sidecar = out / ".trust-boundaries.json"
    _write_json(sidecar, {"schema_version": 1, "trust_boundaries": [_row()]})
    result, _ = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=None, output_dir=out)
    declared = next(row for row in result["trust_boundaries"] if row.get("declaration_key"))
    assert declared["sources"] == ["repo-declared"]
    assert declared["confidence"] == "inferred"
    assert declared["resolution_status"] == "resolved"
    baseline = json.loads((out / ".appsec-cache" / "baseline.json").read_text())
    assert baseline["trust_boundary_declaration_fingerprint"].startswith("sha256:")


def test_changed_declaration_endpoints_conflict_with_detected_prior_identity(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    prior = out / "prior.yaml"
    prior.write_text(
        yaml.safe_dump(
            {
                "components": [{"id": "web-api"}, {"id": "worker"}],
                "trust_boundaries": [
                    {
                        **_row(),
                        "id": "tb-5",
                        "declaration_key": "public-api",
                        "resolution_status": "resolved",
                        "sources": ["detected", "repo-declared"],
                    }
                ],
            }
        )
    )
    declaration = repo / ".appsec" / "trust-boundaries.yaml"
    declaration.parent.mkdir()
    declaration.write_text(
        yaml.safe_dump(
            {
                "api_version": "appsec-advisor/trust-boundaries/v1",
                "boundaries": [
                    {
                        "key": "public-api",
                        "name": "Public API",
                        "from": "external",
                        "to": "worker",
                        "kind": "network",
                        "assumption": "Requests are routed only to the intended component.",
                    }
                ],
            }
        )
    )
    sidecar = out / ".trust-boundaries.json"
    _write_json(sidecar, {"schema_version": 2, "trust_boundaries": [_row(id=None)]})
    result, warnings = prep.normalize(
        repo_root=repo,
        sidecar=sidecar,
        prior_model=prior,
        output_dir=out,
    )
    assert len(result["trust_boundaries"]) == 2
    assert {row["resolution_status"] for row in result["trust_boundaries"]} == {"conflicted"}
    assert any("conflicts" in warning for warning in warnings)


@pytest.mark.parametrize(
    ("depth", "expected"),
    [("quick", 2), ("standard", 4), ("thorough", 6)],
)
def test_context_selection_is_bounded_and_stable(tmp_path: Path, depth: str, expected: int) -> None:
    repo, out = _repo(tmp_path)
    rows = []
    for index in range(1, 9):
        rows.append(
            {
                **_row(f"External {index}"),
                "id": f"tb-{index}",
                "resolution_status": "resolved",
                "sources": ["detected"],
            }
        )
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": rows})
    audit = prep.prepare_contexts(repo_root=repo, output_dir=out, component_ids=["web-api"], depth=depth)
    selected = audit["components"]["web-api"]["selected_ids"]
    assert selected == [f"tb-{index}" for index in range(1, expected + 1)]
    context = json.loads((out / ".dispatch-context" / "web-api" / "trust-boundaries.json").read_text())
    assert len(context["adjacent_trust_boundaries"]) == expected


def test_context_carries_the_assumption_legs_to_the_analyzer(tmp_path: Path) -> None:
    """`boundary_refs[].leg` is a closed enum and the analyzer is told to copy a
    value from the candidate. Dropped from this projection the candidate offers
    only its NAME, and the composed label fails the schema gate and re-dispatches
    the component (juice-shop 2026-08-02: "Sequelize model parameter binding" →
    "parameterized binding", where the boundary declared `data-interpretation`).
    A declared leg keeps its condition; an unannotated directional row still
    ships the vocabulary its direction implies."""
    repo, out = _repo(tmp_path)
    rows = [
        {
            **_row("Sequelize model parameter binding"),
            "id": "tb-1",
            "from": "web-api",
            "to": "worker",
            "kind": "process",
            "assumption_legs": [
                {"leg": "data-interpretation", "condition": "Queries reach the driver through bound parameters."}
            ],
            "resolution_status": "resolved",
            "sources": ["detected"],
        },
        {**_row("Public API"), "id": "tb-2", "resolution_status": "resolved", "sources": ["detected"]},
    ]
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": rows})
    prep.prepare_contexts(repo_root=repo, output_dir=out, component_ids=["web-api"], depth="standard")

    context = json.loads((out / ".dispatch-context" / "web-api" / "trust-boundaries.json").read_text())
    by_id = {row["id"]: row for row in context["adjacent_trust_boundaries"]}
    assert by_id["tb-1"]["assumption_legs"] == [
        {"leg": "data-interpretation", "condition": "Queries reach the driver through bound parameters."}
    ]
    assert [leg["leg"] for leg in by_id["tb-2"]["assumption_legs"]] == list(prep.INGRESS_LEGS)


def test_context_legs_are_a_copy_not_a_reference(tmp_path: Path) -> None:
    """The projection must not alias the canonical row — a later mutation of the
    dispatch context would otherwise rewrite `.trust-boundaries.json`."""
    repo, out = _repo(tmp_path)
    rows = [{**_row("Public API"), "id": "tb-1", "resolution_status": "resolved", "sources": ["detected"]}]
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": rows})
    prep.prepare_contexts(repo_root=repo, output_dir=out, component_ids=["web-api"], depth="standard")

    canonical = json.loads((out / ".trust-boundaries.json").read_text())["trust_boundaries"][0]
    assert "assumption_legs" not in canonical


def test_thorough_excludes_ordinary_process_and_unknown_legacy_boundaries(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    rows = [
        {
            **_row("Ordinary worker process", to="external"),
            "id": "tb-1",
            "from": "worker",
            "to": "external",
            "kind": "process",
            "resolution_status": "resolved",
            "sources": ["detected"],
        },
        {
            **_row("Unknown legacy entry"),
            "id": "tb-2",
            "assumption": prep.NEUTRAL_LEGACY_ASSUMPTION,
            "confidence": "unknown",
            "resolution_status": "resolved",
            "sources": ["legacy"],
        },
    ]
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": rows})
    stale = out / ".dispatch-context" / "worker" / "trust-boundaries.json"
    _write_json(stale, {"schema_version": 1, "adjacent_trust_boundaries": [{"id": "tb-999"}]})
    audit = prep.prepare_contexts(
        repo_root=repo,
        output_dir=out,
        component_ids=["worker", "web-api"],
        depth="thorough",
    )
    assert audit["components"]["worker"]["selected_ids"] == []
    assert audit["components"]["web-api"]["selected_ids"] == []
    assert not stale.exists()


def test_finding_reference_requires_candidate_adjacency_and_owned_evidence() -> None:
    boundary = {
        "id": "tb-1",
        "from": "external",
        "to": "web-api",
        "resolution_status": "resolved",
        "confidence": "confirmed",
    }
    finding = {
        "evidence": {"file": "src/auth.py", "line": 1},
        "boundary_refs": [
            {
                "boundary_id": "tb-1",
                "origin_component_id": "web-api",
                "rationale": "Authorization happens after the protected operation is selected.",
                "evidence_locations": [{"file": "src/auth.py", "line": 1}],
            }
        ],
    }
    refs, warnings = prep.validate_finding_boundary_refs(
        finding,
        boundaries=[boundary],
        origin_component_id="web-api",
        candidate_ids={"tb-1"},
        require_candidate=True,
    )
    assert refs == finding["boundary_refs"]
    assert warnings == []

    refs, warnings = prep.validate_finding_boundary_refs(
        finding,
        boundaries=[boundary],
        origin_component_id="web-api",
        candidate_ids=set(),
        require_candidate=True,
    )
    assert refs == []
    assert "non-candidate" in warnings[0]


def _tiered_repo(tmp_path: Path) -> tuple[Path, Path]:
    """Coarse owner (`routes/**`) plus a fine-grained component on one file."""
    repo, out = _repo(tmp_path)
    _write_json(
        out / ".components.json",
        {
            "schema_version": 1,
            "components": [
                {"id": "web-api", "name": "Web API", "paths": ["server.ts", "routes/**"]},
                {"id": "chat-egress", "name": "Chat Egress", "paths": ["routes/chat.ts"]},
                # Claims server.ts as precisely as web-api does, but `ops/**`
                # keeps it outside web-api's globs so candidate inheritance
                # cannot fire and mask what the evidence rule alone decides.
                {"id": "gateway", "name": "Gateway", "paths": ["server.ts", "ops/**"]},
            ],
        },
    )
    return repo, out


def test_evidence_owner_reaches_the_component_implementing_an_external_crossing(tmp_path: Path) -> None:
    """Regression (juice-shop 2026-07-27): tb-5 `backend-api -> external` is the
    LLM egress, but the component owning that egress is never an endpoint, so it
    was offered no boundary and the crossing shipped with zero linked findings."""
    repo, out = _tiered_repo(tmp_path)
    row = {
        **_row("API to external LLM provider"),
        "id": "tb-1",
        "from": "web-api",
        "to": "external",
        "kind": "third-party",
        "evidence": [{"file": "routes/chat.ts", "line": 9}],
        "resolution_status": "resolved",
        "sources": ["detected"],
    }
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": [row]})

    audit = prep.prepare_contexts(
        repo_root=repo, output_dir=out, component_ids=["web-api", "chat-egress"], depth="standard"
    )

    assert audit["components"]["chat-egress"]["selected_ids"] == ["tb-1"]
    reasons = audit["components"]["chat-egress"]["focus_reasons"]["tb-1"]
    assert any("owns cited evidence" in reason for reason in reasons)


def test_equally_specific_claim_does_not_create_adjacency(tmp_path: Path) -> None:
    """`server.ts` sits in both components' globs. Matching on it loosely would
    hand an admin-zone boundary to an unrelated component, so a tie is not
    ownership."""
    repo, out = _tiered_repo(tmp_path)
    row = {
        **_row("Authenticated user to admin zone"),
        "id": "tb-1",
        "from": "external",
        "to": "web-api",
        "kind": "privilege",
        "evidence": [{"file": "server.ts", "line": 410}],
        "resolution_status": "resolved",
        "sources": ["detected"],
    }
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": [row]})

    audit = prep.prepare_contexts(
        repo_root=repo, output_dir=out, component_ids=["web-api", "gateway"], depth="standard"
    )

    assert audit["components"]["web-api"]["selected_ids"] == ["tb-1"]
    assert audit["components"]["gateway"]["selected_ids"] == []


def test_evidence_owner_requires_the_endpoint_to_claim_the_file_too(tmp_path: Path) -> None:
    """When the endpoint does not claim the cited file at all, topology and
    evidence disagree. That is a data-quality problem to surface, not one to
    paper over by handing the boundary to whoever owns the file."""
    repo, out = _tiered_repo(tmp_path)
    row = {
        **_row("Worker egress"),
        "id": "tb-1",
        "from": "gateway",
        "to": "external",
        "kind": "third-party",
        "evidence": [{"file": "routes/chat.ts", "line": 9}],
        "resolution_status": "resolved",
        "sources": ["detected"],
    }
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": [row]})

    audit = prep.prepare_contexts(
        repo_root=repo, output_dir=out, component_ids=["gateway", "chat-egress"], depth="standard"
    )

    assert audit["components"]["chat-egress"]["selected_ids"] == []


def test_component_without_own_candidates_inherits_from_its_containing_component(tmp_path: Path) -> None:
    """Regression (juice-shop 2026-07-27): `auth` and `web3-nft` are role-folded
    out of `backend-api` after Phase 3, so no boundary names them and both ran
    17 findings' worth of STRIDE with no boundary context at all."""
    repo, out = _repo(tmp_path)
    _write_json(
        out / ".components.json",
        {
            "schema_version": 1,
            "components": [
                {"id": "web-api", "name": "Web API", "paths": ["src/**"], "handles_sensitive_data": True},
                {"id": "auth", "name": "Auth Surface", "paths": ["src/auth.py"]},
            ],
        },
    )
    row = {
        **_row(),
        "id": "tb-1",
        # Evidence outside auth's own glob, so it cannot qualify as an evidence
        # owner — inheritance is the only path that can reach it here.
        "evidence": [{"file": "src/server.py", "line": 1}],
        "resolution_status": "resolved",
        "sources": ["detected"],
    }
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": [row]})

    audit = prep.prepare_contexts(repo_root=repo, output_dir=out, component_ids=["web-api", "auth"], depth="standard")

    assert audit["components"]["auth"]["selected_ids"] == ["tb-1"]
    assert audit["components"]["auth"]["inherited_from"] == "web-api"
    reasons = audit["components"]["auth"]["focus_reasons"]["tb-1"]
    assert any("inherited from containing component" in reason for reason in reasons)


@pytest.mark.parametrize(
    ("parent_id", "child_id", "parent_glob", "child_glob", "evidence_file"),
    [
        ("platform-api", "billing-worker", "services/**", "services/billing/**", "services/root.py"),
        ("monolith", "admin-console", "app/**", "app/admin/**", "app/server.py"),
    ],
)
def test_component_inheritance_is_repository_agnostic(
    tmp_path: Path,
    parent_id: str,
    child_id: str,
    parent_glob: str,
    child_glob: str,
    evidence_file: str,
) -> None:
    repo, out = _repo(tmp_path)
    _write_json(
        out / ".components.json",
        {
            "schema_version": 1,
            "components": [
                {"id": parent_id, "name": "Parent", "paths": [parent_glob]},
                {"id": child_id, "name": "Nested", "paths": [child_glob]},
            ],
        },
    )
    _write_json(
        out / ".trust-boundaries.json",
        {
            "schema_version": 2,
            "trust_boundaries": [
                {
                    **_row(id="tb-1", to=parent_id, evidence=[{"file": evidence_file, "line": 1}]),
                    "resolution_status": "resolved",
                    "sources": ["detected"],
                }
            ],
        },
    )

    audit = prep.prepare_contexts(
        repo_root=repo,
        output_dir=out,
        component_ids=[parent_id, child_id],
        depth="standard",
    )

    assert audit["components"][child_id]["selected_ids"] == ["tb-1"]
    assert audit["components"][child_id]["inherited_from"] == parent_id
    prep.validate_trust_boundary_selection(audit, known_component_ids={parent_id, child_id})


def test_inheritance_never_overrides_a_components_own_candidates(tmp_path: Path) -> None:
    """Every folded sub-component is contained by its parent, so inheriting
    unconditionally would push each one's own crossing out of the cap."""
    repo, out = _tiered_repo(tmp_path)
    rows = [
        {
            **_row("Chat egress"),
            "id": "tb-1",
            "from": "chat-egress",
            "to": "external",
            "kind": "third-party",
            "resolution_status": "resolved",
            "sources": ["detected"],
        },
        {
            **_row("Public API"),
            "id": "tb-2",
            "from": "external",
            "to": "web-api",
            "resolution_status": "resolved",
            "sources": ["detected"],
        },
    ]
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": rows})

    audit = prep.prepare_contexts(
        repo_root=repo, output_dir=out, component_ids=["web-api", "chat-egress"], depth="standard"
    )

    assert audit["components"]["chat-egress"]["selected_ids"] == ["tb-1"]
    assert "inherited_from" not in audit["components"]["chat-egress"]


def test_boundary_below_the_cap_everywhere_is_swapped_in_without_widening_it(tmp_path: Path) -> None:
    """A crossing ranked just under the cap on its only eligible component
    reaches no analyzer at all (juice-shop 2026-07-27: tb-5, rank 5 of 4). It is
    swapped against a boundary another component already covers, so coverage
    grows while each context keeps exactly `limit` rows."""
    repo, out = _repo(tmp_path)
    _write_json(
        out / ".components.json",
        {
            "schema_version": 1,
            "components": [
                {"id": "web-api", "name": "Web API", "paths": ["src/**"], "handles_sensitive_data": True},
                {"id": "edge", "name": "Edge", "paths": ["src/auth.py"]},
            ],
        },
    )
    # Only tb-2 cites the file `edge` claims exactly, so `edge` is eligible for
    # that one alone and is the component that keeps it covered after the swap.
    rows = [
        {
            **_row("Privileged entry"),
            "id": "tb-1",
            "kind": "privilege",
            "evidence": [{"file": "src/priv.py", "line": 1}],
        },
        {**_row("Shared network entry"), "id": "tb-2", "evidence": [{"file": "src/auth.py", "line": 1}]},
        {
            **_row("Lowest ranked entry"),
            "id": "tb-3",
            "confidence": "inferred",
            "evidence": [{"file": "src/other.py", "line": 1}],
        },
    ]
    for row in rows:
        row.update({"resolution_status": "resolved", "sources": ["detected"]})
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": rows})

    audit = prep.prepare_contexts(repo_root=repo, output_dir=out, component_ids=["web-api", "edge"], depth="quick")

    assert audit["coverage"]["uncovered_ids"] == []
    assert audit["coverage"]["redistributed"] == {"tb-3": "web-api"}
    # The cap is preserved exactly — this redistributes, it does not widen.
    assert len(audit["components"]["web-api"]["selected_ids"]) == 2
    assert "tb-3" in audit["components"]["web-api"]["selected_ids"]
    assert audit["components"]["edge"]["selected_ids"] == ["tb-2"]


def test_coverage_block_reports_a_boundary_no_component_can_take(tmp_path: Path) -> None:
    """With more boundaries than capacity the gap is real; it gets reported
    rather than papered over by widening the cap."""
    repo, out = _repo(tmp_path)
    rows = []
    for index in range(1, 6):
        rows.append(
            {
                **_row(f"Entry {index}"),
                "id": f"tb-{index}",
                "resolution_status": "resolved",
                "sources": ["detected"],
            }
        )
    _write_json(out / ".trust-boundaries.json", {"schema_version": 2, "trust_boundaries": rows})

    audit = prep.prepare_contexts(repo_root=repo, output_dir=out, component_ids=["web-api"], depth="quick")

    assert len(audit["components"]["web-api"]["selected_ids"]) == 2
    assert audit["coverage"]["uncovered_ids"] == ["tb-3", "tb-4", "tb-5"]
    assert audit["coverage"]["redistributed"] == {}


# ---------------------------------------------------------------------------
# Consolidation — one row per enforcement point
# ---------------------------------------------------------------------------


def _normalized(tmp_path: Path, rows: list[dict], components: list[dict] | None = None) -> tuple[list[dict], list[str]]:
    repo, out = _repo(tmp_path)
    if components is not None:
        _write_json(out / ".components.json", {"schema_version": 1, "components": components})
    sidecar = out / ".trust-boundaries.json"
    _write_json(sidecar, {"schema_version": 2, "trust_boundaries": rows})
    result, warnings = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=None, output_dir=out)
    return result["trust_boundaries"], warnings


def _resolved(**overrides) -> dict:
    return {**_row(), "resolution_status": "resolved", "sources": ["detected"], **overrides}


def test_identical_rows_collapse_into_one(tmp_path: Path) -> None:
    rows, warnings = _normalized(
        tmp_path, [_resolved(id="tb-1"), _resolved(id="tb-2", evidence=[{"file": "src/auth.py", "line": 2}])]
    )

    assert len(rows) == 1
    assert any("consolidated duplicate" in w for w in warnings)
    # The duplicate's evidence is kept, not discarded with the row.
    assert {entry["line"] for entry in rows[0]["evidence"]} == {1, 2}


def test_privilege_crossing_anchored_at_external_is_moved_inside(tmp_path: Path) -> None:
    """A privilege change is enforced inside the system. Anchoring it at the
    perimeter duplicates the network crossing that must already be there, and
    scatters it away from the privilege boundaries it belongs with."""
    rows, warnings = _normalized(
        tmp_path,
        [
            _resolved(id="tb-1", name="Internet to API", kind="network"),
            _resolved(id="tb-2", name="Anonymous to authenticated", kind="privilege"),
        ],
    )

    by_name = {row["name"]: row for row in rows}
    assert by_name["Anonymous to authenticated"]["from"] == "web-api"
    assert by_name["Anonymous to authenticated"]["to"] == "web-api"
    assert by_name["Internet to API"]["from"] == "external"
    assert any("re-anchored privilege boundary" in w for w in warnings)


def test_lone_privilege_crossing_at_the_perimeter_is_left_alone(tmp_path: Path) -> None:
    """Without a second row covering the same endpoints it is the only record of
    that perimeter — moving it inward would lose the crossing entirely."""
    rows, _warnings = _normalized(tmp_path, [_resolved(id="tb-1", kind="privilege")])

    assert rows[0]["from"] == "external"


def test_ingress_to_embedded_component_folds_into_its_host(tmp_path: Path) -> None:
    """An embedded WebSocket gateway is reached through the same port and
    process as the API it lives in, so both rows name one perimeter."""
    components = [
        {"id": "web-api", "name": "Web API", "paths": ["src/**"], "handles_sensitive_data": True},
        {"id": "ws-gateway", "name": "WS Gateway", "paths": ["src/ws.py"]},
    ]
    rows, warnings = _normalized(
        tmp_path,
        [
            _resolved(id="tb-1", name="Internet to API", to="web-api"),
            _resolved(id="tb-2", name="Internet to WS", to="ws-gateway"),
        ],
        components,
    )

    assert [row["to"] for row in rows] == ["web-api"]
    assert any("folded ingress boundary" in w for w in warnings)


def test_ingress_rows_to_unrelated_components_are_both_kept(tmp_path: Path) -> None:
    """Folding is justified by shared code, not by both being internet-facing."""
    components = [
        {"id": "web-api", "name": "Web API", "paths": ["src/**"], "handles_sensitive_data": True},
        {"id": "worker", "name": "Worker", "paths": ["worker/**"]},
    ]
    rows, _warnings = _normalized(
        tmp_path,
        [
            _resolved(id="tb-1", name="Internet to API", to="web-api"),
            _resolved(id="tb-2", name="Internet to worker", to="worker"),
        ],
        components,
    )

    assert sorted(row["to"] for row in rows) == ["web-api", "worker"]


# --------------------------------------------------------------------------- #
# Deterministic consolidation (juice-shop 2026-07-30)
# --------------------------------------------------------------------------- #
def _cand(key, *, frm, to, kind="network", point=None, conf="inferred", evidence=None, signals=None):
    row = {
        "candidate_key": key,
        "name": f"{frm} to {to}",
        "from": frm,
        "to": to,
        "kind": kind,
        "assumption": "Something must remain true at this crossing for it to hold.",
        "evidence": evidence if evidence is not None else [{"file": "src/auth.py", "line": 1}],
        "confidence": conf,
        "covered_signal_ids": signals if signals is not None else [f"signal-{key}"],
        "covered_flow_ids": [],
    }
    if point:
        row["enforcement_point"] = point
    return row


_COMPONENTS = {
    "api": {"id": "api", "paths": ["server.ts", "routes/**", "models/**"]},
    "db": {"id": "db", "paths": ["models/**"]},
    "worker": {"id": "worker", "paths": ["worker/**"]},
}


def test_same_crossing_without_a_stated_reason_collapses(tmp_path: Path):
    """Separation must be justified, not consolidation. Two candidates on one
    crossing that name no distinct enforcement point are one boundary."""
    merged, alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api"), _cand("c2", frm="external", to="api")],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1"]
    assert alias["c2"] == "c1"
    assert merged[0]["covered_signal_ids"] == ["signal-c1", "signal-c2"]
    assert any("merged into c1" in n for n in notes)


def test_same_crossing_with_differing_kinds_stays_apart(tmp_path: Path):
    """`kind` is a weaker separation claim than `enforcement_point`, but it is
    still one: a generic HTTPS perimeter and an operator crossing on the same
    endpoints ask different enforcement questions, and merging them would let
    whichever candidate came first silently decide which question survives."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api"), _cand("c2", frm="external", to="api", kind="third-party")],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1", "c2"]


def test_distinct_enforcement_points_stay_apart(tmp_path: Path):
    """A declared enforcement point IS the reason to stay separate."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [
            _cand("c1", frm="external", to="api", point="Express route middleware isAuthorized"),
            _cand("c2", frm="external", to="api", point="OAuth authorization-code exchange"),
        ],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1", "c2"]


def test_same_enforcement_point_merges_across_differing_names(tmp_path: Path):
    merged, alias, _notes = prep._consolidate_candidates(
        [
            _cand("c1", frm="external", to="api", point="Express route middleware"),
            _cand("c2", frm="external", to="worker", point="express route MIDDLEWARE  "),
        ],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1"]
    assert alias["c2"] == "c1"


def test_declared_point_is_not_absorbed_by_an_undeclared_neighbour(tmp_path: Path):
    merged, _alias, _notes = prep._consolidate_candidates(
        [
            _cand("c1", frm="external", to="api"),
            _cand("c2", frm="external", to="api", point="OAuth authorization-code exchange"),
        ],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert sorted(c["candidate_key"] for c in merged) == ["c1", "c2"]


# --------------------------------------------------------------------------- #
# Deployable-scoped ingress consolidation
# --------------------------------------------------------------------------- #
_NESTED_COMPONENTS = {
    "api": {"id": "api", "paths": ["server.ts", "routes/**", "lib/**"]},
    "auth": {"id": "auth", "paths": ["routes/login.ts", "lib/insecurity.ts"]},
    "worker": {"id": "worker", "paths": ["worker/**"]},
}


def test_deployable_root_walks_path_containment_not_zones():
    assert prep._deployable_root("auth", _NESTED_COMPONENTS) == "api"
    assert prep._deployable_root("api", _NESTED_COMPONENTS) == "api"
    assert prep._deployable_root("worker", _NESTED_COMPONENTS) == "worker"
    assert prep._deployable_root("external", _NESTED_COMPONENTS) == "external"


def test_ingress_into_one_deployable_is_one_perimeter(tmp_path: Path):
    """The split into `api` and `auth` is a logical view of one Express process;
    two ingress crossings into it are one perimeter, and the surviving row must
    record the component it absorbed so that component keeps its anchor."""
    merged, alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="auth"), _cand("c2", frm="external", to="api")],
        components=_NESTED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1"]
    assert alias["c2"] == "c1"
    assert merged[0]["to"] == "api"
    assert merged[0]["covers_components"] == ["api", "auth"]
    assert any("names the perimeter" in n for n in notes)


def test_deployable_widening_does_not_cross_kinds(tmp_path: Path):
    """An OAuth assertion into the process is not the generic HTTPS perimeter."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api"), _cand("c2", frm="external", to="auth", kind="identity")],
        components=_NESTED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1", "c2"]
    assert "covers_components" not in merged[0]


def test_egress_is_never_widened_by_deployable(tmp_path: Path):
    """On egress the far side is a specific third party; two dependencies of one
    process are two boundaries however tightly the callers ship together."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [
            _cand("c1", frm="auth", to="external", kind="third-party"),
            _cand("c2", frm="api", to="external", kind="third-party"),
        ],
        components=_NESTED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1", "c2"]


def test_lone_ingress_target_keeps_its_own_endpoint(tmp_path: Path):
    """Widening only ever merges; it never rewrites an endpoint on its own."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="auth")],
        components=_NESTED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["to"] == "auth"
    assert "covers_components" not in merged[0]


# --------------------------------------------------------------------------- #
# Enforcement-point hygiene
# --------------------------------------------------------------------------- #
def test_generic_enforcement_points_fall_back_to_the_crossing(tmp_path: Path):
    """A filler value groups by a string that ignores endpoints, so it would
    merge unrelated crossings. Dropping it restores the conservative fallback."""
    merged, _alias, notes = prep._consolidate_candidates(
        [
            _cand("c1", frm="external", to="api", point="application code"),
            _cand("c2", frm="external", to="worker", point="The application code"),
        ],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1", "c2"]
    assert all("enforcement_point" not in c for c in merged)
    assert any("discarded generic enforcement point" in n for n in notes)


def test_specific_enforcement_point_survives(tmp_path: Path):
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api", point="  Express route   middleware isAuthorized ")],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["enforcement_point"] == "Express route middleware isAuthorized"


# --------------------------------------------------------------------------- #
# Route evidence: the cited line, not the file
# --------------------------------------------------------------------------- #
def _repo_with_routes(tmp_path: Path, cited_line: int) -> list[dict]:
    source = ["// header\n"] * 40 + ["app.get('/metrics', handler)\n"] + ["// tail\n"] * 40
    (tmp_path / "server.ts").write_text("".join(source), encoding="utf-8")
    return [{"file": "server.ts", "line": cited_line}]


def test_ingress_upgrade_requires_the_cited_line(tmp_path: Path):
    """server.ts registering routes somewhere is not evidence that THIS crossing
    exists — juice-shop's has 172 of them, which would confirm every candidate."""
    merged, _alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api", evidence=_repo_with_routes(tmp_path, cited_line=5))],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["confidence"] == "inferred"
    assert "confidence_basis" not in merged[0]
    assert not any("confirmed" in n for n in notes)


def test_ingress_upgrade_stamps_its_basis(tmp_path: Path):
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api", evidence=_repo_with_routes(tmp_path, cited_line=41))],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["confidence"] == "confirmed"
    assert merged[0]["confidence_basis"] == "route-evidence"


def test_ingress_upgrade_tolerates_a_wrapped_call(tmp_path: Path):
    """A registration split across lines still anchors at the cited statement."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api", evidence=_repo_with_routes(tmp_path, cited_line=43))],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["confidence"] == "confirmed"


# --------------------------------------------------------------------------- #
# Derived axes
# --------------------------------------------------------------------------- #
def test_axes_are_derived_from_every_kind():
    assert prep._axes_for_kind("identity") == ("network", ["identity"])
    assert prep._axes_for_kind("process") == ("in-process", [])
    assert prep._axes_for_kind("build") == ("build-pipeline", ["operator"])
    assert prep._axes_for_kind("third-party") == ("network", ["operator"])
    # Unknown input defaults exactly like the `kind` normalization itself.
    assert prep._axes_for_kind("nonsense") == ("network", [])
    assert set(prep._KIND_AXES) == prep.KINDS


def test_covered_component_may_reference_the_consolidated_boundary() -> None:
    """The reference validator has to accept the same adjacency the merge created,
    otherwise consolidation silently strips every folded-in component's refs."""
    boundary = {
        "id": "tb-1",
        "from": "external",
        "to": "api",
        "covers_components": ["api", "auth"],
        "resolution_status": "resolved",
        "confidence": "confirmed",
    }
    evidence = {"file": "routes/login.ts", "line": 7}
    finding = {
        "evidence": [evidence],
        "boundary_refs": [
            {
                "boundary_id": "tb-1",
                "origin_component_id": "auth",
                "rationale": "The cited login route accepts unauthenticated requests at this perimeter.",
                "evidence_locations": [evidence],
            }
        ],
    }
    refs, diagnostics = prep.validate_finding_boundary_refs(
        finding,
        boundaries=[boundary],
        origin_component_id="auth",
        candidate_ids=None,
        require_candidate=False,
        known_component_ids={"api", "auth"},
    )
    assert [ref["boundary_id"] for ref in refs] == ["tb-1"]
    assert diagnostics == []

    outsider = deepcopy(finding)
    outsider["boundary_refs"][0]["origin_component_id"] = "worker"
    refs, diagnostics = prep.validate_finding_boundary_refs(
        outsider,
        boundaries=[boundary],
        origin_component_id="worker",
        candidate_ids=None,
        require_candidate=False,
        known_component_ids={"api", "auth", "worker"},
    )
    assert refs == []
    assert any("non-adjacent" in d for d in diagnostics)


def test_normalized_rows_carry_the_axes(tmp_path: Path) -> None:
    rows, _warnings = _normalized(
        tmp_path,
        [_resolved(id="tb-1", name="OAuth callback", to="web-api", kind="identity")],
        [{"id": "web-api", "name": "Web API", "paths": ["src/**"]}],
    )
    assert rows[0]["surface"] == "network"
    assert rows[0]["transition"] == ["identity"]


def test_ingress_and_egress_never_merge(tmp_path: Path):
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api"), _cand("c2", frm="api", to="external")],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert sorted(c["candidate_key"] for c in merged) == ["c1", "c2"]


def test_same_deployable_is_reclassified_to_process_not_discarded(tmp_path: Path):
    """`db` paths sit inside `api` globs -> one process. The row survives as an
    internal enforcement interface; discarding it would strand the injection and
    data-access findings that anchor there."""
    merged, _alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="api", to="db", kind="network")],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert len(merged) == 1
    assert merged[0]["kind"] == "process"
    assert any("ship in one deployable" in n for n in notes)


def test_separate_deployables_keep_their_kind(tmp_path: Path):
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="api", to="worker", kind="network")],
        components=_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["kind"] == "network"


def test_pull_endpoint_modelled_as_egress_is_corrected_to_ingress(tmp_path: Path):
    """Direction is the flow of the REQUEST. `app.get('/metrics')` is scraped
    from outside, so the crossing is inbound however the payload travels."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "server.ts").write_text("const x = 1\napp.get('/metrics', serveMetrics())\n", encoding="utf-8")
    merged, _alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="api", to="external", kind="third-party", evidence=[{"file": "src/server.ts", "line": 2}])],
        components=_COMPONENTS,
        repo_root=repo,
    )
    assert (merged[0]["from"], merged[0]["to"]) == ("external", "api")
    assert any("direction corrected" in n for n in notes)


def test_genuine_outbound_call_keeps_its_direction(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "llm.ts").write_text("const res = await fetch(provider, { method: 'POST' })\n", encoding="utf-8")
    merged, _alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="api", to="external", kind="third-party", evidence=[{"file": "src/llm.ts", "line": 1}])],
        components=_COMPONENTS,
        repo_root=repo,
    )
    assert (merged[0]["from"], merged[0]["to"]) == ("api", "external")
    assert not any("direction corrected" in n for n in notes)


def test_paths_contained_uses_glob_semantics_not_zone_labels():
    assert prep._paths_contained(["models/**"], ["models/**", "routes/**"])
    assert prep._paths_contained(["data/sequelize.ts"], ["data/**"])
    assert prep._paths_contained(["routes/login.ts"], ["routes/**"])
    assert not prep._paths_contained(["worker/**"], ["routes/**"])
    # `*` must not span a separator.
    assert not prep._paths_contained(["a/b/c.ts"], ["a/*"])


def _repo_with(tmp_path: Path, rel: str, body: str) -> Path:
    repo = tmp_path / "repo"
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return repo


def test_ingress_confidence_is_upgraded_when_evidence_registers_routes(tmp_path: Path):
    """`confirmed` gates the entire external-ingress severity channel. juice-shop
    left every ingress boundary at `inferred`, so zero of six were eligible and
    no finding could be elevated. Whether the inbound surface exists is a
    checkable fact — verify it rather than trusting the analyst's caution."""
    repo = _repo_with(tmp_path, "server.ts", "/*\n */\napp.get('/metrics', serve())\n")
    merged, _alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api", conf="inferred", evidence=[{"file": "server.ts", "line": 1}])],
        components=_COMPONENTS,
        repo_root=repo,
    )
    assert merged[0]["confidence"] == "confirmed"
    assert any("inferred -> confirmed" in n for n in notes)


def test_ingress_without_route_evidence_stays_inferred(tmp_path: Path):
    """A CI/CD or build boundary cites no inbound route — it must not be
    upgraded just for being an `external ->` crossing."""
    repo = _repo_with(tmp_path, ".github/workflows/ci.yml", "on: [push]\njobs: {}\n")
    merged, _alias, notes = prep._consolidate_candidates(
        [
            _cand(
                "c1",
                frm="external",
                to="api",
                kind="build",
                conf="inferred",
                evidence=[{"file": ".github/workflows/ci.yml", "line": 1}],
            )
        ],
        components=_COMPONENTS,
        repo_root=repo,
    )
    assert merged[0]["confidence"] == "inferred"
    assert not any("inferred -> confirmed" in n for n in notes)


def test_egress_is_never_upgraded_by_the_ingress_rule(tmp_path: Path):
    repo = _repo_with(tmp_path, "src/llm.ts", "await fetch(provider)\n")
    merged, _alias, _notes = prep._consolidate_candidates(
        [
            _cand(
                "c1",
                frm="api",
                to="external",
                kind="third-party",
                conf="inferred",
                evidence=[{"file": "src/llm.ts", "line": 1}],
            )
        ],
        components=_COMPONENTS,
        repo_root=repo,
    )
    assert merged[0]["confidence"] == "inferred"


def test_unknown_confidence_is_not_promoted(tmp_path: Path):
    """Only `inferred` is upgraded — `unknown` means the analyst could not tell
    what the crossing is, which route evidence alone does not resolve."""
    repo = _repo_with(tmp_path, "server.ts", "app.post('/x', h())\n")
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api", conf="unknown", evidence=[{"file": "server.ts", "line": 1}])],
        components=_COMPONENTS,
        repo_root=repo,
    )
    assert merged[0]["confidence"] == "unknown"


def test_route_scan_does_not_escape_the_repo(tmp_path: Path):
    outside = tmp_path / "outside.ts"
    outside.write_text("app.get('/x', h())\n", encoding="utf-8")
    repo = _repo_with(tmp_path, "keep.ts", "const x = 1\n")
    assert prep._evidence_context(repo, {"file": "../outside.ts", "line": 1}) == ""
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="api", evidence=[{"file": "../outside.ts", "line": 1}])],
        components=_COMPONENTS,
        repo_root=repo,
    )
    assert merged[0]["confidence"] == "inferred"


def test_cross_run_identity_survives_contiguous_delivery_renumbering(tmp_path: Path) -> None:
    """Two consecutive runs with a renumbered prior model.

    `build_threat_model_yaml.renumber_trust_boundaries` ships `tb-1 … tb-N`
    while the baseline ledger keeps counting from its high-watermark. Run 2 must
    still re-identify the unchanged crossings (matching is by `declaration_key`
    / authored id / `(from,to,name)` / endpoints — never by the delivered
    number), must not mis-assign, and the newly reserved ledger id must not
    collide with a dense prior id.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_threat_model_yaml", SCRIPTS / "build_threat_model_yaml.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    repo, out = _repo(tmp_path)
    crossings = [
        ("Public API", "external", "web-api"),
        ("Worker handoff", "web-api", "worker"),
        ("Worker ingress", "external", "worker"),
    ]
    # Run 1 delivered the catalogue renumbered to tb-1..tb-3; the ledger stayed
    # at the counter those rows were actually allocated from (tb-37..tb-39).
    _write_json(out / ".appsec-cache" / "baseline.json", {"id_counters": {"next_trust_boundary_id": 40}})
    prior = out / "prior.yaml"
    prior.write_text(
        yaml.safe_dump(
            {
                "components": [{"id": "web-api"}, {"id": "worker"}],
                "trust_boundaries": [
                    {
                        **_row(name),
                        "id": f"tb-{index}",
                        "from": src,
                        "to": dst,
                        "resolution_status": "resolved",
                        "sources": ["detected"],
                    }
                    for index, (name, src, dst) in enumerate(crossings, start=1)
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    # Run 2 re-emits the same crossings (authored ids are the stale ledger ids
    # the sidecar carried) plus one genuinely new crossing.
    sidecar = out / ".trust-boundaries.json"
    _write_json(
        sidecar,
        {
            "schema_version": 1,
            "trust_boundaries": [
                {**_row(name), "id": f"tb-{37 + offset}", "from": src, "to": dst}
                for offset, (name, src, dst) in enumerate(crossings)
            ]
            + [{**_row("Worker callback"), "id": "tb-99", "from": "worker", "to": "web-api"}],
        },
    )
    result, _ = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=prior, output_dir=out)
    by_name = {row["name"]: row["id"] for row in result["trust_boundaries"]}
    assert by_name["Public API"] == "tb-1"
    assert by_name["Worker handoff"] == "tb-2"
    assert by_name["Worker ingress"] == "tb-3"
    # The new row is reserved above the high-watermark, so it can never take a
    # dense prior id away from a surviving boundary.
    assert by_name["Worker callback"] == "tb-40"

    doc, mapping = builder.renumber_trust_boundaries({"trust_boundaries": result["trust_boundaries"]})
    assert mapping == {"tb-40": "tb-4"}
    assert {row["name"]: row["id"] for row in doc["trust_boundaries"]} == {
        "Public API": "tb-1",
        "Worker handoff": "tb-2",
        "Worker ingress": "tb-3",
        "Worker callback": "tb-4",
    }

    # Run 3 sees the run-2 delivery: unchanged boundaries keep their delivered
    # ids and the pass is a no-op.
    prior.write_text(
        yaml.safe_dump(
            {
                "components": [{"id": "web-api"}, {"id": "worker"}],
                "trust_boundaries": [
                    {**row, "resolution_status": "resolved", "sources": ["detected"]} for row in doc["trust_boundaries"]
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    result3, _ = prep.normalize(repo_root=repo, sidecar=sidecar, prior_model=prior, output_dir=out)
    doc3, mapping3 = builder.renumber_trust_boundaries({"trust_boundaries": result3["trust_boundaries"]})
    assert mapping3 == {}
    assert {row["name"]: row["id"] for row in doc3["trust_boundaries"]} == {
        "Public API": "tb-1",
        "Worker handoff": "tb-2",
        "Worker ingress": "tb-3",
        "Worker callback": "tb-4",
    }


# ---------------------------------------------------------------------------
# Client-side code is not a trust zone
# ---------------------------------------------------------------------------

from _boundary_adjacency import is_adjacent  # noqa: E402

_TIERED_COMPONENTS = {
    "api": {"id": "api", "tier": "application", "paths": ["server.ts", "routes/**"]},
    "spa": {"id": "spa", "tier": "client", "paths": ["frontend/src/**"]},
    "mobile": {"id": "mobile", "tier": "CLIENT ", "paths": ["mobile/**"]},
    "untagged": {"id": "untagged", "paths": ["legacy/**"]},
    "store": {"id": "store", "tier": "data", "paths": ["models/**"]},
}


def test_client_tier_source_is_rewritten_to_external(tmp_path: Path):
    """Browser-resident code sits on the untrusted side WITH the attacker: the
    server cannot tell its requests from forged ones, so the crossing's real
    origin is `external`."""
    merged, _alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="spa", to="api", point="expressJwt Bearer token")],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["from"] == "external"
    assert merged[0]["to"] == "api"
    assert any("source spa -> external" in n for n in notes)


def test_client_tier_source_keeps_its_component_as_an_anchor(tmp_path: Path):
    """The findings that live in the client code must still resolve: rewriting
    the endpoint without recording it would remove their adjacency channel."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="spa", to="api")],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["covers_components"] == ["api", "spa"]
    assert is_adjacent("spa", merged[0])


def test_client_tier_source_name_is_retargeted(tmp_path: Path):
    candidate = _cand("c1", frm="spa", to="api")
    candidate["name"] = "spa → api: expressJwt Bearer token"
    merged, _alias, _notes = prep._consolidate_candidates(
        [candidate], components=_TIERED_COMPONENTS, repo_root=tmp_path
    )
    assert merged[0]["name"] == "external → api: expressJwt Bearer token"


def test_client_tier_target_is_removed_and_reported(tmp_path: Path):
    """Serving static assets into a browser makes no security decision. The row
    must go — and the removal must be auditable, never silent."""
    dropped: dict[str, str] = {}
    merged, _alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="spa"), _cand("c2", frm="external", to="api")],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
        dropped=dropped,
    )
    assert [c["candidate_key"] for c in merged] == ["c2"]
    assert "client-tier component" in dropped["c1"]
    assert any("dropped external -> spa" in n for n in notes)


def test_client_tier_target_with_a_named_control_is_kept(tmp_path: Path):
    """Fail safe. A specific control on the way into the client is either a real
    check this model would lose, or evidence that the component is server-
    rendered or a BFF and only tagged `client`. Deleting an evidenced control is
    the dangerous direction."""
    dropped: dict[str, str] = {}
    merged, _alias, notes = prep._consolidate_candidates(
        [_cand("c1", frm="external", to="spa", point="Signed session cookie issuance")],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
        dropped=dropped,
    )
    assert [c["candidate_key"] for c in merged] == ["c1"]
    assert dropped == {}
    assert any("kept external -> spa" in n for n in notes)


def test_a_generic_control_does_not_rescue_a_client_tier_target(tmp_path: Path):
    """The generic-value filter runs first, so `application code` cannot buy a
    crossing into the browser a reprieve it did not earn."""
    dropped: dict[str, str] = {}
    prep._consolidate_candidates(
        [_cand("c1", frm="external", to="spa", point="application code")],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
        dropped=dropped,
    )
    assert "c1" in dropped


def test_absent_or_non_client_tier_is_never_treated_as_client(tmp_path: Path):
    """An absent tier is not a client tier. Inferring one would fold or drop
    boundaries that are real, which is the dangerous direction."""
    dropped: dict[str, str] = {}
    merged, _alias, _notes = prep._consolidate_candidates(
        [
            _cand("c1", frm="untagged", to="api"),
            _cand("c2", frm="external", to="untagged"),
            _cand("c3", frm="external", to="store"),
        ],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
        dropped=dropped,
    )
    assert dropped == {}
    assert [(c["from"], c["to"]) for c in merged] == [
        ("untagged", "api"),
        ("external", "untagged"),
        ("external", "store"),
    ]


def test_client_tier_is_read_case_and_whitespace_insensitively(tmp_path: Path):
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="mobile", to="api")],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert merged[0]["from"] == "external"


def test_client_tier_source_calling_a_third_party_is_left_alone(tmp_path: Path):
    """`spa -> external` is already anchored outside the system; rewriting the
    source would produce `external -> external`, which is not a crossing."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [_cand("c1", frm="spa", to="external", kind="third-party")],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert (merged[0]["from"], merged[0]["to"]) == ("spa", "external")


def test_rewritten_client_source_still_respects_a_distinct_enforcement_point(tmp_path: Path):
    """The rewrite does not widen the merge: a genuinely different control at the
    same crossing still asks its own question and keeps its own row."""
    merged, _alias, _notes = prep._consolidate_candidates(
        [
            _cand("c1", frm="spa", to="api", kind="identity", point="OAuth authorization-code exchange"),
            _cand("c2", frm="external", to="api", point="Express route middleware isAuthorized"),
        ],
        components=_TIERED_COMPONENTS,
        repo_root=tmp_path,
    )
    assert [c["candidate_key"] for c in merged] == ["c1", "c2"]


def test_duplicate_ingress_rows_fold_into_the_row_that_was_already_there(tmp_path: Path) -> None:
    """Path containment is symmetric when both rows enter the same component, so
    the fold direction must not be decided by list position — the earlier row
    keeps the identity, and with it the stable `tb-N` every finding references."""
    components = [
        {"id": "web-api", "name": "Web API", "paths": ["src/**"], "handles_sensitive_data": True},
        {"id": "spa", "name": "SPA", "tier": "client", "paths": ["frontend/**"]},
    ]
    rows, warnings = _normalized(
        tmp_path,
        [
            _resolved(id="tb-1", name="Internet to API"),
            _resolved(id="tb-2", name="SPA to API", covers_components=["spa", "web-api"]),
        ],
        components,
    )

    assert [(row["id"], row["name"]) for row in rows] == [("tb-1", "Internet to API")]
    # The folded row's anchor survives the fold.
    assert "spa" in rows[0]["covers_components"]
    assert any("folded ingress boundary" in w for w in warnings)


def _client_tier_documents(component_fp: str, input_fp: str) -> tuple[dict, dict]:
    def signal(sid: str, frm: str, to: str, cls: str) -> dict:
        return {
            "id": sid,
            "class": cls,
            "from": frm,
            "to": to,
            "mandatory": True,
            "trigger": "runtime flow crosses components",
            "false_positive_exclusions": [],
            "evidence": [{"file": "src/auth.py", "line": 1}],
            "provenance": ["architecture"],
            "flow_ids": [],
        }

    assessment = _assessment(component_fp, input_fp)
    assessment["components"].append(
        {
            "id": "spa",
            "name": "Browser SPA",
            "tier": "client",
            "deployment_zones": ["client-device"],
            "handles_sensitive_data": False,
            "paths": ["frontend/**"],
        }
    )
    assessment["signals"].extend(
        [
            signal("signal-external-ingress-external-to-spa", "external", "spa", "external-ingress"),
            signal("signal-browser-to-server-spa-to-web-api", "spa", "web-api", "cross-zone-flow"),
        ]
    )

    document = _candidate_doc(component_fp, input_fp)
    document["candidates"][0]["enforcement_point"] = "Express route middleware isAuthorized"
    document["candidates"].extend(
        [
            {
                "candidate_key": "candidate-2",
                "name": "external → spa: Express static file serving",
                "from": "external",
                "to": "spa",
                "kind": "network",
                "assumption": "The bundled assets are public and hold nothing confidential.",
                "evidence": [{"file": "src/auth.py", "line": 1}],
                "confidence": "confirmed",
                "covered_signal_ids": ["signal-external-ingress-external-to-spa"],
                "covered_flow_ids": [],
            },
            {
                "candidate_key": "candidate-3",
                "name": "spa → web-api: Bearer JWT validation",
                "from": "spa",
                "to": "web-api",
                "kind": "network",
                "assumption": "The SPA attaches the stored JWT to every API request.",
                "evidence": [{"file": "src/auth.py", "line": 1}],
                "confidence": "confirmed",
                "covered_signal_ids": ["signal-browser-to-server-spa-to-web-api"],
                "covered_flow_ids": [],
                "enforcement_point": "expressJwt Bearer token validation",
            },
        ]
    )
    document["dispositions"].extend(
        [
            {
                "signal_id": "signal-external-ingress-external-to-spa",
                "disposition": "boundary",
                "candidate_keys": ["candidate-2"],
                "rationale": "Static assets are served to anonymous browsers over the internet.",
            },
            {
                "signal_id": "signal-browser-to-server-spa-to-web-api",
                "disposition": "boundary",
                "candidate_keys": ["candidate-3"],
                "rationale": "The browser application calls the API with a bearer token.",
            },
        ]
    )
    return assessment, document


def test_promote_folds_the_client_crossing_and_reports_the_removed_one(tmp_path: Path):
    """The juice-shop defect end to end: `external → spa` was a boundary with
    nothing to protect and no control, and `spa → web-api` was the perimeter
    counted a second time."""
    repo, out = _repo(tmp_path)
    _write_json(
        out / ".components.json",
        {
            "schema_version": 1,
            "components": [
                {"id": "web-api", "name": "Web API", "tier": "application", "paths": ["src/**"]},
                {"id": "spa", "name": "Browser SPA", "tier": "client", "paths": ["frontend/**"]},
            ],
        },
    )
    component_fp, input_fp = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    assessment_path = out / ".trust-boundary-assessment-input.json"
    candidates_path = out / ".trust-boundary-candidates.json"
    assessment, document = _client_tier_documents(component_fp, input_fp)
    _write_json(assessment_path, assessment)
    _write_json(candidates_path, document)

    canonical, coverage = prep.promote_candidates(
        repo_root=repo,
        output_dir=out,
        candidates_path=candidates_path,
        assessment_input_path=assessment_path,
        prior_model=None,
    )

    rows = canonical["trust_boundaries"]
    assert [(row["from"], row["to"]) for row in rows] == [("external", "web-api")]
    # The folded component keeps a resolvable anchor on the surviving row.
    assert "spa" in rows[0]["covers_components"]
    assert is_adjacent("spa", rows[0])

    by_signal = {row["signal_id"]: row for row in coverage["signals"]}
    dropped_row = by_signal["signal-external-ingress-external-to-spa"]
    assert dropped_row["disposition"] == "same-trust"
    assert dropped_row["boundary_ids"] == []
    assert "client-tier" in dropped_row["rationale"]
    assert [issue["code"] for issue in coverage["issues"] if issue.get("signal_id") == dropped_row["signal_id"]] == [
        "client-tier-crossing-dropped"
    ]
    # The re-anchored browser crossing promotes to the surviving perimeter, so no
    # signal is left without a boundary.
    assert by_signal["signal-browser-to-server-spa-to-web-api"]["boundary_ids"] == [rows[0]["id"]]


def test_assumption_shape_violations_are_reported_not_repaired() -> None:
    """The catalogue prints a derived verdict beneath the assumption, which only
    works if the sentence is one testable condition.

    A real run produced none of the three shapes the contract asks for: fact
    lists joined by semicolons, a restatement of the control the neighbouring
    cell already names, and — on both outbound rows — a description of what is
    ABSENT, i.e. the opposite of an assumption (user 2026-08-01). Warning makes
    that visible in the run issues; rewriting it would invent a security
    assertion no analyst made.
    """
    fact_list = "SQLite runs in-process; no network isolation; Sequelize binds parameters by default."
    assert prep._assumption_shape_warnings(fact_list, None, "tb-3") == [
        "tb-3: assumption reads as a fact list, not one condition"
    ]

    absence = "No outbound content filter or egress allow-list is configured."
    assert prep._assumption_shape_warnings(absence, None, "tb-4") == [
        "tb-4: assumption states an absence instead of a condition"
    ]

    restated = "security.isAuthorized() expressJwt middleware guards the routes."
    assert prep._assumption_shape_warnings(restated, "security.isAuthorized() expressJwt middleware", "tb-1") == [
        "tb-1: assumption restates enforcement_point"
    ]

    good = "Protected routes require a verified JWT."
    assert prep._assumption_shape_warnings(good, "security.isAuthorized() expressJwt middleware", "tb-1") == []
    # The threshold used to be TWO semicolons, on the theory that one joins a
    # clause rather than a list. juice-shop then shipped a one-semicolon row
    # that was plainly two conditions — "Protected API routes require a verified
    # JWT via expressJwt; unauthenticated routes are intentionally public." — and
    # no single verdict can address it (user 2026-08-01). A semicolon joins
    # INDEPENDENT clauses by definition, so one is already two conditions; this
    # example says as much and is now flagged.
    assert prep._assumption_shape_warnings("Requests are authenticated; tokens are signed.", None, "tb-1") == [
        "tb-1: assumption reads as a fact list, not one condition"
    ]


def test_normalize_row_surfaces_an_unusable_assumption_in_the_warnings(tmp_path: Path) -> None:
    repo, out = _repo(tmp_path)
    warnings: list[str] = []
    row = prep._normalize_row(
        {
            "name": "external -> web-api",
            "from": "external",
            "to": "web-api",
            "kind": "network",
            "assumption": "No egress allow-list exists.",
            "enforcement_point": "security.isAuthorized() expressJwt middleware",
            "evidence": [],
            "confidence": "inferred",
        },
        repo_root=repo,
        components={"web-api": {}},
        legacy_input=False,
        warnings=warnings,
        source="detected",
    )
    # Reported, and the text still ships exactly as authored.
    assert row["assumption"] == "No egress allow-list exists."
    assert any("states an absence instead of a condition" in warning for warning in warnings)


def _tb(**overrides) -> dict:
    row = {
        "id": "tb-1",
        "name": "external -> web-api",
        "from": "external",
        "to": "web-api",
        "kind": "network",
        "assumption": "Protected routes require a verified JWT.",
        "evidence": [],
        "confidence": "confirmed",
        "resolution_status": "resolved",
        "sources": ["detected"],
    }
    row.update(overrides)
    return row


def test_boundary_assumption_state_refuted_requires_clean_evidence_check() -> None:
    """A finding that cannot raise a severity must not silently break a boundary.

    The gate mirrors the elevation suppression in `_compute_effective`, so the §1
    verdict a reader sees and the boundary state the scoring reads can never
    disagree about the word "refuted".
    """
    row = _tb()
    verified = {"id": "T-001", "component": "web-api", "boundary_refs": [{"boundary_id": "tb-1"}]}
    assert prep.boundary_assumption_state(row, [verified]) == ("refuted", ["T-001"])

    for state in ("refuted", "ambiguous"):
        unverified = {**verified, "evidence_check": state}
        # Falls through to adjacency: the finding still sits behind the crossing.
        assert prep.boundary_assumption_state(row, [unverified]) == ("unconfirmed", ["T-001"])


def test_boundary_assumption_state_unconfirmed_counts_covered_components() -> None:
    """Folded-in components are protected too; the crossing's own source is not."""
    row = _tb(covers_components=["web-api", "worker"])
    threats = [
        {"id": "T-002", "component": "worker"},
        {"id": "T-010", "component": "web-api"},
        {"id": "T-003", "component": "unrelated"},
    ]
    # Sorted by the numeric tail, so T-010 follows T-002 instead of preceding it.
    assert prep.boundary_assumption_state(row, threats) == ("unconfirmed", ["T-002", "T-010"])


def test_boundary_assumption_state_source_component_is_never_protected() -> None:
    row = _tb(**{"from": "web-api", "to": "db", "covers_components": ["web-api", "db"]})
    assert prep.boundary_protected_components(row) == {"db"}
    assert prep.boundary_assumption_state(row, [{"id": "T-004", "component": "web-api"}]) == ("clean", [])


def test_boundary_assumption_state_not_examined_when_no_protected_side() -> None:
    row = _tb(to="")
    assert prep.boundary_assumption_state(row, [{"id": "T-005", "component": "web-api"}]) == ("not-examined", [])


def test_boundary_assumption_state_clean_when_nothing_contradicts() -> None:
    row = _tb()
    assert prep.boundary_assumption_state(row, [{"id": "T-006", "component": "elsewhere"}]) == ("clean", [])


# --------------------------------------------------------------------------- #
# Assumption legs (user 2026-08-01)
# --------------------------------------------------------------------------- #


def test_crossing_type_comes_from_direction_not_kind() -> None:
    """`kind` cannot discriminate: juice-shop's tb-1 (`network`) and tb-7
    (`third-party`) both carry `surface: network` and are opposite directions.
    Only `from`/`to == external` does, and it always does."""
    assert prep.boundary_crossing_type(_tb(kind="network")) == "ingress"
    assert prep.boundary_crossing_type(_tb(**{"from": "chatbot", "to": "external", "kind": "third-party"})) == "egress"
    assert prep.boundary_crossing_type(_tb(**{"from": "web-api", "to": "db", "kind": "process"})) == "internal"


def test_assumption_legs_are_synthesized_for_directional_crossings_only() -> None:
    """An inbound crossing always has to decide what the payload may contain,
    who is calling and what they may do, so naming those legs asserts nothing
    the direction does not already imply — and it lets a model authored before
    legs existed still report per-leg verdicts. "Every in-process interface has
    an authorization leg" is false, so an internal row gets only what it
    declares."""
    assert [leg["leg"] for leg in prep.boundary_legs(_tb())] == list(prep.INGRESS_LEGS)
    egress = _tb(**{"from": "chatbot", "to": "external"})
    assert [leg["leg"] for leg in prep.boundary_legs(egress)] == list(prep.EGRESS_LEGS)
    assert prep.boundary_legs(_tb(**{"from": "web-api", "to": "db"})) == []


def test_normalize_assumption_legs_drops_a_leg_the_direction_cannot_have() -> None:
    warnings: list[str] = []
    row = _tb()
    legs = prep.normalize_assumption_legs(
        [
            {"leg": "response-trust", "condition": "Only valid on an outbound crossing."},
            {"leg": "authorization", "condition": "Every object reference is checked against the subject."},
            {"leg": "authorization", "condition": "Duplicate."},
            "not-an-object",
        ],
        row,
        "tb-1",
        warnings,
    )
    assert legs == [{"leg": "authorization", "condition": "Every object reference is checked against the subject."}]
    assert any("response-trust" in w for w in warnings)
    assert any("duplicate" in w for w in warnings)


def test_boundary_leg_states_reports_the_leg_no_finding_could_attach_to() -> None:
    """The tb-1 shape: an authentication-only assumption left three authorization
    findings — one a Critical IDOR — linked to nothing. The authorization leg has
    to surface them as `unconfirmed`, not read as unexamined."""
    row = _tb(covers_components=["web-api", "chatbot"])
    threats = [
        {
            "id": "T-040",
            "component": "web-api",
            "cwe": "CWE-306",
            "boundary_refs": [{"boundary_id": "tb-1"}],
        },
        {"id": "T-008", "component": "web-api", "cwe": "CWE-639"},
        {"id": "T-038", "component": "web-api", "cwe": "CWE-862"},
        {"id": "T-003", "component": "web-api", "cwe": "CWE-400"},  # not a boundary condition
    ]
    states = {leg["leg"]: leg for leg in prep.boundary_leg_states(row, threats)}
    assert states["authentication"]["state"] == "refuted"
    assert states["authentication"]["finding_ids"] == ["T-040"]
    assert states["authorization"]["state"] == "unconfirmed"
    assert states["authorization"]["finding_ids"] == ["T-008", "T-038"]
    # CWE-400 maps to no leg: resource exhaustion is not a trust condition.
    assert states["validation"]["state"] == "unexamined"


def test_boundary_leg_states_prefers_the_authored_leg_over_the_cwe() -> None:
    row = _tb()
    threat = {
        "id": "T-012",
        "component": "web-api",
        "cwe": "CWE-306",
        "boundary_refs": [{"boundary_id": "tb-1", "leg": "authorization"}],
    }
    states = {leg["leg"]: leg["state"] for leg in prep.boundary_leg_states(row, [threat])}
    assert states["authorization"] == "refuted"
    assert states["authentication"] == "unexamined"


def test_boundary_leg_states_ignores_a_finding_whose_evidence_was_refuted() -> None:
    row = _tb()
    threat = {
        "id": "T-012",
        "component": "web-api",
        "cwe": "CWE-94",
        "evidence_check": "refuted",
        "boundary_refs": [{"boundary_id": "tb-1"}],
    }
    assert all(leg["state"] == "unexamined" for leg in prep.boundary_leg_states(row, [threat]))


def test_validate_boundary_refs_drops_a_bad_leg_but_keeps_the_link() -> None:
    """Fail-open on the label: the ref already carries a rationale and
    finding-owned evidence, so an unusable leg costs the leg, not the link."""
    boundary = _tb()
    finding = {
        "evidence": [{"file": "server.ts", "line": 638}],
        "boundary_refs": [
            {
                "boundary_id": "tb-1",
                "origin_component_id": "web-api",
                "rationale": "The route is registered without the authentication middleware.",
                "leg": "response-trust",
                "evidence_locations": [{"file": "server.ts", "line": 638}],
            }
        ],
    }
    cleaned, diagnostics = prep.validate_finding_boundary_refs(
        finding,
        boundaries=[boundary],
        origin_component_id="web-api",
        candidate_ids=None,
        require_candidate=False,
    )
    assert len(cleaned) == 1
    assert "leg" not in cleaned[0]
    assert any("invalid leg" in d for d in diagnostics)


def test_assumption_lint_flags_the_two_shapes_one_juice_shop_row_carried() -> None:
    issues = prep._assumption_shape_warnings(
        "Protected API routes require a verified JWT via expressJwt; unauthenticated routes are intentionally public.",
        "security.isAuthorized() expressJwt",
        "tb-1",
    )
    assert any("fact list" in i for i in issues)
    assert any("sanctions the gap" in i for i in issues)


def test_assumption_lint_does_not_flag_its_own_model_answer() -> None:
    """The spec's model answer for an outbound crossing starts with "Nothing".
    A leading no/nothing marks an absence only when the sentence predicates no
    behaviour — otherwise the lint punishes the phrasing it recommends."""
    assert (
        prep._assumption_shape_warnings("Nothing attacker-controlled reaches the provider unfiltered.", None, "tb")
        == []
    )
    assert prep._assumption_shape_warnings("No request reaches the handler without a verified JWT.", None, "tb") == []
    assert prep._assumption_shape_warnings("No outbound content filter or egress allow-list.", None, "tb") == [
        "tb: assumption states an absence instead of a condition"
    ]


def test_partial_leg_declaration_adds_a_condition_but_never_removes_a_leg() -> None:
    """An analyst who names `authorization` alone on an inbound crossing must not
    silently delete validation and authentication — that would be a worse table
    than the one before legs existed. Partial authorship degrades toward MORE
    information, not less."""
    row = _tb(assumption_legs=[{"leg": "authorization", "condition": "Objects are checked against the subject."}])
    legs = prep.boundary_legs(row)
    assert [leg["leg"] for leg in legs] == list(prep.INGRESS_LEGS)
    assert legs[2]["condition"] == "Objects are checked against the subject."
    assert "condition" not in legs[0]
