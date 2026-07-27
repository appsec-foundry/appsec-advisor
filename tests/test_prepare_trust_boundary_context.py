from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

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
