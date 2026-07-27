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
