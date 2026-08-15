from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import build_trust_boundary_assessment_input as builder  # noqa: E402
import finalize_component_inventory as finalizer  # noqa: E402

SIGNAL_KEYS = (
    "has_public_routes",
    "has_auth_surface",
    "has_role_concept",
    "has_secrets_in_repo",
    "has_ci_pipeline",
    "has_external_apis",
    "has_client_storage",
    "has_multi_tenancy_signal",
    "has_open_self_registration",
    "has_llm_surface",
)


def _recon_signals() -> dict:
    return {
        "schema_version": 2,
        "signals": {key: False for key in SIGNAL_KEYS},
        "signal_evidence": {key: {"status": "none", "locations": []} for key in SIGNAL_KEYS},
        "signal_classification": {"has_open_self_registration": "deterministic"},
        "component_hints": [],
    }


def _component(component_id: str, tier: str, zones: list[str]):
    return {
        "id": component_id,
        "name": component_id.title(),
        "description": "Component under test",
        "paths": [f"src/{component_id}/**"],
        "tier": tier,
        "deployment_zones": zones,
        "handles_sensitive_data": tier == "data",
    }


def _setup(tmp_path: Path) -> tuple[Path, Path, dict]:
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "flow.ts").write_text("route('/api')\nconnectDb()\n", encoding="utf-8")
    components = [
        _component("browser", "client", ["client-device"]),
        _component("api", "application", ["internet", "dmz"]),
        _component("database", "data", ["prod-write-db"]),
    ]
    for component in components:
        component_dir = repo / "src" / component["id"]
        component_dir.mkdir()
        (component_dir / "component.ts").write_text("export const component = true\n", encoding="utf-8")
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": components}),
        encoding="utf-8",
    )
    _, receipt = finalizer.finalize(repo, output)
    return repo, output, receipt


def _write_flows(output: Path, receipt: dict, fingerprint: str | None = None):
    (output / ".data-flows.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "component_inventory_fingerprint": fingerprint or receipt["component_inventory_fingerprint"],
                "data_flows": [
                    {
                        "id": "df-001",
                        "from": "browser",
                        "to": "api",
                        "label": "REST API request",
                        "protocol": "HTTPS",
                        "data_classification": "Authenticated",
                        "direction": "request-response",
                        "evidence": [{"file": "src/flow.ts", "line": 1}],
                        "provenance": "architecture",
                    },
                    {
                        "id": "df-002",
                        "from": "api",
                        "to": "database",
                        "label": "ORM query",
                        "protocol": "SQL",
                        "data_classification": "Confidential",
                        "direction": "request-response",
                        "evidence": [{"file": "src/flow.ts", "line": 2}],
                        "provenance": "architecture",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


def test_builds_deterministic_crossing_signals(tmp_path: Path):
    repo, output, receipt = _setup(tmp_path)
    _write_flows(output, receipt)

    first = builder.build(repo, output, "standard")
    second = builder.build(repo, output, "standard")

    assert first == second
    classes = {row["class"] for row in first["signals"]}
    assert {"browser-to-server", "cross-zone-flow", "application-to-data-tier", "external-ingress"} <= classes
    assert first["component_inventory_fingerprint"] == receipt["component_inventory_fingerprint"]
    assert all(not str(e.get("file", "")).startswith("/") for s in first["signals"] for e in s["evidence"])
    assert first["source_context"]["route_inventory"]["status"] == "missing"
    assert first["source_context"]["cross_repository"]["status"] == "missing"


def test_optional_validated_sources_are_bounded_and_fingerprinted(tmp_path: Path):
    repo, output, receipt = _setup(tmp_path)
    _write_flows(output, receipt)
    baseline = builder.build(repo, output, "standard")
    (output / ".route-inventory.json").write_text(
        json.dumps(
            {
                "version": 1,
                "routes": [
                    {
                        "route_id": "R-001",
                        "method": "GET",
                        "path": "/admin",
                        "framework": "express",
                        "handler_file": "src/flow.ts",
                        "handler_line": 1,
                        "authn_signal": "middleware_present",
                        "authz_signal": "unknown",
                        "management_surface": True,
                        "confidence": "high",
                    }
                ],
                "coverage": {"frameworks_detected": ["express"], "unsupported_route_files": []},
            }
        ),
        encoding="utf-8",
    )
    (output / ".attack-surface-overrides.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "curations": {"include_route_ids": ["R-001"]},
                "additions": [{"entry_point": "Nightly import", "protocol": "Cron", "auth_required": False}],
            }
        ),
        encoding="utf-8",
    )
    (output / ".cross-repo-register.json").write_text(
        json.dumps(
            {
                "meta": {
                    "register_version": 1,
                    "generated_at": "2026-07-27T00:00:00Z",
                    "sources": ["declared"],
                },
                "entries": [
                    {
                        "name": "Identity service",
                        "source": "declared",
                        "interface": "OIDC",
                        "type": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    recon = _recon_signals()
    recon["signals"].update({"has_auth_surface": True, "has_public_routes": True})
    recon["signal_evidence"].update(
        {
            "has_auth_surface": {
                "status": "supporting",
                "locations": [{"file": "src/flow.ts", "line": 1}],
            },
            "has_public_routes": {
                "status": "supporting",
                "locations": [{"file": "src/flow.ts", "line": 1}],
            },
        }
    )
    (output / ".recon-signals.json").write_text(json.dumps(recon), encoding="utf-8")
    declarations = repo / ".appsec"
    declarations.mkdir()
    (declarations / "trust-boundaries.yaml").write_text(
        "\n".join(
            [
                "api_version: appsec-advisor/trust-boundaries/v1",
                "boundaries:",
                "  - key: internet-api",
                "    name: Internet to API",
                "    from: external",
                "    to: api",
                "    kind: network",
                "    assumption: The API authenticates protected operations.",
            ]
        ),
        encoding="utf-8",
    )

    enriched = builder.build(repo, output, "standard")

    assert enriched["assessment_input_fingerprint"] != baseline["assessment_input_fingerprint"]
    context = enriched["source_context"]
    assert context["route_inventory"]["status"] == "present"
    assert context["route_inventory"]["routes"][0]["evidence"] == [{"file": "src/flow.ts", "line": 1}]
    assert context["attack_surface_additions"][0]["protocol"] == "Cron"
    assert context["cross_repository"]["entries"][0]["name"] == "Identity service"
    assert context["recon_signals"]["values"]["has_auth_surface"] is True
    assert context["recon_signals"]["evidence"] == [{"file": "src/flow.ts", "line": 1}]
    assert context["boundary_declarations"]["keys"] == ["internet-api"]


@pytest.mark.parametrize("location", [{"file": "missing.ts", "line": 1}, {"file": "src/flow.ts", "line": 99}])
def test_rejects_invalid_recon_repository_evidence(tmp_path: Path, location: dict) -> None:
    repo, output, receipt = _setup(tmp_path)
    _write_flows(output, receipt)
    recon = _recon_signals()
    recon["signals"]["has_auth_surface"] = True
    recon["signal_evidence"]["has_auth_surface"] = {"status": "supporting", "locations": [location]}
    (output / ".recon-signals.json").write_text(json.dumps(recon), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid recon signal evidence"):
        builder.build(repo, output, "standard")


def test_safe_evidence_drops_missing_directories_and_out_of_range_lines(tmp_path: Path) -> None:
    (tmp_path / "source.ts").write_text("line\n", encoding="utf-8")
    (tmp_path / "directory").mkdir()

    assert builder._safe_evidence(
        [
            {"file": "missing.ts", "line": 1},
            {"file": "directory", "line": 1},
            {"file": "source.ts", "line": 2},
            {"file": "source.ts", "line": 1},
        ],
        tmp_path,
    ) == [{"file": "source.ts", "line": 1}]


def test_rejects_malformed_optional_route_inventory(tmp_path: Path):
    repo, output, receipt = _setup(tmp_path)
    _write_flows(output, receipt)
    (output / ".route-inventory.json").write_text(json.dumps({"version": 1, "routes": []}), encoding="utf-8")

    with pytest.raises(builder.jsonschema.ValidationError, match="coverage"):
        builder.build(repo, output, "standard")


def test_incremental_build_preserves_prior_flow_id_by_semantic_identity(tmp_path: Path):
    repo, output, receipt = _setup(tmp_path)
    _write_flows(output, receipt)
    current = json.loads((output / ".data-flows.json").read_text(encoding="utf-8"))
    prior_rows = [dict(row, id=f"df-{777 + index}") for index, row in enumerate(current["data_flows"])]
    (output / "threat-model.yaml").write_text(
        "data_flows:\n"
        + "\n".join(
            [
                f"  - id: {row['id']}\n"
                f"    from: {row['from']}\n"
                f"    to: {row['to']}\n"
                f"    label: {row['label']}\n"
                f"    protocol: {row['protocol']}"
                for row in prior_rows
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (output / ".skill-config.json").write_text(json.dumps({"incremental": True}), encoding="utf-8")

    result = builder.build(repo, output, "standard")

    assert [row["id"] for row in result["data_flows"]] == ["df-777", "df-778"]
    persisted = json.loads((output / ".data-flows.json").read_text(encoding="utf-8"))
    assert [row["id"] for row in persisted["data_flows"]] == ["df-777", "df-778"]


def test_rejects_stale_flow_fingerprint(tmp_path: Path):
    repo, output, receipt = _setup(tmp_path)
    _write_flows(output, receipt, "sha256:" + "0" * 64)

    with pytest.raises(ValueError, match="stale component inventory fingerprint"):
        builder.build(repo, output, "standard")


def test_rejects_unknown_flow_endpoint(tmp_path: Path):
    repo, output, receipt = _setup(tmp_path)
    _write_flows(output, receipt)
    document = json.loads((output / ".data-flows.json").read_text(encoding="utf-8"))
    document["data_flows"][0]["to"] = "invented-component"
    (output / ".data-flows.json").write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown component endpoint"):
        builder.build(repo, output, "standard")
