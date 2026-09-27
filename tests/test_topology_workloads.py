"""Deployment-topology workloads reach the architecture analyst and bind its component inventory."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import aggregate_run_issues  # noqa: E402
import build_architecture_analysis_context as context  # noqa: E402
import finalize_component_inventory as finalize  # noqa: E402
from validate_fragment import workload_coverage_errors  # noqa: E402

SCHEMA = json.loads((ROOT / "schemas" / "architecture-topology-context.schema.json").read_text(encoding="utf-8"))


def _workload(name: str, platform: str, zones: list[str], line: int = 1, source: str = "deploy.yml") -> dict:
    return {"name": name, "platform": platform, "source": source, "line": line, "zones": zones}


def _inventory(workloads: list[dict], bridging: list[tuple[str, str]] = ()) -> dict:
    return {
        "schema_version": 1,
        "topology": {
            "zones": [],
            "workloads": workloads,
            "zone_bridging": [{"name": name, "platform": platform} for name, platform in bridging],
        },
    }


def _project(inventory: dict) -> dict | None:
    return context.project_topology(json.dumps(inventory).encode("utf-8"))


@pytest.mark.parametrize("inventory", [{}, {"schema_version": 1, "compose": None}, _inventory([])])
def test_a_repository_without_topology_gets_no_projection_and_loses_a_stale_one(tmp_path, inventory) -> None:
    assert _project(inventory) is None
    target = tmp_path / context.TOPOLOGY_CONTEXT
    target.parent.mkdir(parents=True)
    target.write_text("{}", encoding="utf-8")
    (tmp_path / ".deployment-inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    assert context.build_topology(tmp_path) is None
    assert not target.exists()


@pytest.mark.parametrize(
    ("names", "zones"),
    [
        (("gateway", "orders", "db"), ("edge", "core", "data")),
        (("front-door", "billing-api", "ledger-store"), ("public-net", "biz-net", "vault-net")),
    ],
)
def test_projection_keeps_one_row_per_workload_with_platform_qualified_zones(names, zones) -> None:
    gateway, service, store = names
    edge, core, data = zones
    projected = _project(
        _inventory(
            [
                _workload(gateway, "compose", [edge, core], line=4),
                _workload(gateway, "kubernetes", [edge], line=9, source="k8s.yaml"),
                _workload(service, "compose", ["default"], line=12),
                _workload(store, "compose", [data], line=20),
            ],
            bridging=[(gateway, "compose")],
        )
    )
    jsonschema.validate(projected, SCHEMA)
    rows = {row["name"]: row for row in projected["workloads"]}
    assert list(rows) == sorted(names)
    assert rows[gateway]["zones"] == sorted([f"compose:{edge}", f"compose:{core}", f"kubernetes:{edge}"])
    assert rows[gateway]["zone_bridging"] is True
    assert [d["platform"] for d in rows[gateway]["definitions"]] == ["compose", "kubernetes"]
    assert rows[service]["zones"] == ["compose:default"] and rows[service]["zone_bridging"] is False
    assert rows[store]["definitions"] == [{"platform": "compose", "source": "deploy.yml", "line": 20}]


def test_projection_bounds_workloads_with_disclosure() -> None:
    many = [_workload(f"svc-{i:03d}", "compose", ["net"], line=i) for i in range(context.MAX_TOPOLOGY_WORKLOADS + 5)]
    projected = _project(_inventory(many))
    jsonschema.validate(projected, SCHEMA)
    assert len(projected["workloads"]) == context.MAX_TOPOLOGY_WORKLOADS
    assert projected["limits"]["omitted_workloads"] == 5


TOPOLOGY = {"workloads": [{"name": "api"}, {"name": "db"}, {"name": "proxy"}]}


@pytest.mark.parametrize(
    ("components", "unmodelled", "expected"),
    [
        ([{"id": "a", "workloads": ["api", "proxy"]}, {"id": "b", "workloads": ["db"]}], [], []),
        ([{"id": "a", "workloads": ["api"]}], [{"name": "db", "reason": "x"}, {"name": "proxy", "reason": "y"}], []),
        ([{"id": "a", "workloads": ["api"]}], [], ["neither listed"]),
        ([{"id": "a", "workloads": ["api", "db", "proxy", "ghost"]}], [], ["'ghost', which the topology"]),
        ([{"id": "a", "workloads": ["api", "db", "proxy"]}], [{"name": "db", "reason": "x"}], ["both modelled"]),
        ([{"id": "a", "workloads": ["api", "db", "proxy"]}], [{"name": "cache", "reason": "x"}], ["'cache'"]),
    ],
)
def test_every_workload_is_modelled_or_declared_unmodelled(components, unmodelled, expected) -> None:
    errors = workload_coverage_errors({"components": components, "unmodelled_workloads": unmodelled}, TOPOLOGY)
    assert len(errors) == len(expected)
    for error, fragment in zip(errors, expected, strict=True):
        assert fragment in error


def test_coverage_is_not_enforced_without_a_topology() -> None:
    assert workload_coverage_errors({"components": [{"id": "a"}]}, None) == []


@pytest.mark.parametrize("with_topology", [False, True])
def test_the_unchanged_self_check_finds_the_runs_topology_beside_the_inventory(tmp_path, with_topology) -> None:
    import validate_fragment

    doc = {"schema_version": 1, "components": [_component("app", ["src/app.py"])]}
    path = tmp_path / ".components.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    if with_topology:
        (tmp_path / ".deployment-inventory.json").write_text(
            json.dumps(_inventory([_workload("api", "compose", ["core"])])), encoding="utf-8"
        )
        context.build_topology(tmp_path)
    assert validate_fragment.validate("components", path) == (1 if with_topology else 0)


def _finalize_run(tmp_path: Path, components: list[dict], inventory: dict | None) -> list[dict]:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
    (repo / "deploy.yml").write_text("services: {}\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": components}), encoding="utf-8"
    )
    if inventory is not None:
        (output / ".deployment-inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    payload, receipt = finalize.finalize(repo, output)
    assert receipt["component_inventory_fingerprint"] == finalize.component_inventory_fingerprint(payload["components"])
    return payload["components"]


def _component(cid: str, paths: list[str], **extra) -> dict:
    return {"id": cid, "name": cid, "description": "d", "paths": paths, "tier": "application", **extra}


def test_finalization_derives_placement_from_workloads_and_discards_authored_values(tmp_path) -> None:
    inventory = _inventory(
        [
            _workload("api", "compose", ["core"], line=3),
            _workload("broker", "compose", ["core", "queue"], line=9),
            _workload("broker", "kubernetes", ["queue"], line=5, source="k8s.yaml"),
        ]
    )
    rows = _finalize_run(
        tmp_path,
        [
            _component("app", ["src/app.py"], workloads=["api"], workload_zones=["compose:forged"]),
            _component("broker", ["deploy.yml"], workloads=["broker"]),
            _component("lib", ["src/app.py"], deployment_evidence=[{"file": "x", "line": 1}]),
        ],
        inventory,
    )
    by_id = {row["id"]: row for row in rows}
    assert by_id["app"]["workload_zones"] == ["compose:core"]
    assert by_id["app"]["deployment_evidence"] == [{"file": "deploy.yml", "line": 3}]
    assert by_id["broker"]["workload_zones"] == ["compose:core", "compose:queue", "kubernetes:queue"]
    assert len(by_id["broker"]["deployment_evidence"]) == 2
    assert "workload_zones" not in by_id["lib"] and "deployment_evidence" not in by_id["lib"]


def test_an_inventory_without_workloads_keeps_its_fingerprint(tmp_path) -> None:
    components = [_component("app", ["src/app.py"])]
    rows = _finalize_run(tmp_path, components, None)
    legacy_fields = ("id", "name", "paths", "tier", "deployment_zones", "handles_sensitive_data")
    legacy = [{key: row.get(key) for key in legacy_fields} for row in rows]
    encoded = json.dumps(legacy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    import hashlib

    expected = "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    assert finalize.component_inventory_fingerprint(rows) == expected


def test_workloads_change_the_fingerprint_because_they_change_boundary_placement() -> None:
    plain = [_component("app", ["src/app.py"])]
    placed = [_component("app", ["src/app.py"], workloads=["api"], workload_zones=["compose:core"])]
    assert finalize.component_inventory_fingerprint(plain) != finalize.component_inventory_fingerprint(placed)


def _run_dir(tmp_path: Path, components: dict, inventory: dict | None) -> Path:
    (tmp_path / ".components.json").write_text(json.dumps(components), encoding="utf-8")
    if inventory is not None:
        (tmp_path / ".deployment-inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("components", "inventory", "issues"),
    [
        ({"components": [{"id": "a", "workloads": ["api"]}]}, _inventory([_workload("api", "compose", ["n"])]), 0),
        ({"components": [{"id": "a"}]}, _inventory([_workload("api", "compose", ["n"])]), 1),
        ({"components": [{"id": "a"}]}, None, 0),
        ({"components": [{"id": "a"}]}, _inventory([]), 0),
    ],
)
def test_a_remaining_workload_gap_is_one_run_issue(tmp_path, components, inventory, issues) -> None:
    found = aggregate_run_issues._extract_unmodelled_workloads(_run_dir(tmp_path, components, inventory))
    assert len(found) == issues
    assert all(issue["category"] == "topology_workload_unmodelled" for issue in found)


def test_recon_projection_keeps_every_component_hint_row() -> None:
    rows = "\n".join(f"| svc-{i} | Service {i} | java | role | /api |" for i in range(30))
    summary = f"# Recon\n\n## 9. Preliminary Components\n\nIntro line.\n\n| ID | Name | T | R | E |\n|---|---|---|---|---|\n{rows}\n\n## 10. Other\n\n- a\n"
    projected = context.project_recon_summary(summary.encode("utf-8"))
    section = next(s for s in projected["sections"] if s["heading"].endswith("Preliminary Components"))
    assert section["omitted_body_lines"] == 0
    assert len(section["lines"]) == 33
