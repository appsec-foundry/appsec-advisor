from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import build_stride_dispatch_manifest as manifest  # noqa: E402
import finalize_component_inventory as finalizer  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent


def _component(component_id: str, **overrides):
    row = {
        "id": component_id,
        "name": component_id.title(),
        "description": "Component under test",
        "paths": [f"src/{component_id}/**"],
        "tier": "application",
        "deployment_zones": ["internal-network"],
        "handles_sensitive_data": False,
    }
    row.update(overrides)
    return row


def _write_components(output_dir: Path, rows: list[dict]) -> None:
    (output_dir / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": rows}),
        encoding="utf-8",
    )


def _materialize_component_paths(repo: Path, rows: list[dict]) -> None:
    for row in rows:
        for pattern in row.get("paths", []):
            base = pattern.split("*", 1)[0].rstrip("/")
            target = repo / base
            if pattern.endswith("/**") or not target.suffix:
                target.mkdir(parents=True, exist_ok=True)
                (target / "component.py").write_text("value = 1\n", encoding="utf-8")
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("value = 1\n", encoding="utf-8")


def test_finalizer_collapses_duplicates_and_is_idempotent(tmp_path: Path):
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    rows = [
        _component("api"),
        _component("api", paths=["src/api/routes/**"], framework="express"),
    ]
    _materialize_component_paths(repo, rows)
    _write_components(output, rows)

    first, receipt1 = finalizer.finalize(repo, output)
    second, receipt2 = finalizer.finalize(repo, output)

    assert [row["id"] for row in first["components"]] == ["api"]
    assert first == second
    assert receipt1["component_inventory_fingerprint"] == receipt2["component_inventory_fingerprint"]
    assert receipt1["collapsed_duplicate_count"] == 1
    assert finalizer.validate_receipt(output) == receipt2


def test_validate_receipt_rejects_post_boundary_drift(tmp_path: Path):
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    rows = [_component("api")]
    _materialize_component_paths(repo, rows)
    _write_components(output, rows)
    finalizer.finalize(repo, output)
    document = json.loads((output / ".components.json").read_text(encoding="utf-8"))
    document["components"][0]["deployment_zones"] = ["internet"]
    (output / ".components.json").write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="fingerprint changed"):
        finalizer.validate_receipt(output)


def test_finalizer_separates_orm_logic_from_store_before_receipting(tmp_path):
    repo, output = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    (repo / "models").mkdir()
    (repo / "models/account.ts").write_text(
        "import { DataTypes } from 'sequelize'; db.define('Account', {name: DataTypes.STRING});"
    )
    _write_components(output, [_component("store", tier="data", framework="sequelize", paths=["models/**"])])
    first, receipt = finalizer.finalize(repo, output)
    assert receipt["injected_component_ids"] == ["sequelize-data-access"]
    assert first["components"][0]["tier"] == "data"
    assert first["components"][0]["framework"] is None
    assert first["components"][1]["tier"] == "application"
    assert first["components"][1]["paths"] == ["models/account.ts"]
    assert finalizer.finalize(repo, output)[0] == first


def test_validate_receipt_rejects_false_injected_component_claim(tmp_path: Path):
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    rows = [_component("api")]
    _materialize_component_paths(repo, rows)
    _write_components(output, rows)
    finalizer.finalize(repo, output)
    receipt_path = output / ".component-inventory-finalization.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["injected_component_ids"] = ["invented-auth"]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(ValueError, match="injected component"):
        finalizer.validate_receipt(output)


def test_manifest_is_read_only_after_finalization(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    rows = [_component("api")]
    _materialize_component_paths(repo, rows)
    _write_components(output, rows)
    finalizer.finalize(repo, output)
    before = (output / ".components.json").read_bytes()

    injected = _component("late-auth")
    monkeypatch.setattr(
        manifest,
        "reconcile_inventory",
        lambda rows, _root: (rows + [injected], [injected]),
    )
    with pytest.raises(ValueError, match="would change after trust-boundary assessment"):
        manifest.build(output, "standard", {}, PLUGIN_ROOT)
    assert (output / ".components.json").read_bytes() == before


def test_finalizer_rejects_component_path_that_matches_nothing(tmp_path: Path):
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    _write_components(output, [_component("api", paths=["src/invented/**"])])
    before = (output / ".components.json").read_bytes()

    with pytest.raises(ValueError, match="matches no repository entry"):
        finalizer.finalize(repo, output)

    assert (output / ".components.json").read_bytes() == before
    assert not (output / ".component-inventory-finalization.json").exists()


def test_validate_receipt_rechecks_paths_against_repository(tmp_path: Path):
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    rows = [_component("api")]
    _materialize_component_paths(repo, rows)
    _write_components(output, rows)
    finalizer.finalize(repo, output)
    source = repo / "src" / "api" / "component.py"
    source.unlink()
    (repo / "src" / "api").rmdir()

    with pytest.raises(ValueError, match="matches no repository entry"):
        finalizer.validate_receipt(output, repo)


def test_existing_auth_inventory_adds_login_handler_before_finalization(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/login.ts").write_text("export function login() {}\n")
    (tmp_path / "routes/token.ts").write_text("export const token = true\n")
    rows = [_component("auth", paths=["routes/token.ts"])]
    result, injected = manifest.reconcile_inventory(rows, tmp_path)
    assert not injected
    assert "routes/login.ts" in result[0]["paths"]
    assert manifest.reconcile_inventory(result, tmp_path)[0] == result


def test_embedded_document_store_is_not_covered_by_sql_store(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"marsdb": "1.0"}}))
    (tmp_path / "data").mkdir()
    (tmp_path / "data/documents.ts").write_text(
        "import Engine from 'marsdb'\nconst records = new Engine.Collection('records')\n"
    )
    rows = [_component("database", framework="sqlite", tier="data", paths=["data/sqlite.db"])]
    result, injected = manifest.reconcile_inventory(rows, tmp_path)
    assert [c["framework"] for c in injected] == ["marsdb"]
    assert len(result) == 2
    assert manifest.reconcile_inventory(result, tmp_path)[1] == []
    (tmp_path / "data/documents.ts").write_text("// import Engine from 'marsdb'\n// new Engine.Collection('records')\n")
    assert manifest.reconcile_inventory(rows, tmp_path)[1] == []


def test_orm_cannot_be_finalized_as_database_engine(tmp_path):
    (tmp_path / "models").mkdir()
    (tmp_path / "models/account.ts").write_text("export const account = true\n")
    _write_components(tmp_path, [_component("database", tier="data", framework="sequelize", paths=["models/**"])])
    with pytest.raises(ValueError, match="ORM"):
        finalizer.finalize(tmp_path, tmp_path)
