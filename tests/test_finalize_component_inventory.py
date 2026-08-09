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
