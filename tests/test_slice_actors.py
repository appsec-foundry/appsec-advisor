"""Unit tests for scripts/slice_actors.py — per-component actor slicing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import slice_actors
import yaml


def _write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data))


@pytest.fixture
def plugin_lib(tmp_path: Path) -> Path:
    proot = tmp_path / "plugin"
    lib = {
        "schema_version": 1,
        "access_zone_aliases": {
            "internet": ["internet-facing"],
            "client-device": ["browser"],
        },
        "component_always_relevant": {
            "auth-service": ["ACT-D-99"],
            "empty-type": None,
        },
    }
    _write_yaml(proot / "data" / "actors" / "default-library.yaml", lib)
    return proot


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def test_load_yaml_empty(tmp_path: Path):
    p = tmp_path / "e.yaml"
    p.write_text("")
    assert slice_actors._load_yaml(str(p)) == {}


def test_load_json_str():
    assert slice_actors._load_json_str('[{"a":1}]') == [{"a": 1}]


def test_sha256_file(tmp_path: Path):
    p = tmp_path / "f.txt"
    p.write_text("data")
    h = slice_actors._sha256_file(str(p))
    assert len(h) == 64


def test_load_component_always_relevant_missing(tmp_path: Path):
    assert slice_actors.load_component_always_relevant(str(tmp_path / "nope")) == {}


def test_load_component_always_relevant(plugin_lib: Path):
    m = slice_actors.load_component_always_relevant(str(plugin_lib))
    assert m["auth-service"] == ["ACT-D-99"]
    assert m["empty-type"] == []  # None normalized to empty list


def test_load_access_zone_aliases(plugin_lib: Path):
    aliases = slice_actors.load_access_zone_aliases(str(plugin_lib))
    assert aliases["internet-facing"] == "internet"
    assert aliases["internet"] == "internet"


def test_compute_fingerprint(tmp_path: Path):
    f1 = tmp_path / "a.json"
    f1.write_text("aaa")
    f2 = tmp_path / "b.json"
    f2.write_text("bbb")
    h = slice_actors.compute_fingerprint([str(f2), str(f1), str(tmp_path / "missing.json")])
    # order-independent: sorted internally
    assert h == slice_actors.compute_fingerprint([str(f1), str(f2)])


# ---------------------------------------------------------------------------
# actor_relevant
# ---------------------------------------------------------------------------
def test_actor_relevant_always_relevant():
    actor = {"id": "ACT-D-99", "access": []}
    comp = {"component_type": "auth-service", "deployment_zones": []}
    rel, reason = slice_actors.actor_relevant(actor, comp, {"ACT-D-99"})
    assert rel and "COMPONENT_ALWAYS_RELEVANT" in reason


def test_actor_relevant_zone_intersection():
    actor = {"id": "A", "access": ["internet", "dmz"]}
    comp = {"component_type": "web", "deployment_zones": ["dmz"]}
    rel, reason = slice_actors.actor_relevant(actor, comp, set())
    assert rel and "deployment_zones" in reason


def test_actor_relevant_none():
    actor = {"id": "A", "access": ["internal"]}
    comp = {"component_type": "web", "deployment_zones": ["dmz"]}
    rel, reason = slice_actors.actor_relevant(actor, comp, set())
    assert not rel and reason == ""


# ---------------------------------------------------------------------------
# slice_for_component
# ---------------------------------------------------------------------------
def test_slice_for_component_filters_inactive_and_builds():
    actors = [
        {
            "id": "A",
            "access": ["dmz"],
            "trust_positions": ["public-endpoint-reach"],
            "label": "la",
            "_provenance": {"active": True},
        },
        {"id": "B", "access": ["dmz"], "_provenance": {"active": False}},  # inactive -> skip
        {"id": "C", "access": ["internal"]},  # no access overlap, active defaults True
        {"id": "D", "access": [], "_provenance": {"proposed": True, "stale": True}},  # always-relevant
    ]
    comp = {"component_id": "c1", "component_type": "auth-service", "deployment_zones": ["dmz"]}
    always = {"auth-service": ["D"]}
    out = slice_actors.slice_for_component(comp, actors, always)
    ids = {a["id"] for a in out["relevant_actors"]}
    assert ids == {"A", "D"}
    assert out["component_id"] == "c1"
    assert out["actor_count"] == 2
    assert "A" in out["relevance_rationale"]
    a_entry = next(a for a in out["relevant_actors"] if a["id"] == "A")
    assert a_entry["trust_positions"] == ["public-endpoint-reach"]
    d_entry = next(a for a in out["relevant_actors"] if a["id"] == "D")
    assert d_entry["proposed"] is True and d_entry["stale"] is True
    assert d_entry["heatmap_slug"] == "internet-user"  # default


def test_slice_accepts_canonical_component_shape_and_normalises_zones():
    actors = [
        {"id": "A", "access": ["internet"], "_provenance": {"active": True}},
        {"id": "ACT-D-99", "access": [], "_provenance": {"active": True}},
    ]
    component = {
        "id": "auth-identity",
        "name": "Authentication Service",
        "deployment_zones": ["internet-facing"],
    }
    out = slice_actors.slice_for_component(
        component,
        actors,
        {"auth-service": ["ACT-D-99"]},
        {"internet-facing": "internet", "internet": "internet"},
    )
    assert out["component_id"] == "auth-identity"
    assert out["component_type"] == "auth-service"
    assert {a["id"] for a in out["relevant_actors"]} == {"A", "ACT-D-99"}


# ---------------------------------------------------------------------------
# CLI / main()
# ---------------------------------------------------------------------------
def _setup_resolved(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / ".actors-resolved.json").write_text(
        json.dumps(
            {
                "resolved_actors": [
                    {"id": "A", "label": "anon", "access": ["dmz"], "_provenance": {"active": True}},
                    {"id": "B", "label": "auth", "access": ["internal"], "_provenance": {"active": True}},
                ]
            }
        )
    )


def test_cli_main_success(run_plugin_script, plugin_lib: Path, tmp_path: Path):
    out = tmp_path / "out"
    _setup_resolved(out)
    repo = tmp_path / "repo"
    repo.mkdir()
    components = json.dumps(
        [
            {"component_id": "web", "component_type": "web", "deployment_zones": ["dmz"]},
            {"component_id": "db", "component_type": "db", "deployment_zones": ["internal"]},
        ]
    )
    res = run_plugin_script(
        "slice_actors.py",
        "--plugin-root",
        str(plugin_lib),
        "--repo-root",
        str(repo),
        "--output-dir",
        str(out),
        "--components",
        components,
        check=True,
    )
    assert res.returncode == 0
    web = json.loads((out / ".actors-for-web.json").read_text())
    assert web["actor_count"] == 1  # actor A (dmz)
    manifest = json.loads((out / ".actors-slice-manifest.json").read_text())
    assert len(manifest["component_slices"]) == 2
    assert manifest["slice_fingerprint"]


def test_cli_main_missing_resolved(run_plugin_script, plugin_lib: Path, tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    res = run_plugin_script(
        "slice_actors.py",
        "--plugin-root",
        str(plugin_lib),
        "--repo-root",
        str(repo),
        "--output-dir",
        str(out),
        "--components",
        "[]",
        check=False,
    )
    assert res.returncode == 1
    assert "not found" in res.stderr


def test_cli_main_bad_components_json(run_plugin_script, plugin_lib: Path, tmp_path: Path):
    out = tmp_path / "out"
    _setup_resolved(out)
    repo = tmp_path / "repo"
    repo.mkdir()
    res = run_plugin_script(
        "slice_actors.py",
        "--plugin-root",
        str(plugin_lib),
        "--repo-root",
        str(repo),
        "--output-dir",
        str(out),
        "--components",
        "{not json",
        check=False,
    )
    assert res.returncode == 1
    assert "invalid component input" in res.stderr


def test_cli_main_component_missing_id(run_plugin_script, plugin_lib: Path, tmp_path: Path):
    out = tmp_path / "out"
    _setup_resolved(out)
    repo = tmp_path / "repo"
    repo.mkdir()
    components = json.dumps([{"component_type": "web", "deployment_zones": ["dmz"]}])
    res = run_plugin_script(
        "slice_actors.py",
        "--plugin-root",
        str(plugin_lib),
        "--repo-root",
        str(repo),
        "--output-dir",
        str(out),
        "--components",
        components,
        check=True,
    )
    assert res.returncode == 0
    assert "missing id" in res.stderr
    manifest = json.loads((out / ".actors-slice-manifest.json").read_text())
    assert manifest["component_slices"] == []


def test_cli_components_file_uses_canonical_inventory(run_plugin_script, plugin_lib: Path, tmp_path: Path):
    out = tmp_path / "out"
    _setup_resolved(out)
    repo = tmp_path / "repo"
    repo.mkdir()
    components_file = tmp_path / ".components.json"
    components_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    {
                        "id": "public-api",
                        "name": "Public API",
                        "deployment_zones": ["internet-facing"],
                    }
                ],
            }
        )
    )
    res = run_plugin_script(
        "slice_actors.py",
        "--plugin-root",
        str(plugin_lib),
        "--repo-root",
        str(repo),
        "--output-dir",
        str(out),
        "--components-file",
        str(components_file),
        check=True,
    )
    assert res.returncode == 0
    actor_slice = json.loads((out / ".actors-for-public-api.json").read_text())
    assert actor_slice["component_id"] == "public-api"
    assert [a["id"] for a in actor_slice["relevant_actors"]] == []
