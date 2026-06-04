"""Unit tests for the Full-M1 STRIDE dispatch manifest validator
(scripts/validate_dispatch_manifest.py) + its schema."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "validate_dispatch_manifest.py"


def _load():
    spec = importlib.util.spec_from_file_location("validate_dispatch_manifest", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vm = _load()


def _component(cid="backend-api", **over):
    comp = {
        "component_id": cid,
        "component_name": "Express REST API Backend",
        "component_description": "Node/Express backend.",
        "component_paths": ["routes/**", "lib/**"],
        "component_complexity": "complex",
        "max_turns": 31,
        "estimated_threat_count": 8,
        "interfaces": "REST endpoints under /rest and /api",
        "trust_boundaries": "Public Internet -> backend-api",
        "controls": "JWT auth (unsafe), input validation (partial)",
        "index_paths": {
            "prior_findings": "none",
            "known_threats": "none",
            "cross_repo": "none",
            "requirements_violations": "none",
            "relevant_actors": "none",
        },
    }
    comp.update(over)
    return comp


def _manifest(*comps):
    return {"schema_version": 1, "generated_at": "2026-06-04T00:00:00Z",
            "stride_profile": "full", "components": list(comps) or [_component()]}


def _write(tmp_path: Path, manifest: dict, components_json: dict | None = None) -> Path:
    mpath = tmp_path / ".stride-dispatch-manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    if components_json is not None:
        (tmp_path / ".components.json").write_text(json.dumps(components_json), encoding="utf-8")
    return mpath


def test_valid_manifest_passes(tmp_path):
    cj = {"schema_version": 1, "components": [{"id": "backend-api", "name": "x"}]}
    mpath = _write(tmp_path, _manifest(), cj)
    ok, errors, _ = vm.validate(mpath, tmp_path)
    assert ok, errors


def test_missing_required_field_fails(tmp_path):
    comp = _component()
    del comp["max_turns"]
    mpath = _write(tmp_path, _manifest(comp))
    ok, errors, _ = vm.validate(mpath, tmp_path)
    assert not ok and any("max_turns" in e for e in errors)


def test_bad_complexity_enum_fails(tmp_path):
    mpath = _write(tmp_path, _manifest(_component(component_complexity="enormous")))
    ok, errors, _ = vm.validate(mpath, tmp_path)
    assert not ok


def test_missing_index_file_fails(tmp_path):
    comp = _component()
    comp["index_paths"]["prior_findings"] = ".dispatch-context/backend-api/prior-findings.json"
    mpath = _write(tmp_path, _manifest(comp))  # file does NOT exist
    ok, errors, _ = vm.validate(mpath, tmp_path)
    assert not ok and any("prior_findings" in e and "missing" in e for e in errors)


def test_existing_index_file_passes(tmp_path):
    dc = tmp_path / ".dispatch-context" / "backend-api"
    dc.mkdir(parents=True)
    (dc / "prior-findings.json").write_text("[]", encoding="utf-8")
    comp = _component()
    comp["index_paths"]["prior_findings"] = ".dispatch-context/backend-api/prior-findings.json"
    mpath = _write(tmp_path, _manifest(comp))
    ok, errors, _ = vm.validate(mpath, tmp_path)
    assert ok, errors


def test_phantom_component_fails(tmp_path):
    cj = {"schema_version": 1, "components": [{"id": "frontend-spa", "name": "x"}]}
    mpath = _write(tmp_path, _manifest(_component(cid="backend-api")), cj)
    ok, errors, _ = vm.validate(mpath, tmp_path)
    assert not ok and any("phantom" in e for e in errors)


def test_uncovered_component_warns_not_fails(tmp_path):
    cj = {"schema_version": 1, "components": [
        {"id": "backend-api", "name": "x"}, {"id": "frontend-spa", "name": "y"}]}
    mpath = _write(tmp_path, _manifest(_component(cid="backend-api")), cj)
    ok, errors, warnings = vm.validate(mpath, tmp_path)
    assert ok, errors
    assert any("frontend-spa" in w for w in warnings)


def test_empty_components_fails(tmp_path):
    m = _manifest()
    m["components"] = []
    mpath = _write(tmp_path, m)
    ok, errors, _ = vm.validate(mpath, tmp_path)
    assert not ok


def test_missing_manifest_file_fails(tmp_path):
    ok, errors, _ = vm.validate(tmp_path / "nope.json", tmp_path)
    assert not ok and any("not found" in e for e in errors)


# ---------------------------------------------------------------------------
# Builder (scripts/build_stride_dispatch_manifest.py)
# ---------------------------------------------------------------------------

BUILDER = PLUGIN_ROOT / "scripts" / "build_stride_dispatch_manifest.py"


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_stride_dispatch_manifest", BUILDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bm = _load_builder()


def _seed_output_dir(tmp_path: Path):
    (tmp_path / ".components.json").write_text(json.dumps({
        "schema_version": 1,
        "components": [
            {"id": "backend-api", "name": "Backend", "description": "d",
             "paths": ["routes/**"], "complexity": "complex"},
            {"id": "frontend-spa", "name": "SPA", "description": "d",
             "paths": ["app/**"], "complexity": "simple"},
        ],
    }), encoding="utf-8")
    (tmp_path / ".trust-boundaries.json").write_text(json.dumps({
        "schema_version": 1,
        "trust_boundaries": [
            {"id": "tb-1", "name": "Public Internet", "from": "external",
             "to": "backend-api", "crossing_enforcement": "None"},
        ],
    }), encoding="utf-8")


def test_builder_roundtrip_validates(tmp_path):
    _seed_output_dir(tmp_path)
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    mpath = tmp_path / ".stride-dispatch-manifest.json"
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    ok, errors, _ = vm.validate(mpath, tmp_path)
    assert ok, errors
    assert {c["component_id"] for c in manifest["components"]} == {"backend-api", "frontend-spa"}


def test_builder_max_turns_from_complexity(tmp_path):
    _seed_output_dir(tmp_path)
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    by_id = {c["component_id"]: c for c in manifest["components"]}
    assert by_id["backend-api"]["max_turns"] == 31   # standard/complex
    assert by_id["frontend-spa"]["max_turns"] == 15  # standard/simple


def test_builder_index_paths_none_when_absent_else_path(tmp_path):
    _seed_output_dir(tmp_path)
    dc = tmp_path / ".dispatch-context" / "backend-api"
    dc.mkdir(parents=True)
    (dc / "prior-findings.json").write_text("[]", encoding="utf-8")
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    be = next(c for c in manifest["components"] if c["component_id"] == "backend-api")
    assert be["index_paths"]["prior_findings"].endswith("prior-findings.json")
    assert be["index_paths"]["known_threats"] == "none"


def test_builder_merges_analyst_context(tmp_path):
    _seed_output_dir(tmp_path)
    ctx = {"backend-api": {"interfaces": "REST /api", "controls": "JWT (unsafe)"}}
    manifest = bm.build(tmp_path, "standard", ctx, PLUGIN_ROOT)
    be = next(c for c in manifest["components"] if c["component_id"] == "backend-api")
    assert be["interfaces"] == "REST /api" and be["controls"] == "JWT (unsafe)"


def test_builder_trust_boundary_scoped_per_component(tmp_path):
    _seed_output_dir(tmp_path)
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    by_id = {c["component_id"]: c for c in manifest["components"]}
    assert "Public Internet" in by_id["backend-api"]["trust_boundaries"]
    assert "No trust boundary" in by_id["frontend-spa"]["trust_boundaries"]


def test_depth_params_in_sync_with_resolve_config(tmp_path):
    """The builder's fallback max_turns table must match resolve_config.DEPTH_PARAMS."""
    import importlib.util as _ilu
    spec = _ilu.spec_from_file_location("resolve_config", PLUGIN_ROOT / "scripts" / "resolve_config.py")
    rc_mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(rc_mod)
    for depth, vals in bm._FALLBACK_DEPTH_PARAMS.items():
        for cx, turns in vals.items():
            assert rc_mod.DEPTH_PARAMS[depth][cx] == turns, f"{depth}/{cx} drift"
