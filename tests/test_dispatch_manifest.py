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


# ---------------------------------------------------------------------------
# Criteria-derived component selection (select_stride_components)
# ---------------------------------------------------------------------------


def _c(cid, *, zones=None, tier="application", sensitive=False, name=None, desc=""):
    comp = {"id": cid, "name": name or cid, "description": desc,
            "paths": [f"{cid}/**"], "tier": tier}
    if zones is not None:
        comp["deployment_zones"] = zones
    if sensitive:
        comp["handles_sensitive_data"] = True
    return comp


def test_select_passthrough_when_no_zones():
    """Un-migrated .components.json (no zones) → all pass through (today's behavior)."""
    comps = [_c("backend-api"), _c("worker"), _c("data-layer", tier="data")]
    selected, report = bm.select_stride_components(comps, "standard")
    assert {c["id"] for c in selected} == {"backend-api", "worker", "data-layer"}
    assert report["mode"] == "passthrough"


def test_select_standard_includes_exposed_cicd_crownjewel_excludes_internal():
    comps = [
        _c("backend-api", zones=["internet"]),
        _c("ci-cd", zones=["ci-cd-runtime"]),
        _c("user-store", zones=["prod-write-db"], tier="data", sensitive=True),
        _c("internal-worker", zones=["internal-network"]),   # internal-only → out at standard
    ]
    selected, report = bm.select_stride_components(comps, "standard")
    assert {c["id"] for c in selected} == {"backend-api", "ci-cd", "user-store"}
    assert report["mode"] == "criteria"
    assert {e["id"] for e in report["excluded"]} == {"internal-worker"}


def test_select_thorough_includes_internal_only():
    comps = [
        _c("backend-api", zones=["internet"]),
        _c("internal-worker", zones=["internal-network"]),
    ]
    selected, _ = bm.select_stride_components(comps, "thorough")
    assert {c["id"] for c in selected} == {"backend-api", "internal-worker"}


def test_select_quick_is_role_floor_plus_exposed_only():
    comps = [
        _c("frontend-spa", zones=["client-device"], tier="client"),  # role-floor
        _c("backend-api", zones=["internet"]),                        # exposed
        _c("ci-cd", zones=["ci-cd-runtime"]),                         # NOT at quick
        _c("user-store", zones=["prod-write-db"], tier="data", sensitive=True),  # NOT at quick
    ]
    selected, _ = bm.select_stride_components(comps, "quick")
    assert {c["id"] for c in selected} == {"frontend-spa", "backend-api"}


def test_select_auth_and_frontend_always_kept_even_without_exposed_zone():
    """M3.4 + frontend invariants: auth/frontend kept at every depth, no exposed zone needed."""
    comps = [
        _c("auth-service", zones=["internal-network"], name="Authentication & Session Store"),
        _c("frontend-spa", zones=["internal-network"], tier="client"),
        _c("plain-internal", zones=["internal-network"]),
    ]
    for depth in ("quick", "standard"):
        selected, _ = bm.select_stride_components(comps, depth)
        ids = {c["id"] for c in selected}
        assert "auth-service" in ids and "frontend-spa" in ids, depth
        assert "plain-internal" not in ids, depth


def test_select_exposure_unknown_failsafe_included_at_standard():
    """A migrated set with one un-tagged component → fail-safe inclusion at standard+."""
    comps = [
        _c("backend-api", zones=["internet"]),
        _c("mystery", zones=[]),   # zones present elsewhere → migrated; this one unknown
    ]
    selected, _ = bm.select_stride_components(comps, "standard")
    assert "mystery" in {c["id"] for c in selected}
    # but excluded at quick (quick stays minimal)
    selected_q, _ = bm.select_stride_components(comps, "quick")
    assert "mystery" not in {c["id"] for c in selected_q}


def test_select_ceiling_sheds_only_internal_never_earned():
    """The ceiling may shed ONLY genuinely-internal components — never anything
    earned by exposure/ci-cd/crown-jewel/auth/frontend. Live-run regression
    (2026-06-07): a ceiling that dropped ci-cd recreated the exact blind spot
    the redesign removes; ci-cd must survive and the ceiling must lift instead."""
    comps = [
        _c("auth-service", zones=["internet"], name="auth"),   # earned (auth/exposed)
        _c("frontend-spa", zones=["internet"], tier="client"), # earned (frontend)
        _c("api-a", zones=["internet"]),                       # earned (exposed)
        _c("api-b", zones=["internet"]),                       # earned (exposed)
        _c("ci-cd", zones=["ci-cd-runtime"]),                  # earned (ci-cd) — must NOT drop
        _c("internal", zones=["internal-network"]),            # internal-only — droppable
    ]
    selected, report = bm.select_stride_components(comps, "thorough", ceiling=3)
    ids = {c["id"] for c in selected}
    # every earned component survives despite ceiling=3 → lift
    assert {"auth-service", "frontend-spa", "api-a", "api-b", "ci-cd"} <= ids
    assert report["lifted"] is True
    # ONLY the genuinely-internal component is shed, and visibly
    assert "internal" not in ids
    assert any(e["id"] == "internal" and e["reason"] == "ceiling-overflow"
               for e in report["excluded"])


def test_select_ceiling_never_drops_crownjewel_silently():
    """A crown-jewel datastore over the ceiling lifts, not drops."""
    comps = [_c(f"api-{i}", zones=["internet"]) for i in range(4)]
    comps.append(_c("creds", zones=["internal-network"], sensitive=True))  # crown, not exposed
    selected, report = bm.select_stride_components(comps, "standard", ceiling=3)
    ids = {c["id"] for c in selected}
    assert "creds" in ids                  # crown-jewel never shed
    assert report["lifted"] is True
    assert not [e for e in report["excluded"] if e["reason"] == "ceiling-overflow"]


def test_builder_carries_zones_and_crownjewel_through(tmp_path):
    (tmp_path / ".components.json").write_text(json.dumps({
        "schema_version": 1,
        "components": [
            _c("backend-api", zones=["internet"], sensitive=True),
            _c("internal-worker", zones=["internal-network"]),
        ],
    }), encoding="utf-8")
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    by_id = {c["component_id"]: c for c in manifest["components"]}
    # internal-only excluded at standard via criteria
    assert set(by_id) == {"backend-api"}
    assert by_id["backend-api"]["deployment_zones"] == ["internet"]
    assert by_id["backend-api"]["handles_sensitive_data"] is True
    # selection report written
    sel = json.loads((tmp_path / ".stride-selection.json").read_text())
    assert sel["mode"] == "criteria"
