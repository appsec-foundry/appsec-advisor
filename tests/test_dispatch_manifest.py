"""Unit tests for the Full-M1 STRIDE dispatch manifest validator
(scripts/validate_dispatch_manifest.py) + its schema."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

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
    return {
        "schema_version": 1,
        "generated_at": "2026-06-04T00:00:00Z",
        "stride_profile": "full",
        "components": list(comps) or [_component()],
    }


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
    cj = {"schema_version": 1, "components": [{"id": "backend-api", "name": "x"}, {"id": "frontend-spa", "name": "y"}]}
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
    (tmp_path / ".components.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    {
                        "id": "backend-api",
                        "name": "Backend",
                        "description": "d",
                        "paths": ["routes/**"],
                        "complexity": "complex",
                    },
                    {
                        "id": "frontend-spa",
                        "name": "SPA",
                        "description": "d",
                        "paths": ["app/**"],
                        "complexity": "simple",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".trust-boundaries.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "trust_boundaries": [
                    {
                        "id": "tb-1",
                        "name": "Public Internet",
                        "from": "external",
                        "to": "backend-api",
                        "crossing_enforcement": "None",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


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
    assert by_id["backend-api"]["max_turns"] == 31  # standard/complex
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
    comp = {"id": cid, "name": name or cid, "description": desc, "paths": [f"{cid}/**"], "tier": tier}
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
        _c("internal-worker", zones=["internal-network"]),  # internal-only → out at standard
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
        _c("backend-api", zones=["internet"]),  # exposed
        _c("ci-cd", zones=["ci-cd-runtime"]),  # NOT at quick
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
        _c("mystery", zones=[]),  # zones present elsewhere → migrated; this one unknown
    ]
    selected, _ = bm.select_stride_components(comps, "standard")
    assert "mystery" in {c["id"] for c in selected}
    # but excluded at quick (quick stays minimal)
    selected_q, _ = bm.select_stride_components(comps, "quick")
    assert "mystery" not in {c["id"] for c in selected_q}


def test_select_runtime_only_zone_is_exposure_unknown_not_internal():
    """A component tagged ONLY with a runtime/where-it-runs zone
    (``docker-container``) carries no reachability signal, so it must hit the
    exposure-unknown fail-safe (included at standard+), NOT be treated as
    internal-only and dropped. Regression for 2026-06-12: b2b-api — a
    JWT-protected /b2b/v2 REST API with a vm.runInContext RCE, tagged only
    ``docker-container`` and not crown-jewel — was silently excluded at
    standard depth, leaving the whole component unanalyzed.
    """
    comps = [
        _c("backend-api", zones=["internet"]),
        _c("b2b-api", zones=["docker-container"]),  # runtime-only, not sensitive
        _c("internal-worker", zones=["internal-network"]),  # genuine internal → still out
    ]
    selected, report = bm.select_stride_components(comps, "standard")
    ids = {c["id"] for c in selected}
    assert "b2b-api" in ids, "runtime-only zone must not exclude a component at standard"
    assert "internal-worker" not in ids, "a genuine internal-network component is still excluded"
    reasons = {s["id"]: s["reasons"] for s in report["selected"]}
    assert "exposure-unknown (fail-safe inclusion)" in reasons["b2b-api"]
    # Still minimal at quick (fail-safe is standard+ only).
    selected_q, _ = bm.select_stride_components(comps, "quick")
    assert "b2b-api" not in {c["id"] for c in selected_q}


def test_select_ceiling_sheds_only_internal_never_earned():
    """The ceiling may shed ONLY genuinely-internal components — never anything
    earned by exposure/ci-cd/crown-jewel/auth/frontend. Live-run regression
    (2026-06-07): a ceiling that dropped ci-cd recreated the exact blind spot
    the redesign removes; ci-cd must survive and the ceiling must lift instead."""
    comps = [
        _c("auth-service", zones=["internet"], name="auth"),  # earned (auth/exposed)
        _c("frontend-spa", zones=["internet"], tier="client"),  # earned (frontend)
        _c("api-a", zones=["internet"]),  # earned (exposed)
        _c("api-b", zones=["internet"]),  # earned (exposed)
        _c("ci-cd", zones=["ci-cd-runtime"]),  # earned (ci-cd) — must NOT drop
        _c("internal", zones=["internal-network"]),  # internal-only — droppable
    ]
    selected, report = bm.select_stride_components(comps, "thorough", ceiling=3)
    ids = {c["id"] for c in selected}
    # every earned component survives despite ceiling=3 → lift
    assert {"auth-service", "frontend-spa", "api-a", "api-b", "ci-cd"} <= ids
    assert report["lifted"] is True
    # ONLY the genuinely-internal component is shed, and visibly
    assert "internal" not in ids
    assert any(e["id"] == "internal" and e["reason"] == "ceiling-overflow" for e in report["excluded"])


def test_select_ceiling_never_drops_crownjewel_silently():
    """A crown-jewel datastore over the ceiling lifts, not drops."""
    comps = [_c(f"api-{i}", zones=["internet"]) for i in range(4)]
    comps.append(_c("creds", zones=["internal-network"], sensitive=True))  # crown, not exposed
    selected, report = bm.select_stride_components(comps, "standard", ceiling=3)
    ids = {c["id"] for c in selected}
    assert "creds" in ids  # crown-jewel never shed
    assert report["lifted"] is True
    assert not [e for e in report["excluded"] if e["reason"] == "ceiling-overflow"]


def test_builder_carries_zones_and_crownjewel_through(tmp_path):
    (tmp_path / ".components.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    _c("backend-api", zones=["internet"], sensitive=True),
                    _c("internal-worker", zones=["internal-network"]),
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    by_id = {c["component_id"]: c for c in manifest["components"]}
    # internal-only excluded at standard via criteria
    assert set(by_id) == {"backend-api"}
    assert by_id["backend-api"]["deployment_zones"] == ["internet"]
    assert by_id["backend-api"]["handles_sensitive_data"] is True
    # selection report written
    sel = json.loads((tmp_path / ".stride-selection.json").read_text())
    assert sel["mode"] == "criteria"


# ---------------------------------------------------------------------------
# Enumeration-completeness reconciliation (reconcile_inventory + detectors)
# Restores security-relevant deployable units Phase-3 folded into a coarser
# parent (the 8→5 component-count regression).
# ---------------------------------------------------------------------------


def _fake_repo(tmp_path: Path, *, cicd=True, socketio=True, auth=True) -> Path:
    repo = tmp_path / "repo"
    (repo / "routes").mkdir(parents=True)
    (repo / "lib").mkdir(parents=True)
    if cicd:
        wf = repo / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("name: ci\n", encoding="utf-8")
        (wf / "release.yml").write_text("name: release\n", encoding="utf-8")
    deps = {}
    if socketio:
        deps["socket.io"] = "^3.1.2"
        (repo / "lib" / "startup.ts").write_text("import { Server } from 'socket.io'\n", encoding="utf-8")
        (repo / "server.ts").write_text("const io = require('socket.io')\n", encoding="utf-8")
        (repo / "lib" / "insecurity.ts").write_text("// jwt helpers, no realtime\n", encoding="utf-8")
    (repo / "package.json").write_text(json.dumps({"dependencies": deps}), encoding="utf-8")
    if auth:
        (repo / "routes" / "login.ts").write_text("export function login(){}\n", encoding="utf-8")
        (repo / "routes" / "resetPassword.ts").write_text("// reset password handler\n", encoding="utf-8")
        if not socketio:
            (repo / "lib" / "insecurity.ts").write_text("// jwt helpers\n", encoding="utf-8")
    return repo


def _backend_only():
    # express-backend's DESCRIPTION mentions auth/uploads but its id/name do not —
    # the exact juice-shop shape where _is_auth never fires on the monolith.
    return [
        {
            "id": "express-backend",
            "name": "Express Backend API",
            "description": "monolith handling all endpoints, authentication, and uploads",
            "paths": ["routes/**", "lib/**", "server.ts"],
            "tier": "application",
            "deployment_zones": ["internet", "dmz"],
            "handles_sensitive_data": True,
        },
        {
            "id": "angular-spa",
            "name": "Angular SPA",
            "description": "frontend",
            "paths": ["frontend/**"],
            "tier": "client",
            "deployment_zones": ["client-device"],
        },
    ]


def test_reconcile_injects_folded_security_units(tmp_path):
    repo = _fake_repo(tmp_path)
    augmented, injected = bm.reconcile_inventory(_backend_only(), repo)
    assert {c["id"] for c in injected} == {"auth", "ci-cd-pipeline", "realtime-channel"}
    for c in injected:
        assert c["origin"] == "reconciliation"
        # all schema-required fields present
        assert c["id"] and c["name"] and c["description"] and c["paths"] and c["tier"]
    assert len(augmented) == len(_backend_only()) + 3


def test_reconcile_idempotent_when_role_present(tmp_path):
    repo = _fake_repo(tmp_path)
    comps = _backend_only() + [
        {"id": "auth-service", "name": "Auth Service", "description": "login", "paths": ["auth/**"], "tier": "application"},
        {"id": "pipeline", "name": "Build Pipeline", "description": "ci", "paths": [".github/**"], "tier": "application"},
        {"id": "ws-gateway", "name": "WebSocket Gateway", "description": "rt", "paths": ["ws/**"], "tier": "application"},
    ]
    augmented, injected = bm.reconcile_inventory(comps, repo)
    assert injected == []  # every role already carried by an enumerated component
    # re-running over already-augmented inventory is also a no-op
    _, injected2 = bm.reconcile_inventory(augmented, repo)
    assert injected2 == []


def test_reconcile_no_evidence_no_injection(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    _, injected = bm.reconcile_inventory(_backend_only(), empty)
    assert injected == []


def test_reconcile_partial_evidence_only_cicd(tmp_path):
    repo = _fake_repo(tmp_path, socketio=False, auth=False)
    _, injected = bm.reconcile_inventory(_backend_only(), repo)
    assert {c["id"] for c in injected} == {"ci-cd-pipeline"}


def test_reconciled_units_selected_at_standard(tmp_path):
    repo = _fake_repo(tmp_path)
    augmented, _ = bm.reconcile_inventory(_backend_only(), repo)
    selected, report = bm.select_stride_components(augmented, "standard")
    sel_ids = {c["id"] for c in selected}
    assert {"auth", "ci-cd-pipeline", "realtime-channel"} <= sel_ids
    assert report["excluded"] == []  # each earned a positive criterion


def test_auth_gets_priority_zero_floor(tmp_path):
    # The dead-_is_auth-floor fix: a folded monolith yields no auth role, but the
    # injected auth component restores the priority-0 never-drop invariant.
    repo = _fake_repo(tmp_path)
    augmented, _ = bm.reconcile_inventory(_backend_only(), repo)
    auth = next(c for c in augmented if c["id"] == "auth")
    assert bm._is_auth(auth) is True
    assert bm._priority(auth) == 0


def test_realtime_paths_are_precise_not_broad(tmp_path):
    repo = _fake_repo(tmp_path)
    rt = bm._detect_realtime(repo)
    assert rt is not None
    assert "lib/startup.ts" in rt["paths"]
    assert "server.ts" in rt["paths"]
    assert "lib/insecurity.ts" not in rt["paths"]  # no socket.io reference
    assert "lib/**" not in rt["paths"]


def test_build_persists_augmented_inventory(tmp_path):
    repo = _fake_repo(tmp_path)
    od = repo / "docs" / "security"  # conventional layout so _guess_repo_root finds repo
    od.mkdir(parents=True)
    (od / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": _backend_only()}), encoding="utf-8"
    )
    manifest = bm.build(od, "standard", {}, PLUGIN_ROOT)
    mids = {c["component_id"] for c in manifest["components"]}
    assert {"auth", "ci-cd-pipeline", "realtime-channel"} <= mids
    persisted = json.loads((od / ".components.json").read_text())
    pids = {c["id"] for c in persisted["components"]}
    assert {"auth", "ci-cd-pipeline", "realtime-channel"} <= pids
    # injected components carry the audit marker on disk
    assert any(c.get("origin") == "reconciliation" for c in persisted["components"])


def test_is_realtime_no_substring_false_positive():
    # "sse" must not match inside "asset service" (the file-upload component);
    # else realtime injection is wrongly suppressed as already-covered.
    fileup = {"id": "file-upload-service", "name": "File Upload and Static Asset Service", "description": "uploads"}
    assert bm._is_realtime(fileup) is False
    classes = {"id": "classes", "name": "Classroom Service", "description": "x"}
    assert bm._is_realtime(classes) is False
    # genuine realtime roles still match
    for name in ("WebSocket Gateway", "Socket.IO Channel", "Realtime Hub", "SSE Stream"):
        assert bm._is_realtime({"id": "x", "name": name, "description": ""}) is True


def test_realtime_injected_when_upload_component_present(tmp_path):
    # Regression for the juice-shop shape: a file-upload component must not
    # absorb the realtime role and block injection.
    repo = _fake_repo(tmp_path)
    comps = _backend_only() + [
        {"id": "file-upload-service", "name": "File Upload and Static Asset Service",
         "description": "uploads", "paths": ["routes/fileUpload.ts"], "tier": "application",
         "deployment_zones": ["internet", "dmz"], "handles_sensitive_data": True},
    ]
    _, injected = bm.reconcile_inventory(comps, repo)
    assert "realtime-channel" in {c["id"] for c in injected}


# ---------------------------------------------------------------------------
# Selection-pipeline coverage hardening: the contract handoff + predicate
# branches that the isolated unit/fixture tests do not exercise.
# ---------------------------------------------------------------------------


def test_selection_report_flows_into_scope_rendering():
    """Contract integration: the REAL select_stride_components report →
    build_component_selection → gen_system_overview. Catches reason-string
    drift between the selector and the §1 Scope renderer that the isolated
    tests (hand-built `cs` fixtures) cannot."""
    import importlib.util as _ilu

    def _load(name):
        s = _ilu.spec_from_file_location(name, PLUGIN_ROOT / "scripts" / f"{name}.py")
        m = _ilu.module_from_spec(s)
        s.loader.exec_module(m)
        return m

    btm = _load("build_threat_model_yaml")
    pf = _load("pregenerate_fragments")

    comps = [
        _c("express-backend", zones=["internet", "dmz"], sensitive=True, name="Express Backend"),
        _c("angular-spa", zones=["client-device"], tier="client", name="Angular SPA"),
        _c("user-store", zones=["internal-network"], tier="data", sensitive=True, name="User Store"),
        _c("ci-cd", zones=["ci-cd-runtime"], name="CI/CD Pipeline"),
        _c("internal-worker", zones=["internal-network"], name="Internal Worker"),
    ]
    selected, report = bm.select_stride_components(comps, "standard")
    assert {c["id"] for c in selected} == {"express-backend", "angular-spa", "user-store", "ci-cd"}
    assert {e["id"] for e in report["excluded"]} == {"internal-worker"}

    # real selector report → §1 scope data model → rendered markdown
    cs = btm.build_component_selection(report, comps)
    assert cs is not None and cs["analyzed"] == 4 and cs["total"] == 5
    out = pf.gen_system_overview({"meta": {"project": {"name": "Acme"}, "component_selection": cs}, "components": comps})

    assert "**4 of 5**" in out
    assert "Internal Worker" in out  # out-of-scope component is named
    assert "not individually analyzed" in out
    # the selector's OWN reason strings survive the handoff into the criteria line
    crit_line = next(line for line in out.splitlines() if "Selection criteria" in line)
    assert "crown-jewel" in crit_line
    assert "internet-exposed" in crit_line
    assert "ci-cd" in crit_line


def test_selection_reasons_cover_each_branch():
    """Every _selection_reasons branch emits its documented string — the
    contract the §1 scope 'Selection criteria' clause depends on."""
    r = bm._selection_reasons
    assert "auth (M3.4 mandatory)" in r(_c("a", zones=["internal-network"], name="Auth Service"), "standard")
    assert "frontend attack surface (mandatory)" in r(_c("f", tier="client"), "standard")
    assert "internet-exposed (internet)" in r(_c("b", zones=["internet"]), "standard")
    assert "ci-cd / deployment (supply-chain boundary)" in r(_c("c", zones=["ci-cd-runtime"]), "standard")
    assert "crown-jewel (credentials/PII/payment/secrets)" in r(_c("d", zones=["internal-network"], sensitive=True), "standard")
    assert "transitively reachable (thorough)" in r(_c("w", zones=["internal-network"]), "thorough")
    assert "exposure-unknown (fail-safe inclusion)" in r(_c("u", zones=["docker-container"]), "standard")
    # ci-cd / crown-jewel are silent at quick (criteria not active) → no reason
    assert r(_c("c", zones=["ci-cd-runtime"]), "quick") == []


def test_mobile_device_zone_is_exposed_at_quick():
    comps = [_c("mobile-api", zones=["mobile-device"])]
    selected, _ = bm.select_stride_components(comps, "quick")  # quick = role-floor + exposed only
    assert {c["id"] for c in selected} == {"mobile-api"}
    assert bm._is_exposed(comps[0]) is True


def test_priority_ladder_full_ordering():
    assert bm._priority(_c("a", zones=["internal-network"], name="Auth")) == 0  # auth
    assert bm._priority(_c("f", tier="client")) == 1  # frontend
    assert bm._priority(_c("e", zones=["internet"])) == 2  # exposed
    assert bm._priority(_c("c", zones=["internal-network"], sensitive=True)) == 3  # crown-jewel
    assert bm._priority(_c("p", zones=["ci-cd-runtime"])) == 4  # ci-cd
    assert bm._priority(_c("w", zones=["internal-network"])) == 5  # internal-only


def test_excluded_reason_is_depth_specific():
    comps = [
        _c("backend", zones=["internet"]),
        _c("ci-cd", zones=["ci-cd-runtime"]),
        _c("worker", zones=["internal-network"]),
    ]
    _, rq = bm.select_stride_components(comps, "quick")
    rq_exc = {e["id"]: e["reason"] for e in rq["excluded"]}
    assert rq_exc["ci-cd"] == "out-of-scope at depth=quick"
    assert rq_exc["worker"] == "out-of-scope at depth=quick"
    _, rs = bm.select_stride_components(comps, "standard")
    rs_exc = {e["id"]: e["reason"] for e in rs["excluded"]}
    assert rs_exc == {"worker": "out-of-scope at depth=standard"}  # ci-cd now in-scope


# ---------------------------------------------------------------------------
# Console rendering of the selection (format_selection_console)
# ---------------------------------------------------------------------------


def test_format_selection_console_criteria_lists_analyzed_and_skipped():
    comps = [
        _c("backend-api", zones=["internet"]),
        _c("worker", zones=["internal-network"]),  # out-of-scope at standard
    ]
    _, report = bm.select_stride_components(comps, "standard")
    out = bm.format_selection_console(report)
    assert "depth=standard, mode=criteria" in out
    assert "ANALYZED (1):" in out
    assert "backend-api — internet-exposed (internet)" in out
    assert "SKIPPED (1):" in out
    assert "worker — out-of-scope at depth=standard" in out


def test_format_selection_console_passthrough_shape():
    comps = [_c("a"), _c("b")]  # no zones → passthrough
    _, report = bm.select_stride_components(comps, "standard")
    out = bm.format_selection_console(report)
    assert "mode=passthrough" in out
    assert "ANALYZED (2): a, b" in out
    assert "SKIPPED (0):" in out
