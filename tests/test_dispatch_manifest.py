"""Unit tests for the Full-M1 STRIDE dispatch manifest validator
(scripts/validate_dispatch_manifest.py) + its schema."""

from __future__ import annotations

import builtins
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


def test_builder_rebuilds_actor_slices_from_canonical_components(tmp_path):
    (tmp_path / ".components.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    {
                        "id": "public-api",
                        "name": "Public API",
                        "description": "Internet-facing API.",
                        "paths": ["api/**"],
                        "tier": "application",
                        "complexity": "moderate",
                        "deployment_zones": ["internet-facing"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".actors-resolved.json").write_text(
        json.dumps(
            {
                "resolved_actors": [
                    {
                        "id": "ACT-D-01",
                        "label": "anonymous-internet-attacker",
                        "access": ["internet"],
                        "_provenance": {"active": True},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    component = manifest["components"][0]
    assert component["index_paths"]["relevant_actors"].endswith(".actors-for-public-api.json")
    actor_slice = json.loads((tmp_path / ".actors-for-public-api.json").read_text())
    assert actor_slice["component_type"] == "public-api"
    assert [actor["id"] for actor in actor_slice["relevant_actors"]] == ["ACT-D-01"]


def test_builder_stamps_stride_model(tmp_path):
    """The dispatched STRIDE reasoning model is recorded in the manifest
    (top-level + per-component) so config→execution is auditable from the
    intermediates — the .stride-<id>.json outputs carry no model field."""
    _seed_output_dir(tmp_path)
    (tmp_path / ".skill-config.json").write_text(json.dumps({"stride_model": "opus"}), encoding="utf-8")
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    assert manifest["stride_model"] == "opus"
    assert manifest["components"]
    assert all(c["model"] == "opus" for c in manifest["components"])


def test_builder_stride_model_unknown_when_config_absent(tmp_path):
    """No .skill-config.json → recorded as 'unknown' (never crashes, never
    silently claims a model)."""
    _seed_output_dir(tmp_path)
    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)
    assert manifest["stride_model"] == "unknown"
    assert all(c["model"] == "unknown" for c in manifest["components"])


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


def test_depth_params_falls_back_when_resolve_config_import_fails(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "resolve_config":
            raise RuntimeError("import failed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert bm._depth_params() == bm._FALLBACK_DEPTH_PARAMS


def test_trust_boundary_summary_skips_non_mapping_rows():
    boundaries = [
        "not-a-boundary",
        {
            "id": "tb-1",
            "from": "frontend",
            "to": "backend-api",
            "crossing_enforcement": "JWT",
        },
    ]

    assert bm._trust_boundaries_for("backend-api", boundaries) == "tb-1: JWT"


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


def test_internal_only_is_false_for_exposure_unknown():
    assert bm._is_internal_only(_c("mystery", zones=[])) is False


# ---------------------------------------------------------------------------
# Cat-13 known_llm_patterns supplement
# ---------------------------------------------------------------------------


def test_cat13_supplement_returns_empty_when_no_recon_patterns(tmp_path):
    """No .recon-patterns.json → supplement is empty string (graceful fallback)."""
    assert bm._cat13_supplement(tmp_path) == ""


def test_cat13_supplement_returns_file_line_entries(tmp_path):
    """When .recon-patterns.json has Cat-13 findings, returns subcategory: file:line pairs."""
    (tmp_path / ".recon-patterns.json").write_text(
        json.dumps(
            {
                "categories": {
                    "13": {
                        "findings": [
                            {"subcategory": "llm-sdk", "file": "package.json", "line": 94},
                            {"subcategory": "llm-invoke", "file": "routes/chat.ts", "line": 191},
                        ],
                        "count": 2,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = bm._cat13_supplement(tmp_path)
    assert "llm-sdk: package.json:94" in result
    assert "llm-invoke: routes/chat.ts:191" in result


def test_builder_supplements_sparse_llm_patterns_from_cat13(tmp_path):
    """LLM component with sparse analyst known_llm_patterns gets Cat-13 supplement appended."""
    (tmp_path / ".components.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    {
                        "id": "llm-chat-service",
                        "name": "LLM Chat Service",
                        "description": "Ollama proxy at POST /rest/chat",
                        "paths": ["routes/chat.ts"],
                        "complexity": "moderate",
                        "deployment_zones": ["internet"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".trust-boundaries.json").write_text(
        json.dumps({"schema_version": 1, "trust_boundaries": []}),
        encoding="utf-8",
    )
    (tmp_path / ".recon-patterns.json").write_text(
        json.dumps(
            {
                "categories": {
                    "13": {
                        "findings": [
                            {"subcategory": "llm-sdk", "file": "package.json", "line": 94},
                            {"subcategory": "llm-invoke", "file": "routes/chat.ts", "line": 191},
                        ],
                        "count": 2,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    # Analyst provides a sparse (< 120 char) known_llm_patterns
    ctx = {"llm-chat-service": {"known_llm_patterns": "chatbot POST /rest/chat"}}
    manifest = bm.build(tmp_path, "standard", ctx, PLUGIN_ROOT)
    comp = manifest["components"][0]
    klp = comp.get("known_llm_patterns", "")
    assert "chatbot POST /rest/chat" in klp, "analyst value should be retained"
    assert "llm-sdk: package.json:94" in klp, "Cat-13 supplement should be appended"
    assert "routes/chat.ts:191" in klp, "Cat-13 file:line should appear in supplement"


# ---------------------------------------------------------------------------
# Spec drift guards — renderer and OWASP LLM Top 10 contract text
# ---------------------------------------------------------------------------

AGENTS_DIR = PLUGIN_ROOT / "agents"


def test_renderer_ms_role_includes_ms_ai_exposure_in_author_list():
    """RENDER_ROLE=ms row in appsec-threat-renderer.md must include ms-ai-exposure.json.

    Guard against future edits that re-strip it from the allowlist — this was the
    root cause of the AI/LLM Exposure section missing from the Management Summary
    on the 2026-06-24 juice-shop standard run.
    """
    renderer_md = (AGENTS_DIR / "appsec-threat-renderer.md").read_text(encoding="utf-8")
    # The ms row must mention both the fragment name and the condition
    assert "ms-ai-exposure.json" in renderer_md, "ms-ai-exposure.json must appear in appsec-threat-renderer.md"
    # The fragment contract list must also include it (not just the table row)
    fragment_contract_idx = renderer_md.index("## Fragment Contract")
    fragment_contract_section = renderer_md[fragment_contract_idx : fragment_contract_idx + 2000]
    assert "ms-ai-exposure.json" in fragment_contract_section, (
        "ms-ai-exposure.json must be listed in the Fragment Contract section"
    )


def test_owasp_llm07_grep_covers_cookie_tool_call_leakage():
    """LLM07 grep in owasp-llm-top10.md must cover cookie/flag-gated tool call disclosure.

    The show_tool_calls cookie pattern (routes/chat.ts:225 in juice-shop) was missed
    because the old LLM07 grep only matched system.?prompt patterns — it did not cover
    an SSE gate controlled by a debug cookie. Fixed 2026-06-24.
    """
    top10_md = (AGENTS_DIR / "shared" / "owasp-llm-top10.md").read_text(encoding="utf-8")
    # Find the LLM07 row
    llm07_idx = top10_md.index("LLM07")
    llm07_row = top10_md[llm07_idx : llm07_idx + 600]
    assert "show_tool_calls" in llm07_row, (
        "LLM07 grep must include show_tool_calls to catch cookie-gated tool call disclosure"
    )


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


def test_select_quick_is_role_floor_plus_exposed_plus_exposure_unknown():
    comps = [
        _c("frontend-spa", zones=["client-device"], tier="client"),  # role-floor
        _c("backend-api", zones=["internet"]),  # exposed
        _c("mystery", zones=[]),  # exposure-unknown → fail-safe at EVERY depth
        _c("ci-cd", zones=["ci-cd-runtime"]),  # proven non-exposed reachability → NOT at quick
        _c("user-store", zones=["prod-write-db"], tier="data", sensitive=True),  # proven-internal → NOT at quick
    ]
    selected, _ = bm.select_stride_components(comps, "quick")
    # Quick = role-floor + directly-exposed + exposure-unknown; only PROVEN-internal
    # (ci-cd / crown-jewel with a reachability zone) is deferred to standard+.
    assert {c["id"] for c in selected} == {"frontend-spa", "backend-api", "mystery"}


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


def test_select_exposure_unknown_failsafe_included_at_every_depth():
    """A migrated set with one un-tagged component → fail-safe inclusion at EVERY
    depth, including quick. Exposure-unknown means the component could be an
    internet-facing door; the asymmetry of error costs (a missed exposed
    component is a whole-component blind spot) makes conservative inclusion the
    correct default even in the fast path. Only proven-internal is deferred."""
    comps = [
        _c("backend-api", zones=["internet"]),
        _c("mystery", zones=[]),  # zones present elsewhere → migrated; this one unknown
    ]
    for depth in ("quick", "standard", "thorough"):
        selected, _ = bm.select_stride_components(comps, depth)
        assert "mystery" in {c["id"] for c in selected}, depth


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
    # Runtime-only tagging is the COMMON outcome in containerised repos, so the
    # b2b-api RCE class must also be caught in quick; only proven-internal is out.
    selected_q, report_q = bm.select_stride_components(comps, "quick")
    ids_q = {c["id"] for c in selected_q}
    assert "b2b-api" in ids_q, "runtime-only / exposure-unknown must be in scope at quick too"
    assert "internal-worker" not in ids_q, "a genuine internal-network component is still excluded at quick"
    reasons_q = {s["id"]: s["reasons"] for s in report_q["selected"]}
    assert "exposure-unknown (fail-safe inclusion)" in reasons_q["b2b-api"]


def test_select_offvocab_zone_is_exposure_unknown_not_internal():
    """A component tagged with an off-vocabulary zone the analyst invented
    (``application-zone`` — not in EXPOSED/CICD/INTERNAL/RUNTIME vocab) carries no
    recognised reachability signal, so it must hit the exposure-unknown fail-safe
    (included at standard+), NOT be mis-read as proven-internal and dropped.
    Regression for 2026-07-23 spring-app: the analyst emitted ``application-zone``
    / ``data-zone`` / ``build-zone``, none of which matched any zone set, so the
    entire zonal exposure/ci-cd classification was silently inert and an off-vocab
    component was treated as proven-internal."""
    comps = [
        _c("backend-api", zones=["internet"]),
        _c("mystery-svc", zones=["application-zone"]),  # off-vocab, not sensitive
        _c("internal-worker", zones=["internal-network"]),  # genuine internal → still out
    ]
    selected, report = bm.select_stride_components(comps, "standard")
    ids = {c["id"] for c in selected}
    assert "mystery-svc" in ids, "off-vocabulary zone must fail-safe to inclusion at standard"
    assert "internal-worker" not in ids, "genuine internal-network zone still shed at standard"
    assert bm._is_internal_only(_c("mystery-svc", zones=["application-zone"])) is False
    reasons = {s["id"]: s["reasons"] for s in report["selected"]}
    assert "exposure-unknown (fail-safe inclusion)" in reasons["mystery-svc"]


def test_offvocab_zones_are_reported_as_drift():
    """Off-vocabulary deployment_zones are surfaced by ``_unknown_zone_tokens`` (not
    silently accepted) so the upstream recon/analyst output gets corrected. Known
    canonical and runtime-only tokens are NOT flagged."""
    assert bm._unknown_zone_tokens(_c("x", zones=["application-zone", "data-zone"])) == {
        "application-zone",
        "data-zone",
    }
    assert bm._unknown_zone_tokens(_c("x", zones=["internet", "internal-network"])) == set()
    assert bm._unknown_zone_tokens(_c("x", zones=["docker-container"])) == set()


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


def test_fifty_exposed_services_lift_ceiling_without_coverage_loss():
    """A large real microservice estate is not truncated to the safety ceiling."""
    components = [_c(f"public-service-{index:02d}", zones=["internet"]) for index in range(1, 51)]

    selected, report = bm.select_stride_components(components, "standard", ceiling=10)

    assert [component["id"] for component in selected] == [component["id"] for component in components]
    assert report["lifted"] is True
    assert report["excluded"] == []


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


def test_builder_normalizes_contextual_fields(tmp_path):
    (tmp_path / ".components.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    _c("api", name="API"),
                    _c("worker", name="Worker"),
                    _c("jobs", name="Jobs"),
                    _c("ingest", name="Ingest"),
                    _c("batch", name="Batch"),
                ],
            }
        ),
        encoding="utf-8",
    )
    ctx = {
        "api": {"controls": {"jwt": "partial", "csrf": "missing"}, "estimated_threat_count": "high"},
        "worker": {"estimated_threat_count": "7"},
        "jobs": {"estimated_threat_count": ["bad"]},
        "ingest": {"estimated_threat_count": 5},
        "batch": {"estimated_threat_count": "many"},
    }

    manifest = bm.build(tmp_path, "standard", ctx, PLUGIN_ROOT)

    by_id = {c["component_id"]: c for c in manifest["components"]}
    assert by_id["api"]["controls"] == "jwt: partial; csrf: missing"
    assert by_id["api"]["estimated_threat_count"] == 12
    assert by_id["worker"]["estimated_threat_count"] == 7
    assert by_id["jobs"]["estimated_threat_count"] == 3
    assert by_id["ingest"]["estimated_threat_count"] == 5
    assert by_id["batch"]["estimated_threat_count"] == 3


def test_builder_handles_non_list_components_payload(tmp_path):
    (tmp_path / ".components.json").write_text(json.dumps({"components": "not-a-list"}), encoding="utf-8")

    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)

    assert manifest["components"] == []


def test_builder_skips_malformed_selected_component_rows(tmp_path, monkeypatch):
    (tmp_path / ".components.json").write_text(json.dumps({"components": []}), encoding="utf-8")

    def fake_select(_components, _depth, _ceiling=None):
        return (
            [
                "not-a-component",
                {"name": "missing id"},
                {"id": "ok", "name": "OK", "description": "d", "paths": ["ok/**"], "complexity": "simple"},
            ],
            {"mode": "criteria", "depth": "standard", "selected": [], "excluded": [], "lifted": False},
        )

    monkeypatch.setattr(bm, "select_stride_components", fake_select)

    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)

    assert [c["component_id"] for c in manifest["components"]] == ["ok"]


# ---------------------------------------------------------------------------
# Enumeration-completeness reconciliation (reconcile_inventory + detectors)
# Restores security-relevant deployable units Phase-3 folded into a coarser
# parent (the 8→5 component-count regression).
# ---------------------------------------------------------------------------


def _fake_repo(tmp_path: Path, *, cicd=True, socketio=True, auth=True, web3=False) -> Path:
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
    if web3:
        deps["ethers"] = "^6.16.0"
        # checkKeys.ts has no web3 token in its STEM — it is captured only by
        # the content scan (the BIP-39 mnemonic), the exact juice-shop shape.
        (repo / "routes" / "checkKeys.ts").write_text(
            "// validates a BIP-39 mnemonic against a hardcoded key\n", encoding="utf-8"
        )
        (repo / "routes" / "nftMint.ts").write_text(
            "import { ethers } from 'ethers'\n// NFT mint listener\n", encoding="utf-8"
        )
        # a shared lib mentioning web3 must NOT be claimed by web3-nft
        (repo / "lib" / "insecurity.ts").write_text("// jwt + a web3 helper line\n", encoding="utf-8")
    (repo / "package.json").write_text(json.dumps({"dependencies": deps}), encoding="utf-8")
    if auth:
        (repo / "routes" / "login.ts").write_text("export function login(){}\n", encoding="utf-8")
        (repo / "routes" / "resetPassword.ts").write_text("// reset password handler\n", encoding="utf-8")
        if not socketio:
            (repo / "lib" / "insecurity.ts").write_text("// jwt helpers\n", encoding="utf-8")
    return repo


def test_guess_repo_root_falls_back_to_output_dir(tmp_path, monkeypatch):
    out = tmp_path / "standalone-output"
    out.mkdir()
    monkeypatch.setattr(Path, "exists", lambda _self: False)
    monkeypatch.setattr(Path, "is_file", lambda _self: False)

    assert bm._guess_repo_root(out) == out.resolve()


def test_glob_files_skips_glob_errors(tmp_path, monkeypatch):
    def fail_glob(_self, _pattern):
        raise OSError("glob failed")

    monkeypatch.setattr(Path, "glob", fail_glob)

    assert bm._glob_files(tmp_path, ["*.yml"]) == []


def test_package_deps_invalid_json_returns_empty(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text("{", encoding="utf-8")

    assert bm._package_deps(repo) == {}


def test_grep_paths_skips_unreadable_candidate(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "server.ts"
    target.write_text("socket.io", encoding="utf-8")

    def fail_read_text(self, *args, **kwargs):
        if self == target:
            raise OSError("unreadable")
        return original_read_text(self, *args, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fail_read_text)

    assert bm._grep_paths(repo, "server.ts", "socket.io") == []


def test_grep_paths_returns_empty_when_walk_fails(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    source = repo / "src"
    source.mkdir(parents=True)

    def fail_rglob(_self, _pattern):
        raise OSError("walk failed")

    monkeypatch.setattr(Path, "rglob", fail_rglob)

    assert bm._grep_paths(repo, "src", "socket.io") == []


def test_detect_auth_skips_scan_dir_errors(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "routes").mkdir(parents=True)

    def fail_rglob(_self, _pattern):
        raise OSError("scan failed")

    monkeypatch.setattr(Path, "rglob", fail_rglob)

    assert bm._detect_auth(repo) is None


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
        {
            "id": "auth-service",
            "name": "Auth Service",
            "description": "login",
            "paths": ["auth/**"],
            "tier": "application",
        },
        {
            "id": "pipeline",
            "name": "Build Pipeline",
            "description": "ci",
            "paths": [".github/**"],
            "tier": "application",
        },
        {
            "id": "ws-gateway",
            "name": "WebSocket Gateway",
            "description": "rt",
            "paths": ["ws/**"],
            "tier": "application",
        },
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


# --- web3/wallet/NFT reconciliation (2026-06-21 juice-shop: standard folded the
#     whole /rest/web3/ surface into backend-api and missed the Critical
#     hardcoded BIP-39 mnemonic; thorough carved out web3-nft and found it) ----


def test_reconcile_injects_web3_when_folded(tmp_path):
    repo = _fake_repo(tmp_path, web3=True)
    _, injected = bm.reconcile_inventory(_backend_only(), repo)
    web3 = next((c for c in injected if c["id"] == "web3-nft"), None)
    assert web3 is not None, "web3 surface evidenced but not injected"
    assert web3["origin"] == "reconciliation"
    assert web3["handles_sensitive_data"] is True
    assert "internet" in web3["deployment_zones"]
    # content-captured handler (no web3 token in its stem) is included…
    assert any("checkKeys" in p for p in web3["paths"])
    # …but the shared lib mentioning web3 is NOT claimed by web3-nft
    assert not any("insecurity" in p for p in web3["paths"])


def test_web3_injected_component_is_selected_at_standard(tmp_path):
    repo = _fake_repo(tmp_path, web3=True)
    augmented, _ = bm.reconcile_inventory(_backend_only(), repo)
    selected, _ = bm.select_stride_components(augmented, "standard")
    assert any(c["id"] == "web3-nft" for c in selected), (
        "injected web3-nft must be selected at standard (internet-exposed + sensitive)"
    )


def test_web3_idempotent_when_role_already_enumerated(tmp_path):
    repo = _fake_repo(tmp_path, web3=True)
    comps = _backend_only() + [
        {
            "id": "web3-nft",
            "name": "Web3 NFT Service",
            "description": "wallet + nft",
            "paths": ["routes/web3*.ts"],
            "tier": "application",
        }
    ]
    _, injected = bm.reconcile_inventory(comps, repo)
    assert not any(c["id"] == "web3-nft" for c in injected)


def test_detect_web3_no_evidence_returns_none(tmp_path):
    # repo with auth/cicd/socketio but no web3 dep and no web3 content.
    repo = _fake_repo(tmp_path, web3=False)
    assert bm._detect_web3(repo) is None


def test_detect_cicd_paths_cover_config_scan_surface(tmp_path):
    # Regression (2026-06-16): config-scan findings are bound to
    # component_id="ci-cd-pipeline" (merge_threats), but the component's paths
    # only globbed .github/workflows/**, so Dockerfile / package*.json /
    # dependabot evidence tripped the validate_intermediate path-glob advisory
    # with no component to reclassify to. The ci-cd-pipeline component (the
    # supply-chain boundary) must glob the full config-scan file surface.
    repo = _fake_repo(tmp_path)
    (repo / "Dockerfile").write_text("FROM node:18\n", encoding="utf-8")
    comp = bm._detect_cicd(repo)
    assert comp is not None
    paths = comp["paths"]
    # The actual files the config/IaC scanner reports against:
    for needed in ("Dockerfile", "package.json", "package-lock.json", ".github/dependabot.yml"):
        assert needed in paths, f"{needed!r} missing from ci-cd-pipeline paths: {paths}"
    # Detected workflow files are still represented.
    assert ".github/workflows/**" in paths


def test_detect_cicd_config_scan_evidence_matches_globs(tmp_path):
    # Verify the broadened globs actually MATCH the config-scan evidence files
    # under the same fnmatch+prefix semantics validate_intermediate uses, so the
    # cross-component advisory no longer fires for these findings.
    import fnmatch

    repo = _fake_repo(tmp_path)
    comp = bm._detect_cicd(repo)
    globs = comp["paths"]

    def _matches(f: str) -> bool:
        return any(fnmatch.fnmatch(f, g) or f.startswith(g.rstrip("*").rstrip("/")) for g in globs)

    for evidence_file in (
        "Dockerfile",
        "package.json",
        "package-lock.json",
        ".github/dependabot.yml",
        ".github/workflows/ci.yml",
    ):
        assert _matches(evidence_file), f"{evidence_file!r} not matched by {globs}"


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


def test_build_ignores_audit_write_failures(tmp_path, monkeypatch, capsys):
    (tmp_path / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [_c("api")]}),
        encoding="utf-8",
    )
    injected = {
        "id": "auth",
        "name": "Authentication",
        "description": "d",
        "paths": ["routes/login.ts"],
        "tier": "application",
        "deployment_zones": ["internet"],
    }

    def fake_reconcile(components, _repo_root):
        return components + [injected], [injected]

    def fail_write_text(_self, *_args, **_kwargs):
        raise OSError("cannot write")

    monkeypatch.setattr(bm, "reconcile_inventory", fake_reconcile)
    monkeypatch.setattr(Path, "write_text", fail_write_text)

    manifest = bm.build(tmp_path, "standard", {}, PLUGIN_ROOT)

    assert {c["component_id"] for c in manifest["components"]} == {"api", "auth"}
    assert "RECONCILE: injected auth" in capsys.readouterr().err


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
        {
            "id": "file-upload-service",
            "name": "File Upload and Static Asset Service",
            "description": "uploads",
            "paths": ["routes/fileUpload.ts"],
            "tier": "application",
            "deployment_zones": ["internet", "dmz"],
            "handles_sensitive_data": True,
        },
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
    out = pf.gen_system_overview(
        {"meta": {"project": {"name": "Acme"}, "component_selection": cs}, "components": comps}
    )

    assert "**4 of 5**" in out
    assert "Internal Worker" in out  # out-of-scope component is named
    assert "not individually analyzed" in out
    # the selector's OWN reason strings survive the handoff into the criteria line
    crit_line = next(line for line in out.splitlines() if "Selection criteria" in line)
    assert "crown-jewel" in crit_line
    assert "internet-exposed" in crit_line
    assert "ci-cd" in crit_line


def test_format_selection_console_renders_empty_skipped_set():
    text = bm.format_selection_console(
        {
            "mode": "criteria",
            "depth": "standard",
            "selected": [{"id": "api", "reasons": ["internet-exposed (internet)"]}],
            "excluded": [],
        }
    )

    assert "SKIPPED (0):" in text
    assert "(none)" in text


def test_print_selection_reads_persisted_json(tmp_path, capsys):
    (tmp_path / ".stride-selection.json").write_text(
        json.dumps(
            {
                "mode": "criteria",
                "depth": "standard",
                "selected": [{"id": "api", "reasons": ["internet-exposed (internet)"]}],
                "excluded": [{"id": "worker", "reason": "out-of-scope at depth=standard"}],
            }
        ),
        encoding="utf-8",
    )
    assert bm.main([str(tmp_path), "--print-selection"]) == 0
    out = capsys.readouterr().out
    assert "ANALYZED (1):" in out and "api — internet-exposed" in out
    assert "SKIPPED (1):" in out and "worker — out-of-scope at depth=standard" in out


def test_print_selection_missing_json_returns_1(tmp_path):
    assert bm.main([str(tmp_path), "--print-selection"]) == 1


def test_skill_surfaces_component_selection_to_console():
    """The skill must surface the analyzed/skipped selection (with reasons) to the
    user console at the manifest-build seam, mirroring report §1 + §11."""
    impl = (PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL-impl.md").read_text(encoding="utf-8")
    assert "Surface the component selection to the user" in impl
    assert "--print-selection" in impl


def test_main_writes_manifest_and_prints_selection(tmp_path, capsys):
    _seed_output_dir(tmp_path)

    assert bm.main([str(tmp_path), "--depth", "standard", "--plugin-root", str(PLUGIN_ROOT)]) == 0

    out = capsys.readouterr().out
    assert (tmp_path / ".stride-dispatch-manifest.json").is_file()
    assert "OK: wrote" in out
    assert "STRIDE component selection" in out


def test_main_returns_1_when_no_components(tmp_path, capsys):
    (tmp_path / ".components.json").write_text(json.dumps({"components": []}), encoding="utf-8")

    assert bm.main([str(tmp_path), "--depth", "standard"]) == 1

    assert "no components found" in capsys.readouterr().err


def test_main_reports_ceiling_lift_and_reads_analyst_context(tmp_path, capsys):
    (tmp_path / ".components.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    _c("api-a", zones=["internet"]),
                    _c("api-b", zones=["internet"]),
                ],
            }
        ),
        encoding="utf-8",
    )
    ctx = tmp_path / "analyst-context.json"
    ctx.write_text(json.dumps({"api-a": {"interfaces": "REST /a"}}), encoding="utf-8")

    rc = bm.main(
        [
            str(tmp_path),
            "--depth",
            "standard",
            "--analyst-context",
            str(ctx),
            "--ceiling",
            "1",
        ]
    )

    out = capsys.readouterr().out
    manifest = json.loads((tmp_path / ".stride-dispatch-manifest.json").read_text(encoding="utf-8"))
    by_id = {c["component_id"]: c for c in manifest["components"]}
    assert rc == 0
    assert by_id["api-a"]["interfaces"] == "REST /a"
    assert "EXPOSURE_CAP_LIFT" in out


def test_selection_reasons_cover_each_branch():
    """Every _selection_reasons branch emits its documented string — the
    contract the §1 scope 'Selection criteria' clause depends on."""
    r = bm._selection_reasons
    assert "auth (M3.4 mandatory)" in r(_c("a", zones=["internal-network"], name="Auth Service"), "standard")
    assert "frontend attack surface (mandatory)" in r(_c("f", tier="client"), "standard")
    assert "internet-exposed (internet)" in r(_c("b", zones=["internet"]), "standard")
    assert "ci-cd / deployment (supply-chain boundary)" in r(_c("c", zones=["ci-cd-runtime"]), "standard")
    assert "crown-jewel (credentials/PII/payment/secrets)" in r(
        _c("d", zones=["internal-network"], sensitive=True), "standard"
    )
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
    assert bm._priority(_c("orders-db", zones=["internal-network"])) == 3  # data-store (type anchor)
    assert bm._priority(_c("p", zones=["ci-cd-runtime"])) == 4  # ci-cd
    assert bm._priority(_c("w", zones=["internal-network"])) == 5  # internal-only


def test_is_llm_detects_by_id_name_and_techstack():
    # id / name signals
    assert bm._is_llm(_c("llm-chat-service")) is True
    assert bm._is_llm(_c("svc", name="LLM Chat Service")) is True
    assert bm._is_llm(_c("chatbot-api")) is True
    # tech_stack signal (a generically-named component whose stack is an LLM SDK)
    comp = {
        "id": "assistant",
        "name": "Assistant",
        "type": "process",
        "tech_stack": ["@ai-sdk/openai-compatible", "Ollama"],
    }
    assert bm._is_llm(comp) is True
    # false-positive guards — bare 'ai' substrings must NOT match
    for cid in ("email-service", "retail-domain", "maintenance-worker", "available-stock"):
        assert bm._is_llm(_c(cid)) is False, cid


def test_is_llm_detects_by_known_llm_patterns_when_folded():
    """Regression (2026-06-24): juice-shop's chat route was folded into a
    generically-named `express-backend` component; the LLM signal lived only in
    `known_llm_patterns`. _is_llm must honour that field so the mandatory floor,
    the OWASP-LLM-Top-10 dispatch reason, and the Cat-13 supplement all fire."""
    folded = {
        "id": "express-backend",
        "name": "Express Backend",
        "type": "process",
        "tech_stack": ["Express", "Node.js"],
        "known_llm_patterns": "Chatbot route POST /rest/chat — proxies to Ollama.",
    }
    assert bm._is_llm(folded) is True
    # list form (manifest sometimes normalises to a list)
    folded_list = dict(folded, known_llm_patterns=["chatbot POST /rest/chat"])
    assert bm._is_llm(folded_list) is True
    # empty / whitespace must NOT flag a non-LLM backend
    assert bm._is_llm(dict(folded, known_llm_patterns="")) is False
    assert bm._is_llm(dict(folded, known_llm_patterns=[])) is False
    assert bm._is_llm(dict(folded, known_llm_patterns="   ")) is False
    # and the folded LLM backend is now mandatory-floored at standard depth
    selected, report = bm.select_stride_components([folded, _c("plain-worker", zones=["internal-network"])], "standard")
    assert "express-backend" in {c["id"] for c in selected}
    reasons = next(s["reasons"] for s in report["selected"] if s["id"] == "express-backend")
    assert any("AI/LLM surface" in r for r in reasons)


def test_path_owns_matches_exact_and_glob():
    assert bm._path_owns(["routes/chat.ts"], "routes/chat.ts") is True
    assert bm._path_owns(["routes/**"], "routes/chat.ts") is True
    assert bm._path_owns(["routes"], "routes/chat.ts") is True
    assert bm._path_owns(["server.ts"], "routes/chat.ts") is False
    assert bm._path_owns([], "routes/chat.ts") is False


def test_seed_llm_role_from_analyst_context(tmp_path):
    comps = [{"id": "express-backend", "name": "Express Backend", "paths": ["server.ts"]}]
    bm._seed_llm_role(comps, tmp_path, {"express-backend": {"known_llm_patterns": "chatbot /rest/chat"}})
    assert comps[0]["known_llm_patterns"] == "chatbot /rest/chat"
    assert bm._is_llm(comps[0]) is True


def test_seed_llm_role_from_recon_when_analyst_omits(tmp_path):
    """Deterministic bridge: a strong Cat-13 finding under a component's paths
    flags it even when the analyst supplied no known_llm_patterns."""
    (tmp_path / ".recon-patterns.json").write_text(
        json.dumps(
            {
                "categories": {
                    "13": {
                        "findings": [
                            {"subcategory": "llm-sdk", "strength": "strong", "file": "routes/chat.ts", "line": 9},
                            {"subcategory": "llm-sdk", "strength": "strong", "file": "package.json", "line": 94},
                            {"subcategory": "tool-use", "strength": "weak", "file": "server.ts", "line": 685},
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    comps = [
        {"id": "express-backend", "name": "Express Backend", "paths": ["server.ts", "routes/chat.ts"]},
        {"id": "sqlite-db", "name": "SQLite DB", "paths": ["models/"]},
    ]
    bm._seed_llm_role(comps, tmp_path, {})  # analyst omitted the flag
    eb = comps[0]
    assert "routes/chat.ts:9" in eb["known_llm_patterns"]
    assert bm._is_llm(eb) is True
    # the weak-only / unrelated component is NOT flagged
    assert not comps[1].get("known_llm_patterns")
    assert bm._is_llm(comps[1]) is False


def test_seed_llm_role_noop_without_recon_or_context(tmp_path):
    comps = [{"id": "worker", "name": "Worker", "paths": ["jobs/"]}]
    bm._seed_llm_role(comps, tmp_path, {})
    assert not comps[0].get("known_llm_patterns")


def test_llm_component_selected_at_every_depth():
    """Regression (2026-06-23): juice-shop's internal-zone `llm-chat-service` was
    dropped at standard depth. An AI/LLM component must be in scope at EVERY depth."""
    llm = _c("llm-chat-service", zones=["internal-network"], name="LLM Chat Service")
    worker = _c("worker", zones=["internal-network"])  # plain internal-only → not selected < thorough
    for depth in ("quick", "standard", "thorough"):
        selected, report = bm.select_stride_components([llm, worker], depth)
        sel_ids = {c["id"] for c in selected}
        assert "llm-chat-service" in sel_ids, f"LLM component dropped at depth={depth}"
    # and the plain internal worker is still shed at standard (proves it's the LLM role, not a passthrough)
    selected_s, _ = bm.select_stride_components([llm, worker], "standard")
    assert "worker" not in {c["id"] for c in selected_s}


def test_llm_is_not_internal_only_and_priority_two():
    llm = _c("llm-chat-service", zones=["internal-network"])
    assert bm._is_internal_only(llm) is False
    assert bm._priority(llm) == 2  # never dropped by the operational ceiling


def test_llm_survives_operational_ceiling():
    """An AI/LLM component (priority 2) is never shed when the ceiling forces drops."""
    comps = [_c("llm-chat-service", zones=["internal-network"])] + [
        _c(f"w{i}", zones=["internal-network"]) for i in range(6)
    ]
    selected, _ = bm.select_stride_components(comps, "thorough", ceiling=2)
    assert "llm-chat-service" in {c["id"] for c in selected}


def test_exposed_zone_synonyms_recognized():
    """The architecture phase labels the same exposure many ways. Genuinely
    internet/client-reachable synonyms must all count as exposed (2026-06-23:
    `internet-facing` socket + upload handler were mis-dropped as internal)."""
    for z in (
        "internet-facing",
        "internet-exposed",
        "public-internet",
        "public",
        "public-facing",
        "publicly-accessible",
        "externally-reachable",
        "external",
        "edge",
        "browser",
        "web-browser",
    ):
        assert bm._is_exposed(_c("x", zones=[z])) is True, z
    # genuinely-internal zones still NOT exposed
    assert bm._is_exposed(_c("y", zones=["internal", "internal-network"])) is False


def test_internet_facing_components_selected_at_standard():
    """The exact juice-shop shed: internet-facing Socket.IO + Multer upload."""
    socket = _c("socketio-server", zones=["internet-facing"], name="Socket.IO channel")
    upload = _c("file-upload-handler", zones=["internet-facing"], name="Multer upload")
    sel, _ = bm.select_stride_components([socket, upload], "standard")
    assert {c["id"] for c in sel} == {"socketio-server", "file-upload-handler"}


def test_is_file_upload_detects_and_guards():
    assert bm._is_file_upload(_c("file-upload-handler")) is True
    assert bm._is_file_upload(_c("uploader")) is True
    assert (
        bm._is_file_upload({"id": "media", "name": "Media", "type": "process", "tech_stack": ["multer", "sharp"]})
        is True
    )
    for cid in ("backend-api", "load-balancer", "download-cache", "payload-router"):
        assert bm._is_file_upload(_c(cid)) is False, cid


def test_is_datastore_detects_and_guards():
    # id / name signals
    assert bm._is_datastore(_c("user-store")) is True
    assert bm._is_datastore(_c("postgres-db")) is True
    assert bm._is_datastore(_c("svc", name="Redis Cache")) is True
    # structured signals: framework / tech_stack / component_type (real inventory
    # carries no `type` field — the engine lives in framework / tech_stack)
    assert bm._is_datastore({"id": "orders", "name": "Orders", "framework": "postgresql"}) is True
    assert bm._is_datastore({"id": "queue", "name": "Q", "tech_stack": ["RabbitMQ"]}) is True
    assert bm._is_datastore({"id": "x", "name": "X", "component_type": "data-store"}) is True
    # false-positive guards — bare tokens must not fire inside unrelated words
    for cid in ("backend-api", "load-balancer", "payload-router", "dashboard-ui", "auth-service"):
        assert bm._is_datastore(_c(cid)) is False, cid


def test_datastore_selected_at_standard_even_when_not_sensitive_tagged():
    """D1: an internal, NON-sensitive-tagged data-store is STRIDE-relevant (SQLi /
    tampering / info-disclosure) and must be selected at standard — a plain
    internal util with no store signal still drops."""
    comps = [
        _c("backend-api", zones=["internet"]),
        # internal SQL DB that recon UNDER-tagged as non-sensitive (no sensitive flag)
        _c("orders-db", zones=["prod-write-db"], tier="data"),
        _c("plain-worker", zones=["internal-network"]),  # no store signal → internal-only
    ]
    selected, report = bm.select_stride_components(comps, "standard")
    assert {c["id"] for c in selected} == {"backend-api", "orders-db"}
    assert {e["id"] for e in report["excluded"]} == {"plain-worker"}
    assert bm._is_internal_only(_c("orders-db", zones=["prod-write-db"])) is False
    reasons = {s["id"]: s["reasons"] for s in report["selected"]}
    assert any("data-store" in r for r in reasons["orders-db"])


def test_file_upload_and_realtime_mandatory_at_standard_even_if_internal():
    upload = _c("file-upload-handler", zones=["internal-network"])
    rt = _c("realtime-bus", zones=["internal-network"], name="Socket.IO channel")
    worker = _c("worker", zones=["internal-network"])
    sel_s = {c["id"] for c in bm.select_stride_components([upload, rt, worker], "standard")[0]}
    assert "file-upload-handler" in sel_s and "realtime-bus" in sel_s
    assert "worker" not in sel_s  # plain internal still shed at standard
    # never treated as internal-only → never ceiling-dropped
    assert bm._is_internal_only(upload) is False
    assert bm._is_internal_only(rt) is False
    # quick stays minimal: a GENUINELY-internal upload/realtime is not force-selected
    sel_q = {c["id"] for c in bm.select_stride_components([upload, rt, worker], "quick")[0]}
    assert "file-upload-handler" not in sel_q and "realtime-bus" not in sel_q


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
