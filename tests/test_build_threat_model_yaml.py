"""Unit tests for scripts/build_threat_model_yaml.py field normalizers
(2026-06-02): title/affected_parameter clamps + cvss_v4 shape coercion, so the
deterministic Phase-11-Substep-2 builder always yields a schema-valid yaml even
when STRIDE analyzers emit verbose titles or a non-canonical cvss_v4."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_threat_model_yaml.py"


def _load():
    spec = importlib.util.spec_from_file_location("build_threat_model_yaml", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


b = _load()


def test_clamp_title_short_passthrough():
    t = "SQL Injection — routes/login.ts:34"
    assert b._clamp_title(t) == t


def test_clamp_title_enforces_maxlen_preserving_locator():
    long = (
        "CPU Exhaustion via MarsDB $where JavaScript Injection blocking the event loop routes/showProductReviews.ts:31"
    )
    out = b._clamp_title(long)
    assert len(out) <= 80
    assert out.endswith("routes/showProductReviews.ts:31")  # locator preserved
    assert "…" in out


def test_clamp_title_no_locator_truncates_with_ellipsis():
    long = "x" * 120
    out = b._clamp_title(long)
    assert len(out) <= 80 and out.endswith("…")


def test_normalize_cvss_v4_coerces_score_and_source():
    raw = {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        "score": 9.4,
        "severity": "Critical",
    }
    out = b._normalize_cvss_v4(raw)
    assert out == {
        "vector": raw["vector"],
        "base_score": 9.4,
        "severity": "Critical",
        "source": "stride-analyzer",
    }


def test_normalize_cvss_v4_drops_invalid():
    assert b._normalize_cvss_v4(None) is None
    assert b._normalize_cvss_v4({"vector": "not-cvss", "score": 5}) is None
    assert b._normalize_cvss_v4({"vector": "CVSS:4.0/AV:N", "severity": "Bogus", "score": 5}) is None


def test_normalize_cvss_v4_keeps_valid_source():
    raw = {"vector": "CVSS:4.0/AV:N/AC:L", "base_score": 7.0, "severity": "High", "source": "nvd"}
    assert b._normalize_cvss_v4(raw)["source"] == "nvd"


# --- Substep-2 schema-drift regressions (2026-06-02 juice-shop) ----------
# Two builder/schema gaps forced Phase-11 Substep 2 into an 8-rebuild +
# 5-hand-patch loop (4m37s instead of <30s). Both are now closed.
import re

import yaml

OUTPUT_SCHEMA = ROOT / "schemas" / "threat-model.output.schema.yaml"


def _walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def _title_pattern():
    schema = yaml.safe_load(OUTPUT_SCHEMA.read_text(encoding="utf-8"))
    for n in _walk(schema):
        p = n.get("pattern") if isinstance(n, dict) else None
        if isinstance(p, str) and p.startswith("^[A-Z][^()@"):
            return p
    raise AssertionError("threats[].title pattern not found in output schema")


def _effectiveness_enum():
    schema = yaml.safe_load(OUTPUT_SCHEMA.read_text(encoding="utf-8"))
    for n in _walk(schema):
        e = n.get("enum") if isinstance(n, dict) else None
        if isinstance(e, list) and "Adequate" in e and "Missing" in e:
            return e
    raise AssertionError("effectiveness enum not found in output schema")


def test_clean_title_long_with_locator_stays_schema_valid():
    # An 81-char body+suffix used to trip the non-paren-aware _clamp_title
    # fallback, chopping the "(file:line)" suffix into an unclosed "(" that
    # violates threats[].title — the orchestrator then hand-patched it.
    raw = "Server side template injection via eval in userProfile (routes/userProfile.ts:64)"
    out = b._clamp_title(b._clean_title(raw))
    assert len(out) <= 80
    assert out.count("(") == out.count(")")  # no unbalanced/unclosed paren
    assert re.match(_title_pattern(), out), f"title not schema-valid: {out!r}"


# --- title hyphen/truncation regressions (2026-06-11 juice-shop) ----------
# Two title-builder defects corrupted every finding name reused across §1–§5:
#   Bug 2: `_TITLE_DASH_RE` rewrote `search-result` → `search result` (any
#          bare hyphen, not just spaced dash separators).
#   Bug 3: a long file path in the suffix crushed the weakness wording to
#          "Stored and Refl…" because body_cap = 80 - len(full_path).


def test_clean_title_preserves_intra_word_hyphen_in_path():
    raw = "Stored and Reflected XSS (frontend/src/app/search-result/search-result.component.ts:132)"
    out = b._clean_title(raw)
    assert "search-result" in out
    assert "search result" not in out


def test_clean_title_preserves_hyphenated_word():
    out = b._clean_title("Client-Side Auth Guard Bypass (frontend/src/app/app.guard.ts:54)")
    assert "Client-Side" in out


def test_clean_title_collapses_spaced_dash_separator():
    # A real ` — ` separator must still collapse to a single space.
    out = b._clean_title("Weak Hash — No Salt (lib/insecurity.ts:43)")
    assert "—" not in out and "Weak Hash No Salt" in out


def test_clean_title_basename_suffix_preserves_description():
    # Long path → basename so the description survives instead of "Stored and Refl…".
    raw = (
        "Stored and Reflected XSS via trust HTML bypass (frontend/src/app/search-result/search-result.component.ts:132)"
    )
    out = b._clamp_title(b._clean_title(raw))
    assert len(out) <= 80
    assert out.endswith("(search-result.component.ts:132)")  # basename suffix
    assert "Reflected" in out and "…" not in out  # weakness wording intact


def test_clean_title_drops_locator_instead_of_ellipsis_when_body_fits():
    # juice-shop 2026-06-11: weakness phrase fits in 80 on its own, but
    # weakness + (file) overflows. The locator (still in evidence_file / §8
    # Location) is DROPPED and the weakness kept FULL — never "…"-truncated,
    # which would propagate a clipped title to every xref link + anchor slug.
    raw = "JWT Stored in localStorage Without HttpOnly Cookie Protection (frontend/src/app/oauth/oauth.component.ts:51)"
    out = b._clamp_title(b._clean_title(raw))
    assert out == "JWT Stored in localStorage Without HttpOnly Cookie Protection"
    assert "…" not in out and len(out) <= 80
    raw2 = "NoSQL Injection via Unvalidated _id in MarsDB Update (routes/updateProductReviews.ts:18)"
    out2 = b._clamp_title(b._clean_title(raw2))
    assert out2 == "NoSQL Injection via Unvalidated _id in MarsDB Update"
    assert "…" not in out2


def test_clean_title_ellipsis_only_when_weakness_alone_exceeds_cap():
    # A weakness phrase that ALONE exceeds 80 is the one unavoidable truncation.
    raw = "X" + " word" * 20 + " (foo.ts:1)"  # ~100-char weakness
    out = b._clean_title(raw)
    assert len(out) <= 80 and out.endswith("…")


def test_clean_title_keeps_short_path_full():
    # Short paths must NOT be basenamed — keep the helpful `routes/` prefix.
    out = b._clamp_title(b._clean_title("SQL Injection via Raw Query String Interpolation (routes/login.ts:34)"))
    assert out.endswith("(routes/login.ts:34)")


def test_effectiveness_unsafe_accepted_by_output_schema():
    # Fragment schema defines effectiveness with 5 tiers incl. "Unsafe" (the
    # present-but-defeated verdict the §7 renderer requires and must NOT
    # conflate with Missing). The output schema must accept the same set, or
    # Substep 2 FATALs on every Phase-8 "Unsafe" control.
    enum = _effectiveness_enum()
    for v in ("Adequate", "Partial", "Weak", "Unsafe", "Missing"):
        assert v in enum, f"{v!r} missing from output-schema effectiveness enum"


# ---------------------------------------------------------------------------
# build_attack_surface — route-inventory baseline auth interpretation, dedup,
# and sidecar-override-on-collision (2026-06-04 regression: §5 rendered only
# the analyst's vuln-picked additions when .route-inventory.json was missing,
# and once present, bool("unknown") flipped every route to authenticated).
# ---------------------------------------------------------------------------


def _routes(*specs):
    """specs: (method, path, authn_signal) → route-inventory shape."""
    return {
        "routes": [
            {"method": m, "path": p, "authn_signal": a, "route_id": f"r{i}"} for i, (m, p, a) in enumerate(specs)
        ]
    }


def test_attack_surface_unknown_authn_is_not_authenticated():
    routes = _routes(
        ("GET", "/public", "unknown"),
        ("POST", "/admin", "middleware_present"),
        ("GET", "/maybe", ""),
    )
    out, _ = b.build_attack_surface(routes, None)
    by_ep = {e["entry_point"]: e for e in out}
    assert by_ep["GET /public"]["auth_required"] is False
    assert by_ep["GET /maybe"]["auth_required"] is False
    assert by_ep["POST /admin"]["auth_required"] is True


def test_attack_surface_dedup_conservative_auth():
    # Same method+path twice: one guarded, one not → reachable unauthenticated.
    routes = _routes(
        ("POST", "/api/Users", "middleware_present"),
        ("POST", "/api/Users", "unknown"),
    )
    out, _ = b.build_attack_surface(routes, None)
    eps = [e["entry_point"] for e in out]
    assert eps.count("POST /api/Users") == 1
    assert out[0]["auth_required"] is False


def test_attack_surface_carries_relevance_tags_from_inventory():
    routes = {
        "routes": [
            {
                "method": "POST",
                "path": "/rest/user/login",
                "authn_signal": "unknown",
                "route_id": "r0",
                "relevance_tags": ["authentication"],
            },
            {"method": "GET", "path": "/rest/products", "authn_signal": "unknown", "route_id": "r1"},
        ]
    }
    out, _ = b.build_attack_surface(routes, None)
    by_ep = {e["entry_point"]: e for e in out}
    assert by_ep["POST /rest/user/login"].get("relevance_tags") == ["authentication"]
    # A route with no tags carries no relevance_tags key (clean yaml).
    assert "relevance_tags" not in by_ep["GET /rest/products"]


def test_attack_surface_relevance_tags_union_on_dedup():
    # Same method+path registered twice with different tags → union, deduped row.
    routes = {
        "routes": [
            {
                "method": "GET",
                "path": "/api/Users/:id",
                "authn_signal": "middleware_present",
                "route_id": "r0",
                "relevance_tags": ["missing-authz"],
            },
            {
                "method": "GET",
                "path": "/api/Users/:id",
                "authn_signal": "middleware_present",
                "route_id": "r1",
                "relevance_tags": ["management"],
            },
        ]
    }
    out, _ = b.build_attack_surface(routes, None)
    assert len(out) == 1
    assert set(out[0]["relevance_tags"]) == {"missing-authz", "management"}


def test_attack_surface_sidecar_override_on_collision():
    # Baseline heuristic says authenticated; analyst sidecar says it is the
    # open-registration endpoint → analyst verdict wins, entry not duplicated.
    routes = _routes(("POST", "/api/Users", "middleware_present"))
    sidecar = {
        "additions": [
            {"entry_point": "POST /api/Users", "protocol": "HTTP", "auth_required": False, "notes": "open registration"}
        ]
    }
    out, warnings = b.build_attack_surface(routes, sidecar)
    assert len(out) == 1
    assert out[0]["auth_required"] is False
    assert out[0]["notes"] == "open registration"
    assert any("merged onto baseline" in w for w in warnings)


def test_attack_surface_empty_baseline_falls_back_to_additions():
    sidecar = {"additions": [{"entry_point": "GET /x", "protocol": "HTTP", "auth_required": False}]}
    out, _ = b.build_attack_surface(None, sidecar)
    assert len(out) == 1 and out[0]["entry_point"] == "GET /x"


# build_attack_surface — class-coverage guard (2026-06-06 regression: an
# all-unauthenticated include allowlist dropped every authenticated route, so
# §5.2 Authenticated Entry Points rendered "(0)" on apps with dozens of guards).


def test_attack_surface_include_allowlist_does_not_empty_auth_class():
    routes = _routes(
        ("POST", "/login", "unknown"),  # r0 unauth — analyst keeps
        ("GET", "/api/admin", "middleware_present"),  # r1 auth — dropped by include
        ("PUT", "/api/orders/1", "middleware_present"),  # r2 auth — dropped by include
    )
    # Analyst's vuln-focused include list keeps only the unauthenticated route.
    sidecar = {"curations": {"include_route_ids": ["r0"]}}
    out, warnings = b.build_attack_surface(routes, sidecar)
    auth = [e for e in out if e.get("auth_required")]
    unauth = [e for e in out if not e.get("auth_required")]
    assert unauth, "curated unauthenticated route must survive"
    assert auth, "guard must restore the authenticated class the allowlist emptied"
    assert {e["entry_point"] for e in auth} == {"GET /api/admin", "PUT /api/orders/1"}
    assert any("completeness guard" in w for w in warnings)


def test_attack_surface_guard_honours_exclude():
    routes = _routes(
        ("POST", "/login", "unknown"),  # r0 unauth — included
        ("GET", "/api/admin", "middleware_present"),  # r1 auth — restored
        ("GET", "/api/secret", "middleware_present"),  # r2 auth — explicitly excluded
    )
    sidecar = {"curations": {"include_route_ids": ["r0"], "exclude_route_ids": ["r2"]}}
    out, _ = b.build_attack_surface(routes, sidecar)
    eps = {e["entry_point"] for e in out}
    assert "GET /api/admin" in eps  # restored by the guard
    assert "GET /api/secret" not in eps  # exclude wins over the guard


def test_attack_surface_completeness_restores_uncurated_routes():
    # Even when the include list already spans BOTH auth classes, the
    # completeness guard must still restore the baseline routes the analyst's
    # vuln-focused allowlist left out — §5 reflects the full reachable surface,
    # not just the curated pick (2026-06-11 regression: include kept a subset of
    # each class, so the old class-coverage guard saw both classes "present" and
    # dropped the rest of the 112-route inventory).
    routes = _routes(
        ("POST", "/login", "unknown"),  # r0 unauth — in include
        ("GET", "/api/admin", "middleware_present"),  # r1 auth — in include
        ("GET", "/api/other", "middleware_present"),  # r2 auth — NOT in include
        ("POST", "/api/feedback", "unknown"),  # r3 unauth — NOT in include
    )
    sidecar = {"curations": {"include_route_ids": ["r0", "r1"]}}
    out, warnings = b.build_attack_surface(routes, sidecar)
    eps = {e["entry_point"] for e in out}
    assert eps == {"POST /login", "GET /api/admin", "GET /api/other", "POST /api/feedback"}
    assert any("completeness guard" in w for w in warnings)


# ── meta.check_requirements gate (2026-06-05) ─────────────────────────────────
# The contract-driven renderer gates the entire Requirements Compliance surface
# (§7b traceability, MS subsection, requirements-compliance.md authoring) on
# meta.check_requirements. build_meta must propagate the resolved skill_cfg flag
# into the yaml, else a --requirements run that ran Phase 8b renders nothing.
def _meta(**cfg):
    return b.build_meta(
        skill_cfg=cfg,
        org=None,
        recon_project=None,
        plugin_root=ROOT,
        repo_root=ROOT,
        prior_yaml=None,
    )


def test_build_meta_propagates_check_requirements_true():
    assert _meta(check_requirements=True)["check_requirements"] is True


def test_build_meta_check_requirements_defaults_false():
    assert _meta()["check_requirements"] is False
    assert _meta(check_requirements=False)["check_requirements"] is False


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def test_cli_merges_supply_chain_sidecars_into_meta_findings(tmp_path: Path):
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write_json(
        out / ".skill-config.json",
        {
            "mode": "full",
            "assessment_depth": "standard",
            "reasoning_model": "sonnet-economy",
            "stride_model": "sonnet",
            "scope": [],
        },
    )
    _write_json(out / ".threats-merged.json", {"threats": []})
    _write_json(out / ".components.json", {"schema_version": 1, "components": [{"id": "C-01", "name": "API"}]})
    _write_json(
        out / ".assets.json",
        {"schema_version": 1, "assets": [{"name": "Customer data", "classification": "Confidential"}]},
    )
    _write_json(
        out / ".trust-boundaries.json",
        {"schema_version": 1, "trust_boundaries": [{"name": "Internet to API"}]},
    )
    _write_json(
        out / ".security-controls.json",
        {
            "schema_version": 1,
            "security_controls": [
                {
                    "domain": "Operations Runtime and Supply Chain Controls",
                    "control": "Automated SCA scanning",
                    "effectiveness": "Missing",
                }
            ],
        },
    )
    _write_json(
        out / ".sca-practice-findings.json",
        {
            "schema_version": 1,
            "findings": [
                {
                    "title": "Automated SCA scanning: missing",
                    "category": "Insufficient Patch Management",
                    "summary": "SCA scanning is not configured.",
                    "derived_from": [],
                    "severity": "High",
                    "control": "Automated SCA scanning",
                    "effectiveness": "Missing",
                    "source": "sca-practice",
                }
            ],
        },
    )
    _write_json(
        out / ".known-bad-libs-findings.json",
        {
            "schema_version": 1,
            "findings": [
                {
                    "title": "Library request (npm) has known track record: deprecated_abandoned",
                    "category": "Insufficient Patch Management",
                    "summary": "The dependency is deprecated and unmaintained.",
                    "derived_from": [],
                    "severity": "Medium",
                    "control": "Library track-record review",
                    "effectiveness": "Weak",
                    "source": "known-bad-libs",
                }
            ],
        },
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(out), "--repo-root", str(repo), "--plugin-root", str(ROOT)],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    rendered = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))
    assert [mf["id"] for mf in rendered["meta_findings"]] == ["MF-001", "MF-002"]
    assert [mf["source"] for mf in rendered["meta_findings"]] == ["sca-practice", "known-bad-libs"]
    assert all(mf["derived_from"] == [] for mf in rendered["meta_findings"])


# ---------------------------------------------------------------------------
# build_component_selection — §1 Scope / verdict coverage transparency
# ---------------------------------------------------------------------------


def test_component_selection_criteria_with_exclusions():
    m = _load()
    comps = [{"id": "web", "name": "Web"}, {"id": "auth", "name": "Auth"}, {"id": "db", "name": "DB"}]
    sel = {
        "mode": "criteria",
        "selected": [
            {"id": "web", "reasons": ["frontend attack surface (mandatory)"]},
            {"id": "auth", "reasons": ["auth (M3.4 mandatory)"]},
        ],
        "excluded": [{"id": "db", "reason": "out-of-scope at depth=standard"}],
    }
    cs = m.build_component_selection(sel, comps)
    assert cs["analyzed"] == 2
    assert cs["total"] == 3
    assert [s["name"] for s in cs["selected"]] == ["Web", "Auth"]
    assert cs["excluded"][0]["name"] == "DB"
    assert "out-of-scope" in cs["excluded"][0]["reason"]


def test_component_selection_passthrough_no_exclusions():
    m = _load()
    comps = [{"id": "a", "name": "A"}]
    sel = {"mode": "passthrough", "selected": ["a"], "excluded": []}
    cs = m.build_component_selection(sel, comps)
    assert cs["analyzed"] == 1 and cs["total"] == 1 and cs["excluded"] == []


def test_component_selection_none_when_absent():
    m = _load()
    assert m.build_component_selection(None, []) is None
    assert m.build_component_selection({}, []) is None


# ─── changelog accumulation (regression: changelog was OVERWRITTEN, not extended) ──
#
# build_changelog historically read the prior history from
# $CLAUDE_PLUGIN_ROOT/.appsec-cache/baseline.json — a file that the writer
# (baseline_state.py) puts in $OUTPUT_DIR and that never carries a `changelog`
# key. So `existing` was always [] and every run reset changelog to a single
# entry. The fix seeds `existing` from the prior threat-model.yaml's
# changelog[] (the committed, accumulating store). These tests pin "extend".

_CL_CFG = {"mode": "full", "assessment_depth": "standard", "reasoning_model": "sonnet-economy"}
_CL_THREATS = [{"id": "T-001", "component": "comp-a"}]
_CL_COMPS = [{"id": "comp-a"}]


def test_changelog_first_run_single_entry(tmp_path):
    b = _load()
    cl = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="sha-1")
    assert len(cl) == 1
    assert cl[0]["current_sha"] == "sha-1"
    assert cl[0]["added"]["threats"] == ["T-001"]


def test_changelog_second_run_extends_not_overwrites(tmp_path):
    b = _load()
    run1 = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="sha-1")
    # T-001 persists (same fingerprint as run1), T-002 is genuinely new.
    threats2 = [
        {"id": "T-001", "component": "comp-a"},
        {"id": "T-002", "component": "comp-a", "cwe": "CWE-79", "title": "XSS"},
    ]
    run2 = b.build_changelog(_CL_CFG, threats2, _CL_COMPS, [], run1, tmp_path, current_sha="sha-2")
    # History grew and is newest-first; the prior entry survives verbatim.
    assert len(run2) == 2
    assert run2[0]["current_sha"] == "sha-2"
    assert run2[1]["current_sha"] == "sha-1"
    # A full run over a FINGERPRINTED prior computes a real per-finding delta:
    # T-001 is carried (not added), only the genuinely-new T-002 is added.
    assert run2[0]["delta_basis"] == "fingerprint"
    assert run2[0]["added"]["threats"] == ["T-002"]
    assert run2[1] == run1[0]


def test_changelog_first_run_is_initial_with_fingerprints(tmp_path):
    b = _load()
    cl = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="sha-1")
    e = cl[0]
    assert e["delta_basis"] == "initial"
    assert e["note"] == "first full scan"
    assert e["threat_count"] == 1
    assert e["fingerprints"]  # stored for the NEXT run to diff against
    assert e["previous_date"] is None


def test_changelog_full_delta_resolves_by_fingerprint(tmp_path):
    b = _load()
    # Run 1 (standard): two findings.
    t1 = [
        {"id": "T-001", "component": "comp-a", "cwe": "CWE-89", "title": "SQLi"},
        {"id": "T-002", "component": "comp-b", "cwe": "CWE-639", "title": "IDOR"},
    ]
    run1 = b.build_changelog(_CL_CFG, t1, _CL_COMPS, [], None, tmp_path, current_sha="sha-1")
    # Run 2 (thorough): T-001 persists, T-002 gone, a new finding appears.
    cfg2 = {"mode": "full", "assessment_depth": "thorough", "reasoning_model": "opus-cheap"}
    t2 = [
        {"id": "T-001", "component": "comp-a", "cwe": "CWE-89", "title": "SQLi"},
        {"id": "T-050", "component": "comp-c", "cwe": "CWE-94", "title": "RCE"},
    ]
    run2 = b.build_changelog(cfg2, t2, _CL_COMPS, [], run1, tmp_path, current_sha="sha-2")
    e = run2[0]
    assert e["delta_basis"] == "fingerprint"
    assert e["added"]["threats"] == ["T-050"]
    # Resolved is carried as the prior FINGERPRINT (T-IDs aren't stable), not a
    # dangling T-NNN.
    assert e["resolved"]["fingerprints"] == ["comp-b|CWE-639|idor"]
    assert e["previous_date"] == run1[0]["date"]
    assert e["previous_threat_count"] == 2
    assert "depth standard→thorough" in e["note"]
    assert "+1/-1 vs prior" in e["note"]


def test_changelog_count_only_when_prior_lacks_fingerprints(tmp_path):
    b = _load()
    # Simulate a legacy prior entry (pre-fingerprinting): no `fingerprints` key.
    legacy_prior = [
        {
            "version": 1,
            "date": "2026-06-12",
            "mode": "full",
            "assessment_depth": "standard",
            "added": {"threats": ["T-001", "T-002", "T-003"]},
            "changed": {"threats": []},
            "resolved": {"threats": []},
        }
    ]
    cfg2 = {"mode": "full", "assessment_depth": "thorough", "reasoning_model": "opus-cheap"}
    t2 = [{"id": "T-001", "component": "comp-a", "cwe": "CWE-89", "title": "SQLi"}]
    cl = b.build_changelog(cfg2, t2, _CL_COMPS, [], legacy_prior, tmp_path, current_sha="sha-2")
    e = cl[0]
    assert e["delta_basis"] == "count-only"
    assert e["threat_count"] == 1
    assert e["previous_threat_count"] == 3  # len(prior added.threats)
    assert "count-only" in e["note"]
    assert "3→1 threats" in e["note"]


def test_changelog_accumulates_across_three_runs(tmp_path):
    b = _load()
    cl = None
    for i in range(1, 4):
        cl = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], cl, tmp_path, current_sha=f"sha-{i}")
    assert [e["current_sha"] for e in cl] == ["sha-3", "sha-2", "sha-1"]


def test_changelog_idempotent_rebuild_same_state_no_duplicate(tmp_path):
    b = _load()
    run1 = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="sha-1")
    # Re-build against the IDENTICAL commit/date/mode/version → replace, not pile up.
    rerun = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], run1, tmp_path, current_sha="sha-1")
    assert len(rerun) == 1
    assert rerun[0]["current_sha"] == "sha-1"


def test_changelog_none_history_treated_as_empty(tmp_path):
    b = _load()
    cl = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha=None)
    assert len(cl) == 1
    assert cl[0]["current_sha"] is None


# ─── mitigation-level changelog delta (added 2026-06-13) ───────────────────
# Newly-added mitigation IDs are recorded alongside threats. Identity is the
# mitigation title (M-IDs renumber every run), persisted per entry as
# `mitigation_fingerprints[]` and diffed against the prior entry's stored set —
# the same self-contained mechanism threats use.

_CL_MITS_1 = [{"id": "M-001", "title": "Use parameterized queries"}]


def test_changelog_mitigation_first_run_all_added(tmp_path):
    b = _load()
    cl = b.build_changelog(
        _CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="sha-1", mitigations=_CL_MITS_1
    )
    e = cl[0]
    assert e["added"]["mitigations"] == ["M-001"]
    assert e["mitigation_fingerprints"] == ["use parameterized queries"]


def test_changelog_mitigation_delta_only_new_title(tmp_path):
    b = _load()
    run1 = b.build_changelog(
        _CL_CFG,
        _CL_THREATS,
        _CL_COMPS,
        [],
        None,
        tmp_path,
        current_sha="sha-1",
        mitigations=[{"id": "M-001", "title": "Use parameterized queries (routes/search.ts:12)"}],
    )
    # Run 2: M-001 persists by TITLE even though its id renumbered to M-007;
    # a genuinely-new mitigation (different title) is the only "added" one.
    mits2 = [
        {"id": "M-007", "title": "Use parameterized queries (routes/search.ts:44)"},  # same title → carried
        {"id": "M-002", "title": "Enforce output encoding"},  # new title → added
    ]
    threats2 = [
        {"id": "T-001", "component": "comp-a"},
        {"id": "T-002", "component": "comp-a", "cwe": "CWE-79", "title": "XSS"},
    ]
    run2 = b.build_changelog(
        _CL_CFG, threats2, _CL_COMPS, [], run1, tmp_path, current_sha="sha-2", mitigations=mits2
    )
    assert run2[0]["added"]["mitigations"] == ["M-002"]


def test_changelog_mitigation_legacy_prior_no_baseline(tmp_path):
    b = _load()
    # A prior entry that predates mitigation fingerprints → cannot diff, so we
    # honestly report no added mitigations rather than marking all of them new.
    legacy_prior = [
        {"version": 1, "date": "2026-06-12", "mode": "full", "added": {"threats": ["T-001"]}}
    ]
    cl = b.build_changelog(
        _CL_CFG, _CL_THREATS, _CL_COMPS, [], legacy_prior, tmp_path, current_sha="sha-2", mitigations=_CL_MITS_1
    )
    assert cl[0]["added"]["mitigations"] == []
    assert cl[0]["mitigation_fingerprints"] == ["use parameterized queries"]


# ─── Incremental depth-downgrade reconciliation (B1+B2) ────────────────────
# reconcile_incremental_threats re-injects prior threats of RE-ANALYZED
# components that a shallower re-scan dropped without an affirmative fix, and
# records honest changelog buckets. See
# docs/internal/analysis/proposal-depth-downgrade-incremental-preservation.md.

import hashlib as _hashlib


def _setup_incremental(tmp_path, *, prior_depth, stride):
    """stride: {cid: (baseline_bytes, current_bytes)}.

    A component is "re-analyzed" when baseline_bytes differ from current_bytes (the on-disk
    .stride file no longer matches the baseline hash); "carried-forward" when they
    are equal.
    """
    cache = tmp_path / ".appsec-cache"
    cache.mkdir(parents=True, exist_ok=True)
    sf = {}
    for cid, (baseline_bytes, current_bytes) in stride.items():
        sf[cid] = {"sha256": "sha256:" + _hashlib.sha256(baseline_bytes).hexdigest()}
        (tmp_path / f".stride-{cid}.json").write_bytes(current_bytes)
    (cache / "baseline.json").write_text(
        json.dumps({"last_run_depth": prior_depth, "stride_files": sf})
    )


def _prior_threat(tid, comp, cwe, title):
    return {"id": tid, "component": comp, "cwe": cwe, "title": title,
            "risk": "High", "likelihood": "Medium", "impact": "High"}


def test_reanalyzed_component_ids_detects_sha_mismatch(tmp_path):
    _setup_incremental(tmp_path, prior_depth="thorough", stride={
        "auth": (b'{"a":1}', b'{"a":2}'),    # changed -> re-analyzed
        "api": (b'{"b":1}', b'{"b":1}'),      # unchanged -> carried-forward
    })
    assert b._reanalyzed_component_ids(tmp_path) == {"auth"}


def test_reanalyzed_component_ids_none_without_baseline(tmp_path):
    assert b._reanalyzed_component_ids(tmp_path) is None


def test_reconcile_carries_dropped_prior_threat_at_shallower_depth(tmp_path):
    _setup_incremental(tmp_path, prior_depth="thorough", stride={"auth": (b"old", b"new")})
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    new_threats = [{"id": "T-001", "component": "auth", "cwe": "CWE-89", "title": "SQLi (db.ts:3)"}]
    out, recon = b.reconcile_incremental_threats(
        new_threats, prior, [{"id": "auth"}], tmp_path, "quick", {})
    carried = [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    assert len(carried) == 1
    assert carried[0]["title"] == "Weak auth (login.ts:10)"
    # fresh, collision-free id (continues after T-001)
    assert carried[0]["id"] == "T-002"
    assert recon is not None
    assert recon["reanalyzed_ids"] == ["auth"]
    assert recon["resolved_reason_by_id"] == {}


def test_reconcile_resolves_when_analyzer_affirms_fix(tmp_path):
    _setup_incremental(tmp_path, prior_depth="thorough", stride={"auth": (b"old", b"new")})
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    resolved_prior = {"T-007": "MFA enforced at login.ts:10"}
    out, recon = b.reconcile_incremental_threats(
        [], prior, [{"id": "auth"}], tmp_path, "quick", resolved_prior)
    assert not [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    assert recon["resolved_reason_by_id"] == {"T-007": "MFA enforced at login.ts:10"}


def test_reconcile_no_carry_at_equal_depth(tmp_path):
    _setup_incremental(tmp_path, prior_depth="quick", stride={"auth": (b"old", b"new")})
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    out, recon = b.reconcile_incremental_threats(
        [], prior, [{"id": "auth"}], tmp_path, "quick", {})
    assert not [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    # equal depth → recorded as resolved, not silently dropped
    assert recon["resolved_reason_by_id"]["T-007"].startswith("not reproduced")


def test_reconcile_skips_carried_forward_component(tmp_path):
    # api unchanged → carried-forward → its prior threats must NOT be touched
    _setup_incremental(tmp_path, prior_depth="thorough", stride={"api": (b"same", b"same")})
    prior = {"threats": [_prior_threat("T-007", "api", "CWE-89", "SQLi (q.ts:9)")]}
    out, recon = b.reconcile_incremental_threats(
        [], prior, [{"id": "api"}], tmp_path, "quick", {})
    assert out == []                       # nothing injected
    assert recon["resolved_reason_by_id"] == {}
    assert recon["carried_forward_ids"] == ["api"]


def test_reconcile_no_double_count_when_reemitted(tmp_path):
    _setup_incremental(tmp_path, prior_depth="thorough", stride={"auth": (b"old", b"new")})
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    # analyzer re-emitted the same finding (same fingerprint) under a fresh id
    new_threats = [{"id": "T-001", "component": "auth", "cwe": "CWE-287",
                    "title": "Weak auth (login.ts:10)"}]
    out, recon = b.reconcile_incremental_threats(
        new_threats, prior, [{"id": "auth"}], tmp_path, "quick", {})
    assert len(out) == 1                    # no re-injection
    assert not [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]


def test_reconcile_noop_on_full_run(tmp_path):
    # no baseline.json → full/first run → no-op, recon_info None
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    out, recon = b.reconcile_incremental_threats(
        [{"id": "T-001", "component": "auth"}], prior, [{"id": "auth"}], tmp_path, "quick", {})
    assert recon is None
    assert len(out) == 1


def test_changelog_incremental_buckets_populated(tmp_path):
    recon = {
        "reanalyzed_ids": ["auth"],
        "carried_forward_ids": ["api"],
        "resolved_reason_by_id": {"T-009": "fixed at x.ts:1"},
        "carried_ids": ["T-002"],
        "added_ids": ["T-001"],
    }
    cl = b.build_changelog(
        {"mode": "incremental", "assessment_depth": "quick"},
        [{"id": "T-001", "component": "auth"}, {"id": "T-002", "component": "auth"}],
        [{"id": "auth"}, {"id": "api"}], [], None, tmp_path,
        current_sha="sha-x", recon_info=recon)
    e = cl[0]
    assert e["reanalyzed_components"] == ["auth"]
    assert e["carried_forward_components"] == ["api"]
    assert e["added"]["threats"] == ["T-001"]
    assert e["resolved"]["threats"] == ["T-009"]
    assert e["resolved"]["reason_by_id"] == {"T-009": "fixed at x.ts:1"}


def test_changelog_full_run_unchanged_without_recon(tmp_path):
    # recon_info=None (full run) keeps the legacy "treat as full" behavior
    cl = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="s")
    assert cl[0]["carried_forward_components"] == []
    assert cl[0]["added"]["threats"] == ["T-001"]
    assert cl[0]["resolved"] == {"threats": [], "reason_by_id": {}, "instances": []}


# ---------------------------------------------------------------------------
# Mitigation control-dedup (Regel B)
# ---------------------------------------------------------------------------


def test_dedupe_mitigation_controls_collapses_identical_titles():
    threats = [
        {"id": "T-001", "mitigation_ids": ["M-004"]},
        {"id": "T-002", "mitigation_ids": ["M-022"]},
    ]
    mits = [
        {"id": "M-004", "title": "Enforce object-level (ownership) authorization",
         "threat_ids": ["T-001"], "severity": "High", "priority": "P2"},
        {"id": "M-022", "title": "Enforce object-level (ownership) authorization",
         "threat_ids": ["T-002"], "severity": "Critical", "priority": "P1"},
    ]
    out_threats, out_mits = b.dedupe_mitigation_controls(threats, mits)
    assert len(out_mits) == 1
    surv = out_mits[0]
    assert surv["id"] == "M-004"                      # lowest id survives
    assert surv["threat_ids"] == ["T-001", "T-002"]   # unioned
    assert surv["severity"] == "Critical"             # max across the group
    assert surv["priority"] == "P1"
    # Both findings now point at the shared mitigation (many findings → 1 control).
    assert out_threats[0]["mitigation_ids"] == ["M-004"]
    assert out_threats[1]["mitigation_ids"] == ["M-004"]


def test_dedupe_mitigation_controls_keeps_distinct_controls():
    threats = [{"id": "T-001", "mitigation_ids": ["M-001", "M-002"]}]
    mits = [
        {"id": "M-001", "title": "Enforce object-level authorization", "threat_ids": ["T-001"], "severity": "High"},
        {"id": "M-002", "title": "Pin base image to a digest", "threat_ids": ["T-001"], "severity": "Low"},
    ]
    out_threats, out_mits = b.dedupe_mitigation_controls(threats, mits)
    assert len(out_mits) == 2                          # different controls untouched
    assert out_threats[0]["mitigation_ids"] == ["M-001", "M-002"]


# ---------------------------------------------------------------------------
# Instance-level delta (Regel C) — partial-progress visibility
# ---------------------------------------------------------------------------


def test_instance_fingerprints_one_per_instance():
    t = {"component": "c", "cwe": "CWE-862", "title": "Sensitive routes",
         "instances": [{"file": "server.ts", "line": 310}, {"file": "server.ts", "line": 311}]}
    fps = b._instance_fingerprints(t)
    assert len(fps) == 2
    assert all(fp.startswith("c|CWE-862|sensitive routes|server.ts:") for fp in fps)


def test_instance_fingerprints_degrades_to_evidence_for_non_systemic():
    t = {"component": "c", "cwe": "CWE-89", "title": "SQLi", "evidence": {"file": "login.ts", "line": 5}}
    assert b._instance_fingerprints(t) == ["c|CWE-89|sqli|login.ts:5"]


def test_changelog_instance_delta_partial_resolution(tmp_path):
    sysfind = {"id": "T-001", "component": "comp-a", "cwe": "CWE-862", "title": "Sensitive routes",
               "instances": [{"file": "server.ts", "line": ln} for ln in (310, 311, 407)]}
    run1 = b.build_changelog(_CL_CFG, [sysfind], _CL_COMPS, [], None, tmp_path, current_sha="s1")
    assert len(run1[0]["instance_fingerprints"]) == 3
    assert run1[0]["added"]["instances"] == []          # first run stays quiet

    # run2: one location (407) fixed; the finding itself is unchanged.
    sysfind2 = dict(sysfind, instances=[{"file": "server.ts", "line": ln} for ln in (310, 311)])
    run2 = b.build_changelog(_CL_CFG, [sysfind2], _CL_COMPS, [], run1, tmp_path, current_sha="s2")
    assert run2[0]["added"]["threats"] == []            # finding-level: nothing new/gone
    assert run2[0]["resolved"]["fingerprints"] == []
    resolved_inst = run2[0]["resolved"]["instances"]    # instance-level: 1 resolved
    assert len(resolved_inst) == 1
    assert "server.ts:407" in resolved_inst[0]


def test_instance_fingerprints_tolerates_list_shaped_evidence():
    # Regression: evidence is a LIST of {file,line} in the final yaml.
    t = {"component": "c", "cwe": "CWE-922", "title": "Token in storage",
         "evidence": [{"file": "oauth.ts", "line": 51}, {"file": "oauth.ts", "line": 52}]}
    assert b._instance_fingerprints(t) == ["c|CWE-922|token in storage|oauth.ts:51"]


def test_dedupe_mitigation_controls_dedupes_within_one_threat():
    # A threat that references both duplicate M-IDs collapses to the survivor once.
    threats = [{"id": "T-001", "mitigation_ids": ["M-004", "M-022"]}]
    mits = [
        {"id": "M-004", "title": "Enforce object-level authorization", "threat_ids": ["T-001"], "severity": "High"},
        {"id": "M-022", "title": "Enforce object-level authorization", "threat_ids": ["T-001"], "severity": "High"},
    ]
    out_threats, out_mits = b.dedupe_mitigation_controls(threats, mits)
    assert len(out_mits) == 1
    assert out_threats[0]["mitigation_ids"] == ["M-004"]  # remapped AND de-duplicated within the threat
