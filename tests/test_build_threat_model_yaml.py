"""Unit tests for scripts/build_threat_model_yaml.py field normalizers
(2026-06-02): title/affected_parameter clamps + cvss_v4 shape coercion, so the
deterministic Phase-11-Substep-2 builder always yields a schema-valid yaml even
when STRIDE analyzers emit verbose titles or a non-canonical cvss_v4."""

from __future__ import annotations

import importlib.util
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
    raw = "Stored and Reflected XSS via trust HTML bypass (frontend/src/app/search-result/search-result.component.ts:132)"
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
            {"method": "POST", "path": "/rest/user/login", "authn_signal": "unknown",
             "route_id": "r0", "relevance_tags": ["authentication"]},
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
            {"method": "GET", "path": "/api/Users/:id", "authn_signal": "middleware_present",
             "route_id": "r0", "relevance_tags": ["missing-authz"]},
            {"method": "GET", "path": "/api/Users/:id", "authn_signal": "middleware_present",
             "route_id": "r1", "relevance_tags": ["management"]},
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
