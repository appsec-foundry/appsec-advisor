"""Unit tests for scripts/build_threat_model_yaml.py field normalizers
(2026-06-02): title/affected_parameter clamps + cvss_v4 shape coercion, so the
deterministic Phase-11-Substep-2 builder always yields a schema-valid yaml even
when STRIDE analyzers emit verbose titles or a non-canonical cvss_v4."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

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


def test_clamp_title_never_leaves_unclosed_markup():
    """Truncating mid-`(...)` or mid-code-span would trade a length violation
    for the unbalanced-markup violation heading_hygiene also rejects."""
    paren = b._clamp_title(
        "Replace req.body.UserId/userId/ownerId with req.user.id "
        "(or equivalent session-derived identity) in every WHERE clause"
    )
    assert len(paren) <= 80
    assert paren.count("(") == paren.count(")")

    code = b._clamp_title(
        "Pass the workflow title via an `env:` block instead of `${{ github.event.issue.title }}` inline"
    )
    assert len(code) <= 80
    assert code.count("`") % 2 == 0


def test_mitigation_titles_are_clamped_like_threat_titles():
    """The register renders `#### M-NNN — <title>`, and qa_checks'
    heading_hygiene rejects headings over 100 chars. Threat titles were
    clamped but mitigation titles were not, so the composer emitted headings
    its own gate then refused (juice-shop 2026-07-31)."""
    threats = [
        {
            "id": "T-001",
            "title": "Hardcoded Private Key",
            "risk": "Critical",
            "mitigation_ids": ["M-001"],
            "mitigation_title": (
                "Remove hardcoded private key and load it from a secrets manager "
                "or environment variable at startup before any signing occurs"
            ),
            "remediation": {"effort": "Medium"},
        }
    ]
    mitigations = b.build_mitigations(threats)
    assert [m["id"] for m in mitigations] == ["M-001"]
    assert len(mitigations[0]["title"]) <= 80
    assert mitigations[0]["title"].endswith("…")


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


# --- `@` in a title aborted the whole run (2026-08-16 juice-shop) --------
# The schema forbids `@` in the title body, `_clean_title` owns making a
# merged title conform, and it handled backticks and parens but not `@`. One
# CI finding named a git ref and Phase 10 failed schema validation, ending a
# 58-minute run that had already produced 65 threats.


@pytest.mark.parametrize(
    ("raw", "must_contain"),
    [
        ("Unpinned CI action at mutable @main tag (image_actions.yml:33)", "main tag"),
        ("Prototype pollution in @angular/core resolver", "angular/core"),
        ("Decorator @Injectable exposes provider scope", "Injectable"),
    ],
)
def test_clean_title_strips_a_technical_at_token(raw, must_contain):
    out = b._clean_title(raw)

    assert re.match(_title_pattern(), out), f"title not schema-valid: {out!r}"
    assert must_contain in out


@pytest.mark.parametrize(
    "raw",
    [
        "Remote code execution via eval( in coupon handler",
        "`Backticked` title with (nested (parens)) and @ref",
        "Unpinned CI action at mutable @main tag (image_actions.yml:33)",
        "JWT accepts alg:none tokens (lib/insecurity.ts:12)",
        "XML parser with noent:true enables entity expansion",
        "Install runs with package-lock=false in CI",
        "Sanitiser calls bypassSecurityTrustHtml on user input",
        "Password hashing uses crypto.createHash md5",
        "Search endpoint uses models.sequelize.query with interpolation",
        "Vulnerable dependency (CVE-2021-23337) reaches the parser",
        "lowercase start of a title that is long enough",
        "Stored and Reflected XSS (frontend/src/app/search-result/search-result.component.ts:132)",
    ],
)
def test_the_cleaner_satisfies_every_title_constraint_it_owns(raw):
    """`_clean_title` exists to make a merged title schema-valid.

    It enforced backticks, spaced dashes and the blocklist, but not `@` and not
    a stray or nested paren — so a single analyzer title aborted a 58-minute
    run at Phase 10. Any constraint the schema states about a title body is
    this function's to satisfy.
    """
    out = b._clamp_title(b._clean_title(raw))

    assert re.match(_title_pattern(), out), f"title not schema-valid: {out!r}"
    assert len(out) <= 80
    assert "@" not in out
    assert "`" not in out
    assert out.count("(") == out.count(")") <= 1


def test_clean_title_drops_a_version_pin_whole():
    """`@\\d` is removed as a unit — stripping only the `@` would leave junk."""
    out = b._clean_title("Outdated jsonwebtoken@0.4.0 permits algorithm confusion")

    assert re.match(_title_pattern(), out), f"title not schema-valid: {out!r}"
    assert "jsonwebtoken" in out
    assert "0.4.0" not in out


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


def test_attack_surface_maps_graphql_inventory_entries():
    routes = {
        "routes": [
            {
                "method": "GRAPHQL",
                "path": "Mutation updateUser",
                "framework": "graphql",
                "authn_signal": "unknown",
                "route_id": "r0",
                "notes": ["GraphQL Mutation", "args: id,input", "returns: User"],
                "relevance_tags": ["graphql-mutation", "missing-auth"],
            }
        ]
    }

    out, _ = b.build_attack_surface(routes, None)

    assert out == [
        {
            "entry_point": "GRAPHQL Mutation updateUser",
            "protocol": "GraphQL",
            "auth_required": False,
            "notes": "GraphQL Mutation; args: id,input; returns: User",
            "relevance_tags": ["graphql-mutation", "missing-auth"],
        }
    ]


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


def test_build_meta_stride_cap_propagated_when_active():
    """--stride-cap N → .skill-config stride_profile.max_threats_per_category
    reaches meta so the report self-discloses the reduced scope."""
    m = _meta(stride_profile={"max_threats_per_category": 2, "stride_profile_label": "full (per-category cap 2)"})
    assert m["stride_per_category_cap"] == 2


def test_build_meta_records_the_register_severity_floor():
    """Reader-facing tallies need the floor to tell "no Low finding" apart from
    "Low was never collected"; .skill-config.json does not survive cleanup."""
    assert _meta()["register_severity_floor"] == "medium"
    assert _meta(register_severity_floor="low")["register_severity_floor"] == "low"


def _business_meta(tmp_path):
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True, exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return repo, output


def test_build_meta_records_which_file_the_context_digest_came_from(tmp_path):
    """The run-only file is cleaned up with its run, so a later scan sees the
    digest go missing. Without the source name that reads as an edit."""
    repo, output = _business_meta(tmp_path)
    (output / ".business-context-input.md").write_text("This run only.\n", encoding="utf-8")

    m = b.build_meta(
        skill_cfg={"output_dir": str(output)},
        org=None,
        recon_project=None,
        plugin_root=ROOT,
        repo_root=repo,
        prior_yaml=None,
    )

    assert m["business_context_source"] == ".business-context-input.md"
    assert m["business_context_sha256"]


def test_build_meta_records_the_repository_file_as_its_own_source(tmp_path):
    repo, output = _business_meta(tmp_path)
    (repo / "docs" / "business-context.md").write_text("Stored context.\n", encoding="utf-8")

    m = b.build_meta(
        skill_cfg={"output_dir": str(output)},
        org=None,
        recon_project=None,
        plugin_root=ROOT,
        repo_root=repo,
        prior_yaml=None,
    )

    assert m["business_context_source"] == "docs/business-context.md"


def test_build_meta_leaves_the_context_source_empty_without_context(tmp_path):
    repo, output = _business_meta(tmp_path)

    m = b.build_meta(
        skill_cfg={"output_dir": str(output)},
        org=None,
        recon_project=None,
        plugin_root=ROOT,
        repo_root=repo,
        prior_yaml=None,
    )

    assert m["business_context_source"] is None
    assert m["business_context_sha256"] is None


def test_build_meta_stride_cap_none_when_full():
    """No cap (full profile or missing) → None, renderer omits the row."""
    assert _meta()["stride_per_category_cap"] is None
    assert _meta(stride_profile={"stride_profile_label": "full"})["stride_per_category_cap"] is None


def test_build_meta_propagates_per_stage_reasoning_models():
    """Per-stage models reach meta so the report can disclose mixed tiers
    (e.g. APPSEC_TRIAGE_MODEL=opus while STRIDE stays sonnet)."""
    m = _meta(stride_model="sonnet", triage_model="opus", merger_model="sonnet")
    assert m["stride_model"] == "sonnet"
    assert m["triage_model"] == "opus"
    assert m["merger_model"] == "sonnet"


def test_build_meta_records_invocation():
    """The exact invocation flags reach meta (reproducibility anchor that
    survives runtime cleanup, unlike .skill-config.json)."""
    m = _meta(invocation_args="--reasoning-model sonnet-economy --triage-model opus --stride-cap 2")
    assert m["invocation"] == "--reasoning-model sonnet-economy --triage-model opus --stride-cap 2"
    assert _meta()["invocation"] is None  # absent → None (renderer falls back)


def test_build_meta_serializes_rebuild_as_full_assessment():
    assert _meta(mode="rebuild")["mode"] == "full"


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


def _write_min_intermediates(out: Path) -> None:
    """Minimal sidecar set so build_threat_model_yaml.py main() runs cleanly."""
    _write_json(
        out / ".skill-config.json",
        {
            "mode": "full",
            "assessment_depth": "quick",
            "reasoning_model": "sonnet-economy",
            "stride_model": "sonnet",
            "scope": [],
        },
    )
    _write_json(out / ".threats-merged.json", {"threats": []})
    _write_json(out / ".components.json", {"schema_version": 1, "components": [{"id": "C-01", "name": "API"}]})
    _write_json(
        out / ".assets.json", {"schema_version": 1, "assets": [{"name": "Data", "classification": "Confidential"}]}
    )
    _write_json(
        out / ".trust-boundaries.json", {"schema_version": 1, "trust_boundaries": [{"name": "Internet to API"}]}
    )
    _write_json(
        out / ".security-controls.json",
        {
            "schema_version": 1,
            "security_controls": [
                {"domain": "Authentication", "control": "JWT verification", "effectiveness": "Partial"}
            ],
        },
    )


def test_validate_and_publish_preserves_prior_yaml_on_schema_failure(tmp_path, monkeypatch):
    out_path = tmp_path / "threat-model.yaml"
    out_path.write_text("prior: true\n", encoding="utf-8")
    validator = tmp_path / "validate_intermediate.py"
    validator.write_text("# test stub\n", encoding="utf-8")

    monkeypatch.setattr(
        b.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "invalid\n", ""),
    )

    result = b._validate_and_publish_yaml(out_path, "replacement: invalid\n", validator)

    assert result.returncode == 1
    assert out_path.read_text(encoding="utf-8") == "prior: true\n"
    assert not (tmp_path / ".threat-model.yaml.pending").exists()


def test_validate_and_publish_rejects_missing_validator_without_writing(tmp_path):
    out_path = tmp_path / "threat-model.yaml"
    out_path.write_text("prior: true\n", encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="schema validator missing"):
        b._validate_and_publish_yaml(out_path, "replacement: true\n", tmp_path / "missing.py")

    assert out_path.read_text(encoding="utf-8") == "prior: true\n"


def test_validate_and_publish_replaces_canonical_only_after_success(tmp_path, monkeypatch):
    out_path = tmp_path / "threat-model.yaml"
    out_path.write_text("prior: true\n", encoding="utf-8")
    validator = tmp_path / "validate_intermediate.py"
    validator.write_text("# test stub\n", encoding="utf-8")
    monkeypatch.setattr(
        b.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "valid\n", ""),
    )

    result = b._validate_and_publish_yaml(out_path, "replacement: true\n", validator)

    assert result.returncode == 0
    assert out_path.read_text(encoding="utf-8") == "replacement: true\n"


def test_cli_persists_validated_data_flow_sidecar_into_yaml(tmp_path: Path):
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write_min_intermediates(out)
    _write_json(out / ".components.json", {"schema_version": 1, "components": [{"id": "api", "name": "API"}]})
    _write_json(
        out / ".data-flows.json",
        {
            "schema_version": 1,
            "component_inventory_fingerprint": "sha256:" + "1" * 64,
            "data_flows": [
                {
                    "id": "df-001",
                    "from": "external",
                    "to": "api",
                    "label": "HTTPS ingress",
                    "protocol": "HTTPS",
                    "data_classification": "Confidential",
                    "direction": "request-response",
                    "evidence": [],
                    "provenance": "architecture",
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
    assert rendered["data_flows"][0]["id"] == "df-001"
    assert rendered["data_flows"][0]["to"] == "api"


def test_changelog_recovers_history_from_cache_mirror_when_yaml_lost(tmp_path: Path):
    """A lost/deleted threat-model.yaml must not silently reset the changelog to
    'first full scan'. main() rehydrates the prior history from the
    .appsec-cache/baseline.json changelog_mirror (written by baseline_state.py
    cmd_update). Regression for the 2026-06-26 juice-shop "--full reset my
    changelog" report."""
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    (out / ".appsec-cache").mkdir()
    _write_min_intermediates(out)
    # Cache mirror from a prior run last week (different commit + date), NO yaml.
    _write_json(
        out / ".appsec-cache" / "baseline.json",
        {
            "schema_version": 1,
            "analysis_version": 2,
            "plugin_version": "0.4.0-beta",
            "last_run_at": "2026-06-19T10:00:00Z",
            "changelog_mirror": [
                {
                    "version": 1,
                    "date": "2026-06-19",
                    "mode": "full",
                    "assessment_depth": "quick",
                    "reasoning_model": "sonnet-economy",
                    "plugin_version": "0.4.0-beta",
                    "analysis_version": 2,
                    "current_sha": "OLDSHA",
                    "threat_count": 31,
                    "delta_basis": "initial",
                    "note": "first full scan",
                    "fingerprints": [],
                    "added": {"threats": []},
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
    assert "recovered 1 prior entr" in result.stderr  # warning fired
    cl = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))["changelog"]
    # Prior run survived — the first-scan date is still visible, not reset.
    assert len(cl) == 2
    assert cl[1]["date"] == "2026-06-19"
    assert cl[1]["note"] == "first full scan"
    assert cl[0]["note"] != "first full scan"  # today is a genuine delta, not "initial"


def test_changelog_warns_when_prior_run_evidenced_but_history_gone(tmp_path: Path):
    """When neither the yaml nor a mirror survived but baseline.json still proves
    a prior run happened (last_run_at), main() warns instead of silently
    claiming 'first full scan' — a false initial claim is the one thing a
    security audit trail must never make."""
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    (out / ".appsec-cache").mkdir()
    _write_min_intermediates(out)
    _write_json(
        out / ".appsec-cache" / "baseline.json",
        {"schema_version": 1, "analysis_version": 2, "last_run_at": "2026-06-19T10:00:00Z"},
    )

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(out), "--repo-root", str(repo), "--plugin-root", str(ROOT)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "prior run is recorded" in result.stderr
    assert "unrecoverable" in result.stderr
    cl = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))["changelog"]
    assert len(cl) == 1  # genuinely cannot recover — single initial entry, but the user was warned


def test_changelog_no_warning_on_genuine_first_run(tmp_path: Path):
    """A true first run (no yaml, no baseline cache at all) stays silent — the
    recovery warnings must not fire when there is genuinely no prior run."""
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write_min_intermediates(out)

    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(out), "--repo-root", str(repo), "--plugin-root", str(ROOT)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "recovered" not in result.stderr
    assert "prior run is recorded" not in result.stderr
    cl = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))["changelog"]
    assert len(cl) == 1
    assert cl[0]["note"] == "first full scan"


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


def test_component_selection_carries_screening_depth():
    """--cheap-stride marks screened components in .stride-selection.json; the
    marker has to survive into meta so §1 Scope, §3 and the verdict can say so."""
    m = _load()
    comps = [{"id": "web", "name": "Web"}, {"id": "worker", "name": "Worker"}]
    sel = {
        "mode": "criteria",
        "selected": [
            {"id": "web", "reasons": ["internet-exposed"]},
            {"id": "worker", "reasons": ["screening depth (--cheap-stride)"], "analysis_depth": "screening"},
        ],
        "excluded": [],
    }
    cs = m.build_component_selection(sel, comps)
    by_id = {s["id"]: s for s in cs["selected"]}
    assert by_id["worker"]["analysis_depth"] == "screening"
    assert "analysis_depth" not in by_id["web"]


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


def test_changelog_rescan_same_commit_suppresses_noise_delta(tmp_path):
    """Regression (2026-06-27 juice-shop): five quick --full re-runs of the SAME
    commit, repo untouched, each reported ~16 added / ~37 resolved — pure LLM
    analysis nondeterminism (title rewording, dropped/phantom findings, anchor
    drift) mislabelled as added/fixed. A same-commit, same-depth re-scan must
    claim NO per-finding delta (resolved-on-unchanged is a false-fixed claim)
    while still accumulating and persisting its own match keys for a later real
    diff against CHANGED code."""
    b = _load()
    cfg = {"mode": "full", "assessment_depth": "quick", "reasoning_model": "sonnet-economy"}
    t1 = [
        {
            "id": "T-001",
            "component": "auth",
            "cwe": "CWE-89",
            "title": "SQLi",
            "evidence": {"file": "routes/login.ts", "line": 34},
        },
        {
            "id": "T-002",
            "component": "auth",
            "cwe": "CWE-639",
            "title": "IDOR",
            "evidence": {"file": "routes/address.ts", "line": 11},
        },
    ]
    m1 = [{"id": "M-001", "title": "Use parameterized queries"}]
    run1 = b.build_changelog(cfg, t1, _CL_COMPS, [], None, tmp_path, current_sha="sha-1", run_id="r1", mitigations=m1)
    # Re-run on the SAME commit: the LLM surfaces a different-looking set —
    # T-002 dropped, T-009 phantom-new, a title reworded, a new mitigation — all
    # noise on untouched code.
    t2 = [
        {
            "id": "T-001",
            "component": "auth",
            "cwe": "CWE-89",
            "title": "SQL Injection in login",
            "evidence": {"file": "routes/login.ts", "line": 34},
        },
        {
            "id": "T-009",
            "component": "web3",
            "cwe": "CWE-306",
            "title": "Missing auth",
            "evidence": {"file": "server.ts", "line": 641},
        },
    ]
    m2 = m1 + [{"id": "M-007", "title": "Rate limit login"}]
    run2 = b.build_changelog(cfg, t2, _CL_COMPS, [], run1, tmp_path, current_sha="sha-1", run_id="r2", mitigations=m2)
    e = run2[0]
    assert e["delta_basis"] == "rescan-unchanged"
    assert e["added"]["threats"] == []
    assert e["added"]["mitigations"] == []
    assert e["added"]["instances"] == []
    assert (e["resolved"].get("fingerprints") or []) == []
    assert (e["resolved"].get("instances") or []) == []
    # Accumulates AND still persists its own match keys for the NEXT real diff.
    assert len(run2) == 2
    assert len(e["match_keys"]) == 2
    assert "re-derived" in e["note"]


def test_changelog_note_rescan_differing_count_reads_as_no_real_change():
    """rescan-unchanged with a drifting raw count must lead with 'no real change'
    so the Note agrees with the Δ +0/~0/-0 cell — the 37→32 count movement is
    labelled re-derivation noise, not a real finding delta (juice-shop v7)."""
    note = b._changelog_note(
        delta_basis="rescan-unchanged",
        prior_entry={"version": 6},
        prior_depth="quick",
        cur_depth="quick",
        prior_n=37,
        cur_n=32,
        n_added=0,
        n_resolved=0,
    )
    assert "no real change" in note
    assert "37→32" in note
    assert "re-derived" in note
    assert len(note) <= 60  # template truncates the Note cell at 60 chars


def test_changelog_rescan_guard_only_on_same_commit_and_depth(tmp_path):
    """The suppression is narrow: a DIFFERENT commit (real change) or a DEEPER
    depth (deeper scan finds genuinely new findings) must keep the real
    fingerprint delta, never collapse to rescan-unchanged."""
    b = _load()
    cfg = {"mode": "full", "assessment_depth": "quick", "reasoning_model": "sonnet-economy"}
    t1 = [
        {"id": "T-001", "component": "auth", "cwe": "CWE-89", "title": "SQLi", "evidence": {"file": "a.ts", "line": 1}}
    ]
    run1 = b.build_changelog(cfg, t1, _CL_COMPS, [], None, tmp_path, current_sha="sha-1", run_id="r1")
    t2 = [
        {"id": "T-001", "component": "auth", "cwe": "CWE-89", "title": "SQLi", "evidence": {"file": "a.ts", "line": 1}},
        {"id": "T-002", "component": "auth", "cwe": "CWE-79", "title": "XSS", "evidence": {"file": "b.ts", "line": 2}},
    ]
    # Different commit → genuine change → fingerprint delta (T-002 added).
    diff_commit = b.build_changelog(cfg, t2, _CL_COMPS, [], run1, tmp_path, current_sha="sha-2", run_id="r2")
    assert diff_commit[0]["delta_basis"] == "fingerprint"
    assert diff_commit[0]["added"]["threats"] == ["T-002"]
    # Same commit but DEEPER depth → not a no-op re-scan; keep the real delta.
    cfg_deep = {"mode": "full", "assessment_depth": "thorough", "reasoning_model": "sonnet-economy"}
    deeper = b.build_changelog(cfg_deep, t2, _CL_COMPS, [], run1, tmp_path, current_sha="sha-1", run_id="r3")
    assert deeper[0]["delta_basis"] == "fingerprint"
    assert deeper[0]["added"]["threats"] == ["T-002"]


def test_changelog_stable_across_cwe_and_title_drift_same_file(tmp_path):
    """Regression (2026-06-26 juice-shop): two --full runs over IDENTICAL code
    churned the whole register (27 added / 31 resolved) because the diff keyed on
    comp|cwe|title — all three LLM-generated and drifting run-to-run. The diff now
    keys on file|cwe-family, so a finding whose component is renamed, whose CWE
    swaps within its family, and whose title is reworded — but whose evidence file
    is unchanged — must be carried, NOT churned."""
    b = _load()
    run1 = b.build_changelog(
        _CL_CFG,
        [
            # RSA key — run1 labels it auth / CWE-798 / "forgery".
            {
                "id": "T-001",
                "component": "auth",
                "cwe": "CWE-798",
                "title": "Hardcoded RSA private key enabling JWT forgery",
                "evidence": {"file": "lib/insecurity.ts", "line": 21},
            },
            # JWT verify — run1 labels it backend-api / CWE-347.
            {
                "id": "T-002",
                "component": "backend-api",
                "cwe": "CWE-347",
                "title": "Insecure JWT verification",
                "evidence": {"file": "lib/insecurity.ts", "line": 52},
            },
        ],
        _CL_COMPS,
        [],
        None,
        tmp_path,
        current_sha="sha-1",
        run_id="1000",
    )
    run2 = b.build_changelog(
        _CL_CFG,
        [
            # Same RSA key — run2 renames component, swaps CWE within the
            # hardcoded-key family (798→321), rewords the title.
            {
                "id": "T-009",
                "component": "express-backend",
                "cwe": "CWE-321",
                "title": "Hardcoded RSA private key enables arbitrary JWT signing",
                "evidence": {"file": "lib/insecurity.ts", "line": 21},
            },
            # Same JWT verify — sig-verify family swap (347→345), component rename.
            {
                "id": "T-014",
                "component": "auth",
                "cwe": "CWE-345",
                "title": "Insecure JWT verification path",
                "evidence": {"file": "lib/insecurity.ts", "line": 52},
            },
        ],
        _CL_COMPS,
        [],
        run1,
        tmp_path,
        current_sha="sha-2",
        run_id="2000",
    )
    e = run2[0]
    assert e["delta_basis"] == "fingerprint"
    # Zero churn: both findings carried despite comp/cwe/title drift.
    assert e["added"]["threats"] == []
    assert e["resolved"]["fingerprints"] == []
    assert "+0/-0 vs prior" in e["note"]
    # match_keys are persisted for the next run to diff against exactly.
    assert sorted(e["match_keys"]) == [
        "lib/insecurity.ts|hardcoded-key",
        "lib/insecurity.ts|sig-verify",
    ]


def test_changelog_distinct_findings_same_file_stay_separate(tmp_path):
    """Narrow families must NOT collapse two genuinely-distinct findings that
    share a file: a hardcoded key (hardcoded-key family) and weak password
    hashing (password-weak family) both in lib/insecurity.ts keep separate
    identities, so fixing one shows exactly one resolved."""
    b = _load()
    run1 = b.build_changelog(
        _CL_CFG,
        [
            {
                "id": "T-001",
                "component": "auth",
                "cwe": "CWE-321",
                "title": "Hardcoded RSA private key",
                "evidence": {"file": "lib/insecurity.ts", "line": 21},
            },
            {
                "id": "T-002",
                "component": "auth",
                "cwe": "CWE-916",
                "title": "MD5 password hashing",
                "evidence": {"file": "lib/insecurity.ts", "line": 41},
            },
        ],
        _CL_COMPS,
        [],
        None,
        tmp_path,
        current_sha="sha-1",
        run_id="1000",
    )
    # Run2: the hardcoded key is fixed (gone); weak hashing persists.
    run2 = b.build_changelog(
        _CL_CFG,
        [
            {
                "id": "T-007",
                "component": "auth",
                "cwe": "CWE-916",
                "title": "Weak MD5 password hashing",
                "evidence": {"file": "lib/insecurity.ts", "line": 41},
            },
        ],
        _CL_COMPS,
        [],
        run1,
        tmp_path,
        current_sha="sha-2",
        run_id="2000",
    )
    e = run2[0]
    assert e["added"]["threats"] == []
    assert e["resolved"]["fingerprints"] == ["auth|CWE-321|hardcoded rsa private key"]


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


def test_changelog_same_run_rebuild_stays_initial(tmp_path):
    """Regression (2026-06-19 juice-shop): a same-run yaml rebuild — identical
    commit/date/mode/plugin/analysis — must NOT treat its own prior build as a
    baseline and self-diff into a bogus '+0 / ~0 / -0 · N threats (stable)'
    delta. The prior same-key entry is excluded as a baseline (and replaced by
    the idempotent dedup), so a first/full run stays 'initial'."""
    b = _load()
    run1 = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="sha-1")
    assert run1[0]["delta_basis"] == "initial"
    # Re-build against the run's OWN just-written entry (same key).
    rerun = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], run1, tmp_path, current_sha="sha-1")
    assert len(rerun) == 1
    assert rerun[0]["delta_basis"] == "initial"
    assert rerun[0]["note"] == "first full scan"
    assert rerun[0]["previous_threat_count"] is None
    # A genuine later run (different commit) still diffs normally.
    run2 = b.build_changelog(
        _CL_CFG,
        [
            {"id": "T-001", "component": "comp-a"},
            {"id": "T-002", "component": "comp-a", "cwe": "CWE-79", "title": "XSS"},
        ],
        _CL_COMPS,
        [],
        rerun,
        tmp_path,
        current_sha="sha-2",
    )
    assert run2[0]["delta_basis"] == "fingerprint"
    assert run2[0]["added"]["threats"] == ["T-002"]


def test_changelog_serializes_runtime_rebuild_as_full_assessment(tmp_path):
    cfg = {**_CL_CFG, "mode": "rebuild"}
    changelog = b.build_changelog(
        cfg,
        _CL_THREATS,
        _CL_COMPS,
        [],
        None,
        tmp_path,
        current_sha="sha-1",
        run_id="rebuild-run",
    )

    assert changelog[0]["mode"] == "full"
    assert changelog[0]["note"] == (
        "full rebuild — prior threat model and changelog history were discarded on user request (--rebuild)"
    )


def test_changelog_two_runs_same_commit_day_params_accumulate_via_run_id(tmp_path):
    """Regression (2026-06-26 juice-shop): two SEPARATE --full invocations on the
    same commit + same day + same depth/model collapsed into one because the
    dedup keyed identity on (commit, date, mode, depth, reasoning, versions) —
    indistinguishable from a single run's Phase-11 yaml rebuild. The second
    genuine run SILENTLY OVERWROTE the first as a fresh 'initial' entry instead
    of appending a v2 delta. With a per-invocation `run_id` (.scan-start-epoch)
    the two runs are distinct and accumulate.

    Same commit + same depth, so the second run's basis is ``rescan-unchanged``:
    the code did not change, so the per-finding delta is suppressed (a re-run's
    finding-set difference is LLM analysis nondeterminism, not added/resolved
    findings). The ACCUMULATION (both entries kept) is what this test guards;
    the genuine fingerprint delta over CHANGED code is covered by
    ``test_changelog_full_delta_resolves_by_fingerprint`` (sha-1 → sha-2)."""
    b = _load()
    # Run 1 — run_id "1000". One finding.
    run1 = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="sha-1", run_id="1000")
    assert run1[0]["delta_basis"] == "initial"
    assert run1[0]["run_id"] == "1000"
    # Run 2 — DIFFERENT run_id "2000", IDENTICAL commit/date/params; the LLM
    # happened to surface an extra finding this time (T-002).
    threats2 = [
        {"id": "T-001", "component": "comp-a"},
        {"id": "T-002", "component": "comp-a", "cwe": "CWE-79", "title": "XSS"},
    ]
    run2 = b.build_changelog(_CL_CFG, threats2, _CL_COMPS, [], run1, tmp_path, current_sha="sha-1", run_id="2000")
    # Accumulates — the prior run survives, the new run diffs against it.
    assert len(run2) == 2
    assert run2[0]["run_id"] == "2000"
    assert run2[1]["run_id"] == "1000"
    # Same commit + depth → no per-finding delta claimed on unchanged code.
    assert run2[0]["delta_basis"] == "rescan-unchanged"
    assert run2[0]["added"]["threats"] == []


def test_changelog_same_run_id_rebuild_collapses(tmp_path):
    """The flip side: a Phase-11 yaml rebuild WITHIN one run carries the SAME
    run_id, so it must still collapse (no duplicate, stays 'initial' — no
    self-diff)."""
    b = _load()
    run1 = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], None, tmp_path, current_sha="sha-1", run_id="1000")
    rerun = b.build_changelog(_CL_CFG, _CL_THREATS, _CL_COMPS, [], run1, tmp_path, current_sha="sha-1", run_id="1000")
    assert len(rerun) == 1
    assert rerun[0]["delta_basis"] == "initial"
    assert rerun[0]["note"] == "first full scan"


def test_changelog_run_id_distinguishes_from_legacy_entry(tmp_path):
    """A pre-run_id entry (no run_id key) is, by definition, from an earlier
    invocation. When THIS run has a run_id, that legacy entry must be preserved
    and diffed against — never collapsed — even on the same commit/day/params."""
    b = _load()
    import datetime as _dt

    legacy_prior = [
        {
            "version": 1,
            "date": _dt.date.today().isoformat(),
            "mode": "full",
            "assessment_depth": "standard",
            "reasoning_model": "sonnet-economy",
            "current_sha": "sha-1",
            "threat_count": 1,
            "fingerprints": ["comp-a|none|"],
            "added": {"threats": ["T-001"]},
            "changed": {"threats": []},
            "resolved": {"threats": []},
        }
    ]
    threats2 = [
        {"id": "T-001", "component": "comp-a"},
        {"id": "T-002", "component": "comp-a", "cwe": "CWE-79", "title": "XSS"},
    ]
    cl = b.build_changelog(_CL_CFG, threats2, _CL_COMPS, [], legacy_prior, tmp_path, current_sha="sha-1", run_id="2000")
    assert len(cl) == 2  # legacy entry preserved, not overwritten
    assert cl[1].get("run_id") is None
    assert cl[0]["run_id"] == "2000"


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
    run2 = b.build_changelog(_CL_CFG, threats2, _CL_COMPS, [], run1, tmp_path, current_sha="sha-2", mitigations=mits2)
    assert run2[0]["added"]["mitigations"] == ["M-002"]


def test_changelog_mitigation_legacy_prior_no_baseline(tmp_path):
    b = _load()
    # A prior entry that predates mitigation fingerprints → cannot diff, so we
    # honestly report no added mitigations rather than marking all of them new.
    legacy_prior = [{"version": 1, "date": "2026-06-12", "mode": "full", "added": {"threats": ["T-001"]}}]
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
    (cache / "baseline.json").write_text(json.dumps({"last_run_depth": prior_depth, "stride_files": sf}))


def _prior_threat(tid, comp, cwe, title):
    return {
        "id": tid,
        "component": comp,
        "cwe": cwe,
        "title": title,
        "risk": "High",
        "likelihood": "Medium",
        "impact": "High",
    }


def test_reanalyzed_component_ids_detects_sha_mismatch(tmp_path):
    _setup_incremental(
        tmp_path,
        prior_depth="thorough",
        stride={
            "auth": (b'{"a":1}', b'{"a":2}'),  # changed -> re-analyzed
            "api": (b'{"b":1}', b'{"b":1}'),  # unchanged -> carried-forward
        },
    )
    assert b._reanalyzed_component_ids(tmp_path) == {"auth"}


def test_reanalyzed_component_ids_none_without_baseline(tmp_path):
    assert b._reanalyzed_component_ids(tmp_path) is None


def test_reconcile_carries_dropped_prior_threat_at_shallower_depth(tmp_path):
    _setup_incremental(tmp_path, prior_depth="thorough", stride={"auth": (b"old", b"new")})
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    new_threats = [{"id": "T-001", "component": "auth", "cwe": "CWE-89", "title": "SQLi (db.ts:3)"}]
    out, recon = b.reconcile_incremental_threats(new_threats, prior, [{"id": "auth"}], tmp_path, "quick", {})
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
    out, recon = b.reconcile_incremental_threats([], prior, [{"id": "auth"}], tmp_path, "quick", resolved_prior)
    assert not [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    assert recon["resolved_reason_by_id"] == {"T-007": "MFA enforced at login.ts:10"}


def test_reconcile_no_carry_at_equal_depth(tmp_path):
    _setup_incremental(tmp_path, prior_depth="quick", stride={"auth": (b"old", b"new")})
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    out, recon = b.reconcile_incremental_threats([], prior, [{"id": "auth"}], tmp_path, "quick", {})
    assert not [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    # equal depth → recorded as resolved, not silently dropped
    assert recon["resolved_reason_by_id"]["T-007"].startswith("not reproduced")


def test_reconcile_skips_carried_forward_component(tmp_path):
    # api unchanged → carried-forward → its prior threats must NOT be touched
    _setup_incremental(tmp_path, prior_depth="thorough", stride={"api": (b"same", b"same")})
    prior = {"threats": [_prior_threat("T-007", "api", "CWE-89", "SQLi (q.ts:9)")]}
    out, recon = b.reconcile_incremental_threats([], prior, [{"id": "api"}], tmp_path, "quick", {})
    assert out == []  # nothing injected
    assert recon["resolved_reason_by_id"] == {}
    assert recon["carried_forward_ids"] == ["api"]


def _prior_threat_with_file(tid, comp, cwe, title, file, line):
    t = _prior_threat(tid, comp, cwe, title)
    t["evidence"] = [{"file": file, "line": line}]
    return t


def test_reconcile_recognises_reproduced_finding_across_cwe_drift(tmp_path):
    """Regression (2026-06-26): an incremental re-scan that re-emits a prior
    finding with a drifted component/CWE/title but the SAME evidence file must
    recognise it as reproduced via the file|cwe-family match key — NOT mark it
    resolved at equal depth (a false "fixed" claim)."""
    _setup_incremental(tmp_path, prior_depth="quick", stride={"auth": (b"old", b"new")})
    prior = {
        "threats": [
            _prior_threat_with_file(
                "T-007", "auth", "CWE-798", "Hardcoded RSA private key enabling JWT forgery", "lib/insecurity.ts", 21
            )
        ]
    }
    # Re-emitted: component renamed, CWE swapped within hardcoded-key family
    # (798→321), title reworded — same file.
    new_threats = [
        _prior_threat_with_file(
            "T-001",
            "express-backend",
            "CWE-321",
            "Hardcoded RSA private key enables arbitrary JWT signing",
            "lib/insecurity.ts",
            21,
        )
    ]
    out, recon = b.reconcile_incremental_threats(new_threats, prior, [{"id": "auth"}], tmp_path, "quick", {})
    # Recognised as present: no bogus resolved, and not double-counted as added.
    assert recon["resolved_reason_by_id"] == {}
    assert recon["added_ids"] == []
    assert not [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]


def test_reconcile_no_duplicate_carry_across_cwe_drift_shallower(tmp_path):
    """Same drift at SHALLOWER depth must not DUPLICATE the finding: the prior
    threat is recognised as re-emitted (match key) and not carried alongside its
    own re-emission."""
    _setup_incremental(tmp_path, prior_depth="thorough", stride={"auth": (b"old", b"new")})
    prior = {
        "threats": [_prior_threat_with_file("T-007", "auth", "CWE-770", "No rate limit on websocket", "lib/ws.ts", 19)]
    }
    new_threats = [
        _prior_threat_with_file(
            "T-001", "realtime-channel", "CWE-400", "No rate limiting on socket.io connections", "lib/ws.ts", 19
        )
    ]
    out, recon = b.reconcile_incremental_threats(new_threats, prior, [{"id": "auth"}], tmp_path, "quick", {})
    assert not [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]
    assert len(out) == 1  # only the re-emitted finding, no carried duplicate


def test_reconcile_distinct_findings_same_file_stay_separate(tmp_path):
    """Narrow families must not over-merge in the incremental path either: a
    distinct finding in a re-analyzed file (different family) that is genuinely
    gone is still recorded resolved at equal depth."""
    _setup_incremental(tmp_path, prior_depth="quick", stride={"auth": (b"old", b"new")})
    prior = {
        "threats": [
            _prior_threat_with_file("T-007", "auth", "CWE-321", "Hardcoded key", "lib/insecurity.ts", 21),
            _prior_threat_with_file("T-008", "auth", "CWE-916", "MD5 hashing", "lib/insecurity.ts", 41),
        ]
    }
    # Only the hardcoded key persists; weak hashing is gone.
    new_threats = [_prior_threat_with_file("T-001", "auth", "CWE-321", "Hardcoded RSA key", "lib/insecurity.ts", 21)]
    out, recon = b.reconcile_incremental_threats(new_threats, prior, [{"id": "auth"}], tmp_path, "quick", {})
    # Hardcoded key recognised (present); weak hashing recorded resolved.
    assert recon["resolved_reason_by_id"].get("T-008", "").startswith("not reproduced")
    assert "T-007" not in recon["resolved_reason_by_id"]


def test_reconcile_no_double_count_when_reemitted(tmp_path):
    _setup_incremental(tmp_path, prior_depth="thorough", stride={"auth": (b"old", b"new")})
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    # analyzer re-emitted the same finding (same fingerprint) under a fresh id
    new_threats = [{"id": "T-001", "component": "auth", "cwe": "CWE-287", "title": "Weak auth (login.ts:10)"}]
    out, recon = b.reconcile_incremental_threats(new_threats, prior, [{"id": "auth"}], tmp_path, "quick", {})
    assert len(out) == 1  # no re-injection
    assert not [t for t in out if t.get("evidence_check") == "carried-unverified-shallower-depth"]


def test_reconcile_noop_on_full_run(tmp_path):
    # no baseline.json → full/first run → no-op, recon_info None
    prior = {"threats": [_prior_threat("T-007", "auth", "CWE-287", "Weak auth (login.ts:10)")]}
    out, recon = b.reconcile_incremental_threats(
        [{"id": "T-001", "component": "auth"}], prior, [{"id": "auth"}], tmp_path, "quick", {}
    )
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
        [{"id": "auth"}, {"id": "api"}],
        [],
        None,
        tmp_path,
        current_sha="sha-x",
        recon_info=recon,
    )
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
        {
            "id": "M-004",
            "title": "Enforce object-level (ownership) authorization",
            "threat_ids": ["T-001"],
            "severity": "High",
            "priority": "P2",
        },
        {
            "id": "M-022",
            "title": "Enforce object-level (ownership) authorization",
            "threat_ids": ["T-002"],
            "severity": "Critical",
            "priority": "P1",
        },
    ]
    out_threats, out_mits = b.dedupe_mitigation_controls(threats, mits)
    assert len(out_mits) == 1
    surv = out_mits[0]
    assert surv["id"] == "M-004"  # lowest id survives
    assert surv["threat_ids"] == ["T-001", "T-002"]  # unioned
    assert surv["severity"] == "Critical"  # max across the group
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
    assert len(out_mits) == 2  # different controls untouched
    assert out_threats[0]["mitigation_ids"] == ["M-001", "M-002"]


# ---------------------------------------------------------------------------
# Instance-level delta (Regel C) — partial-progress visibility
# ---------------------------------------------------------------------------


def test_instance_fingerprints_one_per_instance():
    t = {
        "component": "c",
        "cwe": "CWE-862",
        "title": "Sensitive routes",
        "instances": [{"file": "server.ts", "line": 310}, {"file": "server.ts", "line": 311}],
    }
    fps = b._instance_fingerprints(t)
    assert len(fps) == 2
    assert all(fp.startswith("c|CWE-862|sensitive routes|server.ts:") for fp in fps)


def test_instance_fingerprints_degrades_to_evidence_for_non_systemic():
    t = {"component": "c", "cwe": "CWE-89", "title": "SQLi", "evidence": {"file": "login.ts", "line": 5}}
    assert b._instance_fingerprints(t) == ["c|CWE-89|sqli|login.ts:5"]


def test_changelog_instance_delta_partial_resolution(tmp_path):
    sysfind = {
        "id": "T-001",
        "component": "comp-a",
        "cwe": "CWE-862",
        "title": "Sensitive routes",
        "instances": [{"file": "server.ts", "line": ln} for ln in (310, 311, 407)],
    }
    run1 = b.build_changelog(_CL_CFG, [sysfind], _CL_COMPS, [], None, tmp_path, current_sha="s1")
    assert len(run1[0]["instance_fingerprints"]) == 3
    assert run1[0]["added"]["instances"] == []  # first run stays quiet

    # run2: one location (407) fixed; the finding itself is unchanged.
    sysfind2 = dict(sysfind, instances=[{"file": "server.ts", "line": ln} for ln in (310, 311)])
    run2 = b.build_changelog(_CL_CFG, [sysfind2], _CL_COMPS, [], run1, tmp_path, current_sha="s2")
    assert run2[0]["added"]["threats"] == []  # finding-level: nothing new/gone
    assert run2[0]["resolved"]["fingerprints"] == []
    resolved_inst = run2[0]["resolved"]["instances"]  # instance-level: 1 resolved
    assert len(resolved_inst) == 1
    assert "server.ts:407" in resolved_inst[0]


def test_instance_fingerprints_tolerates_list_shaped_evidence():
    # Regression: evidence is a LIST of {file,line} in the final yaml.
    t = {
        "component": "c",
        "cwe": "CWE-922",
        "title": "Token in storage",
        "evidence": [{"file": "oauth.ts", "line": 51}, {"file": "oauth.ts", "line": 52}],
    }
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


# ===========================================================================
# Coverage extensions (2026-06-15): end-to-end main() against the committed
# _last-run fixture, plus targeted helper/error branches.
# ===========================================================================
import shutil  # noqa: E402

import pytest  # noqa: E402

_LAST_RUN = ROOT / "tests" / "fixtures" / "e2e" / "_last-run"
_REPAIR_RUN = ROOT / "tests" / "fixtures" / "e2e" / "_repair-run"
_LAST_RUN_REQ = ROOT / "tests" / "fixtures" / "e2e" / "_last-run-req"

# `_last-run` is a git-ignored local run dir (regenerate via `make e2e-full`).
# Skip the tests that consume it when it is absent so a fresh checkout / CI
# stays green; the `_repair-run` / `_last-run-req` variants below already guard.
_requires_last_run = pytest.mark.skipif(
    not (_LAST_RUN / "threat-model.yaml").is_file(),
    reason="_last-run fixture absent (git-ignored; regenerate via `make e2e-full`)",
)


def _copy_run(src: Path, tmp_path: Path) -> Path:
    dest = tmp_path / "run"
    shutil.copytree(src, dest)
    return dest


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["build_threat_model_yaml.py", *argv])
    return b.main()


@_requires_last_run
def test_main_dry_run_last_run_fixture(tmp_path, monkeypatch, capsys):
    """End-to-end dry-run against the real --quick --requirements run dir."""
    run = _copy_run(_LAST_RUN, tmp_path)
    rc = _run_main(monkeypatch, [str(run), "--plugin-root", str(ROOT), "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    doc = yaml.safe_load(out)
    assert "meta" in doc and "threats" in doc and "mitigations" in doc
    # dry-run must NOT have rewritten the yaml on disk via atomic_write
    # (the fixture's own yaml is still present, but main only printed).
    assert isinstance(doc["threats"], list)


@_requires_last_run
def test_main_writes_and_schema_validates(tmp_path, monkeypatch, capsys):
    """Full write path: atomic_write + schema-validate subprocess (rc 0).

    The validator subprocess is mocked to return success so it does not spawn
    a child `python3 -m coverage` that would clobber the parent's parallel
    .coverage SQLite file (observed: 'no such table: tracer').
    """
    run = _copy_run(_LAST_RUN, tmp_path)

    class _OkProc:
        returncode = 0
        stdout = ""
        stderr = ""

    real_run = b.subprocess.run

    def fake_run(cmd, *a, **k):
        if any("validate_intermediate.py" in str(c) for c in cmd):
            return _OkProc()
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(b.subprocess, "run", fake_run)
    rc = _run_main(monkeypatch, [str(run), "--plugin-root", str(ROOT)])
    assert rc == 0
    out_yaml = run / "threat-model.yaml"
    assert out_yaml.is_file()
    doc = yaml.safe_load(out_yaml.read_text())
    assert doc["meta"]
    err = capsys.readouterr().err
    assert "built deterministically" in err


def test_main_repair_run_fixture(tmp_path, monkeypatch):
    """Second committed fixture variant exercises a different input mix."""
    if not _REPAIR_RUN.is_dir():
        pytest.skip("repair-run fixture absent")
    run = _copy_run(_REPAIR_RUN, tmp_path)
    rc = _run_main(monkeypatch, [str(run), "--plugin-root", str(ROOT), "--dry-run"])
    assert rc == 0


def test_main_requirements_run_fixture(tmp_path, monkeypatch):
    if not _LAST_RUN_REQ.is_dir():
        pytest.skip("requirements-run fixture absent")
    run = _copy_run(_LAST_RUN_REQ, tmp_path)
    rc = _run_main(monkeypatch, [str(run), "--plugin-root", str(ROOT), "--dry-run"])
    assert rc == 0


def test_main_output_dir_missing_returns_2(tmp_path, monkeypatch, capsys):
    rc = _run_main(monkeypatch, [str(tmp_path / "nope"), "--plugin-root", str(ROOT)])
    assert rc == 2
    assert "output_dir does not exist" in capsys.readouterr().err


@_requires_last_run
def test_main_schema_validation_failure_returns_5(tmp_path, monkeypatch, capsys):
    """A validator that always fails → main returns 5."""
    run = _copy_run(_LAST_RUN, tmp_path)

    class _FakeProc:
        returncode = 1
        stdout = "schema boom stdout"
        stderr = "schema boom stderr"

    real_run = b.subprocess.run

    def fake_run(cmd, *a, **k):
        # Only intercept the validate_intermediate.py invocation.
        if any("validate_intermediate.py" in str(c) for c in cmd):
            return _FakeProc()
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(b.subprocess, "run", fake_run)
    prior = (run / "threat-model.yaml").read_bytes()
    rc = _run_main(monkeypatch, [str(run), "--plugin-root", str(ROOT)])
    assert rc == 5
    assert (run / "threat-model.yaml").read_bytes() == prior
    assert not (run / ".threat-model.yaml.pending").exists()
    assert "schema validation failed" in capsys.readouterr().err


@_requires_last_run
def test_main_fails_closed_when_validator_absent(tmp_path, monkeypatch, capsys):
    """No validator means no canonical output publication."""
    run = _copy_run(_LAST_RUN, tmp_path)
    # Point plugin-root at an empty dir lacking scripts/validate_intermediate.py.
    fake_plugin = tmp_path / "empty_plugin"
    fake_plugin.mkdir()
    prior = (run / "threat-model.yaml").read_bytes()
    rc = _run_main(monkeypatch, [str(run), "--plugin-root", str(fake_plugin)])
    assert rc == 5
    assert (run / "threat-model.yaml").read_bytes() == prior
    assert "schema validator missing" in capsys.readouterr().err


# --- helper / error branches -------------------------------------------------


def test_load_json_required_missing_exits_3(tmp_path):
    with pytest.raises(SystemExit) as exc:
        b._load_json(tmp_path / "absent.json", required=True)
    assert exc.value.code == 3


def test_load_json_optional_missing_returns_none(tmp_path):
    assert b._load_json(tmp_path / "absent.json") is None


def test_load_json_malformed_exits_1(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not json")
    with pytest.raises(SystemExit) as exc:
        b._load_json(p)
    assert exc.value.code == 1


def test_load_yaml_missing_and_malformed(tmp_path, capsys):
    assert b._load_yaml(tmp_path / "absent.yaml") is None
    bad = tmp_path / "bad.yaml"
    bad.write_text("key: [unclosed\n")
    assert b._load_yaml(bad) is None
    assert "malformed YAML" in capsys.readouterr().err


def test_git_returns_none_on_nonrepo(tmp_path):
    # A non-git dir → git returns non-zero → None.
    assert b._git(["rev-parse", "HEAD"], tmp_path) is None


def test_git_handles_missing_binary(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("no git")

    monkeypatch.setattr(b.subprocess, "run", boom)
    assert b._git(["rev-parse", "HEAD"], tmp_path) is None


def test_read_recon_project_variants(tmp_path):
    assert b._read_recon_project(tmp_path / "absent.md") is None
    p = tmp_path / ".recon-summary.md"
    p.write_text("# Recon\n\n**Project**:  My App  \n\nmore text\n")
    assert b._read_recon_project(p) == "My App"
    p.write_text("# Recon\n\nno project line here\n")
    assert b._read_recon_project(p) is None


def test_plugin_version_variants(tmp_path):
    # missing plugin.json
    assert b._plugin_version(tmp_path) == ("unknown", 1)
    # valid
    pj_dir = tmp_path / ".claude-plugin"
    pj_dir.mkdir()
    (pj_dir / "plugin.json").write_text(json.dumps({"version": "0.4.0", "analysis_version": 2}))
    assert b._plugin_version(tmp_path) == ("0.4.0", 2)
    # malformed JSON → fallback
    (pj_dir / "plugin.json").write_text("{ bad")
    assert b._plugin_version(tmp_path) == ("unknown", 1)


def test_carry_forward_hit_and_miss(capsys):
    assert b._carry_forward({"components": [{"id": "c1"}]}, "components", ".components.json") == [{"id": "c1"}]
    with pytest.raises(SystemExit) as exc:
        b._carry_forward(None, "components", ".components.json")
    assert exc.value.code == 4
    assert "neither .components.json" in capsys.readouterr().err


def test_load_last_run_depth_variants(tmp_path):
    assert b._load_last_run_depth(tmp_path) is None  # no baseline.json
    cache = tmp_path / ".appsec-cache"
    cache.mkdir()
    bp = cache / "baseline.json"
    bp.write_text(json.dumps({"last_run_depth": "thorough"}))
    assert b._load_last_run_depth(tmp_path) == "thorough"
    bp.write_text("{ malformed")
    assert b._load_last_run_depth(tmp_path) is None


def test_reanalyzed_component_ids_variants(tmp_path):
    # no baseline → None
    assert b._reanalyzed_component_ids(tmp_path) is None
    cache = tmp_path / ".appsec-cache"
    cache.mkdir()
    bp = cache / "baseline.json"
    # malformed baseline → None
    bp.write_text("{ bad")
    assert b._reanalyzed_component_ids(tmp_path) is None
    # baseline with a stride file whose hash differs → changed set
    import hashlib as _h

    sfile = tmp_path / ".stride-comp-a.json"
    sfile.write_text('{"new": true}')
    bp.write_text(
        json.dumps({"stride_files": {"comp-a": {"sha256": "sha256:deadbeef"}, "comp-gone": {"sha256": "sha256:x"}}})
    )
    changed = b._reanalyzed_component_ids(tmp_path)
    assert changed == {"comp-a"}  # comp-gone has no on-disk stride file → skipped
    # matching hash → not changed
    real = "sha256:" + _h.sha256(sfile.read_bytes()).hexdigest()
    bp.write_text(json.dumps({"stride_files": {"comp-a": {"sha256": real}}}))
    assert b._reanalyzed_component_ids(tmp_path) == set()


# --- build_threats branches --------------------------------------------------


def test_build_threats_skips_info_stubs_and_missing_id():
    merged = {
        "threats": [
            {
                "t_id": "T-001",
                "title": "SQL Injection — routes/x.ts:1",
                "component_id": "c1",
                "likelihood": "High",
                "risk": "High",
                "cwe": "CWE-89",
                "evidence": {"file": "x.ts", "line": 1},
            },
            # info-stub via likelihood
            {"t_id": "T-002", "title": "note", "likelihood": "info"},
            # info-stub via risk
            {"t_id": "T-003", "title": "note", "risk": "info"},
            # missing id entirely
            {"title": "orphan note", "likelihood": "High"},
            # evidence None → []
            {
                "t_id": "T-004",
                "title": "XSS — routes/y.ts:2",
                "component_id": "c1",
                "likelihood": "Medium",
                "risk": "Medium",
                "evidence": None,
                "affected_parameter": "x" * 60,
            },
            # Refuted candidates are evidence-verification output, not active
            # findings. They stay in .threats-merged.json for audit but do not
            # enter threat-model.yaml.
            {
                "t_id": "T-005",
                "title": "Already fixed — routes/z.ts:3",
                "component_id": "c1",
                "likelihood": "High",
                "risk": "High",
                "cwe": "CWE-89",
                "evidence": {"file": "z.ts", "line": 3},
                "evidence_check": "refuted",
            },
        ]
    }
    threats, warnings = b.build_threats(merged)
    ids = [t["id"] for t in threats]
    assert ids == ["T-001", "T-004"]
    # object evidence wrapped to list
    assert threats[0]["evidence"] == [{"file": "x.ts", "line": 1}]
    # None evidence → empty list
    assert threats[1]["evidence"] == []
    # long affected_parameter clamped to <=40 with ellipsis
    assert len(threats[1]["affected_parameter"]) <= 40
    assert threats[1]["affected_parameter"].endswith("…")
    assert any("observation-stub" in w for w in warnings)
    assert any("evidence-refuted" in w for w in warnings)


def test_build_threats_applies_and_can_override_register_severity_floor():
    merged = {
        "threats": [
            {
                "t_id": "T-001",
                "title": "Low-impact diagnostic information disclosure",
                "component_id": "c1",
                "likelihood": "Low",
                "risk": "Low",
                "effective_severity": "Low",
                "cwe": "CWE-200",
                "evidence": {"file": "src/info.py", "line": 4},
            }
        ]
    }
    default_threats, default_warnings = b.build_threats(merged)
    assert default_threats == []
    assert any("below severity floor (medium)" in warning for warning in default_warnings)

    low_threats, low_warnings = b.build_threats(merged, register_floor="low")
    assert [threat["id"] for threat in low_threats] == ["T-001"]
    assert not low_warnings


def test_build_mitigations_bumps_severity_to_max():
    threats = [
        {"id": "T-001", "risk": "Medium", "mitigation_ids": ["M-001"], "mitigation_title": "Fix it"},
        {"id": "T-002", "risk": "Critical", "mitigation_ids": ["M-001"]},
    ]
    mits = b.build_mitigations(threats)
    assert len(mits) == 1
    assert mits[0]["severity"] == "Critical"  # bumped from Medium to Critical
    assert mits[0]["priority"] == "P1"
    assert sorted(mits[0]["threat_ids"]) == ["T-001", "T-002"]


def test_build_mitigations_fallback_synthesis_omits_how_when_steps_present():
    """A threat with no mitigation_ids but structured remediation.steps gets a
    synthesised M-card via the fallback path. The card must NOT carry a `how`
    paragraph duplicating those same steps — compose's render-time fallback
    renders `remediation.steps` as an ordered list from the source threat
    (juice-shop 2026-07-02 / M-038: identical content rendered twice)."""
    threats = [
        {
            "id": "T-001",
            "risk": "Critical",
            "mitigation_title": "Add JWT-verifying middleware",
            "remediation": {
                "effort": "Medium",
                "steps": ["Add middleware.", "Attach the verified user.", "Update the client."],
            },
        },
    ]
    mits = b.build_mitigations(threats)
    assert len(mits) == 1
    assert mits[0]["title"] == "Add JWT-verifying middleware"
    assert "how" not in mits[0]
    assert threats[0]["mitigation_ids"] == [mits[0]["id"]]


# --- apply_mitigation_overrides branches -------------------------------------


def test_apply_mitigation_overrides_none_sidecar_passthrough():
    base = [{"id": "M-001", "title": "x", "threat_ids": ["T-001"]}]
    out, warnings = b.apply_mitigation_overrides(base, None)
    assert out == base and warnings == []


def test_apply_mitigation_overrides_split_and_unknown_source():
    base = [{"id": "M-001", "title": "Auth", "threat_ids": ["T-001"], "remediation": {"effort": "Low"}}]
    sidecar = {
        "splits": [
            {
                "source_mid": "M-001",
                "into": [
                    {"id_suffix": "a", "title": "Part A", "threat_ids": ["T-001"]},
                    {"id_suffix": "b", "title": "Part B"},
                ],
            },
            {"source_mid": "M-999", "into": []},  # unknown source → warning
        ]
    }
    out, warnings = b.apply_mitigation_overrides(base, sidecar)
    ids = {m["id"] for m in out}
    assert ids == {"M-001a", "M-001b"}
    assert any("not in baseline" in w for w in warnings)


def test_apply_mitigation_overrides_addition_collision_subset_and_new():
    base = [
        {"id": "M-001", "title": "Base one", "threat_ids": ["T-001", "T-002"]},
    ]
    sidecar = {
        "additions": [
            # Rule 1: ID collision → overlay authored fields
            {
                "id": "M-001",
                "title": "Authored title",
                "description": "why",
                "reference": "http://x",
                "priority": "P1",
                "effort": "High",
                "kind": "detect",
            },
            # Rule 2: threat_ids subset of M-001 → merge onto it
            {"id": "M-050", "title": "Subset fix", "threat_ids": ["T-001"]},
            # New: genuinely new threat set → appended
            {
                "id": "M-060",
                "title": "New fix",
                "threat_ids": ["T-999"],
                "severity": "High",
                "description": "d",
                "reference": "r",
                "remediation": {"effort": "Low"},
                "kind": "fix",
            },
        ]
    }
    out, warnings = b.apply_mitigation_overrides(base, sidecar)
    by_id = {m["id"]: m for m in out}
    # Both the ID-collision addition AND the subset addition overlay onto M-001;
    # the later subset addition's authored title wins (current behavior).
    assert by_id["M-001"]["title"] == "Subset fix"
    assert by_id["M-001"]["description"] == "why"
    assert by_id["M-001"]["priority"] == "P1"
    assert "M-050" not in by_id  # merged onto M-001, not added
    assert "M-060" in by_id
    assert by_id["M-060"]["severity"] == "High"
    assert by_id["M-060"]["priority"] == "P2"  # derived from High
    assert any("merged onto baseline" in w for w in warnings)
    assert any("true additions" in w for w in warnings)


# --- prune_dangling_mitigation_threat_ids ------------------------------------


def test_prune_dangling_mitigation_threat_ids_drops_unknown_tid():
    # Reproduces juice-shop 2026-06-28 M-901→T-034: an authored supply-chain
    # mitigation names a threat (T-034) the final threat set does not contain.
    threats = [{"id": "T-031"}, {"id": "T-015"}, {"id": "T-016"}]
    mitigations = [
        {"id": "M-901", "threat_ids": ["T-031", "T-034", "T-015", "T-016"]},
        {"id": "M-001", "threat_ids": ["T-015"]},
    ]
    out, warnings = b.prune_dangling_mitigation_threat_ids(threats, mitigations)
    by_id = {m["id"]: m for m in out}
    assert by_id["M-901"]["threat_ids"] == ["T-031", "T-015", "T-016"]  # T-034 dropped, order kept
    assert by_id["M-001"]["threat_ids"] == ["T-015"]  # untouched
    assert any("M-901" in w and "T-034" in w for w in warnings)


def test_prune_dangling_mitigation_threat_ids_noop_when_all_resolve():
    threats = [{"id": "T-001"}, {"id": "T-002"}]
    mitigations = [{"id": "M-001", "threat_ids": ["T-001", "T-002"]}]
    out, warnings = b.prune_dangling_mitigation_threat_ids(threats, mitigations)
    assert out[0]["threat_ids"] == ["T-001", "T-002"]
    assert warnings == []


# --- prune_dangling_weakness_instances ---------------------------------------


def test_prune_dangling_weakness_instances_drops_below_floor_instance():
    # Reproduces juice-shop 2026-07-16 W-006→T-068: build_threats dropped T-068
    # below the medium severity floor (register goes sparse), but the weakness
    # register — built pre-drop — still names it as an instance. Left in, it renders
    # a titleless [F-068] phantom link + inflates the md finding count.
    threats = [{"id": "T-025"}, {"id": "T-038"}, {"id": "T-067"}, {"id": "T-075"}]
    weaknesses = [
        {
            "id": "W-006",
            "instance_count": 5,
            "instances": [
                {"id": "T-025", "file": "a"},
                {"id": "T-038", "file": "b"},
                {"id": "T-067", "file": "c"},
                {"id": "T-068", "file": "d"},  # below-floor, dropped from threats[]
            ],
        }
    ]
    out, warnings = b.prune_dangling_weakness_instances(threats, weaknesses)
    kept = [i["id"] for i in out[0]["instances"]]
    assert kept == ["T-025", "T-038", "T-067"]  # T-068 pruned, order kept
    assert out[0]["instance_count"] == 3  # count field updated
    assert any("W-006" in w and "T-068" in w for w in warnings)


def test_prune_dangling_weakness_instances_noop_when_all_resolve():
    threats = [{"id": "T-001"}, {"id": "T-002"}]
    weaknesses = [{"id": "W-001", "instances": [{"id": "T-001"}, {"id": "T-002"}]}]
    out, warnings = b.prune_dangling_weakness_instances(threats, weaknesses)
    assert [i["id"] for i in out[0]["instances"]] == ["T-001", "T-002"]
    assert warnings == []


def test_prune_practice_evidence_removes_refuted_site_entirely():
    # Reproduces juice-shop 2026-08-02 W-007→T-035. The evidence verifier read
    # lib/insecurity.ts:53 and contradicted the claim (denyAll() uses
    # Math.random() deliberately to reject every token). build_threats excludes
    # such a candidate from threats[] — "must never reach the report, exports,
    # or mitigation register" — but the register is a second path into the yaml.
    # A refuted location is NOT a practice site: the whole entry must go, or the
    # report keeps asserting a weak-crypto site that was proven wrong.
    threats = [{"id": "T-001"}]
    weaknesses = [
        {
            "id": "W-007",
            "observable_backing": {
                "practice_evidence": [
                    {"id": "T-001", "file": "models/user.ts", "line": 76},
                    {"id": "T-035", "file": "lib/insecurity.ts", "line": 53},
                ]
            },
        }
    ]
    out, warnings = b.prune_dangling_weakness_instances(threats, weaknesses, refuted_ids={"T-035"})
    practice = out[0]["observable_backing"]["practice_evidence"]
    assert [p.get("file") for p in practice] == ["models/user.ts"]
    assert "lib/insecurity.ts" not in str(practice)  # site gone, not just the link
    assert any("W-007" in w and "T-035" in w and "refuted" in w for w in warnings)


def test_prune_practice_evidence_below_floor_keeps_site_drops_only_the_id():
    # The severity floor is a reporting threshold, not a truth claim — the
    # observation still stands. Keep the site, strip the unresolvable id so the
    # composer renders a bare location instead of a titleless [F-NNN] phantom.
    threats = [{"id": "T-001"}]
    weaknesses = [
        {
            "id": "W-002",
            "instances": [{"id": "T-001"}, {"id": "T-101"}],
            "observable_backing": {
                "practice_evidence": [
                    {"id": "T-001", "file": "a.ts", "line": 1},
                    {"id": "T-101", "file": "b.ts", "line": 2},
                ]
            },
        }
    ]
    out, warnings = b.prune_dangling_weakness_instances(threats, weaknesses)
    assert [i["id"] for i in out[0]["instances"]] == ["T-001"]  # instance dropped whole
    practice = out[0]["observable_backing"]["practice_evidence"]
    assert [p.get("file") for p in practice] == ["a.ts", "b.ts"]  # both sites survive
    assert practice[0]["id"] == "T-001"  # resolvable id untouched
    assert "id" not in practice[1]  # dangling id stripped
    assert any("W-002" in w and "T-101" in w and "practice-evidence" in w for w in warnings)


def test_prune_practice_evidence_noop_when_all_resolve():
    threats = [{"id": "T-001"}]
    weaknesses = [
        {
            "id": "W-003",
            "observable_backing": {"practice_evidence": [{"id": "T-001", "file": "a.ts"}]},
        }
    ]
    out, warnings = b.prune_dangling_weakness_instances(threats, weaknesses)
    assert out[0]["observable_backing"]["practice_evidence"] == [{"id": "T-001", "file": "a.ts"}]
    assert warnings == []


def test_prune_practice_evidence_tolerates_id_less_and_non_dict_sites():
    threats = [{"id": "T-001"}]
    weaknesses = [
        {
            "id": "W-004",
            "observable_backing": {"practice_evidence": [{"file": "a.ts", "line": 3}, "bare-string"]},
        }
    ]
    out, warnings = b.prune_dangling_weakness_instances(threats, weaknesses, refuted_ids={"T-035"})
    assert out[0]["observable_backing"]["practice_evidence"] == [{"file": "a.ts", "line": 3}, "bare-string"]
    assert warnings == []


def test_refuted_threat_ids_reads_t_id_and_ignores_verified():
    merged = {
        "threats": [
            {"t_id": "T-001", "evidence_check": "verified"},
            {"t_id": "T-035", "evidence_check": "refuted"},
            {"t_id": "T-098", "evidence_check": "unchecked"},
            {"id": "T-050", "evidence_check": "REFUTED"},  # legacy key + case
            {"evidence_check": "refuted"},  # id-less → skipped, must not raise
        ]
    }
    assert b.refuted_threat_ids(merged) == {"T-035", "T-050"}
    assert b.refuted_threat_ids({}) == set()


# --- build_meta_findings branches --------------------------------------------


def test_build_meta_findings_no_sidecar_carries_prior():
    prior = {"meta_findings": [{"id": "MF-001", "title": "kept"}]}
    assert b.build_meta_findings(prior, [None, {"findings": []}]) == [{"id": "MF-001", "title": "kept"}]


def test_build_meta_findings_no_sidecar_no_prior_returns_empty():
    assert b.build_meta_findings(None, [None]) == []


def test_build_meta_findings_allocates_ids_after_manual_prior():
    prior = {
        "meta_findings": [
            {"id": "MF-005", "title": "manual one", "manual": True},
            {"id": "MF-002", "title": "auto, dropped", "manual": False},
        ]
    }
    sidecars = [
        {
            "findings": [
                {"control": "Dependabot", "category": "Patch", "source": "sca", "derived_from": ["T-001", "bad"]},
                # duplicate key (same source/title/category) → deduped
                {"control": "Dependabot", "category": "Patch", "source": "sca"},
            ]
        }
    ]
    out = b.build_meta_findings(prior, sidecars)
    # manual prior kept, auto prior dropped, one new finding (dup removed)
    ids = [m["id"] for m in out]
    assert "MF-005" in ids
    assert len([m for m in out if m.get("source") == "sca"]) == 1
    new = [m for m in out if m.get("source") == "sca"][0]
    # id continues after max manual id (MF-005) → MF-006
    assert new["id"] == "MF-006"
    # derived_from filtered to valid T-ids only
    assert new["derived_from"] == ["T-001"]


def test_build_meta_findings_skips_non_dict_sidecar_and_findings():
    sidecars = ["notdict", {"findings": "notalist"}, {"findings": [{"control": "X", "source": "s"}]}]
    out = b.build_meta_findings(None, sidecars)
    assert len(out) == 1
    assert out[0]["id"] == "MF-001"


# --- build_tier_root_causes branches -----------------------------------------


def test_build_tier_root_causes_sidecar_wins():
    sidecar = {"tier_root_causes": {"edge": ["bullet one", ""], "server": [], "data": ["d1"]}}
    out = b.build_tier_root_causes([], [], sidecar)
    assert out == {"edge": ["bullet one"], "data": ["d1"]}


def test_build_tier_root_causes_fallback_title_frequency():
    components = [
        {"id": "c1", "tier": "client"},
        {"id": "c2", "tier": "application"},
        {"id": "c3", "tier": "unknown-tier-passthrough"},
    ]
    threats = [
        {"component": "c1", "title": "XSS in edge"},
        {"component": "c1", "title": "XSS in edge"},
        {"component": "c2", "title": "SQLi in server"},
        {"component": "missing", "title": "no tier"},  # no tier → skipped
    ]
    out = b.build_tier_root_causes(threats, components, None)
    assert out["edge"] == ["XSS in edge"]
    assert out["server"] == ["SQLi in server"]


# --- build_attack_surface overrides ------------------------------------------


def test_build_attack_surface_curations_and_additions():
    routes = {
        "routes": [
            {
                "route_id": "r1",
                "method": "GET",
                "path": "/a",
                "authn_signal": "middleware_present",
                "handler_file": "a.ts",
                "handler_line": 3,
                "management_surface": True,
            },
            {"route_id": "r2", "method": "POST", "path": "/b", "authn_signal": "unknown"},
            {"route_id": "r3", "method": "GET", "path": "/c", "authn_signal": "absent"},
        ]
    }
    sidecar = {
        "curations": {
            "exclude_route_ids": ["r3"],
            "rationale_by_id": {"r1": "admin only"},
        },
        "additions": [
            # collision on existing entry_point → merge authoritative fields
            {"entry_point": "POST /b", "auth_required": True, "notes": "verified guarded"},
            # no entry_point → skipped
            {"notes": "orphan"},
            # genuine new entry
            {"entry_point": "PUT /d", "protocol": "HTTP", "auth_required": False},
        ],
    }
    out, warnings = b.build_attack_surface(routes, sidecar)
    eps = {e["entry_point"] for e in out}
    assert "GET /c" not in eps  # excluded
    assert "PUT /d" in eps  # added
    by_ep = {e["entry_point"]: e for e in out}
    # GET /a got rationale note + management surface + handler note
    assert by_ep["GET /a"]["notes"] == "admin only"
    assert by_ep["GET /a"]["auth_required"] is True
    # POST /b collision merged authoritative auth + notes
    assert by_ep["POST /b"]["auth_required"] is True
    assert by_ep["POST /b"]["notes"] == "verified guarded"
    assert any("exclude" in w for w in warnings)
    assert any("rationale" in w for w in warnings)


def test_build_attack_surface_include_filter():
    routes = {
        "routes": [
            {"route_id": "r1", "method": "GET", "path": "/a", "authn_signal": "absent"},
            {"route_id": "r2", "method": "GET", "path": "/b", "authn_signal": "absent"},
        ]
    }
    sidecar = {"curations": {"include_route_ids": ["r1"]}}
    out, warnings = b.build_attack_surface(routes, sidecar)
    eps = {e["entry_point"] for e in out}
    # include allowlist may be augmented by class-coverage guard; r1 must remain.
    assert "GET /a" in eps
    assert any("include" in w for w in warnings)


def test_build_attack_surface_sidecar_only_when_no_routes():
    sidecar = {"additions": [{"entry_point": "GET /only", "protocol": "HTTP"}]}
    out, _ = b.build_attack_surface(None, sidecar)
    assert any(e["entry_point"] == "GET /only" for e in out)


# --- _index_resolved_prior ---------------------------------------------------


def test_index_resolved_prior_keys_by_id_and_fingerprint():
    merged = {
        "resolved_prior_findings": [
            {"prior_id": "T-009", "reason": "fixed in PR", "component_id": "c1", "cwe": "CWE-89", "title": "SQLi"},
            {"component_id": "c2", "cwe": "CWE-79", "title": "XSS"},  # no prior_id, no reason
            "not-a-dict",  # skipped
        ]
    }
    idx = b._index_resolved_prior(merged)
    assert idx["T-009"] == "fixed in PR"
    # fingerprint key present for the second (default reason). The key is the
    # _fp_str string (comp|cwe|title), matching how the reconciler probes this
    # dict — resolved findings carry no file, so the secondary key stays the
    # comp|cwe|title fingerprint rather than the file|cwe-family match key.
    fp = b._fp_str({"component": "c2", "cwe": "CWE-79", "title": "XSS"})
    assert idx[fp] == "fix confirmed by re-scan"


# --- renumber_trust_boundaries -----------------------------------------------
#
# Delivered `tb-N` must read 1..N even though the baseline ledger allocates from
# a persistent high-watermark (juice-shop shipped `tb-37 … tb-45`). Mirrors the
# `_assign_t_ids` + `_remap_scenario_local_refs` pair that already keeps
# delivered T-/M-ids contiguous.


def _tb_doc() -> dict:
    return {
        "meta": {
            "boundary_selection": {
                "components": {
                    "backend-api": {
                        "eligible_ids": ["tb-37", "tb-41"],
                        "selected_ids": ["tb-37"],
                        "omitted_ids": ["tb-41"],
                        "deferred_ids": [],
                        "focus_reasons": {"tb-37": ["explicit external entry"]},
                    }
                }
            }
        },
        "trust_boundaries": [
            {"id": "tb-41", "name": "DB crossing"},
            {"id": "tb-37", "name": "External ingress"},
        ],
        "threats": [
            {
                "id": "T-001",
                "boundary_refs": [
                    {
                        "boundary_id": "tb-37",
                        "origin_component_id": "backend-api",
                        "rationale": "expressJwt at tb-37 is the sole enforcement point",
                    }
                ],
            }
        ],
    }


def test_renumber_trust_boundaries_makes_delivered_ids_contiguous():
    doc, mapping = b.renumber_trust_boundaries(_tb_doc())
    assert mapping == {"tb-37": "tb-1", "tb-41": "tb-2"}
    # Neither row resolves to a component endpoint, so both land in the same
    # tier; the linked-findings tiebreak puts the referenced boundary first.
    assert [row["id"] for row in doc["trust_boundaries"]] == ["tb-2", "tb-1"]


def test_renumber_trust_boundaries_remaps_every_consumer_field():
    doc, _ = b.renumber_trust_boundaries(_tb_doc())
    ref = doc["threats"][0]["boundary_refs"][0]
    assert ref["boundary_id"] == "tb-1"
    # Prose too: qa_checks compares the canonical ref set against every tb-N
    # token rendered in the finding cards.
    assert "tb-1 is the sole enforcement point" in ref["rationale"]
    sel = doc["meta"]["boundary_selection"]["components"]["backend-api"]
    assert sel["eligible_ids"] == ["tb-1", "tb-2"]
    assert sel["selected_ids"] == ["tb-1"]
    assert sel["omitted_ids"] == ["tb-2"]
    # focus_reasons carries ids as MAP KEYS.
    assert list(sel["focus_reasons"]) == ["tb-1"]


def test_renumber_trust_boundaries_is_idempotent():
    once, first = b.renumber_trust_boundaries(_tb_doc())
    twice, second = b.renumber_trust_boundaries(once)
    assert first and second == {}
    assert twice == once


def test_renumber_trust_boundaries_does_not_collide_on_shared_prefix():
    doc = {
        "trust_boundaries": [{"id": "tb-4"}, {"id": "tb-41"}],
        # One ref each, so the criticality tiebreaks cancel and the assignment
        # falls through to the previous counter — this test is about the
        # substitution, not the ordering.
        "threats": [
            {
                "boundary_refs": [
                    {"boundary_id": "tb-41", "rationale": "tb-4 and tb-41"},
                    {"boundary_id": "tb-4"},
                ]
            }
        ],
    }
    out, mapping = b.renumber_trust_boundaries(doc)
    # Single-pass substitution: a sequential replace would rewrite the `tb-4`
    # prefix inside `tb-41` and yield `tb-11`.
    assert mapping == {"tb-4": "tb-1", "tb-41": "tb-2"}
    assert [row["id"] for row in out["trust_boundaries"]] == ["tb-1", "tb-2"]
    assert out["threats"][0]["boundary_refs"][0]["rationale"] == "tb-1 and tb-2"


def test_renumber_trust_boundaries_fails_closed_on_unexpected_ids():
    # Duplicate or non-tb-N ids → skip entirely rather than mint a collision.
    dup = {"trust_boundaries": [{"id": "tb-7"}, {"id": "tb-7"}]}
    assert b.renumber_trust_boundaries(dup) == (dup, {})
    legacy = {"trust_boundaries": [{"id": "tb-7"}, {"id": "boundary-x"}]}
    assert b.renumber_trust_boundaries(legacy) == (legacy, {})
    assert b.renumber_trust_boundaries({"trust_boundaries": []}) == ({"trust_boundaries": []}, {})


# --- criticality-ordered numbering -------------------------------------------
#
# `tb-N` order IS relevance order: nine boundaries in a flat catalogue gave the
# reader nothing to sort on (user 2026-07-31). The §1 table stays a plain
# ascending lookup table; the exposure badge shows why the order is what it is.


def _resolved(boundary_id: str, source: str, target: str, **extra) -> dict:
    return {
        "id": boundary_id,
        "from": source,
        "to": target,
        "confidence": "confirmed",
        "resolution_status": "resolved",
        **extra,
    }


def _crit_doc(rows: list[dict], refs: dict[str, int] | None = None) -> dict:
    return {
        "components": [{"id": "web-api"}, {"id": "db"}],
        "trust_boundaries": rows,
        "threats": [
            {
                "id": "T-001",
                "boundary_refs": [{"boundary_id": bid} for bid, n in (refs or {}).items() for _ in range(n)],
            }
        ],
    }


def test_renumber_trust_boundaries_numbers_by_exposure_tier():
    """Internet-facing leads, then unconfirmed, then internal, then outbound —
    the ledger order is irrelevant to the delivered number."""
    doc, _ = b.renumber_trust_boundaries(
        _crit_doc(
            [
                _resolved("tb-11", "web-api", "external"),  # outbound
                _resolved("tb-12", "web-api", "db"),  # internal
                _resolved("tb-13", "web-api", "db", confidence="inferred"),  # unconfirmed
                _resolved("tb-14", "external", "web-api"),  # internet-facing
                {"id": "tb-15", "from": "external", "to": "web-api", "resolution_status": "unresolved"},
            ]
        )
    )
    # Rows keep their catalogue position; only the numbers move. Read down the
    # input order above: outbound=5, internal=4, unconfirmed=3, internet=2,
    # review required=1.
    assert [row["id"] for row in doc["trust_boundaries"]] == ["tb-5", "tb-4", "tb-3", "tb-2", "tb-1"]


def test_renumber_trust_boundaries_breaks_exposure_ties_on_linked_findings():
    """Same tier → the boundary carrying more `boundary_refs[]` leads: evidence
    of a real gap outranks a clean boundary at the same exposure."""
    doc, _ = b.renumber_trust_boundaries(
        _crit_doc(
            [
                _resolved("tb-1", "external", "web-api"),
                _resolved("tb-2", "external", "db"),
            ],
            refs={"tb-2": 3, "tb-1": 1},
        )
    )
    assert {row["to"]: row["id"] for row in doc["trust_boundaries"]} == {"db": "tb-1", "web-api": "tb-2"}


def test_renumber_trust_boundaries_is_deterministic_on_full_ties():
    """Equal tier and equal findings → the previous counter decides, so two
    identical inputs cannot deliver two different catalogues."""
    rows = [_resolved("tb-9", "external", "db"), _resolved("tb-4", "external", "web-api")]
    doc, mapping = b.renumber_trust_boundaries(_crit_doc(rows))
    assert mapping == {"tb-4": "tb-1", "tb-9": "tb-2"}
    again, _ = b.renumber_trust_boundaries(_crit_doc(list(reversed(rows))))
    assert {row["to"]: row["id"] for row in again["trust_boundaries"]} == {"web-api": "tb-1", "db": "tb-2"}


def test_renumber_trust_boundaries_numbers_a_set_with_no_internet_edge():
    """A catalogue of only internal and outbound crossings still numbers
    1..N — the tiers are relative, not a filter."""
    doc, _ = b.renumber_trust_boundaries(
        _crit_doc(
            [
                _resolved("tb-31", "web-api", "external"),
                _resolved("tb-32", "web-api", "db"),
                _resolved("tb-33", "db", "external"),
            ],
            refs={"tb-31": 2},
        )
    )
    assert [row["id"] for row in doc["trust_boundaries"]] == ["tb-2", "tb-1", "tb-3"]


def test_renumber_trust_boundaries_ignores_boundary_refs_of_unknown_boundaries():
    """A ref pointing at an id the catalogue no longer carries must not perturb
    the tiebreak of the rows that remain."""
    doc, mapping = b.renumber_trust_boundaries(
        _crit_doc([_resolved("tb-5", "external", "web-api"), _resolved("tb-6", "external", "db")], refs={"tb-99": 4})
    )
    assert mapping == {"tb-5": "tb-1", "tb-6": "tb-2"}


def test_main_delivers_contiguous_boundary_ids_from_a_sparse_ledger(tmp_path, monkeypatch):
    """End-to-end: a run whose ledger allocated `tb-37 …` still ships `tb-1 …`.

    Shifts every id in the fixture into the sparse range the juice-shop ledger
    was actually in, then asserts the delivered document carries no ledger id
    anywhere — catalogue, refs, `meta.boundary_selection`, or prose — and that
    the remap sidecar the post-build emitters read was published.
    """
    if not _REPAIR_RUN.is_dir():
        pytest.skip("repair-run fixture absent")
    run = _copy_run(_REPAIR_RUN, tmp_path)
    shift = re.compile(r"\btb-(\d+)\b")
    for path in list(run.rglob("*.json")) + [run / "threat-model.yaml"]:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if "tb-" not in text:
            continue
        path.write_text(shift.sub(lambda m: f"tb-{int(m.group(1)) + 36}", text), encoding="utf-8")

    class _OkProc:
        returncode = 0
        stdout = ""
        stderr = ""

    real_run = b.subprocess.run
    monkeypatch.setattr(
        b.subprocess,
        "run",
        lambda cmd, *a, **k: (
            _OkProc() if any("validate_intermediate.py" in str(c) for c in cmd) else real_run(cmd, *a, **k)
        ),
    )
    assert _run_main(monkeypatch, [str(run), "--plugin-root", str(ROOT)]) == 0

    text = (run / "threat-model.yaml").read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    ids = [row["id"] for row in doc["trust_boundaries"]]
    assert len(ids) >= 2, "fixture must carry a boundary catalogue for this to mean anything"
    assert sorted(ids, key=lambda v: int(v.split("-")[1])) == [f"tb-{i}" for i in range(1, len(ids) + 1)]
    assert {int(m) for m in shift.findall(text)} <= set(range(1, len(ids) + 1))
    for threat in doc["threats"]:
        for ref in threat.get("boundary_refs") or []:
            assert ref["boundary_id"] in set(ids)
    remap = json.loads((run / ".trust-boundary-renumber.json").read_text(encoding="utf-8"))
    # A BIJECTION off the shifted ledger onto the dense range — deliberately not
    # `tb-{i+36} → tb-{i}`: numbering follows criticality, so the mapping is not
    # monotone and the pairing depends on the fixture's exposure mix.
    assert set(remap["mapping"]) == {f"tb-{i + 36}" for i in range(1, len(ids) + 1)}
    assert sorted(remap["mapping"].values()) == sorted(f"tb-{i}" for i in range(1, len(ids) + 1))


# ── Title conformance is a PROPERTY, not an example list (2026-08-21) ────────
#
# The defect these pin: `_clean_title` capitalised the lead with `s[0].upper()`,
# which is the identity on any character without a case pairing. A digit,
# path, quote or underscore lead therefore passed through unchanged and the
# schema rejected it at the Stage-2 handoff — terminal, 75 minutes in.
# Example-based assertions had missed it because every example started with a
# letter, so the acceptance criterion here is the schema's own pattern applied
# to arbitrary input.

_TITLE_PATTERN = re.compile(r"^[A-Z][^()@`]+?(?:\s*\([^()]+\))?$")

_HOSTILE_TITLES = [
    "14 Named Accounts Seeded with Hardcoded Password (SecurityConfig.java:71)",
    "404 handler leaks stack traces (ErrorController.java:18)",
    "/admin routes are unauthenticated (SecurityConfig.java:41)",
    ".env file committed to the repository (env:1)",
    "__init__ exposes a debug route (app.py:3)",
    "$JWT_SECRET committed to the image (Dockerfile:7)",
    '"password" is the seeded credential (Seeder.java:12)',
    "'admin' role assignable by any user (Profile.java:44)",
    "<script> injection in the profile page (Profile.html:8)",
    "stored XSS in the profile page (Profile.java:8)",
    "   leading whitespace then lowercase (X.java:1)",
    "12345",
    "!!!",
    "",
]


def _schema_title_constraints():
    """Read the real constraints so a schema change cannot outrun the cleaner."""
    import yaml

    doc = yaml.safe_load((ROOT / "schemas" / "threat-model.output.schema.yaml").read_text(encoding="utf-8"))
    node = doc["properties"]["threats"]["items"]["properties"]["title"]
    return node["pattern"], node["minLength"], node["maxLength"]


def test_schema_pattern_is_the_one_the_test_enforces():
    pattern, minimum, maximum = _schema_title_constraints()
    assert pattern == _TITLE_PATTERN.pattern
    assert (minimum, maximum) == (10, 80)


@pytest.mark.parametrize("raw", _HOSTILE_TITLES)
def test_conform_title_is_total_over_hostile_leads(raw):
    pattern, minimum, maximum = _schema_title_constraints()
    threat = {"title": raw, "cwe": "CWE-798"}
    b._conform_title(threat)
    out = threat["title"]
    assert re.match(pattern, out), f"{raw!r} → {out!r} violates the schema pattern"
    assert minimum <= len(out) <= maximum, f"{raw!r} → {out!r} has length {len(out)}"


def test_conform_title_is_identity_on_conforming_input():
    """No fingerprint churn: only titles that would have been REJECTED change."""
    for raw in ("SQL Injection (routes/login.ts:34)", "Insecure Direct Object Reference"):
        threat = {"title": raw}
        assert b._conform_title(threat) is False
        assert threat["title"] == raw
        assert "_title_source" not in threat


def test_lossy_repair_is_reported_and_stashes_the_original():
    threat = {"title": "404 handler leaks stack traces (ErrorController.java:18)"}
    assert b._conform_title(threat) is True
    assert threat["_title_source"] == "404 handler leaks stack traces (ErrorController.java:18)"
    assert threat["title"].startswith("Handler leaks stack traces")


def test_lowercase_lead_is_repaired_without_loss():
    threat = {"title": "stored XSS in the profile page (Profile.java:8)"}
    assert b._conform_title(threat) is False
    assert threat["title"] == "Stored XSS in the profile page (Profile.java:8)"


def test_orphaned_quote_from_a_dropped_lead_is_removed():
    threat = {"title": '"password" is the seeded credential (Seeder.java:12)'}
    b._conform_title(threat)
    assert '"' not in threat["title"]


def test_unsalvageable_title_falls_back_and_names_the_cwe():
    threat = {"title": "!!!", "cwe": "CWE-798"}
    assert b._conform_title(threat) is True
    assert threat["title"] == "Unclassified security weakness (CWE-798)"


def test_dropping_the_lead_frees_budget_for_the_locator():
    """The lead-strip re-clean is not cosmetic: it changes what ships.

    In the 81-83 char band the `(file:line)` suffix is dropped only because the
    non-conforming lead pushed the title over the cap. Re-cleaning the
    lead-stripped original brings the locator back, so the repair costs the
    lead and nothing else.
    """
    body = "Unauthenticated Admin Promotion Allows Role Escalation Everywhere"
    raw = f"14 {body} (Sec.java:41)"
    assert len(raw) > 80 and len(raw) - 3 <= 80, "fixture must sit in the band where the lead alone overflows"

    single_pass, lossy = b._ensure_pattern_lead(b._clean_title(raw))
    assert lossy and "Sec.java:41" not in single_pass

    threat = {"title": raw}
    assert b._conform_title(threat) is True
    assert threat["title"] == f"{body} (Sec.java:41)"


# ── The title was not a special case (2026-08-21) ────────────────────────────
#
# Injecting one plausible analyst spelling into .threats-merged.json and
# rebuilding showed SEVEN of ten probes ending the run at the Stage-2 handoff.
# `cwe` and the three severity words carry their intended value unambiguously
# in every observed spelling, so they are coerced rather than fatal. `scenario`
# below the minLength is deliberately NOT repaired: no transform can invent a
# scenario, and dropping the finding or fabricating text would both be worse
# than sending it back to the producer.


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CWE-79, CWE-80", "CWE-79"),  # two classes in one string — primary leads
        ("CWE-798 (Hardcoded Credentials)", "CWE-798"),  # id plus gloss
        ("79", "CWE-79"),  # bare number
        ("cwe_89", "CWE-89"),  # separator and case drift
    ],
)
def test_cwe_spellings_are_coerced_to_the_schema_pattern(raw, expected):
    assert b._normalize_cwe(raw) == expected
    assert re.match(r"^CWE-\d+$", b._normalize_cwe(raw))


@pytest.mark.parametrize("raw", ["siehe unten", "", None, "CWE-"])
def test_unreadable_cwe_is_dropped_not_guessed(raw):
    assert b._normalize_cwe(raw) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Critical (see notes)", "Critical"),  # trailing gloss is noise
        ("critical", "Critical"),
        ("MEDIUM", "Medium"),
        ("moderate", "Medium"),
        ("info", "Informational"),
        ("minor", "Low"),
    ],
)
def test_unambiguous_severity_spellings_map_without_a_guess(raw, expected):
    assert b._normalize_severity_word(raw) == (expected, False)


@pytest.mark.parametrize("raw", ["very high", "catastrophic", "severe", "blocker"])
def test_ambiguous_severity_is_reported_never_invented(raw):
    """Ranking an unknown word IS a security claim — the caller must be told."""
    word, guessed = b._normalize_severity_word(raw)
    assert word is None and guessed is True


@pytest.mark.parametrize("raw", ["CWE-79", "CWE-0079", "CWE-000123"])
def test_already_valid_cwe_is_returned_byte_identical(raw):
    """Same identity rule as the title: only REJECTED values may change.

    `cwe` is part of `_threat_fingerprint`, so canonicalising the zero padding
    of an already-valid `CWE-0079` would make an unchanged finding read as
    resolved-and-re-added in the next incremental run.
    """
    assert re.match(r"^CWE-\d+$", raw), "fixture must already satisfy the schema"
    assert b._normalize_cwe(raw) == raw


# ---------------------------------------------------------------------------
# REQ-BIZ-003 — a finding names the declared context that weights it
# ---------------------------------------------------------------------------


def _analyst_context(tmp_path: Path, payload: dict) -> Path:
    (tmp_path / ".stride-analyst-context.json").write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def test_declared_context_marks_the_findings_of_its_component(tmp_path):
    """Only components the analyst mapped material context onto are marked, and
    only the three fields the ranking tie-break also treats as material."""
    _analyst_context(
        tmp_path,
        {
            "payments-svc": {
                "business_context": {
                    "impact_if_compromised": "Loss of customer funds.",
                    "sensitive_assets": ["settlement balances"],
                }
            },
            # business_purpose is descriptive, not material: no mark.
            "docs-site": {"business_context": {"business_purpose": "Publishes marketing pages."}},
        },
    )
    threats = [
        {"id": "T-001", "component": "payments-svc"},
        {"id": "T-002", "component": "docs-site"},
        {"id": "T-003", "component": "unmapped-svc"},
    ]

    marked = b._apply_business_context_basis(threats, tmp_path, {})

    assert marked == 1
    assert threats[0]["business_context_basis"] == ["impact_if_compromised", "sensitive_assets"]
    assert "business_context_basis" not in threats[1]
    assert "business_context_basis" not in threats[2]


def test_business_context_basis_never_carries_the_business_prose(tmp_path):
    """The delivered model records which fields applied, never what they said."""
    secret_prose = "Settles payouts for merchant ACME under contract 4711."
    _analyst_context(
        tmp_path,
        {"payments-svc": {"business_context": {"impact_if_compromised": secret_prose}}},
    )
    threats = [{"id": "T-001", "component": "payments-svc"}]

    b._apply_business_context_basis(threats, tmp_path, {})

    assert threats[0]["business_context_basis"] == ["impact_if_compromised"]
    assert secret_prose not in json.dumps(threats)


def test_skip_context_leaves_every_finding_unmarked(tmp_path):
    _analyst_context(tmp_path, {"payments-svc": {"business_context": {"sensitive_assets": ["funds"]}}})
    threats = [{"id": "T-001", "component": "payments-svc"}]

    assert b._apply_business_context_basis(threats, tmp_path, {"skip_business_context": True}) == 0
    assert "business_context_basis" not in threats[0]


def test_meta_reports_no_business_context_when_the_run_skipped_it(tmp_path):
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "business-context.md").write_text("Handles payouts.\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    cfg = {"output_dir": str(out), "skip_business_context": True}

    assert b._business_context_digest(cfg, repo) is None
    assert b._business_context_source(cfg, repo) is None


# ---------------------------------------------------------------------------
# requirements_compliance export
#
# The Markdown report carried the full §7b table while the YAML carried
# nothing, so a consumer of the export saw no requirements dimension at all and
# render_completion_summary.py reported "0 checked" for a run that had assessed
# 73 of them (run a2a0e355).
# ---------------------------------------------------------------------------

_CATALOG = """\
categories:
- id: CAT-WEB
  requirements:
  - {id: WEB-001, priority: MUST, text: CSRF prevention}
  - {id: WEB-002, priority: MUST, text: No tokens in JS-accessible storage}
  - {id: AC-002, priority: SHOULD, text: Server-side authorization}
  - {id: IV-004, priority: MUST, text: Parameterized queries}
  - {id: DP-005, priority: MUST, text: Secret management}
"""

_FRAGMENT = """\
| Requirement | Status | Priority | Evidence |
| --- | --- | --- | --- |
| `WEB-001`: CSRF prevention | ❌ FAIL | MUST | F-018 shows a GET password change |
| `WEB-002`: No tokens in JS storage | ⚠️ PARTIAL | MUST | F-029 localStorage token |
| `AC-002`: Server-side authorization | ✅ PASS | SHOULD | guard enforced server-side |
| `IV-004`: Parameterized queries | ❓ UNVERIFIABLE | MUST | no query layer observed |
| `DP-005`: Secret management | ➖ N/A | MUST | no secrets in scope |
"""


def _requirements_run(tmp_path: Path, *, catalog=_CATALOG, fragment=_FRAGMENT) -> Path:
    if catalog is not None:
        (tmp_path / ".requirements.yaml").write_text(catalog, encoding="utf-8")
    if fragment is not None:
        (tmp_path / ".fragments").mkdir(exist_ok=True)
        (tmp_path / ".fragments" / "requirements-compliance.md").write_text(fragment, encoding="utf-8")
    return tmp_path


def test_requirements_compliance_counts_every_status(tmp_path):
    out = b.build_requirements_compliance(_requirements_run(tmp_path))
    assert out["total"] == 5
    assert out["fail"] == 1
    assert out["partial"] == 1
    assert out["pass"] == 1
    assert out["unverifiable"] == 1
    assert out["not_applicable"] == 1


def test_the_status_buckets_reconcile_with_the_total(tmp_path):
    # The rule the control-effectiveness line learned the hard way: a breakdown
    # that does not add up to its own total is worse than no breakdown.
    out = b.build_requirements_compliance(_requirements_run(tmp_path))
    buckets = out["pass"] + out["fail"] + out["partial"] + out["unverifiable"] + out["not_applicable"]
    assert buckets == out["total"]


def test_each_requirement_is_exported_with_its_findings(tmp_path):
    out = b.build_requirements_compliance(_requirements_run(tmp_path))
    rows = {r["id"]: r for r in out["requirements"]}
    assert len(rows) == 5
    assert rows["WEB-001"]["status"] == "FAIL"
    assert rows["WEB-001"]["priority"] == "MUST"
    assert rows["WEB-001"]["finding_ids"] == ["F-018"]
    assert rows["DP-005"]["status"] == "N/A"


def test_a_run_without_a_catalog_omits_the_key(tmp_path):
    # Absent, not empty: an empty object would read as "assessed nothing".
    assert b.build_requirements_compliance(_requirements_run(tmp_path, catalog=None)) is None


def test_a_catalog_without_an_assessment_omits_the_key(tmp_path):
    assert b.build_requirements_compliance(_requirements_run(tmp_path, fragment=None)) is None


def test_an_id_outside_the_catalog_is_not_exported(tmp_path):
    # The configured catalog is authoritative; the table is LLM-authored.
    fragment = _FRAGMENT + "| `ZZZ-999`: invented | ❌ FAIL | MUST | made up |\n"
    out = b.build_requirements_compliance(_requirements_run(tmp_path, fragment=fragment))
    assert "ZZZ-999" not in {r["id"] for r in out["requirements"]}
    assert out["total"] == 5
