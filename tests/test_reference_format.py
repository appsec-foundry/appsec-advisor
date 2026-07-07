"""Reference-link format: helpers, the linter, and a live-render guarantee.

Locks in the canonical F-/T-/M- reference format (one full form, one short
form) so the producer can never silently drift back to the mixed variants it
historically shipped (juice-shop 2026-06-29 RC). See
project-threatmodel-ref-link-format memory + scripts/check_reference_format.py.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "compose"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


compose = _load("compose_threat_model")
linter = _load("check_reference_format")
rac = _load("render_abuse_cases")


# ---------------------------------------------------------------------------
# Locator helpers
# ---------------------------------------------------------------------------


def test_basename_locator_keeps_line():
    assert compose._basename_locator("routes/login.ts:34") == "login.ts:34"
    assert compose._basename_locator("frontend/src/app/oauth.component.ts:51") == "oauth.component.ts:51"
    assert compose._basename_locator("server.ts") == "server.ts"
    assert compose._basename_locator("") == ""


def test_strip_trailing_locator_all_forms():
    f = compose._strip_trailing_locator
    base = "Insecure Direct Object Reference"
    assert f(f"{base} (`routes/memory.ts:15`)") == base  # backticked parens
    assert f(f"{base} (routes/memory.ts:15)") == base  # plain parens
    assert f(f"{base} — routes/memory.ts:15") == base  # em-dash
    assert f(f"{base} routes/memory.ts:15") == base  # bare-space-glued


def test_strip_trailing_locator_leaves_prose():
    f = compose._strip_trailing_locator
    # An acronym parenthetical is NOT a locator (no extension / :line).
    assert f("Insecure Direct Object Reference (IDOR)") == "Insecure Direct Object Reference (IDOR)"
    assert f("No locator here") == "No locator here"


def test_evidence_locator_dict_and_list():
    assert compose._evidence_locator({"evidence": {"file": "a/b.ts", "line": 9}}) == "a/b.ts:9"
    assert compose._evidence_locator({"evidence": [{"file": "x.ts", "line": 1}]}) == "x.ts:1"
    assert compose._evidence_locator({"evidence": {"file": "n.ts"}}) == "n.ts"
    assert compose._evidence_locator({}) == ""


# ---------------------------------------------------------------------------
# linkify_with_label — the two canonical forms
# ---------------------------------------------------------------------------


def _ctx(threats=None, mitigations=None):
    return compose.RenderContext(
        output_dir=Path("."),
        contract={},
        yaml_data={"threats": threats or [], "mitigations": mitigations or []},
        triage={},
        fragments_dir=Path("."),
        severity_taxonomy={"high": {"emoji": "🟠", "label": "High"}},
    )


_THREAT = {
    "id": "T-046",
    "risk": "high",
    "title": "XXE file disclosure via XML upload (`routes/fileUpload.ts:76`)",
    "evidence": {"file": "routes/fileUpload.ts", "line": 76},
}


def test_linkify_full_form_basename_and_backticked():
    ctx = _ctx(threats=[_THREAT])
    out = ctx.linkify_with_label("F-046")
    # ID linked once, label locator-free, basename:line backticked in parens.
    assert out == "🟠 [F-046](#f-046) — XXE file disclosure via XML upload (`fileUpload.ts:76`)"


def test_linkify_short_form_is_id_only():
    ctx = _ctx(threats=[_THREAT])
    assert ctx.linkify_with_label("F-046", compact=True) == "🟠 [F-046](#f-046)"


def test_linkify_index_uses_full_path():
    ctx = _ctx(threats=[_THREAT])
    out = ctx.linkify_with_label("F-046", full_path=True)
    assert out == "🟠 [F-046](#f-046) — XXE file disclosure via XML upload (`routes/fileUpload.ts:76`)"


def test_linkify_label_override_locator_not_doubled():
    ctx = _ctx(threats=[_THREAT])
    # A curated override that already embeds a locator must not double it.
    out = ctx.linkify_with_label("F-046", label_override="Custom title (routes/fileUpload.ts:76)")
    assert out == "🟠 [F-046](#f-046) — Custom title (`fileUpload.ts:76`)"
    assert out.count("fileUpload.ts") == 1


def test_linkify_no_location_degrades_cleanly():
    ctx = _ctx(threats=[{"id": "T-099", "risk": "high", "title": "Some finding"}])
    assert ctx.linkify_with_label("F-099") == "🟠 [F-099](#f-099) — Some finding"


# ---------------------------------------------------------------------------
# The linter — catches the historical deviations
# ---------------------------------------------------------------------------


def test_linter_flags_unbackticked_parens_locator():
    bad = "🔴 [F-010](#f-010) — Insecure Direct Object Reference (routes/memory.ts:15)"
    assert linter.lint_text(bad)


def test_linter_flags_id_inside_link_text():
    bad = "[F-010 — Insecure Direct Object Reference](#f-010)"
    assert linter.lint_text(bad)


def test_linter_flags_emdash_locator():
    bad = "[F-010](#f-010) — Insecure Direct Object Reference — routes/memory.ts:15"
    assert linter.lint_text(bad)


def test_linter_passes_canonical_full_form():
    good = "🔴 [F-010](#f-010) — Insecure Direct Object Reference (`memory.ts:15`)"
    assert linter.lint_text(good) == []


def test_linter_passes_short_form():
    assert linter.lint_text("🔴 [F-010](#f-010)") == []


def test_linter_ignores_prose_file_mentions_and_urls():
    # Reference-adjacent only: a bare file mention or a URL is never flagged.
    prose = "The handler in routes/memory.ts is vulnerable; see https://x.org/Cheat_Sheet.html for more."
    assert linter.lint_text(prose) == []


# ---------------------------------------------------------------------------
# _normalize_reference_locators — the global catch-all post-pass
# ---------------------------------------------------------------------------


def test_normalize_backticks_and_basenames_unbackticked_locator():
    md = "🔴 [F-010](#f-010) — Insecure Direct Object Reference (routes/memory.ts:15)"
    out = compose._normalize_reference_locators(md)
    assert out == "🔴 [F-010](#f-010) — Insecure Direct Object Reference (`memory.ts:15`)"


def test_normalize_preserves_already_backticked_full_path():
    # The Findings index deliberately keeps the full path, backticked — untouched.
    md = "🔴 [F-010](#f-010) — Insecure Direct Object Reference (`routes/memory.ts:15`)"
    assert compose._normalize_reference_locators(md) == md


def test_normalize_handles_no_line_locator():
    md = "[F-028](#f-028) — Cross-Site Request Forgery (server.ts)"
    assert compose._normalize_reference_locators(md) == "[F-028](#f-028) — Cross-Site Request Forgery (`server.ts`)"


def test_normalize_does_not_cross_cell_or_tag_boundaries():
    # A locator separated from the ref by a table pipe, an HTML tag, or a
    # sibling reference must NOT be attached to the ref.
    assert compose._normalize_reference_locators("[F-1](#f-1) | (a.ts:1)") == "[F-1](#f-1) | (a.ts:1)"
    assert compose._normalize_reference_locators("[F-1](#f-1) <span> (a.ts:1)") == "[F-1](#f-1) <span> (a.ts:1)"
    assert compose._normalize_reference_locators("[F-1](#f-1) [F-2](#f-2) (a.ts:1)") == (
        "[F-1](#f-1) [F-2](#f-2) (`a.ts:1`)"
    )


def test_normalize_ignores_non_reference_parenthetical():
    # An acronym in parens after a ref is not a locator (no extension / :line).
    md = "[F-010](#f-010) — Insecure Direct Object Reference (IDOR)"
    assert compose._normalize_reference_locators(md) == md


def test_normalize_is_idempotent():
    md = "🔴 [F-010](#f-010) — IDOR (routes/memory.ts:15)"
    once = compose._normalize_reference_locators(md)
    assert compose._normalize_reference_locators(once) == once


# ---------------------------------------------------------------------------
# §9 Abuse Cases (render_abuse_cases.py) — same canonical form
# ---------------------------------------------------------------------------


def test_abuse_locator_helpers():
    assert rac._basename_loc("routes/memory.ts:15") == "memory.ts:15"
    assert rac._strip_locator("IDOR (routes/memory.ts:15)") == "IDOR"
    assert rac._strip_locator("IDOR (IDOR)") == "IDOR (IDOR)"  # acronym preserved
    assert rac._finding_locator({"evidence": {"file": "routes/memory.ts", "line": 15}}) == "routes/memory.ts:15"


def test_abuse_finding_cell_is_canonical_and_lint_clean():
    case = {
        "id": "AC-T-001",
        "title": "Account Takeover",
        "source": "mandatory",
        "chain": [{"step": 1, "description": "reach the sink"}],
    }
    verdict = {
        "chain_verdict": "fully_viable",
        "step_verdicts": [{"step": 1, "verdict": "confirmed", "matched_finding_id": "F-010"}],
    }
    findings_idx = {
        "F-010": {
            "title": "Insecure Direct Object Reference (routes/memory.ts:15)",
            "effective_severity": "critical",
            "evidence": {"file": "routes/memory.ts", "line": 15},
        }
    }
    model = rac.render_case(case, verdict, findings_idx, [], None)
    md = rac._case_markdown(model)
    # Canonical: ID — locator-free title (`basename:line`), and lint-clean.
    assert "[F-010](#f-010) — Insecure Direct Object Reference (`memory.ts:15`)" in md
    assert "(routes/memory.ts:15)" not in md  # no un-backticked full path
    assert linter.lint_text(md) == []


# ---------------------------------------------------------------------------
# Live render must be lint-clean (the durable end-to-end guarantee)
# ---------------------------------------------------------------------------


def _ctx_with_locals():
    return compose.RenderContext(
        output_dir=Path("."),
        contract={},
        yaml_data={
            "threats": [
                {"id": "T-007", "local_id": "auth-001"},
                {"id": "T-012", "local_id": "auth-004"},
                {"id": "T-010", "consolidated_refs": ["express-backend-016"]},
            ]
        },
        triage={},
        fragments_dir=Path("."),
    )


def test_bare_fnnn_in_prose_is_linkified():
    ctx = _ctx_with_locals()
    out = compose._linkify_bare_finding_refs(ctx, "F-007 is exploitable at the edge.")
    assert out == "[F-007](#f-007) is exploitable at the edge."


def test_unknown_fnnn_left_alone():
    ctx = _ctx_with_locals()
    assert compose._linkify_bare_finding_refs(ctx, "F-999 does not exist.") == "F-999 does not exist."


def test_local_id_resolves_to_canonical_flink():
    ctx = _ctx_with_locals()
    out = compose._linkify_bare_finding_refs(ctx, "Combined with auth-001 (committed key).")
    assert out == "Combined with [F-007](#f-007) (committed key)."


def test_multipart_local_id_via_consolidated_ref():
    ctx = _ctx_with_locals()
    out = compose._linkify_bare_finding_refs(ctx, "see finding express-backend-016 here")
    assert out == "see finding [F-010](#f-010) here"


def test_bare_ref_skips_code_links_anchors_headings():
    ctx = _ctx_with_locals()
    # inside backticks
    assert compose._linkify_bare_finding_refs(ctx, "`F-007`") == "`F-007`"
    # already a link (text + anchor both protected)
    assert compose._linkify_bare_finding_refs(ctx, "[F-007](#f-007)") == "[F-007](#f-007)"
    # heading line
    assert compose._linkify_bare_finding_refs(ctx, "### F-007 Something") == "### F-007 Something"
    # anchor declaration row
    row = '| <a id="f-007"></a>F-007 | x |'
    assert compose._linkify_bare_finding_refs(ctx, row) == row


def test_bare_ref_no_false_positive_on_versions():
    ctx = _ctx_with_locals()
    # `sha-256` matches the id shape but is not a known local_id → untouched.
    assert compose._linkify_bare_finding_refs(ctx, "hashed with sha-256 today") == "hashed with sha-256 today"


# ---------------------------------------------------------------------------
# Inline code backticking (Task 4) — extended patterns + the global prose pass
# ---------------------------------------------------------------------------


def test_codify_env_vars():
    f = compose._codify_inline_identifiers
    assert f("the default GITHUB_TOKEN permissions") == "the default `GITHUB_TOKEN` permissions"
    assert f("set NODE_ENV to production") == "set `NODE_ENV` to production"


def test_codify_does_not_wrap_plain_acronyms():
    # All-caps WITHOUT an underscore is prose (XSS, CSRF, SQL) — never wrapped.
    f = compose._codify_inline_identifiers
    assert f("an XSS and CSRF and SQL issue") == "an XSS and CSRF and SQL issue"


def test_codify_mixed_case_member_chains():
    f = compose._codify_inline_identifiers
    assert f("Replace req.body.UserId now") == "Replace `req.body.UserId` now"
    assert f("hands secrets.GITHUB_TOKEN over") == "hands `secrets.GITHUB_TOKEN` over"
    assert f("reads process.env.LLM_API_KEY here") == "reads `process.env.LLM_API_KEY` here"


def test_codify_allows_trailing_sentence_period():
    # A member chain ending a sentence must still be wrapped (the `.`+space is
    # not a member continuation).
    assert compose._codify_inline_identifiers("equivalent to req.user.id.") == "equivalent to `req.user.id`."


def test_codify_does_not_wrap_markdown_italic_close():
    # REGRESSION: `… stay valid._` must NOT become `` `valid._` `` — the `_`
    # is a markdown italic close, not a dotted member (golden caught this).
    assert compose._codify_inline_identifiers("sequences stay valid._") == "sequences stay valid._"
    assert compose._codify_inline_identifiers("_italic phrase here._") == "_italic phrase here._"


def test_codify_prose_pass_skips_fences_and_headings():
    md = (
        "### A heading with req.body.UserId in it\n"
        "Body text uses req.query.q directly.\n"
        "```js\nconst x = req.body.UserId;\n```\n"
    )
    out = compose._codify_inline_code_in_prose(md)
    assert "### A heading with req.body.UserId in it" in out  # heading untouched
    assert "Body text uses `req.query.q` directly." in out  # body codified
    assert "const x = req.body.UserId;" in out  # fence untouched (no backticks added)


def test_codify_prose_pass_idempotent():
    md = "Body text uses req.query.q directly.\n"
    once = compose._codify_inline_code_in_prose(md)
    assert compose._codify_inline_code_in_prose(once) == once


# ---------------------------------------------------------------------------
# Top Threats finding cell carries the component NAME, not a bare C-NN (Task 2)
# ---------------------------------------------------------------------------


def test_top_threats_finding_cell_includes_component_name(tmp_path, monkeypatch):
    out = tmp_path / "out"
    (out / ".fragments").mkdir(parents=True)
    ctx = compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data={
            "components": [{"id": "C-08", "name": "Authentication & Session", "tier": "application"}],
            "threats": [
                {
                    "id": "F-006",
                    "t_id": "T-006",
                    "title": "SQL Injection",
                    "component": "C-08",
                    "risk": "critical",
                    "evidence": {"file": "routes/login.ts", "line": 34},
                }
            ],
        },
        triage={},
        fragments_dir=out / ".fragments",
    )
    monkeypatch.setattr(
        compose,
        "_load_attack_class_taxonomy",
        lambda: {"classes": [{"id": "injection", "threat_label": "Injection", "stride": "T"}]},
    )
    monkeypatch.setattr(
        compose,
        "_load_attack_paths_fragment",
        lambda c, tax, thr: {"attack_paths": [{"class": "injection", "findings": ["F-006"], "impact": []}]},
    )
    rows = compose._compute_top_threats_rows(ctx)
    assert rows, "expected a Top Threats row"
    cell = rows[0]["findings_cell"]
    assert "[C-08](#c-08)" in cell, cell
    assert "Authentication & Session" in cell, cell  # NAME present, not a bare ID


# ---------------------------------------------------------------------------
# Operational Strengths "What's in Place" lists control NAMES only (Task 3)
# ---------------------------------------------------------------------------


def test_operational_strengths_implementations_are_names_only():
    controls = [
        {
            "architectural_control": "Parameterized Database Access",
            "effectiveness": "adequate",
            # A long, multi-clause impl detail that the OLD renderer would have
            # truncated mid-token with "…" and inlined un-code-formatted.
            "implementation": "Sequelize ORM used for most CRUD queries with bound parameters everywhere",
        }
    ]
    clusters = compose._build_strength_clusters(controls, [], all_threats=[])
    impls = [i for cl in clusters for i in (cl.get("implementations") or [])]
    assert impls, "expected at least one implementation entry"
    assert "Parameterized Database Access" in impls  # the control NAME
    # No " — <impl detail>" appended and no mid-token "…" truncation.
    assert all(" — " not in i for i in impls), impls
    assert all("…" not in i for i in impls), impls


def test_rendered_fixture_is_reference_format_clean(tmp_path):
    import shutil

    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    rendered, _ = compose.render(CONTRACT, out)
    violations = linter.lint_text(rendered)
    assert violations == [], "rendered fixture has reference-format violations:\n" + "\n".join(violations[:20])


# ---------------------------------------------------------------------------
# §9 mitigation `**Reference:**` normalization (juice-shop 2026-07-03 user
# report: CWEs unlinked, URLs untitled, inconsistent). compose._normalize_reference
# renders every reference as a titled Markdown link; the linter guards it.
# ---------------------------------------------------------------------------


def test_normalize_reference_titles_bare_cwe():
    out = compose._normalize_reference("CWE-798")
    assert out == "[CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)"


def test_normalize_reference_cwe_missing_from_taxonomy_falls_back_to_url_only():
    # A CWE not in cwe-taxonomy.yaml still becomes a link (URL derivable from
    # the number), just without the ": title" suffix.
    out = compose._normalize_reference("CWE-99999")
    assert out == "[CWE-99999](https://cwe.mitre.org/data/definitions/99999.html)"


def test_normalize_reference_titles_bare_url():
    out = compose._normalize_reference(
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
    )
    assert out == (
        "[OWASP Cheat Sheet: SQL Injection Prevention Cheat Sheet]"
        "(https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)"
    )


def test_normalize_reference_idempotent_for_existing_link():
    src = "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)"
    assert compose._normalize_reference(src) == src


def test_normalize_reference_empty_passthrough():
    assert compose._normalize_reference("") == ""
    assert compose._normalize_reference(None) == ""


def test_linter_flags_bare_cwe_and_url_references():
    md = (
        "#### M-001 — Fix it\n\n**Reference:** CWE-798\n\n"
        "#### M-002 — Fix it\n\n**Reference:** https://cheatsheetseries.owasp.org/x.html\n"
    )
    violations = linter.lint_text(md)
    assert any("bare CWE reference" in v for v in violations), violations
    assert any("untitled URL reference" in v for v in violations), violations


def test_linter_accepts_titled_reference_links():
    md = (
        "#### M-001 — Fix it\n\n"
        "**Reference:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)\n"
    )
    assert linter.lint_text(md) == []
