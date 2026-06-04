"""Unit tests for scripts/apply_prose_fixes.py."""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "apply_prose_fixes.py"


def _load_apply_prose_fixes():
    if "apply_prose_fixes" in sys.modules:
        return sys.modules["apply_prose_fixes"]
    spec = importlib.util.spec_from_file_location("apply_prose_fixes", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_prose_fixes"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


prose = _load_apply_prose_fixes()


def test_apply_fixes_is_idempotent_for_core_rewrites():
    md = textwrap.dedent("""\
        ## 7. Security Architecture

        ### 7.2 Identity and Authentication Controls

        **Controls covered:** [Stale](#stale).

        #### Password Login

        routes/login.ts:34 reaches the SQL query. Additionally, the password hash is trivially crackable. No DDoS protection is configured. Keep this sentence.

        **Relevant findings:** [F-001](#f-001) - SQL injection, [F-002](#f-002) - MD5 hashing.
    """)

    once, n_fixes = prose.apply_fixes(md)
    twice, n_fixes_again = prose.apply_fixes(once)

    assert n_fixes > 0
    assert once == twice
    assert n_fixes_again == 0
    assert "`routes/login.ts:34` reaches the SQL query." in once
    assert "Additionally," not in once
    assert "recoverable by GPU dictionary attack within seconds" in once
    assert "No DDoS protection" not in once
    assert "**Controls covered:** [Password Login](#password-login)" in once
    assert "**Relevant findings**\n\n- [F-001](#f-001) — SQL injection" in once
    assert "- [F-002](#f-002) — MD5 hashing" in once


def test_canonicalize_section8_name_rewrites_stale_refs():
    """Stale `§8 Threat Register` label + dead `#8-threat-register` anchor
    (from older LLM-authored fragments) are rewritten to the renamed §8
    'Findings Register' (2026-06-02 rename). Idempotent."""
    md = "See [§8 Threat Register](#8-threat-register) and the Threat Register table.\n"
    once, n = prose.apply_fixes(md)
    assert "[§8 Findings Register](#8-findings-register)" in once
    assert "Findings Register table" in once
    assert "Threat Register" not in once
    assert "#8-threat-register" not in once
    twice, n2 = prose.apply_fixes(once)
    assert once == twice and n2 == 0


def test_legacy_title_path_tail_uses_canonical_paren_form():
    md = "| ID | Finding |\n|----|---------|\n| F-001 | Hardcoded key — lib/insecurity.ts:23 |\n"

    fixed, n_fixes = prose.apply_fixes(md)

    # 2026-05 R-7 — path-wrapping now runs on table rows too, so the
    # path token gets backticked BEFORE the legacy normalizer can convert
    # the em-dash tail to paren form. The normalizer's "skip if backticked"
    # guard then leaves the line at `key — \`path\``. Both fixes ran (the
    # path-wrap and the now-skipped paren conversion); n_fixes counts the
    # path-wrap only.
    assert n_fixes >= 1
    assert "| F-001 | Hardcoded key — `lib/insecurity.ts:23` |" in fixed


def test_path_wrapping_skips_code_fences_and_markdown_urls():
    md = textwrap.dedent("""\
        ```text
        routes/login.ts:34
        ```

        See [login](routes/login.ts) and routes/admin.ts:12.
    """)

    fixed, n_fixes = prose.apply_fixes(md)

    assert n_fixes == 1
    assert "```text\nroutes/login.ts:34\n```" in fixed
    assert "[login](routes/login.ts)" in fixed
    assert "`routes/admin.ts:12`" in fixed


# ---------------------------------------------------------------------------
# 2026-05 R-7 — code-token classes added on top of `_PATH_RE`:
#   * `_URL_PATH_RE`           — bare URL paths like `/rest/user/login`
#   * `_HTTP_METHOD_PATH_RE`   — `GET /support/logs` → method bare, path wrapped
#   * `_BARE_FILENAME_RE`      — standalone filenames `login.ts`, `app.guard.ts:54`
#   * `_FUNCTION_CALL_RE`      — call tokens like `eval()`, `helmet.noSniff()`
#   * `_LITERAL_TOKEN_RE`      — JWT/HTTP literals like `alg:none`, `role:admin`
# Every pattern must respect the shared forbidden-zone mask (existing
# backticks, link URLs, HTML attrs, `<details>` / `<pre>` / `<code>` blocks,
# markdown link labels).
# ---------------------------------------------------------------------------


def test_url_path_token_is_wrapped():
    md = "Visit /rest/user/login to authenticate.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 1
    assert "`/rest/user/login`" in fixed


def test_url_path_skips_already_backticked():
    md = "Visit `/rest/user/login` to authenticate.\n"
    fixed, n = prose.apply_fixes(md)
    assert n == 0
    assert "``/rest/user/login``" not in fixed


def test_url_path_skips_too_short_first_segment():
    # `and/or` — first segment after `/` is only 2 chars, rejected by the
    # `{2,}` quantifier on the first segment.
    md = "Use and/or to combine clauses.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "`/or`" not in fixed


def test_http_method_path_wraps_only_the_route():
    md = "Call GET /support/logs to fetch the file.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 1
    # Method stays bare; only the route is backticked.
    assert "GET `/support/logs`" in fixed
    assert "`GET /support/logs`" not in fixed


def test_http_method_path_trailing_punctuation_stays_outside():
    md = "Issue POST /api/login, then check the cookie.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "POST `/api/login`," in fixed


def test_bare_filename_is_wrapped():
    md = "The handler in login.ts validates the token.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 1
    assert "`login.ts`" in fixed


def test_bare_filename_with_line_number():
    md = "See app.guard.ts:54 for the missing check.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 1
    assert "`app.guard.ts:54`" in fixed


def test_bare_filename_allowlist_node_js_not_wrapped():
    # `Node.js` matches the filename pattern but is a product name —
    # excluded via _BARE_FILENAME_ALLOWLIST so it reads as prose.
    md = "The Node.js process crashes on malformed input.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "`Node.js`" not in fixed


def test_function_call_token_is_wrapped():
    md = "The handler invokes eval() on user input.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 1
    assert "`eval()`" in fixed


def test_function_call_dotted_path_is_wrapped():
    md = "Configure helmet.noSniff() before mounting routes.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 1
    assert "`helmet.noSniff()`" in fixed


def test_function_call_skips_paren_prose():
    # Parens in prose without a leading identifier must NOT match.
    md = "The resulting (broken) check is silently skipped.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "`(broken)`" not in fixed
    assert "`()`" not in fixed


def test_jwt_literal_alg_none_is_wrapped():
    md = "Submit a token with alg:none to bypass verification.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 1
    assert "`alg:none`" in fixed


def test_role_literal_is_wrapped():
    md = "Promotes the caller to role:admin without checks.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 1
    assert "`role:admin`" in fixed


def test_literal_token_outside_allowlist_left_alone():
    # `alg:CUSTOM` is not in the narrow allowlist — must NOT be wrapped.
    md = "The library accepts alg:CUSTOM via its options.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "`alg:CUSTOM`" not in fixed


def test_r7_tokens_inside_inline_code_tag_are_preserved():
    # Inline `<code>…</code>` spans (single-line) are protected as
    # forbidden zones by `_HTML_CODE_INLINE_RE`. Multi-line `<pre>` blocks
    # are processed per-line and are not currently covered — see
    # _wrap_line docstring; the §8-cell renderer keeps them on one line.
    md = "Example: <code>GET /api/login alg:none</code> stays raw.\n"
    fixed, n = prose.apply_fixes(md)
    assert n == 0
    assert "<code>GET /api/login alg:none</code>" in fixed


def test_r7_tokens_inside_markdown_link_label_are_preserved():
    # Tokens inside `[label](url)` MUST stay raw — backticking them would
    # break the link rendering.
    md = "See [POST /api/login](https://example.com/docs) for details.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "[POST /api/login](https://example.com/docs)" in fixed


def test_lib_version_token_is_wrapped():
    md = "express-jwt@0.1.3 and jsonwebtoken@0.4.0 are both outdated.\n"
    fixed, n = prose.apply_fixes(md)
    assert n >= 2
    assert "`express-jwt@0.1.3`" in fixed
    assert "`jsonwebtoken@0.4.0`" in fixed


def test_scoped_lib_version_token_is_wrapped():
    md = "The app pins @angular/core@15.2.0 in package.json.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "`@angular/core@15.2.0`" in fixed


def test_email_address_is_not_treated_as_lib_version():
    md = "Report issues to security@example.com promptly.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "`security@example.com`" not in fixed
    assert "security@example.com" in fixed


def test_cve_identifier_is_wrapped():
    md = "jsonwebtoken@0.4.0 is vulnerable to CVE-2020-28042.\n"
    fixed, n = prose.apply_fixes(md)
    assert "`CVE-2020-28042`" in fixed


def test_linked_cve_label_is_preserved():
    md = "See [CVE-2020-28042](https://nvd.nist.gov/vuln/detail/CVE-2020-28042) details.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "[CVE-2020-28042](https://nvd.nist.gov/vuln/detail/CVE-2020-28042)" in fixed
    assert "`CVE-2020-28042`" not in fixed


def test_bare_algorithm_name_is_wrapped():
    md = "An attacker can switch to HS256 using the public RS256 key.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "`HS256`" in fixed
    assert "`RS256`" in fixed


def test_alg_prefixed_literal_not_double_wrapped():
    # `alg:HS256` is owned by the literal-token pass — the HS256 inside must
    # not be separately backticked, and the whole literal wraps once.
    md = "The header sets alg:HS256 explicitly.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "`alg:HS256`" in fixed
    assert "alg:`HS256`" not in fixed


def test_algorithm_word_boundary_avoids_false_match():
    md = "The nonce token labelled THINGS256 is unrelated.\n"
    fixed, _ = prose.apply_fixes(md)
    assert "THINGS256" in fixed
    assert "`HS256`" not in fixed


def test_section3_token_block_is_fully_formatted():
    """Regression for the §3 attack-step block reported 2026-05-31 — every
    code-like token (lib@version, function call, file:line, alg literal, bare
    algorithm, path, CVE) must end up backticked in one pass."""
    md = textwrap.dedent("""\
        express-jwt@0.1.3 and jws.verify() in lib/insecurity.ts:57 do not enforce expected algorithm.
        An attacker can modify the JWT header to alg:none, or switch to HS256 using the key from /encryptionkeys/jwt.pub.
        jsonwebtoken@0.4.0 is vulnerable to CVE-2020-28042.
    """)
    fixed, _ = prose.apply_fixes(md)
    for tok in (
        "`express-jwt@0.1.3`", "`jws.verify()`", "`lib/insecurity.ts:57`",
        "`alg:none`", "`HS256`", "`/encryptionkeys/jwt.pub`",
        "`jsonwebtoken@0.4.0`", "`CVE-2020-28042`",
    ):
        assert tok in fixed, f"{tok} not backticked"
    # Idempotent — a second pass changes nothing.
    twice, n2 = prose.apply_fixes(fixed)
    assert n2 == 0
    assert twice == fixed


def test_r7_full_pipeline_is_idempotent():
    md = textwrap.dedent("""\
        Call GET /rest/user/login, then invoke eval() on the body. The
        handler in login.ts:18 promotes the caller to role:admin when
        alg:none is set in the token header.
    """)
    once, n_first = prose.apply_fixes(md)
    twice, n_second = prose.apply_fixes(once)
    assert n_first > 0
    assert n_second == 0
    assert once == twice
    # All five token classes wrapped in the first pass.
    assert "GET `/rest/user/login`" in once
    assert "`eval()`" in once
    assert "`login.ts:18`" in once
    assert "`role:admin`" in once
    assert "`alg:none`" in once


def test_nosql_operator_object_is_backticked():
    # MongoDB/MarsDB operator object literals in prose get wrapped, and the
    # composer's `\$`-escape is undone inside the code span.
    md = "Sending body {id: {\\$gt:''}, message: 'hacked'} matches all docs with multi:true scope."
    out, n = prose.apply_fixes(md)
    assert n > 0
    assert "`{id: {$gt:''}, message: 'hacked'}`" in out
    assert "`multi:true`" in out
    # Idempotent.
    out2, n2 = prose.apply_fixes(out)
    assert n2 == 0 and out2 == out


def test_plain_brace_set_is_not_backticked():
    # A `{...}` span WITHOUT a query operator is plain prose, left untouched.
    md = "The role owns {read, write} on the bucket."
    out, n = prose.apply_fixes(md)
    assert "{read, write}" in out and "`{read, write}`" not in out


def test_nosql_object_inside_existing_code_span_is_preserved():
    md = "Already-formatted `{id: {$gt: ''}}` stays as one span."
    out, _ = prose.apply_fixes(md)
    assert out.count("`") == md.count("`")  # no new backticks injected


def test_controls_covered_bulletized_form_not_reinlined():
    """§7 fix (2026-06-04): when the composer has bulletized
    `**Controls covered:**` into a header + `- [name](#slug)` list, the
    anchor-rewrite must NOT re-add inline links onto the header (that produced
    the double-listing bug). It keeps the header bare and refreshes the bullets.
    """
    md = textwrap.dedent(
        """\
        ### 7.4 Authorization Controls

        **Controls covered:** [7.4.1 Route-Level Authorization](#741-route-level-authorization) · [7.4.2 Object-Level Authorization](#742-object-level-authorization)

        - [7.4.1 Route-Level Authorization](#741-route-level-authorization)
        - [7.4.2 Object-Level Authorization](#742-object-level-authorization)

        #### 7.4.1 Route-Level Authorization

        body

        #### 7.4.2 Object-Level Authorization

        body
        """
    )
    out, n = prose.apply_fixes(md)
    # The inline `· `-joined link line is collapsed to a bare header.
    assert "**Controls covered:**\n" in out
    assert "**Controls covered:** [7.4.1" not in out
    # Exactly one header + the two bullets survive (no duplication).
    assert out.count("**Controls covered:**") == 1
    assert out.count("- [7.4.1 Route-Level Authorization](#741-route-level-authorization)") == 1
    assert out.count("- [7.4.2 Object-Level Authorization](#742-object-level-authorization)") == 1
    # Idempotent.
    out2, n2 = prose.apply_fixes(out)
    assert n2 == 0 and out2 == out


def test_controls_covered_legacy_inline_form_preserved():
    """With no bullet list following, the historical inline `a · b` rendering
    is kept (and anchors refreshed) — only the bulletized layout collapses."""
    md = textwrap.dedent(
        """\
        ### 7.4 Authorization Controls

        **Controls covered:** [7.4.1 Route-Level Authorization](#wrong-anchor)

        #### 7.4.1 Route-Level Authorization

        body
        """
    )
    out, _ = prose.apply_fixes(md)
    assert "**Controls covered:** [7.4.1 Route-Level Authorization](#741-route-level-authorization)" in out
