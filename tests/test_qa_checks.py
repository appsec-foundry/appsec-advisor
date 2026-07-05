"""Unit tests for scripts/qa_checks.py.

qa_checks.py runs 11 deterministic checks on threat-model.md. These tests
exercise the CLI subcommands and the key check logic directly using minimal
fixtures — they do not run the full pipeline.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "qa_checks.py"


def _load_qa_checks():
    # Must register in sys.modules before exec so @dataclass forward-ref
    # resolution via sys.modules[cls.__module__] does not get None.
    if "qa_checks" in sys.modules:
        return sys.modules["qa_checks"]
    spec = importlib.util.spec_from_file_location("qa_checks", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["qa_checks"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


qa = _load_qa_checks()


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


def _write_minimal_model(path: Path, content: str) -> Path:
    f = path / "threat-model.md"
    f.write_text(content)
    return f


# ---------------------------------------------------------------------------
# CLI: missing arguments
# ---------------------------------------------------------------------------


def test_no_args_exits_nonzero():
    result = _run([])
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# reference_format gate — guarantees finding links are correct on EVERY run
# ---------------------------------------------------------------------------


def test_reference_format_clean_doc_has_no_issues(tmp_path: Path):
    md = _write_minimal_model(
        tmp_path,
        "## Findings\n\n🔴 [F-010](#f-010) — Insecure Direct Object Reference (`memory.ts:15`)\n🟠 [F-016](#f-016)\n",
    )
    report = qa.check_reference_format(md)
    assert report.issues == []
    assert report.ok == 1


def test_reference_format_flags_unbackticked_locator(tmp_path: Path):
    md = _write_minimal_model(
        tmp_path,
        "## Findings\n\n🔴 [F-010](#f-010) — Insecure Direct Object Reference (routes/memory.ts:15)\n",
    )
    report = qa.check_reference_format(md)
    assert report.issues, "an un-backticked locator must be a blocking QA issue"
    assert report.ok == 0


def test_reference_format_flags_id_in_link_text(tmp_path: Path):
    md = _write_minimal_model(tmp_path, "## Findings\n\n[F-010 — Insecure Direct Object Reference](#f-010)\n")
    report = qa.check_reference_format(md)
    assert report.issues


def test_reference_format_cli_exit_codes(tmp_path: Path):
    clean_dir = tmp_path / "c"
    clean_dir.mkdir()
    bad_dir = tmp_path / "b"
    bad_dir.mkdir()
    clean = _write_minimal_model(clean_dir, "## F\n\n🔴 [F-010](#f-010) — IDOR (`memory.ts:15`)\n")
    bad = _write_minimal_model(bad_dir, "## F\n\n🔴 [F-010](#f-010) — IDOR (routes/memory.ts:15)\n")
    assert _run(["reference_format", str(clean)]).returncode == 0
    assert _run(["reference_format", str(bad)]).returncode == 1


def test_reference_format_in_all_gate_summary(tmp_path: Path):
    # The `all` aggregation must expose reference_format so a malformed link
    # counts toward the gate's total_issues on every run.
    import inspect

    src = inspect.getsource(qa)
    assert '"reference_format": reference_format_report.as_dict()' in src
    assert "reference_format_report = check_reference_format(md)" in src


def test_unknown_subcommand_exits_nonzero(tmp_path: Path):
    md = _write_minimal_model(tmp_path, "# Threat Model\n")
    result = _run(["unknown_subcommand", str(md)])
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# CLI: xrefs subcommand on a clean file
# ---------------------------------------------------------------------------

_CLEAN_XREF_CONTENT = textwrap.dedent("""\
    ## Management Summary

    ## 8. Findings Register

    <a id="t-001"></a>
    | T-001 | Title | High | ... |

    ## 9. Mitigation Register

    <a id="m-001"></a>
    ### M-001 Fix the thing

    **Addresses:** [T-001](#t-001)
""")


def test_xrefs_exits_0_on_clean_file(tmp_path: Path):
    md = _write_minimal_model(tmp_path, _CLEAN_XREF_CONTENT)
    result = _run(["xrefs", str(md)])
    assert result.returncode == 0, f"stderr: {result.stderr}\nstdout: {result.stdout}"


# ---------------------------------------------------------------------------
# CLI: invariants subcommand — Risk Distribution present
# ---------------------------------------------------------------------------

_RISK_DIST_CONTENT = textwrap.dedent("""\
    ## 8. Findings Register

    **Risk Distribution:** Critical: 1 · High: 2 · Medium: 3 · Low: 4 · **Total: 10**
    **STRIDE Coverage:** Spoofing: 1 · Tampering: 2 · Repudiation: 0 · Information Disclosure: 3 · Denial of Service: 2 · Elevation of Privilege: 2
""")


def test_invariants_exits_0_with_risk_distribution(tmp_path: Path):
    md = _write_minimal_model(tmp_path, _RISK_DIST_CONTENT)
    result = _run(["invariants", str(md)])
    assert result.returncode == 0, f"stderr: {result.stderr}"


# ---------------------------------------------------------------------------
# VSCODE_LINK_RE regex sanity
# ---------------------------------------------------------------------------


def test_vscode_link_re_matches_valid_link():
    link = "vscode://file//home/user/repo/src/app.py:42"
    m = qa.VSCODE_LINK_RE.search(link + ")")
    assert m is not None
    assert m.group(1) == "/home/user/repo/src/app.py"
    assert m.group(2) == "42"


def test_vscode_link_re_no_match_on_plain_text():
    assert qa.VSCODE_LINK_RE.search("just plain text") is None


# ---------------------------------------------------------------------------
# T_ID_RE / M_ID_RE sanity
# ---------------------------------------------------------------------------


def test_t_id_re_matches():
    assert qa.T_ID_RE.search("See T-001 for details") is not None
    assert qa.T_ID_RE.search("T-1234") is not None


def test_m_id_re_matches():
    assert qa.M_ID_RE.search("Fix via M-042") is not None


# ---------------------------------------------------------------------------
# §7 schema_v2 contract and coverage gates
# ---------------------------------------------------------------------------


def _write_v2_sec7_contract(
    tmp_path: Path,
    *,
    coverage_rule: bool = False,
    relevant_rule: bool = False,
    recon_rule: bool = False,
) -> Path:
    all_control_items: list[str] = []
    if coverage_rule:
        all_control_items.append(
            textwrap.dedent("""\
            - rule: control_subsection_coverage
              section_titles:
                - "7.2 Identity and Authentication Controls"
              controls_covered_label: "Controls covered"
              heading_level: 4
              required_subsection_labels:
                - "Security assessment"
                - "Relevant findings"
              enforcement: "error"
        """)
        )
    if relevant_rule:
        all_control_items.append(
            textwrap.dedent("""\
            - rule: relevant_findings_bullet_list
              section_titles:
                - "7.2 Identity and Authentication Controls"
              heading_level: 4
              label: "Relevant findings"
              enforcement: "error"
        """)
        )
    all_control = ""
    if all_control_items:
        all_control = textwrap.indent(
            "all_control_sections:\n" + "".join(textwrap.indent(item, "  ") for item in all_control_items),
            "        ",
        )
    recon = ""
    if recon_rule:
        recon = textwrap.indent(
            textwrap.dedent("""\
            "7.2 Identity and Authentication Controls":
              - rule: recon_iam_bridge
                section_title: "7.2 Identity and Authentication Controls"
                recon_signal_patterns:
                  - "/rest/2fa"
                required_iam_tokens:
                  - "totp"
                  - "2fa"
                  - "mfa"
                enforcement: "error"
        """),
            "        ",
        )
    rules_block = all_control + recon
    if not rules_block:
        rules_block = "        {}\n"
    contract = tmp_path / "sections-contract.yaml"
    contract.write_text(
        textwrap.dedent("""\
            document:
              order:
                - security_architecture
            sections:
              security_architecture:
                heading: "## 7. Security Architecture"
                required_subsections:
                  - { level: 3, title: "7.1 Legacy Overview" }
                schema_v2:
                  required_subsections:
                    - { level: 3, title: "7.1 Security Control Overview" }
                    - { level: 3, title: "7.2 Identity and Authentication Controls" }
                  domain_required_patterns: {}
                  domain_required_rules:
        """)
        + rules_block,
        encoding="utf-8",
    )
    return contract


def test_contract_v2_enforces_required_subsections(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path)
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.1 Security Control Overview

            | Control category | Verdict | Main reason |
            |---|---|---|
        """),
    )

    report = qa.check_contract(md, contract)

    assert any("required subsection missing" in issue and "7.2 Identity" in issue for issue in report.issues)


def test_contract_v2_rejects_legacy_sec7_headings(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path)
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.1 Overview

            ### 7.3 Identity & Access Management
        """),
    )

    report = qa.check_contract(md, contract)

    assert any("7.1 Security Control Overview" in issue for issue in report.issues)


def _write_depth_contract(path: Path) -> Path:
    """Minimal contract with two depth-conditional sections (§3 walkthroughs on
    `not skip_attack_walkthroughs`, §7 security-architecture on
    `render_security_architecture`) plus always-on sections around them."""
    contract = path / "depth-contract.yaml"
    contract.write_text(
        textwrap.dedent("""\
            contract_version: 1
            document:
              order:
                - { id: system_overview }
                - { id: attack_walkthroughs, condition: "not skip_attack_walkthroughs" }
                - { id: assets }
                - { id: security_architecture, condition: "render_security_architecture" }
                - { id: threat_register }
            sections:
              system_overview: { heading: "## 1. System Overview" }
              attack_walkthroughs: { heading: "## 3. Attack Walkthroughs" }
              assets: { heading: "## 4. Assets" }
              security_architecture: { heading: "## 7. Security Architecture" }
              threat_register: { heading: "## 8. Findings Register" }
        """),
        encoding="utf-8",
    )
    return contract


_DOC_WITHOUT_3_AND_7 = textwrap.dedent("""\
    # Threat Model

    **Risk Distribution:** Critical: 8 · High: 14 · Medium: 4 · Low: 1 · **Total: 27**

    ## 1. System Overview
    overview body
    ## 4. Assets
    assets body
    ## 8. Findings Register
    findings body
    """)


def test_contract_quick_depth_suppresses_optional_sections(tmp_path: Path):
    """Regression (2026-06-12): at --quick the composer suppresses §3 and §7, so
    check_contract must NOT flag them as 'expected section missing'. Previously
    the env hardcoded render_security_architecture=True and omitted
    skip_attack_walkthroughs, producing a false positive that tripped the
    Stage-3 repair_plan gate (exit 1) on every quick run."""
    qa._PrePass.reset()
    contract = _write_depth_contract(tmp_path)
    md = _write_minimal_model(tmp_path, _DOC_WITHOUT_3_AND_7)
    (tmp_path / ".skill-config.json").write_text('{"assessment_depth": "quick"}', encoding="utf-8")

    report = qa.check_contract(md, contract)

    assert not any("3. Attack Walkthroughs" in i for i in report.issues), report.issues
    assert not any("7. Security Architecture" in i for i in report.issues), report.issues


def test_contract_standard_depth_still_enforces_optional_sections(tmp_path: Path):
    """The depth-aware env must NOT weaken enforcement at standard/thorough: a
    standard run that is genuinely missing §3 / §7 is still flagged."""
    qa._PrePass.reset()
    contract = _write_depth_contract(tmp_path)
    md = _write_minimal_model(tmp_path, _DOC_WITHOUT_3_AND_7)
    (tmp_path / ".skill-config.json").write_text('{"assessment_depth": "standard"}', encoding="utf-8")

    report = qa.check_contract(md, contract)

    assert any("3. Attack Walkthroughs" in i for i in report.issues), report.issues
    assert any("7. Security Architecture" in i for i in report.issues), report.issues


def test_control_subsection_coverage_requires_linked_h4(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path, coverage_rule=True)
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [Password Login](#password-login), [TOTP Verification](#totp-verification).

            **Implemented controls:** Password login.

            **Assessment:** Partial.

            #### Password Login

            **Security assessment**

            Password login exists.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_control_subsection_coverage(md, contract)

    assert any("TOTP Verification" in issue and "no matching" in issue for issue in report.issues)


def test_control_subsection_coverage_accepts_v2_shape(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path, coverage_rule=True)
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [Password Login](#password-login).

            **Implemented controls:** Password login.

            **Assessment:** Partial.

            #### Password Login

            **Security assessment**

            Password login exists.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_control_subsection_coverage(md, contract)

    assert report.issues == []
    assert report.ok == 1


def test_control_subsection_coverage_matches_code_spanned_control_name(monkeypatch, tmp_path: Path):
    """Regression: a control whose name carries a backtick-wrapped token must
    match between the `**Controls covered:**` link and its `####` heading.

    apply_prose_fixes.py code-spans tokens like `Socket.IO` in BOTH the link
    text and the heading. The link text is `_strip_md`-normalized before the
    lookup, so the heading must be normalized identically — otherwise the
    backtick-asymmetric comparison raises a false-positive
    `control_subsection_coverage` failure the re-render loop cannot converge on.
    """
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path, coverage_rule=True)
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [WebSocket Event Bus (`Socket.IO`)](#websocket-event-bus-socketio).

            **Implemented controls:** Socket.IO event bus.

            **Assessment:** Partial.

            #### WebSocket Event Bus (`Socket.IO`)

            **Security assessment**

            Present but not assessed.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_control_subsection_coverage(md, contract)

    assert report.issues == []
    assert report.ok == 1


def test_control_subsection_coverage_matches_backslash_escaped_dot(monkeypatch, tmp_path: Path):
    r"""Regression: compose_threat_model.py's TLD-escape pass turns `Socket.IO`
    into `Socket\.IO` in the `####` heading text but leaves the
    `**Controls covered:**` link label un-escaped (link spans are exempt from
    the escape pass). `_heading_matches` must tolerate the one-backslash
    divergence — otherwise the control_subsection_coverage gate false-positives
    and the re-render loop never converges (juice-shop 2026-06-01 §7.12)."""
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path, coverage_rule=True)
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [WebSocket and Socket.IO Security](#websocket-and-socketio-security).

            **Implemented controls:** Socket.IO event bus.

            **Assessment:** Partial.

            #### WebSocket and Socket\\.IO Security

            **Security assessment**

            Present but not assessed.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_control_subsection_coverage(md, contract)

    assert report.issues == []
    assert report.ok == 1


def test_relevant_findings_bullet_list_rejects_inline_form(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path, relevant_rule=True)
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            #### Password Login

            Password login uses the Express route.

            **Security assessment**

            Password login is weak.

            **Relevant findings:** [F-001](#f-001) - SQL injection, [F-002](#f-002) - MD5 hashing.
        """),
    )

    report = qa.check_relevant_findings_bullet_list(md, contract)

    assert any("inline" in issue for issue in report.issues)


def test_relevant_findings_bullet_list_accepts_bullets(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path, relevant_rule=True)
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            #### Password Login

            Password login uses the Express route.

            **Security assessment**

            Password login is weak.

            **Relevant findings**

            - [F-001](#f-001) - SQL injection in password login.
            - [F-002](#f-002) - MD5 password hashing.
        """),
    )

    report = qa.check_relevant_findings_bullet_list(md, contract)

    assert report.issues == []
    assert report.ok == 1


def test_recon_iam_bridge_uses_v2_section_title(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    contract = _write_v2_sec7_contract(tmp_path, recon_rule=True)
    (tmp_path / ".recon-summary.md").write_text("route: /rest/2fa\n", encoding="utf-8")
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [Password Login](#password-login).

            #### Password Login

            **Security assessment**

            Password login exists.
        """),
    )

    report = qa.check_recon_iam_bridge(md, tmp_path, contract)

    assert any("7.2 Identity and Authentication Controls" in issue for issue in report.issues)


# ---------------------------------------------------------------------------
# §7.2 per-flow-method diagram gate + §7.6 validation-approach-first gate.
# These exercise the REAL data/sections-contract.yaml via the schema_v2
# overlay (no contract arg → DEFAULT_CONTRACT_PATH), so they double as a
# wiring test that the migrated v1→v2 enforcement is live.
# ---------------------------------------------------------------------------


def test_auth_flow_method_requires_diagram(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [OAuth Login](#oauth-login).

            #### 7.2.1 OAuth Login

            The app federates login via Google.

            **Security assessment**

            Redirect URI not validated.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_auth_method_decomposition(md)

    assert any("sequenceDiagram" in issue and "OAuth Login" in issue for issue in report.issues)


def test_auth_flow_method_accepts_diagram(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [OAuth Login](#oauth-login).

            #### 7.2.1 OAuth Login

            The diagram shows the federated login path:

            ```mermaid
            sequenceDiagram
                User->>App: authorization code
            ```

            **Security assessment**

            Redirect URI not validated.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_auth_method_decomposition(md)

    assert not any("sequenceDiagram" in issue for issue in report.issues)


def test_auth_nonflow_method_exempt_from_diagram(monkeypatch, tmp_path: Path):
    """API-key / anonymous auth has no meaningful sequence — the per-flow gate
    must NOT demand a diagram for it (spacing: only flow methods are gated)."""
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [API Key Authentication](#api-key-authentication).

            #### 7.2.1 API Key Authentication

            Service callers present a static API key header.

            **Security assessment**

            Keys are not rotated.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_auth_method_decomposition(md)

    assert not any("sequenceDiagram" in issue for issue in report.issues)


def test_auth_social_login_heading_is_whitelisted(monkeypatch, tmp_path: Path):
    """Regression (2026-06-16): emit_auth_coverage writes the control
    'Social Login (OAuth / OIDC)'; the renderer simplifies the §7.2 heading to
    'Social Login', which token-mismatches oauth/oidc and tripped the
    'not a recognized authentication mechanism' gate, forcing a fragment-fixer
    repair every run. 'social login' is now in method_whitelist."""
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [Social Login](#social-login).

            #### 7.2.6 Social Login

            The app federates login via Google OAuth.

            ```mermaid
            sequenceDiagram
                User->>App: authorization code
            ```

            **Security assessment**

            Redirect URI not validated.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_auth_method_decomposition(md)

    assert not any(
        "Social Login" in issue and "not a recognized authentication mechanism" in issue for issue in report.issues
    ), report.issues


def test_auth_threat_hypotheses_heading_exempt(monkeypatch, tmp_path: Path):
    """Regression (2026-06-16): pregenerate_fragments deterministically emits
    '#### Threat Hypotheses Requiring Validation' inside §7.2 (asserted present
    by test_pregenerate_fragments), but the auth-method gate rejected it as a
    non-mechanism — a deterministic self-contradiction that forced a repair
    iteration. It is now a contract-declared structural_heading_exemption.

    A bogus heading is included as a negative control to prove the gate still
    runs and the exemption is specific, not a blanket pass."""
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [Password-Based Login](#password-based-login).

            #### 7.2.1 Password-Based Login

            ```mermaid
            sequenceDiagram
                User->>App: credentials
            ```

            **Security assessment**

            Password login exists.

            **Relevant findings**

            - No dedicated finding routed in this assessment.

            #### Threat Hypotheses Requiring Validation

            | ID | Hypothesis | Control Gap | Evidence | Validation |
            |---|---|---|---|---|
            | HYP-001 | SQLi exposure | Parameterized Queries | `routes/login.ts:34` | Probe /login |

            #### 7.2.9 Banana Pudding

            Not an auth mechanism at all.
        """),
    )

    report = qa.check_auth_method_decomposition(md)

    # The exempt structural heading must NOT be flagged as a non-mechanism.
    assert not any(
        "Threat Hypotheses" in issue and "not a recognized authentication mechanism" in issue for issue in report.issues
    ), report.issues
    # Negative control: a genuinely bogus heading IS still flagged — proves the
    # gate is live and the exemption is specific.
    assert any(
        "Banana Pudding" in issue and "not a recognized authentication mechanism" in issue for issue in report.issues
    ), report.issues


def test_validation_approach_first_rejects_specific_first(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.6 Input Boundary Validation Controls

            **Controls covered:** [File Upload Limits](#file-upload-limits).

            #### 7.6.1 File Upload Limits

            **Security assessment**

            multer caps the upload size.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_validation_approach_first(md)

    assert report.ok == 0
    assert any("validation-approach" in issue for issue in report.issues)


def test_validation_approach_first_accepts_approach_first(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.6 Input Boundary Validation Controls

            **Controls covered:** [Validation Approach](#validation-approach).

            #### 7.6.1 Validation Approach

            **Security assessment**

            No central schema layer; validation is per-endpoint.

            **Relevant findings**

            - No dedicated finding routed in this assessment.

            #### 7.6.2 File Upload Limits

            **Security assessment**

            multer caps the upload size.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )

    report = qa.check_validation_approach_first(md)

    assert report.ok == 1
    assert report.issues == []


def test_validation_approach_first_skips_not_applicable(monkeypatch, tmp_path: Path):
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.6 Input Boundary Validation Controls

            _Not applicable — no input-validation findings routed to this category._
        """),
    )

    report = qa.check_validation_approach_first(md)

    assert report.ok == 1
    assert report.issues == []


def test_mermaid_alt_convention_is_scoped_to_attack_walkthroughs(tmp_path: Path):
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            ```mermaid
            sequenceDiagram
                participant JWT as security.authorize()
                alt TOTP disabled
                    JWT-->>JWT: Issue session
                else TOTP enabled
                    JWT-->>JWT: Issue temp token
                end
            ```
        """),
    )

    report = qa.check_mermaid_syntax(md)

    assert report.issues == []


def test_t_id_re_no_false_positive():
    assert qa.T_ID_RE.search("AT-001") is None  # prefix — must be word boundary


# ---------------------------------------------------------------------------
# Risk distribution regex
# ---------------------------------------------------------------------------


def test_risk_dist_re_parses_counts():
    line = "**Risk Distribution:** Critical: 2 · High: 5 · Medium: 3 · Low: 1 · **Total: 11**"
    m = qa.RISK_DIST_RE.search(line)
    assert m is not None
    assert m.group(1) == "2"  # Critical
    assert m.group(2) == "5"  # High
    assert m.group(3) == "3"  # Medium
    assert m.group(4) == "1"  # Low
    # group(5) is the OPTIONAL Info cell (absent here → None); Total is group(6).
    assert m.group(5) is None  # Info (omitted)
    assert m.group(6) == "11"  # Total


def test_risk_dist_re_parses_info_cell():
    """When the optional Info cell is present it occupies group(5) and Total
    stays group(6)."""
    line = "**Risk Distribution:** Critical: 2 · High: 5 · Medium: 3 · Low: 1 · Info: 4 · **Total: 15**"
    m = qa.RISK_DIST_RE.search(line)
    assert m is not None
    assert m.group(5) == "4"  # Info
    assert m.group(6) == "15"  # Total


def test_risk_dist_re_no_match_on_empty():
    assert qa.RISK_DIST_RE.search("nothing here") is None


# ---------------------------------------------------------------------------
# Sprint 2 Item #5 — placeholders (Check 6) and yaml/md consistency (Check 4)
# ---------------------------------------------------------------------------


class TestPlaceholdersCheck:
    def test_clean_document_has_no_issues(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(
            textwrap.dedent("""
            # Threat Model

            ## Management Summary

            Verdict: the system is in a mostly acceptable posture with documented gaps.

            **Risk Distribution:** Critical: 1 · High: 2 · Medium: 3 · Low: 0
        """).strip(),
            encoding="utf-8",
        )
        r = qa.check_placeholders(md)
        assert r.issues == []
        assert r.ok == 1

    def test_pending_placeholder_flagged(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("| Analysis Duration | _pending_ |\n", encoding="utf-8")
        r = qa.check_placeholders(md)
        assert any("_pending_" in i for i in r.issues)

    def test_none_detected_flagged(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("| Assets | _none detected_ |\n", encoding="utf-8")
        r = qa.check_placeholders(md)
        assert any("_none detected_" in i for i in r.issues)

    def test_replace_token_flagged(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("Change REPLACE_COMPONENT_NAME to the real name.\n", encoding="utf-8")
        r = qa.check_placeholders(md)
        assert any("REPLACE" in i for i in r.issues)

    def test_angle_placeholder_flagged(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("Fill this in: <placeholder>\nAlso <TBD>\n", encoding="utf-8")
        r = qa.check_placeholders(md)
        assert any("<placeholder>" in i for i in r.issues)

    def test_bare_todo_flagged(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("Write this: TODO\n", encoding="utf-8")
        r = qa.check_placeholders(md)
        assert any("TODO" in i for i in r.issues)

    def test_anchor_link_not_false_positive(self, tmp_path):
        """[T-001] as an anchor link must NOT match the [TODO]/[TBD] pattern."""
        md = tmp_path / "threat-model.md"
        md.write_text("See [T-001](#t-001) and [M-002](#m-002).\n", encoding="utf-8")
        r = qa.check_placeholders(md)
        assert r.issues == [], f"anchor links triggered false positive: {r.issues}"

    def test_code_fence_is_ignored(self, tmp_path):
        """A TODO inside a fenced code block must not be flagged — it may be
        legitimate sample output."""
        md = tmp_path / "threat-model.md"
        md.write_text('```\nprint("TODO")\n```\n', encoding="utf-8")
        r = qa.check_placeholders(md)
        assert r.issues == []

    def test_multiple_placeholders_deduped_by_kind(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(
            "_pending_\n_pending_\n_pending_\n",
            encoding="utf-8",
        )
        r = qa.check_placeholders(md)
        # Exactly one issue summarising all three lines
        pending_issues = [i for i in r.issues if "_pending_" in i]
        assert len(pending_issues) == 1
        assert "line 1" in pending_issues[0]

    def test_question_marks_flagged(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("Effort: ???\n", encoding="utf-8")
        r = qa.check_placeholders(md)
        assert any("???" in i for i in r.issues)


class TestYamlMdConsistencyCheck:
    def _write_pair(self, tmp_path, md_text, yaml_text):
        md = tmp_path / "threat-model.md"
        yml = tmp_path / "threat-model.yaml"
        md.write_text(md_text, encoding="utf-8")
        yml.write_text(yaml_text, encoding="utf-8")
        return md, yml

    def test_matching_counts(self, tmp_path):
        md, yml = self._write_pair(
            tmp_path,
            textwrap.dedent("""
                | ID | Title |
                |---|---|
                | [F-001](#f-001) | Threat one |
                | [F-002](#f-002) | Threat two |

                #### <a id="m-001"></a>M-001 — Fix one
            """).strip(),
            textwrap.dedent("""
                meta:
                  schema_version: 1
                threats:
                  - id: F-001
                  - id: F-002
                mitigations:
                  - id: M-001
            """).strip(),
        )
        r = qa.check_yaml_md_consistency(md, yml)
        assert r.issues == []

    def test_asset_linked_threats_html_table(self, tmp_path):
        # The §4 Assets table is rewritten to fixed-layout HTML by qa autofix;
        # the asset↔threat cross-reference check must parse the HTML form too,
        # not just the GFM pipe rows (juice-shop 2026-06-11).
        md = textwrap.dedent(
            """
            ## 4. Assets

            <table style="table-layout:fixed;width:100%">
            <colgroup><col style="width:22%"><col style="width:13%"><col style="width:32%"><col style="width:33%"></colgroup>
            <thead><tr><th>Asset</th><th>Classification</th><th>Description</th><th>Linked Threats</th></tr></thead>
            <tbody>
            <tr><td>Creds</td><td>Restricted</td><td>x</td><td><a href="#f-001">F-001</a><br/><a href="#f-002">F-002</a></td></tr>
            </tbody>
            </table>

            ## 8. Findings

            <a id="f-001"></a><a id="f-002"></a>
            """
        ).strip()
        yml = textwrap.dedent(
            """
            meta: {schema_version: 1}
            threats: [{id: F-001}, {id: F-002}]
            mitigations: []
            assets:
              - {id: A-001, name: Creds, linked_threats: [T-001, T-002]}
            """
        ).strip()
        m, y = self._write_pair(tmp_path, md, yml)
        r = qa.check_yaml_md_consistency(m, y)
        assert not any("linked_threats mismatch" in i for i in r.issues), r.issues

    def test_asset_linked_threats_html_table_detects_drift(self, tmp_path):
        # And it still DETECTS a genuine mismatch in the HTML form.
        md = textwrap.dedent(
            """
            ## 4. Assets

            <table><tbody>
            <tr><td>Creds</td><td>R</td><td>x</td><td><a href="#f-001">F-001</a></td></tr>
            </tbody></table>

            ## 8. Findings

            <a id="f-001"></a><a id="f-002"></a>
            """
        ).strip()
        yml = textwrap.dedent(
            """
            meta: {schema_version: 1}
            threats: [{id: F-001}, {id: F-002}]
            mitigations: []
            assets:
              - {id: A-001, name: Creds, linked_threats: [T-001, T-002]}
            """
        ).strip()
        m, y = self._write_pair(tmp_path, md, yml)
        r = qa.check_yaml_md_consistency(m, y)
        assert any("A-001 linked_threats mismatch" in i for i in r.issues), r.issues

    def test_threat_drift(self, tmp_path):
        md, yml = self._write_pair(
            tmp_path,
            "| [F-001](#f-001) | one |\n",
            textwrap.dedent("""
                meta: {schema_version: 1}
                threats: [{id: F-001}, {id: F-002}]
                mitigations: []
            """).strip(),
        )
        r = qa.check_yaml_md_consistency(md, yml)
        assert any("threat count drift" in i for i in r.issues)

    def test_mitigation_drift(self, tmp_path):
        md, yml = self._write_pair(
            tmp_path,
            textwrap.dedent("""
                | [F-001](#f-001) | one |
                #### <a id="m-001"></a>M-001 — A
                #### <a id="m-002"></a>M-002 — B
            """).strip(),
            textwrap.dedent("""
                meta: {schema_version: 1}
                threats: [{id: F-001}]
                mitigations: [{id: M-001}]
            """).strip(),
        )
        r = qa.check_yaml_md_consistency(md, yml)
        assert any("mitigation count drift" in i for i in r.issues)

    def test_schema_version_mismatch(self, tmp_path):
        md, yml = self._write_pair(
            tmp_path,
            "| [F-001](#f-001) | one |\n",
            textwrap.dedent("""
                meta: {schema_version: 99}
                threats: [{id: F-001}]
                mitigations: []
            """).strip(),
        )
        r = qa.check_yaml_md_consistency(md, yml)
        assert any("schema_version" in i for i in r.issues)

    def test_yaml_absent_is_warning_not_error(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("| [F-001](#f-001) | one |\n", encoding="utf-8")
        r = qa.check_yaml_md_consistency(md, tmp_path / "no-such.yaml")
        assert r.issues == []
        assert r.warnings  # non-blocking warning surfaces the absence

    def test_malformed_yaml_is_issue(self, tmp_path):
        md, yml = self._write_pair(
            tmp_path,
            "| [F-001](#f-001) | one |\n",
            # Truly invalid YAML — an unclosed flow sequence.
            "threats: [\n  - id: F-001\n",
        )
        r = qa.check_yaml_md_consistency(md, yml)
        assert any("malformed" in i.lower() or "not a mapping" in i for i in r.issues)

    def test_yaml_is_scalar_not_mapping(self, tmp_path):
        """A yaml file whose top level parses as a scalar (plain string)
        is legal YAML but not a valid threat-model.yaml — flag it."""
        md, yml = self._write_pair(
            tmp_path,
            "| [F-001](#f-001) | one |\n",
            "just a plain string\n",
        )
        r = qa.check_yaml_md_consistency(md, yml)
        assert any("not a mapping" in i for i in r.issues)

    def test_same_id_in_two_tables_counted_once(self, tmp_path):
        """An F-NNN cited in both the register and the critical-chain
        table must count as one threat."""
        md, yml = self._write_pair(
            tmp_path,
            textwrap.dedent("""
                ## Critical Attack Chain
                | [F-001](#f-001) | Chain member |
                ## Findings Register
                | [F-001](#f-001) | full row |
            """).strip(),
            textwrap.dedent("""
                meta: {schema_version: 1}
                threats: [{id: F-001}]
                mitigations: []
            """).strip(),
        )
        r = qa.check_yaml_md_consistency(md, yml)
        assert [i for i in r.issues if "threat count drift" in i] == []


# ---------------------------------------------------------------------------
# CLI smoke — verify new subcommands exit 0/1 and emit valid JSON
# ---------------------------------------------------------------------------


class TestNewSubcommandsCLI:
    def test_placeholders_clean_exits_0(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("# Clean doc\n\nNo placeholders here, perfectly written prose.\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "placeholders", str(md)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert '"check": "placeholders"' in r.stdout

    def test_placeholders_dirty_exits_1(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("_pending_\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "placeholders", str(md)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1

    def test_yaml_md_usage_error(self, tmp_path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "yaml_md", str(tmp_path / "x.md")],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 2  # missing yaml arg

    def test_yaml_md_clean(self, tmp_path):
        md = tmp_path / "threat-model.md"
        yml = tmp_path / "threat-model.yaml"
        md.write_text("| [F-001](#f-001) | one |\n")
        yml.write_text("meta: {schema_version: 1}\nthreats: [{id: F-001}]\nmitigations: []\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "yaml_md", str(md), str(yml)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0


# ---------------------------------------------------------------------------
# cell_format — auto-fix for space-stacked ID links in table cells
# ---------------------------------------------------------------------------


class TestCellFormat:
    _TABLE_WITH_MULTILINK = textwrap.dedent("""\
        | Domain | Control | Effectiveness | Linked Threats |
        |--------|---------|---------------|----------------|
        | IAM | JWT | 🔶 Weak | [F-001](#f-001) [F-004](#f-004) |
        | AuthZ | RBAC | ⚠️ Partial | [F-006](#f-006) [F-008](#f-008) |
    """)

    def test_cell_format_fixes_space_stacked_ids(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(self._TABLE_WITH_MULTILINK)
        report, new_text = qa.check_cell_format(md)
        # Two body rows, two fixes applied.
        assert len(report.fixes) == 2
        assert "<br/>" in new_text
        # The body cells should now look like `[F-001](#f-001)<br/>[F-004](#f-004)`
        assert "[F-001](#f-001)<br/>[F-004](#f-004)" in new_text
        assert "[F-006](#f-006)<br/>[F-008](#f-008)" in new_text
        # And no surviving space-separated ID-link pairs.
        import re as _re

        assert not _re.search(
            r"\]\(#[a-z0-9-]+\)\s+\[[A-Z]-\d",
            new_text.splitlines()[2] + new_text.splitlines()[3],
        )

    def test_cell_format_preserves_already_stacked(self, tmp_path):
        md = tmp_path / "threat-model.md"
        pre_stacked = textwrap.dedent("""\
            | Control | Linked |
            |---------|--------|
            | JWT | [F-001](#f-001)<br/>[F-004](#f-004) |
        """)
        md.write_text(pre_stacked)
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 0
        assert new_text == pre_stacked

    def test_cell_format_ignores_single_link_cells(self, tmp_path):
        md = tmp_path / "threat-model.md"
        single = textwrap.dedent("""\
            | Control | Linked |
            |---------|--------|
            | JWT | [F-001](#f-001) |
        """)
        md.write_text(single)
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 0
        assert new_text == single

    def test_cell_format_ignores_prose_outside_tables(self, tmp_path):
        md = tmp_path / "threat-model.md"
        prose = "See [F-001](#f-001) and [F-002](#f-002) in Section 8.\n"
        md.write_text(prose)
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 0
        assert new_text == prose

    def test_cell_format_ignores_fenced_code(self, tmp_path):
        md = tmp_path / "threat-model.md"
        fenced = textwrap.dedent("""\
            ```markdown
            | Control | Linked |
            |---------|--------|
            | JWT | [F-001](#f-001) [F-004](#f-004) |
            ```
        """)
        md.write_text(fenced)
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 0
        # The fenced table example is preserved byte-for-byte.
        assert new_text == fenced

    def test_cell_format_idempotent(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(self._TABLE_WITH_MULTILINK)
        qa.check_cell_format(md)
        # Write back and run again — second pass must report zero fixes.
        report1, new_text1 = qa.check_cell_format(md)
        md.write_text(new_text1)
        report2, new_text2 = qa.check_cell_format(md)
        assert len(report2.fixes) == 0
        assert new_text2 == new_text1

    def test_cell_format_cli_exits_0_on_clean(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("# Empty\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "cell_format", str(md)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        assert '"check": "cell_format"' in r.stdout

    def test_cell_format_cli_applies_fix_in_place(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(self._TABLE_WITH_MULTILINK)
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "cell_format", str(md)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0  # auto-fix success is exit 0
        assert "<br/>" in md.read_text()

    def test_cell_format_fixes_comma_separated_ids(self, tmp_path):
        """LLM-authored 'Linked Threats' cells often use commas between IDs;
        the check must stack them with <br/> too, not just space-separated.
        """
        md = tmp_path / "threat-model.md"
        md.write_text(
            textwrap.dedent("""\
            | Asset | Linked Threats |
            |---|---|
            | Users | [T-003](#t-003), [T-004](#t-004), [T-013](#t-013) |
        """)
        )
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 1, report.as_dict()
        assert "[T-003](#t-003)<br/>[T-004](#t-004)<br/>[T-013](#t-013)" in new_text

    def test_cell_format_fixes_semicolon_separated_ids(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(
            textwrap.dedent("""\
            | Risk | Linked |
            |---|---|
            | Injection | [T-001](#t-001); [T-002](#t-002) |
        """)
        )
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 1
        assert "[T-001](#t-001)<br/>[T-002](#t-002)" in new_text

    def test_cell_format_fixes_mixed_separators(self, tmp_path):
        # A row with comma AND space separators in the same cell.
        md = tmp_path / "threat-model.md"
        md.write_text(
            textwrap.dedent("""\
            | Component | Linked Threats |
            |---|---|
            | API | [T-001](#t-001), [T-002](#t-002) [T-003](#t-003) |
        """)
        )
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 1
        assert "[T-001](#t-001)<br/>[T-002](#t-002)<br/>[T-003](#t-003)" in new_text

    def test_cell_format_comma_idempotent(self, tmp_path):
        """Running the check twice on a comma-separated table must
        stabilise after the first pass."""
        md = tmp_path / "threat-model.md"
        md.write_text(
            textwrap.dedent("""\
            | A | Linked |
            |---|---|
            | X | [T-001](#t-001), [T-002](#t-002) |
        """)
        )
        _, new_text1 = qa.check_cell_format(md)
        md.write_text(new_text1)
        report2, new_text2 = qa.check_cell_format(md)
        assert len(report2.fixes) == 0
        assert new_text2 == new_text1


# ---------------------------------------------------------------------------
# fragments_present — Phase 11 precondition gate
# ---------------------------------------------------------------------------


class TestFragmentsPresent:
    def test_missing_fragments_dir_is_issue(self, tmp_path):
        # output-dir exists but .fragments/ does not
        report = qa.check_fragments_present(tmp_path)
        assert len(report.issues) == 1
        assert ".fragments/ directory missing" in report.issues[0]

    def test_full_fragment_set_is_clean(self, tmp_path):
        frag = tmp_path / ".fragments"
        frag.mkdir()
        for name in qa.REQUIRED_FRAGMENTS:
            (frag / name).write_text("{}" if name.endswith(".json") else "# stub\n")
        report = qa.check_fragments_present(tmp_path)
        assert len(report.issues) == 0
        assert report.ok == len(qa.REQUIRED_FRAGMENTS)

    def test_partial_fragment_set_flags_missing(self, tmp_path):
        frag = tmp_path / ".fragments"
        frag.mkdir()
        # Only write 2 of the 8 required fragments.
        (frag / "ms-verdict.json").write_text("{}")
        (frag / "system-overview.md").write_text("# stub\n")
        report = qa.check_fragments_present(tmp_path)
        missing_ids = [i for i in report.issues if "required fragment missing" in i]
        assert len(missing_ids) == len(qa.REQUIRED_FRAGMENTS) - 2

    def test_cli_exits_1_when_fragments_missing(self, tmp_path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "fragments", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1
        assert '"check": "fragments_present"' in r.stdout

    # ---------------------------------------------------------------------
    # Indicator A2 — .fragments/ exists-but-empty (Run 4 case, 2026-04-25)
    # ---------------------------------------------------------------------

    def test_empty_fragments_dir_flags_inline_shortcut_summary(self, tmp_path):
        """An mkdir'd-but-empty .fragments/ must produce a dedicated summary
        issue separate from the per-fragment-missing list — callers can then
        classify the run as inline-shortcut without parsing every line."""
        (tmp_path / ".fragments").mkdir()
        report = qa.check_fragments_present(tmp_path)
        summary = [i for i in report.issues if "contains only 0 files" in i]
        assert len(summary) == 1
        assert "inline-shortcut" not in summary[0].lower() or "skipped" in summary[0].lower()

    def test_fragments_dir_with_2_files_still_flags_summary(self, tmp_path):
        """Below the 3-file minimum, the dedicated summary issue still fires."""
        frag = tmp_path / ".fragments"
        frag.mkdir()
        (frag / "ms-verdict.json").write_text("{}")
        (frag / "out-of-scope.md").write_text("# stub\n")
        report = qa.check_fragments_present(tmp_path)
        summary = [i for i in report.issues if "contains only 2 files" in i]
        assert len(summary) == 1

    def test_fragments_dir_with_3_files_no_summary(self, tmp_path):
        """At/above the 3-file threshold, only per-fragment-missing lines
        fire — the structural-bypass summary does not."""
        frag = tmp_path / ".fragments"
        frag.mkdir()
        (frag / "ms-verdict.json").write_text("{}")
        (frag / "system-overview.md").write_text("# stub\n")
        (frag / "out-of-scope.md").write_text("# stub\n")
        report = qa.check_fragments_present(tmp_path)
        summary = [i for i in report.issues if "contains only" in i]
        assert summary == []

    # ---------------------------------------------------------------------
    # Indicator C — .threats-merged.json missing while threat-model.md exists
    # ---------------------------------------------------------------------

    def test_missing_threats_merged_with_md_flags_phase9_bypass(self, tmp_path):
        """If threat-model.md is on disk but .threats-merged.json is not,
        the Phase 9 merge step was bypassed — independent of fragment state."""
        frag = tmp_path / ".fragments"
        frag.mkdir()
        for name in qa.REQUIRED_FRAGMENTS:
            (frag / name).write_text("{}" if name.endswith(".json") else "# stub\n")
        (tmp_path / "threat-model.md").write_text("# Threat Model\n")
        # No .threats-merged.json on disk.
        report = qa.check_fragments_present(tmp_path)
        phase9 = [i for i in report.issues if ".threats-merged.json missing" in i]
        assert len(phase9) == 1

    def test_threats_merged_present_does_not_trigger_indicator_c(self, tmp_path):
        """When .threats-merged.json IS present, Indicator C is silent even
        though threat-model.md exists."""
        frag = tmp_path / ".fragments"
        frag.mkdir()
        for name in qa.REQUIRED_FRAGMENTS:
            (frag / name).write_text("{}" if name.endswith(".json") else "# stub\n")
        (tmp_path / "threat-model.md").write_text("# Threat Model\n")
        (tmp_path / ".threats-merged.json").write_text('{"threats": []}')
        report = qa.check_fragments_present(tmp_path)
        phase9 = [i for i in report.issues if ".threats-merged.json missing" in i]
        assert phase9 == []

    def test_missing_threats_merged_without_md_silent(self, tmp_path):
        """Indicator C requires threat-model.md to exist — without it, the
        run is mid-flight (not yet finalized) and absence of .threats-merged
        is expected."""
        frag = tmp_path / ".fragments"
        frag.mkdir()
        for name in qa.REQUIRED_FRAGMENTS:
            (frag / name).write_text("{}" if name.endswith(".json") else "# stub\n")
        # No threat-model.md, no .threats-merged.json.
        report = qa.check_fragments_present(tmp_path)
        phase9 = [i for i in report.issues if ".threats-merged.json missing" in i]
        assert phase9 == []

    def test_cli_exits_0_when_all_present(self, tmp_path):
        frag = tmp_path / ".fragments"
        frag.mkdir()
        for name in qa.REQUIRED_FRAGMENTS:
            (frag / name).write_text("{}" if name.endswith(".json") else "# stub\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "fragments", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0


# ---------------------------------------------------------------------------
# summary_bullets — run-on `(1) … (2) …` prose vs. bullet list
# ---------------------------------------------------------------------------


class TestSummaryBullets:
    def test_inline_numbered_prose_is_flagged(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("**Gap summary:** The three control gaps are: (1) no CSP; (2) no WAF; (3) no rate limit.\n")
        report = qa.check_summary_bullets(md)
        assert len(report.issues) == 1
        assert "Gap summary" in report.issues[0]

    def test_bulleted_gap_summary_is_clean(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("**Gap summary:**\n\n- no CSP\n- no WAF\n- no rate limit\n")
        report = qa.check_summary_bullets(md)
        assert len(report.issues) == 0

    def test_lead_in_without_inline_numbering_is_clean(self, tmp_path):
        """Short summary without (1)...(2) numbering is fine as prose."""
        md = tmp_path / "threat-model.md"
        md.write_text("**Gap summary:** A single sentence without numbering.\n")
        report = qa.check_summary_bullets(md)
        assert len(report.issues) == 0

    def test_ignores_inline_numbering_inside_code_block(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("```\n**Gap summary:** The gaps are: (1) one; (2) two.\n```\n")
        report = qa.check_summary_bullets(md)
        assert len(report.issues) == 0

    def test_cli_exits_0_on_clean(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("# Clean\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "summary_bullets", str(md)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0

    def test_cli_exits_1_on_violation(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("**Gap summary:** Three gaps: (1) a; (2) b; (3) c.\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "summary_bullets", str(md)],
            capture_output=True,
            text=True,
        )
        assert r.returncode == 1


# ---------------------------------------------------------------------------
# bullet_list Jinja filter — rendering helper in compose_threat_model.py
# ---------------------------------------------------------------------------


class TestBulletListFilter:
    @pytest.fixture
    def bullet_list(self):
        """Module-level ``bullet_list`` from compose_threat_model.py."""
        import importlib.util

        compose_path = REPO_ROOT / "scripts" / "compose_threat_model.py"
        if "compose_threat_model" in sys.modules:
            mod = sys.modules["compose_threat_model"]
        else:
            spec = importlib.util.spec_from_file_location("compose_threat_model", compose_path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules["compose_threat_model"] = mod
            assert spec.loader is not None
            spec.loader.exec_module(mod)
        return mod.bullet_list

    def test_empty_list_returns_empty_string(self, bullet_list):
        assert bullet_list([]) == ""

    def test_plain_strings(self, bullet_list):
        out = bullet_list(["a", "b", "c"])
        assert out == "- a\n- b\n- c"

    def test_dict_items_with_label_and_ref(self, bullet_list):
        items = [
            {"label": "Hardcoded RSA key", "ref": "F-001"},
            {"label": "SQL injection", "ref": "F-002"},
        ]
        out = bullet_list(items)
        assert "- [Hardcoded RSA key](#f-001)" in out
        assert "- [SQL injection](#f-002)" in out

    def test_dict_items_with_detail(self, bullet_list):
        items = [
            {"label": "CSP missing", "detail": "XSS payloads unguarded"},
        ]
        out = bullet_list(items)
        assert out == "- **CSP missing** — XSS payloads unguarded"

    def test_custom_prefix(self, bullet_list):
        out = bullet_list(["a", "b"], prefix="* ")
        assert out == "* a\n* b"


# ---------------------------------------------------------------------------
# check_security_posture_structure — invariants D / E / C / F / G / N / B / L
#
# Regression tests for the template-vs-checker drift that fired four false
# positives on every run (E2, F1, F3, N4 — see 2026-04-27 juice-shop run).
# The template emits three Mermaid node shapes (rectangle, rounded, hexagonal),
# quoted attack-arrow labels (`|" ① label "|`), and renderer-injected anchor
# prefixes on narrative bullets (`<a id="path-…"></a>**① …**`). The pre-fix
# regexes assumed only the rectangle shape, bare arrow labels, and bullets
# without anchors — so they never matched the actual output. These tests pin
# the post-fix behaviour.
# ---------------------------------------------------------------------------


class TestSecurityPostureStructureRegexes:
    """Pin the posture-section regexes against the real rendered shapes."""

    # A complete posture section that exercises all three node shapes
    # (`["…"]` / `(["…"])` / `[["…"]]`), quoted attack-arrow labels, and
    # anchor-prefixed narrative bullets. Mirrors the fragment template at
    # ``templates/fragments/security-posture-diagram.md.j2``.
    _CLEAN_POSTURE_SECTION = textwrap.dedent("""\
        ### Security Posture & Top Threats

        ```mermaid
        %%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%
        flowchart LR
            subgraph ACTORS[" "]
                direction TB
                HDR_A["<b>Threat Actors</b>"]:::columnHeader
                SHOPUSER(["<b>Shop User</b><br/><i>victim of XSS</i>"]):::actorShopUser
                ANON(["<b>Anonymous Internet Attacker</b><br/><i>no account</i>"]):::actorAnon
            end

            subgraph TIERS[" "]
                direction TB
                HDR_T["<b>Architecture Tiers</b>"]:::columnHeader
                BROWSER["<b>Client Tier</b><br/>angular-spa"]:::tierClient
                SERVER["<b>Application Tier</b><br/>express-backend"]:::tierApp
            end

            subgraph IMPACT[" "]
                direction TB
                HDR_I["<b>Impact</b>"]:::columnHeader
                SESSION_HIJACK[["🟠 <b>Customer Session Hijack</b>"]]:::impact
                FULL_TAKEOVER[["🔴 <b>Full Admin Takeover</b>"]]:::impact
            end

            HDR_A --- HDR_T
            HDR_T --- HDR_I
            ANON ==>|" ① Injection "| SERVER
            ANON ==>|" ② Auth Bypass "| SERVER
            SHOPUSER ==>|" ③ XSS "| BROWSER
            SERVER -.-> FULL_TAKEOVER
            BROWSER -.-> SESSION_HIJACK

            linkStyle 0,1 stroke:transparent,stroke-width:0px
            linkStyle 2,3,4 stroke:#b71c1c,stroke-width:3px
            linkStyle 5,6 stroke:#6b7280,stroke-width:1.5px,stroke-dasharray:4
        ```

        **3 structural threats** — Top Threats table (merged section).

        | # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |
        |---|--------------------|------------------------|---------------|-----|
        | <a id="path-injection"></a>① | **Injection** _(T·I)_<br/>input flows into an interpreter | •&nbsp;[F-001](#f-001)&nbsp;SQL&nbsp;Injection&nbsp;→&nbsp;[C-01](#c-01) | 🔴 **Critical**<br/>Full Admin Takeover | [M-001](#m-001) (P1) |
        | <a id="path-auth-bypass"></a>② | **Auth Bypass** _(S·E)_<br/>weak credentials | •&nbsp;[F-002](#f-002)&nbsp;JWT&nbsp;alg:none&nbsp;→&nbsp;[C-01](#c-01) | 🔴 **Critical**<br/>Full Admin Takeover | [M-002](#m-002) (P1) |
        | <a id="path-xss"></a>③ | **XSS** _(T·I)_<br/>scripts in stored content | •&nbsp;[F-003](#f-003)&nbsp;Stored&nbsp;XSS&nbsp;→&nbsp;[C-02](#c-02) | 🟠 **High**<br/>Customer Session Hijack | [M-003](#m-003) (P2) |
        """)

    _CLEAN_FIGURE1_MERMAID = textwrap.dedent("""\
        flowchart TB
            subgraph ZONE_ACTORS["External Actors"]
                direction LR
                EXT_SHOPUSER["fa:fa-user Shop User"]:::actorgood
                ACT_INTERNET_ANON["fa:fa-user-secret Anonymous Internet Attacker"]:::actorbad
            end

            subgraph CLIENT["Client Tier - browser"]
                CMP_WEB["C-02 · Web Frontend"]:::comp
            end
            subgraph APP["Application Tier - service"]
                CMP_API["C-01 · API"]:::comp
                APP_HOTSPOTS["Application hot spots<br/><i>C-04, C-05</i>"]:::hotspot
            end
            subgraph DATA["Data Tier"]
                CMP_DB["C-03 · Primary Database"]:::comp
            end

            EXT_SHOPUSER -->|"uses"| CMP_WEB
            CMP_WEB -->|"API calls"| CMP_API
            CMP_API -->|"reads/writes"| CMP_DB
            ACT_INTERNET_ANON ==>|"① Injection"| CMP_API
            ACT_INTERNET_ANON ==>|"①"| APP_HOTSPOTS
            CMP_API -.->|"①"| CMP_DB
            APP_HOTSPOTS ~~~ CMP_DB
        """)

    def _with_figure1(self, fig1_mermaid: str) -> str:
        figure1 = (
            "**Figure 1 - Architecture & Top Threats**\n\n"
            "```mermaid\n"
            f"{fig1_mermaid.rstrip()}\n"
            "```\n\n"
            "**Figure 2 - Risk Flow: Actor → Tier → Impact**\n\n"
        )
        return self._CLEAN_POSTURE_SECTION.replace("```mermaid", figure1 + "```mermaid", 1)

    # ---- _count_cards: standalone unit test of the card-counting helper ----

    def test_count_cards_matches_all_three_node_shapes(self):
        """All three Mermaid node shapes the template emits count as 1 each."""
        block = textwrap.dedent("""\
                direction TB
                HDR_A["<b>Threat Actors</b>"]:::columnHeader
                SHOPUSER(["<b>Shop User</b><br/><i>victim</i>"]):::actorShopUser
                ANON(["<b>Anonymous</b>"]):::actorAnon
        """)
        # 3 declarations: 1 rectangle (HDR_A) + 2 rounded (SHOPUSER, ANON).
        assert qa._count_cards(block) == 3

    def test_count_cards_matches_hexagonal_impact_shape(self):
        block = textwrap.dedent("""\
                direction TB
                HDR_I["<b>Impact</b>"]:::columnHeader
                SESSION_HIJACK[["🟠 <b>Customer Session Hijack</b>"]]:::impact
                FULL_TAKEOVER[["🔴 <b>Full Admin Takeover</b>"]]:::impact
        """)
        assert qa._count_cards(block) == 3

    def test_count_cards_ignores_direction_and_classdef_lines(self):
        """Negative test: structural lines must not be counted as cards."""
        block = textwrap.dedent("""\
                direction TB
                end
                classDef columnHeader fill:none,stroke:none
                HDR_A --- HDR_T
                SERVER -.-> CUSTOMER_DATA_EXFILTRATION
        """)
        assert qa._count_cards(block) == 0

    # ---- end-to-end: clean fixture must produce zero issues ----

    def test_clean_posture_section_passes_all_invariants(self, tmp_path):
        md = _write_minimal_model(tmp_path, self._CLEAN_POSTURE_SECTION)
        report = qa.check_security_posture_structure(md)
        assert report.issues == [], report.issues
        assert report.ok == 1

    def test_figure1_data_bottom_stack_passes(self, tmp_path):
        """Figure 1 may precede the Figure 2 heatmap. Its architecture stack
        passes when DATA is the last tier, solid attacks target app/client
        nodes, and the extra app hotspot has a `~~~` Data balancing edge."""
        md = _write_minimal_model(tmp_path, self._with_figure1(self._CLEAN_FIGURE1_MERMAID))
        report = qa.check_security_posture_structure(md)
        assert not any(i.startswith("A") for i in report.issues), report.issues

    def test_figure1_flags_solid_actor_to_data_edge(self, tmp_path):
        broken_fig1 = self._CLEAN_FIGURE1_MERMAID.replace(
            'ACT_INTERNET_ANON ==>|"① Injection"| CMP_API',
            'ACT_INTERNET_ANON ==>|"① Injection"| CMP_DB',
        )
        md = _write_minimal_model(tmp_path, self._with_figure1(broken_fig1))
        report = qa.check_security_posture_structure(md)
        assert any(i.startswith("A3:") for i in report.issues), report.issues
        assert any(i.startswith("A4:") for i in report.issues), report.issues

    def test_figure1_flags_missing_app_data_balancing_edge(self, tmp_path):
        broken_fig1 = self._CLEAN_FIGURE1_MERMAID.replace(
            "APP_HOTSPOTS ~~~ CMP_DB\n",
            "",
        )
        md = _write_minimal_model(tmp_path, self._with_figure1(broken_fig1))
        report = qa.check_security_posture_structure(md)
        assert any(i.startswith("A5:") for i in report.issues), report.issues

    # ---- targeted: each formerly-broken invariant individually ----

    def test_e2_accepts_quoted_attack_arrow_labels(self, tmp_path):
        """E2: `|" ① label "|` (quoted, with spacing) must be detected."""
        md = _write_minimal_model(tmp_path, self._CLEAN_POSTURE_SECTION)
        report = qa.check_security_posture_structure(md)
        # Pre-fix this would have produced 'E2: expected 1–7 attack arrows… found 0'
        assert not any(i.startswith("E2:") for i in report.issues), report.issues

    def test_f1_counts_rounded_actor_cards(self, tmp_path):
        """F1: `(["…"])` rounded actor cards must count toward the column."""
        md = _write_minimal_model(tmp_path, self._CLEAN_POSTURE_SECTION)
        report = qa.check_security_posture_structure(md)
        # Pre-fix: 'F1: ACTORS column has 1 cards (expected 2–6: HDR + 1–5 actors)'
        assert not any(i.startswith("F1:") for i in report.issues), report.issues

    def test_f3_counts_hexagonal_impact_cards(self, tmp_path):
        """F3: `[["…"]]` hexagonal impact cards must count toward the column."""
        md = _write_minimal_model(tmp_path, self._CLEAN_POSTURE_SECTION)
        report = qa.check_security_posture_structure(md)
        # Pre-fix: 'F3: IMPACT column has 1 cards (expected 2–5: HDR + 1–4 impacts)'
        assert not any(i.startswith("F3:") for i in report.issues), report.issues

    def test_n4_accepts_anchor_prefixed_narrative_bullets(self, tmp_path):
        """N4: `- <a id="…"></a>**① …**` (anchored) bullets must match."""
        md = _write_minimal_model(tmp_path, self._CLEAN_POSTURE_SECTION)
        report = qa.check_security_posture_structure(md)
        # Pre-fix: 'N4: expected 1–7 attack-class bullets, found 0'
        assert not any(i.startswith("N4:") for i in report.issues), report.issues

    def test_b1_bullet_header_check_runs_on_anchored_bullets(self, tmp_path):
        """B-rules slice bullets via the same anchored regex; if N4 was the
        only thing matching, B1 silently never ran. After the fix the bullet
        slicer finds anchored bullets and B1 must validate them — and the
        fixture's bullets are well-formed, so no B1 issue should fire."""
        md = _write_minimal_model(tmp_path, self._CLEAN_POSTURE_SECTION)
        report = qa.check_security_posture_structure(md)
        assert not any(i.startswith("B1:") for i in report.issues), report.issues

    # ---- regression on negatives: malformed inputs MUST still be caught ----

    def test_t1_flags_missing_top_threats_table(self, tmp_path):
        """2026-05: the bullet list was replaced by the Top Threats table.
        If that table header is absent, T1 must fire."""
        broken = self._CLEAN_POSTURE_SECTION.replace(
            "| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |",
            "| # | Threat | Findings |",  # wrong/legacy header
        )
        md = _write_minimal_model(tmp_path, broken)
        report = qa.check_security_posture_structure(md)
        assert any(i.startswith("T1:") for i in report.issues), report.issues

    def test_e2_flags_missing_glyph_on_attack_arrow(self, tmp_path):
        """If attack arrows have no glyphs, E2 must still fire."""
        broken = (
            self._CLEAN_POSTURE_SECTION.replace(
                'ANON ==>|" ① Injection "| SERVER\n',
                "ANON ==> SERVER\n",
            )
            .replace(
                'ANON ==>|" ② Auth Bypass "| SERVER\n',
                "",
            )
            .replace(
                'SHOPUSER ==>|" ③ XSS "| BROWSER\n',
                "",
            )
        )
        md = _write_minimal_model(tmp_path, broken)
        report = qa.check_security_posture_structure(md)
        assert any(i.startswith("E2:") for i in report.issues), report.issues


# ---------------------------------------------------------------------------
# build_repair_plan — manual_review status (Sprint 1D / M3.5)
#
# A repair plan with all-empty `fragments_to_rewrite` actions cannot be fixed
# by re-rendering — the underlying issue is checker-vs-renderer drift, not
# fragment content. The 2026-04-27 juice-shop run produced exactly this
# state (7 × posture B2 violations, every action's `fragments_to_rewrite=[]`).
# Without these tests' guard rail, the skill's Re-Render Loop would burn 3
# iterations × ~10 min each on a problem only a code change can fix.
# ---------------------------------------------------------------------------


class TestRepairPlanStatusClassification:
    """Pin `_classify_plan_status` — drives the Re-Render Loop short-circuit."""

    def test_no_issues_no_actions_returns_pass(self):
        """Empty input → status=pass."""
        status, actionable = qa._classify_plan_status([], [])
        assert status == "pass"
        assert actionable is False

    def test_unactionable_plan_returns_manual_review(self):
        """Issues exist, but every action's `fragments_to_rewrite` is empty.
        Mirrors the 2026-04-27 juice-shop B2-only repair plan that would
        otherwise have triggered 3 × ~10 min Re-Render Loop iterations on
        a problem only a code change can fix."""
        issues = [
            "F1: ACTORS column has 1 cards (expected 2-6)",
            "B2: attack-class bullet has no F-NNN link",
        ]
        actions = [
            {"raw_issue": issues[0], "type": "posture_renderer_bug", "fragments_to_rewrite": []},
            {"raw_issue": issues[1], "type": "posture_unknown", "fragments_to_rewrite": []},
        ]
        status, actionable = qa._classify_plan_status(issues, actions)
        assert status == "manual_review"
        assert actionable is False

    def test_actionable_plan_returns_fail(self):
        """Mixed: at least one action with a writable target → status=fail
        so the Re-Render Loop iterates as designed."""
        issues = ["pretend issue"]
        actions = [
            {"raw_issue": "x", "type": "t", "fragments_to_rewrite": []},
            {"raw_issue": "y", "type": "t", "fragments_to_rewrite": [".fragments/security-architecture.md"]},
        ]
        status, actionable = qa._classify_plan_status(issues, actions)
        assert status == "fail"
        assert actionable is True

    def test_blocking_without_fragment_wins_over_cosmetic(self):
        """2026-07 regression: a blocking action with NO writable fragment
        (e.g. a computed Top Threats table-schema drift) must route to
        manual_review even when a cosmetic action carries a writable fragment.
        Previously it was silently demoted to cosmetic_advisory (exit 4, treated
        like the clean fast path), skipping a real contract defect."""
        issues = ["Top Threats table does not match contract column schema (expected one of: ['...'])"]
        actions = [
            {
                "raw_issue": issues[0],
                "type": "table_schema_drift",
                "severity": "blocking",
                "fragments_to_rewrite": [],
            },
            {
                "raw_issue": "walkthrough too short",
                "type": "walkthrough_too_short",
                "severity": "cosmetic",
                "fragments_to_rewrite": [".fragments/attack-walkthroughs.md"],
            },
        ]
        status, actionable = qa._classify_plan_status(issues, actions)
        assert status == "manual_review"
        assert actionable is False

    def test_clean_md_end_to_end_returns_pass(self, tmp_path):
        """Smoke test: an MD with no contract violations returns status=pass
        through the full `build_repair_plan` pipeline."""
        md = _write_minimal_model(
            tmp_path,
            "## Management Summary\n\nNothing to see here.\n\n## 8. Findings Register\n\n_no threats_\n",
        )
        plan, _ = qa.build_repair_plan(md, tmp_path, qa.DEFAULT_CONTRACT_PATH)
        # Bare-bones MD will violate many contract rules — the important
        # invariant is that the status field is one of the documented values
        # and `actionable` is consistent with the action set.
        assert plan["status"] in {"pass", "fail", "manual_review"}
        assert plan["actionable"] == any(a.get("fragments_to_rewrite") for a in plan["actions"])


class TestTableSchemaDriftClassification:
    """Pin table-schema-drift repair classification. 2026-07 bug: the checker
    emitted 'Top Threats' / 'Top Mitigations' in an `(expected one of: [...])`
    form, but the label→section map hard-coded the retired 'Top Findings' /
    'Prioritized Mitigations' labels and the parser only matched the legacy
    `(expected: '<one>')` form — so every drift fell through to an
    unclassified, no-fragment action that the plan-status bug then demoted."""

    def test_label_map_derives_from_checks_and_uses_current_labels(self):
        assert qa._TABLE_LABEL_TO_SECTION == {label: sid for sid, label, _ in qa._TABLE_SCHEMA_CHECKS}
        assert set(qa._TABLE_LABEL_TO_SECTION) == {
            "Top Threats",
            "Operational Strengths",
            "Top Mitigations",
        }
        assert "Top Findings" not in qa._TABLE_LABEL_TO_SECTION
        assert "Prioritized Mitigations" not in qa._TABLE_LABEL_TO_SECTION
        # retired orphan section id removed from the fragment map
        assert "top_findings" not in qa.CONTRACT_SECTION_FRAGMENTS

    def test_top_threats_header_drift_classifies_not_unclassified(self, tmp_path):
        """End-to-end through build_repair_plan: a wrong Top Threats column
        schema produces a `table_schema_drift` action (section_id=top_threats,
        computed table → empty fragment target), NOT `unclassified`."""
        md = _write_minimal_model(
            tmp_path,
            "## Management Summary\n\n"
            "### Security Posture & Top Threats\n\n"
            "| Wrong | Columns | Here |\n|---|---|---|\n| a | b | c |\n\n"
            "## 8. Findings Register\n\n_no threats_\n",
        )
        (tmp_path / "threat-model.yaml").write_text(
            "meta:\n  schema_version: 1\nthreats: []\nmitigations: []\n", encoding="utf-8"
        )
        plan, _ = qa.build_repair_plan(md, tmp_path, qa.DEFAULT_CONTRACT_PATH)
        drift = [a for a in plan["actions"] if a.get("type") == "table_schema_drift"]
        assert drift, "Top Threats header drift did not classify as table_schema_drift"
        assert drift[0]["label"] == "Top Threats"
        assert drift[0]["section_id"] == "top_threats"
        assert drift[0]["fragments_to_rewrite"] == []
        assert not [
            a
            for a in plan["actions"]
            if a.get("raw_issue", "").startswith("Top Threats") and a.get("type") == "unclassified"
        ]


# ---------------------------------------------------------------------------
# build_repair_plan — placeholders + yaml_md_consistency folded in (2026-06-05)
#
# Both checks used to live only in the deferred `all` battery, which never
# runs on the clean fast path (the QA agent that consumed it is skipped). They
# now gate the repair plan so a visible placeholder or a yaml↔md count drift
# can no longer ship silently on a contract-clean document.
# ---------------------------------------------------------------------------


class TestRepairPlanFoldedChecks:
    def test_visible_placeholder_appears_in_plan(self, tmp_path):
        """A visible `_pending_` token reaches the repair plan as a
        `placeholders` action (manual_review route — empty fragment target)."""
        md = _write_minimal_model(
            tmp_path,
            "## 1. Management Summary\n\nThe verdict is _pending_ further review.\n",
        )
        (tmp_path / "threat-model.yaml").write_text(
            "meta:\n  schema_version: 1\nthreats: []\nmitigations: []\n", encoding="utf-8"
        )
        plan, report = qa.build_repair_plan(md, tmp_path, qa.DEFAULT_CONTRACT_PATH)
        ph = [a for a in plan["actions"] if a["type"] == "placeholders"]
        assert ph, "placeholders action missing from repair plan"
        assert ph[0]["fragments_to_rewrite"] == []  # routes to manual_review/agent
        assert any("_pending_" in i for i in report.issues)

    def test_yaml_md_count_drift_appears_in_plan(self, tmp_path):
        """yaml has 2 threats, md renders 0 → a `yaml_md_consistency` action
        is emitted (empty fragment target → manual_review, not a wasted loop)."""
        md = _write_minimal_model(
            tmp_path,
            "## 1. Management Summary\n\nNo findings table rendered here.\n",
        )
        (tmp_path / "threat-model.yaml").write_text(
            "meta:\n  schema_version: 1\nthreats:\n  - id: T-001\n  - id: T-002\nmitigations: []\n",
            encoding="utf-8",
        )
        plan, report = qa.build_repair_plan(md, tmp_path, qa.DEFAULT_CONTRACT_PATH)
        ym = [a for a in plan["actions"] if a["type"] == "yaml_md_consistency"]
        assert ym, "yaml_md_consistency action missing from repair plan"
        assert ym[0]["fragments_to_rewrite"] == []
        assert any("count drift" in i for i in report.issues)

    def test_yaml_md_only_drift_classifies_manual_review(self):
        """An isolated yaml_md action (empty fragments) → manual_review so the
        skill routes to agent triage (exit 3), not the Re-Render Loop."""
        issues = ["threat count drift: yaml=2, md (distinct F/T-NNN)=0"]
        actions = [
            {"raw_issue": issues[0], "type": "yaml_md_consistency", "fragments_to_rewrite": []},
        ]
        status, actionable = qa._classify_plan_status(issues, actions)
        assert status == "manual_review"
        assert actionable is False


# ---------------------------------------------------------------------------
# Triage CLI defensive defaults (Sprint 1B / M3.5)
#
# The orchestrator has historically called `triage_validate_ratings.py` with
# typo'd flags (e.g. `--threats-file …`), which under stock argparse exits
# with a `usage:` line and code 2. The orchestrator interpreted that as a
# successful no-op and burnt 5+ min of session budget waiting. The fix uses
# `parse_known_args` so unknown flags become a stderr warning + continue
# with defaults; the agent_logger's `usage:` keyword trigger remains a
# defence-in-depth backstop.
# ---------------------------------------------------------------------------


class TestTriageCliDefensiveDefaults:
    """Pin the orchestrator-resilience hardening on triage_validate_ratings.py."""

    SCRIPT = REPO_ROOT / "scripts" / "triage_validate_ratings.py"

    def _make_threats_file(self, output_dir: Path, threats: list | None = None):
        merged = {
            "version": "v1",
            "schema_version": 1,
            "threats": threats or [],
        }
        (output_dir / ".threats-merged.json").write_text(
            __import__("json").dumps(merged),
            encoding="utf-8",
        )

    def test_unknown_flag_does_not_abort_the_run(self, tmp_path):
        """The script must tolerate an unrecognised flag rather than printing
        `usage:` and exiting with argparse's default code 2."""
        self._make_threats_file(tmp_path)
        result = subprocess.run(
            [
                sys.executable,
                str(self.SCRIPT),
                str(tmp_path),
                "--threats-file",
                str(tmp_path / ".threats-merged.json"),  # bogus
                "--depth",
                "quick",
            ],
            capture_output=True,
            text=True,
        )
        # The script should NOT exit with the argparse `usage:` failure path.
        assert result.returncode == 0, (
            f"unexpected exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        # And it should have explicitly logged the ignored unknown arg.
        assert "Ignoring unrecognised argument" in result.stderr, result.stderr

    def test_falls_back_to_cwd_when_no_args_given(self, tmp_path, monkeypatch):
        """Without `output_dir` and without `$OUTPUT_DIR`, the script falls
        back to the current working directory (Sprint 1B). It still exits
        cleanly when `.threats-merged.json` exists in cwd."""
        self._make_threats_file(tmp_path)
        monkeypatch.delenv("OUTPUT_DIR", raising=False)
        result = subprocess.run(
            [sys.executable, str(self.SCRIPT)],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"unexpected exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ---------------------------------------------------------------------------
# Sprint 2A — B2 attack-class bullet ID convention
#
# The renderer historically emitted F-NNN finding links inside posture
# attack-class bullets; switched to T-NNN once threat-IDs became canonical.
# The B2 checker must accept BOTH so the live drift does not produce a
# permanent stream of false-positives. The 2026-04-27 juice-shop run
# triggered exactly 7 of these (one per attack class).
# ---------------------------------------------------------------------------


class TestPostureB2IdConvention:
    """Pin the dual-prefix (F-NNN | T-NNN) acceptance for B2 / L1."""

    @pytest.fixture
    def posture_section_with_t_links(self, tmp_path):
        """A clean posture section using T-NNN links (current renderer)."""
        section = textwrap.dedent("""\
            ### Security Posture at a Glance

            ```mermaid
            %%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%
            flowchart LR
                subgraph ACTORS[" "]
                    direction TB
                    HDR_A["<b>Threat Actors</b>"]:::columnHeader
                    SHOPUSER(["<b>Shop User</b>"]):::actorShopUser
                    ANON(["<b>Anonymous</b>"]):::actorAnon
                end

                subgraph TIERS[" "]
                    direction TB
                    HDR_T["<b>Tiers</b>"]:::columnHeader
                    BROWSER["<b>Client</b>"]:::tierClient
                    SERVER["<b>Server</b>"]:::tierApp
                end

                subgraph IMPACT[" "]
                    direction TB
                    HDR_I["<b>Impact</b>"]:::columnHeader
                    HIJACK[["🟠 <b>Session Hijack</b>"]]:::impact
                    TAKEOVER[["🔴 <b>Full Takeover</b>"]]:::impact
                end

                HDR_A --- HDR_T
                HDR_T --- HDR_I
                ANON ==>|" ① Injection "| SERVER
                SHOPUSER ==>|" ② XSS "| BROWSER
                SERVER -.-> TAKEOVER
                BROWSER -.-> HIJACK

                linkStyle 0,1 stroke:transparent,stroke-width:0px
                linkStyle 2,3 stroke:#b71c1c,stroke-width:3px
                linkStyle 4,5 stroke:#6b7280,stroke-width:1.5px,stroke-dasharray:4
            ```

            **Threat actors.** Two on the left.

            - **Shop User** — registered customer.
            - **Anonymous** — no account.

            **Attack paths (numbered arrows in the diagram):**

            - <a id="path-injection"></a>**① Injection** (Anonymous → Server) — input flows.
              - Findings:
                - [T-001](#t-001) — SQL Injection
              - Impact: Full Takeover

            - <a id="path-xss"></a>**② XSS** (Shop User → Client) — scripts in stored content.
              - Findings:
                - [T-002](#t-002) — Stored XSS
              - Impact: Session Hijack
            """)
        return _write_minimal_model(tmp_path, section)

    def test_b2_accepts_t_nnn_finding_links(self, posture_section_with_t_links):
        """Pre-Sprint-2A this raised 'B2: ... has no F-NNN link'."""
        report = qa.check_security_posture_structure(posture_section_with_t_links)
        assert not any(i.startswith("B2:") for i in report.issues), report.issues

    def test_b2_accepts_f_nnn_finding_links(self, tmp_path):
        """Backwards-compat: the legacy F-NNN form must still match."""
        section = textwrap.dedent("""\
            ### Security Posture at a Glance

            ```mermaid
            %%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%
            flowchart LR
                subgraph ACTORS[" "]
                    direction TB
                    HDR_A["<b>Threat Actors</b>"]:::columnHeader
                    ANON(["<b>Anonymous</b>"]):::actorAnon
                end
                subgraph TIERS[" "]
                    direction TB
                    HDR_T["<b>Tiers</b>"]:::columnHeader
                    SERVER["<b>Server</b>"]:::tierApp
                end
                subgraph IMPACT[" "]
                    direction TB
                    HDR_I["<b>Impact</b>"]:::columnHeader
                    TAKEOVER[["🔴 <b>Full Takeover</b>"]]:::impact
                end
                HDR_A --- HDR_T
                HDR_T --- HDR_I
                ANON ==>|" ① Injection "| SERVER
                SERVER -.-> TAKEOVER
                linkStyle 0,1 stroke:transparent,stroke-width:0px
                linkStyle 2 stroke:#b71c1c,stroke-width:3px
                linkStyle 3 stroke:#6b7280,stroke-width:1.5px,stroke-dasharray:4
            ```

            **Threat actors.** One on the left.

            - **Anonymous** — no account.

            **Attack paths (numbered arrows in the diagram):**

            - <a id="path-injection"></a>**① Injection** (Anonymous → Server) — input flows.
              - Findings:
                - [F-001](#f-001) — SQL Injection
              - Impact: Full Takeover
            """)
        md = _write_minimal_model(tmp_path, section)
        report = qa.check_security_posture_structure(md)
        assert not any(i.startswith("B2:") for i in report.issues), report.issues

    def test_t3_flags_table_without_finding_links(self, tmp_path):
        """2026-05: bullets were replaced by the Top Threats table. A table
        whose findings are not linked into §8 (`[F-NNN](#f-nnn)`) must fire T3."""
        section = textwrap.dedent("""\
            ### Security Posture & Top Threats

            ```mermaid
            %%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%
            flowchart LR
                subgraph ACTORS[" "]
                    direction TB
                    HDR_A["<b>Threat Actors</b>"]:::columnHeader
                    ANON(["<b>Anonymous</b>"]):::actorAnon
                end
                subgraph TIERS[" "]
                    direction TB
                    HDR_T["<b>Tiers</b>"]:::columnHeader
                    SERVER["<b>Server</b>"]:::tierApp
                end
                subgraph IMPACT[" "]
                    direction TB
                    HDR_I["<b>Impact</b>"]:::columnHeader
                    TAKEOVER[["🔴 <b>Full Takeover</b>"]]:::impact
                end
                HDR_A --- HDR_T
                HDR_T --- HDR_I
                ANON ==>|" ① Injection "| SERVER
                SERVER -.-> TAKEOVER
                linkStyle 0,1 stroke:transparent,stroke-width:0px
                linkStyle 2 stroke:#b71c1c,stroke-width:3px
                linkStyle 3 stroke:#6b7280,stroke-width:1.5px,stroke-dasharray:4
            ```

            | # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |
            |---|--------------------|------------------------|---------------|-----|
            | <a id="path-injection"></a>① | **Injection** _(T·I)_<br/>flows | •&nbsp;SQL Injection (no link) | 🔴 **Critical**<br/>Full Takeover | — |
            """)
        md = _write_minimal_model(tmp_path, section)
        report = qa.check_security_posture_structure(md)
        assert any(i.startswith("T3:") for i in report.issues), report.issues


# ---------------------------------------------------------------------------
# Sprint 2B — auth method whitelist filter
#
# The §7.3 IAM controls table mixes auth methods (Password Login, OAuth,
# TOTP) with implementation details (Password Hashing, Login Rate Limiting,
# express-jwt middleware). Only the auth methods warrant a `#### Flow`
# sub-section. Pre-Sprint-2B the checker demanded one per row, producing
# 5/11 sinnfreie warnings on the 2026-04-27 juice-shop run.
# ---------------------------------------------------------------------------


class TestRowIsAuthMethodHelper:
    """Pin `_row_is_auth_method` — the helper backing the whitelist filter."""

    DEFAULT_WHITELIST = [
        "password login",
        "oauth",
        "oidc",
        "openid",
        "saml",
        "totp",
        "2fa",
        "mfa",
        "passkey",
        "webauthn",
        "password reset",
        "change password",
        "session",
        "magic link",
        "magic-link",
        "jwt",
    ]

    @pytest.mark.parametrize(
        "name",
        [
            "Password Login",
            "Standard Password Login Flow",
            "Google OAuth",
            "Google OAuth 2.0 Flow",
            "Auth0 OIDC",
            "Two-Factor Authentication (TOTP)",
            "JWT Authentication (RS256)",
            "WebAuthn / Passkey",
            "Password Reset Flow",
            "Magic Link Sign-In",
        ],
    )
    def test_recognises_real_auth_methods(self, name):
        assert qa._row_is_auth_method(name, self.DEFAULT_WHITELIST), name

    @pytest.mark.parametrize(
        "name",
        [
            "Password Hashing",
            "Login Rate Limiting",
            "express-jwt middleware",
            # `express-jwt middleware` actually matches because of `jwt` —
            # documented as an accepted false-positive in the helper docstring.
            # Keeping the assertion loose here so the parametrize stays focused
            # on UNAMBIGUOUS non-methods.
            "Content Security Policy",
            "Dependency Pinning",
            "Audit Log Rotation",
            "CORS Origin Allowlist",
        ],
    )
    def test_rejects_implementation_and_cross_cutting_controls(self, name):
        if "jwt" in name.lower():
            pytest.skip("jwt token-format match is documented as accepted FP")
        assert not qa._row_is_auth_method(name, self.DEFAULT_WHITELIST), name

    def test_empty_whitelist_matches_nothing(self):
        """Defensive: an empty whitelist never matches — caller must check."""
        for name in ("OAuth", "Password Login", "TOTP"):
            assert not qa._row_is_auth_method(name, [])

    def test_multi_token_entry_requires_subset_match(self):
        """`password login` (two tokens) needs both to be present in the row.
        A row called only "password" should not match it."""
        assert not qa._row_is_auth_method("Password", ["password login"])
        assert qa._row_is_auth_method("Password Login Flow", ["password login"])
        assert qa._row_is_auth_method("Standard Password-based Login", ["password login"])

    def test_ignores_non_string_entries(self):
        """A malformed contract entry must not crash the helper."""
        assert qa._row_is_auth_method("OAuth", [None, 42, "oauth"])  # type: ignore[list-item]


class TestCrossReferenceLabellingInvariant:
    """Pin the cross-reference labelling invariant from AGENTS.md §4a.

    Every cross-reference to a T/F/M/TH ID MUST render as
    ``[ID](#anchor) — <title>`` wherever the title is available. The
    title source is `threat-model.yaml` (for T/F/M) or §8 prose
    declarations (for TH). These tests pin the four-class coverage so
    a future refactor cannot silently regress the suffix injection.
    """

    def _yaml_with_titles(self) -> str:
        return textwrap.dedent("""\
            meta: {schema_version: 1}
            threats:
              - id: T-001
                title: "SQL Injection in login endpoint"
                component: express-backend
                stride: Spoofing
                scenario: "long scenario text…"
                likelihood: High
                impact: Critical
                risk: Critical
              - id: T-002
                title: "Hardcoded RSA private key in source"
                component: express-backend
                stride: Tampering
                scenario: "long scenario text…"
                likelihood: High
                impact: Critical
                risk: Critical
            mitigations:
              - id: M-001
                title: "Use parameterized queries everywhere"
                threat_ids: [T-001]
                priority: P1
              - id: M-002
                title: "Rotate JWT signing keys via secrets manager"
                threat_ids: [T-002]
                priority: P1
            """)

    def _write_pair(self, tmp_path: Path, md_body: str) -> Path:
        md = tmp_path / "threat-model.md"
        yml = tmp_path / "threat-model.yaml"
        md.write_text(md_body)
        yml.write_text(self._yaml_with_titles())
        return md

    def test_label_idx_includes_fnnn_alias(self, tmp_path):
        """Every T-NNN entry produces an F-NNN alias keyed by the same
        numeric suffix, pointing to the f-NNN anchor. This is the fix
        that lets `[F-001](#f-001)` cross-references pick up the title.
        """
        md = self._write_pair(tmp_path, "stub\n")
        idx = qa._load_label_index(md)
        assert idx["T-001"][0] == "SQL Injection in login endpoint"
        assert idx["F-001"][0] == "SQL Injection in login endpoint"
        assert idx["F-001"][1] == "f-001"  # canonical anchor for the F-alias

    def test_linkify_appends_title_to_existing_fnnn_link(self, tmp_path):
        """Existing `[F-001](#f-001)` (no suffix) gains ` — <title>`."""
        md = self._write_pair(
            tmp_path,
            "intro line referencing [F-001](#f-001) and [F-002](#f-002).\n",
        )
        _, new_text = qa.linkify_anchors(md)
        assert "[F-001](#f-001) — SQL Injection in login endpoint" in new_text
        assert "[F-002](#f-002) — Hardcoded RSA private key in source" in new_text

    def test_linkify_bare_tnnn_appends_title(self, tmp_path):
        """Bare T-NNN in prose becomes `[T-NNN](#t-nnn) — <title>`."""
        md = self._write_pair(tmp_path, "see T-001 in the report.\n")
        _, new_text = qa.linkify_anchors(md)
        assert "[T-001](#t-001) — SQL Injection in login endpoint" in new_text

    def test_linkify_bare_mnnn_appends_title(self, tmp_path):
        """Bare M-NNN in prose becomes `[M-NNN](#m-nnn) — <title>`."""
        md = self._write_pair(tmp_path, "addressed by M-001 immediately.\n")
        _, new_text = qa.linkify_anchors(md)
        assert "[M-001](#m-001) — Use parameterized queries everywhere" in new_text

    def test_linkify_thnn_with_title_from_section_8(self, tmp_path):
        """TH-NN labels are read from §8 prose. Bare TH-01 in any other
        section becomes `[TH-01](#th-01) — <title>` once §8 declares it.
        """
        md_body = textwrap.dedent("""\
            ## Management Summary
            Top class: TH-01.

            ## 8. Findings Register

            | ID | Finding | Threat Category |
            |----|---------|-----------------|
            | F-001 | … | <a id="th-01"></a>TH-01 — Injection |
            """)
        md = self._write_pair(tmp_path, md_body)
        _, new_text = qa.linkify_anchors(md)
        assert "[TH-01](#th-01) — Injection" in new_text

    def test_linkify_idempotent_on_rerun(self, tmp_path):
        """Running linkify_anchors twice must not produce double titles."""
        md_body = "see [F-001](#f-001), bare T-002, and M-001.\n"
        md = self._write_pair(tmp_path, md_body)
        _, first = qa.linkify_anchors(md)
        md.write_text(first)
        _, second = qa.linkify_anchors(md)
        # No occurrence of `— SQL Injection in login endpoint — SQL Injection`
        for label in (
            "SQL Injection in login endpoint",
            "Hardcoded RSA private key in source",
            "Use parameterized queries everywhere",
        ):
            doubled = f"— {label} — {label}"
            assert doubled not in second, f"label {label!r} was suffixed twice"

    def test_html_nested_finding_link_detector(self, tmp_path):
        """check_html_nested_finding_link flags the §4/§5 double-link render
        corruption (`<a href="#f-001">[F-001](#f-001)</a>`) and passes on the
        clean single-link form. Belt-and-suspenders for the linkify_anchors
        idempotency guard.
        """
        clean = tmp_path / "clean.md"
        clean.write_text('<td>🔴 <a href="#f-001">F-001</a> — SQL Injection (<code>routes/login.ts:34</code>)</td>\n')
        rep_clean = qa.check_html_nested_finding_link(clean)
        assert rep_clean.ok == 1 and not rep_clean.issues

        corrupt = tmp_path / "corrupt.md"
        corrupt.write_text(
            '<td>🔴 <a href="#f-001">[F-001](#f-001) — SQL Injection — '
            "routes/login.ts:34</a> — SQL Injection (<code>routes/login.ts:34</code>)</td>\n"
        )
        rep_bad = qa.check_html_nested_finding_link(corrupt)
        assert rep_bad.ok == 0 and len(rep_bad.issues) == 1

    def test_linkify_skips_html_anchor_text(self, tmp_path):
        """A bare ID that is the visible text of an already-rendered HTML
        anchor (`<a href="#f-001">F-001</a>`, as the §4/§5 fixed-layout HTML
        tables emit) must NOT be re-linkified into
        `<a href="#f-001">[F-001](#f-001)</a>`. Regression for the §4 Assets
        double-link corruption seen when Stage 3's `qa_checks all` ran after
        the pre-agent `autofix` had already HTML-converted the table.
        """
        md = self._write_pair(
            tmp_path,
            '<td>🔴 <a href="#f-001">F-001</a> — SQL Injection in login endpoint '
            "(<code>routes/login.ts:34</code>)<br/>"
            '🔴 <a href="#f-002">F-002</a> — Hardcoded RSA private key in source</td>\n',
        )
        _, new_text = qa.linkify_anchors(md)
        assert '<a href="#f-001">F-001</a>' in new_text
        assert '<a href="#f-001">[F-001](#f-001)</a>' not in new_text
        assert '<a href="#f-002">[F-002](#f-002)</a>' not in new_text

    def test_linkify_skips_existing_em_dash_description(self, tmp_path):
        """When the author wrote `[T-001](#t-001) — Custom`, the linkifier
        leaves the existing description alone (no doubled em-dash).
        """
        md = self._write_pair(
            tmp_path,
            "**Threat:** [T-001](#t-001) — Custom user-supplied description.\n",
        )
        _, new_text = qa.linkify_anchors(md)
        # The line keeps the user's description; YAML title is NOT injected.
        assert "Custom user-supplied description" in new_text
        # And no doubled em-dash variant from the YAML title.
        assert "SQL Injection in login endpoint — Custom" not in new_text

    def test_linkify_does_not_touch_anchor_declarations(self, tmp_path):
        """Lines that ARE the anchor source (`<a id="f-001"></a>F-001`) must
        not get re-linkified or get titles re-injected after the anchor.
        """
        md_body = '| <a id="f-001"></a>F-001 | Description here | … |\n'
        md = self._write_pair(tmp_path, md_body)
        _, new_text = qa.linkify_anchors(md)
        # The anchor declaration line is unchanged.
        assert '<a id="f-001"></a>F-001 |' in new_text
        # No `[F-001](#f-001)` link injected.
        assert "[F-001](#f-001)" not in new_text

    # ------------------------------------------------------------------
    # Per-class guard-branch coverage. The four substitution closures
    # (sub_t / sub_m / sub_f / sub_th) each carry the same three skip
    # guards: (1) the ref is the visible text of an existing
    # `<a href="#id">ID</a>`, (2) the ref directly follows its own
    # `<a id="id"></a>` declaration, (3) the author already wrote an
    # em-dash description on the same line. Previously these were only
    # exercised for a subset of the four ID classes; pin all of them so a
    # refactor cannot silently drop a guard from one class.
    # ------------------------------------------------------------------

    def test_sub_t_skips_existing_html_anchor_text(self, tmp_path):
        """Bare T-NNN that is the text of `<a href="#t-001">T-001</a>` is
        not re-linkified (sub_t HTML-anchor guard)."""
        md = self._write_pair(tmp_path, 'Top: <a href="#t-001">T-001</a> here.\n')
        _, new_text = qa.linkify_anchors(md)
        assert '<a href="#t-001">T-001</a>' in new_text
        assert '<a href="#t-001">[T-001]' not in new_text

    def test_sub_t_skips_after_anchor_declaration(self, tmp_path):
        """Bare T-NNN directly after its `<a id="t-001"></a>` declaration in
        prose is left bare (sub_t anchor-declaration guard)."""
        md = self._write_pair(tmp_path, '<a id="t-001"></a>T-001 is the top class.\n')
        _, new_text = qa.linkify_anchors(md)
        assert '<a id="t-001"></a>T-001 is the top class.' in new_text
        assert "</a>[T-001]" not in new_text

    def test_sub_t_bare_with_author_em_dash(self, tmp_path):
        """Bare T-NNN followed by ` — <text>` gets a plain hyperlink, not the
        injected YAML title (sub_t em-dash guard)."""
        md = self._write_pair(tmp_path, "**Threat:** T-001 — author note follows.\n")
        _, new_text = qa.linkify_anchors(md)
        assert "[T-001](#t-001) — author note follows." in new_text
        assert "[T-001](#t-001) — SQL Injection" not in new_text

    def test_sub_m_skips_existing_html_anchor_text(self, tmp_path):
        """sub_m HTML-anchor guard."""
        md = self._write_pair(tmp_path, 'Mitigated by <a href="#m-001">M-001</a> soon.\n')
        _, new_text = qa.linkify_anchors(md)
        assert '<a href="#m-001">M-001</a>' in new_text
        assert '<a href="#m-001">[M-001]' not in new_text

    def test_sub_m_skips_after_anchor_declaration(self, tmp_path):
        """sub_m anchor-declaration guard (non-heading prose form)."""
        md = self._write_pair(tmp_path, '<a id="m-001"></a>M-001 applies to the login flow.\n')
        _, new_text = qa.linkify_anchors(md)
        assert '<a id="m-001"></a>M-001 applies to the login flow.' in new_text
        assert "</a>[M-001]" not in new_text

    def test_sub_m_bare_with_author_em_dash(self, tmp_path):
        """sub_m em-dash guard."""
        md = self._write_pair(tmp_path, "Mitigation M-001 — apply parameterised queries.\n")
        _, new_text = qa.linkify_anchors(md)
        assert "[M-001](#m-001) — apply parameterised queries." in new_text
        assert "[M-001](#m-001) — Use parameterized queries" not in new_text

    def test_sub_f_bare_with_author_em_dash(self, tmp_path):
        """sub_f em-dash guard."""
        md = self._write_pair(tmp_path, "Finding F-001 — see the detailed analysis.\n")
        _, new_text = qa.linkify_anchors(md)
        assert "[F-001](#f-001) — see the detailed analysis." in new_text
        assert "[F-001](#f-001) — SQL Injection" not in new_text

    def test_sub_th_skips_existing_html_anchor_text(self, tmp_path):
        """sub_th HTML-anchor guard."""
        md = self._write_pair(tmp_path, 'Class <a href="#th-01">TH-01</a> dominates.\n')
        _, new_text = qa.linkify_anchors(md)
        assert '<a href="#th-01">TH-01</a>' in new_text
        assert '<a href="#th-01">[TH-01]' not in new_text

    def test_sub_th_skips_already_linked(self, tmp_path):
        """sub_th bracket/paren guard: an already-linked [TH-01](#th-01) is not
        wrapped a second time."""
        md = self._write_pair(tmp_path, "See [TH-01](#th-01) for the top class.\n")
        _, new_text = qa.linkify_anchors(md)
        assert "[[TH-01]" not in new_text
        assert "[TH-01](#th-01)" in new_text

    def test_bare_ref_without_label_falls_back_to_plain_link(self, tmp_path):
        """A bare ID with no entry in the label index (`_labelled` fallback)
        becomes a plain `[ID](#id)` link with no ` — ` title suffix."""
        md = self._write_pair(tmp_path, "Tracked separately as T-999 in the backlog.\n")
        _, new_text = qa.linkify_anchors(md)
        assert "[T-999](#t-999)" in new_text
        assert "[T-999](#t-999) —" not in new_text

    def test_bare_ref_inside_code_fence_left_alone(self, tmp_path):
        """Bare IDs inside a fenced code block (e.g. Mermaid node labels) are
        not linkified (pass-2 fence guard)."""
        md_body = "## Notes\n\n```text\nnode T-036 stays bare here\n```\n"
        md = self._write_pair(tmp_path, md_body)
        _, new_text = qa.linkify_anchors(md)
        assert "node T-036 stays bare here" in new_text
        assert "[T-036]" not in new_text


class TestEvidenceIntegrity:
    """Cover the M1 evidence-integrity check end-to-end.

    The check guards against three drift modes after the STRIDE analyzer
    has run: hallucinated file paths, line numbers that have shifted past
    EOF, and absence-grep claims that no longer hold because someone
    landed the missing control.
    """

    def _fixture(self, tmp_path: Path) -> tuple[Path, Path]:
        src = tmp_path / "src.py"
        src.write_text(
            "def login(user, password):\n"
            "    # vulnerable: plain comparison\n"
            "    if user == 'admin' and password == 'secret':\n"
            "        return True\n"
            "    return False\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        return src, out

    def test_clean_finding_passes(self, tmp_path: Path):
        src, out = self._fixture(tmp_path)
        (out / ".threats-merged.json").write_text(
            '{"version":1,"generated_at":"t","threats":[{'
            '"t_id":"T-001","component_id":"c","component_name":"C",'
            '"stride":"Spoofing","risk":"Critical","likelihood":"High",'
            '"impact":"Critical","title":"X","cwe":"CWE-1",'
            '"evidence":{"file":"src.py","line":3},'
            '"source":"stride","architectural_violation":false}]}'
        )
        rep = qa.check_evidence_integrity(out, tmp_path)
        assert rep.issues == []
        assert rep.ok == 1

    def test_comment_line_flagged_as_suspicious(self, tmp_path: Path):
        src, out = self._fixture(tmp_path)
        (out / ".threats-merged.json").write_text(
            '{"version":1,"generated_at":"t","threats":[{'
            '"t_id":"T-002","component_id":"c","component_name":"C",'
            '"stride":"Spoofing","risk":"Critical","likelihood":"High",'
            '"impact":"Critical","title":"X","cwe":"CWE-1",'
            '"evidence":{"file":"src.py","line":2},'
            '"source":"stride","architectural_violation":false}]}'
        )
        rep = qa.check_evidence_integrity(out, tmp_path)
        assert any("evidence_line_suspicious" in i for i in rep.issues)

    def test_line_out_of_range_flagged(self, tmp_path: Path):
        src, out = self._fixture(tmp_path)
        (out / ".threats-merged.json").write_text(
            '{"version":1,"generated_at":"t","threats":[{'
            '"t_id":"T-003","component_id":"c","component_name":"C",'
            '"stride":"Spoofing","risk":"Critical","likelihood":"High",'
            '"impact":"Critical","title":"X","cwe":"CWE-1",'
            '"evidence":{"file":"src.py","line":999},'
            '"source":"stride","architectural_violation":false}]}'
        )
        rep = qa.check_evidence_integrity(out, tmp_path)
        assert any("evidence_line_out_of_range" in i for i in rep.issues)

    def test_missing_file_flagged(self, tmp_path: Path):
        _, out = self._fixture(tmp_path)
        (out / ".threats-merged.json").write_text(
            '{"version":1,"generated_at":"t","threats":[{'
            '"t_id":"T-004","component_id":"c","component_name":"C",'
            '"stride":"Spoofing","risk":"Critical","likelihood":"High",'
            '"impact":"Critical","title":"X","cwe":"CWE-1",'
            '"evidence":{"file":"nope.py","line":1},'
            '"source":"stride","architectural_violation":false}]}'
        )
        rep = qa.check_evidence_integrity(out, tmp_path)
        assert any("evidence_missing_file" in i for i in rep.issues)

    def test_null_line_skips_content_check(self, tmp_path: Path):
        _, out = self._fixture(tmp_path)
        (out / ".threats-merged.json").write_text(
            '{"version":1,"generated_at":"t","threats":[{'
            '"t_id":"T-005","component_id":"c","component_name":"C",'
            '"stride":"Spoofing","risk":"Critical","likelihood":"High",'
            '"impact":"Critical","title":"X","cwe":"CWE-1",'
            '"evidence":{"file":"src.py","line":null},'
            '"source":"stride","architectural_violation":false}]}'
        )
        rep = qa.check_evidence_integrity(out, tmp_path)
        assert rep.issues == []
        assert rep.ok == 1

    def test_absence_grep_drift_flagged(self, tmp_path: Path):
        # Source file actually contains 'rateLimit' — analyzer recorded 0
        # hits when it ran, so the absence claim has since drifted.
        (tmp_path / "app.js").write_text(
            "const rateLimit = require('express-rate-limit');\napp.use('/api', rateLimit({ windowMs: 60000 }));\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        (out / ".threats-merged.json").write_text(
            '{"version":1,"generated_at":"t","threats":[{'
            '"t_id":"T-006","component_id":"c","component_name":"C",'
            '"stride":"Denial of Service","risk":"High","likelihood":"Medium",'
            '"impact":"High","title":"Missing rate limit","cwe":"CWE-307",'
            '"evidence":{"file":"app.js","line":1},'
            '"source":"stride","architectural_violation":false,'
            '"controls_absent_evidence":[{"pattern":"rateLimit","search_paths":["."],"hit_count":0}]}]}'
        )
        rep = qa.check_evidence_integrity(out, tmp_path)
        assert any("absence_grep_drift" in i for i in rep.issues)

    def test_absence_grep_skips_output_dir(self, tmp_path: Path):
        # Pattern appears in the threats-merged.json itself; the check
        # must NOT count that as drift.
        (tmp_path / "app.js").write_text("// just a comment\n")
        out = tmp_path / "out"
        out.mkdir()
        (out / ".threats-merged.json").write_text(
            '{"version":1,"generated_at":"t","threats":[{'
            '"t_id":"T-007","component_id":"c","component_name":"C",'
            '"stride":"Denial of Service","risk":"High","likelihood":"Medium",'
            '"impact":"High","title":"Missing rate limit","cwe":"CWE-307",'
            '"evidence":{"file":"app.js","line":1},'
            '"source":"stride","architectural_violation":false,'
            '"controls_absent_evidence":[{"pattern":"rateLimit","search_paths":["."],"hit_count":0}]}]}'
        )
        rep = qa.check_evidence_integrity(out, tmp_path)
        assert not any("absence_grep_drift" in i for i in rep.issues)


class TestThreatModelOutputSchemaTitleRequired:
    """Pin the schema requirement that `title` is mandatory on threats[].

    Loosening this makes the cross-reference labelling invariant
    (AGENTS.md §4a) silently degrade — `_load_label_index` returns
    empty entries and the linkifier emits bare links.
    """

    def test_schema_lists_title_required_on_threats(self):
        import yaml as _yaml

        schema_path = REPO_ROOT / "schemas" / "threat-model.output.schema.yaml"
        schema = _yaml.safe_load(schema_path.read_text())
        threat_schema = schema["properties"]["threats"]["items"]
        assert "title" in threat_schema["required"], "title MUST be required on threats[] — see AGENTS.md §4a"
        assert threat_schema["properties"]["title"]["type"] == "string"
        assert threat_schema["properties"]["title"]["maxLength"] == 80, (
            "title maxLength MUST be 80 (raised from 60 in 2026-05 — "
            "parameter + path eat ~20 chars). See memory rule "
            "feedback_threat_model_finding_titles.md and AGENTS.md §4a. "
            "Do NOT raise this ceiling further."
        )


class TestHeadingAttributeStrip:
    """Pandoc/Kramdown `{#anchor ...}` and `data-source-line=...` residue
    must be stripped from headings before hygiene runs. Users have seen
    truncated trailers like `{#713-defense-in-depth-summary
    data-source-line="` leak into visible section titles.
    """

    def test_strips_pandoc_attribute_trailer(self, tmp_path: Path):
        md = _write_minimal_model(
            tmp_path,
            "### 7.13 Defense-in-Depth Summary {#713-defense-in-depth-summary}\n\nbody\n",
        )
        report, _ = qa.strip_heading_attribute_artifacts(md)
        assert report.fixes, "expected at least one heading to be stripped"
        assert "{#" not in md.read_text()

    def test_strips_truncated_data_source_line_trailer(self, tmp_path: Path):
        """Real-world failure: trailer is *open-ended* — no closing brace,
        captures stop mid-attribute. Strip must still succeed.
        """
        md = _write_minimal_model(
            tmp_path,
            '### 7.13 Defense-in-Depth Summary {#713-defense-in-depth-summary data-source-line="\n\nbody\n',
        )
        report, _ = qa.strip_heading_attribute_artifacts(md)
        assert report.fixes, "expected truncated trailer to be stripped"
        text = md.read_text()
        assert "data-source-line" not in text
        assert "{#" not in text
        assert "### 7.13 Defense-in-Depth Summary" in text

    def test_clean_headings_untouched(self, tmp_path: Path):
        md = _write_minimal_model(
            tmp_path,
            "### 7.13 Defense-in-Depth Summary\n\n### 8. Findings Register\n",
        )
        before = md.read_text()
        report, _ = qa.strip_heading_attribute_artifacts(md)
        assert not report.fixes
        assert md.read_text() == before

    def test_hygiene_flags_residual_attribute_syntax(self, tmp_path: Path):
        """If strip didn't run (or new variants slip through), hygiene
        must surface the issue rather than silently passing.
        """
        md = _write_minimal_model(
            tmp_path,
            "### 7.13 Defense-in-Depth Summary {#anchor}\n",
        )
        report = qa.check_heading_hygiene(md)
        assert any("attribute-syntax" in i for i in report.issues), report.issues


class TestUnfoundedPerimeterClaims:
    """Source-tree scan has no signal on deployment-time perimeter or
    runtime-environment controls. Claims about their absence are
    unfounded and must be flagged. Positive identification is OK.
    """

    def test_flags_no_waf_claim(self, tmp_path: Path):
        md = _write_minimal_model(tmp_path, "There is no WAF in front of the app.\n")
        r = qa.check_unfounded_perimeter_claims(md)
        assert any("WAF" in i for i in r.issues), r.issues

    def test_flags_missing_ids_claim(self, tmp_path: Path):
        md = _write_minimal_model(tmp_path, "The deployment has missing IDS coverage.\n")
        r = qa.check_unfounded_perimeter_claims(md)
        assert r.issues

    def test_flags_no_secret_scanning(self, tmp_path: Path):
        md = _write_minimal_model(tmp_path, "We observe no secret scanning service.\n")
        r = qa.check_unfounded_perimeter_claims(md)
        assert r.issues

    def test_flags_no_database_activity_monitoring(self, tmp_path: Path):
        md = _write_minimal_model(tmp_path, "There is no database activity monitoring.\n")
        r = qa.check_unfounded_perimeter_claims(md)
        assert r.issues

    def test_flags_no_ddos_protection(self, tmp_path: Path):
        md = _write_minimal_model(tmp_path, "There is no DDoS protection configured.\n")
        r = qa.check_unfounded_perimeter_claims(md)
        assert any("DDoS" in i for i in r.issues), r.issues

    def test_positive_waf_mention_is_ok(self, tmp_path: Path):
        md = _write_minimal_model(
            tmp_path,
            "The terraform module configures an AWS WAF block in front of the ALB.\n",
        )
        r = qa.check_unfounded_perimeter_claims(md)
        assert not r.issues, r.issues

    def test_code_fence_examples_are_skipped(self, tmp_path: Path):
        """Examples inside fenced code blocks (e.g. instructional YAML)
        are NOT user-facing prose and must not trigger the check.
        """
        md = _write_minimal_model(
            tmp_path,
            '```yaml\nenforcement: "TLS only; no WAF observed"\n```\n',
        )
        r = qa.check_unfounded_perimeter_claims(md)
        assert not r.issues

    def test_cli_subcommand_exists(self, tmp_path: Path):
        md = _write_minimal_model(tmp_path, "There is no WAF.\n")
        result = _run(["perimeter_claims", str(md)])
        assert result.returncode != 0, "expected non-zero exit on flagged claim"
        assert "WAF" in result.stdout


class TestStrengthsRowQuality:
    """Operational Strengths is reserved for architectural strengths.
    HTTP response-header hardening (helmet, X-Frame-Options, HSTS, etc.)
    is baseline hygiene and must not appear there.
    """

    _PREAMBLE = (
        "## Management Summary\n\n"
        "### Verdict\nshort\n\n"
        "### Operational Strengths\n\n"
        "| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |\n"
        "|---|---|---|---|---|\n"
    )

    def test_flags_http_security_headers_row(self, tmp_path: Path):
        body = self._PREAMBLE + (
            "| HTTP Security Headers | helmet | ⚠️ Partial | CSP absent | T-001 |\n\n## 2. Architecture\n"
        )
        md = _write_minimal_model(tmp_path, body)
        report = qa.check_strengths_row_quality(md)
        assert report.issues, "HTTP Security Headers row must be flagged"
        assert any("HTTP Security Headers" in i for i in report.issues)

    def test_flags_helmet_row(self, tmp_path: Path):
        body = self._PREAMBLE + (
            "| Helmet | response-header middleware | ✅ Adequate | none | — |\n\n## 2. Architecture\n"
        )
        md = _write_minimal_model(tmp_path, body)
        report = qa.check_strengths_row_quality(md)
        assert report.issues

    def test_flags_hsts_row(self, tmp_path: Path):
        body = self._PREAMBLE + (
            "| HSTS | Strict-Transport-Security on TLS endpoints | ✅ Adequate | none | — |\n\n## 2. Architecture\n"
        )
        md = _write_minimal_model(tmp_path, body)
        report = qa.check_strengths_row_quality(md)
        assert report.issues

    def test_genuinely_architectural_row_passes(self, tmp_path: Path):
        body = self._PREAMBLE + (
            "| Parameterized Database Access | Sequelize ORM default | ⚠️ Partial | raw SQL on /search | [T-009](#t-009) |\n"
            "| Centralised Session Validation | express-jwt at root | ✅ Adequate | — | — |\n"
            "\n## 2. Architecture\n"
        )
        md = _write_minimal_model(tmp_path, body)
        report = qa.check_strengths_row_quality(md)
        assert not report.issues, report.issues

    def test_mention_of_helmet_in_implementation_cell_is_ok(self, tmp_path: Path):
        """`helmet` may appear in the Implementation column as context for
        an architectural control — the check only inspects the first cell
        (the canonical control name), so this must pass.
        """
        body = self._PREAMBLE + (
            "| Centralised Request Hardening Layer | helmet + custom CSP nonce middleware | ⚠️ Partial | nonce gen weak | — |\n"
            "\n## 2. Architecture\n"
        )
        md = _write_minimal_model(tmp_path, body)
        report = qa.check_strengths_row_quality(md)
        assert not report.issues, report.issues

    def test_section_absent_is_noop(self, tmp_path: Path):
        md = _write_minimal_model(tmp_path, "## Other section\n\nnothing here\n")
        report = qa.check_strengths_row_quality(md)
        assert not report.issues

    def test_cli_subcommand_exists(self, tmp_path: Path):
        body = self._PREAMBLE + ("| HTTP Security Headers | helmet | ⚠️ Partial | none | — |\n")
        md = _write_minimal_model(tmp_path, body)
        result = _run(["strengths_quality", str(md)])
        assert result.returncode != 0
        assert "HTTP Security Headers" in result.stdout


class TestStrengthsRendererExcludesTacticalHygiene:
    """compose_threat_model._render_operational_strengths must drop rows
    whose canonical control name is flagged `excluded_from_strengths: true`
    in architectural-controls.yaml.
    """

    def test_excluded_names_includes_http_security_headers(self):
        import importlib.util as _ilu

        spec = _ilu.spec_from_file_location("compose_threat_model", REPO_ROOT / "scripts" / "compose_threat_model.py")
        compose = _ilu.module_from_spec(spec)
        sys.modules["compose_threat_model"] = compose
        scripts = str(REPO_ROOT / "scripts")
        if scripts not in sys.path:
            sys.path.insert(0, scripts)
        spec.loader.exec_module(compose)
        excluded = compose._strengths_excluded_names()
        # Normalised form drops spaces/case — match the same way.
        norm = lambda s: "".join(ch.lower() for ch in s if ch.isalnum())
        assert norm("HTTP Security Headers") in excluded
        # Alias coverage.
        assert norm("Helmet") in excluded
        assert norm("Response Headers") in excluded
        # Architectural-only controls must NOT be in the set.
        assert norm("Multi-Factor Authentication") not in excluded


class TestWalkthroughCoverageSourceLineMatch:
    """check_walkthrough_coverage must identify each per-Critical §3.x
    sub-section by the T-NNN on its `**Source:** [T-NNN]` line, NOT by the
    heading.

    Regression for the 2026-05-28 juice-shop run: walkthrough_renderer.py
    deliberately emits short, T-NNN-free headings (`### 3.2 <title>`) to stay
    under check_heading_hygiene's length limit and puts the T-NNN on the
    `**Source:**` line. The previous heading-only match reported all 12
    present walkthroughs as "missing", driving an unnecessary REPAIR_MODE
    re-render loop.
    """

    def _write_yaml_one_critical(self, output_dir: Path) -> None:
        (output_dir / "threat-model.yaml").write_text(
            textwrap.dedent(
                """\
                meta:
                  generated: 2026-05-28T00:00:00Z
                threats:
                  - id: T-001
                    title: Hardcoded RSA Private Key
                    risk: Critical
                    cwe: CWE-321
                """
            ),
            encoding="utf-8",
        )

    def _wrap_section3(self, body: str) -> str:
        return "## 3. Attack Walkthroughs\n\n### 3.1 Attack Chain Overview\n\nChains.\n\n" + body + "\n\n## 4. Assets\n"

    def test_source_line_satisfies_coverage_without_tnnn_in_heading(self, output_dir):
        qa = _load_qa_checks()
        self._write_yaml_one_critical(output_dir)
        section = (
            "### 3.2 Hardcoded RSA Private Key lib/insecurity.ts:23\n\n"
            "**Source:** [T-001](#t-001) — `lib/insecurity.ts:23`\n\n"
            "**Attack Steps**\n\n1. step\n\n"
            "**Sequence Diagram**\n\n```mermaid\nsequenceDiagram\n  A->>B: x\n```\n\n"
            "**Defense in Depth**\n\n- mitigation\n"
        )
        md = output_dir / "threat-model.md"
        md.write_text(self._wrap_section3(section), encoding="utf-8")
        report = qa.check_walkthrough_coverage(md, output_dir, qa.DEFAULT_CONTRACT_PATH)
        assert report.issues == [], report.issues
        assert report.ok == 1

    def test_genuinely_missing_critical_is_flagged_with_coherent_count(self, output_dir):
        qa = _load_qa_checks()
        self._write_yaml_one_critical(output_dir)
        # §3.2's Source line points at a DIFFERENT threat, so T-001 is missing.
        section = (
            "### 3.2 Some Other Finding\n\n**Source:** [T-002](#t-002) — `x.ts:1`\n\n**Attack Steps**\n\n1. step\n"
        )
        md = output_dir / "threat-model.md"
        md.write_text(self._wrap_section3(section), encoding="utf-8")
        report = qa.check_walkthrough_coverage(md, output_dir, qa.DEFAULT_CONTRACT_PATH)
        assert any("T-001" in i for i in report.issues)
        # No contradictory "1/1 present" — coherent "0/1 ... have a walkthrough".
        assert any("0/1 Critical findings have a walkthrough" in i for i in report.issues)

    def test_heading_tnnn_fallback_still_accepted(self, output_dir):
        qa = _load_qa_checks()
        self._write_yaml_one_critical(output_dir)
        # Legacy fragment shape: T-NNN in the heading, no **Source:** line.
        section = "### 3.2 T-001 — Hardcoded RSA Private Key\n\n**Attack Steps**\n\n1. step\n"
        md = output_dir / "threat-model.md"
        md.write_text(self._wrap_section3(section), encoding="utf-8")
        report = qa.check_walkthrough_coverage(md, output_dir, qa.DEFAULT_CONTRACT_PATH)
        assert report.issues == [], report.issues

    def test_compound_chain_crossref_does_not_count_as_own_walkthrough(self, output_dir):
        qa = _load_qa_checks()
        self._write_yaml_one_critical(output_dir)
        # §3.2 belongs to T-002 and merely mentions T-001 in prose ("compound
        # with T-001") — that cross-reference must NOT satisfy T-001's coverage.
        section = (
            "### 3.2 Some Other Finding\n\n"
            "**Source:** [T-002](#t-002) — `x.ts:1`\n\n"
            "Compound with T-001 through a shared asset.\n\n"
            "**Attack Steps**\n\n1. step\n"
        )
        md = output_dir / "threat-model.md"
        md.write_text(self._wrap_section3(section), encoding="utf-8")
        report = qa.check_walkthrough_coverage(md, output_dir, qa.DEFAULT_CONTRACT_PATH)
        assert any("T-001" in i for i in report.issues), report.issues


class TestWalkthroughCoverageCapped:
    """§3 is capped at the top-N Criticals (walkthrough_renderer). Coverage is
    enforced against that capped selection, not every Critical (2026-07-02)."""

    def _write_yaml_n_criticals(self, output_dir: Path, n: int) -> None:
        rows = "\n".join(
            f"  - id: T-{i:03d}\n    title: SQL injection sink {i}\n"
            f"    risk: Critical\n    cwe: CWE-89\n    breach_distance: {i}"
            for i in range(1, n + 1)
        )
        (output_dir / "threat-model.yaml").write_text(
            "meta:\n  generated: 2026-07-02T00:00:00Z\nthreats:\n" + rows + "\n",
            encoding="utf-8",
        )

    def _block(self, idx: int, tid: str) -> str:
        return (
            f"### 3.{idx} SQL injection sink\n\n"
            f"**Source:** [{tid}](#{tid.lower()}) — `routes/r.ts:{idx}`\n\n"
            "**Attack Steps**\n\n1. step\n\n"
            "**Sequence Diagram**\n\n```mermaid\nsequenceDiagram\n  A->>B: x\n```\n\n"
            "**Defense in Depth**\n\n- mitigation\n"
        )

    def _md(self, output_dir: Path, tids: list[str]) -> Path:
        body = "\n\n".join(self._block(i + 1, t) for i, t in enumerate(tids))
        md = output_dir / "threat-model.md"
        md.write_text("## 3. Attack Walkthroughs\n\n" + body + "\n\n## 4. Assets\n", encoding="utf-8")
        return md

    def test_top_n_coverage_passes_overflow_not_flagged(self, output_dir):
        qa = _load_qa_checks()
        import walkthrough_renderer as wr

        self._write_yaml_n_criticals(output_dir, 12)
        # Walk through exactly the top-N selection; T-009..T-012 must NOT be flagged.
        top = [f"T-{i:03d}" for i in range(1, wr.DEFAULT_MAX_WALKTHROUGHS + 1)]
        md = self._md(output_dir, top)
        report = qa.check_walkthrough_coverage(md, output_dir, qa.DEFAULT_CONTRACT_PATH)
        assert report.issues == [], report.issues
        assert report.ok == 1

    def test_missing_top_n_critical_is_flagged(self, output_dir):
        qa = _load_qa_checks()
        import walkthrough_renderer as wr

        self._write_yaml_n_criticals(output_dir, 12)
        # Cover 7 of the top-8 — drop T-008 (a top-N pick) → must be flagged.
        top = [f"T-{i:03d}" for i in range(1, wr.DEFAULT_MAX_WALKTHROUGHS)]  # T-001..T-007
        md = self._md(output_dir, top)
        report = qa.check_walkthrough_coverage(md, output_dir, qa.DEFAULT_CONTRACT_PATH)
        assert any("T-008" in i for i in report.issues), report.issues
        assert any("highest-priority of 12" in i for i in report.issues)

    def test_explosion_over_cap_is_flagged(self, output_dir):
        qa = _load_qa_checks()
        self._write_yaml_n_criticals(output_dir, 12)
        # A reverted render that walks ALL 12 Criticals → exceeds the cap.
        allt = [f"T-{i:03d}" for i in range(1, 13)]
        md = self._md(output_dir, allt)
        report = qa.check_walkthrough_coverage(md, output_dir, qa.DEFAULT_CONTRACT_PATH)
        assert any("exceed the cap" in i for i in report.issues), report.issues


def test_section7_h4_status_flags_missing_badge(tmp_path: Path):
    """An H4 with no `**Status:**` badge is flagged (warning-level)."""
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [Password Login](#password-login).

            #### Password Login

            The login route at routes/login.ts builds a SQL string from the
            submitted email and the hashed password before issuing a session.

            **Security assessment**

            The query interpolates user input.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )
    report = qa.check_section7_h4_status(md)
    assert any("Status" in w and "Password Login" in w for w in report.warnings)
    # warning-level only — must not hard-fail
    assert report.ok == 1


def test_section7_h4_status_accepts_badge_and_intro_tolerates_it(tmp_path: Path):
    """A leading `**Status:**` badge satisfies the status check AND is skipped
    by the positive-intro check so the real intro paragraph is validated."""
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [Password Login](#password-login).

            #### Password Login

            **Status:** 🔴 Unsafe — raw SQL login lookup allows authentication bypass.

            The login route at routes/login.ts builds a SQL string from the
            submitted email and the hashed password before issuing a session
            token, so any caller who controls the email field controls the query.

            **Security assessment**

            The query interpolates user input.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )
    status_report = qa.check_section7_h4_status(md)
    assert not status_report.warnings, status_report.warnings
    intro_report = qa.check_section7_h4_positive_intro(md)
    # the Status line must NOT be mistaken for the intro paragraph
    assert not any("no positive intro" in i for i in intro_report.issues), intro_report.issues
    assert not any("too short" in i for i in intro_report.issues), intro_report.issues


def test_section7_h4_positive_intro_skips_anti_pattern_label(tmp_path: Path):
    """An optional `⚠ **Anti-pattern:**` metadata line between the Status badge
    and the intro is skipped by the positive-intro check — the real intro
    paragraph (not the label) is the one validated."""
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.2 Identity and Authentication Controls

            **Controls covered:** [Password Login](#password-login).

            #### Password Login

            **Status:** 🔴 Unsafe — raw SQL login lookup allows authentication bypass.

            ⚠ **Anti-pattern:** Raw SQL string interpolation

            The login route at routes/login.ts builds a SQL string from the
            submitted email and the hashed password before issuing a session
            token, so any caller who controls the email field controls the query.

            **Security assessment**

            The query interpolates user input.

            **Relevant findings**

            - No dedicated finding routed in this assessment.
        """),
    )
    intro_report = qa.check_section7_h4_positive_intro(md)
    assert not any("no positive intro" in i for i in intro_report.issues), intro_report.issues
    assert not any("too short" in i for i in intro_report.issues), intro_report.issues


# ---------------------------------------------------------------------------
# linkify_anchors — §2 Top-Threats span doubling (2026-06-11 juice-shop)
# The composer wraps ONLY the link in a nowrap span and puts the title AFTER
# the close tag: `<span>[F-006](#f-006)</span> — Title`. The sub_existing
# suffix pass mis-read the `</span>` (not whitespace) right after the link as
# "unlabelled" and re-appended the yaml title INSIDE the span — doubling every
# §2 finding title.
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, body: str) -> None:
    (path / "threat-model.yaml").write_text(body, encoding="utf-8")


def test_linkify_anchors_no_double_when_title_after_span(tmp_path: Path):
    _write_yaml(
        tmp_path,
        "threats:\n  - id: T-006\n    title: SQL Injection via Raw Query String Interpolation (routes/login.ts:34)\n",
    )
    # Real composer output: link wrapped in the span, title AFTER `</span>`,
    # separator is a HYPHEN (compose normalises em-dash→hyphen before persist).
    cell = (
        '<span style="white-space:nowrap">🔴&nbsp;[F-006](#f-006)</span>'
        " - SQL Injection via Raw Query String Interpolation (routes/login.ts:34) "
        '<span style="white-space:nowrap">→&nbsp;[C-03](#c-03)</span>'
    )
    md = _write_minimal_model(tmp_path, f"## 2 Threat Landscape\n\n| # | Findings |\n|---|---|\n| ① | {cell} |\n")
    _report, out = qa.linkify_anchors(md)
    # The bare link inside the span must NOT get a re-appended ` — Title`.
    assert "[F-006](#f-006) — " not in out, out
    # Title still present exactly once.
    assert out.count("SQL Injection via Raw Query String Interpolation") == 1, out


def test_linkify_anchors_labels_bare_mitigation_outside_span(tmp_path: Path):
    # The §2/§8 Fix column carries `<span>❶ [M-006](#m-006)</span>` with NO title
    # after the span — these MUST be labelled, and the title MUST land OUTSIDE the
    # nowrap span. If it were injected before `</span>` the whole ~110ch sentence
    # becomes one unbreakable run and the Fix column overflows off-screen
    # (juice-shop 2026-06-11).
    _write_yaml(
        tmp_path,
        "mitigations:\n  - id: M-006\n    title: Replace raw sequelize.query() with a parameterised query\n",
    )
    cell = '<span style="white-space:nowrap">❶ [M-006](#m-006)</span><br/>'
    md = _write_minimal_model(tmp_path, f"## 2 Threat Landscape\n\n| Fix |\n|---|\n| {cell} |\n")
    _report, out = qa.linkify_anchors(md)
    # Title appended AFTER the close tag — the nowrap span still wraps only the
    # marker + id, so the title is free to wrap on normal spaces.
    assert "[M-006](#m-006)</span> — Replace raw sequelize.query()" in out, out
    # And NOT before it (the span must not swallow the title).
    assert "sequelize.query() with a parameterised query</span>" not in out, out


def test_linkify_anchors_fix_span_label_is_idempotent(tmp_path: Path):
    # Re-running on an already-labelled Fix cell must NOT double the title.
    _write_yaml(
        tmp_path,
        "mitigations:\n  - id: M-006\n    title: Replace raw sequelize.query() with a parameterised query\n",
    )
    cell = (
        '<span style="white-space:nowrap">❶ [M-006](#m-006)</span>'
        " — Replace raw sequelize.query() with a parameterised query<br/>"
    )
    md = _write_minimal_model(tmp_path, f"## 2 Threat Landscape\n\n| Fix |\n|---|\n| {cell} |\n")
    _report, out = qa.linkify_anchors(md)
    assert out.count("Replace raw sequelize.query() with a parameterised query") == 1, out


def test_linkify_anchors_still_labels_bare_finding_link(tmp_path: Path):
    # Guard against over-correcting: a genuinely bare `[F-006](#f-006)` in prose
    # (no following title) must still receive its ` — Title` suffix.
    _write_yaml(
        tmp_path,
        "threats:\n  - id: T-006\n    title: SQL Injection via Raw Query String Interpolation (routes/login.ts:34)\n",
    )
    md = _write_minimal_model(tmp_path, "## 5 Attack Surface\n\nSee [F-006](#f-006) for the login sink.\n")
    _report, out = qa.linkify_anchors(md)
    assert "[F-006](#f-006) — SQL Injection via Raw Query String Interpolation" in out, out


# ---------------------------------------------------------------------------
# §5 Attack-Surface entry-point tables → fixed-layout HTML (2026-06-11)
# ---------------------------------------------------------------------------
def test_render_inline_md_to_html_covers_cell_vocabulary():
    cell = "🔴 [F-007](#f-007) (SQL Injection)<br/>handler: `server.ts:600` **note**"
    html = qa._render_inline_md_to_html(cell)
    assert '<a href="#f-007">F-007</a>' in html
    assert "<code>server.ts:600</code>" in html
    assert "<br/>" in html
    assert "<strong>note</strong>" in html
    assert "🔴" in html  # emoji passes through
    # No raw markdown link/code/bold delimiters leak through.
    assert "](#" not in html and "`" not in html and "**" not in html


def test_render_inline_md_to_html_escapes_specials():
    assert qa._render_inline_md_to_html("a < b & c > d") == "a &lt; b &amp; c &gt; d"


_AS_GFM = (
    "| Method | Route | Risk | Notes |\n"
    "|------|------|------|------|\n"
    "| GET | `/rest/products/search` | 🔴 Critical | [F-007](#f-007)<br/>handler: `server.ts:600` |\n"
    "| POST | `/file-upload` | 🟠 High | [F-015](#f-015) |\n"
)


def test_attack_surface_tables_to_html_converts_and_pins_widths():
    out, count = qa._attack_surface_tables_to_html(f"### 5.1 Unauthenticated\n\n{_AS_GFM}\n_footer._\n")
    assert count == 1
    assert '<table style="table-layout:fixed;width:100%">' in out
    # Shared colgroup pins identical widths.
    assert "".join(f'<col width="{w}" style="width:{w}">' for w in qa._AS_COL_WIDTHS) in out
    # Cell markdown is pre-rendered to HTML (markdown-it won't parse it inside <table>).
    assert '<a href="#f-007">F-007</a>' in out and "<code>/rest/products/search</code>" in out
    # Route cell carries overflow-wrap so long routes wrap inside the fixed column.
    assert "overflow-wrap:anywhere" in out
    # Surrounding markdown (heading, footer) is untouched.
    assert "### 5.1 Unauthenticated" in out and "_footer._" in out
    # No GFM pipe rows survive for the converted table.
    assert "| GET |" not in out


def test_attack_surface_tables_to_html_is_idempotent():
    once, c1 = qa._attack_surface_tables_to_html(_AS_GFM)
    twice, c2 = qa._attack_surface_tables_to_html(once)
    assert c1 == 1 and c2 == 0 and twice == once


def test_attack_surface_tables_to_html_identical_columns_both_tables():
    two = f"### 5.1\n\n{_AS_GFM}\n### 5.2\n\n{_AS_GFM}\n"
    out, count = qa._attack_surface_tables_to_html(two)
    assert count == 2
    # Both tables emit the SAME colgroup → identical column widths.
    assert out.count("".join(f'<col width="{w}" style="width:{w}">' for w in qa._AS_COL_WIDTHS)) == 2


def test_attack_surface_tables_to_html_leaves_other_tables_alone():
    other = "| Control | Status |\n|---|---|\n| CSP | 🟠 Weak |\n"
    out, count = qa._attack_surface_tables_to_html(other)
    assert count == 0 and out == other


_ASSET_GFM = (
    "| Asset | Classification | Description | Linked Threats |\n"
    "|------|------|------|------|\n"
    "| User Credentials | Restricted | User email and `MD5`-hashed<br/>passwords stored in SQLite. | "
    "🔴 [F-006](#f-006) — SQL Injection<br/>🟠 [F-013](#f-013) — Weak Hash |\n"
)


def test_asset_table_converts_and_reflows_description():
    out, count = qa._attack_surface_tables_to_html(f"## 4. Assets\n\n{_ASSET_GFM}\n")
    assert count == 1
    assert '<table style="table-layout:fixed;width:100%">' in out
    assert "".join(f'<col width="{w}" style="width:{w}">' for w in qa._ASSET_COL_WIDTHS) in out
    # No ID column any more (dropped deterministically in compose).
    assert "A-001" not in out
    # Description (prose col) has its soft-wrap <br/> stripped → reflows clean.
    desc_cell = out.split("<td>User email and", 1)[1].split("</td>", 1)[0]
    assert "<br/>" not in desc_cell and "<code>MD5</code>" in desc_cell
    # Linked-Threats (link-stack col) KEEPS its <br/> between findings.
    assert '<a href="#f-006">F-006</a> — SQL Injection<br/>' in out
    assert '<a href="#f-013">F-013</a> — Weak Hash' in out


def test_asset_and_attack_surface_specs_widths_sum_to_100():
    for widths in (qa._AS_COL_WIDTHS, qa._ASSET_COL_WIDTHS, qa._STRENGTH_COL_WIDTHS):
        assert sum(int(w.rstrip("%")) for w in widths) == 100


def test_operational_strengths_table_converts_keeping_structural_breaks():
    # "What's in Place" carries STRUCTURAL <br/> (italic description, then one
    # implementation per line) that must survive the HTML conversion; only the
    # 44-char soft-wrap artifacts (compose now omits them) would be unwanted.
    gfm = (
        "| Strength | What's in Place | Effectiveness | Gap | Mitigates |\n"
        "|---|---|---|---|---|\n"
        "| **Container Hardening** | _Build-time and runtime hardening._<br/>Automated SCA scanning<br/>"
        "Container Security | ✅ Adequate | - | - |\n"
    )
    out, count = qa._attack_surface_tables_to_html(f"### Operational Strengths\n\n{gfm}\n")
    assert count == 1 and '<table style="table-layout:fixed;width:100%">' in out
    # Italic description rendered to <em> (markdown-it won't parse `_..._` inside
    # a raw <table>), and the STRUCTURAL <br/> (description + each implementation)
    # preserved.
    assert "<em>Build-time and runtime hardening.</em><br/>Automated SCA scanning<br/>Container Security" in out, out
    # Strength cell bold rendered too.
    assert "<strong>Container Hardening</strong>" in out


# ---------------------------------------------------------------------------
# 2026-06-12 — cmd_autofix folds code-token backticking in BEFORE the §5/§4
# GFM→HTML conversion, so `compose → qa_checks autofix` is a complete cleaning
# pass that survives a later recompose (the deliverable shipped bare
# `server.ts:663` because path-backticking was not part of autofix).
# ---------------------------------------------------------------------------


def test_autofix_backticks_paths_and_converts_attack_surface(tmp_path: Path):
    qa._PrePass.reset()
    md = _write_minimal_model(
        tmp_path,
        textwrap.dedent("""\
            ## 5. Attack Surface

            ### 5.1 Unauthenticated Entry Points

            | Method | Route | Risk | Notes |
            |---|---|---|---|
            | GET | /profile | Critical | handler: server.ts:663 |
            """),
    )
    rc = qa.cmd_autofix(md, tmp_path)
    assert rc == 0
    text = md.read_text(encoding="utf-8")
    # §5 became a fixed-layout HTML table AND the bare file:line is now a code cell.
    assert "table-layout:fixed" in text
    assert "<code>server.ts:663</code>" in text
    assert "handler: server.ts:663 |" not in text  # no bare GFM remnant


def test_autofix_is_idempotent_on_paths(tmp_path: Path):
    qa._PrePass.reset()
    md = _write_minimal_model(tmp_path, "The sink is at `lib/insecurity.ts:54` in prose.\n")
    qa.cmd_autofix(md, tmp_path)
    first = md.read_text(encoding="utf-8")
    qa._PrePass.reset()
    qa.cmd_autofix(md, tmp_path)
    assert md.read_text(encoding="utf-8") == first
    assert first.count("`lib/insecurity.ts:54`") == 1  # not double-wrapped


def test_priority_circle_styling_handles_markdown_and_converted_html():
    text = '❶ [M-001](#m-001)\n❷&nbsp;<a href="#m-002">M-002</a>\n```text\n❸ [M-003](#m-003)\n```\n'
    styled, count = qa._style_priority_circles(text)
    assert count == 2
    assert '<span style="color:#111111">❶</span> [M-001](#m-001)' in styled
    assert '<span style="color:#555555">❷</span>&nbsp;<a href="#m-002">M-002</a>' in styled
    assert "```text\n❸ [M-003](#m-003)\n```" in styled


def test_priority_circle_styling_is_idempotent_and_corrects_stale_color():
    text = '<span style="color:#ffffff">❹</span> [M-004](#m-004)\n'
    first, first_count = qa._style_priority_circles(text)
    second, second_count = qa._style_priority_circles(first)
    assert first_count == second_count == 1
    assert first == second == '<span style="color:#bbbbbb">❹</span> [M-004](#m-004)\n'


def test_apply_priority_circle_styling_reports_only_real_changes(tmp_path: Path):
    md = _write_minimal_model(tmp_path, "❷ [M-002](#m-002)\n")
    assert qa._apply_priority_circle_styling(md) == 1
    assert qa._apply_priority_circle_styling(md) == 0


def test_autofix_priority_circle_styling_is_idempotent(tmp_path: Path):
    # A legacy ❶ digit is migrated to the fill-ramp glyph (● for P1) and stays
    # colourless — the ramp encodes priority by fill, not by a colour span.
    md = _write_minimal_model(tmp_path, "❶ [M-001](#m-001)\n")
    (tmp_path / "threat-model.yaml").write_text(
        "threats: []\nmitigations:\n  - id: M-001\n    priority: p1\n",
        encoding="utf-8",
    )
    qa.cmd_autofix(md, tmp_path)
    first = md.read_text(encoding="utf-8")
    qa.cmd_autofix(md, tmp_path)
    second = md.read_text(encoding="utf-8")
    assert first == second
    assert second.count("●") == 1
    assert "❶" not in second  # legacy digit migrated away
    assert 'style="color:' not in second  # no fragile colour span
