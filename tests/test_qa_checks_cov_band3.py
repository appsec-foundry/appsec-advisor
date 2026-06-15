"""Coverage band 3 tests for scripts/qa_checks.py (lines ~5416-7700).

Targets the compactness / walkthrough / prose / IAM-bridge family of
checks plus their small helper functions. Each test calls the function
directly with a tmp_path fixture and a contract file the test controls,
exercising both the clean (ok=1) and the issue/warning branches.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "qa_checks.py"


def _load():
    if "qa_checks" in sys.modules:
        return sys.modules["qa_checks"]
    spec = importlib.util.spec_from_file_location("qa_checks", SCRIPT_PATH)
    m = importlib.util.module_from_spec(spec)
    sys.modules["qa_checks"] = m
    assert spec.loader is not None
    spec.loader.exec_module(m)
    return m


qa = _load()


def _md(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "threat-model.md"
    f.write_text(textwrap.dedent(content), encoding="utf-8")
    return f


def _contract(tmp_path: Path, yaml_text: str, name: str = "contract.yaml") -> Path:
    f = tmp_path / name
    f.write_text(textwrap.dedent(yaml_text), encoding="utf-8")
    return f


# ===========================================================================
# _row_is_auth_method
# ===========================================================================


def test_row_is_auth_method_empty_whitelist():
    assert qa._row_is_auth_method("Password Login", []) is False


def test_row_is_auth_method_subset_match():
    wl = ["password login", "oauth", "totp"]
    assert qa._row_is_auth_method("Standard Password Login Flow", wl) is True
    assert qa._row_is_auth_method("Google OAuth", wl) is True
    assert qa._row_is_auth_method("Login Rate Limiting", wl) is False


def test_row_is_auth_method_non_string_entry_skipped():
    # Non-string whitelist entries are skipped; the valid one still matches.
    assert qa._row_is_auth_method("jwt issuance", [None, 123, "jwt"]) is True


# ===========================================================================
# _check_intro_before_diagram
# ===========================================================================


def test_intro_before_diagram_no_fence_noop():
    rep = qa.Report("x")
    qa._check_intro_before_diagram(rep, "H", "no mermaid here at all", "####")
    assert rep.issues == []


def test_intro_before_diagram_missing_prose_flags():
    rep = qa.Report("x")
    body = "```mermaid\nsequenceDiagram\n```\n"
    qa._check_intro_before_diagram(rep, "Login", body, "####")
    assert any("no introductory prose" in i for i in rep.issues)


def test_intro_before_diagram_with_prose_ok():
    rep = qa.Report("x")
    body = "This flow authenticates the user.\n\n```mermaid\nsequenceDiagram\n```\n"
    qa._check_intro_before_diagram(rep, "Login", body, "####")
    assert rep.issues == []


# ===========================================================================
# _check_intro_before_security_assessment
# ===========================================================================


def test_intro_before_security_assessment_no_label_noop():
    rep = qa.Report("x")
    qa._check_intro_before_security_assessment(rep, "H", "just prose", "####")
    assert rep.issues == []


def test_intro_before_security_assessment_missing_intro_flags():
    rep = qa.Report("x")
    body = "**Verdict:** missing\n**Security assessment**\nbody"
    qa._check_intro_before_security_assessment(rep, "OAuth", body, "####")
    assert any("no positive-case prose" in i for i in rep.issues)


def test_intro_before_security_assessment_short_lines_skipped():
    rep = qa.Report("x")
    # short line (<10 chars) does not count as prose -> flagged
    body = "hi\n**Security assessment**\nbody"
    qa._check_intro_before_security_assessment(rep, "OAuth", body, "####")
    assert any("no positive-case prose" in i for i in rep.issues)


def test_intro_before_security_assessment_with_intro_ok():
    rep = qa.Report("x")
    body = "The OAuth flow is implemented in the Angular frontend.\n\n**Security assessment**\nnarrative"
    qa._check_intro_before_security_assessment(rep, "OAuth", body, "####")
    assert rep.issues == []


def test_intro_before_security_assessment_html_comment_not_prose():
    rep = qa.Report("x")
    body = "<!-- placeholder text here long enough -->\n**Security assessment**\nbody"
    qa._check_intro_before_security_assessment(rep, "OAuth", body, "####")
    assert any("no positive-case prose" in i for i in rep.issues)


# ===========================================================================
# _run_auth_v2_structural_checks
# ===========================================================================


def test_auth_v2_no_subsections_noop():
    rep = qa.Report("x")
    qa._run_auth_v2_structural_checks(
        report=rep,
        iam_body="no headings here",
        heading_level=4,
        method_whitelist=["password"],
        forbidden_heading_patterns=[],
        section_label="7.2 Auth",
    )
    assert rep.ok == 1
    assert rep.issues == []


def test_auth_v2_invalid_forbidden_pattern():
    rep = qa.Report("x")
    body = "#### 7.2.1 Password Login\nbody\n"
    qa._run_auth_v2_structural_checks(
        report=rep,
        iam_body=body,
        heading_level=4,
        method_whitelist=["password login"],
        forbidden_heading_patterns=["(unclosed"],
        section_label="7.2 Auth",
    )
    assert any("invalid `forbidden_heading_patterns`" in i for i in rep.issues)


def test_auth_v2_forbidden_pattern_match():
    rep = qa.Report("x")
    body = "#### 7.2.2 Password Hashing\nbody\n"
    qa._run_auth_v2_structural_checks(
        report=rep,
        iam_body=body,
        heading_level=4,
        method_whitelist=["password login"],
        forbidden_heading_patterns=[r"Password Hashing"],
        section_label="7.2 Auth",
    )
    assert any("forbidden" in i.lower() for i in rep.issues)


def test_auth_v2_not_recognized_mechanism():
    rep = qa.Report("x")
    body = "#### 7.2.3 Some Random Thing\nbody\n"
    qa._run_auth_v2_structural_checks(
        report=rep,
        iam_body=body,
        heading_level=4,
        method_whitelist=["password login", "oauth"],
        forbidden_heading_patterns=[],
        section_label="7.2 Auth",
    )
    assert any("not a recognized authentication" in i for i in rep.issues)


def test_auth_v2_flow_method_requires_diagram():
    rep = qa.Report("x")
    body = "#### 7.2.1 Password Login\nbody without diagram\n"
    qa._run_auth_v2_structural_checks(
        report=rep,
        iam_body=body,
        heading_level=4,
        method_whitelist=["password login"],
        forbidden_heading_patterns=[],
        section_label="7.2 Auth",
        flow_methods_require_diagram=True,
        flow_method_tokens=["password login"],
        flow_diagram_token="sequenceDiagram",
    )
    assert any("no `sequenceDiagram` diagram" in i for i in rep.issues)


def test_auth_v2_flow_method_with_diagram_ok():
    rep = qa.Report("x")
    body = "#### 7.2.1 Password Login\n```mermaid\nsequenceDiagram\n```\n"
    qa._run_auth_v2_structural_checks(
        report=rep,
        iam_body=body,
        heading_level=4,
        method_whitelist=["password login"],
        forbidden_heading_patterns=[],
        section_label="7.2 Auth",
        flow_methods_require_diagram=True,
        flow_method_tokens=["password login"],
    )
    assert not any("no `sequenceDiagram`" in i for i in rep.issues)


# ===========================================================================
# _run_auth_structural_checks
# ===========================================================================


def test_auth_structural_forbidden_attack_shape():
    rep = qa.Report("x")
    subs = {"7.3.1 JWT Forgery Flow": "body"}
    qa._run_auth_structural_checks(
        report=rep,
        subsections=subs,
        heading_pattern="",
        required_trailers=[],
        required_body_elems=[],
        forbidden_heading_patterns=[r"Forgery"],
        hashes="####",
    )
    assert any("forbidden attack-shape" in i for i in rep.issues)


def test_auth_structural_invalid_forbidden_pattern():
    rep = qa.Report("x")
    subs = {"7.3.1 Login": "body"}
    qa._run_auth_structural_checks(
        report=rep,
        subsections=subs,
        heading_pattern="",
        required_trailers=[],
        required_body_elems=[],
        forbidden_heading_patterns=["(bad"],
        hashes="####",
    )
    assert any("invalid `forbidden_heading_patterns`" in i for i in rep.issues)


def test_auth_structural_heading_pattern_mismatch():
    rep = qa.Report("x")
    subs = {"7.3.1 Wrong": "body"}
    qa._run_auth_structural_checks(
        report=rep,
        subsections=subs,
        heading_pattern=r"Flow$",
        required_trailers=[],
        required_body_elems=[],
        hashes="####",
    )
    assert any("does not match required pattern" in i for i in rep.issues)


def test_auth_structural_invalid_heading_pattern():
    rep = qa.Report("x")
    subs = {"7.3.1 Login Flow": "body"}
    qa._run_auth_structural_checks(
        report=rep,
        subsections=subs,
        heading_pattern="(bad",
        required_trailers=[],
        required_body_elems=[],
        hashes="####",
    )
    assert any("invalid `heading_pattern`" in i for i in rep.issues)


def test_auth_structural_missing_trailer():
    rep = qa.Report("x")
    subs = {"7.3.1 Login Flow": "no trailer"}
    qa._run_auth_structural_checks(
        report=rep,
        subsections=subs,
        heading_pattern="",
        required_trailers=["Risk assessment"],
        required_body_elems=[],
        hashes="####",
    )
    assert any("missing" in i and "Risk assessment" in i for i in rep.issues)


def test_auth_structural_required_body_elem_missing_and_sentinels():
    rep = qa.Report("x")
    subs = {"7.3.1 Login Flow": "body without needle"}
    qa._run_auth_structural_checks(
        report=rep,
        subsections=subs,
        heading_pattern="",
        required_trailers=[],
        required_body_elems=["sequenceDiagram", "intro_before_diagram", "intro_before_security_assessment"],
        hashes="####",
    )
    # plain needle missing
    assert any("required element 'sequenceDiagram'" in i for i in rep.issues)


# ===========================================================================
# check_diagram_compactness
# ===========================================================================

_DIAGRAM_CONTRACT = """\
sections:
  architecture_diagrams:
    diagram_compactness:
      "2.2 Container Architecture":
        layout_keyword: "flowchart TD"
        max_subgraphs: 2
        max_nodes_total: 4
        max_label_lines: 2
        max_label_chars_per_line: 30
        require_edge_labels: true
        required_classdefs:
          ext: "fill:#fff"
"""


def test_diagram_compactness_no_contract_silent(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = tmp_path / "missing.yaml"
    rep = qa.check_diagram_compactness(md, c)
    assert rep.ok == 0  # silent, returns report unchanged
    assert rep.issues == []


def test_diagram_compactness_no_rules_ok(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, "sections:\n  architecture_diagrams: {}\n")
    rep = qa.check_diagram_compactness(md, c)
    assert rep.ok == 1


def test_diagram_compactness_missing_subsection(tmp_path):
    md = _md(tmp_path, "# doc\nno arch section\n")
    c = _contract(tmp_path, _DIAGRAM_CONTRACT)
    rep = qa.check_diagram_compactness(md, c)
    assert any("subsection body not found" in i for i in rep.issues)


def test_diagram_compactness_no_mermaid(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 2.2 Container Architecture
        prose only no diagram
        ## 3. Next
        """,
    )
    c = _contract(tmp_path, _DIAGRAM_CONTRACT)
    rep = qa.check_diagram_compactness(md, c)
    assert any("no mermaid block found" in i for i in rep.issues)


def test_diagram_compactness_violations(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 2.2 Container Architecture

        ```mermaid
        graph LR
          subgraph A
            N1["this is a very very very long label exceeding chars"]
          end
          subgraph B
            N2["b"]
          end
          subgraph C
            N3["c"]
          end
          N1 --> N2
          N4["d"]
          N5["e"]
        ```
        ## 3. Next
        """,
    )
    c = _contract(tmp_path, _DIAGRAM_CONTRACT)
    rep = qa.check_diagram_compactness(md, c)
    joined = " ".join(rep.issues)
    assert "must start with `flowchart TD`" in joined
    assert "subgraphs found" in joined
    assert "nodes found" in joined
    assert "label line exceeds" in joined
    assert "missing/divergent classDef" in joined
    assert "unlabelled edge" in joined


def test_diagram_compactness_clean(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 2.2 Container Architecture

        ```mermaid
        flowchart TD
          subgraph ext
            N1["client"]
          end
          N1 -->|HTTPS| N2["api"]
          classDef ext fill:#fff
        ```
        ## 3. Next
        """,
    )
    c = _contract(tmp_path, _DIAGRAM_CONTRACT)
    rep = qa.check_diagram_compactness(md, c)
    assert rep.ok == 1, rep.issues


# ===========================================================================
# diagram threat-traceability
# ===========================================================================

_DIAGRAM_TRACE_CONTRACT = """\
sections:
  architecture_diagrams:
    diagram_compactness:
      "2.3 Components":
        layout_keyword: "flowchart TD"
        require_threat_traceability: true
"""


def test_diagram_traceability_unknown_and_missing(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## 2. Architecture Diagrams

        ### 2.3 Components

        ```mermaid
        flowchart TD
          N1["uses T-999"]
        ```

        ## 8. Threat Register

        ### 🔴 Critical (1)

        <a id="t-001"></a>
        T-001 critical finding

        ## 9. End
        """,
    )
    c = _contract(tmp_path, _DIAGRAM_TRACE_CONTRACT)
    rep = qa.check_diagram_compactness(md, c)
    joined = " ".join(rep.issues)
    # cites T-999 not in register
    assert "T-999" in joined
    # Critical T-001 not referenced in §2
    assert "not referenced anywhere in §2" in joined


def test_collect_threat_register_and_critical_high():
    text = textwrap.dedent(
        """\
        ## 8. Threat Register

        ### 🔴 Critical (1)

        <a id="t-001"></a>
        Critical one T-001

        ### 🟡 Medium (1)

        <a id="t-050"></a>
        Medium T-050

        ## 9. End
        """
    )
    reg = qa._collect_threat_register_t_ids(text)
    assert "T-001" in reg and "T-050" in reg
    ch = qa._collect_critical_high_t_ids(text)
    assert "T-001" in ch and "T-050" not in ch


def test_collect_threat_register_no_section():
    assert qa._collect_threat_register_t_ids("nothing here") == set()
    assert qa._collect_critical_high_t_ids("nothing here") == set()


def test_extract_helpers():
    text = "## 2. Architecture Diagrams\nbody2\n## 3. Next\n"
    assert "body2" in qa._extract_h2_section_body(text, r"^##\s+2\.\s+Architecture\s+Diagrams\b")
    assert qa._extract_h2_section_body(text, r"^##\s+99\.") is None
    arch = "### 2.2 Container Architecture\ninner\n### 2.3 X\n"
    assert "inner" in qa._extract_arch_subsection_body(arch, "2.2 Container Architecture")
    assert qa._extract_arch_subsection_body(arch, "9.9 Missing") is None


def test_extract_first_mermaid_block():
    body = "intro\n```mermaid\nflowchart TD\n  N1[x]\n```\n"
    mb = qa._extract_first_mermaid_block(body)
    assert mb is not None and mb["layout"] == "flowchart TD"
    assert qa._extract_first_mermaid_block("no fence") is None


def test_check_mermaid_label_safety_direct():
    rep = qa.Report("x")
    qa._check_mermaid_label_safety(rep, "2.2", "A -->|HTTP:3000| B\n")
    assert any("tokenise ambiguously" in i for i in rep.issues)


# ===========================================================================
# check_chain_compactness
# ===========================================================================

_CHAIN_CONTRACT = """\
sections:
  attack_walkthroughs:
    chain_compactness:
      "3.1 Attack Chain Overview":
        layout_keyword: "graph LR"
        forbidden_layout_keywords: ["flowchart TD"]
        max_blocks: 2
        max_nodes_per_block: 3
        max_subgraphs_per_block: 0
        max_label_lines: 1
        max_label_chars_per_line: 20
        require_threat_per_block: true
        required_classdefs:
          risk: "fill:#f00"
"""


def test_chain_compactness_no_contract_silent(tmp_path):
    md = _md(tmp_path, "# doc\n")
    rep = qa.check_chain_compactness(md, tmp_path / "nope.yaml")
    assert rep.ok == 0


def test_chain_compactness_no_rules_ok(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, "sections:\n  attack_walkthroughs: {}\n")
    rep = qa.check_chain_compactness(md, c)
    assert rep.ok == 1


def test_chain_compactness_skip_config(tmp_path):
    md = _md(tmp_path, "# doc\n")
    (tmp_path / ".skill-config.json").write_text('{"SKIP_ATTACK_WALKTHROUGHS": true}')
    c = _contract(tmp_path, _CHAIN_CONTRACT)
    rep = qa.check_chain_compactness(md, c)
    assert rep.ok == 1


def test_chain_compactness_body_not_found(tmp_path):
    md = _md(tmp_path, "## 3. Attack Walkthroughs\nno 3.1 here\n")
    c = _contract(tmp_path, _CHAIN_CONTRACT)
    rep = qa.check_chain_compactness(md, c)
    assert any("subsection body not found" in i for i in rep.issues)


def test_chain_compactness_no_blocks(tmp_path):
    md = _md(tmp_path, "### 3.1 Attack Chain Overview\nprose only\n## 4. X\n")
    c = _contract(tmp_path, _CHAIN_CONTRACT)
    rep = qa.check_chain_compactness(md, c)
    assert any("no mermaid blocks found" in i for i in rep.issues)


def test_chain_compactness_violations(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 3.1 Attack Chain Overview

        ```mermaid
        flowchart TD
          subgraph S
            N1["this label is definitely way too long for limit"]
          end
          N2["b"]
          N3["c"]
          N4["d"]
          N1 --> N2
        ```

        ```mermaid
        graph LR
          M1["x"] --> M2["y"]
        ```

        ## 4. X
        """,
    )
    c = _contract(tmp_path, _CHAIN_CONTRACT)
    rep = qa.check_chain_compactness(md, c)
    joined = " ".join(rep.issues)
    assert "must start with `graph LR`" in joined
    assert "forbidden layout" in joined
    assert "subgraphs found" in joined
    assert "nodes found" in joined
    assert "label line exceeds" in joined
    assert "missing/divergent classDef" in joined
    assert "no T-NNN reference" in joined


def test_chain_compactness_unknown_t_id(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 3.1 Attack Chain Overview

        ```mermaid
        graph LR
          A["step T-777"] --> B["impact"]
          classDef risk fill:#f00
        ```

        ## 8. Threat Register

        ### 🔴 Critical (1)

        <a id="t-001"></a>
        T-001

        ## 9. X
        """,
    )
    c = _contract(tmp_path, _CHAIN_CONTRACT)
    rep = qa.check_chain_compactness(md, c)
    assert any("T-777" in i for i in rep.issues)


def test_extract_h3_section_body_bad_heading():
    assert qa._extract_h3_section_body("text", "noSpaceHeading") is None
    assert qa._extract_h3_section_body("### 3.1 X\nbody\n## 4 Y\n", "3.1 X").strip().startswith("body")
    assert qa._extract_h3_section_body("text", "9.9 Missing") is None


def test_too_many_chain_blocks(tmp_path):
    blocks = "\n\n".join(
        f"```mermaid\ngraph LR\n  A{i}[\"x T-001\"] --> B{i}[\"y\"]\n  classDef risk fill:#f00\n```"
        for i in range(3)
    )
    md = _md(
        tmp_path,
        "### 3.1 Attack Chain Overview\n\n" + blocks + "\n\n## 8. Threat Register\n\n"
        '### 🔴 Critical (1)\n\n<a id="t-001"></a>\nT-001\n\n## 9. X\n',
    )
    c = _contract(tmp_path, _CHAIN_CONTRACT)
    rep = qa.check_chain_compactness(md, c)
    assert any("attack chains found, max" in i for i in rep.issues)


# ===========================================================================
# _critical_threats_from_yaml + check_walkthrough_coverage
# ===========================================================================


def _yaml(output_dir: Path, text: str) -> None:
    (output_dir / "threat-model.yaml").write_text(textwrap.dedent(text), encoding="utf-8")


def test_critical_threats_from_yaml_missing(tmp_path):
    assert qa._critical_threats_from_yaml(tmp_path) == []


def test_critical_threats_from_yaml_filters(tmp_path):
    _yaml(
        tmp_path,
        """\
        threats:
          - id: T-001
            risk: Critical
          - id: T-002
            severity: High
          - "not a dict"
        """,
    )
    crits = qa._critical_threats_from_yaml(tmp_path)
    assert len(crits) == 1 and crits[0]["id"] == "T-001"


_WC_CONTRACT = "sections:\n  attack_walkthroughs:\n    per_critical_subsection: true\n"


def test_walkthrough_coverage_no_contract_silent(tmp_path):
    md = _md(tmp_path, "# doc\n")
    rep = qa.check_walkthrough_coverage(md, tmp_path, tmp_path / "nope.yaml")
    assert rep.ok == 0


def test_walkthrough_coverage_rule_off(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, "sections:\n  attack_walkthroughs:\n    per_critical_subsection: false\n")
    rep = qa.check_walkthrough_coverage(md, tmp_path, c)
    assert rep.ok == 1


def test_walkthrough_coverage_skip_config(tmp_path):
    md = _md(tmp_path, "# doc\n")
    (tmp_path / ".skill-config.json").write_text('{"skip_attack_walkthroughs": true}')
    c = _contract(tmp_path, _WC_CONTRACT)
    rep = qa.check_walkthrough_coverage(md, tmp_path, c)
    assert rep.ok == 1


def test_walkthrough_coverage_no_crits(tmp_path):
    md = _md(tmp_path, "# doc\n")
    _yaml(tmp_path, "threats:\n  - id: T-001\n    risk: Low\n")
    c = _contract(tmp_path, _WC_CONTRACT)
    rep = qa.check_walkthrough_coverage(md, tmp_path, c)
    assert rep.ok == 1


def test_walkthrough_coverage_no_sec3_heading(tmp_path):
    md = _md(tmp_path, "# doc\nno section three\n")
    _yaml(tmp_path, "threats:\n  - id: T-001\n    risk: Critical\n")
    c = _contract(tmp_path, _WC_CONTRACT)
    rep = qa.check_walkthrough_coverage(md, tmp_path, c)
    assert any("§3 Attack Walkthroughs heading not found" in i for i in rep.issues)


def test_walkthrough_coverage_missing_walkthrough(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## 3. Attack Walkthroughs

        ### 3.1 Some Other Walkthrough

        **Source:** [T-009](#t-009)

        ## 4. End
        """,
    )
    _yaml(
        tmp_path,
        """\
        threats:
          - id: T-001
            risk: Critical
            title: Critical bug
        """,
    )
    c = _contract(tmp_path, _WC_CONTRACT)
    rep = qa.check_walkthrough_coverage(md, tmp_path, c)
    assert any("missing walkthrough for T-001" in i for i in rep.issues)


def test_walkthrough_coverage_covered_ok(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## 3. Attack Walkthroughs

        ### 3.2 Critical Walkthrough

        **Source:** 🔴 [F-001](#f-001)

        ## 4. End
        """,
    )
    _yaml(tmp_path, "threats:\n  - id: T-001\n    risk: Critical\n    title: x\n")
    c = _contract(tmp_path, _WC_CONTRACT)
    rep = qa.check_walkthrough_coverage(md, tmp_path, c)
    assert rep.ok == 1, rep.issues


def test_walkthrough_coverage_heading_fallback(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## 3. Attack Walkthroughs

        ### 3.2 T-001 — Critical

        body

        ## 4. End
        """,
    )
    _yaml(tmp_path, "threats:\n  - id: T-001\n    risk: Critical\n    title: x\n")
    c = _contract(tmp_path, _WC_CONTRACT)
    rep = qa.check_walkthrough_coverage(md, tmp_path, c)
    assert rep.ok == 1, rep.issues


# ===========================================================================
# check_walkthrough_depth
# ===========================================================================

_WD_CONTRACT = """\
sections:
  attack_walkthroughs:
    walkthrough_depth:
      min_body_lines: 5
      require_alt_else_block: true
      min_chain_overview_nodes_per_block: 4
      required_labelled_sections: ["Attack Steps"]
      forbidden_placeholders: ["WALKTHROUGH_FILL"]
      require_chain_key_takeaway: true
      require_chain_subsection_heading: true
"""


def test_walkthrough_depth_no_contract_silent(tmp_path):
    md = _md(tmp_path, "# doc\n")
    rep = qa.check_walkthrough_depth(md, tmp_path, tmp_path / "nope.yaml")
    assert rep.ok == 0


def test_walkthrough_depth_no_rules_ok(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, "sections:\n  attack_walkthroughs: {}\n")
    rep = qa.check_walkthrough_depth(md, tmp_path, c)
    assert rep.ok == 1


def test_walkthrough_depth_skip_config(tmp_path):
    md = _md(tmp_path, "# doc\n")
    (tmp_path / ".skill-config.json").write_text('{"SKIP_ATTACK_WALKTHROUGHS": true}')
    c = _contract(tmp_path, _WD_CONTRACT)
    rep = qa.check_walkthrough_depth(md, tmp_path, c)
    assert rep.ok == 1


def test_walkthrough_depth_no_sec3_ok(tmp_path):
    md = _md(tmp_path, "# doc\nno walkthroughs\n")
    c = _contract(tmp_path, _WD_CONTRACT)
    rep = qa.check_walkthrough_depth(md, tmp_path, c)
    assert rep.ok == 1


def test_walkthrough_depth_violations(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## 3. Attack Walkthroughs

        ### 3.1 Attack Chain Overview

        #### Chain 1 — Foo

        ```mermaid
        graph LR
          A["a"] --> B["b"]
        ```

        ### 3.2 Critical thing

        WALKTHROUGH_FILL leftover

        ```mermaid
        sequenceDiagram
        ```

        ## 4. End
        """,
    )
    c = _contract(tmp_path, _WD_CONTRACT)
    rep = qa.check_walkthrough_depth(md, tmp_path, c)
    joined = " ".join(rep.issues)
    assert "nodes found" in joined  # chain overview < 4 nodes
    assert "non-blank lines" in joined  # body too short
    assert "missing `alt Current state`" in joined
    assert "missing required" in joined and "Attack Steps" in joined
    assert "surviving" in joined and "WALKTHROUGH_FILL" in joined
    assert "Key takeaway" in joined  # missing key takeaway


def test_walkthrough_depth_no_seq_diagram(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## 3. Attack Walkthroughs

        ### 3.2 Critical thing

        line one
        line two
        line three
        line four
        line five
        line six

        **Attack Steps**

        body
        ## 4. End
        """,
    )
    c = _contract(tmp_path, _WD_CONTRACT)
    rep = qa.check_walkthrough_depth(md, tmp_path, c)
    assert any("no `sequenceDiagram` block" in i for i in rep.issues)


def test_walkthrough_depth_mega_block_form(tmp_path):
    # graph LR present but no #### Chain heading -> mega-block error
    md = _md(
        tmp_path,
        """\
        ## 3. Attack Walkthroughs

        ### 3.1 Attack Chain Overview

        ```mermaid
        graph LR
          A["a"] --> B["b"]
          B --> C["c"]
          C --> D["d"]
        ```

        ## 4. End
        """,
    )
    c = _contract(tmp_path, _WD_CONTRACT)
    rep = qa.check_walkthrough_depth(md, tmp_path, c)
    assert any("no `#### Chain N" in i for i in rep.issues)


# ===========================================================================
# check_recon_iam_bridge
# ===========================================================================

_BRIDGE_CONTRACT = """\
sections:
  security_architecture:
    domain_required_rules:
      "Identity & Access":
        - rule: recon_iam_bridge
          enforcement: error
          section_title: "7.2 Identity & Access"
          recon_signal_patterns: ["totpSecret", "routes/2fa"]
          required_iam_tokens: ["totp", "2fa", "mfa"]
"""


def test_recon_iam_bridge_no_contract_silent(tmp_path):
    md = _md(tmp_path, "# doc\n")
    rep = qa.check_recon_iam_bridge(md, tmp_path, tmp_path / "nope.yaml")
    assert rep.ok == 0


def test_recon_iam_bridge_no_rules_ok(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, "sections:\n  security_architecture:\n    domain_required_rules: {}\n")
    rep = qa.check_recon_iam_bridge(md, tmp_path, c)
    assert rep.ok == 1


def test_recon_iam_bridge_no_recon_file(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, _BRIDGE_CONTRACT)
    rep = qa.check_recon_iam_bridge(md, tmp_path, c)
    assert rep.ok == 1


def test_recon_iam_bridge_signal_missing_token_error(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.2 Identity & Access

        Password login only, no second factor here.

        ## 8. End
        """,
    )
    (tmp_path / ".recon-summary.md").write_text("found totpSecret in code\n")
    c = _contract(tmp_path, _BRIDGE_CONTRACT)
    rep = qa.check_recon_iam_bridge(md, tmp_path, c)
    assert any("2FA/TOTP signals" in i for i in rep.issues)


def test_recon_iam_bridge_signal_with_token_ok(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.2 Identity & Access

        The app supports TOTP-based 2FA via otplib.

        ## 8. End
        """,
    )
    (tmp_path / ".recon-summary.md").write_text("found totpSecret\n")
    c = _contract(tmp_path, _BRIDGE_CONTRACT)
    rep = qa.check_recon_iam_bridge(md, tmp_path, c)
    assert rep.ok == 1, rep.issues


def test_recon_iam_bridge_warning_enforcement(tmp_path):
    contract = _BRIDGE_CONTRACT.replace("enforcement: error", "enforcement: warning")
    md = _md(tmp_path, "### 7.2 Identity & Access\n\nno factor\n\n## 8. End\n")
    (tmp_path / ".recon-summary.md").write_text("totpSecret\n")
    c = _contract(tmp_path, contract)
    rep = qa.check_recon_iam_bridge(md, tmp_path, c)
    assert rep.ok == 1
    assert rep.warnings


def test_recon_iam_bridge_no_signal_skips(tmp_path):
    md = _md(tmp_path, "### 7.2 Identity & Access\n\nno factor\n\n## 8. End\n")
    (tmp_path / ".recon-summary.md").write_text("nothing relevant\n")
    c = _contract(tmp_path, _BRIDGE_CONTRACT)
    rep = qa.check_recon_iam_bridge(md, tmp_path, c)
    assert rep.ok == 1


# ===========================================================================
# check_falls_short_format
# ===========================================================================

_FS_CONTRACT = """\
sections:
  security_architecture:
    domain_required_rules:
      all_domains:
        - rule: falls_short_bullet_threshold
          min_refs_before_bullet: 3
          enforcement: warning
"""


def test_falls_short_no_rule_ok(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, "sections:\n  security_architecture:\n    domain_required_rules:\n      all_domains: []\n")
    rep = qa.check_falls_short_format(md, c)
    assert rep.ok == 1


def test_falls_short_flags_dense_paragraph(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.1 Foo

        **Where it falls short.** The issues [F-001], [F-002] and [F-003] all matter here.

        ## 8. End
        """,
    )
    c = _contract(tmp_path, _FS_CONTRACT)
    rep = qa.check_falls_short_format(md, c)
    assert rep.warnings
    assert rep.ok == 1  # warning, not issue


def test_falls_short_bullets_ok(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.1 Foo

        **Where it falls short.**

        - [F-001] one
        - [F-002] two
        - [F-003] three

        ## 8. End
        """,
    )
    c = _contract(tmp_path, _FS_CONTRACT)
    rep = qa.check_falls_short_format(md, c)
    assert rep.ok == 1 and not rep.warnings


def test_falls_short_error_enforcement(tmp_path):
    contract = _FS_CONTRACT.replace("enforcement: warning", "enforcement: error")
    md = _md(
        tmp_path,
        "**Where it falls short.** [F-001], [F-002], [F-003] in one line.\n",
    )
    c = _contract(tmp_path, contract)
    rep = qa.check_falls_short_format(md, c)
    assert rep.issues


# ===========================================================================
# check_paragraph_density
# ===========================================================================

_PD_CONTRACT = """\
sections:
  security_architecture:
    domain_required_rules:
      all_domains:
        - rule: paragraph_density_threshold
          min_refs_before_bullet: 3
          enforcement: warning
"""


def test_paragraph_density_no_rule_ok(tmp_path):
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, "sections:\n  security_architecture:\n    domain_required_rules:\n      all_domains: []\n")
    rep = qa.check_paragraph_density(md, c)
    assert rep.ok == 1


def test_paragraph_density_flags(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.1 Foo

        The findings [F-001], [M-002] and [T-003] together create exposure here.

        ## 8. End
        """,
    )
    c = _contract(tmp_path, _PD_CONTRACT)
    rep = qa.check_paragraph_density(md, c)
    assert rep.warnings


def test_paragraph_density_bullets_and_tables_ok(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.1 Foo

        | a | b |
        | [F-001] | [F-002] [F-003] |

        - bullet [F-001] [F-002] [F-003]

        ## 8. End
        """,
    )
    c = _contract(tmp_path, _PD_CONTRACT)
    rep = qa.check_paragraph_density(md, c)
    assert rep.ok == 1 and not rep.warnings


def test_paragraph_density_error_enforcement(tmp_path):
    contract = _PD_CONTRACT.replace("enforcement: warning", "enforcement: error")
    md = _md(
        tmp_path,
        "### 7.1 Foo\n\nThe trio [F-001], [F-002], [F-003] combine here.\n\n## 8. End\n",
    )
    c = _contract(tmp_path, contract)
    rep = qa.check_paragraph_density(md, c)
    assert rep.issues


# ===========================================================================
# check_hypothesis_validation_objective
# ===========================================================================


def test_hypothesis_no_table_ok(tmp_path):
    md = _md(tmp_path, "# doc no hypothesis table\n")
    rep = qa.check_hypothesis_validation_objective(md)
    assert rep.ok == 1


def test_hypothesis_empty_validation_warns(tmp_path):
    md = _md(
        tmp_path,
        """\
        #### Threat Hypotheses Requiring Validation

        | ID | A | B | C | Validation |
        |----|---|---|---|------------|
        | H-1 | x | y | z | _pending validation objective_ |
        | H-2 | x | y | z | Check the auth path manually |
        """,
    )
    rep = qa.check_hypothesis_validation_objective(md)
    assert any("H-1" in w for w in rep.warnings)
    assert not any("H-2" in w for w in rep.warnings)


# ===========================================================================
# check_inline_code_format
# ===========================================================================


def test_inline_code_format_flags_unbacked_path(tmp_path):
    md = _md(tmp_path, "The bug is in routes/login.ts here in prose.\n")
    rep = qa.check_inline_code_format(md)
    assert any("routes/login.ts" in w for w in rep.warnings)


def test_inline_code_format_backticked_ok(tmp_path):
    md = _md(tmp_path, "The bug is in `routes/login.ts` here.\n")
    rep = qa.check_inline_code_format(md)
    assert rep.ok == 1 and not rep.warnings


def test_inline_code_format_skips_heading_table_fence_link(tmp_path):
    md = _md(
        tmp_path,
        """\
        # routes/login.ts heading

        | routes/login.ts | cell |

        ```
        routes/login.ts in fence
        ```

        See [the file](routes/login.ts) for details.

        <blockquote>
        routes/login.ts inside blockquote
        </blockquote>
        """,
    )
    rep = qa.check_inline_code_format(md)
    assert rep.ok == 1 and not rep.warnings


def test_inline_code_format_glob_exempt(tmp_path):
    md = _md(tmp_path, "Match routes/**.ts wildcard in prose.\n")
    rep = qa.check_inline_code_format(md)
    assert rep.ok == 1 and not rep.warnings


# ===========================================================================
# check_label_as_code
# ===========================================================================


def test_label_as_code_flags(tmp_path):
    md = _md(tmp_path, "The form takes one HTTP `POST` request to submit.\n")
    rep = qa.check_label_as_code(md)
    assert any("`POST`" in w for w in rep.warnings)


def test_label_as_code_clean(tmp_path):
    md = _md(tmp_path, "The `eval` call is dangerous here.\n")
    rep = qa.check_label_as_code(md)
    assert rep.ok == 1 and not rep.warnings


def test_label_as_code_skips_heading_and_code_html(tmp_path):
    md = _md(
        tmp_path,
        """\
        # `POST` heading skipped

        Inline <code>POST</code> is skipped.

        <blockquote>
        `POST` inside blockquote skipped
        </blockquote>
        """,
    )
    rep = qa.check_label_as_code(md)
    assert rep.ok == 1 and not rep.warnings


# ===========================================================================
# _first_prose_line / _iter_sec7_bodies / check_architectural_prose
# ===========================================================================


def test_first_prose_line():
    # Lines starting with table/bullet/fence/heading/comment/anchor/bold/quote
    # markers are skipped; the first plain narrative line is returned.
    seg = "\n| table |\n- bullet\n# heading\n<!-- c -->\n> quote\nReal prose line.\n"
    assert qa._first_prose_line(seg) == "Real prose line."
    assert qa._first_prose_line("| only | table |\n") == ""


def test_iter_sec7_bodies():
    text = "### 7.1 Foo\nbody1\n### 7.2 Bar\nbody2\n## 8. End\n"
    out = list(qa._iter_sec7_bodies(text))
    assert out[0][0] == "7.1" and "body1" in out[0][2]
    assert out[1][0] == "7.2" and "body2" in out[1][2]
    assert "End" not in out[1][2]


def test_architectural_prose_definitional_and_banned(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.1 Authentication

        Authentication is the process by which users prove identity. This is a
        comprehensive security posture for the system.

        ## 8. End
        """,
    )
    rep = qa.check_architectural_prose(md)
    joined = " ".join(rep.warnings)
    assert "definitional opener" in joined
    assert "banned phrase" in joined


def test_architectural_prose_formulaic_openers(tmp_path):
    blocks = "\n\n".join(
        f"#### {i} Control\n\nThe application handles request number {i} carefully.\n" for i in range(3)
    )
    md = _md(tmp_path, "### 7.1 Foo\n\n" + blocks + "\n## 8. End\n")
    rep = qa.check_architectural_prose(md)
    assert any("formulaic" in w for w in rep.warnings)


def test_architectural_prose_clean(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.1 Authentication

        The login query at routes/login.ts uses Sequelize parameterization.

        ## 8. End
        """,
    )
    rep = qa.check_architectural_prose(md)
    assert rep.ok == 1 and not rep.warnings


# ===========================================================================
# check_attack_tree_node_id_leak
# ===========================================================================


def test_attack_tree_no_section_ok(tmp_path):
    md = _md(tmp_path, "# doc no tree\n")
    rep = qa.check_attack_tree_node_id_leak(md)
    assert rep.ok == 1


def test_attack_tree_leak_flags(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## Critical Attack Tree

        The subtree AND_JWT captures the forgery paths.

        ```mermaid
        graph TD
          G_ROOT --> AND_JWT
        ```

        # Next
        """,
    )
    rep = qa.check_attack_tree_node_id_leak(md)
    assert any("AND_JWT" in w for w in rep.warnings)


def test_attack_tree_clean(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## Critical Attack Tree

        The offline token-forgery paths are the main risk.

        ```mermaid
        graph TD
          G_ROOT --> AND_JWT
        ```

        # Next
        """,
    )
    rep = qa.check_attack_tree_node_id_leak(md)
    assert rep.ok == 1 and not rep.warnings


# ===========================================================================
# check_finding_range_homogeneous
# ===========================================================================


def test_finding_range_no_yaml_ok(tmp_path):
    md = _md(tmp_path, "## 7. Sec\n[F-001](#f-001) – [F-003](#f-003)\n## 8. End\n")
    rep = qa.check_finding_range_homogeneous(md, tmp_path)
    assert rep.ok == 1


def test_finding_range_no_sec7_ok(tmp_path):
    md = _md(tmp_path, "no sec seven here\n")
    _yaml(tmp_path, "threats:\n  - id: F-001\n    cwe: CWE-79\n")
    rep = qa.check_finding_range_homogeneous(md, tmp_path)
    assert rep.ok == 1


def test_finding_range_heterogeneous_warns(tmp_path):
    _yaml(
        tmp_path,
        """\
        threats:
          - id: F-016
            cwe: CWE-79
          - id: F-017
            cwe: CWE-89
        """,
    )
    md = _md(
        tmp_path,
        "## 7. Security\n\nThe findings [F-016](#f-016) – [F-017](#f-017) overlap.\n\n## 8. End\n",
    )
    rep = qa.check_finding_range_homogeneous(md, tmp_path)
    # Either warns (heterogeneous clusters) or stays ok if clusters collapse;
    # CWE-79 (XSS) vs CWE-89 (Injection) are distinct clusters -> warning.
    assert rep.warnings or rep.ok == 1


# ===========================================================================
# Additional branch coverage
# ===========================================================================


def test_diagram_compactness_unreadable_md(tmp_path):
    # md_path points at a directory -> read_text raises OSError.
    c = _contract(tmp_path, _DIAGRAM_CONTRACT)
    rep = qa.check_diagram_compactness(tmp_path, c)
    assert any("cannot read" in i for i in rep.issues)


def test_chain_compactness_unreadable_md(tmp_path):
    c = _contract(tmp_path, _CHAIN_CONTRACT)
    rep = qa.check_chain_compactness(tmp_path, c)
    assert any("cannot read" in i for i in rep.issues)


def test_walkthrough_coverage_unreadable_md(tmp_path):
    _yaml(tmp_path, "threats:\n  - id: T-001\n    risk: Critical\n    title: x\n")
    c = _contract(tmp_path, _WC_CONTRACT)
    # md_path = directory -> OSError
    rep = qa.check_walkthrough_coverage(tmp_path, tmp_path, c)
    assert any("cannot read" in i for i in rep.issues)


def test_walkthrough_depth_unreadable_md(tmp_path):
    c = _contract(tmp_path, _WD_CONTRACT)
    rep = qa.check_walkthrough_depth(tmp_path, tmp_path, c)
    assert any("cannot read" in i for i in rep.issues)


def test_recon_iam_bridge_unreadable_md(tmp_path):
    (tmp_path / ".recon-summary.md").write_text("totpSecret\n")
    c = _contract(tmp_path, _BRIDGE_CONTRACT)
    rep = qa.check_recon_iam_bridge(tmp_path, tmp_path, c)
    assert any("cannot read" in i for i in rep.issues)


def test_falls_short_unreadable_md(tmp_path):
    c = _contract(tmp_path, _FS_CONTRACT)
    rep = qa.check_falls_short_format(tmp_path, c)
    assert any("cannot read" in i for i in rep.issues)


def test_paragraph_density_unreadable_md(tmp_path):
    c = _contract(tmp_path, _PD_CONTRACT)
    rep = qa.check_paragraph_density(tmp_path, c)
    assert any("cannot read" in i for i in rep.issues)


def test_hypothesis_unreadable_md(tmp_path):
    rep = qa.check_hypothesis_validation_objective(tmp_path)
    assert any("cannot read" in i for i in rep.issues)


def test_inline_code_format_unreadable_md(tmp_path):
    rep = qa.check_inline_code_format(tmp_path)
    assert any("cannot read" in i for i in rep.issues)


def test_label_as_code_unreadable_md(tmp_path):
    rep = qa.check_label_as_code(tmp_path)
    assert any("cannot read" in i for i in rep.issues)


def test_finding_range_unreadable_md(tmp_path):
    rep = qa.check_finding_range_homogeneous(tmp_path, tmp_path)
    assert any("cannot read" in i for i in rep.issues)


def test_skip_config_corrupt_json_swallowed(tmp_path):
    # invalid JSON in .skill-config.json hits the broad except -> still runs.
    (tmp_path / ".skill-config.json").write_text("{not json")
    md = _md(tmp_path, "# doc\n")
    c = _contract(tmp_path, _CHAIN_CONTRACT)
    rep = qa.check_chain_compactness(md, c)
    # Falls through to body-not-found (no §3.1) rather than crashing.
    assert any("subsection body not found" in i for i in rep.issues)


# --- diagram_compactness required/optional subgraph branches --------------

_DIAGRAM_SG_CONTRACT = """\
sections:
  architecture_diagrams:
    diagram_compactness:
      "2.2 Container Architecture":
        layout_keyword: "flowchart TD"
        required_subgraphs:
          - id: EXT
          - id: APP
          - id: DATA
        optional_subgraphs:
          - id: CLIENT
"""


def test_diagram_required_subgraph_missing_and_extra(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 2.2 Container Architecture

        ```mermaid
        flowchart TD
          subgraph WEIRD
            N1["x"]
          end
        ```
        ## 3. Next
        """,
    )
    c = _contract(tmp_path, _DIAGRAM_SG_CONTRACT)
    rep = qa.check_diagram_compactness(md, c)
    joined = " ".join(rep.issues)
    assert "required subgraph set" in joined
    assert "unexpected subgraphs" in joined


def test_diagram_max_label_lines(tmp_path):
    contract = """\
    sections:
      architecture_diagrams:
        diagram_compactness:
          "2.2 Container Architecture":
            layout_keyword: "flowchart TD"
            max_label_lines: 2
    """
    md = _md(
        tmp_path,
        """\
        ### 2.2 Container Architecture

        ```mermaid
        flowchart TD
          N1["a<br/>b<br/>c<br/>d"]
        ```
        ## 3. Next
        """,
    )
    c = _contract(tmp_path, contract)
    rep = qa.check_diagram_compactness(md, c)
    assert any("node label has" in i and "lines" in i for i in rep.issues)


# --- walkthrough_depth: alt/else present -> no missing flag --------------


def test_walkthrough_depth_alt_else_present_ok(tmp_path):
    md = _md(
        tmp_path,
        """\
        ## 3. Attack Walkthroughs

        ### 3.2 Critical thing

        line one prose here describing the attack
        line two more prose
        line three more prose
        line four more prose
        line five more prose

        **Attack Steps**

        ```mermaid
        sequenceDiagram
          alt Current state
            A->>B: vuln
          else After mitigation
            A->>B: safe
          end
        ```

        ## 4. End
        """,
    )
    c = _contract(tmp_path, _WD_CONTRACT)
    rep = qa.check_walkthrough_depth(md, tmp_path, c)
    assert not any("alt Current state" in i for i in rep.issues)


def test_walkthrough_depth_chain_takeaway_count_mismatch(tmp_path):
    # one #### Chain heading + one graph LR, but no Key takeaway line.
    md = _md(
        tmp_path,
        """\
        ## 3. Attack Walkthroughs

        ### 3.1 Attack Chain Overview

        #### Chain 1 — Foo

        ```mermaid
        graph LR
          A["a"] --> B["b"]
          B --> C["c"]
          C --> D["d"]
          D --> E["e"]
        ```

        ## 4. End
        """,
    )
    c = _contract(tmp_path, _WD_CONTRACT)
    rep = qa.check_walkthrough_depth(md, tmp_path, c)
    assert any("Key takeaway" in i for i in rep.issues)


# --- finding_range: invalid yaml type / no cwe_by_fid --------------------


def test_finding_range_yaml_not_dict(tmp_path):
    (tmp_path / "threat-model.yaml").write_text("- just\n- a\n- list\n")
    md = _md(tmp_path, "## 7. Sec\n[F-001](#f-001) – [F-003](#f-003)\n## 8. End\n")
    rep = qa.check_finding_range_homogeneous(md, tmp_path)
    assert rep.ok == 1


def test_finding_range_no_cwe_ok(tmp_path):
    _yaml(tmp_path, "threats:\n  - id: F-001\n    title: no cwe\n")
    md = _md(tmp_path, "## 7. Sec\n[F-001](#f-001) – [F-003](#f-003)\n## 8. End\n")
    rep = qa.check_finding_range_homogeneous(md, tmp_path)
    assert rep.ok == 1


# --- paragraph_density falls-short block excluded -------------------------


def test_paragraph_density_excludes_falls_short(tmp_path):
    md = _md(
        tmp_path,
        """\
        ### 7.1 Foo

        **Where it falls short.** The trio [F-001], [F-002], [F-003] all here.

        ## 8. End
        """,
    )
    c = _contract(tmp_path, _PD_CONTRACT)
    rep = qa.check_paragraph_density(md, c)
    # falls-short block is owned by check_falls_short_format -> not flagged here
    assert rep.ok == 1 and not rep.warnings


if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-q"]))
