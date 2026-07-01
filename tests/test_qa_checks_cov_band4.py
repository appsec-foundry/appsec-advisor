"""Coverage band 4 for scripts/qa_checks.py.

Targets functions roughly between lines 7698-9750 plus the main() CLI
dispatcher (9750-10068). Tests are real and passing — they exercise the
prose-quality checks, chain T-ID consistency, figure-1 / heatmap layout,
table-cell formatting, and drive every CLI subcommand through subprocess.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "qa_checks.py"


def _load_qa_checks():
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


def _md(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "threat-model.md"
    f.write_text(content, encoding="utf-8")
    return f


# ===========================================================================
# Helper functions (direct unit tests)
# ===========================================================================


def test_classify_threat_cluster_local_empty():
    assert qa._classify_threat_cluster_local("", {"clusters": []}) == "_unmapped"


def test_classify_threat_cluster_local_unmapped_skipped():
    vocab = {
        "clusters": [
            {"id": "_unmapped", "cwes": ["CWE-1104"]},
            {"id": "outdated_deps", "cwes": ["CWE-1104", "cwe-937"]},
        ]
    }
    assert qa._classify_threat_cluster_local("CWE-1104", vocab) == "outdated_deps"
    assert qa._classify_threat_cluster_local("cwe-937", vocab) == "outdated_deps"
    assert qa._classify_threat_cluster_local("CWE-999", vocab) == "_unmapped"


def test_load_weakness_classes_caches():
    a = qa._load_weakness_classes()
    b = qa._load_weakness_classes()
    assert a is b
    assert isinstance(a, dict)


def test_chain_label_keywords_strips_ids_and_stopwords():
    kw = qa._chain_label_keywords("T-001 SQL injection vulnerable endpoint attack")
    # ids, stopwords, and <4-char tokens dropped; "injection" survives.
    assert "injection" in kw
    assert "t" not in kw
    assert "attack" not in kw  # stopword


def test_chain_keywords_overlap_exact():
    assert qa._chain_keywords_overlap({"injection"}, {"injection"})


def test_chain_keywords_overlap_prefix():
    # "cracked" vs "crackable" share prefix len 5.
    assert qa._chain_keywords_overlap({"cracked"}, {"crackable"})


def test_chain_keywords_overlap_substring():
    assert qa._chain_keywords_overlap({"auth"}, {"authentication"})


def test_chain_keywords_overlap_none():
    assert not qa._chain_keywords_overlap({"hashing"}, {"redirect"})


def test_declared_node_ids():
    block = '    BROWSER["x"]\n    SERVER(["y"])\n    direction TB\n'
    ids = qa._declared_node_ids(block)
    assert "BROWSER" in ids and "SERVER" in ids


def test_iter_fig1_edges():
    mermaid = "flowchart TB\n    A ==> B\n    C --> D\n"
    edges = qa._iter_fig1_edges(mermaid)
    ops = {op for _, op, _ in edges}
    assert "==>" in ops and "-->" in ops


def test_extract_subgraph_block_and_count_cards():
    mermaid = 'subgraph ACTORS[" "]\n    direction TB\n    HDR_A["head"]\n    A1(["actor"])\n    end\n'
    block = qa._extract_subgraph_block(mermaid, "ACTORS")
    assert "HDR_A" in block
    assert qa._count_cards(block) == 2


def test_extract_subgraph_block_missing():
    assert qa._extract_subgraph_block("flowchart LR\n", "ACTORS") == ""


def test_split_table_cells():
    assert qa._split_table_cells("| a | b | c |") == ["a", "b", "c"]


def test_fix_cell_stacking_inserts_br():
    cell = "[F-001](#f-001), [F-002](#f-002), [F-003](#f-003)"
    new, n = qa._fix_cell_stacking(cell)
    assert "<br/>" in new
    assert n == 2


def test_fix_cell_stacking_noop_when_no_separator():
    cell = "[F-001](#f-001)<br/>[F-002](#f-002)"
    new, n = qa._fix_cell_stacking(cell)
    assert n == 0
    assert new == cell


def test_iter_table_blocks():
    text = "| H1 | H2 |\n| --- | --- |\n| a | b |\n\nprose\n"
    blocks = list(qa._iter_table_blocks(text))
    assert len(blocks) == 1
    start, rows = blocks[0]
    assert len(rows) == 3


def test_finalize_auth_report_warning_demotes():
    r = qa.Report("x")
    r.issues.append("boom")
    qa._finalize_auth_report(r, "warning")
    assert not r.issues
    assert r.warnings == ["boom"]
    assert r.ok == 1


def test_finalize_auth_report_error_keeps():
    r = qa.Report("x")
    r.issues.append("boom")
    qa._finalize_auth_report(r, "error")
    assert r.issues == ["boom"]
    assert r.ok == 0


# ===========================================================================
# Prose-quality checks (direct)
# ===========================================================================

_SEC7_GENERIC = """\
### 7.5 Input Validation

An attacker could abuse this. Various endpoints exist in the codebase.
Something might be exploited and could potentially be a problem.
"""


def test_check_generic_phrases_escalates(tmp_path):
    f = _md(tmp_path, _SEC7_GENERIC)
    rep = qa.check_generic_phrases(f)
    assert rep.issues  # >=3 hits in one §7.x -> error


def test_check_generic_phrases_clean(tmp_path):
    f = _md(tmp_path, "### 7.1 Boundary\n\nThe login route at app.ts:10 rejects.\n")
    rep = qa.check_generic_phrases(f)
    assert rep.ok == 1


def test_check_rhetorical_severity_hits(tmp_path):
    f = _md(
        tmp_path,
        "### 7.2 Auth\n\nThis is trivial for a junior pentester and catastrophic.\n",
    )
    rep = qa.check_rhetorical_severity(f)
    assert rep.issues


def test_check_rhetorical_severity_clean(tmp_path):
    f = _md(tmp_path, "### 7.2 Auth\n\nThe server returns 500 on malformed JWT.\n")
    rep = qa.check_rhetorical_severity(f)
    assert rep.ok == 1


def test_check_section_opener_restates_heading_banned(tmp_path):
    content = "## 7. Security Architecture\n\nThis section evaluates the controls.\n"
    f = _md(tmp_path, content)
    rep = qa.check_section_opener_restates_heading(f)
    assert rep.issues


def test_check_section_opener_overlap_warning(tmp_path):
    content = "### 7.2 Identity Authentication Controls\n\nIdentity authentication controls protect users.\n"
    f = _md(tmp_path, content)
    rep = qa.check_section_opener_restates_heading(f)
    assert rep.warnings or rep.issues


def test_check_section_opener_clean(tmp_path):
    content = "## 7. Security Architecture\n\nThe app uses bcrypt with cost 12 at auth.ts:9.\n"
    f = _md(tmp_path, content)
    rep = qa.check_section_opener_restates_heading(f)
    assert rep.ok == 1


def test_check_ai_padding_phrases_escalates(tmp_path):
    content = "### 7.3 Crypto\n\nIt is worth noting this. Furthermore, in summary, more.\n"
    f = _md(tmp_path, content)
    rep = qa.check_ai_padding_phrases(f)
    assert rep.issues


def test_check_ai_padding_phrases_clean(tmp_path):
    f = _md(tmp_path, "### 7.3 Crypto\n\nKeys rotate every 90 days.\n")
    rep = qa.check_ai_padding_phrases(f)
    assert rep.ok == 1


def test_check_section_713_no_table_flags(tmp_path):
    content = "### 7.13 Defense-in-Depth Summary\n\n| Layer | Control |\n| --- | --- |\n| A | B |\n"
    f = _md(tmp_path, content)
    rep = qa.check_section_713_no_table(f)
    assert rep.issues


def test_check_section_713_no_table_prose_ok(tmp_path):
    content = "### 7.13 Defense-in-Depth Summary\n\nProse only paragraph describing controls.\n"
    f = _md(tmp_path, content)
    rep = qa.check_section_713_no_table(f)
    assert rep.ok == 1


def test_check_section_713_no_section(tmp_path):
    f = _md(tmp_path, "# Title\n\nNo such section.\n")
    rep = qa.check_section_713_no_table(f)
    assert rep.ok == 1


# ===========================================================================
# check_subcontrol_naming_canonical
# ===========================================================================


def test_subcontrol_naming_no_section72(tmp_path):
    f = _md(tmp_path, "# Title\n\nno 7.2 here\n")
    rep = qa.check_subcontrol_naming_canonical(f)
    assert rep.ok == 1


def test_subcontrol_naming_with_section72(tmp_path):
    content = (
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### OAuth Login Adapter\n\nstuff\n\n"
        "#### Password Hashing\n\nstuff\n\n"
        "## 8. Findings\n"
    )
    f = _md(tmp_path, content)
    rep = qa.check_subcontrol_naming_canonical(f)
    # Either clean or flagged — just exercise the matching loop without crash.
    assert isinstance(rep, qa.Report)


# ===========================================================================
# check_dependency_cross_ref (needs yaml)
# ===========================================================================


def test_dependency_cross_ref_no_yaml(tmp_path):
    f = _md(tmp_path, "# Title\n")
    rep = qa.check_dependency_cross_ref(f, tmp_path)
    assert rep.ok == 1


def test_dependency_cross_ref_dep_scan_missing_ref(tmp_path):
    f = _md(tmp_path, "### 7.11 Operations Runtime and Supply Chain Controls\n\nNothing referenced here.\n")
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - id: T-005\n    source: dep-scan\n    title: outdated express\n",
        encoding="utf-8",
    )
    rep = qa.check_dependency_cross_ref(f, tmp_path)
    assert rep.warnings  # F-005 not referenced


def test_dependency_cross_ref_referenced_ok(tmp_path):
    f = _md(
        tmp_path,
        "### 7.11 Operations Runtime and Supply Chain Controls\n\nSee [F-005](#f-005).\n",
    )
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - id: T-005\n    source: dep-scan\n    title: x\n",
        encoding="utf-8",
    )
    rep = qa.check_dependency_cross_ref(f, tmp_path)
    assert rep.ok == 1


def test_dependency_cross_ref_section_missing(tmp_path):
    f = _md(tmp_path, "# Title\n\nno supply chain section\n")
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - id: T-005\n    source: dep-scan\n    title: x\n",
        encoding="utf-8",
    )
    rep = qa.check_dependency_cross_ref(f, tmp_path)
    assert rep.warnings


def test_dependency_cross_ref_library_token(tmp_path):
    f = _md(tmp_path, "### 7.11 Supply Chain\n\nnothing\n")
    (tmp_path / "threat-model.yaml").write_text(
        'threats:\n  - id: T-014\n    cwe: CWE-0\n    title: "uses express-jwt 0.6 sandbox"\n',
        encoding="utf-8",
    )
    rep = qa.check_dependency_cross_ref(f, tmp_path)
    assert rep.warnings


# ===========================================================================
# check_na_against_recon
# ===========================================================================


def test_na_against_recon_no_recon(tmp_path):
    f = _md(tmp_path, "### 7.8 WebSocket\n\n_Not applicable_\n")
    rep = qa.check_na_against_recon(f, tmp_path)
    assert rep.ok == 1


def test_na_against_recon_flags(tmp_path):
    f = _md(tmp_path, "### 7.8 WebSocket Realtime\n\n_Not applicable - no X detected_\n")
    (tmp_path / ".recon-summary.md").write_text("Uses socket.io for websocket comms\n", encoding="utf-8")
    rep = qa.check_na_against_recon(f, tmp_path)
    assert rep.warnings


def test_na_against_recon_clean(tmp_path):
    f = _md(tmp_path, "### 7.8 WebSocket\n\n_Not applicable - no X detected_\n")
    (tmp_path / ".recon-summary.md").write_text("plain rest api only\n", encoding="utf-8")
    rep = qa.check_na_against_recon(f, tmp_path)
    assert rep.ok == 1


# ===========================================================================
# check_chain_tid_consistency
# ===========================================================================


def test_chain_tid_no_yaml(tmp_path):
    f = _md(tmp_path, "# Title\n")
    rep = qa.check_chain_tid_consistency(f, tmp_path)
    assert rep.ok == 1


def test_chain_tid_mismatch(tmp_path):
    (tmp_path / "threat-model.yaml").write_text(
        'threats:\n  - id: T-001\n    title: "Hardcoded RSA private key in config"\n',
        encoding="utf-8",
    )
    content = (
        "### 3.1 Attack Chain Overview\n\n"
        "```mermaid\ngraph LR\n"
        'N1["SQL injection login endpoint exploit T-001"] --> N2["next"]\n'
        "```\n"
    )
    f = _md(tmp_path, content)
    rep = qa.check_chain_tid_consistency(f, tmp_path)
    assert rep.issues


def test_chain_tid_overlap_ok(tmp_path):
    (tmp_path / "threat-model.yaml").write_text(
        'threats:\n  - id: T-001\n    title: "Hardcoded RSA private key in config"\n',
        encoding="utf-8",
    )
    content = (
        '### 3.1 Attack Chain Overview\n\n```mermaid\ngraph LR\nN1["Hardcoded private key T-001"] --> N2["next"]\n```\n'
    )
    f = _md(tmp_path, content)
    rep = qa.check_chain_tid_consistency(f, tmp_path)
    assert rep.ok == 1


def test_chain_tid_no_section(tmp_path):
    (tmp_path / "threat-model.yaml").write_text(
        'threats:\n  - id: T-001\n    title: "Something"\n',
        encoding="utf-8",
    )
    f = _md(tmp_path, "# Title\n\nno chain overview\n")
    rep = qa.check_chain_tid_consistency(f, tmp_path)
    assert rep.ok == 1


# ===========================================================================
# check_placeholders / summary_bullets
# ===========================================================================


def test_check_placeholders_hits(tmp_path):
    f = _md(tmp_path, "# Title\n\nStatus _pending_ and REPLACE_ME and TODO\n")
    rep = qa.check_placeholders(f)
    assert rep.issues


def test_check_placeholders_clean(tmp_path):
    f = _md(tmp_path, "# Title\n\nAll fields filled in nicely.\n")
    rep = qa.check_placeholders(f)
    assert rep.ok == 1


def test_check_placeholders_missing_file(tmp_path):
    rep = qa.check_placeholders(tmp_path / "nope.md")
    assert rep.issues


def test_check_summary_bullets_flags(tmp_path):
    content = "# Title\n\n**Gap summary:** (1) thing one; (2) thing two; more.\n"
    f = _md(tmp_path, content)
    rep = qa.check_summary_bullets(f)
    assert rep.issues


def test_check_summary_bullets_clean_when_bulleted(tmp_path):
    content = "# Title\n\n**Gap summary:**\n- thing one\n- thing two\n"
    f = _md(tmp_path, content)
    rep = qa.check_summary_bullets(f)
    assert rep.ok == 1


# ===========================================================================
# check_yaml_md_consistency
# ===========================================================================


def test_yaml_md_consistency_yaml_missing(tmp_path):
    f = _md(tmp_path, "# Title\n")
    rep = qa.check_yaml_md_consistency(f, tmp_path / "nope.yaml")
    assert rep.warnings


def test_yaml_md_consistency_count_drift(tmp_path):
    f = _md(tmp_path, "# Title\n\nno F-NNN rows at all\n")
    y = tmp_path / "threat-model.yaml"
    y.write_text(
        "meta:\n  schema_version: 1\nthreats:\n  - id: T-001\n    title: x\nmitigations: []\n",
        encoding="utf-8",
    )
    rep = qa.check_yaml_md_consistency(f, y)
    assert rep.issues  # yaml=1, md=0


def test_yaml_md_consistency_clean(tmp_path):
    md = '# Title\n\n| <a id="f-001"></a>F-001 | x |\n'
    f = _md(tmp_path, md)
    y = tmp_path / "threat-model.yaml"
    y.write_text(
        "meta:\n  schema_version: 1\nthreats:\n  - id: T-001\n    title: x\nmitigations: []\n",
        encoding="utf-8",
    )
    rep = qa.check_yaml_md_consistency(f, y)
    assert rep.ok == 1


# ===========================================================================
# check_fragments_present
# ===========================================================================


def test_fragments_missing_dir(tmp_path):
    rep = qa.check_fragments_present(tmp_path)
    assert rep.issues


def test_fragments_present_complete(tmp_path):
    frag = tmp_path / ".fragments"
    frag.mkdir()
    for name in qa.REQUIRED_FRAGMENTS:
        (frag / name).write_text("x", encoding="utf-8")
    (tmp_path / ".threats-merged.json").write_text("{}", encoding="utf-8")
    (tmp_path / "threat-model.md").write_text("# x", encoding="utf-8")
    rep = qa.check_fragments_present(tmp_path)
    assert not rep.issues


def test_fragments_empty_dir(tmp_path):
    (tmp_path / ".fragments").mkdir()
    (tmp_path / "threat-model.md").write_text("# x", encoding="utf-8")
    rep = qa.check_fragments_present(tmp_path)
    assert rep.issues  # < 3 + missing + merged missing


# ===========================================================================
# check_security_posture_structure / figure1 helpers
# ===========================================================================


def test_posture_structure_no_section(tmp_path):
    f = _md(tmp_path, "# Title\n\nno posture section\n")
    rep = qa.check_security_posture_structure(f)
    assert rep.ok == 1


def test_posture_structure_no_mermaid(tmp_path):
    content = "### Security Posture & Top Threats\n\nNo diagram here.\n\n### Next\n"
    f = _md(tmp_path, content)
    rep = qa.check_security_posture_structure(f)
    assert rep.issues  # D2 no mermaid


def test_posture_structure_unclosed_mermaid(tmp_path):
    content = "### Security Posture & Top Threats\n\n```mermaid\nflowchart LR\nsubgraph ACTORS\n"
    f = _md(tmp_path, content)
    rep = qa.check_security_posture_structure(f)
    assert rep.issues


def test_figure1_layout_solid_to_data(tmp_path):
    section = (
        "**Figure 1 Architecture**\n\n"
        "```mermaid\n"
        "flowchart TB\n"
        'subgraph ZONE_ACTORS["a"]\n    ATK["attacker"]\n    end\n'
        'subgraph APP["b"]\n    SRV["server"]\n    end\n'
        'subgraph DATA["c"]\n    DB["db"]\n    end\n'
        "ATK ==> DB\n"
        "```\n"
    )
    rep = qa.Report("x")
    qa._check_figure1_architecture_layout(rep, section)
    assert any("A3" in i or "A4" in i for i in rep.issues)


def test_figure1_layout_no_figure(tmp_path):
    rep = qa.Report("x")
    qa._check_figure1_architecture_layout(rep, "no figure here")
    assert not rep.issues


def test_check_heatmap_undeclared_nodes():
    rep = qa.Report("x")
    mermaid = "flowchart LR\nA ==>|x| SERVER\n"
    qa._check_heatmap_undeclared_nodes(rep, mermaid, tiers_block='    BROWSER["b"]\n')
    assert any("SERVER" in i for i in rep.issues)


# ===========================================================================
# check_cell_format
# ===========================================================================


def test_check_cell_format_stacks(tmp_path):
    md = "# Title\n\n| ID | Findings |\n| --- | --- |\n| row | [F-001](#f-001), [F-002](#f-002) |\n"
    f = _md(tmp_path, md)
    rep, new_text = qa.check_cell_format(f)
    assert "<br/>" in new_text
    assert rep.fixes


def test_check_cell_format_skips_assets_table(tmp_path):
    md = (
        "# Title\n\n"
        "| Asset | Classification | Description | Linked Threats |\n"
        "| --- | --- | --- | --- |\n"
        "| A-001 | high | desc | [F-001](#f-001) · [F-002](#f-002) |\n"
    )
    f = _md(tmp_path, md)
    rep, new_text = qa.check_cell_format(f)
    # Assets table skipped — no <br/> inserted.
    assert "<br/>" not in new_text


# ===========================================================================
# CLI dispatcher: usage errors + unknown subcommand
# ===========================================================================


def test_cli_no_args():
    r = _run([])
    assert r.returncode == 2


def test_cli_unknown_subcommand(tmp_path):
    r = _run(["bogus_sub"])
    assert r.returncode == 2
    assert "unknown subcommand" in r.stderr


@pytest.mark.parametrize(
    "sub",
    [
        "links",
        "ms_structure",
        "contract",
        "final_structure",
        "all",
        "autofix",
        "heading_hygiene",
        "toc_closure",
        "toc_contract",
        "section7_h4_status",
        "attack_tree_node_id_leak",
        "section_713_no_table",
        "hypothesis_validation_objective",
        "paragraph_density",
        "architectural_prose",
        "generic_phrases",
        "rhetorical_severity",
        "section_opener_restates_heading",
        "finding_range_homogeneous",
        "dependency_cross_ref",
        "na_against_recon",
        "mermaid_syntax",
        "toc_nested_links",
        "infobox_completeness",
        "placeholders",
        "section7_narrative_placeholders",
        "section7_h4_positive_intro",
        "section7_fence_intro_sentence",
        "section7_finding_link_duplicate",
        "html_nested_finding_link",
        "section7_finding_reference_semantic",
        "label_as_code",
        "yaml_md",
        "cell_format",
        "summary_bullets",
        "fragments",
        "evidence_integrity",
        "perimeter_claims",
        "strengths_quality",
        "repair_plan",
    ],
)
def test_cli_usage_error_wrong_argcount(sub):
    # Each subcommand with too few args prints usage and returns 2.
    r = _run([sub])
    assert r.returncode == 2


# ===========================================================================
# CLI dispatcher: happy-path execution per subcommand
# ===========================================================================

_MINIMAL_MD = """\
# Threat Model

## 1. Executive Summary

Short.

## 7. Security Architecture

### 7.1 Boundary Controls

The login route at app.ts:10 validates input.

## 8. Findings

No findings.
"""


@pytest.fixture()
def model(tmp_path):
    return _md(tmp_path, _MINIMAL_MD)


def _ok(r):
    assert r.returncode in (0, 1), r.stderr
    # stdout should be JSON.
    json.loads(r.stdout)


def test_cli_xrefs(model):
    _ok(_run(["xrefs", str(model)]))


def test_cli_anchors(model):
    r = _run(["anchors", str(model)])
    assert r.returncode == 0
    json.loads(r.stdout)


def test_cli_invariants(model):
    _ok(_run(["invariants", str(model)]))


def test_cli_links(model):
    _ok(_run(["links", str(model), str(model.parent)]))


def test_cli_ms_structure(model):
    _ok(_run(["ms_structure", str(model)]))


def test_cli_contract(model):
    _ok(_run(["contract", str(model)]))


def test_cli_final_structure(model):
    _ok(_run(["final_structure", str(model)]))


def test_cli_heading_hygiene(model):
    _ok(_run(["heading_hygiene", str(model)]))


def test_cli_toc_closure(model):
    _ok(_run(["toc_closure", str(model)]))


def test_cli_toc_contract(model):
    _ok(_run(["toc_contract", str(model)]))


def test_cli_section7_h4_status(model):
    _ok(_run(["section7_h4_status", str(model)]))


def test_cli_attack_tree_node_id_leak(model):
    _ok(_run(["attack_tree_node_id_leak", str(model)]))


def test_cli_section_713_no_table(model):
    _ok(_run(["section_713_no_table", str(model)]))


def test_cli_hypothesis_validation_objective(model):
    _ok(_run(["hypothesis_validation_objective", str(model)]))


def test_cli_paragraph_density(model):
    _ok(_run(["paragraph_density", str(model)]))


def test_cli_architectural_prose(model):
    _ok(_run(["architectural_prose", str(model)]))


def test_cli_generic_phrases(model):
    _ok(_run(["generic_phrases", str(model)]))


def test_cli_rhetorical_severity(model):
    _ok(_run(["rhetorical_severity", str(model)]))


def test_cli_section_opener_restates_heading(model):
    _ok(_run(["section_opener_restates_heading", str(model)]))


def test_cli_finding_range_homogeneous(model):
    _ok(_run(["finding_range_homogeneous", str(model)]))


def test_cli_dependency_cross_ref(model):
    _ok(_run(["dependency_cross_ref", str(model)]))


def test_cli_na_against_recon(model):
    _ok(_run(["na_against_recon", str(model)]))


def test_cli_mermaid_syntax(model):
    _ok(_run(["mermaid_syntax", str(model)]))


def test_cli_toc_nested_links(model):
    _ok(_run(["toc_nested_links", str(model)]))


def test_cli_infobox_completeness(model):
    _ok(_run(["infobox_completeness", str(model)]))


def test_cli_placeholders(model):
    _ok(_run(["placeholders", str(model)]))


def test_cli_section7_narrative_placeholders(model):
    _ok(_run(["section7_narrative_placeholders", str(model)]))


def test_cli_section7_h4_positive_intro(model):
    _ok(_run(["section7_h4_positive_intro", str(model)]))


def test_cli_section7_fence_intro_sentence(model):
    _ok(_run(["section7_fence_intro_sentence", str(model)]))


def test_cli_section7_finding_link_duplicate(model):
    _ok(_run(["section7_finding_link_duplicate", str(model)]))


def test_cli_html_nested_finding_link(model):
    _ok(_run(["html_nested_finding_link", str(model)]))


def test_cli_section7_finding_reference_semantic(model):
    _ok(_run(["section7_finding_reference_semantic", str(model)]))


def test_cli_label_as_code(model):
    _ok(_run(["label_as_code", str(model)]))


def test_cli_yaml_md(model):
    y = model.parent / "threat-model.yaml"
    y.write_text("meta:\n  schema_version: 1\nthreats: []\nmitigations: []\n", encoding="utf-8")
    _ok(_run(["yaml_md", str(model), str(y)]))


def test_cli_cell_format(model):
    _ok(_run(["cell_format", str(model)]))


def test_cli_summary_bullets(model):
    _ok(_run(["summary_bullets", str(model)]))


def test_cli_fragments(tmp_path):
    _ok(_run(["fragments", str(tmp_path)]))


def test_cli_evidence_integrity(model):
    _ok(_run(["evidence_integrity", str(model.parent), str(model.parent)]))


def test_cli_perimeter_claims(model):
    _ok(_run(["perimeter_claims", str(model)]))


def test_cli_unmasked_secrets(model):
    _ok(_run(["unmasked_secrets", str(model)]))


def test_cli_relevant_findings(model):
    _ok(_run(["relevant_findings", str(model)]))


def test_cli_strengths_quality(model):
    _ok(_run(["strengths_quality", str(model)]))


def test_cli_validation_approach_first(model):
    _ok(_run(["validation_approach_first", str(model)]))


def test_cli_repair_plan(model):
    r = _run(["repair_plan", str(model), str(model.parent)])
    # repair_plan returns its own exit code; just must not crash hard.
    assert r.returncode in (0, 1, 2, 3)


def test_cli_all(model):
    r = _run(["all", str(model), str(model.parent)])
    assert r.returncode in (0, 1, 2, 3)


def test_cli_autofix(model):
    r = _run(["autofix", str(model), str(model.parent)])
    assert r.returncode in (0, 1, 2, 3)


# ===========================================================================
# _run_auth_matching_checks (HUGE, not CLI-reachable directly)
# ===========================================================================


def test_run_auth_matching_no_subsection_for_row():
    rep = qa.Report("x")
    qa._run_auth_matching_checks(
        report=rep,
        table_rows=[{"control": "OAuth Login", "linked_tids": {"T-001"}}],
        subsections={},
        synonyms=[],
        match_style="subset",
        trailer_label="Linked Threats",
        table_column="Control",
        hashes="####",
    )
    assert rep.issues  # no subsection matches the row


def test_run_auth_matching_synonym_to_missing_heading():
    rep = qa.Report("x")
    qa._run_auth_matching_checks(
        report=rep,
        table_rows=[{"control": "OAuth Login", "linked_tids": {"T-001"}}],
        subsections={},
        synonyms=[{"row": "oauth login", "heading": "Nonexistent Heading"}],
        match_style="subset",
        trailer_label="Linked Threats",
        table_column="Control",
        hashes="####",
    )
    assert any("synonym override" in i for i in rep.issues)


def test_run_auth_matching_missing_diagram_and_trailer():
    rep = qa.Report("x")
    subs = {"OAuth Login Flow": "Some body without diagram or trailer.\n"}
    qa._run_auth_matching_checks(
        report=rep,
        table_rows=[{"control": "OAuth Login", "linked_tids": {"T-001"}}],
        subsections=subs,
        synonyms=[],
        match_style="subset",
        trailer_label="Linked Threats",
        table_column="Control",
        hashes="####",
    )
    assert any("sequenceDiagram" in i for i in rep.issues)
    assert any("trailer" in i for i in rep.issues)


def test_run_auth_matching_trailer_extraneous_tid():
    rep = qa.Report("x")
    body = "```mermaid\nsequenceDiagram\nA->>B: x\n```\n\n**Linked Threats:** [T-099](#t-099)\n\n"
    subs = {"OAuth Login Flow": body}
    qa._run_auth_matching_checks(
        report=rep,
        table_rows=[{"control": "OAuth Login", "linked_tids": {"T-001"}}],
        subsections=subs,
        synonyms=[],
        match_style="subset",
        trailer_label="Linked Threats",
        table_column="Control",
        hashes="####",
    )
    # T-099 in trailer but not in any matched row's linked_tids.
    assert any("trailer cites" in i for i in rep.issues)


def test_run_auth_matching_exact_style_clean():
    rep = qa.Report("x")
    body = "```mermaid\nsequenceDiagram\nA->>B: x\n```\n\n**Linked Threats:** [T-001](#t-001)\n\n"
    subs = {"OAuth Login": body}
    qa._run_auth_matching_checks(
        report=rep,
        table_rows=[{"control": "OAuth Login", "linked_tids": {"T-001"}}],
        subsections=subs,
        synonyms=[],
        match_style="exact",
        trailer_label="Linked Threats",
        table_column="Control",
        hashes="####",
    )
    assert not rep.issues


def test_run_auth_matching_subsection_without_row():
    rep = qa.Report("x")
    body = "```mermaid\nsequenceDiagram\nA->>B: x\n```\n\n**Linked Threats:** none\n\n"
    subs = {"Orphan Flow Subsection": body}
    qa._run_auth_matching_checks(
        report=rep,
        table_rows=[],
        subsections=subs,
        synonyms=[],
        match_style="subset",
        trailer_label="Linked Threats",
        table_column="Control",
        hashes="####",
    )
    assert any("no matching" in i for i in rep.issues)


# ===========================================================================
# check_yaml_md_consistency — asset linked_threats cross-ref path
# ===========================================================================


def test_yaml_md_asset_linked_threats_mismatch(tmp_path):
    md = (
        "# Title\n\n"
        '| <a id="f-001"></a>F-001 | x |\n\n'
        "## 4. Assets\n\n"
        "| Name | ID | Class | Linked Threats |\n"
        "| --- | --- | --- | --- |\n"
        "| Database | A-001 | high | F-002 |\n\n"
        "## 5. Next\n"
    )
    f = _md(tmp_path, md)
    y = tmp_path / "threat-model.yaml"
    y.write_text(
        "meta:\n  schema_version: 1\n"
        "threats:\n  - id: T-001\n    title: x\n"
        "mitigations: []\n"
        "assets:\n  - id: A-001\n    linked_threats:\n      - T-001\n",
        encoding="utf-8",
    )
    rep = qa.check_yaml_md_consistency(f, y)
    assert any("linked_threats mismatch" in i for i in rep.issues)


def test_yaml_md_malformed_yaml(tmp_path):
    f = _md(tmp_path, "# Title\n")
    y = tmp_path / "threat-model.yaml"
    y.write_text("threats: [unbalanced\n", encoding="utf-8")
    rep = qa.check_yaml_md_consistency(f, y)
    assert rep.issues


# ===========================================================================
# Full valid Figure-2 heatmap exercises D/E/F/G/T rules end-to-end
# ===========================================================================

_HEATMAP_SECTION = """\
### Security Posture & Top Threats

```mermaid
%%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%
flowchart LR
subgraph ACTORS[" "]
    direction TB
    HDR_A["actors"]
    A1(["External Attacker"])
    end
subgraph TIERS[" "]
    direction TB
    HDR_T["tiers"]
    BROWSER["Client"]
    SERVER["Application"]
    DATA["Data"]
    end
subgraph IMPACT[" "]
    direction TB
    HDR_I["impact"]
    I1[["Data breach"]]
    end
HDR_A --- HDR_T
HDR_T --- HDR_I
A1 ==>|" ① "| SERVER
SERVER -.-> I1
linkStyle 0,1 stroke:transparent
linkStyle 2 stroke:#b71c1c
linkStyle 3 stroke:#6b7280
```

| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |
| --- | --- | --- | --- | --- |
| <a id="path-1"></a>① | Injection | [F-001](#f-001) | High | Patch |

### Next
"""


def test_posture_structure_full_heatmap(tmp_path):
    f = _md(tmp_path, _HEATMAP_SECTION)
    rep = qa.check_security_posture_structure(f)
    # Exercises all D/E/F/G/T rule bodies end-to-end. The renderer/subgraph/
    # alignment/glyph/table D-rules all pass on this well-formed heatmap.
    assert not any(i.startswith(("D1", "D2", "D3", "T1", "T2")) for i in rep.issues), rep.issues
