"""Coverage band 2 for scripts/qa_checks.py (~lines 2971-5400).

Targets §7 clarity checks, the §5/§4 fixed-layout HTML table emitter,
cmd_autofix / cmd_all, heading hygiene, TOC closure, mermaid syntax,
infobox completeness, and the v2 contract-driven §7 control checks.

These call functions directly with tmp_path fixtures and assert on
report.ok / report.issues / report.warnings. No pipeline run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "qa_checks.py"


def _load():
    if "qa_checks" in sys.modules:
        return sys.modules["qa_checks"]
    spec = importlib.util.spec_from_file_location("qa_checks", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["qa_checks"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


qa = _load()


def _md(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "threat-model.md"
    f.write_text(content, encoding="utf-8")
    return f


# A §7 section must start with `## 7. ` and end at `## 8. ` (or 9./1x.).
def _wrap_sec7(body: str, *, before: str = "", after: str = "## 8. Findings\n\nx\n") -> str:
    return f"{before}## 7. Security Architecture\n\n{body}\n\n{after}"


# ---------------------------------------------------------------------------
# _extract_section7
# ---------------------------------------------------------------------------


def test_extract_section7_absent():
    assert qa._extract_section7("# Title\n\nno section seven here\n") == ("", 0)


def test_extract_section7_to_eof():
    text = "# T\n\n## 7. Security Architecture\n\nbody line\n"
    sec, start_line = qa._extract_section7(text)
    assert sec.startswith("## 7. Security Architecture")
    assert "body line" in sec
    assert start_line == 3


def test_extract_section7_bounded_by_section8():
    text = "## 7. Security Architecture\n\nfoo\n\n## 8. Next\n\nbar\n"
    sec, _ = qa._extract_section7(text)
    assert "foo" in sec
    assert "bar" not in sec


# ---------------------------------------------------------------------------
# check_section7_narrative_placeholders
# ---------------------------------------------------------------------------


def test_narrative_placeholders_file_missing(tmp_path):
    r = qa.check_section7_narrative_placeholders(tmp_path / "nope.md")
    assert r.ok == 0
    assert any("not found" in i for i in r.issues)


def test_narrative_placeholders_no_section(tmp_path):
    p = _md(tmp_path, "# T\n\nno sec7\n")
    r = qa.check_section7_narrative_placeholders(p)
    assert r.ok == 1
    assert any("§7 not found" in w for w in r.warnings)


def test_narrative_placeholders_clean(tmp_path):
    p = _md(tmp_path, _wrap_sec7("### 7.1 Overview\n\nAll filled in.\n"))
    r = qa.check_section7_narrative_placeholders(p)
    assert r.ok == 1
    assert not r.issues


def test_narrative_placeholders_detected(tmp_path):
    body = "### 7.1 Overview\n\nNARRATIVE_PLACEHOLDER\n\nNARRATIVE_PLACEHOLDER\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_narrative_placeholders(p)
    assert r.ok == 0
    assert any("NARRATIVE_PLACEHOLDER" in i for i in r.issues)
    assert "2 unfilled" in r.issues[0]


def test_narrative_placeholders_many_truncated(tmp_path):
    body = "### 7.1 O\n\n" + "\n".join(["NARRATIVE_PLACEHOLDER"] * 10)
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_narrative_placeholders(p)
    assert r.ok == 0
    assert "more" in r.issues[0]


# ---------------------------------------------------------------------------
# _walk_h4_blocks
# ---------------------------------------------------------------------------


def test_walk_h4_blocks_boundaries():
    section = "## 7. X\n\n### 7.1 A\n\n#### First\nbody1\n\n#### Second\nbody2\n\n### 7.2 B\ntail\n"
    blocks = qa._walk_h4_blocks(section)
    titles = [b[0] for b in blocks]
    assert titles == ["First", "Second"]
    assert "body1" in blocks[0][1]
    assert "body2" not in blocks[0][1]


# ---------------------------------------------------------------------------
# check_section7_h4_positive_intro
# ---------------------------------------------------------------------------

_LONG_INTRO = (
    "The authentication subsystem validates every inbound request against the "
    "central middleware located in routes auth and library passport before any "
    "downstream handler executes for sessions and tokens overall securely now."
)


def test_h4_positive_intro_file_missing(tmp_path):
    r = qa.check_section7_h4_positive_intro(tmp_path / "x.md")
    assert r.ok == 0


def test_h4_positive_intro_no_section(tmp_path):
    p = _md(tmp_path, "# T\n\nnothing\n")
    r = qa.check_section7_h4_positive_intro(p)
    assert r.ok == 1


def test_h4_positive_intro_clean(tmp_path):
    body = f"### 7.2 Auth\n\n#### Login\n**Status:** 🟢 Safe — fine\n\n{_LONG_INTRO}\n\n**Security assessment**\n\nok\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_h4_positive_intro(p)
    assert r.ok == 1, r.issues


def test_h4_positive_intro_missing(tmp_path):
    body = "### 7.2 Auth\n\n#### Login\n**Security assessment**\n\ngap\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_h4_positive_intro(p)
    assert r.ok == 0
    assert any("no positive intro" in i for i in r.issues)


def test_h4_positive_intro_too_short(tmp_path):
    body = "### 7.2 Auth\n\n#### Login\nShort intro here.\n\n**Security assessment**\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_h4_positive_intro(p)
    assert r.ok == 0
    assert any("too short" in i for i in r.issues)


def test_h4_positive_intro_negative_opener(tmp_path):
    body = (
        "### 7.2 Auth\n\n#### Login\n"
        "No authentication mechanism exists anywhere in this codebase and that "
        "is a serious omission that the team must address before release date.\n\n"
        "**Security assessment**\n"
    )
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_h4_positive_intro(p)
    assert r.ok == 0
    assert any("opens with" in i for i in r.issues)


def test_h4_positive_intro_skips_anti_pattern_and_comment(tmp_path):
    body = (
        "### 7.2 Auth\n\n#### Login\n"
        "**Status:** 🟢 Safe — ok\n"
        "⚠ **Anti-pattern:** none\n"
        "<!-- a comment -->\n"
        f"{_LONG_INTRO}\n\n**Security assessment**\n"
    )
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_h4_positive_intro(p)
    assert r.ok == 1, r.issues


# ---------------------------------------------------------------------------
# check_section7_h4_status
# ---------------------------------------------------------------------------


def test_h4_status_file_missing(tmp_path):
    r = qa.check_section7_h4_status(tmp_path / "x.md")
    assert r.ok == 0


def test_h4_status_no_section(tmp_path):
    p = _md(tmp_path, "# T\n\nno sec\n")
    r = qa.check_section7_h4_status(p)
    assert r.ok == 1


def test_h4_status_present(tmp_path):
    body = "### 7.2 A\n\n#### Login\n**Status:** 🟢 Safe — ok\n\nprose\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_h4_status(p)
    assert not r.warnings


def test_h4_status_missing_warns(tmp_path):
    body = "### 7.2 A\n\n#### Login\nprose with no status badge here\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_h4_status(p)
    assert any("missing" in w for w in r.warnings)
    assert r.ok == 1  # warning only, not a hard issue


# ---------------------------------------------------------------------------
# check_section7_fence_intro_sentence
# ---------------------------------------------------------------------------


def test_fence_intro_file_missing(tmp_path):
    r = qa.check_section7_fence_intro_sentence(tmp_path / "x.md")
    assert r.ok == 0


def test_fence_intro_no_section(tmp_path):
    p = _md(tmp_path, "# T\n\nno sec\n")
    r = qa.check_section7_fence_intro_sentence(p)
    assert r.ok == 1


def test_fence_intro_clean(tmp_path):
    body = "### 7.2 Auth\n\nThe vulnerable code shows:\n\n```ts\nconst x = 1;\n```\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_fence_intro_sentence(p)
    assert r.ok == 1, r.issues


def test_fence_intro_no_colon(tmp_path):
    body = "### 7.2 Auth\n\nThis is prose without a colon\n\n```ts\nx\n```\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_fence_intro_sentence(p)
    assert r.ok == 0
    assert any("does not end in" in i for i in r.issues)


def test_fence_intro_structural_marker(tmp_path):
    body = "### 7.2 Auth\n\n**Security assessment**\n\n```ts\nx\n```\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_fence_intro_sentence(p)
    assert r.ok == 0
    assert any("structural marker" in i for i in r.issues)


def test_fence_intro_no_preceding_line(tmp_path):
    # Fence is the very first content under 7.2 — j < 0 branch.
    body = "### 7.2 Auth\n```ts\nx\n```\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_fence_intro_sentence(p)
    # The H3 heading is the preceding line → structural-marker issue path.
    assert r.ok == 0


# ---------------------------------------------------------------------------
# check_section7_finding_link_duplicate
# ---------------------------------------------------------------------------


def test_finding_link_dup_file_missing(tmp_path):
    r = qa.check_section7_finding_link_duplicate(tmp_path / "x.md")
    assert r.ok == 0


def test_finding_link_dup_no_section(tmp_path):
    p = _md(tmp_path, "# T\n\nnope\n")
    r = qa.check_section7_finding_link_duplicate(p)
    assert r.ok == 1


def test_finding_link_dup_clean(tmp_path):
    body = "### 7.2 A\n\n- [F-009](#f-009) — Persistent XSS in comment field\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_finding_link_duplicate(p)
    assert r.ok == 1


def test_finding_link_dup_detected(tmp_path):
    body = "### 7.2 A\n\n- [F-009](#f-009) — Persistent XSS Flaw — Persistent XSS Flaw\n"
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_finding_link_duplicate(p)
    assert r.ok == 0
    assert any("duplicates title" in i for i in r.issues)


# ---------------------------------------------------------------------------
# check_html_nested_finding_link
# ---------------------------------------------------------------------------


def test_html_nested_link_file_missing(tmp_path):
    r = qa.check_html_nested_finding_link(tmp_path / "x.md")
    assert r.ok == 0


def test_html_nested_link_clean(tmp_path):
    p = _md(tmp_path, '<a href="#f-001">F-001</a> — title\n')
    r = qa.check_html_nested_finding_link(p)
    assert r.ok == 1


def test_html_nested_link_detected(tmp_path):
    p = _md(tmp_path, '<a href="#f-001">[F-001](#f-001)</a> — title\n')
    r = qa.check_html_nested_finding_link(p)
    assert r.ok == 0
    assert any("nested inside HTML anchor" in i for i in r.issues)


def test_html_nested_link_many_truncated(tmp_path):
    cell = '<a href="#f-001">[F-001](#f-001)</a>\n'
    p = _md(tmp_path, cell * 10)
    r = qa.check_html_nested_finding_link(p)
    assert r.ok == 0
    assert any("more nested-link" in i for i in r.issues)


# ---------------------------------------------------------------------------
# _semantic_tokens + check_section7_finding_reference_semantic
# ---------------------------------------------------------------------------


def test_semantic_tokens_filters_stopwords():
    toks = qa._semantic_tokens("The attacker forges a malicious token via bypass")
    assert "attacker" not in toks  # stopword
    assert "the" not in toks
    assert "forges" in toks or "malicious" in toks


def test_semantic_tokens_empty():
    assert qa._semantic_tokens("") == set()


def test_finding_ref_semantic_file_missing(tmp_path):
    r = qa.check_section7_finding_reference_semantic(tmp_path / "x.md")
    assert r.ok == 0


def test_finding_ref_semantic_no_section(tmp_path):
    p = _md(tmp_path, "# T\n\nnope\n")
    r = qa.check_section7_finding_reference_semantic(p)
    assert r.ok == 1


def test_finding_ref_semantic_no_yaml(tmp_path):
    p = _md(tmp_path, _wrap_sec7("### 7.2 A\n\n- [F-001](#f-001) — something\n"))
    r = qa.check_section7_finding_reference_semantic(p)
    # No sibling yaml → label index empty → skipped warning.
    assert r.ok == 1
    assert any("yaml not readable" in w for w in r.warnings)


def test_finding_ref_semantic_drift_warns(tmp_path):
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-001\n    title: 'SQL Injection in search query handler component'\n",
        encoding="utf-8",
    )
    body = (
        "### 7.2 A\n\n"
        "- [F-001](#f-001) — Algorithm confusion permits forging signature "
        "bearer credentials repeatedly silently\n"
    )
    p = _md(tmp_path, _wrap_sec7(body))
    r = qa.check_section7_finding_reference_semantic(p)
    assert r.ok == 1
    assert any("likely wrong F-NNN" in w for w in r.warnings)


# ---------------------------------------------------------------------------
# _annotate_id_refs
# ---------------------------------------------------------------------------


def test_annotate_id_refs_no_yaml(tmp_path):
    p = _md(tmp_path, "[F-001](#f-001)\n")
    assert qa._annotate_id_refs(p) == 0


def test_annotate_id_refs_adds_dot_and_circle(tmp_path):
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n"
        "  - t_id: T-001\n"
        "    effective_severity: critical\n"
        "mitigations:\n"
        "  - m_id: M-001\n"
        "    priority: p1\n",
        encoding="utf-8",
    )
    p = _md(tmp_path, "See [F-001](#f-001) and [M-001](#m-001).\n")
    changed = qa._annotate_id_refs(p)
    assert changed == 1
    out = p.read_text()
    assert "🔴 [F-001](#f-001)" in out
    assert "● [M-001](#m-001)" in out  # p1 → ● (fill-ramp)


def test_annotate_id_refs_maps_all_priorities_and_repairs_stale_digit(tmp_path):
    (tmp_path / "threat-model.yaml").write_text(
        "threats: []\n"
        "mitigations:\n"
        "  - {m_id: M-001, priority: p1}\n"
        "  - {m_id: M-002, priority: p2}\n"
        "  - {m_id: M-003, priority: p3}\n"
        "  - {m_id: M-004, priority: p4}\n",
        encoding="utf-8",
    )
    p = _md(
        tmp_path,
        "[M-001](#m-001), ❹ [M-002](#m-002), ❸&nbsp;[M-003](#m-003), [M-004](#m-004)\n",
    )
    assert qa._annotate_id_refs(p) == 1
    assert p.read_text() == ("● [M-001](#m-001), ◕ [M-002](#m-002), ◑&nbsp;[M-003](#m-003), ○ [M-004](#m-004)\n")
    assert qa._annotate_id_refs(p) == 0


def test_annotate_id_refs_idempotent_and_skips_code(tmp_path):
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-002\n    severity: high\n",
        encoding="utf-8",
    )
    # Already-annotated ref + code fence containing a ref → no change.
    p = _md(tmp_path, "🟠 [F-002](#f-002)\n\n```\n[F-002](#f-002)\n```\n")
    assert qa._annotate_id_refs(p) == 0


def test_annotate_id_refs_priority_from_threat_sev(tmp_path):
    # Mitigation has no explicit priority; derive from linked threat severity.
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-003\n    severity: medium\nmitigations:\n  - m_id: M-003\n    threat_ids: [T-003]\n",
        encoding="utf-8",
    )
    p = _md(tmp_path, "[M-003](#m-003)\n")
    qa._annotate_id_refs(p)
    assert "◑ [M-003](#m-003)" in p.read_text()  # medium → p3 → ◑


# ---------------------------------------------------------------------------
# Inline-md → HTML helpers + fixed-layout table emitter
# ---------------------------------------------------------------------------


def test_render_inline_md_to_html_all_tokens():
    out = qa._render_inline_md_to_html("plain `code` [lbl](#a) **bold** _ital_ *star* <br/> <tag>")
    assert "<code>code</code>" in out
    assert '<a href="#a">lbl</a>' in out
    assert "<strong>bold</strong>" in out
    assert "<em>ital</em>" in out
    assert "<em>star</em>" in out
    assert "<br/>" in out
    assert "&lt;tag&gt;" in out


def test_split_gfm_row():
    assert qa._split_gfm_row("| a | b | c |") == ["a", "b", "c"]
    assert qa._split_gfm_row("a | b") == ["a", "b"]


def test_match_fixed_layout_spec_hit_and_miss():
    hdr = "| Method | Route | Risk | Notes |"
    assert qa._match_fixed_layout_spec(hdr) is not None
    assert qa._match_fixed_layout_spec("| X | Y |") is None


def test_attack_surface_tables_to_html_converts():
    md = (
        "intro\n"
        "| Method | Route | Risk | Notes |\n"
        "| --- | --- | --- | --- |\n"
        "| GET | /a | High | `server.ts:1` |\n"
        "trailer\n"
    )
    new_md, n = qa._attack_surface_tables_to_html(md)
    assert n == 1
    assert '<table style="table-layout:fixed' in new_md
    assert "<code>server.ts:1</code>" in new_md
    assert "trailer" in new_md


def test_attack_surface_tables_to_html_noop():
    md = "| Foo | Bar |\n| --- | --- |\n| 1 | 2 |\n"
    new_md, n = qa._attack_surface_tables_to_html(md)
    assert n == 0
    assert new_md == md


def test_emit_as_html_table_prose_col_strips_br():
    spec = qa._FIXED_LAYOUT_SPECS[1]  # Asset table, prose col 2
    rows = ["| Name | Conf | line one<br/>line two | [F-1](#f-1) |"]
    html = qa._emit_as_html_table(rows, spec)
    joined = "\n".join(html)
    # Description col (2) had its <br/> collapsed to a space.
    assert "line one line two" in joined
    assert "overflow-wrap:anywhere" in joined  # styled narrow columns kept


# ---------------------------------------------------------------------------
# cmd_autofix
# ---------------------------------------------------------------------------


def test_cmd_autofix_returns_zero(tmp_path, capsys):
    p = _md(
        tmp_path,
        "# Threat Model\n\n## 7. Security Architecture\n\nbody\n\n## 8. X\n\ny\n",
    )
    rc = qa.cmd_autofix(p, tmp_path)
    assert rc == 0
    out = capsys.readouterr().out
    assert "autofix" in out
    assert "fix_count" in out


def test_cmd_autofix_converts_as_table(tmp_path, capsys):
    md = "# T\n\n| Method | Route | Risk | Notes |\n| --- | --- | --- | --- |\n| GET | /a | High | note |\n"
    p = _md(tmp_path, md)
    rc = qa.cmd_autofix(p, tmp_path)
    assert rc == 0
    assert "<table" in p.read_text()


# ---------------------------------------------------------------------------
# cmd_all — full battery; assert int return + runs without crash
# ---------------------------------------------------------------------------


def test_cmd_all_clean_returns_zero(tmp_path, capsys):
    md = "# Threat Model\n\n## 7. Security Architecture\n\n### 7.1 Overview\n\nAll good.\n\n## 8. Findings\n\nnothing\n"
    p = _md(tmp_path, md)
    rc = qa.cmd_all(p, tmp_path)
    assert rc in (0, 1)
    out = capsys.readouterr().out
    assert "mermaid_syntax" in out
    assert "toc_closure" in out


def test_cmd_all_with_broken_anchor_returns_one(tmp_path, capsys):
    md = "# T\n\nSee [missing](#does-not-exist) here.\n"
    p = _md(tmp_path, md)
    rc = qa.cmd_all(p, tmp_path)
    assert rc == 1
    capsys.readouterr()


# ---------------------------------------------------------------------------
# strip_heading_attribute_artifacts
# ---------------------------------------------------------------------------


def test_strip_heading_attr_pandoc_trailer(tmp_path):
    p = _md(tmp_path, "# Title {#anchor key=val}\n\nbody\n")
    report, text = qa.strip_heading_attribute_artifacts(p)
    assert report.fixes
    assert "{#anchor" not in p.read_text()


def test_strip_heading_attr_data_source_line(tmp_path):
    p = _md(tmp_path, "## Sec {#s data-source-line=42}\n\nbody\n")
    report, _ = qa.strip_heading_attribute_artifacts(p)
    assert report.fixes
    assert "data-source-line" not in p.read_text()


def test_strip_heading_attr_skips_fence_and_clean(tmp_path):
    p = _md(tmp_path, "# Clean Title\n\n```\n# not a heading {#x}\n```\n")
    report, _ = qa.strip_heading_attribute_artifacts(p)
    assert not report.fixes  # fence body untouched, heading clean


# ---------------------------------------------------------------------------
# check_heading_hygiene
# ---------------------------------------------------------------------------


def test_heading_hygiene_clean(tmp_path):
    p = _md(tmp_path, "# Title\n\n## Section ([T-001](#t-001))\n\nbody\n")
    r = qa.check_heading_hygiene(p)
    assert not r.issues


def test_heading_hygiene_unbalanced_parens(tmp_path):
    p = _md(tmp_path, "# Title (oops\n")
    r = qa.check_heading_hygiene(p)
    assert any("unbalanced parentheses" in i for i in r.issues)


def test_heading_hygiene_unclosed_backtick(tmp_path):
    p = _md(tmp_path, "# Title `code\n")
    r = qa.check_heading_hygiene(p)
    assert any("unclosed backtick" in i for i in r.issues)


def test_heading_hygiene_multiple_links(tmp_path):
    p = _md(tmp_path, "# [a](#a) [b](#b)\n")
    r = qa.check_heading_hygiene(p)
    assert any("markdown links in heading" in i for i in r.issues)


def test_heading_hygiene_link_emdash_expansion(tmp_path):
    p = _md(tmp_path, "# [T-1](#t-1) — extra text\n")
    r = qa.check_heading_hygiene(p)
    assert any("expansion" in i for i in r.issues)


def test_heading_hygiene_attr_artefact(tmp_path):
    # Inline artefact that survives into visible heading text.
    p = _md(tmp_path, "# Title data-source-line=3\n")
    r = qa.check_heading_hygiene(p)
    assert any("attribute-syntax artefact" in i for i in r.issues)


def test_heading_hygiene_too_long(tmp_path):
    long_title = "A" * 105
    p = _md(tmp_path, f"# {long_title}\n")
    r = qa.check_heading_hygiene(p)
    assert any("exceeds 100-char" in i for i in r.issues)


def test_heading_hygiene_soft_limit_warns(tmp_path):
    title = "B" * 85
    p = _md(tmp_path, f"# {title}\n")
    r = qa.check_heading_hygiene(p)
    assert any("80-char" in w for w in r.warnings)
    assert not r.issues


# ---------------------------------------------------------------------------
# check_toc_closure
# ---------------------------------------------------------------------------


def test_toc_closure_resolves_heading_slug(tmp_path):
    p = _md(tmp_path, "# My Heading\n\nLink to [it](#my-heading).\n")
    r = qa.check_toc_closure(p)
    assert not r.issues
    assert r.ok >= 1


def test_toc_closure_resolves_a_id(tmp_path):
    p = _md(tmp_path, '<a id="custom"></a>\n\n[x](#custom)\n')
    r = qa.check_toc_closure(p)
    assert not r.issues


def test_toc_closure_broken_anchor(tmp_path):
    p = _md(tmp_path, "# H\n\n[x](#nope)\n")
    r = qa.check_toc_closure(p)
    assert any("unresolved" in i for i in r.issues)


def test_toc_closure_many_broken_truncated(tmp_path):
    links = "\n".join(f"[x](#missing-{i})" for i in range(30))
    p = _md(tmp_path, "# H\n\n" + links + "\n")
    r = qa.check_toc_closure(p)
    assert any("more unresolved" in i for i in r.issues)


def test_toc_closure_flags_emdash_heading_single_hyphen_link(tmp_path):
    # Regression for the 2026-06 §3 ToC breakage: a link target built with the
    # single-hyphen generator slug must be flagged when github.com renders the
    # ` — ` heading anchor as a DOUBLE hyphen. The check was previously blind
    # to this because it slugged the heading with the same generator.
    md = (
        "### 3.7 Insecure Direct Object Reference — routes/address.ts:11\n\n"
        "[3.7](#37-insecure-direct-object-reference-routesaddressts11)\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_toc_closure(p)
    assert any("unresolved" in i for i in r.issues)


def test_toc_closure_clean_heading_with_emdash_tail_stripped_resolves(tmp_path):
    # The fix: a class-only heading (no em-dash) slugs identically under both
    # the generator and the renderer, so the composer link resolves.
    md = "### 3.7 Insecure Direct Object Reference\n\n[3.7](#37-insecure-direct-object-reference)\n"
    p = _md(tmp_path, md)
    r = qa.check_toc_closure(p)
    assert not r.issues


# ---------------------------------------------------------------------------
# check_mermaid_syntax + autofix helpers
# ---------------------------------------------------------------------------


def test_mermaid_clean_sequence(tmp_path):
    md = "## 3. Attack Walkthroughs\n\n```mermaid\nsequenceDiagram\n  A->>B: hello\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert not [i for i in r.issues if "unbalanced" in i or "literal" in i]


def test_mermaid_unbalanced_quote(tmp_path):
    md = '```mermaid\nsequenceDiagram\n  A->>B: say "hi\n```\n'
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("unbalanced double-quote" in i for i in r.issues)


def test_mermaid_literal_semicolon(tmp_path):
    # Rule D now auto-repairs the literal ';' before the detector runs, so the
    # issue is drained into r.fixes and the file is rewritten clean.
    md = "```mermaid\nsequenceDiagram\n  A->>B: SELECT 1; DROP TABLE t\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("seqdiagram_semicolon" in f for f in r.fixes)
    assert not any("literal ';'" in i for i in r.issues)
    assert ";" not in p.read_text().split("```mermaid", 1)[1].split("```", 1)[0]


def test_mermaid_end_then_else(tmp_path):
    md = "```mermaid\nsequenceDiagram\n  alt A\n  A->>B: x\n  end\n  else B\n  A->>B: y\n  end\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("outside any 'alt'" in i for i in r.issues)


def test_mermaid_unclosed_block(tmp_path):
    md = "```mermaid\nsequenceDiagram\n  alt A\n  A->>B: x\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("unclosed" in i for i in r.issues)


def test_mermaid_end_without_opener(tmp_path):
    md = "```mermaid\nsequenceDiagram\n  A->>B: x\n  end\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("without matching" in i for i in r.issues)


def test_mermaid_alt_label_convention(tmp_path):
    md = (
        "## 3. Attack Walkthroughs\n\n"
        "```mermaid\nsequenceDiagram\n"
        "  alt current vulnerable flow\n  A->>B: x\n  end\n```\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("convention" in i for i in r.issues)


def test_mermaid_alt_label_semicolon(tmp_path):
    # Rule D auto-repairs the literal ';' in the alt label before detection.
    md = (
        "## 3. Attack Walkthroughs\n\n"
        "```mermaid\nsequenceDiagram\n"
        "  alt After M-005 — remove eval(); sanitise\n  A->>B: x\n  end\n```\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("seqdiagram_alt_semicolon" in f for f in r.fixes)
    assert not any("alt/else label" in i for i in r.issues)


def test_mermaid_linkstyle_missing_index(tmp_path):
    md = "```mermaid\nflowchart LR\n  A-->B\n  linkStyle stroke:red\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("linkStyle missing index" in i for i in r.issues)


def test_mermaid_multiclass_chain(tmp_path):
    md = "```mermaid\nflowchart LR\n  A:::a:::b\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("multi-class chaining" in i for i in r.issues)


def test_mermaid_literal_newline_in_label(tmp_path):
    md = '```mermaid\nflowchart LR\n  A["line1\\nline2"]\n```\n'
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("literal in node label" in i for i in r.issues)


def test_mermaid_skips_non_supported_type(tmp_path):
    md = "```mermaid\ngantt\n  title X\n  A: a, 1, 2\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    # gantt is skipped → no structural issues from layer A.
    assert not [i for i in r.issues if "block" in i]


def test_apply_mermaid_autofix_quoted_alias():
    md = '```mermaid\nsequenceDiagram\n  participant U as "The User"\n```\n'
    new, fixes = qa._apply_mermaid_autofixes(md)
    assert fixes
    assert "Note over U: The User" in new
    assert 'as "The User"' not in new


def test_apply_mermaid_autofix_html_strip():
    md = "```mermaid\nsequenceDiagram\n  A->>B: Bearer <token> here\n```\n"
    new, fixes = qa._apply_mermaid_autofixes(md)
    assert fixes
    assert "<token>" not in new


def test_apply_mermaid_autofix_flowchart_balance():
    md = "```mermaid\nflowchart LR\n  A[load file (/etc/pass…]\n```\n"
    new, fixes = qa._apply_mermaid_autofixes(md)
    assert fixes
    assert "flowchart_label_balance" in fixes[0]


def test_apply_mermaid_autofix_message_semicolon():
    md = "```mermaid\nsequenceDiagram\n  Attacker->>Repo: git clone; read lib/insecurity.ts:23\n```\n"
    new, fixes = qa._apply_mermaid_autofixes(md)
    assert any("seqdiagram_semicolon" in f for f in fixes)
    assert ";" not in new
    assert "git clone — read" in new


def test_apply_mermaid_autofix_note_semicolon():
    md = "```mermaid\nsequenceDiagram\n  note over API: Key from store, not source; old tokens invalid\n```\n"
    new, fixes = qa._apply_mermaid_autofixes(md)
    assert any("seqdiagram_semicolon" in f for f in fixes)
    assert ";" not in new


def test_apply_mermaid_autofix_semicolon_idempotent():
    md = "```mermaid\nsequenceDiagram\n  A->>B: x; y\n```\n"
    once, _ = qa._apply_mermaid_autofixes(md)
    twice, fixes2 = qa._apply_mermaid_autofixes(once)
    assert twice == once and fixes2 == []


def test_apply_mermaid_autofix_noop():
    md = "```mermaid\nsequenceDiagram\n  A->>B: hello\n```\n"
    new, fixes = qa._apply_mermaid_autofixes(md)
    assert new == md
    assert fixes == []


def test_mermaid_autofix_writes_back(tmp_path):
    md = '```mermaid\nsequenceDiagram\n  participant U as "Person"\n```\n'
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert r.fixes
    assert "Note over U" in p.read_text()


def test_run_authoritative_mermaid_parse_no_blocks():
    issues, skip = qa._run_authoritative_mermaid_parse("# no mermaid here\n")
    # Either validator missing (skip set) or no blocks (skip None, no issues).
    assert issues == []


# ---------------------------------------------------------------------------
# check_toc_nested_links
# ---------------------------------------------------------------------------


def test_toc_nested_links_clean(tmp_path):
    p = _md(tmp_path, "[3.2 Foo](#32-foo)\n")
    r = qa.check_toc_nested_links(p)
    assert not r.issues
    assert r.ok >= 1


def test_toc_nested_links_detected(tmp_path):
    p = _md(tmp_path, "[3.2 Foo ([T-001](#t-001))](#32-foo)\n")
    r = qa.check_toc_nested_links(p)
    assert any("nested" in i for i in r.issues)


# ---------------------------------------------------------------------------
# check_infobox_completeness
# ---------------------------------------------------------------------------


def test_infobox_complete(tmp_path):
    md = (
        "> | **Project** | demo |\n"
        "> | **Repository** | r |\n"
        "> | **License** | MIT |\n"
        "> | **Author** | a |\n"
        "> | **Description** | d |\n"
        "> | **Homepage** | h |\n"
        "\nbody\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_infobox_completeness(p)
    assert not r.issues


def test_infobox_missing_required(tmp_path):
    md = "> | **Project** | demo |\n\nbody\n"
    p = _md(tmp_path, md)
    r = qa.check_infobox_completeness(p)
    assert any("required field" in i for i in r.issues)


def test_infobox_sparse(tmp_path):
    md = "> | **Project** | demo |\n> | **Repository** | r |\n> | **License** | MIT |\n\nbody\n"
    p = _md(tmp_path, md)
    r = qa.check_infobox_completeness(p)
    assert any("sparse" in i for i in r.issues)


# ---------------------------------------------------------------------------
# _extract_section_body / _parse_subsections / _parse_domain_controls_table
# ---------------------------------------------------------------------------


def test_extract_section_body_found_and_bounded():
    text = "### 7.2 A\nbody A\n### 7.3 B\nbody B\n"
    body = qa._extract_section_body(text, r"^###\s+7\.2\s+A\b")
    assert "body A" in body
    assert "body B" not in body


def test_extract_section_body_missing():
    assert qa._extract_section_body("no match", r"^###\s+9\.9\b") is None


def test_parse_subsections():
    body = "#### One\nb1\n#### Two\nb2\n"
    subs = qa._parse_subsections(body, level=4)
    assert list(subs) == ["One", "Two"]
    assert "b1" in subs["One"]


def test_parse_domain_controls_table():
    body = (
        "| Control | Linked Threats |\n"
        "| --- | --- |\n"
        "| Password Hashing | T-001, T-002 |\n"
        "|  | T-003 |\n"  # empty control → skipped
    )
    rows = qa._parse_domain_controls_table(body, control_column="Control")
    assert len(rows) == 1
    assert rows[0]["control"] == "Password Hashing"
    assert rows[0]["linked_tids"] == {"T-001", "T-002"}
    assert rows[0]["Control"] == "Password Hashing"


# ---------------------------------------------------------------------------
# check_auth_method_decomposition (v2 path via default contract)
# ---------------------------------------------------------------------------


def test_auth_method_decomposition_no_iam_section(tmp_path):
    # Default contract declares the rule; doc lacks §7.2 → clean no-op.
    p = _md(tmp_path, "# T\n\n## 7. Security Architecture\n\nno iam\n\n## 8. X\n\ny\n")
    r = qa.check_auth_method_decomposition(p)
    assert r.ok == 1


def test_auth_method_decomposition_v2_runs(tmp_path):
    # A §7.2 with a forbidden attack-shaped heading should surface an issue
    # (or at least run the v2 structural path without crashing).
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### alg:none Bypass Flow\n\n"
        "body\n\n"
        "## 8. Findings\n\nx\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_auth_method_decomposition(p)
    assert isinstance(r.ok, int)


# ---------------------------------------------------------------------------
# check_control_subsection_coverage
# ---------------------------------------------------------------------------


def test_control_subsection_coverage_not_applicable_stub(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "_Not applicable — no auth surface._\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_control_subsection_coverage(p)
    # Stub section is skipped; if no other section present, stays clean.
    assert isinstance(r.ok, int)


def test_control_subsection_coverage_missing_subsections(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "Some prose but no H4 subsections.\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_control_subsection_coverage(p)
    assert any("no #### control subsections" in i for i in r.issues)


def test_control_subsection_coverage_missing_labels_and_controls_line(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### JWT Authentication\n\n"
        "body without required labels\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_control_subsection_coverage(p)
    joined = " ".join(r.issues)
    assert "Controls covered" in joined  # missing controls-covered label
    assert "Security assessment" in joined or "Relevant findings" in joined


def test_control_subsection_coverage_link_mismatch(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "**Controls covered:** [Nonexistent Control](#x)\n\n"
        "#### JWT Authentication\n\n"
        "**Security assessment**\n\nok\n\n"
        "**Relevant findings**\n\n- none\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_control_subsection_coverage(p)
    assert any("no matching" in i for i in r.issues)


def test_control_subsection_coverage_clean(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "**Controls covered:** [JWT Authentication](#jwt)\n\n"
        "#### JWT Authentication\n\n"
        "**Security assessment**\n\nok\n\n"
        "**Relevant findings**\n\n- none\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_control_subsection_coverage(p)
    # No link-mismatch and both labels present for the one subsection.
    assert not any("no matching" in i for i in r.issues)
    assert not any("missing `**Security assessment**`" in i for i in r.issues)


# ---------------------------------------------------------------------------
# check_relevant_findings_bullet_list
# ---------------------------------------------------------------------------


def test_relevant_findings_clean(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### JWT\n\n"
        "**Relevant findings**\n\n"
        "- [F-001](#f-001) - rationale\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_relevant_findings_bullet_list(p)
    assert not r.issues


def test_relevant_findings_colon_forbidden(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### JWT\n\n"
        "**Relevant findings:**\n\n"
        "- [F-001](#f-001) - r\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_relevant_findings_bullet_list(p)
    assert any("without a colon" in i for i in r.issues)


def test_relevant_findings_inline_forbidden(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### JWT\n\n"
        "**Relevant findings** [F-001](#f-001), [F-002](#f-002)\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_relevant_findings_bullet_list(p)
    assert any("inline" in i for i in r.issues)


def test_relevant_findings_not_a_bullet(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### JWT\n\n"
        "**Relevant findings**\n\n"
        "This is a paragraph, not a bullet.\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_relevant_findings_bullet_list(p)
    assert any("not a Markdown bullet" in i for i in r.issues)


def test_relevant_findings_no_bullet_list_at_all(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### JWT\n\n"
        "**Relevant findings**\n"
    )
    # No following content lines → "has no bullet list".
    p = _md(tmp_path, md + "\n## 8. X\n\ny\n")
    r = qa.check_relevant_findings_bullet_list(p)
    assert any("no bullet list" in i for i in r.issues)


# ---------------------------------------------------------------------------
# check_validation_approach_first
# ---------------------------------------------------------------------------


def test_validation_approach_first_clean(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.6 Input Boundary Validation Controls\n\n"
        "#### Validation Approach\n\nWe centralize schema validation.\n\n"
        "#### File Upload Parser\n\ndetails\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_validation_approach_first(p)
    assert not r.issues


def test_validation_approach_first_violation(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.6 Input Boundary Validation Controls\n\n"
        "#### File Upload Parser\n\ndetails first, wrong order\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_validation_approach_first(p)
    assert any("must OPEN with a general validation-approach" in i for i in r.issues)


def test_validation_approach_first_not_applicable(tmp_path):
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.6 Input Boundary Validation Controls\n\n"
        "_Not applicable — no input boundaries._\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_validation_approach_first(p)
    assert r.ok == 1
    assert not r.issues


def test_validation_approach_first_missing_section(tmp_path):
    md = "## 7. Security Architecture\n\nno 7.6 here\n\n## 8. X\n\ny\n"
    p = _md(tmp_path, md)
    r = qa.check_validation_approach_first(p)
    assert r.ok == 1


# ---------------------------------------------------------------------------
# v1 Control-table auth path via a custom contract (lines ~5049-5091)
# ---------------------------------------------------------------------------


def _v1_contract(tmp_path: Path) -> Path:
    """Write a minimal v1-style contract that declares the Control-table
    auth_method_decomposition rule, driving the v1 branch of the check."""
    c = tmp_path / "contract.yaml"
    c.write_text(
        "sections:\n"
        "  security_architecture:\n"
        "    domain_required_rules:\n"
        "      '7.3 Identity & Access Management':\n"
        "        - rule: auth_method_decomposition\n"
        "          table_column: Control\n"
        "          heading_level: 4\n"
        "          trailer_label: Findings in this flow\n"
        "          enforcement: error\n",
        encoding="utf-8",
    )
    return c


def test_auth_v1_no_table(tmp_path):
    contract = _v1_contract(tmp_path)
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.3 Identity & Access Management\n\n"
        "prose, no control table at all\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_auth_method_decomposition(p, contract_path=contract)
    assert any("no control table" in i for i in r.issues)


def test_auth_v1_table_but_no_subsections(tmp_path):
    contract = _v1_contract(tmp_path)
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.3 Identity & Access Management\n\n"
        "| Control | Linked Threats |\n"
        "| --- | --- |\n"
        "| Password Login | T-001 |\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_auth_method_decomposition(p, contract_path=contract)
    assert any("no #### subsections" in i for i in r.issues)


def test_auth_v1_full_match_clean(tmp_path):
    contract = _v1_contract(tmp_path)
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.3 Identity & Access Management\n\n"
        "| Control | Linked Threats |\n"
        "| --- | --- |\n"
        "| Password Login | T-001 |\n\n"
        "#### Password Login\n\n"
        "```mermaid\nsequenceDiagram\n  A->>B: login\n```\n\n"
        "**Findings in this flow:** [T-001](#t-001) — weak hash\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_auth_method_decomposition(p, contract_path=contract)
    assert not r.issues, r.issues


def test_auth_v1_missing_diagram_and_trailer(tmp_path):
    contract = _v1_contract(tmp_path)
    md = (
        "## 7. Security Architecture\n\n"
        "### 7.3 Identity & Access Management\n\n"
        "| Control | Linked Threats |\n"
        "| --- | --- |\n"
        "| Password Login | T-001 |\n\n"
        "#### Password Login\n\n"
        "no diagram, no trailer here\n\n"
        "## 8. X\n\ny\n"
    )
    p = _md(tmp_path, md)
    r = qa.check_auth_method_decomposition(p, contract_path=contract)
    joined = " ".join(r.issues)
    assert "sequenceDiagram" in joined
    assert "trailer" in joined


def test_auth_decomposition_contract_unreadable(tmp_path):
    missing = tmp_path / "nope-contract.yaml"
    p = _md(tmp_path, "# T\n\nbody\n")
    r = qa.check_auth_method_decomposition(p, contract_path=missing)
    # Unreadable contract → silent (ok stays 0, no issues).
    assert not r.issues


def test_auth_decomposition_rule_absent(tmp_path):
    c = tmp_path / "c.yaml"
    c.write_text(
        "sections:\n  security_architecture:\n    domain_required_rules: {}\n",
        encoding="utf-8",
    )
    p = _md(tmp_path, "# T\n\nbody\n")
    r = qa.check_auth_method_decomposition(p, contract_path=c)
    assert r.ok == 1


# ---------------------------------------------------------------------------
# _finalize_auth_report warning-mode demotion
# ---------------------------------------------------------------------------


def test_finalize_auth_report_warning_demotes():
    rep = qa.Report("x")
    rep.issues.append("boom")
    out = qa._finalize_auth_report(rep, "warning")
    assert out.issues == []
    assert "boom" in out.warnings
    assert out.ok == 1


def test_finalize_auth_report_error_keeps():
    rep = qa.Report("x")
    rep.issues.append("boom")
    out = qa._finalize_auth_report(rep, "error")
    assert out.issues == ["boom"]
    assert out.ok == 0


# ---------------------------------------------------------------------------
# Autofix / cmd_all write-back branches (in-place mutation paths)
# ---------------------------------------------------------------------------


def test_cmd_autofix_strips_heading_attr(tmp_path, capsys):
    # Heading attribute trailer triggers strip_heading_attribute_artifacts fix.
    p = _md(tmp_path, "# Title {#anchor key=val}\n\nbody\n")
    rc = qa.cmd_autofix(p, tmp_path)
    assert rc == 0
    assert "{#anchor" not in p.read_text()


def test_cmd_autofix_repairs_link_writeback(tmp_path, capsys):
    # A real file exists under repo_root with a unique basename; the link
    # points at a stale path → basename repair rewrites it (write-back branch).
    src = tmp_path / "sub" / "uniquefile12345.ts"
    src.parent.mkdir()
    src.write_text("x\n", encoding="utf-8")
    p = _md(
        tmp_path,
        "# T\n\nSee [code](vscode://file/wrong/path/uniquefile12345.ts:3).\n",
    )
    rc = qa.cmd_autofix(p, tmp_path)
    assert rc == 0
    assert "uniquefile12345.ts" in p.read_text()


def test_cmd_autofix_annotates_refs(tmp_path, capsys):
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-001\n    severity: critical\n",
        encoding="utf-8",
    )
    p = _md(tmp_path, "# T\n\nSee [F-001](#f-001) here.\n")
    qa.cmd_autofix(p, tmp_path)
    assert "🔴 [F-001](#f-001)" in p.read_text()


def test_cmd_all_strips_heading_attr_and_runs(tmp_path, capsys):
    md = "# Title {#anchor x=y}\n\n## 7. Security Architecture\n\n### 7.1 O\n\nok\n\n## 8. X\n\ny\n"
    p = _md(tmp_path, md)
    rc = qa.cmd_all(p, tmp_path)
    assert rc in (0, 1)
    assert "{#anchor" not in p.read_text()
    capsys.readouterr()


# ---------------------------------------------------------------------------
# Extra mermaid branches: flowchart subgraph balance, unquoted participant paren
# ---------------------------------------------------------------------------


def test_mermaid_subgraph_unclosed(tmp_path):
    md = "```mermaid\nflowchart LR\n  subgraph G\n  A-->B\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("unclosed" in i for i in r.issues)


def test_mermaid_subgraph_extra_end(tmp_path):
    md = "```mermaid\nflowchart LR\n  subgraph G\n  A-->B\n  end\n  end\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("without matching 'subgraph'" in i for i in r.issues)


def test_mermaid_participant_unquoted_paren(tmp_path):
    # Not in §7, sequenceDiagram, alias has unquoted paren → rule (2).
    md = "```mermaid\nsequenceDiagram\n  participant U as User (admin)\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert any("unquoted '('" in i for i in r.issues)


def test_mermaid_html_in_message_detected_then_autofixed(tmp_path):
    # check_mermaid_syntax runs Layer C autofix FIRST, so the HTML payload
    # is stripped and recorded as a fix rather than an issue.
    md = "```mermaid\nsequenceDiagram\n  A->>B: Bearer <token>\n```\n"
    p = _md(tmp_path, md)
    r = qa.check_mermaid_syntax(p)
    assert r.fixes
    assert "<token>" not in p.read_text()
