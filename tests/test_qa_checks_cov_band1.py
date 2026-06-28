"""Coverage band 1 (lines ~342-2700) for scripts/qa_checks.py.

Direct-call unit tests for the link/xref/anchor/strengths/secrets/perimeter/
invariants/MS-structure/contract/repair-plan/evidence-integrity functions.
Exercises both clean (ok=1) and issue/warning branches.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "qa_checks.py"


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


# ---------------------------------------------------------------------------
# check_links
# ---------------------------------------------------------------------------


def test_check_links_existing_absolute_ok(tmp_path: Path):
    target = tmp_path / "real.py"
    target.write_text("x = 1\n")
    md = _md(tmp_path, f"See [code](vscode://file/{target}:1) here.\n")
    report, new_text = qa.check_links(md, tmp_path)
    assert report.ok == 1
    assert not report.issues
    assert new_text == md.read_text()


def test_check_links_basename_repair(tmp_path: Path):
    sub = tmp_path / "src"
    sub.mkdir()
    real = sub / "uniquefile.py"
    real.write_text("y = 2\n")
    # Reference a wrong absolute path with the same basename.
    md = _md(tmp_path, "Link [x](vscode://file/wrong/path/uniquefile.py:3) end.\n")
    report, new_text = qa.check_links(md, tmp_path)
    assert any("repaired" in f for f in report.fixes)
    assert str(real.resolve()) in new_text


def test_check_links_ambiguous(tmp_path: Path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "dup.py").write_text("1\n")
    (tmp_path / "b" / "dup.py").write_text("2\n")
    md = _md(tmp_path, "[x](vscode://file/nowhere/dup.py)\n")
    report, _ = qa.check_links(md, tmp_path)
    assert any("ambiguous" in i for i in report.issues)


def test_check_links_missing(tmp_path: Path):
    md = _md(tmp_path, "[x](vscode://file/does/not/exist/ghost.py:9)\n")
    report, _ = qa.check_links(md, tmp_path)
    assert any("missing" in i for i in report.issues)


def test_check_links_dedups_same_key(tmp_path: Path):
    md = _md(
        tmp_path,
        "[a](vscode://file/ghost.py:1) and [b](vscode://file/ghost.py:1)\n",
    )
    report, _ = qa.check_links(md, tmp_path)
    # Only one missing issue despite two identical references.
    assert len([i for i in report.issues if "ghost.py" in i]) == 1


# ---------------------------------------------------------------------------
# check_xrefs
# ---------------------------------------------------------------------------


def test_check_xrefs_clean(tmp_path: Path):
    md = _md(
        tmp_path,
        "## 8. Findings Register\n| T-001 | a |\n### M-001 Fix it\nReference T-001 and M-001 in prose.\n",
    )
    report = qa.check_xrefs(md)
    assert not report.issues


def test_check_xrefs_orphan_threat_and_mitigation(tmp_path: Path):
    md = _md(
        tmp_path,
        "## 8. Findings Register\n"
        "| T-001 | a |\n"
        "### M-001 Fix it\n"
        "Prose refers to T-999 and M-999 which have no definitions.\n",
    )
    report = qa.check_xrefs(md)
    assert any("orphaned-threat-ref: T-999" in i for i in report.issues)
    assert any("orphaned-mitigation-ref: M-999" in i for i in report.issues)


# ---------------------------------------------------------------------------
# _inject_row_anchors
# ---------------------------------------------------------------------------


def test_inject_row_anchors_threat_and_mitigation():
    lines = [
        "## 8. Findings Register\n",
        "| T-001 | desc |\n",
        "## 10. Mitigations\n",
        "### M-002 Some fix\n",
    ]
    out, count = qa._inject_row_anchors(list(lines))
    assert count == 2
    assert any('<a id="t-001"></a>' in ln for ln in out)
    assert any('<a id="m-002"></a>' in ln for ln in out)


def test_inject_row_anchors_skips_fence():
    lines = [
        "## 8. Findings\n",
        "```\n",
        "| T-001 | x |\n",
        "```\n",
    ]
    out, count = qa._inject_row_anchors(list(lines))
    assert count == 0


def test_inject_row_anchors_idempotent():
    lines = [
        "## 8. Findings Register\n",
        '| <a id="t-001"></a> T-001 | desc |\n',
    ]
    out, count = qa._inject_row_anchors(list(lines))
    assert count == 0


# ---------------------------------------------------------------------------
# _load_label_index / _load_th_label_index
# ---------------------------------------------------------------------------


def test_load_label_index_absent_yaml(tmp_path: Path):
    md = _md(tmp_path, "x\n")
    assert qa._load_label_index(md) == {}


def test_load_label_index_builds_aliases(tmp_path: Path):
    md = _md(tmp_path, "x\n")
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n"
        "  - t_id: T-001\n"
        "    title: SQL Injection\n"
        "    original_id: T-OLD\n"
        "mitigations:\n"
        "  - m_id: M-001\n"
        "    title: Parameterize queries\n",
        encoding="utf-8",
    )
    idx = qa._load_label_index(md)
    assert idx["T-001"][0] == "SQL Injection"
    assert "F-001" in idx  # F-alias from numeric suffix
    assert idx["T-OLD"][0] == "SQL Injection"  # legacy original_id
    assert idx["M-001"][0] == "Parameterize queries"


def test_load_label_index_escapes_dollar(tmp_path: Path):
    md = _md(tmp_path, "x\n")
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-002\n    title: $where injection\n",
        encoding="utf-8",
    )
    idx = qa._load_label_index(md)
    assert idx["T-002"][0].startswith("\\$where")


def test_load_label_index_malformed_yaml(tmp_path: Path):
    md = _md(tmp_path, "x\n")
    (tmp_path / "threat-model.yaml").write_text("threats: [unclosed\n", encoding="utf-8")
    assert qa._load_label_index(md) == {}


def test_load_th_label_index_parses_decls():
    text = '| <a id="th-01"></a>TH-01 — Injection | foo |\n'
    idx = qa._load_th_label_index(text)
    assert idx["TH-01"] == ("Injection", "th-01")


def test_load_th_label_index_empty_when_no_decls():
    assert qa._load_th_label_index("nothing here\n") == {}


# ---------------------------------------------------------------------------
# linkify_anchors
# ---------------------------------------------------------------------------


def test_linkify_anchors_bare_refs(tmp_path: Path):
    md = _md(
        tmp_path,
        "## 8. Findings Register\n"
        "| T-001 | desc |\n"
        "## 11. Notes\n"
        "Prose mentioning T-001 and M-001 and F-001 and TH-01.\n",
    )
    report, new_text = qa.linkify_anchors(md)
    # T-001 in prose linkified.
    assert "[T-001](#" in new_text
    assert report.fixes  # at least anchor injection + linkify


def test_linkify_anchors_skips_toc(tmp_path: Path):
    md = _md(
        tmp_path,
        "## Table of Contents\n- [3.2 T-001 — Foo](#slug)\n## 1. Body\nT-001 here gets linkified.\n",
    )
    _, new_text = qa.linkify_anchors(md)
    toc_line = [l for l in new_text.splitlines() if "Table of Contents" not in l and "3.2 T-001" in l][0]
    # TOC line keeps bare T-001 (not double-linkified)
    assert "[3.2 T-001 — Foo](#slug)" in toc_line


def test_linkify_anchors_with_label_index(tmp_path: Path):
    md = _md(
        tmp_path,
        "## 11. Notes\nDiscussion of T-001 in prose.\n",
    )
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-001\n    title: Cool Threat\n",
        encoding="utf-8",
    )
    _, new_text = qa.linkify_anchors(md)
    assert "Cool Threat" in new_text


def test_linkify_anchors_all_id_classes_in_prose(tmp_path: Path):
    md = _md(
        tmp_path,
        "## 11. Notes\nMentions M-001 and F-002 and TH-03 in plain prose.\n",
    )
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-002\n    title: FThreat\nmitigations:\n  - m_id: M-001\n    title: MFix\n",
        encoding="utf-8",
    )
    _, new_text = qa.linkify_anchors(md)
    assert "[M-001](#m-001)" in new_text
    assert "[F-002](#f-002)" in new_text
    assert "[TH-03](#th-03)" in new_text


def test_linkify_anchors_skips_already_linked(tmp_path: Path):
    md = _md(
        tmp_path,
        "## 11. Notes\nAlready linked [M-001](#m-001) stays single.\n",
    )
    _, new_text = qa.linkify_anchors(md)
    assert new_text.count("[M-001](#m-001)") == 1


def test_linkify_anchors_em_dash_suffix_for_m_and_f(tmp_path: Path):
    md = _md(
        tmp_path,
        "## 3.1 Walk\n**Mit:** M-001 — author text\n**Find:** F-002 — author text\n**Class:** TH-03 — author text\n",
    )
    _, new_text = qa.linkify_anchors(md)
    assert "[M-001](#m-001)" in new_text
    assert "[F-002](#f-002)" in new_text
    assert "[TH-03](#th-03)" in new_text


def test_linkify_anchors_em_dash_suffix_no_title(tmp_path: Path):
    md = _md(
        tmp_path,
        "## 3.1 Walk\n**Threat:** T-001 — author wrote this\n",
    )
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-001\n    title: YamlTitle\n",
        encoding="utf-8",
    )
    _, new_text = qa.linkify_anchors(md)
    # Author em-dash present -> bare link, no injected yaml title.
    assert "YamlTitle" not in new_text
    assert "[T-001](#t-001)" in new_text


# ---------------------------------------------------------------------------
# check_strengths_row_quality / _flag_forbidden_strength_control
# ---------------------------------------------------------------------------


def test_strengths_no_section_is_ok(tmp_path: Path):
    md = _md(tmp_path, "## 1. Overview\nno strengths here\n")
    report = qa.check_strengths_row_quality(md)
    assert report.ok == 1


def test_strengths_flags_tactical_hygiene(tmp_path: Path):
    md = _md(
        tmp_path,
        "### Operational Strengths\n"
        "| Strength | What's in Place |\n"
        "| --- | --- |\n"
        "| Helmet | sets response headers |\n"
        "## Next\n",
    )
    report = qa.check_strengths_row_quality(md)
    assert any("tactical baseline" in i for i in report.issues)


def test_strengths_clean_arch_row(tmp_path: Path):
    md = _md(
        tmp_path,
        "### Operational Strengths\n"
        "| Strength | What's in Place |\n"
        "| --- | --- |\n"
        "| Centralized AuthZ | RBAC middleware |\n",
    )
    report = qa.check_strengths_row_quality(md)
    assert report.ok == 1


def test_strengths_html_table_flagged(tmp_path: Path):
    md = _md(
        tmp_path,
        "### Operational Strengths\n<table><tr><td>HSTS</td><td>enabled</td></tr></table>\n",
    )
    report = qa.check_strengths_row_quality(md)
    assert any("tactical baseline" in i for i in report.issues)


# ---------------------------------------------------------------------------
# check_unmasked_secrets
# ---------------------------------------------------------------------------


def test_unmasked_secrets_clean(tmp_path: Path):
    md = _md(tmp_path, "Nothing secret here, just prose.\n")
    report = qa.check_unmasked_secrets(md)
    assert report.ok == 1


def test_unmasked_secrets_detects_raw_key(tmp_path: Path):
    md = _md(tmp_path, "key = AKIAIOSFODNN7EXAMPLE\n")
    report = qa.check_unmasked_secrets(md)
    assert any("threat-model.md" in i for i in report.issues)


def test_unmasked_secrets_scans_yaml_too(tmp_path: Path):
    md = _md(tmp_path, "clean prose\n")
    (tmp_path / "threat-model.yaml").write_text("aws: AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    report = qa.check_unmasked_secrets(md, output_dir=tmp_path)
    assert any("threat-model.yaml" in i for i in report.issues)


# ---------------------------------------------------------------------------
# check_unfounded_perimeter_claims
# ---------------------------------------------------------------------------


def test_perimeter_clean(tmp_path: Path):
    md = _md(tmp_path, "The app uses a WAF in production.\n")
    report = qa.check_unfounded_perimeter_claims(md)
    assert report.ok == 1


def test_perimeter_flags_absence_claim(tmp_path: Path):
    md = _md(tmp_path, "The deployment has no WAF protecting it.\n")
    report = qa.check_unfounded_perimeter_claims(md)
    assert any("WAF-absence" in i for i in report.issues)


def test_perimeter_skips_code_fence(tmp_path: Path):
    md = _md(
        tmp_path,
        "```yaml\nnote: no WAF here is inside a fence\n```\n",
    )
    report = qa.check_unfounded_perimeter_claims(md)
    assert report.ok == 1


def test_perimeter_truncates_many(tmp_path: Path):
    lines = "\n".join("the system has no WAF deployed" for _ in range(30))
    md = _md(tmp_path, lines + "\n")
    report = qa.check_unfounded_perimeter_claims(md)
    assert any("truncated" in i for i in report.issues)


# ---------------------------------------------------------------------------
# check_invariants
# ---------------------------------------------------------------------------


def test_invariants_clean_no_log(tmp_path: Path):
    md = _md(tmp_path, "no log present\n")
    report = qa.check_invariants(md)
    assert report.ok == 1


def test_invariants_phase_burst_flagged(tmp_path: Path):
    md = _md(tmp_path, "x\n")
    log = tmp_path / ".agent-run.log"
    ts = "2026-06-14T10:00:00"
    # Same timestamp, phases 3,4,5,8 -> outside legal {4,5,6,7} and >3 distinct.
    log.write_text(
        "\n".join(f"{ts} PHASE_START [Phase {p}/11]" for p in (3, 4, 5, 8)) + "\n",
        encoding="utf-8",
    )
    report = qa.check_invariants(md)
    assert any("PHASE_BURST" in i for i in report.issues)


def test_invariants_legal_burst_not_flagged(tmp_path: Path):
    md = _md(tmp_path, "x\n")
    log = tmp_path / ".agent-run.log"
    ts = "2026-06-14T10:00:00"
    log.write_text(
        "\n".join(f"{ts} PHASE_START [Phase {p}/11]" for p in (4, 5, 6, 7)) + "\n",
        encoding="utf-8",
    )
    report = qa.check_invariants(md)
    assert report.ok == 1


# ---------------------------------------------------------------------------
# _slice_management_summary / check_ms_structure
# ---------------------------------------------------------------------------


def test_slice_ms_none_when_absent():
    assert qa._slice_management_summary("## 1. Overview\nbody\n") is None


def test_slice_ms_found():
    text = "## Management Summary\nbody\n## 1. Overview\nx\n"
    res = qa._slice_management_summary(text)
    assert res is not None
    start, end, heading = res
    assert "Management Summary" in heading


_GOOD_MS = (
    "## Management Summary\n"
    "### Verdict\n"
    '<blockquote style="border-left: 3px solid #dc2626; padding:1px">worst case</blockquote>\n'
    "### Security Posture & Top Threats\n"
    "body\n"
    "### Top Mitigations\n"
    "body\n"
    "### Operational Strengths\n"
    "body\n"
    "## 1. Overview\n"
)


def test_ms_structure_clean(tmp_path: Path):
    md = _md(tmp_path, _GOOD_MS)
    report, _ = qa.check_ms_structure(md)
    assert report.ok == 1, report.issues


def test_ms_structure_missing_heading(tmp_path: Path):
    md = _md(tmp_path, "## 1. Overview\nno MS here\n")
    report, _ = qa.check_ms_structure(md)
    assert any("missing" in i for i in report.issues)


def test_ms_structure_strips_numeric_prefix(tmp_path: Path):
    md = _md(
        tmp_path,
        _GOOD_MS.replace("## Management Summary", "## 1. Management Summary"),
    )
    report, new_text = qa.check_ms_structure(md)
    assert any("Stripped numeric prefix" in f for f in report.fixes)
    assert "## Management Summary" in new_text


def test_ms_structure_renames_legacy_subsection(tmp_path: Path):
    src = _GOOD_MS.replace("### Top Mitigations", "### Follow-up Actions")
    md = _md(tmp_path, src)
    report, new_text = qa.check_ms_structure(md)
    assert any("Renamed" in f for f in report.fixes)
    assert "### Mitigations" in new_text


def test_ms_structure_strips_forbidden_heading(tmp_path: Path):
    src = _GOOD_MS.replace("### Operational Strengths", "### Risk Distribution\n### Operational Strengths")
    md = _md(tmp_path, src)
    report, new_text = qa.check_ms_structure(md)
    assert any("forbidden" in f.lower() for f in report.fixes)
    assert "QA-STRIPPED" in new_text


def test_ms_structure_missing_verdict_blockquote(tmp_path: Path):
    src = _GOOD_MS.replace(
        '<blockquote style="border-left: 3px solid #dc2626; padding:1px">worst case</blockquote>\n',
        "plain verdict text\n",
    )
    md = _md(tmp_path, src)
    report, _ = qa.check_ms_structure(md)
    assert any("blockquote" in i for i in report.issues)


def test_ms_structure_missing_subsection(tmp_path: Path):
    src = _GOOD_MS.replace("### Operational Strengths\nbody\n", "")
    md = _md(tmp_path, src)
    report, _ = qa.check_ms_structure(md)
    assert any("Operational Strengths" in i for i in report.issues)


def test_ms_structure_critical_attack_tree_required(tmp_path: Path):
    # 2 criticals via risk distribution, no Critical Attack Tree section.
    src = "**Risk Distribution:** Critical: 2 · High: 1 · Medium: 0 · Low: 0 · **Total: 3**\n\n" + _GOOD_MS
    md = _md(tmp_path, src)
    report, _ = qa.check_ms_structure(md)
    assert any("Critical Attack Tree" in i for i in report.issues)


def test_ms_structure_skip_walkthroughs_suppresses_tree(tmp_path: Path):
    src = "**Risk Distribution:** Critical: 2 · High: 1 · Medium: 0 · Low: 0 · **Total: 3**\n\n" + _GOOD_MS
    md = _md(tmp_path, src)
    (tmp_path / ".skill-config.json").write_text('{"SKIP_ATTACK_WALKTHROUGHS": true}', encoding="utf-8")
    report, _ = qa.check_ms_structure(md)
    assert not any("Critical Attack Tree" in i for i in report.issues)


# ---------------------------------------------------------------------------
# _resolve_contract_run_flags
# ---------------------------------------------------------------------------


def test_resolve_flags_defaults_standard(tmp_path: Path):
    flags = qa._resolve_contract_run_flags(tmp_path)
    assert flags["depth"] == "standard"
    assert flags["is_quick_depth"] is False


def test_resolve_flags_quick_from_config(tmp_path: Path):
    (tmp_path / ".skill-config.json").write_text('{"assessment_depth": "quick"}', encoding="utf-8")
    flags = qa._resolve_contract_run_flags(tmp_path)
    assert flags["is_quick_depth"] is True
    assert flags["skip_attack_walkthroughs"] is True


def test_resolve_flags_reads_yaml_depth(tmp_path: Path):
    (tmp_path / "threat-model.yaml").write_text("meta:\n  assessment_depth: thorough\n", encoding="utf-8")
    flags = qa._resolve_contract_run_flags(tmp_path)
    assert flags["depth"] == "thorough"


def test_resolve_flags_check_requirements_flag(tmp_path: Path):
    (tmp_path / ".skill-config.json").write_text('{"check_requirements": true, "verbose": true}', encoding="utf-8")
    flags = qa._resolve_contract_run_flags(tmp_path)
    assert flags["check_requirements"] is True
    assert flags["verbose_report"] is True


# ---------------------------------------------------------------------------
# check_contract — empty/non-mapping
# ---------------------------------------------------------------------------


def test_contract_required_subsection_pattern_match(tmp_path: Path):
    qa._PrePass.reset()
    contract = tmp_path / "c.yaml"
    contract.write_text(
        "document:\n  order:\n    - sec\n"
        "sections:\n"
        "  sec:\n"
        "    heading: '## 7. Security Architecture'\n"
        "    required_subsections:\n"
        "      - level: 3\n"
        "        pattern: '7\\.2 .*Identity.*'\n",
        encoding="utf-8",
    )
    md = _md(tmp_path, "## 7. Security Architecture\n### 7.2 Identity Controls\nbody\n")
    report = qa.check_contract(md, contract)
    assert not any("required subsection missing" in i for i in report.issues)


def test_contract_required_subsection_invalid_pattern(tmp_path: Path):
    qa._PrePass.reset()
    contract = tmp_path / "c.yaml"
    contract.write_text(
        "document:\n  order:\n    - sec\n"
        "sections:\n"
        "  sec:\n"
        "    heading: '## 7. Security Architecture'\n"
        "    required_subsections:\n"
        "      - level: 3\n"
        "        pattern: '(unclosed'\n",
        encoding="utf-8",
    )
    md = _md(tmp_path, "## 7. Security Architecture\nbody\n")
    report = qa.check_contract(md, contract)
    assert any("invalid required_subsection pattern" in i for i in report.issues)


def test_contract_required_subsection_order_violation(tmp_path: Path):
    qa._PrePass.reset()
    contract = tmp_path / "c.yaml"
    contract.write_text(
        "document:\n  order:\n    - sec\n"
        "sections:\n"
        "  sec:\n"
        "    heading: '## 7. Security Architecture'\n"
        "    required_subsections:\n"
        "      - level: 3\n        title: 'Alpha Sub'\n"
        "      - level: 3\n        title: 'Beta Sub'\n",
        encoding="utf-8",
    )
    # Beta before Alpha -> subsection order violation.
    md = _md(
        tmp_path,
        "## 7. Security Architecture\n### Beta Sub\nb\n### Alpha Sub\na\n",
    )
    report = qa.check_contract(md, contract)
    assert any("required subsection order violation" in i for i in report.issues)


def test_contract_empty_file_flagged(tmp_path: Path):
    contract = tmp_path / "empty.yaml"
    contract.write_text("", encoding="utf-8")
    md = _md(tmp_path, "## 1. Overview\n")
    report = qa.check_contract(md, contract)
    assert any("not a mapping or empty" in i for i in report.issues)


# ---------------------------------------------------------------------------
# _safe_eval_cond
# ---------------------------------------------------------------------------


def test_safe_eval_cond_empty_false():
    assert qa._safe_eval_cond("", {}) is False


def test_safe_eval_cond_true():
    # _safe_cond only supports bare-name / not-name / membership grammar.
    assert qa._safe_eval_cond("check_requirements", {"check_requirements": True}) is True


def test_safe_eval_cond_not_name():
    assert qa._safe_eval_cond("not is_quick_depth", {"is_quick_depth": False}) is True


def test_safe_eval_cond_membership():
    assert qa._safe_eval_cond("depth in [quick, standard]", {"depth": "quick"}) is True


def test_safe_eval_cond_malformed_returns_false():
    assert qa._safe_eval_cond("@@@ not valid @@@", {}) is False


# ---------------------------------------------------------------------------
# _heading_to_section_id
# ---------------------------------------------------------------------------


def test_heading_to_section_id_match():
    contract = {"sections": {"sysov": {"heading": "## 1. System Overview"}}}
    assert qa._heading_to_section_id("## 1. System Overview", contract) == "sysov"


def test_heading_to_section_id_no_match():
    contract = {"sections": {"sysov": {"heading": "## 1. System Overview"}}}
    assert qa._heading_to_section_id("## 99. Nope", contract) is None


def test_heading_to_section_id_ignores_non_dict_section():
    contract = {"sections": {"bad": "not a dict", "ok": {"heading": "## X"}}}
    assert qa._heading_to_section_id("## X", contract) == "ok"


# ---------------------------------------------------------------------------
# _classify_plan_status
# ---------------------------------------------------------------------------


def test_classify_plan_status_pass():
    status, actionable = qa._classify_plan_status([], [])
    assert status == "pass"


def test_classify_plan_status_manual_review():
    actions = [{"fragments_to_rewrite": []}]
    status, actionable = qa._classify_plan_status(["issue"], actions)
    assert status == "manual_review"
    assert actionable is False


def test_classify_plan_status_fail():
    actions = [{"fragments_to_rewrite": [".fragments/x.md"]}]
    status, actionable = qa._classify_plan_status(["issue"], actions)
    assert status == "fail"
    assert actionable is True


# ---------------------------------------------------------------------------
# Cosmetic severity gating (2026-06-22)
# ---------------------------------------------------------------------------


def test_action_severity_cosmetic_types(monkeypatch):
    monkeypatch.delenv("APPSEC_QA_COSMETIC_BLOCKING", raising=False)
    for t in (
        "diagram_compactness",
        "chain_compactness",
        "walkthrough_depth",
        "relevant_findings_bullet_list",
        "recon_iam_bridge",
    ):
        assert qa._action_severity(t) == "cosmetic"


def test_action_severity_blocking_types(monkeypatch):
    monkeypatch.delenv("APPSEC_QA_COSMETIC_BLOCKING", raising=False)
    # chain_tid_consistency and walkthrough_coverage are deliberately blocking.
    for t in (
        "mermaid_syntax",
        "missing_section",
        "table_schema_drift",
        "chain_tid_consistency",
        "walkthrough_coverage",
        "unclassified",
    ):
        assert qa._action_severity(t) == "blocking"


def test_action_severity_env_override_forces_blocking(monkeypatch):
    monkeypatch.setenv("APPSEC_QA_COSMETIC_BLOCKING", "1")
    assert qa._action_severity("diagram_compactness") == "blocking"


def test_classify_plan_status_cosmetic_only():
    actions = [{"fragments_to_rewrite": [".fragments/x.md"], "severity": "cosmetic"}]
    status, actionable = qa._classify_plan_status(["issue"], actions)
    assert status == "cosmetic_advisory"
    # cosmetic-only must NOT be actionable so the loop short-circuits.
    assert actionable is False


def test_classify_plan_status_mixed_blocking_wins():
    actions = [
        {"fragments_to_rewrite": [".fragments/x.md"], "severity": "cosmetic"},
        {"fragments_to_rewrite": [".fragments/y.md"], "severity": "blocking"},
    ]
    status, actionable = qa._classify_plan_status(["issue"], actions)
    assert status == "fail"
    assert actionable is True


def test_classify_plan_status_no_severity_key_is_blocking():
    # Backward-compat: an action without a `severity` key is treated as blocking.
    actions = [{"fragments_to_rewrite": [".fragments/x.md"]}]
    status, _ = qa._classify_plan_status(["issue"], actions)
    assert status == "fail"


def test_cmd_repair_plan_cosmetic_only_returns_4(tmp_path: Path, monkeypatch):
    md = _md(tmp_path, "## x\n")
    out = tmp_path / "out"
    plan = {
        "status": "cosmetic_advisory",
        "actions": [
            {
                "type": "diagram_compactness",
                "raw_issue": "§2.4: 9 nodes (>7)",
                "fragments_to_rewrite": [".fragments/architecture-diagrams.md"],
                "severity": "cosmetic",
            }
        ],
    }
    monkeypatch.setattr(qa, "build_repair_plan", lambda *a, **k: (plan, None))
    rc = qa.cmd_repair_plan(md, out, _minimal_contract(tmp_path))
    assert rc == 4
    # Plan is kept on disk so the Completion Summary can surface the advisory.
    assert (out / ".qa-repair-plan.json").is_file()


# ---------------------------------------------------------------------------
# build_repair_plan / cmd_repair_plan
# ---------------------------------------------------------------------------

_DOC_WITH_MISSING_SECTION = (
    "## Management Summary\n"
    "### Verdict\n"
    '<blockquote style="border-left: 3px solid #dc2626;">x</blockquote>\n'
    "### Security Posture & Top Threats\n"
    "### Top Mitigations\n"
    "### Operational Strengths\n"
    "**Risk Distribution:** Critical: 0 · High: 1 · Medium: 0 · Low: 0\n"
    "## 1. System Overview\nbody\n"
)


def _minimal_contract(tmp_path: Path) -> Path:
    contract = tmp_path / "contract.yaml"
    contract.write_text(
        "document:\n"
        "  order:\n"
        "    - system_overview\n"
        "    - assets\n"
        "sections:\n"
        "  system_overview:\n"
        "    heading: '## 1. System Overview'\n"
        "  assets:\n"
        "    heading: '## 4. Assets'\n",
        encoding="utf-8",
    )
    return contract


def test_build_repair_plan_missing_section(tmp_path: Path):
    qa._PrePass.reset()
    contract = _minimal_contract(tmp_path)
    md = _md(tmp_path, _DOC_WITH_MISSING_SECTION)
    plan, report = qa.build_repair_plan(md, tmp_path, contract)
    assert plan["issue_count"] >= 1
    assert any(a["type"] == "missing_section" for a in plan["actions"])
    assert plan["status"] in ("fail", "manual_review")


def test_build_repair_plan_no_missing_section_when_present(tmp_path: Path):
    # When both contract sections are present, no missing_section action fires
    # (other folded checks may still flag table-schema/infobox issues — those
    # are out of scope for the section-presence branch under test).
    qa._PrePass.reset()
    contract = _minimal_contract(tmp_path)
    md = _md(
        tmp_path,
        _DOC_WITH_MISSING_SECTION + "## 4. Assets\nassets body\n",
    )
    plan, report = qa.build_repair_plan(md, tmp_path, contract)
    assert not any(a.get("type") == "missing_section" for a in plan["actions"])
    assert not any("expected section missing" in i for i in report.issues)


def test_build_repair_plan_required_subsection_missing(tmp_path: Path):
    qa._PrePass.reset()
    contract = tmp_path / "c.yaml"
    contract.write_text(
        "document:\n  order:\n    - sec7\n"
        "sections:\n"
        "  sec7:\n"
        "    heading: '## 7. Security Architecture'\n"
        "    required_subsections:\n"
        "      - level: 3\n"
        "        title: 'Mandatory Sub'\n",
        encoding="utf-8",
    )
    md = _md(tmp_path, "## 7. Security Architecture\nbody without the sub\n")
    plan, _ = qa.build_repair_plan(md, tmp_path, contract)
    assert any(a["type"] == "missing_required_subsection" for a in plan["actions"])


def test_build_repair_plan_section_order_violation(tmp_path: Path):
    qa._PrePass.reset()
    contract = tmp_path / "c.yaml"
    contract.write_text(
        "document:\n  order:\n    - first\n    - second\n"
        "sections:\n"
        "  first:\n    heading: '## 1. Alpha'\n"
        "  second:\n    heading: '## 2. Beta'\n",
        encoding="utf-8",
    )
    # Beta appears BEFORE Alpha -> order violation.
    md = _md(tmp_path, "## 2. Beta\nb\n## 1. Alpha\na\n")
    plan, _ = qa.build_repair_plan(md, tmp_path, contract)
    assert any(a["type"] == "section_order_drift" for a in plan["actions"])


def test_build_repair_plan_forbidden_ms_heading(tmp_path: Path):
    qa._PrePass.reset()
    contract = tmp_path / "c.yaml"
    contract.write_text(
        "document:\n  order:\n    - ms\n"
        "sections:\n"
        "  management_summary:\n"
        "    heading: '## Management Summary'\n"
        "    forbidden_subsection_patterns:\n"
        "      - 'Forbidden Thing'\n"
        "  ms:\n    heading: '## Management Summary'\n",
        encoding="utf-8",
    )
    md = _md(
        tmp_path,
        "## Management Summary\n### Forbidden Thing\nbody\n## 1. Next\n",
    )
    plan, _ = qa.build_repair_plan(md, tmp_path, contract)
    assert any(a["type"] == "forbidden_ms_heading" for a in plan["actions"])


def test_cmd_repair_plan_missing_md_returns_2(tmp_path: Path):
    contract = _minimal_contract(tmp_path)
    rc = qa.cmd_repair_plan(tmp_path / "nope.md", tmp_path / "out", contract)
    assert rc == 2


def test_cmd_repair_plan_creates_output_dir(tmp_path: Path):
    # output_dir does not pre-exist — cmd_repair_plan must mkdir it.
    qa._PrePass.reset()
    contract = _minimal_contract(tmp_path)
    md = tmp_path / "threat-model.md"
    md.write_text(_DOC_WITH_MISSING_SECTION, encoding="utf-8")
    out = tmp_path / "fresh-out"
    rc = qa.cmd_repair_plan(md, out, contract)
    assert out.is_dir()
    assert rc in (1, 3)


def test_cmd_repair_plan_violations_returns_1_or_3(tmp_path: Path):
    qa._PrePass.reset()
    contract = _minimal_contract(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    md = out / "threat-model.md"
    md.write_text(_DOC_WITH_MISSING_SECTION, encoding="utf-8")
    rc = qa.cmd_repair_plan(md, out, contract)
    assert rc in (1, 3)
    assert (out / ".qa-repair-plan.json").is_file()


# ---------------------------------------------------------------------------
# _check_requirements_violated_coverage
# ---------------------------------------------------------------------------


def test_req_violated_coverage_no_merged_file_skips(tmp_path: Path):
    md = _md(tmp_path, "x\n")
    report = qa.Report("x")
    qa._check_requirements_violated_coverage(md, tmp_path, report)
    assert not report.issues


def test_req_violated_coverage_flags_missing_annotation(tmp_path: Path):
    md = _md(
        tmp_path,
        '| <a id="t-001"></a>T-001 | comp | cat | scenario text no annotation |\n',
    )
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"t_id": "T-001", "source": "requirements-compliance"}]}),
        encoding="utf-8",
    )
    report = qa.Report("x")
    qa._check_requirements_violated_coverage(md, tmp_path, report)
    assert any("Violated:" in i for i in report.issues)


def test_req_violated_coverage_ok_when_annotated(tmp_path: Path):
    md = _md(
        tmp_path,
        '| <a id="t-001"></a>T-001 | comp | cat | Violated: [R-1](http://x) here |\n',
    )
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"t_id": "T-001", "source": "requirements-compliance"}]}),
        encoding="utf-8",
    )
    report = qa.Report("x")
    qa._check_requirements_violated_coverage(md, tmp_path, report)
    assert not report.issues


def test_req_violated_coverage_empty_merged_present(tmp_path: Path):
    # merged file present but no req-sourced threats -> still scans, no issues
    md = _md(tmp_path, "no rows\n")
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"t_id": "T-009", "source": "stride"}]}),
        encoding="utf-8",
    )
    report = qa.Report("x")
    qa._check_requirements_violated_coverage(md, tmp_path, report)
    assert not report.issues


# ---------------------------------------------------------------------------
# _is_suspicious_evidence_line
# ---------------------------------------------------------------------------


def test_suspicious_blank_line():
    susp, reason = qa._is_suspicious_evidence_line("   ", ".py")
    assert susp and "blank" in reason


def test_suspicious_noise_brace():
    susp, reason = qa._is_suspicious_evidence_line("}", ".js")
    assert susp and "noise-only" in reason


def test_suspicious_comment_python():
    susp, reason = qa._is_suspicious_evidence_line("# a comment", ".py")
    assert susp and "comment-only" in reason


def test_suspicious_shebang_exempt():
    susp, _ = qa._is_suspicious_evidence_line("#!/usr/bin/env python", ".py")
    assert susp is False


def test_suspicious_block_comment_continuation():
    susp, reason = qa._is_suspicious_evidence_line("* docstring", ".java")
    assert susp and "block-comment" in reason


def test_suspicious_real_code_not_flagged():
    susp, _ = qa._is_suspicious_evidence_line("const x = require('db');", ".js")
    assert susp is False


# ---------------------------------------------------------------------------
# _GrepCache / _replay_absence_grep
# ---------------------------------------------------------------------------


def test_replay_absence_grep_counts_hits(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\nimport os\n", encoding="utf-8")
    n = qa._replay_absence_grep(tmp_path, r"import os", ["."])
    assert n == 2


def test_replay_absence_grep_invalid_pattern_none(tmp_path: Path):
    assert qa._replay_absence_grep(tmp_path, "(unclosed", ["."]) is None


def test_replay_absence_grep_unresolvable_path_none(tmp_path: Path):
    # path escapes repo root -> not any_resolved -> None
    assert qa._replay_absence_grep(tmp_path, "x", ["../../outside"]) is None


def test_replay_absence_grep_with_cache(tmp_path: Path):
    (tmp_path / "b.py").write_text("secret_token = 1\n", encoding="utf-8")
    cache = qa._GrepCache()
    n1 = qa._replay_absence_grep(tmp_path, "secret_token", ["."], cache=cache)
    n2 = qa._replay_absence_grep(tmp_path, "secret_token", ["."], cache=cache)
    assert n1 == n2 == 1


def test_replay_absence_grep_bre_alternation(tmp_path: Path):
    (tmp_path / "c.py").write_text("foo\nbar\n", encoding="utf-8")
    n = qa._replay_absence_grep(tmp_path, r"foo\|bar", ["."])
    assert n == 2


def test_grepcache_get_files_single_file(tmp_path: Path):
    f = tmp_path / "x.py"
    f.write_text("a\n")
    cache = qa._GrepCache()
    files = cache.get_files(f, None)
    assert files == [f]


def test_grepcache_skips_node_modules(tmp_path: Path):
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "junk.js").write_text("x\n")
    (tmp_path / "real.js").write_text("y\n")
    cache = qa._GrepCache()
    files = cache.get_files(tmp_path, None)
    names = [f.name for f in files]
    assert "real.js" in names
    assert "junk.js" not in names


# ---------------------------------------------------------------------------
# check_evidence_integrity
# ---------------------------------------------------------------------------


def test_evidence_integrity_no_files_warns(tmp_path: Path):
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert any("neither" in w for w in report.warnings)


def test_evidence_integrity_clean(tmp_path: Path):
    code = tmp_path / "app.py"
    code.write_text("line1\nimport secrets\nline3\n", encoding="utf-8")
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"t_id": "T-001", "evidence": {"file": "app.py", "line": 2}}]}),
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert report.ok == 1
    assert not report.issues


def test_evidence_integrity_missing_file(tmp_path: Path):
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"t_id": "T-001", "evidence": {"file": "ghost.py", "line": 1}}]}),
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert any("evidence_missing_file" in i for i in report.issues)


def test_evidence_integrity_config_absence_not_flagged(tmp_path: Path):
    """A config-posture absence finding (iac_type set, line 0) legitimately
    cites a deliberately-missing artifact — the absence IS the evidence (e.g.
    IAC-050 package-lock.json not committed). It must not be flagged as a
    hallucinated evidence_missing_file."""
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps(
            {
                "threats": [
                    {
                        "t_id": "T-012",
                        "iac_type": "npm_config",
                        "evidence": {"file": "package-lock.json", "line": 0},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert not any("evidence_missing_file" in i for i in report.issues)


def test_evidence_integrity_iac_with_line_still_flagged(tmp_path: Path):
    """The carve-out is line-0 only: an iac_type finding that cites a real line
    in a non-existent file is still a hallucinated citation and IS flagged."""
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps(
            {
                "threats": [
                    {
                        "t_id": "T-099",
                        "iac_type": "dockerfile",
                        "evidence": {"file": "ghost.Dockerfile", "line": 7},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert any("evidence_missing_file" in i for i in report.issues)


def test_evidence_integrity_line_out_of_range(tmp_path: Path):
    code = tmp_path / "small.py"
    code.write_text("only one line\n", encoding="utf-8")
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"t_id": "T-002", "evidence": {"file": "small.py", "line": 99}}]}),
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert any("out_of_range" in i for i in report.issues)


def test_evidence_integrity_suspicious_line(tmp_path: Path):
    code = tmp_path / "c.py"
    code.write_text("# a comment line\n", encoding="utf-8")
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"t_id": "T-003", "evidence": {"file": "c.py", "line": 1}}]}),
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert any("suspicious" in i for i in report.issues)


def test_evidence_integrity_absence_grep_drift(tmp_path: Path):
    # repo_root must differ from output_dir; the absence grep skips files under
    # output_dir, so the searched code must live in a separate repo dir.
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    code = repo / "auth.py"
    code.write_text("def login(): pass\ncsrf_protect()\n", encoding="utf-8")
    (out / ".threats-merged.json").write_text(
        json.dumps(
            {
                "threats": [
                    {
                        "t_id": "T-004",
                        "evidence": {"file": "auth.py", "line": 1},
                        "controls_absent_evidence": [
                            {
                                "pattern": "csrf_protect",
                                "search_paths": ["."],
                                "hit_count": 0,
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(out, repo)
    assert any("absence_grep_drift" in i for i in report.issues)


def test_evidence_integrity_absence_grep_unresolved_warns(tmp_path: Path):
    code = tmp_path / "auth.py"
    code.write_text("x = 1\n", encoding="utf-8")
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps(
            {
                "threats": [
                    {
                        "t_id": "T-005",
                        "evidence": {"file": "auth.py", "line": 1},
                        "controls_absent_evidence": [{"pattern": "(bad", "search_paths": ["."], "hit_count": 0}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert any("absence_grep_unresolved" in w for w in report.warnings)


def test_evidence_integrity_malformed_merged_warns(tmp_path: Path):
    (tmp_path / ".threats-merged.json").write_text("{not json", encoding="utf-8")
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert any("could not parse" in w for w in report.warnings)


def test_evidence_integrity_yaml_fallback(tmp_path: Path):
    code = tmp_path / "app.py"
    code.write_text("line1\nreal code line\n", encoding="utf-8")
    (tmp_path / "threat-model.yaml").write_text(
        "threats:\n  - t_id: T-006\n    evidence:\n      file: app.py\n      line: 2\n",
        encoding="utf-8",
    )
    report = qa.check_evidence_integrity(tmp_path, tmp_path)
    assert report.ok == 1
