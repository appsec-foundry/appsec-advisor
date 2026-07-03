"""Tests for scripts/renumber_sections_display.py — the cosmetic §7-§11 -> §6-§10
display renumbering pass (juice-shop 2026-07-03 user request).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import renumber_sections_display as rsd  # noqa: E402


def _canonical(body: str) -> str:
    """Prepend the trigger marker so the guard doesn't no-op the sample."""
    return "## 7. Security Architecture\n\n" + body


def test_top_level_headings_renumbered():
    doc = (
        "## 7. Security Architecture\n\n"
        "## 8. Findings Register\n\n"
        "## 9. Abuse Cases\n\n"
        "## 10. Mitigation Register\n\n"
        "## 11. Out of Scope\n"
    )
    out = rsd.renumber_sections_display(doc)
    assert "## 6. Security Architecture" in out
    assert "## 7. Findings Register" in out
    assert "## 8. Abuse Cases" in out
    assert "## 9. Mitigation Register" in out
    assert "## 10. Out of Scope" in out
    assert "## 11." not in out


def test_7b_requirements_compliance_renumbered():
    doc = _canonical("## 7b. Requirements Compliance\n")
    out = rsd.renumber_sections_display(doc)
    assert "## 6b. Requirements Compliance" in out


def test_subsection_heading_no_stray_period():
    """Regression: the first implementation injected "6.2." (extra period) —
    subsection headings use "N.M Title" (space only), unlike top-level "N. Title"."""
    doc = _canonical("### 7.2 Identity and Authentication Controls\n")
    out = rsd.renumber_sections_display(doc)
    assert "### 6.2 Identity and Authentication Controls" in out
    assert "6.2." not in out


def test_sub_subsection_h4_renumbered_no_stray_period():
    doc = _canonical("#### 7.2.1 Threat Hypotheses Requiring Validation\n")
    out = rsd.renumber_sections_display(doc)
    assert "#### 6.2.1 Threat Hypotheses Requiring Validation" in out
    assert "6.2.1." not in out


def test_anchor_ids_and_hrefs_renumbered_consistently():
    doc = _canonical(
        '<a id="7-security-architecture"></a>\n'
        "### 7.2 Identity and Authentication Controls\n\n"
        "See [§7.2](#72-identity-and-authentication-controls) and [§7](#7-security-architecture).\n"
    )
    out = rsd.renumber_sections_display(doc)
    assert 'id="6-security-architecture"' in out
    assert "(#6-security-architecture)" in out
    assert "(#62-identity-and-authentication-controls)" in out
    assert "72-identity" not in out


def test_toc_top_level_ordered_list_renumbered():
    # A real document always carries the actual heading alongside any TOC/prose
    # reference to it — anchor remapping is learned from the heading (see
    # _collect_heading_renumbers), so the two must appear together here too.
    doc = (
        "5. [Attack Surface](#5-attack-surface)\n"
        "7. [Security Architecture](#7-security-architecture)\n"
        "8. [Findings Register](#8-findings-register)\n"
        "## 7. Security Architecture\n"
        "## 8. Findings Register\n"
    )
    out = rsd.renumber_sections_display(doc)
    assert "5. [Attack Surface](#5-attack-surface)" in out  # untouched, out of scope
    assert "6. [Security Architecture](#6-security-architecture)" in out
    assert "7. [Findings Register](#7-findings-register)" in out


def test_toc_subsection_bracket_entries_renumbered():
    doc = _canonical(
        "   - [7.2 Identity and Authentication Controls](#72-identity-and-authentication-controls)\n"
        "### 7.2 Identity and Authentication Controls\n"
    )
    out = rsd.renumber_sections_display(doc)
    assert "[6.2 Identity and Authentication Controls](#62-identity-and-authentication-controls)" in out


def test_inline_section_symbol_prose_renumbered():
    doc = _canonical(
        "### 7.3 Session and Token Controls\n"
        "Handled in [§7.3 Session and Token Controls](#73-session-and-token-controls) and §8.\n"
    )
    out = rsd.renumber_sections_display(doc)
    assert "§6.3 Session and Token Controls" in out
    assert "(#63-session-and-token-controls)" in out
    assert "and §7." in out


def test_html_comment_markers_renumbered():
    doc = _canonical("<!-- §7.1 MECHANICAL-FROZEN — DO NOT EDIT -->\n")
    out = rsd.renumber_sections_display(doc)
    assert "<!-- §6.1 MECHANICAL-FROZEN" in out


def test_gap_note_box_removed():
    doc = _canonical(
        "> _Section numbering is non-contiguous: §6 was retired in a prior revision. The remaining sections keep their original numbers so existing cross-references stay valid._\n"
    )
    out = rsd.renumber_sections_display(doc)
    assert "non-contiguous" not in out


def test_unrelated_numbers_left_untouched():
    """§1-§5, bare prose counts, CWE ids, and CVSS-shaped decimals must never be
    touched — only the exact §7-§11 in-scope tokens are in play."""
    doc = _canonical(
        "§1 System Overview, §5 Attack Surface, CVSS 7.2, CWE-79, "
        "**7 structural threats**, port 8080, the year 2026, 11 findings total.\n"
    )
    out = rsd.renumber_sections_display(doc)
    assert "§1 System Overview" in out
    assert "§5 Attack Surface" in out
    assert "CVSS 7.2" in out
    assert "CWE-79" in out
    assert "**7 structural threats**" in out
    assert "port 8080" in out
    assert "2026" in out
    assert "11 findings total" in out


def test_noop_when_canonical_marker_absent():
    """No '## 7. Security Architecture' heading (already renumbered, or a
    --quick run where §7 never rendered) -> untouched, not a partial shift."""
    doc = "## 6. Security Architecture\n\n## 7. Findings Register\n"
    out = rsd.renumber_sections_display(doc)
    assert out == doc


def test_double_run_is_a_noop_not_a_double_shift():
    """Regression: a naive in-scope check treated the NEW "7" (from old "8")
    as still-in-scope on a second run and silently shifted it again."""
    doc = _canonical("## 8. Findings Register\n")
    once = rsd.renumber_sections_display(doc)
    twice = rsd.renumber_sections_display(once)
    assert once == twice
    assert "## 7. Findings Register" in once


def test_main_dry_run_prints_diff_and_does_not_write(tmp_path, capsys):
    p = tmp_path / "threat-model.md"
    p.write_text(_canonical("## 8. Findings Register\n"), encoding="utf-8")
    original = p.read_text(encoding="utf-8")
    rc = rsd.main([str(p), "--dry-run"])
    assert rc == 0
    assert p.read_text(encoding="utf-8") == original
    out = capsys.readouterr().out
    assert "-## 8. Findings Register" in out
    assert "+## 7. Findings Register" in out


def test_main_writes_renumbered_file(tmp_path):
    p = tmp_path / "threat-model.md"
    p.write_text(_canonical("## 8. Findings Register\n"), encoding="utf-8")
    rc = rsd.main([str(p)])
    assert rc == 0
    assert "## 7. Findings Register" in p.read_text(encoding="utf-8")


def test_main_missing_file_returns_error(tmp_path, capsys):
    rc = rsd.main([str(tmp_path / "nope.md")])
    assert rc == 1
    assert "no such file" in capsys.readouterr().err
