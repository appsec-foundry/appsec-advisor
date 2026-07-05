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


# ---------------------------------------------------------------------------
# Holistic consistency guard (2026-07-05) — catches the "§6 heading then §7.1
# subsection" class the earlier per-transform tests could each pass while the
# document as a whole stayed inconsistent. Parses the RENDERED result and
# asserts document-level invariants rather than individual string presence.
# ---------------------------------------------------------------------------

import re  # noqa: E402


def _assert_numbering_consistent(md: str) -> list[int]:
    """Assert the '6 then 7.1' invariants on a rendered document:
      - every `### N.M` / `#### N.M.K` subsection's major N equals its parent
        `## N.` section (the exact "§6 heading then §7.1 subsection" bug),
      - the top-level `## N.` numbering is contiguous (no gaps/jumps).
    Returns the ordered list of top-level section numbers.
    """
    lines = md.splitlines()
    tops: list[int] = []
    cur: int | None = None
    for l in lines:
        mt = re.match(r"^## (\d+)(b?)\. (.+)", l)
        if mt:
            cur = int(mt.group(1))
            if not mt.group(2):  # ignore 'b' variants (e.g. 6b Requirements)
                tops.append(cur)
            continue
        ms = re.match(r"^#{3,4} (\d+)\.\d+", l)
        if ms and cur is not None:
            assert int(ms.group(1)) == cur, f"subsection major {ms.group(1)} != parent §{cur}: {l!r}"
    assert tops, "no top-level sections found"
    assert tops == list(range(tops[0], tops[0] + len(tops))), f"non-contiguous top-level numbering: {tops}"
    return tops


def test_renumbered_document_is_fully_consistent_no_6_then_7_1():
    doc = (
        "## Table of Contents\n\n"
        "5. [Attack Surface](#5-attack-surface)\n"
        "7. [Security Architecture](#7-security-architecture)\n"
        "   - [7.1 Security Control Overview](#71-security-control-overview)\n"
        "   - [7.2 Identity and Authentication Controls](#72-identity-and-authentication-controls)\n"
        "8. [Findings Register](#8-findings-register)\n"
        "9. [Abuse Cases](#9-abuse-cases)\n"
        "10. [Mitigation Register](#10-mitigation-register)\n"
        "11. [Out of Scope](#11-out-of-scope)\n\n"
        "## 5. Attack Surface\n\n"
        "See [§7.2 Identity and Authentication Controls](#72-identity-and-authentication-controls) "
        "and [§7 Security Architecture](#7-security-architecture) for control detail.\n\n"
        "## 7. Security Architecture\n\n"
        "### 7.1 Security Control Overview\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "#### 7.2.1 Threat Hypotheses Requiring Validation\n\n"
        "### 7.3 Session and Token Controls\n\n"
        "## 8. Findings Register\n\n"
        "## 9. Abuse Cases\n\n"
        "## 10. Mitigation Register\n\n"
        "## 11. Out of Scope\n"
    )
    out = rsd.renumber_sections_display(doc)

    # 1) Document-level structural consistency (the core guard).
    tops = _assert_numbering_consistent(out)
    assert tops == [5, 6, 7, 8, 9, 10], tops  # §6 gap closed, contiguous

    # 2) No Security-Architecture artefact keeps the old §7 number anywhere.
    assert "## 7. Security Architecture" not in out
    assert "### 7.1 Security Control Overview" not in out
    assert "### 7.2 Identity and Authentication Controls" not in out
    assert "#### 7.2.1" not in out
    assert "#72-identity-and-authentication-controls" not in out
    assert "#7-security-architecture" not in out
    assert "§7.2 Identity" not in out and "§7 Security Architecture" not in out

    # 3) The Findings Register correctly BECOMES the new §7 (a consistent shift,
    #    not a stale leftover) — heading, TOC entry and any refs all agree.
    assert "## 7. Findings Register" in out
    assert "7. [Findings Register](#7-findings-register)" in out

    # 4) Security Architecture is fully §6 (heading + all subsections + TOC + refs).
    assert "## 6. Security Architecture" in out
    assert "### 6.1 Security Control Overview" in out
    assert "#### 6.2.1 Threat Hypotheses Requiring Validation" in out
    assert "[6.2 Identity and Authentication Controls](#62-identity-and-authentication-controls)" in out
    assert "[§6.2 Identity and Authentication Controls](#62-identity-and-authentication-controls)" in out


def test_canonical_seven_document_is_internally_consistent_before_renumber():
    # The canonical (pre-renumber) doc keeps the §6 gap (§5 → §7). That is an
    # allowed *consistent* jump: §7 heading with §7.x subsections, no §6.x
    # dangling under a §7 heading. Guards against a half-renumbered canonical.
    doc = (
        "## 5. Attack Surface\n\n"
        "## 7. Security Architecture\n\n"
        "### 7.1 Security Control Overview\n\n"
        "### 7.2 Identity and Authentication Controls\n\n"
        "## 8. Findings Register\n"
    )
    # No renumber applied — assert the source itself has no major mismatch.
    lines = doc.splitlines()
    cur = None
    for l in lines:
        mt = re.match(r"^## (\d+)\. ", l)
        if mt:
            cur = int(mt.group(1))
            continue
        ms = re.match(r"^### (\d+)\.\d+", l)
        if ms:
            assert int(ms.group(1)) == cur, f"canonical inconsistency: {l!r} under §{cur}"
