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

REPO_ROOT   = Path(__file__).parent.parent
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


def test_unknown_subcommand_exits_nonzero(tmp_path: Path):
    md = _write_minimal_model(tmp_path, "# Threat Model\n")
    result = _run(["unknown_subcommand", str(md)])
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# CLI: xrefs subcommand on a clean file
# ---------------------------------------------------------------------------

_CLEAN_XREF_CONTENT = textwrap.dedent("""\
    ## Management Summary

    ## 8. Threat Register

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
    ## 8. Threat Register

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


def test_t_id_re_no_false_positive():
    assert qa.T_ID_RE.search("AT-001") is None  # prefix — must be word boundary


# ---------------------------------------------------------------------------
# Risk distribution regex
# ---------------------------------------------------------------------------

def test_risk_dist_re_parses_counts():
    line = "**Risk Distribution:** Critical: 2 · High: 5 · Medium: 3 · Low: 1 · **Total: 11**"
    m = qa.RISK_DIST_RE.search(line)
    assert m is not None
    assert m.group(1) == "2"   # Critical
    assert m.group(2) == "5"   # High
    assert m.group(5) == "11"  # Total


def test_risk_dist_re_no_match_on_empty():
    assert qa.RISK_DIST_RE.search("nothing here") is None


# ---------------------------------------------------------------------------
# Sprint 2 Item #5 — placeholders (Check 6) and yaml/md consistency (Check 4)
# ---------------------------------------------------------------------------


class TestPlaceholdersCheck:
    def test_clean_document_has_no_issues(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(textwrap.dedent("""
            # Threat Model

            ## Management Summary

            Verdict: the system is in a mostly acceptable posture with documented gaps.

            **Risk Distribution:** Critical: 1 · High: 2 · Medium: 3 · Low: 0
        """).strip(), encoding="utf-8")
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
        md.write_text("```\nprint(\"TODO\")\n```\n", encoding="utf-8")
        r = qa.check_placeholders(md)
        assert r.issues == []

    def test_multiple_placeholders_deduped_by_kind(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(
            "_pending_\n"
            "_pending_\n"
            "_pending_\n",
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
        assert r.warnings   # non-blocking warning surfaces the absence

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
                ## Threat Register
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
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert '"check": "placeholders"' in r.stdout

    def test_placeholders_dirty_exits_1(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("_pending_\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "placeholders", str(md)],
            capture_output=True, text=True,
        )
        assert r.returncode == 1

    def test_yaml_md_usage_error(self, tmp_path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "yaml_md", str(tmp_path / "x.md")],
            capture_output=True, text=True,
        )
        assert r.returncode == 2  # missing yaml arg

    def test_yaml_md_clean(self, tmp_path):
        md = tmp_path / "threat-model.md"
        yml = tmp_path / "threat-model.yaml"
        md.write_text("| [F-001](#f-001) | one |\n")
        yml.write_text("meta: {schema_version: 1}\nthreats: [{id: F-001}]\nmitigations: []\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "yaml_md", str(md), str(yml)],
            capture_output=True, text=True,
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
            capture_output=True, text=True,
        )
        assert r.returncode == 0
        assert '"check": "cell_format"' in r.stdout

    def test_cell_format_cli_applies_fix_in_place(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(self._TABLE_WITH_MULTILINK)
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "cell_format", str(md)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0  # auto-fix success is exit 0
        assert "<br/>" in md.read_text()

    def test_cell_format_fixes_comma_separated_ids(self, tmp_path):
        """LLM-authored 'Linked Threats' cells often use commas between IDs;
        the check must stack them with <br/> too, not just space-separated.
        """
        md = tmp_path / "threat-model.md"
        md.write_text(textwrap.dedent("""\
            | Asset | Linked Threats |
            |---|---|
            | Users | [T-003](#t-003), [T-004](#t-004), [T-013](#t-013) |
        """))
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 1, report.as_dict()
        assert (
            "[T-003](#t-003)<br/>[T-004](#t-004)<br/>[T-013](#t-013)"
            in new_text
        )

    def test_cell_format_fixes_semicolon_separated_ids(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(textwrap.dedent("""\
            | Risk | Linked |
            |---|---|
            | Injection | [T-001](#t-001); [T-002](#t-002) |
        """))
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 1
        assert "[T-001](#t-001)<br/>[T-002](#t-002)" in new_text

    def test_cell_format_fixes_mixed_separators(self, tmp_path):
        # A row with comma AND space separators in the same cell.
        md = tmp_path / "threat-model.md"
        md.write_text(textwrap.dedent("""\
            | Component | Linked Threats |
            |---|---|
            | API | [T-001](#t-001), [T-002](#t-002) [T-003](#t-003) |
        """))
        report, new_text = qa.check_cell_format(md)
        assert len(report.fixes) == 1
        assert (
            "[T-001](#t-001)<br/>[T-002](#t-002)<br/>[T-003](#t-003)"
            in new_text
        )

    def test_cell_format_comma_idempotent(self, tmp_path):
        """Running the check twice on a comma-separated table must
        stabilise after the first pass."""
        md = tmp_path / "threat-model.md"
        md.write_text(textwrap.dedent("""\
            | A | Linked |
            |---|---|
            | X | [T-001](#t-001), [T-002](#t-002) |
        """))
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
            capture_output=True, text=True,
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
            capture_output=True, text=True,
        )
        assert r.returncode == 0


# ---------------------------------------------------------------------------
# summary_bullets — run-on `(1) … (2) …` prose vs. bullet list
# ---------------------------------------------------------------------------


class TestSummaryBullets:
    def test_inline_numbered_prose_is_flagged(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(
            "**Gap summary:** The three control gaps are: "
            "(1) no CSP; (2) no WAF; (3) no rate limit.\n"
        )
        report = qa.check_summary_bullets(md)
        assert len(report.issues) == 1
        assert "Gap summary" in report.issues[0]

    def test_bulleted_gap_summary_is_clean(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(
            "**Gap summary:**\n"
            "\n"
            "- no CSP\n"
            "- no WAF\n"
            "- no rate limit\n"
        )
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
        md.write_text(
            "```\n"
            "**Gap summary:** The gaps are: (1) one; (2) two.\n"
            "```\n"
        )
        report = qa.check_summary_bullets(md)
        assert len(report.issues) == 0

    def test_cli_exits_0_on_clean(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text("# Clean\n")
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "summary_bullets", str(md)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0

    def test_cli_exits_1_on_violation(self, tmp_path):
        md = tmp_path / "threat-model.md"
        md.write_text(
            "**Gap summary:** Three gaps: (1) a; (2) b; (3) c.\n"
        )
        r = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "summary_bullets", str(md)],
            capture_output=True, text=True,
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
# check_auth_method_decomposition — §7.3 IAM per-auth-method contract rule
# ---------------------------------------------------------------------------


class TestAuthMethodDecomposition:
    """Exercises the `auth_method_decomposition` rule declared in
    sections-contract.yaml under security_architecture.domain_required_rules.

    The rule enforces that every row of the §7.3 IAM control table has a
    matching `#### <method>` subsection with its own sequenceDiagram and a
    `**Findings in this flow:**` trailer.  T-IDs in the trailer must be a
    subset of the row's Linked Threats cell (bidirectional consistency).
    """

    # Contract templates. The rule only runs when the contract declares
    # `auth_method_decomposition` — so every test writes its own minimal
    # contract alongside the MD.

    _CONTRACT_BASE = textwrap.dedent("""\
        document:
          order: []
        severity_taxonomy: {}
        sections:
          security_architecture:
            heading: "## 7. Security Architecture"
            heading_numbered: true
            fragment_type: markdown
            fragment: "security-architecture.md"
            domain_required_rules:
              "7.3 Identity & Access Management":
                - rule: "auth_method_decomposition"
                  table_column: "Control"
                  heading_level: 4
                  trailer_label: "Findings in this flow"
                  match_style: "token-subset"
                  synonyms: []
                  enforcement: "ENFORCEMENT"
        """)

    def _write_contract(self, tmp_path, enforcement: str = "error",
                        synonyms_yaml: str = "[]") -> Path:
        c = self._CONTRACT_BASE.replace("ENFORCEMENT", enforcement)
        c = c.replace("synonyms: []", f"synonyms: {synonyms_yaml}")
        path = tmp_path / "contract.yaml"
        path.write_text(c)
        return path

    def _write_md(self, tmp_path, body: str) -> Path:
        md = tmp_path / "threat-model.md"
        # Prepend an outer ## heading so the §7.3 slice is bounded at EOF too.
        md.write_text("## 7. Security Architecture\n\n" + body + "\n")
        return md

    # -----------------------------------------------------------------------
    # Full-coverage happy path
    # -----------------------------------------------------------------------

    _FULL_SEC73 = textwrap.dedent("""\
        ### 7.3 Identity & Access Management

        Authentication uses RS256 JWT signing.

        | Domain | Control | Implementation | Effectiveness | Linked Threats |
        |--------|---------|----------------|---------------|----------------|
        | IAM | Password Login | handler | 🔶 Weak | [T-001](#t-001) — SQLi |
        | IAM | Google OAuth | provider | 🔶 Weak | [T-002](#t-002) — open redirect |

        #### Password Login Flow

        Vulnerable sequence.

        ```mermaid
        sequenceDiagram
          User->>API: login
        ```

        **Findings in this flow:** [T-001](#t-001) — SQLi

        #### Google OAuth Flow

        OAuth sequence.

        ```mermaid
        sequenceDiagram
          User->>API: /oauth/cb
        ```

        **Findings in this flow:** [T-002](#t-002) — open redirect

        """)

    def test_full_coverage_error_mode_passes(self, tmp_path):
        contract = self._write_contract(tmp_path, enforcement="error")
        md = self._write_md(tmp_path, self._FULL_SEC73)
        report = qa.check_auth_method_decomposition(md, contract)
        assert report.issues == [], report.issues
        assert report.warnings == []
        assert report.ok == 1

    # -----------------------------------------------------------------------
    # Missing subsection for a row
    # -----------------------------------------------------------------------

    def test_missing_subsection_for_row_is_flagged(self, tmp_path):
        contract = self._write_contract(tmp_path, enforcement="error")
        # Two rows in the control table but only one matching #### subsection.
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Domain | Control | Implementation | Effectiveness | Linked Threats |
            |--------|---------|----------------|---------------|----------------|
            | IAM | Password Login | handler | 🔶 Weak | [T-001](#t-001) — SQLi |
            | IAM | Google OAuth | provider | 🔶 Weak | [T-002](#t-002) — open redirect |

            #### Password Login Flow

            ```mermaid
            sequenceDiagram
              User->>API: login
            ```

            **Findings in this flow:** [T-001](#t-001) — SQLi

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        joined = " ".join(report.issues)
        assert "Google OAuth" in joined
        assert "no #### subsection matches control-table row" in joined

    # -----------------------------------------------------------------------
    # Missing sequenceDiagram inside a ####
    # -----------------------------------------------------------------------

    def test_missing_sequence_diagram_in_subsection_is_flagged(self, tmp_path):
        contract = self._write_contract(tmp_path, enforcement="error")
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Domain | Control | Implementation | Effectiveness | Linked Threats |
            |--------|---------|----------------|---------------|----------------|
            | IAM | Password Login | handler | 🔶 Weak | [T-001](#t-001) — SQLi |

            #### Password Login Flow

            No diagram here.

            **Findings in this flow:** [T-001](#t-001) — SQLi

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        joined = " ".join(report.issues)
        assert "missing `sequenceDiagram`" in joined

    # -----------------------------------------------------------------------
    # Missing Findings-trailer
    # -----------------------------------------------------------------------

    def test_missing_findings_trailer_is_flagged(self, tmp_path):
        contract = self._write_contract(tmp_path, enforcement="error")
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Domain | Control | Implementation | Effectiveness | Linked Threats |
            |--------|---------|----------------|---------------|----------------|
            | IAM | Password Login | handler | 🔶 Weak | [T-001](#t-001) — SQLi |

            #### Password Login Flow

            ```mermaid
            sequenceDiagram
              User->>API: login
            ```

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        joined = " ".join(report.issues)
        assert "Findings in this flow" in joined
        assert "trailer" in joined

    # -----------------------------------------------------------------------
    # T-ID in trailer not in matching row's Linked Threats cell
    # -----------------------------------------------------------------------

    def test_trailer_tid_not_in_row_is_flagged(self, tmp_path):
        contract = self._write_contract(tmp_path, enforcement="error")
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Domain | Control | Implementation | Effectiveness | Linked Threats |
            |--------|---------|----------------|---------------|----------------|
            | IAM | Password Login | handler | 🔶 Weak | [T-001](#t-001) — SQLi |

            #### Password Login Flow

            ```mermaid
            sequenceDiagram
              User->>API: login
            ```

            **Findings in this flow:** [T-001](#t-001) — SQLi, [T-099](#t-099) — rogue

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        joined = " ".join(report.issues)
        assert "T-099" in joined
        assert "bidirectional consistency" in joined

    # -----------------------------------------------------------------------
    # Token-subset matching
    # -----------------------------------------------------------------------

    def test_token_subset_match_allows_suffix_in_heading(self, tmp_path):
        """row 'Google OAuth' should match heading 'Google OAuth 2.0 Flow'
        via token-subset (tokens {google, oauth} ⊆ {google, oauth, 2, 0, flow})."""
        contract = self._write_contract(tmp_path, enforcement="error")
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Domain | Control | Implementation | Effectiveness | Linked Threats |
            |--------|---------|----------------|---------------|----------------|
            | IAM | Google OAuth | provider | 🔶 Weak | [T-002](#t-002) — open redirect |

            #### Google OAuth 2.0 Flow

            ```mermaid
            sequenceDiagram
              User->>Google: SSO
            ```

            **Findings in this flow:** [T-002](#t-002) — open redirect

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        assert report.issues == [], report.issues

    # -----------------------------------------------------------------------
    # Synonym override
    # -----------------------------------------------------------------------

    def test_synonyms_override_lets_mismatched_names_pass(self, tmp_path):
        """row 'JWT Signing' shares a subsection 'JWT Issuance' — token-subset
        alone would fail (signing ∉ heading tokens), synonyms override fixes it."""
        syn_yaml = ('[{"row": "JWT Signing", '
                    '"heading": "JWT Issuance"}]')
        contract = self._write_contract(
            tmp_path, enforcement="error", synonyms_yaml=syn_yaml
        )
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Domain | Control | Implementation | Effectiveness | Linked Threats |
            |--------|---------|----------------|---------------|----------------|
            | IAM | JWT Signing | insecurity.ts:56 | 🔶 Weak | [T-001](#t-001) — RSA key |

            #### JWT Issuance

            ```mermaid
            sequenceDiagram
              API->>Auth: sign
            ```

            **Findings in this flow:** [T-001](#t-001) — RSA key

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        assert report.issues == [], report.issues

    # -----------------------------------------------------------------------
    # No rule declared in contract — check is a no-op
    # -----------------------------------------------------------------------

    def test_no_rule_in_contract_is_noop(self, tmp_path):
        # Bare contract without domain_required_rules at all.
        (tmp_path / "contract.yaml").write_text(
            "document:\n  order: []\n"
            "sections:\n"
            "  security_architecture:\n"
            "    heading: \"## 7. Security Architecture\"\n"
        )
        md = self._write_md(tmp_path, "### 7.3 Identity & Access Management\n")
        report = qa.check_auth_method_decomposition(
            md, tmp_path / "contract.yaml"
        )
        assert report.ok == 1
        assert report.issues == []
        assert report.warnings == []

    # -----------------------------------------------------------------------
    # enforcement: warning moves issues into warnings
    # -----------------------------------------------------------------------

    def test_warning_mode_diverts_issues_to_warnings(self, tmp_path):
        contract = self._write_contract(tmp_path, enforcement="warning")
        # One row + one matching subsection but the subsection has NO
        # sequenceDiagram AND no trailer — in error mode this is 2 issues,
        # both of which warning-mode demotes to report.warnings.
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Domain | Control | Implementation | Effectiveness | Linked Threats |
            |--------|---------|----------------|---------------|----------------|
            | IAM | Password Login | handler | 🔶 Weak | [T-001](#t-001) — SQLi |

            #### Password Login Flow

            Prose without a diagram or a trailer.

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        assert report.issues == [], report.issues
        assert len(report.warnings) == 2, report.warnings
        joined = " ".join(report.warnings)
        assert "sequenceDiagram" in joined
        assert "Findings in this flow" in joined
        assert report.ok == 1

    # -----------------------------------------------------------------------
    # §7.3 absent from MD is handled as no-op
    # -----------------------------------------------------------------------

    def test_section_73_absent_is_noop(self, tmp_path):
        contract = self._write_contract(tmp_path, enforcement="error")
        md = self._write_md(tmp_path, "### 7.2 Key Architectural Risks\n\nbody\n")
        report = qa.check_auth_method_decomposition(md, contract)
        assert report.ok == 1
        assert report.issues == []

    # -----------------------------------------------------------------------
    # Structural gates — heading_pattern + required_trailers + required_body_elements
    # (Fix 7: §7.3 auth-flow mini-report shape)
    # -----------------------------------------------------------------------

    _CONTRACT_WITH_STRUCTURE = textwrap.dedent("""\
        document:
          order: []
        severity_taxonomy: {}
        sections:
          security_architecture:
            heading: "## 7. Security Architecture"
            heading_numbered: true
            fragment_type: markdown
            fragment: "security-architecture.md"
            domain_required_rules:
              "7.3 Identity & Access Management":
                - rule: "auth_method_decomposition"
                  table_column: "Control"
                  heading_level: 4
                  trailer_label: "Findings in this flow"
                  heading_pattern: '^7\\.3\\.\\d+\\s+.+\\s+Flow$'
                  required_trailers:
                    - "Risk assessment"
                    - "Findings in this flow"
                  required_body_elements:
                    - "sequenceDiagram"
                  match_style: "token-subset"
                  synonyms: []
                  enforcement: "error"
        """)

    def _write_contract_with_structure(self, tmp_path) -> Path:
        p = tmp_path / "contract.yaml"
        p.write_text(self._CONTRACT_WITH_STRUCTURE)
        return p

    def test_heading_pattern_requires_7_3_N_prefix(self, tmp_path):
        contract = self._write_contract_with_structure(tmp_path)
        # Heading is "#### Password Login Flow" — lacks 7.3.N prefix.
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Control | Linked Threats |
            |---|---|
            | Password Login | [T-001](#t-001) — SQLi |

            #### Password Login Flow

            Flow intro.

            ```mermaid
            sequenceDiagram
              User->>API: login
            ```

            **Risk assessment:** Critical risk summary. **Residual risk:** Critical.

            **Findings in this flow:** [T-001](#t-001) — SQLi

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        joined = " ".join(report.issues)
        assert "heading does not match required pattern" in joined
        assert "7.3.N" in joined or "7\\.3\\.\\d+" in joined

    def test_required_trailer_risk_assessment_missing(self, tmp_path):
        contract = self._write_contract_with_structure(tmp_path)
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Control | Linked Threats |
            |---|---|
            | Password Login | [T-001](#t-001) — SQLi |

            #### 7.3.1 Password Login Flow

            Flow intro.

            ```mermaid
            sequenceDiagram
              User->>API: login
            ```

            **Findings in this flow:** [T-001](#t-001) — SQLi

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        joined = " ".join(report.issues)
        assert "Risk assessment" in joined
        assert "missing" in joined.lower()

    def test_required_body_element_sequence_diagram_absent(self, tmp_path):
        contract = self._write_contract_with_structure(tmp_path)
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Control | Linked Threats |
            |---|---|
            | Password Login | [T-001](#t-001) — SQLi |

            #### 7.3.1 Password Login Flow

            Flow without a diagram.

            **Risk assessment:** Critical. **Residual risk:** Critical.

            **Findings in this flow:** [T-001](#t-001) — SQLi

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        joined = " ".join(report.issues)
        assert "sequenceDiagram" in joined

    def test_full_structured_block_is_clean(self, tmp_path):
        contract = self._write_contract_with_structure(tmp_path)
        body = textwrap.dedent("""\
            ### 7.3 Identity & Access Management

            | Control | Linked Threats |
            |---|---|
            | Password Login | [T-001](#t-001) — SQLi |

            #### 7.3.1 Password Login Flow

            The login endpoint is vulnerable.

            ```mermaid
            sequenceDiagram
              User->>API: login
            ```

            | Control | Implementation | Effectiveness | Finding |
            |---|---|---|---|
            | SQL Parameterization | Absent | Missing | [T-001](#t-001) |

            **Risk assessment:** Critical risk. **Residual risk:** Critical — unauth bypass possible.

            **Findings in this flow:** [T-001](#t-001) — SQLi

            """)
        md = self._write_md(tmp_path, body)
        report = qa.check_auth_method_decomposition(md, contract)
        assert report.issues == [], report.issues
        assert report.ok == 1


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
        ### Security Posture at a Glance

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

        **Threat actors.** Two actors sit on the left.

        - **Shop User** — legitimate registered customer.
        - **Anonymous Internet Attacker** — no account.

        **Attack paths (numbered arrows in the diagram):**

        - <a id="path-injection"></a>**① Injection** (Anonymous Internet Attacker → Application Tier) — user input flows into a server-side interpreter.
          - Findings:
            - [F-001](#f-001) — SQL Injection
          - Impact: Full Admin Takeover

        - <a id="path-auth-bypass"></a>**② Auth Bypass** (Anonymous Internet Attacker → Application Tier) — credentials weak.
          - Findings:
            - [F-002](#f-002) — JWT alg:none
          - Impact: Full Admin Takeover

        - <a id="path-xss"></a>**③ XSS** (Shop User → Client Tier) — scripts in stored content.
          - Findings:
            - [F-003](#f-003) — Stored XSS
          - Impact: Customer Session Hijack
        """)

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

    def test_n4_flags_missing_attack_class_bullets(self, tmp_path):
        """If the narrative has no glyph bullets at all, N4 must still fire."""
        broken = self._CLEAN_POSTURE_SECTION.replace(
            '- <a id="path-injection"></a>**① Injection**',
            "- **Injection** (no glyph)",
        ).replace(
            '- <a id="path-auth-bypass"></a>**② Auth Bypass**',
            "- **Auth Bypass** (no glyph)",
        ).replace(
            '- <a id="path-xss"></a>**③ XSS**',
            "- **XSS** (no glyph)",
        )
        md = _write_minimal_model(tmp_path, broken)
        report = qa.check_security_posture_structure(md)
        assert any(i.startswith("N4:") for i in report.issues), report.issues

    def test_e2_flags_missing_glyph_on_attack_arrow(self, tmp_path):
        """If attack arrows have no glyphs, E2 must still fire."""
        broken = self._CLEAN_POSTURE_SECTION.replace(
            'ANON ==>|" ① Injection "| SERVER\n',
            "ANON ==> SERVER\n",
        ).replace(
            'ANON ==>|" ② Auth Bypass "| SERVER\n',
            "",
        ).replace(
            'SHOPUSER ==>|" ③ XSS "| BROWSER\n',
            "",
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
            {"raw_issue": issues[0], "type": "posture_renderer_bug",
             "fragments_to_rewrite": []},
            {"raw_issue": issues[1], "type": "posture_unknown",
             "fragments_to_rewrite": []},
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
            {"raw_issue": "y", "type": "t",
             "fragments_to_rewrite": [".fragments/security-architecture.md"]},
        ]
        status, actionable = qa._classify_plan_status(issues, actions)
        assert status == "fail"
        assert actionable is True

    def test_clean_md_end_to_end_returns_pass(self, tmp_path):
        """Smoke test: an MD with no contract violations returns status=pass
        through the full `build_repair_plan` pipeline."""
        md = _write_minimal_model(
            tmp_path,
            "## Management Summary\n\nNothing to see here.\n\n"
            "## 8. Threat Register\n\n_no threats_\n",
        )
        plan, _ = qa.build_repair_plan(md, tmp_path, qa.DEFAULT_CONTRACT_PATH)
        # Bare-bones MD will violate many contract rules — the important
        # invariant is that the status field is one of the documented values
        # and `actionable` is consistent with the action set.
        assert plan["status"] in {"pass", "fail", "manual_review"}
        assert plan["actionable"] == any(
            a.get("fragments_to_rewrite") for a in plan["actions"]
        )


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
            __import__("json").dumps(merged), encoding="utf-8",
        )

    def test_unknown_flag_does_not_abort_the_run(self, tmp_path):
        """The script must tolerate an unrecognised flag rather than printing
        `usage:` and exiting with argparse's default code 2."""
        self._make_threats_file(tmp_path)
        result = subprocess.run(
            [
                sys.executable, str(self.SCRIPT),
                str(tmp_path),
                "--threats-file", str(tmp_path / ".threats-merged.json"),  # bogus
                "--depth", "quick",
            ],
            capture_output=True, text=True,
        )
        # The script should NOT exit with the argparse `usage:` failure path.
        assert result.returncode == 0, (
            f"unexpected exit {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
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
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"unexpected exit {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
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

    def test_b2_still_flags_bullet_with_no_finding_links(self, tmp_path):
        """Negative regression: a bullet without ANY F-/T-link must still fire B2."""
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

            **Threat actors.** One.

            - **Anonymous** — no account.

            **Attack paths (numbered arrows in the diagram):**

            - <a id="path-injection"></a>**① Injection** (Anonymous → Server) — flows.
              - Findings:
                - SQL Injection (no link)
              - Impact: Full Takeover
            """)
        md = _write_minimal_model(tmp_path, section)
        report = qa.check_security_posture_structure(md)
        assert any(
            i.startswith("B2:") and "no F-NNN/T-NNN link" in i
            for i in report.issues
        ), report.issues


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
        "password login", "oauth", "oidc", "openid", "saml",
        "totp", "2fa", "mfa", "passkey", "webauthn",
        "password reset", "change password", "session",
        "magic link", "magic-link", "jwt",
    ]

    @pytest.mark.parametrize("name", [
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
    ])
    def test_recognises_real_auth_methods(self, name):
        assert qa._row_is_auth_method(name, self.DEFAULT_WHITELIST), name

    @pytest.mark.parametrize("name", [
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
    ])
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
        assert qa._row_is_auth_method("Standard Password-based Login",
                                     ["password login"])

    def test_ignores_non_string_entries(self):
        """A malformed contract entry must not crash the helper."""
        assert qa._row_is_auth_method("OAuth", [None, 42, "oauth"])  # type: ignore[list-item]


class TestAuthMethodDecompositionWhitelistIntegration:
    """End-to-end: a §7.3 with mixed rows + the default whitelist must NOT
    flag implementation rows for missing #### Flow sub-sections."""

    @pytest.fixture
    def section_73_with_mixed_rows(self, tmp_path):
        """§7.3 with one real auth method (`Password Login`) plus three
        non-method rows (`Password Hashing`, `Login Rate Limiting`,
        `express-jwt middleware`). Only the auth-method row gets a
        sub-section — the others should not trigger warnings under the
        whitelist filter."""
        body = textwrap.dedent("""\
            ## 7. Security Architecture

            ### 7.3 Identity & Access Management

            | Domain | Control | Implementation | Effectiveness | Linked Threats |
            |--------|---------|----------------|---------------|----------------|
            | IAM | Password Login | `routes/login.ts` | 🔶 Weak | [T-001](#t-001) |
            | IAM | Password Hashing | `lib/insecurity.ts:43` | ❌ Missing | [T-002](#t-002) |
            | IAM | Login Rate Limiting | none | ❌ Missing | — |
            | IAM | express-jwt middleware | v0.1.3 | 🔶 Weak | — |

            #### 7.3.1 Password Login Flow

            Endpoint: `POST /rest/user/login`. Implementation: `routes/login.ts:34`.

            ```mermaid
            sequenceDiagram
                User->>API: POST /login
            ```

            **Risk assessment:** Critical — SQL injection bypass present. **Residual risk:** Critical — bypass.

            **Findings in this flow:** [T-001](#t-001) — SQL Injection
            """)
        return _write_minimal_model(tmp_path, body)

    def test_whitelist_filters_non_method_rows(
        self, section_73_with_mixed_rows
    ):
        """With the default whitelist, only the real auth-method row
        ('Password Login') is required to have a sub-section. The three
        implementation rows must NOT trigger 'no #### subsection matches
        control-table row …' warnings."""
        report = qa.check_auth_method_decomposition(section_73_with_mixed_rows)
        # Implementation/cross-cutting rows MUST NOT produce per-row
        # missing-subsection warnings.
        unwanted_substrings = [
            "Password Hashing",
            "Login Rate Limiting",
            "express-jwt middleware",
        ]
        for w in report.warnings:
            for s in unwanted_substrings:
                assert s not in w, (
                    f"unexpected warning targeting non-method row: {w}"
                )


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
        assert idx["F-001"][1] == "f-001"   # canonical anchor for the F-alias

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

            ## 8. Threat Register

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
            assert doubled not in second, (
                f"label {label!r} was suffixed twice"
            )

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


class TestThreatModelOutputSchemaTitleRequired:
    """Pin the schema requirement that `title` is mandatory on threats[].

    Loosening this makes the cross-reference labelling invariant
    (AGENTS.md §4a) silently degrade — `_load_label_index` returns
    empty entries and the linkifier emits bare links.
    """

    def test_schema_lists_title_required_on_threats(self):
        import yaml as _yaml
        schema_path = (
            REPO_ROOT / "schemas" / "threat-model.output.schema.yaml"
        )
        schema = _yaml.safe_load(schema_path.read_text())
        threat_schema = schema["properties"]["threats"]["items"]
        assert "title" in threat_schema["required"], (
            "title MUST be required on threats[] — see AGENTS.md §4a"
        )
        assert threat_schema["properties"]["title"]["type"] == "string"
        assert threat_schema["properties"]["title"]["maxLength"] == 60, (
            "title maxLength MUST be 60 — keeps table columns scannable. "
            "See AGENTS.md §4a. Do NOT raise this ceiling."
        )

