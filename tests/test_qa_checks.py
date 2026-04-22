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
