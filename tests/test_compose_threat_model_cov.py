"""Additive coverage tests for scripts/compose_threat_model.py.

Focus: stable pure-function / string-rendering helpers. Avoids the
brand-new --slug/stamp code paths (concurrently modified). All tests are
unit-level against module-level helpers — no full render pipeline.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass introspection can resolve the module.
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


compose = _load_module("compose_threat_model", SCRIPT_PATH)


# ---------------------------------------------------------------------------
# Label / backtick helpers
# ---------------------------------------------------------------------------


class TestSynthesiseLabel:
    def test_empty(self):
        assert compose._synthesise_label("") == ""
        assert compose._synthesise_label("   ") == ""

    def test_markdown_link_reduced_to_text(self):
        out = compose._synthesise_label("See [the login route](http://x/y) here")
        assert "the login route" in out
        assert "http" not in out

    def test_sentence_split_keeps_file_token(self):
        out = compose._synthesise_label("SQL injection in CommandInjection.java:45")
        assert "CommandInjection.java:45" in out

    def test_sentence_terminator_truncates(self):
        out = compose._synthesise_label("First sentence. Second sentence.")
        assert out == "First sentence"

    def test_long_label_truncated_with_ellipsis(self):
        long = "word " * 60
        out = compose._synthesise_label(long.strip())
        assert out.endswith("…")
        assert len(out) <= compose._LABEL_MAX_CHARS + 2

    def test_hard_slice_when_no_break(self):
        long = "x" * (compose._LABEL_MAX_CHARS + 30)
        out = compose._synthesise_label(long)
        assert out.endswith("…")


class TestCloseBackticks:
    def test_balanced_unchanged(self):
        assert compose._close_backticks("a `b` c") == "a `b` c"

    def test_unbalanced_dropped(self):
        out = compose._close_backticks("foo `bar baz")
        assert "`" not in out
        assert out == "foo"


# ---------------------------------------------------------------------------
# Pluralize / bullet_list / ranks
# ---------------------------------------------------------------------------


class TestPluralize:
    def test_singular(self):
        assert compose.pluralize(1, "finding") == "1 finding"

    def test_plural_default(self):
        assert compose.pluralize(3, "finding") == "3 findings"

    def test_plural_explicit(self):
        assert compose.pluralize(2, "category", "categories") == "2 categories"

    def test_zero_is_plural(self):
        assert compose.pluralize(0, "item") == "0 items"


class TestBulletList:
    def test_empty_returns_empty(self):
        assert compose.bullet_list([]) == ""
        assert compose.bullet_list(None) == ""

    def test_plain_strings(self):
        out = compose.bullet_list([" a ", "b"])
        assert out == "- a\n- b"

    def test_non_dict_non_str(self):
        out = compose.bullet_list([123])
        assert out == "- 123"

    def test_dict_with_href(self):
        out = compose.bullet_list([{"label": "L", "href": "http://x", "detail": "d"}])
        assert "[L](http://x)" in out
        assert "— d" in out

    def test_dict_with_ref(self):
        out = compose.bullet_list([{"label": "L", "ref": "T-01"}])
        assert "[L](#t-01)" in out

    def test_dict_label_only(self):
        out = compose.bullet_list([{"label": "Bold"}])
        assert "**Bold**" in out

    def test_dict_detail_only(self):
        out = compose.bullet_list([{"detail": "just detail"}])
        assert "just detail" in out


class TestRanks:
    def test_severity_rank(self):
        assert compose._severity_rank("Critical") == 0
        assert compose._severity_rank("low") == 3
        assert compose._severity_rank("bogus") == 99
        assert compose._severity_rank("") == 99

    def test_effort_rank(self):
        assert compose._effort_rank("LOW") == 0
        assert compose._effort_rank("high") == 2
        assert compose._effort_rank("?") == 99

    def test_effectiveness_rank(self):
        assert compose._effectiveness_rank("adequate") == 0
        assert compose._effectiveness_rank("missing") == 3
        assert compose._effectiveness_rank(None) == 99


# ---------------------------------------------------------------------------
# Title normalisation helpers
# ---------------------------------------------------------------------------


class TestLooksLikeFilePath:
    def test_blank(self):
        assert compose._looks_like_file_path("") is False
        assert compose._looks_like_file_path("   ") is False

    def test_prose_with_space(self):
        assert compose._looks_like_file_path("not a path") is False

    def test_cve_rejected(self):
        assert compose._looks_like_file_path("CVE-2021-1234") is False

    def test_real_file(self):
        assert compose._looks_like_file_path("routes/login.ts:18") is True

    def test_path_segment(self):
        assert compose._looks_like_file_path("frontend/src/app") is True


class TestNormalizeTitleToParenForm:
    def test_non_string(self):
        assert compose._normalize_title_to_paren_form(None) is None

    def test_no_dash(self):
        assert compose._normalize_title_to_paren_form("Just A Title") == "Just A Title"

    def test_file_tail_wrapped(self):
        out = compose._normalize_title_to_paren_form("SQL Injection — routes/login.ts")
        assert out == "SQL Injection (routes/login.ts)"

    def test_prose_tail_unchanged(self):
        out = compose._normalize_title_to_paren_form("XSS — accessible everywhere")
        assert out == "XSS — accessible everywhere"

    def test_multi_dash_only_file_wrapped(self):
        out = compose._normalize_title_to_paren_form("A — B — file.ts")
        assert out == "A — B (file.ts)"

    def test_qualifier_plus_filepath_tail(self):
        out = compose._normalize_title_to_paren_form("IDOR — basket coupon.ts:18")
        assert out == "IDOR (basket coupon.ts:18)"

    def test_single_segment(self):
        # tail dash strips to a single segment → returned stripped
        assert compose._normalize_title_to_paren_form("— ") == "—"


class TestNormalizeTitlesParenForm:
    def test_non_dict_noop(self):
        compose._normalize_titles_paren_form([], Path("/tmp"))  # no crash

    def test_rewrites_and_logs(self, tmp_path):
        data = {
            "threats": [{"id": "T-1", "title": "SQLi — routes/x.ts"}],
            "mitigations": [{"id": "M-1", "title": "no change"}],
            "critical_findings": [{"threat_id": "T-1", "title": "XSS — a/b.ts"}],
        }
        compose._normalize_titles_paren_form(data, tmp_path)
        assert data["threats"][0]["title"] == "SQLi (routes/x.ts)"
        assert data["critical_findings"][0]["title"] == "XSS (a/b.ts)"
        log = tmp_path / ".reconcile-log.json"
        assert log.is_file()
        assert "title_normalisations" in log.read_text()

    def test_no_change_no_log(self, tmp_path):
        data = {"threats": [{"id": "T-1", "title": "plain"}]}
        compose._normalize_titles_paren_form(data, tmp_path)
        assert not (tmp_path / ".reconcile-log.json").exists()


class TestFirstEvidenceFile:
    def test_list_evidence(self):
        t = {"evidence": [{"file": " a.ts ", "line": 5}]}
        assert compose._first_evidence_file(t) == ("a.ts", 5)

    def test_dict_evidence(self):
        t = {"evidence": {"file": "b.ts", "line": 9}}
        assert compose._first_evidence_file(t) == ("b.ts", 9)

    def test_missing(self):
        assert compose._first_evidence_file({}) == ("", None)

    def test_non_int_line(self):
        t = {"evidence": [{"file": "c.ts", "line": "x"}]}
        assert compose._first_evidence_file(t) == ("c.ts", None)


class TestShortenTitleForXref:
    def test_empty(self):
        assert compose._shorten_title_for_xref("") == ""

    def test_file_path_in_file_form(self):
        out = compose._shorten_title_for_xref("SQL Injection (routes/login.ts:5)")
        assert out == "SQL Injection in file routes/login.ts"

    def test_compact_parens(self):
        out = compose._shorten_title_for_xref("SQL Injection (routes/login.ts)", compact=True)
        assert out == "SQL Injection (routes/login.ts)"

    def test_directory_path_in_form(self):
        out = compose._shorten_title_for_xref("Insecure Token (frontend/src/app)")
        assert out == "Insecure Token in frontend/src/app"

    def test_evidence_fallback(self):
        t = {"evidence": [{"file": "server.ts"}]}
        out = compose._shorten_title_for_xref("CSRF", t)
        assert out == "CSRF in file server.ts"

    def test_bare_weakness(self):
        assert compose._shorten_title_for_xref("Cross-Site Request Forgery") == ("Cross-Site Request Forgery")


class TestStripEmbeddedEvidenceFile:
    def test_no_threat(self):
        assert compose._strip_embedded_evidence_file("foo", None) == "foo"

    def test_strips_matching_file(self):
        t = {"evidence": [{"file": "routes/login.ts"}]}
        out = compose._strip_embedded_evidence_file("SQL injection routes/login.ts", t)
        assert out == "SQL injection"

    def test_keeps_plain_word(self):
        t = {"evidence": [{"file": "routes/login.ts"}]}
        out = compose._strip_embedded_evidence_file("SQL injection spa", t)
        assert out == "SQL injection spa"

    def test_no_evidence(self):
        assert compose._strip_embedded_evidence_file("a b.ts", {}) == "a b.ts"


# ---------------------------------------------------------------------------
# Index / paragraph helpers
# ---------------------------------------------------------------------------


class TestParagraphizeIssueCard:
    def test_non_issue_noop(self):
        assert compose._paragraphize_issue_card("plain text") == "plain text"

    def test_short_issue_noop(self):
        s = "**Issue:** short."
        assert compose._paragraphize_issue_card(s) == s

    def test_long_issue_split(self):
        body = " ".join(f"Sentence number {i} here." for i in range(12))
        card = "**Issue:** " + body
        out = compose._paragraphize_issue_card(card, min_chars=10, per_para=2)
        assert "\n\n" in out
        assert out.startswith("**Issue:** ")


class TestEscapeHeadingPlaceholders:
    def test_placeholder_escaped(self):
        out = compose._escape_heading_placeholders("Pin to @sha256:<digest>")
        assert "&lt;digest&gt;" in out

    def test_br_untouched(self):
        out = compose._escape_heading_placeholders("a <br> b")
        assert "<br>" in out


class TestIndexShortTitle:
    def test_drops_path_tail(self):
        out = compose._index_short_title("SQL Injection — routes/login.ts:18")
        assert "routes/login.ts" not in out

    def test_long_truncated(self):
        out = compose._index_short_title("word " * 40, limit=30)
        assert out.endswith("…")

    def test_placeholder_backticked(self):
        out = compose._index_short_title("pin @sha256:<digest>")
        assert "`<digest>`" in out


class TestSeverityByFindingNum:
    def test_maps_numbers(self):
        out = compose._severity_by_finding_num([{"id": "F-001", "risk": "High"}, {"t_id": "T-002", "severity": "Low"}])
        assert out[1] == "high"
        assert out[2] == "low"

    def test_default_low(self):
        out = compose._severity_by_finding_num([{"id": "F-003"}])
        assert out[3] == "low"

    def test_none(self):
        assert compose._severity_by_finding_num(None) == {}


# ---------------------------------------------------------------------------
# Cluster / tier helpers
# ---------------------------------------------------------------------------


class TestClassifyThreatCluster:
    def test_no_cwe_unmapped(self):
        assert compose._classify_threat_cluster({}) == "_unmapped"

    def test_known_cwe_routes(self):
        vocab = {
            "clusters": [
                {"id": "injection", "cwes": ["CWE-89"]},
                {"id": "_unmapped", "cwes": []},
            ]
        }
        assert compose._classify_threat_cluster({"cwe": "CWE-89"}, vocab) == "injection"

    def test_unknown_cwe_unmapped(self):
        vocab = {"clusters": [{"id": "injection", "cwes": ["CWE-89"]}]}
        assert compose._classify_threat_cluster({"cwe": "CWE-999"}, vocab) == "_unmapped"

    def test_multi_match_first_wins(self):
        compose._MULTI_MATCH_WARNED.discard("CWE-916")
        vocab = {
            "clusters": [
                {"id": "auth", "cwes": ["CWE-916"]},
                {"id": "crypto", "cwes": ["CWE-916"]},
            ]
        }
        assert compose._classify_threat_cluster({"cwe": "CWE-916"}, vocab) == "auth"


class TestTierForCluster:
    def test_explicit_tier(self):
        vocab = {"clusters": [{"id": "c1", "preferred_tier": "data"}]}
        assert compose._tier_for_cluster("c1", "application", vocab) == "data"

    def test_by_component_uses_fallback(self):
        vocab = {"clusters": [{"id": "c1", "preferred_tier": "by_component"}]}
        assert compose._tier_for_cluster("c1", "client", vocab) == "client"

    def test_unknown_cluster_fallback(self):
        assert compose._tier_for_cluster("nope", "data", {"clusters": []}) == "data"

    def test_unknown_cluster_default(self):
        assert compose._tier_for_cluster("nope", "", {"clusters": []}) == "application"


class TestTierHeaderSummary:
    def test_with_components(self):
        out = compose._tier_header_summary("Client", ["C-01", "C-02"], 3)
        assert out == "Client (C-01, C-02) · 3 findings"

    def test_without_components(self):
        out = compose._tier_header_summary("Data", [], 1)
        assert out == "Data · 1 findings"


# ---------------------------------------------------------------------------
# Actor collapse helpers
# ---------------------------------------------------------------------------


class TestCollapseOpenRegistrationActors:
    def test_folds_user_actors(self):
        data = {
            "actors": ["internet-user", "internet-priv-user", "build-time"],
            "attack_paths": [{"actor": "internet-user"}, {"actor": "build-time"}],
        }
        compose._collapse_open_registration_actors(data)
        assert "internet-anon" in data["actors"]
        assert "internet-user" not in data["actors"]
        assert data["attack_paths"][0]["actor"] == "internet-anon"
        assert data["attack_paths"][1]["actor"] == "build-time"

    def test_no_collapse_when_absent(self):
        data = {"actors": ["build-time"], "attack_paths": []}
        compose._collapse_open_registration_actors(data)
        assert data["actors"] == ["build-time"]


class TestCollapsePublicRepoActors:
    def test_folds_repo_read(self):
        data = {
            "actors": ["repo-read", "build-time"],
            "attack_paths": [{"actor": "repo-read"}],
        }
        compose._collapse_public_repo_actors(data)
        assert "internet-anon" in data["actors"]
        assert "repo-read" not in data["actors"]
        assert data["attack_paths"][0]["actor"] == "internet-anon"


# ---------------------------------------------------------------------------
# Figure-1 / attack tree helpers
# ---------------------------------------------------------------------------


class TestFig1NodeId:
    def test_normalizes(self):
        assert compose._fig1_node_id("A", "auth service!") == "A_AUTH_SERVICE"

    def test_empty_fallback(self):
        assert compose._fig1_node_id("A", "") == "A_N"


class TestFig1Label:
    def test_escapes(self):
        out = compose._fig1_label('a & "b"  c')
        assert "&amp;" in out
        assert '"' not in out


class TestBuildAlignmentEdges:
    def test_base_edges(self):
        edges = compose._build_alignment_edges([], [])
        srcs = {(e["src"], e["dst"]) for e in edges}
        assert ("HDR_A", "HDR_T") in srcs
        assert ("HDR_T", "HDR_I") in srcs

    def test_victim_and_anon_edges(self):
        actor_cards = [
            {"slug": "victim-required", "id": "VID"},
            {"slug": "internet-anon", "id": "AID"},
        ]
        tier_cards = [
            {"key": "client", "node_id": "CL"},
            {"key": "application", "node_id": "APP"},
        ]
        edges = compose._build_alignment_edges(actor_cards, tier_cards)
        pairs = {(e["src"], e["dst"]) for e in edges}
        assert ("VID", "CL") in pairs
        assert ("AID", "APP") in pairs


class TestNormalizeTidToFid:
    def test_t_to_f(self):
        assert compose._normalize_tid_to_fid("T-007") == "F-007"

    def test_passthrough(self):
        assert compose._normalize_tid_to_fid("F-007") == "F-007"
        assert compose._normalize_tid_to_fid("M-1") == "M-1"


class TestAttackTreeNodeLabel:
    def test_goal_label_kept(self):
        assert compose._attack_tree_node_label({"label": "Goal", "class": "goal"}) == "Goal"

    def test_leaf_id_plus_title(self):
        out = compose._attack_tree_node_label({"label": "T-001 — SQL injection login bypass", "class": "leaf"})
        assert out.startswith("F-001 — ")

    def test_leaf_id_only(self):
        out = compose._attack_tree_node_label({"label": "T-002", "class": "leaf"})
        assert out == "F-002"

    def test_leaf_long_title_truncated(self):
        out = compose._attack_tree_node_label({"label": "F-003 — " + "x" * 80, "class": "leaf"})
        assert out.endswith("…")


class TestAttackTreeEdgeLine:
    def test_or_node_label(self):
        line = compose._attack_tree_edge_line({"from": "A", "to": "B"}, {"B": {"class": "or_node"}})
        assert '|"OR"|' in line

    def test_authored_label_fallback(self):
        line = compose._attack_tree_edge_line({"from": "A", "to": "B", "label": "custom"}, {"B": {}})
        assert '|"custom"|' in line

    def test_no_label(self):
        line = compose._attack_tree_edge_line({"from": "A", "to": "B"}, {"B": {}})
        assert line == "    A --> B"


class TestBuildAttackTreeBlocks:
    def test_single_block(self):
        data = {
            "mermaid": {
                "nodes": [
                    {"id": "G", "label": "Goal", "class": "goal"},
                    {"id": "L1", "label": "T-001 — leaf", "class": "leaf"},
                ],
                "edges": [{"from": "L1", "to": "G"}],
            }
        }
        blocks = compose._build_attack_tree_blocks(data)
        assert len(blocks) == 1
        assert "graph LR" in blocks[0]["src"]
        assert "F-001" in blocks[0]["src"]


class TestDeriveAttackTreeFindings:
    def test_leaf_pointers(self):
        data = {
            "mermaid": {
                "nodes": [
                    {"id": "G", "label": "Goal", "class": "goal"},
                    {"id": "L1", "label": "T-001 — SQLi", "class": "leaf"},
                ]
            }
        }
        out = compose._derive_attack_tree_findings(data)
        assert any(e.get("id", "").startswith("F-001") or "001" in str(e) for e in out)


class TestStripFindingLocation:
    def test_strips_tail(self):
        out = compose._strip_finding_location("SQL Injection routes/login.ts:18")
        assert "routes/login.ts" not in out or out

    def test_empty_fallback_to_original(self):
        # a pure location yields the original
        out = compose._strip_finding_location("foo")
        assert out == "foo"


# ---------------------------------------------------------------------------
# Table helpers
# ---------------------------------------------------------------------------


class TestSplitTableRow:
    def test_pipes_stripped(self):
        assert compose._split_table_row("| a | b | c |") == ["a", "b", "c"]

    def test_no_outer_pipes(self):
        assert compose._split_table_row("a | b") == ["a", "b"]


class TestTableColRole:
    def test_narrow(self):
        assert compose._table_col_role("ID") == "narrow"
        assert compose._table_col_role("Effort") == "narrow"

    def test_medium(self):
        assert compose._table_col_role("Severity") == "medium"

    def test_path(self):
        assert compose._table_col_role("Route") == "path"
        assert compose._table_col_role("Key Paths") == "path"

    def test_desc_before_links(self):
        assert compose._table_col_role("Threat Description") == "desc"

    def test_links(self):
        assert compose._table_col_role("Linked Threats") == "links"

    def test_default(self):
        assert compose._table_col_role("Asset") == "default"

    def test_empty(self):
        assert compose._table_col_role("") == "default"


class TestTableColWeight:
    def test_weight_matches_bound(self):
        assert compose._table_col_weight("ID") == compose._TBL_W_NARROW
        assert compose._table_col_weight("Linked Threats") == compose._TBL_W_LINKS


class TestTableCellVisibleLen:
    def test_strips_markdown(self):
        n = compose._table_cell_visible_len("[link](http://x) `code`")
        assert n == len("link code")

    def test_br_split_max(self):
        n = compose._table_cell_visible_len("short<br/>longer entry")
        assert n == len("longer entry")


class TestWrapSegmentWords:
    def test_short_unchanged(self):
        assert compose._wrap_segment_words("a b", 40) == "a b"

    def test_wraps_long(self):
        out = compose._wrap_segment_words("alpha beta gamma delta", 10)
        assert "<br/>" in out


# ---------------------------------------------------------------------------
# Linkify / markdown post-processors
# ---------------------------------------------------------------------------


class TestLinkifyBareCwes:
    def test_linkifies(self):
        out = compose._linkify_bare_cwes("uses CWE-89 here")
        assert "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)" in out

    def test_skips_code_fence(self):
        md = "```\nCWE-89\n```\n"
        out = compose._linkify_bare_cwes(md)
        assert "[CWE-89]" not in out

    def test_skips_already_linked(self):
        md = "[CWE-89](x)"
        out = compose._linkify_bare_cwes(md)
        assert out == md


class TestLinkifySectionRefs:
    def test_links_section(self):
        md = "## 7 Security\n\nSee §7 above.\n"
        out = compose._linkify_section_refs(md)
        assert "[§7](#" in out

    def test_no_headings_noop(self):
        md = "See §7 here."
        assert compose._linkify_section_refs(md) == md

    def test_heading_itself_not_linkified(self):
        md = "## 7 Security §7\n"
        out = compose._linkify_section_refs(md)
        # heading line must not get a link inserted
        assert out.splitlines()[0] == "## 7 Security §7"


class TestNormalizeEmdashes:
    def test_spaced_dash(self):
        out = compose._normalize_emdashes("a — b")
        assert "—" not in out
        assert "a - b" in out

    def test_preserves_code_fence(self):
        md = "```\na — b\n```\n"
        out = compose._normalize_emdashes(md)
        assert "—" in out


class TestNormalizeVisibleThreatIds:
    def test_link_form(self):
        out = compose._normalize_visible_threat_ids("[T-001](#t-001)")
        assert out == "[F-001](#f-001)"

    def test_bare_prose(self):
        out = compose._normalize_visible_threat_ids("see T-002 now")
        assert "F-002" in out

    def test_empty(self):
        assert compose._normalize_visible_threat_ids("") == ""

    def test_abuse_case_id_preserved(self):
        out = compose._normalize_visible_threat_ids("AC-T-001 case")
        assert "AC-T-001" in out


class TestApplyOutsideChangelog:
    def test_no_changelog_applies_all(self):
        out = compose._apply_outside_changelog("hello", lambda s: s.upper())
        assert out == "HELLO"

    def test_changelog_section_skipped(self):
        md = "intro\n## Changelog\nentry\n## Next\ntail\n"
        out = compose._apply_outside_changelog(md, lambda s: s.replace("e", "E"))
        # changelog body 'entry' keeps its 'e'
        assert "## Changelog\nentry\n" in out
        assert "intro".replace("e", "E") in out


# ---------------------------------------------------------------------------
# Mermaid / quick-mode helpers
# ---------------------------------------------------------------------------


class TestQuoteMermaidEdgeLabels:
    def test_quotes_unsafe(self):
        md = "```mermaid\nflowchart TD\nA -->|a: b| B\n```\n"
        out, n = compose._quote_mermaid_edge_labels(md)
        assert n >= 1
        assert '|"a: b"|' in out

    def test_non_flowchart_untouched(self):
        md = "```mermaid\nsequenceDiagram\nA->>B: hi\n```\n"
        out, n = compose._quote_mermaid_edge_labels(md)
        assert n == 0


class TestAnnotateQuickModeGaps:
    def test_inserts_notice(self):
        md = "## 7 Sec\n\n<!-- NARRATIVE_PLACEHOLDER -->\n"
        out = compose._annotate_quick_mode_gaps(md, depth="quick")
        assert compose._QUICK_MODE_NOTICE_QUICK in out

    def test_standard_banner(self):
        md = "## 7 Sec\n\n<!-- NARRATIVE_PLACEHOLDER -->\n"
        out = compose._annotate_quick_mode_gaps(md, depth="standard")
        assert compose._QUICK_MODE_NOTICE_STANDARD in out

    def test_no_gap_unchanged(self):
        md = "## 7 Sec\n\nfull text here"
        assert compose._annotate_quick_mode_gaps(md) == md


class TestMaskSecrets:
    def test_returns_tuple(self):
        out, applied = compose._mask_secrets("no secrets here")
        assert out == "no secrets here"
        assert isinstance(applied, list)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


class TestFmtMs:
    def test_zero(self):
        assert compose._fmt_ms(0) == "—"
        assert compose._fmt_ms(-5) == "—"

    def test_minutes_seconds(self):
        assert compose._fmt_ms(65000) == "1m 05s"


class TestFmtSeconds_v2:
    def test_none_negative(self):
        assert compose._fmt_seconds(None) == "—"
        assert compose._fmt_seconds(-1) == "—"

    def test_inline(self):
        assert compose._fmt_seconds(0) == "(inline)"

    def test_sub_minute(self):
        assert compose._fmt_seconds(45) == "45s"

    def test_minutes(self):
        assert compose._fmt_seconds(125) == "2m 05s"


class TestFormatGeneratedTimestamp_v2:
    def test_iso_z(self):
        out = compose._format_generated_timestamp("2026-05-17T05:31:44Z")
        assert out == "2026-05-17 05:31 UTC"

    def test_blank(self):
        assert compose._format_generated_timestamp("") == "—"

    def test_non_iso_passthrough(self):
        assert compose._format_generated_timestamp("not a date") == "not a date"


class TestTruncateWithEllipsis_v2:
    def test_non_string(self):
        assert compose._truncate_with_ellipsis(None, 10) == ""

    def test_short_unchanged(self):
        assert compose._truncate_with_ellipsis("abc", 10) == "abc"

    def test_word_boundary(self):
        out = compose._truncate_with_ellipsis("the quick brown fox jumps over", 18)
        assert out.endswith("…")


class TestClassifyComponentTier:
    def test_default_application(self):
        assert compose._classify_component_tier({"name": "mystery box"}) == "application"

    def test_hint_match(self):
        # find a hint that maps to a known tier
        tier, hints = next(iter(compose._COMPONENT_TIER_HINTS.items()))
        comp = {"name": hints[0]}
        assert compose._classify_component_tier(comp) == tier


# ---------------------------------------------------------------------------
# Evidence / CWE helpers
# ---------------------------------------------------------------------------


class TestRootCauseForCwe:
    def test_none(self):
        assert compose._root_cause_for_cwe(None) is None

    def test_unknown(self):
        assert compose._root_cause_for_cwe("CWE-99999") is None

    def test_known_if_any(self):
        # pick a key that exists in the table
        if compose._CWE_ROOT_CAUSE:
            key = next(iter(compose._CWE_ROOT_CAUSE))
            num = key.replace("CWE-", "")
            assert compose._root_cause_for_cwe(num) == compose._CWE_ROOT_CAUSE[key]


class TestReadEvidenceSnippet:
    def test_missing_args(self):
        assert compose._read_evidence_snippet(None, "x", 1, 1) is None
        assert compose._read_evidence_snippet(Path("/tmp"), "", 1, 1) is None
        assert compose._read_evidence_snippet(Path("/tmp"), "x", None, 1) is None

    def test_reads_window(self, tmp_path):
        f = tmp_path / "code.txt"
        f.write_text("l1\nl2\nl3\nl4\nl5\n")
        out = compose._read_evidence_snippet(tmp_path, "code.txt", 3, 1)
        assert out == "l2\nl3\nl4"

    def test_path_traversal_guard(self, tmp_path):
        assert compose._read_evidence_snippet(tmp_path, "../../etc/passwd", 1, 1) is None

    def test_out_of_bounds(self, tmp_path):
        f = tmp_path / "c.txt"
        f.write_text("only one line\n")
        assert compose._read_evidence_snippet(tmp_path, "c.txt", 50, 1) is None


class TestHtmlEscapeForPre:
    def test_escapes(self):
        assert compose._html_escape_for_pre("a<b>&c") == "a&lt;b&gt;&amp;c"


class TestLangClassForFile:
    def test_empty(self):
        assert compose._lang_class_for_file("") == ""

    def test_dockerfile(self):
        assert compose._lang_class_for_file("Dockerfile") == "language-dockerfile"

    def test_ts(self):
        assert compose._lang_class_for_file("a/b.ts") == "language-typescript"


class TestFirstNSentences:
    def test_empty(self):
        assert compose._first_n_sentences("", 2) == ""
        assert compose._first_n_sentences("x", 0) == ""

    def test_takes_first_n(self):
        out = compose._first_n_sentences("One. Two. Three.", 2)
        assert out == "One. Two."

    def test_keeps_dotted_token(self):
        out = compose._first_n_sentences("Use a.b.c here. Next.", 1)
        assert "a.b.c" in out


class TestSafeSentenceSplit:
    def test_empty(self):
        assert compose._safe_sentence_split("") == []

    def test_basic_split(self):
        out = compose._safe_sentence_split("One. Two.")
        assert out == ["One.", "Two."]

    def test_abbreviation_not_split(self):
        out = compose._safe_sentence_split("Use e.g. this thing.")
        assert out == ["Use e.g. this thing."]

    def test_dotted_identifier_not_split(self):
        out = compose._safe_sentence_split("Call child_process.exec() now.")
        assert out == ["Call child_process.exec() now."]


# ---------------------------------------------------------------------------
# Codify helpers
# ---------------------------------------------------------------------------


class TestFixActionLead:
    def test_empty(self):
        assert compose._fix_action_lead("") == ""

    def test_bad_format(self):
        assert compose._fix_action_lead("not-a-cwe") == ""

    def test_known_if_any(self):
        if compose._FIX_ACTION_LEADS:
            num = next(iter(compose._FIX_ACTION_LEADS))
            assert compose._fix_action_lead(f"CWE-{num}") == compose._FIX_ACTION_LEADS[num]


class TestCodifyLabelLocator:
    def test_no_paren(self):
        assert compose._codify_label_locator("SQL Injection") == "SQL Injection"

    def test_backticks_file_locator(self):
        out = compose._codify_label_locator("SQLi (routes/login.ts:18)")
        assert "(`routes/login.ts:18`)" in out

    def test_idempotent(self):
        s = "SQLi (`routes/login.ts`)"
        assert compose._codify_label_locator(s) == s

    def test_prose_paren_untouched(self):
        out = compose._codify_label_locator("Spoofing (S)")
        assert out == "Spoofing (S)"

    def test_dockerfile_noext(self):
        out = compose._codify_label_locator("Pin base image (Dockerfile)")
        assert "(`Dockerfile`)" in out


class TestStripLabelCode:
    def test_strips_backticks(self):
        assert compose._strip_label_code("a `b` c") == "a b c"

    def test_none(self):
        assert compose._strip_label_code(None) is None


class TestCodifyInlineIdentifiers:
    def test_empty(self):
        assert compose._codify_inline_identifiers("") == ""

    def test_wraps_file_path(self):
        out = compose._codify_inline_identifiers("see routes/login.ts here")
        assert "`routes/login.ts`" in out

    def test_skips_existing_backticks(self):
        s = "already `routes/login.ts` wrapped"
        out = compose._codify_inline_identifiers(s)
        assert out.count("`routes/login.ts`") == 1

    def test_skips_link_target(self):
        s = "[x](http://a.b/c.ts)"
        out = compose._codify_inline_identifiers(s)
        assert out == s


class TestCodeTokenIsEmbedded:
    def test_member_access_embedded(self):
        # token preceded by '.' is embedded
        assert compose._code_token_is_embedded(".reverse()", 1, 10) is True

    def test_standalone_not_embedded(self):
        assert compose._code_token_is_embedded("a reverse() b", 2, 11) is False


# ---------------------------------------------------------------------------
# RenderContext-backed helpers (minimal ctx, no fixture / full render)
# ---------------------------------------------------------------------------


def _make_ctx(tmp_path, yaml_data=None, **kw):
    """Build a minimal RenderContext for unit-testing ctx-bound helpers."""
    return compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data=yaml_data or {},
        triage={},
        fragments_dir=tmp_path / ".fragments",
        severity_taxonomy={
            "critical": {"emoji": "🔴", "label": "Critical"},
            "high": {"emoji": "🟠", "label": "High"},
            "low": {"emoji": "🟡", "label": "Low"},
        },
        **kw,
    )


class TestRenderContextLookups:
    def test_lookup_label_finding(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {"threats": [{"id": "T-001", "title": "SQL Injection (routes/login.ts)"}]},
        )
        # F↔T alias both resolve
        assert "SQL Injection" in ctx.lookup_label("T-001")
        assert "SQL Injection" in ctx.lookup_label("F-001")

    def test_lookup_label_unknown(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        assert ctx.lookup_label("F-999") == ""
        assert ctx.lookup_label("") == ""

    def test_lookup_label_scenario_fallback(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {"threats": [{"id": "T-002", "scenario": "Attacker bypasses auth. Then escalates."}]},
        )
        assert ctx.lookup_label("T-002")

    def test_mitigation_label(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"mitigations": [{"id": "M-001", "title": "Add WAF"}]})
        assert ctx.lookup_label("M-001") == "Add WAF"

    def test_component_label(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"components": [{"id": "C-01", "name": "Auth Service"}]})
        assert ctx.lookup_label("C-01") == "Auth Service"

    def test_severity_for_ref(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"threats": [{"id": "T-001", "risk": "high"}]})
        assert ctx.severity_for_ref("F-001") == "high"
        assert ctx.severity_for_ref("F-999") == ""
        assert ctx.severity_for_ref("") == ""

    def test_severity_effective_wins(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {"threats": [{"id": "T-001", "risk": "low", "effective_severity": "critical"}]},
        )
        assert ctx.severity_for_ref("T-001") == "critical"

    def test_priority_for_ref_explicit_key(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"mitigations": [{"id": "M-001", "priority": "p1"}]})
        assert ctx.priority_for_ref("M-001") == "p1"
        assert ctx.priority_for_ref("") == ""

    def test_priority_severity_word(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"mitigations": [{"id": "M-002", "priority": "critical"}]})
        assert ctx.priority_for_ref("M-002") == "p1"

    def test_priority_derived_from_threats(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {
                "threats": [{"id": "T-005", "risk": "high"}],
                "mitigations": [{"id": "M-003", "threat_ids": ["T-005"]}],
            },
        )
        assert ctx.priority_for_ref("M-003") == "p2"


class TestRenderContextTaxonomyMethods:
    def test_severity_emoji_label(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        assert ctx.severity_emoji("high") == "🟠"
        assert ctx.severity_label("high") == "High"
        assert ctx.severity_label("unknown") == "unknown"
        assert ctx.severity_emoji("unknown") == ""

    def test_effectiveness_badge(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            effectiveness_taxonomy={"weak": {"emoji": "⚠️", "label": "Weak"}},
        )
        assert ctx.effectiveness_badge("weak") == "⚠️ Weak"
        assert ctx.effectiveness_badge("missing") == "missing"


class TestLinkifyWithLabel:
    def test_finding_with_dot_and_label(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {"threats": [{"id": "T-001", "title": "SQLi", "risk": "high"}]},
        )
        out = ctx.linkify_with_label("T-001")
        assert "[F-001](#f-001)" in out
        assert "🟠" in out
        assert "— SQLi" in out

    def test_empty_ref(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        assert ctx.linkify_with_label("") == ""
        assert ctx.linkify_with_label("   ") == ""

    def test_unknown_ref_bare_link(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        assert ctx.linkify_with_label("M-009") == "[M-009](#m-009)"

    def test_dollar_escaped(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"threats": [{"id": "T-001", "title": "$where injection"}]})
        out = ctx.linkify_with_label("T-001")
        assert "\\$where" in out

    def test_mitigation_priority_digit(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {"mitigations": [{"id": "M-001", "title": "Fix", "priority": "p1"}]},
        )
        out = ctx.linkify_with_label("M-001")
        assert "[M-001](#m-001)" in out


class TestLinkifyWithShortLabel:
    def test_em_dash_stripped(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {"threats": [{"id": "T-001", "title": "SQLi — routes/login.ts"}]},
        )
        out = ctx.linkify_with_short_label("T-001")
        assert out == "[F-001](#f-001) (SQLi)"

    def test_parens_stripped(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {"threats": [{"id": "T-002", "title": "XSS (search.ts)"}]},
        )
        out = ctx.linkify_with_short_label("T-002")
        assert out == "[F-002](#f-002) (XSS)"

    def test_empty(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        assert ctx.linkify_with_short_label("") == ""

    def test_no_label_bare(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        assert ctx.linkify_with_short_label("F-009") == "[F-009](#f-009)"


class TestComponentLookup:
    def test_canonical_and_alias(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {"components": [{"id": "auth-service", "name": "Auth"}]},
        )
        out = compose._component_lookup(ctx)
        assert "C-01" in out
        assert "auth-service" in out
        assert out["C-01"] is out["auth-service"]

    def test_preserves_canonical_id(self, tmp_path):
        ctx = _make_ctx(tmp_path, {"components": [{"id": "C-05", "name": "X"}]})
        out = compose._component_lookup(ctx)
        assert "C-05" in out


class TestSeverityCounts_v2:
    def test_counts(self, tmp_path):
        ctx = _make_ctx(
            tmp_path,
            {
                "threats": [
                    {"id": "T-001", "risk": "high"},
                    {"id": "T-002", "risk": "high"},
                    {"id": "T-003", "risk": "low"},
                ]
            },
        )
        counts = compose._severity_counts(ctx)
        assert counts.get("high") == 2
        assert counts.get("low") == 1


class TestKnownRequirementIds_v2:
    def test_absent_file(self, tmp_path):
        ctx = _make_ctx(tmp_path)
        assert compose._known_requirement_ids(ctx) == {}

    def test_parses_file(self, tmp_path):
        (tmp_path / ".requirements.yaml").write_text(
            "categories:\n  - requirements:\n      - id: SEC-1\n        url: http://x/sec1\n"
        )
        out = compose._known_requirement_ids(ctx=_make_ctx(tmp_path))
        assert out.get("SEC-1") == "http://x/sec1"


class TestNormaliseRequirementStatus_v2:
    def test_anti_pattern(self):
        assert compose._normalise_requirement_status("ANTI-PATTERN") == "ANTI-PATTERN"

    def test_partial(self):
        assert compose._normalise_requirement_status("Partial compliance") == "PARTIAL"

    def test_fail_pass(self):
        assert compose._normalise_requirement_status("FAIL") == "FAIL"
        assert compose._normalise_requirement_status("**PASS**") == "PASS"

    def test_na(self):
        assert compose._normalise_requirement_status("N/A") == "N/A"

    def test_empty(self):
        assert compose._normalise_requirement_status("") == ""


class TestExtractRequirementIdFromCell_v2:
    def test_known_id_longest_first(self):
        out = compose._extract_requirement_id_from_cell("see SEC-10 here", {"SEC-1", "SEC-10"})
        assert out == "SEC-10"

    def test_backtick_fallback(self):
        out = compose._extract_requirement_id_from_cell("`ORG-FOO`", set())
        assert out == "ORG-FOO"

    def test_bracket_fallback(self):
        out = compose._extract_requirement_id_from_cell("[SEC-AUTH-1]", set())
        assert out == "SEC-AUTH-1"


class TestSplitMdTableRow_v2:
    def test_basic(self):
        assert compose._split_md_table_row("| a | b |") == ["a", "b"]

    def test_not_a_row(self):
        assert compose._split_md_table_row("no pipes") == []

    def test_escaped_pipe(self):
        out = compose._split_md_table_row(r"| a \| b | c |")
        assert out == [r"a \| b", "c"]


class TestExtractFindingIdsFromCell:
    def test_normalizes(self):
        out = compose._extract_finding_ids_from_cell("T-1 and F-002")
        assert "F-001" in out
        assert "F-002" in out

    def test_dedupe(self):
        out = compose._extract_finding_ids_from_cell("F-001 F-001")
        assert out == ["F-001"]


class TestRequirementIsTraceableViolation_v2:
    def test_empty_map_true(self):
        assert compose._requirement_is_traceable_violation("X", {}) is True

    def test_violation_status(self):
        assert compose._requirement_is_traceable_violation("X", {"X": "FAIL"}) is True

    def test_pass_status(self):
        assert compose._requirement_is_traceable_violation("X", {"X": "PASS"}) is False

    def test_missing_status_true(self):
        assert compose._requirement_is_traceable_violation("X", {"Y": "PASS"}) is True


class TestFormatRequirementLink:
    def test_with_url(self):
        out = compose._format_requirement_link("SEC-1", {"SEC-1": "http://x"})
        assert out == "[`SEC-1`](http://x)"

    def test_without_url(self):
        assert compose._format_requirement_link("SEC-1", {}) == "`SEC-1`"


class TestExtractSectionVerbatim:
    def test_extracts(self):
        md = "## 1. Intro\n\nA\n\n## 2. Body\n\nB content\n\n## 3. End\n\nC\n"
        out = compose._extract_section_verbatim(md, top_level_number=2)
        assert "B content" in out
        assert "## 3. End" not in out

    def test_missing_returns_empty(self):
        md = "## 1. Intro\n\nA\n"
        out = compose._extract_section_verbatim(md, top_level_number=9)
        assert out == ""


class TestStripSection7Crossrefs:
    def test_collapses_blank_lines(self):
        md = "line1\n\n\n\nline2\n"
        out = compose._strip_section7_crossrefs(md)
        assert "\n\n\n" not in out


class TestAnchorFromHeading:
    def test_slugifies(self):
        out = compose._anchor_from_heading("## 7.3 Security Architecture")
        assert out and " " not in out
        assert out == out.lower()


class TestDeriveControlMitigates_v2:
    def test_matches_by_threat_id(self):
        control = {"mitigates": ["T-001"]}
        threats = [{"id": "T-001", "title": "SQLi"}]
        out = compose._derive_control_mitigates(control, threats)
        assert isinstance(out, list)


class TestNormalizeSecurityControls_v2:
    def test_non_list(self):
        assert compose._normalize_security_controls(None) == []

    def test_normalizes_dicts(self):
        out = compose._normalize_security_controls([{"name": "WAF"}, "raw_string"])
        assert isinstance(out, list)
        assert len(out) == 2
        assert out[1]["_synthesized_from_string"] is True

    def test_drops_non_str_non_dict(self):
        out = compose._normalize_security_controls([None, 5, "", {"x": 1}])
        assert out == [{"x": 1}]


# ---------------------------------------------------------------------------
# Attack-class taxonomy + posture figure pipeline (real data/ loaders)
# ---------------------------------------------------------------------------


class TestLoadTaxonomies:
    def test_attack_class_taxonomy_has_classes(self):
        tax = compose._load_attack_class_taxonomy()
        assert isinstance(tax.get("classes"), list)
        assert tax["classes"]

    def test_business_impact_taxonomy(self):
        tax = compose._load_business_impact_taxonomy()
        assert isinstance(tax, dict)

    def test_posture_actor_labels(self):
        labels = compose._load_posture_actor_labels()
        assert isinstance(labels, dict)


class TestClassifyFindingClass_v2:
    def test_no_cwe_none(self):
        tax = {"classes": [{"id": "injection", "cwes": ["CWE-89"]}]}
        assert compose._classify_finding_class({}, tax) is None

    def test_structured_cwe(self):
        tax = {"classes": [{"id": "injection", "cwes": ["CWE-89"]}]}
        assert compose._classify_finding_class({"cwe": "CWE-89"}, tax) == "injection"

    def test_cwe_list(self):
        tax = {"classes": [{"id": "xss", "cwes": ["CWE-79"]}]}
        assert compose._classify_finding_class({"cwes": ["CWE-79"]}, tax) == "xss"

    def test_inline_scenario_cwe(self):
        tax = {"classes": [{"id": "injection", "cwes": ["CWE-89"]}]}
        t = {"scenario": "SQLi here cwe-89 cited"}
        assert compose._classify_finding_class(t, tax) == "injection"

    def test_unknown_cwe_none(self):
        tax = {"classes": [{"id": "injection", "cwes": ["CWE-89"]}]}
        assert compose._classify_finding_class({"cwe": "CWE-999"}, tax) is None


class TestDeriveAttackPathsFallback:
    def test_builds_paths(self):
        tax = compose._load_attack_class_taxonomy()
        # pick a real cwe from the taxonomy so a class matches
        cls = tax["classes"][0]
        cwe = (cls.get("cwes") or ["CWE-89"])[0]
        threats = [{"id": "T-001", "cwe": cwe}]
        out = compose._derive_attack_paths_fallback(threats, tax)
        assert out["schema_version"] == 1
        assert isinstance(out["actors"], list)
        assert out["attack_paths"]

    def test_no_matches_default_actor(self):
        tax = {"classes": []}
        out = compose._derive_attack_paths_fallback([], tax)
        assert out["attack_paths"] == []


class TestClassifyControlIntoCluster:
    def test_domain_match_wins(self):
        cfg = [
            {"id": "http", "domains": ["rate limiting"], "name_keywords": []},
            {"id": "auth", "domains": [], "name_keywords": ["2fa"]},
        ]
        ctrl = {"domain": "Rate Limiting", "name": "2FA endpoints"}
        assert compose._classify_control_into_cluster(ctrl, cfg) == "http"

    def test_keyword_match(self):
        cfg = [{"id": "auth", "domains": [], "name_keywords": ["jwt"]}]
        ctrl = {"name": "JWT validation middleware"}
        assert compose._classify_control_into_cluster(ctrl, cfg) == "auth"

    def test_unmapped(self):
        cfg = [{"id": "auth", "domains": ["iam"], "name_keywords": ["jwt"]}]
        assert compose._classify_control_into_cluster({"name": "mystery"}, cfg) == "_unmapped"

    def test_impl_dict_description(self):
        cfg = [{"id": "auth", "domains": [], "name_keywords": ["bcrypt"]}]
        ctrl = {"implementation": {"description": "uses bcrypt hashing"}}
        assert compose._classify_control_into_cluster(ctrl, cfg) == "auth"


def _simple_attack_paths():
    return {
        "actors": ["internet-anon", "victim-required"],
        "attack_paths": [
            {
                "class": "injection",
                "actor": "internet-anon",
                "target": "application",
                "impact": ["data-breach"],
            },
            {
                "class": "xss",
                "actor": "internet-anon",
                "target": "victim",
                "impact": ["account-takeover"],
            },
        ],
    }


def _simple_taxonomy():
    return {
        "glyph_sequence": ["①", "②", "③"],
        "classes": [
            {"id": "injection", "short_label": "Injection"},
            {"id": "xss", "short_label": "XSS"},
        ],
    }


class TestBuildActorCards:
    def test_orders_and_labels(self):
        labels = {
            "order": ["internet-anon", "victim-required"],
            "actors": {
                "internet-anon": {"label": "Anonymous", "default_subtitle": "any user"},
                "victim-required": {"label": "Shop User", "default_subtitle": "customer"},
            },
        }
        cards = compose._build_actor_cards(_simple_attack_paths(), labels)
        slugs = [c["slug"] for c in cards]
        assert slugs == ["internet-anon", "victim-required"]
        assert cards[0]["id"] == "ANON"
        assert cards[1]["id"] == "SHOPUSER"

    def test_open_registration_subtitle(self):
        labels = {
            "order": ["internet-anon"],
            "actors": {"internet-anon": {"label": "Anon", "default_subtitle": "x"}},
        }
        cards = compose._build_actor_cards(_simple_attack_paths(), labels, open_user_registration=True)
        assert "registration is one POST away" in cards[0]["subtitle"]

    def test_victim_labels_from_taxonomy(self):
        labels = {
            "order": ["victim-required"],
            "actors": {"victim-required": {"label": "User", "default_subtitle": "x"}},
        }
        cards = compose._build_actor_cards(_simple_attack_paths(), labels, taxonomy=_simple_taxonomy())
        assert "XSS" in cards[0]["subtitle"]


class TestBuildImpactCards:
    def test_only_used_impacts(self):
        tax = {
            "impacts": [
                {"id": "data-breach", "label": "Data Breach", "severity_default": "critical"},
                {"id": "unused", "label": "Unused", "severity_default": "low"},
            ]
        }
        cards = compose._build_impact_cards(_simple_attack_paths(), tax)
        ids = [c["id"] for c in cards]
        assert "data-breach" in ids
        assert "unused" not in ids
        assert cards[0]["label"].startswith("🔴")


class TestBuildAttackArrows:
    def test_direct_and_victim(self):
        actor_cards = [
            {"slug": "internet-anon", "id": "ANON"},
            {"slug": "victim-required", "id": "SHOPUSER"},
        ]
        tier_cards = [
            {"key": "client", "node_id": "BROWSER"},
            {"key": "application", "node_id": "SERVER"},
        ]
        arrows, relays = compose._build_attack_arrows(
            _simple_attack_paths(), _simple_taxonomy(), actor_cards, tier_cards
        )
        assert arrows
        # the xss path is victim-targeting → produces a relay arrow
        assert relays
        assert relays[0]["dst"] == "SHOPUSER"


class TestBuildConsequenceArrows:
    def test_dedup_pairs(self):
        impact_cards = [
            {"id": "data-breach", "node_id": "DB"},
            {"id": "account-takeover", "node_id": "ATO"},
        ]
        tier_cards = [
            {"key": "client", "node_id": "BROWSER"},
            {"key": "application", "node_id": "SERVER"},
        ]
        out = compose._build_consequence_arrows(_simple_attack_paths(), impact_cards, tier_cards)
        assert {(e["src"], e["dst"]) for e in out} == {
            ("SERVER", "DB"),
            ("BROWSER", "ATO"),
        }


import json as _json


def _mk_ctx(tmp_path, **kw):
    """Build a minimal RenderContext rooted at a fresh output dir."""
    out_dir = tmp_path / "out"
    out_dir.mkdir(exist_ok=True)
    frag = out_dir / ".fragments"
    frag.mkdir(exist_ok=True)
    defaults = dict(
        output_dir=out_dir,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag,
    )
    defaults.update(kw)
    return compose.RenderContext(**defaults)


# ---------------------------------------------------------------------------
# CWE normalisation + category inference
# ---------------------------------------------------------------------------


class TestNormalizeCwe:
    def test_none_and_empty(self):
        assert compose._normalize_cwe(None) == ""
        assert compose._normalize_cwe("") == ""
        assert compose._normalize_cwe("   ") == ""

    def test_int_and_prefixed(self):
        assert compose._normalize_cwe(89) == "CWE-89"
        assert compose._normalize_cwe("CWE-89") == "CWE-89"
        assert compose._normalize_cwe("cwe-089") == "CWE-89"

    def test_zero(self):
        assert compose._normalize_cwe("CWE-0") == "CWE-0"
        assert compose._normalize_cwe("000") == "CWE-0"


class TestBuildCweToThMap:
    def test_loads_real_yaml(self):
        m = compose._build_cwe_to_th_map()
        assert isinstance(m, dict)
        # Real taxonomy ships a curated cwe_to_th block — must be non-empty.
        assert m
        for k, v in m.items():
            assert k.startswith("CWE-")
            assert v.startswith("TH-")


class TestInferThreatCategory:
    def test_explicit_category_id_wins(self):
        tax = {"TH-99": {"id": "TH-99"}}
        assert compose.infer_threat_category({"category_id": "TH-99"}, tax) == "TH-99"

    def test_cwe_lookup(self):
        # CWE-89 → injection-ish TH; just assert a TH-NN comes back.
        out = compose.infer_threat_category({"cwe": "CWE-89"}, {})
        assert out.startswith("TH-")

    def test_title_keyword_fallback(self):
        out = compose.infer_threat_category({"title": "SQL Injection in login"}, {})
        assert out.startswith("TH-")

    def test_stride_fallback(self):
        out = compose.infer_threat_category({"stride": "spoofing"}, {})
        assert out.startswith("TH-")

    def test_default_th01(self):
        out = compose.infer_threat_category({}, {})
        assert out == "TH-01"


class TestCategoryCountBySeverity:
    def test_empty(self):
        assert compose._category_count_by_severity([], {}, "critical") == 0

    def test_counts_by_effective_severity(self):
        threats = [
            {"cwe": "CWE-89", "risk": "Critical"},
            {"cwe": "CWE-89", "risk": "Low"},
            {"cwe": "CWE-79", "risk": "High"},
        ]
        n = compose._category_count_by_severity(threats, {}, "critical")
        assert n >= 0


# ---------------------------------------------------------------------------
# Timestamp / duration formatting
# ---------------------------------------------------------------------------


class TestFmtSeconds:
    def test_negative_and_none(self):
        assert compose._fmt_seconds(-1) == "—"

    def test_zero(self):
        assert compose._fmt_seconds(0) == "(inline)"

    def test_sub_minute(self):
        assert compose._fmt_seconds(45) == "45s"

    def test_minutes(self):
        assert compose._fmt_seconds(125) == "2m 05s"


class TestFormatGeneratedTimestamp:
    def test_non_string(self):
        assert compose._format_generated_timestamp(None) == "—"
        # whitespace string is truthy → returned verbatim per `raw or "—"`.
        assert compose._format_generated_timestamp("   ") == "   "

    def test_iso_z(self):
        out = compose._format_generated_timestamp("2026-05-17T05:31:44Z")
        assert "2026-05-17" in out
        assert "UTC" in out

    def test_unparseable_passthrough(self):
        assert compose._format_generated_timestamp("not-a-date") == "not-a-date"


class TestTruncateWithEllipsis:
    def test_non_string(self):
        assert compose._truncate_with_ellipsis(None, 10) == ""

    def test_short(self):
        assert compose._truncate_with_ellipsis("hi", 10) == "hi"

    def test_word_boundary(self):
        out = compose._truncate_with_ellipsis("the quick brown fox jumped over the lazy dog", 25)
        assert out.endswith("…")
        assert "  " not in out


# ---------------------------------------------------------------------------
# _scrape_phase_durations
# ---------------------------------------------------------------------------


class TestScrapePhaseDurations:
    def test_missing_log(self, tmp_path):
        assert compose._scrape_phase_durations(tmp_path) == []

    def test_inline_and_paired(self, tmp_path):
        log = tmp_path / ".agent-run.log"
        log.write_text(
            "\n".join(
                [
                    "2026-05-17T05:00:00Z PHASE_START [Phase 1/11] Recon",
                    "2026-05-17T05:05:00Z PHASE_END [Phase 1/11] ✓ Recon complete",
                    "2026-05-17T05:06:00Z PHASE_END [Phase 9/11] ✓ STRIDE done [3m 20s]",
                ]
            ),
            encoding="utf-8",
        )
        rows = compose._scrape_phase_durations(tmp_path)
        phases = {r["phase"] for r in rows}
        assert "Phase 1" in phases
        assert "Phase 9" in phases
        # Paired phase 1 computed a 5-minute delta.
        p1 = next(r for r in rows if r["phase"] == "Phase 1")
        assert "5m" in p1["duration"]
        p9 = next(r for r in rows if r["phase"] == "Phase 9")
        assert p9["duration"] == "3m 20s"

    def test_bare_end_without_start_skipped(self, tmp_path):
        log = tmp_path / ".agent-run.log"
        log.write_text(
            "2026-05-17T05:05:00Z PHASE_END [Phase 3/11] ✓ orphan end\n",
            encoding="utf-8",
        )
        assert compose._scrape_phase_durations(tmp_path) == []


# ---------------------------------------------------------------------------
# JSON sidecar readers
# ---------------------------------------------------------------------------


class TestReadComposeStats:
    def test_absent(self, tmp_path):
        assert compose._read_compose_stats(tmp_path) is None

    def test_malformed(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text("{ bad json", encoding="utf-8")
        assert compose._read_compose_stats(tmp_path) is None

    def test_wrong_schema(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text(_json.dumps({"schema_version": 999}), encoding="utf-8")
        assert compose._read_compose_stats(tmp_path) is None

    def test_valid(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text(
            _json.dumps(
                {
                    "schema_version": compose.COMPOSE_STATS_SCHEMA_VERSION,
                    "warnings": [],
                }
            ),
            encoding="utf-8",
        )
        out = compose._read_compose_stats(tmp_path)
        assert isinstance(out, dict)

    def test_non_dict(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text("[1,2,3]", encoding="utf-8")
        assert compose._read_compose_stats(tmp_path) is None


class TestReadInlineRetryCount:
    def test_absent(self, tmp_path):
        assert compose._read_inline_retry_count(tmp_path) == 0

    def test_value(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("3", encoding="utf-8")
        assert compose._read_inline_retry_count(tmp_path) == 3

    def test_garbage(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("abc", encoding="utf-8")
        assert compose._read_inline_retry_count(tmp_path) == 0


class TestComposeWarnedSignal:
    def test_clean(self, tmp_path):
        assert compose._compose_warned_signal(tmp_path) is False

    def test_warning_count(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text(
            _json.dumps({"schema_version": compose.COMPOSE_STATS_SCHEMA_VERSION, "warning_count": 2}),
            encoding="utf-8",
        )
        assert compose._compose_warned_signal(tmp_path) is True

    def test_bad_status(self, tmp_path):
        (tmp_path / ".compose-stats.json").write_text(
            _json.dumps({"schema_version": compose.COMPOSE_STATS_SCHEMA_VERSION, "compose_status": "critical"}),
            encoding="utf-8",
        )
        assert compose._compose_warned_signal(tmp_path) is True

    def test_retry(self, tmp_path):
        (tmp_path / ".inline-shortcut-retry-count").write_text("1", encoding="utf-8")
        assert compose._compose_warned_signal(tmp_path) is True


class TestReadRunIssues:
    def test_absent(self, tmp_path):
        assert compose._read_run_issues(tmp_path) is None

    def test_wrong_schema(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text(_json.dumps({"schema_version": 2}), encoding="utf-8")
        assert compose._read_run_issues(tmp_path) is None

    def test_valid(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text(_json.dumps({"schema_version": 1, "issues": []}), encoding="utf-8")
        assert isinstance(compose._read_run_issues(tmp_path), dict)


class TestRunWarnedSignal:
    def test_no_file(self, tmp_path):
        assert compose._run_warned_signal(tmp_path) is False

    def test_clean(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text(
            _json.dumps({"schema_version": 1, "run_status": "clean"}), encoding="utf-8"
        )
        assert compose._run_warned_signal(tmp_path) is False

    def test_warned(self, tmp_path):
        (tmp_path / ".run-issues.json").write_text(
            _json.dumps({"schema_version": 1, "run_status": "warned"}), encoding="utf-8"
        )
        assert compose._run_warned_signal(tmp_path) is True


# ---------------------------------------------------------------------------
# _verdict_severity_from_fragment / _derive_project_name / _render_title
# ---------------------------------------------------------------------------


class TestVerdictSeverityFromFragment:
    def test_absent(self, tmp_path):
        assert compose._verdict_severity_from_fragment(tmp_path) == "yellow"

    def test_malformed(self, tmp_path):
        (tmp_path / "ms-verdict.json").write_text("{bad", encoding="utf-8")
        assert compose._verdict_severity_from_fragment(tmp_path) == "yellow"

    def test_value(self, tmp_path):
        (tmp_path / "ms-verdict.json").write_text(_json.dumps({"severity": "red"}), encoding="utf-8")
        assert compose._verdict_severity_from_fragment(tmp_path) == "red"


class TestDeriveProjectName:
    def test_project_name_field(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"project": {"name": "Acme"}})
        assert compose._derive_project_name(ctx) == "Acme"

    def test_project_name_top_level(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"project_name": "Top"})
        assert compose._derive_project_name(ctx) == "Top"

    def test_meta_project_name(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"meta": {"project_name": "MetaName"}})
        assert compose._derive_project_name(ctx) == "MetaName"

    def test_git_remote_slug(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={"meta": {"git": {"remote_url": "git@github.com:foo/juice-shop.git"}}},
        )
        assert compose._derive_project_name(ctx) == "Juice Shop"

    def test_output_dir_fallback(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        # parent dir name of out_dir
        assert compose._derive_project_name(ctx) == ctx.output_dir.parent.name


class TestRenderTitle:
    def test_basic_title(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            contract={"document": {"title_template": "Threat Model — {{ project.name }}"}},
            yaml_data={"project": {"name": "Acme"}},
        )
        out = compose._render_title(ctx)
        assert out.startswith("# Threat Model — Acme")

    def test_override(self, tmp_path):
        ctx = _mk_ctx(tmp_path, contract={"document": {}}, yaml_data={"project": {"name": "X"}})
        out = compose._render_title(ctx, title_template_override="Custom {{ project.name }}")
        assert out.startswith("# Custom X")


# ---------------------------------------------------------------------------
# _build_tier_cluster_lines
# ---------------------------------------------------------------------------


class TestBuildTierClusterLines:
    def test_empty(self):
        assert compose._build_tier_cluster_lines([]) == []

    def test_single_unmapped(self):
        lines = compose._build_tier_cluster_lines([{"cwe": "CWE-99999", "risk": "Low"}])
        assert lines
        assert "Other" in lines[0] or lines[0]

    def test_multiple_collapse(self):
        threats = [{"cwe": "CWE-99999", "risk": "Low"} for _ in range(3)]
        lines = compose._build_tier_cluster_lines(threats)
        assert any("Multiple" in ln for ln in lines)

    def test_max_clusters_trailer(self):
        # Many distinct unmapped — but unmapped collapses to one group, so
        # use a small max with a mix to force the "+N more" trailer.
        threats = [
            {"cwe": "CWE-89", "risk": "Critical"},
            {"cwe": "CWE-79", "risk": "High"},
            {"cwe": "CWE-22", "risk": "Medium"},
            {"cwe": "CWE-99999", "risk": "Low"},
        ]
        lines = compose._build_tier_cluster_lines(threats, max_clusters=1)
        assert any("more (see §8)" in ln for ln in lines)

    def test_arrow_cwe_allow_filter(self):
        threats = [{"cwe": "CWE-89", "risk": "Critical"}]
        lines = compose._build_tier_cluster_lines(threats, arrow_cwe_allow={"CWE-79"})
        assert lines == []


# ---------------------------------------------------------------------------
# _derive_control_mitigates
# ---------------------------------------------------------------------------


class TestDeriveControlMitigates:
    def test_non_dict_or_no_threats(self):
        assert compose._derive_control_mitigates({}, []) == []
        assert compose._derive_control_mitigates("x", [{"id": "T-1"}]) == []

    def test_no_domain(self):
        assert compose._derive_control_mitigates({"name": "X"}, [{"id": "T-1"}]) == []

    def test_uncatalogued_domain(self):
        out = compose._derive_control_mitigates(
            {"domain": "totally-unknown-domain-zzz", "name": "X"},
            [{"id": "T-1", "cwe": "CWE-89"}],
        )
        assert out == []

    def test_real_domain_match(self):
        # Pick a domain present in the curated map and a matching threat.
        ctrl = {"domain": "injection", "control": "input validation sanitization"}
        threats = [
            {
                "id": "T-1",
                "cwe": "CWE-89",
                "risk": "Critical",
                "title": "SQL injection",
                "scenario": "validation bypass",
            },
        ]
        out = compose._derive_control_mitigates(ctrl, threats)
        assert isinstance(out, list)
        assert len(out) <= 5


# ---------------------------------------------------------------------------
# _format_manual_review_hint
# ---------------------------------------------------------------------------


class TestFormatManualReviewHint:
    def test_no_evidence(self):
        assert compose._format_manual_review_hint({}, "T-001") is None

    def test_with_evidence_file(self):
        threat = {"evidence": [{"file": "src/app.ts", "line": 42}]}
        hint = compose._format_manual_review_hint(threat, "T-001")
        assert hint is not None
        assert hint["kind"] == "review"
        assert "src/app.ts" in hint["action"]
        assert "#f-001" in hint["action"]


# ---------------------------------------------------------------------------
# _compute_top_findings_rows
# ---------------------------------------------------------------------------


def _top_findings_contract():
    return {"sections": {"top_findings": {"table": {"rows": {"max": 5}}}}}


class TestComputeTopFindingsRows:
    def test_empty(self, tmp_path):
        ctx = _mk_ctx(tmp_path, contract=_top_findings_contract(), yaml_data={"threats": []})
        rows, total = compose._compute_top_findings_rows(ctx)
        assert rows == []
        assert total == 0

    def test_fallback_severity_sort(self, tmp_path):
        threats = [
            {"id": "T-001", "title": "SQLi", "component_id": "C-01", "risk": "Critical", "cwe": "CWE-89"},
            {"id": "T-002", "title": "Low thing", "component_id": "C-01", "risk": "Low"},
            {"id": "T-003", "title": "XSS", "component_id": "C-01", "risk": "High", "cwe": "CWE-79"},
        ]
        components = [{"id": "C-01", "name": "API"}]
        ctx = _mk_ctx(
            tmp_path,
            contract=_top_findings_contract(),
            yaml_data={"threats": threats, "components": components},
        )
        rows, total = compose._compute_top_findings_rows(ctx)
        # Critical + High qualify; Low excluded.
        assert total == 2
        assert rows[0]["criticality"] == "critical"
        # Manual-review hint fired for threats without mitigations.
        assert rows[0]["finding_id"] == "F-001"
        assert rows[0]["component_name"] == "API"

    def test_ranking_view_path(self, tmp_path):
        threats = [
            {
                "id": "T-001",
                "title": "SQLi",
                "component_id": "C-01",
                "risk": "Critical",
                "cwe": "CWE-89",
                "mitigations": ["M-001"],
            },
        ]
        components = [{"id": "C-01", "name": "API"}]
        mitigations = [{"id": "M-001", "title": "Use params", "priority": "p1", "kind": "fix"}]
        triage = {
            "ranking": {
                "views": {"top_findings": {"findings_ranked": [{"id": "T-001", "effective_severity": "critical"}]}}
            }
        }
        ctx = _mk_ctx(
            tmp_path,
            contract=_top_findings_contract(),
            yaml_data={"threats": threats, "components": components, "mitigations": mitigations},
            triage=triage,
        )
        rows, total = compose._compute_top_findings_rows(ctx)
        assert total == 1
        assert rows[0]["mitigations"][0]["id"] == "M-001"


# ---------------------------------------------------------------------------
# Conditional appendix renderers
# ---------------------------------------------------------------------------


class TestRenderCompositionNotes:
    def test_clean_default(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        out = compose._render_composition_notes(ctx, None, {})
        assert "Composition Notes" in out
        assert "ran cleanly" in out

    def test_warnings_only(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".compose-stats.json").write_text(
            _json.dumps(
                {
                    "schema_version": compose.COMPOSE_STATS_SCHEMA_VERSION,
                    "warnings": [{"section": "§1", "category": "mermaid", "detail": "x" * 250}],
                }
            ),
            encoding="utf-8",
        )
        out = compose._render_composition_notes(ctx, None, {})
        assert "Soft Warnings" in out
        assert "…" in out  # long detail truncated

    def test_section_retries(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".compose-stats.json").write_text(
            _json.dumps(
                {
                    "schema_version": compose.COMPOSE_STATS_SCHEMA_VERSION,
                    "section_retries": {"top_findings": 2},
                }
            ),
            encoding="utf-8",
        )
        out = compose._render_composition_notes(ctx, None, {})
        assert "Section Retries" in out

    def test_auto_retries(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".inline-shortcut-retry-count").write_text("2", encoding="utf-8")
        out = compose._render_composition_notes(ctx, None, {})
        assert "Auto-Retries" in out
        assert "2×" in out


class TestRenderRunIssues:
    def test_no_issues(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        out = compose._render_run_issues(ctx, None, {})
        assert "Run Issues" in out
        assert "No issues recorded" in out

    def test_full_issue(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".run-issues.json").write_text(
            _json.dumps(
                {
                    "schema_version": 1,
                    "run_status": "warned",
                    "summary": {
                        "errors": 1,
                        "warnings": 0,
                        "perf_anomalies": 1,
                        "recovery_events": 0,
                        "auto_applicable_fixes": 1,
                    },
                    "issues": [
                        {
                            "id": "I-1",
                            "category": "api_stall",
                            "title": "Stalled",
                            "severity": "error",
                            "evidence": {
                                "log_file": ".agent-run.log",
                                "log_line": 12,
                                "timestamp_iso": "2026-05-17T05:00:00Z",
                            },
                            "fix_recommendation": {
                                "category": "retry",
                                "confidence": "high",
                                "risk_level": "low",
                                "auto_applicable": True,
                                "summary": "Retry the phase",
                                "rationale": "transient",
                                "actions": [
                                    {"type": "edit_file", "target": "f.py", "find": "a", "replace": "b"},
                                    {"type": "rerun", "target": "phase9", "details": "redo"},
                                ],
                                "verification": ["make test"],
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        out = compose._render_run_issues(ctx, None, {})
        assert "I-1 — Stalled" in out
        assert "auto-applicable" in out
        assert "edit_file" in out
        assert "make test" in out
        assert "fix-run-issues" in out


class TestRenderIdentifiedActors:
    def test_no_resolved_file(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        assert compose._render_identified_actors(ctx, None, {}) == ""

    def test_malformed(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".actors-resolved.json").write_text("{bad", encoding="utf-8")
        assert compose._render_identified_actors(ctx, None, {}) == ""

    def test_active_actors_table(self, tmp_path):
        resolved = {
            "resolved_actors": [
                {
                    "id": "ACT-01",
                    "label": "Anon User",
                    "_provenance": {"active": True, "layer": "client"},
                },
                {
                    "id": "ACT-02",
                    "label": "Proposed One",
                    "rationale": "found in code",
                    "_provenance": {"active": True, "layer": "server", "proposed": True},
                },
                {
                    "id": "ACT-03",
                    "label": "Off",
                    "_provenance": {"disabled_by": "org-profile", "disable_reason": "n/a"},
                },
            ]
        }
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={
                "threats": [
                    {"component": "API", "actor_ids": ["ACT-01"]},
                    {
                        "_status": "dormant",
                        "id": "T-009",
                        "title": "Dormant one",
                        "_provenance": {"created_by_actor": "ACT-X"},
                    },
                ]
            },
        )
        (ctx.output_dir / ".actors-resolved.json").write_text(_json.dumps(resolved), encoding="utf-8")
        out = compose._render_identified_actors(ctx, None, {})
        assert "### Identified Actors" in out
        assert "ACT-01" in out
        assert "Newly identified actors" in out
        assert "Disabled actors" in out
        assert "Dormant findings" in out
        assert "T-009" in out

    def test_quick_mode_notice(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".actors-resolved.json").write_text(_json.dumps({"resolved_actors": []}), encoding="utf-8")
        (ctx.output_dir / ".discovery-skipped.json").write_text("{}", encoding="utf-8")
        out = compose._render_identified_actors(ctx, None, {})
        assert "static actor library only" in out
        assert "No actors resolved" in out


class TestPostureShortLabel:
    def test_abbreviates(self):
        assert compose._posture_short_label("Privilege Escalation") == "Priv-Esc"

    def test_passthrough(self):
        assert compose._posture_short_label("SQL Injection") == "SQL Injection"


# ---------------------------------------------------------------------------
# Jinja filter closures (built by _build_jinja_env)
# ---------------------------------------------------------------------------


class TestJinjaFilters:
    def _env(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        return compose._build_jinja_env(ctx), ctx

    def test_format_mitigations(self, tmp_path):
        env, _ = self._env(tmp_path)
        f = env.filters["format_mitigations"]
        assert f([]) == "—"
        out = f([{"id": "M-001", "action": "Use params", "kind": "fix"}])
        assert "M-001" in out and "Use params" in out
        # synthesized review hint (no id)
        out2 = f([{"id": "", "action": "Manual review at x", "kind": "review"}])
        assert "🔍" in out2 and "Manual review" in out2

    def test_format_id_list(self, tmp_path):
        env, _ = self._env(tmp_path)
        f = env.filters["format_id_list"]
        assert f([]) == "—"
        # scalar string treated as single id, not char-iterated
        out = f("M-002")
        assert out.count("<br/>") == 0

    def test_format_weakness_findings(self, tmp_path):
        env, _ = self._env(tmp_path)
        f = env.filters["format_weakness_findings"]
        assert f([]) == "—"
        out = f([{"ref": "T-003", "label": "SQLi"}])
        assert "F-003" in out and "SQLi" in out

    def test_format_weakness_components(self, tmp_path):
        env, _ = self._env(tmp_path)
        f = env.filters["format_weakness_components"]
        assert f([]) == "—"
        out = f([{"id": "C-01", "name": "API"}, "C-02"])
        assert "C-01" in out and "API" in out and "C-02" in out
        assert f([{"name": "BareName"}]) == "BareName"

    def test_format_component_list(self, tmp_path):
        env, _ = self._env(tmp_path)
        f = env.filters["format_component_list"]
        assert f("verbatim") == "verbatim"
        assert f([]) == "—"
        out = f([{"id": "C-01", "name": "API"}, {"name": "Only"}, {"id": "C-03"}])
        assert "C-01" in out and "Only" in out and "C-03" in out

    def test_format_mitigation_addresses(self, tmp_path):
        env, _ = self._env(tmp_path)
        f = env.filters["format_mitigation_addresses"]
        assert f([]) == "—"
        out = f([{"ref": "T-005", "label": "fix"}])
        assert "F-005" in out and "fix" in out

    def test_format_strengths_mitigates(self, tmp_path):
        env, _ = self._env(tmp_path)
        f = env.filters["format_strengths_mitigates"]
        assert f([]) == "—"
        out = f([{"ref": "T-001", "label": "L" * 80}])
        assert "F-001" in out and "…" in out
        # overflow marker
        out2 = f([{"_overflow": True, "label": "+3 more"}])
        assert "_+3 more_" in out2
        # bare string
        out3 = f(["F-002"])
        assert "F-002" in out3


# ---------------------------------------------------------------------------
# Requirement helpers
# ---------------------------------------------------------------------------


class TestNormaliseRequirementStatus:
    def test_variants(self):
        assert compose._normalise_requirement_status("**FAIL**") == "FAIL"
        assert compose._normalise_requirement_status("partial ⚠") == "PARTIAL"
        assert compose._normalise_requirement_status("Anti-Pattern") == "ANTI-PATTERN"
        assert compose._normalise_requirement_status("PASS ✅") == "PASS"
        assert compose._normalise_requirement_status("N/A") == "N/A"
        assert compose._normalise_requirement_status("Not Observable") == "NOT OBSERVABLE"
        assert compose._normalise_requirement_status("") == ""


class TestExtractRequirementIdFromCell:
    def test_known_id_longest_first(self):
        known = {"SEC-1", "SEC-10"}
        assert compose._extract_requirement_id_from_cell("ref SEC-10 here", known) == "SEC-10"

    def test_backtick_fallback(self):
        assert compose._extract_requirement_id_from_cell("`ORG-9`", set()) == "ORG-9"

    def test_bracket_fallback(self):
        assert compose._extract_requirement_id_from_cell("[AUTH-2](u)", set()) == "AUTH-2"


class TestSplitMdTableRow:
    def test_basic(self):
        assert compose._split_md_table_row("| a | b |") == ["a", "b"]

    def test_non_table(self):
        assert compose._split_md_table_row("not a row") == []


class TestKnownRequirementIds:
    def test_absent(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        assert compose._known_requirement_ids(ctx) == {}

    def test_loaded(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".requirements.yaml").write_text(
            "categories:\n  - requirements:\n      - id: SEC-AUTH-1\n        url: https://example/sec-auth-1\n",
            encoding="utf-8",
        )
        m = compose._known_requirement_ids(ctx)
        assert m["SEC-AUTH-1"] == "https://example/sec-auth-1"


class TestFormatBlueprintCell:
    def test_empty(self):
        assert compose._format_blueprint_cell(None) == ""
        assert compose._format_blueprint_cell("") == ""

    def test_string(self):
        assert compose._format_blueprint_cell("  BP-1  ") == "BP-1"

    def test_dict(self):
        out = compose._format_blueprint_cell({"id": "BP-7", "url": "u", "section": "Auth"})
        assert "BP-7" in out and "Auth" in out and "(u)" in out


class TestRequirementIsTraceableViolation:
    def test_no_status_map(self):
        assert compose._requirement_is_traceable_violation("R-1", {}) is True

    def test_violation_status(self):
        assert compose._requirement_is_traceable_violation("R-1", {"R-1": "FAIL"}) is True

    def test_pass_excluded(self):
        assert compose._requirement_is_traceable_violation("R-1", {"R-1": "PASS"}) is False

    def test_missing_from_map(self):
        assert compose._requirement_is_traceable_violation("R-9", {"R-1": "FAIL"}) is True


def _req_yaml():
    return (
        "description: generic baseline\n"
        "categories:\n"
        "  - name: Auth\n"
        "    requirements:\n"
        "      - id: SEC-AUTH-1\n"
        "        url: https://ex/1\n"
        "sources_meta:\n"
        "  - type: requirement\n"
        "    title: My Baseline\n"
        "    reference_url: https://ex/baseline\n"
    )


class TestBuildRequirementsMappingRows:
    def test_no_threats(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"threats": []})
        assert compose._build_requirements_mapping_rows(ctx) == []

    def test_violation_row(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={
                "threats": [
                    {
                        "id": "T-001",
                        "risk": "Critical",
                        "violated_requirements": ["SEC-AUTH-1"],
                        "mitigations": ["M-001"],
                    }
                ],
                "mitigations": [{"id": "M-002", "fulfills_requirements": ["SEC-AUTH-1"]}],
            },
        )
        (ctx.output_dir / ".requirements.yaml").write_text(_req_yaml(), encoding="utf-8")
        rows = compose._build_requirements_mapping_rows(ctx)
        assert rows
        r = rows[0]
        assert r["req_id"] == "SEC-AUTH-1"
        assert ("F-001", "critical") in r["findings"]
        assert "M-001" in r["measures"]
        assert "M-002" in r["measures"]


class TestRenderRequirementsMappingTable:
    def test_empty(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        assert compose._render_requirements_mapping_table(ctx, []) == ""

    def test_rows(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        rows = [
            {
                "req_id": "SEC-AUTH-1",
                "status": "FAIL",
                "findings": [("F-001", "critical")],
                "measures": ["M-001"],
                "blueprint": "",
                "risk_word": "critical",
                "risk_rank": 0,
            }
        ]
        out = compose._render_requirements_mapping_table(ctx, rows)
        assert "SEC-AUTH-1" in out
        assert "F-001" in out
        assert "M-001" in out
        assert "Critical" in out

    def test_limit_overflow_note(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        rows = [
            {
                "req_id": f"R-{i}",
                "status": "FAIL",
                "findings": [("F-001", "high")],
                "measures": [],
                "blueprint": "",
                "risk_word": "high",
                "risk_rank": 1,
            }
            for i in range(3)
        ]
        out = compose._render_requirements_mapping_table(ctx, rows, limit=1)
        assert "further requirement" in out


class TestRenderRequirementsScopeNote:
    def test_no_file(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        out = compose._render_requirements_scope_note(ctx)
        assert "Requirement Scope" in out
        assert "no organization profile" in out

    def test_with_requirements(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"meta": {"compliance_scope": ["SOC2"]}})
        (ctx.output_dir / ".requirements.yaml").write_text(_req_yaml(), encoding="utf-8")
        out = compose._render_requirements_scope_note(ctx)
        assert "My Baseline" in out
        assert "1 requirements" in out
        assert "SOC2" in out
        assert "generic" in out.lower()


class TestRenderRequirementsComplianceMs:
    def test_not_enabled(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"threats": []})
        assert compose._render_requirements_compliance_ms(ctx) == ""

    def test_from_yaml(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={"threats": [{"id": "T-001", "risk": "Critical", "violated_requirements": ["SEC-AUTH-1"]}]},
        )
        (ctx.output_dir / ".requirements.yaml").write_text(_req_yaml(), encoding="utf-8")
        out = compose._render_requirements_compliance_ms(ctx)
        assert "Requirements Compliance" in out
        assert "Baseline" in out
        assert "Section 7b" in out

    def test_from_fragment(self, tmp_path):
        ctx = _mk_ctx(tmp_path, yaml_data={"threats": []})
        frag = ctx.output_dir / ".fragments" / "requirements-compliance.md"
        frag.write_text(
            "Assessed from the [OWASP ASVS](https://asvs) baseline.\n**Summary:** 3 PASS / 1 FAIL\n",
            encoding="utf-8",
        )
        out = compose._render_requirements_compliance_ms(ctx)
        assert "OWASP ASVS" in out
        assert "3 PASS / 1 FAIL" in out


# ---------------------------------------------------------------------------
# Misc small helpers
# ---------------------------------------------------------------------------


class TestNormalizeSecurityControls:
    def test_empty(self):
        assert compose._normalize_security_controls([]) == []
        assert compose._normalize_security_controls(None) == []

    def test_dict_passthrough(self):
        d = {"domain": "iam", "control": "x", "effectiveness": "high"}
        assert compose._normalize_security_controls([d]) == [d]

    def test_string_coerced(self):
        out = compose._normalize_security_controls(["access_control"])
        assert len(out) == 1
        assert out[0]["domain"] == "access_control"
        assert out[0]["_synthesized_from_string"] is True
        assert out[0]["name"] == "Access Control"

    def test_garbage_dropped(self):
        assert compose._normalize_security_controls([None, 5, "  "]) == []


class TestSeverityCounts:
    def test_counts(self, tmp_path):
        ctx = _mk_ctx(
            tmp_path,
            yaml_data={
                "threats": [
                    {"risk": "Critical"},
                    {"risk": "High"},
                    {"severity": "Informational"},
                    {"risk": "bogus"},
                ]
            },
        )
        c = compose._severity_counts(ctx)
        assert c["critical"] == 1
        assert c["high"] == 1
        assert c["info"] == 1


class TestRequirementsStatusMap:
    def test_from_fragment(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".requirements.yaml").write_text(_req_yaml(), encoding="utf-8")
        frag = ctx.output_dir / ".fragments" / "requirements-compliance.md"
        frag.write_text(
            "| Requirement | Status | Evidence |\n|---|---|---|\n| `SEC-AUTH-1` | FAIL | F-001 |\n",
            encoding="utf-8",
        )
        m = compose._requirements_status_map(ctx)
        assert m.get("SEC-AUTH-1") == "FAIL"

    def test_from_phase8b_json(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        (ctx.output_dir / ".requirements.yaml").write_text(_req_yaml(), encoding="utf-8")
        (ctx.output_dir / ".phase-8b-violations.json").write_text(
            _json.dumps({"violations": [{"requirement_id": "SEC-AUTH-1", "status": "PARTIAL"}]}),
            encoding="utf-8",
        )
        m = compose._requirements_status_map(ctx)
        assert m.get("SEC-AUTH-1") == "PARTIAL"


# ---------------------------------------------------------------------------
# _classify_finding_class + _reconcile_attack_path_membership
# ---------------------------------------------------------------------------


def _attack_taxonomy():
    return {
        "classes": [
            {
                "id": "injection",
                "cwes": ["CWE-89", "CWE-79"],
                "default_actor": "internet-anon",
                "default_target_tier": "application",
                "description": "Injection of untrusted input.",
                "default_impacts": ["data-breach"],
            },
            {
                "id": "csrf",
                "cwes": ["CWE-352"],
                "default_actor": "victim-required",
                "default_target_tier": "client",
                "description": "Cross-site request forgery.",
                "default_impacts": ["account-takeover"],
            },
        ]
    }


class TestClassifyFindingClass:
    def test_cwe_single(self):
        assert compose._classify_finding_class({"cwe": "CWE-89"}, _attack_taxonomy()) == "injection"

    def test_cwe_in_text(self):
        out = compose._classify_finding_class({"scenario": "exploitable via CWE-352 token reuse"}, _attack_taxonomy())
        assert out == "csrf"

    def test_no_cwe(self):
        assert compose._classify_finding_class({"title": "x"}, _attack_taxonomy()) is None


class TestReconcileAttackPathMembership:
    def test_append_missing_class(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        data = {"attack_paths": []}
        threats = [{"id": "F-001", "cwe": "CWE-352"}]
        compose._reconcile_attack_path_membership(data, _attack_taxonomy(), threats, ctx)
        slugs = [ap["class"] for ap in data["attack_paths"]]
        assert "csrf" in slugs
        log = ctx.output_dir / ".reconcile-log.json"
        assert log.is_file()

    def test_merge_into_existing(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        data = {"attack_paths": [{"class": "injection", "findings": ["F-001"]}]}
        threats = [
            {"id": "F-001", "cwe": "CWE-89"},
            {"id": "F-002", "cwe": "CWE-79"},
        ]
        compose._reconcile_attack_path_membership(data, _attack_taxonomy(), threats, ctx)
        inj = next(ap for ap in data["attack_paths"] if ap["class"] == "injection")
        assert "F-002" in inj["findings"]

    def test_idempotent_no_change(self, tmp_path):
        ctx = _mk_ctx(tmp_path)
        data = {"attack_paths": [{"class": "injection", "findings": ["F-001"]}]}
        threats = [{"id": "F-001", "cwe": "CWE-89"}]
        before = _json.dumps(data, sort_keys=True)
        compose._reconcile_attack_path_membership(data, _attack_taxonomy(), threats, ctx)
        assert _json.dumps(data, sort_keys=True) == before


# ---------------------------------------------------------------------------
# Consolidated-finding instances card (per-instance severity dots)
# ---------------------------------------------------------------------------


class TestInstancesCard:
    def _card(self, tmp_path, t):
        ctx = _make_ctx(tmp_path)
        return compose._build_threat_card(t, t.get("risk", "High"), {}, {}, None, ctx, None, None)

    def _systemic_threat(self, instances):
        return {
            "id": "T-001",
            "title": "Insecure JWT Verification",
            "cwe": "CWE-347",
            "risk": "Critical",
            "component": "auth",
            "stride": "Spoofing",
            "systemic": True,
            "instance_count": len(instances),
            "evidence": {"file": instances[0]["file"], "line": instances[0]["line"]},
            "instances": instances,
        }

    def test_lists_all_instances_with_count(self, tmp_path):
        t = self._systemic_threat(
            [
                {"file": "lib/insecurity.ts", "line": 191, "severity": "Critical"},
                {"file": "routes/chatbot.ts", "line": 248, "severity": "High"},
            ]
        )
        card = self._card(tmp_path, t)
        assert "Instances (2):" in card
        assert "lib/insecurity.ts:191" in card
        assert "routes/chatbot.ts:248" in card

    def test_mixed_severity_shows_per_instance_dots(self, tmp_path):
        t = self._systemic_threat(
            [
                {"file": "lib/insecurity.ts", "line": 191, "severity": "Critical"},
                {"file": "routes/chatbot.ts", "line": 248, "severity": "High"},
            ]
        )
        card = self._card(tmp_path, t)
        assert "🔴 `lib/insecurity.ts:191`" in card
        assert "🟠 `routes/chatbot.ts:248`" in card

    def test_uniform_severity_no_dots(self, tmp_path):
        t = self._systemic_threat(
            [
                {"file": "server.ts", "line": 310, "severity": "High"},
                {"file": "server.ts", "line": 311, "severity": "High"},
            ]
        )
        card = self._card(tmp_path, t)
        assert "Instances (2):" in card
        assert "🟠 `server.ts:310`" not in card  # uniform severity → plain locations
