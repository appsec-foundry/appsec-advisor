"""Unit tests for scripts/enrich_asset_links.py (deterministic linked_threats)."""

from __future__ import annotations

from pathlib import Path

import enrich_asset_links as eal
import yaml


# ---------------------------------------------------------------------------
# tokenisation helpers
# ---------------------------------------------------------------------------
class TestTokens:
    def test_basic(self):
        assert eal._tokens("Session Token Storage") == {"session", "token", "storage"}

    def test_stopwords_and_short_dropped(self):
        # "of", "the", "in" are stopwords; "is" too; 2-char dropped by length
        assert eal._tokens("the JWT in localStorage") == {"jwt", "localstorage"}

    def test_empty(self):
        assert eal._tokens("") == set()
        assert eal._tokens(None) == set()


class TestBasenameTokens:
    def test_strips_path_and_ext(self):
        # "service" is a stopword -> only "auth" survives
        assert eal._basename_tokens("/src/foo/authService.ts") == {"auth"}

    def test_camelcase_split(self):
        # camelCase split yields user+profile; "user" is a stopword
        assert eal._basename_tokens("userProfile.js") == {"profile"}
        # a non-stopword camelCase pair survives split
        assert eal._basename_tokens("encryptionKeys.js") == {"encryption", "keys"}

    def test_dot_dash(self):
        toks = eal._basename_tokens("rate-limit.config.js")
        assert "rate" in toks and "limit" in toks

    def test_empty(self):
        assert eal._basename_tokens("") == set()
        assert eal._basename_tokens(None) == set()


# ---------------------------------------------------------------------------
# _classify_asset
# ---------------------------------------------------------------------------
class TestClassify:
    def test_credentials(self):
        assert eal._classify_asset({"name": "User credentials store"}) == "credentials"

    def test_key_material_wins_over_session(self):
        # name mentions both encryption key and jwt token -> key_material first
        a = {"name": "Encryption key for JWT token", "description": ""}
        assert eal._classify_asset(a) == "key_material"

    def test_session_token(self):
        assert eal._classify_asset({"name": "bearer token store"}) == "session_token"

    def test_ftp_before_uploaded(self):
        assert eal._classify_asset({"name": "/ftp directory"}) == "ftp_files"

    def test_matches_in_description(self):
        a = {"name": "X", "description": "holds the product catalog"}
        assert eal._classify_asset(a) == "product_data"

    def test_matches_in_id(self):
        a = {"id": "payment-records", "name": "X"}
        assert eal._classify_asset(a) == "payment_data"

    def test_unclassified(self):
        assert eal._classify_asset({"name": "random widget"}) == ""


# ---------------------------------------------------------------------------
# _threat_relevance
# ---------------------------------------------------------------------------
class TestRelevance:
    def test_non_dict_threat(self):
        assert eal._threat_relevance({}, "credentials", "junk") == (False, "")

    def test_cwe_match(self):
        asset = {"name": "session tokens"}
        threat = {"cwe": "cwe-79", "title": "irrelevant words here"}
        rel, reason = eal._threat_relevance(asset, "session_token", threat)
        assert rel and reason.startswith("cwe_match:CWE-79")

    def test_cwe_not_in_class(self):
        asset = {"name": "challenge state"}
        threat = {"cwe": "CWE-79", "title": "zzz"}
        rel, _ = eal._threat_relevance(asset, "challenge_state", threat)
        assert rel is False

    def test_keyword_overlap_title(self):
        asset = {"name": "encryption keys directory", "description": "premium signing material"}
        threat = {"cwe": "", "title": "Encryption keys leaked via directory traversal"}
        rel, reason = eal._threat_relevance(asset, "key_material", threat)
        assert rel and reason.startswith("keyword_overlap:")

    def test_keyword_overlap_via_file_basename(self):
        # 1 token from title + 1 from basename -> ≥2 overlap
        asset = {"name": "payment wallet records", "description": ""}
        threat = {"cwe": "", "title": "payment leak", "evidence": {"file": "/src/x/walletRecords.js"}}
        rel, reason = eal._threat_relevance(asset, "payment_data", threat)
        assert rel and "keyword_overlap" in reason

    def test_evidence_list_form(self):
        asset = {"name": "payment wallet", "description": ""}
        threat = {"cwe": "", "title": "zzz", "evidence": [{"file": "payment-wallet.js"}]}
        rel, _ = eal._threat_relevance(asset, "payment_data", threat)
        assert rel

    def test_evidence_non_dict_list_yields_no_file_tokens(self):
        # evidence is a list whose first item isn't a dict -> file_tokens = set()
        asset = {"name": "session tokens store", "description": ""}
        threat = {"cwe": "", "title": "session tokens leak", "evidence": ["junk"]}
        rel, reason = eal._threat_relevance(asset, "session_token", threat)
        # overlap comes only from title (session, tokens) -> still relevant
        assert rel and "keyword_overlap" in reason

    def test_no_signal(self):
        asset = {"name": "alpha beta", "description": ""}
        threat = {"cwe": "CWE-999", "title": "gamma delta", "evidence": {}}
        rel, _ = eal._threat_relevance(asset, "credentials", threat)
        assert rel is False


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------
class TestEnrich:
    def test_bad_shapes_passthrough(self):
        data = {"assets": "notalist", "threats": []}
        out, summary = eal.enrich(data)
        assert out is data and summary == {}

    def test_non_dict_asset_skipped(self):
        data = {"assets": ["junk", {"id": "A", "name": "random thing"}], "threats": []}
        _, summary = eal.enrich(data)
        assert "A" in summary

    def test_unclassified_keeps_links(self):
        data = {
            "assets": [{"id": "A", "name": "random widget", "linked_threats": ["T-1", "T-2"]}],
            "threats": [],
        }
        _, summary = eal.enrich(data)
        assert summary["A"]["class"] == "unclassified"
        assert summary["A"]["kept"] == 2

    def test_prune_irrelevant_and_flag(self):
        data = {
            "assets": [
                {
                    "id": "tokens",
                    "name": "session tokens",
                    "linked_threats": ["T-IRREL"],
                }
            ],
            "threats": [
                {"id": "T-IRREL", "cwe": "CWE-999", "title": "yaml bomb upload"},
            ],
        }
        out, summary = eal.enrich(data)
        a = out["assets"][0]
        assert a["linked_threats"] == []
        assert any("auto_pruned_threats:T-IRREL" in f for f in a["evidence_flags"])
        assert summary["tokens"]["pruned"] == ["T-IRREL"]

    def test_add_relevant_via_cwe(self):
        data = {
            "assets": [{"id": "tokens", "name": "session tokens", "linked_threats": []}],
            "threats": [{"id": "T-XSS", "cwe": "CWE-79", "title": "stored xss"}],
        }
        out, summary = eal.enrich(data)
        assert "T-XSS" in out["assets"][0]["linked_threats"]
        assert summary["tokens"]["added"] == ["T-XSS"]

    def test_preserves_prior_ordering(self):
        data = {
            "assets": [
                {
                    "id": "tokens",
                    "name": "session tokens",
                    "linked_threats": ["T-B", "T-A"],
                }
            ],
            "threats": [
                {"id": "T-A", "cwe": "CWE-79", "title": "a"},
                {"id": "T-B", "cwe": "CWE-352", "title": "b"},
            ],
        }
        out, _ = eal.enrich(data)
        # both relevant; prior order [T-B, T-A] preserved
        assert out["assets"][0]["linked_threats"] == ["T-B", "T-A"]

    def test_manual_pin_preserved(self):
        # T-MANUAL has no signal but is pinned manually -> kept
        data = {
            "assets": [
                {
                    "id": "tokens",
                    "name": "session tokens",
                    "linked_threats": ["T-MANUAL"],
                    "linked_threats_manual": ["T-MANUAL"],
                }
            ],
            "threats": [{"id": "T-MANUAL", "cwe": "CWE-999", "title": "zzz"}],
        }
        out, summary = eal.enrich(data)
        assert "T-MANUAL" in out["assets"][0]["linked_threats"]
        assert summary["tokens"]["pruned"] == []

    def test_idempotent(self):
        data = {
            "assets": [{"id": "tokens", "name": "session tokens", "linked_threats": []}],
            "threats": [{"id": "T-XSS", "cwe": "CWE-79", "title": "xss"}],
        }
        out1, _ = eal.enrich(data)
        links1 = list(out1["assets"][0]["linked_threats"])
        out2, summary2 = eal.enrich(out1)
        assert out2["assets"][0]["linked_threats"] == links1
        assert summary2["tokens"]["added"] == []

    def test_asset_id_falls_back_to_name(self):
        data = {
            "assets": [{"name": "session tokens", "linked_threats": []}],
            "threats": [{"id": "T-XSS", "cwe": "CWE-79", "title": "xss"}],
        }
        _, summary = eal.enrich(data)
        assert "session tokens" in summary


# ---------------------------------------------------------------------------
# _format_summary
# ---------------------------------------------------------------------------
class TestFormatSummary:
    def test_counts_and_detail_lines(self):
        summary = {
            "A": {"class": "session_token", "kept": 1, "added": ["T-1"], "pruned": ["T-2"]},
            "B": {"class": "unclassified", "kept": 3},
        }
        out = eal._format_summary(summary)
        assert "2 asset(s) processed" in out
        assert "+1 added" in out and "-1 pruned" in out
        assert "A [session_token]" in out
        # B has no add/prune -> no detail line
        assert "B [" not in out

    def test_empty(self):
        assert "0 asset(s)" in eal._format_summary({})


# ---------------------------------------------------------------------------
# main / CLI
# ---------------------------------------------------------------------------
def _write_yaml(output_dir: Path, data) -> Path:
    p = output_dir / "threat-model.yaml"
    if isinstance(data, str):
        p.write_text(data, encoding="utf-8")
    else:
        p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return p


class TestMain:
    def test_missing_yaml(self, output_dir, capsys):
        rc = eal.main([str(output_dir)])
        assert rc == 1
        assert "no yaml" in capsys.readouterr().err

    def test_parse_error(self, output_dir, capsys):
        _write_yaml(output_dir, "key: [unterminated")
        rc = eal.main([str(output_dir)])
        assert rc == 1
        assert "could not parse" in capsys.readouterr().err

    def test_not_a_mapping(self, output_dir, capsys):
        _write_yaml(output_dir, "- just\n- a\n- list\n")
        rc = eal.main([str(output_dir)])
        assert rc == 1
        assert "did not parse to a mapping" in capsys.readouterr().err

    def test_writes_and_reports(self, output_dir, capsys):
        data = {
            "assets": [{"id": "tokens", "name": "session tokens", "linked_threats": []}],
            "threats": [{"id": "T-XSS", "cwe": "CWE-79", "title": "xss"}],
        }
        p = _write_yaml(output_dir, data)
        rc = eal.main([str(output_dir)])
        assert rc == 0
        assert "asset(s) processed" in capsys.readouterr().out
        out = yaml.safe_load(p.read_text())
        assert "T-XSS" in out["assets"][0]["linked_threats"]

    def test_report_only_no_write(self, output_dir):
        data = {
            "assets": [{"id": "tokens", "name": "session tokens", "linked_threats": []}],
            "threats": [{"id": "T-XSS", "cwe": "CWE-79", "title": "xss"}],
        }
        p = _write_yaml(output_dir, data)
        before = p.read_text()
        rc = eal.main([str(output_dir), "--report-only"])
        assert rc == 0
        assert p.read_text() == before


def test_cli_subprocess(run_plugin_script, output_dir):
    data = {
        "assets": [{"id": "tokens", "name": "session tokens", "linked_threats": []}],
        "threats": [{"id": "T-XSS", "cwe": "CWE-79", "title": "xss"}],
    }
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")
    res = run_plugin_script("enrich_asset_links.py", str(output_dir), check=False)
    assert res.returncode == 0
    assert "asset(s) processed" in res.stdout
