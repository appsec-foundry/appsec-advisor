"""Unit tests for scripts/classify_component.py (M8 + M18 classifier)."""

from __future__ import annotations

import json

import classify_component as cc


# ---------------------------------------------------------------------------
# _to_canonical
# ---------------------------------------------------------------------------
class TestToCanonical:
    def test_hint_wins_and_lowercased(self):
        assert cc._to_canonical("anything", "AUTH-Identity") == "auth-identity"

    def test_alias_lookup(self):
        assert cc._to_canonical("auth-jwt") == "auth-identity"
        assert cc._to_canonical("rest-api") == "backend-api"
        assert cc._to_canonical("database") == "data-persistence"
        assert cc._to_canonical("file-upload") == "file-handling"
        assert cc._to_canonical("angular-spa") == "frontend-spa"

    def test_alias_case_insensitive(self):
        assert cc._to_canonical("AUTH-JWT") == "auth-identity"

    def test_unknown_passthrough_lowered(self):
        assert cc._to_canonical("Some-Custom-Thing") == "some-custom-thing"


# ---------------------------------------------------------------------------
# _bump_complexity
# ---------------------------------------------------------------------------
class TestBumpComplexity:
    def test_floor_higher_bumps(self):
        assert cc._bump_complexity("simple", "moderate") == "moderate"
        assert cc._bump_complexity("simple", "complex") == "complex"
        assert cc._bump_complexity("moderate", "complex") == "complex"

    def test_floor_lower_or_equal_keeps_current(self):
        assert cc._bump_complexity("complex", "moderate") == "complex"
        assert cc._bump_complexity("moderate", "moderate") == "moderate"

    def test_unknown_floor_defaults_zero(self):
        assert cc._bump_complexity("moderate", "bogus") == "moderate"


# ---------------------------------------------------------------------------
# _count_recon_pattern
# ---------------------------------------------------------------------------
class TestCountReconPattern:
    def test_empty_returns_zero(self):
        assert cc._count_recon_pattern("", "7.8 ", "auth") == 0

    def test_section_missing_returns_zero(self):
        text = "## 1.0 Overview\nnothing here\n"
        assert cc._count_recon_pattern(text, "7.8 ", "auth") == 0

    def test_counts_matching_lines_in_section(self):
        text = (
            "## 7.8 Dangerous Sinks\n"
            "auth-core uses eval\n"
            "auth-core uses exec\n"
            "unrelated line\n"
            "## 7.9 Next\n"
            "auth-core here should not count\n"
        )
        assert cc._count_recon_pattern(text, "7.8 ", "auth-core") == 2

    def test_section_runs_to_eof_when_no_next_header(self):
        text = "## 7.8 Sinks\nfoo line\nfoo again\n"
        assert cc._count_recon_pattern(text, "7.8 ", "foo") == 2

    def test_hint_case_insensitive(self):
        text = "## 7.8 Sinks\nAUTH-CORE danger\n"
        assert cc._count_recon_pattern(text, "7.8 ", "Auth-Core") == 1


# ---------------------------------------------------------------------------
# classify — Step 1: auth invariant
# ---------------------------------------------------------------------------
class TestClassifyAuthInvariant:
    def test_auth_via_canonical_id_hint(self):
        r = cc.classify("login", "", interfaces=1, depth="standard", canonical_id="auth-identity")
        assert r["complexity"] == "complex"
        assert r["max_turns"] == 31
        assert r["estimated_threat_count"] == "high"
        assert r["canonical_id"] == "auth-identity"

    def test_auth_via_alias(self):
        r = cc.classify("auth-jwt", "", interfaces=1, depth="quick")
        assert r["complexity"] == "complex"
        assert r["max_turns"] == 20  # quick complex budget

    def test_auth_overrides_low_interfaces(self):
        # Would otherwise be trivial-skip, but auth wins
        r = cc.classify("auth-session", "", interfaces=0, depth="thorough")
        assert r["complexity"] == "complex"
        assert r["max_turns"] == 35


# ---------------------------------------------------------------------------
# classify — Step 2: trivial skip
# ---------------------------------------------------------------------------
class TestClassifyTrivialSkip:
    def test_trivial_skip(self):
        r = cc.classify("misc-util", "", interfaces=2, depth="standard")
        assert r["complexity"] == "trivial"
        assert r["max_turns"] == 0
        assert r["estimated_threat_count"] == "low"

    def test_frontend_not_trivial(self):
        # is_frontend blocks the trivial path even with 0 signals
        r = cc.classify("angular-spa", "", interfaces=1, depth="standard")
        assert r["complexity"] != "trivial"

    def test_sinks_block_trivial(self):
        text = "## 7.8 Sinks\nmisc-util eval\n"
        r = cc.classify("misc-util", text, interfaces=1, depth="standard")
        assert r["complexity"] != "trivial"


# ---------------------------------------------------------------------------
# classify — Step 3/4/5: thin / moderate / complex
# ---------------------------------------------------------------------------
class TestClassifyTiers:
    def test_thin_simple(self):
        # <3 interfaces, 0 sinks, 0 secrets, but has input handling so not trivial
        text = "## 7.4 Inputs\nbackend-api parses body\n"
        r = cc.classify("backend-api", text, interfaces=2, depth="standard")
        assert r["complexity"] == "simple"
        assert r["max_turns"] == 8
        assert r["estimated_threat_count"] == "low"

    def test_moderate(self):
        r = cc.classify("backend-api", "", interfaces=5, depth="standard")
        assert r["complexity"] == "moderate"
        assert r["max_turns"] == 22
        assert "5 interfaces" in r["reason"]

    def test_complex_by_interfaces(self):
        r = cc.classify("backend-api", "", interfaces=9, depth="standard")
        assert r["complexity"] == "complex"
        assert r["max_turns"] == 31

    def test_complex_by_sinks(self):
        text = "## 7.8 Sinks\nbackend-api eval\nbackend-api exec\nbackend-api system\n"
        r = cc.classify("backend-api", text, interfaces=4, depth="standard")
        assert r["complexity"] == "complex"


# ---------------------------------------------------------------------------
# classify — Step 6: M18 per-type floor
# ---------------------------------------------------------------------------
class TestClassifyTypeFloor:
    def test_file_handling_floor_bumps_simple_to_moderate(self):
        text = "## 7.4 Inputs\nfile-upload reads file\n"
        r = cc.classify("file-upload", text, interfaces=2, depth="standard")
        assert r["complexity"] == "moderate"
        assert "M18 file-handling floor" in r["reason"]

    def test_data_persistence_floor(self):
        text = "## 7.4 Inputs\ndatabase query\n"
        r = cc.classify("database", text, interfaces=2, depth="standard")
        assert r["complexity"] == "moderate"
        assert r["canonical_id"] == "data-persistence"

    def test_floor_no_bump_when_already_higher(self):
        # file-handling but already complex -> reason has no M18 suffix
        r = cc.classify("file-upload", "", interfaces=9, depth="standard")
        assert r["complexity"] == "complex"
        assert "M18" not in r["reason"]


# ---------------------------------------------------------------------------
# classify — depth budget fallback
# ---------------------------------------------------------------------------
class TestClassifyDepthFallback:
    def test_unknown_depth_falls_back_to_standard(self):
        r = cc.classify("backend-api", "", interfaces=5, depth="bogus-depth")
        assert r["max_turns"] == 22  # standard moderate


# ---------------------------------------------------------------------------
# main / CLI
# ---------------------------------------------------------------------------
class TestMain:
    def test_main_basic_stdout(self, capsys):
        rc = cc.main(["backend-api", "--interfaces", "5"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["component_id"] == "backend-api"
        assert out["complexity"] == "moderate"

    def test_main_reads_recon_file(self, tmp_path, capsys):
        recon = tmp_path / ".recon-summary.md"
        recon.write_text(
            "## 7.8 Sinks\nbackend-api eval\nbackend-api exec\nbackend-api spawn\n",
            encoding="utf-8",
        )
        rc = cc.main(["backend-api", "--interfaces", "4", "--recon-summary", str(recon)])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["complexity"] == "complex"

    def test_main_missing_recon_file_ignored(self, tmp_path, capsys):
        missing = tmp_path / "nope.md"
        rc = cc.main(["misc", "--interfaces", "1", "--recon-summary", str(missing)])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["complexity"] == "trivial"

    def test_main_canonical_id_override(self, capsys):
        rc = cc.main(["whatever", "--interfaces", "1", "--canonical-id", "auth-identity"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["complexity"] == "complex"

    def test_main_depth_choice(self, capsys):
        rc = cc.main(["backend-api", "--interfaces", "9", "--depth", "thorough"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["max_turns"] == 35


def test_run_via_subprocess(run_plugin_script):
    proc = run_plugin_script("classify_component.py", "backend-api", "--interfaces", "5", check=True)
    out = json.loads(proc.stdout)
    assert out["complexity"] == "moderate"
    assert out["max_turns"] == 22
