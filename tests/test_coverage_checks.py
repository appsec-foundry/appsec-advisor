"""
Tests for scripts/coverage_checks.py — Sprint 2 Item #6.

Covers:
  - OWASP Top 10 coverage (Check A): set-membership of CWEs in threats[]
    against the OWASP 2021 category→CWE mapping in
    data/owasp-top10-cwes.yaml.
  - Cross-repo boundary coverage (Check D): parse
    .threat-modeling-context.md for dependencies with threat_model=missing,
    then check whether any merged threat references the dependency name
    or interface.
  - CLI / orchestration glue.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import coverage_checks  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent
OWASP_YAML = PLUGIN_ROOT / "data" / "owasp-top10-cwes.yaml"
SCRIPT = PLUGIN_ROOT / "scripts" / "coverage_checks.py"


# ---------------------------------------------------------------------------
# OWASP mapping file integrity
# ---------------------------------------------------------------------------


class TestOwaspMappingFile:
    def test_yaml_exists(self):
        assert OWASP_YAML.is_file()

    def test_schema_shape(self):
        data = yaml.safe_load(OWASP_YAML.read_text(encoding="utf-8"))
        assert data.get("version") == 1
        cats = data["categories"]
        assert len(cats) == 10, "OWASP 2021 defines exactly 10 categories"
        for cat in cats:
            for key in ("id", "name", "stride", "default_risk", "cwes"):
                assert key in cat, f"category {cat.get('id')!r} missing {key}"
            assert cat["id"].endswith(":2021")
            assert cat["stride"] in {
                "Spoofing", "Tampering", "Repudiation",
                "Information Disclosure", "Denial of Service", "Elevation of Privilege",
            }
            assert cat["default_risk"] in {"Critical", "High", "Medium", "Low"}
            assert isinstance(cat["cwes"], list) and cat["cwes"]
            assert all(isinstance(n, int) for n in cat["cwes"])

    def test_has_all_10_categories(self):
        data = yaml.safe_load(OWASP_YAML.read_text(encoding="utf-8"))
        ids = {c["id"] for c in data["categories"]}
        expected = {f"A{i:02d}:2021" for i in range(1, 11)}
        assert ids == expected

    def test_cwe_89_sql_injection_in_a03(self):
        """Regression guard: CWE-89 is the canonical injection CWE and
        must live in A03:2021."""
        data = yaml.safe_load(OWASP_YAML.read_text(encoding="utf-8"))
        a03 = next(c for c in data["categories"] if c["id"] == "A03:2021")
        assert 89 in a03["cwes"]

    def test_cwe_918_ssrf_in_a10(self):
        data = yaml.safe_load(OWASP_YAML.read_text(encoding="utf-8"))
        a10 = next(c for c in data["categories"] if c["id"] == "A10:2021")
        assert 918 in a10["cwes"]


# ---------------------------------------------------------------------------
# _parse_cwe — robustness on real-world CWE shapes
# ---------------------------------------------------------------------------


class TestParseCwe:
    @pytest.mark.parametrize("value,expected", [
        ("CWE-89", 89),
        ("cwe-89", 89),
        ("CWE_89", 89),
        ("CWE 89", 89),
        ("89", 89),
        (89, 89),
        ("CWE-89 (SQL injection)", 89),
        ("  CWE-89  ", 89),
        ("CWE-1059", 1059),
        ("no-cwe-here", None),
        ("", None),
        (None, None),
        ("CWE-", None),
    ])
    def test_parse(self, value, expected):
        assert coverage_checks._parse_cwe(value) == expected


# ---------------------------------------------------------------------------
# OWASP Top 10 check
# ---------------------------------------------------------------------------


class TestCheckOwasp:
    def test_empty_threats_all_missing(self):
        rep = coverage_checks.check_owasp_top10([])
        assert rep["missing_count"] == 10
        assert rep["covered_count"] == 0

    def test_one_threat_per_cat_all_covered(self):
        """A representative CWE from every category → zero gaps."""
        threats = [
            {"cwe": "CWE-284"},    # A01 (Access Control)
            {"cwe": "CWE-327"},    # A02 (Crypto)
            {"cwe": "CWE-89"},     # A03 (Injection)
            {"cwe": "CWE-434"},    # A04 (Insecure Design)
            {"cwe": "CWE-611"},    # A05 (Misconfig)
            {"cwe": "CWE-937"},    # A06 (Vuln Components)
            {"cwe": "CWE-287"},    # A07 (Auth)
            {"cwe": "CWE-502"},    # A08 (Deserialization)
            {"cwe": "CWE-778"},    # A09 (Logging)
            {"cwe": "CWE-918"},    # A10 (SSRF)
        ]
        rep = coverage_checks.check_owasp_top10(threats)
        assert rep["missing_count"] == 0
        assert rep["covered_count"] == 10

    def test_partial_coverage_produces_gaps(self):
        threats = [{"cwe": "CWE-89"}, {"cwe": "CWE-287"}]
        rep = coverage_checks.check_owasp_top10(threats)
        covered_ids = {c["id"] for c in rep["covered"]}
        missing_ids = {c["id"] for c in rep["missing"]}
        assert "A03:2021" in covered_ids
        assert "A07:2021" in covered_ids
        assert covered_ids.isdisjoint(missing_ids)
        assert len(missing_ids) == 8

    def test_missing_entries_carry_suggested_threat(self):
        rep = coverage_checks.check_owasp_top10([])
        for m in rep["missing"]:
            st = m["suggested_threat"]
            assert st["source"] == "coverage-gap"
            assert st["coverage_category"] == m["id"]
            assert st["stride"] == m["stride"]
            assert st["risk"] == m["default_risk"]
            assert "no threats identified" in st["title"]
            # CWE reference picks a real CWE from the category's list
            if st["cwe"]:
                assert st["cwe"].startswith("CWE-")

    def test_unknown_cwe_does_not_cover_anything(self):
        threats = [{"cwe": "CWE-99999"}]
        rep = coverage_checks.check_owasp_top10(threats)
        assert rep["covered_count"] == 0
        assert rep["missing_count"] == 10

    def test_cwe_null_skipped(self):
        """A threat without a CWE contributes nothing to coverage."""
        threats = [{"cwe": None, "title": "architectural gap"}]
        rep = coverage_checks.check_owasp_top10(threats)
        assert rep["covered_count"] == 0

    def test_duplicate_cwe_same_category_counts_once(self):
        threats = [{"cwe": "CWE-89"}, {"cwe": "CWE-89"}, {"cwe": "CWE-89"}]
        rep = coverage_checks.check_owasp_top10(threats)
        a03 = next(c for c in rep["covered"] if c["id"] == "A03:2021")
        assert a03["covered_by_cwes"] == [89]


# ---------------------------------------------------------------------------
# Cross-repo section parsing
# ---------------------------------------------------------------------------


CONTEXT_MD_SAMPLE = textwrap.dedent("""
    # Context

    ## Project Overview

    Some intro prose.

    ## Cross-Repository Dependency Threat Models

    ### Declared Dependencies (`docs/related-repos.yaml`)

    | Dependency | Interface | Threat Model | Generated | Threats (C/H/M/L) | Findings Loaded |
    |------------|-----------|-------------|-----------|-------------------|-----------------|
    | auth-service | REST /v1/auth (JWT tokens) | ✓ found | 2026-03-01 | 1/2/3/0 | 2 loaded |
    | payment-gateway | gRPC Payments | ✗ not found | — | — | — |
    | user-directory | REST /users (PII) | ✗ missing | — | — | — |

    ### Auto-Discovered Siblings

    | Dependency | Source | Threat Model | Generated | Threats (C/H/M/L) | Open |
    |------------|--------|-------------|-----------|-------------------|------|
    | analytics-service | sibling | ✗ missing | — | — | — |
    | metrics-service | sibling | ✓ found | 2026-02-01 | 0/1/2/0 | 1 |

    ## Known Threats

    not relevant to cross-repo check.
""").strip()


class TestCrossRepoParsing:
    def test_parses_declared_and_discovered(self):
        deps = coverage_checks.parse_cross_repo_deps(CONTEXT_MD_SAMPLE)
        names = [d["name"] for d in deps]
        assert "auth-service" in names
        assert "payment-gateway" in names
        assert "user-directory" in names
        assert "analytics-service" in names
        assert "metrics-service" in names

    def test_status_classification(self):
        deps = coverage_checks.parse_cross_repo_deps(CONTEXT_MD_SAMPLE)
        by_name = {d["name"]: d for d in deps}
        assert by_name["auth-service"]["status"] == "found"
        assert by_name["payment-gateway"]["status"] == "missing"
        assert by_name["user-directory"]["status"] == "missing"
        assert by_name["analytics-service"]["status"] == "missing"
        assert by_name["metrics-service"]["status"] == "found"

    def test_source_classification(self):
        deps = coverage_checks.parse_cross_repo_deps(CONTEXT_MD_SAMPLE)
        by_name = {d["name"]: d for d in deps}
        assert by_name["auth-service"]["source"] == "declared"
        assert by_name["payment-gateway"]["source"] == "declared"
        assert by_name["analytics-service"]["source"] == "discovered"
        assert by_name["metrics-service"]["source"] == "discovered"

    def test_interface_captured_for_declared(self):
        deps = coverage_checks.parse_cross_repo_deps(CONTEXT_MD_SAMPLE)
        auth = next(d for d in deps if d["name"] == "auth-service")
        assert "REST /v1/auth" in (auth["interface"] or "")

    def test_auto_discovered_has_no_interface(self):
        deps = coverage_checks.parse_cross_repo_deps(CONTEXT_MD_SAMPLE)
        analytics = next(d for d in deps if d["name"] == "analytics-service")
        assert analytics["interface"] is None, (
            "auto-discovered siblings carry a 'Source' column, not an 'Interface' "
            "column — the parser must not treat 'sibling' as an interface"
        )

    def test_stops_at_next_heading(self):
        """Content after the next ## heading must not be parsed as cross-repo."""
        md = CONTEXT_MD_SAMPLE + "\n\n## Misleading Section\n\n| foo | bar |\n| fake-dep | ✗ missing |\n"
        deps = coverage_checks.parse_cross_repo_deps(md)
        assert "fake-dep" not in {d["name"] for d in deps}

    def test_no_cross_repo_section_returns_empty(self):
        md = "# Context\n\n## Project Overview\n\nsome content only.\n"
        assert coverage_checks.parse_cross_repo_deps(md) == []


# ---------------------------------------------------------------------------
# Cross-repo coverage check (the full round trip)
# ---------------------------------------------------------------------------


class TestCheckCrossRepo:
    def test_absent_context_file(self, tmp_path):
        rep = coverage_checks.check_cross_repo(tmp_path / "missing.md", [])
        assert rep["context_file_present"] is False
        assert rep["missing_tm_count"] == 0
        assert rep["uncovered_boundaries"] == []

    def test_missing_tm_not_mentioned_by_any_threat(self, tmp_path):
        ctx = tmp_path / ".threat-modeling-context.md"
        ctx.write_text(CONTEXT_MD_SAMPLE)
        threats = [{"title": "SQL injection in login", "scenario": "raw query"}]
        rep = coverage_checks.check_cross_repo(ctx, threats)
        uncovered_names = [b["name"] for b in rep["uncovered_boundaries"]]
        assert "payment-gateway" in uncovered_names
        assert "user-directory" in uncovered_names
        assert "analytics-service" in uncovered_names
        assert "auth-service" not in uncovered_names       # found → not checked
        assert "metrics-service" not in uncovered_names    # found → not checked

    def test_dependency_mentioned_in_threat_title_is_covered(self, tmp_path):
        ctx = tmp_path / ".threat-modeling-context.md"
        ctx.write_text(CONTEXT_MD_SAMPLE)
        threats = [
            {"title": "Unauthenticated webhook from payment-gateway accepted",
             "scenario": "service accepts unsigned payloads"},
        ]
        rep = coverage_checks.check_cross_repo(ctx, threats)
        covered = [b["name"] for b in rep["covered_boundaries"]]
        uncovered = [b["name"] for b in rep["uncovered_boundaries"]]
        assert "payment-gateway" in covered
        assert "payment-gateway" not in uncovered

    def test_dependency_mentioned_via_interface_is_covered(self, tmp_path):
        ctx = tmp_path / ".threat-modeling-context.md"
        ctx.write_text(CONTEXT_MD_SAMPLE)
        threats = [
            {"title": "Credential leak through gRPC Payments client",
             "scenario": "logs emit bearer token on error"},
        ]
        rep = coverage_checks.check_cross_repo(ctx, threats)
        covered = [b["name"] for b in rep["covered_boundaries"]]
        assert "payment-gateway" in covered

    def test_pii_interface_gets_medium_severity(self, tmp_path):
        ctx = tmp_path / ".threat-modeling-context.md"
        ctx.write_text(CONTEXT_MD_SAMPLE)
        rep = coverage_checks.check_cross_repo(ctx, [])
        user_dir = next(
            b for b in rep["uncovered_boundaries"] if b["name"] == "user-directory"
        )
        assert user_dir["suggested_threat"]["risk"] == "Medium"

    def test_generic_interface_gets_low_severity(self, tmp_path):
        ctx = tmp_path / ".threat-modeling-context.md"
        ctx.write_text(CONTEXT_MD_SAMPLE)
        rep = coverage_checks.check_cross_repo(ctx, [])
        # analytics-service is auto-discovered, no interface → Low
        analytics = next(
            b for b in rep["uncovered_boundaries"] if b["name"] == "analytics-service"
        )
        assert analytics["suggested_threat"]["risk"] == "Low"

    def test_suggested_threat_is_information_disclosure(self, tmp_path):
        ctx = tmp_path / ".threat-modeling-context.md"
        ctx.write_text(CONTEXT_MD_SAMPLE)
        rep = coverage_checks.check_cross_repo(ctx, [])
        for b in rep["uncovered_boundaries"]:
            assert b["suggested_threat"]["source"] == "coverage-gap"
            assert b["suggested_threat"]["stride"] == "Information Disclosure"
            assert b["suggested_threat"]["coverage_category"] == "cross-repo-boundary"


# ---------------------------------------------------------------------------
# run_all + CLI
# ---------------------------------------------------------------------------


class TestRunAll:
    def test_end_to_end(self, tmp_path):
        (tmp_path / ".threats-merged.json").write_text(json.dumps({
            "version": 1,
            "threats": [
                {"t_id": "T-001", "title": "SQL injection in login", "cwe": "CWE-89"},
                {"t_id": "T-002", "title": "JWT alg confusion", "cwe": "CWE-287"},
            ],
        }))
        (tmp_path / ".threat-modeling-context.md").write_text(CONTEXT_MD_SAMPLE)
        report = coverage_checks.run_all(tmp_path)
        assert report["threats_evaluated"] == 2
        assert report["owasp"]["missing_count"] == 8   # only A03 + A07 covered
        assert report["cross_repo"]["missing_tm_count"] == 3  # 2 declared + 1 discovered
        assert len(report["cross_repo"]["uncovered_boundaries"]) == 3
        assert report["gap_count"] == 8 + 3

    def test_no_threats_file(self, tmp_path):
        (tmp_path / ".threat-modeling-context.md").write_text(CONTEXT_MD_SAMPLE)
        report = coverage_checks.run_all(tmp_path)
        assert report["threats_evaluated"] == 0
        assert report["owasp"]["missing_count"] == 10


class TestCLI:
    def test_owasp_subcommand_emits_valid_json(self, tmp_path):
        (tmp_path / ".threats-merged.json").write_text(json.dumps({
            "version": 1, "threats": [{"cwe": "CWE-89"}],
        }))
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "owasp", "--output-dir", str(tmp_path)],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(r.stdout)
        assert out["check"] == "owasp-top10"

    def test_cross_repo_subcommand(self, tmp_path):
        (tmp_path / ".threat-modeling-context.md").write_text(CONTEXT_MD_SAMPLE)
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "cross-repo", "--output-dir", str(tmp_path)],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(r.stdout)
        assert out["check"] == "cross-repo-boundary"

    def test_all_subcommand(self, tmp_path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "all", "--output-dir", str(tmp_path)],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(r.stdout)
        assert "owasp" in out and "cross_repo" in out

    def test_cli_missing_output_dir(self, tmp_path):
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "all", "--output-dir",
             str(tmp_path / "does-not-exist")],
            capture_output=True, text=True,
        )
        assert r.returncode == 1
