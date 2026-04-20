"""Unit tests for claude-plugin/scripts/dep_scan.py.

Exercises:
  * manifest discovery (skip vendored dirs)
  * MD5 hash + cache validity
  * heuristic version comparison
  * heuristic match for npm and python manifests
  * native-tool output parsing (npm audit / pip-audit / govulncheck)
  * end-to-end main(): writes a schema-compatible .dep-scan.json
  * --with-sca gating remains a SKILL-level concern; this script always runs
    when invoked (the orchestrator decides whether to invoke it)
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = (
    Path(__file__).parent.parent / "claude-plugin" / "scripts" / "dep_scan.py"
)


@pytest.fixture(scope="module")
def ds():
    spec = importlib.util.spec_from_file_location("dep_scan", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["dep_scan"] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_finds_known_manifests(self, ds, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "requirements.txt").write_text("")
        (tmp_path / "go.mod").write_text("module x\n")
        found = ds._discover_manifests(tmp_path)
        names = sorted(p.name for p in found)
        assert names == ["go.mod", "package.json", "requirements.txt"]

    def test_skips_vendored_dirs(self, ds, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "package.json").write_text("{}")
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "go.mod").write_text("module v\n")
        found = ds._discover_manifests(tmp_path)
        # Only the top-level package.json — vendored manifests skipped
        assert len(found) == 1
        assert found[0].name == "package.json"

    def test_ignores_dot_directories(self, ds, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "package.json").write_text("{}")
        (tmp_path / "package.json").write_text("{}")
        found = ds._discover_manifests(tmp_path)
        assert [p.name for p in found] == ["package.json"]


# ---------------------------------------------------------------------------
# Hash + cache
# ---------------------------------------------------------------------------

class TestCache:
    def test_md5_hash_is_8_chars_by_default(self, ds, tmp_path):
        f = tmp_path / "a.txt"
        f.write_text("hello")
        assert len(ds._md5_hash(f)) == 8

    def test_md5_hash_changes_with_content(self, ds, tmp_path):
        f = tmp_path / "a.txt"
        f.write_text("v1")
        h1 = ds._md5_hash(f)
        f.write_text("v2")
        h2 = ds._md5_hash(f)
        assert h1 != h2

    def test_cache_invalid_when_missing(self, ds, tmp_path):
        assert ds._is_cache_valid(tmp_path, {"a": "h"}) is False

    def test_cache_invalid_when_hashes_differ(self, ds, tmp_path):
        # Build a fresh-looking cache with hash X, query with hash Y
        ds._write_output(tmp_path, tmp_path, [], {"package.json": "aaaa1111"})
        assert ds._is_cache_valid(tmp_path, {"package.json": "bbbb2222"}) is False

    def test_cache_valid_when_hashes_match_and_fresh(self, ds, tmp_path):
        ds._write_output(tmp_path, tmp_path, [], {"package.json": "aaaa1111"})
        assert ds._is_cache_valid(tmp_path, {"package.json": "aaaa1111"}) is True


# ---------------------------------------------------------------------------
# Heuristic version compare
# ---------------------------------------------------------------------------

class TestVersionCompare:
    @pytest.mark.parametrize("found,threshold,expected", [
        ("4.17.20", "4.17.21", True),
        ("4.17.21", "4.17.21", False),
        ("4.18.0",  "4.17.21", False),
        ("^4.17.20", "4.17.21", True),
        ("v1.0.0", "1.0.1", True),
        ("",       "1.0.0", False),
        ("garbage", "1.0.0", False),
    ])
    def test_version_below(self, ds, found, threshold, expected):
        assert ds._version_below(found, threshold) is expected


# ---------------------------------------------------------------------------
# Heuristic matching (npm + python)
# ---------------------------------------------------------------------------

class TestHeuristicMatch:
    def test_npm_below_threshold_flagged(self, ds, tmp_path):
        manifest = tmp_path / "package.json"
        manifest.write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
        heuristics = [{
            "ecosystem": "npm", "package": "lodash",
            "vulnerable_below": "4.17.21",
            "cve": "CVE-2021-23337", "severity": "High", "issue": "x",
        }]
        f = ds._heuristic_npm(manifest, manifest.read_text(), heuristics)
        assert len(f) == 1
        assert f[0]["package"] == "lodash"
        assert f[0]["source"] == "heuristic"
        assert f[0]["cve_id"] == "CVE-2021-23337"

    def test_npm_at_threshold_not_flagged(self, ds, tmp_path):
        manifest = tmp_path / "package.json"
        manifest.write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}))
        heuristics = [{"ecosystem": "npm", "package": "lodash",
                       "vulnerable_below": "4.17.21",
                       "severity": "High", "issue": "x"}]
        f = ds._heuristic_npm(manifest, manifest.read_text(), heuristics)
        assert f == []

    def test_python_requirements_match(self, ds, tmp_path):
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("requests==2.30.0\njinja2==3.1.0\n")
        heuristics = [{
            "ecosystem": "python", "package": "requests",
            "vulnerable_below": "2.32.0",
            "cve": "CVE-2024-35195", "severity": "Medium", "issue": "x",
        }]
        f = ds._heuristic_python(manifest, manifest.read_text(), heuristics)
        assert len(f) == 1
        assert f[0]["package"] == "requests"


# ---------------------------------------------------------------------------
# Native-tool output parsers
# ---------------------------------------------------------------------------

class TestNpmAuditParse:
    def test_basic_parse(self, ds):
        sample = json.dumps({
            "vulnerabilities": {
                "lodash": {
                    "name": "lodash", "severity": "high",
                    "via": [{"title": "CMD injection", "cves": ["CVE-2021-23337"],
                             "cvss": {"score": 7.5,
                                      "vectorString": "CVSS:3.1/AV:N/AC:L"}}],
                    "range": ">=0 <4.17.21",
                }
            }
        })
        f = ds._npm_audit_findings(sample, "package.json")
        assert len(f) == 1
        assert f[0]["package"] == "lodash"
        assert f[0]["cve_id"] == "CVE-2021-23337"
        assert f[0]["severity"] == "High"
        assert f[0]["source"] == "live-audit"
        assert f[0]["cvss_v4"]["version_fallback"] == "3.1"

    def test_invalid_json_returns_empty(self, ds):
        assert ds._npm_audit_findings("not json", "x") == []


class TestPipAuditParse:
    def test_basic_parse(self, ds):
        sample = json.dumps({
            "dependencies": [
                {"name": "requests", "version": "2.30.0",
                 "vulns": [{"id": "CVE-2024-35195", "description": "credential leak"}]},
            ]
        })
        f = ds._pip_audit_findings(sample, "requirements.txt")
        assert len(f) == 1
        assert f[0]["cve_id"] == "CVE-2024-35195"
        assert f[0]["source"] == "live-audit"


class TestGovulncheckParse:
    def test_jsonl_parse(self, ds):
        sample = '\n'.join([
            json.dumps({"finding": {"osv": "CVE-2023-45288", "symbol": "x/y/z.Func"}}),
            json.dumps({"some_other_event": True}),
        ])
        f = ds._govulncheck_findings(sample, "go.mod")
        assert len(f) == 1
        assert f[0]["cve_id"] == "CVE-2023-45288"


# ---------------------------------------------------------------------------
# End-to-end main()
# ---------------------------------------------------------------------------

class TestMainEndToEnd:
    def test_main_writes_schema_compatible_output(self, ds, tmp_path):
        repo = tmp_path / "repo"
        out = tmp_path / "out"
        repo.mkdir()
        (repo / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "4.17.20"}
        }))
        rc = ds.main([
            "--repo-root", str(repo),
            "--output-dir", str(out),
            "--manifests", "package.json",
        ])
        assert rc == 0
        with (out / ".dep-scan.json").open() as fh:
            data = json.load(fh)
        # Required top-level fields per the legacy agent contract
        for key in ("scanned_at", "repo_root", "manifest_hashes",
                    "summary", "vulnerable_dependencies"):
            assert key in data, f"missing required field: {key}"
        assert data["summary"]["vulnerable_dependencies"] == len(
            data["vulnerable_dependencies"])
        # Heuristic should have flagged lodash 4.17.20
        names = [v["package"] for v in data["vulnerable_dependencies"]]
        assert "lodash" in names

    def test_main_no_manifests_writes_empty_file(self, ds, tmp_path):
        repo = tmp_path / "repo"
        out = tmp_path / "out"
        repo.mkdir()
        rc = ds.main([
            "--repo-root", str(repo),
            "--output-dir", str(out),
        ])
        assert rc == 0
        with (out / ".dep-scan.json").open() as fh:
            data = json.load(fh)
        assert data["summary"]["vulnerable_dependencies"] == 0
        assert data["vulnerable_dependencies"] == []

    def test_main_cache_hit_skips_rescan(self, ds, tmp_path):
        repo = tmp_path / "repo"
        out = tmp_path / "out"
        repo.mkdir()
        (repo / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "4.17.20"}
        }))
        # First run populates cache
        ds.main(["--repo-root", str(repo), "--output-dir", str(out),
                 "--manifests", "package.json"])
        first_mtime = (out / ".dep-scan.json").stat().st_mtime
        # Second run should be a cache hit — file not rewritten
        ds.main(["--repo-root", str(repo), "--output-dir", str(out),
                 "--manifests", "package.json"])
        second_mtime = (out / ".dep-scan.json").stat().st_mtime
        assert first_mtime == second_mtime

    def test_main_missing_repo_returns_error(self, ds, tmp_path):
        rc = ds.main([
            "--repo-root", str(tmp_path / "nonexistent"),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert rc == 1


# ---------------------------------------------------------------------------
# Heuristics file integrity
# ---------------------------------------------------------------------------

class TestHeuristicsFile:
    def test_heuristics_file_loads(self, ds):
        h = ds._load_heuristics()
        assert isinstance(h, list)
        assert len(h) > 0, "dep-scan-heuristics.yaml produced an empty list"

    def test_every_entry_has_required_fields(self, ds):
        for entry in ds._load_heuristics():
            for key in ("ecosystem", "package", "vulnerable_below", "severity"):
                assert key in entry, f"heuristic missing '{key}': {entry}"
            assert entry["ecosystem"] in {"npm", "python", "go", "maven"}, (
                f"unknown ecosystem: {entry}"
            )
            assert entry["severity"] in {"Critical", "High", "Medium", "Low"}, (
                f"invalid severity: {entry}"
            )
