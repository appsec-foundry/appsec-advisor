"""Tests for ``scripts/aggregate_threat_summary.py`` multi-repo aggregation.

Covers:
  - per-repo loading + filter (status, severity)
  - shared CWE detection across repos
  - chain-candidate heuristic
  - shared mitigations
  - Markdown rendering structure
  - JSON schema validation
  - CLI surface
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import aggregate_threat_summary as ats  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "aggregate_threat_summary.py"
SCHEMA = PLUGIN_ROOT / "schemas" / "threat-summary.schema.json"


def _make_repo(
    tmp_path: Path,
    name: str,
    *,
    threats: list[dict[str, Any]] | None = None,
    mitigations: list[dict[str, Any]] | None = None,
    trust_boundaries: list[dict[str, Any]] | None = None,
    related: list[dict[str, Any]] | None = None,
    generated: str = "2099-01-01T00:00:00Z",
) -> Path:
    repo = tmp_path / name
    (repo / "docs" / "security").mkdir(parents=True)
    tm = {
        "meta": {"generated": generated, "git": {"commit_sha": f"sha-{name}"}, "project": name},
        "components": [{"name": "Service"}],
        "threats": threats or [],
        "mitigations": mitigations or [],
        "trust_boundaries": trust_boundaries or [],
    }
    (repo / "docs" / "security" / "threat-model.yaml").write_text(yaml.safe_dump(tm))
    if related is not None:
        (repo / "docs" / "related-repos.yaml").write_text(yaml.safe_dump({"related": related}))
    return repo


def _t(
    id_: str,
    sev: str,
    *,
    cwe: str = "CWE-79",
    status: str = "open",
    component: str = "Service",
    stride: str = "Spoofing",
) -> dict[str, Any]:
    return {
        "id": id_,
        "title": f"{id_} title",
        "severity": sev,
        "status": status,
        "cwe": cwe,
        "component": component,
        "stride": stride,
    }


# ---------------------------------------------------------------------------
# Per-repo loading
# ---------------------------------------------------------------------------


class TestRepoLoading:
    def test_missing_threat_model_marks_skipped(self, tmp_path: Path) -> None:
        repo = tmp_path / "empty"
        repo.mkdir()
        out = ats.load_repo(repo, min_severity="medium", open_only=False)
        assert out["loaded"] is False
        assert "no threat-model.yaml" in (out["skip_reason"] or "")

    def test_threat_counts_by_severity(self, tmp_path: Path) -> None:
        repo = _make_repo(
            tmp_path,
            "svc",
            threats=[
                _t("T-1", "Critical"),
                _t("T-2", "Critical"),
                _t("T-3", "High"),
                _t("T-4", "Medium"),
                _t("T-5", "Low"),
            ],
        )
        out = ats.load_repo(repo, min_severity="low", open_only=False)
        assert out["by_severity"] == {"critical": 2, "high": 1, "medium": 1, "low": 1}
        assert out["findings_total"] == 5
        assert out["findings_after_filter"] == 5

    def test_min_severity_filter(self, tmp_path: Path) -> None:
        repo = _make_repo(
            tmp_path,
            "svc",
            threats=[
                _t("T-1", "Critical"),
                _t("T-2", "Medium"),
                _t("T-3", "Low"),
            ],
        )
        out = ats.load_repo(repo, min_severity="high", open_only=False)
        assert out["findings_after_filter"] == 1

    def test_open_only_filter(self, tmp_path: Path) -> None:
        repo = _make_repo(
            tmp_path,
            "svc",
            threats=[
                _t("T-1", "Critical", status="open"),
                _t("T-2", "Critical", status="mitigated"),
            ],
        )
        out = ats.load_repo(repo, min_severity="critical", open_only=True)
        assert out["findings_after_filter"] == 1

    def test_outdated_marker(self, tmp_path: Path) -> None:
        import datetime as _dt

        old = (_dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(days=200)).isoformat()
        repo = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")], generated=old)
        out = ats.load_repo(repo, min_severity="medium", open_only=False)
        assert out["outdated"] is True


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


class TestAggregator:
    def test_shared_cwes_detected(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "auth", threats=[_t("T-1", "Critical", cwe="CWE-89")])
        b = _make_repo(tmp_path, "api", threats=[_t("T-9", "High", cwe="CWE-89")])
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        cwes = {e["cwe"]: e for e in summary["shared_cwes"]}
        assert "CWE-89" in cwes
        assert sorted(cwes["CWE-89"]["repos"]) == ["api", "auth"]
        assert cwes["CWE-89"]["finding_count"] == 2

    def test_consolidated_findings_sorted_by_severity(self, tmp_path: Path) -> None:
        a = _make_repo(
            tmp_path,
            "auth",
            threats=[
                _t("T-1", "High"),
                _t("T-2", "Critical"),
            ],
        )
        b = _make_repo(tmp_path, "api", threats=[_t("T-9", "Medium")])
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        order = [(f["severity"], f["repo"], f["id"]) for f in summary["consolidated_findings"]]
        assert order[0][0] == "Critical"
        assert order[-1][0] == "Medium"

    def test_chain_candidates_via_related_repos(self, tmp_path: Path) -> None:
        a = _make_repo(
            tmp_path,
            "auth-service",
            threats=[_t("T-1", "Critical", component="TokenIssuer")],
        )
        b = _make_repo(
            tmp_path,
            "api-gateway",
            threats=[_t("T-9", "High")],
            trust_boundaries=[{"name": "gateway-auth", "description": "Uses TokenIssuer for JWT validation"}],
            related=[
                {
                    "name": "auth-service",
                    "threat_model": str(a / "docs/security/threat-model.yaml"),
                    "interface": "REST API /v1/auth",
                }
            ],
        )
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        assert any(
            c["upstream_repo"] == "auth-service" and c["downstream_repo"] == "api-gateway"
            for c in summary["chain_candidates"]
        )

    def test_chain_candidates_capped_at_5(self, tmp_path: Path) -> None:
        upstream_threats = [_t(f"T-{i}", "Critical", component=f"Comp{i}") for i in range(10)]
        a = _make_repo(tmp_path, "upstream", threats=upstream_threats)
        b = _make_repo(
            tmp_path,
            "downstream",
            threats=[_t("T-99", "High")],
            trust_boundaries=[{"description": " ".join(f"Comp{i}" for i in range(10))}],
            related=[{"name": "upstream", "threat_model": str(a / "docs/security/threat-model.yaml")}],
        )
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        assert len(summary["chain_candidates"]) == 5

    def test_shared_mitigations(self, tmp_path: Path) -> None:
        a = _make_repo(
            tmp_path,
            "auth",
            threats=[_t("T-1", "Critical", cwe="CWE-79")],
            mitigations=[{"id": "M-1", "title": "CSP headers", "addresses_cwes": ["CWE-79"]}],
        )
        b = _make_repo(
            tmp_path,
            "api",
            threats=[_t("T-9", "High", cwe="CWE-79")],
            mitigations=[{"id": "M-9", "title": "Output encoding", "addresses_cwes": ["CWE-79"]}],
        )
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        assert any(m["cwe"] == "CWE-79" and len(m["repos"]) == 2 for m in summary["shared_mitigations"])


# ---------------------------------------------------------------------------
# Markdown + JSON output
# ---------------------------------------------------------------------------


class TestRendering:
    def test_markdown_contains_required_sections(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "auth", threats=[_t("T-1", "Critical")])
        summary = ats.aggregate([a], min_severity="medium", open_only=False)
        md = ats.render_markdown(summary)
        assert "# Threat Summary" in md
        assert "## Risk Overview" in md
        assert "## Consolidated Finding Register" in md
        assert "T-1" in md

    def test_markdown_chain_candidates_section_only_when_present(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "lonely", threats=[_t("T-1", "Critical")])
        summary = ats.aggregate([a], min_severity="medium", open_only=False)
        md = ats.render_markdown(summary)
        assert "Cross-Repo Attack Chain Candidates" not in md

    def test_schema_validates_full_output(self, tmp_path: Path) -> None:
        a = _make_repo(
            tmp_path,
            "auth",
            threats=[
                _t("T-1", "Critical", cwe="CWE-89"),
            ],
            mitigations=[{"title": "Bind params", "addresses_cwes": ["CWE-89"]}],
        )
        b = _make_repo(tmp_path, "api", threats=[_t("T-9", "High", cwe="CWE-89")])
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        errors = ats.validate(summary, SCHEMA)
        assert errors == [], errors

    def test_schema_validates_empty(self, tmp_path: Path) -> None:
        summary = ats.aggregate([], min_severity="medium", open_only=False)
        errors = ats.validate(summary, SCHEMA)
        assert errors == []

    def test_schema_validates_skipped_repo(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        summary = ats.aggregate([empty], min_severity="medium", open_only=False)
        errors = ats.validate(summary, SCHEMA)
        assert errors == []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_dry_run_emits_markdown_to_stdout(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo", str(a), "--format", "md", "--dry-run"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        assert "Threat Summary" in r.stdout
        assert "T-1" in r.stdout

    def test_format_json_writes_valid_json(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        out = tmp_path / "out.json"
        r = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo", str(a), "--format", "json", "--output", str(out)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["meta"]["aggregator_version"] == 1

    def test_min_severity_critical_filters(self, tmp_path: Path) -> None:
        a = _make_repo(
            tmp_path,
            "svc",
            threats=[
                _t("T-1", "Critical"),
                _t("T-2", "Medium"),
            ],
        )
        out = tmp_path / "out.json"
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repo",
                str(a),
                "--format",
                "json",
                "--min-severity",
                "critical",
                "--output",
                str(out),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["repos"][0]["findings_after_filter"] == 1


# ---------------------------------------------------------------------------
# Coverage extension: edge/error/CLI branches
# ---------------------------------------------------------------------------


class TestExtractThreatsCategoryShape:
    def test_threat_categories_fallback(self, tmp_path: Path) -> None:
        # No top-level `threats` list -> falls back to threat_categories.findings
        tm = {
            "threat_categories": [
                {"findings": [_t("T-1", "Critical"), "not-a-dict"]},
                "bad-cat",
                {"findings": None},
            ]
        }
        out = ats._extract_threats(tm)
        assert len(out) == 1
        assert out[0]["id"] == "T-1"


class TestLoadRepoErrorPaths:
    def test_unreadable_yaml_marks_skipped(self, tmp_path: Path) -> None:
        repo = tmp_path / "broken"
        (repo / "docs" / "security").mkdir(parents=True)
        (repo / "docs" / "security" / "threat-model.yaml").write_text("key: [unclosed\n")
        out = ats.load_repo(repo, min_severity="medium", open_only=False)
        assert out["loaded"] is False
        assert "unreadable threat-model.yaml" in (out["skip_reason"] or "")

    def test_root_level_threat_model_located(self, tmp_path: Path) -> None:
        repo = tmp_path / "rootlevel"
        repo.mkdir()
        (repo / "threat-model.yaml").write_text(
            yaml.safe_dump({"meta": {"generated": "2099-01-01T00:00:00Z"}, "threats": [_t("T-1", "Critical")]})
        )
        out = ats.load_repo(repo, min_severity="medium", open_only=False)
        assert out["loaded"] is True
        assert out["findings_total"] == 1

    def test_generated_unparseable_not_outdated(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")], generated="not-a-date")
        out = ats.load_repo(repo, min_severity="medium", open_only=False)
        assert out["outdated"] is False

    def test_naive_generated_timestamp(self, tmp_path: Path) -> None:
        # ISO without timezone -> branch ts.tzinfo is None
        repo = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")], generated="2099-01-01T00:00:00")
        out = ats.load_repo(repo, min_severity="medium", open_only=False)
        assert out["outdated"] is False


class TestRelatedReposLoading:
    def test_related_repos_missing_returns_empty(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        assert ats._load_related_repos(repo) == []

    def test_related_repos_unreadable_yaml(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        (repo / "docs" / "related-repos.yaml").write_text("related: [unclosed\n")
        assert ats._load_related_repos(repo) == []

    def test_related_repos_not_a_dict(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        (repo / "docs" / "related-repos.yaml").write_text(yaml.safe_dump(["a", "b"]))
        assert ats._load_related_repos(repo) == []

    def test_related_repos_filters_non_dict_entries(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        (repo / "docs" / "related-repos.yaml").write_text(
            yaml.safe_dump({"related": [{"name": "x"}, "bad"]})
        )
        assert ats._load_related_repos(repo) == [{"name": "x"}]


class TestSharedCwesSkipsBranches:
    def test_skips_unloaded_and_blank_cwe(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "a", threats=[_t("T-1", "Critical", cwe="")])
        empty = tmp_path / "empty"
        empty.mkdir()
        summary = ats.aggregate([a, empty], min_severity="medium", open_only=False)
        # blank cwe excluded -> no shared cwes
        assert summary["shared_cwes"] == []


class TestChainCandidateBranches:
    def test_skips_low_severity_and_no_component(self, tmp_path: Path) -> None:
        a = _make_repo(
            tmp_path,
            "up",
            threats=[
                _t("T-low", "Low", component="Widget"),
                _t("T-nocomp", "Critical", component=""),
            ],
        )
        b = _make_repo(
            tmp_path,
            "down",
            threats=[_t("T-9", "High")],
            trust_boundaries=[{"description": "Widget pipeline"}],
            related=[{"name": "up", "threat_model": "x"}],
        )
        summary = ats.aggregate([a, b], min_severity="low", open_only=False)
        assert summary["chain_candidates"] == []

    def test_match_via_interface_text(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "up", threats=[_t("T-1", "Critical", component="QueueBus")])
        b = _make_repo(
            tmp_path,
            "down",
            threats=[_t("T-9", "High")],
            trust_boundaries=[{"description": "talks over a queuebus channel"}],
            related=[{"name": "up", "interface": "queuebus", "threat_model": "x"}],
        )
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        assert len(summary["chain_candidates"]) == 1

    def test_match_via_declared_interface_in_tb(self, tmp_path: Path) -> None:
        # component does NOT appear, but the interface text does -> 2nd elif branch
        a = _make_repo(tmp_path, "up", threats=[_t("T-1", "Critical", component="ZZZComp")])
        b = _make_repo(
            tmp_path,
            "down",
            threats=[_t("T-9", "High")],
            trust_boundaries=[{"description": "connects via grpc bridge endpoint"}],
            related=[{"name": "up", "interface": "grpc bridge", "threat_model": "x"}],
        )
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        assert summary["chain_candidates"][0]["match_reason"].startswith("declared interface")

    def test_related_unknown_upstream_skipped(self, tmp_path: Path) -> None:
        b = _make_repo(
            tmp_path,
            "down",
            threats=[_t("T-9", "High")],
            related=[{"name": "ghost", "threat_model": "x"}, {"name": "", "interface": "y"}],
        )
        summary = ats.aggregate([b], min_severity="medium", open_only=False)
        assert summary["chain_candidates"] == []


class TestSharedMitigationsBranches:
    def test_non_dict_mitigation_skipped(self, tmp_path: Path) -> None:
        a = tmp_path / "a"
        (a / "docs" / "security").mkdir(parents=True)
        (a / "docs" / "security" / "threat-model.yaml").write_text(
            yaml.safe_dump(
                {
                    "meta": {"generated": "2099-01-01T00:00:00Z"},
                    "threats": [_t("T-1", "Critical", cwe="CWE-1")],
                    "mitigations": ["not-a-dict", {"title": "M", "cwes": ["CWE-1"]}],
                }
            )
        )
        b = _make_repo(tmp_path, "b", threats=[_t("T-2", "High", cwe="CWE-1")],
                       mitigations=[{"title": "N", "cwes": ["CWE-1"]}])
        summary = ats.aggregate([a, b], min_severity="medium", open_only=False)
        assert any(m["cwe"] == "CWE-1" for m in summary["shared_mitigations"])


class TestConsolidateBlankSeverity:
    def test_blank_severity_finding_skipped(self, tmp_path: Path) -> None:
        repo = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical"), _t("T-2", "Nonsense")])
        summary = ats.aggregate([repo], min_severity="low", open_only=False)
        ids = [f["id"] for f in summary["consolidated_findings"]]
        assert "T-1" in ids and "T-2" not in ids

    def test_consolidate_skips_blank_severity_directly(self) -> None:
        # A threat whose severity does not normalise -> `if not sev: continue`.
        loaded = [
            {
                "loaded": True,
                "name": "svc",
                "_threats": [
                    {"id": "T-good", "severity": "Critical"},
                    {"id": "T-bad", "severity": "WeirdValue"},
                ],
            },
            {"loaded": False, "name": "skip"},
        ]
        out = ats._consolidate_findings(loaded)
        ids = [f["id"] for f in out]
        assert ids == ["T-good"]


class TestAggregateValidation:
    def test_invalid_min_severity_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            ats.aggregate([], min_severity="bogus")


class TestValidateNoJsonschema:
    def test_returns_empty_when_jsonschema_missing(self, monkeypatch) -> None:
        monkeypatch.setattr(ats, "jsonschema", None)
        assert ats.validate({"anything": 1}) == []

    def test_schema_not_found(self, tmp_path: Path) -> None:
        if ats.jsonschema is None:
            import pytest

            pytest.skip("jsonschema not installed")
        errs = ats.validate({}, tmp_path / "missing.schema.json")
        assert errs and "schema not found" in errs[0]


class TestRenderMarkdownAllSections:
    def test_full_render_exercises_all_sections(self, tmp_path: Path) -> None:
        a = _make_repo(
            tmp_path,
            "up",
            threats=[_t("T-1", "Critical", cwe="CWE-79", component="TokenIssuer")],
            mitigations=[{"title": "CSP", "addresses_cwes": ["CWE-79"]}],
            generated=(
                __import__("datetime").datetime.now(tz=__import__("datetime").timezone.utc)
                - __import__("datetime").timedelta(days=200)
            ).isoformat(),
        )
        b = _make_repo(
            tmp_path,
            "down",
            threats=[_t("T-9", "High", cwe="CWE-79")],
            mitigations=[{"title": "Encode", "addresses_cwes": ["CWE-79"]}],
            trust_boundaries=[{"description": "uses TokenIssuer"}],
            related=[{"name": "up", "interface": "rest", "threat_model": "x"}],
        )
        empty = tmp_path / "empty"
        empty.mkdir()
        summary = ats.aggregate([a, b, empty], min_severity="medium", open_only=False)
        md = ats.render_markdown(summary)
        assert "Systemic Weaknesses (Shared CWEs)" in md
        assert "Cross-Repo Attack Chain Candidates" in md
        assert "Shared Mitigation Candidates" in md
        assert "_skipped:" in md
        assert "⚠" in md  # outdated marker

    def test_no_findings_register_message(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        summary = ats.aggregate([empty], min_severity="medium", open_only=False)
        md = ats.render_markdown(summary)
        assert "_No findings matched the filter._" in md


class TestCLIMore:
    def test_default_repo_is_cwd(self, monkeypatch, tmp_path: Path) -> None:
        args = ats._parse_args(["--format", "json"])
        monkeypatch.chdir(tmp_path)
        repos = ats._resolve_repos(args)
        assert repos == [tmp_path.resolve()]

    def test_main_dry_run_both(self, tmp_path: Path, capsys) -> None:
        a = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        rc = ats.main(["--repo", str(a), "--format", "both", "--dry-run"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Threat Summary" in out and '"meta"' in out

    def test_main_no_validate_stdout_json(self, tmp_path: Path, capsys) -> None:
        a = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        rc = ats.main(["--repo", str(a), "--format", "json", "--no-validate"])
        assert rc == 0
        assert '"aggregator_version": 1' in capsys.readouterr().out

    def test_main_output_md_file(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        out = tmp_path / "report.md"
        rc = ats.main(["--repo", str(a), "--format", "md", "--output", str(out), "--no-validate"])
        assert rc == 0
        assert "Threat Summary" in out.read_text(encoding="utf-8")

    def test_main_output_both_to_directory(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        outdir = tmp_path / "outdir"
        outdir.mkdir()
        rc = ats.main(["--repo", str(a), "--format", "both", "--output", str(outdir), "--no-validate"])
        assert rc == 0
        assert (outdir / "threat-summary.md").is_file()
        assert (outdir / "threat-summary.json").is_file()

    def test_main_output_both_to_file(self, tmp_path: Path) -> None:
        a = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        out = tmp_path / "report.md"
        rc = ats.main(["--repo", str(a), "--format", "both", "--output", str(out), "--no-validate"])
        assert rc == 0
        assert out.is_file()
        assert out.with_suffix(".json").is_file()

    def test_main_validation_failure_returns_2(self, tmp_path: Path, monkeypatch, capsys) -> None:
        a = _make_repo(tmp_path, "svc", threats=[_t("T-1", "Critical")])
        monkeypatch.setattr(ats, "validate", lambda *a, **k: ["forced error"])
        rc = ats.main(["--repo", str(a), "--format", "md", "--dry-run"])
        assert rc == 2
        assert "schema validation failed" in capsys.readouterr().err
