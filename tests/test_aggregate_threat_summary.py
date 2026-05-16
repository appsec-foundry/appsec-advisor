"""Tests for ``scripts/aggregate_threat_summary.py`` — multi-repo aggregator
that backs ``/appsec-advisor:generate-threat-summary``.

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
