"""Tests for ``scripts/load_related_repos.py`` — declared cross-repo dependency
loader. Covers schema validation, path resolution, finding filter, cap, and the
``meta.generated`` outdated marker.
"""

from __future__ import annotations

import datetime as _dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import load_related_repos as lrr  # noqa: E402

PLUGIN_ROOT = Path(__file__).parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "load_related_repos.py"


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _make_tm(
    *,
    generated: str = "2099-01-01T00:00:00Z",
    commit_sha: str = "abc123",
    components: list[str] | None = None,
    threats: list[dict[str, Any]] | None = None,
    attack_surface: list[dict[str, Any]] | None = None,
    security_controls: list[dict[str, Any]] | None = None,
    component_paths: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    components = components if components is not None else ["AuthController"]
    threats = threats if threats is not None else []
    component_paths = component_paths or {}
    comp_blocks: list[dict[str, Any]] = []
    for i, n in enumerate(components):
        block: dict[str, Any] = {"id": f"c-{i}", "name": n}
        if n in component_paths:
            block["paths"] = component_paths[n]
        comp_blocks.append(block)
    tm: dict[str, Any] = {
        "meta": {"generated": generated, "git": {"commit_sha": commit_sha}},
        "components": comp_blocks,
        "threats": threats,
    }
    if attack_surface is not None:
        tm["attack_surface"] = attack_surface
    if security_controls is not None:
        tm["security_controls"] = security_controls
    return tm


# ---------------------------------------------------------------------------
# YAML absence / schema violations
# ---------------------------------------------------------------------------


class TestSchemaValidation:
    def test_missing_yaml_returns_empty(self, tmp_path: Path) -> None:
        result = lrr.load(tmp_path)
        assert result["related"] == []
        assert result["errors"] == []
        assert result["meta"]["yaml_present"] is False

    def test_top_level_not_mapping_is_error(self, tmp_path: Path) -> None:
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "related-repos.yaml").write_text("- not a mapping\n")
        result = lrr.load(tmp_path)
        assert result["related"] == []
        assert result["errors"]

    def test_missing_related_key_fails(self, tmp_path: Path) -> None:
        _write_yaml(tmp_path / "docs" / "related-repos.yaml", {"other": []})
        result = lrr.load(tmp_path)
        assert any("related" in e for e in result["errors"])

    def test_empty_related_list_fails(self, tmp_path: Path) -> None:
        _write_yaml(tmp_path / "docs" / "related-repos.yaml", {"related": []})
        result = lrr.load(tmp_path)
        assert result["errors"]

    def test_more_than_16_entries_fails(self, tmp_path: Path) -> None:
        entries = [{"name": f"svc-{i}", "threat_model": "../whatever.yaml"} for i in range(17)]
        _write_yaml(tmp_path / "docs" / "related-repos.yaml", {"related": entries})
        result = lrr.load(tmp_path)
        assert any("16" in e or "maxItems" in e for e in result["errors"])

    def test_missing_threat_model_field_fails(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path / "docs" / "related-repos.yaml",
            {"related": [{"name": "auth"}]},
        )
        result = lrr.load(tmp_path)
        assert any("threat_model" in e for e in result["errors"])

    def test_additional_properties_rejected(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path / "docs" / "related-repos.yaml",
            {"related": [{"name": "a", "threat_model": "x.yaml", "rogue": 1}]},
        )
        result = lrr.load(tmp_path)
        assert any("rogue" in e or "additional" in e.lower() for e in result["errors"])


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


class TestPathResolution:
    def test_relative_path_resolves_against_repo_root(self, tmp_path: Path) -> None:
        sibling_dir = tmp_path / "sibling"
        sibling_dir.mkdir()
        tm_path = sibling_dir / "tm.yaml"
        tm_path.write_text(yaml.safe_dump(_make_tm()))

        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {"related": [{"name": "sib", "threat_model": "../sibling/tm.yaml"}]},
        )
        result = lrr.load(tmp_path / "repo")
        assert result["related"][0]["threat_model"]["status"] == "found"
        assert result["related"][0]["threat_model"]["ref_kind"] == "relative"

    def test_absolute_path_used_as_is(self, tmp_path: Path) -> None:
        tm_path = tmp_path / "abs-tm.yaml"
        tm_path.write_text(yaml.safe_dump(_make_tm()))

        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {"related": [{"name": "abs", "threat_model": str(tm_path)}]},
        )
        result = lrr.load(tmp_path / "repo")
        rec = result["related"][0]
        assert rec["threat_model"]["status"] == "found"
        assert rec["threat_model"]["ref_kind"] == "absolute"

    def test_missing_file_becomes_not_found(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path / "docs" / "related-repos.yaml",
            {"related": [{"name": "ghost", "threat_model": "./nope.yaml"}]},
        )
        result = lrr.load(tmp_path)
        assert result["related"][0]["threat_model"]["status"] == "not found"
        assert result["related"][0]["interface_findings"] is None

    def test_disallowed_url_scheme_marked_unavailable(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path / "docs" / "related-repos.yaml",
            {"related": [{"name": "bad", "threat_model": "file:///etc/passwd"}]},
        )
        result = lrr.load(tmp_path)
        rec = result["related"][0]
        assert rec["threat_model"]["status"] == "unavailable"
        assert "scheme" in rec["threat_model"]["fetch_detail"]


# ---------------------------------------------------------------------------
# Findings filtering
# ---------------------------------------------------------------------------


def _threat(
    id_: str,
    sev: str,
    *,
    status: str = "open",
    component: str = "AuthController",
    cwe: str = "CWE-79",
    stride: str = "Spoofing",
) -> dict[str, Any]:
    return {
        "id": id_,
        "title": f"{id_} title",
        "severity": sev,
        "status": status,
        "component": component,
        "cwe": cwe,
        "stride": stride,
    }


class TestFindingFilter:
    def _setup(self, tmp_path: Path, threats: list[dict[str, Any]], **entry: Any) -> dict[str, Any]:
        tm_path = tmp_path / "tm.yaml"
        tm_path.write_text(yaml.safe_dump(_make_tm(threats=threats)))
        entry.setdefault("name", "svc")
        entry["threat_model"] = str(tm_path)
        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {"related": [entry]},
        )
        return lrr.load(tmp_path / "repo")

    def test_only_open_findings_included(self, tmp_path: Path) -> None:
        threats = [
            _threat("T-1", "Critical"),
            _threat("T-2", "Critical", status="mitigated"),
            _threat("T-3", "High", status="accepted"),
            _threat("T-4", "High", status="false-positive"),
        ]
        result = self._setup(tmp_path, threats)
        ids = [f["id"] for f in result["related"][0]["interface_findings"]["findings"]]
        assert ids == ["T-1"]

    def test_critical_and_high_included_without_component_filter(self, tmp_path: Path) -> None:
        threats = [
            _threat("T-1", "Critical"),
            _threat("T-2", "High"),
            _threat("T-3", "Medium"),
            _threat("T-4", "Low"),
        ]
        result = self._setup(tmp_path, threats)
        ids = sorted(f["id"] for f in result["related"][0]["interface_findings"]["findings"])
        assert ids == ["T-1", "T-2"]

    def test_medium_included_only_when_component_match(self, tmp_path: Path) -> None:
        threats = [
            _threat("T-A", "Medium", component="AuthController"),
            _threat("T-B", "Medium", component="Unrelated"),
        ]
        result = self._setup(tmp_path, threats, components=["AuthController"])
        ids = sorted(f["id"] for f in result["related"][0]["interface_findings"]["findings"])
        assert ids == ["T-A"]

    def test_component_filter_excludes_critical_from_other_components(self, tmp_path: Path) -> None:
        threats = [
            _threat("T-A", "Critical", component="AuthController"),
            _threat("T-B", "Critical", component="OtherComponent"),
        ]
        result = self._setup(tmp_path, threats, components=["AuthController"])
        ids = sorted(f["id"] for f in result["related"][0]["interface_findings"]["findings"])
        assert ids == ["T-A"]

    def test_cap_truncates_and_reports_excluded_count(self, tmp_path: Path) -> None:
        threats = [_threat(f"T-{i}", "High") for i in range(20)]
        tm_path = tmp_path / "tm.yaml"
        tm_path.write_text(yaml.safe_dump(_make_tm(threats=threats)))
        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {"related": [{"name": "x", "threat_model": str(tm_path)}]},
        )
        result = lrr.load(tmp_path / "repo", cap=5)
        block = result["related"][0]["interface_findings"]
        assert block["included"] == 5
        assert block["excluded_count"] == 15

    def test_status_whitespace_tolerated(self, tmp_path: Path) -> None:
        threats = [_threat("T-1", "Critical")]
        threats[0]["status"] = " OPEN "
        result = self._setup(tmp_path, threats)
        ids = [f["id"] for f in result["related"][0]["interface_findings"]["findings"]]
        assert ids == ["T-1"]

    def test_component_whitespace_tolerated(self, tmp_path: Path) -> None:
        threats = [_threat("T-A", "Medium", component=" AuthController ")]
        result = self._setup(tmp_path, threats, components=["AuthController"])
        ids = [f["id"] for f in result["related"][0]["interface_findings"]["findings"]]
        assert ids == ["T-A"]

    def test_v2_threat_categories_schema_supported(self, tmp_path: Path) -> None:
        tm = {
            "meta": {"generated": "2099-01-01T00:00:00Z"},
            "components": [{"name": "AuthController"}],
            "threat_categories": [
                {"name": "S", "findings": [_threat("T-1", "Critical")]},
                {"name": "T", "findings": [_threat("T-2", "High")]},
            ],
        }
        tm_path = tmp_path / "tm.yaml"
        tm_path.write_text(yaml.safe_dump(tm))
        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {"related": [{"name": "x", "threat_model": str(tm_path)}]},
        )
        result = lrr.load(tmp_path / "repo")
        ids = sorted(f["id"] for f in result["related"][0]["interface_findings"]["findings"])
        assert ids == ["T-1", "T-2"]


# ---------------------------------------------------------------------------
# Outdated detection
# ---------------------------------------------------------------------------


class TestOutdated:
    def test_recent_is_found(self, tmp_path: Path) -> None:
        tm_path = tmp_path / "tm.yaml"
        recent = (_dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(days=10)).isoformat()
        tm_path.write_text(yaml.safe_dump(_make_tm(generated=recent)))
        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {"related": [{"name": "x", "threat_model": str(tm_path)}]},
        )
        result = lrr.load(tmp_path / "repo")
        assert result["related"][0]["threat_model"]["status"] == "found"

    def test_old_is_outdated(self, tmp_path: Path) -> None:
        tm_path = tmp_path / "tm.yaml"
        old = (_dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(days=200)).isoformat()
        tm_path.write_text(yaml.safe_dump(_make_tm(generated=old)))
        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {"related": [{"name": "x", "threat_model": str(tm_path)}]},
        )
        result = lrr.load(tmp_path / "repo", outdated_days=90)
        rec = result["related"][0]
        assert rec["threat_model"]["status"] == "outdated"
        # Outdated still loads findings — that is the documented behaviour.
        assert rec["interface_findings"] is not None


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


class TestAuthEnv:
    """Per-entry ``auth_env`` lets each upstream SCM have its own credentials.

    The unit tests focus on the resolution logic — exercising live HTTP
    requests would require a test server. ``_resolve_auth_header`` is the
    seam everything else depends on, so testing it covers the behaviour.
    """

    def test_per_entry_env_wins_over_global(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RELATED_REPOS_AUTH_HEADER", "global")
        monkeypatch.setenv("PAYMENT_TOKEN", "per-entry")
        assert lrr._resolve_auth_header("PAYMENT_TOKEN") == "per-entry"

    def test_global_fallback_when_per_entry_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RELATED_REPOS_AUTH_HEADER", "global")
        monkeypatch.delenv("PAYMENT_TOKEN", raising=False)
        assert lrr._resolve_auth_header("PAYMENT_TOKEN") == "global"

    def test_returns_none_when_both_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("RELATED_REPOS_AUTH_HEADER", raising=False)
        monkeypatch.delenv("PAYMENT_TOKEN", raising=False)
        assert lrr._resolve_auth_header("PAYMENT_TOKEN") is None

    def test_no_auth_env_falls_back_to_global(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("RELATED_REPOS_AUTH_HEADER", "global")
        assert lrr._resolve_auth_header(None) == "global"

    def test_auth_env_recorded_in_output(self, tmp_path: Path) -> None:
        tm_path = tmp_path / "tm.yaml"
        tm_path.write_text(yaml.safe_dump(_make_tm()))
        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {
                "related": [
                    {
                        "name": "svc",
                        "threat_model": str(tm_path),
                        "auth_env": "PAYMENT_TOKEN",
                    }
                ]
            },
        )
        result = lrr.load(tmp_path / "repo")
        # The variable NAME is recorded; the VALUE is never serialised.
        assert result["related"][0]["auth_env"] == "PAYMENT_TOKEN"

    def test_auth_env_pattern_validates(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path / "docs" / "related-repos.yaml",
            {"related": [{"name": "a", "threat_model": "x", "auth_env": "lower_case"}]},
        )
        result = lrr.load(tmp_path)
        assert any("auth_env" in e or "pattern" in e.lower() for e in result["errors"])


class TestUpstreamProperties:
    """Variante X — Consumer-Pull-Extraction von Architektur-Eigenschaften
    am deklarierten Interface des Upstream-TMs.
    """

    def _build_repo(
        self,
        tmp_path: Path,
        *,
        related_entry: dict[str, Any],
        upstream_tm: dict[str, Any],
    ) -> dict[str, Any]:
        tm_path = tmp_path / "upstream-tm.yaml"
        tm_path.write_text(yaml.safe_dump(upstream_tm))
        entry = {"name": related_entry.pop("name", "payments-api"), "threat_model": str(tm_path)}
        entry.update(related_entry)
        _write_yaml(
            tmp_path / "repo" / "docs" / "related-repos.yaml",
            {"related": [entry]},
        )
        return lrr.load(tmp_path / "repo")

    def test_no_consumer_declares_means_no_block(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {"entry_point": "POST /api/v1/payments", "protocol": "HTTPS", "auth_required": True}
            ],
            component_paths={"AuthController": ["POST /api/v1/payments"]},
        )
        result = self._build_repo(
            tmp_path,
            related_entry={"interface": "REST POST /api/v1/payments"},
            upstream_tm=tm,
        )
        rec = result["related"][0]
        assert rec["consumer_declares"] is None
        # upstream_properties is still populated because interface matches
        assert rec["upstream_properties"] is not None
        assert rec["upstream_properties"]["matched_entry_point"] == "POST /api/v1/payments"
        assert rec["upstream_properties"]["provenance"] == "upstream-asserted"
        assert rec["upstream_properties"]["auth_required"] is True
        assert rec["upstream_properties"]["protocol"] == "HTTPS"
        assert "AuthController" in rec["upstream_properties"]["handling_components"]
        # Without consumer declarations, no mismatch can be computed.
        assert rec["expectation_mismatch"] is None

    def test_consumer_declares_recorded(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {"entry_point": "POST /api/v1/payments", "protocol": "HTTPS", "auth_required": True}
            ],
            component_paths={"AuthController": ["POST /api/v1/payments"]},
        )
        result = self._build_repo(
            tmp_path,
            related_entry={
                "interface": "POST /api/v1/payments",
                "expected_auth": "JWT",
                "expected_validation": "schema",
            },
            upstream_tm=tm,
        )
        rec = result["related"][0]
        assert rec["consumer_declares"] == {
            "expected_auth": "JWT",
            "expected_validation": "schema",
        }

    def test_interface_substring_match_against_attack_surface(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {"entry_point": "POST /api/v1/payments", "protocol": "HTTPS", "auth_required": True},
                {"entry_point": "GET /api/v1/payments/:id", "protocol": "HTTPS", "auth_required": True},
            ],
        )
        result = self._build_repo(
            tmp_path,
            related_entry={"interface": "REST POST /api/v1/payments"},
            upstream_tm=tm,
        )
        up = result["related"][0]["upstream_properties"]
        # Bidirectional substring — entry_point is contained in declared interface.
        assert up["matched_entry_point"] == "POST /api/v1/payments"
        assert up["match_confidence"] == "substring"

    def test_no_attack_surface_means_no_upstream_properties(self, tmp_path: Path) -> None:
        tm = _make_tm()  # no attack_surface
        result = self._build_repo(
            tmp_path,
            related_entry={"interface": "REST POST /v1/auth"},
            upstream_tm=tm,
        )
        assert result["related"][0]["upstream_properties"] is None

    def test_no_interface_declared_means_no_upstream_properties(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {"entry_point": "POST /api/v1/payments", "protocol": "HTTPS", "auth_required": True}
            ],
        )
        result = self._build_repo(
            tmp_path,
            related_entry={},  # no `interface` field
            upstream_tm=tm,
        )
        assert result["related"][0]["upstream_properties"] is None

    def test_controls_attached_when_handling_component_matched(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {"entry_point": "POST /api/v1/payments", "protocol": "HTTPS", "auth_required": True}
            ],
            component_paths={"AuthController": ["POST /api/v1/payments"]},
            security_controls=[
                {"domain": "Authentication", "control": "JWT bearer", "effectiveness": "Adequate"},
                {"domain": "Input Validation", "control": "JSON schema", "effectiveness": "Adequate"},
            ],
        )
        result = self._build_repo(
            tmp_path,
            related_entry={"interface": "POST /api/v1/payments"},
            upstream_tm=tm,
        )
        up = result["related"][0]["upstream_properties"]
        ctrl_titles = sorted(c["control"] for c in up["controls"])
        assert ctrl_titles == ["JSON schema", "JWT bearer"]
        for c in up["controls"]:
            assert c["effectiveness"] == "Adequate"

    def test_controls_dropped_when_no_handling_component(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {"entry_point": "POST /api/v1/payments", "protocol": "HTTPS", "auth_required": True}
            ],
            # No component.paths references the entry_point — so no handling component.
            security_controls=[
                {"domain": "Authentication", "control": "JWT bearer", "effectiveness": "Adequate"},
            ],
        )
        result = self._build_repo(
            tmp_path,
            related_entry={"interface": "POST /api/v1/payments"},
            upstream_tm=tm,
        )
        up = result["related"][0]["upstream_properties"]
        assert up["handling_components"] == []
        assert up["controls"] == []

    def test_expectation_mismatch_auth_detected(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {
                    "entry_point": "POST /api/v1/payments",
                    "protocol": "HTTPS",
                    "auth_required": True,
                    "notes": "api-key in X-API-Key header",
                }
            ],
            component_paths={"AuthController": ["POST /api/v1/payments"]},
            security_controls=[
                {"domain": "Authentication", "control": "API key", "effectiveness": "Adequate"},
            ],
        )
        result = self._build_repo(
            tmp_path,
            related_entry={
                "interface": "POST /api/v1/payments",
                "expected_auth": "JWT",
            },
            upstream_tm=tm,
        )
        mm = result["related"][0]["expectation_mismatch"]
        assert mm is not None
        assert mm["auth"] is not None
        assert "JWT" in mm["auth"]
        assert mm["validation"] is None  # not declared → no mismatch

    def test_expectation_mismatch_validation_detected(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {"entry_point": "POST /api/v1/payments", "protocol": "HTTPS", "auth_required": True}
            ],
            component_paths={"AuthController": ["POST /api/v1/payments"]},
            security_controls=[
                {"domain": "Authentication", "control": "JWT bearer", "effectiveness": "Adequate"},
                # No validation control on the upstream side.
            ],
        )
        result = self._build_repo(
            tmp_path,
            related_entry={
                "interface": "POST /api/v1/payments",
                "expected_validation": "schema",
            },
            upstream_tm=tm,
        )
        mm = result["related"][0]["expectation_mismatch"]
        assert mm is not None
        assert mm["validation"] is not None
        assert "schema" in mm["validation"]

    def test_expectation_match_no_mismatch_block(self, tmp_path: Path) -> None:
        tm = _make_tm(
            attack_surface=[
                {
                    "entry_point": "POST /api/v1/payments",
                    "protocol": "HTTPS",
                    "auth_required": True,
                    "notes": "JWT bearer required",
                }
            ],
            component_paths={"AuthController": ["POST /api/v1/payments"]},
            security_controls=[
                {"domain": "Authentication", "control": "JWT bearer", "effectiveness": "Adequate"},
                {"domain": "Input Validation", "control": "JSON schema", "effectiveness": "Adequate"},
            ],
        )
        result = self._build_repo(
            tmp_path,
            related_entry={
                "interface": "POST /api/v1/payments",
                "expected_auth": "JWT",
                "expected_validation": "schema",
            },
            upstream_tm=tm,
        )
        # Both expectations matched — no mismatch block.
        assert result["related"][0]["expectation_mismatch"] is None

    def test_staleness_days_computed_from_generated(self, tmp_path: Path) -> None:
        old = (_dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(days=45)).isoformat()
        tm = _make_tm(
            generated=old,
            attack_surface=[
                {"entry_point": "POST /api/v1/payments", "protocol": "HTTPS", "auth_required": True}
            ],
        )
        result = self._build_repo(
            tmp_path,
            related_entry={"interface": "POST /api/v1/payments"},
            upstream_tm=tm,
        )
        up = result["related"][0]["upstream_properties"]
        assert up["staleness_days"] is not None
        assert 40 <= up["staleness_days"] <= 50


class TestCLI:
    def test_writes_output_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "out.json"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo-root", str(tmp_path), "--output", str(out_file)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["meta"]["yaml_present"] is False
        assert data["related"] == []

    def test_stdout_dash(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo-root", str(tmp_path), "--output", "-"],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert "related" in data

    def test_schema_violation_returns_exit_2(self, tmp_path: Path) -> None:
        _write_yaml(tmp_path / "docs" / "related-repos.yaml", {"related": []})
        out_file = tmp_path / "out.json"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--repo-root", str(tmp_path), "--output", str(out_file)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_meta_records_loader_version(self, tmp_path: Path) -> None:
        out_file = tmp_path / "out.json"
        subprocess.run(
            [sys.executable, str(SCRIPT), "--repo-root", str(tmp_path), "--output", str(out_file)],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data["meta"]["loader_version"] == 1
        assert data["meta"]["cap"] == 12
        assert data["meta"]["outdated_days"] == 90
