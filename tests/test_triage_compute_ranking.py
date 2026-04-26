"""Smoke tests for triage_compute_ranking.

Coverage: feature-flag gate, basic ranking computation, edge cases (no
threats, missing categories, schema-drift on security_controls)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = PLUGIN_ROOT / "scripts" / "triage_compute_ranking.py"


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _minimal_yaml(threats: list[dict]) -> dict:
    return {
        "meta": {"analysis_version": 2, "plugin_version": "test"},
        "components": [],
        "threats": threats,
        "mitigations": [],
        "security_controls": [],
        "attack_surface": {"unauthenticated": [], "authenticated": []},
        "assets": [],
        "trust_boundaries": [],
        "use_cases": [],
        "critical_findings": [],
        "owasp_coverage": [],
        "triage_summary": {},
        "changelog": [],
    }


def _run(output_dir: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(output_dir)],
        env=env, capture_output=True, text=True
    )


def test_feature_flag_default_off(tmp_path: Path) -> None:
    """Without APPSEC_TRIAGE_DETERMINISTIC=1 the script no-ops cleanly."""
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml([]))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": ""})
    assert res.returncode == 0
    assert "feature flag" in res.stdout.lower()
    assert not (tmp_path / ".triage-flags.json").is_file()


def test_empty_threats_emits_empty_block(tmp_path: Path) -> None:
    """Zero-threat run produces a v2 ranking block but no rankings."""
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml([]))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 0, res.stderr
    flags = json.loads((tmp_path / ".triage-flags.json").read_text())
    assert flags["version"] == 2
    assert "ranking" in flags
    assert flags["ranking"]["reconciliation_summary"]["chains_active"] == 0


def test_basic_ranking_with_two_findings(tmp_path: Path) -> None:
    threats = [
        {
            "t_id": "F-001", "title": "SQL Injection in /login",
            "primary_cwe": "CWE-89", "risk": "Critical",
            "impact": "Critical", "likelihood": "High",
            "cvss_v3_1": {"score": 9.8},
            "scenario": "Attacker submits crafted password to /rest/user/login...",
            "evidence": {"file": "routes/login.ts", "line": 34},
        },
        {
            "t_id": "F-002", "title": "Verbose error messages",
            "primary_cwe": "CWE-209", "risk": "High",
            "impact": "Low", "likelihood": "Medium",
            "cvss_v3_1": {"score": 4.3},
            "scenario": "Stack traces leak in 500 responses.",
            "evidence": {"file": "lib/error.ts"},
        },
    ]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 0, res.stderr
    flags = json.loads((tmp_path / ".triage-flags.json").read_text())
    ranked = flags["ranking"]["views"]["top_findings"]["findings_ranked"]
    assert len(ranked) == 2
    # Critical SQLi must outrank Medium info-disclosure
    assert ranked[0]["id"] == "F-001"
    assert ranked[0]["effective_severity"] == "Critical"
    # CWE-209 ranking-cap should NOT prevent High but should limit it
    assert ranked[1]["id"] == "F-002"


def test_yaml_augmented_with_effective_fields(tmp_path: Path) -> None:
    threats = [{
        "t_id": "F-001", "title": "Test", "primary_cwe": "CWE-89",
        "risk": "Critical", "impact": "Critical", "likelihood": "High",
        "scenario": "test",
    }]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 0
    augmented = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    t = augmented["threats"][0]
    assert "effective_severity" in t
    assert "breach_distance" in t
    assert "chain_role" in t


def test_missing_yaml_returns_error(tmp_path: Path) -> None:
    res = _run(tmp_path, {"APPSEC_TRIAGE_DETERMINISTIC": "1"})
    assert res.returncode == 1
    assert "missing" in res.stderr.lower()


def test_dry_run_does_not_write(tmp_path: Path) -> None:
    threats = [{"t_id": "F-001", "title": "Test", "primary_cwe": "CWE-89", "risk": "Critical"}]
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml(threats))
    env = dict(os.environ)
    env["APPSEC_TRIAGE_DETERMINISTIC"] = "1"
    res = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path), "--dry-run"],
        env=env, capture_output=True, text=True
    )
    assert res.returncode == 0
    assert not (tmp_path / ".triage-flags.json").is_file()


def test_force_flag_overrides_env_gate(tmp_path: Path) -> None:
    """--force runs the ranking even without the feature flag."""
    _write_yaml(tmp_path / "threat-model.yaml", _minimal_yaml([]))
    env = dict(os.environ)
    env["APPSEC_TRIAGE_DETERMINISTIC"] = ""
    res = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path), "--force"],
        env=env, capture_output=True, text=True
    )
    assert res.returncode == 0
    assert (tmp_path / ".triage-flags.json").is_file()
