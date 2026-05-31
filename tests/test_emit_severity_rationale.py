"""Tests for emit_severity_rationale.py — the deterministic above-baseline
severity-rationale annotator."""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import emit_severity_rationale as esr  # type: ignore[import-not-found]


def _write(tmp_path: Path, threats: list[dict]) -> Path:
    p = tmp_path / "threat-model.yaml"
    p.write_text(yaml.safe_dump({"threats": threats}, sort_keys=False), encoding="utf-8")
    return tmp_path


def _reload(out_dir: Path) -> list[dict]:
    data = yaml.safe_load((out_dir / "threat-model.yaml").read_text(encoding="utf-8"))
    return data.get("threats") or []


def test_repo_read_secret_gets_public_repo_note(tmp_path: Path) -> None:
    out = _write(tmp_path, [{"id": "T-001", "risk": "Critical", "cwe": "CWE-321", "vektor": "repo-read"}])
    esr.emit(out)
    t = _reload(out)[0]
    assert "public source repo" in t["severity_rationale"]


def test_mass_assignment_unauth_gets_endpoint_note(tmp_path: Path) -> None:
    out = _write(tmp_path, [{"id": "T-012", "risk": "Critical", "cwe": "CWE-915", "vektor": "internet-anon"}])
    esr.emit(out)
    t = _reload(out)[0]
    assert "unauthenticated endpoint" in t["severity_rationale"]


def test_naturally_critical_class_gets_no_note(tmp_path: Path) -> None:
    # SQL injection (CWE-89) is Critical by class — no above-baseline note.
    out = _write(tmp_path, [{"id": "T-002", "risk": "Critical", "cwe": "CWE-89", "vektor": "internet-anon"}])
    esr.emit(out)
    t = _reload(out)[0]
    assert "severity_rationale" not in t


def test_non_critical_gets_no_note(tmp_path: Path) -> None:
    out = _write(tmp_path, [{"id": "T-040", "risk": "High", "cwe": "CWE-321", "vektor": "repo-read"}])
    esr.emit(out)
    t = _reload(out)[0]
    assert "severity_rationale" not in t


def test_manual_note_is_preserved(tmp_path: Path) -> None:
    out = _write(tmp_path, [{
        "id": "T-001", "risk": "Critical", "cwe": "CWE-321", "vektor": "repo-read",
        "severity_rationale": "hand authored", "severity_rationale_manual": True,
    }])
    esr.emit(out)
    t = _reload(out)[0]
    assert t["severity_rationale"] == "hand authored"


def test_stale_note_cleared_on_downgrade(tmp_path: Path) -> None:
    # Auto note present but the finding is now High → note must be removed.
    out = _write(tmp_path, [{"id": "T-001", "risk": "High", "cwe": "CWE-89", "severity_rationale": "old note"}])
    esr.emit(out)
    t = _reload(out)[0]
    assert "severity_rationale" not in t


def test_idempotent(tmp_path: Path) -> None:
    out = _write(tmp_path, [{"id": "T-001", "risk": "Critical", "cwe": "CWE-321", "vektor": "repo-read"}])
    esr.emit(out)
    first = (out / "threat-model.yaml").read_text(encoding="utf-8")
    esr.emit(out)
    second = (out / "threat-model.yaml").read_text(encoding="utf-8")
    assert first == second
