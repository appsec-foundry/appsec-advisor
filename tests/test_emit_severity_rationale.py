"""Tests for emit_severity_rationale.py — the deterministic above-baseline
severity-rationale annotator."""
from __future__ import annotations

import json
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


# -- verified abuse-chain provenance (item 4) -------------------------------

def _write_matches(out_dir: Path, mapping: dict[str, str]) -> None:
    (out_dir / ".abuse-case-matches.json").write_text(
        json.dumps({"matches": [{"abuse_case_id": k, "title": v} for k, v in mapping.items()]}),
        encoding="utf-8",
    )


def test_verified_chain_keystone_names_chain(tmp_path: Path) -> None:
    # Already Critical (no numeric elevation) — must still document the role.
    out = _write(tmp_path, [{
        "id": "T-011", "risk": "Critical", "effective_severity": "Critical",
        "cwe": "CWE-639", "chain_role": "keystone", "verified_chain_ids": ["AC-T-002"],
    }])
    _write_matches(out, {"AC-T-002": "Bulk Data Exfiltration"})
    esr.emit(out)
    note = _reload(out)[0]["severity_rationale"]
    assert "verified attack-chain keystone in AC-T-002 (Bulk Data Exfiltration)" in note
    assert "see §9" in note
    assert "elevated to" not in note  # not numerically elevated


def test_verified_chain_elevated_says_elevated(tmp_path: Path) -> None:
    out = _write(tmp_path, [{
        "id": "T-019", "risk": "High", "effective_severity": "Critical",
        "cwe": "CWE-918", "chain_role": "keystone", "verified_chain_ids": ["AC-T-007"],
    }])
    _write_matches(out, {"AC-T-007": "SSRF Pivot"})
    esr.emit(out)
    note = _reload(out)[0]["severity_rationale"]
    assert note.startswith("elevated to Critical as a verified attack-chain keystone in AC-T-007 (SSRF Pivot)")


def test_chain_combines_with_intrinsic_repo_read(tmp_path: Path) -> None:
    out = _write(tmp_path, [{
        "id": "T-002", "risk": "Critical", "effective_severity": "Critical",
        "cwe": "CWE-321", "vektor": "repo-read",
        "chain_role": "keystone", "verified_chain_ids": ["AC-T-005"],
    }])
    _write_matches(out, {"AC-T-005": "Auth Bypass"})
    esr.emit(out)
    note = _reload(out)[0]["severity_rationale"]
    assert "public source repo" in note  # intrinsic note preserved
    assert "verified attack-chain keystone in AC-T-005 (Auth Bypass)" in note  # chain appended


def test_chain_dedupes_repeated_ac_ids(tmp_path: Path) -> None:
    out = _write(tmp_path, [{
        "id": "T-002", "risk": "Critical", "effective_severity": "Critical",
        "cwe": "CWE-89", "chain_role": "keystone", "verified_chain_ids": ["AC-T-005", "AC-T-005"],
    }])
    _write_matches(out, {"AC-T-005": "Auth Bypass"})
    esr.emit(out)
    note = _reload(out)[0]["severity_rationale"]
    assert note.count("AC-T-005") == 1


def test_chain_membership_without_verified_ids_gets_no_chain_note(tmp_path: Path) -> None:
    # keyword-chain keystone (no verified_chain_ids) + naturally-Critical CWE → no note.
    out = _write(tmp_path, [{
        "id": "T-005", "risk": "Critical", "effective_severity": "Critical",
        "cwe": "CWE-89", "chain_role": "keystone", "verified_chain_ids": [],
    }])
    esr.emit(out)
    assert "severity_rationale" not in _reload(out)[0]
