from __future__ import annotations

import sys
from pathlib import Path

import emit_finding_fix_mitigations as effm
import yaml


def _write_yaml(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def _run(output_dir: Path, monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["emit_finding_fix_mitigations.py", str(output_dir)])
    return effm.main()


def _threat(tid: str, **extra) -> dict:
    threat = {
        "id": tid,
        "source": "stride",
        "title": "SQL injection in search",
        "risk": "High",
        "cwe": "CWE-89",
        "mitigation_title": "Parameterize raw queries",
        "remediation": {"effort": "Medium", "steps": ["Replace string concatenation with bound parameters"]},
    }
    threat.update(extra)
    return threat


def test_groups_uncovered_code_findings_by_mitigation_title(tmp_path: Path, monkeypatch) -> None:
    _write_yaml(
        tmp_path,
        {
            "mitigations": [{"id": "M-010", "title": "Manual fix", "threat_ids": ["T-999"], "priority": "P3"}],
            "threats": [
                _threat("T-001", risk="Critical", vektor="internet-anon"),
                _threat(
                    "T-002",
                    risk="High",
                    mitigation_title="  parameterize raw queries  ",
                    remediation={"effort": "Low", "steps": ["Use the ORM parameter API", "Add regression coverage"]},
                ),
            ],
        },
    )

    assert _run(tmp_path, monkeypatch) == 0

    data = _read_yaml(tmp_path)
    card = data["mitigations"][1]
    assert card["id"] == "M-011"
    assert card["title"] == "Parameterize raw queries"
    assert card["kind"] == "fix"
    assert card["priority"] == "P1"
    assert card["severity"] == "Critical"
    assert card["effort"] == "Low"
    assert card["threat_ids"] == ["T-001", "T-002"]
    assert card["prevents"] == ["CWE-89"]
    threats = {t["id"]: t for t in data["threats"]}
    assert threats["T-001"]["mitigation_ids"] == ["M-011"]
    assert threats["T-002"]["mitigation_ids"] == ["M-011"]


def test_remediation_string_fallback_and_priority_rules(tmp_path: Path, monkeypatch) -> None:
    _write_yaml(
        tmp_path,
        {
            "threats": [
                _threat(
                    "T-001",
                    title="Weak deserialization",
                    risk="Critical",
                    mitigation_title="Replace unsafe deserialization",
                    remediation={"effort": "High", "steps": ["Replace pickle with a signed JSON envelope"]},
                    vektor="",
                ),
                _threat(
                    "T-002",
                    title="Open redirect",
                    risk="High",
                    mitigation_title="",
                    remediation="Validate redirects against a local allow-list.",
                    cwe="CWE-601",
                ),
            ]
        },
    )

    assert _run(tmp_path, monkeypatch) == 0

    data = _read_yaml(tmp_path)
    by_threat = {m["threat_ids"][0]: m for m in data["mitigations"]}
    assert by_threat["T-001"]["priority"] == "P2"
    assert by_threat["T-001"]["effort"] == "High"
    assert by_threat["T-002"]["title"] == "Remediate Open redirect"
    assert by_threat["T-002"]["how"] == "Validate redirects against a local allow-list."
    assert by_threat["T-002"]["priority"] == "P2"


def test_skips_config_scan_existing_links_and_empty_remediation(tmp_path: Path, monkeypatch, capsys) -> None:
    _write_yaml(
        tmp_path,
        {
            "threats": [
                _threat("T-001", source="config-scan"),
                _threat("T-002", mitigation_ids=["M-001"]),
                _threat("T-003", mitigation_title="", remediation={}),
                "not-a-threat",
            ]
        },
    )

    assert _run(tmp_path, monkeypatch) == 0

    data = _read_yaml(tmp_path)
    assert "mitigations" not in data
    assert "no uncovered code findings" in capsys.readouterr().err


def test_rerun_clears_stale_auto_cards_and_writes_even_without_new_cards(tmp_path: Path, monkeypatch) -> None:
    _write_yaml(
        tmp_path,
        {
            "mitigations": [
                {"id": "M-001", "title": "Manual fix", "threat_ids": ["T-001"], "priority": "P2"},
                {
                    "id": "M-002",
                    "title": "Old finding fix",
                    "threat_ids": ["T-001"],
                    "priority": "P3",
                    "auto_emitted": True,
                    "auto_source": "finding-fix",
                },
            ],
            "threats": [_threat("T-001", mitigation_ids=["M-001", "M-002"])],
        },
    )

    assert _run(tmp_path, monkeypatch) == 0

    data = _read_yaml(tmp_path)
    assert [m["id"] for m in data["mitigations"]] == ["M-001"]
    assert data["threats"][0]["mitigation_ids"] == ["M-001"]


def test_invalid_inputs_are_best_effort_noops(tmp_path: Path, monkeypatch, capsys) -> None:
    assert _run(tmp_path, monkeypatch) == 0
    assert "no" in capsys.readouterr().err

    (tmp_path / "threat-model.yaml").write_text("threats: [\n", encoding="utf-8")
    assert _run(tmp_path, monkeypatch) == 0
    assert "failed to load yaml" in capsys.readouterr().err

    (tmp_path / "threat-model.yaml").write_text("- not-a-mapping\n", encoding="utf-8")
    assert _run(tmp_path, monkeypatch) == 0
    assert "yaml root is not a mapping" in capsys.readouterr().err


def test_usage_error_is_best_effort_success(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["emit_finding_fix_mitigations.py"])

    assert effm.main() == 0

    assert "usage:" in capsys.readouterr().err
