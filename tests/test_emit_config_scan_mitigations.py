from __future__ import annotations

import sys
from pathlib import Path

import emit_config_scan_mitigations as ecm
import yaml


def _write_yaml(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def _run(output_dir: Path, monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["emit_config_scan_mitigations.py", str(output_dir)])
    return ecm.main()


def _config_threat(tid: str, **extra) -> dict:
    threat = {
        "id": tid,
        "source": "config-scan",
        "title": "Config scan finding",
        "scenario": "Weak configuration",
        "risk": "High",
        "cwe": "CWE-732",
        "evidence": [{"file": "Dockerfile", "line": 1}],
    }
    threat.update(extra)
    return threat


def test_load_iac_checks_missing_file_returns_empty(tmp_path: Path) -> None:
    assert ecm._load_iac_checks(tmp_path) == {}


def test_helpers_tolerate_noncanonical_yaml_shapes() -> None:
    data = {
        "mitigations": ["not-a-mapping", {"id": "M-007"}, {"id": "manual"}],
        "threats": [
            "not-a-mapping",
            {"id": "T-001"},
            {"id": "T-002", "mitigation_ids": []},
            {"id": "T-003", "mitigation_ids": ["M-002", "M-009"]},
        ],
    }

    assert ecm._scan_max_m_id(data) == 7
    assert ecm._clear_prior_auto_mitigations({"mitigations": {"id": "M-001"}}) == set()

    ecm._clear_stale_threat_refs(data, {"M-002"})

    assert data["threats"][3]["mitigation_ids"] == ["M-009"]


def test_synthesize_skips_malformed_threat_rows() -> None:
    data = {
        "threats": [
            "not-a-mapping",
            {"source": "config-scan"},
            _config_threat("T-010", title="Unknown config issue", risk="Unexpected"),
        ]
    }
    state = {"counter": 0}

    cards = ecm._synthesize_fix_mitigations(data, state, {})

    assert [card["id"] for card in cards] == ["M-001"]
    assert cards[0]["priority"] == "P3"
    assert data["threats"][2]["mitigation_ids"] == ["M-001"]
    assert "mitigation_ids" not in data["threats"][1]


def test_iac_check_id_uses_canonical_remediation_and_priority(tmp_path: Path, monkeypatch) -> None:
    _write_yaml(
        tmp_path,
        {
            "mitigations": [{"id": "M-010", "title": "Manual fix", "threat_ids": ["T-999"], "priority": "P3"}],
            "threats": [_config_threat("T-001", config_check_id="IAC-001", risk="High")],
        },
    )

    assert _run(tmp_path, monkeypatch) == 0

    data = _read_yaml(tmp_path)
    mitigation = data["mitigations"][1]
    assert mitigation["id"] == "M-011"
    assert mitigation["title"] == "Dockerfile base image must be digest-pinned"
    assert mitigation["kind"] == "fix"
    assert mitigation["priority"] == "P2"
    assert mitigation["auto_source"] == "config-scan"
    assert "Pin base image to @sha256:<digest>" in mitigation["how"]
    assert data["threats"][0]["mitigation_ids"] == ["M-011"]


def test_builtin_slug_and_haystack_fallbacks_emit_fix_cards(tmp_path: Path, monkeypatch) -> None:
    _write_yaml(
        tmp_path,
        {
            "threats": [
                _config_threat("T-001", config_check_slug="cors-wildcard", risk="Critical"),
                _config_threat(
                    "T-002",
                    title="Missing Content Security Policy",
                    scenario="The service has no CSP header",
                    risk="Medium",
                ),
            ]
        },
    )

    assert _run(tmp_path, monkeypatch) == 0

    data = _read_yaml(tmp_path)
    cards = {m["threat_ids"][0]: m for m in data["mitigations"]}
    assert cards["T-001"]["title"] == "Restrict CORS to an explicit origin allow-list"
    assert cards["T-001"]["priority"] == "P1"
    assert cards["T-002"]["title"] == "Configure a strict Content-Security-Policy header"
    assert cards["T-002"]["priority"] == "P3"
    assert data["threats"][0]["mitigation_ids"] == ["M-001"]
    assert data["threats"][1]["mitigation_ids"] == ["M-002"]


def test_generic_fallback_and_existing_mitigation_ids_are_preserved(tmp_path: Path, monkeypatch) -> None:
    _write_yaml(
        tmp_path,
        {
            "mitigations": [{"id": "M-004", "title": "Existing fix", "threat_ids": ["T-002"], "priority": "P3"}],
            "threats": [
                _config_threat("T-001", title="Unknown config issue", scenario="No known pattern", risk="Low"),
                _config_threat("T-002", mitigation_ids=["M-004"]),
            ],
        },
    )

    assert _run(tmp_path, monkeypatch) == 0

    data = _read_yaml(tmp_path)
    assert [m["id"] for m in data["mitigations"]] == ["M-004", "M-005"]
    assert data["mitigations"][1]["title"] == "Review and tighten the flagged configuration"
    assert data["mitigations"][1]["priority"] == "P4"
    assert data["threats"][0]["mitigation_ids"] == ["M-005"]
    assert data["threats"][1]["mitigation_ids"] == ["M-004"]


def test_rerun_clears_stale_auto_cards_and_writes_even_without_new_cards(tmp_path: Path, monkeypatch) -> None:
    _write_yaml(
        tmp_path,
        {
            "mitigations": [
                {"id": "M-001", "title": "Manual fix", "threat_ids": ["T-001"], "priority": "P2"},
                {
                    "id": "M-002",
                    "title": "Old config fix",
                    "threat_ids": ["T-001"],
                    "priority": "P3",
                    "auto_emitted": True,
                    "auto_source": "config-scan",
                },
            ],
            "threats": [_config_threat("T-001", source="stride", mitigation_ids=["M-001", "M-002"])],
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
    monkeypatch.setattr(sys, "argv", ["emit_config_scan_mitigations.py"])

    assert ecm.main() == 0

    assert "usage:" in capsys.readouterr().err
