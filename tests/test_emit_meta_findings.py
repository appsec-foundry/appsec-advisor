from __future__ import annotations

from pathlib import Path

import emit_meta_findings as emf
import yaml


def _write_yaml(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def _threat(tid: str, source: str) -> dict:
    return {"id": tid, "source": source, "title": "Finding"}


def test_emits_meta_findings_for_thresholded_source_clusters(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "threats": [
                _threat("T-002", "dep-scan"),
                _threat("T-001", "dep-scan"),
                _threat("T-004", "configuration-defect"),
                _threat("T-003", "configuration-defect"),
                _threat("X-001", "dep-scan"),
                "not-a-threat",
            ]
        },
    )

    assert emf.main([str(tmp_path)]) == 0

    meta = _read_yaml(tmp_path)["meta_findings"]
    assert [m["id"] for m in meta] == ["MF-001", "MF-002"]
    assert meta[0]["category"] == "Insufficient Patch Management"
    assert meta[0]["derived_from"] == ["T-001", "T-002"]
    assert "2 findings trace to outdated dependencies" in meta[0]["summary"]
    assert meta[1]["category"] == "Insufficient Secret Management"
    assert meta[1]["derived_from"] == ["T-003", "T-004"]


def test_preserves_manual_meta_findings_and_allocates_after_highest_manual_id(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "meta_findings": [
                {
                    "id": "MF-010",
                    "title": "Manual governance gap",
                    "category": "Governance",
                    "summary": "Pinned by reviewer",
                    "derived_from": ["T-999"],
                    "severity": "Medium",
                    "manual": True,
                }
            ],
            "threats": [_threat("T-001", "dep-scan"), _threat("T-002", "dep-scan")],
        },
    )

    assert emf.main([str(tmp_path)]) == 0

    meta = _read_yaml(tmp_path)["meta_findings"]
    assert [m["id"] for m in meta] == ["MF-010", "MF-011"]
    assert meta[0]["manual"] is True
    assert meta[1]["category"] == "Insufficient Patch Management"


def test_stale_auto_meta_findings_are_removed_when_threshold_no_longer_matches(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "meta_findings": [
                {
                    "id": "MF-001",
                    "title": "Old auto finding",
                    "category": "Insufficient Patch Management",
                    "summary": "stale",
                    "derived_from": ["T-001", "T-002"],
                    "severity": "High",
                }
            ],
            "threats": [_threat("T-001", "dep-scan")],
        },
    )

    assert emf.main([str(tmp_path)]) == 0

    assert "meta_findings" not in _read_yaml(tmp_path)


def test_missing_invalid_and_non_mapping_yaml_return_errors(tmp_path: Path, capsys) -> None:
    assert emf.main([str(tmp_path)]) == 1
    assert "no yaml" in capsys.readouterr().err

    (tmp_path / "threat-model.yaml").write_text("threats: [\n", encoding="utf-8")
    assert emf.main([str(tmp_path)]) == 1
    assert "could not parse" in capsys.readouterr().err

    (tmp_path / "threat-model.yaml").write_text("- not-a-mapping\n", encoding="utf-8")
    assert emf.main([str(tmp_path)]) == 1
    assert "did not parse to a mapping" in capsys.readouterr().err


def test_usage_error() -> None:
    assert emf.main([]) == 2
