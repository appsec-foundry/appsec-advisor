"""Fail-closed tests for the final per-section integrity gate."""

from __future__ import annotations

import json
from pathlib import Path

import section_integrity as integrity
import yaml


def _plugin_root(tmp_path: Path) -> Path:
    root = tmp_path / "plugin"
    data = root / "data"
    data.mkdir(parents=True)
    (data / "sections-contract.yaml").write_text(
        yaml.safe_dump(
            {
                "document": {"order": ["one", "two"]},
                "sections": {
                    "one": {"heading": "## 1. One"},
                    "two": {"heading": "## 2. Two"},
                },
                "preserve_on_downgrade": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return root


def _certificate(sections: list[dict]) -> dict:
    in_scope = [section for section in sections if section["in_scope"]]

    def count(outcome: str) -> int:
        return sum(section["outcome"] == outcome for section in in_scope)

    rendered = count("rendered")
    fallback = count("fallback")
    degraded = count("degraded")
    empty = count("empty")
    return {
        "schema_version": 1,
        "report_integrity_ok": degraded == 0 and empty == 0,
        "integrity_pct": (100 if not in_scope else round(100 * (rendered + fallback) / len(in_scope))),
        "sections_in_scope": len(in_scope),
        "sections_rendered": rendered,
        "sections_fallback": fallback,
        "sections_degraded": degraded,
        "sections_empty": empty,
        "sections_skipped_conditional": len(sections) - len(in_scope),
        "fragments_expected": sum(len(section.get("expected_fragments") or []) for section in in_scope),
        "fragments_wired": sum(len(section.get("present_fragments") or []) for section in in_scope),
        "broken_sections": [section["id"] for section in in_scope if section["outcome"] in {"degraded", "empty"}],
        "sections": sections,
    }


def _write_run(
    tmp_path: Path,
    sections: list[dict] | None = None,
) -> tuple[Path, Path]:
    plugin_root = _plugin_root(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "threat-model.md").write_text(
        "# Threat Model\n\n## 1. One\n\nBody.\n",
        encoding="utf-8",
    )
    (output_dir / "threat-model.yaml").write_text(
        "meta:\n  assessment_depth: standard\n",
        encoding="utf-8",
    )
    if sections is None:
        sections = [
            {
                "id": sid,
                "in_scope": True,
                "outcome": "rendered",
                "expected_fragments": [],
                "present_fragments": [],
            }
            for sid in ("one", "two")
        ]
    (output_dir / ".render-integrity.json").write_text(
        json.dumps(_certificate(sections)),
        encoding="utf-8",
    )
    return output_dir, plugin_root


def test_clean_complete_certificate_passes_and_writes_matrix(
    tmp_path: Path,
) -> None:
    output_dir, plugin_root = _write_run(tmp_path)

    assert integrity.run(output_dir, plugin_root) == 0
    matrix = json.loads((output_dir / ".section-integrity.json").read_text(encoding="utf-8"))
    assert matrix["ok"] is True
    assert [row["id"] for row in matrix["rows"]] == ["one", "two"]


def test_missing_certificate_blocks(tmp_path: Path) -> None:
    output_dir, plugin_root = _write_run(tmp_path)
    (output_dir / ".render-integrity.json").unlink()

    assert integrity.run(output_dir, plugin_root) == 2


def test_malformed_certificate_blocks(tmp_path: Path) -> None:
    output_dir, plugin_root = _write_run(tmp_path)
    (output_dir / ".render-integrity.json").write_text("{", encoding="utf-8")

    assert integrity.run(output_dir, plugin_root) == 2


def test_malformed_manifest_entry_blocks_without_crashing(tmp_path: Path) -> None:
    output_dir, plugin_root = _write_run(tmp_path)
    cert_path = output_dir / ".render-integrity.json"
    payload = json.loads(cert_path.read_text(encoding="utf-8"))
    del payload["sections"][0]["id"]
    cert_path.write_text(json.dumps(payload), encoding="utf-8")

    assert integrity.run(output_dir, plugin_root) == 2


def test_empty_manifest_blocks(tmp_path: Path) -> None:
    output_dir, plugin_root = _write_run(tmp_path)
    payload = _certificate([])
    payload["sections"] = []
    (output_dir / ".render-integrity.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    assert integrity.run(output_dir, plugin_root) == 2


def test_incomplete_manifest_blocks(tmp_path: Path) -> None:
    sections = [
        {
            "id": "one",
            "in_scope": True,
            "outcome": "rendered",
            "expected_fragments": [],
            "present_fragments": [],
        }
    ]
    output_dir, plugin_root = _write_run(tmp_path, sections)

    assert integrity.run(output_dir, plugin_root) == 2


def test_internally_inconsistent_aggregate_blocks(tmp_path: Path) -> None:
    output_dir, plugin_root = _write_run(tmp_path)
    cert_path = output_dir / ".render-integrity.json"
    payload = json.loads(cert_path.read_text(encoding="utf-8"))
    payload["integrity_pct"] = 12
    cert_path.write_text(json.dumps(payload), encoding="utf-8")

    assert integrity.run(output_dir, plugin_root) == 2


def test_empty_in_scope_section_blocks(tmp_path: Path) -> None:
    sections = [
        {
            "id": "one",
            "in_scope": True,
            "outcome": "rendered",
            "expected_fragments": [],
            "present_fragments": [],
        },
        {
            "id": "two",
            "in_scope": True,
            "outcome": "empty",
            "expected_fragments": ["two.json"],
            "present_fragments": [],
        },
    ]
    output_dir, plugin_root = _write_run(tmp_path, sections)

    assert integrity.run(output_dir, plugin_root) == 2


def test_missing_final_markdown_blocks(tmp_path: Path) -> None:
    output_dir, plugin_root = _write_run(tmp_path)
    (output_dir / "threat-model.md").unlink()

    assert integrity.run(output_dir, plugin_root) == 2
