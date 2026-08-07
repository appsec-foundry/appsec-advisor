"""Tests for scripts/normalize_config_scan.py (deterministic generated_at fix)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

import normalize_config_scan as nc  # noqa: E402


def test_strips_microseconds():
    assert nc.normalize_generated_at("2026-06-27T17:25:34.082802Z") == "2026-06-27T17:25:34Z"


def test_already_canonical_unchanged():
    assert nc.normalize_generated_at("2026-06-27T17:25:34Z") == "2026-06-27T17:25:34Z"


def test_numeric_offset_collapsed_to_z():
    assert nc.normalize_generated_at("2026-06-27T17:25:34.5+02:00") == "2026-06-27T17:25:34Z"


def test_non_string_unchanged():
    assert nc.normalize_generated_at(None) is None
    assert nc.normalize_generated_at(123) == 123


def test_unrecognised_unchanged():
    assert nc.normalize_generated_at("not-a-timestamp") == "not-a-timestamp"


def test_normalize_cwe_restores_prefix_without_rewriting_canonical_values():
    assert nc.normalize_cwe(["1104", 732, "CWE-89", None]) == ["CWE-1104", "CWE-732", "CWE-89", None]
    assert nc.normalize_cwe("1104") == "1104"


def test_file_rewrite_only_when_needed(tmp_path):
    p = tmp_path / ".config-scan-findings.json"
    p.write_text(
        json.dumps({"generated_at": "2026-06-27T17:25:34.082802Z", "findings": []}),
        encoding="utf-8",
    )
    assert nc.normalize_file(p) is True
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["generated_at"] == "2026-06-27T17:25:34Z"
    assert data["findings"] == []
    # idempotent — second pass is a no-op
    assert nc.normalize_file(p) is False


def test_normalize_file_repairs_config_scanner_cwe_projection(tmp_path):
    path = tmp_path / ".config-scan-findings.json"
    path.write_text(
        json.dumps(
            {
                "generated_at": "2026-06-27T17:25:34Z",
                "findings": [{"cwe": ["1104"]}, {"cwe": [732]}, {"cwe": ["CWE-89"]}],
            }
        ),
        encoding="utf-8",
    )

    assert nc.normalize_file(path) is True
    findings = json.loads(path.read_text(encoding="utf-8"))["findings"]
    assert [finding["cwe"] for finding in findings] == [["CWE-1104"], ["CWE-732"], ["CWE-89"]]


def test_missing_file_is_false(tmp_path):
    assert nc.normalize_file(tmp_path / "nope.json") is False
