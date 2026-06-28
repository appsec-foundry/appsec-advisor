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


def test_missing_file_is_false(tmp_path):
    assert nc.normalize_file(tmp_path / "nope.json") is False
