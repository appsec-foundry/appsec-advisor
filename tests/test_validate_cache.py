"""Unit tests for scripts/validate_cache.py — pre-flight integrity + quarantine."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_cache.py"


def _load():
    spec = importlib.util.spec_from_file_location("validate_cache", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_cache"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


validate_cache = _load()


def _seed_fragments(out: Path) -> None:
    (out / ".fragments").mkdir()
    (out / ".appsec-cache").mkdir()


# ---------------------------------------------------------------------------
# No-op / happy path
# ---------------------------------------------------------------------------


def test_empty_dir_is_clean(tmp_path: Path):
    rep = validate_cache.run(tmp_path, quarantine=False)
    assert rep["checked_count"] == 0
    assert rep["ok_count"] == 0
    assert rep["corrupt"] == []


def test_all_healthy_files_reported_ok(tmp_path: Path):
    _seed_fragments(tmp_path)
    (tmp_path / ".threats-merged.json").write_text(json.dumps({"threats": []}))
    (tmp_path / ".stride-api.json").write_text(json.dumps({"threats": []}))
    (tmp_path / ".appsec-cache/baseline.json").write_text(json.dumps({"schema_version": 1}))
    (tmp_path / ".fragments/ok.json").write_text(json.dumps({"a": 1}))
    (tmp_path / ".fragments/ok.md").write_text("# hello")
    rep = validate_cache.run(tmp_path, quarantine=False)
    assert rep["checked_count"] == 5
    assert rep["ok_count"] == 5
    assert rep["corrupt"] == []


# ---------------------------------------------------------------------------
# Detection of corruption
# ---------------------------------------------------------------------------


def test_detects_truncated_json(tmp_path: Path):
    _seed_fragments(tmp_path)
    (tmp_path / ".stride-partial.json").write_text('{"threats": [')
    rep = validate_cache.run(tmp_path, quarantine=False)
    assert len(rep["corrupt"]) == 1
    assert rep["corrupt"][0]["path"] == ".stride-partial.json"
    assert "invalid JSON" in rep["corrupt"][0]["error"]


def test_detects_empty_json_as_corrupt(tmp_path: Path):
    _seed_fragments(tmp_path)
    (tmp_path / ".threats-merged.json").write_text("")
    rep = validate_cache.run(tmp_path, quarantine=False)
    assert len(rep["corrupt"]) == 1
    assert rep["corrupt"][0]["error"] == "empty file"


def test_detects_zero_byte_markdown_fragment(tmp_path: Path):
    _seed_fragments(tmp_path)
    (tmp_path / ".fragments/empty.md").write_text("")
    rep = validate_cache.run(tmp_path, quarantine=False)
    assert len(rep["corrupt"]) == 1
    assert "zero bytes" in rep["corrupt"][0]["error"]


def test_non_empty_markdown_is_ok(tmp_path: Path):
    _seed_fragments(tmp_path)
    (tmp_path / ".fragments/one-byte.md").write_text("x")
    rep = validate_cache.run(tmp_path, quarantine=False)
    assert rep["ok_count"] == 1
    assert rep["corrupt"] == []


def test_rejects_non_object_json(tmp_path: Path):
    """A JSON scalar (``42``, ``"str"``) is parseable but not a valid fragment."""
    _seed_fragments(tmp_path)
    (tmp_path / ".stride-scalar.json").write_text('42')
    rep = validate_cache.run(tmp_path, quarantine=False)
    assert len(rep["corrupt"]) == 1
    assert "unexpected top-level type" in rep["corrupt"][0]["error"]


# ---------------------------------------------------------------------------
# Quarantine behaviour
# ---------------------------------------------------------------------------


def test_quarantine_moves_corrupt_files(tmp_path: Path):
    _seed_fragments(tmp_path)
    (tmp_path / ".stride-broken.json").write_text('{bad json')
    (tmp_path / ".stride-good.json").write_text(json.dumps({"threats": []}))

    rep = validate_cache.run(tmp_path, quarantine=True)

    # Healthy file untouched, corrupt file moved
    assert (tmp_path / ".stride-good.json").exists()
    assert not (tmp_path / ".stride-broken.json").exists()
    qdir = Path(rep["quarantine_dir"])
    assert (qdir / ".stride-broken.json").exists()


def test_quarantine_preserves_nested_fragment_path(tmp_path: Path):
    _seed_fragments(tmp_path)
    (tmp_path / ".fragments/empty.md").write_text("")
    rep = validate_cache.run(tmp_path, quarantine=True)
    qdir = Path(rep["quarantine_dir"])
    # nested path preserved under quarantine/<ts>/.fragments/empty.md
    assert (qdir / ".fragments" / "empty.md").exists()


def test_quarantine_twice_produces_clean_second_pass(tmp_path: Path):
    _seed_fragments(tmp_path)
    (tmp_path / ".threats-merged.json").write_text("garbage")
    validate_cache.run(tmp_path, quarantine=True)
    rep2 = validate_cache.run(tmp_path, quarantine=False)
    # After quarantine the file is gone → nothing to check
    assert rep2["corrupt"] == []


def test_quarantine_never_touches_threat_model_outputs(tmp_path: Path):
    (tmp_path / "threat-model.md").write_text("broken")  # not JSON-parsed anyway
    (tmp_path / "threat-model.yaml").write_text("broken")
    rep = validate_cache.run(tmp_path, quarantine=True)
    # Neither file is in the inspection set
    assert rep["checked_count"] == 0
    assert (tmp_path / "threat-model.md").exists()
    assert (tmp_path / "threat-model.yaml").exists()


# ---------------------------------------------------------------------------
# CLI exit codes
# ---------------------------------------------------------------------------


def test_cli_exit_0_when_clean(tmp_path: Path, capsys):
    exit_code = validate_cache.main([str(tmp_path)])
    assert exit_code == 0


def test_cli_exit_1_when_corrupt_without_quarantine(tmp_path: Path, capsys):
    _seed_fragments(tmp_path)
    (tmp_path / ".stride-bad.json").write_text("not json")
    exit_code = validate_cache.main([str(tmp_path)])
    assert exit_code == 1


def test_cli_exit_0_when_corrupt_but_quarantined(tmp_path: Path, capsys):
    _seed_fragments(tmp_path)
    (tmp_path / ".stride-bad.json").write_text("not json")
    exit_code = validate_cache.main([str(tmp_path), "--quarantine"])
    assert exit_code == 0


def test_cli_missing_output_dir_exit_0(tmp_path: Path, capsys):
    exit_code = validate_cache.main([str(tmp_path / "does-not-exist")])
    assert exit_code == 0
