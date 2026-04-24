"""Unit tests for scripts/_atomic_io.py — crash-safe file writes."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "_atomic_io.py"


def _load():
    spec = importlib.util.spec_from_file_location("_atomic_io", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_atomic_io"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


atomic_io = _load()


# ---------------------------------------------------------------------------
# Baseline behaviour
# ---------------------------------------------------------------------------


def test_atomic_write_text_creates_file(tmp_path: Path):
    target = tmp_path / "note.txt"
    atomic_io.atomic_write_text(target, "hello world\n")
    assert target.read_text() == "hello world\n"


def test_atomic_write_text_overwrites_existing(tmp_path: Path):
    target = tmp_path / "note.txt"
    target.write_text("stale")
    atomic_io.atomic_write_text(target, "fresh")
    assert target.read_text() == "fresh"


def test_atomic_write_text_leaves_no_tempfile(tmp_path: Path):
    target = tmp_path / "note.txt"
    atomic_io.atomic_write_text(target, "x")
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "note.txt"]
    assert leftovers == [], f"temp files left: {leftovers}"


def test_atomic_write_json_round_trip(tmp_path: Path):
    target = tmp_path / "data.json"
    payload = {"b": 2, "a": [1, 2, 3], "nested": {"z": True}}
    atomic_io.atomic_write_json(target, payload)
    loaded = json.loads(target.read_text())
    assert loaded == payload


def test_atomic_write_json_sorts_keys_by_default(tmp_path: Path):
    target = tmp_path / "data.json"
    atomic_io.atomic_write_json(target, {"b": 2, "a": 1})
    text = target.read_text()
    # sort_keys=True means "a" appears before "b"
    assert text.index('"a"') < text.index('"b"')


def test_atomic_write_json_trailing_newline(tmp_path: Path):
    target = tmp_path / "data.json"
    atomic_io.atomic_write_json(target, {"a": 1})
    assert target.read_text().endswith("\n")


def test_atomic_write_json_no_trailing_newline_when_disabled(tmp_path: Path):
    target = tmp_path / "data.json"
    atomic_io.atomic_write_json(target, {"a": 1}, trailing_newline=False)
    assert not target.read_text().endswith("\n")


# ---------------------------------------------------------------------------
# Crash safety
# ---------------------------------------------------------------------------


def test_exception_during_write_preserves_old_file(tmp_path: Path, monkeypatch):
    """If the write fails partway, the existing file must remain intact."""
    target = tmp_path / "data.json"
    target.write_text('{"old": true}\n')

    # Inject a failure by monkeypatching os.replace to raise
    original = os.replace
    def failing_replace(src, dst):
        raise OSError("simulated rename failure")
    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(OSError):
        atomic_io.atomic_write_json(target, {"new": True})

    # Old content survived
    assert json.loads(target.read_text()) == {"old": True}
    # No leftover tmpfile in the directory
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "data.json"]
    assert leftovers == [], leftovers


def test_exception_on_fresh_write_leaves_no_file(tmp_path: Path, monkeypatch):
    """If the target did not exist and the write fails, no file is created."""
    target = tmp_path / "data.json"
    original = os.replace
    def failing_replace(src, dst):
        raise OSError("simulated rename failure")
    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(OSError):
        atomic_io.atomic_write_json(target, {"new": True})

    assert not target.exists()
    leftovers = list(tmp_path.iterdir())
    assert leftovers == [], leftovers


def test_atomic_write_json_accepts_dataclass_via_default_str(tmp_path: Path):
    """default=str in json.dumps lets us serialise Path/datetime-like values."""
    from pathlib import Path as _P

    target = tmp_path / "data.json"
    atomic_io.atomic_write_json(target, {"path": _P("/tmp/foo")})
    loaded = json.loads(target.read_text())
    assert loaded == {"path": "/tmp/foo"}
