"""Tests for scripts/_yaml_io.py — load_yaml read semantics.

Covers the three declared semantics:
  * raise on error (no default)
  * return default on missing file
  * return default on malformed YAML
plus successful parse and the generic-OSError fallback path.
"""

from __future__ import annotations

from pathlib import Path

import _yaml_io
import pytest
import yaml
from _yaml_io import load_yaml


def test_successful_parse(tmp_path: Path):
    p = tmp_path / "ok.yaml"
    p.write_text("a: 1\nb: [x, y]\n", encoding="utf-8")
    data = load_yaml(p)
    assert data == {"a": 1, "b": ["x", "y"]}


def test_missing_file_raises_without_default(tmp_path: Path):
    p = tmp_path / "nope.yaml"
    with pytest.raises(FileNotFoundError):
        load_yaml(p)


def test_missing_file_returns_default_none(tmp_path: Path):
    p = tmp_path / "nope.yaml"
    assert load_yaml(p, default=None) is None


def test_missing_file_returns_default_dict(tmp_path: Path):
    p = tmp_path / "nope.yaml"
    assert load_yaml(p, default={}) == {}


def test_malformed_yaml_raises_without_default(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    # Unclosed flow sequence -> YAMLError
    p.write_text("a: [1, 2\n", encoding="utf-8")
    with pytest.raises(yaml.YAMLError):
        load_yaml(p)


def test_malformed_yaml_returns_default(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text("a: [1, 2\n", encoding="utf-8")
    assert load_yaml(p, default="fallback") == "fallback"


def test_generic_oserror_routes_to_default(tmp_path: Path):
    """A directory passed as path raises OSError on read_text -> default path."""
    d = tmp_path / "adir"
    d.mkdir()
    assert load_yaml(d, default=[]) == []


def test_generic_oserror_raises_without_default(tmp_path: Path):
    d = tmp_path / "adir2"
    d.mkdir()
    with pytest.raises(OSError):
        load_yaml(d)


def test_empty_file_parses_to_none(tmp_path: Path):
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")
    # safe_load("") -> None; no error, so default is irrelevant
    assert load_yaml(p, default={}) is None


def test_all_exports():
    assert _yaml_io.__all__ == ["load_yaml"]
