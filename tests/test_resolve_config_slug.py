"""Tests for the ``--slug`` flag of scripts/runtime/resolve_config.py.

``--slug`` (optionally with a value) makes a run emit an additional
postfix-stamped, copy-ready deliverable set so several models can share one
output directory. Bare ``--slug`` generates a random postfix; ``--slug
<value>`` uses an explicit filename-safe value; omitting it leaves ``slug`` as
``None`` (canonical names only).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_resolve_config import _resolve_argv as _run  # noqa: E402


def test_no_slug_is_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = json.loads(_run("--quick").stdout)
    assert cfg["slug"] is None


def test_explicit_slug_passthrough(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = json.loads(_run("--quick", "--slug", "juice-shop-quick").stdout)
    assert cfg["slug"] == "juice-shop-quick"


def test_explicit_slug_equals_syntax(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = json.loads(_run("--quick", "--slug=model_a.v1").stdout)
    assert cfg["slug"] == "model_a.v1"


def test_max_length_slug_allowed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    slug = "x" * 64
    cfg = json.loads(_run("--quick", "--slug", slug).stdout)
    assert cfg["slug"] == slug


def test_bare_slug_generates_random_hex(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = json.loads(_run("--quick", "--slug").stdout)
    assert re.fullmatch(r"[0-9a-f]{4}", cfg["slug"]), cfg["slug"]


def test_bare_slug_before_another_flag_is_not_consumed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = json.loads(_run("--slug", "--quick").stdout)
    assert cfg["assessment_depth"] == "quick"
    assert re.fullmatch(r"[0-9a-f]{4}", cfg["slug"]), cfg["slug"]


def test_invalid_slug_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = _run("--quick", "--slug", "bad/slug")
    assert r.returncode != 0
    assert "slug" in r.stderr.lower()


def test_overlong_slug_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = _run("--quick", "--slug", "x" * 65)
    assert r.returncode != 0


def test_empty_slug_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = _run("--quick", "--slug=")
    assert r.returncode != 0
    assert "slug" in r.stderr.lower()
