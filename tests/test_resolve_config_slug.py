"""Tests for the ``--slug`` flag of scripts/resolve_config.py.

``--slug`` (optionally with a value) makes a run emit an additional
postfix-stamped, copy-ready deliverable set so several models can share one
output directory. Bare ``--slug`` generates a random postfix; ``--slug
<value>`` uses an explicit filename-safe value; omitting it leaves ``slug`` as
``None`` (canonical names only).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "resolve_config.py"


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *argv],
        capture_output=True,
        text=True,
    )


def test_no_slug_is_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = json.loads(_run("--quick").stdout)
    assert cfg["slug"] is None


def test_explicit_slug_passthrough(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = json.loads(_run("--quick", "--slug", "juice-shop-quick").stdout)
    assert cfg["slug"] == "juice-shop-quick"


def test_bare_slug_generates_random_hex(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = json.loads(_run("--quick", "--slug").stdout)
    assert re.fullmatch(r"[0-9a-f]{4}", cfg["slug"]), cfg["slug"]


def test_invalid_slug_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = _run("--validate-only", "--quick", "--slug", "bad/slug")
    assert r.returncode != 0
    assert "slug" in r.stderr.lower()


def test_overlong_slug_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = _run("--validate-only", "--quick", "--slug", "x" * 65)
    assert r.returncode != 0


def test_slug_persisted_to_skill_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    r = _run("--quick", "--slug", "modelA", "--output", str(out), "--emit-file")
    assert r.returncode == 0
    assert json.loads((out / ".skill-config.json").read_text())["slug"] == "modelA"
