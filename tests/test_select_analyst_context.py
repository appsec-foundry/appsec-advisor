"""Deterministic surrounding-code selection of the change review."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from contexts import select_analyst_context as sel  # noqa: E402


@pytest.mark.parametrize(
    ("path", "text", "expected"),
    [
        ("src/a.ts", "import { x } from './lib/auth'\n", ["src/lib/auth.ts"]),
        ("src/a.js", "const g = require('../guard')\n", ["guard/index.js"]),
        ("src/a.tsx", "export * from './b'\nconst m = await import('./c.js')\n", ["src/b.tsx", "src/c.js"]),
        ("pkg/views.py", "from .guard import check\nfrom . import util\n", ["pkg/guard.py", "pkg/util/__init__.py"]),
        ("pkg/sub/v.py", "from ..models import User\n", ["pkg/models.py"]),
    ],
)
def test_relative_imports_resolve_to_files_of_the_view(path, text, expected):
    available = {
        "src/lib/auth.ts",
        "guard/index.js",
        "src/b.tsx",
        "src/c.js",
        "pkg/guard.py",
        "pkg/util/__init__.py",
        "pkg/models.py",
    }
    assert sel.relative_imports(path, text, available) == expected


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("a.ts", "import x from 'express'\n"),
        ("a.ts", "import x from '../../outside'\n"),
        ("a.py", "import requests\nfrom os import path\n"),
        ("a.go", 'import "./local"\n'),
    ],
)
def test_package_imports_escapes_and_other_languages_select_nothing(path, text):
    assert sel.relative_imports(path, text, {"express.ts", "outside.ts", "requests.py", "local.go"}) == []


def test_select_orders_imports_before_threat_evidence_and_respects_the_limit(tmp_path):
    (tmp_path / "proposed").mkdir()
    (tmp_path / "proposed" / "a.ts").write_text("import './b'\nimport './c'\n")
    snapshot = {"admitted": [{"path": "a.ts", "side": "proposed", "change": "modified"}]}
    model = {"focus_components": ["C-01"], "threats": [{"id": "F-001", "component": "C-01", "files": ["d.ts", "a.ts"]}]}
    available = {"a.ts", "b.ts", "c.ts", "d.ts"}
    chosen = sel.select(snapshot, available, tmp_path, model, limit=3)
    assert [c["path"] for c in chosen] == ["b.ts", "c.ts", "d.ts"]
    assert chosen[2]["reason"] == "threat model evidence for F-001 on a touched component"
    assert [c["path"] for c in sel.select(snapshot, available, tmp_path, model, limit=1)] == ["b.ts"]


def test_evidence_of_untouched_components_is_not_selected(tmp_path):
    (tmp_path / "proposed").mkdir()
    snapshot = {"admitted": []}
    model = {"focus_components": [], "threats": [{"id": "F-001", "component": "C-09", "files": ["d.ts"]}]}
    assert sel.select(snapshot, {"d.ts"}, tmp_path, model, limit=5) == []
