"""Tests for scripts/load_org_context.py."""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "load_org_context.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "org-profiles" / "acme"
FIXTURE_PATH = FIXTURE_DIR / "org-profile.yaml"


def _load_module():
    if "load_org_context" in sys.modules:
        return sys.modules["load_org_context"]
    spec = importlib.util.spec_from_file_location("load_org_context", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["load_org_context"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


loc = _load_module()


def test_loads_fixture_documents():
    wrapped, manifest, hard_errors = loc.load(FIXTURE_PATH)
    assert hard_errors == []
    assert wrapped.startswith("<!--")
    assert "untrusted reference data" in wrapped
    assert "## Context: sso" in wrapped
    ids = {m["id"] for m in manifest if m["loaded"]}
    assert {"organization", "sso", "platform"}.issubset(ids)
    for m in manifest:
        if m["loaded"]:
            assert m["sha256"]
            assert m["bytes"] > 0


def test_document_ids_filter_narrows_set():
    wrapped, manifest, _ = loc.load(FIXTURE_PATH, ["sso"])
    assert "## Context: sso" in wrapped
    assert "## Context: organization" not in wrapped
    loaded = [m for m in manifest if m["loaded"]]
    assert {m["id"] for m in loaded} == {"sso"}


def test_oversize_document_is_skipped(tmp_path):
    staged = tmp_path / "profile"
    shutil.copytree(FIXTURE_DIR, staged)
    big = staged / "context" / "sso.md"
    big.write_text("X" * 60_000)
    profile = staged / "org-profile.yaml"
    _, manifest, _ = loc.load(profile, ["sso"])
    sso = next(m for m in manifest if m["id"] == "sso")
    assert sso["loaded"] is False
    assert "oversize" in sso["reason"]


def test_symlink_escape_is_hard_error(tmp_path):
    staged = tmp_path / "profile"
    shutil.copytree(FIXTURE_DIR, staged)
    target = tmp_path / "leak.md"
    target.write_text("# outside")
    (staged / "context" / "sso.md").unlink()
    (staged / "context" / "sso.md").symlink_to(target)
    profile = staged / "org-profile.yaml"
    _, manifest, hard_errors = loc.load(profile, ["sso"])
    assert hard_errors
    sso = next(m for m in manifest if m["id"] == "sso")
    assert sso["loaded"] is False
    assert sso["reason"] == "symlink"


def test_secret_pattern_blocks_load(tmp_path):
    staged = tmp_path / "profile"
    shutil.copytree(FIXTURE_DIR, staged)
    (staged / "context" / "sso.md").write_text(
        "# Heading\n\nAKIA1234567890ABCDEF\n"
    )
    profile = staged / "org-profile.yaml"
    _, manifest, hard_errors = loc.load(profile, ["sso"])
    assert hard_errors
    sso = next(m for m in manifest if m["id"] == "sso")
    assert sso["loaded"] is False
    assert "secret-detected" in sso["reason"]


def test_wrapper_always_present_even_when_no_documents(tmp_path):
    staged = tmp_path / "profile"
    shutil.copytree(FIXTURE_DIR, staged)
    profile = staged / "org-profile.yaml"
    wrapped, _, _ = loc.load(profile, ["no-such-id"])
    assert "untrusted reference data" in wrapped


def test_frontmatter_is_stripped_from_body():
    wrapped, manifest, _ = loc.load(FIXTURE_PATH, ["sso"])
    sso = next(m for m in manifest if m["id"] == "sso")
    assert sso["loaded"] is True
    # The wrapped output should not contain the frontmatter delimiter.
    body_lines = wrapped.splitlines()
    body_idx = body_lines.index("## Context: sso (identity_ecosystem)")
    body = "\n".join(body_lines[body_idx:])
    assert "id: acme-sso" not in body


def test_emit_file_writes_threat_modeling_context(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    rc = loc.main([
        "--profile", str(FIXTURE_PATH),
        "--output-dir", str(out),
        "--emit-file",
    ])
    assert rc == 0
    assert (out / ".threat-modeling-context.md").exists()
    manifest = json.loads((out / ".org-context-manifest.json").read_text())
    assert any(d["loaded"] for d in manifest["documents"])
