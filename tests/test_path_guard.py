"""Tests for scripts/_path_guard.py — symlink-escape detection."""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import _path_guard as guard  # noqa: E402


def test_is_within_repo_true_for_nested_path(tmp_path):
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert guard.is_within_repo(nested, tmp_path)


def test_is_within_repo_false_for_outside_path(tmp_path):
    outside = tmp_path.parent / "elsewhere"
    assert not guard.is_within_repo(outside, tmp_path)


def test_is_safe_to_read_rejects_escaping_symlink(tmp_path):
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    try:
        link = tmp_path / "link.txt"
        os.symlink(outside, link)
        assert not guard.is_safe_to_read(link, tmp_path)
    finally:
        outside.unlink(missing_ok=True)


def test_is_safe_to_read_accepts_internal_symlink(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("ok", encoding="utf-8")
    link = tmp_path / "link.txt"
    os.symlink(target, link)
    assert guard.is_safe_to_read(link, tmp_path)


def test_iter_escaping_symlinks_finds_file_escape(tmp_path):
    outside = tmp_path.parent / "secret.key"
    outside.write_text("k", encoding="utf-8")
    try:
        link = tmp_path / "policy.md"
        os.symlink(outside, link)
        findings = list(guard.iter_escaping_symlinks(tmp_path))
        assert any(f.path == link and f.kind == "file" for f in findings)
    finally:
        outside.unlink(missing_ok=True)


def test_iter_escaping_symlinks_finds_directory_escape(tmp_path):
    outside_dir = tmp_path.parent / "outside_dir"
    outside_dir.mkdir(exist_ok=True)
    try:
        link = tmp_path / "linked_dir"
        os.symlink(outside_dir, link, target_is_directory=True)
        findings = list(guard.iter_escaping_symlinks(tmp_path))
        kinds = {(f.path, f.kind) for f in findings}
        assert (link, "directory") in kinds
    finally:
        try:
            outside_dir.rmdir()
        except OSError:
            pass


def test_iter_escaping_symlinks_handles_broken_link(tmp_path):
    link = tmp_path / "broken"
    os.symlink(tmp_path.parent / "does-not-exist", link)
    findings = list(guard.iter_escaping_symlinks(tmp_path))
    assert any(f.path == link and f.kind == "broken" for f in findings)


# ---------------------------------------------------------------------------
# is_within_repo: resolve() raising (lines 35-36)
# ---------------------------------------------------------------------------


def test_is_within_repo_false_when_resolve_raises(tmp_path, monkeypatch):
    def _boom(self, *a, **kw):
        raise RuntimeError("symlink loop")

    monkeypatch.setattr(Path, "resolve", _boom)
    assert guard.is_within_repo(tmp_path / "x", tmp_path) is False


# ---------------------------------------------------------------------------
# is_safe_to_read: missing path (line 54) + OSError guard (lines 60-61)
# ---------------------------------------------------------------------------


def test_is_safe_to_read_false_for_missing_path(tmp_path):
    assert guard.is_safe_to_read(tmp_path / "nope.txt", tmp_path) is False


def test_is_safe_to_read_false_when_exists_raises(tmp_path, monkeypatch):
    target = tmp_path / "real.txt"
    target.write_text("ok", encoding="utf-8")

    def _boom(self):
        raise OSError("stat boom")

    monkeypatch.setattr(Path, "exists", _boom)
    assert guard.is_safe_to_read(target, tmp_path) is False


# ---------------------------------------------------------------------------
# iter_escaping_symlinks: file symlink whose resolve() raises (lines 95-97)
# ---------------------------------------------------------------------------


def test_iter_escaping_symlinks_file_resolve_raises_is_broken(tmp_path, monkeypatch):
    # A self-referential symlink loop makes Path.resolve(strict=False) raise
    # RuntimeError on some platforms; force it deterministically so the
    # broken-via-exception branch (lines 95-97) is exercised.
    link = tmp_path / "loop"
    os.symlink(tmp_path.parent / "target", link)

    real_resolve = Path.resolve

    def maybe_boom(self, *a, **kw):
        if self == link:
            raise OSError("ELOOP")
        return real_resolve(self, *a, **kw)

    monkeypatch.setattr(Path, "resolve", maybe_boom)
    findings = list(guard.iter_escaping_symlinks(tmp_path))
    assert any(f.path == link and f.kind == "broken" for f in findings)
