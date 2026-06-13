"""Unit tests for scripts/check_release_meta.py — the release-boundary gate."""

from __future__ import annotations

import pytest

from scripts.check_release_meta import (
    changelog_has_version,
    main,
    read_pyproject_version,
    tag_version_matches,
)

PYPROJECT = '[project]\nname = "appsec-advisor"\nversion = "0.4.0b0"\n'
CHANGELOG = "# Changelog\n\n## 0.4.0-beta — 2026-06-13\n\n- thing\n"


def test_read_pyproject_version():
    assert read_pyproject_version(PYPROJECT) == "0.4.0b0"


def test_read_pyproject_version_missing():
    with pytest.raises(SystemExit):
        read_pyproject_version('[project]\nname = "x"\n')


@pytest.mark.parametrize(
    "tag,version,expected",
    [
        ("v0.4.0b0", "0.4.0b0", True),
        ("v0.4.0-beta", "0.4.0b0", True),  # PEP 440-equal across spellings
        ("v0.4.0b0", "0.4.0-beta", True),
        ("0.4.0b0", "0.4.0b0", False),  # missing leading v
        ("v0.5.0", "0.4.0b0", False),  # different version
        ("vnope", "0.4.0b0", False),  # unparseable
    ],
)
def test_tag_version_matches(tag, version, expected):
    assert tag_version_matches(tag, version) is expected


@pytest.mark.parametrize(
    "version,expected",
    [
        ("0.4.0b0", True),  # matches the '0.4.0-beta' heading
        ("0.4.0-beta", True),
        ("0.5.0", False),  # no heading
    ],
)
def test_changelog_has_version(version, expected):
    assert changelog_has_version(CHANGELOG, version) is expected


def test_changelog_ignores_unreleased_and_dates():
    text = "## Unreleased\n\n## 0.4.0-beta — 2026-06-13\n"
    assert changelog_has_version(text, "0.4.0b0") is True
    assert changelog_has_version(text, "2026.5.25") is False  # the date is not a release heading match


def _write_repo(tmp_path, pyproject=PYPROJECT, changelog=CHANGELOG):
    (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return tmp_path


def test_main_no_tag_passes(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    _write_repo(tmp_path)
    assert main(["--repo-root", str(tmp_path)]) == 0


def test_main_with_matching_tag_passes(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    _write_repo(tmp_path)
    assert main(["--repo-root", str(tmp_path), "--tag", "v0.4.0-beta"]) == 0


def test_main_tag_mismatch_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    _write_repo(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["--repo-root", str(tmp_path), "--tag", "v0.5.0"])
    assert exc.value.code == 1


def test_main_invalid_pyproject_version_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    _write_repo(tmp_path, pyproject='[project]\nversion = "not-a-version"\n')
    with pytest.raises(SystemExit) as exc:
        main(["--repo-root", str(tmp_path)])
    assert exc.value.code == 1


def test_main_changelog_missing_entry_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    _write_repo(tmp_path, changelog="# Changelog\n\n## Unreleased\n")
    with pytest.raises(SystemExit) as exc:
        main(["--repo-root", str(tmp_path)])
    assert exc.value.code == 1


def test_main_reads_tag_from_env(tmp_path, monkeypatch):
    _write_repo(tmp_path)
    monkeypatch.setenv("GITHUB_REF_NAME", "v0.4.0-beta")
    assert main(["--repo-root", str(tmp_path)]) == 0


def test_main_ignores_branch_ref_env(tmp_path, monkeypatch):
    # A branch push sets GITHUB_REF_NAME to the branch name; must not be read as a tag.
    _write_repo(tmp_path)
    monkeypatch.setenv("GITHUB_REF_NAME", "dev")
    assert main(["--repo-root", str(tmp_path)]) == 0  # passes via the no-tag path
