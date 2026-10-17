"""The external assessment destination (decision AS-1, REQ-TRU-005)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from shared import assessment_location as loc  # noqa: E402

TAIL = Path("appsec-advisor") / "assessments"


def test_linux_base_follows_xdg_and_ignores_an_empty_or_relative_value(tmp_path):
    home = tmp_path / "home"
    assert loc.data_base({"XDG_DATA_HOME": str(tmp_path / "x")}, "linux", home) == tmp_path / "x" / TAIL
    assert loc.data_base({"XDG_DATA_HOME": ""}, "linux", home) == home / ".local/share" / TAIL
    assert loc.data_base({"XDG_DATA_HOME": "rel"}, "linux", home) == home / ".local/share" / TAIL


def test_macos_and_windows_bases(tmp_path):
    assert loc.data_base({}, "darwin", tmp_path) == tmp_path / "Library/Application Support" / TAIL
    assert loc.data_base({"LOCALAPPDATA": str(tmp_path)}, "win32", tmp_path) == tmp_path / TAIL
    with pytest.raises(loc.LocationError):
        loc.data_base({}, "win32", tmp_path)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/Juice-Shop/juice-shop.git",
        "https://user:ghp_secret@GitHub.com/Juice-Shop/juice-shop/",
        "ssh://git@github.com:22/Juice-Shop/juice-shop.git",
        "git@github.com:Juice-Shop/juice-shop.git",
    ],
)
def test_ssh_and_https_clones_share_one_identity(url):
    assert loc.normalize_remote(url) == "github.com/Juice-Shop/juice-shop"


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "file:///srv/repo.git",
        "C:\\work\\repo",
        "https:///nohost",
        "https://h/a/../b",
        "https://h/a\nb",
        "x" * 3000,
    ],
)
def test_unusable_remotes_have_no_identity(url):
    assert loc.normalize_remote(url) is None


def test_name_is_a_sanitized_slug_and_never_carries_credentials(tmp_path):
    name = loc.application_name(tmp_path, "https://alice:tok3n@example.com/team/Web App!.git")
    assert name.startswith("web-app-") and len(name) == len("web-app-") + 8
    assert "tok3n" not in name and "alice" not in name
    assert name == loc.application_name(tmp_path / "other", "git@example.com:team/Web App!.git")


def test_equal_names_from_different_remotes_do_not_collide(tmp_path):
    first = loc.application_name(tmp_path, "https://github.com/a/app.git")
    second = loc.application_name(tmp_path, "https://github.com/b/app.git")
    assert first != second and first.startswith("app-") and second.startswith("app-")


def test_without_a_remote_the_canonical_root_decides(tmp_path):
    root = tmp_path / "My Repo"
    root.mkdir()
    link = tmp_path / "alias"
    link.symlink_to(root)
    assert loc.application_name(link, None) == loc.application_name(root, None)
    assert loc.application_name(root, None).startswith("my-repo-")
    assert loc.application_name(tmp_path / "!!!", None).startswith("repository-")


def test_combined_identity_ignores_selection_order_and_needs_two_members(tmp_path):
    a = loc.application_name(tmp_path, "https://h/x/a")
    b = loc.application_name(tmp_path, "https://h/x/b")
    assert loc.combined_application_name([a, b]) == loc.combined_application_name([b, a])
    with pytest.raises(loc.LocationError):
        loc.combined_application_name([a, a])
    with pytest.raises(loc.LocationError):
        loc.combined_application_name([a, "../escape-00000000"])


@pytest.mark.parametrize("name", ["../x-0123abcd", "x", "a/b-0123abcd", "App-0123abcd", ""])
def test_only_produced_names_select_a_directory(tmp_path, name):
    with pytest.raises(loc.LocationError):
        loc.assessment_directory(name, tmp_path / TAIL)


def _target(tmp_path):
    base = tmp_path / TAIL
    return base, loc.assessment_directory(loc.application_name(tmp_path, "https://h/x/app"), base)


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX permissions")
def test_destination_is_created_private(tmp_path):
    base, target = _target(tmp_path)
    loc.private_directory(target, base)
    for path in (base.parent, base, target):
        assert path.is_dir() and path.stat().st_mode & 0o777 == 0o700


def test_a_symlinked_level_is_refused(tmp_path):
    base, target = _target(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    base.parent.mkdir(parents=True, mode=0o700)
    base.symlink_to(elsewhere)
    with pytest.raises(loc.LocationError, match="plain directory"):
        loc.private_directory(target, base)
    assert not any(elsewhere.iterdir())


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX permissions")
def test_a_level_open_to_others_is_refused(tmp_path):
    base, target = _target(tmp_path)
    base.mkdir(parents=True)
    base.chmod(0o755)
    with pytest.raises(loc.LocationError, match="other users"):
        loc.private_directory(target, base)


def test_a_destination_outside_the_base_is_refused(tmp_path):
    base, _ = _target(tmp_path)
    with pytest.raises(loc.LocationError, match="outside"):
        loc.private_directory(tmp_path / "repo" / "docs" / "security", base)
    with pytest.raises(loc.LocationError, match="appsec-advisor/assessments"):
        loc.private_directory(tmp_path / "x" / "y", tmp_path / "x")


def _clone(path: Path, origin: str | None) -> Path:
    import subprocess

    subprocess.run(["git", "init", "-q", str(path)], check=True)
    if origin:
        subprocess.run(["git", "-C", str(path), "remote", "add", "origin", origin], check=True)
    return path


def test_clones_of_one_remote_share_their_directory(tmp_path):
    base = tmp_path / TAIL
    a = _clone(tmp_path / "a", "git@github.com:org/app.git")
    b = _clone(tmp_path / "b", "https://token@github.com/org/app")
    c = _clone(tmp_path / "c", None)
    assert loc.application_directory(a, base) == loc.application_directory(b, base)
    assert loc.application_directory(c, base) != loc.application_directory(a, base)


def test_consumers_read_the_external_set_and_fall_back_to_legacy(tmp_path):
    base = tmp_path / TAIL
    repo = _clone(tmp_path / "repo", "https://h/org/app.git")
    external = loc.application_directory(repo, base)
    assert loc.locate(repo, base) == (external, False)
    legacy = repo / "docs" / "security"
    legacy.mkdir(parents=True)
    (legacy / "threat-model.yaml").write_text("x")
    assert loc.locate(repo, base) == (legacy, True)
    external.mkdir(parents=True)
    (external / "security-assessment.yaml").write_text("x")
    assert loc.locate(repo, base) == (external, False)


def test_cli_refuses_a_mixed_set_without_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(loc.sys, "platform", "linux")
    repo = _clone(tmp_path / "repo", None)
    legacy = repo / "docs" / "security"
    legacy.mkdir(parents=True)
    (legacy / "threat-model.yaml").write_text("x")
    (legacy / "security-assessment.yaml").write_text("x")
    assert loc.main(["locate", "--repo", str(repo)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("Error:") and "Traceback" not in err
    assert loc.main(["destination", "--repo", str(repo), "--json"]) == 0
    assert str(tmp_path / "data" / TAIL) in capsys.readouterr().out


def test_hooks_and_exports_find_the_checkouts_assessment_from_any_subdirectory(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(loc.sys, "platform", "linux")
    repo = _clone(tmp_path / "repo", "https://h/org/app.git")
    (repo / "src").mkdir()
    external = loc.application_directory(repo)
    assert loc.locate_from(repo / "src") == external
    assert loc.default_report(repo / "src") == external / "security-assessment.md"
    legacy = repo / "docs" / "security"
    legacy.mkdir(parents=True)
    (legacy / "threat-model.md").write_text("x")
    assert loc.default_report(repo) == legacy.resolve() / "threat-model.md"


def test_cli_creates_the_destination_privately_on_request(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(loc.sys, "platform", "linux")
    repo = _clone(tmp_path / "repo", None)
    assert loc.main(["destination", "--repo", str(repo)]) == 0
    directory = Path(capsys.readouterr().out.strip())
    assert not directory.exists()
    assert loc.main(["destination", "--repo", str(repo), "--create"]) == 0
    assert directory.is_dir() and directory.stat().st_mode & 0o777 == 0o700
    (tmp_path / "data" / "appsec-advisor").chmod(0o755)
    assert loc.main(["destination", "--repo", str(repo), "--create"]) == 2
    assert "accessible to other users" in capsys.readouterr().err
