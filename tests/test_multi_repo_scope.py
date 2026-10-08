"""Admission and abuse cases for the controller-owned multi-repository scope."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime import multi_repo_scope as scope


def repository(path: Path, text: str = "print('source')\n") -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "initial",
        ],
        check=True,
    )
    (path / "app.py").write_text(text)
    return path


def pair(tmp_path: Path) -> list[str]:
    return [str(repository(tmp_path / "one")), str(repository(tmp_path / "two"))]


def test_scanner_snapshot_uses_frozen_regular_files_and_cleans_up_on_failure(tmp_path):
    roots = pair(tmp_path)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    selected = admitted.repositories[0]
    (selected.root / "app.py").write_text("changed source\n")
    with pytest.raises(RuntimeError, match="scanner failed"):
        with admitted.scanner_snapshot(selected.repository_id) as snapshot:
            assert (snapshot / "app.py").read_bytes() == selected.files["app.py"]
            assert not (snapshot / ".git").exists()
            assert not (snapshot / "app.py").stat().st_mode & 0o111
            assert not snapshot.stat().st_mode & 0o077
            (snapshot / "app.py").write_text("scanner-local mutation\n")
            raise RuntimeError("scanner failed")
    assert not snapshot.exists()
    assert (selected.root / "app.py").read_text() == "changed source\n"
    with pytest.raises(scope.ScopeError, match="outside admitted"):
        with admitted.scanner_snapshot("repo-ffffffffffffffff"):
            pytest.fail("Unknown repository entered a scanner snapshot")


def test_all_selected_roots_have_distinct_portable_identity_and_order_is_irrelevant(tmp_path):
    roots = [str(repository(tmp_path / "team-a" / "service")), str(repository(tmp_path / "team-b" / "service"))]
    first = scope.admit(roots, str(tmp_path / "report"))
    second = scope.admit(list(reversed(roots)), str(tmp_path / "report"))
    assert first.inventory() == second.inventory()
    assert len({r.repository_id for r in first.repositories}) == 2
    assert len({r["label"] for r in first.inventory()["repositories"]}) == 2
    assert all(r["dirty"] for r in first.inventory()["repositories"])
    assert {r.root.name for r in first.repositories} == {"service"}
    assert str(tmp_path) not in json.dumps(first.inventory())
    assert not (tmp_path / "report").exists()


def test_spaces_and_shell_metacharacters_are_literal_paths(tmp_path):
    roots = [str(repository(tmp_path / "service $(touch escaped)")), str(repository(tmp_path / "other service"))]
    admitted = scope.admit(roots, str(tmp_path / "out"))
    assert len(admitted.repositories) == 2
    assert not (tmp_path / "escaped").exists()


@pytest.mark.parametrize("kind", ["duplicate", "symlink-alias", "overlap", "subdirectory", "missing"])
def test_invalid_selection_fails_without_output_mutation(tmp_path, kind):
    roots = pair(tmp_path)
    if kind == "duplicate":
        roots[1] = roots[0]
    elif kind == "symlink-alias":
        alias = tmp_path / "alias"
        alias.symlink_to(roots[0], target_is_directory=True)
        roots[1] = str(alias)
    elif kind == "overlap":
        roots[1] = str(repository(Path(roots[0]) / "nested"))
    elif kind == "subdirectory":
        child = Path(roots[0]) / "src"
        child.mkdir()
        roots[0] = str(child)
    else:
        roots[0] = str(tmp_path / "missing")
    with pytest.raises(scope.ScopeError):
        scope.admit(roots, str(tmp_path / "report"))
    assert not (tmp_path / "report").exists()


@pytest.mark.parametrize("target", ["source", "inside", "parent", "empty"])
def test_output_cannot_alias_or_contain_selected_sources(tmp_path, target):
    roots = pair(tmp_path)
    output = {"source": roots[0], "inside": str(Path(roots[1]) / "docs"), "parent": str(tmp_path), "empty": ""}[target]
    with pytest.raises(scope.ScopeError):
        scope.admit(roots, output)


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "src/../../outside", "x\\y", ".git/config", "x\ny"])
def test_untrusted_references_cannot_escape_the_admitted_view(tmp_path, path):
    admitted = scope.admit(pair(tmp_path), str(tmp_path / "out"))
    with pytest.raises(scope.ScopeError):
        admitted.read(admitted.repositories[0].repository_id, path)
    with pytest.raises(scope.ScopeError, match="outside admitted"):
        admitted.read("repo-invented", "app.py")


@pytest.mark.parametrize("directory", [False, True])
def test_symlinked_sources_are_never_read(tmp_path, directory):
    roots = pair(tmp_path)
    sentinel = tmp_path / "outside"
    sentinel.mkdir()
    (sentinel / "marker").write_text("unselected source")
    if directory:
        child = Path(roots[0]) / "linked"
        child.mkdir()
        (child / "marker").write_text("original")
        subprocess.run(["git", "-C", roots[0], "add", "linked/marker"], check=True)
        (child / "marker").unlink()
        child.rmdir()
        child.symlink_to(sentinel, target_is_directory=True)
    else:
        (Path(roots[0]) / "link").symlink_to(sentinel / "marker")
    with pytest.raises(scope.ScopeError):
        scope.admit(roots, str(tmp_path / "out"))


def test_snapshot_reads_are_frozen_and_publication_rejects_changed_secondary_root(tmp_path):
    roots = pair(tmp_path)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    second = admitted.repositories[1]
    (second.root / "app.py").write_text("print('changed')\n")
    assert admitted.read(second.repository_id, "app.py")["lines"] == ["print('source')"]
    with pytest.raises(scope.ScopeError, match="state changed"):
        admitted.verify_unchanged()


def test_post_admission_link_replacement_cannot_change_a_slice(tmp_path):
    roots = pair(tmp_path)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = admitted.repositories[0]
    (first.root / "app.py").unlink()
    (first.root / "app.py").symlink_to(tmp_path / "not-admitted")
    assert admitted.read(first.repository_id, "app.py")["lines"] == ["print('source')"]
    with pytest.raises(scope.ScopeError):
        admitted.verify_unchanged()


def test_sensitive_names_are_excluded_and_source_credentials_are_masked(tmp_path):
    roots = pair(tmp_path)
    # Artificial data is used only inside this temporary, non-runnable fixture.
    credential = "not-a-live-secret-" + "ab" * 15
    (Path(roots[0]) / ".env").write_text("unreadable input")
    (Path(roots[0]) / "app.py").write_text(f'password = "{credential}"\nprint(1)\n')
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = admitted.repositories[0]
    assert ".env" not in first.files
    assert {"path": ".env", "reason": "sensitive-name"} in first.exclusions
    reply = admitted.read(first.repository_id, "app.py")
    assert credential not in json.dumps(reply)
    assert reply["end_line"] == 2 and "****" in reply["lines"][0]


def test_source_and_slice_limits_fail_closed(tmp_path, monkeypatch):
    roots = pair(tmp_path)
    monkeypatch.setattr(scope, "MAX_TOTAL_BYTES", 1)
    with pytest.raises(scope.ScopeError, match="aggregate"):
        scope.admit(roots, str(tmp_path / "out"))
    monkeypatch.setattr(scope, "MAX_TOTAL_BYTES", 1000)
    monkeypatch.setattr(scope, "MAX_FILE_BYTES", 1)
    with pytest.raises(scope.ScopeError, match="file exceeds"):
        scope.admit(roots, str(tmp_path / "out"))


def test_git_environment_cannot_redirect_repository_selection(tmp_path, monkeypatch):
    roots = pair(tmp_path)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "foreign"))
    admitted = scope.admit(roots, str(tmp_path / "out"))
    admitted.verify_unchanged()
    assert len(admitted.repositories) == 2


def test_new_untracked_file_invalidates_the_scope(tmp_path):
    roots = pair(tmp_path)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    (Path(roots[1]) / "new.py").write_text("print(2)\n")
    with pytest.raises(scope.ScopeError, match="state changed"):
        admitted.verify_unchanged()


def _configure(root: str, *pairs: tuple[str, str]) -> None:
    for key, value in pairs:
        subprocess.run(["git", "-C", root, "config", key, value], check=True)


@pytest.mark.parametrize(
    ("driver", "key"),
    [("probe", "clean"), ("vendor.tool", "process")],
)
def test_admission_never_runs_repository_configured_filters(tmp_path, driver, key):
    roots = pair(tmp_path)
    marker = tmp_path / "filter-ran"
    command = f"sh -c 'touch {marker}; cat'"
    subprocess.run(["git", "-C", roots[1], "add", "app.py"], check=True)
    _configure(roots[1], (f"filter.{driver}.{key}", command), (f"filter.{driver}.required", "true"))
    (Path(roots[1]) / ".gitattributes").write_text(f"*.py filter={driver}\n")
    # Same size, new timestamp: Git must compare content through the filter.
    source = Path(roots[1]) / "app.py"
    stamp = source.stat().st_mtime_ns + 5_000_000_000
    os.utime(source, ns=(stamp, stamp))
    admitted = scope.admit(roots, str(tmp_path / "out"))
    admitted.verify_unchanged()
    assert not marker.exists()


def test_filter_neutralization_keeps_dirty_state(tmp_path):
    roots = pair(tmp_path)
    _configure(roots[0], ("filter.probe.clean", "cat"))
    assert all(r["dirty"] for r in scope.admit(roots, str(tmp_path / "out")).inventory()["repositories"])


def test_unrepresentable_filter_driver_fails_closed(tmp_path):
    roots = pair(tmp_path)
    _configure(roots[0], ("filter.a=b.clean", "cat"))
    with pytest.raises(scope.ScopeError, match="filter"):
        scope.admit(roots, str(tmp_path / "out"))


def test_slice_line_numbers_follow_the_raw_file_after_multiline_masking(tmp_path):
    roots = pair(tmp_path)
    # Artificial, non-functional key material inside a temporary fixture.
    body = "\n".join(["MIIB" + "A" * 60] * 2)
    header, footer = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
    text = f"first = 1\n{header}\n{body}\n{footer}\nafter = 6\nlast = 7\n"
    (Path(roots[0]) / "app.py").write_text(text)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = admitted.repositories[0]
    reply = admitted.read(first.repository_id, "app.py", 1, 7)
    assert reply["end_line"] == 7
    assert reply["lines"][0] == "first = 1"
    assert reply["lines"][5:] == ["after = 6", "last = 7"]
    assert "MIIB" not in json.dumps(reply)
    assert admitted.read(first.repository_id, "app.py", 6, 6)["lines"] == ["after = 6"]


def test_slice_lines_end_only_at_line_feeds(tmp_path):
    roots = pair(tmp_path)
    (Path(roots[0]) / "app.py").write_text("a = 1\r\nb = '\f\v'\nc = 3\n", newline="")
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = admitted.repositories[0]
    reply = admitted.read(first.repository_id, "app.py", 1, 10)
    assert reply["end_line"] == 3
    assert reply["lines"][0] == "a = 1" and reply["lines"][2] == "c = 3"
