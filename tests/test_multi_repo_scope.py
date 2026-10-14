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


@pytest.mark.parametrize("directory", ["docs/security-old", "audit/prior-run"])
def test_prior_outputs_never_enter_model_reads_or_scanner_snapshots(tmp_path, directory):
    root = repository(tmp_path / "service")
    old = root / directory
    old.mkdir(parents=True)
    for name in ("threat-model.md", "threat-model.yaml", ".abuse-case-verdict-AC-T-006.json"):
        (old / name).write_text("Earlier generated assessment\n")
    # User-authored context in a report directory remains an admitted input.
    context = root / "docs/security/business-context.md"
    context.parent.mkdir(parents=True, exist_ok=True)
    context.write_text("# Business purpose\nServe records.\n")
    (context.parent / "threat-model.md").write_text("Earlier report\n")
    (context.parent / "threat-model.yaml").write_text("meta: {}\n")
    admitted = scope.admit([str(root)], str(tmp_path / "out"), minimum=1)
    repo = admitted.repositories[0]
    assert "app.py" in repo.files
    assert "docs/security/business-context.md" in repo.files
    for name in ("threat-model.md", "threat-model.yaml", ".abuse-case-verdict-AC-T-006.json"):
        path = f"{directory}/{name}"
        assert path in repo.artifacts and path not in repo.files
        with pytest.raises(scope.ScopeError, match="outside admitted"):
            admitted.read(repo.repository_id, path)
    with admitted.scanner_snapshot(repo.repository_id) as snapshot:
        assert not (snapshot / directory).exists()
        assert (snapshot / "docs/security/business-context.md").is_file()
    admitted.verify_unchanged()


def _commit_all(root: Path) -> None:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "src",
        ],
        check=True,
    )


@pytest.mark.parametrize("directory", ["docs/security", "audit/run-2"])
def test_a_concurrent_run_writing_into_the_checkout_leaves_its_source_state_unchanged(tmp_path, directory):
    root = repository(tmp_path / "service")
    _commit_all(root)
    admitted = scope.admit([str(root)], str(tmp_path / "out"), minimum=1)
    assert admitted.repositories[0].dirty is False
    # Another session's run and the plugin's hooks write their state into the checkout.
    output = root / directory
    for relative in (
        ".active-tool-calls/toolu_01.json",
        ".active-tool-calls/.agent-lifecycle.lock",
        ".assessment-work/host-events/0001-recon_scanner.jsonl",
        ".assessment-state.json",
        ".budget-state.json",
        ".assessment-summary-emitted",
        ".hook-events.log",
        ".agent-run.log",
    ):
        (output / relative).parent.mkdir(parents=True, exist_ok=True)
        (output / relative).write_text("run state\n")
    admitted.verify_unchanged()
    again = scope.admit([str(root)], str(tmp_path / "out"), minimum=1).repositories[0]
    assert again.dirty is False and not any(".active-tool-calls" in path for path in again.files)
    # A real source change still invalidates the assessment.
    (root / "worker.py").write_text("print('new')\n")
    with pytest.raises(scope.ScopeError, match="source state changed"):
        admitted.verify_unchanged()


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
    with admitted.scanner_snapshot(selected.repository_id) as recovered:
        assert (recovered / "app.py").read_bytes() == selected.files["app.py"]
    assert not recovered.exists()
    with pytest.raises(scope.ScopeError, match="outside admitted"):
        with admitted.scanner_snapshot("repo-ffffffffffffffff"):
            pytest.fail("Unknown repository entered a scanner snapshot")


@pytest.mark.parametrize("relative", ["src/handler.py", "worker/consumer.js"])
def test_repeated_scanner_snapshots_mask_once_and_isolate_consumer_changes(tmp_path, monkeypatch, relative):
    files = {relative: b"result = request.args['input']\n", "config/settings.yaml": b"mode: standard\n"}
    repo = scope.RepositoryView("repo-1111111111111111", tmp_path / "service", "a" * 40, "b" * 64, files)
    admitted = scope.AssessmentScope((repo,), tmp_path / "out")
    masked = []
    original = scope._masked_bytes

    def mask(data):
        masked.append(data)
        return original(data)

    monkeypatch.setattr(scope, "_masked_bytes", mask)
    assert not masked
    with admitted.scanner_snapshot(repo.repository_id) as first:
        (first / relative).write_text("scanner-local mutation\n")
        (first / "extra.py").write_text("unexpected = True\n")
    assert not first.exists()
    with admitted.scanner_snapshot(repo.repository_id) as second:
        assert second != first
        assert (second / relative).read_bytes() == files[relative]
        assert (second / "config/settings.yaml").read_bytes() == files["config/settings.yaml"]
        assert not (second / "extra.py").exists()
        assert not second.stat().st_mode & 0o077
        assert (second / relative).stat().st_mode & 0o777 == 0o600
    assert not second.exists()
    assert masked == list(files.values())
    assert dict(repo.files) == files


def test_scanner_mask_cache_does_not_cross_repository_views_or_new_admissions(tmp_path):
    roots = pair(tmp_path)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first, peer = admitted.repositories
    with admitted.scanner_snapshot(first.repository_id) as snapshot:
        assert (snapshot / "app.py").read_bytes() == first.files["app.py"]
    (first.root / "app.py").write_text("updated = True\n")
    refreshed = scope.admit(roots, str(tmp_path / "out"))
    assert refreshed.repositories[0].repository_id == first.repository_id
    with refreshed.scanner_snapshot(first.repository_id) as snapshot:
        assert (snapshot / "app.py").read_bytes() == b"updated = True\n"
    with admitted.scanner_snapshot(first.repository_id) as snapshot:
        assert (snapshot / "app.py").read_bytes() == first.files["app.py"]
    with admitted.scanner_snapshot(peer.repository_id) as snapshot:
        assert (snapshot / "app.py").read_bytes() == peer.files["app.py"]
    with pytest.raises(scope.ScopeError, match="changed"):
        admitted.verify_unchanged()


def test_failed_scanner_masking_cleans_up_and_never_caches_partial_results(tmp_path, monkeypatch):
    files = {"app.py": b"first = 1\n", "worker.py": b"second = 2\n"}
    repo = scope.RepositoryView("repo-1111111111111111", tmp_path / "service", "a" * 40, "b" * 64, files)
    admitted = scope.AssessmentScope((repo,), tmp_path / "out")
    directories, masked = [], []
    temporary = scope.tempfile.TemporaryDirectory
    original = scope._masked_bytes

    def directory(**kwargs):
        result = temporary(dir=tmp_path, **kwargs)
        directories.append(Path(result.name))
        return result

    def mask(data):
        masked.append(data)
        if len(masked) == 2:
            raise RuntimeError("masking failed")
        return original(data)

    monkeypatch.setattr(scope.tempfile, "TemporaryDirectory", directory)
    monkeypatch.setattr(scope, "_masked_bytes", mask)
    with pytest.raises(RuntimeError, match="masking failed"):
        with admitted.scanner_snapshot(repo.repository_id):
            pytest.fail("Incomplete masking must not reach a scanner")
    assert not directories[0].exists()
    with admitted.scanner_snapshot(repo.repository_id) as snapshot:
        assert {p.name: p.read_bytes() for p in snapshot.iterdir()} == files
    assert all(not path.exists() for path in directories)
    assert masked == list(files.values()) * 2


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
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = next(r for r in admitted.repositories if str(r.root) == roots[0])
    omitted = {"path": "linked/marker" if directory else "link", "reason": "symlink"}
    assert omitted in first.exclusions
    assert "app.py" in first.files
    assert not any(name.startswith(("link", "linked/")) for name in first.files)
    assert "unselected source" not in json.dumps(admitted.inventory())
    with pytest.raises(scope.ScopeError, match="outside admitted"):
        admitted.read(first.repository_id, "linked/marker" if directory else "link")
    with admitted.scanner_snapshot(first.repository_id) as snapshot:
        assert not (snapshot / ("linked" if directory else "link")).exists()


def _commit(root: str, *paths: str) -> None:
    subprocess.run(["git", "-C", root, "add", *paths], check=True)
    subprocess.run(
        ["git", "-C", root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "add"],
        check=True,
    )


@pytest.mark.parametrize("name", ["link", "config/alias.py"])
def test_tracked_symlink_is_recorded_as_omitted_not_followed(tmp_path, name):
    roots = pair(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("unselected source\n")
    link = Path(roots[0]) / name
    link.parent.mkdir(exist_ok=True)
    link.symlink_to(outside)
    _commit(roots[0], name)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = next(r for r in admitted.repositories if str(r.root) == roots[0])
    assert {"path": name, "reason": "symlink"} in first.exclusions
    assert name not in first.files
    row = next(r for r in admitted.inventory()["repositories"] if r["repository_id"] == first.repository_id)
    assert {"path": name, "reason": "symlink"} in row["exclusions"]
    admitted.verify_unchanged()


@pytest.mark.parametrize("name", ["vendor/lib", "deps"])
def test_submodule_is_recorded_as_omitted_and_never_read(tmp_path, name):
    roots = pair(tmp_path)
    inner = repository(tmp_path / "inner")
    (inner / "secret.py").write_text("inner = 1\n")
    _commit(str(inner), "secret.py")
    subprocess.run(
        ["git", "-C", roots[0], "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(inner), name],
        check=True,
        capture_output=True,
    )
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = next(r for r in admitted.repositories if str(r.root) == roots[0])
    assert {"path": name, "reason": "submodule"} in first.exclusions
    assert not any(path.startswith(name) for path in first.files)
    assert ".gitmodules" in first.files


@pytest.mark.parametrize("name", ["nested", "tools/embedded"])
def test_untracked_nested_repository_is_recorded_as_omitted(tmp_path, name):
    roots = pair(tmp_path)
    nested = repository(Path(roots[0]) / name)
    (nested / "inner.py").write_text("inner = 1\n")
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = next(r for r in admitted.repositories if str(r.root) == roots[0])
    assert {"path": name, "reason": "nested-repository"} in first.exclusions
    assert not any(path.startswith(name + "/") for path in first.files)
    assert "app.py" in first.files
    admitted.verify_unchanged()


@pytest.mark.parametrize("name", [".bashrc", "run/server.py"])
def test_listed_special_file_is_recorded_as_omitted_and_never_opened(tmp_path, name):
    roots = pair(tmp_path)
    special = Path(roots[0]) / name
    special.parent.mkdir(exist_ok=True)
    special.write_text("listed = 1\n")
    _commit(roots[0], name)
    # Git lists the path; a FIFO or a sandbox's /dev/null mask now sits there.
    special.unlink()
    os.mkfifo(special)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = next(r for r in admitted.repositories if str(r.root) == roots[0])
    assert {"path": name, "reason": "special-file"} in first.exclusions
    assert name not in first.files
    assert "app.py" in first.files
    row = next(r for r in admitted.inventory()["repositories"] if r["repository_id"] == first.repository_id)
    assert {"path": name, "reason": "special-file"} in row["exclusions"]


def test_omissions_are_covered_by_the_scope_fingerprint(tmp_path):
    roots = pair(tmp_path)
    before = scope.admit(roots, str(tmp_path / "out")).inventory()
    (Path(roots[0]) / "link").symlink_to(tmp_path / "missing-target")
    after = scope.admit(roots, str(tmp_path / "out")).inventory()
    assert after["schema_version"] == 2
    assert before["scope_sha256"] != after["scope_sha256"]


def test_captured_file_replaced_by_link_after_admission_never_yields_new_content(tmp_path):
    roots = pair(tmp_path)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = next(r for r in admitted.repositories if str(r.root) == roots[0])
    outside = tmp_path / "outside.py"
    outside.write_text("unselected source\n")
    (first.root / "app.py").unlink()
    (first.root / "app.py").symlink_to(outside)
    assert admitted.read(first.repository_id, "app.py")["lines"] == ["print('source')"]
    with admitted.scanner_snapshot(first.repository_id) as snapshot:
        assert (snapshot / "app.py").read_text() == "print('source')\n"
    with pytest.raises(scope.ScopeError, match="state changed"):
        admitted.verify_unchanged()


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
    # MR-10: past the per-file limit a file is excluded; only the aggregate limit rejects.
    admitted = scope.admit(roots, str(tmp_path / "out"))
    assert {"path": "app.py", "reason": "oversized"} in admitted.repositories[0].exclusions


@pytest.mark.parametrize("payload", [b"GIF89a\x10\x00\x10\x00" * 8, b"\xff\xd8\xff\xe0 jpeg-like" * 8])
def test_an_oversized_file_is_excluded_by_its_kind_not_rejecting_its_repository(tmp_path, monkeypatch, payload):
    """MR-10: an oversized text file, such as a lockfile, is excluded as not analysed."""
    roots = pair(tmp_path)
    (Path(roots[0]) / "assets").mkdir()
    (Path(roots[0]) / "assets" / "clip.bin").write_bytes(payload)
    (Path(roots[1]) / "package-lock.json").write_text('{"lockfileVersion": 3}\n' * 8)
    monkeypatch.setattr(scope, "MAX_FILE_BYTES", 32)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    assert {"path": "assets/clip.bin", "reason": "binary"} in admitted.repositories[0].exclusions
    assert {"path": "package-lock.json", "reason": "oversized"} in admitted.repositories[1].exclusions
    assert "package-lock.json" not in admitted.repositories[1].files
    # The inventory that records the exclusion still satisfies its contract.
    admitted.inventory()


@pytest.fixture
def operator_excludes(tmp_path, monkeypatch):
    """An operator home whose global Git configuration names its own ignore file."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "ignore-list").write_text(".editor-state/\n")
    (home / ".gitconfig").write_text("[core]\n\texcludesFile = ~/ignore-list\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    scope._user_excludes_file.cache_clear()
    yield
    scope._user_excludes_file.cache_clear()


def test_the_operators_global_ignore_list_keeps_editor_files_out_of_the_scope(tmp_path, operator_excludes):
    roots = pair(tmp_path)
    state = Path(roots[0]) / ".editor-state"
    state.mkdir()
    (state / "workspace.xml").write_text("<state/>\n")
    admitted = scope.admit(roots, str(tmp_path / "out"))
    assert not any(path.startswith(".editor-state/") for path in admitted.repositories[0].files)
    # An editor rewriting its state during the run is not a source change.
    (state / "workspace.xml").write_text("<state changed='1'/>\n")
    admitted.verify_unchanged()
    # The list hides only what it names; a change to admitted source still counts.
    (Path(roots[0]) / "app.py").write_text("print(3)\n")
    with pytest.raises(scope.ScopeError, match="state changed"):
        admitted.verify_unchanged()


def test_a_tracked_file_stays_in_the_scope_whatever_the_global_ignore_list_says(tmp_path, operator_excludes):
    roots = pair(tmp_path)
    state = Path(roots[0]) / ".editor-state"
    state.mkdir()
    (state / "shared.xml").write_text("<shared/>\n")
    subprocess.run(["git", "-C", roots[0], "add", "-f", ".editor-state/shared.xml"], check=True)
    admitted = scope.admit(roots, str(tmp_path / "out"))
    assert ".editor-state/shared.xml" in admitted.repositories[0].files


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


def _alias_stat(monkeypatch, alias: Path, real: Path) -> None:
    """Let one distinct directory report another's identity, like a bind mount."""
    original = os.stat

    def fake(path, *args, **kwargs):
        if kwargs.get("dir_fd") is None and isinstance(path, (str, os.PathLike)) and os.fspath(path) == str(alias):
            return original(real, *args, **kwargs)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(scope.os, "stat", fake)


@pytest.mark.parametrize("child", ["", "report"])
def test_output_aliasing_a_selected_root_by_identity_is_rejected(tmp_path, monkeypatch, child):
    roots = pair(tmp_path)
    mounted = (tmp_path / "mounted").resolve()
    mounted.mkdir()
    _alias_stat(monkeypatch, mounted, Path(roots[0]))
    with pytest.raises(scope.ScopeError, match="separate"):
        scope.admit(roots, str(mounted / child) if child else str(mounted))
    assert not (mounted / "report").exists()


def test_output_containing_a_selected_root_by_identity_is_rejected(tmp_path, monkeypatch):
    roots = pair(tmp_path)
    holder = (tmp_path / "holder").resolve()
    holder.mkdir()
    # The output reports the identity of the checkouts' common parent.
    _alias_stat(monkeypatch, holder, tmp_path.resolve())
    with pytest.raises(scope.ScopeError, match="separate"):
        scope.admit(roots, str(holder))


@pytest.mark.parametrize("label", ["alias", "renamed"])
def test_selection_aliasing_another_root_by_identity_is_rejected(tmp_path, monkeypatch, label):
    roots = pair(tmp_path)
    other = repository((tmp_path / label).resolve())
    _alias_stat(monkeypatch, other, Path(roots[0]))
    with pytest.raises(scope.ScopeError, match="overlapping"):
        scope.admit([roots[0], str(other)], str(tmp_path / "out"))


def test_selection_through_a_symlinked_parent_is_an_alias(tmp_path):
    roots = pair(tmp_path)
    (tmp_path / "linked-parent").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(scope.ScopeError, match="overlapping"):
        scope.admit([roots[0], str(tmp_path / "linked-parent" / "one")], str(tmp_path / "out"))
    with pytest.raises(scope.ScopeError, match="separate"):
        scope.admit(roots, str(tmp_path / "linked-parent" / "two" / "out"))


def test_distinct_identities_keep_admission(tmp_path, monkeypatch):
    roots = pair(tmp_path)
    unrelated = (tmp_path / "unrelated").resolve()
    unrelated.mkdir()
    _alias_stat(monkeypatch, unrelated, unrelated)
    admitted = scope.admit(roots, str(unrelated / "report"))
    assert len(admitted.repositories) == 2


@pytest.mark.parametrize("name", ["notes/settings.txt", "deploy/values.yaml"])
def test_untracked_unlisted_file_secret_is_masked_in_reads_and_snapshots(tmp_path, name):
    roots = pair(tmp_path)
    # Built at runtime so no credential-shaped literal is committed.
    key = "AK" + "IA" + "Q7RZ3K5V2M8N4P6T"
    target = Path(roots[0]) / name
    target.parent.mkdir(parents=True)
    target.write_text(f"first: 1\naccess_key: {key}\nlast: 3\n")
    (Path(roots[0]) / ".env.local").write_text(f"KEY={key}\n")
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = next(r for r in admitted.repositories if str(r.root) == roots[0])
    assert name in first.files
    assert {"path": ".env.local", "reason": "sensitive-name"} in first.exclusions
    reply = admitted.read(first.repository_id, name, 1, 3)
    assert key not in json.dumps(reply)
    assert reply["lines"][0] == "first: 1" and reply["lines"][2] == "last: 3"
    for _ in range(2):
        with admitted.scanner_snapshot(first.repository_id) as snapshot:
            text = (snapshot / name).read_text()
            assert key not in text
            assert text.splitlines() == reply["lines"]
            assert not (snapshot / ".env.local").exists()
            assert all(key.encode() not in path.read_bytes() for path in snapshot.rglob("*") if path.is_file())


def test_snapshot_keeps_line_numbers_after_multiline_masking(tmp_path):
    roots = pair(tmp_path)
    # Artificial, non-functional key material inside a temporary fixture.
    body = "\n".join(["MIIB" + "A" * 60] * 2)
    header, footer = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
    (Path(roots[0]) / "app.py").write_text(f"first = 1\n{header}\n{body}\n{footer}\nafter = 6\n")
    admitted = scope.admit(roots, str(tmp_path / "out"))
    first = next(r for r in admitted.repositories if str(r.root) == roots[0])
    for _ in range(2):
        with admitted.scanner_snapshot(first.repository_id) as snapshot:
            lines = (snapshot / "app.py").read_text().split("\n")
        assert lines[0] == "first = 1" and lines[5] == "after = 6" and lines[6] == ""
        assert "MIIB" not in "\n".join(lines)
