"""
Tests for scripts/repo_profile.py.

Covers:
  * Sizes: the totals are ``st_size`` sums of exactly the files in the tree, and
    ``.git`` never counts — a shallow clone must not profile smaller than a full
    one for the same commit.
  * Vendoring: installed dependencies and build output are counted, kept out of
    the language split, and their manifests do not invent components.
  * Classification: extension, bare filename, and the unknown case.
  * Layout: manifest directories are what tells a service from a monorepo.
  * Determinism: two runs over one tree are byte-identical, and equal-sized
    languages keep a stable order instead of following the filesystem.
  * Git basis: tracked versus working tree, and the note that appears when a
    scan would read files a clone would not have.
  * Symlinks are counted but never followed, so a cycle terminates.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import repo_profile as rp  # noqa: E402

HAS_GIT = shutil.which("git") is not None


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _lang(result: dict, language: str) -> dict | None:
    for row in result["languages"]:
        if row["language"] == language:
            return row
    return None


def _git_init(root: Path) -> None:
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PATH": "/usr/bin:/bin"}
    subprocess.run(["git", "init", "-q", str(root)], check=True, env=env)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "t@example.invalid"], check=True, env=env)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "test"], check=True, env=env)


def _git_commit_all(root: Path) -> None:
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PATH": "/usr/bin:/bin"}
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "initial"], check=True, env=env)


# ── sizes ────────────────────────────────────────────────────────────────────


def test_totals_are_the_sum_of_file_sizes(tmp_path: Path):
    _write(tmp_path, "a.py", "x" * 100)
    _write(tmp_path, "pkg/b.py", "y" * 50)

    result = rp.profile(tmp_path)

    assert result["totals"]["files"] == 2
    assert result["totals"]["bytes"] == 150


def test_git_directory_never_counts(tmp_path: Path):
    """git's object store is bookkeeping. Counting it would make the same commit
    profile differently depending on how it was cloned."""
    _write(tmp_path, "a.py", "x" * 10)
    _write(tmp_path, ".git/objects/pack/huge.pack", "z" * 100_000)
    _write(tmp_path, "sub/.git/objects/also-huge.pack", "z" * 100_000)

    result = rp.profile(tmp_path)

    assert result["totals"]["files"] == 1
    assert result["totals"]["bytes"] == 10


# ── vendoring ────────────────────────────────────────────────────────────────


def test_vendored_content_is_counted_but_kept_out_of_the_language_split(tmp_path: Path):
    _write(tmp_path, "app.ts", "x" * 100)
    _write(tmp_path, "node_modules/left-pad/index.js", "y" * 900)

    result = rp.profile(tmp_path)
    totals = result["totals"]

    assert totals["bytes"] == 1000
    assert totals["vendored_bytes"] == 900
    assert totals["source_bytes"] == 100
    assert _lang(result, "TypeScript")["share"] == 100.0
    assert _lang(result, "JavaScript") is None
    assert result["vendor_dirs"] == ["node_modules"]


def test_vendored_manifests_do_not_become_components(tmp_path: Path):
    """A dependency's own package.json is not a component of this repository —
    counting it would report a monorepo for every npm project on disk."""
    _write(tmp_path, "package.json", "{}")
    for name in ("left-pad", "chalk", "lodash"):
        _write(tmp_path, f"node_modules/{name}/package.json", "{}")

    result = rp.profile(tmp_path)

    assert result["manifest_roots"] == 1
    assert result["manifests"] == [{"ecosystem": "npm", "directories": ["."]}]


def test_vendor_share_note_names_the_directories(tmp_path: Path):
    _write(tmp_path, "app.py", "x" * 10)
    _write(tmp_path, "node_modules/dep/index.js", "y" * 500)
    _write(tmp_path, "dist/bundle.js", "z" * 500)

    result = rp.profile(tmp_path)

    note = next(n for n in result["notes"] if "installed dependencies" in n)
    assert "dist, node_modules" in note


# ── classification ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("path", "language", "category"),
    [
        ("src/main.py", "Python", "code"),
        ("src/App.tsx", "TypeScript (TSX)", "code"),
        ("Dockerfile", "Dockerfile", "config"),
        ("Makefile", "Make", "code"),
        ("docs/readme.MD", "Markdown", "docs"),
        ("data/rows.csv", "CSV", "data"),
        ("LICENSE", "Other", "other"),
        (".gitignore", "Other", "other"),
    ],
)
def test_classify(path: str, language: str, category: str):
    assert rp.classify(path) == (language, category)


def test_a_repository_without_source_says_so(tmp_path: Path):
    _write(tmp_path, "README.md", "x" * 100)
    _write(tmp_path, "docs/guide.md", "y" * 100)

    result = rp.profile(tmp_path)

    assert result["totals"]["code_bytes"] == 0
    assert any("no source files detected" in note for note in result["notes"])


def test_source_repository_has_no_such_note(tmp_path: Path):
    _write(tmp_path, "app.py", "x" * 100)

    result = rp.profile(tmp_path)

    assert result["totals"]["code_bytes"] == 100
    assert not any("no source files detected" in note for note in result["notes"])


# ── layout ───────────────────────────────────────────────────────────────────


def test_manifest_directories_distinguish_a_monorepo(tmp_path: Path):
    _write(tmp_path, "services/api/package.json", "{}")
    _write(tmp_path, "services/web/package.json", "{}")
    _write(tmp_path, "ml/pyproject.toml", "")
    _write(tmp_path, "svc/Api.csproj", "<Project/>")

    result = rp.profile(tmp_path)

    assert result["manifest_roots"] == 4
    assert result["manifests"] == [
        {"ecosystem": ".NET", "directories": ["svc"]},
        {"ecosystem": "Python", "directories": ["ml"]},
        {"ecosystem": "npm", "directories": ["services/api", "services/web"]},
    ]
    assert any("monorepo" in note for note in result["notes"])


def test_single_manifest_root_raises_no_monorepo_note(tmp_path: Path):
    _write(tmp_path, "package.json", "{}")
    _write(tmp_path, "pyproject.toml", "")

    result = rp.profile(tmp_path)

    assert result["manifest_roots"] == 1
    assert not any("monorepo" in note for note in result["notes"])


# ── determinism ──────────────────────────────────────────────────────────────


def test_two_runs_over_one_tree_are_identical(tmp_path: Path):
    for i in range(30):
        _write(tmp_path, f"pkg{i % 5}/mod{i}.py", "x" * (i + 1))
        _write(tmp_path, f"pkg{i % 5}/mod{i}.ts", "y" * (i + 1))

    first = json.dumps(rp.profile(tmp_path), sort_keys=True)
    second = json.dumps(rp.profile(tmp_path), sort_keys=True)

    assert first == second


def test_equal_sized_languages_are_ordered_by_name(tmp_path: Path):
    """Ties must not follow directory order — that is the one thing that differs
    between two machines holding the same commit."""
    _write(tmp_path, "a.rb", "x" * 100)
    _write(tmp_path, "b.go", "x" * 100)
    _write(tmp_path, "c.py", "x" * 100)

    languages = [row["language"] for row in rp.profile(tmp_path)["languages"]]

    assert languages == ["Go", "Python", "Ruby"]


def test_human_sizes_do_not_depend_on_the_filesystem(tmp_path: Path):
    assert rp._human(0) == "0 B"
    assert rp._human(1023) == "1023 B"
    assert rp._human(1024) == "1.0 KB"
    assert rp._human(1536) == "1.5 KB"
    assert rp._human(1024 * 1024) == "1.0 MB"


# ── git basis ────────────────────────────────────────────────────────────────


def test_a_plain_directory_is_reported_as_not_reproducible(tmp_path: Path):
    _write(tmp_path, "app.py", "x" * 10)

    result = rp.profile(tmp_path)

    assert result["git"] is False
    assert "tracked" not in result
    assert any("not a git repository" in note for note in result["notes"])


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_untracked_files_are_named_as_such(tmp_path: Path):
    _git_init(tmp_path)
    _write(tmp_path, "app.py", "x" * 10)
    _git_commit_all(tmp_path)
    _write(tmp_path, "scratch.py", "y" * 10)

    result = rp.profile(tmp_path)

    assert result["git"] is True
    assert result["tracked"]["files"] == 1
    assert result["tracked"]["untracked_files"] == 1
    assert result["head"]
    assert any("untracked" in note for note in result["notes"])


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_a_clean_checkout_gets_no_untracked_note(tmp_path: Path):
    _git_init(tmp_path)
    _write(tmp_path, "app.py", "x" * 10)
    _git_commit_all(tmp_path)

    result = rp.profile(tmp_path)

    assert result["tracked"]["untracked_files"] == 0
    assert not any("untracked" in note for note in result["notes"])


# ── symlinks ─────────────────────────────────────────────────────────────────


def test_symlinks_are_counted_and_not_followed(tmp_path: Path):
    _write(tmp_path, "app.py", "x" * 10)
    (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
    (tmp_path / "alias.py").symlink_to(tmp_path / "app.py")

    result = rp.profile(tmp_path)

    assert result["totals"]["files"] == 1
    assert result["totals"]["bytes"] == 10
    assert result["totals"]["symlinks"] == 2
    assert any("symlink" in note for note in result["notes"])


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_json_output_is_parseable(tmp_path: Path, capsys):
    _write(tmp_path, "app.py", "x" * 10)

    assert rp.main(["--repo", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["totals"]["bytes"] == 10


def test_text_output_carries_the_headline(tmp_path: Path, capsys):
    _write(tmp_path, "app.py", "x" * 10)

    assert rp.main(["--repo", str(tmp_path)]) == 0
    out = capsys.readouterr().out

    assert "Repository profile" in out
    assert "source" in out


def test_a_missing_directory_fails_without_a_traceback(tmp_path: Path, capsys):
    assert rp.main(["--repo", str(tmp_path / "nope")]) == 1
    assert "not a directory" in capsys.readouterr().err
