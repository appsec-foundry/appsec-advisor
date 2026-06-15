"""Tests for ``scripts/build_verify_diff.py`` — verify-requirements change-set
builder.

Covers:
  - base-ref resolution order (--base, --staged, origin/HEAD, fallbacks)
  - --numstat parsing including binary ('-') rows and malformed lines
  - the happy path: writes .verify-diff.json, prints changed count
  - error/exit paths: not-a-git-repo (exit 2), git diff failure (exit 2)
  - git-not-found shim
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import build_verify_diff as bvd  # noqa: E402

# ---------------------------------------------------------------------------
# Real-git fixtures
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "t@t.t")
    _git(path, "config", "user.name", "t")
    _git(path, "config", "commit.gpgsign", "false")
    return path


def _commit(repo: Path, fname: str, content: str, msg: str) -> None:
    (repo / fname).write_text(content, encoding="utf-8")
    _git(repo, "add", fname)
    _git(repo, "commit", "-q", "-m", msg)


# ---------------------------------------------------------------------------
# _git helper
# ---------------------------------------------------------------------------


class TestGitHelper:
    def test_git_returns_stdout_on_success(self, tmp_path: Path) -> None:
        repo = _init_repo(tmp_path / "r")
        _commit(repo, "a.txt", "x", "init")
        rc, out = bvd._git(repo, "rev-parse", "--is-inside-work-tree")
        assert rc == 0
        assert out.strip() == "true"

    def test_git_returns_stderr_on_failure(self, tmp_path: Path) -> None:
        repo = _init_repo(tmp_path / "r")
        rc, out = bvd._git(repo, "rev-parse", "--verify", "nope-no-such-ref")
        assert rc != 0
        assert out  # stderr text present

    def test_git_not_found(self, tmp_path: Path, monkeypatch) -> None:
        def _boom(*a, **k):
            raise FileNotFoundError()

        monkeypatch.setattr(bvd.subprocess, "run", _boom)
        rc, out = bvd._git(tmp_path, "status")
        assert rc == 127
        assert "git not found" in out


# ---------------------------------------------------------------------------
# _resolve_base
# ---------------------------------------------------------------------------


class TestResolveBase:
    def test_staged_mode(self, tmp_path: Path) -> None:
        mode, base = bvd._resolve_base(tmp_path, None, True)
        assert mode == "staged"
        assert base is None

    def test_explicit_base_wins(self, tmp_path: Path) -> None:
        mode, base = bvd._resolve_base(tmp_path, "feature-x", False)
        assert mode == "range"
        assert base == "feature-x"

    def test_origin_head_used_when_present(self, tmp_path: Path, monkeypatch) -> None:
        def _fake(repo, *args):
            if args[:2] == ("rev-parse", "--abbrev-ref"):
                return 0, "origin/main\n"
            return 1, ""

        monkeypatch.setattr(bvd, "_git", _fake)
        mode, base = bvd._resolve_base(tmp_path, None, False)
        assert mode == "range"
        assert base == "origin/main"

    def test_falls_back_to_origin_main(self, tmp_path: Path, monkeypatch) -> None:
        def _fake(repo, *args):
            # no origin/HEAD
            if args[:2] == ("rev-parse", "--abbrev-ref"):
                return 1, ""
            # origin/main verifies, origin/master not reached
            if args[:2] == ("rev-parse", "--verify") and args[2] == "origin/main":
                return 0, ""
            return 1, ""

        monkeypatch.setattr(bvd, "_git", _fake)
        mode, base = bvd._resolve_base(tmp_path, None, False)
        assert base == "origin/main"

    def test_falls_back_to_origin_master(self, tmp_path: Path, monkeypatch) -> None:
        def _fake(repo, *args):
            if args[:2] == ("rev-parse", "--abbrev-ref"):
                return 1, ""
            if args[:2] == ("rev-parse", "--verify") and args[2] == "origin/master":
                return 0, ""
            return 1, ""

        monkeypatch.setattr(bvd, "_git", _fake)
        mode, base = bvd._resolve_base(tmp_path, None, False)
        assert base == "origin/master"

    def test_ultimate_fallback_head_tilde(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(bvd, "_git", lambda *a, **k: (1, ""))
        mode, base = bvd._resolve_base(tmp_path, None, False)
        assert mode == "range"
        assert base == "HEAD~1"


# ---------------------------------------------------------------------------
# _changed_files
# ---------------------------------------------------------------------------


class TestChangedFiles:
    def test_numstat_parsed(self, tmp_path: Path) -> None:
        repo = _init_repo(tmp_path / "r")
        _commit(repo, "a.txt", "one\n", "init")
        _commit(repo, "a.txt", "one\ntwo\n", "edit")
        files = bvd._changed_files(repo, ["HEAD~1...HEAD"])
        assert len(files) == 1
        assert files[0]["path"] == "a.txt"
        assert files[0]["added"] == 1
        assert files[0]["removed"] == 0

    def test_binary_dash_rows(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(bvd, "_git", lambda *a, **k: (0, "-\t-\timg.png\n"))
        files = bvd._changed_files(tmp_path, ["x...HEAD"])
        assert files == [{"path": "img.png", "added": None, "removed": None}]

    def test_malformed_lines_skipped(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(bvd, "_git", lambda *a, **k: (0, "garbage line\n1\t2\tok.py\n"))
        files = bvd._changed_files(tmp_path, ["x...HEAD"])
        assert files == [{"path": "ok.py", "added": 1, "removed": 2}]

    def test_git_error_returns_empty(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(bvd, "_git", lambda *a, **k: (1, "boom"))
        assert bvd._changed_files(tmp_path, ["x"]) == []


# ---------------------------------------------------------------------------
# main() — integration over real repos
# ---------------------------------------------------------------------------


class TestMain:
    def test_not_a_git_repo(self, tmp_path: Path) -> None:
        non_git = tmp_path / "plain"
        non_git.mkdir()
        out = tmp_path / "out"
        rc = bvd.main(["--repo-root", str(non_git), "--output-dir", str(out)])
        assert rc == 2

    def test_range_mode_writes_payload(self, tmp_path: Path) -> None:
        repo = _init_repo(tmp_path / "r")
        _commit(repo, "a.txt", "one\n", "init")
        _commit(repo, "b.txt", "two\n", "add b")
        out = tmp_path / "out"
        rc = bvd.main(
            ["--repo-root", str(repo), "--output-dir", str(out), "--base", "HEAD~1"]
        )
        assert rc == 0
        payload = json.loads((out / ".verify-diff.json").read_text())
        assert payload["version"] == 1
        assert payload["mode"] == "range"
        assert payload["base_ref"] == "HEAD~1"
        assert payload["merge_base"]  # resolved
        assert any(f["path"] == "b.txt" for f in payload["changed_files"])
        assert "diff --git" in payload["diff_unified"]

    def test_staged_mode_writes_payload(self, tmp_path: Path) -> None:
        repo = _init_repo(tmp_path / "r")
        _commit(repo, "a.txt", "one\n", "init")
        # stage a new file without committing
        (repo / "c.txt").write_text("staged\n", encoding="utf-8")
        _git(repo, "add", "c.txt")
        out = tmp_path / "out"
        rc = bvd.main(["--repo-root", str(repo), "--output-dir", str(out), "--staged"])
        assert rc == 0
        payload = json.loads((out / ".verify-diff.json").read_text())
        assert payload["mode"] == "staged"
        assert payload["base_ref"] == "STAGED"
        assert payload["merge_base"] is None
        assert any(f["path"] == "c.txt" for f in payload["changed_files"])

    def test_empty_diff_is_success(self, tmp_path: Path, capsys) -> None:
        repo = _init_repo(tmp_path / "r")
        _commit(repo, "a.txt", "one\n", "init")
        out = tmp_path / "out"
        # diff HEAD...HEAD == empty
        rc = bvd.main(
            ["--repo-root", str(repo), "--output-dir", str(out), "--base", "HEAD"]
        )
        assert rc == 0
        assert capsys.readouterr().out.strip() == "0"

    def test_git_diff_failure_exits_2(self, tmp_path: Path, monkeypatch) -> None:
        repo = _init_repo(tmp_path / "r")
        _commit(repo, "a.txt", "one\n", "init")
        out = tmp_path / "out"

        real_git = bvd._git
        calls = {"n": 0}

        def _fake(r, *args):
            # let everything succeed until the unified `diff` (no --numstat) call
            if args and args[0] == "diff" and "--numstat" not in args:
                return 1, "fatal: bad revision"
            return real_git(r, *args)

        monkeypatch.setattr(bvd, "_git", _fake)
        rc = bvd.main(
            ["--repo-root", str(repo), "--output-dir", str(out), "--base", "HEAD~1"]
        )
        assert rc == 2

    def test_not_a_git_repo_via_rev_parse_fallback(self, tmp_path: Path, monkeypatch) -> None:
        # .git absent AND rev-parse --git-dir fails -> exit 2 branch (line 92-95)
        plain = tmp_path / "plain"
        plain.mkdir()
        out = tmp_path / "out"
        # Force the rev-parse probe to fail explicitly.
        monkeypatch.setattr(bvd, "_git", lambda *a, **k: (128, "not a repo"))
        rc = bvd.main(["--repo-root", str(plain), "--output-dir", str(out)])
        assert rc == 2


# ---------------------------------------------------------------------------
# CLI / __main__ dispatch via subprocess
# ---------------------------------------------------------------------------


class TestCLI:
    def test_cli_subprocess_happy_path(self, tmp_path: Path) -> None:
        repo = _init_repo(tmp_path / "r")
        _commit(repo, "a.txt", "one\n", "init")
        _commit(repo, "b.txt", "two\n", "add b")
        out = tmp_path / "out"
        script = Path(__file__).parent.parent / "scripts" / "build_verify_diff.py"
        proc = subprocess.run(
            [
                sys.executable,
                str(script),
                "--repo-root",
                str(repo),
                "--output-dir",
                str(out),
                "--base",
                "HEAD~1",
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == "1"
        assert (out / ".verify-diff.json").is_file()
