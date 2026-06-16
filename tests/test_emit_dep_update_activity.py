from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import emit_dep_update_activity as dep
import pytest


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _payload(output_dir: Path) -> dict:
    return json.loads((output_dir / ".dep-update-activity.json").read_text(encoding="utf-8"))


def test_walk_manifests_detects_supported_files_and_skips_vendor_dirs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "package.json", "{}")
    _write(repo / "requirements-test.txt", "pytest\n")
    _write(repo / "src" / "Service.csproj", "<Project />")
    _write(repo / "node_modules" / "package.json", "{}")
    _write(repo / ".venv" / "requirements.txt", "flask\n")
    _write(repo / "vendor" / "composer.json", "{}")
    _write(repo / "docs" / "README.md", "docs")

    assert dep._walk_manifests(repo) == [
        "package.json",
        "requirements-test.txt",
        "src/Service.csproj",
    ]


@pytest.mark.parametrize(
    ("dep_commits", "bot_commits", "in_git_repo", "expected"),
    [
        (0, 0, False, "unknown"),
        (0, 0, True, "inactive"),
        (1, 0, True, "sporadic"),
        (6, 0, True, "active"),
        (0, 3, True, "active"),
    ],
)
def test_classify_cadence(dep_commits: int, bot_commits: int, in_git_repo: bool, expected: str) -> None:
    assert dep._classify_cadence(dep_commits, bot_commits, in_git_repo) == expected


def test_is_git_repo_handles_success_false_and_subprocess_errors(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    monkeypatch.setattr(
        dep.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="true\n"),
    )
    assert dep._is_git_repo(repo) is True

    monkeypatch.setattr(
        dep.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="false\n"),
    )
    assert dep._is_git_repo(repo) is False

    def raise_timeout(*_args, **_kwargs):
        raise dep.subprocess.TimeoutExpired("git", 10)

    monkeypatch.setattr(dep.subprocess, "run", raise_timeout)
    assert dep._is_git_repo(repo) is False


def test_git_log_parses_valid_lines_and_ignores_malformed_rows(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "abc123\tAlice\tchore(deps): bump express\n"
                "malformed line without tabs\n"
                "def456\tBob\tupdate flask to 3.0.0\n"
            ),
        )

    monkeypatch.setattr(dep.subprocess, "run", fake_run)

    commits = dep._git_log(repo, 30, ["package.json", "requirements.txt"])

    assert commits == [
        {"sha": "abc123", "author": "Alice", "subject": "chore(deps): bump express"},
        {"sha": "def456", "author": "Bob", "subject": "update flask to 3.0.0"},
    ]
    cmd, kwargs = calls[0]
    assert cmd[:4] == ["git", "-C", str(repo), "log"]
    assert "--since=30 days ago" in cmd
    assert cmd[-2:] == ["package.json", "requirements.txt"]
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True


def test_git_log_returns_empty_on_no_paths_failures_and_timeouts(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    assert dep._git_log(repo, 90, []) == []

    monkeypatch.setattr(dep.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""))
    assert dep._git_log(repo, 90, ["package.json"]) == []

    def raise_os_error(*_args, **_kwargs):
        raise OSError("git unavailable")

    monkeypatch.setattr(dep.subprocess, "run", raise_os_error)
    assert dep._git_log(repo, 90, ["package.json"]) == []


def test_gh_dep_pr_count_handles_missing_cli_failures_and_valid_json(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    monkeypatch.setattr(dep.shutil, "which", lambda name: None)
    assert dep._gh_dep_pr_count(repo, 90) is None

    monkeypatch.setattr(dep.shutil, "which", lambda name: "/usr/bin/gh")
    monkeypatch.setattr(dep, "_iso_days_ago", lambda days: "2026-01-01")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps([{"number": 1}, {"number": 2}]))

    monkeypatch.setattr(dep.subprocess, "run", fake_run)

    assert dep._gh_dep_pr_count(repo, 30) == 2
    cmd, kwargs = calls[0]
    assert cmd[:3] == ["gh", "pr", "list"]
    assert any("merged:>=2026-01-01" in arg for arg in cmd)
    assert kwargs["cwd"] == str(repo)

    monkeypatch.setattr(
        dep.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="{bad json")
    )
    assert dep._gh_dep_pr_count(repo, 30) is None

    monkeypatch.setattr(dep.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="[]"))
    assert dep._gh_dep_pr_count(repo, 30) is None


def test_gh_dep_pr_count_handles_timeout_oserror_and_non_list_json(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(dep.shutil, "which", lambda name: "/usr/bin/gh")

    def raise_timeout(*_args, **_kwargs):
        raise dep.subprocess.TimeoutExpired("gh", 30)

    monkeypatch.setattr(dep.subprocess, "run", raise_timeout)
    assert dep._gh_dep_pr_count(repo, 30) is None

    def raise_os_error(*_args, **_kwargs):
        raise OSError("gh unavailable")

    monkeypatch.setattr(dep.subprocess, "run", raise_os_error)
    assert dep._gh_dep_pr_count(repo, 30) is None

    monkeypatch.setattr(dep.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="{}"))
    assert dep._gh_dep_pr_count(repo, 30) is None


def test_run_writes_activity_sidecar_with_git_and_gh_evidence(monkeypatch, tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()

    monkeypatch.setattr(dep, "_is_git_repo", lambda root: True)
    monkeypatch.setattr(dep, "_walk_manifests", lambda root: ["package.json", "src/App.csproj"])
    monkeypatch.setattr(
        dep,
        "_git_log",
        lambda root, days, paths: [
            {"sha": "1", "author": "renovate[bot]", "subject": "chore(deps): bump express"},
            {"sha": "2", "author": "Alice", "subject": "Improve docs"},
            {"sha": "3", "author": "Bob", "subject": "update flask to 3.0.0"},
            {"sha": "4", "author": "dependabot[bot]", "subject": "Bumps urllib3 from 1.2 to 1.3"},
            {"sha": "5", "author": "renovate-bot", "subject": "maintenance"},
        ],
    )
    monkeypatch.setattr(dep, "_gh_dep_pr_count", lambda root, days: 2)

    assert dep.run(repo, out, window_days=45, use_gh=True) == 0

    payload = _payload(out)
    assert payload["schema_version"] == 1
    assert payload["window_days"] == 45
    assert payload["total_manifest_commits"] == 5
    assert payload["dep_update_commits"] == 3
    assert payload["bot_authored_commits"] == 3
    assert payload["merged_dep_prs"] == 2
    assert payload["manifests_seen"] == ["package.json", "src/App.csproj"]
    assert payload["cadence"] == "active"
    assert "5 commit(s) touched dependency manifests" in payload["evidence"][0]
    assert "gh CLI reported 2 merged dep-update PR(s)" in payload["evidence"][1]
    assert [line for line in payload["evidence"] if line.startswith("  e.g. ")] == [
        "  e.g. chore(deps): bump express",
        "  e.g. update flask to 3.0.0",
        "  e.g. Bumps urllib3 from 1.2 to 1.3",
    ]
    assert "cadence=active" in capsys.readouterr().out


def test_run_writes_unknown_signal_without_git_history(monkeypatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()

    monkeypatch.setattr(dep, "_is_git_repo", lambda root: False)
    monkeypatch.setattr(dep, "_walk_manifests", lambda root: ["package.json"])

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("_git_log must not run outside a git repo")

    monkeypatch.setattr(dep, "_git_log", fail_if_called)

    assert dep.run(repo, out, window_days=90, use_gh=False) == 0

    payload = _payload(out)
    assert payload["cadence"] == "unknown"
    assert payload["total_manifest_commits"] == 0
    assert payload["dep_update_commits"] == 0
    assert payload["bot_authored_commits"] == 0
    assert payload["merged_dep_prs"] is None
    assert payload["evidence"] == ["Repository is not a git checkout — activity signal unavailable."]


def test_main_validates_paths_and_passes_no_gh(monkeypatch, tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()

    assert dep.main(["--repo-root", str(tmp_path / "missing"), "--output-dir", str(out)]) == 2
    assert "repo-root not a directory" in capsys.readouterr().err

    assert dep.main(["--repo-root", str(repo), "--output-dir", str(tmp_path / "missing")]) == 2
    assert "output-dir not a directory" in capsys.readouterr().err

    seen = {}

    def fake_run(repo_root, output_dir, window_days, use_gh):
        seen.update(
            {
                "repo_root": repo_root,
                "output_dir": output_dir,
                "window_days": window_days,
                "use_gh": use_gh,
            }
        )
        return 9

    monkeypatch.setattr(dep, "run", fake_run)

    assert dep.main(["--repo-root", str(repo), "--output-dir", str(out), "--window-days", "14", "--no-gh"]) == 9
    assert seen == {
        "repo_root": repo,
        "output_dir": out,
        "window_days": 14,
        "use_gh": False,
    }
