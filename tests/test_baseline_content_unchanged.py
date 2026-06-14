"""Functional tests for the content-equality incremental pre-check.

Regression coverage for the "dirty-but-unchanged manifest re-scans forever"
bug: ``baseline_state.py check-changes`` must treat a file that git lists as
changed (working tree dirty vs HEAD) but whose bytes are identical to what the
last threat model analysed as *unchanged* — incremental means "changed since
the last threat model", not "dirty vs the last commit".

These exercise the real Python (no LLM) end-to-end against a throwaway git
repo, including ``cmd_update`` (which records the content hashes) and
``cmd_check_changes`` (which consumes them).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).parent.parent / "scripts"
_spec = importlib.util.spec_from_file_location("baseline_state", SCRIPTS / "baseline_state.py")
baseline_state = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(baseline_state)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _head(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def _make_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"express": "^4.0.0"}}, indent=2),
        encoding="utf-8",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    out = repo / "docs" / "security"
    out.mkdir(parents=True)
    return repo, out


def _write_baseline_yaml(out: Path, sha: str) -> None:
    (out / "threat-model.yaml").write_text(
        f"meta:\n  git:\n    commit_sha: {sha}\n", encoding="utf-8",
    )


def _update(repo: Path, out: Path) -> None:
    baseline_state.cmd_update(
        argparse.Namespace(output_dir=str(out), repo_root=str(repo), mode="full")
    )


def _check_changes(repo: Path, out: Path):
    """Return (exit_code, payload_dict). Captures stdout JSON."""
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = baseline_state.cmd_check_changes(
            argparse.Namespace(output_dir=str(out), repo_root=str(repo), base_ref=None)
        )
    return rc, json.loads(buf.getvalue())


def test_dirty_but_unchanged_manifest_is_noop(tmp_path):
    """package.json dirty-vs-HEAD at baseline time, unchanged since → no re-scan."""
    repo, out = _make_repo(tmp_path)
    # The manifest is dirty (uncommitted edit) when the baseline is written.
    (repo / "package.json").write_text(
        json.dumps(
            {"name": "app", "dependencies": {"express": "^4.0.0", "lodash": "^4.17.0"}},
            indent=2,
        ),
        encoding="utf-8",
    )
    _write_baseline_yaml(out, _head(repo))
    _update(repo, out)  # records recon fingerprint + working_tree_snapshot of the dirty file

    # Second invocation, nothing touched: the file is still dirty-vs-HEAD but
    # byte-identical to what was analysed -> must NOT be a security-relevant change.
    rc, payload = _check_changes(repo, out)
    assert rc in (0, 2), payload  # 0 = unchanged, 2 = noise-only — both fast-abort
    assert payload["security_relevant_change_count"] == 0
    assert "package.json" in payload["content_unchanged_dropped_sample"]


def test_genuinely_changed_manifest_still_triggers(tmp_path):
    """A real dependency change after the baseline must still trigger exit 1."""
    repo, out = _make_repo(tmp_path)
    (repo / "package.json").write_text(
        json.dumps(
            {"name": "app", "dependencies": {"express": "^4.0.0", "lodash": "^4.17.0"}},
            indent=2,
        ),
        encoding="utf-8",
    )
    _write_baseline_yaml(out, _head(repo))
    _update(repo, out)

    # Now actually change the manifest content.
    (repo / "package.json").write_text(
        json.dumps(
            {"name": "app", "dependencies": {"express": "^4.0.0", "axios": "^1.0.0"}},
            indent=2,
        ),
        encoding="utf-8",
    )
    rc, payload = _check_changes(repo, out)
    assert rc == 1, payload
    assert payload["security_relevant_change_count"] >= 1
    assert "package.json" not in payload.get("content_unchanged_dropped_sample", [])


def test_working_tree_snapshot_recorded_by_update(tmp_path):
    """cmd_update persists content hashes of dirty-vs-HEAD files."""
    repo, out = _make_repo(tmp_path)
    (repo / "src.txt").write_text("hello", encoding="utf-8")  # untracked, non-manifest
    _git(repo, "add", "src.txt")  # staged -> dirty vs HEAD
    _write_baseline_yaml(out, _head(repo))
    _update(repo, out)
    cache = json.loads((out / ".appsec-cache" / "baseline.json").read_text())
    snap = cache.get("working_tree_snapshot", {})
    assert "src.txt" in snap
    assert snap["src.txt"].startswith("sha256:")
