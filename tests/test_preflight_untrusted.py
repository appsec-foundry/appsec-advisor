"""Tests for scripts/preflight_untrusted.py."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "preflight_untrusted.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import preflight_untrusted as pre  # noqa: E402


def _run(repo_root: Path, *extra: str) -> tuple[int, str]:
    env = dict(os.environ)
    env.pop("APPSEC_URL_ALLOWLIST", None)
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo_root), "--format", "json", *extra],
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.returncode, proc.stdout


def test_clean_repo_passes(tmp_path):
    (tmp_path / "README.md").write_text("clean", encoding="utf-8")
    code, out = _run(tmp_path)
    assert code == 0
    report = json.loads(out)
    assert report["finding_count"] == 0


def test_repo_owned_claude_settings_flagged(tmp_path):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text("{}", encoding="utf-8")
    code, out = _run(tmp_path, "--strict")
    assert code == 2
    report = json.loads(out)
    kinds = {f["kind"] for f in report["findings"]}
    assert "repo-owned-hook" in kinds


def test_escaping_symlink_flagged(tmp_path):
    outside = tmp_path.parent / "x_leak.txt"
    outside.write_text("x", encoding="utf-8")
    try:
        os.symlink(outside, tmp_path / "leak.txt")
        code, out = _run(tmp_path, "--strict")
        assert code == 2
        report = json.loads(out)
        assert any(f["kind"] == "escaping-symlink" for f in report["findings"])
    finally:
        outside.unlink(missing_ok=True)


def test_related_repos_url_rejected_in_strict_mode(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "related-repos.yaml").write_text(
        "related:\n"
        "  - name: bad\n"
        "    threat_model: http://127.0.0.1/threat-model.yaml\n",
        encoding="utf-8",
    )
    code, out = _run(tmp_path, "--strict", "--strict-urls")
    assert code == 2
    report = json.loads(out)
    assert any(f["kind"] == "related-repos-url-rejected" for f in report["findings"])


def test_run_function_returns_structured_report(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    report = pre.run(tmp_path, strict=True, strict_urls=False)
    assert report["finding_count"] >= 1
    assert isinstance(report["findings"], list)
