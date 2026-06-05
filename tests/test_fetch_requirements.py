"""Unit tests for scripts/fetch_requirements.py — the deterministic
fetch-or-abort gate for security requirements.

Exit-code contract:
  0  requirements available (.requirements.yaml written: remote / cache / stub)
  2  requested but UNAVAILABLE — caller aborts
  3  usage / tool error

`file://` URLs exercise both the success and failure branches without a network
(urllib handles http/https/file uniformly).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "fetch_requirements.py"


def _run(output_dir: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(output_dir), *extra],
        capture_output=True,
        text=True,
    )


def _reqs_file(tmp_path: Path) -> str:
    f = tmp_path / "reqs.yaml"
    f.write_text("categories:\n  - id: SEC-AUTH\n", encoding="utf-8")
    return f"file://{f}"


# ---------------------------------------------------------------------------
# disabled / skipped
# ---------------------------------------------------------------------------
def test_no_requirements_writes_skipped_stub(tmp_path):
    r = _run(tmp_path, "--no-requirements")
    assert r.returncode == 0
    data = json.loads((tmp_path / ".requirements.yaml").read_text())
    assert data["source"] == "skipped"


# ---------------------------------------------------------------------------
# fail_closed — explicit --requirements <url>
# ---------------------------------------------------------------------------
def test_cli_url_reachable_fetches_ok(tmp_path):
    r = _run(tmp_path, "--requirements", _reqs_file(tmp_path))
    assert r.returncode == 0
    assert "SEC-AUTH" in (tmp_path / ".requirements.yaml").read_text()


def test_cli_url_unreachable_aborts(tmp_path):
    """The user's scenario: --requirements <url> but the URL is unreachable
    -> fail_closed -> exit 2, no cache fallback."""
    missing = f"file://{tmp_path}/does-not-exist.yaml"
    r = _run(tmp_path, "--requirements", missing)
    assert r.returncode == 2
    assert "could not be loaded" in r.stderr
    assert "fail_mode=fail_closed" in r.stderr


def test_cli_url_unreachable_ignores_cache(tmp_path):
    """fail_closed must NOT fall back to a populated cache."""
    cache = tmp_path / "cache.yaml"
    cache.write_text("categories: [stale]\n", encoding="utf-8")
    missing = f"file://{tmp_path}/missing.yaml"
    r = _run(tmp_path, "--requirements", missing, "--cache-path", str(cache))
    assert r.returncode == 2


# ---------------------------------------------------------------------------
# cache_fallback — org-profile source via .org-profile-effective.json
# ---------------------------------------------------------------------------
def _write_org_profile(tmp_path: Path, url: str, cache: bool = True) -> None:
    (tmp_path / ".org-profile-effective.json").write_text(
        json.dumps(
            {"requirements_source": {"requirements_yaml_url": url, "cache": cache,
                                     "fail_mode": "cache_fallback"}}
        ),
        encoding="utf-8",
    )


def test_cache_fallback_uses_cache_when_remote_fails(tmp_path):
    _write_org_profile(tmp_path, f"file://{tmp_path}/missing.yaml")
    cache = tmp_path / "cache.yaml"
    cache.write_text("categories:\n  - id: CACHED\n", encoding="utf-8")
    r = _run(tmp_path, "--cache-path", str(cache))
    assert r.returncode == 0
    assert "CACHED" in (tmp_path / ".requirements.yaml").read_text()


def test_cache_fallback_aborts_when_remote_and_cache_both_gone(tmp_path):
    _write_org_profile(tmp_path, f"file://{tmp_path}/missing.yaml")
    r = _run(tmp_path, "--cache-path", str(tmp_path / "no-cache.yaml"))
    assert r.returncode == 2
    assert "could not be loaded" in r.stderr


# ---------------------------------------------------------------------------
# --require — caller (skill) asserts requirements ARE requested
# ---------------------------------------------------------------------------
def test_require_with_reachable_config_url_ok(tmp_path):
    _write_org_profile(tmp_path, _reqs_file(tmp_path))
    r = _run(tmp_path, "--require", "--cache-path", str(tmp_path / "c.yaml"))
    assert r.returncode == 0
    assert "SEC-AUTH" in (tmp_path / ".requirements.yaml").read_text()


def test_require_with_unreachable_url_and_no_cache_aborts(tmp_path):
    """Skill resolved CHECK_REQUIREMENTS=true (no explicit URL) but the configured
    source is unreachable and there is no cache -> exit 2."""
    _write_org_profile(tmp_path, f"file://{tmp_path}/missing.yaml")
    r = _run(tmp_path, "--require", "--cache-path", str(tmp_path / "no-cache.yaml"))
    assert r.returncode == 2


# ---------------------------------------------------------------------------
# tool error
# ---------------------------------------------------------------------------
def test_missing_output_dir_errors(tmp_path):
    r = _run(tmp_path / "does-not-exist")
    assert r.returncode == 3
