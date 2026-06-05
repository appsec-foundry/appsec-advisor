"""Unit tests for scripts/fetch_requirements.py — the deterministic
fetch-or-abort gate for security requirements.

Exit-code contract:
  0  requirements available (.requirements.yaml written: remote / cache / stub)
  2  requested but UNAVAILABLE — caller aborts
  3  usage / tool error

A source is fetched remotely only when it is an ``http(s)://`` URL; anything
else is read as a local file path. Local files exercise the success/failure
branches without a network; an ``http://`` URL to a refused port exercises the
remote branch.
"""

from __future__ import annotations

import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
from contextlib import contextmanager
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
    return str(f)  # bare local path — no scheme


@contextmanager
def _http_server(body: bytes):
    """Serve ``body`` over http on an ephemeral localhost port; yield the URL."""
    class _H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "application/yaml")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # silence per-request logging
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}/reqs.yaml"
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# disabled / skipped
# ---------------------------------------------------------------------------
def test_no_requirements_writes_skipped_stub(tmp_path):
    r = _run(tmp_path, "--no-requirements")
    assert r.returncode == 0
    data = json.loads((tmp_path / ".requirements.yaml").read_text())
    assert data["source"] == "skipped"


# ---------------------------------------------------------------------------
# fail_closed — explicit --requirements <src>
# ---------------------------------------------------------------------------
def test_cli_local_path_reads_ok(tmp_path):
    r = _run(tmp_path, "--requirements", _reqs_file(tmp_path))
    assert r.returncode == 0
    assert "SEC-AUTH" in (tmp_path / ".requirements.yaml").read_text()


def test_cli_relative_local_path_reads_ok(tmp_path):
    """A relative bare path resolves against the current working directory."""
    f = tmp_path / "reqs.yaml"
    f.write_text("categories:\n  - id: SEC-REL\n", encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(tmp_path),
         "--requirements", "reqs.yaml"],
        cwd=str(tmp_path), capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "SEC-REL" in (tmp_path / ".requirements.yaml").read_text()


def test_cli_local_path_missing_aborts(tmp_path):
    """--requirements <local file> that does not exist -> fail_closed -> exit 2."""
    missing = str(tmp_path / "does-not-exist.yaml")
    r = _run(tmp_path, "--requirements", missing)
    assert r.returncode == 2
    assert "could not be loaded" in r.stderr
    assert "fail_mode=fail_closed" in r.stderr


def test_cli_remote_url_reachable_fetches_ok(tmp_path):
    """--requirements <http URL> that responds -> fetched + cached, exit 0."""
    cache = tmp_path / "cache.yaml"
    with _http_server(b"categories:\n  - id: SEC-REMOTE\n") as url:
        r = _run(tmp_path, "--requirements", url, "--cache-path", str(cache))
    assert r.returncode == 0
    assert "SEC-REMOTE" in (tmp_path / ".requirements.yaml").read_text()
    # fail_closed (explicit --requirements) must NOT refresh the plugin cache.
    assert not cache.exists()


def test_cli_remote_url_unreachable_aborts(tmp_path):
    """--requirements <http(s) URL> that is unreachable -> fail_closed -> exit 2."""
    r = _run(tmp_path, "--requirements", "http://127.0.0.1:1/reqs.yaml", "--timeout", "2")
    assert r.returncode == 2
    assert "fail_mode=fail_closed" in r.stderr


def test_cli_empty_local_file_aborts(tmp_path):
    """An empty source loads but has no content -> exit 2 (no silent pass)."""
    f = tmp_path / "empty.yaml"
    f.write_text("", encoding="utf-8")
    r = _run(tmp_path, "--requirements", str(f))
    assert r.returncode == 2


def test_cli_tilde_local_path_reads_ok(tmp_path):
    """A ``~``-prefixed path expands against HOME and is read as a local file."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "reqs.yaml").write_text("categories:\n  - id: SEC-TILDE\n", encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(tmp_path),
         "--requirements", "~/reqs.yaml"],
        env={**os.environ, "HOME": str(home)}, capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "SEC-TILDE" in (tmp_path / ".requirements.yaml").read_text()


def test_cli_missing_source_ignores_cache(tmp_path):
    """fail_closed must NOT fall back to a populated cache."""
    cache = tmp_path / "cache.yaml"
    cache.write_text("categories: [stale]\n", encoding="utf-8")
    missing = str(tmp_path / "missing.yaml")
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


def test_cache_fallback_uses_cache_when_source_fails(tmp_path):
    _write_org_profile(tmp_path, str(tmp_path / "missing.yaml"))
    cache = tmp_path / "cache.yaml"
    cache.write_text("categories:\n  - id: CACHED\n", encoding="utf-8")
    r = _run(tmp_path, "--cache-path", str(cache))
    assert r.returncode == 0
    assert "CACHED" in (tmp_path / ".requirements.yaml").read_text()


def test_cache_fallback_aborts_when_source_and_cache_both_gone(tmp_path):
    _write_org_profile(tmp_path, str(tmp_path / "missing.yaml"))
    r = _run(tmp_path, "--cache-path", str(tmp_path / "no-cache.yaml"))
    assert r.returncode == 2
    assert "could not be loaded" in r.stderr


# ---------------------------------------------------------------------------
# --require — caller (skill) asserts requirements ARE requested
# ---------------------------------------------------------------------------
def test_require_with_reachable_config_source_ok(tmp_path):
    _write_org_profile(tmp_path, _reqs_file(tmp_path))
    r = _run(tmp_path, "--require", "--cache-path", str(tmp_path / "c.yaml"))
    assert r.returncode == 0
    assert "SEC-AUTH" in (tmp_path / ".requirements.yaml").read_text()


def test_require_with_unreachable_source_and_no_cache_aborts(tmp_path):
    """Skill resolved CHECK_REQUIREMENTS=true (no explicit source) but the
    configured source is unreachable and there is no cache -> exit 2."""
    _write_org_profile(tmp_path, str(tmp_path / "missing.yaml"))
    r = _run(tmp_path, "--require", "--cache-path", str(tmp_path / "no-cache.yaml"))
    assert r.returncode == 2


# ---------------------------------------------------------------------------
# tool error
# ---------------------------------------------------------------------------
def test_missing_output_dir_errors(tmp_path):
    r = _run(tmp_path / "does-not-exist")
    assert r.returncode == 3
