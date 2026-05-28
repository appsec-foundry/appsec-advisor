"""Tests for scripts/_url_guard.py — SSRF defence helpers."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import _url_guard as guard  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_allowlist(monkeypatch):
    monkeypatch.delenv("APPSEC_URL_ALLOWLIST", raising=False)
    yield


def _fake_resolver(addresses):
    """Patch socket.getaddrinfo to return the given IP literals."""

    def _stub(host, _port, *_a, **_kw):
        import socket as _socket

        out = []
        for a in addresses:
            if ":" in a:
                out.append((_socket.AF_INET6, None, None, "", (a, 0, 0, 0)))
            else:
                out.append((_socket.AF_INET, None, None, "", (a, 0)))
        return out

    return _stub


def test_rejects_non_http_scheme():
    ok, reason, _ = guard.validate_target_url("file:///etc/passwd")
    assert not ok and "scheme" in reason


def test_rejects_loopback_literal():
    ok, reason, ip = guard.validate_target_url("http://127.0.0.1/x")
    assert not ok and "loopback" in reason and ip == "127.0.0.1"


def test_rejects_link_local_metadata():
    ok, reason, _ = guard.validate_target_url("http://169.254.169.254/latest/meta-data/")
    assert not ok and "link-local" in reason


def test_rejects_rfc1918_literal():
    for url in ("http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/"):
        ok, reason, _ = guard.validate_target_url(url)
        assert not ok and "private" in reason


def test_rejects_when_dns_points_to_internal():
    with mock.patch("socket.getaddrinfo", _fake_resolver(["10.0.0.5"])):
        ok, reason, _ = guard.validate_target_url("http://intranet.example/")
    assert not ok and "private" in reason


def test_accepts_public_resolution():
    with mock.patch("socket.getaddrinfo", _fake_resolver(["8.8.8.8"])):
        ok, reason, ip = guard.validate_target_url("http://public.example/")
    assert ok and reason == "ok" and ip == "8.8.8.8"


def test_strict_requires_allowlist(monkeypatch):
    monkeypatch.delenv("APPSEC_URL_ALLOWLIST", raising=False)
    ok, reason, _ = guard.validate_target_url("http://public.example/", strict=True)
    assert not ok and "APPSEC_URL_ALLOWLIST" in reason


def test_allowlist_match_exact(monkeypatch):
    monkeypatch.setenv("APPSEC_URL_ALLOWLIST", "git.acme.com")
    with mock.patch("socket.getaddrinfo", _fake_resolver(["8.8.8.8"])):
        ok, _r, _ = guard.validate_target_url("http://git.acme.com/x", strict=True)
    assert ok


def test_allowlist_match_subdomain(monkeypatch):
    monkeypatch.setenv("APPSEC_URL_ALLOWLIST", "acme.com")
    with mock.patch("socket.getaddrinfo", _fake_resolver(["8.8.8.8"])):
        ok, _r, _ = guard.validate_target_url("http://docs.acme.com/", strict=True)
    assert ok


def test_allowlist_rejects_other_host(monkeypatch):
    monkeypatch.setenv("APPSEC_URL_ALLOWLIST", "acme.com")
    ok, reason, _ = guard.validate_target_url("http://evil.com/")
    assert not ok and "APPSEC_URL_ALLOWLIST" in reason


def test_same_host_compares_scheme_host_port():
    assert guard.same_host("https://a.com/x", "https://a.com/y")
    assert not guard.same_host("https://a.com", "http://a.com")
    assert not guard.same_host("https://a.com", "https://b.com")
    assert not guard.same_host("https://a.com:443", "https://a.com:8443")
