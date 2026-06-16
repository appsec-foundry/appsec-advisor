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


# ---------------------------------------------------------------------------
# Resolver failure (lines 44-48) + did-not-resolve (line 131)
# ---------------------------------------------------------------------------


def test_resolver_gaierror_yields_no_addresses():
    import socket as _socket

    def _raise(*_a, **_kw):
        raise _socket.gaierror("name resolution failed")

    with mock.patch("socket.getaddrinfo", _raise):
        ok, reason, ip = guard.validate_target_url("http://nope.invalid/")
    assert not ok and "did not resolve" in reason and ip is None


def test_resolved_addresses_handles_ipv6(monkeypatch):
    # Drive the AF_INET6 branch (lines 44-46): a scoped IPv6 link-local addr
    # with a zone id that must be stripped before parsing.
    with mock.patch("socket.getaddrinfo", _fake_resolver(["fe80::1%eth0"])):
        addrs = guard._resolved_addresses("v6host.example")
    assert [str(a) for a in addrs] == ["fe80::1"]


def test_rejects_ipv6_link_local_via_resolution():
    with mock.patch("socket.getaddrinfo", _fake_resolver(["fe80::1"])):
        ok, reason, _ = guard.validate_target_url("http://v6.example/")
    assert not ok and "link-local" in reason


def test_resolved_addresses_returns_empty_on_oserror():
    def _raise(*_a, **_kw):
        raise OSError("boom")

    with mock.patch("socket.getaddrinfo", _raise):
        assert guard._resolved_addresses("anything.example") == []


# ---------------------------------------------------------------------------
# Each dangerous-IP branch (lines 60, 62, 64, 66)
# ---------------------------------------------------------------------------


def test_rejects_multicast_literal():
    ok, reason, _ = guard.validate_target_url("http://224.0.0.1/")
    assert not ok and "multicast" in reason


# Note: in CPython's ipaddress, 240.x / 0.0.0.0 / 255.255.255.255 all report
# is_private=True, so validate_target_url labels them "private" — the
# reserved/unspecified/broadcast branches of _is_dangerous are unreachable via
# real IPv4 literals. We pin that observable behaviour here, and exercise the
# remaining _is_dangerous branches by calling it directly with crafted objects.


def test_validate_labels_reserved_and_unspecified_as_private():
    # Pin current behaviour: is_private wins the ordering.
    ok1, r1, _ = guard.validate_target_url("http://240.0.0.1/")
    ok2, r2, _ = guard.validate_target_url("http://0.0.0.0/")
    ok3, r3, _ = guard.validate_target_url("http://255.255.255.255/")
    assert not ok1 and "private" in r1
    assert not ok2 and "private" in r2
    assert not ok3 and "private" in r3


class _FakeIP:
    """Minimal IP-shaped object to drive _is_dangerous past the early
    predicates and hit the reserved/unspecified branches."""

    def __init__(self, **flags):
        self.is_loopback = flags.get("loopback", False)
        self.is_link_local = flags.get("link_local", False)
        self.is_private = flags.get("private", False)
        self.is_multicast = flags.get("multicast", False)
        self.is_reserved = flags.get("reserved", False)
        self.is_unspecified = flags.get("unspecified", False)


def test_is_dangerous_reserved_branch():
    assert guard._is_dangerous(_FakeIP(reserved=True)) == "reserved"


def test_is_dangerous_unspecified_branch():
    assert guard._is_dangerous(_FakeIP(unspecified=True)) == "unspecified"


def test_is_dangerous_returns_none_for_safe_ip():
    assert guard._is_dangerous(_FakeIP()) is None


def test_is_dangerous_broadcast_branch():
    # The broadcast branch needs a real IPv4Address whose value is the
    # all-ones address but with the earlier predicates not firing; that is
    # impossible with a real object, so drive the isinstance+str path with the
    # genuine 255.255.255.255 address while monkeypatching is_private off.
    import ipaddress

    real = ipaddress.IPv4Address("255.255.255.255")

    class _Bcast(ipaddress.IPv4Address):
        is_private = False
        is_reserved = False

    bcast = _Bcast("255.255.255.255")
    assert str(bcast) == "255.255.255.255"
    assert guard._is_dangerous(bcast) == "broadcast"
    assert real.is_private  # pin: the real one is still "private"


# ---------------------------------------------------------------------------
# Parse + host edge cases (lines 96-97, 105, 125-126)
# ---------------------------------------------------------------------------


def test_unparseable_url_returns_reason():
    def _boom(_url):
        raise ValueError("bad url")

    with mock.patch("urllib.parse.urlsplit", _boom):
        ok, reason, ip = guard.validate_target_url("http://x/")
    assert not ok and "unparseable url" in reason and ip is None


def test_missing_host_rejected():
    ok, reason, _ = guard.validate_target_url("http:///path-only")
    assert not ok and "missing host" in reason


def test_ip_shaped_host_that_is_not_a_valid_ip_falls_back_to_resolution():
    # Host matches the numeric/colon regex but ip_address() raises ValueError,
    # forcing the _resolved_addresses fallback (lines 125-126).
    with mock.patch("socket.getaddrinfo", _fake_resolver(["8.8.8.8"])):
        ok, reason, ip = guard.validate_target_url("http://1.2.3.4.5/")
    assert ok and reason == "ok" and ip == "8.8.8.8"


# ---------------------------------------------------------------------------
# same_host parse failure (lines 150-151)
# ---------------------------------------------------------------------------


def test_same_host_false_on_unparseable():
    def _boom(_url):
        raise ValueError("bad")

    with mock.patch("urllib.parse.urlsplit", _boom):
        assert guard.same_host("http://a/", "http://a/") is False
