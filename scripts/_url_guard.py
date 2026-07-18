"""URL-target validation for SSRF defence.

Used by any plugin component that fetches remote resources from
attacker-influenced configuration (today: ``load_related_repos.py``).

Rejects loopback, RFC1918 private ranges, link-local (incl. the
169.254.169.254 cloud-metadata endpoint), multicast, reserved, and
broadcast addresses. Optional host allowlist from the
``APPSEC_URL_ALLOWLIST`` env var (comma-separated hostnames) and/or an
org profile's ``policy.url_allowlist`` — when either is set, any host
not listed is rejected even if the IP would pass.

Resolves the host via ``socket.getaddrinfo`` once before the request
so a DNS rebind cannot flip the IP between validation and connect.
The caller is expected to pin connections to the resolved IP if the
attack model requires defeating rebind — for the threat model this
module targets (mis-authored ``related-repos.yaml`` in an untrusted
repo), single-resolution is sufficient.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import urllib.parse
from typing import Iterable, NamedTuple

_ALLOWED_SCHEMES = ("http", "https")


class ValidationResult(NamedTuple):
    ok: bool
    reason: str
    resolved_ip: str | None


def _resolved_addresses(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    out: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        for fam, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
            if fam == socket.AF_INET:
                out.append(ipaddress.IPv4Address(sockaddr[0]))
            elif fam == socket.AF_INET6:
                addr_str = sockaddr[0].split("%", 1)[0]
                out.append(ipaddress.IPv6Address(addr_str))
    except (socket.gaierror, ValueError, OSError):
        return []
    return out


def _is_dangerous(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private (RFC1918 / ULA)"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    if isinstance(ip, ipaddress.IPv4Address) and str(ip) == "255.255.255.255":
        return "broadcast"
    return None


def _allowlist_from_env() -> list[str] | None:
    raw = os.environ.get("APPSEC_URL_ALLOWLIST", "").strip()
    if not raw:
        return None
    return [h.strip().lower() for h in raw.split(",") if h.strip()]


def _allowlist_from_profile() -> list[str] | None:
    """Read ``policy.url_allowlist`` from the active org profile, if any.

    Best-effort: the allowlist rides in ``.org-profile-effective.json`` under
    ``defaults.url_allowlist`` (written by resolve_config). Any IO/parse error
    returns None so a missing profile simply means "no profile allowlist".
    """
    candidates = []
    output_dir = os.environ.get("OUTPUT_DIR")
    if output_dir:
        candidates.append(os.path.join(output_dir, ".org-profile-effective.json"))
    candidates.append(os.path.join(os.getcwd(), "docs", "security", ".org-profile-effective.json"))
    for path in candidates:
        try:
            with open(path) as fh:
                eff = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        hosts = (eff.get("defaults") or {}).get("url_allowlist")
        if isinstance(hosts, list) and hosts:
            return [str(h).strip().lower() for h in hosts if str(h).strip()]
    return None


def _active_allowlist() -> list[str] | None:
    """Union of the env allowlist and the org-profile allowlist (either may be
    None). A non-None result means the host must be on the list."""
    env = _allowlist_from_env()
    prof = _allowlist_from_profile()
    if env is None and prof is None:
        return None
    return sorted(set((env or []) + (prof or [])))


def _host_allowed(host: str, allowlist: Iterable[str] | None) -> bool:
    if allowlist is None:
        return True
    host_l = host.lower()
    for allowed in allowlist:
        if host_l == allowed or host_l.endswith("." + allowed):
            return True
    return False


def validate_target_url(url: str, *, strict: bool = False, check_ip_safety: bool = True) -> ValidationResult:
    """Return (ok, reason, resolved_ip).

    ``strict=True`` requires an allowlist (env or org profile) to be set; an
    absent allowlist is treated as a rejection. Without ``strict``, an absent
    allowlist allows any host through (subject to ``check_ip_safety``).

    ``check_ip_safety=True`` (default) additionally rejects hosts that resolve
    to loopback / RFC1918 / link-local / metadata addresses — the right posture
    for *untrusted* config (e.g. related-repos.yaml). Pass ``check_ip_safety=
    False`` for an org-/developer-supplied URL (e.g. the requirements catalog),
    which may legitimately be an internal host: the allowlist still applies, but
    a private IP is not itself a rejection.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        return ValidationResult(False, f"unparseable url: {exc}", None)

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return ValidationResult(False, f"scheme '{scheme}' not allowed", None)

    host = parsed.hostname or ""
    if not host:
        return ValidationResult(False, "missing host", None)

    allowlist = _active_allowlist()
    if strict and allowlist is None:
        return ValidationResult(
            False,
            "strict mode: APPSEC_URL_ALLOWLIST is unset",
            None,
        )
    if not _host_allowed(host, allowlist):
        return ValidationResult(
            False,
            f"host '{host}' not in APPSEC_URL_ALLOWLIST",
            None,
        )

    if not check_ip_safety:
        # Allowlist satisfied; the caller trusts the target host (may be
        # internal). Skip DNS + private-range rejection.
        return ValidationResult(True, "ok", None)

    if re.match(r"^[\d.]+$|^\[?[0-9a-fA-F:]+\]?$", host):
        try:
            literal_ip = ipaddress.ip_address(host.strip("[]"))
            addresses = [literal_ip]
        except ValueError:
            addresses = _resolved_addresses(host)
    else:
        addresses = _resolved_addresses(host)

    if not addresses:
        return ValidationResult(False, f"host '{host}' did not resolve", None)

    for ip in addresses:
        danger = _is_dangerous(ip)
        if danger is not None:
            return ValidationResult(
                False,
                f"host '{host}' resolves to {ip} ({danger})",
                str(ip),
            )

    return ValidationResult(True, "ok", str(addresses[0]))


def same_host(url_a: str, url_b: str) -> bool:
    """True when both URLs target the same scheme + hostname + port."""
    try:
        a = urllib.parse.urlsplit(url_a)
        b = urllib.parse.urlsplit(url_b)
    except ValueError:
        return False
    return (
        a.scheme.lower() == b.scheme.lower()
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and a.port == b.port
    )
