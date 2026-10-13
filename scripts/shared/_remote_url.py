"""A repository remote URL as it may appear in a published model.

A remote can embed credentials (``https://user:token@host/repo.git``); Git
stores them verbatim in ``.git/config``. Every producer that publishes a remote
URL passes it through ``public_remote_url`` first.
"""

from __future__ import annotations

import urllib.parse


def public_remote_url(url: str | None) -> str | None:
    """Return ``url`` without user information, or None when it is not a usable remote.

    SCP-style remotes (``git@host:path``) name the SSH user, not a secret, and
    are kept. Any ``scheme://user[:password]@host`` drops the user information.
    """
    if not isinstance(url, str) or not url.strip() or any(ord(c) < 32 for c in url):
        return None
    url = url.strip()
    if "://" not in url:
        return url
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        return None
    if "@" not in parts.netloc:
        return url
    host = parts.hostname
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
