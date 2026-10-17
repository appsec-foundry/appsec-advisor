"""Where an application's assessment lives outside its checkout (decision AS-1).

Every producer and consumer resolves the same directory through this module:
``<base>/<repo-name>-<hash8>``, where ``<base>`` is the platform data directory
plus ``appsec-advisor/assessments``. The hash comes from the normalized
``origin`` remote, or from the canonical repository root when there is no
usable remote, so clones and worktrees of one remote share one assessment.

Repository content never contributes to the path: the name is a sanitized
slug of the remote's last path segment or of the root's directory name, and
the remote itself is never returned or written. ``private_directory`` refuses a
destination that a symlink, another user, or broad permissions could redirect
or expose (``REQ-TRU-005``).
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import urllib.parse
from collections.abc import Iterable, Mapping
from pathlib import Path

APP_DIRECTORY = "appsec-advisor"
ASSESSMENTS_DIRECTORY = "assessments"
NAME_LIMIT = 40
_SCP_REMOTE = re.compile(r"^(?:[^@/\s]+@)?(?P<host>[^:/\s]+):(?P<path>.+)$")


class LocationError(ValueError):
    """The assessment destination cannot be resolved or used safely."""


def data_base(env: Mapping[str, str] | None = None, platform: str | None = None, home: Path | None = None) -> Path:
    """The per-user directory that holds every application's assessment."""
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path.home() if home is None else home
    if platform == "win32":
        local = env.get("LOCALAPPDATA", "")
        if not local or not Path(local).is_absolute():
            raise LocationError("LOCALAPPDATA is not set to an absolute path")
        root = Path(local)
    elif platform == "darwin":
        root = home / "Library" / "Application Support"
    else:
        xdg = env.get("XDG_DATA_HOME", "")
        # The XDG specification ignores a relative value.
        root = Path(xdg) if xdg and Path(xdg).is_absolute() else home / ".local" / "share"
    return root / APP_DIRECTORY / ASSESSMENTS_DIRECTORY


def normalize_remote(url: str | None) -> str | None:
    """``host/path`` for a network remote, or None when the remote cannot identify one.

    User information, scheme, port, letter case of the host, a trailing ``.git``
    and slashes are dropped, so SSH and HTTPS clones of one repository agree.
    """
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url or len(url) > 2048 or any(ord(c) < 32 or c == "\x7f" for c in url):
        return None
    if "://" in url:
        try:
            parts = urllib.parse.urlsplit(url)
            host = parts.hostname
        except ValueError:
            return None
        if parts.scheme.lower() == "file" or not host:
            return None
        path = urllib.parse.unquote(parts.path)
    else:
        match = _SCP_REMOTE.match(url)
        # A Windows drive path (C:\repo) is local, not an SCP remote.
        if not match or len(match.group("host")) == 1:
            return None
        host, path = match.group("host"), match.group("path")
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")].rstrip("/")
    segments = [s for s in path.split("/") if s]
    if not segments or any(s in (".", "..") for s in segments):
        return None
    return f"{host.lower()}/{'/'.join(segments)}"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:NAME_LIMIT].strip("-")
    return slug or "repository"


def application_name(repo_root: Path, remote_url: str | None) -> str:
    """``<repo-name>-<hash8>`` for one repository."""
    identity = normalize_remote(remote_url)
    if identity is None:
        root = Path(os.path.realpath(repo_root))
        return f"{_slug(root.name)}-{_hash8('path:' + str(root))}"
    return f"{_slug(identity.rsplit('/', 1)[-1])}-{_hash8('remote:' + identity)}"


def combined_application_name(names: Iterable[str]) -> str:
    """The identity of a combined assessment, independent of selection order."""
    members = sorted(set(names))
    if len(members) < 2 or any(not _valid_name(name) for name in members):
        raise LocationError("a combined assessment needs at least two distinct application names")
    return f"combined-{_hash8('combined:' + chr(10).join(members))}"


def _hash8(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:8]


def _valid_name(name: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,%d}[a-z0-9])?-[0-9a-f]{8}" % (NAME_LIMIT - 2), name))


def assessment_directory(name: str, base: Path | None = None) -> Path:
    """The application's directory under ``base``; the name must be one this module produced."""
    if not _valid_name(name):
        raise LocationError("invalid application name")
    return (data_base() if base is None else base) / name


def private_directory(directory: Path, base: Path) -> Path:
    """Create ``directory`` and the ``appsec-advisor`` levels under it with mode 0700.

    Refuses when ``directory`` is not below ``base`` or when any level from the
    ``appsec-advisor`` directory down is a symlink, not a directory, owned by
    another user, or open to group or others.
    """
    app_root = base.parent if base.name == ASSESSMENTS_DIRECTORY else base
    if app_root.name != APP_DIRECTORY:
        raise LocationError("the assessment base must end in appsec-advisor/assessments")
    try:
        relative = directory.relative_to(app_root)
    except ValueError as exc:
        raise LocationError("the destination lies outside the assessment base") from exc
    if ".." in relative.parts:
        raise LocationError("the destination lies outside the assessment base")
    app_root.parent.mkdir(parents=True, exist_ok=True)
    current = app_root
    for part in (None, *relative.parts):
        if part is not None:
            current = current / part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _check_private(current)
    return directory


def _check_private(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise LocationError(f"{path.name} in the assessment destination is not a plain directory")
    if hasattr(os, "getuid"):
        if info.st_uid != os.getuid():
            raise LocationError(f"{path.name} in the assessment destination belongs to another user")
        if info.st_mode & 0o077:
            raise LocationError(f"{path.name} in the assessment destination is accessible to other users")
