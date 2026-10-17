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

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import urllib.parse
from collections.abc import Iterable, Mapping
from pathlib import Path

from shared.artifact_names import ArtifactSetError, artifact_stem, report_path

APP_DIRECTORY = "appsec-advisor"
ASSESSMENTS_DIRECTORY = "assessments"
NAME_LIMIT = 40
LEGACY_DIRECTORY = Path("docs") / "security"
GIT_TIMEOUT = 10
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


def remote_of(repo_root: Path) -> str | None:
    """The checkout's ``origin`` URL, read without hooks, system or global configuration."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    try:
        proc = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo_root), "remote", "get-url", "origin"],
            capture_output=True,
            env=env,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = proc.stdout[:4096].decode("utf-8", "replace").strip()
    return value if proc.returncode == 0 and value and "\n" not in value else None


def application_directory(repo_root: Path, base: Path | None = None) -> Path:
    """The external directory of the checkout at ``repo_root``."""
    return assessment_directory(application_name(repo_root, remote_of(repo_root)), base)


def locate(repo_root: Path, base: Path | None = None) -> tuple[Path, bool]:
    """``(directory, legacy)`` of the assessment a consumer reads for ``repo_root``.

    The external directory wins whenever it holds an assessment. A
    ``docs/security`` set in the same checkout is read only as the legacy
    fallback this release keeps for migration; otherwise the external
    directory is returned, assessment or not.
    """
    directory = application_directory(repo_root, base)
    if artifact_stem(directory) is not None:
        return directory, False
    legacy = Path(os.path.realpath(repo_root)) / LEGACY_DIRECTORY
    if artifact_stem(legacy) is not None:
        return legacy, True
    return directory, False


def locate_from(cwd: Path) -> Path | None:
    """The assessment directory of the checkout containing ``cwd``, or None when there is none.

    For hooks that run in a session without an explicit output directory. A
    failed resolution returns None rather than a directory inside the checkout,
    so no caller falls back to writing there.
    """
    for candidate in (cwd, *cwd.parents):
        if (candidate / ".git").exists():
            try:
                return locate(candidate)[0]
            except (LocationError, ArtifactSetError, OSError):
                return None
    return None


def default_report(cwd: Path) -> Path:
    """The report an export reads when no input is named: the assessment of the checkout containing ``cwd``.

    Outside a checkout, or when the directory holds both naming sets, the
    published report name under ``docs/security`` of ``cwd`` is returned; the
    caller reports it as missing.
    """
    located = locate_from(cwd)
    try:
        if located is not None:
            return report_path(located)
    except ArtifactSetError:
        pass
    return cwd / LEGACY_DIRECTORY / "security-assessment.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve the assessment directory of a checkout.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("destination", "Print where a new assessment of the checkout is written."),
        ("locate", "Print the directory whose assessment consumers read."),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--repo", type=Path, required=True)
        command.add_argument("--json", action="store_true")
        if name == "destination":
            command.add_argument("--create", action="store_true", help="Create it with mode 0700 at every level.")
    args = parser.parse_args(argv)
    if not args.repo.is_dir():
        print("Error: --repo is not a directory", file=sys.stderr)
        return 2
    try:
        if args.command == "destination":
            directory, legacy = application_directory(args.repo), False
            if args.create:
                private_directory(directory, data_base())
        else:
            directory, legacy = locate(args.repo)
    except (LocationError, ArtifactSetError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"directory": str(directory), "legacy": legacy}))
    else:
        print(directory)
    return 0


if __name__ == "__main__":
    sys.exit(main())
