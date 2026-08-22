"""Path/symlink defence helpers for repo-rooted file access.

Used by recon, preflight, and any consumer that must not read a file
through a symlink escaping the scanned repository.

The threat model is a malicious repo containing
``./policy.md -> /home/<user>/.ssh/id_rsa`` (or similar) that would
otherwise be opened by an unsuspecting reader and end up in the LLM
context or in ``.recon-summary.md``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, NamedTuple


class EscapingSymlink(NamedTuple):
    path: Path  # location inside the repo
    target: Path  # resolved target (outside repo_root)
    kind: str  # "file" | "directory" | "broken"


class RunPathError(ValueError):
    """The run path argument is unusable and must not be written to."""


def require_run_path(value: str | os.PathLike[str] | None, prog: str) -> Path:
    """Return ``value`` as a Path, or raise if it cannot name an output dir.

    An unset ``$OUTPUT_DIR`` reaches a script as an empty argument, and
    ``Path("")`` is ``PosixPath('.')`` — the *scanned repository's* root for
    anything running under an agent. Every writer that skipped this check
    created its artifact there instead: ``.agent-run.log``,
    ``.appsec-checkpoint``, ``.run-issues.json`` and ``.run-metrics.json`` were
    all reproduced in a foreign working directory this way. An ``is_dir()``
    test is not a substitute, because ``'.'`` is always a directory.

    A leading ``-`` means the arguments shifted and an option landed in this
    slot, which would write to a directory named after a flag.

    ``scripts/log_event.py`` carries the original inline form of this guard;
    this is the shared version for the writers that lacked one.
    """
    text = "" if value is None else str(value)
    if not text.strip():
        raise RunPathError(f"{prog}: <output_dir> is empty — is $OUTPUT_DIR set?")
    if text.startswith("-"):
        raise RunPathError(f"{prog}: <output_dir> looks like an option: {text!r}")
    return Path(text)


def run_path_arg(value: str) -> Path:
    """``argparse`` ``type=`` for a positional output directory.

    Guarding after argparse has already applied ``type=Path`` is too late:
    ``Path("")`` is ``PosixPath('.')``, so the empty argument is indistinguishable
    from an explicit ``.`` by then. As a ``type=`` callable this sees the raw
    string and can still tell them apart.
    """
    import argparse

    try:
        return require_run_path(value, "output_dir")
    except RunPathError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def is_within_repo(path: Path, repo_root: Path) -> bool:
    """True when ``path`` resolves to a location inside ``repo_root``.

    Uses ``Path.resolve()`` so symlink chains are followed before the
    containment check. Both arguments are resolved so the comparison is
    canonical even when callers pass relative or symlink-laden roots.
    """
    try:
        resolved = path.resolve(strict=False)
        root_resolved = repo_root.resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    try:
        resolved.relative_to(root_resolved)
        return True
    except ValueError:
        return False


def is_safe_to_read(path: Path, repo_root: Path) -> bool:
    """True when ``path`` is a regular file inside ``repo_root`` and any
    symlink in the resolution chain stays inside the repo.

    A symlink whose target stays inside the repo is treated as safe so
    legitimate intra-repo symlinks (e.g. monorepo workspaces) still
    work.
    """
    try:
        if not path.exists():
            return False
        if path.is_symlink():
            target = path.resolve(strict=False)
            if not is_within_repo(target, repo_root):
                return False
        return is_within_repo(path, repo_root)
    except (OSError, RuntimeError):
        return False


def iter_escaping_symlinks(
    repo_root: Path,
    *,
    excluded_dir_names: frozenset[str] | None = None,
) -> Iterator[EscapingSymlink]:
    """Yield every symlink under ``repo_root`` whose target escapes it.

    Walks with ``followlinks=False`` so we never descend into an
    escaping directory symlink (which would otherwise reach the entire
    filesystem). ``excluded_dir_names`` is matched on the basename and
    used to prune common heavyweight directories (``node_modules``,
    ``.git``, …).
    """
    excluded_dir_names = excluded_dir_names or frozenset({".git", "node_modules", ".venv", "venv", "__pycache__"})
    root_resolved = repo_root.resolve(strict=False)
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in excluded_dir_names]
        for name in list(dirnames):
            p = Path(dirpath) / name
            if p.is_symlink():
                target = p.resolve(strict=False)
                try:
                    target.relative_to(root_resolved)
                except ValueError:
                    yield EscapingSymlink(p, target, "directory")
                dirnames.remove(name)
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                try:
                    target = p.resolve(strict=False)
                except (OSError, RuntimeError):
                    yield EscapingSymlink(p, Path(os.readlink(p)), "broken")
                    continue
                try:
                    target.relative_to(root_resolved)
                except ValueError:
                    kind = "file"
                    if not target.exists():
                        kind = "broken"
                    yield EscapingSymlink(p, target, kind)
