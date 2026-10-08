"""Admit local source roots and capture a bounded, repository-qualified view.

This module never invokes a model or writes to a selected repository. A caller
owns the returned scope and must not reconstruct authority from a model reply
or from an on-disk manifest. Captured content is kept in memory; public metadata
does not contain workstation paths. This is an internal building block, not a
multi-repository assessment entry point.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from collections import Counter
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from jsonschema import Draft202012Validator
from validators.secret_scan import mask_text

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "multi-repo-scope.schema.json"
MAX_REPOSITORIES = 16
MAX_FILES = 20_000
MAX_FILE_BYTES = 1_048_576
MAX_TOTAL_BYTES = 67_108_864
MAX_GIT_BYTES = 4_194_304
GIT_TIMEOUT = 30
SENSITIVE_NAMES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*")


class ScopeError(ValueError):
    """Admission or source validation failed; no partial scope is usable."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_digest(value: object) -> str:
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _git(root: Path, *args: str) -> bytes:
    """Read Git metadata without hooks, external filters, or unbounded output."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    command = [
        "git",
        "--no-pager",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "core.quotePath=false",
        "-C",
        str(root),
        *args,
    ]
    try:
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, start_new_session=True
        )
    except OSError:
        raise ScopeError("Git metadata cannot be read") from None
    chunks = bytearray()
    deadline = time.monotonic() + GIT_TIMEOUT
    try:
        assert proc.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise ScopeError("Git metadata read exceeded its time limit")
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        break
                    chunks.extend(chunk)
                    if len(chunks) > MAX_GIT_BYTES:
                        raise ScopeError("Git metadata exceeds the admission limit")
        if proc.wait(timeout=max(0.01, deadline - time.monotonic())):
            raise ScopeError("Git metadata validation failed")
        return bytes(chunks)
    except subprocess.TimeoutExpired:
        raise ScopeError("Git metadata read exceeded its time limit") from None
    finally:
        # Also terminate descendants if the direct child has already exited.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        if proc.stdout:
            proc.stdout.close()


def _relative(value: str) -> tuple[str, ...]:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
        or "\\" in value
        or ":" in value
        or value.startswith("/")
        or any(p in ("", ".", "..", ".git") for p in value.split("/"))
    ):
        raise ScopeError("Invalid repository-relative source path")
    return tuple(PurePosixPath(value).parts)


def _read(root: Path, relative: str) -> bytes:
    """Open every path segment relative to pinned descriptors without links."""
    parts = _relative(relative)
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for segment in parts[:-1]:
            descriptors.append(os.open(segment, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1]))
            # Git files and directories both mark a nested worktree.
            try:
                os.stat(".git", dir_fd=descriptors[-1], follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ScopeError("Nested repositories are not admitted")
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptors[-1])
        descriptors.append(fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ScopeError("Source is not a regular file")
        if before.st_size > MAX_FILE_BYTES:
            raise ScopeError("Source file exceeds the admission limit")
        result = bytearray()
        while chunk := os.read(fd, min(65_536, MAX_FILE_BYTES + 1 - len(result))):
            result.extend(chunk)
            if len(result) > MAX_FILE_BYTES:
                raise ScopeError("Source file exceeds the admission limit")
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ScopeError("Source changed during capture")
        return bytes(result)
    except OSError:
        raise ScopeError("Source cannot be read without following links") from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


@dataclass(frozen=True)
class RepositoryView:
    repository_id: str
    root: Path
    head: str
    state_sha256: str
    files: Mapping[str, bytes] = field(repr=False)
    exclusions: tuple[dict[str, str], ...] = ()
    dirty: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "files", MappingProxyType(dict(self.files)))

    def inventory(self) -> dict:
        return {
            "repository_id": self.repository_id,
            "label": self.root.name,
            "head": self.head,
            "state_sha256": self.state_sha256,
            "dirty": self.dirty,
            "files": [
                {"path": path, "sha256": _digest(data), "bytes": len(data)} for path, data in sorted(self.files.items())
            ],
            "exclusions": list(self.exclusions),
        }


def _capture(root: Path, repository_id: str, remaining: int) -> RepositoryView:
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    dirty = bool(_git(root, "status", "--porcelain=v1", "-z", "--untracked-files=normal"))
    raw_paths = _git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    try:
        paths = sorted(set(p.decode("utf-8") for p in raw_paths.split(b"\0") if p))
    except UnicodeError:
        raise ScopeError("Source paths must be valid UTF-8") from None
    if len(paths) > MAX_FILES:
        raise ScopeError("Source inventory exceeds the file limit")
    files: dict[str, bytes] = {}
    exclusions: list[dict[str, str]] = []
    for path in paths:
        parts = _relative(path)
        if any(fnmatch.fnmatchcase(parts[-1].lower(), pattern) for pattern in SENSITIVE_NAMES):
            exclusions.append({"path": path, "reason": "sensitive-name"})
            continue
        # A deletion is recorded, not confused with an empty captured file.
        if not os.path.lexists(root / path):
            exclusions.append({"path": path, "reason": "deleted"})
            continue
        data = _read(root, path)
        remaining -= len(data)
        if remaining < 0:
            raise ScopeError("Selected sources exceed the aggregate admission limit")
        try:
            data.decode("utf-8")
        except UnicodeError:
            exclusions.append({"path": path, "reason": "binary"})
            continue
        if b"\0" in data:
            exclusions.append({"path": path, "reason": "binary"})
            continue
        files[path] = data
    state = {
        "head": head,
        "dirty": dirty,
        "files": {p: _digest(b) for p, b in sorted(files.items())},
        "exclusions": exclusions,
    }
    return RepositoryView(repository_id, root, head, _json_digest(state), files, tuple(exclusions), dirty)


@dataclass(frozen=True)
class AssessmentScope:
    repositories: tuple[RepositoryView, ...]
    output: Path

    def inventory(self) -> dict:
        rows = [r.inventory() for r in sorted(self.repositories, key=lambda row: row.repository_id)]
        counts = Counter(row["label"] for row in rows)
        for row in rows:
            if counts[row["label"]] > 1:
                row["label"] = row["label"][:240] + " [" + row["repository_id"][-8:] + "]"
        result = {"schema_version": 1, "scope_sha256": _json_digest(rows), "repositories": rows}
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema).iter_errors(result))
        if errors:
            raise ScopeError("Captured source inventory failed schema validation")
        return result

    def read(self, repository_id: str, path: str, start: int = 1, end: int = 200) -> dict:
        """Return a bounded, redacted source slice from the admitted view only."""
        _relative(path)
        if type(start) is not int or type(end) is not int or start < 1 or end < start or end - start >= 400:
            raise ScopeError("Invalid source line range")
        repo = next((r for r in self.repositories if r.repository_id == repository_id), None)
        if repo is None or path not in repo.files:
            raise ScopeError("Source reference is outside admitted scope")
        data = repo.files[path]
        text, _ = mask_text(data.decode("utf-8"))
        lines = text.splitlines()
        if start > len(lines):
            raise ScopeError("Source line range does not exist")
        selected = lines[start - 1 : end]
        if sum(len(s.encode()) for s in selected) > 65_536:
            raise ScopeError("Source slice exceeds its byte limit")
        return {
            "repository_id": repository_id,
            "path": path,
            "start_line": start,
            "end_line": start + len(selected) - 1,
            "sha256": _digest(data),
            "lines": selected,
        }

    def verify_unchanged(self) -> None:
        """Recheck every selected root before accepting or publishing results."""
        current = admit([str(r.root) for r in self.repositories], str(self.output))
        if current.inventory() != self.inventory():
            raise ScopeError("Selected source state changed; a fresh assessment is required")

    @contextmanager
    def scanner_snapshot(self, repository_id: str):
        """Expose one frozen checkout to trusted, read-only Python scanners.

        The private temporary tree contains regular, non-executable files,
        not links to original sources. Never launch a model, build command or
        repository executable in it. It has no Git metadata and is destroyed
        on normal completion and exceptions.
        """
        repo = next((r for r in self.repositories if r.repository_id == repository_id), None)
        if repo is None:
            raise ScopeError("Scanner repository is outside admitted scope")
        with tempfile.TemporaryDirectory(prefix="appsec-source-") as directory:
            root = Path(directory)
            for relative, data in repo.files.items():
                parts = _relative(relative)
                target = root.joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as handle:
                    os.chmod(target, 0o600)
                    handle.write(data)
            yield root


def admit(selections: list[str], output: str) -> AssessmentScope:
    """Validate all roots before capture, with no filesystem mutation."""
    if not isinstance(selections, list) or not 2 <= len(selections) <= MAX_REPOSITORIES:
        raise ScopeError("Multi-repository scope requires 2 to 16 local checkouts")
    if not isinstance(output, str) or not output.strip() or any(ord(c) < 32 for c in output):
        raise ScopeError("Multi-repository scope requires an explicit output directory")
    roots: list[Path] = []
    for value in selections:
        if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
            raise ScopeError("Invalid repository selection")
        try:
            root = Path(value).resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            raise ScopeError("Selected repository does not exist") from None
        top = _git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
        if root != Path(top).resolve():
            raise ScopeError("Multi-repository selections must name top-level Git checkouts")
        if any(root == other or root in other.parents or other in root.parents for other in roots):
            raise ScopeError("Duplicate or overlapping repository selections")
        roots.append(root)
    try:
        target = Path(output).resolve()
    except (OSError, RuntimeError, ValueError):
        raise ScopeError("Invalid output directory") from None
    if any(target == root or root in target.parents or target in root.parents for root in roots):
        raise ScopeError("Output must be separate from all selected repositories")
    if target.exists() and not target.is_dir():
        raise ScopeError("Output is not a directory")
    remaining = MAX_TOTAL_BYTES
    views = []
    for root in sorted(roots):
        repository_id = "repo-" + _digest(os.fsencode(root))[:16]
        view = _capture(root, repository_id, remaining)
        remaining -= sum(len(data) for data in view.files.values())
        views.append(view)
    scope = AssessmentScope(tuple(views), target)
    scope.inventory()
    return scope
