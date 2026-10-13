"""Admit local source roots and capture a bounded, repository-qualified view.

This module never invokes a model or writes to a selected repository. A caller
owns the returned scope and must not reconstruct authority from a model reply
or from an on-disk manifest. Captured content is kept in memory; public metadata
does not contain workstation paths. This is an internal building block, not a
multi-repository assessment entry point.
"""

from __future__ import annotations

import codecs
import difflib
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

from analyzers.scan_excludes import assessment_artifacts_in_inventory, declared_repository_input
from jsonschema import Draft202012Validator
from validators.secret_scan import mask_text

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "multi-repo-scope.schema.json"
MAX_REPOSITORIES = 16
MAX_FILES = 20_000
MAX_FILE_BYTES = 1_048_576
MAX_TOTAL_BYTES = 67_108_864
MAX_GIT_BYTES = 4_194_304
GIT_TIMEOUT = 30
# MR-6: the one output location a sole repository may hold, as in a single scan.
CHECKOUT_OUTPUT = PurePosixPath("docs/security")
SENSITIVE_NAMES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*")


class ScopeError(ValueError):
    """Admission or source validation failed; no partial scope is usable."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_digest(value: object) -> str:
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _git(root: Path, *args: str, overrides: tuple[str, ...] = ()) -> bytes:
    """Read Git metadata without hooks, fsmonitor, or unbounded output.

    Commands that compare worktree content also need ``_filter_overrides``.
    """
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
        *(item for value in overrides for item in ("-c", value)),
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


def _filter_overrides(root: Path) -> tuple[str, ...]:
    """Disable every repository-configured content filter driver.

    ``.gitattributes`` selects drivers whose commands come from the selected
    repository's own config; Git runs them while comparing worktree content.
    An empty command disables a driver, and it must not be required then.
    """
    names = _git(root, "config", "--list", "--name-only", "-z").split(b"\0")
    drivers = set()
    for raw in names:
        name = raw.decode("utf-8", "replace")
        if name.startswith("filter.") and name.count(".") >= 2:
            driver = name[len("filter.") : name.rindex(".")]
            # A command-line override cannot name such a driver reliably.
            if "=" in driver or any(ord(c) < 32 for c in driver):
                raise ScopeError("Repository filter configuration cannot be neutralized")
            drivers.add(driver)
    return tuple(
        f"filter.{driver}.{key}={value}"
        for driver in sorted(drivers)
        for key, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false"))
    )


def _lines(text: str) -> list[str]:
    """Split like Git and grep: only LF ends a line; CR of CRLF is dropped."""
    rows = text.split("\n")
    if rows[-1] == "":
        rows.pop()
    return [row[:-1] if row.endswith("\r") else row for row in rows]


def _masked_lines(text: str) -> list[str]:
    """Redact the whole text, but keep each line at its source line number.

    A masked multi-line secret collapses into fewer lines. Its redacted text
    stays on the first line of that block and the rest become empty, so later
    evidence lines still match the raw file. Every returned line is masked
    output or empty.
    """
    raw = _lines(text)
    masked = _lines(mask_text(text)[0])
    if len(masked) == len(raw):
        return masked
    result: list[str] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, raw, masked, autojunk=False).get_opcodes():
        if tag == "equal":
            result.extend(masked[j1:j2])
            continue
        block, width = masked[j1:j2], i2 - i1
        if len(block) > width:
            block = block[: max(width - 1, 0)] + [" ".join(block[max(width - 1, 0) :])]
        if width:
            result.extend(block + [""] * (width - len(block)))
        elif block and result:
            result[-1] = " ".join([result[-1], *block])
    return result


def _masked_bytes(data: bytes) -> bytes:
    """Redact captured bytes for a scanner file without moving any line."""
    text = data.decode("utf-8")
    masked = mask_text(text)[0]
    if len(_lines(masked)) != len(_lines(text)):
        masked = "\n".join(_masked_lines(text)) + ("\n" if text.endswith("\n") else "")
    return masked.encode("utf-8")


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


class OversizedBinary(ScopeError):
    """An oversized file whose leading bytes are binary."""


def _binary_prefix(prefix: bytes) -> bool:
    """Apply the captured-file binary rule to a leading chunk."""
    if b"\0" in prefix:
        return True
    try:
        codecs.getincrementaldecoder("utf-8")().decode(prefix, final=False)
    except UnicodeError:
        return True
    return False


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
            # An oversized binary would be excluded after capture anyway; only
            # oversized text stops admission.
            if _binary_prefix(os.read(fd, 8192)):
                raise OversizedBinary("Oversized binary source is excluded")
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


def _omission(root: Path, parts: tuple[str, ...], mode: str | None) -> str | None:
    """Name why a listed path is not captured, without following or reading it.

    Git index modes mark tracked links and submodules; ``lstat`` marks a link
    or nested worktree that replaced a path or any of its parents.
    """
    if mode == "160000":
        return "submodule"
    if mode == "120000":
        return "symlink"
    current = root
    for segment in parts:
        current = current / segment
        try:
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                return "symlink"
            if stat.S_ISDIR(info.st_mode) and os.path.lexists(current / ".git"):
                return "nested-repository"
        except (FileNotFoundError, NotADirectoryError):
            return "deleted"
        except OSError:
            raise ScopeError("Source cannot be inspected without following links") from None
    return None


def _capture(root: Path, repository_id: str, remaining: int, output: PurePosixPath | None = None) -> RepositoryView:
    """Capture one checkout; ``output`` names its report directory, if inside it.

    The report directory is not source: only declared inputs kept there are
    captured, and files the run writes there leave the state unchanged.
    """
    head = _git(root, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    outside = (":(exclude,literal)" + output.as_posix(),) if output else ()
    dirty = bool(
        _git(
            root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=normal",
            "--ignore-submodules=all",
            "--",
            ".",
            *outside,
            overrides=_filter_overrides(root),
        )
    )
    # Index modes identify tracked links and submodules; untracked nested
    # repositories are listed once, as a directory with a trailing slash.
    modes: dict[str, str | None] = {}
    try:
        for row in _git(root, "ls-files", "--cached", "--stage", "-z").split(b"\0"):
            if row:
                meta, _, name = row.partition(b"\t")
                modes[name.decode("utf-8")] = meta.split(b" ", 1)[0].decode("ascii")
        for raw in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
            if raw:
                modes.setdefault(raw.decode("utf-8"), None)
    except UnicodeError:
        raise ScopeError("Source paths must be valid UTF-8") from None
    if output:
        modes = {
            listed: mode
            for listed, mode in modes.items()
            if output not in PurePosixPath(listed.rstrip("/")).parents
            or declared_repository_input(PurePosixPath(listed.rstrip("/")))
        }
    paths = sorted(modes)
    if len(paths) > MAX_FILES:
        raise ScopeError("Source inventory exceeds the file limit")
    omissions = {listed: _omission(root, _relative(listed.rstrip("/")), modes[listed]) for listed in paths}
    artifacts = assessment_artifacts_in_inventory(listed for listed in paths if omissions[listed] is None)
    files: dict[str, bytes] = {}
    exclusions: list[dict[str, str]] = []
    for listed in paths:
        path = listed[:-1] if listed.endswith("/") else listed
        parts = _relative(path)
        reason = omissions[listed]
        if listed.endswith("/") and reason not in ("nested-repository", "symlink"):
            raise ScopeError("Unexpected directory entry in the source inventory")
        if reason not in (None, "deleted"):
            exclusions.append({"path": path, "reason": reason})
            continue
        if any(fnmatch.fnmatchcase(parts[-1].lower(), pattern) for pattern in SENSITIVE_NAMES):
            exclusions.append({"path": path, "reason": "sensitive-name"})
            continue
        # A deletion is recorded, not confused with an empty captured file.
        if reason == "deleted":
            exclusions.append({"path": path, "reason": "deleted"})
            continue
        if path in artifacts:
            exclusions.append({"path": path, "reason": "assessment-artifact"})
            continue
        try:
            data = _read(root, path)
        except OversizedBinary:
            exclusions.append({"path": path, "reason": "binary"})
            continue
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
        result = {"schema_version": 2, "scope_sha256": _json_digest(rows), "repositories": rows}
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
        lines = _masked_lines(data.decode("utf-8"))
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

    def output_in_checkout(self) -> bool:
        """Whether the output is the report directory of the sole checkout (MR-6)."""
        return len(self.repositories) == 1 and self.output == self.repositories[0].root.joinpath(*CHECKOUT_OUTPUT.parts)

    def verify_unchanged(self) -> None:
        """Recheck every selected root before accepting or publishing results."""
        current = admit([str(r.root) for r in self.repositories], str(self.output), minimum=1)
        if current.inventory() != self.inventory():
            raise ScopeError("Selected source state changed; a fresh assessment is required")

    @contextmanager
    def scanner_snapshot(self, repository_id: str):
        """Expose one frozen checkout to trusted, read-only Python scanners.

        The private temporary tree contains regular, non-executable files,
        not links to original sources. Each file holds the same redacted text
        that ``read`` serves, at unchanged line numbers. Never launch a model, build command or
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
                    handle.write(_masked_bytes(data))
            yield root


def _identity(path: Path, *, missing_ok: bool = False) -> tuple[int, int] | None:
    """Return the (device, inode) pair that names a directory in any spelling."""
    try:
        info = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        if missing_ok:
            return None
        raise ScopeError("Selected path cannot be identified") from None
    except OSError:
        raise ScopeError("Selected path cannot be identified") from None
    return (info.st_dev, info.st_ino)


def _lineage(path: Path) -> set[tuple[int, int]]:
    """Identify a path and every existing ancestor directory."""
    return {i for i in (_identity(item, missing_ok=True) for item in (path, *path.parents)) if i is not None}


def _checkout_output(roots: list[Path], target: Path) -> PurePosixPath | None:
    """The report directory inside a sole checkout (MR-6), or None.

    Only `docs/security` of the one selected root qualifies. ``target`` is
    resolved, so a symbolic link never makes another directory match.
    """
    if len(roots) == 1 and target == roots[0].joinpath(*CHECKOUT_OUTPUT.parts):
        return CHECKOUT_OUTPUT
    return None


def admit(selections: list[str], output: str, *, minimum: int = 2) -> AssessmentScope:
    """Validate all roots before capture, with no filesystem mutation."""
    if not isinstance(selections, list) or not minimum <= len(selections) <= MAX_REPOSITORIES:
        raise ScopeError(f"Multi-repository scope requires {minimum} to {MAX_REPOSITORIES} local checkouts")
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
    # Lexical checks miss bind mounts and case-insensitive or other aliases;
    # equal device and inode numbers name the same directory in any spelling.
    identities = {root: _identity(root) for root in roots}
    lineages = {root: _lineage(root) for root in roots}
    for root in roots:
        if any(other != root and identities[other] in lineages[root] for other in roots):
            raise ScopeError("Duplicate or overlapping repository selections")
    try:
        target = Path(output).resolve()
    except (OSError, RuntimeError, ValueError):
        raise ScopeError("Invalid output directory") from None
    inside = _checkout_output(roots, target)
    if inside is None:
        if any(target == root or root in target.parents or target in root.parents for root in roots):
            raise ScopeError("Output must be separate from all selected repositories")
        output_lineage = _lineage(target)
        output_identity = _identity(target, missing_ok=True)
        if any(
            identities[root] in output_lineage or (output_identity is not None and output_identity in lineages[root])
            for root in roots
        ):
            raise ScopeError("Output must be separate from all selected repositories")
    if target.exists() and not target.is_dir():
        raise ScopeError("Output is not a directory")
    remaining = MAX_TOTAL_BYTES
    views = []
    for root in sorted(roots):
        repository_id = "repo-" + _digest(os.fsencode(root))[:16]
        view = _capture(root, repository_id, remaining, inside)
        remaining -= sum(len(data) for data in view.files.values())
        views.append(view)
    scope = AssessmentScope(tuple(views), target)
    scope.inventory()
    return scope
