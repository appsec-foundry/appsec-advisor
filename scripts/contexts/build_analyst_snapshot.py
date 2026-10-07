#!/usr/bin/env python3
"""contexts/build_analyst_snapshot.py — frozen source view of one analyst job.

Captures the baseline and proposed content of a change into the job root's
temporary ``source/`` directory and returns an ``analyst-snapshot`` document.
Every later read of the job, including surrounding-code context admitted on
request, comes from the same view.

Git is read without side effects of repository or user configuration:

* system and global configuration are ignored and every ``GIT_*`` variable
  is dropped; hooks, fsmonitor, external diff drivers, and textconv are off;
* blob content comes from ``git cat-file --batch``, which applies no filters;
* worktree files are hashed with ``hash-object --no-filters``, opened without
  following symlinks, and hashed again when admitted, so a file that changes
  during capture rejects the snapshot instead of mixing two states.

Ignored files are never admitted and appear only as a count. Symlinks,
submodules, nested repositories, special files, binaries, oversized files,
sensitive files, and files beyond the job limits are recorded as exclusions.
Worktree renames appear as a deletion plus an addition. Nothing here writes
outside the job root or runs repository code.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import fnmatch
import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from runtime.analyst_state import Job, utc_now
from validators.secret_scan import scan_text
from validators.validate_analyst import validate_snapshot

GIT_CONFIG = (
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "diff.external=",
    "-c",
    "core.quotePath=false",
)
GIT_TIMEOUT_SECONDS = 120
SENSITIVE_NAMES = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "*.keystore",
    "*.jks",
)
BINARY_PROBE_BYTES = 8192
MAX_EXCLUDED_ENTRIES = 1900
VIEW_FILE = ".view.json"
SUBMODULE_MODE = "160000"
SYMLINK_MODE = "120000"


class SnapshotError(Exception):
    """The requested source view cannot be captured consistently."""


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_OPTIONAL_LOCKS="0",
        GIT_LITERAL_PATHSPECS="1",
    )
    try:
        proc = subprocess.run(
            ["git", "--no-pager", *GIT_CONFIG, "-C", str(repo), *args],
            input=stdin,
            capture_output=True,
            env=env,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SnapshotError(f"git {args[0]} timed out") from None
    if proc.returncode != 0:
        raise SnapshotError(f"git {args[0]} failed with exit code {proc.returncode}")
    return proc.stdout


def _commit(repo: Path, rev: str) -> str:
    if rev.startswith("-"):
        raise SnapshotError("revision must not start with '-'")
    return _git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{rev}^{{commit}}").decode().strip()


def _tree(repo: Path, commit: str) -> dict[str, tuple[str, str]]:
    """Map path -> (mode, object id) for a commit."""
    entries = {}
    for record in _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if record:
            meta, path = record.split(b"\t", 1)
            mode, _kind, oid = meta.decode().split(" ")
            entries[path.decode("utf-8", "surrogateescape")] = (mode, oid)
    return entries


def _index(repo: Path) -> dict[str, tuple[str, str]]:
    entries = {}
    for record in _git(repo, "ls-files", "-s", "-z").split(b"\0"):
        if record:
            meta, path = record.split(b"\t", 1)
            mode, oid, _stage = meta.decode().split(" ")
            entries[path.decode("utf-8", "surrogateescape")] = (mode, oid)
    return entries


def _blobs(repo: Path, oids: list[str]) -> dict[str, bytes]:
    if not oids:
        return {}
    out = _git(repo, "cat-file", "--batch", stdin="".join(f"{oid}\n" for oid in oids).encode())
    blobs, pos = {}, 0
    for oid in oids:
        end = out.index(b"\n", pos)
        header = out[pos:end].decode().split(" ")
        if len(header) != 3 or header[1] != "blob":
            raise SnapshotError("object is not a blob")
        size = int(header[2])
        blobs[oid] = out[end + 1 : end + 1 + size]
        pos = end + 1 + size + 1
    return blobs


def _hash_blob(repo: Path, content: bytes) -> str:
    return _git(repo, "hash-object", "--no-filters", "--stdin", stdin=content).decode().strip()


def _read_worktree(repo: Path, path: str) -> bytes:
    fd = os.open(repo / path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SnapshotError("worktree entry is not a regular file")
        chunks = []
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _safe_path(path: str) -> bool:
    """A repository-relative path without escapes or control characters."""
    parts = set(path.split("/"))
    return (
        bool(path)
        and not path.startswith("/")
        and not {"..", ".", ""} & parts
        and not any(ch in path for ch in "\n\r\x00")
    )


@dataclass
class _Capture:
    repo: Path
    job: Job
    limits: dict
    admitted: list[dict] = field(default_factory=list)
    excluded: list[dict] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    total: int = 0

    def exclude(self, path: str | None, reason: str) -> None:
        if path is None or not _safe_path(path) or len(self.excluded) >= MAX_EXCLUDED_ENTRIES:
            self.counts[reason] = self.counts.get(reason, 0) + 1
        else:
            self.excluded.append({"path": path, "reason": reason, "count": 1})

    def reason_to_reject(self, path: str, content: bytes) -> str | None:
        if not _safe_path(path):
            return "special_file"
        name = PurePosixPath(path).name
        if any(fnmatch.fnmatch(name, pattern) for pattern in SENSITIVE_NAMES):
            return "sensitive"
        if len(content) > self.limits["file_kib"] * 1024:
            return "too_large"
        if b"\0" in content[:BINARY_PROBE_BYTES]:
            return "binary"
        if scan_text(content.decode("utf-8", "replace")):
            return "sensitive"
        return None

    def admit(self, path: str, side: str, change: str, content: bytes, previous: str | None = None) -> None:
        reason = self.reason_to_reject(path, content)
        if reason is None and (
            len(self.admitted) >= self.limits["admitted_files"]
            or self.total + len(content) > self.limits["job_kib"] * 1024
        ):
            reason = "limit_reached"
        if reason is not None:
            self.exclude(path, reason)
            return
        target = self.job.root / "source" / side / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        entry = {
            "path": path,
            "side": side,
            "change": change,
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }
        if previous is not None:
            entry["previous_path"] = previous
        self.admitted.append(entry)
        self.total += len(content)

    def excluded_entries(self) -> list[dict]:
        return self.excluded + [{"reason": r, "count": n} for r, n in sorted(self.counts.items())]


def _excluded_by_mode(capture: _Capture, path: str, mode: str) -> bool:
    if mode == SUBMODULE_MODE:
        capture.exclude(path, "submodule")
    elif mode == SYMLINK_MODE:
        capture.exclude(path, "symlink")
    else:
        return False
    return True


def _object_changes(repo: Path, args: list[str]) -> list[tuple[str, str, str | None]]:
    """Parse ``--name-status -z`` output into (status, path, previous path)."""
    fields = _git(repo, *args, "--name-status", "-z", "-M", "--no-ext-diff", "--no-textconv").split(b"\0")
    changes, i = [], 0
    while i < len(fields) and fields[i]:
        status = fields[i].decode()[0]
        if status in "RC":
            old, new = (f.decode("utf-8", "surrogateescape") for f in fields[i + 1 : i + 3])
            changes.append((status, new, old))
            i += 3
        else:
            changes.append((status, fields[i + 1].decode("utf-8", "surrogateescape"), None))
            i += 2
    return changes


def _capture_objects(capture: _Capture, baseline: dict, proposed: dict, changes) -> None:
    wanted = []
    for status, path, old in changes:
        if status in "MTRD":
            wanted.append(baseline[old or path])
        if status in "AMTRC":
            wanted.append(proposed[path])
    blobs = _blobs(capture.repo, [oid for mode, oid in wanted if mode not in (SUBMODULE_MODE, SYMLINK_MODE)])
    for status, path, old in sorted(changes, key=lambda c: c[1]):
        change = {"A": "added", "C": "added", "D": "deleted", "R": "renamed"}.get(status, "modified")
        previous = old if status == "R" else None
        if status in "MTRD":
            mode, oid = baseline[old or path]
            if not _excluded_by_mode(capture, old or path, mode):
                capture.admit(path, "baseline", change, blobs[oid], previous)
        if status in "AMTRC":
            mode, oid = proposed[path]
            if not _excluded_by_mode(capture, path, mode):
                capture.admit(path, "proposed", change, blobs[oid], previous)


def _worktree_view(repo: Path, capture: _Capture) -> dict[str, str]:
    """Return path -> worktree object id for tracked and untracked, not ignored files."""
    listed = _git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    candidates = sorted({p.decode("utf-8", "surrogateescape") for p in listed.split(b"\0") if p})
    ignored = _git(repo, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory")
    for _ in (p for p in ignored.split(b"\0") if p):
        capture.counts["ignored"] = capture.counts.get("ignored", 0) + 1
    regular = []
    for path in candidates:
        if path.endswith("/"):
            capture.exclude(path.rstrip("/"), "nested_repository")
            continue
        try:
            info = os.lstat(repo / path)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            capture.exclude(path, "symlink")
        elif stat.S_ISDIR(info.st_mode):
            capture.exclude(path, "submodule")
        elif not stat.S_ISREG(info.st_mode) or "\n" in path:
            capture.exclude(path, "special_file")
        else:
            regular.append(path)
    hashed = _git(
        repo, "hash-object", "--no-filters", "--stdin-paths", stdin="".join(f"{p}\n" for p in regular).encode()
    )
    return dict(zip(regular, hashed.decode().split(), strict=True))


def _capture_worktree(capture: _Capture, head_tree: dict) -> dict[str, str]:
    repo = capture.repo
    view = _worktree_view(repo, capture)
    tracked_head = {p: v for p, v in head_tree.items() if v[0] not in (SUBMODULE_MODE, SYMLINK_MODE)}
    changed = sorted(p for p, oid in view.items() if tracked_head.get(p, (None, None))[1] != oid)
    deleted = sorted(p for p in tracked_head if p not in view and not os.path.lexists(repo / p))
    blobs = _blobs(repo, [tracked_head[p][1] for p in changed + deleted if p in tracked_head])
    for path in sorted(set(changed) | set(deleted)):
        if path in tracked_head:
            change = "deleted" if path in deleted else "modified"
            capture.admit(path, "baseline", change, blobs[tracked_head[path][1]])
        if path in view:
            content = _read_worktree(repo, path)
            if _hash_blob(repo, content) != view[path]:
                raise SnapshotError("worktree changed during capture")
            capture.admit(path, "proposed", "added" if path not in tracked_head else "modified", content)
    return view


def capture(request: dict, job: Job, design_text: str | None = None) -> dict:
    """Capture the source view the request names and return its snapshot."""
    scope = request["scope"]
    repo = Path(request["repository"]["root"])
    cap = _Capture(repo, job, request["limits"])
    objects: dict[str, str] = {}
    view: dict[str, list[str]] = {}
    if scope["kind"] == "design":
        content = (design_text or "").encode() if scope["source"] == "text" else _read_design(scope["design_path"])
        if hashlib.sha256(content).hexdigest() != scope["content_sha256"]:
            raise SnapshotError("design content does not match the request")
        if len(content) > request["limits"]["file_kib"] * 1024:
            raise SnapshotError("design input exceeds the file size limit")
        if scan_text(content.decode("utf-8", "replace")):
            raise SnapshotError("design input contains a secret")
        target = job.root / "source" / "design"
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        objects["design_sha256"] = scope["content_sha256"]
    else:
        revision = scope["revision"] if scope["kind"] == "hypothesis" else scope.get("head", "HEAD")
        objects["head"] = _commit(repo, revision)
        head_tree = _tree(repo, objects["head"])
        if scope["kind"] == "hypothesis":
            for selected in scope["paths"]:
                if not any(p == selected or p.startswith(selected + "/") for p in head_tree):
                    cap.exclude(selected, "outside_scope")
            for path, (mode, oid) in sorted(head_tree.items()):
                if not any(path == p or path.startswith(p + "/") for p in scope["paths"]):
                    continue
                if _excluded_by_mode(cap, path, mode):
                    continue
                if not _safe_path(path):
                    cap.exclude(None, "special_file")
                    continue
                if len(cap.admitted) >= cap.limits["admitted_files"]:
                    cap.exclude(path, "limit_reached")
                    continue
                size = int(_git(repo, "cat-file", "-s", oid))
                if size > cap.limits["file_kib"] * 1024:
                    cap.exclude(path, "too_large")
                    continue
                if cap.total + size > cap.limits["job_kib"] * 1024:
                    cap.exclude(path, "limit_reached")
                    continue
                cap.admit(path, "proposed", "context", _blobs(repo, [oid])[oid])
                if any(e["path"] == path for e in cap.admitted):
                    view[path] = ["blob", oid]
        elif scope["kind"] == "commits":
            objects["base"] = _commit(repo, scope["base"])
            baseline_commit = objects["base"]
            if scope["comparison"] == "merge_base":
                try:
                    baseline_commit = objects["merge_base"] = (
                        _git(repo, "merge-base", objects["base"], objects["head"]).decode().strip()
                    )
                except SnapshotError:
                    raise SnapshotError("base and head share no history") from None
            changes = _object_changes(repo, ["diff-tree", "-r", baseline_commit, objects["head"]])
            _capture_objects(cap, _tree(repo, baseline_commit), head_tree, changes)
            view = {
                p: ["blob", oid] for p, (mode, oid) in head_tree.items() if mode not in (SUBMODULE_MODE, SYMLINK_MODE)
            }
        elif scope["kind"] == "staged":
            index = _index(repo)
            changes = _object_changes(repo, ["diff-index", "--cached", "-r", objects["head"]])
            _capture_objects(cap, head_tree, index, changes)
            view = {p: ["blob", oid] for p, (mode, oid) in index.items() if mode not in (SUBMODULE_MODE, SYMLINK_MODE)}
        else:
            view = {p: ["worktree", oid] for p, oid in _capture_worktree(cap, head_tree).items()}
    _write_view(job, view)
    snapshot = {
        "schema_version": 1,
        "job_id": request["job_id"],
        "scope_kind": scope["kind"],
        "objects": objects,
        "admitted": cap.admitted,
        "excluded": cap.excluded_entries(),
        "captured_at": utc_now(),
    }
    errors = validate_snapshot(snapshot, request)
    if errors:
        raise SnapshotError("; ".join(errors))
    return snapshot


def _read_design(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise SnapshotError("design file is not a regular file")
        return handle.read()


def _write_view(job: Job, view: dict) -> None:
    target = job.root / "source" / VIEW_FILE
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(view, handle)


def admit_context(request: dict, job: Job, snapshot: dict, path: str) -> dict:
    """Admit one surrounding file of the proposed state from the frozen view.

    Returns the updated snapshot. A path outside the view, one already
    admitted, or a worktree file that changed since capture is rejected.
    """
    with open(job.root / "source" / VIEW_FILE, encoding="utf-8") as handle:
        view = json.load(handle)
    if path not in view:
        raise SnapshotError("path is outside the captured view")
    if any(entry["path"] == path and entry["side"] == "proposed" for entry in snapshot["admitted"]):
        raise SnapshotError("path is already admitted")
    repo = Path(request["repository"]["root"])
    kind, oid = view[path]
    if kind == "blob":
        content = _blobs(repo, [oid])[oid]
    else:
        content = _read_worktree(repo, path)
        if _hash_blob(repo, content) != oid:
            raise SnapshotError("worktree changed since capture")
    cap = _Capture(repo, job, request["limits"], list(snapshot["admitted"]), list(snapshot["excluded"]))
    cap.total = sum(entry["bytes"] for entry in snapshot["admitted"])
    cap.admit(path, "proposed", "context", content)
    updated = dict(snapshot, admitted=cap.admitted, excluded=cap.excluded_entries())
    errors = validate_snapshot(updated, request)
    if errors:
        raise SnapshotError("; ".join(errors))
    return updated
