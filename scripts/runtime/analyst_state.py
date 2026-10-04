#!/usr/bin/env python3
"""runtime/analyst_state.py — job roots of the on-demand threat analysis.

Each job lives in a private directory outside the target repository and
outside any assessment output directory:

    <state root>/<repository key>/<job id>/

The state root is ``$XDG_STATE_HOME/appsec-advisor/analyst`` (default
``~/.local/state/appsec-advisor/analyst``) unless the caller passes one. The
repository key is a hash of the canonical repository path, so two worktrees
never share jobs. Job ids are unpredictable. Directories are mode 0700 and
must be owned by the current user; a loosened or foreign directory is refused,
not repaired.

The controller holds an exclusive ``flock`` on ``<job>/lock`` for the job's
lifetime. A job whose lock can be taken has no live owner, which is how
``recover_stale`` finds crashed jobs. Artifacts are written atomically, only
under fixed names, and controller-owned contracts are validated before they
are published. Nothing here reads or writes assessment state; assessment
cleanup never sees these directories.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import contextlib
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from validators.validate_analyst import (
    TERMINAL_REASONS,
    validate_request,
    validate_snapshot,
    validate_state,
    validate_transition,
)

JOB_ID_RE = re.compile(r"^aj-[0-9a-f]{32}$")
JOB_FILES = frozenset(
    {
        "request.json",
        "state.json",
        "snapshot.json",
        "context.json",
        "packages.json",
        "response.json",
        "questions.json",
        "result.json",
        "result.md",
    }
)
TEMP_DIRS = frozenset({"source", "prompt", "work"})
CANCEL_MARKER = "cancel"
LOCK_FILE = "lock"
OUTPUT_MARKER = ".appsec-analyst-output"
# Files whose presence identifies an assessment output directory. Generic for
# any --output location, because the assessment output path is caller-chosen.
ASSESSMENT_MARKERS = (
    ".appsec-lock",
    ".appsec-cache",
    ".appsec-checkpoint",
    ".agent-run.log",
    "threat-model.md",
    "threat-model.yaml",
)
_VALIDATORS = {"request.json": validate_request, "snapshot.json": validate_snapshot}


class AnalystStateError(Exception):
    """A job root, lock, or artifact violates the analyst state contract."""


@dataclass
class Job:
    root: Path
    job_id: str
    lock_fd: int | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_state_root(env: dict | None = None) -> Path:
    env = os.environ if env is None else env
    base = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "appsec-advisor" / "analyst"


def repository_key(repo_root: Path) -> str:
    return hashlib.sha256(str(Path(repo_root).resolve()).encode("utf-8")).hexdigest()[:16]


def _private_dir(path: Path) -> Path:
    """Create ``path`` as a private directory, or verify an existing one."""
    with contextlib.suppress(FileExistsError):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.mkdir(path, 0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise AnalystStateError(f"{path.name}: not a directory")
    if info.st_uid != os.geteuid():
        raise AnalystStateError(f"{path.name}: owned by another user")
    if info.st_mode & 0o077:
        raise AnalystStateError(f"{path.name}: accessible to other users")
    return path


def repository_dir(repo_root: Path, state_root: Path | None = None) -> Path:
    base = _private_dir(Path(state_root or default_state_root()))
    return _private_dir(base / repository_key(repo_root))


def _lock(path: Path, create: bool) -> int:
    flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if create else 0)
    fd = os.open(path / LOCK_FILE, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise AnalystStateError(f"{path.name}: owned by a running controller") from None
    return fd


def create_job(repo_root: Path, state_root: Path | None = None) -> Job:
    """Create and lock a new job root."""
    job_id = "aj-" + secrets.token_hex(16)
    root = repository_dir(repo_root, state_root) / job_id
    os.mkdir(root, 0o700)
    return Job(root, job_id, _lock(root, create=True))


def job_path(job_id: str, repo_root: Path, state_root: Path | None = None) -> Path:
    """Return the verified root of an existing job of this repository."""
    if not JOB_ID_RE.fullmatch(job_id):
        raise AnalystStateError("invalid job id")
    root = repository_dir(repo_root, state_root) / job_id
    if not root.exists():
        raise AnalystStateError(f"{job_id}: no such job")
    return _private_dir(root)


def acquire(root: Path) -> Job:
    """Take ownership of an existing job; fails while another controller holds it."""
    return Job(root, root.name, _lock(root, create=False))


def release(job: Job) -> None:
    if job.lock_fd is not None:
        os.close(job.lock_fd)
        job.lock_fd = None


def _require_owner(job: Job) -> None:
    if job.lock_fd is None:
        raise AnalystStateError(f"{job.job_id}: not owned by this controller")


def write_artifact(job: Job, name: str, data: dict | str) -> None:
    """Atomically publish one artifact under a fixed name."""
    _require_owner(job)
    if name not in JOB_FILES:
        raise AnalystStateError(f"{name}: not an analyst job artifact")
    if name in _VALIDATORS:
        errors = _VALIDATORS[name](data)
        if errors:
            raise AnalystStateError("; ".join(errors))
    text = data if isinstance(data, str) else json.dumps(data, indent=2, sort_keys=True) + "\n"
    fd, tmp = tempfile.mkstemp(dir=job.root, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, job.root / name)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def read_artifact(root: Path, name: str) -> dict | str | None:
    """Read one artifact without following symlinks; ``None`` when absent."""
    if name not in JOB_FILES:
        raise AnalystStateError(f"{name}: not an analyst job artifact")
    try:
        fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AnalystStateError(f"{name}: is a symlink") from None
        raise
    with os.fdopen(fd, encoding="utf-8") as handle:
        text = handle.read()
    return json.loads(text) if name.endswith(".json") else text


def transition(job: Job, new_state: dict, limits: dict | None = None) -> None:
    """Validate and publish the next state document of an owned job."""
    _require_owner(job)
    errors = validate_state(new_state, limits)
    if not errors:
        if new_state["job_id"] != job.job_id:
            errors = ["state: job_id does not match the job root"]
        else:
            current = read_artifact(job.root, "state.json")
            if current is None:
                if new_state["state"] != "prepared":
                    errors = ["state: a job starts in state prepared"]
            else:
                errors = validate_transition(current, new_state)
    if errors:
        raise AnalystStateError("; ".join(errors))
    write_artifact(job, "state.json", new_state)


def deadline_exceeded(request: dict, now: datetime | None = None) -> bool:
    """Whether the job wall-clock limit has elapsed since the request."""
    started = datetime.strptime(request["requested_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    elapsed = ((now or datetime.now(timezone.utc)) - started).total_seconds()
    return elapsed > request["limits"]["job_seconds"]


def request_cancel(root: Path) -> None:
    """Ask the owning controller to stop; it records the cancellation itself."""
    fd = os.open(root / CANCEL_MARKER, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.close(fd)


def cancel_requested(root: Path) -> bool:
    return os.path.lexists(root / CANCEL_MARKER)


def _remove_tree(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def cleanup_temporaries(job: Job) -> None:
    """Remove captured source, prompts, and partial writes; keep artifacts."""
    _require_owner(job)
    for name in TEMP_DIRS:
        _remove_tree(job.root / name)
    for entry in job.root.iterdir():
        if entry.name.startswith(".tmp-"):
            _remove_tree(entry)


def discard_job(job: Job) -> None:
    """Delete an owned job root entirely."""
    _require_owner(job)
    if not JOB_ID_RE.fullmatch(job.root.name) or job.root.is_symlink():
        raise AnalystStateError(f"{job.root.name}: not a job root")
    shutil.rmtree(job.root)
    release(job)


def _older_than(state: dict, now: datetime, seconds: int) -> bool:
    changed = datetime.strptime(state["updated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (now - changed).total_seconds() > seconds


def _answer_window_open(root: Path, current: dict, now: datetime) -> bool:
    request = read_artifact(root, "request.json")
    if not isinstance(request, dict):
        return False
    waiting_since = datetime.strptime(current["updated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (now - waiting_since).total_seconds() <= request["limits"]["answer_hours"] * 3600


def recover_stale(
    repo_root: Path, state_root: Path | None = None, now: datetime | None = None, result_days: int | None = None
) -> list[str]:
    """Close jobs of this repository whose controller is gone.

    A job waiting for answers keeps its captured view for the request's
    ``answer_hours`` and then ends as ``incomplete`` with reason
    ``required_answers_missing``. Any other non-terminal job ends as
    ``cancelled`` with reason ``terminated``. Closed jobs lose their
    temporaries and keep their artifacts. With ``result_days``, a terminal job
    whose last state change is older than that is deleted. Jobs with a live
    owner and jobs of other repositories are untouched.
    """
    now = now or datetime.now(timezone.utc)
    recovered = []
    for root in sorted(repository_dir(repo_root, state_root).iterdir()):
        if not JOB_ID_RE.fullmatch(root.name) or root.is_symlink() or not root.is_dir():
            continue
        try:
            job = acquire(root)
        except (AnalystStateError, FileNotFoundError):
            continue
        try:
            current = read_artifact(root, "state.json")
            state = current.get("state") if isinstance(current, dict) else None
            if state == "awaiting_answers" and _answer_window_open(root, current, now):
                continue
            if state == "awaiting_answers":
                final = dict(current, state="incomplete", terminal_reason="required_answers_missing")
            elif state is not None and state not in TERMINAL_REASONS:
                final = dict(current, state="cancelled", terminal_reason="terminated", pending_questions=[])
            else:
                final = None
            if final is not None:
                transition(job, dict(final, updated_at=utc_now()))
                recovered.append(root.name)
            elif (
                state in TERMINAL_REASONS and result_days is not None and _older_than(current, now, result_days * 86400)
            ):
                discard_job(job)
                continue
            cleanup_temporaries(job)
        finally:
            release(job)
    return recovered


def check_output_dir(output_dir: Path, repo_root: Path, state_root: Path | None = None) -> list[str]:
    """Reject result destinations that overlap assessment or analyst state."""
    target = Path(os.path.abspath(output_dir))
    errors = []
    if target.is_symlink():
        errors.append("output: is a symlink")
    resolved = target.resolve()
    git_dir = Path(repo_root).resolve() / ".git"
    if resolved == git_dir or git_dir in resolved.parents:
        errors.append("output: inside the repository's .git directory")
    state = Path(state_root or default_state_root()).resolve()
    if resolved == state or state in resolved.parents or resolved in state.parents:
        errors.append("output: overlaps the analyst state root")
    for directory in (resolved, *resolved.parents):
        if any(os.path.lexists(directory / marker) for marker in ASSESSMENT_MARKERS):
            errors.append("output: inside an assessment output directory")
            break
    if resolved.exists():
        if not resolved.is_dir():
            errors.append("output: not a directory")
        elif any(resolved.iterdir()) and not (resolved / OUTPUT_MARKER).is_file():
            errors.append("output: non-empty directory that is not an analyst output")
    return errors


def mark_output_dir(output_dir: Path) -> None:
    """Create the result destination and mark it as analyst-owned."""
    output_dir.mkdir(parents=True, exist_ok=True)
    marker = output_dir / OUTPUT_MARKER
    if not marker.is_file():
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        os.close(fd)
