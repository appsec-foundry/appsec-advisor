#!/usr/bin/env python3
"""Import a finished assessment from a checkout's ``docs/security`` into its external directory.

Releases before decision AS-1 wrote assessments into ``<repo>/docs/security``.
This release still reads them there and offers to import one into the
application's directory under the user data directory. Only a finished set is
imported: an interrupted run is reported as incomplete and must be started
again. The import copies; the files in the checkout stay until the operator
removes them.

Every copied file is a regular file of a fixed product name, read through the
legacy directory itself, never through a link. The copies are staged in the
destination and installed together with an import receipt, which a later run
treats as the earlier, completed assessment whose history it continues.

Usage (the skill asks the operator on ``offer``; the controller imports with --migrate-legacy):
    python3 runtime/legacy_import.py check --repo <path> --output <dir>

``check`` prints ``none``, ``offer`` or ``incomplete: <reason>``.
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
import shutil
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import yaml
from shared.artifact_names import ArtifactSetError, artifact_stem, published_name

from runtime import acquire_lock

IMPORT_NAME = ".assessment-import.json"
STATE_NAME = ".assessment-state.json"
STAGING_NAME = ".assessment-import-staging"
LEGACY_DIRECTORY = Path("docs") / "security"
MAX_FILE_BYTES = 64 * 1024 * 1024
# Product suffixes of one naming set, besides its figures.
_SUFFIXES = (".md", ".yaml", ".pdf", ".html", ".sarif.json", ".threatdragon.json", "-changelog.md", "-changelog.jsonl")
_FIXED = ("pentest-tasks.yaml",)


class LegacyImportError(ValueError):
    """The legacy assessment cannot be imported; the message says why."""


@dataclass(frozen=True)
class Legacy:
    """A legacy assessment directory and whether its run finished."""

    directory: Path
    stem: str
    complete: bool
    reason: str


def find(repo_root: Path) -> Legacy | None:
    """The legacy assessment in ``repo_root``'s ``docs/security``, or None when it holds none."""
    directory = Path(os.path.realpath(repo_root)) / LEGACY_DIRECTORY
    try:
        info = directory.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    if Path(os.path.realpath(directory)) != directory:
        return Legacy(directory, "", False, "docs/security is a link out of the checkout")
    try:
        stem = artifact_stem(directory)
    except ArtifactSetError as exc:
        return Legacy(directory, "", False, str(exc))
    if stem is None:
        return None
    return Legacy(directory, stem, *_finished(directory, stem))


def _finished(directory: Path, stem: str) -> tuple[bool, str]:
    """Whether the run behind the set finished, with the reason when it did not."""
    if acquire_lock.lock_held_by_live_other_run(directory / ".appsec-lock"):
        return False, "an assessment is still running there"
    for suffix in (".md", ".yaml"):
        if not _regular(directory / f"{stem}{suffix}"):
            return False, f"{stem}{suffix} is missing"
    try:
        model = yaml.safe_load((directory / f"{stem}.yaml").read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError):
        return False, f"{stem}.yaml is unreadable"
    if not isinstance(model, dict) or not isinstance(model.get("threats"), list):
        return False, f"{stem}.yaml is not a complete assessment model"
    state = directory / STATE_NAME
    if _regular(state):
        try:
            status = json.loads(state.read_text(encoding="utf-8")).get("status")
        except (OSError, ValueError, AttributeError):
            status = None
        if status != "complete":
            return False, "its last run did not finish"
    checkpoint = directory / ".appsec-checkpoint"
    if _regular(checkpoint):
        try:
            tokens = checkpoint.read_text(encoding="utf-8", errors="replace").split()
        except OSError:
            tokens = []
        if "status=completed" not in tokens:
            return False, "its last run did not finish"
    return True, ""


def _regular(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE_BYTES


def _products(legacy: Legacy) -> list[str]:
    """The fixed product names of the set that exist as regular files."""
    names = [legacy.stem + suffix for suffix in _SUFFIXES]
    names += sorted(p.name for p in legacy.directory.glob(f"{legacy.stem}.figure*.svg"))
    names += list(_FIXED)
    return [name for name in names if _regular(legacy.directory / name)]


def destination_holds_assessment(destination: Path) -> bool:
    """Whether ``destination`` already holds an assessment, a run state or an import."""
    try:
        if artifact_stem(destination) is not None:
            return True
    except ArtifactSetError:
        return True
    return any((destination / name).exists() for name in (STATE_NAME, IMPORT_NAME))


def offer(repo_root: Path, destination: Path) -> Legacy | None:
    """The legacy assessment a run into ``destination`` should offer to import, finished or not."""
    if Path(os.path.realpath(destination)) == Path(os.path.realpath(repo_root)) / LEGACY_DIRECTORY:
        return None
    if destination.is_dir() and destination_holds_assessment(destination):
        return None
    return find(repo_root)


def import_legacy(legacy: Legacy, destination: Path) -> dict[str, str]:
    """Copy the finished legacy set into ``destination`` under the published names.

    Returns the imported deliverables and their digests. The legacy files stay.
    """
    if not legacy.complete:
        raise LegacyImportError(
            f"the assessment in docs/security is incomplete ({legacy.reason}); start a new assessment"
        )
    if destination_holds_assessment(destination):
        raise LegacyImportError("the destination already holds an assessment; nothing was imported")
    staging = destination / STAGING_NAME
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(mode=0o700)
    delivered: dict[str, str] = {}
    try:
        for name in _products(legacy):
            data = _read_regular(legacy.directory / name)
            if name == f"{legacy.stem}.md":
                # The report links its figures by name; they are renamed with it.
                data = data.replace(f"{legacy.stem}.figure".encode(), b"security-assessment.figure")
            target = published_name(name)
            _write_private(staging / target, data)
            delivered[target] = hashlib.sha256(data).hexdigest()
        receipt = {
            "schema_version": 1,
            "source": LEGACY_DIRECTORY.as_posix(),
            "imported_at": int(time.time()),
            "deliverables": delivered,
        }
        _write_private(staging / IMPORT_NAME, (json.dumps(receipt, indent=2) + "\n").encode())
        # The receipt is installed last: an interrupted import leaves no receipt.
        for name in [*delivered, IMPORT_NAME]:
            os.replace(staging / name, destination / name)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return delivered


def _read_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise LegacyImportError(f"{path.name} is not a regular file of a supported size")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read(MAX_FILE_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def read_receipt(destination: Path) -> dict | None:
    """The import receipt in ``destination``, or None when it is absent or malformed."""
    path = destination / IMPORT_NAME
    if not _regular(path):
        return None
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    deliverables = receipt.get("deliverables") if isinstance(receipt, dict) else None
    if not isinstance(deliverables, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in deliverables.items()
    ):
        return None
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report whether a docs/security assessment can be imported.")
    parser.add_argument("command", choices=("check",))
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    legacy = offer(args.repo, args.output)
    if legacy is None:
        print("none")
    elif legacy.complete:
        print("offer")
    else:
        print(f"incomplete: {legacy.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
