#!/usr/bin/env python3
"""
_atomic_io.py — crash-safe file-write helpers.

All JSON and text cache files the orchestrator persists (baseline.json,
.threats-merged.json, .merge-candidates.json, .merge-decisions.json, per-run
checkpoints, fragments) must survive a mid-write crash without leaving a
truncated file on disk. A torn write is how `.appsec-cache/baseline.json`
becomes invalid JSON and silently forces a full re-scan on the next run;
the orchestrator assumes intact cache files and does not checksum on read.

The two helpers here encapsulate the standard tempfile-plus-rename dance:

  1. Write to a unique tempfile in the same directory as the target (so
     os.replace is guaranteed atomic — must be same filesystem)
  2. Flush + fsync the file and its directory entry
  3. os.replace(tmp, target) — atomic on POSIX, atomic-except-for-power-loss
     on Windows (the standard library contract).
  4. On any exception, best-effort unlink the tempfile.

Callers get the property: after the call returns successfully, `path`
contains exactly the new contents; if the process dies mid-call, `path`
contains either the old contents (if it existed) or nothing — never a
half-written file.

Usage:
    from _atomic_io import atomic_write_text, atomic_write_json

    atomic_write_json(cache_path, state)
    atomic_write_text(checkpoint_path, "phase=3 status=started\\n")
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_text(path: Path | str, text: str, *, encoding: str = "utf-8") -> None:
    """Write `text` to `path` atomically (tmp + fsync + rename).

    The parent directory must exist — this helper does not create it, to keep
    the crash-semantics predictable (a missing parent is a programming bug,
    not a runtime condition to paper over).
    """
    target = Path(path)
    parent = target.parent
    # mkstemp in the same directory guarantees os.replace is on one filesystem.
    fd, tmp_name = tempfile.mkstemp(
        dir=str(parent),
        prefix=f".{target.name}.tmp-",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, target)
        _fsync_dir(parent)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def atomic_write_json(
    path: Path | str,
    obj: Any,
    *,
    indent: int | None = 2,
    sort_keys: bool = True,
    trailing_newline: bool = True,
) -> None:
    """Serialize `obj` to JSON and write atomically.

    `trailing_newline=True` matches POSIX convention and keeps most diff
    tools happy; set it to False only if the consumer is byte-exact-sensitive.
    """
    text = json.dumps(obj, indent=indent, sort_keys=sort_keys, default=str)
    if trailing_newline:
        text += "\n"
    atomic_write_text(path, text)


def _fsync_dir(directory: Path) -> None:
    """Best-effort fsync of the directory entry after a rename.

    On Linux this is required to guarantee the rename hits disk if the
    system loses power between the replace() and the implicit flush. On
    platforms that do not support directory fsync (Windows, some macOS
    filesystems) the operation is silently skipped.
    """
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        # Directory fsync is not supported on all platforms / filesystems
        # (Windows + some exotic mounts). The rename itself is already
        # atomic; dir fsync is just durability insurance.
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
