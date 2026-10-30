"""Exclusive advisory locks on an open file descriptor, on POSIX and Windows.

POSIX uses ``fcntl.flock``. Windows has no ``fcntl``; there the lock is a
``msvcrt`` byte-range lock on one byte far beyond any real file size. Windows
byte-range locks are mandatory, so locking real content would make other
processes fail to read the file; the distant byte keeps the file readable while
still serializing every caller that locks through this module.

Callers keep their own descriptor lifecycle. Closing the descriptor releases
the lock on both platforms, so an explicit ``unlock`` is optional before close.
The descriptor's file position is preserved.
"""

from __future__ import annotations

import os
import time

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
    import msvcrt

# Far past any file this plugin locks, below the 2 GiB boundary of the C runtime.
_WINDOWS_LOCK_OFFSET = 0x7FFFFFF0
_WINDOWS_RETRY_SECONDS = 0.01


def lock_exclusive(fd: int, *, blocking: bool = True) -> None:
    """Take an exclusive lock on ``fd``.

    A blocking call waits until the lock is free. A non-blocking call raises
    ``BlockingIOError`` when another descriptor holds the lock.
    """
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)
        return
    while True:
        try:
            _windows_locking(fd, msvcrt.LK_NBLCK)
            return
        except OSError as exc:
            if not blocking:
                raise BlockingIOError(*exc.args) from None
        time.sleep(_WINDOWS_RETRY_SECONDS)


def unlock(fd: int) -> None:
    """Release the lock taken by ``lock_exclusive`` on the same descriptor."""
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    _windows_locking(fd, msvcrt.LK_UNLCK)


def _windows_locking(fd: int, mode: int) -> None:
    # msvcrt.locking acts on the current file position; restore it afterwards.
    position = os.lseek(fd, 0, os.SEEK_CUR)
    os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
    try:
        msvcrt.locking(fd, mode, 1)
    finally:
        os.lseek(fd, position, os.SEEK_SET)
