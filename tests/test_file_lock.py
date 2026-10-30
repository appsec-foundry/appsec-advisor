from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import textwrap
import threading
import types
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

from shared._file_lock import lock_exclusive, unlock  # noqa: E402

LOCKING_SCRIPTS = (
    "analyzers/architect_review_runtime.py",
    "model/reserve_ids.py",
    "runtime/acquire_lock.py",
    "runtime/agent_lifecycle.py",
    "runtime/agent_logger.py",
    "runtime/analyst_state.py",
    "runtime/budget_watchdog.py",
    "runtime/remote_repositories.py",
    "runtime/stride_attempt_writer.py",
)
# The architect review runtime is checked statically only: importing it loads
# most of the assessment pipeline, and its lock is taken inside a function.
IMPORTED_LOCKING_MODULES = tuple(
    path[: -len(".py")].replace("/", ".") for path in LOCKING_SCRIPTS if path != "analyzers/architect_review_runtime.py"
)

_FAKE_MSVCRT = """
import sys, types
# subprocess detects Windows by importing msvcrt; load it before the stand-in exists.
import subprocess
fake = types.ModuleType("msvcrt")
fake.LK_NBLCK, fake.LK_UNLCK = 2, 0
fake.locking = lambda fd, mode, nbytes: None
sys.modules["fcntl"] = None
sys.modules["msvcrt"] = fake
"""


def test_locking_scripts_take_locks_through_the_helper_only():
    pattern = re.compile(r"^\s*(import fcntl|from fcntl import)", re.MULTILINE)
    offenders = [path for path in LOCKING_SCRIPTS if pattern.search((SCRIPTS / path).read_text(encoding="utf-8"))]
    assert offenders == []


def test_locking_modules_import_on_a_platform_without_fcntl():
    imports = "\n".join(f"import {name}" for name in IMPORTED_LOCKING_MODULES)
    code = f"{_FAKE_MSVCRT}\nsys.path.insert(0, {str(SCRIPTS)!r})\n{imports}\nprint('ok')\n"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def _windows_variant(monkeypatch, locking):
    fake = types.ModuleType("msvcrt")
    fake.LK_NBLCK, fake.LK_UNLCK = 2, 0
    fake.locking = locking
    monkeypatch.setitem(sys.modules, "fcntl", None)
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    spec = importlib.util.spec_from_file_location("_file_lock_windows_variant", SCRIPTS / "shared" / "_file_lock.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.fcntl is None
    return module


@pytest.fixture
def descriptor(tmp_path):
    path = tmp_path / "state.json"
    path.write_text('{"counter": 1}', encoding="utf-8")
    fd = os.open(path, os.O_RDWR)
    yield fd
    os.close(fd)


def test_windows_fallback_locks_a_distant_byte_and_restores_the_position(monkeypatch, descriptor):
    calls = []
    module = _windows_variant(monkeypatch, lambda fd, mode, n: calls.append((os.lseek(fd, 0, os.SEEK_CUR), mode, n)))
    os.lseek(descriptor, 3, os.SEEK_SET)

    module.lock_exclusive(descriptor)
    module.unlock(descriptor)

    offset = module._WINDOWS_LOCK_OFFSET
    assert calls == [(offset, 2, 1), (offset, 0, 1)]
    assert os.lseek(descriptor, 0, os.SEEK_CUR) == 3


def test_windows_fallback_non_blocking_reports_a_held_lock_as_blocking_io_error(monkeypatch, descriptor):
    def held(_fd, _mode, _n):
        raise PermissionError(13, "Permission denied")

    module = _windows_variant(monkeypatch, held)

    with pytest.raises(BlockingIOError):
        module.lock_exclusive(descriptor, blocking=False)
    assert os.lseek(descriptor, 0, os.SEEK_CUR) == 0


def test_windows_fallback_blocking_retries_until_the_lock_is_free(monkeypatch, descriptor):
    attempts = []

    def free_on_third_attempt(_fd, _mode, _n):
        attempts.append(1)
        if len(attempts) < 3:
            raise PermissionError(13, "Permission denied")

    module = _windows_variant(monkeypatch, free_on_third_attempt)
    monkeypatch.setattr(module, "_WINDOWS_RETRY_SECONDS", 0)

    module.lock_exclusive(descriptor)
    assert len(attempts) == 3


def _hold_lock(path: Path) -> subprocess.Popen:
    code = textwrap.dedent(f"""
        import os, sys
        sys.path.insert(0, {str(SCRIPTS)!r})
        from shared._file_lock import lock_exclusive
        fd = os.open({str(path)!r}, os.O_RDWR)
        lock_exclusive(fd)
        print("locked", flush=True)
        sys.stdin.readline()
        os.close(fd)
    """)
    holder = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert holder.stdout.readline().strip() == "locked"
    return holder


def _release(holder: subprocess.Popen) -> None:
    holder.stdin.write("\n")
    holder.stdin.flush()
    assert holder.wait(timeout=30) == 0


def test_a_held_lock_rejects_a_non_blocking_caller_until_it_is_released(tmp_path, descriptor):
    holder = _hold_lock(tmp_path / "state.json")
    try:
        with pytest.raises(BlockingIOError):
            lock_exclusive(descriptor, blocking=False)
        assert (tmp_path / "state.json").read_text(encoding="utf-8") == '{"counter": 1}'
    finally:
        _release(holder)

    lock_exclusive(descriptor, blocking=False)
    unlock(descriptor)


def test_a_blocking_caller_waits_for_the_holder(tmp_path, descriptor):
    holder = _hold_lock(tmp_path / "state.json")
    acquired = threading.Event()

    def wait_for_lock():
        lock_exclusive(descriptor)
        acquired.set()

    waiter = threading.Thread(target=wait_for_lock, daemon=True)
    waiter.start()
    try:
        assert not acquired.wait(0.3)
    finally:
        _release(holder)
    assert acquired.wait(30)
    waiter.join(30)
    unlock(descriptor)
