"""Owned state and cumulative budgets for one admitted headless assessment.

The existing orchestration controller owns phases and completion gates. This
helper only holds its output lock, persists accounting, and checks resume
identity. No value read here grants a model source or publication authority.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import secrets
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from jsonschema import Draft202012Validator
from shared._atomic_io import atomic_write_json

from runtime import acquire_lock
from runtime.analyst_host import HostCancelled
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import AssessmentBudget, digest
from runtime.multi_repo_scope import AssessmentScope

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas/multi-repo-state.schema.json"
STATE_NAME = ".assessment-state.json"
WORK_NAME = ".assessment-work"
MAX_STATE_BYTES = 2_097_152
MAX_DELIVERABLE_BYTES = 67_108_864


def _real_directory(path: Path, *, create=False):
    """Reject links in the controller-selected writable path and its parents."""
    for parent in reversed((path, *path.parents)):
        if parent.exists() or parent.is_symlink():
            if not stat.S_ISDIR(parent.lstat().st_mode):
                raise ExchangeError("Assessment output contains a non-directory or link")
        elif create:
            parent.mkdir(mode=0o700)
        else:
            raise ExchangeError("Assessment output directory is missing")


def _read_state(path: Path):
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_STATE_BYTES:
            raise ExchangeError("Assessment state must be a bounded regular file")
        state = json.loads(path.read_text(encoding="utf-8"))
        if not Draft202012Validator(json.loads(SCHEMA.read_text())).is_valid(state):
            raise ExchangeError("Assessment state violates its contract")
        return state
    except ExchangeError:
        raise
    except (OSError, ValueError):
        raise ExchangeError("Assessment state is unreadable or malformed") from None


def _deliverable(output: Path, name: str) -> str:
    # The controller supplies public basenames, never source/model paths.
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
        raise ExchangeError("Assessment deliverable must have a controller-selected basename")
    target = output / name
    try:
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DELIVERABLE_BYTES:
            raise ExchangeError("Assessment deliverable must be a bounded regular file")
        return hashlib.sha256(target.read_bytes()).hexdigest()
    except OSError:
        raise ExchangeError("Assessment deliverable is missing or unreadable") from None


class AssessmentState:
    def __init__(self, scope, *, configuration, runtime_sha256, budget, resume=False):
        if not isinstance(scope, AssessmentScope) or not isinstance(budget, AssessmentBudget):
            raise ExchangeError("Assessment lifecycle requires an admitted scope and full budget")
        if not isinstance(runtime_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", runtime_sha256):
            raise ExchangeError("Assessment lifecycle requires the trusted runtime fingerprint")
        self.scope, self.budget, self.resume = scope, budget, resume
        self.output = scope.output
        self.path = self.output / STATE_NAME
        self.directory = self.output / WORK_NAME
        self.lock = self.output / ".appsec-lock"
        self.identity = {
            "scope_sha256": scope.inventory()["scope_sha256"],
            "configuration_sha256": digest(configuration),
            "runtime_sha256": runtime_sha256,
            "limits": {
                "max_usd": budget.max_usd,
                "call_usd": budget.call_usd,
                "max_calls": budget.max_calls,
                "timeout_s": budget.timeout_s,
            },
        }
        self.state = None
        self.cancelled = False
        self._held = False
        self._last_heartbeat = 0.0

    @contextmanager
    def hold(self):
        if self._held:
            raise ExchangeError("Assessment lifecycle is already active")
        self.scope.verify_unchanged()
        _real_directory(self.output, create=True)
        with acquire_lock.serialization_guard(self.output):
            self._open()
            self._held = True
            now = int(time.time())
            acquire_lock._write_lock(self.lock, os.getpid(), now, self.state["run_id"], acquired_ts=now)
            self.lock.chmod(0o600)
            try:
                self.checkpoint()
                yield self
            except BaseException as error:
                self.state["status"] = (
                    "interrupted" if isinstance(error, (HostCancelled, KeyboardInterrupt)) else "failed"
                )
                self.checkpoint()
                raise
            else:
                if self.state["status"] != "complete":
                    self.state["status"] = "interrupted"
                    self.checkpoint()
            finally:
                acquire_lock.release_lock(self.lock, self.state["run_id"])
                self._held = False

    def _open(self):
        self._check_lock()
        lock_state, _ = acquire_lock._classify_lock(self.lock)
        if lock_state == "fresh":
            raise ExchangeError("Assessment output belongs to another live run")
        if self.resume:
            self.state = _read_state(self.path)
            if self.state["identity"] != self.identity:
                raise ExchangeError("Assessment resume requires unchanged sources, settings and runtime")
            accounting = self.state["accounting"]
            if not math.isfinite(accounting["spent_usd"]):
                raise ExchangeError("Assessment resume cost accounting is invalid")
            if self.state["expires_at"] != self.state["started_at"] + self.budget.timeout_s:
                raise ExchangeError("Assessment resume deadline differs from its original limit")
            if accounting["unavailable"]:
                raise ExchangeError("Assessment resume cannot reconcile an unfinished cost reservation")
            if (
                accounting["calls"] > self.budget.max_calls
                or accounting["spent_usd"] > self.budget.max_usd
                or self.state["expires_at"] <= time.time()
            ):
                raise ExchangeError("Assessment resume budget is exhausted")
            _real_directory(self.directory)
            self.budget.calls = accounting["calls"]
            self.budget.spent_usd = accounting["spent_usd"]
            self.budget.deadline = time.monotonic() + self.state["expires_at"] - time.time()
            for name, expected in self.state["deliverables"].items():
                if _deliverable(self.output, name) != expected:
                    raise ExchangeError("Assessment deliverable changed after completion")
            if self.state["status"] != "complete":
                self.state["status"] = "running"
        else:
            allowed = {".appsec-lock", ".appsec-lock.guard"}
            if any(child.name not in allowed for child in self.output.iterdir()):
                raise ExchangeError("A fresh multi-repository assessment requires an empty output directory")
            now = int(time.time())
            self.state = {
                "schema_version": 1,
                "run_id": "assessment-" + secrets.token_hex(16),
                "identity": copy.deepcopy(self.identity),
                "started_at": now,
                "expires_at": now + self.budget.timeout_s,
                "status": "running",
                "accounting": {"calls": 0, "spent_usd": 0.0, "unavailable": False},
                "deliverables": {},
            }
            self.directory.mkdir(mode=0o700)

    def _check_lock(self):
        # Link-safe, bounded checks precede any read or in-place write.
        if self.lock.exists() or self.lock.is_symlink():
            metadata = self.lock.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 4096:
                raise ExchangeError("Assessment liveness lock is not a bounded regular file")

    def checkpoint(self):
        self._check_lock()
        if not self._held or acquire_lock.read_run_id(self.lock) != self.state["run_id"]:
            raise ExchangeError("Assessment no longer owns its output lock")
        _real_directory(self.output)
        _real_directory(self.directory)
        self.state["accounting"] = {
            "calls": self.budget.calls,
            "spent_usd": self.budget.spent_usd,
            "unavailable": self.budget.failed,
        }
        Draft202012Validator(json.loads(SCHEMA.read_text())).validate(self.state)
        atomic_write_json(self.path, self.state)
        self.path.chmod(0o600)
        now = int(time.time())
        acquire_lock._write_lock(self.lock, os.getpid(), now, self.state["run_id"])
        self.lock.chmod(0o600)
        self._last_heartbeat = time.monotonic()

    def should_stop(self):
        if not self._held:
            raise ExchangeError("Assessment lifecycle is not active")
        if time.monotonic() - self._last_heartbeat >= 10:
            self.checkpoint()
        return self.cancelled

    def complete(self, deliverables):
        """Record exact deliverables after the controller's existing final gates."""
        if self.budget.failed or not deliverables:
            raise ExchangeError("Assessment cannot complete without accounted, gated deliverables")
        self.budget.remaining_seconds()
        self.scope.verify_unchanged()
        self.state["deliverables"] = {name: _deliverable(self.output, name) for name in deliverables}
        self.state["status"] = "complete"
        self.checkpoint()
