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
import shutil
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from jsonschema import Draft202012Validator
from shared._atomic_io import atomic_write_json

from runtime import acquire_lock
from runtime.analyst_host import HostCancelled
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import RECEIPT_SCHEMA, AssessmentBudget, _read_json, digest
from runtime.multi_repo_scope import AssessmentScope

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "schemas/multi-repo-state.schema.json"
STATE_NAME = ".assessment-state.json"
WORK_NAME = ".assessment-work"
# What a refused resume names when its recorded identity no longer matches.
_IDENTITY_LABELS = (
    ("scope_sha256", "the selected source code"),
    ("configuration_sha256", "the assessment settings"),
    ("runtime_sha256", "the plugin version"),
    ("limits", "the budget or time limits"),
)
# The controller keeps accepted job receipts under the work directory.
JOBS_NAME = "jobs"
MAX_STATE_BYTES = 2_097_152
MAX_DELIVERABLE_BYTES = 67_108_864


class AssessmentPaused(Exception):
    """The run stopped at a requested phase boundary; --resume continues it."""

    def __init__(self, number: int, total: int, phase: str):
        super().__init__(f"paused after phase {number}/{total} ({phase})")
        self.number, self.total, self.phase = number, total, phase


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
    # The lock is refreshed on this clock, independent of job progress, and
    # states the threshold after which a holder that stopped refreshing it (a
    # process killed with its session) no longer blocks the directory.
    HEARTBEAT_SECONDS = 20
    STALE_AFTER_SECONDS = 60

    def __init__(self, scope, *, configuration, runtime_sha256, budget, resume=False, replace=False):
        if not isinstance(scope, AssessmentScope) or not isinstance(budget, AssessmentBudget):
            raise ExchangeError("Assessment lifecycle requires an admitted scope and full budget")
        if not isinstance(runtime_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", runtime_sha256):
            raise ExchangeError("Assessment lifecycle requires the trusted runtime fingerprint")
        self.scope, self.budget, self.resume, self.replace = scope, budget, resume, replace
        # Component workers poll `should_stop` concurrently; one checkpoint at a time.
        self._checkpoint_lock = threading.RLock()
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
        # Set when --resume continues an unfinished run after a plugin change.
        self.runtime_changed = False
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
            acquire_lock._write_lock(
                self.lock, os.getpid(), now, self.state["run_id"], acquired_ts=now, stale_after=self.STALE_AFTER_SECONDS
            )
            self.lock.chmod(0o600)
            beating = threading.Event()

            def heartbeat():
                while not beating.wait(self.HEARTBEAT_SECONDS):
                    try:
                        self.checkpoint()
                    except Exception:  # noqa: BLE001 - the run's own checkpoints report a lost lock
                        return

            threading.Thread(target=heartbeat, daemon=True).start()
            try:
                self.checkpoint()
                yield self
            except BaseException as error:
                self.state["status"] = (
                    "interrupted"
                    if isinstance(error, (HostCancelled, KeyboardInterrupt, AssessmentPaused))
                    else "failed"
                )
                self.checkpoint()
                raise
            else:
                if self.state["status"] != "complete":
                    self.state["status"] = "interrupted"
                    self.checkpoint()
            finally:
                beating.set()
                acquire_lock.release_lock(self.lock, self.state["run_id"])
                self._held = False

    def _open(self):
        self._check_lock()
        lock_state, _ = acquire_lock._classify_lock(self.lock)
        if lock_state == "fresh":
            raise ExchangeError("Assessment output belongs to another live run")
        if self.resume:
            self.state = _read_state(self.path)
            if self.state["identity"] != self.identity and self._continues_after_plugin_change(self.state):
                # MR-4: the earlier run's accepted jobs stay as a cache that the
                # job layer rechecks per request; this session starts afresh.
                self.resume, self.runtime_changed, self.state = False, True, None
        if self.resume:
            if self.state["identity"] != self.identity:
                again = (
                    "run again with --rebuild"
                    if self.state["status"] == "complete"
                    else "run again without --resume; unchanged model steps are reused"
                )
                raise ExchangeError(
                    f"Assessment cannot resume: {self._changed(self.state['identity'])} changed since it "
                    f"started. A new scan is required: {again}"
                )
            accounting = self.state["accounting"]
            if not math.isfinite(accounting["spent_usd"]):
                raise ExchangeError("Assessment resume cost accounting is invalid")
            if self.state["expires_at"] != self.state["started_at"] + self.budget.timeout_s:
                raise ExchangeError("Assessment resume deadline differs from its original limit")
            if accounting["unavailable"]:
                raise ExchangeError(
                    "Assessment resume cannot reconcile an unfinished cost reservation; rerun the same "
                    "command without --resume, which reuses every accepted job that still matches"
                )
            if (
                accounting["calls"] > self.budget.max_calls
                or accounting["spent_usd"] > self.budget.max_usd
                or self.state["expires_at"] <= time.time()
            ):
                raise ExchangeError("Assessment resume budget is exhausted")
            _real_directory(self.directory)
            self._check_receipts(accounting)
            self.budget.calls = accounting["calls"]
            self.budget.spent_usd = accounting["spent_usd"]
            self.budget.deadline = time.monotonic() + self.state["expires_at"] - time.time()
            for name, expected in self.state["deliverables"].items():
                if _deliverable(self.output, name) != expected:
                    raise ExchangeError("Assessment deliverable changed after completion")
            if self.state["status"] != "complete":
                self.state["status"] = "running"
        else:
            self._discard_unfinished_run()
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
            self.directory.mkdir(mode=0o700, exist_ok=True)

    def _continues_after_plugin_change(self, earlier) -> bool:
        """Whether --resume may continue an unfinished run whose only change is the plugin.

        A completed run, an unknown-cost reservation, or any other identity
        change still refuses the resume.
        """
        unchanged = {key: value for key, value in earlier["identity"].items() if key != "runtime_sha256"}
        return (
            unchanged == {key: value for key, value in self.identity.items() if key != "runtime_sha256"}
            and earlier["status"] != "complete"
            and not earlier["accounting"]["unavailable"]
        )

    def _changed(self, identity) -> str:
        """Name what differs between a stored run identity and this one."""
        changed = [label for key, label in _IDENTITY_LABELS if identity.get(key) != self.identity.get(key)]
        if not changed:
            return "its identity"
        return changed[0] if len(changed) == 1 else ", ".join(changed[:-1]) + " and " + changed[-1]

    def _discard_unfinished_run(self):
        """Clear what an unfinished earlier assessment left, or refuse a fresh start.

        Only its own state file and work directory qualify, and only while the
        state is not complete. Its accepted jobs stay as a cache that the job
        layer rechecks against each new request. A completed run, a deliverable
        or any other file still blocks, so a fresh start never erases a report
        or a user's file; only --rebuild removes an earlier run's own files.
        The refusal names why the earlier run cannot continue.

        In a sole checkout's `docs/security` (MR-6) only the controller's own
        files count: inputs and a legacy report beside them are kept as they are.
        """
        leftovers = {child.name for child in self.output.iterdir()} - {".appsec-lock", ".appsec-lock.guard"}
        if self.scope.output_in_checkout():
            leftovers &= self._own_names()
        if not leftovers:
            return
        if STATE_NAME in leftovers and leftovers <= {STATE_NAME, WORK_NAME}:
            try:
                status = _read_state(self.path)["status"]
            except ExchangeError:
                status = None
            if status not in (None, "complete"):
                if WORK_NAME in leftovers:
                    # Accepted jobs stay as a cache the job layer rechecks
                    # against each new request; everything else is cleared.
                    _real_directory(self.directory)
                    for child in self.directory.iterdir():
                        if child.name == JOBS_NAME:
                            _real_directory(child)
                        elif child.is_dir() and not child.is_symlink():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                self.path.unlink()
                return
        if STATE_NAME in leftovers:
            try:
                earlier = _read_state(self.path)
            except ExchangeError:
                earlier = None
            foreign = self._remove_earlier_run(earlier, leftovers) if self.replace and earlier is not None else None
            if foreign == []:
                return
            fresh = "choose another --output or empty this one"
            if earlier is None:
                message = f"holds an unreadable earlier assessment; {fresh}"
            elif self.replace:
                shown = ", ".join(foreign[:3]) + (", ..." if len(foreign) > 3 else "")
                message = f"holds files the earlier assessment did not write or that changed since ({shown}); {fresh}"
            elif earlier["identity"] != self.identity:
                message = (
                    "holds an earlier assessment that cannot be continued because "
                    f"{self._changed(earlier['identity'])} changed since it started. A new scan is required: "
                    f"add --rebuild to replace it, or {fresh}"
                )
            elif earlier["status"] == "complete":
                message = (
                    "holds a completed combined assessment with nothing left to continue. For a new scan, "
                    f"add --rebuild to replace it, or {fresh}"
                )
            else:
                message = (
                    f"holds an unfinished combined assessment. Add --resume to continue it, or for a new scan, {fresh}"
                )
            raise ExchangeError("This output directory " + message)
        shown = ", ".join(sorted(leftovers)[:3]) + (", ..." if len(leftovers) > 3 else "")
        raise ExchangeError(
            f"A fresh combined assessment needs an empty output directory, and this one contains other files "
            f"({shown}); choose another --output or empty this one"
        )

    def _own_names(self) -> set[str]:
        """The state, work directory and recorded deliverables of an earlier run."""
        names = {STATE_NAME, WORK_NAME}
        if self.path.is_file():
            try:
                names |= set(_read_state(self.path)["deliverables"])
            except ExchangeError:
                pass
        return names

    def _remove_earlier_run(self, earlier, leftovers) -> list[str]:
        """Remove an earlier assessment for --rebuild when it owns every file.

        Owned are its state, its work directory and each recorded deliverable
        whose bytes are unchanged. Any other or edited file keeps the
        directory, so a rebuild never erases a user's file. Returns those
        files, sorted; an empty list means the earlier run was removed.
        """
        owned = {STATE_NAME, WORK_NAME}
        for name, expected in earlier["deliverables"].items():
            try:
                if _deliverable(self.output, name) == expected:
                    owned.add(name)
            except ExchangeError:
                continue
        if self.scope.output_in_checkout():
            # MR-6: an edited deliverable is kept until publication overwrites it.
            leftovers &= owned
        if not leftovers <= owned:
            return sorted(leftovers - owned)
        if WORK_NAME in leftovers:
            _real_directory(self.directory)
            shutil.rmtree(self.directory)
        for name in sorted(leftovers - {STATE_NAME, WORK_NAME}):
            (self.output / name).unlink()
        self.path.unlink()
        return []

    def _check_receipts(self, accounting):
        """Require state accounting to cover every accepted job receipt.

        State also retains reservations of failed calls, so it may exceed the
        receipt totals but never fall below them.
        """
        jobs = self.directory / JOBS_NAME
        if not (jobs.exists() or jobs.is_symlink()):
            return
        _real_directory(jobs)
        validator = Draft202012Validator(json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8")))
        calls, costs = 0, []
        try:
            entries = sorted(entry.name for entry in os.scandir(jobs))
        except OSError:
            raise ExchangeError("Assessment job receipts are unreadable") from None
        for name in entries:
            if not name.endswith(".receipt.json"):
                continue
            match = re.fullmatch(r"(job-[0-9a-f]{24})\.receipt\.json", name)
            receipt = _read_json(jobs / name)
            if (
                match is None
                or not validator.is_valid(receipt)
                or receipt["job_id"] != match.group(1)
                or receipt["scope_sha256"] != self.identity["scope_sha256"]
                or not math.isfinite(receipt["usd"])
            ):
                raise ExchangeError("Assessment job receipt is foreign or malformed")
            calls += receipt["calls"]
            costs.append(receipt["usd"])
            # Stop as soon as receipts exceed the state; this bounds the scan.
            if calls > accounting["calls"]:
                break
        spent = math.fsum(costs)
        if calls > accounting["calls"] or spent > accounting["spent_usd"] + 1e-9 * max(1.0, spent):
            raise ExchangeError("Assessment resume accounting is below its accepted job receipts")

    def _check_lock(self):
        # Link-safe, bounded checks precede any read or in-place write.
        if self.lock.exists() or self.lock.is_symlink():
            metadata = self.lock.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 4096:
                raise ExchangeError("Assessment liveness lock is not a bounded regular file")

    def checkpoint(self):
        with self._checkpoint_lock:
            self._checkpoint()

    def _checkpoint(self):
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
        acquire_lock._write_lock(self.lock, os.getpid(), now, self.state["run_id"], stale_after=self.STALE_AFTER_SECONDS)
        self.lock.chmod(0o600)
        self._last_heartbeat = time.monotonic()

    def should_stop(self):
        if not self._held:
            raise ExchangeError("Assessment lifecycle is not active")
        with self._checkpoint_lock:
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
