"""One bounded, receipted semantic job of the existing assessment controller.

This module has no pipeline, role registry or publication decision. The
controller supplies the role, instructions, contract, scope and successor.
Cached outputs confer no source authority and are revalidated before use.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import stat
import threading
import time
from pathlib import Path

from jsonschema import Draft202012Validator
from shared._atomic_io import atomic_write_json

from runtime.analyst_host import HostTimeout, TransportError
from runtime.assessment_host import MAX_EXCHANGES, ExchangeError, ExchangeResult, ModelAnswerFailure, run_exchange
from runtime.multi_repo_discovery import BudgetedHost, DiscoveryBudget

ROOT = Path(__file__).resolve().parents[2]
RECEIPT_SCHEMA = ROOT / "schemas/assessment-job-receipt.schema.json"
MAX_ARTIFACT_BYTES = 2_097_152
# 1,600 component analyses/verifications, 4,096 connection reviews, and
# bounded architecture/boundary/report jobs, each with at most six exchanges.
MAX_ASSESSMENT_CALLS = (1600 * 2 + 4096 + 500 + 16 * 4 + 16) * MAX_EXCHANGES
MAX_ASSESSMENT_SECONDS = 43_200


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


class AssessmentBudget(DiscoveryBudget):
    """Aggregate the full assessment rather than the discovery phase alone."""

    def __post_init__(self):
        if (
            any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in (self.max_usd, self.call_usd))
            or self.call_usd > self.max_usd
            or type(self.max_calls) is not int
            or not 1 <= self.max_calls <= MAX_ASSESSMENT_CALLS
            or type(self.timeout_s) is not int
            or not 1 <= self.timeout_s <= MAX_ASSESSMENT_SECONDS
            or self.spent_usd != 0
            or self.calls != 0
        ):
            raise ExchangeError("Invalid full-assessment budget")
        self.deadline = time.monotonic() + self.timeout_s
        self.failed = False
        self.init_retries()

    def remaining_seconds(self):
        # Every individual exchange still has the existing one-hour ceiling.
        return min(3600, super().remaining_seconds())


def _read_json(path: Path):
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARTIFACT_BYTES:
            raise ExchangeError("Assessment artifact is not a bounded regular file")
        return json.loads(path.read_text(encoding="utf-8"))
    except ExchangeError:
        raise
    except (OSError, ValueError):
        raise ExchangeError("Assessment artifact is unreadable or malformed") from None


def _ranges(slices) -> list[dict]:
    return [{k: row[k] for k in ("repository_id", "path", "sha256", "start_line", "end_line")} for row in slices]


class AssessmentJobs:
    def __init__(
        self, scope, directory, budget, host_factory, should_stop, checkpoint, *, inherited=False, reuse_inherited=True
    ):
        """`inherited` marks receipts already present as an earlier, unfinished run's cache.

        Such a job is reused only when it still matches its request and passes
        today's acceptance checks, and is redone otherwise; with
        `reuse_inherited` false it is always redone. A receipt this session
        wrote, or a resumed session's, stays strict.
        """
        self.scope = scope
        self.directory = Path(directory)
        self.budget = budget
        self.host_factory = host_factory
        self.should_stop = should_stop
        # MR-16: concurrent jobs share receipts, timing and the checkpoint file.
        self._lock = threading.RLock()

        def locked_checkpoint():
            with self._lock:
                checkpoint()

        self.checkpoint = locked_checkpoint
        self.reuse_inherited = reuse_inherited
        self.scope_sha256 = scope.inventory()["scope_sha256"]
        if self.directory.exists() and not stat.S_ISDIR(self.directory.lstat().st_mode):
            raise ExchangeError("Assessment job directory must be a real directory")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        self._inherited = (
            {path.name.removesuffix(".receipt.json") for path in self.directory.glob("*.receipt.json")}
            if inherited
            else set()
        )
        # Wall time and calls per role of the jobs this session ran; a reused
        # job counts as reused, since its time was spent in an earlier run.
        self.timing: dict[str, dict] = {}
        # Optional jobs replaced after a model failure, in run order (OR-39).
        self.gaps: list[dict] = []
        # Run warnings the controller derives from accepted jobs, in run order.
        self.notes: list[str] = []
        # Coverage statements that need no action, such as files no target covered.
        self.infos: list[str] = []
        # Set by a concurrent caller after a failure: no further job starts (MR-16).
        self.halt = None

    def view(self):
        """Jobs for one concurrently analyzed component, with its own notes and gaps (MR-16).

        Receipts, accounting and timing stay shared; `join` appends the view's
        notes and gaps, so the caller keeps component order whatever finishes first.
        """
        child = copy.copy(self)
        child.notes, child.gaps, child.infos = [], [], []
        return child

    def join(self, child) -> None:
        self.notes.extend(child.notes)
        self.gaps.extend(child.gaps)
        self.infos.extend(child.infos)

    def _record(self, role: str, *, seconds: float | None = None, calls: int = 0) -> None:
        with self._lock:
            row = self.timing.setdefault(role, {"jobs": 0, "reused": 0, "calls": 0, "seconds": 0.0})
            if seconds is None:
                row["reused"] += 1
            else:
                row["jobs"] += 1
                row["calls"] += calls
                row["seconds"] += seconds

    def execute(self, **kwargs):
        """Return the accepted artifact of one controller-selected job."""
        return self.exchange(**kwargs).artifact

    def exchange(
        self,
        *,
        role,
        selector,
        instructions,
        context,
        schema,
        allowed_sources,
        validate,
        normalize=None,
        on_failure=None,
        preload=(),
    ):
        """Execute or resume one job, including its accepted retrieval receipt.

        ``normalize`` derives controller-known fields of each complete result
        before review (see ``run_exchange``); the receipt records the
        normalized artifact. Its identity joins the request, so a changed
        normalizer redoes the job instead of failing a resumed one.

        ``preload`` slices reach the first packet (see ``run_exchange``) and
        join the request identity.

        ``on_failure(reason)`` makes the job optional (decision OR-39): when
        the model returns no acceptable result, a call times out after its
        retries, or the host fails with its cost settled, the job returns that
        deterministic replacement instead of stopping the run, records the gap
        in ``gaps`` and writes no receipt, so a later run retries it. A scope or
        receipt breach, the budget or time limit, a cancellation and unsettled
        accounting still stop the run.
        """
        if self.should_stop() or (self.halt is not None and self.halt.is_set()):
            raise ExchangeError("Assessment cancelled")
        self.budget.remaining_seconds()
        request = {
            "role": role,
            "selector": selector,
            "scope_sha256": self.scope_sha256,
            "instructions_sha256": hashlib.sha256(instructions.encode()).hexdigest(),
            "schema_sha256": digest(schema),
            "context": context,
            "allowed_sources": sorted(allowed_sources),
        }
        if normalize is not None:
            request["normalizer"] = getattr(normalize, "version", None) or normalize.__qualname__
        if preload:
            request["preload"] = [list(key) for key in preload]
        request_sha256 = digest(request)
        job_id = "job-" + digest({"role": role, "selector": selector})[:24]
        artifact_path = self.directory / f"{job_id}.json"
        receipt_path = self.directory / f"{job_id}.receipt.json"
        validator = Draft202012Validator(json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8")))

        def accept(artifact, ranges):
            if not Draft202012Validator(schema).is_valid(artifact):
                raise ExchangeError("Assessment job artifact violates its output contract")
            for row in ranges:
                if (row["repository_id"], row["path"]) not in allowed_sources:
                    raise ExchangeError("Assessment receipt contains an unauthorized source")
                captured = self.scope.read(row["repository_id"], row["path"], row["start_line"], row["end_line"])
                if captured["sha256"] != row["sha256"]:
                    raise ExchangeError("Assessment receipt refers to changed source")
            validate(artifact, ranges)

        if receipt_path.exists() or receipt_path.is_symlink():
            inherited = job_id in self._inherited
            self._inherited.discard(job_id)
            receipt = _read_json(receipt_path)
            current = (
                validator.is_valid(receipt)
                and receipt["job_id"] == job_id
                and receipt["role"] == role
                and receipt["request_sha256"] == request_sha256
                and receipt["scope_sha256"] == self.scope_sha256
            )
            if inherited and not self.reuse_inherited:
                current = False  # A rebuild redoes every earlier run's job.
            if not current and not inherited:
                raise ExchangeError("Assessment job receipt is stale or belongs to another request")
            if current:
                artifact = _read_json(artifact_path)
                # A changed artifact is tampering, not a changed request: never redo it silently.
                if digest(artifact) != receipt["artifact_sha256"]:
                    raise ExchangeError("Assessment job artifact changed after acceptance")
                try:
                    accept(artifact, receipt["source_ranges"])
                except ValueError:
                    if not inherited:
                        raise
                    current = False
            if current:
                if inherited:
                    # The reused calls count against this run, so its accounting covers every receipt.
                    with self.budget._lock:
                        self.budget.calls += receipt["calls"]
                        self.budget.spent_usd += receipt["usd"]
                    self.checkpoint()
                slices = tuple(
                    self.scope.read(r["repository_id"], r["path"], r["start_line"], r["end_line"])
                    for r in receipt["source_ranges"]
                )
                self._record(role)
                return ExchangeResult(copy.deepcopy(artifact), slices, receipt["calls"], receipt["usd"])
            receipt_path.unlink()
            artifact_path.unlink(missing_ok=True)

        # Persist the call reservation before the host starts. The caller's
        # checkpoint retains failed/unknown accounting and owns resume policy.
        def factory(ceiling):
            self.checkpoint()
            return self.host_factory(role, ceiling)

        def review(artifact, slices):
            accept(copy.deepcopy(artifact), _ranges(slices))

        started = time.monotonic()
        try:
            result = run_exchange(
                BudgetedHost(factory, self.budget),
                self.scope,
                instructions=instructions,
                context=context,
                artifact_schema=schema,
                allowed_sources=allowed_sources,
                timeout_s=self.budget.remaining_seconds(),
                should_stop=self.should_stop,
                review=review,
                normalize=normalize,
                preload=preload,
            )
        except (ModelAnswerFailure, HostTimeout, TransportError) as exc:
            # A login or billing failure fails every later call too; it is never replaced.
            operator = isinstance(exc, TransportError) and exc.reason in ("authentication_failed", "billing_error")
            replaceable = not operator and (
                isinstance(exc, (ModelAnswerFailure, HostTimeout)) or not self.budget.unsettled
            )
            if on_failure is None or not replaceable or self.should_stop():
                if isinstance(exc, HostTimeout):
                    # Name the job, so a hang that survived its retry can be traced.
                    raise HostTimeout(f"{selector}: {exc}") from None
                raise
            reason = re.sub(r"\s+", " ", str(exc))[:300]
            self.gaps.append({"role": role, "selector": selector, "reason": reason})
            self._record(role, seconds=time.monotonic() - started)
            return ExchangeResult(on_failure(reason), (), 0, None)
        ranges = _ranges(result.source_slices)
        artifact = copy.deepcopy(result.artifact)
        accept(artifact, ranges)
        receipt = {
            "schema_version": 1,
            "job_id": job_id,
            "role": role,
            "scope_sha256": self.scope_sha256,
            "request_sha256": request_sha256,
            "artifact_sha256": digest(artifact),
            "source_ranges": ranges,
            "calls": result.calls,
            "usd": result.usd,
        }
        validator.validate(receipt)
        atomic_write_json(artifact_path, artifact)
        artifact_path.chmod(0o600)
        atomic_write_json(receipt_path, receipt)
        receipt_path.chmod(0o600)
        self.checkpoint()
        self._record(role, seconds=time.monotonic() - started, calls=result.calls)
        return ExchangeResult(artifact, result.source_slices, result.calls, result.usd)
