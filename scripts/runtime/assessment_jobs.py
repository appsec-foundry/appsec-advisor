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
import stat
import time
from pathlib import Path

from jsonschema import Draft202012Validator
from shared._atomic_io import atomic_write_json

from runtime.assessment_host import MAX_EXCHANGES, ExchangeError, ExchangeResult, run_exchange
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


class AssessmentJobs:
    def __init__(self, scope, directory, budget, host_factory, should_stop, checkpoint):
        self.scope = scope
        self.directory = Path(directory)
        self.budget = budget
        self.host_factory = host_factory
        self.should_stop = should_stop
        self.checkpoint = checkpoint
        self.scope_sha256 = scope.inventory()["scope_sha256"]
        if self.directory.exists() and not stat.S_ISDIR(self.directory.lstat().st_mode):
            raise ExchangeError("Assessment job directory must be a real directory")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)

    def execute(self, **kwargs):
        """Return the accepted artifact of one controller-selected job."""
        return self.exchange(**kwargs).artifact

    def exchange(self, *, role, selector, instructions, context, schema, allowed_sources, validate):
        """Execute or resume one job, including its accepted retrieval receipt."""
        if self.should_stop():
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
            receipt = _read_json(receipt_path)
            if (
                not validator.is_valid(receipt)
                or receipt["job_id"] != job_id
                or receipt["role"] != role
                or receipt["request_sha256"] != request_sha256
                or receipt["scope_sha256"] != self.scope_sha256
            ):
                raise ExchangeError("Assessment job receipt is stale or belongs to another request")
            artifact = _read_json(artifact_path)
            if digest(artifact) != receipt["artifact_sha256"]:
                raise ExchangeError("Assessment job artifact changed after acceptance")
            accept(artifact, receipt["source_ranges"])
            slices = tuple(
                self.scope.read(r["repository_id"], r["path"], r["start_line"], r["end_line"])
                for r in receipt["source_ranges"]
            )
            return ExchangeResult(copy.deepcopy(artifact), slices, receipt["calls"], receipt["usd"])

        # Persist the call reservation before the host starts. The caller's
        # checkpoint retains failed/unknown accounting and owns resume policy.
        def factory(ceiling):
            self.checkpoint()
            return self.host_factory(role, ceiling)

        result = run_exchange(
            BudgetedHost(factory, self.budget),
            self.scope,
            instructions=instructions,
            context=context,
            artifact_schema=schema,
            allowed_sources=allowed_sources,
            timeout_s=self.budget.remaining_seconds(),
            should_stop=self.should_stop,
        )
        ranges = [
            {k: row[k] for k in ("repository_id", "path", "sha256", "start_line", "end_line")}
            for row in result.source_slices
        ]
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
        return ExchangeResult(artifact, result.source_slices, result.calls, result.usd)
