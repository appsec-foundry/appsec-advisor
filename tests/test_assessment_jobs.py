"""Resume rechecks scoped contracts and never grants authority from a receipt."""

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime.analyst_host import HostCancelled, HostReply
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
from runtime.multi_repo_scope import AssessmentScope, RepositoryView

RID = "repo-0123456789abcdef"
SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["result"],
    "properties": {"result": {"type": "string"}},
}


class Host:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = 0

    def invoke(self, *args):
        self.calls += 1
        return HostReply(next(self.replies), 0.01)


def setup(tmp_path, *, replies=None, validate=None, should_stop=lambda: False):
    scope = AssessmentScope(
        (
            RepositoryView(RID, tmp_path / "source", "a" * 40, "b" * 64, {"app.py": b"print('test')\n"}),
            RepositoryView("repo-abcdef0123456789", tmp_path / "peer", "c" * 40, "d" * 64, {"peer.py": b"pass\n"}),
        ),
        tmp_path / "out",
    )
    host = Host(replies or [{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}])
    budget = AssessmentBudget(1.0, 0.05, 10, 60)
    checkpoints = []
    jobs = AssessmentJobs(
        scope,
        tmp_path / "out/jobs",
        budget,
        lambda role, ceiling: host,
        should_stop,
        lambda: checkpoints.append((budget.calls, budget.failed)),
    )
    kwargs = dict(
        role="architecture_analyst",
        selector="one",
        instructions="trusted",
        context={},
        schema=SCHEMA,
        allowed_sources=frozenset({(RID, "app.py")}),
        validate=validate or (lambda artifact, ranges: None),
    )
    return jobs, host, kwargs, checkpoints


def test_accepted_job_is_revalidated_and_reused_without_dispatch(tmp_path):
    seen = []
    jobs, host, kwargs, checkpoints = setup(tmp_path, validate=lambda a, r: seen.append(a["result"]))
    first = jobs.execute(**kwargs)
    first["result"] = "modified by caller"
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    # Reviewed inside the exchange, accepted before the receipt, revalidated on reuse.
    assert host.calls == 1 and seen == ["accepted", "accepted", "accepted"]
    assert checkpoints == [(1, True), (1, False)]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in jobs.directory.iterdir())


@pytest.mark.parametrize(
    "field,value", [("instructions", "different"), ("context", {"changed": True}), ("allowed_sources", frozenset())]
)
def test_changed_request_cannot_reuse_completed_job(tmp_path, field, value):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    kwargs[field] = value
    with pytest.raises(ExchangeError, match="stale"):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_changed_artifact_fails_without_another_call(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    artifact = next(path for path in jobs.directory.iterdir() if not path.name.endswith(".receipt.json"))
    artifact.write_text(json.dumps({"result": "changed"}))
    with pytest.raises(ExchangeError, match="changed"):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_receipt_cannot_replace_artifact_with_an_external_link(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    artifact = next(path for path in jobs.directory.iterdir() if not path.name.endswith(".receipt.json"))
    outside = tmp_path / "external.json"
    outside.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(outside)
    with pytest.raises(ExchangeError, match="regular"):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_rejected_semantics_never_get_a_completion_receipt(tmp_path):
    def reject(artifact, ranges):
        raise ExchangeError("semantics rejected")

    reply = {"action": "complete", "reads": [], "artifact": {"result": "accepted"}}
    jobs, host, kwargs, _ = setup(tmp_path, replies=[reply] * 6, validate=reject)
    with pytest.raises(ExchangeError, match="semantics"):
        jobs.execute(**kwargs)
    assert list(jobs.directory.iterdir()) == []
    # The first result and at most two corrections; no receipt for any of them.
    assert host.calls == 3


def test_a_rejected_result_is_corrected_with_the_controller_reason(tmp_path):
    prompts = []

    def accept_only_corrected(artifact, ranges):
        if artifact["result"] != "corrected":
            raise ExchangeError("result must name the corrected state")

    replies = [
        {"action": "complete", "reads": [], "artifact": {"result": "first"}},
        {"action": "complete", "reads": [], "artifact": {"result": "corrected"}},
    ]
    jobs, host, kwargs, _ = setup(tmp_path, replies=replies, validate=accept_only_corrected)
    original = host.invoke

    def record(*args):
        prompts.append(args[1])
        return original(*args)

    host.invoke = record
    assert jobs.execute(**kwargs) == {"result": "corrected"}
    assert host.calls == 2
    assert "rejected_result" not in prompts[0]
    assert "result must name the corrected state" in prompts[1]


def test_cancellation_stops_even_a_cached_job(tmp_path):
    cancelled = [False]
    jobs, host, kwargs, _ = setup(tmp_path, should_stop=lambda: cancelled[0])
    jobs.execute(**kwargs)
    cancelled[0] = True
    with pytest.raises(ExchangeError, match="cancelled"):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_controller_retrieval_is_receipted_and_rechecked(tmp_path):
    replies = [
        {
            "action": "read",
            "artifact": None,
            "reads": [{"repository_id": RID, "path": "app.py", "start_line": 1, "end_line": 1}],
        },
        {"action": "complete", "reads": [], "artifact": {"result": "accepted"}},
    ]
    seen = []
    jobs, host, kwargs, _ = setup(tmp_path, replies=replies, validate=lambda a, ranges: seen.append(ranges))
    jobs.execute(**kwargs)
    jobs.execute(**kwargs)
    assert len(seen[0]) == 1 and seen[0] == seen[1] and host.calls == 2


@pytest.mark.parametrize("seconds", [0, 43201, True])
def test_assessment_duration_remains_bounded(seconds):
    with pytest.raises(ExchangeError):
        AssessmentBudget(1, 0.1, 10, seconds)


def test_aggregate_deadline_and_unknown_cost_close_dispatch(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.budget.deadline = 0
    with pytest.raises(HostCancelled):
        jobs.execute(**kwargs)
    assert host.calls == 0
    jobs.budget.deadline = time.monotonic() + 60
    jobs.budget.failed = True
    with pytest.raises(ExchangeError):
        jobs.budget.invoke(lambda ceiling: host, "", "", {}, 1, lambda: False)
    assert host.calls == 0


def test_each_host_call_gets_at_most_the_per_call_time_limit(tmp_path):
    from runtime.multi_repo_discovery import MAX_CALL_SECONDS

    granted = []

    class Timed(Host):
        def invoke(self, system, prompt, schema, timeout_s, should_stop):
            granted.append(timeout_s)
            return super().invoke(system, prompt, schema, timeout_s, should_stop)

    jobs, host, kwargs, _ = setup(tmp_path)
    timed = Timed([{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}])
    jobs.host_factory = lambda role, ceiling: timed
    jobs.budget.deadline += 10 * MAX_CALL_SECONDS
    jobs.execute(**kwargs)
    assert granted and all(value <= MAX_CALL_SECONDS for value in granted)


def _inherit(tmp_path, jobs, kwargs, **change):
    """A fresh session over the job directory an unfinished earlier run left."""
    budget = AssessmentBudget(1.0, 0.05, 10, 60)
    host = Host([{"action": "complete", "reads": [], "artifact": {"result": "redone"}}])
    fresh = AssessmentJobs(
        jobs.scope, jobs.directory, budget, lambda role, ceiling: host, lambda: False, lambda: None, inherited=True
    )
    return fresh, host, {**kwargs, **change}


def test_a_fresh_run_reuses_an_earlier_run_s_accepted_job_and_counts_its_cost(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    fresh, fresh_host, request = _inherit(tmp_path, jobs, kwargs)
    assert fresh.execute(**request) == {"result": "accepted"}
    assert fresh_host.calls == 0
    assert (fresh.budget.calls, fresh.budget.spent_usd) == (1, pytest.approx(0.01))


@pytest.mark.parametrize("change", [{"instructions": "changed task"}, {"validate": "reject"}])
def test_an_inherited_job_that_no_longer_fits_is_redone_not_fatal(tmp_path, change):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    if change.get("validate") == "reject":

        def stricter(artifact, ranges):
            if artifact["result"] == "accepted":
                raise ValueError("rule added since the earlier run")

        change = {"validate": stricter}
    fresh, fresh_host, request = _inherit(tmp_path, jobs, kwargs, **change)
    assert fresh.execute(**request) == {"result": "redone"}
    assert fresh_host.calls == 1


def test_an_inherited_job_whose_artifact_changed_still_fails(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.execute(**kwargs)
    artifact = next(path for path in jobs.directory.iterdir() if not path.name.endswith(".receipt.json"))
    artifact.write_text(json.dumps({"result": "changed"}))
    fresh, fresh_host, request = _inherit(tmp_path, jobs, kwargs)
    with pytest.raises(ExchangeError, match="changed"):
        fresh.execute(**request)
    assert fresh_host.calls == 0


class Hanging(Host):
    """Times out for the first `hangs` calls, as a stalled host call does."""

    def __init__(self, hangs, error=None):
        super().__init__([{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}])
        self.hangs, self.error = hangs, error

    def invoke(self, *args):
        self.calls += 1
        if self.calls <= self.hangs:
            from runtime.analyst_host import HostTimeout

            raise (self.error or HostTimeout("host call exceeded its time limit"))
        return HostReply(next(self.replies), 0.01)


def _hanging(tmp_path, host):
    jobs, _, kwargs, _ = setup(tmp_path)
    jobs.host_factory = lambda role, ceiling: host
    return jobs, kwargs


def test_a_hung_call_is_retried_once_with_its_reservation_kept(tmp_path):
    host = Hanging(1)
    jobs, kwargs = _hanging(tmp_path, host)
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert host.calls == 2 and jobs.budget.calls == 2
    # The hung call keeps its full reservation; accounting stays available.
    assert jobs.budget.spent_usd == pytest.approx(0.05 + 0.01) and not jobs.budget.failed


def test_a_second_hang_fails_and_names_its_job(tmp_path):
    from runtime.analyst_host import HostTimeout

    host = Hanging(2)
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(HostTimeout, match="^one: host call exceeded its time limit"):
        jobs.execute(**kwargs)
    assert host.calls == 2


def test_a_cancelled_call_is_never_retried(tmp_path):
    host = Hanging(1, error=HostCancelled("job cancelled"))
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(HostCancelled, match="job cancelled"):
        jobs.execute(**kwargs)
    assert host.calls == 1


class Refused(Host):
    """Fails the first `failures` calls with a settled host error, as an overloaded API does."""

    def __init__(self, failures, reason, usd=0.0):
        super().__init__([{"action": "complete", "reads": [], "artifact": {"result": "accepted"}}])
        self.failures, self.reason, self.usd = failures, reason, usd

    def invoke(self, *args):
        from runtime.analyst_host import TransportError

        self.calls += 1
        if self.calls <= self.failures:
            raise TransportError(f"host call failed: {self.reason}", reason=self.reason, usd=self.usd)
        return HostReply(next(self.replies), 0.01)


@pytest.fixture
def no_retry_wait(monkeypatch):
    from runtime import multi_repo_discovery

    monkeypatch.setattr(multi_repo_discovery, "TRANSIENT_RETRY_DELAYS", (0, 0, 0))


@pytest.mark.parametrize("reason", ["rate_limit", "server_error", "api_error", "no_structured_output"])
def test_a_transient_settled_failure_is_retried_until_the_call_succeeds(tmp_path, no_retry_wait, reason):
    host = Refused(2, reason)
    jobs, kwargs = _hanging(tmp_path, host)
    assert jobs.execute(**kwargs) == {"result": "accepted"}
    assert host.calls == 3 and jobs.budget.calls == 3
    # Refused calls settle at their reported cost; accounting stays available.
    assert jobs.budget.spent_usd == pytest.approx(0.01) and not jobs.budget.failed


def test_a_transient_failure_that_persists_still_stops_a_required_job(tmp_path, no_retry_wait):
    from runtime.analyst_host import TransportError

    host = Refused(10, "rate_limit")
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(TransportError, match="rate_limit.*--resume"):
        jobs.execute(**kwargs)
    assert host.calls == 4 and not jobs.budget.failed


@pytest.mark.parametrize(
    "reason,usd",
    [("authentication_failed", 0.0), ("billing_error", 0.0), ("invalid_request", 0.0), ("error_max_budget_usd", 0.05)],
)
def test_a_failure_a_repeat_cannot_clear_is_not_retried(tmp_path, no_retry_wait, reason, usd):
    from runtime.analyst_host import TransportError

    host = Refused(1, reason, usd)
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(TransportError, match=reason):
        jobs.execute(**kwargs)
    assert host.calls == 1


def test_an_unsettled_failure_is_never_retried(tmp_path, no_retry_wait):
    from runtime.analyst_host import TransportError

    host = Refused(1, "no_result", usd=None)
    jobs, kwargs = _hanging(tmp_path, host)
    with pytest.raises(TransportError, match="no_result"):
        jobs.execute(**kwargs)
    assert host.calls == 1 and jobs.budget.failed


def test_a_retry_wait_ends_when_the_run_is_stopped(tmp_path, monkeypatch):
    from runtime import multi_repo_discovery

    monkeypatch.setattr(multi_repo_discovery, "TRANSIENT_RETRY_DELAYS", (30,))
    stops = iter([False] * 6 + [True] * 10)
    host = Refused(1, "server_error")
    jobs, kwargs = _hanging(tmp_path, host)
    jobs.should_stop = lambda: next(stops)
    started = time.monotonic()
    with pytest.raises((HostCancelled, ExchangeError)):
        jobs.execute(**kwargs)
    assert host.calls == 1 and time.monotonic() - started < 10


def test_the_receipt_records_the_normalized_artifact_and_names_its_normalizer(tmp_path):
    def normalize(artifact):
        artifact["result"] = artifact["result"].upper()
        return artifact

    normalize.version = "upper-1"
    reviewed = []
    jobs, host, kwargs, _ = setup(tmp_path, validate=lambda a, r: reviewed.append(a["result"]))
    assert jobs.execute(**kwargs, normalize=normalize) == {"result": "ACCEPTED"}
    # Resumed from the receipt: the stored result is the normalized one and passes unchanged.
    assert jobs.execute(**kwargs, normalize=normalize) == {"result": "ACCEPTED"}
    assert host.calls == 1 and set(reviewed) == {"ACCEPTED"}
    # A changed normalizer is a changed request, never a silent reuse.
    normalize.version = "upper-2"
    with pytest.raises(ExchangeError, match="stale"):
        jobs.execute(**kwargs, normalize=normalize)


def test_an_optional_job_the_model_cannot_answer_is_replaced_without_a_receipt(tmp_path):
    """OR-39: the replacement stands in, the gap is named, and a later run retries the job."""

    def reject(artifact, ranges):
        raise ValueError("never acceptable")

    replies = [{"action": "complete", "reads": [], "artifact": {"result": "draft"}}] * 3
    jobs, host, kwargs, _ = setup(tmp_path, replies=replies, validate=reject)
    result = jobs.execute(**kwargs, on_failure=lambda reason: {"result": "replacement"})
    assert result == {"result": "replacement"} and host.calls == 3
    assert [gap["selector"] for gap in jobs.gaps] == ["one"] and "never acceptable" in jobs.gaps[0]["reason"]
    assert not list(jobs.directory.glob("*.receipt.json"))


def test_a_required_job_still_stops_on_the_same_failure(tmp_path):
    def reject(artifact, ranges):
        raise ValueError("never acceptable")

    replies = [{"action": "complete", "reads": [], "artifact": {"result": "draft"}}] * 3
    jobs, _, kwargs, _ = setup(tmp_path, replies=replies, validate=reject)
    with pytest.raises(ExchangeError, match="rejected after"):
        jobs.execute(**kwargs)
    assert jobs.gaps == []


@pytest.mark.parametrize("breach", ["scope", "unsettled-cost"])
def test_a_trust_or_accounting_failure_is_never_replaced(tmp_path, breach):
    from runtime.analyst_host import TransportError

    if breach == "scope":
        replies = [
            {
                "action": "read",
                "artifact": None,
                "reads": [{"repository_id": "repo-ffffffffffffffff", "path": "x.py", "start_line": 1, "end_line": 1}],
            }
        ]
        jobs, _, kwargs, _ = setup(tmp_path, replies=replies)
    else:
        jobs, host, kwargs, _ = setup(tmp_path)

        def unsettled(*args):
            raise TransportError("host call failed: no_result", reason="no_result", usd=None)

        host.invoke = unsettled
    with pytest.raises((ExchangeError, TransportError)):
        jobs.execute(**kwargs, on_failure=lambda reason: {"result": "replacement"})
    assert jobs.gaps == []
