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
    assert host.calls == 1 and seen == ["accepted", "accepted"]
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

    jobs, host, kwargs, _ = setup(tmp_path, validate=reject)
    with pytest.raises(ExchangeError, match="semantics"):
        jobs.execute(**kwargs)
    assert list(jobs.directory.iterdir()) == []
    assert host.calls == 1


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
