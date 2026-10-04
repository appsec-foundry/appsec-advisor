"""Job roots of the on-demand threat analysis: ownership, locks, cancellation, cleanup."""

from __future__ import annotations

import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from runtime import analyst_state as st  # noqa: E402

SHA = "b" * 64


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "app.js").write_text("app\n")
    return repo


@pytest.fixture
def state_root(tmp_path: Path) -> Path:
    return tmp_path / "state" / "analyst"


def _state(job_id: str, state: str = "prepared", reason: str | None = None, pending: list | None = None) -> dict:
    return {
        "schema_version": 1,
        "job_id": job_id,
        "state": state,
        "input_fingerprint": SHA,
        "counters": {"host_calls": 0, "evidence_rounds": 0, "question_rounds": 0, "transport_retries": 0},
        "pending_questions": pending or [],
        "terminal_reason": reason,
        "updated_at": st.utc_now(),
    }


def _request(job_id: str, repo: Path, out: Path, requested_at: str | None = None) -> dict:
    return {
        "schema_version": 1,
        "job_id": job_id,
        "mode": "review",
        "scope": {"kind": "staged"},
        "repository": {"root": str(repo)},
        "output_dir": str(out),
        "packages": [],
        "limits": {
            "job_seconds": 60,
            "call_seconds": 30,
            "host_calls": 4,
            "evidence_rounds": 2,
            "question_rounds": 2,
            "transport_retries": 1,
            "admitted_files": 10,
            "file_kib": 64,
            "job_kib": 400,
            "response_kib": 64,
            "selected_questions": 40,
            "answer_hours": 72,
        },
        "plugin_version": "0.9.0",
        "requested_at": requested_at or st.utc_now(),
    }


def _tree(path: Path) -> dict[str, bytes]:
    return {str(p.relative_to(path)): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()}


def test_job_root_is_private_unpredictable_and_outside_the_repository(repo, state_root):
    before = _tree(repo)
    first, second = st.create_job(repo, state_root), st.create_job(repo, state_root)
    assert first.job_id != second.job_id
    assert st.JOB_ID_RE.fullmatch(first.job_id)
    assert repo not in first.root.parents
    assert stat.S_IMODE(os.stat(first.root).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(first.root.parent).st_mode) == 0o700
    assert _tree(repo) == before


def test_two_worktrees_never_share_a_job_directory(tmp_path, state_root):
    one, two = tmp_path / "wt-one", tmp_path / "wt-two"
    one.mkdir()
    two.mkdir()
    assert st.create_job(one, state_root).root.parent != st.create_job(two, state_root).root.parent


def test_default_state_root_follows_xdg(tmp_path):
    assert st.default_state_root({"XDG_STATE_HOME": str(tmp_path)}) == tmp_path / "appsec-advisor" / "analyst"


def test_loosened_or_symlinked_repository_directory_is_refused(repo, state_root, tmp_path):
    job = st.create_job(repo, state_root)
    os.chmod(job.root.parent, 0o755)
    with pytest.raises(st.AnalystStateError, match="accessible to other users"):
        st.create_job(repo, state_root)
    os.chmod(job.root.parent, 0o700)
    other = tmp_path / "other-repo"
    other.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (state_root / st.repository_key(other)).symlink_to(elsewhere)
    with pytest.raises(st.AnalystStateError, match="not a directory"):
        st.create_job(other, state_root)


def test_a_job_has_exactly_one_owner(repo, state_root):
    job = st.create_job(repo, state_root)
    with pytest.raises(st.AnalystStateError, match="running controller"):
        st.acquire(job.root)
    st.release(job)
    again = st.acquire(job.root)
    assert again.lock_fd is not None
    st.release(again)


def test_job_lookup_rejects_invalid_ids_and_foreign_repositories(repo, state_root, tmp_path):
    job = st.create_job(repo, state_root)
    assert st.job_path(job.job_id, repo, state_root) == job.root
    for bad in ("../x", "aj-123", job.job_id + "/.."):
        with pytest.raises(st.AnalystStateError, match="invalid job id"):
            st.job_path(bad, repo, state_root)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(st.AnalystStateError, match="no such job"):
        st.job_path(job.job_id, other, state_root)


def test_artifacts_are_validated_named_and_owner_only(repo, state_root, tmp_path):
    job = st.create_job(repo, state_root)
    out = tmp_path / "out"
    st.write_artifact(job, "request.json", _request(job.job_id, repo, out))
    assert st.read_artifact(job.root, "request.json")["job_id"] == job.job_id
    assert stat.S_IMODE(os.stat(job.root / "request.json").st_mode) == 0o600
    with pytest.raises(st.AnalystStateError, match="not an analyst job artifact"):
        st.write_artifact(job, "../escape.json", {})
    bad = _request(job.job_id, repo, out)
    bad["mode"] = "design"
    with pytest.raises(st.AnalystStateError, match="does not match scope"):
        st.write_artifact(job, "request.json", bad)
    st.release(job)
    with pytest.raises(st.AnalystStateError, match="not owned"):
        st.write_artifact(job, "result.md", "text")


def test_symlinked_artifacts_are_neither_followed_on_read_nor_written_through(repo, state_root, tmp_path):
    job = st.create_job(repo, state_root)
    victim = tmp_path / "victim.json"
    victim.write_text('{"keep": true}')
    (job.root / "result.json").symlink_to(victim)
    with pytest.raises(st.AnalystStateError, match="symlink"):
        st.read_artifact(job.root, "result.json")
    st.write_artifact(job, "result.json", {"new": True})
    assert json.loads(victim.read_text()) == {"keep": True}
    assert not (job.root / "result.json").is_symlink()


def test_state_machine_is_enforced_on_publication(repo, state_root):
    job = st.create_job(repo, state_root)
    with pytest.raises(st.AnalystStateError, match="starts in state prepared"):
        st.transition(job, _state(job.job_id, "analyzing"))
    st.transition(job, _state(job.job_id))
    st.transition(job, _state(job.job_id, "analyzing"))
    st.transition(job, _state(job.job_id, "complete", "analysis_complete"))
    with pytest.raises(st.AnalystStateError, match="terminal state complete cannot change"):
        st.transition(job, _state(job.job_id, "analyzing"))
    with pytest.raises(st.AnalystStateError, match="job_id does not match"):
        st.transition(job, _state("aj-" + "e" * 32))
    assert st.read_artifact(job.root, "state.json")["state"] == "complete"


def test_counters_beyond_limits_are_not_published(repo, state_root):
    job = st.create_job(repo, state_root)
    st.transition(job, _state(job.job_id))
    over = _state(job.job_id, "analyzing")
    over["counters"]["host_calls"] = 5
    with pytest.raises(st.AnalystStateError, match="host_calls exceeds"):
        st.transition(job, over, {"host_calls": 4, "evidence_rounds": 2, "question_rounds": 2, "transport_retries": 1})


def test_deadline_is_derived_from_the_request(repo, tmp_path):
    started = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
    request = _request("aj-" + "a" * 32, repo, tmp_path / "out", "2026-10-04T12:00:00Z")
    assert not st.deadline_exceeded(request, started + timedelta(seconds=60))
    assert st.deadline_exceeded(request, started + timedelta(seconds=61))


def test_cancellation_is_requested_by_marker_and_needs_no_ownership(repo, state_root):
    job = st.create_job(repo, state_root)
    assert not st.cancel_requested(job.root)
    st.request_cancel(job.root)
    assert st.cancel_requested(job.root)


def test_cleanup_removes_temporaries_but_keeps_results_and_foreign_files(repo, state_root, tmp_path):
    job = st.create_job(repo, state_root)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    (job.root / "source").mkdir()
    (job.root / "source" / "app.js").write_text("captured")
    (job.root / "source" / "link").symlink_to(outside)
    (job.root / "prompt").symlink_to(outside)
    (job.root / ".tmp-partial").write_text("partial")
    st.write_artifact(job, "result.md", "result")
    st.cleanup_temporaries(job)
    assert sorted(p.name for p in job.root.iterdir()) == ["lock", "result.md"]
    assert (outside / "keep.txt").read_text() == "keep"


def test_discard_requires_ownership_and_removes_only_that_job(repo, state_root):
    keep, gone = st.create_job(repo, state_root), st.create_job(repo, state_root)
    st.release(gone)
    with pytest.raises(st.AnalystStateError, match="not owned"):
        st.discard_job(gone)
    gone = st.acquire(gone.root)
    st.discard_job(gone)
    assert not gone.root.exists()
    assert keep.root.exists()


def test_recovery_closes_only_ownerless_jobs_of_this_repository(repo, state_root, tmp_path):
    crashed, running, finished = (st.create_job(repo, state_root) for _ in range(3))
    for job in (crashed, running, finished):
        st.transition(job, _state(job.job_id))
        st.transition(job, _state(job.job_id, "analyzing"))
    st.transition(finished, _state(finished.job_id, "complete", "analysis_complete"))
    (crashed.root / "source").mkdir()
    st.release(crashed)
    st.release(finished)
    other_repo = tmp_path / "other"
    other_repo.mkdir()
    foreign = st.create_job(other_repo, state_root)
    st.transition(foreign, _state(foreign.job_id))
    st.release(foreign)

    assert st.recover_stale(repo, state_root) == [crashed.job_id]
    closed = st.read_artifact(crashed.root, "state.json")
    assert (closed["state"], closed["terminal_reason"]) == ("cancelled", "terminated")
    assert not (crashed.root / "source").exists()
    assert st.read_artifact(running.root, "state.json")["state"] == "analyzing"
    assert st.read_artifact(finished.root, "state.json")["state"] == "complete"
    assert st.read_artifact(foreign.root, "state.json")["state"] == "prepared"


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        (lambda repo, out: (repo / ".git" / "out"), ".git directory"),
        (lambda repo, out: (out.mkdir(), (out / ".appsec-lock").write_text(""), out)[-1], "assessment output"),
        (
            lambda repo, out: (out.mkdir(), (out / "threat-model.yaml").write_text(""), out / "analyst")[-1],
            "assessment output",
        ),
        (lambda repo, out: (out.mkdir(), (out / "notes.txt").write_text(""), out)[-1], "non-empty"),
        (lambda repo, out: (out.write_text(""), out)[-1], "not a directory"),
    ],
    ids=["git-dir", "assessment-dir", "inside-assessment-dir", "foreign-content", "file"],
)
def test_output_destinations_overlapping_other_state_are_rejected(repo, state_root, tmp_path, setup, expected):
    target = setup(repo, tmp_path / "out")
    errors = st.check_output_dir(target, repo, state_root)
    assert any(expected in error for error in errors), errors


def test_output_overlapping_the_state_root_or_a_symlink_is_rejected(repo, state_root, tmp_path):
    st.create_job(repo, state_root)
    assert any("analyst state root" in e for e in st.check_output_dir(state_root / "x", repo, state_root))
    assert any("analyst state root" in e for e in st.check_output_dir(state_root.parent, repo, state_root))
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    assert any("symlink" in e for e in st.check_output_dir(tmp_path / "link", repo, state_root))


def test_new_empty_or_marked_output_is_accepted(repo, state_root, tmp_path):
    out = tmp_path / "reports" / "analysis"
    assert st.check_output_dir(out, repo, state_root) == []
    st.mark_output_dir(out)
    (out / "result.md").write_text("previous result")
    assert st.check_output_dir(out, repo, state_root) == []


def test_old_terminal_results_expire_and_waiting_jobs_keep_their_window(repo, state_root, tmp_path):
    from datetime import datetime, timedelta, timezone

    done = st.create_job(repo, state_root)
    st.transition(done, _state(done.job_id))
    st.transition(done, _state(done.job_id, "complete", "analysis_complete"))
    st.release(done)
    waiting = st.create_job(repo, state_root)
    st.write_artifact(waiting, "request.json", _request(waiting.job_id, repo, tmp_path / "out"))
    st.transition(waiting, _state(waiting.job_id))
    st.transition(waiting, _state(waiting.job_id, "analyzing"))
    st.transition(waiting, _state(waiting.job_id, "awaiting_answers", pending=["q-001"]))
    (waiting.root / "source").mkdir()
    st.release(waiting)
    now = datetime.now(timezone.utc)

    assert st.recover_stale(repo, state_root, now=now + timedelta(hours=1), result_days=30) == []
    assert done.root.exists() and (waiting.root / "source").exists()

    assert st.recover_stale(repo, state_root, now=now + timedelta(days=31), result_days=30) == [waiting.job_id]
    assert not done.root.exists()
    closed = st.read_artifact(waiting.root, "state.json")
    assert (closed["state"], closed["terminal_reason"]) == ("incomplete", "required_answers_missing")
    assert not (waiting.root / "source").exists()
