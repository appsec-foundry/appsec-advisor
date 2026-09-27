"""Tests for the deterministic background abuse-verifier waiter."""

from __future__ import annotations

import json

import wait_abuse_progress as wap


def _write_verdict(path, candidate_id: str, *, state: str, reason: str) -> None:
    path.write_text(
        json.dumps(
            {
                "abuse_case_id": candidate_id,
                "step_verdicts": [
                    {
                        "step": 1,
                        "verdict": "inconclusive",
                        "state": state,
                        "reason": reason,
                        "evidence": {"excerpt": ""},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_write_first_preseed_is_pending(tmp_path):
    _write_verdict(
        tmp_path / ".abuse-case-verdict-AC-T-001.json",
        "AC-T-001",
        state="pending",
        reason="pre-seed: checking sink",
    )

    assert wap.candidate_status(tmp_path, "AC-T-001") == "pending"
    assert wap.main([str(tmp_path), "AC-T-001", "--rounds", "1"]) == 1


def test_reasoned_inconclusive_is_complete(tmp_path):
    _write_verdict(
        tmp_path / ".abuse-case-verdict-AC-T-001.json",
        "AC-T-001",
        state="decided",
        reason="The bounded source flow does not establish reachability.",
    )

    assert wap.candidate_status(tmp_path, "AC-T-001") == "complete"
    assert wap.main([str(tmp_path), "AC-T-001", "--rounds", "1"]) == 0


def test_waiter_requires_every_candidate_and_rechecks(tmp_path, monkeypatch):
    states = iter(
        [
            {"AC-T-001": "complete", "AC-T-002": "pending"},
            {"AC-T-001": "complete", "AC-T-002": "complete"},
        ]
    )
    current = {}

    def fake_status(_output_dir, candidate_id):
        nonlocal current
        if candidate_id == "AC-T-001":
            current = next(states)
        return current[candidate_id]

    monkeypatch.setattr(wap, "candidate_status", fake_status)
    slept = []
    monkeypatch.setattr(wap.time, "sleep", lambda seconds: slept.append(seconds))

    assert wap.main([str(tmp_path), "AC-T-001", "AC-T-002"]) == 0
    assert slept == [20]


def test_invalid_or_missing_output_cannot_release_waiter(tmp_path):
    (tmp_path / ".abuse-case-verdict-AC-T-001.json").write_text("{", encoding="utf-8")

    assert wap.candidate_status(tmp_path, "AC-T-001") == "invalid"
    assert wap.candidate_status(tmp_path, "AC-T-002") == "pending"
    assert wap.main([str(tmp_path), "AC-T-001", "AC-T-002", "--rounds", "1"]) == 1


def test_candidate_ids_are_bounded_and_safe(tmp_path):
    assert wap.main([str(tmp_path)]) == 0
    assert wap.main([str(tmp_path), "../escape"]) == 2
    assert wap.main([str(tmp_path), "AC-T-001", "AC-T-001"]) == 2


def test_an_unchanged_count_is_reported_once(tmp_path, monkeypatch, capsys):
    rounds = iter(["pending", "pending", "pending", "complete"])
    monkeypatch.setattr(wap, "candidate_status", lambda _output_dir, _candidate_id: next(rounds))
    monkeypatch.setattr(wap.time, "sleep", lambda seconds: None)

    assert wap.main([str(tmp_path), "AC-T-001"]) == 0
    out = capsys.readouterr().out
    assert out.count("abuse verification 0/1 complete") == 1
    assert out.count("abuse verification 1/1 complete") == 1


def _live_call(job_id: str, spawned_at: float) -> dict:
    return {"state": "running", "job_id": job_id, "spawned_at": spawned_at}


def test_a_slice_ending_on_a_live_verifier_is_repeatable_and_closes_nothing(tmp_path, monkeypatch):
    """A verifier can outlive one Bash call; the waiter must hand back exit 75
    instead of closing a running job, or finalize-abuse re-dispatches a
    duplicate next to it."""
    monkeypatch.setattr(wap, "candidate_status", lambda _o, _c: "pending")
    monkeypatch.setattr(wap.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        wap.agent_lifecycle, "running_calls", lambda _o: [_live_call("phase10c-abuse-AC-T-003", wap.time.time())]
    )
    closed = []
    monkeypatch.setattr(wap, "_close_jobs", lambda _o, ids, **kw: closed.append((ids, kw)))

    assert wap.main([str(tmp_path), "AC-T-003", "--rounds", "2"]) == wap.PENDING_EXIT_CODE
    assert closed == [([], {"success": True})] * 2


def test_a_stopped_or_expired_verifier_still_closes_at_the_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(wap, "candidate_status", lambda _o, _c: "pending")
    monkeypatch.setattr(wap.time, "sleep", lambda _s: None)
    expired = wap.time.time() - wap.wait_agent_calls.DEFAULT_DEADLINE_MINUTES * 60 - 1
    monkeypatch.setattr(
        wap.agent_lifecycle, "running_calls", lambda _o: [_live_call("phase10c-abuse-AC-T-003", expired)]
    )
    closed = []
    monkeypatch.setattr(wap, "_close_jobs", lambda _o, ids, **kw: closed.append((ids, kw)))

    assert wap.main([str(tmp_path), "AC-T-003", "--rounds", "1"]) == 1
    assert closed[-1] == (["AC-T-003"], {"success": False, "reason": "join_deadline_expired"})
