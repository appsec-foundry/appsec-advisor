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
