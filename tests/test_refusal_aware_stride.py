"""A declined analyzer turn is named as such, waited for no longer than needed,
and ends as a declared coverage gap instead of an aborted run (run 5a9d03be).

Every assertion compares a surface to the lifecycle or attempt file it must agree
with, so the rules hold for any component, not the one that exposed them.
"""

from __future__ import annotations

import json
from pathlib import Path

import model.build_threat_model_yaml as tm_yaml
import orchestrator.stride_dispatch_waves as waves
import orchestrator.wait_abuse_progress as wap
import orchestrator.wait_stride_progress as wsp
import pytest
import renderers.pregenerate_fragments as pregen
import runtime.agent_lifecycle as lifecycle
import runtime.agent_logger as agent_logger
import runtime.telemetry_consistency as telemetry

ALL = list(waves.STRIDE_CATEGORIES)


def _manifest(*component_ids: str) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-09-28T12:00:00Z",
        "components": [
            {
                "component_id": cid,
                "component_name": cid.title(),
                "component_paths": [f"src/{cid}.ts"],
                "component_complexity": "moderate",
                "max_turns": 22,
                "index_paths": {
                    "prior_findings": "none",
                    "known_threats": "none",
                    "cross_repo": "none",
                    "requirements_violations": "none",
                    "relevant_actors": "none",
                },
            }
            for cid in component_ids
        ],
    }


def _register(output_dir: Path, job_id: str, *, call_id: str | None = None, attempt: int | None = None) -> str:
    call_id = call_id or "toolu_" + job_id.replace(":", "_").replace("-", "_")
    identity = {
        "agent_call_id": call_id,
        "session_id": "shared01",
        "agent": "stride-analyzer-v2",
        "agent_type": "appsec-advisor:appsec-stride-analyzer-v2",
        "model": "opus",
        "description": "STRIDE",
        "background": True,
        "job_id": job_id,
    }
    if attempt is not None:
        identity.update(component_id=job_id.split(":")[1], attempt=attempt)
    lifecycle.register_call(output_dir, identity)
    return call_id


def _attempt_file(output_dir: Path, component_id: str, attempt: int, *, skipped: list[str], seed: bool = False) -> None:
    path = output_dir / waves.attempt_artifact(component_id, attempt)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "component_id": component_id,
        "component_name": component_id,
        "started_at": "2026-09-28T12:00:00Z",
        "analyzed_at": "2026-09-28T12:00:00Z",
        "partial": True,
        "skipped_categories": skipped,
        "discovery_escapes": [],
        "threats": [],
    }
    if seed:
        body["seed_only"] = True
    path.write_text(json.dumps(body), encoding="utf-8")


# --- lifecycle: the cause of a stop -------------------------------------------------


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        (
            lambda d, c: lifecycle.record_lossy_turns(d, c, refused=1, truncated=0) and lifecycle.finish_call(d, c),
            "refusal",
        ),
        (lambda d, c: lifecycle.fail_call(d, c, "subagent_stop:refusal"), "refusal"),
        (lambda d, c: lifecycle.fail_call(d, c, "subagent_stop:max_turns"), "turn_limit"),
        (lambda d, c: lifecycle.note_child_handback(d, c, at_turn_limit=True), "turn_limit"),
        (lambda d, c: lifecycle.fail_call(d, c, "subagent_stop:api_error"), "api_error"),
        (lambda d, c: lifecycle.finish_call(d, c), None),
        (lambda d, c: lifecycle.record_lossy_turns(d, c, refused=0, truncated=3) and lifecycle.finish_call(d, c), None),
    ],
    ids=[
        "refused-then-clean",
        "refused-last",
        "max-turns",
        "handback-at-limit",
        "other-failure",
        "clean",
        "truncated-only",
    ],
)
def test_job_stop_cause_reads_the_lifecycle(tmp_path: Path, setup, expected) -> None:
    call_id = _register(tmp_path, "stride:api:attempt-1")
    setup(tmp_path, call_id)
    assert lifecycle.job_stop_cause(tmp_path, "stride:api:attempt-1") == expected


def test_job_stop_cause_is_unknown_without_a_call_or_state(tmp_path: Path) -> None:
    assert lifecycle.job_stop_cause(tmp_path, "stride:api:attempt-1") is None
    _register(tmp_path, "stride:web:attempt-1")
    assert lifecycle.job_stop_cause(tmp_path, "stride:api:attempt-1") is None


def test_lossy_turns_are_recorded_once_and_logged_as_warnings(tmp_path: Path) -> None:
    call_id = _register(tmp_path, "stride:api:attempt-1")
    first = lifecycle.record_lossy_turns(tmp_path, call_id, refused=2, truncated=1)
    assert [event.event for event in first] == ["AGENT_TURNS_DECLINED", "AGENT_OUTPUT_TRUNCATED"]
    assert lifecycle.record_lossy_turns(tmp_path, call_id, refused=2, truncated=1) == []
    lifecycle.append_events(tmp_path, first)
    log = (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
    assert "WARN" in log and "AGENT_TURNS_DECLINED" in log and "reason=turns=2" in log
    state = json.loads(lifecycle.state_path(tmp_path).read_text(encoding="utf-8"))
    lifecycle.validate_state(state)


def test_jobs_settled_needs_every_current_call_registered_and_stopped(tmp_path: Path) -> None:
    jobs = ["stride:api:attempt-2", "stride:web:attempt-1"]
    assert lifecycle.jobs_settled(tmp_path, []) is False
    earlier = _register(tmp_path, "stride:api:attempt-1")
    lifecycle.fail_call(tmp_path, earlier, "subagent_stop:refusal")
    web = _register(tmp_path, "stride:web:attempt-1")
    lifecycle.finish_call(tmp_path, web)
    assert lifecycle.jobs_settled(tmp_path, jobs) is False, "a terminal earlier attempt must not settle the retry"
    api = _register(tmp_path, "stride:api:attempt-2")
    assert lifecycle.jobs_settled(tmp_path, jobs) is False, "a running child holds the wave"
    lifecycle.note_child_stop(tmp_path, api)
    assert lifecycle.jobs_settled(tmp_path, jobs) is True


# --- transcript: a declined turn anywhere is seen -----------------------------------


def _transcript(path: Path, reasons: list[str | None]) -> str:
    lines = [json.dumps({"message": {"role": "user", "content": "go"}})]
    lines += [
        json.dumps({"message": {"role": "assistant", "stop_reason": reason, "content": []}}) for reason in reasons
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


@pytest.mark.parametrize(
    ("reasons", "last", "lossy"),
    [
        (["tool_use", "refusal", None, "end_turn"], "end_turn", (1, 0)),
        (["tool_use", "refusal"], "refusal", (1, 0)),
        (["tool_use", "max_tokens", "max_tokens", "stop_sequence"], "stop_sequence", (0, 2)),
        (["tool_use", "end_turn"], "end_turn", (0, 0)),
        (["tool_use", "tool_use"], "tool_use", (0, 0)),
    ],
    ids=["refusal-then-handback", "refusal-last", "truncated", "clean", "cut-off"],
)
def test_transcript_scan_keeps_the_last_reason_and_counts_lossy_turns(tmp_path: Path, reasons, last, lossy) -> None:
    path = _transcript(tmp_path / "child.jsonl", reasons)
    assert agent_logger._stop_reason_from_transcript(path) == last
    assert agent_logger._lossy_turns_from_transcript(path) == lossy


def test_transcript_scan_tolerates_a_missing_file(tmp_path: Path) -> None:
    assert agent_logger._lossy_turns_from_transcript(str(tmp_path / "absent.jsonl")) == (0, 0)
    assert agent_logger._lossy_turns_from_transcript("") == (0, 0)


# --- gate: the reason names the cause ------------------------------------------------


@pytest.mark.parametrize(
    ("stop", "seed", "fragment"),
    [
        ("subagent_stop:refusal", True, waves.REFUSAL_REASON_PREFIX + "no STRIDE category was persisted"),
        ("subagent_stop:refusal", False, waves.REFUSAL_REASON_PREFIX + "categories persisted"),
        ("subagent_stop:max_turns", True, "likely needs a larger turn budget"),
        ("subagent_stop:api_error", True, "analyzer stopped (api_error)"),
        (None, True, "likely needs a larger turn budget"),
        (None, False, "partial is not false"),
    ],
)
def test_gate_reason_follows_the_lifecycle_cause(tmp_path: Path, stop, seed, fragment) -> None:
    _attempt_file(tmp_path, "api", 1, skipped=ALL if seed else ALL[3:], seed=seed)
    call_id = _register(tmp_path, "stride:api:attempt-1", attempt=1)
    if stop:
        lifecycle.fail_call(tmp_path, call_id, stop)
    reason = waves.completion_error(tmp_path, "api", attempt=1)
    assert reason is not None and fragment in reason
    if stop != "subagent_stop:refusal":
        assert not reason.startswith(waves.REFUSAL_REASON_PREFIX)


# --- join: a settled wave returns at once, a live one does not ----------------------


def _claimed_wave(tmp_path: Path, *component_ids: str) -> tuple[dict, dict]:
    manifest = _manifest(*component_ids)
    plan = waves.build_plan(manifest, concurrency=5)
    waves.claim(plan, manifest, tmp_path)
    for cid in component_ids:
        plan["wait_started_at"][cid] = 1
    return plan, manifest


def test_wait_status_settles_once_every_current_attempt_stopped(tmp_path: Path) -> None:
    plan, manifest = _claimed_wave(tmp_path, "api", "web")
    _attempt_file(tmp_path, "api", 1, skipped=ALL, seed=True)
    api = _register(tmp_path, "stride:api:attempt-1", attempt=1)
    web = _register(tmp_path, "stride:web:attempt-1", attempt=1)
    lifecycle.note_child_stop(tmp_path, api)
    assert waves.wait_status(plan, manifest, tmp_path, ["api", "web"], now=10)["status"] == "pending"
    lifecycle.note_child_stop(tmp_path, web)
    assert waves.wait_status(plan, manifest, tmp_path, ["api", "web"], now=10)["status"] == "settled"
    reasons = {
        c["job_id"]: c.get("failure_reason")
        for c in lifecycle.validate_state(json.loads(lifecycle.state_path(tmp_path).read_text(encoding="utf-8")))[
            "calls"
        ]
    }
    assert reasons == {"stride:api:attempt-1": "settled_incomplete", "stride:web:attempt-1": "settled_incomplete"}


def test_wait_status_keeps_an_unregistered_attempt_pending_until_the_deadline(tmp_path: Path) -> None:
    plan, manifest = _claimed_wave(tmp_path, "api")
    assert waves.wait_status(plan, manifest, tmp_path, ["api"], now=10)["status"] == "pending"
    deadline = waves.wave_deadline_seconds(manifest, ["api"])
    assert waves.wait_status(plan, manifest, tmp_path, ["api"], now=1 + deadline)["status"] == "expired"


def _call(output_dir: Path, job_id: str) -> dict:
    state = lifecycle.validate_state(json.loads(lifecycle.state_path(output_dir).read_text(encoding="utf-8")))
    return next(c for c in state["calls"] if c["job_id"] == job_id)


def test_a_live_attempt_holds_its_wave_past_the_deadline(tmp_path: Path) -> None:
    """Expiring a wave closes its job and lets claim() dispatch the next attempt
    beside the analyzer that is still writing; the deadline frees only calls
    that stopped or outlived the ceiling."""
    plan, manifest = _claimed_wave(tmp_path, "api", "web")
    _register(tmp_path, "stride:api:attempt-1", attempt=1)
    web = _register(tmp_path, "stride:web:attempt-1", attempt=1)
    lifecycle.note_child_stop(tmp_path, web)
    spawned = _call(tmp_path, "stride:api:attempt-1")["spawned_at"]
    deadline = waves.wave_deadline_seconds(manifest, ["api", "web"])
    plan["wait_started_at"] = {"api": spawned, "web": spawned}

    status = waves.wait_status(plan, manifest, tmp_path, ["api", "web"], now=spawned + deadline + 60)

    assert status["status"] == "pending"
    assert _call(tmp_path, "stride:api:attempt-1")["state"] == "running"


def test_a_call_past_the_ceiling_no_longer_holds_its_wave(tmp_path: Path) -> None:
    plan, manifest = _claimed_wave(tmp_path, "api")
    _register(tmp_path, "stride:api:attempt-1", attempt=1)
    spawned = _call(tmp_path, "stride:api:attempt-1")["spawned_at"]
    plan["wait_started_at"] = {"api": spawned}

    status = waves.wait_status(plan, manifest, tmp_path, ["api"], now=spawned + waves.WAIT_DEADLINE_CEILING_SECONDS + 1)

    assert status["status"] == "expired"
    assert _call(tmp_path, "stride:api:attempt-1")["failure_reason"] == "join_deadline_expired"


def test_claim_never_dispatches_a_retry_beside_a_live_attempt(tmp_path: Path, monkeypatch) -> None:
    """The cost invariant itself: whatever the waiter reported, a component's
    next attempt is not claimed while its current attempt still runs."""
    plan, manifest = _claimed_wave(tmp_path, "api")
    _attempt_file(tmp_path, "api", 1, skipped=ALL[3:])
    _register(tmp_path, "stride:api:attempt-1", attempt=1)
    spawned = _call(tmp_path, "stride:api:attempt-1")["spawned_at"]
    plan["wait_started_at"] = {"api": spawned}
    late = spawned + waves.wave_deadline_seconds(manifest, ["api"]) + 60
    monkeypatch.setattr(waves.time, "time", lambda: late)

    payload, changed = waves.claim(plan, manifest, tmp_path)

    assert payload["status"] == "in_flight" and changed is False
    assert plan["attempts"]["api"] == 1


def test_stride_waiter_returns_to_the_controller_on_a_settled_wave(tmp_path: Path, monkeypatch) -> None:
    plan, manifest = _claimed_wave(tmp_path, "api")
    (tmp_path / ".dispatch-waves.json").write_text(json.dumps(plan), encoding="utf-8")
    (tmp_path / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    call_id = _register(tmp_path, "stride:api:attempt-1", attempt=1)
    lifecycle.note_child_stop(tmp_path, call_id)
    monkeypatch.setattr(wsp, "_run_progress", lambda *a, **k: (1, ""))
    monkeypatch.setattr(wsp.time, "sleep", lambda _s: pytest.fail("a settled wave must not keep polling"))
    assert wsp.main([str(tmp_path), "1", "--component", "api", "--rounds", "24"]) == 1


def test_abuse_waiter_stops_polling_once_every_verifier_stopped(tmp_path: Path, monkeypatch) -> None:
    for cid in ("AC-T-001", "AC-T-002"):
        call_id = _register(tmp_path, f"phase10c-abuse-{cid}", call_id=f"toolu_{cid.replace('-', '_')}")
        lifecycle.note_child_stop(tmp_path, call_id)
    monkeypatch.setattr(wap.time, "sleep", lambda _s: pytest.fail("stopped verifiers must not keep polling"))
    assert wap.main([str(tmp_path), "AC-T-001", "AC-T-002", "--rounds", "24"]) == 1


def test_abuse_waiter_keeps_polling_while_a_verifier_runs(tmp_path: Path, monkeypatch) -> None:
    _register(tmp_path, "phase10c-abuse-AC-T-001", call_id="toolu_AC_T_001")
    sleeps: list[int] = []
    monkeypatch.setattr(wap.time, "sleep", sleeps.append)
    assert wap.main([str(tmp_path), "AC-T-001", "--rounds", "3", "--interval", "1"]) == wap.PENDING_EXIT_CODE
    assert len(sleeps) == 2


# --- budget: a refusal becomes a declared gap, anything else still aborts ----------


def _exhaust(tmp_path: Path, plan: dict, manifest: dict, component_id: str, stop: str, *, skipped=None) -> None:
    for attempt in (1, 2):
        _attempt_file(tmp_path, component_id, attempt, skipped=skipped or ALL, seed=skipped is None)
        call_id = _register(tmp_path, f"stride:{component_id}:attempt-{attempt}", attempt=attempt)
        lifecycle.fail_call(tmp_path, call_id, stop)
        plan["wait_started_at"][component_id] = 1
        payload, _ = waves.claim(plan, manifest, tmp_path)
    return payload


def test_exhausted_refusal_is_declared_and_the_run_continues(tmp_path: Path) -> None:
    manifest = _manifest("api", "web")
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)
    payload = _exhaust(tmp_path, plan, manifest, "api", "subagent_stop:refusal")
    assert payload["status"] == "claimed"
    assert [c["component_id"] for c in payload["wave"]["components"]] == ["web"]
    declared = json.loads((tmp_path / ".stride-api.json").read_text(encoding="utf-8"))
    assert declared["coverage_declined"] == {"reason": "model_refusal", "attempts": 2, "categories": ALL}
    assert waves.completion_error(tmp_path, "api") is None
    assert "STRIDE_COVERAGE_DECLINED" in (tmp_path / ".agent-run.log").read_text(encoding="utf-8")


def test_declared_gap_keeps_the_categories_an_attempt_persisted(tmp_path: Path) -> None:
    manifest = _manifest("api")
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)
    _exhaust(tmp_path, plan, manifest, "api", "subagent_stop:refusal", skipped=ALL[4:])
    declared = json.loads((tmp_path / ".stride-api.json").read_text(encoding="utf-8"))
    assert declared["skipped_categories"] == declared["coverage_declined"]["categories"] == ALL[4:]
    assert "seed_only" not in declared and declared["partial"] is True


@pytest.mark.parametrize("stop", ["subagent_stop:max_turns", "subagent_stop:api_error"])
def test_other_exhaustion_causes_still_block(tmp_path: Path, stop: str) -> None:
    manifest = _manifest("api")
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)
    payload = _exhaust(tmp_path, plan, manifest, "api", stop)
    assert payload["status"] == "blocked"
    assert not (tmp_path / ".stride-api.json").exists()


def test_cli_still_aborts_a_blocked_claim_after_clearing_the_join(tmp_path: Path) -> None:
    manifest = _manifest("api")
    plan = waves.build_plan(manifest, concurrency=1)
    (tmp_path / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    waves.claim(plan, manifest, tmp_path)
    for attempt in (1, 2):
        call_id = _register(tmp_path, f"stride:api:attempt-{attempt}", attempt=attempt)
        lifecycle.fail_call(tmp_path, call_id, "subagent_stop:max_turns")
        plan["wait_started_at"]["api"] = 1
        if attempt == 1:
            waves.claim(plan, manifest, tmp_path)
    (tmp_path / waves.PLAN_NAME).write_text(json.dumps(plan), encoding="utf-8")
    assert waves.main(["claim", str(tmp_path)]) == 1


# --- report: the gap is stated, never counted as coverage ---------------------------


def test_declined_component_is_its_own_coverage_class(tmp_path: Path) -> None:
    (tmp_path / ".stride-api.json").write_text(
        json.dumps(
            {
                "component_id": "api",
                "threats": [],
                "coverage_declined": {"reason": "model_refusal", "attempts": 2, "categories": ["Tampering"]},
            }
        ),
        encoding="utf-8",
    )
    selection = tm_yaml.build_component_selection(
        {"selected": [{"id": "api"}, {"id": "web", "analysis_depth": "screening"}, "db"], "excluded": []},
        [{"id": "api", "name": "API"}, {"id": "web", "name": "Web"}, {"id": "db", "name": "DB"}],
        tm_yaml.declined_components(tmp_path),
    )
    coverage = pregen.component_coverage({"component_selection": selection})
    assert [e["id"] for e in coverage["declined"]] == ["api"]
    assert [e["id"] for e in coverage["full"]] == ["db"]
    assert [e["id"] for e in coverage["screened"]] == ["web"]
    line = pregen.method_and_limits({"component_selection": selection})
    assert "API was only partly analysed (model declined)" in line
    assert "(Tampering not covered)" in pregen.declined_clause(coverage["declined"])


def test_selection_without_declined_components_is_unchanged(tmp_path: Path) -> None:
    selection = tm_yaml.build_component_selection({"selected": [{"id": "api"}], "excluded": []}, [], {})
    assert "coverage_declined" not in selection["selected"][0]
    assert pregen.component_coverage({"component_selection": selection})["declined"] == []


# --- telemetry: an explained failure is not a mismatch ------------------------------


@pytest.mark.parametrize(
    ("stop", "flagged"),
    [
        ("subagent_stop:refusal", False),
        ("subagent_stop:max_turns", False),
        ("settled_incomplete", False),
        ("subagent_stop:unknown", True),
    ],
)
def test_telemetry_flags_only_unexplained_failures(tmp_path: Path, stop: str, flagged: bool) -> None:
    (tmp_path / ".context-routing-plan.json").write_text(
        json.dumps({"actions": [{"action_id": "stage1c:x", "job_ids": ["stride:api:attempt-1"]}]}), encoding="utf-8"
    )
    lifecycle.register_call(
        tmp_path,
        {
            "agent_call_id": "toolu_api",
            "session_id": "shared01",
            "agent": "stride-analyzer-v2",
            "agent_type": "appsec-advisor:appsec-stride-analyzer-v2",
            "model": "opus",
            "description": "STRIDE",
            "background": False,
            "action_id": "stage1c:x",
            "job_id": "stride:api:attempt-1",
        },
    )
    lifecycle.fail_call(tmp_path, "toolu_api", stop)
    codes = [finding["code"] for finding in telemetry.check_returned_calls(tmp_path)]
    assert ("lifecycle_failed_after_accepted_output" in codes) is flagged


# --- retry: continue from what an earlier attempt persisted -------------------------


def _first_attempt_then_retry(tmp_path: Path, write_first) -> tuple[dict, dict, dict]:
    manifest = _manifest("api")
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)
    write_first(tmp_path)
    call_id = _register(tmp_path, "stride:api:attempt-1", attempt=1)
    lifecycle.fail_call(tmp_path, call_id, "subagent_stop:refusal")
    plan["wait_started_at"]["api"] = 1
    payload, _ = waves.claim(plan, manifest, tmp_path)
    return payload, plan, manifest


def test_retry_resumes_from_the_categories_an_attempt_persisted(tmp_path: Path) -> None:
    payload, _, _ = _first_attempt_then_retry(tmp_path, lambda d: _attempt_file(d, "api", 1, skipped=ALL[2:]))
    assert payload["wave"]["attempts"] == {"api": 2}
    assert payload["wave"]["resumed_from_attempt"] == {"api": 1}
    seeded = json.loads((tmp_path / waves.attempt_artifact("api", 2)).read_text(encoding="utf-8"))
    assert seeded["resumed_from_attempt"] == 1
    assert seeded["skipped_categories"] == ALL[2:]
    assert seeded["partial"] is True and "seed_only" not in seeded


@pytest.mark.parametrize(
    "write_first",
    [
        lambda d: _attempt_file(d, "api", 1, skipped=ALL, seed=True),
        lambda d: _attempt_file(d, "api", 1, skipped=ALL),
        lambda d: None,
        lambda d: (
            (d / waves.attempt_artifact("api", 1)).parent.mkdir(parents=True, exist_ok=True),
            (d / waves.attempt_artifact("api", 1)).write_text("{broken", encoding="utf-8"),
        ),
    ],
    ids=["seed-only", "nothing-persisted", "no-file", "malformed"],
)
def test_retry_starts_fresh_when_nothing_was_persisted(tmp_path: Path, write_first) -> None:
    payload, _, _ = _first_attempt_then_retry(tmp_path, write_first)
    assert "resumed_from_attempt" not in payload["wave"]
    assert not (tmp_path / waves.attempt_artifact("api", 2)).exists()


def test_complete_but_rejected_attempt_goes_to_the_repair_path_not_resume(tmp_path: Path) -> None:
    def complete(d: Path) -> None:
        _attempt_file(d, "api", 1, skipped=[])
        path = d / waves.attempt_artifact("api", 1)
        body = json.loads(path.read_text(encoding="utf-8"))
        body["partial"] = False
        path.write_text(json.dumps(body), encoding="utf-8")

    assert waves.seed_resumed_attempt(tmp_path, "api", 2) is None
    complete(tmp_path)
    assert waves.seed_resumed_attempt(tmp_path, "api", 2) is None


def test_declared_gap_uses_the_resumed_attempts_progress(tmp_path: Path) -> None:
    payload, plan, manifest = _first_attempt_then_retry(tmp_path, lambda d: _attempt_file(d, "api", 1, skipped=ALL[1:]))
    path = tmp_path / waves.attempt_artifact("api", 2)
    body = json.loads(path.read_text(encoding="utf-8"))
    body["skipped_categories"] = ALL[3:]
    path.write_text(json.dumps(body), encoding="utf-8")
    call_id = _register(tmp_path, "stride:api:attempt-2", attempt=2)
    lifecycle.fail_call(tmp_path, call_id, "subagent_stop:refusal")
    plan["wait_started_at"]["api"] = 1
    waves.claim(plan, manifest, tmp_path)
    declared = json.loads((tmp_path / ".stride-api.json").read_text(encoding="utf-8"))
    assert declared["coverage_declined"]["categories"] == ALL[3:]


# --- headless: a self-reported refusal words the diagnosis, nothing more -------------


def test_self_reported_refusal_words_the_reason_without_the_refusal_prefix(tmp_path: Path) -> None:
    _attempt_file(tmp_path, "api", 1, skipped=ALL, seed=True)
    path = tmp_path / waves.attempt_artifact("api", 1)
    body = json.loads(path.read_text(encoding="utf-8"))
    body["declined_turns"] = 1
    path.write_text(json.dumps(body), encoding="utf-8")
    reason = waves.completion_error(tmp_path, "api", attempt=1)
    assert reason is not None and "self-reported" in reason
    assert not reason.startswith(waves.REFUSAL_REASON_PREFIX)


def test_self_reported_refusal_alone_never_declares_a_gap(tmp_path: Path) -> None:
    manifest = _manifest("api")
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)
    for attempt in (1, 2):
        _attempt_file(tmp_path, "api", attempt, skipped=ALL, seed=True)
        path = tmp_path / waves.attempt_artifact("api", attempt)
        body = json.loads(path.read_text(encoding="utf-8"))
        body["declined_turns"] = 1
        path.write_text(json.dumps(body), encoding="utf-8")
        plan["wait_started_at"]["api"] = 1
        payload, _ = waves.claim(plan, manifest, tmp_path)
    assert payload["status"] == "blocked"
    assert not (tmp_path / ".stride-api.json").exists()


def test_lifecycle_refusal_outranks_the_self_report(tmp_path: Path) -> None:
    _attempt_file(tmp_path, "api", 1, skipped=ALL, seed=True)
    call_id = _register(tmp_path, "stride:api:attempt-1", attempt=1)
    lifecycle.fail_call(tmp_path, call_id, "subagent_stop:refusal")
    assert waves.completion_error(tmp_path, "api", attempt=1).startswith(waves.REFUSAL_REASON_PREFIX)
