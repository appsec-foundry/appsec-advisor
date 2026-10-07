"""Contracts of the on-demand threat analysis job: request, state, snapshot."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validators import validate_analyst as va  # noqa: E402

JOB = "aj-" + "a" * 32
SHA = "b" * 64
OID = "c" * 40


def _limits() -> dict:
    return {
        "job_seconds": 900,
        "call_seconds": 300,
        "host_calls": 4,
        "evidence_rounds": 2,
        "question_rounds": 2,
        "transport_retries": 1,
        "admitted_files": 3,
        "file_kib": 64,
        "job_kib": 100,
        "response_kib": 64,
        "selected_questions": 40,
        "answer_hours": 72,
    }


def _request(**overrides) -> dict:
    request = {
        "schema_version": 1,
        "job_id": JOB,
        "mode": "review",
        "scope": {"kind": "commits", "base": "main", "head": OID, "comparison": "merge_base"},
        "repository": {"root": "/work/repo"},
        "output_dir": "/work/out",
        "packages": [
            {"id": "appsec/core", "kind": "questions", "version": "1.0.0", "sha256": SHA, "authority": "core"},
        ],
        "limits": _limits(),
        "plugin_version": "0.9.0",
        "requested_at": "2026-10-04T12:00:00Z",
    }
    request.update(overrides)
    return request


def _state(**overrides) -> dict:
    state = {
        "schema_version": 1,
        "job_id": JOB,
        "state": "analyzing",
        "input_fingerprint": SHA,
        "counters": {"host_calls": 1, "evidence_rounds": 0, "question_rounds": 0, "transport_retries": 0},
        "pending_questions": [],
        "terminal_reason": None,
        "updated_at": "2026-10-04T12:00:01Z",
    }
    state.update(overrides)
    return state


def _entry(path: str, side: str = "proposed", change: str = "modified", size: int = 10) -> dict:
    return {"path": path, "side": side, "change": change, "sha256": SHA, "bytes": size}


def _snapshot(**overrides) -> dict:
    snapshot = {
        "schema_version": 1,
        "job_id": JOB,
        "scope_kind": "commits",
        "objects": {"head": OID, "base": OID, "merge_base": OID},
        "admitted": [_entry("src/app.js"), _entry("src/app.js", side="baseline")],
        "excluded": [{"reason": "ignored", "count": 4}, {"path": ".env", "reason": "sensitive", "count": 1}],
        "captured_at": "2026-10-04T12:00:02Z",
    }
    snapshot.update(overrides)
    return snapshot


# --- request ---------------------------------------------------------------


def test_valid_review_and_design_requests_pass():
    assert va.validate_request(_request()) == []
    design = _request(mode="design", scope={"kind": "design", "source": "text", "content_sha256": SHA})
    assert va.validate_request(design) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(unexpected=True),
        lambda r: r.update(job_id="aj-guessable"),
        lambda r: r["scope"].update(base="--upload-pack=evil"),
        lambda r: r["scope"].update(comparison="nearest"),
        lambda r: r.update(output_dir="relative/out"),
        lambda r: r["packages"][0].update(authority="feature_file"),
        lambda r: r["packages"][0].update(command="rm -rf /"),
        lambda r: r["limits"].pop("host_calls"),
        lambda r: r["limits"].update(host_calls=0),
        lambda r: r.update(scope={"kind": "staged", "base": "main"}),
    ],
    ids=[
        "unknown-field",
        "predictable-job-id",
        "option-shaped-revision",
        "unknown-comparison",
        "relative-output",
        "untrusted-authority",
        "package-command",
        "missing-limit",
        "zero-limit",
        "staged-with-revision",
    ],
)
def test_request_schema_rejects_malformed_input(mutate):
    request = _request()
    mutate(request)
    assert va.validate_request(request)


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda r: r.update(mode="design"), "does not match scope"),
        (lambda r: r.update(output_dir="/work/repo/../out"), "output_dir is not a canonical"),
        (lambda r: r["repository"].update(root="//work/repo"), "repository/root is not a canonical"),
        (lambda r: r["limits"].update(call_seconds=901), "call_seconds exceeds"),
        (lambda r: r["limits"].update(file_kib=101), "file_kib exceeds"),
        (lambda r: r["packages"].append(dict(r["packages"][0], authority="explicit")), "selected more than once"),
    ],
)
def test_request_semantics_reject_inconsistent_input(mutate, expected):
    request = _request()
    mutate(request)
    errors = va.validate_request(request)
    assert any(expected in error for error in errors), errors


def test_design_file_requires_its_path():
    request = _request(mode="design", scope={"kind": "design", "source": "file", "content_sha256": SHA})
    assert any("design_path" in error for error in va.validate_request(request))
    request["scope"]["design_path"] = "/work/design.md"
    assert va.validate_request(request) == []


def test_schema_errors_never_echo_rejected_values():
    secret = "AKIA" + "Z" * 16
    request = _request(plugin_version=secret * 10)
    request["scope"]["head"] = secret
    errors = va.validate_request(request)
    assert errors
    assert not any(secret in error for error in errors)


# --- state -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "reason", "pending"),
    [
        ("prepared", None, []),
        ("analyzing", None, []),
        ("awaiting_answers", None, ["q-001"]),
        ("complete", "analysis_complete", []),
        ("complete", "empty_scope", []),
        ("incomplete", "required_answers_missing", ["q-001"]),
        ("failed", "invalid_model_output", []),
        ("cancelled", "terminated", []),
    ],
)
def test_valid_states_pass(state, reason, pending):
    assert va.validate_state(_state(state=state, terminal_reason=reason, pending_questions=pending)) == []


@pytest.mark.parametrize(
    ("state", "reason", "pending"),
    [
        ("complete", None, []),
        ("complete", "limit_exhausted", []),
        ("analyzing", "analysis_complete", []),
        ("complete", "analysis_complete", ["q-001"]),
        ("awaiting_answers", None, []),
    ],
    ids=[
        "terminal-without-reason",
        "complete-with-incomplete-reason",
        "running-with-reason",
        "complete-with-pending",
        "waiting-without-questions",
    ],
)
def test_inconsistent_states_fail(state, reason, pending):
    assert va.validate_state(_state(state=state, terminal_reason=reason, pending_questions=pending))


def test_state_rejects_unknown_state_and_model_shaped_fields():
    assert va.validate_state(_state(state="approved"))
    assert va.validate_state(_state(completed_by_model=True))


def test_state_counters_cannot_exceed_limits():
    state = _state(counters={"host_calls": 5, "evidence_rounds": 0, "question_rounds": 0, "transport_retries": 0})
    assert va.validate_state(state) == []
    assert va.validate_state(state, _limits()) == ["state: counters/host_calls exceeds limits/host_calls"]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("prepared", "analyzing"),
        ("analyzing", "awaiting_answers"),
        ("awaiting_answers", "analyzing"),
        ("analyzing", "complete"),
        ("prepared", "complete"),
    ],
)
def test_allowed_transitions(old, new):
    reason = {"complete": "analysis_complete"}.get(new)
    pending = ["q-001"] if new == "awaiting_answers" else []
    assert (
        va.validate_transition(_state(state=old), _state(state=new, terminal_reason=reason, pending_questions=pending))
        == []
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("complete", "analyzing"),
        ("cancelled", "analyzing"),
        ("failed", "complete"),
        ("prepared", "awaiting_answers"),
        ("awaiting_answers", "complete"),
    ],
)
def test_forbidden_transitions(old, new):
    assert va.validate_transition(_state(state=old), _state(state=new))


def test_transition_rejects_counter_rollback_job_swap_and_silent_input_change():
    previous = _state(counters={"host_calls": 2, "evidence_rounds": 0, "question_rounds": 0, "transport_retries": 0})
    assert va.validate_transition(previous, _state()) == ["transition: counters/host_calls decreased"]
    assert va.validate_transition(_state(), _state(job_id="aj-" + "d" * 32)) == ["transition: job_id changed"]
    changed = _state(input_fingerprint="e" * 64)
    assert va.validate_transition(_state(), changed)
    resumed = va.validate_transition(_state(state="awaiting_answers", pending_questions=["q-001"]), changed)
    assert resumed == []


# --- snapshot --------------------------------------------------------------


def test_valid_snapshots_pass():
    assert va.validate_snapshot(_snapshot(), _request()) == []
    design_request = _request(mode="design", scope={"kind": "design", "source": "text", "content_sha256": SHA})
    design = _snapshot(scope_kind="design", objects={"design_sha256": SHA}, admitted=[], excluded=[])
    assert va.validate_snapshot(design, design_request) == []


@pytest.mark.parametrize(
    "path",
    ["../etc/passwd", "/etc/passwd", "src/../../x", "./src/app.js", "src/./app.js", "a\x00b"],
)
def test_snapshot_rejects_non_relative_or_escaping_paths(path):
    assert va.validate_snapshot(_snapshot(admitted=[_entry(path)]))


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({"objects": {"head": OID}}, "requires objects"),
        ({"scope_kind": "design", "objects": {"design_sha256": SHA, "head": OID}}, "carries no source objects"),
        ({"objects": {"head": OID, "base": OID, "design_sha256": SHA}}, "carries no design hash"),
        ({"admitted": [_entry("a.js"), _entry("a.js")]}, "admitted twice"),
        ({"admitted": [_entry("a.js", change="renamed")]}, "previous_path"),
        ({"excluded": [{"path": ".env", "reason": "sensitive", "count": 2}]}, "count 1"),
    ],
)
def test_snapshot_semantics_reject_inconsistent_views(overrides, expected):
    errors = va.validate_snapshot(_snapshot(**overrides))
    assert any(expected in error for error in errors), errors


def test_snapshot_must_match_its_request_and_limits():
    request = _request()
    assert any("merge_base" in e for e in va.validate_snapshot(_snapshot(objects={"head": OID, "base": OID}), request))
    assert any("job_id" in e for e in va.validate_snapshot(_snapshot(job_id="aj-" + "f" * 32), request))
    many = [_entry(f"f{i}.js") for i in range(4)]
    assert any("admitted_files" in e for e in va.validate_snapshot(_snapshot(admitted=many), request))
    big = [_entry("big.js", size=65 * 1024)]
    assert any("file_kib" in e for e in va.validate_snapshot(_snapshot(admitted=big), request))
    total = [_entry(f"f{i}.js", size=60 * 1024) for i in range(2)]
    assert any("job_kib" in e for e in va.validate_snapshot(_snapshot(admitted=total), request))
    exact = copy.deepcopy(request)
    exact["scope"]["comparison"] = "exact"
    assert va.validate_snapshot(_snapshot(objects={"head": OID, "base": OID}), exact) == []


def test_missing_jsonschema_fails_closed(monkeypatch):
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    assert va.validate_request(_request()) == ["jsonschema not installed; analyst contracts fail closed"]


def test_hypothesis_request_requires_matching_mode_scope_and_text():
    r = _request(
        mode="hypothesis",
        scope={"kind": "hypothesis", "revision": "HEAD", "paths": ["src/api"]},
        hypothesis="Can a caller read another account?",
    )
    assert va.validate_request(r) == []
    for key in ("hypothesis", "mode"):
        invalid = copy.deepcopy(r)
        invalid.pop(key)
        assert va.validate_request(invalid)
    r["mode"] = "review"
    assert va.validate_request(r)


@pytest.mark.parametrize("path", [".", "..", "src/../other", "/etc", "src//api", "src/", "src\\api", "src\napi"])
def test_hypothesis_scope_rejects_noncanonical_paths(path):
    r = _request(
        mode="hypothesis", scope={"kind": "hypothesis", "revision": "HEAD", "paths": [path]}, hypothesis="Check access."
    )
    assert va.validate_request(r)


def test_hypothesis_snapshot_cannot_claim_outside_or_baseline_evidence():
    r = _request(
        mode="hypothesis",
        scope={"kind": "hypothesis", "revision": "HEAD", "paths": ["src"]},
        hypothesis="Check access.",
    )
    s = _snapshot(
        scope_kind="hypothesis", objects={"head": OID}, admitted=[_entry("src/api.py", change="context")], excluded=[]
    )
    assert va.validate_snapshot(s, r) == []
    for e in (_entry("src-other/api.py", change="context"), _entry("src/api.py", side="baseline", change="context")):
        s["admitted"] = [e]
        assert va.validate_snapshot(s, r)
