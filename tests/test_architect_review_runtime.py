"""Offline integration of review admission, durable publication and consumers."""

import json
from copy import deepcopy

import analyzers.architect_review_runtime as runtime
import pytest
import yaml
from analyzers.architect_review import ReviewError
from model.build_threat_model_yaml import build_mitigations, build_threats
from model.hydrate_mitigation_details import hydrate

from tests.test_architect_review import decision, finding, merged


def answer(packet):
    return {
        **{
            key: packet[key]
            for key in ("schema_version", "run_id", "packet_id", "input_sha256", "context_sha256", "policy_sha256")
        },
        "decisions": [decision(row["finding"]["t_id"]) for row in packet["findings"]],
    }


def run_agents(tmp_path, jobs, respond=answer, calls=None):
    """Act as the dispatched architect_reviewer agents for one wave."""
    for job in jobs:
        document = json.loads((tmp_path / job["input_artifact"]).read_text())
        assert document["job_id"] == job["job_id"]
        proposals = {}
        for packet in document["packets"]:
            if calls is not None:
                calls.append(packet)
            proposal = respond(packet)
            if proposal is not None:
                proposals[packet["packet_id"]] = proposal
        (tmp_path / job["output_artifact"]).write_text(
            json.dumps({"schema_version": 1, "job_id": job["job_id"], "proposals": proposals})
        )


def review(tmp_path, cfg, respond=answer, calls=None, **kwargs):
    """Drive every wave to completion and return the saved transaction."""
    while jobs := runtime.advance_review(tmp_path, cfg, **kwargs):
        run_agents(tmp_path, jobs, respond, calls)
    return runtime.load_review(tmp_path)


def setup_run(tmp_path, *, component="gateway", filename="routes/orders.py", count=1):
    cfg = {"run_id": "synthetic-run", "architect_review": True, "architect_model": "sonnet", "mode": "full"}
    source = merged(*(finding(f"T-{i:03d}", component, filename) for i in range(1, count + 1)))
    for name, value in (
        (".skill-config.json", cfg),
        (".threats-merged.json", source),
        (".stride-analyst-context.json", {}),
    ):
        (tmp_path / name).write_text(json.dumps(value))
    return cfg, source, []


def model_for(source):
    threats, _ = build_threats(source)
    return {"threats": threats, "mitigations": build_mitigations(threats)}


@pytest.mark.parametrize("component,filename", [("gateway", "routes/orders.py"), ("processor", "lib/records.rs")])
def test_corrections_survive_grouping_hydration_and_repeat_rebuild(tmp_path, component, filename):
    cfg, source, calls = setup_run(tmp_path, component=component, filename=filename, count=2)
    result = review(tmp_path, cfg, calls=calls)
    snapshot = result["snapshot"]
    assert snapshot["threats"][0]["risk"] == "High"
    assert source["threats"][0]["risk"] == "Medium"
    model = runtime.project_model(tmp_path, model_for(snapshot), snapshot)
    hydrate(model)
    assert runtime.verify_model(tmp_path, model) == result
    assert len(model["mitigations"]) == 2
    for threat in model["threats"]:
        assert len(threat["mitigation_ids"]) == len(set(threat["mitigation_ids"]))
    assert {row["priority"] for row in model["mitigations"]} == {"P2"}
    assert runtime.project_model(tmp_path, model, snapshot) == model
    assert review(tmp_path, cfg, calls=calls) == result
    assert len(calls) == 1


def test_disabled_review_does_not_read_sources_or_dispatch(tmp_path):
    assert runtime.advance_review(tmp_path, {"architect_review": False}) is None
    assert runtime.advance_review(tmp_path, {"architect_review": True, "dry_run": True}) is None
    assert list(tmp_path.iterdir()) == []


def test_empty_review_dispatches_nothing_and_records_empty_coverage(tmp_path):
    cfg, source, _ = setup_run(tmp_path)
    source["threats"] = []
    (tmp_path / ".threats-merged.json").write_text(json.dumps(source))
    assert runtime.advance_review(tmp_path, cfg) is None
    result = runtime.load_review(tmp_path)
    assert result["application"]["outcomes"] == []
    assert result["dispatch_jobs"] == []
    assert result["snapshot"] == source
    assert runtime.review_coverage(result)["outcome"] == "reviewed"


def _respond_missing_second(packet):
    return None if packet["packet_id"].endswith("2") else answer(packet)


@pytest.mark.parametrize(
    ("shape", "outcome", "reason", "reviewed"),
    [
        ("all", "reviewed", None, 7),
        ("some-missing", "incomplete", None, 4),
        ("invalid-file", "unavailable", "no_proposals", 0),
        ("none-returned", "unavailable", "no_proposals", 0),
        ("foreign-context", "unavailable", "rejected_proposals", 0),
    ],
)
def test_every_result_shape_is_recorded_explicitly(tmp_path, shape, outcome, reason, reviewed):
    cfg, _, _ = setup_run(tmp_path, count=7)
    jobs = runtime.advance_review(tmp_path, cfg)
    assert [job["packet_count"] for job in jobs] == [3]
    if shape == "invalid-file":
        (tmp_path / jobs[0]["output_artifact"]).write_text("{not json")
    elif shape == "some-missing":
        run_agents(tmp_path, jobs, _respond_missing_second)
    elif shape == "foreign-context":
        run_agents(tmp_path, jobs, lambda packet: {**answer(packet), "context_sha256": "0" * 64})
    elif shape == "all":
        run_agents(tmp_path, jobs)
    assert runtime.advance_review(tmp_path, cfg) is None
    coverage = runtime.review_coverage(runtime.load_review(tmp_path))
    assert (coverage["outcome"], coverage.get("reason"), coverage["reviewed"]) == (outcome, reason, reviewed)
    assert coverage["findings_recorded"] == 7
    assert coverage["jobs_dispatched"] == 1
    runtime.validate_status({"status": "pass", "review_kind": "semantic", **coverage})


def test_waves_respect_concurrency_and_never_repeat_a_returned_job(tmp_path):
    cfg = {"run_id": "synthetic-run", "architect_review": True, "architect_model": "sonnet", "mode": "full"}
    source = merged(*(finding(f"T-{i:03d}", f"svc-{i}", f"src/svc{i}/api.py") for i in range(1, 8)))
    (tmp_path / ".skill-config.json").write_text(json.dumps(cfg))
    (tmp_path / ".threats-merged.json").write_text(json.dumps(source))
    (tmp_path / ".stride-analyst-context.json").write_text("{}")
    first = runtime.advance_review(tmp_path, cfg, concurrency=5)
    assert len(first) == 5 and len({job["component_id"] for job in first}) == 5
    run_agents(tmp_path, first)
    second = runtime.advance_review(tmp_path, cfg, concurrency=5)
    assert len(second) == 2
    assert not {job["job_id"] for job in first} & {job["job_id"] for job in second}
    run_agents(tmp_path, second)
    assert runtime.advance_review(tmp_path, cfg, concurrency=5) is None
    assert runtime.advance_review(tmp_path, cfg, concurrency=5) is None
    result = runtime.load_review(tmp_path)
    assert {job["status"] for job in result["dispatch_jobs"]} == {"returned"}
    assert len(result["application"]["accepted"]) == 7


def test_a_missing_job_is_closed_not_dispatched_again(tmp_path):
    cfg, source, _ = setup_run(tmp_path, count=2)
    assert runtime.advance_review(tmp_path, cfg)
    assert runtime.advance_review(tmp_path, cfg) is None
    result = runtime.load_review(tmp_path)
    assert [job["status"] for job in result["dispatch_jobs"]] == ["missing"]
    assert result["snapshot"] == source
    assert runtime.advance_review(tmp_path, cfg) is None


def test_a_large_component_splits_into_successive_waves(tmp_path):
    cfg, _, _ = setup_run(tmp_path, count=3 * (runtime.JOB_PACKET_LIMIT + 1))
    first = runtime.advance_review(tmp_path, cfg)
    assert [job["packet_count"] for job in first] == [runtime.JOB_PACKET_LIMIT]
    run_agents(tmp_path, first)
    second = runtime.advance_review(tmp_path, cfg)
    assert [job["packet_count"] for job in second] == [1]
    assert second[0]["input_artifact"] == first[0]["input_artifact"]
    run_agents(tmp_path, second)
    assert runtime.advance_review(tmp_path, cfg) is None
    assert runtime.review_coverage(runtime.load_review(tmp_path))["outcome"] == "reviewed"


def test_publication_recovers_without_repeating_the_review(tmp_path, monkeypatch):
    cfg, source, calls = setup_run(tmp_path)
    write = runtime.atomic_write_json

    def crash(path, data):
        if (
            path.name == ".threats-merged.json"
            and json.loads((tmp_path / runtime.ARTIFACT).read_text())["phase"] == "complete"
        ):
            raise OSError("interrupted publication")
        write(path, data)

    monkeypatch.setattr(runtime, "atomic_write_json", crash)
    with pytest.raises(OSError):
        review(tmp_path, cfg, calls=calls)
    assert json.loads((tmp_path / ".threats-merged.json").read_text()) == source
    monkeypatch.setattr(runtime, "atomic_write_json", write)
    result = review(tmp_path, cfg, calls=calls)
    assert json.loads((tmp_path / ".threats-merged.json").read_text()) == result["snapshot"]
    assert len(calls) == 1


@pytest.mark.parametrize("mutation", ["rating", "fix", "drop", "priority"])
def test_final_gate_rejects_lost_corrections_and_clears_old_success(tmp_path, monkeypatch, mutation):
    cfg, _, _ = setup_run(tmp_path)
    result = review(tmp_path, cfg)
    model = runtime.project_model(tmp_path, model_for(result["snapshot"]), result["snapshot"])
    if mutation == "rating":
        model["threats"][0]["risk"] = "Low"
    elif mutation == "fix":
        model["mitigations"][0]["steps"] = ["Log requests."]
    elif mutation == "priority":
        model["mitigations"][0]["priority"] = "P4"
    else:
        model["threats"] = []
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(model))
    (tmp_path / ".architect-status.json").write_text('{"status":"pass"}')
    assert runtime.main(["--output-dir", str(tmp_path)]) == 1
    assert not (tmp_path / ".architect-status.json").exists()


def test_tampered_transaction_and_foreign_run_are_rejected(tmp_path, monkeypatch):
    cfg, _, _ = setup_run(tmp_path)
    result = review(tmp_path, cfg)
    with pytest.raises(ReviewError, match="another run"):
        runtime.advance_review(tmp_path, {**cfg, "run_id": "other"})
    result["snapshot"]["threats"][0]["risk"] = "Low"
    (tmp_path / runtime.ARTIFACT).write_text(json.dumps(result))
    with pytest.raises(ReviewError, match="altered"):
        runtime.load_review(tmp_path)


def test_later_source_changes_are_not_hidden_by_projection(tmp_path, monkeypatch):
    cfg, _, _ = setup_run(tmp_path)
    result = review(tmp_path, cfg)
    changed = deepcopy(result["snapshot"])
    changed["threats"][0]["remediation"]["steps"] = ["Log requests."]
    with pytest.raises(ReviewError, match="source values"):
        runtime.project_model(tmp_path, model_for(changed), changed)


def test_already_correct_findings_remain_unchanged(tmp_path):
    cfg, source, _ = setup_run(tmp_path)

    def unchanged(packet):
        return {
            **answer(packet),
            "decisions": [{"t_id": "T-001", "assessment": "unchanged", "remediation": "unchanged"}],
        }

    result = review(tmp_path, cfg, unchanged)
    assert result["snapshot"] == source
    assert result["application"]["accepted"] == []
    model = model_for(source)
    assert runtime.project_model(tmp_path, model, source) == model


def test_missing_required_review_cannot_close_successfully(tmp_path):
    (tmp_path / ".skill-config.json").write_text('{"architect_review":true,"mode":"full"}')
    (tmp_path / "threat-model.yaml").write_text("threats: []\nmitigations: []\n")
    assert runtime.main(["--output-dir", str(tmp_path)]) == 1
    assert not (tmp_path / ".architect-status.json").exists()


def test_old_rerender_does_not_claim_a_semantic_review(tmp_path, capsys):
    (tmp_path / ".skill-config.json").write_text('{"architect_review":true,"mode":"rerender"}')
    (tmp_path / "threat-model.yaml").write_text("threats: []\nmitigations: []\n")
    assert runtime.main(["--output-dir", str(tmp_path)]) == 0
    assert "not_run" in capsys.readouterr().out


def test_changed_context_cannot_publish_a_stale_model_answer(tmp_path):
    cfg, source, _ = setup_run(tmp_path)

    def mutate_context(packet):
        (tmp_path / ".stride-analyst-context.json").write_text('{"gateway":{}}')
        return {}

    with pytest.raises(ReviewError, match="context changed"):
        review(tmp_path, cfg, mutate_context)
    assert json.loads((tmp_path / ".threats-merged.json").read_text()) == source
    with pytest.raises(ReviewError, match="context changed"):
        runtime.advance_review(tmp_path, cfg)


def test_non_object_yaml_fails_without_a_stale_success(tmp_path):
    (tmp_path / "threat-model.yaml").write_text("- invalid model\n")
    (tmp_path / ".architect-status.json").write_text('{"status":"pass"}')
    assert runtime.main(["--output-dir", str(tmp_path)]) == 1
    assert not (tmp_path / ".architect-status.json").exists()


def test_controller_dispatches_review_then_applies_corrections_before_triage(tmp_path, monkeypatch):
    import orchestrator.orchestration_controller as controller

    cfg, _, calls = setup_run(tmp_path)
    cfg["output_dir"] = str(tmp_path)
    observed = []

    def script(name, args, **kwargs):
        observed.append(name)
        if name == "validators/triage_validate_ratings.py":
            assert json.loads((tmp_path / ".threats-merged.json").read_text())["threats"][0]["risk"] == "High"
            assert len(calls) == 1

    events = []
    monkeypatch.setattr(controller, "_run_script", script)
    monkeypatch.setattr(controller, "_append_event", lambda _out, event, *_a, **_k: events.append(event))
    monkeypatch.setattr(controller, "_context_v2_after_triage", lambda *_a: {"action": "synthesis"})
    action = controller._context_v2_after_evidence(tmp_path, cfg)
    assert action["action"] == "dispatch_parallel"
    assert action["next_boundary"] == "context-v2-post-architect-review"
    assert "validators/triage_validate_ratings.py" not in observed
    job = action["dispatch_jobs"][0]
    assert job["semantic_role"] == "architect_reviewer"
    assert job["agent_type"] == "appsec-advisor:appsec-architect-reviewer"
    assert [receipt["artifact_path"] for receipt in action["artifact_receipts"]] == job["input_artifacts"]
    run_agents(
        tmp_path,
        [
            {
                "job_id": job["job_id"],
                "input_artifact": job["input_artifacts"][0],
                "output_artifact": job["output_artifacts"][0],
            }
        ],
        calls=calls,
    )
    assert controller._context_v2_architect_review(tmp_path, cfg) == {"action": "synthesis"}
    assert observed.index("model/reclassify_components.py") < observed.index("validators/triage_validate_ratings.py")
    assert runtime.load_review(tmp_path)["application"]["accepted"]
    assert "ARCHITECT_REVIEW_COMPLETE" in events and "ORCHESTRATION_GATE_WARN" not in events


def test_controller_warns_when_the_review_decided_nothing(tmp_path, monkeypatch):
    import orchestrator.orchestration_controller as controller

    cfg, _, _ = setup_run(tmp_path)
    cfg["output_dir"] = str(tmp_path)
    events = []
    monkeypatch.setattr(controller, "_run_script", lambda *_a, **_k: None)
    monkeypatch.setattr(controller, "_append_event", lambda _out, event, *_a, **_k: events.append(event))
    monkeypatch.setattr(controller, "_context_v2_after_triage", lambda *_a: {"action": "synthesis"})
    assert controller._context_v2_after_evidence(tmp_path, cfg)["action"] == "dispatch_parallel"
    assert controller._context_v2_architect_review(tmp_path, cfg) == {"action": "synthesis"}
    assert "ORCHESTRATION_GATE_WARN" in events


def test_controller_skips_dispatch_when_review_is_disabled(tmp_path, monkeypatch):
    import orchestrator.orchestration_controller as controller

    cfg, _, _ = setup_run(tmp_path)
    cfg.update(architect_review=False, output_dir=str(tmp_path))
    monkeypatch.setattr(controller, "_run_script", lambda *_a, **_k: None)
    monkeypatch.setattr(controller, "_append_event", lambda *_a, **_k: None)
    monkeypatch.setattr(controller, "_context_v2_after_triage", lambda *_a: {"action": "synthesis"})
    assert controller._context_v2_after_evidence(tmp_path, cfg) == {"action": "synthesis"}
    assert not (tmp_path / runtime.ARTIFACT).exists()


def test_concurrent_boundary_cannot_spend_or_consume_inflight_work(tmp_path, monkeypatch):
    import fcntl
    import os

    cfg, _, calls = setup_run(tmp_path)
    descriptor = os.open(tmp_path, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ReviewError, match="already running"):
            runtime.advance_review(tmp_path, cfg)
        assert calls == []
        assert not (tmp_path / runtime.ARTIFACT).exists()
    finally:
        os.close(descriptor)


def test_scoring_opt_out_is_preserved_through_context_application_and_replay(tmp_path, monkeypatch):
    from analyzers.architect_review import _canonical_valid

    cfg, source, _ = setup_run(tmp_path)
    source["threats"][0]["source"] = "known-vuln"
    cfg["stride_profile"] = {"skip_cvss_scoring": True}
    (tmp_path / ".skill-config.json").write_text(json.dumps(cfg))
    (tmp_path / ".threats-merged.json").write_text(json.dumps(source))
    with pytest.raises(ReviewError):
        _canonical_valid(source)
    _canonical_valid(source, tmp_path)
    result = review(tmp_path, cfg)
    assert result["application"]["accepted"]
    assert runtime.load_review(tmp_path) == result
    import runtime.runtime_cleanup as runtime_cleanup

    runtime_cleanup.run_cleanup(tmp_path, "all", keep_runtime_files=False, force=True)
    assert not (tmp_path / ".skill-config.json").exists()
    assert runtime.load_review(tmp_path) == result
    threats, _ = build_threats(result["snapshot"])
    model = runtime.project_model(
        tmp_path, {"threats": threats, "mitigations": build_mitigations(threats)}, result["snapshot"]
    )
    assert runtime.verify_model(tmp_path, model) == result


def test_scoring_profile_change_during_review_blocks_publication(tmp_path):
    cfg, source, _ = setup_run(tmp_path)

    def change_profile(packet):
        cfg["stride_profile"] = {"skip_cvss_scoring": True}
        (tmp_path / ".skill-config.json").write_text(json.dumps(cfg))
        return answer(packet)

    with pytest.raises(ReviewError, match="scoring profile changed"):
        review(tmp_path, cfg, change_profile)
    assert json.loads((tmp_path / ".threats-merged.json").read_text()) == source


def test_required_review_is_preserved_by_cleanup_and_removed_by_fresh_preflight(tmp_path, monkeypatch):
    import orchestrator.orchestration_controller as controller
    import runtime.runtime_cleanup as runtime_cleanup

    cfg, _, _ = setup_run(tmp_path)
    review(tmp_path, cfg)
    runtime_cleanup.run_cleanup(tmp_path, "all", keep_runtime_files=False, force=True)
    assert (tmp_path / runtime.ARTIFACT).exists()
    assert runtime.ARTIFACT in runtime_cleanup.NEVER
    assert runtime.ARTIFACT in controller._FULL_INTERMEDIATE_NAMES
    assert runtime.ARTIFACT in controller._REBUILD_NAMES
    controller._cleanup_full(tmp_path)
    assert not (tmp_path / runtime.ARTIFACT).exists()


def test_real_yaml_builder_publishes_schema_valid_reviewed_ratings_and_fixes(tmp_path, monkeypatch):
    import sys

    import model.build_threat_model_yaml as builder
    from validators.validate_intermediate import validate_threat_model_output

    cfg, source, _ = setup_run(tmp_path)
    source["threats"][0]["scenario"] = (
        "A signed-in account updates a foreign order because the handler selects only by order ID."
    )
    (tmp_path / ".threats-merged.json").write_text(json.dumps(source))
    (tmp_path / ".components.json").write_text(
        json.dumps({"components": [{"id": "gateway", "name": "Gateway", "kind": "service", "paths": ["routes/"]}]})
    )
    (tmp_path / ".trust-boundaries.json").write_text(json.dumps({"schema_version": 2, "trust_boundaries": []}))
    (tmp_path / ".assets.json").write_text(
        json.dumps({"assets": [{"name": "Orders", "classification": "Confidential"}]})
    )
    (tmp_path / ".security-controls.json").write_text(
        json.dumps(
            {
                "security_controls": [
                    {"domain": "AuthN", "control": "Session authentication", "effectiveness": "Partial"}
                ]
            }
        )
    )
    review(tmp_path, cfg)
    monkeypatch.setattr(sys, "argv", ["model/build_threat_model_yaml.py", str(tmp_path), "--repo-root", str(tmp_path)])
    assert builder.main() == 0
    model = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    valid, errors = validate_threat_model_output(model)
    assert valid, errors
    assert model["threats"][0]["risk"] == "High"
    assert model["mitigations"][0]["steps"] == decision()["fix"]["value"]["steps"]
    assert runtime.verify_model(tmp_path, model)


def test_completion_reports_assessment_and_mitigation_corrections_independently(tmp_path, monkeypatch):
    from renderers.render_completion_summary import _summary_architect

    cfg, _, _ = setup_run(tmp_path)
    result = review(tmp_path, cfg)
    model = runtime.project_model(tmp_path, model_for(result["snapshot"]), result["snapshot"])
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(model))
    assert runtime.main(["--output-dir", str(tmp_path)]) == 0
    summary = _summary_architect(tmp_path, cfg)
    assert "1 assessment(s), 1 mitigation(s) corrected" in summary
    assert "0/1 unresolved or unreviewed" in summary
    status = json.loads((tmp_path / ".architect-status.json").read_text())
    status.update(outcome="incomplete", unresolved_or_unreviewed=1)
    (tmp_path / ".architect-status.json").write_text(json.dumps(status))
    assert "incomplete" in _summary_architect(tmp_path, cfg)
    assert "no validated result" not in _summary_architect(tmp_path, cfg)
    status["assessment_corrected"] = 2
    (tmp_path / ".architect-status.json").write_text(json.dumps(status))
    assert _summary_architect(tmp_path, cfg) == "status unreadable"


def test_generic_mitigation_titles_leave_an_accepted_fix_title_alone(tmp_path):
    import model.emit_general_mitigation_titles as titles

    cfg, _, _ = setup_run(tmp_path)
    result = review(tmp_path, cfg)
    model = runtime.project_model(tmp_path, model_for(result["snapshot"]), result["snapshot"])
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(model))
    assert titles.main([str(tmp_path)]) == 0
    model = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    assert model["mitigations"][0]["title"] == decision()["fix"]["value"]["title"]
    assert runtime.verify_model(tmp_path, model)


def _unsampled_run(tmp_path):
    cfg, source, _ = setup_run(tmp_path)
    source["threats"][0]["evidence_check"] = None
    (tmp_path / ".threats-merged.json").write_text(json.dumps(source))
    result = review(tmp_path, cfg)
    model = runtime.project_model(tmp_path, model_for(result["snapshot"]), result["snapshot"])
    return result, model


def test_evidence_floor_may_fill_the_verdict_of_an_unsampled_reviewed_finding(tmp_path):
    from validators.validate_evidence_lines import persist_to_merged

    _, model = _unsampled_run(tmp_path)
    model["threats"][0]["evidence_check"] = "verified"
    assert persist_to_merged(tmp_path, model) == 1
    assert runtime.verify_model(tmp_path, model)


def test_a_set_evidence_verdict_of_a_reviewed_finding_stays_fixed(tmp_path):
    cfg, _, _ = setup_run(tmp_path)
    result = review(tmp_path, cfg)
    model = runtime.project_model(tmp_path, model_for(result["snapshot"]), result["snapshot"])
    merged_now = deepcopy(result["snapshot"])
    merged_now["threats"][0]["evidence_check"] = "ambiguous"
    (tmp_path / ".threats-merged.json").write_text(json.dumps(merged_now))
    with pytest.raises(ReviewError, match="lost downstream"):
        runtime.verify_model(tmp_path, model)


def _coverage_row(tid, status, reason, assessment=None):
    assessment = assessment or ("unchanged" if status == "accepted" else "unreviewed")
    remediation = "unchanged" if status == "accepted" else "unreviewed"
    return {"t_id": tid, "status": status, "reason": reason, "assessment": assessment, "remediation": remediation}


@pytest.mark.parametrize(
    ("excluded", "expected_outcome", "expected_unresolved", "expected_refuted"),
    [
        ([], "reviewed", 0, 0),
        ([("T-9", "unreviewed", "refuted")], "reviewed", 0, 1),
        ([("T-9", "unreviewed", "oversized")], "incomplete", 1, 0),
        ([("T-9", "unreviewed", "packet_limit")], "incomplete", 1, 0),
        ([("T-9", "unreviewed", "missing_result")], "incomplete", 1, 0),
        ([("T-8", "unreviewed", "refuted"), ("T-9", "unreviewed", "oversized")], "incomplete", 1, 1),
    ],
)
def test_refuted_exclusions_are_not_coverage_gaps(excluded, expected_outcome, expected_unresolved, expected_refuted):
    rows = [_coverage_row("T-1", "accepted", "validated"), _coverage_row("T-2", "accepted", "validated")]
    rows += [_coverage_row(*row) for row in excluded]
    value = {"application": {"outcomes": rows}, "dispatch_jobs": [{"status": "returned"}]}
    coverage = runtime.review_coverage(value)
    runtime.validate_status({"status": "pass", "review_kind": "semantic", **coverage})
    assert coverage["outcome"] == expected_outcome
    assert coverage["unresolved_or_unreviewed"] == expected_unresolved
    assert coverage["excluded_refuted"] == expected_refuted
    assert coverage["findings_recorded"] == len(rows) - expected_refuted


def test_reviewer_unresolved_assessment_still_counts():
    rows = [_coverage_row("T-1", "accepted", "validated", assessment="unresolved")]
    coverage = runtime.review_coverage({"application": {"outcomes": rows}, "dispatch_jobs": []})
    assert coverage["outcome"] == "incomplete"
    assert coverage["unresolved_or_unreviewed"] == 1
