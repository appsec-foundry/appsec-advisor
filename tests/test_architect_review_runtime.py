"""Offline integration of review admission, durable publication and consumers."""

import json
from copy import deepcopy

import architect_review_runtime as runtime
import pytest
import yaml
from architect_review import ReviewError
from build_threat_model_yaml import build_mitigations, build_threats
from hydrate_mitigation_details import hydrate

from tests.test_architect_review import decision, finding, merged


def setup_run(tmp_path, monkeypatch, *, component="gateway", filename="routes/orders.py", count=1):
    cfg = {"run_id": "synthetic-run", "architect_review": True, "architect_model": "sonnet", "mode": "full"}
    source = merged(*(finding(f"T-{i:03d}", component, filename) for i in range(1, count + 1)))
    for name, value in (
        (".skill-config.json", cfg),
        (".threats-merged.json", source),
        (".stride-analyst-context.json", {}),
    ):
        (tmp_path / name).write_text(json.dumps(value))
    calls = []

    def host(packet, **kwargs):
        calls.append(packet)
        kwargs["telemetry"]["wall_seconds"] = 0.01
        return "completed", {
            **{
                key: packet[key]
                for key in ("schema_version", "run_id", "packet_id", "input_sha256", "context_sha256", "policy_sha256")
            },
            "decisions": [decision(row["finding"]["t_id"]) for row in packet["findings"]],
        }

    monkeypatch.setattr(runtime, "run_packet", host)
    return cfg, source, calls


def model_for(source):
    threats, _ = build_threats(source)
    return {"threats": threats, "mitigations": build_mitigations(threats)}


@pytest.mark.parametrize("component,filename", [("gateway", "routes/orders.py"), ("processor", "lib/records.rs")])
def test_corrections_survive_grouping_hydration_and_repeat_rebuild(tmp_path, monkeypatch, component, filename):
    cfg, source, calls = setup_run(tmp_path, monkeypatch, component=component, filename=filename, count=2)
    result = runtime.run_review(tmp_path, cfg)
    snapshot = result["snapshot"]
    assert snapshot["threats"][0]["risk"] == "High"
    assert source["threats"][0]["risk"] == "Medium"
    model = runtime.project_model(tmp_path, model_for(snapshot), snapshot)
    hydrate(model)
    assert runtime.verify_model(tmp_path, model) == result
    assert len(model["mitigations"]) == 2
    assert {row["priority"] for row in model["mitigations"]} == {"P2"}
    assert runtime.project_model(tmp_path, model, snapshot) == model
    assert runtime.run_review(tmp_path, cfg) == result
    assert len(calls) == 1


def test_disabled_review_does_not_read_sources_or_call_model(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "run_packet", lambda *_args, **_kwargs: pytest.fail("paid call"))
    assert runtime.run_review(tmp_path, {"architect_review": False}) is None
    assert runtime.run_review(tmp_path, {"architect_review": True, "dry_run": True}) is None
    assert list(tmp_path.iterdir()) == []


def test_empty_review_has_no_host_call_and_records_empty_coverage(tmp_path, monkeypatch):
    cfg, source, calls = setup_run(tmp_path, monkeypatch)
    source["threats"] = []
    (tmp_path / ".threats-merged.json").write_text(json.dumps(source))
    result = runtime.run_review(tmp_path, cfg)
    assert calls == []
    assert result["application"]["outcomes"] == []
    assert result["snapshot"] == source


def test_stage_deadline_keeps_completed_packets_without_starting_the_rest(tmp_path, monkeypatch):
    cfg, _, calls = setup_run(tmp_path, monkeypatch, count=7)
    clock = iter([0, 0, runtime.STAGE_SECONDS + 1])
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(clock))
    result = runtime.run_review(tmp_path, cfg)
    assert len(calls) == 1
    assert len(result["application"]["accepted"]) == 3
    assert sum(row["status"] == "unreviewed" for row in result["application"]["outcomes"]) == 4


def test_host_failure_stops_further_spending_and_records_coverage(tmp_path, monkeypatch):
    cfg, source, _ = setup_run(tmp_path, monkeypatch, count=7)
    calls = []

    def failed(packet, **kwargs):
        calls.append(packet)
        return "deadline_exceeded", None

    monkeypatch.setattr(runtime, "run_packet", failed)
    result = runtime.run_review(tmp_path, cfg)
    assert len(calls) == 1
    assert result["snapshot"] == source
    assert [j["status"] for j in result["jobs"]] == ["deadline_exceeded", "stage_exhausted", "stage_exhausted"]
    assert len(result["application"]["outcomes"]) == 7
    assert all(row["status"] == "unreviewed" for row in result["application"]["outcomes"])
    runtime.run_review(tmp_path, cfg)
    assert len(calls) == 1


def test_interruption_never_restarts_a_model_call(tmp_path, monkeypatch):
    cfg, source, _ = setup_run(tmp_path, monkeypatch)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime, "run_packet", interrupted)
    with pytest.raises(KeyboardInterrupt):
        runtime.run_review(tmp_path, cfg)
    monkeypatch.setattr(runtime, "run_packet", lambda *_a, **_k: pytest.fail("retry"))
    result = runtime.run_review(tmp_path, cfg)
    assert result["snapshot"] == source
    assert result["jobs"][0]["status"] == "interrupted"


def test_publication_recovers_without_repeating_the_review(tmp_path, monkeypatch):
    cfg, source, calls = setup_run(tmp_path, monkeypatch)
    write = runtime.atomic_write_json

    def crash(path, data):
        if path.name == ".threats-merged.json":
            raise OSError("interrupted publication")
        write(path, data)

    monkeypatch.setattr(runtime, "atomic_write_json", crash)
    with pytest.raises(OSError):
        runtime.run_review(tmp_path, cfg)
    assert json.loads((tmp_path / ".threats-merged.json").read_text()) == source
    monkeypatch.setattr(runtime, "atomic_write_json", write)
    result = runtime.run_review(tmp_path, cfg)
    assert json.loads((tmp_path / ".threats-merged.json").read_text()) == result["snapshot"]
    assert len(calls) == 1


@pytest.mark.parametrize("mutation", ["rating", "fix", "drop", "priority"])
def test_final_gate_rejects_lost_corrections_and_clears_old_success(tmp_path, monkeypatch, mutation):
    cfg, _, _ = setup_run(tmp_path, monkeypatch)
    result = runtime.run_review(tmp_path, cfg)
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
    cfg, _, _ = setup_run(tmp_path, monkeypatch)
    result = runtime.run_review(tmp_path, cfg)
    with pytest.raises(ReviewError, match="another run"):
        runtime.run_review(tmp_path, {**cfg, "run_id": "other"})
    result["snapshot"]["threats"][0]["risk"] = "Low"
    (tmp_path / runtime.ARTIFACT).write_text(json.dumps(result))
    with pytest.raises(ReviewError, match="altered"):
        runtime.load_review(tmp_path)


def test_later_source_changes_are_not_hidden_by_projection(tmp_path, monkeypatch):
    cfg, _, _ = setup_run(tmp_path, monkeypatch)
    result = runtime.run_review(tmp_path, cfg)
    changed = deepcopy(result["snapshot"])
    changed["threats"][0]["remediation"]["steps"] = ["Log requests."]
    with pytest.raises(ReviewError, match="source values"):
        runtime.project_model(tmp_path, model_for(changed), changed)


def test_already_correct_findings_remain_unchanged(tmp_path, monkeypatch):
    cfg, source, _ = setup_run(tmp_path, monkeypatch)

    def unchanged(packet, **kwargs):
        return "completed", {
            **{
                key: packet[key]
                for key in ("schema_version", "run_id", "packet_id", "input_sha256", "context_sha256", "policy_sha256")
            },
            "decisions": [{"t_id": "T-001", "assessment": "unchanged", "remediation": "unchanged"}],
        }

    monkeypatch.setattr(runtime, "run_packet", unchanged)
    result = runtime.run_review(tmp_path, cfg)
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


def test_changed_context_cannot_publish_a_stale_model_answer(tmp_path, monkeypatch):
    cfg, source, _ = setup_run(tmp_path, monkeypatch)

    def mutate_context(packet, **kwargs):
        (tmp_path / ".stride-analyst-context.json").write_text('{"gateway":{}}')
        return "completed", {}

    monkeypatch.setattr(runtime, "run_packet", mutate_context)
    with pytest.raises(ReviewError, match="context changed"):
        runtime.run_review(tmp_path, cfg)
    assert json.loads((tmp_path / ".threats-merged.json").read_text()) == source
    monkeypatch.setattr(runtime, "run_packet", lambda *_a, **_k: pytest.fail("retry"))
    with pytest.raises(ReviewError, match="context changed"):
        runtime.run_review(tmp_path, cfg)


def test_non_object_yaml_fails_without_a_stale_success(tmp_path):
    (tmp_path / "threat-model.yaml").write_text("- invalid model\n")
    (tmp_path / ".architect-status.json").write_text('{"status":"pass"}')
    assert runtime.main(["--output-dir", str(tmp_path)]) == 1
    assert not (tmp_path / ".architect-status.json").exists()


def test_controller_applies_corrections_before_triage_and_synthesis(tmp_path, monkeypatch):
    import orchestration_controller as controller

    cfg, _, calls = setup_run(tmp_path, monkeypatch)
    observed = []

    def script(name, args, **kwargs):
        observed.append(name)
        if name == "triage_validate_ratings.py":
            assert json.loads((tmp_path / ".threats-merged.json").read_text())["threats"][0]["risk"] == "High"
            assert len(calls) == 1

    monkeypatch.setattr(controller, "_run_script", script)
    monkeypatch.setattr(controller, "_append_event", lambda *_a, **_k: None)
    monkeypatch.setattr(controller, "_context_v2_after_triage", lambda *_a: {"action": "synthesis"})
    assert controller._context_v2_after_evidence(tmp_path, cfg) == {"action": "synthesis"}
    assert observed.index("reclassify_components.py") < observed.index("triage_validate_ratings.py")
    assert runtime.load_review(tmp_path)["application"]["accepted"]


def test_concurrent_boundary_cannot_spend_or_consume_inflight_work(tmp_path, monkeypatch):
    import fcntl
    import os

    cfg, _, calls = setup_run(tmp_path, monkeypatch)
    descriptor = os.open(tmp_path, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ReviewError, match="already running"):
            runtime.run_review(tmp_path, cfg)
        assert calls == []
        assert not (tmp_path / runtime.ARTIFACT).exists()
    finally:
        os.close(descriptor)


def test_scoring_opt_out_is_preserved_through_context_application_and_replay(tmp_path, monkeypatch):
    from architect_review import _canonical_valid

    cfg, source, _ = setup_run(tmp_path, monkeypatch)
    source["threats"][0]["source"] = "known-vuln"
    cfg["stride_profile"] = {"skip_cvss_scoring": True}
    (tmp_path / ".skill-config.json").write_text(json.dumps(cfg))
    (tmp_path / ".threats-merged.json").write_text(json.dumps(source))
    with pytest.raises(ReviewError):
        _canonical_valid(source)
    _canonical_valid(source, tmp_path)
    result = runtime.run_review(tmp_path, cfg)
    assert result["application"]["accepted"]
    assert runtime.load_review(tmp_path) == result
    import runtime_cleanup

    runtime_cleanup.run_cleanup(tmp_path, "all", keep_runtime_files=False, force=True)
    assert not (tmp_path / ".skill-config.json").exists()
    assert runtime.load_review(tmp_path) == result
    threats, _ = build_threats(result["snapshot"])
    model = runtime.project_model(
        tmp_path, {"threats": threats, "mitigations": build_mitigations(threats)}, result["snapshot"]
    )
    assert runtime.verify_model(tmp_path, model) == result


def test_scoring_profile_change_during_review_blocks_publication(tmp_path, monkeypatch):
    cfg, source, _ = setup_run(tmp_path, monkeypatch)
    host = runtime.run_packet

    def change_profile(packet, **kwargs):
        cfg["stride_profile"] = {"skip_cvss_scoring": True}
        (tmp_path / ".skill-config.json").write_text(json.dumps(cfg))
        return host(packet, **kwargs)

    monkeypatch.setattr(runtime, "run_packet", change_profile)
    with pytest.raises(ReviewError, match="scoring profile changed"):
        runtime.run_review(tmp_path, cfg)
    assert json.loads((tmp_path / ".threats-merged.json").read_text()) == source


def test_required_review_is_preserved_by_cleanup_and_removed_by_fresh_preflight(tmp_path, monkeypatch):
    import orchestration_controller as controller
    import runtime_cleanup

    cfg, _, _ = setup_run(tmp_path, monkeypatch)
    runtime.run_review(tmp_path, cfg)
    runtime_cleanup.run_cleanup(tmp_path, "all", keep_runtime_files=False, force=True)
    assert (tmp_path / runtime.ARTIFACT).exists()
    assert runtime.ARTIFACT in runtime_cleanup.NEVER
    assert runtime.ARTIFACT in controller._FULL_INTERMEDIATE_NAMES
    assert runtime.ARTIFACT in controller._REBUILD_NAMES
    controller._cleanup_full(tmp_path)
    assert not (tmp_path / runtime.ARTIFACT).exists()


def test_real_yaml_builder_publishes_schema_valid_reviewed_ratings_and_fixes(tmp_path, monkeypatch):
    import sys

    import build_threat_model_yaml as builder
    from validate_intermediate import validate_threat_model_output

    cfg, source, _ = setup_run(tmp_path, monkeypatch)
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
    runtime.run_review(tmp_path, cfg)
    monkeypatch.setattr(sys, "argv", ["build_threat_model_yaml.py", str(tmp_path), "--repo-root", str(tmp_path)])
    assert builder.main() == 0
    model = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    valid, errors = validate_threat_model_output(model)
    assert valid, errors
    assert model["threats"][0]["risk"] == "High"
    assert model["mitigations"][0]["steps"] == decision()["fix"]["value"]["steps"]
    assert runtime.verify_model(tmp_path, model)


def test_completion_reports_assessment_and_mitigation_corrections_independently(tmp_path, monkeypatch):
    from render_completion_summary import _summary_architect

    cfg, _, _ = setup_run(tmp_path, monkeypatch)
    result = runtime.run_review(tmp_path, cfg)
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
