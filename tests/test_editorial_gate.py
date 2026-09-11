"""Accepted QA observations survive editorial edits; new defects do not."""

import json
from pathlib import Path

import build_editorial_context as builder
import editorial_gate as gate
import pytest
import yaml


def _action(raw="Existing observation", severity="manual_review"):
    return {
        "type": "reference_format",
        "section_id": "threat_register",
        "raw_issue": raw,
        "severity": severity,
        "fragments_to_rewrite": [],
    }


@pytest.mark.parametrize("exit_code", [0, 3, 4])
def test_existing_observations_are_not_regressions(exit_code):
    keys = gate.action_keys({"actions": [_action()]})
    assert gate.compare({"actions": keys}, exit_code, keys if exit_code == 3 else [])


@pytest.mark.parametrize("exit_code", [1, 2, 5, -9])
def test_blockers_and_tool_errors_never_pass_as_numeric_improvements(exit_code):
    assert not gate.compare({"actions": ["same"]}, exit_code, ["same"])


def test_changed_observation_under_same_action_id_is_a_regression():
    before = gate.action_keys({"actions": [{**_action(), "id": "QA-001"}]})
    after = gate.action_keys({"actions": [{**_action("New broken reference"), "id": "QA-001"}]})
    assert not gate.compare({"actions": before}, 3, after)


def test_new_cosmetic_observation_is_advisory():
    assert gate.compare({"actions": []}, 4, gate.action_keys({"actions": [_action(severity="cosmetic")]}))


def test_increased_multiplicity_and_changed_severity_are_regressions():
    before = gate.action_keys({"actions": [_action()]})
    assert not gate.compare({"actions": before}, 3, before * 2)
    assert not gate.compare({"actions": before}, 3, gate.action_keys({"actions": [_action(severity="blocking")]}))


@pytest.mark.parametrize(
    "plan", [{}, {"actions": ["bad"]}, {"actions": [{}]}, {"actions": [_action(severity="unknown")]}]
)
def test_malformed_observations_fail_closed(plan):
    with pytest.raises(ValueError):
        gate.action_keys(plan)


@pytest.fixture
def run(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "threat-model.yaml").write_text(
        yaml.safe_dump({"threats": [{"risk": "High", "scenario": "The endpoint accepts input."}]})
    )
    (output / "threat-model.md").write_text("Report.\n")
    (output / ".qa-status.json").write_text(
        json.dumps({"status": "pass", "manual_review_items": [{"issue": "Accepted reference format"}]})
    )
    (output / ".qa-repair-plan.json").write_text(json.dumps({"status": "manual_review", "actions": [_action()]}))
    assert builder.main([str(output)]) == 0
    return output


def _argv(command, output):
    return [command, "--output-dir", str(output), "--repo-root", str(output)]


def test_prepare_check_and_close_preserve_triage(run, monkeypatch):
    keys = gate.action_keys({"actions": [_action()]})
    monkeypatch.setattr(gate, "_gate", lambda *_: (3, keys))
    original = json.loads((run / ".qa-status.json").read_text())
    assert gate.main(_argv("prepare", run)) == 0
    assert gate.main(_argv("check", run)) == 0
    (run / ".qa-secret-scan.json").write_text(json.dumps({"check": "unmasked_secrets", "ok": 1, "issues": []}))
    assert gate.main(_argv("close", run)) == 0
    assert json.loads((run / ".qa-status.json").read_text()) == original


def test_same_exit_with_new_issue_fails_then_restored_state_passes(run, monkeypatch):
    keys = gate.action_keys({"actions": [_action()]})
    monkeypatch.setattr(gate, "_gate", lambda *_: (3, keys))
    assert gate.main(_argv("prepare", run)) == 0
    monkeypatch.setattr(gate, "_gate", lambda *_: (3, gate.action_keys({"actions": [_action("New observation")]})))
    assert gate.main(_argv("check", run)) == 1
    assert gate.main(_argv("close", run)) == 2
    monkeypatch.setattr(gate, "_gate", lambda *_: (3, keys))
    assert gate.main(_argv("check", run)) == 0


def test_old_baseline_and_changed_dispositions_are_rejected(run, monkeypatch):
    monkeypatch.setattr(gate, "_gate", lambda *_: (0, []))
    assert gate.main(_argv("prepare", run)) == 0
    status = run / ".qa-status.json"
    status.write_text(json.dumps({"status": "pass", "manual_review_items": []}))
    assert gate.main(_argv("check", run)) == 2
    assert builder.main([str(run)]) == 0
    assert gate.main(_argv("check", run)) == 2


def test_close_requires_fresh_gates_and_no_secret_issue(run, monkeypatch):
    monkeypatch.setattr(gate, "_gate", lambda *_: (0, []))
    assert gate.main(_argv("prepare", run)) == 0
    assert gate.main(_argv("check", run)) == 0
    secret = run / ".qa-secret-scan.json"
    secret.write_text(json.dumps({"check": "unmasked_secrets", "ok": 0, "issues": ["leak"]}))
    assert gate.main(_argv("close", run)) == 2
    secret.write_text(json.dumps({"check": "unmasked_secrets", "ok": 1, "issues": []}))
    (run / "threat-model.md").write_text("Later mutation.\n")
    assert gate.main(_argv("close", run)) == 2


def test_missing_stage3_receipt_is_blocking(run):
    (run / ".qa-status.json").unlink()
    assert gate.main(_argv("prepare", run)) == 2


def test_runtime_uses_packet_dispatch_and_comparison_before_release():
    root = Path(__file__).resolve().parents[1]
    runtime = (root / "skills/create-threat-model/SKILL-thin-stage4.md").read_text()
    assert "at most three concurrent calls" in runtime
    assert "Do not retry a failed packet" in runtime
    assert runtime.index('editorial_gate.py" prepare') < runtime.index("## 2.")
    assert (
        runtime.index('editorial_gate.py" check')
        < runtime.index("unmasked_secrets")
        < runtime.index('editorial_gate.py" close')
    )


def test_failed_gate_cannot_leave_a_previous_success_reusable(run, monkeypatch):
    monkeypatch.setattr(gate, "_gate", lambda *_: (0, []))
    assert gate.main(_argv("prepare", run)) == 0
    assert gate.main(_argv("check", run)) == 0
    (run / ".qa-secret-scan.json").write_text(json.dumps({"check": "unmasked_secrets", "ok": 1, "issues": []}))

    def broken_gate(*_):
        raise ValueError("unreadable result")

    monkeypatch.setattr(gate, "_gate", broken_gate)
    assert gate.main(_argv("check", run)) == 2
    assert gate.main(_argv("close", run)) == 2


def test_close_rejects_a_fragment_changed_after_the_gates(run, monkeypatch):
    monkeypatch.setattr(gate, "_gate", lambda *_: (0, []))
    assert gate.main(_argv("prepare", run)) == 0
    assert gate.main(_argv("check", run)) == 0
    (run / ".qa-secret-scan.json").write_text(json.dumps({"check": "unmasked_secrets", "ok": 1, "issues": []}))
    fragments = run / ".fragments"
    fragments.mkdir()
    (fragments / "security-architecture.md").write_text("Later fragment mutation.")
    assert gate.main(_argv("close", run)) == 2
