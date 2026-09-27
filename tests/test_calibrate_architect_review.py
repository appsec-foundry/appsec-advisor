"""Calibration is explicitly opt-in, bounded and independent of runtime state."""

import json
from copy import deepcopy

import calibrate_architect_review as calibration
import pytest
from architect_review import ReviewError


def fixture():
    return json.loads(calibration.DEFAULT_FIXTURE.read_text(encoding="utf-8"))


def test_default_calibration_prepares_four_calls_without_launching_any(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("offline preparation must never launch a model")

    monkeypatch.setattr(calibration, "run_packet", forbidden)
    result = calibration.calibrate(fixture())
    assert [len(row["jobs"]) for row in result["comparisons"]] == [3, 1]
    assert all(row["application"] is None for row in result["comparisons"])
    assert all(job["status"] == "prepared" for row in result["comparisons"] for job in row["jobs"])
    calibration.validate(result)


def test_live_driver_passes_bound_context_and_records_independent_dispositions(monkeypatch):
    calls = []

    def model(packet, *, model, timeout_seconds, telemetry):
        calls.append((model, timeout_seconds))
        telemetry["usage"] = {"input_tokens": 10, "output_tokens": 5}
        return "completed", {
            **{
                key: packet[key]
                for key in ("schema_version", "run_id", "packet_id", "input_sha256", "context_sha256", "policy_sha256")
            },
            "decisions": [
                {
                    "t_id": row["finding"]["t_id"],
                    "assessment": "unchanged",
                    "remediation": "unresolved",
                    "reason": "The fixture needs independent semantic review.",
                }
                for row in packet["findings"]
            ],
        }

    monkeypatch.setattr(calibration, "run_packet", model)
    original = fixture()
    before = deepcopy(original)
    result = calibration.calibrate(original, live=True)
    assert len(calls) == 4
    assert all(name == "sonnet" and 0 < seconds <= 90 for name, seconds in calls)
    for comparison in result["comparisons"]:
        assert len(comparison["application"]["outcomes"]) == 3
        assert all(row["remediation"] == "unresolved" for row in comparison["application"]["outcomes"])
    assert original == before


def test_stage_deadline_prevents_any_further_call(monkeypatch):
    ticks = iter([0, 1000, 1000, 1000, 1000])
    monkeypatch.setattr(calibration.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(calibration, "run_packet", lambda *_args, **_kwargs: pytest.fail("exhausted stage dispatched"))
    result = calibration.calibrate(fixture(), live=True)
    assert all(job["status"] == "stage_exhausted" for row in result["comparisons"] for job in row["jobs"])
    assert all(
        outcome["status"] == "unreviewed" for row in result["comparisons"] for outcome in row["application"]["outcomes"]
    )


def test_failed_packet_is_not_retried_or_reported_as_success(monkeypatch):
    calls = []

    def failed(*_args, **_kwargs):
        calls.append(1)
        return "deadline_exceeded", None

    monkeypatch.setattr(calibration, "run_packet", failed)
    result = calibration.calibrate(fixture(), live=True)
    assert len(calls) == 4
    assert all(
        outcome["status"] == "unreviewed" for row in result["comparisons"] for outcome in row["application"]["outcomes"]
    )


@pytest.mark.parametrize("mutation", ["rubric", "components", "count", "unknown"])
def test_invalid_fixture_never_dispatches(monkeypatch, mutation):
    value = fixture()
    if mutation == "rubric":
        value["rubric"][0]["t_id"] = "T-999"
    elif mutation == "components":
        value["merged"]["threats"][0]["component_id"] = "unrelated"
    elif mutation == "count":
        value["merged"]["threats"].pop()
    else:
        value["command"] = "run an arbitrary command"
    monkeypatch.setattr(calibration, "run_packet", lambda *_args, **_kwargs: pytest.fail("invalid fixture dispatched"))
    with pytest.raises(ReviewError):
        calibration.calibrate(value, live=True)


@pytest.mark.parametrize("options", [{"live": "false"}, {"live": 1}, {"model": "--tools=Bash"}])
def test_malformed_execution_selection_never_spends_model_budget(monkeypatch, options):
    monkeypatch.setattr(
        calibration, "run_packet", lambda *_args, **_kwargs: pytest.fail("invalid selection dispatched")
    )
    with pytest.raises(ReviewError):
        calibration.calibrate(fixture(), **options)


def test_both_groupings_fit_before_the_first_paid_call(monkeypatch):
    value = fixture()
    for row in value["merged"]["threats"]:
        row["scenario"] = "x" * 6000
    monkeypatch.setattr(
        calibration, "run_packet", lambda *_args, **_kwargs: pytest.fail("unadmitted comparison dispatched")
    )
    with pytest.raises(ReviewError, match="both planned groupings"):
        calibration.calibrate(value, live=True)


def test_cli_writes_only_calibration_artifact_by_default(tmp_path):
    assert calibration.main(["--output-dir", str(tmp_path)]) == 0
    assert [path.name for path in tmp_path.iterdir()] == ["architect-calibration.json"]
    value = json.loads((tmp_path / "architect-calibration.json").read_text())
    assert value["live"] is False
    calibration.validate(value)


def test_cli_retains_failed_live_evidence_without_success_exit(tmp_path, monkeypatch):
    monkeypatch.setattr(calibration, "run_packet", lambda *_args, **_kwargs: ("unavailable", None))
    assert calibration.main(["--output-dir", str(tmp_path), "--live"]) == 2
    value = json.loads((tmp_path / "architect-calibration.json").read_text())
    assert value["live"] is True
    assert all(job["status"] == "unavailable" for comparison in value["comparisons"] for job in comparison["jobs"])


def test_deeply_nested_fixture_is_rejected_before_output_or_dispatch(tmp_path, monkeypatch):
    path = tmp_path / "invalid.json"
    path.write_text("[" * 2000 + "0" + "]" * 2000)
    monkeypatch.setattr(calibration, "run_packet", lambda *_args, **_kwargs: pytest.fail("invalid fixture dispatched"))
    assert calibration.main(["--fixture", str(path), "--output-dir", str(tmp_path), "--live"]) == 1
    assert not (tmp_path / "architect-calibration.json").exists()
