"""Calibration is offline, bounded and independent of runtime state."""

import json

import calibrate_architect_review as calibration
import pytest
from analyzers.architect_review import ReviewError


def fixture():
    return json.loads(calibration.DEFAULT_FIXTURE.read_text(encoding="utf-8"))


def test_calibration_prepares_both_groupings_without_a_model():
    result = calibration.calibrate(fixture())
    assert result["live"] is False
    assert [len(row["jobs"]) for row in result["comparisons"]] == [3, 1]
    assert all(row["application"] is None for row in result["comparisons"])
    assert all(job["status"] == "prepared" for row in result["comparisons"] for job in row["jobs"])
    calibration.validate(result)


def test_calibration_has_no_model_transport():
    assert not hasattr(calibration, "run_packet")


@pytest.mark.parametrize("mutation", ["rubric", "components", "count", "unknown"])
def test_invalid_fixture_is_rejected(mutation):
    value = fixture()
    if mutation == "rubric":
        value["rubric"][0]["t_id"] = "T-999"
    elif mutation == "components":
        value["merged"]["threats"][0]["component_id"] = "unrelated"
    elif mutation == "count":
        value["merged"]["threats"].pop()
    else:
        value["command"] = "run an arbitrary command"
    with pytest.raises(ReviewError):
        calibration.calibrate(value)


def test_malformed_model_selection_is_rejected():
    with pytest.raises(ReviewError):
        calibration.calibrate(fixture(), model="--tools=Bash")


def test_both_groupings_must_fit():
    value = fixture()
    for row in value["merged"]["threats"]:
        row["scenario"] = "x" * 6000
    with pytest.raises(ReviewError, match="both planned groupings"):
        calibration.calibrate(value)


def test_cli_writes_only_calibration_artifact(tmp_path):
    assert calibration.main(["--output-dir", str(tmp_path)]) == 0
    assert [path.name for path in tmp_path.iterdir()] == ["architect-calibration.json"]
    value = json.loads((tmp_path / "architect-calibration.json").read_text())
    assert value["live"] is False
    calibration.validate(value)


def test_cli_rejects_the_removed_live_mode(tmp_path):
    with pytest.raises(SystemExit):
        calibration.main(["--output-dir", str(tmp_path), "--live"])
    assert not (tmp_path / "architect-calibration.json").exists()


def test_deeply_nested_fixture_is_rejected_before_output(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("[" * 2000 + "0" + "]" * 2000)
    assert calibration.main(["--fixture", str(path), "--output-dir", str(tmp_path)]) == 1
    assert not (tmp_path / "architect-calibration.json").exists()
