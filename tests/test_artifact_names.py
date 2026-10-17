"""One naming set per directory; published names for internal artifacts."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from shared import artifact_names as names  # noqa: E402


@pytest.mark.parametrize(
    "internal,published",
    [
        ("threat-model.md", "security-assessment.md"),
        ("threat-model.yaml", "security-assessment.yaml"),
        ("threat-model.figure1-dark.svg", "security-assessment.figure1-dark.svg"),
        ("threat-model.sarif.json", "security-assessment.sarif.json"),
        ("threat-model-changelog.jsonl", "security-assessment-changelog.jsonl"),
        ("threat-model-juice.md", "security-assessment-juice.md"),
        ("pentest-tasks.yaml", "pentest-tasks.yaml"),
        ("threat-modeling-context.md", "threat-modeling-context.md"),
    ],
)
def test_published_name(internal, published):
    assert names.published_name(internal) == published


def test_each_set_is_found_by_its_own_files(tmp_path):
    assert names.artifact_stem(tmp_path) is None
    assert names.model_path(tmp_path) == tmp_path / "security-assessment.yaml"
    (tmp_path / "threat-model.md").write_text("x")
    assert names.report_path(tmp_path) == tmp_path / "threat-model.md"
    assert names.model_path(tmp_path) == tmp_path / "threat-model.yaml"


def test_a_published_set_is_preferred_only_when_alone(tmp_path):
    (tmp_path / "security-assessment.yaml").write_text("x")
    assert names.report_path(tmp_path) == tmp_path / "security-assessment.md"
    (tmp_path / "threat-model.yaml").write_text("x")
    with pytest.raises(names.ArtifactSetError, match="both"):
        names.model_path(tmp_path)
