"""Importing a finished docs/security assessment into the external destination (decision AS-1)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from orchestrator import orchestration_controller as controller  # noqa: E402
from runtime import legacy_import  # noqa: E402


def _legacy(repo: Path, stem: str = "threat-model") -> Path:
    legacy = repo / "docs" / "security"
    legacy.mkdir(parents=True)
    (legacy / f"{stem}.md").write_text(f"# Report\n\n![Figure 1]({stem}.figure1.svg)\n")
    (legacy / f"{stem}.yaml").write_text(yaml.safe_dump({"meta": {}, "threats": [], "changelog": [{"version": 1}]}))
    (legacy / f"{stem}.figure1.svg").write_text("<svg/>\n")
    (legacy / f"{stem}.sarif.json").write_text("{}\n")
    (legacy / "pentest-tasks.yaml").write_text("tasks: []\n")
    (legacy / "business-context.md").write_text("# Business context\n")
    return legacy


def test_a_finished_set_is_copied_under_the_published_names(tmp_path):
    repo = tmp_path / "repo"
    legacy = _legacy(repo)
    destination = tmp_path / "dest"
    destination.mkdir(mode=0o700)
    found = legacy_import.offer(repo, destination)
    assert found is not None and found.complete
    delivered = legacy_import.import_legacy(found, destination)
    assert set(delivered) == {
        "security-assessment.md",
        "security-assessment.yaml",
        "security-assessment.figure1.svg",
        "security-assessment.sarif.json",
        "pentest-tasks.yaml",
    }
    assert "(security-assessment.figure1.svg)" in (destination / "security-assessment.md").read_text()
    # Repository-owned inputs are not assessment results; the legacy files stay.
    assert not (destination / "business-context.md").exists()
    assert sorted(p.name for p in legacy.iterdir()) == sorted(
        [
            "business-context.md",
            "pentest-tasks.yaml",
            "threat-model.figure1.svg",
            "threat-model.md",
            "threat-model.sarif.json",
            "threat-model.yaml",
        ]
    )
    receipt = legacy_import.read_receipt(destination)
    assert receipt["deliverables"] == delivered and receipt["source"] == "docs/security"
    assert all((destination / name).stat().st_mode & 0o777 == 0o600 for name in [*delivered, legacy_import.IMPORT_NAME])
    # A second offer sees the imported assessment and stays silent.
    assert legacy_import.offer(repo, destination) is None


@pytest.mark.parametrize(
    ("leftover", "reason"),
    [
        ((".assessment-state.json", '{"status": "running"}'), "did not finish"),
        ((".appsec-checkpoint", "phase=7 status=running\n"), "did not finish"),
        (("threat-model.yaml", "not: [a model"), "unreadable"),
    ],
)
def test_an_interrupted_or_broken_run_is_reported_and_never_imported(tmp_path, leftover, reason):
    repo = tmp_path / "repo"
    legacy = _legacy(repo)
    (legacy / leftover[0]).write_text(leftover[1])
    destination = tmp_path / "dest"
    destination.mkdir()
    found = legacy_import.offer(repo, destination)
    assert found is not None and not found.complete and reason in found.reason
    with pytest.raises(legacy_import.LegacyImportError, match="incomplete"):
        legacy_import.import_legacy(found, destination)
    assert not any(destination.iterdir())


def test_a_linked_set_is_never_read(tmp_path):
    repo = tmp_path / "repo"
    elsewhere = _legacy(tmp_path / "other")
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "security").symlink_to(elsewhere)
    assert legacy_import.find(repo) is None
    # A linked parent leads out of the checkout as well.
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "docs").symlink_to(elsewhere.parent)
    found = legacy_import.find(linked)
    assert found is not None and not found.complete and "link" in found.reason
    # A linked report inside a real directory counts as missing.
    repo2 = tmp_path / "repo2"
    legacy = _legacy(repo2)
    (legacy / "threat-model.md").unlink()
    (legacy / "threat-model.md").symlink_to(elsewhere / "threat-model.md")
    assert not legacy_import.find(repo2).complete


def test_no_offer_into_the_legacy_directory_itself_or_an_assessed_destination(tmp_path):
    repo = tmp_path / "repo"
    legacy = _legacy(repo)
    assert legacy_import.offer(repo, legacy) is None
    destination = tmp_path / "dest"
    destination.mkdir()
    (destination / "security-assessment.yaml").write_text("threats: []\n")
    assert legacy_import.offer(repo, destination) is None
    assert legacy_import.offer(tmp_path / "plain", destination) is None


def _ns(repo, **flags):
    defaults = {"resume": False, "rebuild": False, "migrate_legacy": False, "ignore_legacy": False}
    return SimpleNamespace(repo=[str(repo)], **{**defaults, **flags})


def test_without_a_choice_the_run_stops_with_the_instruction(tmp_path):
    repo = tmp_path / "repo"
    _legacy(repo)
    destination = tmp_path / "dest"
    destination.mkdir()
    with pytest.raises(controller.CallError, match="--migrate-legacy .* or --ignore-legacy"):
        controller._assessment_legacy(_ns(repo), destination)
    assert controller._assessment_legacy(_ns(repo, ignore_legacy=True), destination) is None
    assert not any(destination.iterdir())
    note = controller._assessment_legacy(_ns(repo, migrate_legacy=True), destination)
    assert note.startswith("imported the earlier assessment") and (destination / "security-assessment.md").is_file()


def test_an_incomplete_legacy_run_is_named_but_does_not_stop_the_run(tmp_path):
    repo = tmp_path / "repo"
    (_legacy(repo) / ".assessment-state.json").write_text(json.dumps({"status": "interrupted"}))
    destination = tmp_path / "dest"
    destination.mkdir()
    note = controller._assessment_legacy(_ns(repo), destination)
    assert "incomplete" in note and not any(destination.iterdir())
