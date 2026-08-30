"""
Tests for scripts/check_editorial_diff.py — the Stage-4 editorial guard.

Covers:
  * a clean rewrite of prose passes;
  * a changed severity, a rewritten `file:line` locator, a dropped unproven
    marking and a removed mitigation step are each caught;
  * blanking a field is a violation even though the blanked skeletons match;
  * Markdown fragments keep their heading lines;
  * `--restore` rolls the guarded files back and still exits 2.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_editorial_diff as guard  # noqa: E402

BASE_MODEL = {
    "meta": {"version": "1"},
    "threats": [
        {
            "id": "F-001",
            "title": "SQL injection — server/api.ts:42",
            "risk": "Critical",
            "effective_severity": "Critical",
            "evidence_check": "unproven",
            "scenario": "An anonymous caller reaches `server/api.ts:42`, where the query is built by string concatenation.",
            "evidence_summary": "The handler in `server/api.ts:42` concatenates `req.query.id` into the statement.",
            "impact_description": "Full read access to the 3 tables the account owns.",
            "evidence": [{"file": "server/api.ts", "line": 42}],
        }
    ],
    "mitigations": [
        {
            "id": "M-001",
            "title": "Parameterise the query",
            "priority": "P1",
            "kind": "fix",
            "steps": [
                "Replace the concatenation in `server/api.ts:42` with a parameterised statement.",
                "Add a regression test that sends `' OR 1=1--` and expects a 400.",
            ],
            "verification": "Re-run the scanner and confirm CWE-89 no longer reports `server/api.ts:42`.",
        }
    ],
    "verdict": {
        "severity": "Critical",
        "opening": "The application is not production ready.",
        "bullets_intro": "Three findings drive the verdict.",
        "bullets": [{"title": "Injection", "body": "Unparameterised SQL in `server/api.ts:42`.", "refs": ["F-001"]}],
        "closing": "Close F-001 before the next release.",
    },
}

FRAGMENT_MD = """## 6.1 Input validation

The handler in `server/api.ts:42` builds its query by concatenation.

#### 6.1.1 Query construction

No parameterisation is in place.
"""


def _write_model(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "security"
    (out / ".fragments").mkdir(parents=True)
    _write_model(out, BASE_MODEL)
    (out / ".fragments" / "security-architecture.md").write_text(FRAGMENT_MD, encoding="utf-8")
    return out


def _snapshot(output_dir: Path) -> dict:
    assert guard.main(["snapshot", "--output-dir", str(output_dir)]) == 0
    return json.loads((output_dir / guard.SNAPSHOT_NAME).read_text(encoding="utf-8"))


def _verify(output_dir: Path) -> list[dict]:
    return guard.verify(_load_snapshot(output_dir), output_dir)


def _load_snapshot(output_dir: Path) -> dict:
    return json.loads((output_dir / guard.SNAPSHOT_NAME).read_text(encoding="utf-8"))


# ---------- the pass this guard exists to allow ----------------------------


def test_a_clean_rewrite_passes(output_dir: Path) -> None:
    _snapshot(output_dir)
    edited = copy.deepcopy(BASE_MODEL)
    edited["threats"][0]["scenario"] = (
        "`server/api.ts:42` concatenates the query, so an anonymous caller reaches the database directly."
    )
    edited["mitigations"][0]["steps"][1] = "Add a regression test sending `' OR 1=1--` and asserting a 400."
    edited["verdict"]["closing"] = "F-001 must close before the next release."
    _write_model(output_dir, edited)

    assert _verify(output_dir) == []


def test_a_markdown_rewrite_that_keeps_headings_passes(output_dir: Path) -> None:
    _snapshot(output_dir)
    fragment = output_dir / ".fragments" / "security-architecture.md"
    fragment.write_text(
        FRAGMENT_MD.replace(
            "The handler in `server/api.ts:42` builds its query by concatenation.",
            "`server/api.ts:42` builds its query by concatenation.",
        ),
        encoding="utf-8",
    )

    assert _verify(output_dir) == []


# ---------- what it must catch ---------------------------------------------


def test_a_changed_severity_is_caught(output_dir: Path) -> None:
    _snapshot(output_dir)
    edited = copy.deepcopy(BASE_MODEL)
    edited["threats"][0]["effective_severity"] = "Medium"
    _write_model(output_dir, edited)

    kinds = {v["kind"] for v in _verify(output_dir)}
    assert kinds == {"structure_changed"}


def test_a_rewritten_evidence_locator_is_caught(output_dir: Path) -> None:
    _snapshot(output_dir)
    edited = copy.deepcopy(BASE_MODEL)
    edited["threats"][0]["evidence_summary"] = "The handler in `server/api.ts:57` concatenates the id."
    _write_model(output_dir, edited)

    violations = _verify(output_dir)
    assert {v["kind"] for v in violations} >= {"code_spans_changed"}
    assert any("server/api.ts:42" in v["detail"] for v in violations)


def test_a_dropped_unproven_marking_is_caught(output_dir: Path) -> None:
    _snapshot(output_dir)
    edited = copy.deepcopy(BASE_MODEL)
    edited["threats"][0]["evidence_check"] = "confirmed"
    _write_model(output_dir, edited)

    assert [v["kind"] for v in _verify(output_dir)] == ["structure_changed"]


def test_a_removed_mitigation_step_is_caught(output_dir: Path) -> None:
    _snapshot(output_dir)
    edited = copy.deepcopy(BASE_MODEL)
    edited["mitigations"][0]["steps"] = edited["mitigations"][0]["steps"][:1]
    _write_model(output_dir, edited)

    violations = _verify(output_dir)
    assert [v["kind"] for v in violations] == ["structure_changed"]
    assert "mitigations[0].steps" in violations[0]["detail"]


def test_blanking_a_field_is_caught(output_dir: Path) -> None:
    _snapshot(output_dir)
    edited = copy.deepcopy(BASE_MODEL)
    edited["mitigations"][0]["verification"] = ""
    _write_model(output_dir, edited)

    violations = _verify(output_dir)
    assert [v["kind"] for v in violations] == ["field_blanked"]
    assert violations[0]["detail"] == "mitigations[0].verification"


def test_a_renamed_heading_is_caught(output_dir: Path) -> None:
    _snapshot(output_dir)
    fragment = output_dir / ".fragments" / "security-architecture.md"
    fragment.write_text(
        FRAGMENT_MD.replace("#### 6.1.1 Query construction", "#### 6.1.1 Query building"), encoding="utf-8"
    )

    assert [v["kind"] for v in _verify(output_dir)] == ["headings_changed"]


def test_a_changed_number_in_prose_is_caught(output_dir: Path) -> None:
    _snapshot(output_dir)
    edited = copy.deepcopy(BASE_MODEL)
    edited["threats"][0]["impact_description"] = "Full read access to the 12 tables the account owns."
    _write_model(output_dir, edited)

    assert [v["kind"] for v in _verify(output_dir)] == ["numbers_changed"]


# ---------- CLI behaviour ---------------------------------------------------


def test_verify_restores_and_still_fails(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    _snapshot(output_dir)
    edited = copy.deepcopy(BASE_MODEL)
    edited["threats"][0]["risk"] = "Low"
    _write_model(output_dir, edited)
    capsys.readouterr()  # drop the snapshot command's own stdout

    rc = guard.main(["verify", "--output-dir", str(output_dir), "--restore"])
    report = json.loads(capsys.readouterr().out)

    assert rc == 2
    assert report["status"] == "violations"
    assert report["restored"] == ["threat-model.yaml"]
    restored = yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))
    assert restored["threats"][0]["risk"] == "Critical"
    assert guard.main(["verify", "--output-dir", str(output_dir)]) == 0


def test_verify_without_a_snapshot_is_a_usage_error(output_dir: Path) -> None:
    assert guard.main(["verify", "--output-dir", str(output_dir)]) == 1


def test_a_deleted_guarded_file_is_caught(output_dir: Path) -> None:
    _snapshot(output_dir)
    (output_dir / ".fragments" / "security-architecture.md").unlink()

    assert [v["kind"] for v in _verify(output_dir)] == ["file_removed"]


def test_only_existing_guarded_files_are_snapshotted(output_dir: Path) -> None:
    snapshot = _snapshot(output_dir)

    assert sorted(snapshot["files"]) == [".fragments/security-architecture.md", "threat-model.yaml"]
