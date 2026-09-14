"""
Tests for scripts/apply_editorial_plan.py — the deterministic applier for the
Stage-4 editorial plan.

Covers:
  * a field rewrite and a Markdown block rewrite land;
  * the optimistic lock rejects a stale `find`;
  * an address outside the editable allow-list is refused, so `find`/`replace`
    cannot reach a severity, an identifier or an evidence entry;
  * a target file outside the four allowed ones fails schema validation;
  * a Markdown block that matches twice is rejected rather than guessed;
  * rejects do not stop the remaining actions, and the exit code says so.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import apply_editorial_plan as applier  # noqa: E402

MODEL = {
    "threats": [
        {
            "id": "F-001",
            "title": "SQL injection — server/api.ts:42",
            "risk": "Critical",
            "scenario": "The handler concatenates the id.",
            "impact_description": "Read access to every row.",
        }
    ],
    "mitigations": [
        {
            "id": "M-001",
            "title": "Parameterise the query",
            "priority": "P1",
            "kind": "fix",
            "steps": ["Rewrite the statement.", "Add a regression test."],
            "verification": "Re-run the scanner.",
        }
    ],
}

FRAGMENT = """## 6.1 Input validation

The handler builds its query by concatenation.

## 6.2 Output encoding

Nothing is escaped.
"""


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "security"
    (out / ".fragments").mkdir(parents=True)
    (out / "threat-model.yaml").write_text(yaml.safe_dump(MODEL, sort_keys=False), encoding="utf-8")
    (out / ".fragments" / "security-architecture.md").write_text(FRAGMENT, encoding="utf-8")
    return out


def _plan(output_dir: Path, actions: list[dict], status: str = "edits") -> Path:
    plan = {
        "schema_version": 1,
        "generated": "2026-08-30T09:00:00Z",
        "status": status,
        "actions": actions,
    }
    path = output_dir / applier.PLAN_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def _model(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


# ---------- the happy path --------------------------------------------------


def test_a_field_rewrite_lands(output_dir: Path) -> None:
    _plan(
        output_dir,
        [
            {
                "file": "threat-model.yaml",
                "path": "threats[0].scenario",
                "find": "The handler concatenates the id.",
                "replace": "The handler concatenates the id into the statement.",
                "rationale": "names what the concatenation reaches",
            }
        ],
    )

    assert applier.main([str(output_dir)]) == 0
    assert _model(output_dir)["threats"][0]["scenario"] == "The handler concatenates the id into the statement."


def test_a_markdown_block_rewrite_lands(output_dir: Path) -> None:
    _plan(
        output_dir,
        [
            {
                "file": ".fragments/security-architecture.md",
                "find": "The handler builds its query by concatenation.",
                "replace": "The handler builds its query by string concatenation.",
            }
        ],
    )

    assert applier.main([str(output_dir)]) == 0
    text = (output_dir / ".fragments" / "security-architecture.md").read_text(encoding="utf-8")
    assert "string concatenation" in text
    assert text.startswith("## 6.1 Input validation")


def test_a_markdown_action_may_carry_an_explicit_null_path(output_dir: Path) -> None:
    """The projection addresses the §6 fragment with `"path": null`.

    Copying that key back is the natural reading of the block, and the
    applier's own check already treats null and missing alike. The schema used
    to disagree, and one such action rejected the whole plan — the 19 valid
    yaml actions beside it included.
    """
    _plan(
        output_dir,
        [
            {
                "file": ".fragments/security-architecture.md",
                "path": None,
                "find": "The handler builds its query by concatenation.",
                "replace": "The handler builds its query by string concatenation.",
            },
            {
                "file": "threat-model.yaml",
                "path": "threats[0].scenario",
                "find": "The handler concatenates the id.",
                "replace": "The handler concatenates the id into the statement.",
            },
        ],
    )

    assert applier.main([str(output_dir)]) == 0
    assert "string concatenation" in (output_dir / ".fragments" / "security-architecture.md").read_text(
        encoding="utf-8"
    )
    assert _model(output_dir)["threats"][0]["scenario"] == "The handler concatenates the id into the statement."


def test_a_step_inside_a_list_is_addressable(output_dir: Path) -> None:
    _plan(
        output_dir,
        [
            {
                "file": "threat-model.yaml",
                "path": "mitigations[0].steps[1]",
                "find": "Add a regression test.",
                "replace": "Add a regression test for the injected payload.",
            }
        ],
    )

    assert applier.main([str(output_dir)]) == 0
    assert _model(output_dir)["mitigations"][0]["steps"] == [
        "Rewrite the statement.",
        "Add a regression test for the injected payload.",
    ]


# ---------- what it refuses -------------------------------------------------


def test_a_stale_find_is_rejected(output_dir: Path) -> None:
    _plan(
        output_dir,
        [
            {
                "file": "threat-model.yaml",
                "path": "threats[0].scenario",
                "find": "Some text that is not in the model.",
                "replace": "Anything.",
            }
        ],
    )

    assert applier.main([str(output_dir)]) == 1
    assert _model(output_dir)["threats"][0]["scenario"] == "The handler concatenates the id."


@pytest.mark.parametrize(
    "field_path,find",
    [
        ("threats[0].risk", "Critical"),
        ("threats[0].title", "SQL injection — server/api.ts:42"),
        ("mitigations[0].title", "Parameterise the query"),
    ],
)
def test_an_address_outside_the_allow_list_is_refused(output_dir: Path, field_path: str, find: str) -> None:
    _plan(output_dir, [{"file": "threat-model.yaml", "path": field_path, "find": find, "replace": "rewritten"}])

    assert applier.main([str(output_dir)]) == 1
    before = yaml.safe_load(yaml.safe_dump(MODEL, sort_keys=False))
    assert _model(output_dir) == before


def test_a_file_outside_the_allowed_targets_fails_validation(output_dir: Path) -> None:
    _plan(
        output_dir,
        [{"file": ".fragments/attack-walkthroughs.md", "find": "anything", "replace": "anything else"}],
    )

    assert applier.main([str(output_dir)]) == 1


def test_a_markdown_block_matching_twice_is_rejected(output_dir: Path) -> None:
    fragment = output_dir / ".fragments" / "security-architecture.md"
    fragment.write_text(FRAGMENT + "\nNothing is escaped.\n", encoding="utf-8")
    _plan(
        output_dir,
        [{"file": ".fragments/security-architecture.md", "find": "Nothing is escaped.", "replace": "Output is raw."}],
    )

    assert applier.main([str(output_dir)]) == 1
    assert "Output is raw." not in fragment.read_text(encoding="utf-8")


def test_a_markdown_action_may_not_carry_a_field_address(output_dir: Path) -> None:
    _plan(
        output_dir,
        [
            {
                "file": ".fragments/security-architecture.md",
                "path": "anti_patterns[0].description",
                "find": "Nothing is escaped.",
                "replace": "Output is raw.",
            }
        ],
    )

    assert applier.main([str(output_dir)]) == 1


def test_no_change_with_actions_is_rejected(output_dir: Path) -> None:
    _plan(
        output_dir,
        [
            {
                "file": "threat-model.yaml",
                "path": "threats[0].scenario",
                "find": "The handler concatenates the id.",
                "replace": "Rewritten.",
            }
        ],
        status="no_change",
    )

    assert applier.main([str(output_dir)]) == 1
    assert _model(output_dir)["threats"][0]["scenario"] == "The handler concatenates the id."


# ---------- partial application --------------------------------------------


def test_one_reject_does_not_stop_the_other_actions(output_dir: Path, capsys: pytest.CaptureFixture) -> None:
    _plan(
        output_dir,
        [
            {
                "file": "threat-model.yaml",
                "path": "threats[0].scenario",
                "find": "The handler concatenates the id.",
                "replace": "The handler concatenates the id into the statement.",
            },
            {
                "file": "threat-model.yaml",
                "path": "threats[0].impact_description",
                "find": "stale text",
                "replace": "never applied",
            },
        ],
    )

    rc = applier.main([str(output_dir)])
    report = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert report["applied_count"] == 1
    assert report["rejected_count"] == 1
    assert report["files_touched"] == ["threat-model.yaml"]
    model = _model(output_dir)
    assert model["threats"][0]["scenario"].endswith("into the statement.")
    assert model["threats"][0]["impact_description"] == "Read access to every row."


def test_dry_run_writes_nothing(output_dir: Path) -> None:
    before = (output_dir / "threat-model.yaml").read_text(encoding="utf-8")
    _plan(
        output_dir,
        [
            {
                "file": "threat-model.yaml",
                "path": "threats[0].scenario",
                "find": "The handler concatenates the id.",
                "replace": "Rewritten.",
            }
        ],
    )

    assert applier.main([str(output_dir), "--dry-run"]) == 0
    assert (output_dir / "threat-model.yaml").read_text(encoding="utf-8") == before


def test_local_rejection_and_global_guard_both_protect_evidence(output_dir: Path) -> None:
    """Reject an unsafe action locally; retain the global guard against other writers."""
    import check_editorial_diff as guard

    (output_dir / "threat-model.yaml").write_text(
        yaml.safe_dump(
            {**MODEL, "threats": [{**MODEL["threats"][0], "scenario": "Concatenation at `server/api.ts:42`."}]},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    assert guard.main(["snapshot", "--output-dir", str(output_dir)]) == 0
    _plan(
        output_dir,
        [
            {
                "file": "threat-model.yaml",
                "path": "threats[0].scenario",
                "find": "Concatenation at `server/api.ts:42`.",
                "replace": "Concatenation at `server/api.ts:57`.",
            }
        ],
    )

    assert applier.main([str(output_dir)]) == 1
    assert _model(output_dir)["threats"][0]["scenario"] == "Concatenation at `server/api.ts:42`."
    # A direct mutation must still be caught even though plans reject it early.
    model = _model(output_dir)
    model["threats"][0]["scenario"] = "Concatenation at `server/api.ts:57`."
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(model))
    assert guard.main(["verify", "--output-dir", str(output_dir), "--restore"]) == 2
    assert _model(output_dir)["threats"][0]["scenario"] == "Concatenation at `server/api.ts:42`."


def test_field_path_parsing_rejects_junk() -> None:
    assert applier.parse_field_path("verdict.bullets[0].body") == ("verdict", "bullets", 0, "body")
    with pytest.raises(ValueError):
        applier.parse_field_path("threats[0]..scenario")
    with pytest.raises(ValueError):
        applier.parse_field_path("../../etc/passwd")


def _packets(output_dir):
    import build_editorial_context as builder

    assert builder.main([str(output_dir)]) == 0
    return json.loads((output_dir / builder.CONTEXT_DIR / builder.BLOCKS_NAME).read_text())


def _packet_plan(output_dir, work, batch, actions):
    path = output_dir / ".dispatch-context/editorial" / f"plan-{batch['id']}.json"
    payload = {
        "schema_version": 2,
        "run_id": work["run_id"],
        "batch_id": batch["id"],
        "status": "edits" if actions else "no_change",
        "actions": actions,
    }
    path.write_text(json.dumps(payload))
    return path


def test_id_packet_resolves_original_text_and_records_completion(output_dir, capsys):
    work = _packets(output_dir)
    block = next(b for b in work["blocks"] if b["path"] == "threats[0].scenario")
    for batch in work["batches"]:
        actions = (
            [{"id": block["id"], "replace": "The handler concatenates the id into the statement."}]
            if block["id"] in batch["block_ids"]
            else []
        )
        _packet_plan(output_dir, work, batch, actions)
    capsys.readouterr()
    assert applier.main([str(output_dir)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["complete"] is True
    assert report["applied_count"] == 1
    assert report["blocks_reviewed"] == len(work["blocks"])


@pytest.mark.parametrize(
    "defect", ["stale_run", "wrong_batch", "unknown_id", "extra_target", "duplicate_id", "truncated", "symlink"]
)
def test_invalid_packet_cannot_write_the_model(output_dir, defect, tmp_path):
    work = _packets(output_dir)
    batch = work["batches"][0]
    path = _packet_plan(output_dir, work, batch, [{"id": batch["block_ids"][0], "replace": "Replacement."}])
    plan = json.loads(path.read_text())
    if defect == "stale_run":
        plan["run_id"] = "0" * 32
    if defect == "wrong_batch":
        plan["batch_id"] = "9999"
    if defect == "unknown_id":
        plan["actions"][0]["id"] = "b999999"
    if defect == "extra_target":
        plan["actions"][0]["file"] = "../outside"
    if defect == "duplicate_id":
        plan["actions"] *= 2
    path.write_text("{" if defect == "truncated" else json.dumps(plan))
    if defect == "symlink":
        outside = tmp_path / "outside.json"
        outside.write_text(json.dumps(plan))
        path.unlink()
        path.symlink_to(outside)
    before = (output_dir / "threat-model.yaml").read_bytes()
    assert applier.main([str(output_dir)]) == 1
    assert (output_dir / "threat-model.yaml").read_bytes() == before


def test_completed_packet_survives_missing_sibling(output_dir, capsys):
    import build_editorial_context as builder

    model = _model(output_dir)
    model["threats"] = [{**model["threats"][0], "id": f"F-{i:03d}"} for i in range(1, 16)]
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(model))
    work = _packets(output_dir)
    assert len(work["batches"]) > 1
    batch = work["batches"][0]
    block = next(b for b in work["blocks"] if b["id"] in batch["block_ids"] and b["path"].endswith("scenario"))
    _packet_plan(
        output_dir, work, batch, [{"id": block["id"], "replace": "The handler concatenates the id into the statement."}]
    )
    capsys.readouterr()
    assert applier.main([str(output_dir)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["applied_count"] == 1
    assert report["complete"] is False
    assert report["batches_completed"] == 1
    assert report["blocks_reviewed"] <= builder.MAX_BATCH_BLOCKS


def test_local_invariant_violation_does_not_discard_good_neighbor(output_dir, capsys):
    _plan(
        output_dir,
        [
            {
                "file": "threat-model.yaml",
                "path": "threats[0].scenario",
                "find": MODEL["threats"][0]["scenario"],
                "replace": "The handler never concatenates the id.",
            },
            {
                "file": "threat-model.yaml",
                "path": "threats[0].impact_description",
                "find": MODEL["threats"][0]["impact_description"],
                "replace": "Every row can be read.",
            },
        ],
    )
    assert applier.main([str(output_dir)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["applied_count"] == 1
    assert report["rejected_count"] == 1
    assert _model(output_dir)["threats"][0]["scenario"] == MODEL["threats"][0]["scenario"]


def test_id_resolution_retains_the_stale_text_lock(output_dir, capsys):
    work = _packets(output_dir)
    block = next(b for b in work["blocks"] if b["path"] == "threats[0].scenario")
    batch = next(b for b in work["batches"] if block["id"] in b["block_ids"])
    _packet_plan(
        output_dir, work, batch, [{"id": block["id"], "replace": "The handler concatenates the id into the statement."}]
    )
    model = _model(output_dir)
    model["threats"][0]["scenario"] = "The current value changed."
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(model))
    assert applier.main([str(output_dir)]) == 1
    assert _model(output_dir)["threats"][0]["scenario"] == "The current value changed."


def test_missing_schema_validator_cannot_enable_unvalidated_writes(output_dir, monkeypatch):
    path = _plan(output_dir, [], status="no_change")
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    with pytest.raises(applier.PlanError, match="jsonschema is required"):
        applier.load_plan(path)


def test_empty_edits_plan_is_not_a_no_change_receipt(output_dir):
    _plan(output_dir, [])
    assert applier.main([str(output_dir)]) == 1


def test_unchanged_markdown_is_not_counted_as_a_rewrite(output_dir, capsys):
    _plan(
        output_dir,
        [
            {
                "file": ".fragments/security-architecture.md",
                "find": "Nothing is escaped.",
                "replace": "Nothing is escaped.",
            }
        ],
    )
    assert applier.main([str(output_dir)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["applied_count"] == 0
    assert report["files_touched"] == []


def test_markdown_target_cannot_alias_another_run_artifact(output_dir):
    target = output_dir / ".fragments/security-architecture.md"
    unrelated = output_dir / "other-artifact.md"
    unrelated.write_text(FRAGMENT)
    target.unlink()
    target.symlink_to(unrelated)
    _plan(
        output_dir,
        [{"file": ".fragments/security-architecture.md", "find": "Nothing is escaped.", "replace": "Output is raw."}],
    )
    assert applier.main([str(output_dir)]) == 1
    assert unrelated.read_text() == FRAGMENT
