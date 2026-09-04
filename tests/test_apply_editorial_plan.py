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


def test_the_guard_catches_what_the_applier_cannot(output_dir: Path) -> None:
    """An allow-listed field may still carry an evidence locator — the applier
    accepts the rewrite, and check_editorial_diff.py is what reverts it."""
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

    assert applier.main([str(output_dir)]) == 0
    assert guard.main(["verify", "--output-dir", str(output_dir), "--restore"]) == 2
    assert _model(output_dir)["threats"][0]["scenario"] == "Concatenation at `server/api.ts:42`."


def test_field_path_parsing_rejects_junk() -> None:
    assert applier.parse_field_path("verdict.bullets[0].body") == ("verdict", "bullets", 0, "body")
    with pytest.raises(ValueError):
        applier.parse_field_path("threats[0]..scenario")
    with pytest.raises(ValueError):
        applier.parse_field_path("../../etc/passwd")
