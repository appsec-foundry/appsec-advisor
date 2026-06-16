from __future__ import annotations

import json
from pathlib import Path

import apply_finding_refs_repair as repair


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_plan(path: Path, actions: list[dict]) -> None:
    _write(path, json.dumps({"actions": actions}, indent=2))


def _run_main(monkeypatch, *args: object) -> int:
    monkeypatch.setattr(repair.sys, "argv", ["apply_finding_refs_repair.py", *[str(a) for a in args]])
    return repair.main()


def test_apply_plan_reports_missing_files(tmp_path: Path, capsys) -> None:
    md = tmp_path / "threat-model.md"
    plan = tmp_path / ".finding-refs-repair-plan.json"

    assert repair.apply_plan(md, plan, min_score=0.2, dry_run=False) == 1
    assert "threat-model.md" in capsys.readouterr().err

    _write(md, "report\n")
    assert repair.apply_plan(md, plan, min_score=0.2, dry_run=False) == 1
    assert ".finding-refs-repair-plan.json" in capsys.readouterr().err


def test_apply_plan_empty_plan_is_noop(tmp_path: Path, capsys) -> None:
    md = tmp_path / "threat-model.md"
    plan = tmp_path / ".finding-refs-repair-plan.json"
    _write(md, "report\n")
    _write_plan(plan, [])

    assert repair.apply_plan(md, plan, min_score=0.2, dry_run=False) == 0

    assert md.read_text(encoding="utf-8") == "report\n"
    assert "no actions in plan" in capsys.readouterr().err


def test_apply_plan_filters_actions_scores_and_rewrites_atomically(tmp_path: Path, capsys) -> None:
    md = tmp_path / "threat-model.md"
    plan = tmp_path / ".finding-refs-repair-plan.json"
    _write(
        md,
        "\n".join(
            [
                "[F-001](#f-001) — SQL injection",
                "[F-003](#f-003) — low score skip",
                "[F-004](#f-004) — no match target",
                "[F-006](#f-006) — phantom remap",
            ]
        )
        + "\n",
    )
    _write_plan(
        plan,
        [
            {"fragment": str(md), "line": 1, "bad_f_id": "F-001", "suggested_f_id": "F-002", "remap_score": 0.9},
            {"fragment": str(md), "line": 1, "bad_f_id": "F-001", "suggested_f_id": "F-002", "remap_score": 0.9},
            {"fragment": str(md), "line": 2, "bad_f_id": "F-003", "suggested_f_id": "F-005", "remap_score": 0.1},
            {"fragment": str(md), "line": 3, "bad_f_id": "F-999", "suggested_f_id": "F-005", "remap_score": 0.9},
            {"fragment": str(md), "line": 99, "bad_f_id": "F-004", "suggested_f_id": "F-005", "remap_score": 0.9},
            {"fragment": str(md), "line": 1, "bad_f_id": "F-008", "suggested_f_id": "F-009", "remap_score": "bad"},
            {
                "fragment": str(md),
                "line": 4,
                "bad_f_id": "F-006",
                "suggested_f_id": "F-007",
                "remap_score": 0.0,
                "defect": "phantom_f_id",
            },
            {
                "fragment": str(tmp_path / ".fragments" / "security.md"),
                "line": 1,
                "bad_f_id": "F-010",
                "suggested_f_id": "F-011",
            },
            {"fragment": str(md), "line": 1, "bad_f_id": "F-012", "suggested_f_id": "T-012", "remap_score": 0.9},
            {"fragment": str(md), "line": 1, "bad_f_id": "F-013", "suggested_f_id": "F-013", "remap_score": 0.9},
            {"fragment": str(md), "line": 1, "bad_f_id": "F-014", "remap_score": 0.9},
        ],
    )

    assert repair.apply_plan(md, plan, min_score=0.2, dry_run=False) == 0

    assert (
        md.read_text(encoding="utf-8")
        == "\n".join(
            [
                "[F-002](#f-002) — SQL injection",
                "[F-003](#f-003) — low score skip",
                "[F-004](#f-004) — no match target",
                "[F-007](#f-007) — phantom remap",
            ]
        )
        + "\n"
    )
    err = capsys.readouterr().err
    assert "applied 2 remap(s)" in err
    assert "skipped 2 low-score" in err
    assert "2 no-match" in err


def test_apply_plan_dry_run_does_not_write(tmp_path: Path, capsys) -> None:
    md = tmp_path / "threat-model.md"
    plan = tmp_path / ".finding-refs-repair-plan.json"
    original = "[F-001](#f-001) — SQL injection\n"
    _write(md, original)
    _write_plan(
        plan,
        [{"fragment": str(md), "line": 1, "bad_f_id": "F-001", "suggested_f_id": "F-002", "remap_score": 0.9}],
    )

    assert repair.apply_plan(md, plan, min_score=0.2, dry_run=True) == 0

    assert md.read_text(encoding="utf-8") == original
    err = capsys.readouterr().err
    assert "DRY-RUN" in err
    assert "would apply 1 swap(s)" in err


def test_apply_plan_idempotent_rerun_reports_no_changes(tmp_path: Path, capsys) -> None:
    md = tmp_path / "threat-model.md"
    plan = tmp_path / ".finding-refs-repair-plan.json"
    _write(md, "[F-002](#f-002) — SQL injection\n")
    _write_plan(
        plan,
        [{"fragment": str(md), "line": 1, "bad_f_id": "F-001", "suggested_f_id": "F-002", "remap_score": 0.9}],
    )

    assert repair.apply_plan(md, plan, min_score=0.2, dry_run=False) == 0

    assert "no changes" in capsys.readouterr().err


def test_main_uses_default_plan_and_cli_flags(monkeypatch, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    md = out / "threat-model.md"
    _write(md, "[F-001](#f-001) — SQL injection\n")
    _write_plan(
        out / ".finding-refs-repair-plan.json",
        [{"fragment": str(md), "line": 1, "bad_f_id": "F-001", "suggested_f_id": "F-002", "remap_score": 0.1}],
    )

    assert _run_main(monkeypatch, out, "--min-score", "0", "--dry-run") == 0
    assert md.read_text(encoding="utf-8") == "[F-001](#f-001) — SQL injection\n"
    assert "would apply 1 swap(s)" in capsys.readouterr().err

    assert _run_main(monkeypatch, out, "--min-score", "0") == 0
    assert md.read_text(encoding="utf-8") == "[F-002](#f-002) — SQL injection\n"
