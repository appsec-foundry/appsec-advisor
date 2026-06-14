from __future__ import annotations

import json
from pathlib import Path

import apply_finding_refs_repair as repair
import validate_finding_refs as vfr


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_yaml(path: Path, threats: list[dict]) -> None:
    _write(path, vfr.yaml.safe_dump({"threats": threats}, sort_keys=False))


def _run_main(monkeypatch, *args: object) -> int:
    monkeypatch.setattr(vfr.sys, "argv", ["validate_finding_refs.py", *[str(a) for a in args]])
    return vfr.main()


def test_tokenize_and_jaccard_ignore_noise() -> None:
    tokens = vfr.tokenize("The SQL injection in (`routes/login.ts`) via `db.query` and password")

    assert tokens == {"sql", "injection", "password"}
    assert vfr.jaccard({"sql", "login"}, {"sql", "idor"}) == 1 / 3
    assert vfr.jaccard(set(), {"sql"}) == 0.0
    assert vfr.jaccard({"sql"}, set()) == 0.0


def test_load_threats_maps_t_ids_to_f_ids_and_extracts_evidence_files(tmp_path: Path) -> None:
    yaml_path = tmp_path / "threat-model.yaml"
    _write_yaml(
        yaml_path,
        [
            {
                "id": "T-001",
                "title": "SQL injection in login route",
                "evidence": {"file": "routes/login.ts", "line": 37},
            },
            {
                "t_id": "T-002",
                "title": "Basket IDOR allows order access",
                "evidence": [{"file": "routes/basket.ts", "line": 12}],
            },
            {"id": "X-003", "title": "Non-threat ids are preserved by convention"},
            {"title": "ignored without id"},
            "ignored non-dict",
        ],
    )

    threats = vfr.load_threats(yaml_path)

    assert threats["F-001"] == {
        "id": "T-001",
        "title": "SQL injection in login route",
        "evidence_file": "routes/login.ts",
    }
    assert threats["F-002"]["id"] == "T-002"
    assert threats["F-002"]["evidence_file"] == "routes/basket.ts"
    assert threats["X-003"]["evidence_file"] == "?"


def test_scan_fragment_detects_phantom_and_mislabeled_refs(tmp_path: Path) -> None:
    fragment = tmp_path / ".fragments" / "security-architecture.md"
    _write(
        fragment,
        "\n".join(
            [
                "[F-001](#f-001) — SQL injection in login route",
                "[F-009](#f-009) — Basket IDOR allows order access",
                "[F-003](#f-003) — Basket IDOR allows order access",
                "[F-099](#f-099) — x",
            ]
        ),
    )
    threats = {
        "F-001": {"title": "SQL injection in login route"},
        "F-002": {"title": "Basket IDOR allows order access"},
        "F-003": {"title": "MD5 password hashing trivially reversible"},
    }

    defects = vfr.scan_fragment(fragment, threats)

    assert [d["defect"] for d in defects] == ["phantom_f_id", "mislabeled_f_id", "phantom_f_id"]
    assert defects[0]["f_id"] == "F-009"
    assert defects[0]["remap_candidate"] == "F-002"
    assert defects[1]["f_id"] == "F-003"
    assert defects[1]["yaml_title"] == "MD5 password hashing trivially reversible"
    assert defects[1]["remap_candidate"] == "F-002"
    assert defects[2]["f_id"] == "F-099"
    assert defects[2]["remap_candidate"] is None
    assert vfr.scan_fragment(tmp_path / "missing.md", threats) == []


def test_main_reports_missing_yaml_and_empty_threats(monkeypatch, tmp_path: Path, capsys) -> None:
    assert _run_main(monkeypatch, tmp_path) == 2
    assert "not found" in capsys.readouterr().err

    _write_yaml(tmp_path / "threat-model.yaml", [])
    assert _run_main(monkeypatch, tmp_path) == 2
    assert "no threats" in capsys.readouterr().err


def test_main_writes_clean_report_and_json(monkeypatch, tmp_path: Path, capsys) -> None:
    _write_yaml(
        tmp_path / "threat-model.yaml",
        [{"id": "T-001", "title": "SQL injection in login route"}],
    )
    _write(tmp_path / ".fragments" / "security-architecture.md", "[F-001](#f-001) — SQL injection in login route\n")

    assert _run_main(monkeypatch, tmp_path, "--strict", "--json") == 0

    report = json.loads((tmp_path / ".finding-refs-report.json").read_text(encoding="utf-8"))
    stdout_report = json.loads(capsys.readouterr().out)
    assert report["defect_count"] == 0
    assert stdout_report["defect_count"] == 0
    assert report["threats_in_yaml"] == ["F-001"]


def test_main_strict_remap_writes_report_and_repair_plan(monkeypatch, tmp_path: Path, capsys) -> None:
    _write_yaml(
        tmp_path / "threat-model.yaml",
        [
            {"id": "T-001", "title": "SQL injection in login route"},
            {"id": "T-002", "title": "Basket IDOR allows order access"},
        ],
    )
    _write(
        tmp_path / ".fragments" / "security-architecture.md",
        "[F-009](#f-009) — Basket IDOR allows order access\n",
    )

    assert _run_main(monkeypatch, tmp_path, "--strict", "--remap", "--json") == 1

    captured = capsys.readouterr()
    report = json.loads((tmp_path / ".finding-refs-report.json").read_text(encoding="utf-8"))
    plan = json.loads((tmp_path / ".finding-refs-repair-plan.json").read_text(encoding="utf-8"))
    stdout_report = json.loads(captured.out)

    assert report["defect_count"] == 1
    assert stdout_report["defect_count"] == 1
    assert plan["actions"][0]["bad_f_id"] == "F-009"
    assert plan["actions"][0]["suggested_f_id"] == "F-002"
    assert "wrote" in captured.err
    assert "phantom_f_id" in captured.err


def test_validator_repair_plan_feeds_rendered_markdown_applier(monkeypatch, tmp_path: Path) -> None:
    _write_yaml(
        tmp_path / "threat-model.yaml",
        [
            {"id": "T-001", "title": "SQL injection in login route"},
            {"id": "T-002", "title": "Basket IDOR allows order access"},
        ],
    )
    md_path = tmp_path / "threat-model.md"
    _write(md_path, "| Ref |\n| [F-009](#f-009) — Basket IDOR allows order access |\n")

    assert _run_main(monkeypatch, tmp_path, "--remap") == 0
    assert repair.apply_plan(md_path, tmp_path / ".finding-refs-repair-plan.json", min_score=0.2, dry_run=False) == 0

    assert "[F-002](#f-002) — Basket IDOR allows order access" in md_path.read_text(encoding="utf-8")
