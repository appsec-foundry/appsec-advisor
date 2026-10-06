from __future__ import annotations

from pathlib import Path

import pytest
import validators.validate_evidence_lines as vel
from shared._finding_state import is_confirmed


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _threat(tid: str, evidence=None, *, evidence_check: str | None = None, flags: list[str] | None = None) -> dict:
    threat = {"id": tid, "title": tid}
    if evidence is not None:
        threat["evidence"] = evidence
    if evidence_check is not None:
        threat["evidence_check"] = evidence_check
    if flags is not None:
        threat["evidence_flags"] = flags
    return threat


def test_line_classifiers_distinguish_comments_imports_and_code() -> None:
    assert vel._is_comment_only("")
    assert vel._is_comment_only("   // only a comment")
    assert vel._is_comment_only("<!-- html comment -->")
    assert vel._is_comment_only("-- sql comment")
    assert not vel._is_comment_only("const token = req.headers.authorization // trailing note")

    assert vel._is_import_line("import express from 'express'")
    assert vel._is_import_line("const jwt = require('jsonwebtoken')")
    assert vel._is_import_line("from flask import request")
    assert vel._is_import_line("package com.example.auth;")
    assert vel._is_import_line("using System.Text;")
    assert vel._is_import_line('import "net/http"')
    assert not vel._is_import_line("const route = await import('./route.js')")


def test_resolve_evidence_file_direct_basename_unique_and_rejects_repo_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    outside = tmp_path / "outside.ts"
    _write(repo / "src" / "app.ts", "const app = express()\n")
    _write(repo / "node_modules" / "app.ts", "generated\n")
    _write(outside, "secret\n")

    assert vel._resolve_evidence_file(repo, "src/app.ts") == (repo / "src" / "app.ts").resolve()
    assert vel._resolve_evidence_file(repo, "app.ts") == (repo / "src" / "app.ts").resolve()
    assert vel._resolve_evidence_file(repo, "../outside.ts") is None
    assert vel._resolve_evidence_file(repo, "") is None

    _write(repo / "other" / "app.ts", "duplicate\n")

    assert vel._resolve_evidence_file(repo, "app.ts") is None


def test_read_line_and_evidence_entry_normalization(tmp_path: Path) -> None:
    source = tmp_path / "repo" / "src" / "app.ts"
    _write(source, "one\ntwo\n")

    assert vel._read_line(source, 2) == "two"
    assert vel._read_line(source, 3) is None
    assert vel._read_line(tmp_path / "missing.ts", 1) is None

    assert vel._evidence_entries({"evidence": {"file": "a.ts"}}) == [{"file": "a.ts"}]
    assert vel._evidence_entries({"evidence": [{"file": "a.ts"}, "bad", {"file": "b.ts"}]}) == [
        {"file": "a.ts"},
        {"file": "b.ts"},
    ]
    assert vel._evidence_entries({"evidence": "bad"}) == []


def test_validate_yaml_marks_evidence_outcomes_and_merges_flags(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(
        repo / "src" / "app.ts",
        "\n".join(
            [
                "const sql = query(req.body.id)",
                "// comment only",
                "import express from 'express'",
                "const token = req.headers.authorization",
            ]
        )
        + "\n",
    )

    data = {
        "threats": [
            _threat("valid", {"file": "src/app.ts", "line": 1}),
            _threat("file-only", {"file": "src/app.ts"}),
            _threat("bad-line-token", {"file": "src/app.ts", "line": "not-a-number"}),
            _threat("missing-file", {"file": "src/missing.ts", "line": 1}),
            _threat("comment", {"file": "src/app.ts", "line": 2}),
            _threat("import", {"file": "src/app.ts", "line": 3}),
            _threat("out-of-range", {"file": "src/app.ts", "line": 99}),
            _threat(
                "mixed-missing",
                [{"file": "src/missing.ts", "line": 1}, {"file": "src/app.ts", "line": 4}],
                flags=["existing"],
            ),
            _threat("mixed-comment", [{"file": "src/app.ts", "line": 2}, {"file": "src/app.ts", "line": 4}]),
            _threat("mixed-import", [{"file": "src/app.ts", "line": 3}, {"file": "src/app.ts", "line": 4}]),
            _threat("no-evidence"),
            "ignored non-dict",
        ]
    }

    updated, stats = vel.validate_yaml(data, repo)
    threats = {t["id"]: t for t in updated["threats"] if isinstance(t, dict)}

    assert threats["valid"]["evidence_check"] == "verified"
    # A file without a usable line proves nothing about the defect.
    assert threats["file-only"]["evidence_check"] == "ambiguous"
    assert threats["file-only"]["evidence_flags"] == ["no_line_cited"]
    assert threats["bad-line-token"]["evidence_check"] == "ambiguous"
    assert threats["bad-line-token"]["evidence_flags"] == ["no_line_cited"]
    assert threats["missing-file"]["evidence_check"] == "refuted"
    assert threats["missing-file"]["evidence_flags"] == ["file_missing"]
    assert threats["comment"]["evidence_check"] == "ambiguous"
    assert threats["comment"]["evidence_flags"] == ["comment_only_line"]
    assert threats["import"]["evidence_check"] == "ambiguous"
    assert threats["import"]["evidence_flags"] == ["import_line_only"]
    assert threats["out-of-range"]["evidence_check"] == "ambiguous"
    assert threats["out-of-range"]["evidence_flags"] == ["line_out_of_range"]
    assert threats["mixed-missing"]["evidence_check"] == "verified"
    assert threats["mixed-missing"]["evidence_flags"] == ["existing", "partial_file_missing"]
    assert threats["mixed-comment"]["evidence_flags"] == ["some_comment_lines"]
    assert threats["mixed-import"]["evidence_flags"] == ["some_import_lines"]
    assert threats["no-evidence"]["evidence_check"] == "ambiguous"
    assert threats["no-evidence"]["evidence_flags"] == ["no_evidence"]
    assert stats == {"sampled": 11, "verified": 4, "refuted": 1, "ambiguous": 6, "skipped": 0}


def test_validate_yaml_respects_prior_verdicts_and_non_list_threats(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    data = {
        "threats": [
            _threat("verified", {"file": "missing.ts", "line": 1}, evidence_check="verified"),
            _threat("refuted", {"file": "missing.ts", "line": 1}, evidence_check="refuted"),
            _threat("ambiguous", {"file": "missing.ts", "line": 1}, evidence_check="ambiguous"),
            _threat("prior", {"file": "missing.ts", "line": 1}, evidence_check="verified-prior"),
        ]
    }

    updated, stats = vel.validate_yaml(data, repo)

    assert [t["evidence_check"] for t in updated["threats"]] == [
        "verified",
        "refuted",
        "ambiguous",
        "verified-prior",
    ]
    assert stats == {"sampled": 0, "verified": 0, "refuted": 0, "ambiguous": 0, "skipped": 4}
    assert vel.validate_yaml({"threats": "bad"}, repo)[1] == {
        "sampled": 0,
        "verified": 0,
        "refuted": 0,
        "ambiguous": 0,
        "skipped": 0,
    }


def test_config_file_exists_violation_verifies_when_target_file_is_absent(tmp_path: Path) -> None:
    """A missing lockfile proves IAC-050; it is not a broken evidence anchor."""
    repo = tmp_path / "repo"
    repo.mkdir()
    finding = _threat("T-040", {"file": "package-lock.json", "line": 0})
    finding.update(source="config-scan", config_check_id="IAC-050")

    updated, stats = vel.validate_yaml({"threats": [finding]}, repo)

    assert updated["threats"][0]["evidence_check"] == "verified"
    assert updated["threats"][0]["evidence_flags"] == ["expected_file_absent"]
    assert stats == {"sampled": 1, "verified": 1, "refuted": 0, "ambiguous": 0, "skipped": 0}


def test_main_reports_input_errors(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()

    assert vel.main([str(out), "--repo-root", str(tmp_path / "missing")]) == 1
    assert "repo-root" in capsys.readouterr().err

    assert vel.main([str(out), "--repo-root", str(repo)]) == 1
    assert "no yaml" in capsys.readouterr().err

    _write(out / "threat-model.yaml", ":\n")
    assert vel.main([str(out), "--repo-root", str(repo)]) == 1
    assert "could not parse" in capsys.readouterr().err

    _write(out / "threat-model.yaml", "- not a mapping\n")
    assert vel.main([str(out), "--repo-root", str(repo)]) == 1
    assert "did not parse to a mapping" in capsys.readouterr().err


def test_main_updates_yaml_and_prints_stats(tmp_path: Path, capsys) -> None:
    repo = tmp_path / "repo"
    out = tmp_path / "out"
    repo.mkdir()
    out.mkdir()
    _write(repo / "src" / "app.ts", "const sql = query(req.body.id)\n")
    _write(
        out / "threat-model.yaml",
        vel.yaml.safe_dump(
            {
                "threats": [
                    _threat("T-001", {"file": "src/app.ts", "line": 1}),
                    _threat("T-002", {"file": "missing.ts", "line": 1}, evidence_check="unchecked"),
                    _threat("T-003", {"file": "missing.ts", "line": 1}, evidence_check="verified"),
                ]
            },
            sort_keys=False,
        ),
    )

    assert vel.main([str(out), "--repo-root", str(repo)]) == 0

    written = vel.yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))
    assert [t["evidence_check"] for t in written["threats"]] == ["verified", "verified"]
    assert "sampled=2 verified=1 refuted=1 ambiguous=0 skipped(prior)=1 dropped_refuted=1" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Floor durability under rebuild.
#
# Stage 1d regenerates threat-model.yaml from .threats-merged.json whenever
# abuse-case verification ran (standard/thorough depth). A floor that wrote
# only to the YAML was discarded there — observed as 0 verified / 56 unchecked
# on standard-depth runs while quick, which skips the rebuild, kept 33
# verified. These tests pin the verdicts into the merged intermediate so the
# rebuild cannot drop them.
# ---------------------------------------------------------------------------


def _merged(*t_ids: str, evidence_check: str | None = None) -> dict:
    threats = []
    for tid in t_ids:
        threat = {"t_id": tid, "title": tid, "risk": "High", "cwe": "CWE-89", "likelihood": "High"}
        if evidence_check is not None:
            threat["evidence_check"] = evidence_check
        threats.append(threat)
    return {"threats": threats}


@pytest.mark.parametrize(
    ("evidence", "check", "basis"),
    [
        ({"file": "src/app.ts", "line": 1}, "verified", "pointer-resolved"),
        ({"file": "lib/handlers/upload.py", "line": 2}, "verified", "pointer-resolved"),
        ({"file": "src/missing.ts", "line": 1}, "refuted", "refuted"),
        ({"file": "src/app.ts", "line": 2}, "ambiguous", "ambiguous"),
    ],
)
def test_a_resolved_pointer_is_verified_but_not_confirmed(tmp_path: Path, evidence, check, basis) -> None:
    repo = tmp_path / "repo"
    _write(repo / "src" / "app.ts", "const sql = query(req.body.id)\n// comment only\n")
    _write(repo / "lib" / "handlers" / "upload.py", "import os\nopen(request.files['f'].filename, 'wb')\n")

    updated, _ = vel.validate_yaml({"threats": [_threat("T-1", evidence)]}, repo)

    threat = updated["threats"][0]
    assert (threat["evidence_check"], threat["evidence_basis"]) == (check, basis)
    # Finding the cited line does not establish the finding.
    assert not is_confirmed(threat)


def test_a_verifier_verdict_keeps_its_basis(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "src" / "app.ts", "const sql = query(req.body.id)\n")
    threat = _threat("T-1", {"file": "src/app.ts", "line": 1}, evidence_check="verified")
    threat["evidence_basis"] = "llm-verified"

    updated, _ = vel.validate_yaml({"threats": [threat]}, repo)

    assert updated["threats"][0]["evidence_basis"] == "llm-verified"
    assert is_confirmed(updated["threats"][0])


def test_persist_to_merged_mirrors_verdicts_and_respects_prior(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write(
        out / ".threats-merged.json",
        vel.json.dumps(
            {
                "threats": [
                    {"t_id": "T-001", "title": "a"},
                    {"t_id": "T-002", "title": "b"},
                    # A genuine LLM verdict already present — must not be lowered.
                    {"t_id": "T-003", "title": "c", "evidence_check": "verified"},
                ]
            }
        ),
    )
    data = {
        "threats": [
            {**_threat("T-001", evidence_check="verified", flags=["ok"]), "evidence_basis": "pointer-resolved"},
            _threat("T-002", evidence_check="refuted", flags=["file_missing"]),
            _threat("T-003", evidence_check="ambiguous"),
        ]
    }

    assert vel.persist_to_merged(out, data) == 2

    merged = vel.json.loads((out / ".threats-merged.json").read_text(encoding="utf-8"))
    by_id = {t["t_id"]: t for t in merged["threats"]}
    assert by_id["T-001"]["evidence_check"] == "verified"
    assert by_id["T-001"]["evidence_basis"] == "pointer-resolved"
    assert by_id["T-001"]["evidence_flags"] == ["ok"]
    # Refuted is retained in the merged intermediate for audit — the drop
    # happens only in the active model.
    assert by_id["T-002"]["evidence_check"] == "refuted"
    assert by_id["T-003"]["evidence_check"] == "verified"


def test_persist_to_merged_tolerates_missing_or_malformed_intermediate(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    data = {"threats": [_threat("T-001", evidence_check="verified")]}

    assert vel.persist_to_merged(out, data) == 0

    _write(out / ".threats-merged.json", "{ not json")
    assert vel.persist_to_merged(out, data) == 0

    _write(out / ".threats-merged.json", vel.json.dumps({"threats": "not-a-list"}))
    assert vel.persist_to_merged(out, data) == 0


def test_floor_verdicts_survive_yaml_rebuild(tmp_path: Path) -> None:
    """End-to-end: run the floor, then rebuild from the merged intermediate.

    This is the regression the previous test suite could not catch — it
    asserted the floor ran, never that its output reached the final artifact.
    """
    import model.build_threat_model_yaml as btm

    repo = tmp_path / "repo"
    out = tmp_path / "out"
    out.mkdir()
    _write(repo / "src" / "app.ts", "const sql = query(req.body.id)\n")
    _write(out / ".threats-merged.json", vel.json.dumps(_merged("T-001", "T-002")))
    _write(
        out / "threat-model.yaml",
        vel.yaml.safe_dump(
            {
                "threats": [
                    _threat("T-001", {"file": "src/app.ts", "line": 1}),
                    _threat("T-002", {"file": "gone.ts", "line": 1}),
                ]
            },
            sort_keys=False,
        ),
    )

    assert vel.main([str(out), "--repo-root", str(repo)]) == 0

    merged = vel.json.loads((out / ".threats-merged.json").read_text(encoding="utf-8"))
    rebuilt, _warnings = btm.build_threats(merged)

    by_id = {t["id"]: t for t in rebuilt}
    # The verified verdict survived the rebuild instead of resetting to unchecked.
    assert by_id["T-001"]["evidence_check"] == "verified"
    # The refuted candidate is dropped by the rebuild's own filter.
    assert "T-002" not in by_id


# ---------------------------------------------------------------------------
# Inference / coverage-gap provenance gate — must NOT auto-verify off a
# structurally-valid-but-attached evidence anchor (the T-065 case).
# ---------------------------------------------------------------------------


def test_inferred_source_caps_at_ambiguous_not_verified(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "data" / "static" / "challenges.yml", "\n" * 1380 + "  key: value\n")
    t = _threat("coverage-gap-finding", {"file": "data/static/challenges.yml", "line": 1381})
    t["source"] = "coverage-gap"
    data = {"threats": [t]}
    vel.validate_yaml(data, repo)
    assert data["threats"][0]["evidence_check"] == "ambiguous"
    assert "evidence_anchor_unverified" in data["threats"][0]["evidence_flags"]


def test_tier_reclassified_flag_caps_at_ambiguous(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "data" / "static" / "challenges.yml", "\n" * 1380 + "  key: value\n")
    data = {
        "threats": [
            _threat(
                "T-065",
                {"file": "data/static/challenges.yml", "line": 1381},
                flags=["tier_reclassified_from_data"],
            )
        ]
    }
    vel.validate_yaml(data, repo)
    assert data["threats"][0]["evidence_check"] == "ambiguous"
    assert "evidence_anchor_unverified" in data["threats"][0]["evidence_flags"]


def test_code_source_on_same_line_still_verifies(tmp_path: Path) -> None:
    # Negative control: a non-inferred (stride) finding on the SAME real line
    # still verifies — proving the gate is provenance-scoped, not blanket.
    repo = tmp_path / "repo"
    _write(repo / "data" / "static" / "challenges.yml", "\n" * 1380 + "  key: value\n")
    t = _threat("T-001", {"file": "data/static/challenges.yml", "line": 1381})
    t["source"] = "stride"
    data = {"threats": [t]}
    vel.validate_yaml(data, repo)
    assert data["threats"][0]["evidence_check"] == "verified"


SIGNED = "      - run: cosign sign img\n"
PUSHING_WORKFLOW = """\
jobs:
  image:
    steps:
      - uses: docker/build-push-action@v6
        with:
          push: true
"""


def _absence_threat(check_id: str, file: str, searched: list[str]) -> dict:
    finding = _threat(
        "T-050",
        {"file": file, "line": 0, "kind": "absence", "searched_files": searched, "searched_file_count": len(searched)},
    )
    finding.update(source="config-scan", config_check_id=check_id)
    return finding


def test_a_repository_absence_is_verified_by_rerunning_its_check_not_by_a_line(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    workflow = repo / ".github" / "workflows" / "release.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(PUSHING_WORKFLOW, encoding="utf-8")
    finding = _absence_threat("IAC-040", ".github/workflows/*.yml", [".github/workflows/release.yml"])

    updated, _ = vel.validate_yaml({"threats": [dict(finding)]}, repo)
    assert updated["threats"][0]["evidence_check"] == "verified"
    assert updated["threats"][0]["evidence_flags"] == ["absence_confirmed"]
    assert updated["threats"][0]["evidence_basis"] == "absence-verified"
    assert is_confirmed(updated["threats"][0])

    workflow.write_text(PUSHING_WORKFLOW + SIGNED, encoding="utf-8")
    updated, _ = vel.validate_yaml({"threats": [dict(finding)]}, repo)
    assert updated["threats"][0]["evidence_check"] == "refuted"
    assert updated["threats"][0]["evidence_flags"] == ["absence_contradicted"]


def test_an_absent_file_absence_is_refuted_once_the_file_exists(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    finding = _absence_threat("IAC-050", "package-lock.json", [])

    updated, _ = vel.validate_yaml({"threats": [dict(finding)]}, repo)
    assert updated["threats"][0]["evidence_check"] == "verified"

    (repo / "package-lock.json").write_text("{}", encoding="utf-8")
    updated, _ = vel.validate_yaml({"threats": [dict(finding)]}, repo)
    assert updated["threats"][0]["evidence_check"] == "refuted"


def test_absence_evidence_on_a_non_config_finding_is_not_trusted(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    finding = _threat("T-051", {"file": "app.py", "line": 0, "kind": "absence", "searched_files": ["app.py"]})
    finding["source"] = "stride"

    updated, _ = vel.validate_yaml({"threats": [finding]}, repo)
    assert updated["threats"][0]["evidence_check"] == "ambiguous"
    assert updated["threats"][0]["evidence_flags"] == ["no_line_cited"]
