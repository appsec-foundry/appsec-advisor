from __future__ import annotations

from pathlib import Path

import validate_evidence_lines as vel


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
    assert threats["file-only"]["evidence_check"] == "verified"
    assert threats["bad-line-token"]["evidence_check"] == "verified"
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
    assert stats == {"sampled": 11, "verified": 6, "refuted": 1, "ambiguous": 4, "skipped": 0}


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
    assert [t["evidence_check"] for t in written["threats"]] == ["verified", "refuted", "verified"]
    assert written["threats"][1]["evidence_flags"] == ["file_missing"]
    assert "sampled=2 verified=1 refuted=1 ambiguous=0 skipped(prior)=1" in capsys.readouterr().out


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
