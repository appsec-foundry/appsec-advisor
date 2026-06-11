"""Schema validity + diff-builder smoke for the verify-requirements pipeline.

Covers:
  * schemas/requirements-verification.schema.json is valid Draft 2020-12 and a
    representative verdict validates against it.
  * scripts/build_verify_diff.py produces a well-formed .verify-diff.json on a
    real (temporary) git repo.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).parent.parent
SCHEMA_PATH = ROOT / "schemas" / "requirements-verification.schema.json"
sys.path.insert(0, str(ROOT / "scripts"))

import build_verify_diff  # noqa: E402

# --- schema ------------------------------------------------------------------


def test_schema_is_valid_jsonschema():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)


def test_representative_verdict_validates():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    verdict = {
        "version": 1,
        "generated_at": "2026-06-07T00:00:00Z",
        "model_id": "sonnet",
        "base_ref": "origin/main",
        "head_ref": "HEAD",
        "priority_floor": "MUST",
        "requirements_source": "remote",
        "summary": {
            "changed_files": 2,
            "candidates": 3,
            "in_scope": 2,
            "pass": 1,
            "partial": 0,
            "fail": 1,
            "unverifiable": 0,
            "not_applicable": 1,
            "gating_failures": 1,
        },
        "results": [
            {
                "id": "SEC-SQL",
                "category": "SEC-SECURE_DATA_HANDLING",
                "priority": "MUST",
                "status": "FAIL",
                "in_scope": True,
                "evidence": [{"file": "src/routes/search.ts", "line": 23}],
                "finding": "raw input reaches sequelize.query() at line 23",
                "fix": "bind the term via replacements",
                "effort": "M",
                "url": "https://asr.int.example.com/scg#sec-sql",
                "gating": True,
            },
            {
                "id": "SEC-CSP",
                "priority": "SHOULD",
                "status": "PASS",
                "in_scope": True,
            },
            {
                "id": "SEC-CORS",
                "priority": "MUST",
                "status": "NOT_APPLICABLE",
                "in_scope": False,
                "finding": "diff does not touch any cross-origin surface",
            },
        ],
    }
    errors = sorted(Draft202012Validator(schema).iter_errors(verdict), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(f"{'.'.join(str(p) for p in e.absolute_path) or 'root'}: {e.message}" for e in errors)


def test_schema_rejects_unknown_status():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    bad = {
        "version": 1,
        "generated_at": "2026-06-07T00:00:00Z",
        "base_ref": "main",
        "priority_floor": "MUST",
        "summary": {
            "changed_files": 0,
            "candidates": 0,
            "in_scope": 0,
            "pass": 0,
            "partial": 0,
            "fail": 0,
            "unverifiable": 0,
            "not_applicable": 0,
            "gating_failures": 0,
        },
        "results": [{"id": "X", "priority": "MUST", "status": "MAYBE", "in_scope": True}],
    }
    errors = list(Draft202012Validator(schema).iter_errors(bad))
    assert errors, "schema must reject an out-of-enum status"


# --- diff builder ------------------------------------------------------------


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_build_verify_diff_on_staged_change(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True, text=True)

    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "Test")
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    git("add", "app.py")
    git("commit", "-qm", "init")

    # Make a staged change.
    (repo / "app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    git("add", "app.py")

    out_dir = repo / "docs" / "security"
    rc = build_verify_diff.main(
        [
            "--repo-root",
            str(repo),
            "--output-dir",
            str(out_dir),
            "--staged",
        ]
    )
    assert rc == 0
    sidecar = json.loads((out_dir / ".verify-diff.json").read_text(encoding="utf-8"))
    assert sidecar["mode"] == "staged"
    assert [f["path"] for f in sidecar["changed_files"]] == ["app.py"]
    assert "y = 2" in sidecar["diff_unified"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_build_verify_diff_not_a_git_repo(tmp_path):
    rc = build_verify_diff.main(
        [
            "--repo-root",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 2


# --- best-practices baseline + helper fallback -------------------------------

BASELINE_PATH = ROOT / "data" / "appsec-bestpractices-baseline.yaml"


def test_baseline_is_vendor_neutral_and_well_formed():
    import yaml

    d = yaml.safe_load(BASELINE_PATH.read_text(encoding="utf-8"))
    assert d["source"] == "bundled-bestpractices"
    reqs = [r for c in d["categories"] for r in c["requirements"]]
    assert reqs, "baseline must contain requirements"
    # Vendor-neutral: BP-* ids, no internal company host, public OWASP urls.
    assert all(r["id"].startswith("BP-") for r in reqs)
    assert all(r["priority"] in ("MUST", "SHOULD", "MAY") for r in reqs)
    text = BASELINE_PATH.read_text(encoding="utf-8")
    assert "int.kn" not in text and "asr.int" not in text


def test_fetch_falls_back_to_baseline_when_no_company_source(tmp_path):
    import fetch_requirements

    rc = fetch_requirements.main(
        [
            "--caller",
            "verify-requirements",
            "--output-dir",
            str(tmp_path),
            "--plugin-root",
            str(ROOT),
            "--cache-path",
            str(tmp_path / "absent-cache.yaml"),
            "--require",
            "--fallback-baseline",
            str(BASELINE_PATH),
        ]
    )
    assert rc == 0
    written = (tmp_path / ".requirements.yaml").read_text(encoding="utf-8")
    assert "source: bundled-bestpractices" in written


def test_fetch_explicit_source_failure_does_not_fall_back(tmp_path):
    # An explicitly-named --requirements source that fails must still abort
    # (exit 2) — the baseline fallback must NOT rescue a deliberately-named source.
    import fetch_requirements

    rc = fetch_requirements.main(
        [
            "--caller",
            "verify-requirements",
            "--output-dir",
            str(tmp_path),
            "--plugin-root",
            str(ROOT),
            "--requirements",
            str(tmp_path / "does-not-exist.yaml"),
            "--fallback-baseline",
            str(BASELINE_PATH),
        ]
    )
    assert rc == 2
    assert not (tmp_path / ".requirements.yaml").exists() or "bundled-bestpractices" not in (
        tmp_path / ".requirements.yaml"
    ).read_text(encoding="utf-8")
