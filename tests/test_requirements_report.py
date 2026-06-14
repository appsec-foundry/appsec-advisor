"""Tests for scripts/requirements_report.py and the requirements-audit verdict.

Covers deterministic summary recomputation, schema validation, and that the
shared scripts/requirements_gate.py reads the full-repo audit verdict.
"""

from __future__ import annotations

import builtins
import json
import subprocess
import sys
from pathlib import Path

import requirements_report as rr

REPO_ROOT = Path(__file__).parent.parent
REPORT = REPO_ROOT / "scripts" / "requirements_report.py"
GATE = REPO_ROOT / "scripts" / "requirements_gate.py"


def _verdict() -> dict:
    return {
        "version": 1,
        "generated_at": "2026-06-13T00:00:00Z",
        "repository": "juice-shop",
        "requirements_source": "cached",
        "priority_floor": "MUST",
        "summary": {"total": 0, "pass": 0, "partial": 0, "fail": 0, "unverifiable": 0, "not_applicable": 0},
        "results": [
            {"id": "SEC-SQL", "priority": "MUST", "status": "FAIL", "in_scope": True, "finding": "raw query"},
            {"id": "SEC-CSP", "priority": "SHOULD", "status": "PARTIAL", "in_scope": True},
            {"id": "SEC-HSTS", "priority": "MUST", "status": "PASS", "in_scope": True},
            {"id": "SCG-XML", "priority": "MUST", "status": "NOT_APPLICABLE", "in_scope": False},
        ],
    }


def test_recompute_summary_counts():
    s = rr.recompute_summary(_verdict())
    assert s == {"total": 4, "pass": 1, "partial": 1, "fail": 1, "unverifiable": 0, "not_applicable": 1}


def test_recompute_summary_skips_non_mapping_rows():
    v = _verdict()
    v["results"].append("not-a-result")

    s = rr.recompute_summary(v)

    assert s["total"] == 4


def test_schema_errors_minimal_fallback_without_jsonschema(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    assert rr._schema_errors(["not-an-object"]) == ["top level is not an object"]
    assert rr._schema_errors({"results": "not-a-list"}) == ["results: must be an array"]
    assert rr._schema_errors({"results": [{}, "not-a-result"]}) == [
        "results[0]: missing id",
        "results[1]: missing id",
    ]


def test_schema_errors_reports_unreadable_schema(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "SCHEMA_PATH", tmp_path / "missing.schema.json")

    errors = rr._schema_errors(_verdict())

    assert len(errors) == 1
    assert errors[0].startswith("cannot read schema:")


def test_schema_valid_verdict_passes(tmp_path):
    f = tmp_path / ".requirements-audit.json"
    f.write_text(json.dumps(_verdict()), encoding="utf-8")
    r = subprocess.run([sys.executable, str(REPORT), "--audit", str(f)], capture_output=True, text=True)
    assert r.returncode == 0
    assert r.stdout.strip() == "total=4 pass=1 partial=1 fail=1 unverifiable=0 not_applicable=1"


def test_write_persists_recomputed_summary(tmp_path):
    f = tmp_path / ".requirements-audit.json"
    f.write_text(json.dumps(_verdict()), encoding="utf-8")
    subprocess.run([sys.executable, str(REPORT), "--audit", str(f), "--write"], capture_output=True, text=True)
    data = json.loads(f.read_text())
    assert data["summary"]["fail"] == 1 and data["summary"]["total"] == 4


def test_schema_invalid_verdict_fails(tmp_path):
    bad = _verdict()
    bad["results"][0]["status"] = "BROKEN"  # not in enum
    f = tmp_path / ".requirements-audit.json"
    f.write_text(json.dumps(bad), encoding="utf-8")
    r = subprocess.run([sys.executable, str(REPORT), "--audit", str(f)], capture_output=True, text=True)
    assert r.returncode == 2
    assert "schema-invalid" in r.stderr


def test_zero_placeholder_summary_emits_no_miscount_note(tmp_path):
    """The model writes summary as zeros by design — that must NOT warn."""
    f = tmp_path / ".requirements-audit.json"
    f.write_text(json.dumps(_verdict()), encoding="utf-8")  # summary all zeros
    r = subprocess.run([sys.executable, str(REPORT), "--audit", str(f)], capture_output=True, text=True)
    assert r.returncode == 0
    assert "disagreed" not in r.stderr


def test_populated_wrong_summary_warns(tmp_path):
    v = _verdict()
    v["summary"] = {"total": 99, "pass": 99, "partial": 0, "fail": 0, "unverifiable": 0, "not_applicable": 0}
    f = tmp_path / ".requirements-audit.json"
    f.write_text(json.dumps(v), encoding="utf-8")
    r = subprocess.run([sys.executable, str(REPORT), "--audit", str(f)], capture_output=True, text=True)
    assert r.returncode == 0
    assert "disagreed" in r.stderr


def test_missing_verdict_errors(tmp_path):
    r = subprocess.run([sys.executable, str(REPORT), "--audit", str(tmp_path / "nope.json")], capture_output=True, text=True)
    assert r.returncode == 2


def test_invalid_json_verdict_errors(tmp_path, capsys):
    f = tmp_path / ".requirements-audit.json"
    f.write_text("{", encoding="utf-8")

    assert rr.main(["--audit", str(f)]) == 2

    assert "could not read verdict" in capsys.readouterr().err


# --- the shared gate reads the full-repo audit verdict ---------------------
def test_gate_reads_audit_verdict_blocks_on_must_fail(tmp_path):
    f = tmp_path / ".requirements-audit.json"
    f.write_text(json.dumps(_verdict()), encoding="utf-8")
    r = subprocess.run([sys.executable, str(GATE), "--verdict", str(f), "--gate"], capture_output=True, text=True)
    assert r.returncode == 1  # SEC-SQL is in_scope MUST FAIL
    assert "BLOCK" in r.stdout


def test_gate_advisory_mode_never_blocks(tmp_path):
    f = tmp_path / ".requirements-audit.json"
    f.write_text(json.dumps(_verdict()), encoding="utf-8")
    r = subprocess.run([sys.executable, str(GATE), "--verdict", str(f)], capture_output=True, text=True)
    assert r.returncode == 0


def test_gate_partial_does_not_block_below_floor(tmp_path):
    """SEC-CSP is PARTIAL but SHOULD — below the MUST floor, so --gate-on partial still passes here."""
    v = _verdict()
    v["results"] = [v["results"][1]]  # only the SHOULD PARTIAL
    f = tmp_path / ".requirements-audit.json"
    f.write_text(json.dumps(v), encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(GATE), "--verdict", str(f), "--gate", "--gate-on", "partial"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
