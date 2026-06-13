"""Tests for scripts/requirements_report.py and the requirements-audit verdict.

Covers deterministic summary recomputation, schema validation, and that the
shared scripts/requirements_gate.py reads the full-repo audit verdict.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
REPORT = REPO_ROOT / "scripts" / "requirements_report.py"
GATE = REPO_ROOT / "scripts" / "requirements_gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("requirements_report", REPORT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rr = _load()


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


def test_missing_verdict_errors(tmp_path):
    r = subprocess.run([sys.executable, str(REPORT), "--audit", str(tmp_path / "nope.json")], capture_output=True, text=True)
    assert r.returncode == 2


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
