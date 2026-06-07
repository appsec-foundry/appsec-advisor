"""Tests for scripts/render_review_report.py — the appsec-reviewer Markdown artifact."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import render_review_report as rr  # noqa: E402


def _verdict(results, source="bundled-bestpractices"):
    fail = sum(1 for r in results if r["status"] == "FAIL")
    partial = sum(1 for r in results if r["status"] == "PARTIAL")
    return {
        "version": 1, "generated_at": "2026-06-07T00:00:00Z", "base_ref": "origin/main",
        "priority_floor": "MUST", "requirements_source": source,
        "summary": {
            "changed_files": 2, "candidates": len(results),
            "in_scope": sum(1 for r in results if r["in_scope"]),
            "pass": sum(1 for r in results if r["status"] == "PASS"),
            "partial": partial, "fail": fail, "unverifiable": 0,
            "not_applicable": sum(1 for r in results if r["status"] == "NOT_APPLICABLE"),
            "gating_failures": fail,
        },
        "results": results,
    }


def test_open_findings_render_with_fix_and_effort():
    md = rr.render(_verdict([
        {"id": "BP-INJ-SQL-PARAM", "priority": "MUST", "status": "FAIL", "in_scope": True,
         "finding": "raw query in search.ts:23", "fix": "use bound params", "effort": "M",
         "evidence": [{"file": "search.ts", "line": 23}], "url": "https://owasp.org/x"},
        {"id": "BP-HEADERS-CSP", "priority": "SHOULD", "status": "PARTIAL", "in_scope": True,
         "finding": "CSP allows unsafe-inline", "fix": "drop unsafe-inline", "effort": "S"},
        {"id": "BP-AUTH-PWD-HASH", "priority": "MUST", "status": "PASS", "in_scope": True},
    ]))
    assert "## What to fix" in md
    assert "BP-INJ-SQL-PARAM" in md and "BP-HEADERS-CSP" in md
    assert "use bound params" in md
    assert "`search.ts:23`" in md
    assert "built-in best-practices baseline" in md
    # PASS items are not detailed, only summarised.
    assert "### 🟢 PASS" not in md


def test_fail_sorts_before_partial():
    md = rr.render(_verdict([
        {"id": "R-PARTIAL", "priority": "MUST", "status": "PARTIAL", "in_scope": True, "finding": "p"},
        {"id": "R-FAIL", "priority": "MUST", "status": "FAIL", "in_scope": True, "finding": "f"},
    ]))
    assert md.index("R-FAIL") < md.index("R-PARTIAL")


def test_not_applicable_and_out_of_scope_never_shown_as_open():
    md = rr.render(_verdict([
        {"id": "R-NA", "priority": "MUST", "status": "NOT_APPLICABLE", "in_scope": False, "finding": "n/a"},
        {"id": "R-OOS", "priority": "MUST", "status": "FAIL", "in_scope": False, "finding": "out of scope"},
    ]))
    assert "## What to fix" not in md
    assert "No open requirements" in md


def test_company_source_label():
    md = rr.render(_verdict([], source="https://asr.int.example.com"))
    assert "https://asr.int.example.com" in md


def test_main_writes_file(tmp_path):
    vp = tmp_path / "v.json"
    vp.write_text(json.dumps(_verdict([
        {"id": "BP-X", "priority": "MUST", "status": "FAIL", "in_scope": True, "finding": "x", "fix": "y", "effort": "S"},
    ])), encoding="utf-8")
    out = tmp_path / "report.md"
    assert rr.main(["--verdict", str(vp), "--output", str(out)]) == 0
    assert "BP-X" in out.read_text(encoding="utf-8")


def test_main_missing_verdict_exits_two(tmp_path):
    assert rr.main(["--verdict", str(tmp_path / "nope.json"), "--output", str(tmp_path / "o.md")]) == 2
