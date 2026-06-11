"""Tests for run_summary — console intake/findings summaries for run-headless.

Covers requirement+blueprint counting with source names (and the description
fallback), Critical/High findings extraction with severity-field precedence and
ordering, and the fail-soft contract (missing/empty files print nothing, rc 0).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import run_summary  # noqa: E402


def _write(tmp_path: Path, data: dict) -> str:
    p = tmp_path / "f.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


# --- requirements ----------------------------------------------------------


def test_requirements_counts_and_source_names(tmp_path, capsys):
    path = _write(
        tmp_path,
        {
            "sources_meta": [
                {"title": "OWASP Security Requirements", "type": "requirement"},
                {"title": "OWASP Cheat Sheet Series", "type": "blueprint"},
            ],
            "categories": [
                {"id": "CAT-WEB", "requirements": [{"id": "W1"}, {"id": "W2"}]},
                {"id": "CAT-AC", "requirements": [{"id": "A1"}]},
            ],
            "blueprints": [{"id": "BP-1"}, {"id": "BP-2"}],
        },
    )
    assert run_summary.main(["run_summary.py", "requirements", path]) == 0
    out = capsys.readouterr().out
    assert "3 requirements" in out
    assert "2 blueprints" in out
    assert "OWASP Security Requirements, OWASP Cheat Sheet Series" in out


def test_requirements_falls_back_to_description(tmp_path, capsys):
    path = _write(
        tmp_path,
        {
            "description": "Generic OWASP baseline",
            "categories": [{"requirements": [{"id": "W1"}]}],
            "blueprints": [],
        },
    )
    run_summary.main(["run_summary.py", "requirements", path])
    out = capsys.readouterr().out
    assert "1 requirements, 0 blueprints" in out
    assert "Generic OWASP baseline" in out


def test_requirements_empty_prints_nothing(tmp_path, capsys):
    path = _write(tmp_path, {"categories": [], "blueprints": []})
    run_summary.main(["run_summary.py", "requirements", path])
    assert capsys.readouterr().out == ""


# --- findings --------------------------------------------------------------


def test_findings_lists_critical_then_high(tmp_path, capsys):
    path = _write(
        tmp_path,
        {
            "threats": [
                {"id": "T-001", "title": "SQLi", "effective_severity": "Critical"},
                {"id": "T-002", "title": "XSS", "effective_severity": "High"},
                {"id": "T-003", "title": "Info leak", "effective_severity": "Medium"},
                {"id": "T-004", "title": "Auth bypass", "effective_severity": "Critical"},
            ]
        },
    )
    run_summary.main(["run_summary.py", "findings", path])
    out = capsys.readouterr().out
    assert "Critical: 2, High: 1" in out
    # Medium is excluded; Criticals are listed before Highs.
    assert "Info leak" not in out
    assert out.index("T-001") < out.index("T-004") < out.index("T-002")


def test_findings_severity_field_precedence(tmp_path, capsys):
    # effective_severity wins; else risk; else severity.
    path = _write(
        tmp_path,
        {
            "threats": [
                {"id": "T-1", "title": "a", "risk": "High", "severity": "Low"},
                {"id": "T-2", "title": "b", "severity": "Critical"},
            ]
        },
    )
    run_summary.main(["run_summary.py", "findings", path])
    out = capsys.readouterr().out
    assert "Critical: 1, High: 1" in out


def test_findings_none_prints_nothing(tmp_path, capsys):
    path = _write(
        tmp_path,
        {
            "threats": [
                {"id": "T-1", "title": "x", "effective_severity": "Low"},
            ]
        },
    )
    run_summary.main(["run_summary.py", "findings", path])
    assert capsys.readouterr().out == ""


# --- contract --------------------------------------------------------------


def test_missing_file_is_silent_rc0(capsys):
    assert run_summary.main(["run_summary.py", "findings", "/no/such.yaml"]) == 0
    assert capsys.readouterr().out == ""


def test_bad_usage_returns_2():
    assert run_summary.main(["run_summary.py", "bogus", "x"]) == 2
