"""Tests for scripts/check_fragment_registry.py — fragment-registry drift linter.

Covers the AST literal extractor (literal, annotated-assign, non-literal,
not-found), the contract-section parser, on-disk schema enumeration, the
real-repo consistency check (must be clean), and the CLI clean/quiet/drift
exit codes. Pins CURRENT behavior — no producer edits.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_fragment_registry as cfr  # noqa: E402

# ---------- _extract_dict_literal ----------------------------------------


def test_extract_plain_assign():
    src = "FOO = {'a': 1, 'b': [2, 3]}\n"
    assert cfr._extract_dict_literal(src, "FOO") == {"a": 1, "b": [2, 3]}


def test_extract_annotated_assign():
    src = "BAR: dict = {'x': 'y'}\n"
    assert cfr._extract_dict_literal(src, "BAR") == {"x": "y"}


def test_extract_non_literal_assign_exits():
    src = "FOO = some_func()\n"
    with pytest.raises(SystemExit) as e:
        cfr._extract_dict_literal(src, "FOO")
    assert "not a literal" in str(e.value)


def test_extract_non_literal_annassign_exits():
    src = "FOO: dict = make_it()\n"
    with pytest.raises(SystemExit) as e:
        cfr._extract_dict_literal(src, "FOO")
    assert "not a literal" in str(e.value)


def test_extract_not_found_exits():
    src = "OTHER = {}\n"
    with pytest.raises(SystemExit) as e:
        cfr._extract_dict_literal(src, "MISSING")
    assert "not found" in str(e.value)


# ---------- contract parser ----------------------------------------------


def test_contract_sections_by_fragment_type():
    contract = {
        "sections": {
            "s_data": {"fragment_type": "data", "fragment": "f.json", "schema": "f.schema.json"},
            "s_hybrid": {"fragment_type": "hybrid", "fragment": "h.md", "schema": "h.schema.json"},
            "s_md": {"fragment_type": "markdown", "fragment": "m.md"},
            "s_skip": "not-a-dict",
            "s_other": {"fragment_type": "unknown"},
        },
        "document": {
            "order": [
                "s_data",
                {"id": "s_md", "condition": "always"},
                42,  # neither str nor dict → ignored
            ]
        },
    }
    data, md, allsec, order = cfr._contract_sections_by_fragment_type(contract)
    assert data["s_data"]["schema"] == "f.schema.json"
    assert "s_hybrid" in data
    assert md["s_md"] == "m.md"
    assert ("s_data", None) in order
    assert ("s_md", "always") in order


def test_contract_empty_sections():
    data, md, allsec, order = cfr._contract_sections_by_fragment_type({})
    assert data == {} and md == {} and order == []


# ---------- on-disk schemas + real check ---------------------------------


def test_on_disk_schema_stems_nonempty():
    stems = cfr._on_disk_schema_stems()
    assert stems
    assert all(s.endswith(".schema.json") for s in stems)


def test_real_repo_check_is_clean():
    """The shipped repo must have zero drift — pins the invariant."""
    assert cfr.check() == []


def test_reverse_guard_flags_orphan_contract_section_fragment(monkeypatch):
    """A retired section id left in CONTRACT_SECTION_FRAGMENTS that is not a
    real contract section must be rejected. Checks 4/5 compare only SHARED
    keys, so the 2026-07 `top_findings` orphan (retired into `top_threats`)
    stayed invisible and mis-routed table-schema repairs."""
    real = cfr._extract_dict_literal

    def fake(src, name):
        d = real(src, name)
        if name == "CONTRACT_SECTION_FRAGMENTS":
            return {**d, "totally_retired_section": []}
        return d

    monkeypatch.setattr(cfr, "_extract_dict_literal", fake)
    errors = cfr.check()
    assert any("totally_retired_section" in e and "not a section" in e for e in errors)


# ---------- CLI -----------------------------------------------------------


def test_main_clean(capsys):
    assert cfr.main([]) == 0
    assert "consistent" in capsys.readouterr().out


def test_main_quiet(capsys):
    assert cfr.main(["--quiet"]) == 0
    assert capsys.readouterr().out == ""


def test_main_drift_reports(monkeypatch, capsys):
    monkeypatch.setattr(cfr, "check", lambda: ["drift A", "drift B"])
    rc = cfr.main([])
    assert rc == 1
    err = capsys.readouterr().err
    assert "drift detected" in err
    assert "drift A" in err
    assert "2 drift(s) found" in err
