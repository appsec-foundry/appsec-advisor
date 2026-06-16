"""In-process coverage tests for scripts/check_inline_shortcut.py.

The existing test_check_inline_shortcut.py drives the gate as a subprocess.
These tests import the module directly to deterministically exercise the
Indicator-D YAML path, banner branches, the qa-fragments error paths, the
repair-plan write (success + OSError), and _list_missing_fragments edges.

Pins CURRENT behavior — no producer edits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_inline_shortcut as cis  # noqa: E402


def _make_full_run(d: Path):
    """Create a directory that passes A1/A2/B/C so we can isolate Indicator D."""
    frag = d / ".fragments"
    frag.mkdir()
    for n in ("a.md", "b.md", "c.json"):
        (frag / n).write_text("x", encoding="utf-8")
    (d / "threat-model.md").write_text("# md", encoding="utf-8")
    (d / ".threats-merged.json").write_text("{}", encoding="utf-8")
    (d / ".triage-flags.json").write_text("{}", encoding="utf-8")


# ---------- Indicator D (lines 113-128) ----------------------------------


def test_indicator_d_missing_arrays(tmp_path):
    _make_full_run(tmp_path)
    (tmp_path / "threat-model.yaml").write_text("attack_surface: []\n", encoding="utf-8")
    reasons = cis._detect_indicators(tmp_path, "standard")
    # All three required arrays absent/empty → 3 Indicator-D reasons.
    d_reasons = [r for r in reasons if "threat-model.yaml:" in r]
    assert len(d_reasons) == 3


def test_indicator_d_present_arrays_clean(tmp_path):
    _make_full_run(tmp_path)
    (tmp_path / "threat-model.yaml").write_text(
        "attack_surface: [x]\ntrust_boundaries: [y]\nsecurity_controls: [z]\n",
        encoding="utf-8",
    )
    reasons = cis._detect_indicators(tmp_path, "standard")
    assert reasons == []


def test_indicator_d_unparseable_yaml(tmp_path):
    _make_full_run(tmp_path)
    (tmp_path / "threat-model.yaml").write_text("a: [: broken : yaml", encoding="utf-8")
    reasons = cis._detect_indicators(tmp_path, "standard")
    assert any("could not be parsed for Indicator D" in r for r in reasons)


# ---------- _run_qa_fragments_check (lines 141, 150-151) ------------------


def test_qa_check_missing_qa_script(tmp_path, monkeypatch):
    monkeypatch.setattr(cis, "PLUGIN_ROOT", tmp_path)  # scripts/qa_checks.py absent
    assert cis._run_qa_fragments_check(tmp_path) == 3


def test_qa_check_subprocess_error(tmp_path, monkeypatch):
    qa = tmp_path / "scripts"
    qa.mkdir()
    (qa / "qa_checks.py").write_text("# stub", encoding="utf-8")
    monkeypatch.setattr(cis, "PLUGIN_ROOT", tmp_path)

    def boom(*a, **k):
        raise OSError("no exec")

    monkeypatch.setattr(cis.subprocess, "run", boom)
    assert cis._run_qa_fragments_check(tmp_path) == 3


# ---------- _print_banner Indicator-D branch (lines 186-193) -------------


def test_banner_yaml_indicator_branch(capsys):
    reasons = ["threat-model.yaml: 'attack_surface' is absent or empty — ..."]
    cis._print_banner(reasons, 0, Path("/tmp/x"))
    err = capsys.readouterr().err
    assert "Root cause (Indicator D)" in err
    # Pure-D reasons → structural root-cause block should NOT appear.
    assert "skipped Phase 11 Substep 4" not in err


def test_banner_structural_branch(capsys):
    cis._print_banner([".fragments/ directory missing — ..."], 2, Path("/tmp/x"))
    err = capsys.readouterr().err
    assert "skipped Phase 11 Substep 4" in err


# ---------- main(): output dir missing (lines 223-225) -------------------


def test_main_output_dir_missing(tmp_path, capsys):
    rc = cis.main([str(tmp_path / "nope")])
    assert rc == 3
    assert "does not exist" in capsys.readouterr().err


# ---------- main(): --write-repair-plan success (lines 238-250) ----------


def test_main_write_repair_plan(tmp_path, monkeypatch):
    # A1 trips (no .fragments). Force qa exit non-zero so we hit the fail path.
    monkeypatch.setattr(cis, "_run_qa_fragments_check", lambda d: 1)
    rc = cis.main([str(tmp_path), "--write-repair-plan"])
    assert rc == 2
    plan = json.loads((tmp_path / ".inline-shortcut-repair-plan.json").read_text())
    assert plan["kind"] == "inline_shortcut"
    assert plan["status"] == "fail"


# ---------- main(): repair-plan OSError (lines 251-252) -------------------


def test_main_write_repair_plan_oserror(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cis, "_run_qa_fragments_check", lambda d: 1)
    orig_write = Path.write_text

    def fail_write(self, *a, **k):
        if self.name == ".inline-shortcut-repair-plan.json":
            raise OSError("disk full")
        return orig_write(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", fail_write)
    rc = cis.main([str(tmp_path), "--write-repair-plan"])
    assert rc == 2
    assert "Failed to write repair plan" in capsys.readouterr().err


# ---------- main(): clean run returns 0 ----------------------------------


def test_main_clean(tmp_path, monkeypatch):
    _make_full_run(tmp_path)
    (tmp_path / "threat-model.yaml").write_text(
        "attack_surface: [x]\ntrust_boundaries: [y]\nsecurity_controls: [z]\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cis, "_run_qa_fragments_check", lambda d: 0)
    assert cis.main([str(tmp_path)]) == 0


# ---------- _list_missing_fragments (lines 266-267, 273-276) -------------


def test_list_missing_fragments_import_fails(tmp_path, monkeypatch):
    """ImportError on qa_checks → [] (lines 266-267)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "qa_checks":
            raise ImportError("nope")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert cis._list_missing_fragments(tmp_path) == []


def test_list_missing_fragments_no_dir(tmp_path):
    """No .fragments dir → returns all REQUIRED_FRAGMENTS (line 273-274)."""
    out = cis._list_missing_fragments(tmp_path)
    assert isinstance(out, list)
    assert len(out) > 0


def test_list_missing_fragments_with_present(tmp_path):
    """Some fragments present → filters them out (line 275-276)."""
    frag = tmp_path / ".fragments"
    frag.mkdir()
    full = cis._list_missing_fragments(tmp_path)
    # Create the first required fragment; it should drop from the missing list.
    (frag / full[0]).write_text("x", encoding="utf-8")
    after = cis._list_missing_fragments(tmp_path)
    assert full[0] not in after
    assert len(after) == len(full) - 1
