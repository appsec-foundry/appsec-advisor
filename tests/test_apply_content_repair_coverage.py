"""Coverage extension for scripts/apply_content_repair.py — error/CLI/edge paths.

Pins current behavior (test-files-only campaign). No producer edits.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "apply_content_repair.py"


def _load():
    if "apply_content_repair" in sys.modules:
        return sys.modules["apply_content_repair"]
    spec = importlib.util.spec_from_file_location("apply_content_repair", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_content_repair"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


acr = _load()


def _out_dir(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    (out / ".fragments").mkdir(parents=True)
    return out


def _frag(out: Path, name: str, content: str) -> Path:
    p = out / ".fragments" / name
    p.write_text(content, encoding="utf-8")
    return p


# --- _op_heading_rename_cascade missing/empty fields (lines 155, 157) ------


def test_heading_rename_missing_old_name_raises():
    with pytest.raises(acr.ApplyError, match="old_name"):
        acr._op_heading_rename_cascade("text", {"new_name": "X"})


def test_heading_rename_empty_old_name_raises():
    with pytest.raises(acr.ApplyError, match="old_name"):
        acr._op_heading_rename_cascade("text", {"old_name": "  ", "new_name": "X"})


def test_heading_rename_missing_new_name_raises():
    with pytest.raises(acr.ApplyError, match="new_name"):
        acr._op_heading_rename_cascade("text", {"old_name": "Old"})


def test_heading_rename_empty_new_name_raises():
    with pytest.raises(acr.ApplyError, match="new_name"):
        acr._op_heading_rename_cascade("text", {"old_name": "Old", "new_name": ""})


# --- _validate_plan: non-dict action (lines 239-240) ----------------------


def test_validate_plan_non_dict_action():
    errs = acr._validate_plan({"schema_version": acr.SCHEMA_VERSION, "actions": ["not-a-dict"]})
    assert any("actions[0] is not an object" in e for e in errs)


# --- apply_plan: read OSError (lines 320-324) -----------------------------


def test_apply_plan_unreadable_fragment(tmp_path: Path, monkeypatch):
    out = _out_dir(tmp_path)
    _frag(out, "f.md", "hello")
    plan = {
        "schema_version": acr.SCHEMA_VERSION,
        "actions": [
            {
                "check": "c",
                "type": "t",
                "fragment": ".fragments/f.md",
                "operation": {"op": "replace_string", "find": "hello", "replace": "bye"},
            }
        ],
    }
    # The fragment passes path-jail/is_file resolution; force read_text to fail
    # so the OSError branch in apply_plan (skip + exit_code=1) is exercised.
    real_read = Path.read_text

    def boom(self, *a, **k):
        if self.name == "f.md":
            raise OSError("read fail")
        return real_read(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", boom)
    report = acr.apply_plan(plan, out)
    assert report["exit_code"] == 1
    assert any("read error" in s["reason"] for s in report["skipped"])


# --- apply_plan: unknown op in nested form (lines 352-354) ----------------


def test_apply_plan_unknown_op(tmp_path: Path):
    out = _out_dir(tmp_path)
    _frag(out, "f.md", "hello")
    plan = {
        "schema_version": acr.SCHEMA_VERSION,
        "actions": [
            {
                "check": "c",
                "type": "t",
                "fragment": ".fragments/f.md",
                "operation": {"op": "no_such_op"},
            }
        ],
    }
    report = acr.apply_plan(plan, out)
    assert report["exit_code"] == 1
    assert any("unknown op" in s["reason"] for s in report["skipped"])


# --- apply_plan: non-dict operation (lines 333-349 defensive) -------------


def test_apply_plan_operation_not_dict(tmp_path: Path, capsys):
    out = _out_dir(tmp_path)
    _frag(out, "f.md", "hello")
    plan = {
        "schema_version": acr.SCHEMA_VERSION,
        "actions": [{"check": "c", "type": "t", "fragment": ".fragments/f.md", "operation": "flat"}],
    }
    report = acr.apply_plan(plan, out)
    assert report["exit_code"] == 1
    assert any("not an object" in s["reason"] for s in report["skipped"])


# --- apply_plan: write OSError (lines 376-378) ----------------------------


def test_apply_plan_write_error(tmp_path: Path, monkeypatch):
    out = _out_dir(tmp_path)
    _frag(out, "f.md", "hello world")
    plan = {
        "schema_version": acr.SCHEMA_VERSION,
        "actions": [
            {
                "check": "c",
                "type": "t",
                "fragment": ".fragments/f.md",
                "operation": {"op": "replace_string", "find": "hello", "replace": "bye"},
            }
        ],
    }
    real_write = Path.write_text

    def boom(self, *a, **k):
        if self.name == "f.md":
            raise OSError("disk full")
        return real_write(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", boom)
    report = acr.apply_plan(plan, out)
    assert report["exit_code"] == 1
    assert any("write error" in s["reason"] for s in report["skipped"])


# --- main(): output_dir not a directory (lines 412-413) -------------------


def test_main_output_dir_not_dir(tmp_path: Path, capsys):
    rc = acr.main([str(tmp_path / "missing")])
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err


# --- main(): no plan present -> exit 0 ------------------------------------


def test_main_no_plan(tmp_path: Path, capsys):
    out = _out_dir(tmp_path)
    rc = acr.main([str(out)])
    assert rc == 0
    assert "nothing to do" in capsys.readouterr().err


# --- main(): plan JSON decode error (lines 423-425) -----------------------


def test_main_bad_plan_json(tmp_path: Path, capsys):
    out = _out_dir(tmp_path)
    (out / acr.PLAN_FILENAME).write_text("{not json", encoding="utf-8")
    rc = acr.main([str(out)])
    assert rc == 2
    assert "cannot read plan" in capsys.readouterr().err


# --- main(): validation failure -> exit 3 --------------------------------


def test_main_plan_validation_fails(tmp_path: Path, capsys):
    out = _out_dir(tmp_path)
    (out / acr.PLAN_FILENAME).write_text(json.dumps({"schema_version": 999, "actions": "nope"}), encoding="utf-8")
    rc = acr.main([str(out)])
    assert rc == 3
    assert "failed validation" in capsys.readouterr().err


# --- main() --dry-run: ok and bad actions (lines 434-452) -----------------


def test_main_dry_run_ok(tmp_path: Path):
    out = _out_dir(tmp_path)
    _frag(out, "f.md", "hello world")
    (out / acr.PLAN_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": acr.SCHEMA_VERSION,
                "actions": [
                    {
                        "check": "c",
                        "type": "t",
                        "fragment": ".fragments/f.md",
                        "operation": {"op": "replace_string", "find": "hello", "replace": "bye"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rc = acr.main([str(out), "--dry-run"])
    assert rc == 0
    # No write happened.
    assert (out / ".fragments" / "f.md").read_text() == "hello world"


def test_main_dry_run_unknown_op_rejected_by_validation(tmp_path: Path, capsys):
    # An unknown op never reaches the dry-run loop: _validate_plan rejects it
    # first, so main() exits 3 (pins current behavior — the dry-run unknown-op
    # branch is unreachable via the CLI because validation runs before it).
    out = _out_dir(tmp_path)
    _frag(out, "f.md", "hello")
    (out / acr.PLAN_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": acr.SCHEMA_VERSION,
                "actions": [
                    {
                        "check": "c",
                        "type": "t",
                        "fragment": ".fragments/f.md",
                        "operation": {"op": "ghost_op"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rc = acr.main([str(out), "--dry-run"])
    assert rc == 3
    assert "unknown" in capsys.readouterr().err


def test_main_dry_run_apply_error(tmp_path: Path):
    out = _out_dir(tmp_path)
    _frag(out, "f.md", "hello")
    (out / acr.PLAN_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": acr.SCHEMA_VERSION,
                "actions": [
                    {
                        "check": "c",
                        "type": "t",
                        "fragment": ".fragments/f.md",
                        "operation": {"op": "replace_string", "find": "NEEDLE-MISSING", "replace": "x"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rc = acr.main([str(out), "--dry-run"])
    assert rc == 1


# --- main() full apply happy path (json summary path) ---------------------


def test_main_apply_writes_summary(tmp_path: Path, capsys):
    out = _out_dir(tmp_path)
    _frag(out, "f.md", "hello world")
    (out / acr.PLAN_FILENAME).write_text(
        json.dumps(
            {
                "schema_version": acr.SCHEMA_VERSION,
                "actions": [
                    {
                        "check": "c",
                        "type": "t",
                        "fragment": ".fragments/f.md",
                        "operation": {"op": "replace_string", "find": "hello", "replace": "bye"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rc = acr.main([str(out)])
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["applied_count"] == 1
    assert (out / ".fragments" / "f.md").read_text() == "bye world"


# --- __main__ guard (line 469) -------------------------------------------


def test_module_runpy_main_guard(tmp_path: Path):
    import runpy

    out = _out_dir(tmp_path)
    argv = sys.argv
    sys.argv = ["apply_content_repair.py", str(out)]
    sys.modules.pop("apply_content_repair", None)
    try:
        with pytest.raises(SystemExit) as ei:
            runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
        assert ei.value.code == 0
    finally:
        sys.argv = argv
        # Restore the importlib-loaded module for other tests.
        _load()
