"""Coverage-focused tests for scripts/check_permissions.py.

Targets error/CLI/edge branches not exercised by test_check_permissions.py:
schema-validation paths, load_required error exits, load_allow warnings,
_rule_covers edge branches, write_missing error exits, the user-only and
failure+user-only render paths, --help, and JSON --update output.

Pins CURRENT behavior — no producer edits.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_permissions as cp  # noqa: E402

# ---------- _validate_against_schema -------------------------------------


def test_validate_schema_missing_jsonschema(monkeypatch):
    """ImportError on jsonschema → silent return (lines 63-64)."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "jsonschema":
            raise ImportError("no jsonschema")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # Should not raise even with a bogus doc.
    cp._validate_against_schema({"required": []}, Path("doc.yaml"))


def test_validate_schema_file_missing(tmp_path):
    """Missing schema file → silent return (lines 65-66)."""
    pytest.importorskip("jsonschema")
    cp._validate_against_schema({"required": []}, Path("doc.yaml"), schema_path=tmp_path / "nope.yaml")


def test_validate_schema_unreadable_schema(tmp_path):
    """Schema YAML invalid → SystemExit (lines 69-70)."""
    pytest.importorskip("jsonschema")
    bad = tmp_path / "schema.yaml"
    bad.write_text("[: this is : not : valid", encoding="utf-8")
    with pytest.raises(SystemExit):
        cp._validate_against_schema({"required": []}, Path("doc.yaml"), schema_path=bad)


def test_validate_schema_validation_error(tmp_path):
    """Doc violates schema → SystemExit with path (lines 73-75)."""
    pytest.importorskip("jsonschema")
    schema = tmp_path / "schema.yaml"
    schema.write_text(
        yaml.safe_dump(
            {
                "type": "object",
                "properties": {"required": {"type": "array"}},
                "required": ["required"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit):
        cp._validate_against_schema({"required": "not-a-list"}, Path("doc.yaml"), schema_path=schema)


# ---------- load_required error paths ------------------------------------


def test_load_required_oserror(tmp_path):
    with pytest.raises(SystemExit) as e:
        cp.load_required(tmp_path / "does-not-exist.yaml")
    assert "cannot read" in str(e.value)


def test_load_required_invalid_yaml(tmp_path):
    bad = tmp_path / "req.yaml"
    bad.write_text("required: [: broken", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cp.load_required(bad)
    assert "invalid YAML" in str(e.value)


def test_load_required_missing_required_key(tmp_path):
    f = tmp_path / "req.yaml"
    f.write_text("other: 1\n", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cp.load_required(f)
    assert "missing top-level 'required'" in str(e.value)


def test_load_required_not_a_dict(tmp_path):
    f = tmp_path / "req.yaml"
    f.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        cp.load_required(f)


def test_load_required_required_not_list(tmp_path, monkeypatch):
    # Bypass schema validation so the explicit list-check (line 90) is reached.
    monkeypatch.setattr(cp, "_validate_against_schema", lambda *a, **k: None)
    f = tmp_path / "req.yaml"
    f.write_text("required: 7\n", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cp.load_required(f)
    assert "not a list" in str(e.value)


def test_load_required_entry_missing_field(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "_validate_against_schema", lambda *a, **k: None)
    f = tmp_path / "req.yaml"
    f.write_text("required:\n  - reason: x\n", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cp.load_required(f)
    assert "missing 'entry'" in str(e.value)


# ---------- load_allow error path ----------------------------------------


def test_load_allow_invalid_json_warns(tmp_path, capsys):
    f = tmp_path / "settings.json"
    f.write_text("{not json", encoding="utf-8")
    out = cp.load_allow(f)
    assert out == []
    assert "ignoring unreadable" in capsys.readouterr().err


# ---------- _rule_covers edge branches -----------------------------------


def test_rule_covers_non_tool_form_returns_false():
    """Neither rule nor need match Tool(args) → line 168."""
    assert cp._rule_covers("plainstring", "otherstring") is False


def test_rule_covers_glob_exact_base():
    """need_arg == base under /** → line 186-187."""
    assert cp._rule_covers("Write(/a/b/**)", "Write(/a/b)") is True


# ---------- write_missing error paths ------------------------------------


def test_write_missing_invalid_json(tmp_path):
    f = tmp_path / "s.json"
    f.write_text("{bad", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cp.write_missing(f, ["Bash(ls:*)"])
    assert "invalid JSON" in str(e.value)


def test_write_missing_top_level_not_object(tmp_path):
    f = tmp_path / "s.json"
    f.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cp.write_missing(f, ["Bash(ls:*)"])
    assert "top level is not an object" in str(e.value)


def test_write_missing_permissions_not_object(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"permissions": [1, 2]}), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cp.write_missing(f, ["Bash(ls:*)"])
    assert "'permissions' is not an object" in str(e.value)


def test_write_missing_allow_not_list(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"permissions": {"allow": "x"}}), encoding="utf-8")
    with pytest.raises(SystemExit) as e:
        cp.write_missing(f, ["Bash(ls:*)"])
    assert "'permissions.allow' is not a list" in str(e.value)


# ---------- render_human user-only + failure paths -----------------------


def test_render_human_user_only_path():
    """No missing but user_only set (lines 295-308)."""
    user_only = [{"entry": "Bash(ls:*)", "reason": "r", "category": "exec"}]
    out = cp.render_human(
        required=[],
        missing=[],
        scopes_with_counts={},
        scope_in_use=None,
        user_only=user_only,
    )
    assert "only in ~/.claude/settings.json (user-level)" in out
    assert "Bash(ls:*)" in out


def test_render_human_user_only_plural():
    user_only = [
        {"entry": "Bash(ls:*)", "reason": "", "category": "exec"},
        {"entry": "Bash(cat:*)", "reason": "", "category": "exec"},
    ]
    out = cp.render_human([], [], {}, None, user_only=user_only)
    assert "entries are" in out


def test_render_human_failure_with_user_only(tmp_path):
    """Missing AND user_only (lines 321-331) + scope_paths not-found branch."""
    missing = [{"entry": "Write(/x/**)", "reason": "needit", "category": "write"}]
    user_only = [{"entry": "Bash(ls:*)", "reason": "", "category": "exec"}]
    scope_paths = {"local": tmp_path / "missing.json"}
    out = cp.render_human(
        required=missing,
        missing=missing,
        scopes_with_counts={"local": 0},
        scope_in_use="local",
        user_only=user_only,
        scope_paths=scope_paths,
    )
    assert "Missing permissions" in out
    assert "will not be inherited by sub-agents" in out
    assert "not found" in out
    assert "--scope local" in out


def test_render_human_scope_paths_one_entry(tmp_path):
    """Singular 'entry' label when count==1 (line 282)."""
    f = tmp_path / "s.json"
    f.write_text("{}", encoding="utf-8")
    out = cp.render_human(
        required=[],
        missing=[],
        scopes_with_counts={"local": 1},
        scope_in_use=None,
        scope_paths={"local": f},
    )
    assert "1 entry" in out


# ---------- main() CLI paths ---------------------------------------------


def test_main_help(capsys):
    assert cp.main(["--help"]) == 0
    assert "USAGE" in capsys.readouterr().out


def test_main_update_json(tmp_path, monkeypatch, capsys):
    """--update --json output branch (line 461)."""
    monkeypatch.setattr(
        cp, "load_required", lambda *a, **k: [{"entry": "Bash(zzz:*)", "reason": "r", "category": "exec"}]
    )
    monkeypatch.setattr(cp, "effective_allow", lambda root: {"user": [], "project": [], "local": []})
    rc = cp.main(["--repo-root", str(tmp_path), "--update", "--json", "--scope", "local"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["added"] == 1
    assert (tmp_path / ".claude" / "settings.local.json").is_file()


def test_main_update_human(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        cp, "load_required", lambda *a, **k: [{"entry": "Bash(zzz:*)", "reason": "r", "category": "exec"}]
    )
    monkeypatch.setattr(cp, "effective_allow", lambda root: {"user": [], "project": [], "local": []})
    rc = cp.main(["--repo-root", str(tmp_path), "--update"])
    assert rc == 0
    assert "Wrote 1 new entry" in capsys.readouterr().out
