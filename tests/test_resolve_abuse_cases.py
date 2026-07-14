"""Tests for scripts/resolve_abuse_cases.py — the abuse-case set resolver.

Covers the three merge sources (standard library, org glob, disable list),
grants/requires chain consistency, and duplicate-id detection.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "resolve_abuse_cases.py"


def _load_module():
    if "resolve_abuse_cases" in sys.modules:
        return sys.modules["resolve_abuse_cases"]
    spec = importlib.util.spec_from_file_location("resolve_abuse_cases", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["resolve_abuse_cases"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rac = _load_module()

_VALID_CASE = """\
schema_version: 1
abuse_cases:
  - id: ORG-AC-001
    title: Custom org scenario
    source: mandatory
    attacker:
      actor_id: external-attacker
      initial_access: unauthenticated
    goal: Do the bad thing.
    chain:
      - step: 1
        label: First
        grants: foothold
        probe:
          sink_patterns: ["eval\\\\("]
      - step: 2
        label: Second
        grants: takeover
        requires: foothold
        probe:
          sink_patterns: ["exec\\\\("]
"""


# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------


_LIBRARY_IDS = ["AC-T-001", "AC-T-002", "AC-T-003", "AC-T-004", "AC-T-005", "AC-T-006"]


def test_library_loads_mandatory_cases():
    cases, errors = rac.resolve_abuse_cases(None, None)
    assert errors == [], errors
    ids = [c["id"] for c in cases]
    assert ids == _LIBRARY_IDS
    assert all(c["source"] == "mandatory" for c in cases)


def test_inherit_defaults_false_yields_no_library():
    cases, errors = rac.resolve_abuse_cases({"abuse_cases": {"inherit_defaults": False}}, None)
    assert errors == []
    assert cases == []


def test_disable_filters_named_ids():
    profile = {"abuse_cases": {"disable": ["AC-T-002"]}}
    cases, errors = rac.resolve_abuse_cases(profile, None)
    assert errors == []
    assert [c["id"] for c in cases] == [i for i in _LIBRARY_IDS if i != "AC-T-002"]


# ---------------------------------------------------------------------------
# Org glob
# ---------------------------------------------------------------------------


def _write_org(tmp_path: Path, body: str, glob: str = "abuse-cases/*.yaml") -> Path:
    d = tmp_path / "abuse-cases"
    d.mkdir(parents=True, exist_ok=True)
    (d / "custom.yaml").write_text(body, encoding="utf-8")
    return tmp_path


def test_org_glob_adds_custom_case(tmp_path: Path):
    profile_dir = _write_org(tmp_path, _VALID_CASE)
    profile = {"abuse_cases": {"inherit_defaults": False, "add": "abuse-cases/*.yaml"}}
    cases, errors = rac.resolve_abuse_cases(profile, profile_dir)
    assert errors == [], errors
    assert [c["id"] for c in cases] == ["ORG-AC-001"]


def test_library_and_org_merge(tmp_path: Path):
    profile_dir = _write_org(tmp_path, _VALID_CASE)
    profile = {"abuse_cases": {"inherit_defaults": True, "add": "abuse-cases/*.yaml"}}
    cases, errors = rac.resolve_abuse_cases(profile, profile_dir)
    assert errors == []
    assert [c["id"] for c in cases] == _LIBRARY_IDS + ["ORG-AC-001"]


def test_duplicate_id_is_reported(tmp_path: Path):
    dup = _VALID_CASE.replace("ORG-AC-001", "AC-T-001")
    profile_dir = _write_org(tmp_path, dup)
    profile = {"abuse_cases": {"inherit_defaults": True, "add": "abuse-cases/*.yaml"}}
    _, errors = rac.resolve_abuse_cases(profile, profile_dir)
    assert any("duplicate" in e.lower() and "AC-T-001" in e for e in errors), errors


# ---------------------------------------------------------------------------
# Repo-local layer  (<repo>/.appsec/abuse-cases/*.yaml)
# ---------------------------------------------------------------------------


def _write_repo_local(repo_root: Path, body: str, name: str = "custom.yaml") -> Path:
    d = repo_root / ".appsec" / "abuse-cases"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body, encoding="utf-8")
    return repo_root


def test_repo_local_adds_case_without_org_profile(tmp_path: Path):
    repo_root = _write_repo_local(tmp_path, _VALID_CASE)
    cases, errors = rac.resolve_abuse_cases(None, None, repo_root=repo_root)
    assert errors == [], errors
    assert [c["id"] for c in cases] == _LIBRARY_IDS + ["ORG-AC-001"]


def test_repo_local_absent_dir_is_noop(tmp_path: Path):
    cases, errors = rac.resolve_abuse_cases(None, None, repo_root=tmp_path)
    assert errors == []
    assert [c["id"] for c in cases] == _LIBRARY_IDS


def test_repo_local_honours_disable(tmp_path: Path):
    dup = _VALID_CASE.replace("ORG-AC-001", "REPO-AC-009")
    repo_root = _write_repo_local(tmp_path, dup)
    profile = {"abuse_cases": {"disable": ["REPO-AC-009"]}}
    cases, errors = rac.resolve_abuse_cases(profile, None, repo_root=repo_root)
    assert errors == []
    assert "REPO-AC-009" not in [c["id"] for c in cases]


def test_repo_local_duplicate_of_library_is_reported(tmp_path: Path):
    dup = _VALID_CASE.replace("ORG-AC-001", "AC-T-001")
    repo_root = _write_repo_local(tmp_path, dup)
    _, errors = rac.resolve_abuse_cases(None, None, repo_root=repo_root)
    assert any("duplicate" in e.lower() and "AC-T-001" in e for e in errors), errors


def test_explicit_case_file_under_repo_is_loaded(tmp_path: Path):
    case_file = tmp_path / "security" / "payments.yaml"
    case_file.parent.mkdir()
    case_file.write_text(_VALID_CASE.replace("ORG-AC-001", "REPO-AC-010"), encoding="utf-8")

    cases, errors = rac.resolve_abuse_cases(
        {"abuse_cases": {"inherit_defaults": False}},
        None,
        repo_root=tmp_path,
        extra_case_files=[Path("security/payments.yaml")],
    )

    assert errors == []
    assert [case["id"] for case in cases] == ["REPO-AC-010"]


def test_explicit_case_file_cannot_escape_repo(tmp_path: Path):
    outside = tmp_path.parent / "outside.yaml"
    outside.write_text(_VALID_CASE, encoding="utf-8")
    cases, errors = rac.resolve_abuse_cases(
        {"abuse_cases": {"inherit_defaults": False}}, None, repo_root=tmp_path, extra_case_files=[outside]
    )
    assert cases == []
    assert any("outside the repository" in error for error in errors)


# ---------------------------------------------------------------------------
# grants / requires chain consistency
# ---------------------------------------------------------------------------


def test_dangling_requires_is_rejected(tmp_path: Path):
    bad = _VALID_CASE.replace("requires: foothold", "requires: nonexistent_state")
    profile_dir = _write_org(tmp_path, bad)
    profile = {"abuse_cases": {"inherit_defaults": False, "add": "abuse-cases/*.yaml"}}
    cases, errors = rac.resolve_abuse_cases(profile, profile_dir)
    assert cases == []
    assert any("requires" in e and "nonexistent_state" in e for e in errors), errors


def test_schema_violation_is_rejected(tmp_path: Path):
    bad = _VALID_CASE.replace("initial_access: unauthenticated", "initial_access: telepathy")
    profile_dir = _write_org(tmp_path, bad)
    profile = {"abuse_cases": {"inherit_defaults": False, "add": "abuse-cases/*.yaml"}}
    cases, errors = rac.resolve_abuse_cases(profile, profile_dir)
    assert cases == []
    assert errors, "expected a schema error for invalid initial_access enum"


def test_default_library_file_is_self_consistent():
    """The shipped library must validate against its own schema + chain rules."""
    cases, errors = rac.resolve_abuse_cases(None, None)
    assert errors == [], errors
    assert len(cases) == len(_LIBRARY_IDS)


# ---------------------------------------------------------------------------
# _load_case_file error paths
# ---------------------------------------------------------------------------


def test_load_case_file_unparseable_yaml(tmp_path: Path):
    schema = rac._load_schema()
    bad = tmp_path / "bad.yaml"
    bad.write_text("abuse_cases: [ : : :\n", encoding="utf-8")
    cases, errors = rac._load_case_file(bad, schema)
    assert cases == []
    assert any("cannot parse" in e for e in errors)


def test_load_case_file_non_mapping_top_level(tmp_path: Path):
    schema = rac._load_schema()
    bad = tmp_path / "list.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    cases, errors = rac._load_case_file(bad, schema)
    assert cases == []
    assert any("top-level must be a mapping" in e for e in errors)


def test_schema_errors_without_jsonschema(monkeypatch):
    """When jsonschema is unavailable the validator degrades to a single
    error line rather than crashing."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "jsonschema":
            raise ImportError("no jsonschema")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    errors = rac._schema_errors({}, {}, "lbl")
    assert errors == ["lbl: jsonschema not installed; cannot validate abuse cases"]


# ---------------------------------------------------------------------------
# main() CLI
# ---------------------------------------------------------------------------


def test_main_default_emits_json(capsys):
    rc = rac.main([])
    assert rc == 0
    out = capsys.readouterr().out
    import json as _json

    data = _json.loads(out)
    assert [c["id"] for c in data["abuse_cases"]] == _LIBRARY_IDS


def test_main_list_ids(capsys):
    rc = rac.main(["--list-ids"])
    assert rc == 0
    ids = capsys.readouterr().out.split()
    assert ids == _LIBRARY_IDS


def test_main_with_org_profile(tmp_path: Path, capsys):
    profile_dir = _write_org(tmp_path, _VALID_CASE)
    profile_path = profile_dir / "org-profile.yaml"
    profile_path.write_text(
        "abuse_cases:\n  inherit_defaults: false\n  add: abuse-cases/*.yaml\n",
        encoding="utf-8",
    )
    rc = rac.main(["--org-profile", str(profile_path), "--list-ids"])
    assert rc == 0
    assert capsys.readouterr().out.split() == ["ORG-AC-001"]


def test_main_with_repo_root(tmp_path: Path, capsys):
    repo_root = _write_repo_local(tmp_path, _VALID_CASE)
    rc = rac.main(["--repo-root", str(repo_root), "--list-ids"])
    assert rc == 0
    ids = capsys.readouterr().out.split()
    assert "ORG-AC-001" in ids


def test_main_errors_return_one(tmp_path: Path, capsys):
    bad = _VALID_CASE.replace("requires: foothold", "requires: nonexistent_state")
    profile_dir = _write_org(tmp_path, bad)
    profile_path = profile_dir / "org-profile.yaml"
    profile_path.write_text(
        "abuse_cases:\n  inherit_defaults: false\n  add: abuse-cases/*.yaml\n",
        encoding="utf-8",
    )
    rc = rac.main(["--org-profile", str(profile_path)])
    assert rc == 1
    assert "ERROR:" in capsys.readouterr().err


def test_main_plugin_root_override(tmp_path: Path, capsys):
    # Point plugin_root at an empty dir → no default library loaded.
    rc = rac.main(["--plugin-root", str(tmp_path), "--list-ids"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == ""
