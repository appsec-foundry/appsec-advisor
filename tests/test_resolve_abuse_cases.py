"""Tests for scripts/model/resolve_abuse_cases.py — the abuse-case set resolver.

Covers the three merge sources (standard library, org glob, disable list),
grants/requires chain consistency, and duplicate-id detection.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "model/resolve_abuse_cases.py"


def _load_module():
    if "model.resolve_abuse_cases" in sys.modules:
        return sys.modules["model.resolve_abuse_cases"]
    spec = importlib.util.spec_from_file_location("model.resolve_abuse_cases", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["model.resolve_abuse_cases"] = mod
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


_TECHNICAL_IDS = ["AC-T-001", "AC-T-002", "AC-T-003", "AC-T-004", "AC-T-005", "AC-T-006", "AC-T-007"]
# The generic business cases load after the technical library.
_LIBRARY_IDS = _TECHNICAL_IDS + [f"AC-T-{n}" for n in range(101, 108)]


def test_library_loads_mandatory_cases():
    cases, errors = rac.resolve_abuse_cases(None, None)
    assert errors == [], errors
    ids = [c["id"] for c in cases]
    assert ids == _LIBRARY_IDS
    assert all(c.get("source") == "mandatory" or c.get("kind") == "descriptive" for c in cases)


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


def test_repo_local_duplicate_of_library_is_rejected_without_replacing_it(tmp_path: Path):
    dup = _VALID_CASE.replace("ORG-AC-001", "AC-T-001")
    repo_root = _write_repo_local(tmp_path, dup)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=repo_root)
    assert errors == []
    assert [c["id"] for c in cases] == _LIBRARY_IDS
    library_case = next(c for c in cases if c["id"] == "AC-T-001")
    assert library_case["title"] != "Custom org scenario"
    assert rejected == [
        {"path": ".appsec/abuse-cases/custom.yaml", "reason": "custom.yaml: duplicate abuse-case id 'AC-T-001'"}
    ]


def test_invalid_repo_file_is_rejected_alone_and_keeps_every_other_case(tmp_path: Path):
    """One broken repository file must not remove the library or the
    repository's valid cases from the run (it used to fail the matcher)."""
    _write_repo_local(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-001"), "a-valid.yaml")
    broken = _VALID_CASE.replace("ORG-AC-001", "REPO-AC-002").replace("initial_access: unauthenticated", "x: 1")
    _write_repo_local(tmp_path, broken, "b-broken.yaml")
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert errors == []
    assert [c["id"] for c in cases] == _LIBRARY_IDS + ["REPO-AC-001"]
    assert [r["path"] for r in rejected] == [".appsec/abuse-cases/b-broken.yaml"]
    assert "REPO-AC-002" in rejected[0]["reason"]


def test_repo_files_with_the_same_id_keep_only_the_first(tmp_path: Path):
    _write_repo_local(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-001"), "a.yaml")
    _write_repo_local(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-001"), "b.yml")
    cases, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert [c["id"] for c in cases].count("REPO-AC-001") == 1
    assert [r["path"] for r in rejected] == [".appsec/abuse-cases/b.yml"]


def test_repo_local_discovers_yml_like_explicit_files(tmp_path: Path):
    _write_repo_local(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-003"), "case.yml")
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert (errors, rejected) == ([], [])
    assert cases[-1]["id"] == "REPO-AC-003"


def test_repo_local_symlink_is_rejected_even_inside_the_repository(tmp_path: Path):
    repo = tmp_path / "repo"
    outside = tmp_path / "outside.yaml"
    outside.write_text(_VALID_CASE.replace("ORG-AC-001", "REPO-AC-004"), encoding="utf-8")
    d = repo / ".appsec" / "abuse-cases"
    d.mkdir(parents=True)
    (d / "escape.yaml").symlink_to(outside)
    inside = repo / "inside.yaml"
    inside.write_text(_VALID_CASE.replace("ORG-AC-001", "REPO-AC-005"), encoding="utf-8")
    (d / "inside.yaml").symlink_to(inside)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=repo)
    assert errors == []
    assert not {"REPO-AC-004", "REPO-AC-005"} & {c["id"] for c in cases}
    assert {r["reason"] for r in rejected} == {"symbolic links are not admitted"}


def test_repo_local_directory_escaping_the_repository_is_rejected(tmp_path: Path):
    repo = tmp_path / "repo"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "c.yaml").write_text(_VALID_CASE.replace("ORG-AC-001", "REPO-AC-006"), encoding="utf-8")
    (repo / ".appsec").mkdir(parents=True)
    (repo / ".appsec" / "abuse-cases").symlink_to(elsewhere, target_is_directory=True)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=repo)
    assert errors == []
    assert "REPO-AC-006" not in {c["id"] for c in cases}
    assert rejected == [{"path": ".appsec/abuse-cases", "reason": "directory resolves outside the repository"}]


def test_oversized_and_surplus_repo_files_are_rejected(tmp_path: Path):
    limits = {**rac.load_limits(), "case_file_kib": 1, "repo_case_files": 2}
    big = _VALID_CASE.replace("ORG-AC-001", "REPO-AC-007") + "# " + "x" * 2048 + "\n"
    _write_repo_local(tmp_path, big, "a-big.yaml")
    _write_repo_local(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-008"), "b.yaml")
    _write_repo_local(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-009"), "c.yaml")
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path, limits=limits)
    assert errors == []
    assert [c["id"] for c in cases][-1] == "REPO-AC-008"
    reasons = {r["path"].rsplit("/", 1)[-1]: r["reason"] for r in rejected}
    assert "size limit" in reasons["a-big.yaml"]
    assert "limit of 2" in reasons["c.yaml"]


def _write_docs_security(repo_root: Path, body: str, name: str = "custom.yaml") -> Path:
    d = repo_root / "docs" / "security" / "abuse-cases"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body, encoding="utf-8")
    return repo_root


def test_docs_security_location_loads_before_the_legacy_location(tmp_path: Path):
    _write_repo_local(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-002"), "legacy.yaml")
    _write_docs_security(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-001"), "team.yml")
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert (errors, rejected) == ([], [])
    assert [c["id"] for c in cases] == _LIBRARY_IDS + ["REPO-AC-001", "REPO-AC-002"]


def test_legacy_file_reusing_an_id_from_docs_security_is_rejected(tmp_path: Path):
    _write_docs_security(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-001"))
    stale = _VALID_CASE.replace("ORG-AC-001", "REPO-AC-001").replace("Custom org scenario", "Stale copy")
    _write_repo_local(tmp_path, stale)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert errors == []
    assert next(c for c in cases if c["id"] == "REPO-AC-001")["title"] == "Custom org scenario"
    assert [r["path"] for r in rejected] == [".appsec/abuse-cases/custom.yaml"]


def test_file_limit_counts_both_locations_together(tmp_path: Path):
    limits = {**rac.load_limits(), "repo_case_files": 1}
    _write_docs_security(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-001"))
    _write_repo_local(tmp_path, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-002"))
    cases, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path, limits=limits)
    assert "REPO-AC-002" not in {c["id"] for c in cases}
    assert rejected == [
        {"path": ".appsec/abuse-cases/custom.yaml", "reason": "exceeds the limit of 1 repository case files"}
    ]


def test_docs_security_escaping_the_repository_is_rejected(tmp_path: Path):
    repo = tmp_path / "repo"
    elsewhere = tmp_path / "elsewhere"
    _write_docs_security(elsewhere, _VALID_CASE.replace("ORG-AC-001", "REPO-AC-006"))
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "security").symlink_to(elsewhere / "docs" / "security", target_is_directory=True)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=repo)
    assert errors == []
    assert "REPO-AC-006" not in {c["id"] for c in cases}
    assert rejected == [{"path": "docs/security/abuse-cases", "reason": "directory resolves outside the repository"}]


def test_oversized_explicit_file_fails_closed(tmp_path: Path):
    limits = {**rac.load_limits(), "case_file_kib": 1}
    case_file = tmp_path / "big.yaml"
    case_file.write_text(_VALID_CASE + "# " + "x" * 2048 + "\n", encoding="utf-8")
    cases, errors, _ = rac.resolve_abuse_case_sources(
        {"abuse_cases": {"inherit_defaults": False}},
        None,
        repo_root=tmp_path,
        extra_case_files=[Path("big.yaml")],
        limits=limits,
    )
    assert cases == []
    assert any("size limit" in e for e in errors), errors


def test_unknown_schema_version_names_the_supported_versions(tmp_path: Path):
    _write_repo_local(tmp_path, _VALID_CASE.replace("schema_version: 1", "schema_version: 7"))
    _, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert rejected[0]["reason"] == "custom.yaml: schema_version 7 is not supported; supported versions: 1, 2"


def test_schema_error_names_the_case_id(tmp_path: Path):
    bad = _VALID_CASE.replace("initial_access: unauthenticated", "initial_access: telepathy")
    _write_repo_local(tmp_path, bad.replace("ORG-AC-001", "REPO-AC-011"))
    _, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert "abuse_cases/0 (REPO-AC-011)/attacker/initial_access" in rejected[0]["reason"]


def test_limits_file_matches_its_schema():
    limits = rac.load_limits()
    assert limits["descriptive_candidates_standard"] <= limits["descriptive_candidates_thorough"]


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


def test_explicit_file_already_loaded_from_the_repo_layer_is_not_a_duplicate(tmp_path: Path):
    """Pointing --abuse-case-file at a file `.appsec/abuse-cases/` already picks
    up names it twice; it does not define its ids twice."""
    repo = tmp_path / "repo"
    (repo / ".appsec" / "abuse-cases").mkdir(parents=True)
    (repo / ".appsec" / "abuse-cases" / "c.yaml").write_text(_VALID_CASE, encoding="utf-8")
    cases, errors = rac.resolve_abuse_cases(
        {"abuse_cases": {"inherit_defaults": False}},
        None,
        repo_root=repo,
        extra_case_files=[Path(".appsec/abuse-cases/c.yaml")],
    )
    assert errors == [], errors
    assert len(cases) == 1


def test_example_case_file_loads_the_way_a_user_would_pass_it(tmp_path: Path):
    """examples/abuse-cases.yaml is what users copy — it must survive the same
    path a `--abuse-case-file` argument takes, not just a schema check."""
    repo = tmp_path / "repo"
    (repo / ".appsec").mkdir(parents=True)
    (repo / ".appsec" / "my-case.yaml").write_text(
        (REPO_ROOT / "examples" / "abuse-cases.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    cases, errors = rac.resolve_abuse_cases(
        {"abuse_cases": {"inherit_defaults": False}},
        None,
        repo_root=repo,
        extra_case_files=[Path(".appsec/my-case.yaml")],
    )
    assert errors == [], errors
    assert [c["id"] for c in cases] == ["REPO-AC-001"]


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


def test_main_validation_fails_on_a_rejected_repo_file(tmp_path: Path, capsys):
    _write_repo_local(tmp_path, "abuse_cases: [1]\n", "bad.yaml")
    assert rac.main(["--repo-root", str(tmp_path), "--list-ids"]) == 1
    assert "REJECTED: .appsec/abuse-cases/bad.yaml:" in capsys.readouterr().err


def test_main_plugin_root_override(tmp_path: Path, capsys):
    # Point plugin_root at an empty dir → no default library loaded.
    rc = rac.main(["--plugin-root", str(tmp_path), "--list-ids"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == ""


# ---------------------------------------------------------------------------
# Descriptive (business) cases
# ---------------------------------------------------------------------------

_DESCRIPTIVE = """\
schema_version: 2
abuse_cases:
  - id: REPO-AC-020
    kind: descriptive
    title: Restricted administrator grants themselves a role outside their delegation
    actor: Delegated administrator of one department
    initial_access: authenticated_high_priv
    goal: Obtain a role the delegation does not include.
    boundary: Roles and subjects the delegation permits.
    steps:
      - Call the role-assignment operation with their own user as the subject.
      - Choose a role outside the delegated set.
    expected_controls:
      - The assignment operation checks the target role against the caller's delegation.
    exclusions:
      - Fully authorized administrators who may assign every role.
    scope_qualifier:
      path_patterns: ["**/*role*"]
"""


def test_descriptive_case_is_admitted_from_the_repository(tmp_path: Path):
    _write_repo_local(tmp_path, _DESCRIPTIVE)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert (errors, rejected) == ([], [])
    assert cases[-1]["kind"] == "descriptive"


def test_descriptive_case_requires_schema_version_2(tmp_path: Path):
    _write_repo_local(tmp_path, _DESCRIPTIVE.replace("schema_version: 2", "schema_version: 1"))
    _, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert rejected[0]["reason"] == "custom.yaml: REPO-AC-020: descriptive cases require schema_version: 2"


def test_descriptive_case_cannot_carry_authority_fields(tmp_path: Path):
    """Severity, gates, and mandatory status stay with trusted policy; a
    repository-authored business case cannot set them."""
    for extra in (
        "    severity: Critical\n",
        "    goal_impact: Critical\n",
        "    source: mandatory\n",
        "    release_gate: {fail_on: [fully_viable]}\n",
        "    chain: []\n",
    ):
        _write_repo_local(tmp_path, _DESCRIPTIVE + extra)
        _, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
        assert rejected and "Additional properties are not allowed" in rejected[0]["reason"], extra


def test_descriptive_case_needs_a_preselection_qualifier(tmp_path: Path):
    body = _DESCRIPTIVE.replace('    scope_qualifier:\n      path_patterns: ["**/*role*"]\n', "")
    _write_repo_local(tmp_path, body)
    _, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert "scope_qualifier" in rejected[0]["reason"]


_OPEN = """\
schema_version: 2
abuse_cases:
  - id: REPO-AC-021
    kind: descriptive
    title: No self-approval
    check: Check whether a user can approve a request they created.
"""


def test_an_open_case_states_only_what_to_check(tmp_path: Path):
    _write_repo_local(tmp_path, _OPEN)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert (errors, rejected) == ([], [])
    chain = rac.case_chain(cases[-1])
    assert [(s["step"], s["description"]) for s in chain] == [
        (1, "Check whether a user can approve a request they created.")
    ]


def test_an_organization_ships_an_open_case(tmp_path: Path):
    profile_dir = _write_org(tmp_path, _OPEN.replace("REPO-AC-021", "ORG-AC-021"))
    profile = {"abuse_cases": {"inherit_defaults": False, "add": "abuse-cases/*.yaml"}}
    cases, errors = rac.resolve_abuse_cases(profile, profile_dir)
    assert errors == [], errors
    assert [(c["id"], c["check"]) for c in cases] == [
        ("ORG-AC-021", "Check whether a user can approve a request they created.")
    ]


def test_a_case_without_check_or_steps_is_rejected(tmp_path: Path):
    _write_repo_local(
        tmp_path, _OPEN.replace("    check: Check whether a user can approve a request they created.\n", "")
    )
    _, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert rejected and "REPO-AC-021" in rejected[0]["reason"]


def test_descriptive_prose_is_bounded(tmp_path: Path):
    _write_repo_local(tmp_path, _DESCRIPTIVE.replace("Obtain a role", "x" * 700))
    _, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert "REPO-AC-020" in rejected[0]["reason"] and "goal" in rejected[0]["reason"]


@pytest.mark.parametrize(
    "qualifier",
    ["      detector_rules: [AUTHZ-003]\n", '      route_patterns: ["*role*"]\n'],
)
def test_a_detector_rule_or_route_pattern_alone_preselects_a_descriptive_case(tmp_path: Path, qualifier):
    body = _DESCRIPTIVE.replace('      path_patterns: ["**/*role*"]\n', qualifier)
    _write_repo_local(tmp_path, body)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert (errors, rejected) == ([], [])
    assert cases[-1]["scope_qualifier"] == yaml.safe_load(qualifier)


def test_locators_reject_a_malformed_rule_id_and_stay_off_probe_cases(tmp_path: Path):
    body = _DESCRIPTIVE.replace('      path_patterns: ["**/*role*"]\n', '      detector_rules: ["$(id)"]\n')
    _write_repo_local(tmp_path, body)
    _, _, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert rejected
    probe = _VALID_CASE + "    scope_qualifier:\n      route_patterns: ['*role*']\n"
    profile = {"abuse_cases": {"inherit_defaults": False, "add": "abuse-cases/*.yaml"}}
    cases, errors = rac.resolve_abuse_cases(profile, _write_org(tmp_path, probe))
    assert cases == [] and errors


def test_a_repeated_case_field_rejects_the_repository_file(tmp_path: Path):
    body = _DESCRIPTIVE + '    scope_qualifier:\n      path_patterns: ["**/*"]\n'
    _write_repo_local(tmp_path, body)
    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, repo_root=tmp_path)
    assert all(case.get("id") != "REPO-AC-020" for case in cases)
    assert "duplicate key 'scope_qualifier'" in rejected[0]["reason"]


def test_a_repeated_nested_key_rejects_an_organization_file(tmp_path: Path):
    bad = _VALID_CASE.replace(
        "initial_access: unauthenticated", "initial_access: unauthenticated\n      initial_access: physical"
    )
    assert bad != _VALID_CASE
    profile = {"abuse_cases": {"inherit_defaults": False, "add": "abuse-cases/*.yaml"}}
    cases, errors = rac.resolve_abuse_cases(profile, _write_org(tmp_path, bad))
    assert cases == []
    assert any("duplicate key 'initial_access'" in error for error in errors)


def test_equal_keys_in_separate_mappings_and_merge_keys_still_load(tmp_path: Path):
    body = _DESCRIPTIVE.replace("schema_version: 2\n", "schema_version: 2\nx-defaults: &defaults\n  actor: Base\n")
    body = body.replace(
        "    actor: Delegated administrator of one department\n",
        "    <<: *defaults\n    actor: Delegated administrator of one department\n",
    )
    two = body + _DESCRIPTIVE.split("abuse_cases:\n", 1)[1].replace("REPO-AC-020", "REPO-AC-021")
    doc = rac._load_case_yaml(two)
    assert [case["actor"] for case in doc["abuse_cases"]] == ["Delegated administrator of one department"] * 2
