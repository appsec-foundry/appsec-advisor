"""Versioned models preserve source ownership in canonical and display views."""

from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime.multi_repo_scope import AssessmentScope, RepositoryView
from shared import assessment_sources as sources
from validators.validate_intermediate import validate_threat_model_output


def fixture(tmp_path):
    views = tuple(
        RepositoryView(
            f"repo-{i:016x}", tmp_path / f"repository-{i}", "a" * 40, "b" * 64, {"src/app.py": b"value = 1\n"}
        )
        for i in (1, 2)
    )
    scope = AssessmentScope(views, tmp_path / "out")
    evidence = [
        {
            "repository_id": r.repository_id,
            "file": "src/app.py",
            "line": 1,
            "sha256": hashlib.sha256(r.files["src/app.py"]).hexdigest(),
        }
        for r in views
    ]
    return {
        "meta": {
            "schema_version": 2,
            "project": "System",
            "generated": "2026-01-01T00:00:00Z",
            "mode": "full",
            "model": "test",
        },
        "source_inventory": scope.inventory(),
        "components": [
            {
                "id": f"component-{i}",
                "name": "Application",
                "tier": "application",
                "paths": [{"repository_id": e["repository_id"], "path": e["file"], "sha256": e["sha256"]}],
                "repository_ids": [e["repository_id"]],
            }
            for i, e in enumerate(evidence, 1)
        ],
        "data_flows": [],
        "assets": [],
        "attack_surface": [],
        "trust_boundaries": [],
        "security_controls": [],
        "threats": [],
        "mitigations": [],
    }, evidence


def test_qualified_output_validates_and_keeps_legacy_models_distinct(tmp_path):
    document, _ = fixture(tmp_path)
    assert validate_threat_model_output(document)[0]
    sources.validate_portable_model(document)
    legacy = copy.deepcopy(document)
    legacy["meta"]["schema_version"] = 1
    assert not validate_threat_model_output(legacy)[0]
    for c in legacy["components"]:
        c["paths"] = [p["path"] for p in c["paths"]]
    assert validate_threat_model_output(legacy)[0]
    assert sources.presentation_model(legacy) is legacy


def test_display_view_keeps_identical_paths_distinct_without_mutating_model(tmp_path):
    document, evidence = fixture(tmp_path)
    document["meta"]["open_registration_resolution"] = {
        "open": False,
        "disputed": True,
        "reason": "unresolved-candidate",
        "evidence": evidence,
    }
    original = copy.deepcopy(document)
    view = sources.presentation_model(document)
    assert document == original
    assert view["components"][0]["paths"] != view["components"][1]["paths"]
    assert view["meta"]["open_registration_resolution"]["evidence"][0]["file"] == sources.source_key(evidence[0])
    assert sources.location_label(evidence[0], document) == "repository-1:src/app.py"


@pytest.mark.parametrize("kind", ["missing-owner", "foreign-owner", "hash", "duplicate", "scope", "escape", "omission"])
def test_invalid_ownership_fails_before_display_or_export(tmp_path, kind):
    document, _ = fixture(tmp_path)
    path = document["components"][0]["paths"][0]
    if kind == "missing-owner":
        path.pop("repository_id")
    elif kind == "foreign-owner":
        path["repository_id"] = "repo-ffffffffffffffff"
    elif kind == "hash":
        path["sha256"] = "0" * 64
    elif kind == "duplicate":
        document["components"].append(copy.deepcopy(document["components"][0]))
    elif kind == "scope":
        document["source_inventory"]["scope_sha256"] = "0" * 64
    elif kind == "escape":
        path["path"] = "../src/app.py"
    else:
        document["components"].pop()
    assert not validate_threat_model_output(document)[0]
    with pytest.raises(ValueError):
        sources.presentation_model(document)


def test_yaml_aliases_are_qualified_once_and_cycles_fail_closed(tmp_path, monkeypatch):
    document, evidence = fixture(tmp_path)
    document["meta"]["open_registration_resolution"] = {
        "open": False,
        "disputed": True,
        "reason": "unresolved-candidate",
        "evidence": [evidence[0]],
    }
    document["external_entities"] = [
        {
            "id": "ext-service",
            "name": "Service",
            "kind": "external-service",
            "description": "External service",
            "evidence": [evidence[0]],
        }
    ]
    document = yaml.safe_load(yaml.safe_dump(document))
    view = sources.presentation_model(document)
    assert all(e["file"].count("repo-") == 1 for e in view["meta"]["open_registration_resolution"]["evidence"])
    assert view["external_entities"][0]["evidence"][0]["file"].count("repo-") == 1
    cyclic = {}
    cyclic["cycle"] = cyclic
    with pytest.raises(ValueError, match="cyclic"):
        list(sources.source_rows(cyclic))
    monkeypatch.setattr(sources, "MAX_MODEL_NODES", 2)
    with pytest.raises(ValueError, match="structural limits"):
        sources.validate_portable_model(document)


def test_a_system_wide_control_with_a_textual_statement_is_a_valid_portable_row(tmp_path):
    from model.build_threat_model_yaml import build_assessment_model
    from shared.assessment_sources import validate_portable_model

    from tests.test_multi_repo_builder import inputs

    scope, kwargs = inputs(tmp_path)
    document, _ = build_assessment_model(scope, **kwargs)
    document["security_controls"].append(
        {
            "domain": "Identity and Authentication",
            "control": "User Registration",
            "kind": "lifecycle",
            "effectiveness": "Missing",
            "implementation": None,
            "evidence": "No endpoint detected in scope",
            "main_reason": "No registration endpoint was found in the selected repositories.",
            "auto_source": "auth-coverage",
        }
    )
    validate_portable_model(document)
    foreign = dict(document["components"][0]["paths"][0])
    document["security_controls"][-1]["component_ids"] = [document["components"][1]["id"]]
    document["security_controls"][-1]["evidence"] = [
        {"repository_id": foreign["repository_id"], "file": foreign["path"], "line": 1, "sha256": foreign["sha256"]}
    ]
    if foreign["repository_id"] not in document["components"][1]["repository_ids"]:
        with pytest.raises(ValueError, match="outside its component ownership"):
            validate_portable_model(document)


def _unlisted_fixture(tmp_path):
    """Two repositories, each with a file its only component does not list."""
    files = {"src/app.py": b"value = 1\n", "web/client.ts": b"localStorage.setItem('t', t)\n"}
    views = tuple(
        RepositoryView(f"repo-{i:016x}", tmp_path / f"repository-{i}", "a" * 40, "b" * 64, dict(files)) for i in (1, 2)
    )
    document, _ = fixture(tmp_path)
    document["source_inventory"] = AssessmentScope(views, tmp_path / "out").inventory()

    def cite(rid, path):
        return {"repository_id": rid, "file": path, "line": 1, "sha256": hashlib.sha256(files[path]).hexdigest()}

    return document, cite


def _finding(component, anchor):
    return {
        "id": "T-001",
        "title": "Session token stored in web-accessible client storage",
        "scenario": "A script running in the page reads the stored session token.",
        "stride": "Information Disclosure",
        "likelihood": "High",
        "impact": "High",
        "risk": "High",
        "component": component,
        "evidence": [anchor],
    }


@pytest.mark.parametrize("where", ["finding", "control"])
def test_a_cited_file_no_component_lists_joins_its_own_component(tmp_path, where):
    """A late producer's fallback owner lists the file it cites, so publication never fails on it."""
    document, cite = _unlisted_fixture(tmp_path)
    rid = document["components"][0]["repository_ids"][0]
    anchor = cite(rid, "web/client.ts")
    if where == "finding":
        document["threats"] = [_finding("component-1", anchor)]
    else:
        document["security_controls"] = [
            {
                "domain": "Session management",
                "control": "Token storage",
                "effectiveness": "Weak",
                "component_ids": ["component-1"],
                "evidence": [anchor],
            }
        ]
    with pytest.raises(ValueError, match="outside its component ownership"):
        sources.validate_portable_model(copy.deepcopy(document))
    assert sources.claim_cited_files(document) == [f"{rid}:web/client.ts"]
    sources.validate_portable_model(document)
    # Idempotent, and the other repository's component is untouched.
    assert sources.claim_cited_files(document) == []
    assert [p["path"] for p in document["components"][1]["paths"]] == ["src/app.py"]


def test_a_file_of_another_repository_is_never_claimed(tmp_path):
    document, cite = _unlisted_fixture(tmp_path)
    other = document["components"][1]["repository_ids"][0]
    document["threats"] = [_finding("component-1", cite(other, "web/client.ts"))]
    assert sources.claim_cited_files(document) == []
    with pytest.raises(ValueError, match="outside its component ownership"):
        sources.validate_portable_model(document)


def test_a_listed_file_changes_nothing(tmp_path):
    document, cite = _unlisted_fixture(tmp_path)
    rid = document["components"][0]["repository_ids"][0]
    document["threats"] = [_finding("component-1", cite(rid, "src/app.py"))]
    before = copy.deepcopy(document["components"])
    assert sources.claim_cited_files(document) == [] and document["components"] == before
