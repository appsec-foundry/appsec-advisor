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
