"""Portable exports distinguish equal relative files in independent sources."""

import copy
import json

import pytest
from exporters.export_sarif import build_sarif
from exporters.export_threat_dragon import build_threat_dragon

from tests.test_multi_repo_builder import build_assessment_model, inputs


@pytest.mark.parametrize("names", [("edge", "service"), ("gateway", "processor")])
def test_exports_keep_all_sources_and_public_finding_identity(tmp_path, names):
    scope, kwargs = inputs(tmp_path, names=names)
    model, _ = build_assessment_model(scope, **kwargs)
    original = copy.deepcopy(model)
    sarif = build_sarif(model)
    run = sarif["runs"][0]
    assert set(run["originalUriBaseIds"]) == {r.repository_id for r in scope.repositories}
    assert {r["ruleId"] for r in run["results"]} == {t["id"] for t in model["threats"]}
    locations = [r["locations"][0]["physicalLocation"] for r in run["results"]]
    assert {p["artifactLocation"]["uri"] for p in locations} == {"app.py"}
    assert len({p["artifactLocation"]["uriBaseId"] for p in locations}) == 2
    for p in locations:
        rid = p["artifactLocation"]["uriBaseId"]
        assert run["originalUriBaseIds"][rid]["uri"] == f"appsec-repository://{rid}/"
        assert p["properties"]["repositoryId"] == rid
        assert len(p["properties"]["sourceSha256"]) == 64
    dragon, warnings = build_threat_dragon(model)
    descriptions = json.dumps(dragon, ensure_ascii=False)
    assert all(f"{name}:app.py" in descriptions for name in names)
    assert "Repository-qualified" in " ".join(warnings)
    cells = dragon["detail"]["diagrams"][0]["cells"]
    exported = [t for c in cells for t in (c.get("data") or {}).get("threats", [])]
    assert {t["title"].split("]")[0] + "]" for t in exported} == {f"[F-{t['id'][2:]}]" for t in model["threats"]}
    assert model == original
    assert all(str(repo.root) not in json.dumps(sarif) for repo in scope.repositories)


@pytest.mark.parametrize("exporter", [build_sarif, build_threat_dragon])
@pytest.mark.parametrize("kind", ["hash", "owner", "other-root", "missing-root", "flow-endpoint"])
def test_exports_reject_invalid_qualified_models(tmp_path, exporter, kind):
    scope, kwargs = inputs(tmp_path)
    model, _ = build_assessment_model(scope, **kwargs)
    if kind == "hash":
        model["threats"][0]["evidence"][0]["sha256"] = "0" * 64
    elif kind == "owner":
        model["threats"][0]["evidence"][0]["repository_id"] = "repo-ffffffffffffffff"
    elif kind == "other-root":
        # Both admitted checkouts have identical bytes at app.py. A valid hash
        # alone must not let one root impersonate the finding's actual owner.
        model["threats"][0]["evidence"][0] = copy.deepcopy(model["threats"][1]["evidence"][0])
    elif kind == "flow-endpoint":
        model["data_flows"][0]["to"] = "unknown-component"
    else:
        model["components"].pop()
    with pytest.raises(ValueError):
        exporter(model)
