"""Figure 1 retains source ownership without inventing repository trust zones."""

import copy
import xml.etree.ElementTree as ET

import pytest
from renderers import figure1_dfd as figure

from tests.test_assessment_sources import fixture


@pytest.mark.parametrize("labels", [("edge", "service"), ("gateway & input", "processor <output>")])
def test_qualified_overview_and_detail_keep_both_owners_and_geometry(tmp_path, labels):
    document, evidence = fixture(tmp_path)
    for row, label in zip(document["source_inventory"]["repositories"], labels, strict=True):
        row["label"] = label
    # Labels are part of the immutable public inventory fingerprint.
    import hashlib
    import json

    document["source_inventory"]["scope_sha256"] = hashlib.sha256(
        json.dumps(document["source_inventory"]["repositories"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    document["data_flows"] = [
        dict(
            id="df-001",
            **{"from": "component-1", "to": "component-2"},
            label="Request records",
            protocol="HTTPS",
            direction="request-response",
            data_classification="Internal",
            evidence=evidence,
        )
    ]
    original = copy.deepcopy(document)
    for detail in (False, True):
        svg, errors = figure.check_diagram(document, {}, {}, detail=detail)
        assert not errors
        root = ET.fromstring(svg)
        legends = root.findall("{*}g[@data-legend-section='repositories']/{*}g[@data-repository-id]")
        assert {g.get("data-repository-id") for g in legends} == {e["repository_id"] for e in evidence}
        assert all(label in "".join(root.itertext()) for label in labels)
        assert len(root.findall(".//{*}g[@data-repository-owner]")) == 2
        assert "Repos: R1" in "".join(root.itertext()) and "Repos: R2" in "".join(root.itertext())
        assert not root.findall(".//{*}g[@data-boundary-id]")
        assert figure.build_figure1_dfd_svg(document, {}, {}, detail=detail) == svg
    assert document == original


def test_qualified_figure_rejects_forged_inventory_before_drawing(tmp_path):
    document, _ = fixture(tmp_path)
    document["components"][0]["paths"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        figure.check_diagram(document, {}, {})
    with pytest.raises(ValueError):
        figure.build_figure1_dfd_svg(document, {}, {})


def test_qualified_empty_inventory_cannot_silently_omit_selected_repositories(tmp_path):
    document, _ = fixture(tmp_path)
    document["components"] = []
    with pytest.raises(ValueError):
        figure.build_figure1_dfd_svg(document, {}, {})


def test_legacy_figure_has_no_repository_annotation(tmp_path):
    document, _ = fixture(tmp_path)
    document["meta"]["schema_version"] = 1
    document.pop("source_inventory")
    for component in document["components"]:
        component.pop("repository_ids")
        component["paths"] = ["src/app.py"]
    svg, errors = figure.check_diagram(document, {}, {}, detail=False)
    assert not errors and "data-repository-owner" not in svg and "Source repositories" not in svg
