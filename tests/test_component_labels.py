"""Report text names components; identifiers stay lookup keys."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from renderers.component_labels import component_names, crossing_text, endpoint_label


@pytest.mark.parametrize(("cid", "name"), [("component-5641940a8bd20431", "user-service"), ("web-api", "Web   API")])
def test_a_boundary_crossing_names_its_components(cid, name):
    model = {"components": [{"id": cid, "name": name}, {"id": "db", "name": "Orders DB"}]}
    names = component_names(model)
    shown = " ".join(name.split())
    assert crossing_text({"from": "external", "to": cid}, names) == f"external → {shown}"
    assert crossing_text({"from": cid, "to": "db"}, names) == f"{shown} → Orders DB"


def test_unknown_or_missing_endpoints_are_kept_or_left_empty():
    names = component_names({"components": [{"id": "api", "name": ""}, {"name": "No id"}, "junk"]})
    assert names == {}
    assert endpoint_label(names, "api") == "api"
    assert crossing_text({"from": "external"}, names) == ""
