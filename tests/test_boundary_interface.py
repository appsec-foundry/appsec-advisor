"""One rule for "internal interface, not a trust boundary" across every surface."""

from __future__ import annotations

import pytest
from renderers import compose_threat_model, figure1_dfd, pregenerate_fragments
from shared._boundary_interface import is_internal_interface

SHAPES = [
    ({"surface": "in-process", "transition": []}, True),
    ({"kind": "process"}, True),
    ({"kind": "process", "surface": "network", "transition": []}, False),
    ({"surface": "in-process", "transition": ["privilege"]}, False),
    ({"surface": "network", "transition": []}, False),
    ({"surface": "build-pipeline", "transition": []}, False),
    ({"kind": "network"}, False),
    ({}, False),
]


@pytest.mark.parametrize(("row", "expected"), SHAPES)
def test_predicate(row, expected):
    assert is_internal_interface(row) is expected


@pytest.mark.parametrize(("row", "expected"), SHAPES)
def test_figure1_and_catalogue_agree_with_the_shared_rule(row, expected):
    assert figure1_dfd._internal_interface(row) is expected
    label = compose_threat_model._boundary_kind_label(row)
    assert ("enforcement interface" in label) is expected


@pytest.mark.parametrize(("row", "expected"), SHAPES)
def test_container_diagram_partitions_interfaces_by_the_shared_rule(row, expected):
    components = [{"id": "api", "tier": "application"}, {"id": "db", "tier": "data"}]
    tb = {"id": "tb-1", "from": "api", "to": "db", "confidence": "confirmed", "resolution_status": "resolved", **row}
    *_, interfaces = pregenerate_fragments._container_boundaries({"trust_boundaries": [tb]}, components)
    assert bool(interfaces) is expected
