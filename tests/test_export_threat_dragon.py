"""
Tests for `scripts/export_threat_dragon.py` — deterministic OWASP Threat
Dragon v2 export from a `threat-model.yaml`.

Two contracts are guarded here:

* the Threat Dragon v2 envelope, so the file opens in Threat Dragon itself;
* the narrower subset OWASP ThreatAtlas' importer actually reads
  (`detail.diagrams[0].cells`, `shape`, `source.cell`, `data.threats`), so an
  import creates threats and not just boxes.

The export is best-effort: thin, legacy-shaped or inconsistent input must still
produce a usable diagram, with the problems reported as warnings.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import export_threat_dragon as etd  # noqa: E402

SCRIPT = ROOT / "scripts" / "export_threat_dragon.py"
FIXTURES = ROOT / "tests" / "fixtures"
COMPOSE_YAML = FIXTURES / "compose" / "threat-model.yaml"
# The schema owners' canonical example — the same file `tests/test_schemas.py`
# and `tests/test_new_schemas.py` validate the output schema against.
SCHEMA_VALID_YAML = FIXTURES / "schema" / "threat-model.valid.yaml"

TD_DIR = FIXTURES / "threat-dragon"
# Threat Dragon's own model schema, and the source/golden pair pinning the
# mapping. See TD_DIR/README.md for provenance and how to regenerate.
TD_SCHEMA = TD_DIR / "owasp.threat-dragon-v2.schema.json"
GOLDEN_YAML = TD_DIR / "threat-model.source.yaml"
GOLDEN_JSON = TD_DIR / "threat-model.threatdragon.golden.json"
GOLDEN_TOOL_VERSION = "0.0.0-test"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cells(doc: dict) -> list[dict]:
    return doc["detail"]["diagrams"][0]["cells"]


def _nodes(doc: dict) -> list[dict]:
    return [c for c in _cells(doc) if c["shape"] != "flow"]


def _flows(doc: dict) -> list[dict]:
    return [c for c in _cells(doc) if c["shape"] == "flow"]


def _node(doc: dict, node_id: str) -> dict:
    for cell in _nodes(doc):
        if cell["id"] == node_id:
            return cell
    raise AssertionError(f"node {node_id!r} not in {[c['id'] for c in _nodes(doc)]}")


def _all_threats(doc: dict) -> list[dict]:
    return [t for cell in _cells(doc) for t in cell["data"]["threats"]]


def _model(**overrides) -> dict:
    base = {
        "meta": {"project": "Shop", "team_owner": "Platform"},
        "components": [
            {"id": "C-01", "name": "Web UI", "tier": "client"},
            {"id": "C-02", "name": "REST API", "tier": "application"},
            {"id": "C-03", "name": "Order DB", "tier": "data"},
        ],
        "data_flows": [
            {"id": "DF-01", "from": "C-01", "to": "C-02", "label": "order submit", "protocol": "HTTPS"},
        ],
        "threats": [
            {
                "id": "T-001",
                "component": "C-02",
                "stride": "Tampering",
                "title": "SQL injection in product search",
                "scenario": "Raw SQL built via template literal.",
                "risk": "Critical",
                "likelihood": "High",
                "impact": "Critical",
                "cwe": "CWE-89",
                "evidence": [{"file": "routes/search.ts", "line": 42}],
                "mitigation_ids": ["M-001"],
            }
        ],
        "mitigations": [
            {
                "id": "M-001",
                "title": "Parameterize SQL queries",
                "threat_ids": ["T-001"],
                "priority": "P1",
                "effort": "Medium",
                "steps": ["Replace template literals", "Add a lint rule"],
                "verification": "sqlmap reports no injectable parameter.",
            }
        ],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def test_envelope_is_threat_dragon_v2():
    doc, _ = etd.build_threat_dragon(_model())
    assert doc["version"] == etd.TD_VERSION
    assert doc["summary"]["title"] == "Shop"
    assert doc["summary"]["owner"] == "Platform"
    diagrams = doc["detail"]["diagrams"]
    assert len(diagrams) == 1, "ThreatAtlas reads detail.diagrams[0] only — never emit a second diagram"
    assert diagrams[0]["diagramType"] == "STRIDE"
    assert doc["detail"]["threatTop"] == 1


def test_summary_description_marks_the_export_alpha():
    doc, _ = etd.build_threat_dragon(_model(), tool_version="9.9.9")
    description = doc["summary"]["description"]
    assert "ALPHA" in description
    assert "9.9.9" in description


def test_diagram_title_override():
    doc, _ = etd.build_threat_dragon(_model(), diagram_title="Checkout DFD")
    assert doc["detail"]["diagrams"][0]["title"] == "Checkout DFD"
    assert doc["summary"]["title"] == "Shop", "the override retitles the diagram, not the project"


# ---------------------------------------------------------------------------
# Component → node mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tier", "shape", "tm_type"),
    [
        ("client", "actor", "tm.Actor"),
        ("application", "process", "tm.Process"),
        ("data", "store", "tm.Store"),
    ],
)
def test_tier_maps_to_dfd_shape(tier, shape, tm_type):
    doc, _ = etd.build_threat_dragon(_model(components=[{"id": "C-01", "name": "X", "tier": tier}], threats=[]))
    node = _node(doc, "C-01")
    assert node["shape"] == shape
    assert node["data"]["type"] == tm_type


@pytest.mark.parametrize(
    ("kind", "shape"),
    [("database", "store"), ("frontend", "actor"), ("service", "process"), ("nonsense", "process")],
)
def test_legacy_kind_is_the_fallback_when_tier_is_absent(kind, shape):
    doc, _ = etd.build_threat_dragon(_model(components=[{"id": "C-01", "name": "X", "kind": kind}], threats=[]))
    assert _node(doc, "C-01")["shape"] == shape


def test_unclassified_component_defaults_to_process():
    doc, _ = etd.build_threat_dragon(_model(components=[{"id": "C-01", "name": "X"}], threats=[]))
    assert _node(doc, "C-01")["shape"] == "process"


def test_node_carries_the_label_where_both_importers_read_it():
    doc, _ = etd.build_threat_dragon(_model())
    node = _node(doc, "C-02")
    assert node["data"]["name"] == "REST API"
    assert node["attrs"]["text"]["text"] == "REST API"


def test_duplicate_component_id_is_skipped_with_a_warning():
    doc, warnings = etd.build_threat_dragon(
        _model(components=[{"id": "C-01", "name": "A"}, {"id": "C-01", "name": "B"}], threats=[])
    )
    assert len(_nodes(doc)) == 1
    assert _node(doc, "C-01")["data"]["name"] == "A"
    assert any("duplicate component id" in w for w in warnings)


def test_component_without_id_or_name_is_skipped():
    doc, warnings = etd.build_threat_dragon(
        _model(components=[{"tier": "data"}, {"id": "C-02", "name": "Keep"}], threats=[])
    )
    assert [c["id"] for c in _nodes(doc)] == ["C-02"]
    assert any("without id or name" in w for w in warnings)


def test_layout_is_column_per_shape_and_row_per_index():
    doc, _ = etd.build_threat_dragon(
        _model(
            components=[
                {"id": "C-01", "name": "A", "tier": "application"},
                {"id": "C-02", "name": "B", "tier": "application"},
                {"id": "C-03", "name": "C", "tier": "data"},
            ],
            threats=[],
            data_flows=[],
        )
    )
    assert _node(doc, "C-01")["position"] == {"x": 440, "y": 80}
    assert _node(doc, "C-02")["position"] == {"x": 440, "y": 220}
    assert _node(doc, "C-03")["position"] == {"x": 800, "y": 80}


# ---------------------------------------------------------------------------
# Threat mapping
# ---------------------------------------------------------------------------


def test_threat_lands_on_its_component():
    doc, warnings = etd.build_threat_dragon(_model())
    assert warnings == []
    threats = _node(doc, "C-02")["data"]["threats"]
    assert len(threats) == 1
    assert _node(doc, "C-02")["data"]["hasOpenThreats"] is True
    assert _node(doc, "C-01")["data"]["threats"] == []


def test_component_id_is_read_before_component():
    """The composer resolves `component_id or component`; mirror that order so
    a threat carrying both lands on the same element the report shows."""
    doc, warnings = etd.build_threat_dragon(
        _model(threats=[{"id": "T-001", "component_id": "C-03", "component": "REST API", "title": "X"}])
    )
    assert warnings == []
    assert len(_node(doc, "C-03")["data"]["threats"]) == 1
    assert _node(doc, "C-02")["data"]["threats"] == []


def test_threat_component_may_be_a_name_instead_of_an_id():
    doc, warnings = etd.build_threat_dragon(
        _model(threats=[{"id": "T-001", "component": "REST API", "stride": "Spoofing", "title": "X"}])
    )
    assert warnings == []
    assert len(_node(doc, "C-02")["data"]["threats"]) == 1


def test_title_carries_the_report_anchor_not_the_yaml_id():
    """The composer renders yaml `T-NNN` as `F-NNN`. A Threat Dragon entry must
    cite the id the reader sees in threat-model.md."""
    doc, _ = etd.build_threat_dragon(_model())
    threat = _all_threats(doc)[0]
    assert threat["title"] == "[F-001] SQL injection in product search"
    assert threat["id"] == "F-001"


def test_stride_category_and_numbering():
    doc, _ = etd.build_threat_dragon(_model())
    threat = _all_threats(doc)[0]
    assert threat["type"] == "Tampering"
    assert threat["modelType"] == "STRIDE"
    assert threat["number"] == 1
    assert threat["status"] == "Open"


def test_non_stride_category_passes_through():
    doc, _ = etd.build_threat_dragon(
        _model(threats=[{"id": "T-001", "component": "C-02", "stride": "Privacy", "title": "X"}])
    )
    assert _all_threats(doc)[0]["type"] == "Privacy"


@pytest.mark.parametrize(
    ("risk", "severity"),
    [("Critical", "Critical"), ("High", "High"), ("Medium", "Medium"), ("Low", "Low")],
)
def test_risk_maps_to_threat_dragon_severity(risk, severity):
    doc, _ = etd.build_threat_dragon(_model(threats=[{"id": "T-001", "component": "C-02", "title": "X", "risk": risk}]))
    assert _all_threats(doc)[0]["severity"] == severity


def test_informational_degrades_to_low():
    """ThreatAtlas' severity map has no `informational` key and imports an
    unmatched severity with null likelihood and impact — i.e. unscored."""
    doc, _ = etd.build_threat_dragon(
        _model(threats=[{"id": "T-001", "component": "C-02", "title": "X", "risk": "Informational"}])
    )
    assert _all_threats(doc)[0]["severity"] == "Low"


def test_missing_risk_becomes_tbd_rather_than_an_invented_rating():
    """`TBD` is Threat Dragon's own value for an unrated threat, so the
    severity control has a selection. ThreatAtlas imports it unscored, exactly
    as it would an absent severity."""
    doc, _ = etd.build_threat_dragon(_model(threats=[{"id": "T-001", "component": "C-02", "title": "X"}]))
    assert _all_threats(doc)[0]["severity"] == "TBD"


def test_stride_category_uses_threat_dragons_own_spelling():
    """Ours is title case, Threat Dragon's is sentence case. Emitting theirs
    keeps the editor's type dropdown at one option instead of two."""
    doc, _ = etd.build_threat_dragon(
        _model(
            threats=[
                {"id": "T-001", "component": "C-02", "stride": "Information Disclosure", "title": "A"},
                {"id": "T-002", "component": "C-02", "stride": "Denial of Service", "title": "B"},
                {"id": "T-003", "component": "C-02", "stride": "Elevation of Privilege", "title": "C"},
            ]
        )
    )
    assert [t["type"] for t in _all_threats(doc)] == [
        "Information disclosure",
        "Denial of service",
        "Elevation of privilege",
    ]


def test_cvss_base_score_lands_in_the_score_field():
    """Threat Dragon's free-text `score` is the one numeric rating field it
    has; the vector stays in the description because nothing holds it."""
    doc, _ = etd.build_threat_dragon(
        _model(
            threats=[
                {
                    "id": "T-001",
                    "component": "C-02",
                    "title": "X",
                    "cvss_v4": {"base_score": 8.7, "vector": "CVSS:4.0/AV:N"},
                }
            ]
        )
    )
    threat = _all_threats(doc)[0]
    assert threat["score"] == "8.7"
    assert "CVSS:4.0/AV:N" in threat["description"]


def test_threat_without_cvss_has_no_score_field():
    doc, _ = etd.build_threat_dragon(_model())
    assert "score" not in _all_threats(doc)[0]


def test_description_folds_in_the_fields_threat_dragon_cannot_hold():
    doc, _ = etd.build_threat_dragon(_model())
    description = _all_threats(doc)[0]["description"]
    assert "Raw SQL built via template literal." in description
    assert "Risk: Critical (likelihood High, impact Critical)" in description
    assert "CWE-89" in description
    assert "- routes/search.ts:42" in description
    assert "threat-model.md#f-001" in description


def test_evidence_summary_heads_the_evidence_block():
    """The prose naming the concrete evidence is a separate field from
    `scenario` and is where the file references get their meaning."""
    doc, _ = etd.build_threat_dragon(
        _model(
            threats=[
                {
                    "id": "T-001",
                    "component": "C-02",
                    "title": "X",
                    "scenario": "Search is injectable.",
                    "evidence_summary": "`db.query` concatenates `q` at search.ts:42.",
                    "evidence": [{"file": "search.ts", "line": 42}],
                }
            ]
        )
    )
    description = _all_threats(doc)[0]["description"]
    assert "Evidence:\n`db.query` concatenates `q` at search.ts:42.\n- search.ts:42" in description


def test_description_includes_cvss_when_present():
    doc, _ = etd.build_threat_dragon(
        _model(
            threats=[
                {
                    "id": "T-001",
                    "component": "C-02",
                    "title": "X",
                    "cvss_v4": {"base_score": 8.7, "vector": "CVSS:4.0/AV:N"},
                }
            ]
        )
    )
    assert "CVSS v4: 8.7 (CVSS:4.0/AV:N)" in _all_threats(doc)[0]["description"]


def test_evidence_accepts_the_legacy_single_dict_shape():
    doc, _ = etd.build_threat_dragon(
        _model(threats=[{"id": "T-001", "component": "C-02", "title": "X", "evidence": {"file": "a.ts", "line": 7}}])
    )
    assert "- a.ts:7" in _all_threats(doc)[0]["description"]


# ---------------------------------------------------------------------------
# Mitigation mapping
# ---------------------------------------------------------------------------


def test_mitigation_text_is_rendered_into_the_single_field():
    doc, _ = etd.build_threat_dragon(_model())
    mitigation = _all_threats(doc)[0]["mitigation"]
    assert "M-001 — Parameterize SQL queries (priority P1, effort Medium)" in mitigation
    assert "1. Replace template literals" in mitigation
    assert "2. Add a lint rule" in mitigation
    assert "Verification: sqlmap reports no injectable parameter." in mitigation


def test_mitigation_links_from_either_side_and_either_vocabulary():
    """Canonical: mitigation.threat_ids. Legacy: mitigation.addresses with an
    `m_id`. Both must resolve, and neither may duplicate the entry."""
    doc, _ = etd.build_threat_dragon(
        _model(
            threats=[{"id": "T-001", "component": "C-02", "title": "X", "mitigation_ids": ["M-001"]}],
            mitigations=[{"m_id": "M-001", "title": "Fix", "addresses": ["T-001"], "why": "w", "how": "h"}],
        )
    )
    mitigation = _all_threats(doc)[0]["mitigation"]
    assert mitigation.count("M-001") == 1
    assert "Why: w" in mitigation and "How: h" in mitigation


def test_accepted_risk_is_the_one_status_that_is_not_open():
    """`accept_risk` records a decision that has been taken, unlike every other
    kind, which proposes work. `Accepted` is Threat Dragon's own status value
    and ThreatAtlas maps it onto its accepted state."""
    doc, _ = etd.build_threat_dragon(
        _model(mitigations=[{"id": "M-001", "title": "Accept", "threat_ids": ["T-001"], "kind": "accept_risk"}])
    )
    assert _all_threats(doc)[0]["status"] == "Accepted"


def test_a_threat_with_any_actionable_mitigation_stays_open():
    doc, _ = etd.build_threat_dragon(
        _model(
            mitigations=[
                {"id": "M-001", "title": "Accept", "threat_ids": ["T-001"], "kind": "accept_risk"},
                {"id": "M-002", "title": "Fix", "threat_ids": ["T-001"], "kind": "fix"},
            ]
        )
    )
    assert _all_threats(doc)[0]["status"] == "Open"


def test_unlinked_mitigation_is_not_attached():
    doc, _ = etd.build_threat_dragon(
        _model(mitigations=[{"id": "M-009", "title": "Unrelated", "threat_ids": ["T-999"]}])
    )
    assert _all_threats(doc)[0]["mitigation"] == ""


# ---------------------------------------------------------------------------
# Data flows
# ---------------------------------------------------------------------------


def test_flow_uses_source_cell_which_is_the_only_field_the_importer_reads():
    doc, _ = etd.build_threat_dragon(_model())
    flow = _flows(doc)[0]
    assert flow["source"] == {"cell": "C-01"}
    assert flow["target"] == {"cell": "C-02"}
    assert flow["data"]["name"] == "order submit (HTTPS)"
    assert flow["data"]["isEncrypted"] is True


def test_flow_has_no_labels_key():
    """ThreatAtlas reads `labels[0]` and uses it only when it is a plain
    string — an object label would relabel every flow "Data Flow" instead of
    falling through to `data.name`."""
    assert "labels" not in _flows(etd.build_threat_dragon(_model())[0])[0]


def test_flow_endpoints_resolve_by_component_name_too():
    doc, warnings = etd.build_threat_dragon(
        _model(data_flows=[{"from": "Web UI", "to": "Order DB", "label": "export"}])
    )
    assert warnings == []
    assert _flows(doc)[0]["source"] == {"cell": "C-01"}
    assert _flows(doc)[0]["target"] == {"cell": "C-03"}


def test_flow_with_an_unresolved_endpoint_is_dropped_with_a_warning():
    doc, warnings = etd.build_threat_dragon(_model(data_flows=[{"from": "C-01", "to": "C-99", "label": "ghost"}]))
    assert _flows(doc) == []
    assert any("unresolved endpoint" in w for w in warnings)


def test_missing_data_flows_is_not_an_error():
    doc, warnings = etd.build_threat_dragon(_model(data_flows=None))
    assert _flows(doc) == []
    assert warnings == []


def test_external_endpoint_becomes_an_actor_instead_of_a_dropped_flow():
    """`external` is the one reserved value the output schema allows in
    `data_flows[].from`/`.to`. Dropping those would lose exactly the edges a
    DFD is drawn for."""
    doc, warnings = etd.build_threat_dragon(
        _model(data_flows=[{"id": "df-001", "from": "external", "to": "C-02", "label": "browse", "protocol": "HTTPS"}])
    )
    assert warnings == []
    assert _node(doc, "external")["shape"] == "actor"
    assert _flows(doc)[0]["source"] == {"cell": "external"}


def test_only_one_external_actor_is_created():
    doc, _ = etd.build_threat_dragon(
        _model(
            data_flows=[
                {"from": "external", "to": "C-01", "label": "a"},
                {"from": "C-03", "to": "external", "label": "b"},
            ]
        )
    )
    assert [c["id"] for c in _nodes(doc)].count("external") == 1
    assert len(_flows(doc)) == 2


def test_legacy_flow_endpoint_aliases_are_accepted():
    """The §2.2 diagram renderer tolerates src/dst and source/destination;
    this export must not be stricter than the in-repo consumer."""
    doc, warnings = etd.build_threat_dragon(
        _model(
            data_flows=[
                {"src": "C-01", "dst": "C-02", "name": "aliased"},
                {"source": "C-02", "destination": "C-03", "label": "also aliased"},
            ]
        )
    )
    assert warnings == []
    assert [f["data"]["name"] for f in _flows(doc)] == ["aliased", "also aliased"]


@pytest.mark.parametrize(
    ("direction", "expected"),
    [("bidirectional", True), ("request-response", True), ("unidirectional", False), ("", False)],
)
def test_direction_enum_maps_to_is_bidirectional(direction, expected):
    doc, _ = etd.build_threat_dragon(
        _model(data_flows=[{"from": "C-01", "to": "C-02", "label": "x", "direction": direction}])
    )
    assert _flows(doc)[0]["data"]["isBidirectional"] is expected


# ---------------------------------------------------------------------------
# Best-effort degradation
# ---------------------------------------------------------------------------


def test_unresolved_threat_component_goes_to_an_unassigned_element():
    doc, warnings = etd.build_threat_dragon(
        _model(threats=[{"id": "T-007", "component": "Ghost service", "title": "X"}])
    )
    assert len(_node(doc, "C-UNASSIGNED")["data"]["threats"]) == 1
    assert any("F-007" in w and "Ghost service" in w for w in warnings)


def test_only_one_unassigned_element_is_created():
    doc, _ = etd.build_threat_dragon(
        _model(
            threats=[
                {"id": "T-001", "component": "Ghost", "title": "A"},
                {"id": "T-002", "component": "Phantom", "title": "B"},
            ]
        )
    )
    assert [c["id"] for c in _nodes(doc)].count("C-UNASSIGNED") == 1
    assert len(_node(doc, "C-UNASSIGNED")["data"]["threats"]) == 2


def test_nodes_are_synthesised_when_the_yaml_has_no_components():
    doc, warnings = etd.build_threat_dragon(
        _model(
            components=[],
            data_flows=[],
            threats=[
                {"id": "T-001", "component": "Billing", "title": "A"},
                {"id": "T-002", "component": "Billing", "title": "B"},
            ],
        )
    )
    assert [c["id"] for c in _nodes(doc)] == ["Billing"]
    assert len(_node(doc, "Billing")["data"]["threats"]) == 2
    assert any("synthesised" in w for w in warnings)


def test_empty_model_still_yields_one_element():
    """Both importers reject a cell-less diagram — ThreatAtlas throws
    "No diagram elements found"."""
    doc, warnings = etd.build_threat_dragon({})
    assert len(_nodes(doc)) == 1
    assert doc["detail"]["threatTop"] == 0
    assert any("placeholder" in w for w in warnings)


def test_the_placeholder_is_the_unassigned_sink():
    """A placeholder and an Unassigned element are the same catch-all. Two of
    them would be drawn on top of each other, since each takes the first row of
    the process column."""
    doc, _ = etd.build_threat_dragon({"threats": [{"id": "T-001", "title": "X"}]})
    nodes = _nodes(doc)
    assert [c["id"] for c in nodes] == ["C-SYSTEM"]
    assert len(nodes[0]["data"]["threats"]) == 1


def test_no_two_elements_share_a_position():
    doc, _ = etd.build_threat_dragon(
        _model(
            threats=[{"id": "T-001", "component": "Ghost", "title": "X"}],
            data_flows=[{"from": "external", "to": "C-01", "label": "a"}],
        )
    )
    positions = [(c["position"]["x"], c["position"]["y"]) for c in _nodes(doc)]
    assert len(set(positions)) == len(positions)


def test_a_one_character_id_is_padded_to_the_schema_minimum():
    """`cells[].id` has minLength 2 in the Threat Dragon v2 schema. Endpoints
    still resolve, because lookups key off the source reference."""
    doc, warnings = etd.build_threat_dragon(
        _model(
            components=[{"id": "a", "name": "A"}, {"id": "b", "name": "B"}],
            threats=[],
            data_flows=[{"from": "a", "to": "b", "label": "x"}],
        )
    )
    assert warnings == []
    assert [c["id"] for c in _nodes(doc)] == ["td-a", "td-b"]
    assert _flows(doc)[0]["source"] == {"cell": "td-a"}
    assert _flows(doc)[0]["target"] == {"cell": "td-b"}


def test_trust_boundary_geometry_is_reported_as_not_drawn():
    doc, warnings = etd.build_threat_dragon(
        _model(trust_boundaries=[{"id": "TB-01", "name": "Edge", "from": "C-01", "to": "C-02"}])
    )
    assert all("boundary" not in c["shape"] for c in _cells(doc))
    assert any("trust boundary" in w for w in warnings)


def _boundary(bid: str, source: str, target: str, **overrides) -> dict:
    return {
        "id": bid,
        "name": f"{source} → {target}",
        "from": source,
        "to": target,
        "kind": "network",
        "assumption": "Requests are authenticated before protected operations.",
        "evidence": [],
        "confidence": "confirmed",
        "resolution_status": "resolved",
        "sources": ["detected"],
        **overrides,
    }


def test_referenced_crossing_is_folded_into_the_threat_description():
    # Threat Dragon has no boundary field on a threat, and a bare `tb-N` means
    # nothing outside the run — so the crossing and its exposure travel as text.
    threat = dict(_model()["threats"][0])
    threat["boundary_refs"] = [{"boundary_id": "tb-1", "rationale": "The edge does not authenticate."}]
    doc, _ = etd.build_threat_dragon(_model(threats=[threat], trust_boundaries=[_boundary("tb-1", "external", "C-02")]))
    assert (
        "Trust boundary crossings:\n- tb-1 external → C-02 (internet-facing): The edge does not authenticate."
        in _all_threats(doc)[0]["description"]
    )


def test_unresolvable_boundary_ref_degrades_to_the_bare_id():
    threat = dict(_model()["threats"][0])
    threat["boundary_refs"] = [{"boundary_id": "tb-9"}]
    doc, _ = etd.build_threat_dragon(_model(threats=[threat], trust_boundaries=[_boundary("tb-1", "external", "C-02")]))
    assert "Trust boundary crossings:\n- tb-9" in _all_threats(doc)[0]["description"]


@pytest.mark.parametrize(
    ("boundary", "expected"),
    [
        # Inbound and outbound both leave the machine — Threat Dragon's flag is
        # about the network the flow traverses, not the direction.
        (_boundary("tb-1", "external", "C-02"), True),
        (_boundary("tb-1", "C-02", "external"), True),
        # An unconfirmed or unresolved row is not evidence of a public network.
        (_boundary("tb-1", "external", "C-02", confidence="inferred"), False),
        (_boundary("tb-1", "external", "C-02", resolution_status="unresolved"), False),
        # A crossing between two internal components is not one either.
        (_boundary("tb-1", "C-01", "C-02"), False),
    ],
)
def test_is_public_network_follows_the_boundary_exposure(boundary, expected):
    doc, _ = etd.build_threat_dragon(
        _model(
            data_flows=[{"id": "DF-01", "from": "external", "to": "C-02", "label": "browse"}],
            trust_boundaries=[boundary],
        )
    )
    assert _flows(doc)[0]["data"]["isPublicNetwork"] is expected


def test_non_dict_entries_are_ignored():
    doc, _ = etd.build_threat_dragon(
        _model(components=["oops", {"id": "C-01", "name": "A"}], threats=[None], data_flows=["nope"])
    )
    assert [c["id"] for c in _nodes(doc)] == ["C-01"]
    assert _all_threats(doc) == []


# ---------------------------------------------------------------------------
# Importer contract — assertions mirroring ThreatAtlas' parser
# ---------------------------------------------------------------------------


def test_every_cell_satisfies_the_threatatlas_parser_contract():
    doc, _ = etd.build_threat_dragon(_model())
    cells = _cells(doc)
    assert cells, "parseThreatDragonJson throws when no element survives"
    for cell in cells:
        assert isinstance(cell.get("id"), str) and cell["id"]
        assert cell["shape"] in {"actor", "process", "store", "flow"}
        assert cell["shape"] != "trust-boundary-curve", "the parser skips curves outright"
        if cell["shape"] == "flow":
            assert isinstance(cell["source"]["cell"], str)
            assert isinstance(cell["target"]["cell"], str)
        else:
            assert isinstance(cell["position"]["x"], int)
            assert isinstance(cell["size"]["width"], int)
        assert isinstance(cell["data"]["threats"], list)


def test_flow_endpoints_reference_existing_nodes():
    doc, _ = etd.build_threat_dragon(_model())
    node_ids = {c["id"] for c in _nodes(doc)}
    for flow in _flows(doc):
        assert flow["source"]["cell"] in node_ids
        assert flow["target"]["cell"] in node_ids


# --- ThreatAtlas importer simulation ---------------------------------------
#
# A faithful port of ThreatAtlas' `parseThreatDragonJson` and the threat/
# mitigation creation that follows it
# (`frontend/src/components/ImportDrawioButton.tsx`). Structural assertions
# alone cannot show that an import produces *scored findings* rather than
# empty boxes — this replays the importer's own logic to prove it. Keep it in
# sync with upstream when the alpha marker comes off.

_TA_SEVERITY = {"critical": (5, 5), "high": (4, 4), "medium": (3, 3), "low": (2, 2)}
_TA_STATUS = {
    "open": "identified",
    "mitigated": "mitigated",
    "not applicable": "accepted",
    "accepted": "accepted",
    "closed": "mitigated",
}


def _ta_element_type(cell: dict) -> str:
    shape = (cell.get("shape") or "").lower()
    data_type = (cell.get("data", {}).get("type") or "").lower()
    if "trust-boundary" in shape or "boundarybox" in data_type:
        return "boundary"
    if shape == "process" or "process" in data_type:
        return "process"
    if shape == "store" or "store" in data_type:
        return "datastore"
    if shape == "actor" or "actor" in data_type:
        return "external"
    return "external"


def _threatatlas_import(doc: dict) -> dict:
    """Return what ThreatAtlas would persist: elements, flows, DiagramThreats."""
    cells = doc["detail"]["diagrams"][0]["cells"]
    elements: dict[str, str] = {}
    flows: list[tuple[str, str, str]] = []
    carried: list[tuple[str, dict]] = []

    for cell in cells:
        cell_type = (cell.get("shape") or cell.get("type") or "").lower()
        cid = cell.get("id")
        if cell_type == "trust-boundary-curve":
            continue  # the importer skips curves outright
        if cell_type == "flow":
            source = (cell.get("source") or {}).get("cell")
            target = (cell.get("target") or {}).get("cell")
            if not (source and target):
                continue
            edge_id = f"td-edge-{cid}"
            label = (cell.get("labels") or [None])[0] or cell.get("data", {}).get("name") or "Data Flow"
            flows.append((f"td-{source}", f"td-{target}", label if isinstance(label, str) else "Data Flow"))
            carried.extend((edge_id, t) for t in cell.get("data", {}).get("threats") or [])
            continue
        elements[f"td-{cid}"] = _ta_element_type(cell)
        carried.extend((f"td-{cid}", t) for t in cell.get("data", {}).get("threats") or [])

    assert elements, "parseThreatDragonJson throws 'No diagram elements found'"

    diagram_threats = []
    for element_id, threat in carried:
        severity = _TA_SEVERITY.get((threat.get("severity") or "").lower())
        diagram_threats.append(
            {
                "element_id": element_id,
                "element_type": elements.get(element_id, "process"),
                "name": threat["title"],
                "category": threat["type"],
                "status": _TA_STATUS.get((threat.get("status") or "open").lower(), "identified"),
                "likelihood": severity[0] if severity else None,
                "impact": severity[1] if severity else None,
                "mitigation": threat.get("mitigation") or None,
            }
        )
    return {"elements": elements, "flows": flows, "diagram_threats": diagram_threats}


def test_threatatlas_import_creates_scored_findings_not_just_boxes():
    doc, _ = etd.build_threat_dragon(_model())
    imported = _threatatlas_import(doc)

    assert imported["elements"] == {"td-C-01": "external", "td-C-02": "process", "td-C-03": "datastore"}
    assert imported["flows"] == [("td-C-01", "td-C-02", "order submit (HTTPS)")]

    assert len(imported["diagram_threats"]) == 1
    finding = imported["diagram_threats"][0]
    assert finding["element_id"] == "td-C-02"
    assert finding["element_type"] == "process"
    assert finding["name"] == "[F-001] SQL injection in product search"
    assert finding["category"] == "Tampering"
    assert finding["status"] == "identified"
    assert (finding["likelihood"], finding["impact"]) == (5, 5)
    assert finding["mitigation"], "the mitigation string is what becomes a Mitigation record"


def test_threatatlas_import_scores_an_informational_finding():
    """Left as `Informational`, ThreatAtlas' severity lookup misses and the
    finding is persisted with null likelihood and impact."""
    doc, _ = etd.build_threat_dragon(
        _model(threats=[{"id": "T-002", "component": "C-03", "title": "X", "risk": "Informational"}])
    )
    finding = _threatatlas_import(doc)["diagram_threats"][0]
    assert (finding["likelihood"], finding["impact"]) == (2, 2)


def test_threatatlas_import_survives_an_empty_model():
    doc, _ = etd.build_threat_dragon({})
    imported = _threatatlas_import(doc)
    assert len(imported["elements"]) == 1
    assert imported["diagram_threats"] == []


def test_production_vocabulary_exports_cleanly():
    """Guards against fixtures that only use the tidy shapes.

    Real output uses lowercase-slug component ids (`^[a-z][a-z0-9-]+$`, see
    `schemas/component-inventory-finalization.schema.json`), `df-NNN` flow ids,
    the reserved `external` endpoint, and `component_id` on threats. `C-01` is
    a display label the composer assigns, never the yaml id — an export that
    only handled `C-NN` would drop every real flow.
    """
    doc, warnings = etd.build_threat_dragon(
        {
            "meta": {"project": "Shop", "team_owner": "Platform"},
            "components": [
                {"id": "web-ui", "name": "Web UI", "tier": "client"},
                {"id": "rest-api", "name": "REST API", "tier": "application"},
                {"id": "order-db", "name": "Order DB", "tier": "data"},
            ],
            "data_flows": [
                {
                    "id": "df-001",
                    "from": "external",
                    "to": "web-ui",
                    "label": "browse",
                    "protocol": "HTTPS",
                    "data_classification": "Public",
                    "direction": "request-response",
                },
                {
                    "id": "df-002",
                    "from": "rest-api",
                    "to": "order-db",
                    "label": "persist order",
                    "protocol": "TCP",
                    "data_classification": "Confidential",
                    "direction": "unidirectional",
                },
            ],
            "threats": [
                {
                    "id": "T-001",
                    "component_id": "rest-api",
                    "stride": "Tampering",
                    "title": "SQL injection",
                    "scenario": "Raw SQL.",
                    "risk": "High",
                }
            ],
            "mitigations": [],
        }
    )

    assert warnings == [], "a production-shaped model must export without a single warning"

    imported = _threatatlas_import(doc)
    assert imported["elements"] == {
        "td-web-ui": "external",
        "td-rest-api": "process",
        "td-order-db": "datastore",
        "td-external": "external",
    }
    assert imported["flows"] == [
        ("td-external", "td-web-ui", "browse (HTTPS)"),
        ("td-rest-api", "td-order-db", "persist order (TCP)"),
    ]
    assert len(imported["diagram_threats"]) == 1
    assert imported["diagram_threats"][0]["element_id"] == "td-rest-api"
    assert imported["diagram_threats"][0]["likelihood"] == 4


# ---------------------------------------------------------------------------
# Threat Dragon's own schema
# ---------------------------------------------------------------------------
#
# Threat Dragon compiles `threat-dragon-v2.schema.json` with ajv and validates
# every model it opens against it. A model that misses it still opens, with a
# "does not strictly match schema" warning — which is exactly the state this
# export must not ship in. Validating here is what makes "the file opens in
# Threat Dragon" a checked claim rather than a hopeful one.


@pytest.fixture(scope="module")
def td_validator():
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft7Validator(json.loads(TD_SCHEMA.read_text(encoding="utf-8")))


def _assert_td_valid(td_validator, doc: dict) -> None:
    errors = [f"{'/'.join(str(p) for p in e.path)}: {e.message}" for e in td_validator.iter_errors(doc)]
    assert errors == []


@pytest.mark.parametrize(
    "model",
    [
        pytest.param({}, id="empty"),
        pytest.param(_model(), id="tidy"),
        pytest.param(_model(components=[{"id": "a", "name": "A"}], threats=[], data_flows=[]), id="short-ids"),
        pytest.param(
            _model(components=[], data_flows=[], threats=[{"id": "T-001", "component": "Ghost", "title": "X"}]),
            id="synthesised",
        ),
        pytest.param(
            _model(threats=[{"id": "T-001", "component": "C-02", "stride": "Privacy", "title": "X"}]),
            id="foreign-category",
        ),
    ],
)
def test_output_matches_threat_dragons_own_schema(td_validator, model):
    _assert_td_valid(td_validator, etd.build_threat_dragon(model)[0])


@pytest.mark.parametrize("path", [SCHEMA_VALID_YAML, COMPOSE_YAML, GOLDEN_YAML])
def test_fixture_exports_match_threat_dragons_own_schema(td_validator, path):
    _assert_td_valid(td_validator, etd.build_threat_dragon(yaml.safe_load(path.read_text()))[0])


# ---------------------------------------------------------------------------
# Determinism and CLI
# ---------------------------------------------------------------------------


def test_golden_export_is_unchanged(tmp_path: Path):
    """One schema-valid model through the whole mapping, pinned byte for byte:
    three tiers, an `external` endpoint, CVSS, an accepted risk, evidence.
    A diff here is a mapping change — review it, then regenerate deliberately
    (see tests/fixtures/threat-dragon/README.md)."""
    out = tmp_path / "threat-model.threatdragon.json"
    result = _run(
        "--threat-model",
        str(GOLDEN_YAML),
        "--output",
        str(out),
        "--tool-version",
        GOLDEN_TOOL_VERSION,
    )

    assert result.returncode == 0, result.stderr
    assert out.read_text(encoding="utf-8") == GOLDEN_JSON.read_text(encoding="utf-8")


def test_output_is_byte_stable():
    model = _model()
    first, _ = etd.build_threat_dragon(model, tool_version="1.2.3")
    second, _ = etd.build_threat_dragon(model, tool_version="1.2.3")
    assert json.dumps(first, indent=2) == json.dumps(second, indent=2)


def _run(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_cli_writes_the_export(tmp_path: Path):
    src = tmp_path / "threat-model.yaml"
    src.write_text(yaml.safe_dump(_model()))
    out = tmp_path / "exports" / "threat-model.threatdragon.json"

    result = _run("--threat-model", str(src), "--output", str(out))

    assert result.returncode == 0, result.stderr
    assert "VALID: wrote Threat Dragon" in result.stdout
    assert "ALPHA" in result.stderr, "the alpha notice belongs on stderr, out of the artifact"
    doc = json.loads(out.read_text())
    assert doc["version"] == etd.TD_VERSION


def test_cli_reports_warnings_on_stderr(tmp_path: Path):
    src = tmp_path / "threat-model.yaml"
    src.write_text(yaml.safe_dump(_model(threats=[{"id": "T-001", "component": "Ghost", "title": "X"}])))
    out = tmp_path / "out.json"

    result = _run("--threat-model", str(src), "--output", str(out))

    assert result.returncode == 0
    assert "WARNING:" in result.stderr
    assert out.is_file(), "a warning must not suppress the export"


def test_cli_exit_codes(tmp_path: Path):
    missing = _run("--threat-model", str(tmp_path / "nope.yaml"), "--output", str(tmp_path / "o.json"))
    assert missing.returncode == 1

    broken = tmp_path / "broken.yaml"
    broken.write_text("threats: [\n")
    assert _run("--threat-model", str(broken), "--output", str(tmp_path / "o.json")).returncode == 2

    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("just a string\n")
    assert _run("--threat-model", str(scalar), "--output", str(tmp_path / "o.json")).returncode == 2


def test_cli_runs_against_the_canonical_schema_valid_fixture(tmp_path: Path):
    """The one fixture in the repo that satisfies the output schema. Tying the
    export to it means a schema change the owners make shows up here."""
    out = tmp_path / "threat-model.threatdragon.json"
    result = _run("--threat-model", str(SCHEMA_VALID_YAML), "--output", str(out))

    assert result.returncode == 0, result.stderr
    # Dropped trust boundaries are documented behaviour, not a defect. Nothing
    # else may warn on a schema-valid input.
    unexpected = [
        line for line in result.stderr.splitlines() if line.startswith("WARNING:") and "trust boundary" not in line
    ]
    assert unexpected == [], unexpected
    doc = json.loads(out.read_text())
    source = yaml.safe_load(SCHEMA_VALID_YAML.read_text())
    assert [c["id"] for c in _nodes(doc)] == [c["id"] for c in source["components"]]
    assert len(_all_threats(doc)) == len(source["threats"])
    assert _threatatlas_import(doc)["diagram_threats"], "the import must yield findings, not just elements"


def test_cli_runs_against_the_legacy_compose_fixture(tmp_path: Path):
    """The compose fixture uses the older vocabulary (`t_id`/`m_id`,
    `addresses`, `kind`, component references by name) and carries no
    data_flows — the export must still be complete."""
    out = tmp_path / "threat-model.threatdragon.json"
    result = _run("--threat-model", str(COMPOSE_YAML), "--output", str(out))

    assert result.returncode == 0, result.stderr
    doc = json.loads(out.read_text())
    source = yaml.safe_load(COMPOSE_YAML.read_text())
    assert doc["detail"]["threatTop"] == len(source["threats"])
    assert len(_all_threats(doc)) == len(source["threats"])
    assert all(t["title"].startswith("[F-") for t in _all_threats(doc))
