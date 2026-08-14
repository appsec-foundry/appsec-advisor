from __future__ import annotations

from _threat_model_fields import evidence_file_of, extract_threats, is_active, severity_of


def test_current_output_fields_take_precedence_over_legacy_aliases() -> None:
    threat = {
        "effective_severity": "High",
        "risk": "Medium",
        "severity": "Low",
        "_status": "active",
        "status": "mitigated",
        "evidence": [{"file": "src/current.py", "line": 4}],
        "evidence_file": "src/legacy.py",
    }

    assert severity_of(threat) == "High"
    assert is_active(threat) is True
    assert evidence_file_of(threat) == "src/current.py"


def test_absent_status_is_active_but_dormant_is_not() -> None:
    assert is_active({"risk": "High"}) is True
    assert is_active({"risk": "High", "_status": "dormant"}) is False


def test_extract_threats_supports_flat_and_legacy_category_shapes() -> None:
    assert extract_threats({"threats": [{"id": "T-001"}, "bad"]}) == [{"id": "T-001"}]
    assert extract_threats({"threat_categories": [{"findings": [{"id": "T-002"}]}]}) == [{"id": "T-002"}]
