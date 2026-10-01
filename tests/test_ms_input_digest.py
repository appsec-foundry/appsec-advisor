"""The Management-Summary input digest agrees with the rules its fragments are gated on.

Every assertion compares the digest to the shared rule it delegates to
(``renderers._severity_rollup``), not to numbers from one run, so the shapes
below hold for any model.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import renderers._severity_rollup as rollup
import renderers.ms_input_digest as digest
import yaml


def _threat(n: int, risk: str, **extra) -> dict:
    row = {
        "id": f"T-{n:03d}",
        "title": f"Finding {n} title",
        "risk": risk,
        "stride": "Tampering",
        "cwe": "CWE-89",
        "component": "api",
        "component_name": "API",
        "impact_description": "An attacker reads every customer record.",
        "mitigation_ids": [f"M-{n:03d}"],
    }
    row.update(extra)
    return row


def _model(threats: list[dict], **extra) -> dict:
    model = {
        "components": [
            {"id": "web", "name": "Web Client", "tier": "client"},
            {"id": "api", "name": "API", "tier": "application", "framework": "Express"},
        ],
        "threats": threats,
        "mitigations": [
            {"id": t["mitigation_ids"][0], "title": "Fix it", "priority": "P1", "threat_ids": [t["id"]]}
            for t in threats
            if t.get("risk") == "Critical"
        ],
    }
    model.update(extra)
    return model


def _triage(ids: list[str]) -> dict:
    return {"ranking": {"views": {"top_findings": {"findings_ranked": [{"id": i} for i in ids]}}}}


def _built(model: dict, triage: dict | None = None) -> dict:
    result = digest.fit_budget(digest.build_digest(model, triage))
    assert digest.validate(result) == []
    return result


@pytest.mark.parametrize(
    "threats",
    [
        [_threat(1, "Critical"), _threat(2, "High"), _threat(3, "Medium")],
        [_threat(1, "High"), _threat(2, "Medium")],
        [_threat(1, "Medium")],
        [_threat(1, "Critical", effective_severity="High"), _threat(2, "High", effective_severity="Critical")],
    ],
    ids=["mixed", "no-critical", "medium-only", "priority-elevation"],
)
def test_verdict_fields_follow_the_shared_rule(threats: list[dict]) -> None:
    model = _model(threats)
    triage = _triage([t["id"] for t in reversed(threats)])
    result = _built(model, triage)

    assert result["verdict"]["severity"] == rollup.verdict_severity(model)
    assert result["verdict"]["floor_refs"] == rollup.verdict_floor_ids(model, rollup.verdict_ranked_ids(triage))
    detailed = {row["ref"] for row in result["findings"]}
    expected = {rollup.display_id(t["id"]) for t in threats if rollup.priority_severity(t) in ("Critical", "High")}
    assert detailed == expected
    assert set(result["verdict"]["floor_refs"]) <= detailed


def test_refuted_findings_never_reach_the_digest() -> None:
    result = _built(_model([_threat(1, "Critical", evidence_check="refuted"), _threat(2, "High")]))
    refs = {row["ref"] for row in result["findings"] + result["other_findings"]}
    assert refs == {"F-002"}


def test_llm_surface_comes_from_the_finding_not_its_component() -> None:
    model = _model(
        [
            _threat(1, "High", owasp_llm_ids=["LLM01"]),
            _threat(2, "High", title="Prompt injection into the support chatbot"),
            _threat(3, "High"),
        ]
    )
    model["components"][1]["capabilities"] = [{"capability": "llm-calls", "evidence": "src/chat.js:3"}]
    result = _built(model)

    flagged = {row["ref"] for row in result["findings"] if row.get("llm_surface")}
    assert flagged == {"F-001", "F-002"}
    assert [c["llm_surface"] for c in result["components"]] == [False, True]


def test_no_ai_surface_and_no_mitigations_leave_those_parts_empty() -> None:
    model = _model([_threat(1, "High")])
    model["mitigations"] = []
    result = _built(model)
    assert result["p1_mitigations"] == []
    assert not any(row.get("llm_surface") for row in result["findings"])


def test_an_oversized_model_is_cut_from_the_least_severe_end_but_keeps_the_floor() -> None:
    long = "x" * 400
    threats = [_threat(n, "Critical", title=long) for n in range(1, 11)]
    threats += [_threat(n, "High", title=long) for n in range(11, 300)]
    threats += [_threat(n, "Medium", title=long) for n in range(300, 600)]
    model = _model(threats)
    result = _built(model)

    assert digest._size(result) <= digest.MAX_BYTES
    assert result["omitted"]["other_findings"] == 300
    assert result["omitted"]["findings"] > 0
    kept = {row["ref"] for row in result["findings"]}
    assert set(result["verdict"]["floor_refs"]) <= kept


def test_the_digest_is_deterministic() -> None:
    model = _model([_threat(2, "High"), _threat(1, "Critical")])
    assert digest._dumps(_built(model)) == digest._dumps(_built(model))


def test_write_digest_replaces_a_stale_one_and_removes_it_without_a_model(tmp_path: Path) -> None:
    path = tmp_path / digest.DIGEST_RELPATH
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(_model([_threat(1, "Critical")])), encoding="utf-8")

    assert digest.write_digest(tmp_path) == path
    assert json.loads(path.read_text(encoding="utf-8"))["verdict"]["floor_refs"] == ["F-001"]

    (tmp_path / "threat-model.yaml").unlink()
    assert digest.write_digest(tmp_path) is None
    assert not path.exists(), "a digest of an earlier model must not outlive it"
