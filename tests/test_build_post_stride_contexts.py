from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_post_stride_contexts as contexts  # noqa: E402


def _threat(t_id: str, risk: str, file: str, line: int, component: str = "api") -> dict:
    return {
        "t_id": t_id,
        "title": f"Threat {t_id}",
        "scenario": f"An attacker reaches the sink for {t_id}.",
        "risk": risk,
        "source": "stride",
        "evidence_summary": "The cited call consumes untrusted input.",
        "evidence": {"file": file, "line": line},
        "evidence_check": "unchecked",
        "component_id": component,
        "stride": "Tampering",
        "cwe": "CWE-20",
        "evidence_tier": "confirmed-exploitable",
        "mitigation_title": f"Fix {t_id}",
        "remediation": {
            "effort": "Low",
            "steps": ["Validate the value before the sink."],
            "verification": "Submit an invalid value and expect rejection.",
            "reference": "CWE-20",
        },
    }


def _write_inputs(tmp_path: Path, threats: list[dict]) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    (repo / "app.py").write_text("\n".join(f"line {number}" for number in range(1, 31)) + "\n")
    (output / ".threats-merged.json").write_text(json.dumps({"version": 1, "threats": threats}))
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api", "tier": "application"}]})
    )
    return output, repo


def _schema_errors(name: str, value: dict) -> list:
    schema = json.loads((ROOT / "schemas" / name).read_text())
    return list(Draft202012Validator(schema).iter_errors(value))


def test_evidence_context_selects_and_embeds_exact_source_windows(tmp_path: Path) -> None:
    threats = [
        _threat("T-001", "Critical", "app.py", 10),
        _threat("T-002", "High", "app.py", 20),
        _threat("T-003", "Low", "app.py", 5),
    ]
    output, repo = _write_inputs(tmp_path, threats)

    path = contexts.write_evidence_context(output, repo, "standard", 30)
    value = json.loads(path.read_text())

    assert [sample["t_id"] for sample in value["samples"]] == ["T-001", "T-002"]
    assert [row["line"] for row in value["samples"][0]["source_window"]] == list(range(5, 16))
    assert value["limits"]["serialized_bytes"] == path.stat().st_size
    assert not _schema_errors("evidence-verifier-context.schema.json", value)
    contexts.validate_evidence_context_sources(value, (output / ".threats-merged.json").read_bytes(), repo)


def test_evidence_context_rejects_stale_source_window(tmp_path: Path) -> None:
    output, repo = _write_inputs(tmp_path, [_threat("T-001", "Critical", "app.py", 10)])
    value = contexts.build_evidence_context(
        (output / ".threats-merged.json").read_bytes(), repo, depth="quick", noncritical_cap=20
    )
    (repo / "app.py").write_text("changed\n")

    with pytest.raises(contexts.PostStrideContextError, match="stale for app.py"):
        contexts.validate_evidence_context_sources(value, (output / ".threats-merged.json").read_bytes(), repo)


def test_evidence_application_accepts_only_selected_unique_flags(tmp_path: Path) -> None:
    threats = [_threat("T-001", "Critical", "app.py", 10), _threat("T-002", "Low", "app.py", 20)]
    output, repo = _write_inputs(tmp_path, threats)
    context = contexts.build_evidence_context(
        (output / ".threats-merged.json").read_bytes(), repo, depth="quick", noncritical_cap=20
    )
    verification = {
        "version": 1,
        "generated_at": "2026-08-09T12:00:00Z",
        "model_id": "sonnet",
        "depth": "quick",
        "summary": {
            "total_threats": 2,
            "sampled": 1,
            "verified": 1,
            "refuted": 0,
            "ambiguous": 0,
            "unchecked": 0,
        },
        "flags": [
            {
                "flag_id": "EV-001",
                "t_id": "T-001",
                "verdict": "verified",
                "reason": "The cited sink is present.",
                "line_excerpt": "line 10",
            }
        ],
    }

    merged = contexts.apply_evidence_verification(
        {"version": 1, "threats": copy.deepcopy(threats)}, context, verification
    )
    assert merged["threats"][0]["evidence_check"] == "verified"
    assert merged["threats"][1]["evidence_check"] == "unchecked"
    verification["flags"][0]["t_id"] = "T-002"
    with pytest.raises(contexts.PostStrideContextError, match="unselected"):
        contexts.apply_evidence_verification({"version": 1, "threats": copy.deepcopy(threats)}, context, verification)


def test_synthesis_contexts_separate_threats_from_mitigations_and_validate(tmp_path: Path) -> None:
    output, _repo = _write_inputs(tmp_path, [_threat("T-001", "High", "app.py", 10)])

    generated_path, mitigations_path = contexts.write_synthesis_contexts(output)
    generated = json.loads(generated_path.read_text())
    mitigations = json.loads(mitigations_path.read_text())

    assert generated["threats"][0]["component_tier"] == "application"
    assert "remediation" not in generated["threats"][0]
    assert mitigations["mitigations"][0]["steps"] == ["Validate the value before the sink."]
    assert generated["limits"]["serialized_bytes"] == generated_path.stat().st_size
    assert mitigations["limits"]["serialized_bytes"] == mitigations_path.stat().st_size
    assert not _schema_errors("post-stride-generated-threats.schema.json", generated)
    assert not _schema_errors("post-stride-proposed-mitigations.schema.json", mitigations)


def test_synthesis_context_rejects_unknown_component(tmp_path: Path) -> None:
    output, _repo = _write_inputs(tmp_path, [_threat("T-001", "High", "app.py", 10, component="missing")])

    with pytest.raises(contexts.PostStrideContextError, match="unknown component"):
        contexts.write_synthesis_contexts(output)
