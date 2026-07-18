"""Tests for deterministic promotion of confirmed abuse-case source probes."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "promote_verified_abuse_cases.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("promote_verified_abuse_cases", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["promote_verified_abuse_cases"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


mod = _load_module()


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _sidecars(tmp_path: Path, *, with_metadata: bool = True, verdict: str = "confirmed") -> None:
    finding = {
        "title": "Untrusted template input reaches dynamic evaluation",
        "cwe": "CWE-94",
        "stride": "Elevation of Privilege",
        "severity": "High",
        "mitigation_title": "Remove dynamic template evaluation",
        "remediation": "Use fixed templates and data-only rendering.",
    }
    step = {
        "step": 1,
        "label": "Template evaluation reaches executable code",
        "grants": "code_execution",
        "description": "Attacker input reaches an evaluation sink.",
        "probe": {"sink_patterns": ["eval\\("]},
    }
    if with_metadata:
        step["finding"] = finding
    _write(
        tmp_path / ".threats-merged.json",
        {
            "version": 1,
            "generated_at": "2026-07-14T00:00:00Z",
            "threats": [{"t_id": "T-001", "title": "Existing finding"}],
        },
    )
    _write(
        tmp_path / ".abuse-case-matches.json",
        {
            "schema_version": 1,
            "matches": [
                {
                    "abuse_case_id": "REPO-AC-001",
                    "case": {"id": "REPO-AC-001", "chain": [step]},
                    "step_matches": [
                        {
                            "step": 1,
                            "match_basis": "source_probe",
                            "matched_finding_id": None,
                            "evidence": {"file": "src/template.ts", "line": 17, "excerpt": "eval(input)"},
                        }
                    ],
                    "matched_finding_ids": [],
                }
            ],
        },
    )
    _write(
        tmp_path / ".abuse-case-verdicts.json",
        {
            "schema_version": 1,
            "verdicts": [
                {
                    "abuse_case_id": "REPO-AC-001",
                    "chain_verdict": "fully_viable",
                    "step_verdicts": [
                        {
                            "step": 1,
                            "verdict": verdict,
                            "matched_finding_id": None,
                            "evidence": {"file": "src/template.ts", "line": 17},
                        }
                    ],
                }
            ],
        },
    )


def test_confirmed_source_probe_becomes_normal_bound_finding(tmp_path: Path) -> None:
    _sidecars(tmp_path)

    count, notes = mod.promote(tmp_path)

    assert count == 1
    assert "promoted 1" in notes[0]
    merged = json.loads((tmp_path / ".threats-merged.json").read_text())
    created = merged["threats"][-1]
    assert created["t_id"] == "T-002"
    assert created["source"] == "source-scan"
    assert created["evidence_check"] == "verified"
    assert created["abuse_case_id"] == "REPO-AC-001"
    assert created["abuse_case_step"] == 1
    assert created["mitigation_title"] == "Remove dynamic template evaluation"
    assert created["remediation"]["how"] == "Use fixed templates and data-only rendering."

    # The promoted record must be acceptable to the same merged-threat contract
    # that Stage 11 consumes, then produce a normal YAML finding and mitigation.
    merged_schema = yaml.safe_load((ROOT / "schemas" / "threats-merged.schema.yaml").read_text())
    jsonschema.Draft202012Validator(merged_schema).validate(
        {"version": 1, "generated_at": "2026-07-14T00:00:00Z", "threats": [created]}
    )
    sys.path.insert(0, str(ROOT / "scripts"))
    import build_threat_model_yaml as builder  # type: ignore[import-not-found]

    yaml_threats, warnings = builder.build_threats({"threats": [created]})
    assert not warnings
    assert yaml_threats[0]["id"] == "T-002"
    assert yaml_threats[0]["evidence"] == [{"file": "src/template.ts", "line": 17}]
    mitigations = builder.build_mitigations(yaml_threats)
    assert mitigations[0]["threat_ids"] == ["T-002"]
    assert yaml_threats[0]["mitigation_ids"] == [mitigations[0]["id"]]

    matches = json.loads((tmp_path / ".abuse-case-matches.json").read_text())
    assert matches["matches"][0]["matched_finding_ids"] == ["T-002"]
    assert matches["matches"][0]["step_matches"][0]["match_basis"] == "promoted_source_probe"
    verdicts = json.loads((tmp_path / ".abuse-case-verdicts.json").read_text())
    assert verdicts["verdicts"][0]["step_verdicts"][0]["matched_finding_id"] == "T-002"


def test_promotion_is_idempotent_when_next_scan_rediscovers_same_source_probe(tmp_path: Path) -> None:
    _sidecars(tmp_path)
    assert mod.promote(tmp_path)[0] == 1
    matches_path = tmp_path / ".abuse-case-matches.json"
    matches = json.loads(matches_path.read_text())
    step = matches["matches"][0]["step_matches"][0]
    step["match_basis"] = "source_probe"
    step["matched_finding_id"] = None
    matches["matches"][0]["matched_finding_ids"] = []
    _write(matches_path, matches)

    count, _ = mod.promote(tmp_path)

    assert count == 0
    merged = json.loads((tmp_path / ".threats-merged.json").read_text())
    assert len(merged["threats"]) == 2
    rebound = json.loads(matches_path.read_text())["matches"][0]["step_matches"][0]
    assert rebound["matched_finding_id"] == "T-002"


def test_unconfirmed_or_unclassified_probe_is_never_promoted(tmp_path: Path) -> None:
    _sidecars(tmp_path, verdict="blocked")
    assert mod.promote(tmp_path)[0] == 0
    assert len(json.loads((tmp_path / ".threats-merged.json").read_text())["threats"]) == 1

    _sidecars(tmp_path, with_metadata=False, verdict="confirmed")
    count, notes = mod.promote(tmp_path)
    assert count == 0
    assert "missing finding metadata" in notes[-1]
    assert len(json.loads((tmp_path / ".threats-merged.json").read_text())["threats"]) == 1


def test_source_probe_evidence_wins_when_verifier_omits_a_file(tmp_path: Path) -> None:
    _sidecars(tmp_path)
    verdicts_path = tmp_path / ".abuse-case-verdicts.json"
    verdicts = json.loads(verdicts_path.read_text())
    verdicts["verdicts"][0]["step_verdicts"][0]["evidence"] = {"excerpt": "confirmed by control-flow trace"}
    _write(verdicts_path, verdicts)

    assert mod.promote(tmp_path)[0] == 1
    created = json.loads((tmp_path / ".threats-merged.json").read_text())["threats"][-1]
    assert created["evidence"] == {"file": "src/template.ts", "line": 17}
