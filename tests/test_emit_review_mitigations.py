from __future__ import annotations

from pathlib import Path

import emit_review_mitigations as erm
import yaml


def _write_yaml(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def _threat(
    tid: str,
    *,
    title: str = "SQL injection (routes/search.ts:12)",
    cwe: str = "CWE-89",
    file: str = "routes/search.ts",
    line: int = 12,
    source: str = "stride",
    **extra,
) -> dict:
    threat = {
        "id": tid,
        "title": title,
        "cwe": cwe,
        "source": source,
        "component": "API",
        "evidence": [{"file": file, "line": line}],
    }
    threat.update(extra)
    return threat


def test_evidence_verifier_results_emit_review_cards_and_canonical_links(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "mitigations": [{"id": "M-010", "title": "Existing fix", "threat_ids": ["T-999"], "priority": "P2"}],
            "threats": [
                _threat("T-001", title="SQL injection (routes/search.ts:12)", evidence_check="ambiguous"),
                _threat(
                    "T-002",
                    title="Open redirect — routes/redirect.ts:18",
                    cwe="CWE-601",
                    file="routes/redirect.ts",
                    line=18,
                    evidence_check="refuted",
                ),
            ],
        },
    )

    assert erm.main([str(tmp_path)]) == 0

    data = _read_yaml(tmp_path)
    by_id = {m["id"]: m for m in data["mitigations"]}
    assert by_id["M-011"]["kind"] == "review"
    assert by_id["M-011"]["priority"] == "P3"
    assert by_id["M-011"]["auto_source"] == "evidence-check-ambiguous"
    assert by_id["M-011"]["threat_ids"] == ["T-001"]
    assert by_id["M-012"]["title"] == "Confirm fix coverage at routes/redirect.ts:18"
    assert by_id["M-012"]["auto_source"] == "evidence-check-refuted"
    threats = {t["id"]: t for t in data["threats"]}
    assert threats["T-001"]["mitigation_ids"] == ["M-011"]
    assert threats["T-002"]["mitigation_ids"] == ["M-012"]


def test_architectural_findings_cluster_by_theme_across_arch_sources(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "threats": [
                _threat(
                    "T-010",
                    title="Missing authorization boundary (architecture)",
                    source="architecture-coverage",
                    cwe="CWE-862",
                    architectural_theme="auth-boundary",
                ),
                _threat(
                    "T-011",
                    title="Missing authorization boundary (worker)",
                    source="threat-hypothesis",
                    cwe="CWE-862",
                    architectural_theme="auth-boundary",
                ),
            ],
        },
    )

    assert erm.main([str(tmp_path)]) == 0

    data = _read_yaml(tmp_path)
    auto_cards = [m for m in data["mitigations"] if m.get("auto_source") == "architectural-theme-cluster"]
    assert len(auto_cards) == 1
    card = auto_cards[0]
    assert card["kind"] == "investigate"
    assert card["priority"] == "P2"
    assert card["threat_ids"] == ["T-010", "T-011"]
    threats = {t["id"]: t for t in data["threats"]}
    assert threats["T-010"]["mitigation_ids"] == [card["id"]]
    assert threats["T-011"]["mitigation_ids"] == [card["id"]]


def test_poc_hint_added_for_injection_parameter_without_inflating_mitigations(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "mitigations": [],
            "threats": [
                _threat(
                    "T-020",
                    title="GET search SQL injection (routes/search.ts:12)",
                    scenario="GET route concatenates query into SQL",
                    affected_parameter="query",
                    cwe="CWE-89",
                    file="routes/search.ts",
                ),
                _threat(
                    "T-021",
                    title="Existing PoC is preserved",
                    affected_parameter="next",
                    cwe="CWE-601",
                    file="routes/redirect.ts",
                    poc_hint="manual payload",
                ),
            ],
        },
    )

    assert erm.main([str(tmp_path)]) == 0

    data = _read_yaml(tmp_path)
    threats = {t["id"]: t for t in data["threats"]}
    assert threats["T-020"]["poc_hint"].startswith("GET /search with {query:")
    assert "SQL injection" in threats["T-020"]["poc_hint"]
    assert threats["T-021"]["poc_hint"] == "manual payload"
    assert data["mitigations"] == []


def test_rerun_clears_prior_auto_cards_and_stale_threat_links(tmp_path: Path) -> None:
    _write_yaml(
        tmp_path,
        {
            "mitigations": [
                {"id": "M-005", "title": "Manual fix", "threat_ids": ["T-001"], "priority": "P2"},
                {
                    "id": "M-006",
                    "title": "Old auto review",
                    "threat_ids": ["T-001"],
                    "priority": "P3",
                    "auto_emitted": True,
                    "auto_source": "evidence-check-ambiguous",
                },
            ],
            "threats": [
                _threat(
                    "T-001",
                    evidence_check="verified",
                    mitigation_ids=["M-005", "M-006"],
                    mitigations=["M-006"],
                )
            ],
        },
    )

    assert erm.main([str(tmp_path)]) == 0

    data = _read_yaml(tmp_path)
    assert [m["id"] for m in data["mitigations"]] == ["M-005"]
    assert data["threats"][0]["mitigation_ids"] == ["M-005"]
    assert data["threats"][0]["mitigations"] == []


def test_missing_yaml_returns_error(tmp_path: Path, capsys) -> None:
    assert erm.main([str(tmp_path)]) == 1

    assert "no yaml" in capsys.readouterr().err


def test_usage_error() -> None:
    assert erm.main([]) == 2
