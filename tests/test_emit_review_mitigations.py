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
    assert "M-012" not in by_id
    threats = {t["id"]: t for t in data["threats"]}
    assert threats["T-001"]["mitigation_ids"] == ["M-011"]
    assert "mitigation_ids" not in threats["T-002"]


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


# ---------------------------------------------------------------------------
# Helper-level edge branches
# ---------------------------------------------------------------------------


def test_scan_max_m_id_skips_non_dict() -> None:
    """Line 80: a non-dict entry in mitigations[] is skipped."""
    data = {"mitigations": ["not-a-dict", {"id": "M-007"}, {"id": "not-an-m-id"}]}
    assert erm._scan_max_m_id(data) == 7


def test_evidence_file_dict_form() -> None:
    """Lines 93-94: evidence as a single dict (not a list)."""
    f, ln = erm._evidence_file({"evidence": {"file": "a/b.ts", "line": 5}})
    assert f == "a/b.ts"
    assert ln == 5


def test_evidence_file_line_not_int() -> None:
    f, ln = erm._evidence_file({"evidence": [{"file": "a.ts", "line": "x"}]})
    assert f == "a.ts"
    assert ln is None


def test_short_weakness_empty_title() -> None:
    """Line 105: empty title returns the default phrase."""
    assert erm._short_weakness("") == "the finding"
    assert erm._short_weakness("   ") == "the finding"


def test_short_weakness_only_suffix_returns_default() -> None:
    assert erm._short_weakness("(routes/x.ts:1)") == "the finding"


def test_clear_prior_auto_mitigations_non_list() -> None:
    """Line 117: mitigations is not a list → no-op, no crash."""
    data = {"mitigations": "oops"}
    erm._clear_prior_auto_mitigations(data)
    assert data["mitigations"] == "oops"


def test_clear_prior_auto_mitigations_skips_non_dict_threat() -> None:
    """Line 125: non-dict threat in the unlink loop is skipped."""
    data = {
        "mitigations": [{"id": "M-001", "auto_emitted": True}],
        "threats": ["not-a-dict", {"id": "T-1", "mitigation_ids": ["M-001", "M-002"]}],
    }
    erm._clear_prior_auto_mitigations(data)
    assert data["mitigations"] == []
    assert data["threats"][1]["mitigation_ids"] == ["M-002"]


def test_link_threat_to_mitigation_missing_threat() -> None:
    """Line 149: tid absent from threats_by_id → no-op."""
    erm._link_threat_to_mitigation({}, "T-404", "M-001")  # must not raise


def test_arch_theme_key_fallback_cwe_component() -> None:
    """Lines 236-238: no theme/rule_id → (cwe@component) key."""
    assert erm._arch_theme_key({"cwe": "CWE-862", "component": "API"}) == "CWE-862@API"
    assert erm._arch_theme_key({}) == "UNKNOWN-CWE@any"
    assert erm._arch_theme_key({"component_id": "Worker"}) == "UNKNOWN-CWE@Worker"


def test_extract_route_no_slash_fallback() -> None:
    """Line 358: evidence file without a slash → /<endpoint>."""
    assert erm._extract_route_for_threat({"evidence": [{"file": "noslash"}]}) == "/<endpoint>"
    assert erm._extract_route_for_threat({"evidence": [{"file": "routes/login.ts"}]}) == "/login"


def test_extract_method_default_post() -> None:
    """Line 367: no HTTP verb in title/scenario → POST default."""
    assert erm._extract_method_for_threat({"title": "no verb here"}) == "POST"
    assert erm._extract_method_for_threat({"title": "DELETE the user"}) == "DELETE"


# ---------------------------------------------------------------------------
# Synthesis-loop skip branches (non-dict / empty entries)
# ---------------------------------------------------------------------------


def test_evidence_review_skips_non_dict_and_idless_threats(tmp_path: Path) -> None:
    """Lines 168, 174: non-dict threats and threats without ids are skipped."""
    _write_yaml(
        tmp_path,
        {
            "threats": [
                "not-a-dict",
                {"evidence_check": "ambiguous"},  # no id → skipped (line 174)
                _threat("T-100", evidence_check="ambiguous"),
            ]
        },
    )
    assert erm.main([str(tmp_path)]) == 0
    data = _read_yaml(tmp_path)
    auto = [m for m in (data.get("mitigations") or []) if m.get("auto_emitted")]
    assert len(auto) == 1
    assert auto[0]["threat_ids"] == ["T-100"]


def test_arch_skips_non_dict_and_threats_with_existing_mitigation(tmp_path: Path) -> None:
    """Lines 247, 255: non-dict arch threats and threats already carrying an
    LLM-authored `mitigations` value are excluded from clustering."""
    _write_yaml(
        tmp_path,
        {
            "threats": [
                "not-a-dict",
                _threat(
                    "T-200",
                    source="architecture-coverage",
                    cwe="CWE-862",
                    architectural_theme="auth",
                    mitigations=["already authored"],  # line 255 skip
                ),
                _threat(
                    "T-201",
                    source="architecture-coverage",
                    cwe="CWE-862",
                    architectural_theme="auth",
                ),
            ]
        },
    )
    assert erm.main([str(tmp_path)]) == 0
    data = _read_yaml(tmp_path)
    auto = [m for m in (data.get("mitigations") or []) if m.get("auto_source") == "architectural-theme-cluster"]
    assert len(auto) == 1
    assert auto[0]["threat_ids"] == ["T-201"]


def test_poc_skips_non_dict_and_non_injection_cwe(tmp_path: Path) -> None:
    """Lines 330, 336: non-dict threats and non-injection CWEs get no poc_hint."""
    _write_yaml(
        tmp_path,
        {
            "threats": [
                "not-a-dict",
                _threat(
                    "T-300",
                    affected_parameter="x",
                    cwe="CWE-200",  # not in injection allowlist → line 336
                    file="routes/info.ts",
                ),
            ]
        },
    )
    assert erm.main([str(tmp_path)]) == 0
    data = _read_yaml(tmp_path)
    assert "poc_hint" not in data["threats"][1]


# ---------------------------------------------------------------------------
# main() error paths
# ---------------------------------------------------------------------------


def test_malformed_yaml_returns_error(tmp_path: Path, capsys) -> None:
    """Lines 386-391: unparseable YAML → exit 1."""
    (tmp_path / "threat-model.yaml").write_text("key: [unterminated\n", encoding="utf-8")
    assert erm.main([str(tmp_path)]) == 1
    assert "could not parse" in capsys.readouterr().err


def test_yaml_not_a_mapping_returns_error(tmp_path: Path, capsys) -> None:
    """Lines 393-394: YAML that parses to a list → exit 1."""
    (tmp_path / "threat-model.yaml").write_text("- a\n- b\n", encoding="utf-8")
    assert erm.main([str(tmp_path)]) == 1
    assert "did not parse to a mapping" in capsys.readouterr().err


def test_existing_mitigations_not_a_list_is_reset(tmp_path: Path) -> None:
    """Line 413: when mitigations isn't a list, new cards still append onto []."""
    _write_yaml(
        tmp_path,
        {
            "mitigations": "not-a-list",
            "threats": [_threat("T-400", evidence_check="ambiguous")],
        },
    )
    assert erm.main([str(tmp_path)]) == 0
    data = _read_yaml(tmp_path)
    assert isinstance(data["mitigations"], list)
    assert any(m.get("auto_emitted") for m in data["mitigations"])
