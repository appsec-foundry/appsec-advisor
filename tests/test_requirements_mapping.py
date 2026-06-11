"""Tests for the deterministic requirement → finding → mitigation traceability
mapping in scripts/compose_threat_model.py.

These pin the behaviour of the §7b "Requirements Traceability" table and the
compact Management-Summary variant. Finding/mitigation links come from
threat-model.yaml; PASS/N/A filtering comes from the Phase 8b compliance
fragment when present:

  * threats sharing a requirement collapse into one row, max-severity wins
  * findings link to §8 (#f-nnn), mitigations to §9 (#m-nnn)
  * the legacy singular `requirement_id` field is honoured as a fallback
  * threats with no requirement link are excluded
  * an empty row set renders nothing (no orphan table header)
  * the MS `limit` caps rows and emits an overflow pointer to §7b
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "compose"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("compose_threat_model", SCRIPT_PATH)


def _ctx(threats: list[dict], mitigations: list[dict] | None = None):
    return compose.RenderContext(
        output_dir=Path("/tmp"),
        contract={},
        yaml_data={"threats": threats, "mitigations": mitigations or []},
        triage={},
        fragments_dir=Path("/tmp"),
    )


_THREATS = [
    {
        "id": "T-001",
        "risk": "critical",
        "violated_requirements": ["SEC-AUTH-1"],
        "mitigation_ids": ["M-001", "M-002"],
    },
    {
        "id": "T-002",
        "risk": "high",
        "violated_requirements": ["SEC-AUTH-1", "SEC-SQL-1"],
        "mitigation_ids": ["M-003"],
        "remediation": {"blueprint": {"id": "BP-API", "url": "https://x/bp", "section": "API Auth"}},
    },
    # Legacy singular field, no mitigations.
    {"id": "T-003", "risk": "medium", "requirement_id": "SEC-LOG-1"},
    # No requirement link — excluded.
    {"id": "T-100", "risk": "high", "source": "stride"},
]


def test_rows_group_by_requirement_and_take_max_severity() -> None:
    rows = compose._build_requirements_mapping_rows(_ctx(_THREATS))
    assert [r["req_id"] for r in rows] == ["SEC-AUTH-1", "SEC-SQL-1", "SEC-LOG-1"]

    auth = rows[0]
    # T-001 (critical) + T-002 (high) → critical wins.
    assert auth["risk_word"] == "critical"
    assert [fid for fid, _ in auth["findings"]] == ["F-001", "F-002"]
    # Mitigations unioned across both threats, order-preserving.
    assert auth["measures"] == ["M-001", "M-002", "M-003"]
    assert "BP-API" in auth["blueprint"]


def test_legacy_requirement_id_is_honoured_and_unlinked_threats_excluded() -> None:
    rows = compose._build_requirements_mapping_rows(_ctx(_THREATS))
    req_ids = {r["req_id"] for r in rows}
    assert "SEC-LOG-1" in req_ids  # singular requirement_id picked up
    assert "T-100" not in req_ids  # stride threat without requirement excluded
    log = next(r for r in rows if r["req_id"] == "SEC-LOG-1")
    assert log["measures"] == []


def test_reverse_fulfills_requirements_adds_measure() -> None:
    # A mitigation that declares fulfills_requirements is included even though
    # no threat lists it in mitigation_ids.
    threats = [{"id": "T-001", "risk": "high", "violated_requirements": ["SEC-AUTH-1"]}]
    mitigations = [
        {"id": "M-001", "fulfills_requirements": ["SEC-AUTH-1"]},
        {"id": "M-099", "fulfills_requirements": ["SEC-OTHER-9"]},  # different req → excluded
    ]
    rows = compose._build_requirements_mapping_rows(_ctx(threats, mitigations))
    auth = next(r for r in rows if r["req_id"] == "SEC-AUTH-1")
    assert auth["measures"] == ["M-001"]


def test_mapping_is_prefix_agnostic_for_requirement_ids() -> None:
    # Requirement IDs are used verbatim (dict keys, no regex) — any org prefix
    # works, not just SEC-*. Findings/mitigations keep the system's fixed
    # F-/M- namespace.
    threats = [
        {"id": "T-001", "risk": "high", "violated_requirements": ["AC-001"], "mitigation_ids": ["M-001"]},
        {"id": "T-002", "risk": "critical", "violated_requirements": ["ISO27K-9", "SSLM-WAF"]},
        {"id": "T-003", "risk": "medium", "requirement_id": "OWASP-A01"},  # legacy singular field
    ]
    ctx = _ctx(threats)
    rows = compose._build_requirements_mapping_rows(ctx)
    assert {r["req_id"] for r in rows} == {"AC-001", "ISO27K-9", "SSLM-WAF", "OWASP-A01"}

    table = compose._render_requirements_mapping_table(ctx, rows)
    for rid in ("AC-001", "ISO27K-9", "SSLM-WAF", "OWASP-A01"):
        assert f"| `{rid}` |" in table
    assert "[F-001](#f-001)" in table and "[M-001](#m-001)" in table


def test_remediation_reference_populates_when_requirement_is_known(tmp_path: Path) -> None:
    # Field-name split fix: a STRIDE analyzer parks a matched requirement in
    # `remediation.reference` ("[ID](url)") instead of `violated_requirements`.
    # When the ID is declared in .requirements.yaml, the traceability table
    # picks it up — so §7b/§MS stop diverging from the §8 `Violated:` note.
    (tmp_path / ".requirements.yaml").write_text(
        "categories:\n- id: C1\n  requirements:\n  - id: SEC-AUTH-1\n    url: https://x/auth\n",
        encoding="utf-8",
    )
    threats = [
        {
            "id": "T-001",
            "risk": "high",
            "remediation": {"reference": "[SEC-AUTH-1](https://x/auth)"},
            "mitigation_ids": ["M-001"],
        },
        # An OWASP reference shares the bracket-link shape but is NOT a declared
        # requirement ID → must be ignored (no phantom row).
        {"id": "T-002", "risk": "low", "remediation": {"reference": "[A01:2021](https://owasp.org)"}},
    ]
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={"threats": threats, "mitigations": []},
        triage={},
        fragments_dir=tmp_path,
    )
    rows = compose._build_requirements_mapping_rows(ctx)
    assert {r["req_id"] for r in rows} == {"SEC-AUTH-1"}
    auth = rows[0]
    assert [fid for fid, _ in auth["findings"]] == ["F-001"]
    assert auth["measures"] == ["M-001"]


def test_remediation_reference_ignored_without_requirements_yaml() -> None:
    # No declared-ID set (bare tmp dir) → degrade to array-only behaviour, so a
    # reference-only threat does not enter the table. Pins the safe default.
    threats = [{"id": "T-001", "risk": "high", "remediation": {"reference": "[SEC-AUTH-1](u)"}}]
    assert compose._build_requirements_mapping_rows(_ctx(threats)) == []


def test_no_requirement_linked_threats_yields_empty() -> None:
    rows = compose._build_requirements_mapping_rows(_ctx([{"id": "T-1", "source": "stride"}]))
    assert rows == []
    assert compose._render_requirements_mapping_table(_ctx([]), rows) == ""


def test_table_has_six_columns_and_links_requirements_findings_and_mitigations() -> None:
    ctx = _ctx(_THREATS)
    table = compose._render_requirements_mapping_table(ctx, compose._build_requirements_mapping_rows(ctx))
    header = table.splitlines()[0]
    assert header.count("|") == 7  # 6 columns -> 7 pipes
    assert "Requirement" in header and "Status" in header and "Maßnahmen" in header and "Guidance" in header
    assert "| `SEC-AUTH-1` |" in table
    assert "[F-001](#f-001)" in table
    assert "[M-002](#m-002)" in table
    assert "[BP-API](https://x/bp) · API Auth" in table


def test_traceability_filters_pass_and_na_statuses_from_compliance_fragment(tmp_path: Path) -> None:
    (tmp_path / ".requirements.yaml").write_text(
        "categories:\n"
        "- id: C1\n"
        "  requirements:\n"
        "  - id: SEC-FAIL-1\n"
        "    url: https://x/fail\n"
        "  - id: SEC-PASS-1\n"
        "    url: https://x/pass\n"
        "  - id: SEC-NA-1\n"
        "    url: https://x/na\n",
        encoding="utf-8",
    )
    frag = tmp_path / ".fragments" / "requirements-compliance.md"
    frag.parent.mkdir()
    frag.write_text(
        "## 7b. Requirements Compliance\n\n"
        "| ID | Status | Evidence |\n"
        "|---|---|---|\n"
        "| SEC-FAIL-1 | **FAIL** | real finding - F-001 |\n"
        "| SEC-PASS-1 | **PASS** | positive control |\n"
        "| SEC-NA-1 | **N/A** | not applicable |\n",
        encoding="utf-8",
    )
    threats = [
        {"id": "T-001", "risk": "high", "violated_requirements": ["SEC-FAIL-1"], "mitigation_ids": ["M-001"]},
        {"id": "T-002", "risk": "high", "violated_requirements": ["SEC-PASS-1"], "mitigation_ids": ["M-002"]},
        {"id": "T-003", "risk": "medium", "violated_requirements": ["SEC-NA-1"], "mitigation_ids": ["M-003"]},
    ]
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={"threats": threats, "mitigations": []},
        triage={},
        fragments_dir=tmp_path / ".fragments",
        eval_context={"check_requirements": True},
    )
    rows = compose._build_requirements_mapping_rows(ctx)
    assert [r["req_id"] for r in rows] == ["SEC-FAIL-1"]
    assert rows[0]["status"] == "FAIL"
    table = compose._render_requirements_mapping_table(ctx, rows)
    assert "[`SEC-FAIL-1`](https://x/fail)" in table
    assert "SEC-PASS-1" not in table
    assert "SEC-NA-1" not in table


def test_traceability_prefers_compliance_row_finding_links_over_stale_yaml_requirement_ids(tmp_path: Path) -> None:
    (tmp_path / ".requirements.yaml").write_text(
        "categories:\n- id: C1\n  requirements:\n  - id: SEC-KEY-1\n    url: https://x/key\n",
        encoding="utf-8",
    )
    frag = tmp_path / ".fragments" / "requirements-compliance.md"
    frag.parent.mkdir()
    frag.write_text(
        "## 7b. Requirements Compliance\n\n"
        "| ID | Status | Evidence |\n"
        "|---|---|---|\n"
        "| SEC-KEY-1 | **FAIL** | hardcoded key - F-002 |\n",
        encoding="utf-8",
    )
    threats = [
        # Stale semantic requirement edge: this should be ignored because the
        # compliance row names F-002 as the actual evidence.
        {"id": "T-001", "risk": "critical", "violated_requirements": ["SEC-KEY-1"], "mitigation_ids": ["M-001"]},
        {"id": "T-002", "risk": "high", "mitigation_ids": ["M-002"]},
    ]
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={"threats": threats, "mitigations": []},
        triage={},
        fragments_dir=tmp_path / ".fragments",
        eval_context={"check_requirements": True},
    )
    rows = compose._build_requirements_mapping_rows(ctx)
    assert len(rows) == 1
    assert [fid for fid, _ in rows[0]["findings"]] == ["F-002"]
    assert rows[0]["measures"] == ["M-002"]


def test_ms_limit_caps_rows_and_emits_overflow_pointer() -> None:
    ctx = _ctx(_THREATS)
    rows = compose._build_requirements_mapping_rows(ctx)  # 3 rows
    table = compose._render_requirements_mapping_table(ctx, rows, limit=2)
    assert table.count("\n| `") == 2  # only 2 data rows rendered
    assert "1 further requirement(s)" in table
    assert "#7b-requirements-compliance" in table


# --- Wiring: §7b hybrid renderer + Management-Summary subsection -------------
# Exercises the dispatcher-wired renderers directly against the compose fixture
# (a full render() is avoided here: it trips an unrelated §7 fixture/contract
# subsection-count drift that has nothing to do with requirements).


def _fixture_ctx_with_requirements(tmp_path: Path):
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)

    data = yaml.safe_load((out / "threat-model.yaml").read_text())
    data.setdefault("meta", {})["check_requirements"] = True
    threats = data["threats"]
    threats[0]["violated_requirements"] = ["SEC-AUTH-1"]
    threats[0].setdefault("mitigation_ids", threats[0].get("mitigation_ids") or ["M-001"])
    threats[1]["violated_requirements"] = ["SEC-AUTH-1", "SEC-SQL-1"]
    threats[1]["remediation"] = {"blueprint": {"id": "BP-API", "url": "https://x/bp", "section": "API Auth"}}

    frag = out / ".fragments" / "requirements-compliance.md"
    frag.parent.mkdir(parents=True, exist_ok=True)
    frag.write_text(
        "## 7b. Requirements Compliance\n\n"
        "Compliance from the [OWASP ASVS](https://owasp.org/asvs) baseline.\n\n"
        "**Summary:** 3 requirements assessed — 1 PASS · 2 FAIL · 0 ANTI-PATTERN · 0 PARTIAL · 0 N/A · 0 NOT OBSERVABLE · 0 UNVERIFIABLE\n"
    )
    contract = yaml.safe_load(CONTRACT.read_text())
    ctx = compose.RenderContext(
        output_dir=out,
        contract=contract,
        yaml_data=data,
        triage={},
        fragments_dir=out / ".fragments",
        eval_context={"check_requirements": True},
    )
    return ctx, contract["sections"]["requirements_compliance"]


def test_7b_hybrid_inlines_fragment_and_appends_traceability(tmp_path: Path) -> None:
    ctx, section = _fixture_ctx_with_requirements(tmp_path)
    body = compose._render_requirements_compliance(ctx, None, section)
    assert "OWASP ASVS" in body  # LLM narrative preserved
    assert "### Requirement Scope" in body  # deterministic scope guardrail
    assert "### Requirements Traceability" in body  # deterministic table appended
    assert "| Requirement | Status | Risk | Findings | Maßnahmen | Guidance |" in body
    assert "[F-001](#f-001)" in body and "[M-001](#m-001)" in body
    assert "[BP-API](https://x/bp) · API Auth" in body


def test_ms_subsection_carries_summary_and_links(tmp_path: Path) -> None:
    ctx, _section = _fixture_ctx_with_requirements(tmp_path)
    ms = compose._render_requirements_compliance_ms(ctx)
    assert ms.startswith("### Requirements Compliance")
    assert "OWASP ASVS" in ms  # baseline from fragment
    assert "3 requirements assessed" in ms  # summary counts preserved
    assert "**Failed or partial requirements → findings & mitigations:**" in ms
    assert "[F-001](#f-001)" in ms  # G2 fix: links now present
    assert "#7b-requirements-compliance" in ms


def _prepare_req_output_dir(tmp_path: Path) -> Path:
    """Copy the fixture to a temp output dir and patch it on disk for a full
    compose.render (check_requirements on, threats requirement-linked, fragment
    present). Runs under the suite-wide APPSEC_SCHEMA_V1 pin (see conftest)."""
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    data = yaml.safe_load((out / "threat-model.yaml").read_text())
    data.setdefault("meta", {})["check_requirements"] = True
    data["threats"][0]["violated_requirements"] = ["SEC-AUTH-1"]
    data["threats"][0].setdefault("mitigation_ids", data["threats"][0].get("mitigation_ids") or ["M-001"])
    (out / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
    frag = out / ".fragments" / "requirements-compliance.md"
    frag.parent.mkdir(parents=True, exist_ok=True)
    frag.write_text(
        "## 7b. Requirements Compliance\n\n"
        "Compliance from the [OWASP ASVS](https://owasp.org/asvs) baseline.\n\n"
        "**Summary:** 1 requirements assessed — 1 PASS · 0 FAIL · 0 ANTI-PATTERN · 0 PARTIAL · 0 N/A · 0 NOT OBSERVABLE · 0 UNVERIFIABLE\n"
    )
    return out


# --- §10 Mitigation Register: Fulfills Requirements + Blueprint guidance -----
# These lines are demanded by the QA reviewer and specified in the §10 block
# template, but the renderer previously emitted neither (mitigations[] carries
# no such field). Both are now derived deterministically from the addressed
# threats — only when check_requirements is on.


def test_mitigation_register_renders_fulfills_and_blueprint(tmp_path: Path) -> None:
    (tmp_path / ".requirements.yaml").write_text(
        "categories:\n- id: C1\n  requirements:\n  - id: SEC-AUTH-1\n    url: https://x/auth\n",
        encoding="utf-8",
    )
    threats = [
        {
            "id": "T-001",
            "risk": "critical",
            "title": "Auth bypass",
            "violated_requirements": ["SEC-AUTH-1"],
            "mitigation_ids": ["M-001"],
            "remediation": {"blueprint": {"id": "BP-API", "url": "https://x/bp", "section": "API Auth"}},
        },
    ]
    mitigations = [
        {"id": "M-001", "title": "Add auth", "threat_ids": ["T-001"], "priority": "P1", "severity": "Critical"},
    ]
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={"threats": threats, "mitigations": mitigations},
        triage={},
        fragments_dir=tmp_path,
        eval_context={"check_requirements": True},
    )
    out = compose._render_mitigation_register(ctx, None, {"heading": "## 10. Mitigation Register"})
    assert "**Fulfills Requirements:**" in out
    assert "[SEC-AUTH-1](https://x/auth)" in out  # linked via declared URL
    assert "**Blueprint guidance:**" in out
    assert "BP-API" in out


def test_mitigation_register_requirement_reference_renders_as_fulfills_not_reference(tmp_path: Path) -> None:
    # A requirement parked in remediation.reference must surface under Fulfills
    # Requirements — NOT be harvested into a cheatsheet `**Reference:**` line.
    (tmp_path / ".requirements.yaml").write_text(
        "categories:\n- id: C1\n  requirements:\n  - id: SEC-AUTH-1\n    url: https://x/auth\n",
        encoding="utf-8",
    )
    threats = [
        {
            "id": "T-001",
            "risk": "high",
            "title": "Auth gap",
            "mitigation_ids": ["M-001"],
            "remediation": {"reference": "[SEC-AUTH-1](https://x/auth)"},
        },
    ]
    mitigations = [{"id": "M-001", "title": "Fix auth", "threat_ids": ["T-001"], "priority": "P2", "severity": "High"}]
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={"threats": threats, "mitigations": mitigations},
        triage={},
        fragments_dir=tmp_path,
        eval_context={"check_requirements": True},
    )
    out = compose._render_mitigation_register(ctx, None, {"heading": "## 10. Mitigation Register"})
    assert "**Fulfills Requirements:**" in out
    assert "[SEC-AUTH-1](https://x/auth)" in out
    assert "**Reference:** [SEC-AUTH-1]" not in out


def test_mitigation_register_filters_pass_requirements(tmp_path: Path) -> None:
    (tmp_path / ".requirements.yaml").write_text(
        "categories:\n- id: C1\n  requirements:\n  - id: SEC-PASS-1\n    url: https://x/pass\n",
        encoding="utf-8",
    )
    frag = tmp_path / ".fragments" / "requirements-compliance.md"
    frag.parent.mkdir()
    frag.write_text(
        "## 7b. Requirements Compliance\n\n| ID | Status | Evidence |\n|---|---|---|\n| SEC-PASS-1 | **PASS** | ok |\n",
        encoding="utf-8",
    )
    threats = [
        {
            "id": "T-001",
            "risk": "high",
            "title": "stale requirement ref",
            "violated_requirements": ["SEC-PASS-1"],
            "mitigation_ids": ["M-001"],
        },
    ]
    mitigations = [{"id": "M-001", "title": "No-op", "threat_ids": ["T-001"], "priority": "P2", "severity": "High"}]
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={"threats": threats, "mitigations": mitigations},
        triage={},
        fragments_dir=tmp_path / ".fragments",
        eval_context={"check_requirements": True},
    )
    out = compose._render_mitigation_register(ctx, None, {"heading": "## 10. Mitigation Register"})
    assert "**Fulfills Requirements:**" not in out
    assert "SEC-PASS-1" not in out


def test_mitigation_register_omits_requirement_lines_when_disabled(tmp_path: Path) -> None:
    threats = [
        {
            "id": "T-001",
            "risk": "high",
            "title": "x",
            "violated_requirements": ["SEC-AUTH-1"],
            "mitigation_ids": ["M-001"],
        },
    ]
    mitigations = [{"id": "M-001", "title": "y", "threat_ids": ["T-001"], "priority": "P2", "severity": "High"}]
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={"threats": threats, "mitigations": mitigations},
        triage={},
        fragments_dir=tmp_path,
        eval_context={},  # check_requirements falsy → both lines suppressed
    )
    out = compose._render_mitigation_register(ctx, None, {"heading": "## 10. Mitigation Register"})
    assert "**Fulfills Requirements:**" not in out
    assert "**Blueprint guidance:**" not in out


def test_full_render_emits_traceability_in_7b_and_ms(tmp_path: Path) -> None:
    out = _prepare_req_output_dir(tmp_path)
    rendered, _warnings = compose.render(CONTRACT, out)
    # §7b: LLM narrative + deterministic table, end-to-end through the dispatcher.
    assert "## 7b. Requirements Compliance" in rendered
    assert "### Requirements Traceability" in rendered
    assert "| Requirement | Status | Risk | Findings | Maßnahmen | Guidance |" in rendered
    assert "[F-001](#f-001)" in rendered
    # MS subsection rendered via the document.order conditional.
    assert "### Requirements Compliance" in rendered
    assert "**Failed or partial requirements → findings & mitigations:**" in rendered
