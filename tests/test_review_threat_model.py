"""Tests for scripts/review_threat_model.py — the deterministic half of the
``/appsec-advisor:review-threat-model`` consumer skill.

Covers:
  * reconcile joins model + sidecar by finding key, ranks by severity.
  * new findings surface as ``untriaged``; sidecar entries with no matching
    finding surface as ``stale`` (never dropped, never a hard error).
  * key falls back from local_id to id.
  * a hand-edited unknown decision is coerced to ``untriaged``.
  * render is deterministic (byte-stable) and never mutates the model.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import review_threat_model as rtm  # noqa: E402


def _write_model(output_dir: Path, threats: list[dict], meta: dict | None = None) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = {"meta": meta or {"project": "demo", "generated": "2026-07-17T00:00:00Z"}, "threats": threats}
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")


def _write_sidecar(path: Path, findings: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({"version": 1, "findings": findings}), encoding="utf-8")


THREATS = [
    {
        "id": "T-001",
        "local_id": "auth-006",
        "title": "Hardcoded secrets in source",
        "component": "auth",
        "effective_severity": "Critical",
        "risk": "High",
        "mitigation_ids": ["M-001"],
        "remediation": {"effort": "Low", "steps": ["Rotate the secret", "Move it to a vault"]},
    },
    {
        "id": "T-002",
        "local_id": "web-003",
        "title": "Missing rate limiting",
        "component": "web",
        "effective_severity": "High",
        "remediation": {"effort": "Medium", "steps": ["Add a rate limiter"]},
    },
    {
        "id": "T-003",  # no local_id -> key falls back to id
        "title": "Verbose error messages",
        "component": "api",
        "effective_severity": "Medium",
    },
]


def test_reconcile_ranks_and_marks_untriaged(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, THREATS)
    view = rtm.reconcile(out, tmp_path / ".appsec-triage" / "triage.yaml")

    assert view["total"] == 3
    # severity-ranked: Critical, High, Medium
    assert [f["severity"] for f in view["findings"]] == ["Critical", "High", "Medium"]
    # everything untriaged with no sidecar
    assert all(f["decision"] == "untriaged" for f in view["findings"])
    assert view["by_decision"]["untriaged"] == 3
    # key fallback: the third finding has no local_id -> keyed by id
    assert view["findings"][2]["key"] == "T-003"
    assert view["findings"][0]["has_mitigation"] is True
    assert view["findings"][1]["has_mitigation"] is False


def test_reconcile_merges_sidecar_decisions(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, THREATS)
    sidecar = tmp_path / ".appsec-triage" / "triage.yaml"
    _write_sidecar(
        sidecar,
        {
            "auth-006": {"decision": "fix", "owner": "team-sec", "target_sprint": "2026-Q3"},
            "web-003": {"decision": "accept-risk", "rationale": "internal only"},
        },
    )
    view = rtm.reconcile(out, sidecar)
    by_key = {f["key"]: f for f in view["findings"]}
    assert by_key["auth-006"]["decision"] == "fix"
    assert by_key["auth-006"]["owner"] == "team-sec"
    assert by_key["web-003"]["decision"] == "accept-risk"
    assert by_key["web-003"]["rationale"] == "internal only"
    assert by_key["T-003"]["decision"] == "untriaged"
    assert view["by_decision"] == {"fix": 1, "defer": 0, "accept-risk": 1, "untriaged": 1}


def test_reconcile_flags_stale_entries(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, THREATS)
    sidecar = tmp_path / ".appsec-triage" / "triage.yaml"
    _write_sidecar(
        sidecar,
        {
            "auth-006": {"decision": "fix"},
            "gone-999": {"decision": "accept-risk", "rationale": "was here last scan"},
        },
    )
    view = rtm.reconcile(out, sidecar)
    assert [s["key"] for s in view["stale"]] == ["gone-999"]
    assert view["stale"][0]["decision"] == "accept-risk"
    # stale entry is NOT counted among live findings
    assert view["total"] == 3


def test_unknown_decision_coerced_to_untriaged(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, THREATS)
    sidecar = tmp_path / ".appsec-triage" / "triage.yaml"
    _write_sidecar(sidecar, {"auth-006": {"decision": "wontfix-lol"}})
    view = rtm.reconcile(out, sidecar)
    by_key = {f["key"]: f for f in view["findings"]}
    assert by_key["auth-006"]["decision"] == "untriaged"


def test_render_is_deterministic_and_groups_by_decision(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, THREATS)
    sidecar = tmp_path / ".appsec-triage" / "triage.yaml"
    _write_sidecar(
        sidecar,
        {
            "auth-006": {"decision": "fix", "owner": "team-sec"},
            "web-003": {"decision": "accept-risk", "rationale": "internal only"},
        },
    )
    plan = tmp_path / ".appsec-triage" / "remediation-plan.md"

    model_before = (out / "threat-model.yaml").read_text()
    p1 = rtm.render(out, sidecar, plan)
    text1 = p1.read_text()
    p2 = rtm.render(out, sidecar, plan)
    text2 = p2.read_text()

    assert text1 == text2, "render must be byte-stable"
    # model untouched (Consumer, never Producer)
    assert (out / "threat-model.yaml").read_text() == model_before

    assert "## To Fix" in text1
    assert "## Accepted Risk" in text1
    assert "## Untriaged" in text1
    # remediation steps rendered for fix bucket, verbatim from model
    assert "1. Rotate the secret" in text1
    assert "**Owner:** team-sec" in text1
    # accept-risk carries the rationale
    assert "internal only" in text1


def test_missing_model_exits_1(tmp_path):
    with pytest.raises(SystemExit) as ei:
        rtm.reconcile(tmp_path / "nowhere", tmp_path / "triage.yaml")
    assert ei.value.code == 1


def test_corrupt_sidecar_exits_2(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, THREATS)
    sidecar = tmp_path / ".appsec-triage" / "triage.yaml"
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text("findings: [unbalanced\n", encoding="utf-8")
    with pytest.raises(SystemExit) as ei:
        rtm.reconcile(out, sidecar)
    assert ei.value.code == 2


# ---------------------------------------------------------------------------
# Console view — verdict + areas + mitigations (deterministic reads)
# ---------------------------------------------------------------------------

CONSOLE_THREATS = [
    {
        "id": "T-001",
        "local_id": "auth-006",
        "title": "Hardcoded secret",
        "component": "auth",
        "effective_severity": "Critical",
        "threat_category_id": "TH-02",
        "mitigation_ids": ["M-001"],
    },
    {
        "id": "T-002",
        "local_id": "auth-007",
        "title": "Session in localStorage",
        "component": "auth",
        "effective_severity": "High",
        "threat_category_id": "TH-02",
        "mitigation_ids": ["M-001"],
    },
    {
        "id": "T-003",
        "local_id": "api-004",
        "title": "SQL injection",
        "component": "api",
        "effective_severity": "Critical",
        "threat_category_id": "TH-01",
        "mitigation_ids": ["M-002"],
    },
    {
        "id": "T-004",
        "local_id": "api-009",
        "title": "Verbose error",
        "component": "api",
        "effective_severity": "Medium",
        # no threat_category_id -> collapses into Uncategorized area
    },
]

CONSOLE_MITIGATIONS = [
    {
        "id": "M-001",
        "title": "Adopt BFF",
        "priority": "P1",
        "severity": "Critical",
        "kind": "fix",
        "threat_ids": ["T-001", "T-002"],
    },
    {
        "id": "M-002",
        "title": "Parameterize queries",
        "priority": "P2",
        "severity": "Critical",
        "kind": "fix",
        "threat_ids": ["T-003"],
    },
]

CATEGORY_NAMES = {"TH-01": "Injection", "TH-02": "Broken Authentication"}


def _write_full_model(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "meta": {"project": "demo", "generated": "2026-07-17T00:00:00Z"},
        "threats": CONSOLE_THREATS,
        "mitigations": CONSOLE_MITIGATIONS,
        "weaknesses": [{"id": "W-001"}, {"id": "W-002"}],
    }
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")


def test_reconcile_enriches_category_name(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_full_model(out)
    view = rtm.reconcile(out, tmp_path / "triage.yaml", category_names=CATEGORY_NAMES)
    by_key = {f["key"]: f for f in view["findings"]}
    assert by_key["auth-006"]["category_id"] == "TH-02"
    assert by_key["auth-006"]["category_name"] == "Broken Authentication"
    # unknown / missing category -> empty name, never a crash
    assert by_key["api-009"]["category_id"] == ""
    assert by_key["api-009"]["category_name"] == ""


def test_build_mitigations_ranks_and_fans_out_coverage():
    model = {"mitigations": CONSOLE_MITIGATIONS}
    key_by_tid = {"T-001": "auth-006", "T-002": "auth-007", "T-003": "api-004"}
    mits = rtm.build_mitigations(model, key_by_tid)
    # P1 before P2
    assert [m["id"] for m in mits] == ["M-001", "M-002"]
    m1 = mits[0]
    # threat_ids (global) fan out to finding keys (local_id)
    assert m1["coverage"] == 2
    assert set(m1["covered_keys"]) == {"auth-006", "auth-007"}


def test_build_areas_groups_and_ranks_by_blast():
    findings = [
        {"key": "auth-006", "severity": "Critical", "category_id": "TH-02", "category_name": "Broken Authentication"},
        {"key": "auth-007", "severity": "High", "category_id": "TH-02", "category_name": "Broken Authentication"},
        {"key": "api-004", "severity": "Critical", "category_id": "TH-01", "category_name": "Injection"},
        {"key": "api-009", "severity": "Medium", "category_id": "", "category_name": ""},
    ]
    areas = rtm.build_areas(findings)
    names = [a["category_name"] for a in areas]
    # Broken Authentication (1 Crit + 1 High) ranks above Injection (1 Crit only)
    assert names[0] == "Broken Authentication"
    assert names[1] == "Injection"
    # uncategorized collapses into a trailing bucket labelled Uncategorized
    assert names[-1] == "Uncategorized"
    ba = areas[0]
    assert ba["total"] == 2 and ba["critical"] == 1 and ba["high"] == 1


def test_console_composes_verdict_and_views(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_full_model(out)
    tax = tmp_path / "tax.yaml"
    tax.write_text(
        yaml.safe_dump(
            {"categories": [{"id": "TH-01", "name": "Injection"}, {"id": "TH-02", "name": "Broken Authentication"}]}
        ),
        encoding="utf-8",
    )
    payload = rtm.console(out, tmp_path / "triage.yaml", taxonomy_path=tax)
    v = payload["verdict"]
    assert v["by_severity"] == {"Critical": 2, "High": 1, "Medium": 1}
    assert v["weaknesses"] == 2
    assert v["with_mitigation"] == 3  # T-004 has no mitigation_ids
    assert v["p1_mitigations"] == 1
    assert v["triaged"] == 0
    assert ("Broken Authentication", 2) in v["top_areas"]
    # composed sub-views present and non-empty
    assert len(payload["mitigations"]) == 2
    assert len(payload["areas"]) == 3  # TH-02, TH-01, Uncategorized
    assert payload["mitigations"][0]["covered_keys"] == ["auth-006", "auth-007"]


def test_load_category_names_missing_taxonomy_is_empty(tmp_path):
    assert rtm._load_category_names(tmp_path / "does-not-exist.yaml") == {}


# ---------------------------------------------------------------------------
# Priority backlog spine — kind ordering, backlog/uncovered verdict
# ---------------------------------------------------------------------------


def test_build_mitigations_orders_fix_before_investigate_within_band():
    model = {
        "mitigations": [
            {"id": "M-050", "title": "look into it", "priority": "P2", "kind": "investigate", "threat_ids": ["T-1"]},
            {"id": "M-051", "title": "fix it", "priority": "P2", "kind": "fix", "threat_ids": ["T-2"]},
        ]
    }
    key_by_tid = {"T-1": "a-1", "T-2": "a-2"}
    mits = rtm.build_mitigations(model, key_by_tid)
    # same P2 band -> actionable fix ranks above investigate
    assert [m["id"] for m in mits] == ["M-051", "M-050"]


def test_verdict_reports_backlog_by_priority_and_uncovered(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_full_model(out)  # T-004 has no mitigation_ids -> 1 uncovered
    payload = rtm.console(out, tmp_path / "triage.yaml")
    v = payload["verdict"]
    assert v["by_priority"] == {"P1": 1, "P2": 1}
    assert v["uncovered"] == 1
    # mitigations carry the severity mix of the findings they cover
    m1 = payload["mitigations"][0]
    assert m1["id"] == "M-001"
    assert m1["covered_severities"] == {"Critical": 1, "High": 1}


# ---------------------------------------------------------------------------
# Worst-case scenarios (read verbatim from critical_findings)
# ---------------------------------------------------------------------------


def test_build_worst_case_joins_curated_critical_findings(tmp_path):
    out = tmp_path / "docs" / "security"
    output_dir = out
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "meta": {"project": "demo", "generated": "2026-07-17T00:00:00Z"},
        "threats": CONSOLE_THREATS,
        "mitigations": CONSOLE_MITIGATIONS,
        "critical_findings": [
            {"threat_id": "T-003", "summary": "attacker dumps the users table", "mitigation_id": "M-002"},
            {"threat_id": "T-001", "summary": "secret leaks, full account takeover", "mitigation_id": "M-001"},
            {"threat_id": "T-999", "summary": "gone finding — must be skipped", "mitigation_id": "M-000"},
        ],
    }
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    payload = rtm.console(output_dir, tmp_path / "triage.yaml")
    wc = payload["worst_case"]
    # unresolved threat_id dropped; two Criticals, severity-ranked by id
    assert [w["id"] for w in wc] == ["T-001", "T-003"]
    first = wc[0]
    assert first["summary"] == "secret leaks, full account takeover"  # verbatim
    assert first["mitigation_id"] == "M-001" and first["priority"] == "P1"
    assert first["severity"] == "Critical" and first["component"] == "auth"


def test_build_worst_case_falls_back_to_top_severity_findings(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_full_model(out)  # no critical_findings key
    payload = rtm.console(out, tmp_path / "triage.yaml")
    wc = payload["worst_case"]
    # degrade to Critical/High findings only, capped at 3, Medium excluded
    assert all(w["severity"] in ("Critical", "High") for w in wc)
    assert "T-004" not in {w["id"] for w in wc}  # the Medium finding
    assert all(w["mitigation_id"] == "" for w in wc)  # no curated mitigation link


# ---------------------------------------------------------------------------
# Requirements badge/lens — explicit custom requirements only
# ---------------------------------------------------------------------------

_CUSTOM_THREATS = [
    {
        "id": "T-001",
        "local_id": "auth-006",
        "title": "Weak password policy",
        "component": "auth",
        "effective_severity": "High",
        "mitigation_ids": ["M-001"],
        "violated_requirements": ["ASR-12"],
    },
    {
        "id": "T-002",
        "local_id": "api-004",
        "title": "No audit log",
        "component": "api",
        "effective_severity": "Medium",
        "requirement_id": "ASR-12",  # single-id form also folds in
    },
    {
        "id": "T-003",
        "local_id": "web-002",
        "title": "Unrelated finding",
        "component": "web",
        "effective_severity": "Low",
    },
]


def _write_reqs_model(output_dir: Path, requirements_source: str | None, check: bool = True) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "meta": {"project": "demo", "generated": "2026-07-17T00:00:00Z", "check_requirements": check},
        "threats": _CUSTOM_THREATS,
        "mitigations": [{"id": "M-001", "priority": "P2", "kind": "fix", "threat_ids": ["T-001"]}],
    }
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    if requirements_source is not None:
        reqs = {
            "source": requirements_source,
            "categories": [{"id": "C1", "requirements": [{"id": "ASR-12", "url": "https://asr/12"}]}],
        }
        (output_dir / ".requirements.yaml").write_text(yaml.safe_dump(reqs), encoding="utf-8")


def test_requirements_badge_for_explicit_custom_source(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_reqs_model(out, requirements_source="harvested")
    payload = rtm.console(out, tmp_path / "triage.yaml")
    by_key = {f["key"]: f for f in payload["findings"]}
    assert by_key["auth-006"]["requirements"] == ["ASR-12"]
    assert by_key["api-004"]["requirements"] == ["ASR-12"]  # single requirement_id folded
    assert by_key["web-002"]["requirements"] == []
    v = payload["verdict"]["requirements"]
    assert v == {"integrated": True, "findings_violating": 2, "requirement_count": 1}
    # requirement lens groups both findings under ASR-12 with its url
    rg = payload["requirements"]
    assert len(rg) == 1
    assert rg[0]["requirement_id"] == "ASR-12" and rg[0]["total"] == 2
    assert rg[0]["url"] == "https://asr/12"


def test_requirements_suppressed_for_bundled_baseline(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_reqs_model(out, requirements_source="bundled-bestpractices")
    payload = rtm.console(out, tmp_path / "triage.yaml")
    assert all(f["requirements"] == [] for f in payload["findings"])
    assert payload["verdict"]["requirements"]["integrated"] is False
    assert payload["requirements"] == []


def test_requirements_suppressed_for_skipped_stub(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_reqs_model(out, requirements_source="skipped")
    payload = rtm.console(out, tmp_path / "triage.yaml")
    assert payload["verdict"]["requirements"]["integrated"] is False


def test_requirements_suppressed_when_check_disabled(tmp_path):
    out = tmp_path / "docs" / "security"
    # a real custom source is present, but the run did NOT request the check
    _write_reqs_model(out, requirements_source="harvested", check=False)
    payload = rtm.console(out, tmp_path / "triage.yaml")
    assert payload["verdict"]["requirements"]["integrated"] is False
    assert all(f["requirements"] == [] for f in payload["findings"])


def test_build_requirement_groups_ranks_by_blast():
    findings = [
        {"key": "a-1", "severity": "Critical", "requirements": ["R-1"]},
        {"key": "a-2", "severity": "High", "requirements": ["R-1", "R-2"]},
        {"key": "a-3", "severity": "Low", "requirements": ["R-2"]},
    ]
    groups = rtm.build_requirement_groups(findings, {"R-1": "u1"})
    # R-1 (1 Critical) ranks above R-2 (no Critical)
    assert [g["requirement_id"] for g in groups] == ["R-1", "R-2"]
    assert groups[0]["total"] == 2 and groups[0]["critical"] == 1
