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


def test_primary_location_prefers_evidence_file():
    # evidence file:line wins over the mostly-empty affected_files and component
    t = {"component": "ci", "evidence": [{"file": ".github/workflows/tests.yml", "line": 19}]}
    assert rtm._primary_location(t) == ".github/workflows/tests.yml:19"
    # affected_files is the next best source
    assert rtm._primary_location({"component": "api", "affected_files": ["src/db.py"]}) == "src/db.py"
    # component is the last-resort so a row is never location-less
    assert rtm._primary_location({"component": "auth"}) == "auth"


def test_reconcile_exposes_cwe_and_location(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(
        out,
        [
            {
                "id": "T-001",
                "local_id": "ci-1",
                "title": "Supply chain",
                "component": "ci",
                "effective_severity": "Critical",
                "cwe": "CWE-829",
                "evidence": [{"file": ".github/workflows/tests.yml", "line": 19}],
            }
        ],
    )
    view = rtm.reconcile(out, tmp_path / "triage.yaml")
    f = view["findings"][0]
    assert f["cwe"] == "CWE-829"
    assert f["location"] == ".github/workflows/tests.yml:19"


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


def test_build_quick_wins_low_effort_high_impact():
    mits = [
        {"id": "M-001", "priority": "P2", "effort": "Low", "coverage": 2, "covered_severities": {"High": 2}},
        {"id": "M-002", "priority": "P1", "effort": "Low", "coverage": 1, "covered_severities": {"Critical": 1}},
        {"id": "M-003", "priority": "P2", "effort": "High", "coverage": 5, "covered_severities": {"High": 5}},
        {"id": "M-004", "priority": "P3", "effort": "Low", "coverage": 3, "covered_severities": {"Medium": 3}},
        {"id": "M-005", "priority": "P2", "effort": "", "coverage": 1, "covered_severities": {"High": 1}},
    ]
    qw = rtm.build_quick_wins(mits)
    # only Low-effort AND covering a Critical/High; ranked by coverage desc
    assert [m["id"] for m in qw] == ["M-001", "M-002"]
    # M-003 excluded (High effort), M-004 (only Medium), M-005 (no effort)


def test_build_recommended_fix_first():
    mits = [
        # ideal: fix + Low + covers Critical -> top
        {
            "id": "M-001",
            "priority": "P1",
            "kind": "fix",
            "effort": "Low",
            "coverage": 1,
            "covered_severities": {"Critical": 1},
        },
        # fix + Low + High -> included, ranks below the Critical one
        {
            "id": "M-002",
            "priority": "P2",
            "kind": "fix",
            "effort": "Low",
            "coverage": 2,
            "covered_severities": {"High": 2},
        },
        # low-effort High but kind=investigate -> excluded (needs analysis first)
        {
            "id": "M-003",
            "priority": "P2",
            "kind": "investigate",
            "effort": "Low",
            "coverage": 1,
            "covered_severities": {"High": 1},
        },
        # fix but High effort -> excluded (not cheap)
        {
            "id": "M-004",
            "priority": "P2",
            "kind": "fix",
            "effort": "High",
            "coverage": 1,
            "covered_severities": {"High": 1},
        },
        # fix + Low but only Medium -> excluded (not worth-it enough)
        {
            "id": "M-005",
            "priority": "P3",
            "kind": "fix",
            "effort": "Low",
            "coverage": 1,
            "covered_severities": {"Medium": 1},
        },
    ]
    rec = rtm.build_recommended(mits)
    assert [m["id"] for m in rec] == ["M-001", "M-002"]  # Critical before High


def test_build_control_posture_groups_and_ranks_worst_first():
    model = {
        "security_controls": [
            {"domain": "Cryptography", "control": "TLS", "effectiveness": "Adequate", "assessment": "ok"},
            {"domain": "Cryptography", "control": "Secrets", "effectiveness": "Weak", "assessment": "hardcoded"},
            {"domain": "Authorization", "control": "RBAC", "effectiveness": "Missing", "assessment": "none"},
            {"domain": "", "control": "orphan"},  # no domain -> skipped
        ]
    }
    posture = rtm.build_control_posture(model)
    # Authorization (Missing) ranks worst-first; a domain's weakest control drives its rank
    assert [d["domain"] for d in posture] == ["Authorization", "Cryptography"]
    assert posture[0]["worst_effectiveness"] == "Missing"
    crypto = posture[1]
    assert crypto["worst_effectiveness"] == "Weak" and crypto["total"] == 2
    assert crypto["by_effectiveness"] == {"Adequate": 1, "Weak": 1}


def test_console_exposes_quick_wins_and_posture(tmp_path):
    out = tmp_path / "docs" / "security"
    output_dir = out
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "meta": {"project": "demo", "generated": "2026-07-17T00:00:00Z"},
        "threats": CONSOLE_THREATS,
        "mitigations": [
            {
                "id": "M-001",
                "priority": "P1",
                "kind": "fix",
                "threat_ids": ["T-001", "T-002"],
                "remediation": {"effort": "Low"},
            },
            {
                "id": "M-002",
                "priority": "P2",
                "kind": "fix",
                "threat_ids": ["T-003"],
                "remediation": {"effort": "High"},
            },
        ],
        "security_controls": [
            {"domain": "Authorization", "control": "RBAC", "effectiveness": "Missing", "assessment": "none"},
        ],
    }
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    payload = rtm.console(output_dir, tmp_path / "triage.yaml")
    # M-001 is Low effort and covers a Critical (T-001) -> quick win; M-002 is High effort -> not
    assert [m["id"] for m in payload["quick_wins"]] == ["M-001"]
    assert payload["verdict"]["quick_wins"] == 1
    assert [d["domain"] for d in payload["control_posture"]] == ["Authorization"]
    assert payload["control_posture"][0]["worst_effectiveness"] == "Missing"


def test_normalize_domain_auth_and_authz():
    assert rtm._normalize_domain("Authorization Controls") == "Authorization"
    assert rtm._normalize_domain("Broken Access Control") == "Authorization"
    assert rtm._normalize_domain("Identity and Authentication Controls") == "Authentication"
    assert rtm._normalize_domain("Identity and Authentication") == "Authentication"
    # non-auth: just trims a trailing " Controls"
    assert rtm._normalize_domain("Session and Token Controls") == "Session and Token"
    assert (
        rtm._normalize_domain("Cryptography Secrets and Data Protection") == "Cryptography Secrets and Data Protection"
    )


def test_control_posture_normalizes_and_merges_auth_domains():
    model = {
        "security_controls": [
            {"domain": "Identity and Authentication Controls", "control": "login", "effectiveness": "Missing"},
            {"domain": "Identity and Authentication", "control": "mfa", "effectiveness": "Weak"},
            {"domain": "Authorization Controls", "control": "rbac", "effectiveness": "Missing"},
            {"domain": "Session and Token Controls", "control": "sess", "effectiveness": "Partial"},
        ]
    }
    posture = rtm.build_control_posture(model)
    domains = [d["domain"] for d in posture]
    assert "Authentication" in domains and "Authorization" in domains
    # the two Identity/Authentication label variants fold into ONE domain
    auth = next(d for d in posture if d["domain"] == "Authentication")
    assert auth["total"] == 2
    assert auth["worst_effectiveness"] == "Missing"
    # non-auth domain kept (trimmed)
    assert "Session and Token" in domains


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


# ---------------------------------------------------------------------------
# promote-accepted → docs/known-threats.yaml (opt-in Step 6b)
# ---------------------------------------------------------------------------

_KT_THREATS = [
    {
        "id": "T-001",
        "local_id": "auth-006",
        "title": "SQL injection in login",
        "component": "auth",
        "stride": "Spoofing",
        "effective_severity": "Critical",
        "scenario": "Attacker posts ' OR 1=1-- and logs in as admin.",
        "evidence": [{"file": "routes/login.ts", "line": 34}],
        "mitigation_title": "Use parameterized queries",
    },
    {
        "id": "T-002",
        "local_id": "web-003",
        "title": "Missing rate limiting",
        "component": "web",
        "stride": "Denial of Service",
        "risk": "High",
        "impact_description": "Brute force possible.",
    },
    {
        "id": "T-003",
        "local_id": "api-009",
        "title": "Unmappable STRIDE",
        "component": "api",
        "stride": "Nonsense",  # not in the enum -> cannot form a valid entry
        "effective_severity": "Medium",
    },
]


def _read_yaml(p: Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def test_build_known_threat_entry_shape():
    e = rtm._build_known_threat_entry(_KT_THREATS[0], "Accepted for release.")
    assert e["id"] == "auth-006"  # stable local_id, never the renumbering T-001
    assert e["stride"] == "Spoofing"
    assert e["severity"] == "Critical"
    assert e["status"] == "accepted"
    assert e["accepted_risk"] == "Accepted for release."
    assert e["evidence"] == "routes/login.ts:34"
    assert e["mitigation_ref"] == "Use parameterized queries"
    assert e["description"]  # non-empty (from scenario)


def test_build_known_threat_entry_rejects_unmappable_stride():
    assert rtm._build_known_threat_entry(_KT_THREATS[2], "x") is None


def test_build_known_threat_entry_defaults_rationale_and_severity():
    t = {"local_id": "x-1", "title": "t", "component": "c", "stride": "Tampering"}
    e = rtm._build_known_threat_entry(t, "")
    assert e["severity"] == "Medium"  # no derivable severity -> safe default
    assert e["accepted_risk"] == "Risk accepted during triage."


def test_promote_accepted_writes_valid_known_threats(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, _KT_THREATS)
    sc = tmp_path / ".appsec-triage" / "triage.yaml"
    _write_sidecar(
        sc,
        {
            "auth-006": {"decision": "accept-risk", "rationale": "Compensating control."},
            "web-003": {"decision": "accept-risk", "rationale": "Low traffic service."},
            "api-009": {"decision": "fix"},  # not accepted -> ignored
        },
    )
    kt = tmp_path / "docs" / "known-threats.yaml"
    summary = rtm.promote_accepted(out, sc, kt)
    assert summary["added"] == 2 and summary["updated"] == 0 and summary["skipped"] == []
    doc = _read_yaml(kt)
    assert {t["id"] for t in doc["threats"]} == {"auth-006", "web-003"}
    assert all(t["status"] == "accepted" for t in doc["threats"])
    import validate_intermediate as vi  # the pipeline's own validator

    assert vi.validate_known_threats(doc)[0]


def test_promote_accepted_merges_preserves_and_dedups(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, _KT_THREATS)
    sc = tmp_path / ".appsec-triage" / "triage.yaml"
    _write_sidecar(sc, {"auth-006": {"decision": "accept-risk", "rationale": "r1"}})
    kt = tmp_path / "docs" / "known-threats.yaml"
    kt.parent.mkdir(parents=True, exist_ok=True)
    kt.write_text(
        yaml.safe_dump(
            {
                "owner_team": "sec",  # extra top-level key must survive
                "threats": [
                    {
                        "id": "TEAM-1",
                        "title": "team known",
                        "stride": "Repudiation",
                        "component": "x",
                        "severity": "Low",
                        "status": "accepted",
                        "description": "d",
                        "custom": "keep-me",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    rtm.promote_accepted(out, sc, kt)  # first pass: appends auth-006
    summary = rtm.promote_accepted(out, sc, kt)  # second pass: updates, no dup
    assert summary["added"] == 0 and summary["updated"] == 1
    doc = _read_yaml(kt)
    assert [t["id"] for t in doc["threats"]] == ["TEAM-1", "auth-006"]  # order + team entry kept
    assert doc["owner_team"] == "sec"
    team = next(t for t in doc["threats"] if t["id"] == "TEAM-1")
    assert team["custom"] == "keep-me"  # team's extra field untouched


def test_promote_accepted_skips_stale_and_noops_without_file(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, _KT_THREATS)
    sc = tmp_path / ".appsec-triage" / "triage.yaml"
    _write_sidecar(sc, {"ghost-1": {"decision": "accept-risk", "rationale": "gone"}})
    kt = tmp_path / "docs" / "known-threats.yaml"
    summary = rtm.promote_accepted(out, sc, kt)
    assert summary["skipped"] == ["ghost-1"] and summary["added"] == 0
    assert not kt.exists()  # nothing mappable + no existing file -> no empty file written


def test_promote_accepted_never_touches_model(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_model(out, _KT_THREATS)
    before = (out / "threat-model.yaml").read_text()
    sc = tmp_path / ".appsec-triage" / "triage.yaml"
    _write_sidecar(sc, {"auth-006": {"decision": "accept-risk", "rationale": "r"}})
    rtm.promote_accepted(out, sc, tmp_path / "docs" / "known-threats.yaml")
    assert (out / "threat-model.yaml").read_text() == before  # Consumer guarantee


# ---------------------------------------------------------------------------
# Pre-rendered console screens — the deterministic display blocks the skill
# echoes verbatim instead of re-composing each menu (glyph contract, category
# grouping and continuous numbering baked in here, not left to the LLM).
# ---------------------------------------------------------------------------


def _write_screen_model(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "meta": {"project": "demo", "generated": "2026-07-17T00:00:00Z"},
        "threats": [
            {
                "id": "T-001",
                "local_id": "auth-1",
                "title": "Insecure JWT verification",
                "component": "auth",
                "effective_severity": "Critical",
                "threat_category_id": "TH-02",
                "mitigation_ids": ["M-001"],
                "evidence": [{"file": "lib/insecurity.ts", "line": 52}],
            },
            {
                "id": "T-002",
                "local_id": "api-1",
                "title": "SQL injection in login",
                "component": "api",
                "effective_severity": "Critical",
                "threat_category_id": "TH-01",
                "mitigation_ids": ["M-002"],
                "evidence": [{"file": "routes/login.ts", "line": 34}],
            },
            {
                "id": "T-003",
                "local_id": "api-2",
                "title": "Verbose error leak",
                "component": "api",
                "effective_severity": "Medium",
                "threat_category_id": "TH-01",
                "mitigation_ids": ["M-003"],
                "evidence": [{"file": "routes/err.ts", "line": 9}],
            },
        ],
        "mitigations": [
            {  # P1 fix, Low, covers Critical -> recommended
                "id": "M-001",
                "title": "Verify JWT signature and algorithm",
                "priority": "P1",
                "kind": "fix",
                "threat_ids": ["T-001"],
                "remediation": {"effort": "Low"},
            },
            {  # P2 fix, Low, covers Critical -> recommended
                "id": "M-002",
                "title": "Parameterize database queries",
                "priority": "P2",
                "kind": "fix",
                "threat_ids": ["T-002"],
                "remediation": {"effort": "Low"},
            },
            {  # P3 review -> hidden in fix_list default, not recommended
                "id": "M-003",
                "title": "Investigate error handling",
                "priority": "P3",
                "kind": "review",
                "threat_ids": ["T-003"],
                "remediation": {"effort": "Low"},
            },
        ],
        "critical_findings": [
            {"threat_id": "T-001", "summary": "Anyone can forge an admin token", "mitigation_id": "M-001"},
        ],
        "security_controls": [
            {"domain": "Authorization", "control": "RBAC", "effectiveness": "Missing", "assessment": "none"},
        ],
        "weaknesses": [{"id": "W-001"}],
    }
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")


def _screens(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_screen_model(out)
    tax = tmp_path / "tax.yaml"
    tax.write_text(
        yaml.safe_dump(
            {"categories": [{"id": "TH-01", "name": "Injection"}, {"id": "TH-02", "name": "Broken Authentication"}]}
        ),
        encoding="utf-8",
    )
    payload = rtm.console(out, tmp_path / "triage.yaml", taxonomy_path=tax)
    return payload, payload["screens"]


def test_console_payload_carries_prerendered_screens(tmp_path):
    _, s = _screens(tmp_path)
    assert set(s) == {
        "landing",
        "fix_start",
        "fix_list",
        "fix_list_full",
        "browse_severity",
        "browse_type",
        "browse_requirement",
        "posture",
    }
    assert all(isinstance(v, str) for v in s.values())


def test_screen_landing_has_verdict_rows_and_single_worst_case_header(tmp_path):
    _, s = _screens(tmp_path)
    land = s["landing"]
    assert land.startswith("**demo** · generated 2026-07-17T00:00:00Z · **3 findings** · 0/3 triaged")
    assert "**Backlog**    1× P1 · 1× P2 · 1× P3   ·   0 without a fix" in land
    assert "🔴 2 Critical · 🟡 1 Medium" in land  # severity dots, only non-zero bands
    assert "🧩 1 design weaknesses" in land
    # worst-case block header appears exactly once (regression: it once repeated per row)
    assert land.count("**⚠ Worst case if nothing changes**") == 1
    # finding uses a severity dot, the fix reference uses the priority ramp
    assert "🔴 **[T-001]** auth — Anyone can forge an admin token   → fix with ● M-001" in land


def test_screen_landing_omits_requirements_row_without_custom_reqs(tmp_path):
    _, s = _screens(tmp_path)
    assert "**Requirements**" not in s["landing"]  # gated to integrated custom requirements


def test_screen_fix_start_groups_by_category_worst_first(tmp_path):
    _, s = _screens(tmp_path)
    fs = s["fix_start"]
    assert fs.startswith("🛠 **Fix these first**")
    # both P1(Injection-header? no) grouped by the hardened category; both covered are Critical
    assert "**Fix Broken Authentication** — 1" in fs
    assert "**Fix Injection** — 1" in fs
    # measure led by ramp glyph; covered finding on a severity-dot sub-line with file:line
    assert "● M-001 (P1) Verify JWT signature and algorithm" in fs
    assert "└ 🔴 T-001 · lib/insecurity.ts:52" in fs
    # P3 review is NOT cheap-and-low-risk -> never recommended
    assert "M-003" not in fs


def test_screen_fix_start_empty_when_no_recommendation(tmp_path):
    # a model whose only fix is High effort -> recommended[] empty -> screen is ""
    out = tmp_path / "docs" / "security"
    out.mkdir(parents=True, exist_ok=True)
    doc = {
        "meta": {"project": "d", "generated": "g"},
        "threats": [
            {"id": "T-1", "local_id": "a-1", "title": "x", "effective_severity": "High", "mitigation_ids": ["M-1"]}
        ],
        "mitigations": [
            {
                "id": "M-1",
                "title": "big",
                "priority": "P2",
                "kind": "fix",
                "threat_ids": ["T-1"],
                "remediation": {"effort": "High"},
            }
        ],
    }
    (out / "threat-model.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    s = rtm.console(out, tmp_path / "triage.yaml")["screens"]
    assert s["fix_start"] == ""


def test_screen_fix_list_numbers_continuously_and_hides_p3(tmp_path):
    _, s = _screens(tmp_path)
    fl = s["fix_list"]
    # continuous numbering across category groups: 1 then 2, no reset
    assert "  1. " in fl and "  2. " in fl and "  3. " not in fl
    # recommended fixes carry a star
    assert "★" in fl
    # P3 hidden by default, surfaced via a hint line
    assert "M-003" not in fl
    assert "(+1 P3 — type `show P3` to include)" in fl
    # the full variant includes the P3 band and numbers it (Injection group leads —
    # 2 findings vs Broken Auth's 1 — so M-002=1, M-003=2, M-001=3)
    assert "M-003" in s["fix_list_full"]
    assert "  2. ◑ M-003 (P3)" in s["fix_list_full"]


def test_screen_browse_and_posture_gating(tmp_path):
    payload, s = _screens(tmp_path)
    # by-type numbered blast table, ranked by blast (Injection has 2 findings)
    assert "1. Injection — 2 findings (🔴 1 · 🟠 0)" in s["browse_type"]
    assert "2. Broken Authentication — 1 findings (🔴 1 · 🟠 0)" in s["browse_type"]
    # posture present (controls exist); no custom requirements -> browse_requirement empty
    assert s["browse_requirement"] == ""
    assert "Authorization — Missing (1 controls: 1 Missing)" in s["posture"]
    # by-severity leads each row with the severity dot, untriaged first
    first = s["browse_severity"].splitlines()[0]
    assert first.startswith("🔴 T-001") or first.startswith("🔴 T-002")


def test_screen_posture_empty_without_controls(tmp_path):
    out = tmp_path / "docs" / "security"
    _write_full_model(out)  # no security_controls
    s = rtm.console(out, tmp_path / "triage.yaml")["screens"]
    assert s["posture"] == ""


def test_screens_are_byte_stable(tmp_path):
    # same (model, sidecar) -> identical screens (no wall-clock / ordering drift)
    _, a = _screens(tmp_path / "run-a")
    _, b = _screens(tmp_path / "run-b")
    assert a == b


def test_glyph_helpers_map_axes():
    assert rtm._sev_dot("Critical") == "🔴" and rtm._sev_dot("High") == "🟠"
    assert rtm._sev_dot("nonsense") == "⚪"  # unrated / unknown -> hollow
    assert rtm._ramp("P1") == "●" and rtm._ramp("P4") == "○"
    assert rtm._ramp("") == "○"  # default fill
