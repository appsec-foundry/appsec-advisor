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
