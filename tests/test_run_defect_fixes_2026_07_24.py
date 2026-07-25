"""Regressions for the six defects surfaced by the juice-shop run of 2026-07-24.

Each test pins the *behaviour* that was wrong, not the implementation that
happened to fix it. Sources for every case are recorded in
`docs/internal/analysis/analysis-run-defects-2026-07-24.md`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agent_logger  # noqa: E402
import build_stride_dispatch_manifest as manifest  # noqa: E402
import enforce_control_taxonomy as taxonomy  # noqa: E402
import match_abuse_cases as mac  # noqa: E402

# ---------------------------------------------------------------------------
# 1. Zone vocabulary — the analyst's tier-shaped tokens are recognised
# ---------------------------------------------------------------------------


def _component(zones: list[str], cid: str = "c1") -> dict:
    return {"id": cid, "name": cid, "description": "", "deployment_zones": zones}


@pytest.mark.parametrize("token", ["server", "server-side", "backend", "app-server", "service", "worker"])
def test_server_side_placement_tokens_are_not_zone_drift(token: str):
    """`server` is where a component RUNS; it was 7 of 11 components on the
    juice-shop run and every one fell off-vocabulary."""
    assert manifest._unknown_zone_tokens(_component([token])) == set()


@pytest.mark.parametrize("token", ["server", "backend", "service"])
def test_server_side_tokens_stay_exposure_unknown(token: str):
    """Recognised, but they carry NO reachability signal — the fail-safe
    inclusion branch must still fire, never "proven internal"."""
    assert manifest._reachability_zones(_component([token])) == set()


@pytest.mark.parametrize("token", ["ci", "cicd", "ci-cd", "build", "pipeline"])
def test_ci_shorthands_restore_the_cicd_signal(token: str):
    assert manifest._is_cicd(_component([token], cid="pipe")) is True
    assert manifest._unknown_zone_tokens(_component([token])) == set()


def test_genuinely_invented_zone_labels_still_drift():
    """The warning must keep its meaning — this is the 2026-07-23 spring-app
    regression it exists for."""
    assert manifest._unknown_zone_tokens(_component(["application-zone"])) == {"application-zone"}


def test_canonical_zones_are_untouched():
    assert manifest._reachability_zones(_component(["internet"])) == {"internet"}
    assert manifest._reachability_zones(_component(["internal-network"])) == {"internal-network"}


# ---------------------------------------------------------------------------
# 2. Control taxonomy — a comma is punctuation, not a different domain
# ---------------------------------------------------------------------------


def _controls(*pairs: tuple[str, str]) -> dict:
    return {"security_controls": [{"id": f"c{i}", "control": c, "domain": d} for i, (c, d) in enumerate(pairs)]}


def test_comma_domain_does_not_reroute_rate_limiting():
    """The juice-shop defect: `Rate Limiting` left §6.11 for §6.2 IAM purely
    because its incoming domain carried commas."""
    out, _, _ = taxonomy.enforce(_controls(("Rate Limiting", "Operations, Runtime and Supply Chain Controls")))
    assert out["security_controls"][0]["domain"] == "Operations Runtime and Supply Chain Controls"


def test_comma_normalisation_is_flagged_as_stylistic():
    out, _, changes = taxonomy.enforce(
        _controls(("SSRF / Outbound Request Controls", "File, Parser and Outbound Request Controls"))
    )
    assert out["security_controls"][0]["domain"] == "File Parser and Outbound Request Controls"
    assert "control_domain_comma_normalised" in out["security_controls"][0]["audit_flags"]
    assert changes and changes[0]["to"] == "File Parser and Outbound Request Controls"


def test_intentional_reroutes_survive_the_comma_branch():
    """Password hashing → §6.9 and JWT → §6.3 are deliberate, and must still
    fire even when the incoming domain has commas."""
    out, _, _ = taxonomy.enforce(
        _controls(
            ("Password Hashing", "Cryptography, Secrets and Data Protection"),
            ("JWT Token Issuance", "Identity and Authentication Controls"),
        )
    )
    assert out["security_controls"][0]["domain"] == "Cryptography Secrets and Data Protection"
    assert out["security_controls"][1]["domain"] == "Session and Token Controls"


def test_auth_rate_limiting_still_belongs_to_iam():
    """The catalog genuinely splits rate limiting; the auth-flavoured one stays."""
    out, _, _ = taxonomy.enforce(_controls(("Authentication Rate Limiting", "Identity and Authentication Controls")))
    assert out["security_controls"][0]["domain"] == "Identity and Authentication Controls"


def test_supply_chain_producer_emits_the_canonical_comma_free_domain():
    """The plugin's own deterministic producer was the source of the comma form."""
    source = (SCRIPTS / "assess_supply_chain_controls.py").read_text(encoding="utf-8")
    assert '"domain": "Operations Runtime and Supply Chain Controls"' in source
    assert '"domain": "Operations, Runtime and Supply Chain Controls"' not in source


# ---------------------------------------------------------------------------
# 3. Stop reason — derived from the transcript, since the hook never sends one
# ---------------------------------------------------------------------------


def _transcript(tmp_path: Path, *stop_reasons: str | None) -> str:
    path = tmp_path / "transcript.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for reason in stop_reasons:
            msg: dict = {"role": "assistant", "content": []}
            if reason is not None:
                msg["stop_reason"] = reason
            fh.write(json.dumps({"message": msg}) + "\n")
    return str(path)


def test_clean_session_is_detected_from_the_transcript(tmp_path: Path):
    """A finished session ends on end_turn — it must NOT be reported as an
    abort. This is the 11-false-WARN defect."""
    reason = agent_logger._stop_reason_from_transcript(_transcript(tmp_path, "tool_use", "tool_use", "end_turn"))
    assert reason == "end_turn"
    assert reason in agent_logger._CLEAN_STOP_REASONS


def test_cut_off_session_is_detected_from_the_transcript(tmp_path: Path):
    """A session still in its tool loop was cut off — the signal that was
    completely missing when both abuse verifiers burned their turn ceiling."""
    reason = agent_logger._stop_reason_from_transcript(_transcript(tmp_path, "end_turn", "tool_use"))
    assert reason == "tool_use"
    assert reason not in agent_logger._CLEAN_STOP_REASONS


def test_unreadable_transcript_yields_no_verdict(tmp_path: Path):
    assert agent_logger._stop_reason_from_transcript("") == ""
    assert agent_logger._stop_reason_from_transcript(str(tmp_path / "nope.jsonl")) == ""
    assert agent_logger._stop_reason_from_transcript(_transcript(tmp_path)) == ""


def test_non_assistant_records_are_ignored(tmp_path: Path):
    path = tmp_path / "t.jsonl"
    path.write_text(
        json.dumps({"message": {"role": "user", "stop_reason": "tool_use"}})
        + "\n"
        + json.dumps({"message": {"role": "assistant", "stop_reason": "end_turn"}})
        + "\n",
        encoding="utf-8",
    )
    assert agent_logger._stop_reason_from_transcript(str(path)) == "end_turn"


# ---------------------------------------------------------------------------
# 4. wall_secs — a subagent's Stop runs under a different session id
# ---------------------------------------------------------------------------


def test_dispatch_time_is_redeemable_by_agent_name(tmp_path: Path, monkeypatch):
    """The timestamp is recorded under the PARENT sid but redeemed in the
    CHILD session, so the sid key never matched and wall_secs stayed '?'."""
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    agent_logger._DISPATCH_TIMES.clear()
    for ts in (1000.0, 1010.0, 1020.0):
        agent_logger._record_dispatch_time(f"agent:stride:{ts}", ts)

    assert agent_logger._take_dispatch_time("childsid") is None
    # FIFO: oldest dispatch first, so a parallel fan-out pairs up in order.
    assert agent_logger._take_dispatch_time_for_agent("stride") == 1000.0
    assert agent_logger._take_dispatch_time_for_agent("stride") == 1010.0
    assert agent_logger._take_dispatch_time_for_agent("stride") == 1020.0
    assert agent_logger._take_dispatch_time_for_agent("stride") is None


def test_dispatch_time_lookup_is_scoped_to_the_agent(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    agent_logger._DISPATCH_TIMES.clear()
    agent_logger._record_dispatch_time("agent:stride:1000.0", 1000.0)
    assert agent_logger._take_dispatch_time_for_agent("renderer") is None
    assert agent_logger._take_dispatch_time_for_agent("") is None
    assert agent_logger._take_dispatch_time_for_agent("stride") == 1000.0


# ---------------------------------------------------------------------------
# 5. Abuse-case matcher — a shared CWE family is not evidence of a mechanism
# ---------------------------------------------------------------------------


def _finding(fid: str, cwe: str, title: str) -> dict:
    return {"id": fid, "cwe": cwe, "title": title, "evidence": {"file": f"{fid}.ts", "line": 1}}


def _role_step() -> dict:
    """The juice-shop AC-T-003 step 2 shape: code patterns plus a broad CWE
    family alternation."""
    return {
        "step": 2,
        "label": "Role claim trusted from token without re-fetch",
        "required": False,
        "finding": {"cwe": "CWE-863"},
        "probe": {"sink_patterns": [r"token\.role", r"req\.user\.role", "CWE-(863|862|266|269)"]},
    }


def test_family_only_tie_does_not_bind_an_unrelated_finding():
    """Four same-family findings tied; list order picked a chatbot coupon bug
    as evidence for a role-claim step, and the verifier burned its budget."""
    findings = [
        _finding("T-016", "CWE-862", "Discount Cap Bypass via Prompt Injection"),
        _finding("T-050", "CWE-862", "Sensitive Routes Without Auth Middleware"),
        _finding("T-075", "CWE-862", "Write-All GITHUB_TOKEN"),
    ]
    result = mac.match_step(_role_step(), findings)
    assert result["matched_finding_id"] is None


def test_the_steps_own_cwe_wins_a_family_tie():
    """A finding carrying exactly the CWE the chain step declares IS the
    intended target and must still bind — juice-shop AC-T-002 step 1."""
    findings = [
        _finding("T-016", "CWE-862", "Discount Cap Bypass"),
        _finding("T-009", "CWE-863", "Authorization trusts an unrefreshed role claim"),
        _finding("T-050", "CWE-862", "Sensitive Routes Without Auth"),
    ]
    result = mac.match_step(_role_step(), findings)
    assert result["matched_finding_id"] == "T-009"


def test_mechanism_evidence_still_binds_a_single_family_member():
    """One family member whose text carries the step's code shape is not
    ambiguous — it is the match."""
    findings = [
        _finding("T-016", "CWE-862", "Discount Cap Bypass"),
        {
            "id": "T-040",
            "cwe": "CWE-862",
            "title": "Role read from token",
            # `scenario` is one of the fields _finding_text actually scans.
            "scenario": "handler reads req.user.role directly",
            "evidence": {"file": "a.ts", "line": 2},
        },
    ]
    result = mac.match_step(_role_step(), findings)
    assert result["matched_finding_id"] == "T-040"


def test_single_family_match_is_not_treated_as_ambiguous():
    findings = [_finding("T-016", "CWE-862", "Discount Cap Bypass")]
    assert mac.match_step(_role_step(), findings)["matched_finding_id"] == "T-016"


# ---------------------------------------------------------------------------
# 6. Source probe — must not quote the assessment's own output back at itself
# ---------------------------------------------------------------------------


def test_source_probe_ignores_the_assessment_output_directory(tmp_path: Path):
    """The probe returned a line out of docs/security/.abuse-case-matches.json
    as source evidence for a role-claim sink."""
    (tmp_path / "docs" / "security").mkdir(parents=True)
    (tmp_path / "docs" / "security" / ".abuse-case-matches.json").write_text(
        '{"rationale": "lets the actor self-elevate via req.user.role"}\n', encoding="utf-8"
    )
    step = {
        "step": 1,
        "label": "role claim",
        "probe": {"sink_patterns": [r"req\.user\.role"]},
    }
    assert mac._source_probe(step, tmp_path) is None


def test_source_probe_ignores_prose_only_patterns(tmp_path: Path):
    """An i18n bundle discussing "privilege escalation" is not a sink."""
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "ar_SA.json").write_text(
        '{"DESC": "attacks, including privilege escalation attacks."}\n', encoding="utf-8"
    )
    step = {"step": 1, "label": "role", "probe": {"sink_patterns": ["(?i)(role|privilege) escalation"]}}
    assert mac._source_probe(step, tmp_path) is None


def test_source_probe_still_finds_real_code(tmp_path: Path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "address.ts").write_text(
        "const a = await AddressModel.findOne({ where: { id: req.params.id } })\n", encoding="utf-8"
    )
    step = {"step": 1, "label": "idor", "probe": {"sink_patterns": [r"params\.id"]}}
    hit = mac._source_probe(step, tmp_path)
    assert hit and hit["file"] == "routes/address.ts"


def test_bare_code_identifiers_remain_probeable(tmp_path: Path):
    """`innerHTML` carries no regex escape but is still a code token."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "t.ts").write_text("render(innerHTML);\n", encoding="utf-8")
    step = {"step": 1, "label": "xss", "probe": {"sink_patterns": ["innerHTML"]}}
    hit = mac._source_probe(step, tmp_path)
    assert hit and hit["file"] == "src/t.ts"
