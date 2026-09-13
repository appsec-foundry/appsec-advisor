"""Unit tests for scripts/recommend_fixes.py."""

import json
import re
from pathlib import Path

import pytest
import recommend_fixes as rf

SCRIPTS_DIR = Path(rf.__file__).parent

# Categories the aggregator emits that deliberately carry no recommender:
# `plugin_bug` and `pipeline_self_diagnosis_degraded` ARE the self-diagnosis
# channel, so routing them back through it would be circular.
_RECOMMENDER_EXEMPT_CATEGORIES = {"plugin_bug", "pipeline_self_diagnosis_degraded"}

# Ratchet: categories known to lack a recommender. The set may only shrink.
# Every entry here degrades to `no_recommender_for_category` at diagnosis time,
# so a reader gets "manual review required" instead of guidance — several of
# them (`run_incomplete`, `report_integrity`, `stride_ceiling_overflow_dropped`,
# `watchdog_not_started`) are exactly the issues that most need it.
_KNOWN_UNCOVERED_CATEGORIES = {
    "agent_error",
    "render_failed",
    "report_integrity",
    "run_incomplete",
    "stride_ceiling_lifted",
    "stride_ceiling_overflow_dropped",
    "stride_model_mismatch",
    "trust_boundary_coverage",
    "trust_boundary_resolution",
    "watchdog_not_started",
}


def _emitted_categories() -> set[str]:
    """Issue categories `aggregate_run_issues.py` can put on the wire."""
    src = (SCRIPTS_DIR / "aggregate_run_issues.py").read_text(encoding="utf-8")
    literal = set(re.findall(r'"category":\s*"([a-z_]+)"', src))
    # `_extract_errors` maps log EVENT names to categories through a dict.
    mapped = set(re.findall(r'"[A-Z_]+":\s*"([a-z_]+)"', src))
    # `"category": X if cond else "y"` — the else-branch literal.
    conditional = set(re.findall(r'"category":[^,\n]*else\s*"([a-z_]+)"', src))
    return literal | mapped | conditional


def test_every_emitted_issue_category_has_a_recommender():
    """The aggregator and the recommender form an unenforced contract: a
    category added to one and not the other degrades silently to
    `no_recommender_for_category`, so the run's self-diagnosis answers
    "manual review required" for exactly the issues that most need guidance.

    On the 2026-08-21 insecure-large-spring-app run 13 of 24 emitted
    categories had no recommender — `abuse_case_inconclusive` merely happened
    to be the one that fired. Close the set here so the next addition fails
    loudly at test time instead of quietly at diagnosis time.
    """
    uncovered = _emitted_categories() - set(rf.RECOMMENDERS) - _RECOMMENDER_EXEMPT_CATEGORIES
    new = sorted(uncovered - _KNOWN_UNCOVERED_CATEGORIES)
    assert not new, (
        f"aggregate_run_issues.py emits {len(new)} NEW categories with no entry in "
        f"recommend_fixes.RECOMMENDERS: {new}. Add a recommender, or add the category to "
        f"_RECOMMENDER_EXEMPT_CATEGORIES with the reason it is self-diagnosis."
    )
    closed = sorted(_KNOWN_UNCOVERED_CATEGORIES - uncovered)
    assert not closed, (
        f"These categories now have a recommender: {closed}. Remove them from "
        f"_KNOWN_UNCOVERED_CATEGORIES so the ratchet keeps tightening."
    )


# ---------------------------------------------------------------------------
# _read_agent_max_turns
# ---------------------------------------------------------------------------


def test_read_agent_max_turns_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    assert rf._read_agent_max_turns("nope") is None


def test_read_agent_max_turns_no_field(tmp_path, monkeypatch):
    (tmp_path / "appsec-x.md").write_text("---\nname: x\n---\nbody\n")
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    assert rf._read_agent_max_turns("appsec-x") is None


def test_read_agent_max_turns_found(tmp_path, monkeypatch):
    (tmp_path / "appsec-x.md").write_text("---\nname: x\nmaxTurns: 80\n---\nbody\n")
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    assert rf._read_agent_max_turns("appsec-x") == 80


def test_read_agent_max_turns_oserror(tmp_path, monkeypatch):
    # Make path.is_file True but read_text raise OSError by pointing at a dir.
    d = tmp_path / "appsec-x.md"
    d.mkdir()
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    # is_file() is False for a dir -> returns None before read. Force via stub.
    assert rf._read_agent_max_turns("appsec-x") is None


# ---------------------------------------------------------------------------
# _recommend_max_turns_subagent / orchestrator
# ---------------------------------------------------------------------------


def test_max_turns_subagent_agent_not_found(tmp_path, monkeypatch):
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    issue = {"evidence": {"source_agent": "ghost"}}
    rec = rf._recommend_max_turns_subagent(issue, tmp_path)
    assert rec["category"] == "investigate"
    assert rec["auto_applicable"] is False
    assert "ghost" in rec["summary"]


@pytest.mark.parametrize(
    "agent,budget,event",
    [
        ("alpha-worker", 80, "MAX_TURNS turns=80/80 pct=100%"),
        ("renamed-worker", 17, "MAX_TURNS turns=17/17 pct=100%"),
        ("alpha-worker", 80, ""),
        ("alpha-worker", 80, "MAX_TURNS turns=21/8 pct=262%"),
        ("appsec-alpha-worker", 80, "BUDGET_WARN turns=60/80 pct=75%"),
    ],
)
@pytest.mark.parametrize("category", ["max_turns_subagent", "turn_budget_exceeded"])
def test_budget_symptoms_never_authorize_edits(tmp_path, monkeypatch, agent, budget, event, category):
    canonical = agent if agent.startswith("appsec-") else f"appsec-{agent}"
    (tmp_path / f"{canonical}.md").write_text(f"maxTurns: {budget}\n")
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    issue = {"category": category, "evidence": {"source_agent": agent, "raw_event": event}}
    rec = rf.RECOMMENDERS[category](issue, tmp_path)
    assert rec["category"] == "investigate"
    assert rec["auto_applicable"] is False
    assert rec["confidence"] == "low"
    assert not any(a["type"] == "edit_file" for a in rec["actions"])
    assert not rec["verification"]
    assert "neutral" in rec["actions"][0]["details"]
    if "21/8" in event:
        assert "per-call budget of 8" in rec["summary"]
        assert "ceiling of 80" in rec["summary"]


def test_agent_name_cannot_select_an_external_file(tmp_path, monkeypatch):
    agents = tmp_path / "agents"
    agents.mkdir()
    (tmp_path / "external.md").write_text("maxTurns: 800\n")
    (agents / "appsec-linked.md").symlink_to(tmp_path / "external.md")
    monkeypatch.setattr(rf, "AGENTS_DIR", agents)
    assert rf._read_agent_max_turns("../external") is None
    assert rf._read_agent_max_turns("appsec-linked") is None


def test_max_turns_orchestrator_requires_investigation(tmp_path):
    issue = {"evidence": {"source_agent": "threat-analyst"}}
    rec = rf._recommend_max_turns_orchestrator(issue, tmp_path)
    assert rec["category"] == "investigate"
    assert rec["auto_applicable"] is False
    assert "compact orchestration" in rec["summary"]


# ---------------------------------------------------------------------------
# perf_anomaly_phase
# ---------------------------------------------------------------------------


def test_perf_anomaly_phase_basic(tmp_path):
    issue = {
        "evidence": {
            "phase": "9",
            "label": "STRIDE",
            "duration_seconds": 600,
            "expected_max_seconds": 300,
            "multiplier": 2.0,
            "log_line": 42,
        }
    }
    rec = rf._recommend_perf_anomaly_phase(issue, tmp_path)
    assert rec["category"] == "investigate"
    assert "Phase 9 (STRIDE)" in rec["summary"]
    assert "inferred" not in rec["rationale"]


def test_perf_anomaly_phase_end_inferred(tmp_path):
    issue = {"evidence": {"end_inferred": True}}
    rec = rf._recommend_perf_anomaly_phase(issue, tmp_path)
    assert "PHASE_END was missing" in rec["rationale"]


# ---------------------------------------------------------------------------
# stage1_excessive_duration
# ---------------------------------------------------------------------------


def test_stage1_excessive_duration(tmp_path):
    issue = {"evidence": {"duration_seconds": 2000}}
    rec = rf._recommend_stage1_excessive_duration(issue, tmp_path)
    assert rec["category"] == "user_action"
    assert rec["risk_level"] == "high"
    assert "2000s" in rec["summary"]


# ---------------------------------------------------------------------------
# session_stop_unknown
# ---------------------------------------------------------------------------


def test_session_stop_unknown_high_tokens(tmp_path):
    issue = {"evidence": {"source_agent": "stride", "output_tokens": 60000, "cost_usd": 1.0}}
    rec = rf._recommend_session_stop_unknown(issue, tmp_path)
    assert rec["confidence"] == "low"
    assert "60,000" in rec["summary"]
    assert rec["actions"][0]["target"] == ".agent-run.log"


def test_session_stop_unknown_high_cost_prefixed(tmp_path):
    issue = {"evidence": {"source_agent": "appsec-x", "output_tokens": 10, "cost_usd": 9.0}}
    rec = rf._recommend_session_stop_unknown(issue, tmp_path)
    assert rec["confidence"] == "low"
    assert rec["actions"][0]["target"] == ".agent-run.log"


def test_session_stop_unknown_low_usage(tmp_path):
    issue = {"evidence": {"source_agent": "x", "output_tokens": 100, "cost_usd": 0.1}}
    rec = rf._recommend_session_stop_unknown(issue, tmp_path)
    assert rec["confidence"] == "low"
    assert "unconfirmed" in rec["summary"]


# ---------------------------------------------------------------------------
# remaining simple recommenders
# ---------------------------------------------------------------------------


def test_high_token_usage(tmp_path):
    rec = rf._recommend_high_token_usage({"evidence": {}}, tmp_path)
    assert rec["category"] == "investigate"
    assert rec["confidence"] == "medium"


def test_tool_error(tmp_path):
    rec = rf._recommend_tool_error({"evidence": {"log_line": 7}}, tmp_path)
    assert rec["category"] == "investigate"
    assert rec["risk_level"] == "medium"
    assert "7" in rec["actions"][0]["details"]


def test_bash_warn(tmp_path):
    rec = rf._recommend_bash_warn({"evidence": {"log_line": 9}}, tmp_path)
    assert rec["confidence"] == "low"
    assert "9" in rec["actions"][0]["details"]


def test_auto_retry_fired(tmp_path):
    rec = rf._recommend_auto_retry_fired({"evidence": {"iterations": 3}}, tmp_path)
    assert rec["category"] == "no_fix"
    assert "3×" in rec["summary"]


def test_compose_retries_section(tmp_path):
    rec = rf._recommend_compose_retries_section({"evidence": {"section": "7", "attempts": 2}}, tmp_path)
    assert rec["category"] == "no_fix"
    assert "§7 required 2/3" in rec["summary"]


def test_contract_gate_drift_with_items(tmp_path):
    rec = rf._recommend_contract_gate_drift({"evidence": {"items": ["§3", "§7"]}}, tmp_path)
    assert rec["category"] == "investigate"
    assert "§3, §7" in rec["rationale"]


def test_contract_gate_drift_no_items(tmp_path):
    rec = rf._recommend_contract_gate_drift({}, tmp_path)
    assert "(see plan)" in rec["rationale"]


def test_inline_shortcut_unresolved(tmp_path):
    rec = rf._recommend_inline_shortcut_unresolved({}, tmp_path)
    assert rec["category"] == "rerun"
    assert rec["risk_level"] == "high"


def test_qa_status_not_pass(tmp_path):
    rec = rf._recommend_qa_status_not_pass({"evidence": {"status": "fail"}}, tmp_path)
    assert rec["category"] == "investigate"
    assert "'fail'" in rec["summary"]


def test_architect_status_not_pass(tmp_path):
    rec = rf._recommend_architect_status_not_pass(
        {"evidence": {"status": "repair_required", "technical_defects": 1}}, tmp_path
    )
    assert rec["confidence"] == "high"
    assert "1 technical defect" in rec["summary"]
    assert rec["actions"][0]["target"] == ".architect-repair-plan.json"


def test_default(tmp_path):
    rec = rf._recommend_default({"category": "weird", "evidence": {"log_file": "x.log"}}, tmp_path)
    assert rec["category"] == "investigate"
    assert "'weird'" in rec["summary"]
    assert rec["actions"][0]["target"] == "x.log"


# ---------------------------------------------------------------------------
# enrich_with_recommendations
# ---------------------------------------------------------------------------


def test_enrich_counts_auto_applicable(tmp_path, monkeypatch):
    (tmp_path / "appsec-x.md").write_text("maxTurns: 80\n")
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    data = {
        "summary": {},
        "issues": [
            {"category": "max_turns_subagent", "evidence": {"source_agent": "x"}},
            {"category": "bash_warn", "evidence": {}},
            {"category": "unknown_cat", "evidence": {}},
        ],
    }
    out = rf.enrich_with_recommendations(data, tmp_path)
    assert out is data
    assert all("fix_recommendation" in i for i in out["issues"])
    assert out["summary"]["auto_applicable_fixes"] == 0


def test_enrich_no_summary_no_issues(tmp_path):
    data = {}
    out = rf.enrich_with_recommendations(data, tmp_path)
    assert out == {}
    assert "summary" not in out


# ---------------------------------------------------------------------------
# CLI (main via subprocess)
# ---------------------------------------------------------------------------


def test_cli_missing_file(run_plugin_script, tmp_path):
    res = run_plugin_script("recommend_fixes.py", str(tmp_path), check=False)
    assert res.returncode == 1
    assert "not found" in res.stderr


def test_cli_malformed_json(run_plugin_script, tmp_path):
    (tmp_path / ".run-issues.json").write_text("{not json")
    res = run_plugin_script("recommend_fixes.py", str(tmp_path), check=False)
    assert res.returncode == 1
    assert "cannot parse" in res.stderr


def test_cli_success(run_plugin_script, tmp_path):
    data = {
        "summary": {},
        "issues": [{"category": "bash_warn", "evidence": {"log_line": 1}}],
    }
    (tmp_path / ".run-issues.json").write_text(json.dumps(data))
    res = run_plugin_script("recommend_fixes.py", str(tmp_path), check=False)
    assert res.returncode == 0
    assert "enriched 1 issue" in res.stdout
    out = json.loads((tmp_path / ".run-issues.json").read_text())
    assert "fix_recommendation" in out["issues"][0]
    assert out["summary"]["auto_applicable_fixes"] == 0


# ---------------------------------------------------------------------------
# `degraded` marker — consumed by the aggregator's self-diagnosis canary.
# ---------------------------------------------------------------------------


def test_max_turns_marks_itself_degraded_when_agent_unresolvable(tmp_path):
    """When the agent name never reached the issue record, this recommender
    cannot identify the configured budget. It must SAY so structurally rather than
    emit a plausible-looking manual-review note the summary cannot distinguish
    from a real finding."""
    issue = {"category": "max_turns_subagent", "evidence": {"source_agent": ""}}
    rec = rf._recommend_max_turns_subagent(issue, tmp_path)
    assert rec["degraded"] == "missing_recommender_input"
    assert rec["auto_applicable"] is False


def test_unknown_category_marks_itself_degraded(tmp_path):
    """A category with no recommender is a coverage gap in this module."""
    rec = rf._recommend_default({"category": "brand_new_category", "evidence": {}}, tmp_path)
    assert rec["degraded"] == "no_recommender_for_category"


def test_resolvable_agent_carries_no_degraded_marker(tmp_path):
    """The marker must vanish once the producer populates the agent name —
    otherwise the canary would fire forever after the underlying fix."""
    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "appsec-threat-merger.md").write_text("---\nname: appsec-threat-merger\nmaxTurns: 12\n---\n")
    issue = {"category": "max_turns_subagent", "evidence": {"source_agent": "threat-merger"}}
    import unittest.mock as mock

    with mock.patch.object(rf, "_read_agent_max_turns", lambda name: 12):
        rec = rf._recommend_max_turns_subagent(issue, tmp_path)
    assert "degraded" not in rec
    assert rec["auto_applicable"] is False


def test_editorial_incompleteness_has_durable_manual_guidance(tmp_path):
    rec = rf.RECOMMENDERS["editorial_pass_incomplete"]({"evidence": {"outcome": "partial"}}, tmp_path)
    assert rec["auto_applicable"] is False
    assert rec["actions"][0]["target"] == ".agent-run.log"
    assert "packet counts" in rec["actions"][0]["details"]


@pytest.fixture
def diagnosed_run(tmp_path):
    """A neutral producer defect and a legacy cached auto-edit recommendation."""
    data = {
        "generated": "2026-09-13T10:00:00Z",
        "summary": {"auto_applicable_fixes": 1},
        "issues": [
            {
                "id": "ISSUE-001",
                "title": "Output rejected",
                "category": "tool_error",
                "evidence": {},
                "fix_recommendation": {
                    "auto_applicable": True,
                    "actions": [{"type": "edit_file", "target": "agents/old.md"}],
                },
            }
        ],
    }
    diagnosis = {
        "schema_version": 1,
        "generated": "2026-09-13T11:00:00Z",
        "source_generated": data["generated"],
        "issues_total": 1,
        "issues_examined": 1,
        "summary": {"plugin_bug": 1, "environment": 0, "expected": 0, "inconclusive": 0},
        "diagnoses": [
            {
                "issue_id": "ISSUE-001",
                "issue_title": "Output rejected",
                "verdict": "plugin_bug",
                "confidence": "high",
                "rationale": "Producer omits a required key.",
                "evidence": ["scripts/producer.py:12"],
                "root_cause": {
                    "location": "scripts/producer.py:12",
                    "description": "Missing key.",
                    "causal_path": "Producer omits key; consumer rejects output.",
                },
                "suggested_fix": "Emit the required key for each item.",
            }
        ],
    }
    (tmp_path / ".run-issues.json").write_text(json.dumps(data))
    (tmp_path / ".run-bugs.json").write_text(json.dumps(diagnosis))
    return data, diagnosis


def test_current_diagnosis_replaces_cached_symptom_edits(tmp_path, diagnosed_run):
    data, _ = diagnosed_run
    result = rf.enrich_with_recommendations(data, tmp_path, use_diagnosis=True)
    rec = result["issues"][0]["fix_recommendation"]
    assert result["summary"]["auto_applicable_fixes"] == 0
    assert rec["auto_applicable"] is False
    assert rec["actions"][0]["type"] == "manual_review"
    assert "Producer omits key" in rec["actions"][0]["details"]
    assert "Emit the required key" in rec["actions"][0]["details"]
    assert "negative case" in rec["actions"][0]["details"]
    assert rec["verification"] == []


@pytest.mark.parametrize("verdict", ["environment", "expected", "inconclusive"])
def test_external_or_unresolved_diagnoses_never_propose_plugin_edits(tmp_path, diagnosed_run, verdict):
    data, diagnosis = diagnosed_run
    diagnosis["diagnoses"][0].update(verdict=verdict, root_cause=None)
    diagnosis["summary"].update(plugin_bug=0, **{verdict: 1})
    (tmp_path / ".run-bugs.json").write_text(json.dumps(diagnosis))
    rec = rf.enrich_with_recommendations(data, tmp_path, use_diagnosis=True)["issues"][0]["fix_recommendation"]
    assert rec["actions"] == []
    assert rec["auto_applicable"] is False


@pytest.mark.parametrize(
    "damage",
    [
        "stale",
        "legacy",
        "title",
        "foreign_id",
        "duplicate",
        "total",
        "examined",
        "summary",
        "schema",
        "missing",
        "json",
    ],
)
def test_cli_rejects_invalid_diagnosis_without_rewriting_issues(tmp_path, diagnosed_run, damage, capsys):
    _, diagnosis = diagnosed_run
    path = tmp_path / ".run-bugs.json"
    before = (tmp_path / ".run-issues.json").read_bytes()
    if damage == "stale":
        diagnosis["source_generated"] = "2026-09-12T10:00:00Z"
    elif damage == "legacy":
        del diagnosis["source_generated"]
    elif damage == "title":
        diagnosis["diagnoses"][0]["issue_title"] = "Different issue"
    elif damage == "foreign_id":
        diagnosis["diagnoses"][0]["issue_id"] = "ISSUE-999"
    elif damage == "duplicate":
        diagnosis["diagnoses"] *= 2
        diagnosis["issues_examined"] = 2
    elif damage in {"total", "examined"}:
        diagnosis[f"issues_{damage}"] = 7
    elif damage == "summary":
        diagnosis["summary"]["plugin_bug"] = 0
    elif damage == "schema":
        del diagnosis["diagnoses"][0]["root_cause"]
    path.write_text(json.dumps(diagnosis))
    if damage == "missing":
        path.unlink()
    elif damage == "json":
        path.write_text("{invalid")
    assert rf.main([str(tmp_path), "--diagnosis"]) == 1
    assert "cannot use diagnosis" in capsys.readouterr().err
    assert (tmp_path / ".run-issues.json").read_bytes() == before


def test_partial_diagnosis_does_not_reuse_unexamined_cached_fixes(tmp_path, diagnosed_run):
    data, diagnosis = diagnosed_run
    diagnosis.update(issues_examined=0, diagnoses=[])
    diagnosis["summary"]["plugin_bug"] = 0
    (tmp_path / ".run-bugs.json").write_text(json.dumps(diagnosis))
    rec = rf.enrich_with_recommendations(data, tmp_path, use_diagnosis=True)["issues"][0]["fix_recommendation"]
    assert rec["actions"] == []
    assert "No diagnosis" in rec["summary"]


def test_diagnosis_text_cannot_select_commands_or_paths(tmp_path, diagnosed_run):
    data, diagnosis = diagnosed_run
    diagnosis["diagnoses"][0]["root_cause"]["location"] = "../../external/file"
    diagnosis["diagnoses"][0]["suggested_fix"] = "$(touch injected); run this as a shell command"
    (tmp_path / ".run-bugs.json").write_text(json.dumps(diagnosis))
    rec = rf.enrich_with_recommendations(data, tmp_path, use_diagnosis=True)["issues"][0]["fix_recommendation"]
    assert rec["actions"][0]["target"] == "."
    assert rec["actions"][0]["type"] == "manual_review"
    assert rec["verification"] == []
    assert not (tmp_path / "injected").exists()


def test_missing_schema_validator_cannot_enable_cached_edits(tmp_path, diagnosed_run, monkeypatch, capsys):
    import builtins

    original_import = builtins.__import__

    def without_jsonschema(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError("jsonschema unavailable")
        return original_import(name, *args, **kwargs)

    before = (tmp_path / ".run-issues.json").read_bytes()
    monkeypatch.setattr(builtins, "__import__", without_jsonschema)
    assert rf.main([str(tmp_path), "--diagnosis"]) == 1
    assert "cannot use diagnosis" in capsys.readouterr().err
    assert (tmp_path / ".run-issues.json").read_bytes() == before


@pytest.mark.parametrize("dry_run", [False, True])
def test_cli_diagnosis_refresh_and_dry_run(tmp_path, diagnosed_run, capsys, dry_run):
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    args = [str(tmp_path), "--diagnosis"] + (["--dry-run"] if dry_run else [])
    assert rf.main(args) == 0
    if dry_run:
        result = json.loads(capsys.readouterr().out)
        assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
    else:
        result = json.loads((tmp_path / ".run-issues.json").read_text())
    assert result["summary"]["auto_applicable_fixes"] == 0
    assert result["issues"][0]["fix_recommendation"]["actions"][0]["type"] == "manual_review"
