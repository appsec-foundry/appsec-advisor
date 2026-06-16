"""Unit tests for scripts/recommend_fixes.py."""

import json

import recommend_fixes as rf

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


def test_max_turns_subagent_found(tmp_path, monkeypatch):
    (tmp_path / "appsec-stride-analyzer.md").write_text("maxTurns: 80\n")
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    issue = {"evidence": {"source_agent": "stride-analyzer"}}
    rec = rf._recommend_max_turns_subagent(issue, tmp_path)
    assert rec["category"] == "agent_def"
    assert rec["auto_applicable"] is True
    assert rec["confidence"] == "high"
    # 80 -> max(85, 120) == 120
    assert "80 → 120" in rec["summary"]
    assert rec["actions"][0]["find"] == "maxTurns: 80"
    assert rec["actions"][0]["replace"] == "maxTurns: 120"


def test_max_turns_subagent_already_prefixed(tmp_path, monkeypatch):
    (tmp_path / "appsec-foo.md").write_text("maxTurns: 10\n")
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    issue = {"evidence": {"source_agent": "appsec-foo"}}
    rec = rf._recommend_max_turns_subagent(issue, tmp_path)
    # 10 -> max(15, 15) == 15
    assert "10 → 15" in rec["summary"]


def test_max_turns_orchestrator_delegates(tmp_path, monkeypatch):
    (tmp_path / "appsec-threat-analyst.md").write_text("maxTurns: 75\n")
    monkeypatch.setattr(rf, "AGENTS_DIR", tmp_path)
    issue = {"evidence": {"source_agent": "threat-analyst"}}
    rec = rf._recommend_max_turns_orchestrator(issue, tmp_path)
    assert rec["category"] == "agent_def"
    assert "75 → 112" in rec["summary"]


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
    assert rec["confidence"] == "high"
    assert "60,000" in rec["summary"]
    assert rec["actions"][0]["target"] == "agents/appsec-stride.md"


def test_session_stop_unknown_high_cost_prefixed(tmp_path):
    issue = {"evidence": {"source_agent": "appsec-x", "output_tokens": 10, "cost_usd": 9.0}}
    rec = rf._recommend_session_stop_unknown(issue, tmp_path)
    assert rec["confidence"] == "high"
    assert rec["actions"][0]["target"] == "agents/appsec-x.md"


def test_session_stop_unknown_low_usage(tmp_path):
    issue = {"evidence": {"source_agent": "x", "output_tokens": 100, "cost_usd": 0.1}}
    rec = rf._recommend_session_stop_unknown(issue, tmp_path)
    assert rec["confidence"] == "low"
    assert "normal" in rec["summary"]


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
    assert out["summary"]["auto_applicable_fixes"] == 1


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
