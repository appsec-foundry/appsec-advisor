"""Unit tests for scripts/verify_run_costs.py.

Covers parsing (SESSION_STOP, ASSESSMENT_TOKENS, AGENT_SPAWN), run-window
detection, delta aggregation, cross-check, sub-agent estimate signals,
calibration read/write, model detection/normalization, the verbose printer,
and the CLI (--json / --actual-cost / error paths).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import verify_run_costs as vrc

SONNET = vrc.PRICING_MODELS["sonnet-4-6"]


# ---------------------------------------------------------------------------
# Log-line builders matching the module's regexes
# ---------------------------------------------------------------------------
def session_stop(ts: str, sid: str, *, in_=0, out=0, cw=0, cr=0, cost=None) -> str:
    line = f"{ts} [{sid}] INFO SESSION_STOP in={in_:,} out={out:,} cache_write={cw:,} cache_read={cr:,}"
    if cost is not None:
        line += f" cost=${cost}"
    return line + "\n"


def agent_spawn(ts: str, sid: str, agent: str) -> str:
    return f"{ts} [{sid}] INFO AGENT_SPAWN {agent}\n"


def assessment_tokens(ts: str, sid: str, *, inp, out, cw, cr, cost, fresh=None) -> str:
    line = f"{ts} [{sid}] INFO ASSESSMENT_TOKENS throughput=100 input={inp:,} output={out:,}"
    if fresh is not None:
        line += f" (input split: fresh={fresh:,} cache_write={cw:,} cache_read={cr:,})"
    else:
        line += f" cache_write={cw:,} cache_read={cr:,}"
    line += f" cost=${cost}\n"
    return line


def write_logs(d: Path, hook_lines: list[str] = None, agent_lines: list[str] = None) -> None:
    if hook_lines is not None:
        (d / ".hook-events.log").write_text("".join(hook_lines), encoding="utf-8")
    if agent_lines is not None:
        (d / ".agent-run.log").write_text("".join(agent_lines), encoding="utf-8")


# ===========================================================================
# TokenSnapshot
# ===========================================================================
class TestTokenSnapshot:
    def test_total_and_subtract_and_as_dict(self):
        a = vrc.TokenSnapshot(10, 20, 30, 40, cost=1.5)
        assert a.total() == 100
        b = vrc.TokenSnapshot(1, 2, 3, 4, cost=0.5)
        d = a.subtract(b)
        assert (d.in_tokens, d.out_tokens, d.cache_write, d.cache_read) == (9, 18, 27, 36)
        assert d.cost == 1.0
        dd = a.as_dict()
        assert dd["in"] == 10 and dd["cost"] == 1.5


# ===========================================================================
# Pricing helpers
# ===========================================================================
class TestPricing:
    def test_calc_cost(self):
        snap = vrc.TokenSnapshot(in_tokens=1_000_000, out_tokens=1_000_000, cache_write=1_000_000, cache_read=1_000_000)
        # 3 + 15 + 3.75 + 0.30
        assert vrc.calc_cost(snap, SONNET) == pytest.approx(22.05)

    def test_calc_no_cache_cost(self):
        snap = vrc.TokenSnapshot(in_tokens=1_000_000, out_tokens=0, cache_write=1_000_000, cache_read=1_000_000)
        # all 3M input as regular input at $3/M
        assert vrc.calc_no_cache_cost(snap, SONNET) == pytest.approx(9.0)

    def test_load_plugin_pricing_no_root(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)
        assert vrc._load_plugin_pricing() is None

    def test_load_plugin_pricing_missing_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        assert vrc._load_plugin_pricing() is None

    def test_load_plugin_pricing_from_config(self, monkeypatch, tmp_path):
        (tmp_path / "config.json").write_text(json.dumps({"pricing": {"input_per_1m": 9.9}}))
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        p = vrc._load_plugin_pricing()
        assert p["input"] == 9.9 and p["output"] == 15.00

    def test_load_plugin_pricing_local_overrides(self, monkeypatch, tmp_path):
        (tmp_path / "config.json").write_text(json.dumps({"pricing": {"input_per_1m": 1.0}}))
        (tmp_path / "config.local.json").write_text(json.dumps({"pricing": {"input_per_1m": 2.0}}))
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        assert vrc._load_plugin_pricing()["input"] == 2.0

    def test_load_plugin_pricing_no_pricing_key(self, monkeypatch, tmp_path):
        (tmp_path / "config.json").write_text(json.dumps({"other": 1}))
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        assert vrc._load_plugin_pricing() is None

    def test_load_plugin_pricing_bad_json(self, monkeypatch, tmp_path):
        (tmp_path / "config.json").write_text("{not json")
        monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path))
        assert vrc._load_plugin_pricing() is None


# ===========================================================================
# Parsing
# ===========================================================================
class TestParsing:
    def test_parse_session_stops(self, tmp_path):
        log = tmp_path / "h.log"
        log.write_text(
            session_stop("2026-01-01T00:00:00Z", "aaa111", in_=100, out=50, cw=200, cr=300, cost=1.23)
            + "noise line\n"
            + session_stop("2026-01-01T00:01:00Z", "aaa111", in_=200, cost=2.0)
        )
        entries = vrc.parse_session_stops(log)
        assert len(entries) == 2
        assert entries[0].snapshot.in_tokens == 100
        assert entries[0].snapshot.cost == 1.23

    def test_parse_session_stops_skips_no_usage(self, tmp_path):
        log = tmp_path / "h.log"
        log.write_text(
            "2026-01-01T00:00:00Z [aaa111] INFO SESSION_STOP cost=n/a\n"
            "2026-01-01T00:00:01Z [bbb222] INFO SESSION_STOP no usage data\n"
        )
        assert vrc.parse_session_stops(log) == []

    def test_parse_assessment_tokens_with_fresh(self, tmp_path):
        log = tmp_path / "h.log"
        log.write_text(
            assessment_tokens("2026-01-01T00:00:00Z", "aaa", inp=5000, out=100, cw=200, cr=300, cost=0.9, fresh=400)
        )
        entries = vrc.parse_assessment_tokens(log)
        assert len(entries) == 1
        e = entries[0]
        assert e.snapshot.in_tokens == 400  # fresh override
        assert e.total_input_reported == 5000
        assert e.snapshot.cost == 0.9

    def test_parse_assessment_tokens_no_fresh(self, tmp_path):
        log = tmp_path / "h.log"
        log.write_text(assessment_tokens("2026-01-01T00:00:00Z", "aaa", inp=5000, out=100, cw=200, cr=300, cost=0.9))
        e = vrc.parse_assessment_tokens(log)[0]
        assert e.snapshot.in_tokens == 5000


# ===========================================================================
# Run window detection
# ===========================================================================
class TestRunWindow:
    def test_basic_start_end(self, tmp_path):
        agent = tmp_path / "a.log"
        hook = tmp_path / "h.log"
        agent.write_text("2026-01-01T00:00:00Z INFO ASSESSMENT_START\n2026-01-01T00:30:00Z INFO ASSESSMENT_END\n")
        hook.write_text("")
        start, end = vrc.find_run_window(agent, hook)
        assert start == "2026-01-01T00:00:00Z"
        # end + 180s buffer
        assert end == "2026-01-01T00:33:00Z"

    def test_end_uses_max_of_qa_arch(self, tmp_path):
        agent = tmp_path / "a.log"
        hook = tmp_path / "h.log"
        agent.write_text(
            "2026-01-01T00:00:00Z INFO ASSESSMENT_START\n"
            "2026-01-01T00:10:00Z INFO ASSESSMENT_END\n"
            "2026-01-01T00:20:00Z appsec-qa-reviewer CHECK_END\n"
            "2026-01-01T00:25:00Z appsec-architect-reviewer STEP_END\n"
        )
        hook.write_text("")
        _, end = vrc.find_run_window(agent, hook)
        assert end == "2026-01-01T00:28:00Z"  # 00:25 + 180s

    def test_start_pulled_back_by_spawn(self, tmp_path):
        agent = tmp_path / "a.log"
        hook = tmp_path / "h.log"
        agent.write_text("2026-01-01T00:10:00Z INFO ASSESSMENT_START\n")
        # spawn 5 min before start, within 30-min window
        hook.write_text(agent_spawn("2026-01-01T00:05:00Z", "51d1", "orchestrator"))
        start, _ = vrc.find_run_window(agent, hook)
        # earliest spawn 00:05:00 minus 5s
        assert start == "2026-01-01T00:04:55Z"

    def test_fallback_scan_start_from_hook(self, tmp_path):
        agent = tmp_path / "a.log"
        hook = tmp_path / "h.log"
        agent.write_text("nothing relevant\n")
        hook.write_text("2026-01-01T00:00:00Z INFO SCAN_START\n")
        start, end = vrc.find_run_window(agent, hook)
        assert start == "2026-01-01T00:00:00Z"
        assert end is None

    def test_missing_agent_log(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text("")
        start, end = vrc.find_run_window(tmp_path / "missing.log", hook)
        assert start is None and end is None


# ===========================================================================
# Duration
# ===========================================================================
class TestDuration:
    def test_run_duration(self, tmp_path):
        agent = tmp_path / "a.log"
        agent.write_text("2026-01-01T00:00:00Z INFO ASSESSMENT_START\n2026-01-01T00:40:00Z INFO ASSESSMENT_END\n")
        assert vrc._run_duration_seconds(agent, None, None) == 2400

    def test_run_duration_missing_file(self, tmp_path):
        assert vrc._run_duration_seconds(tmp_path / "no.log", None, None) is None

    def test_run_duration_no_start(self, tmp_path):
        agent = tmp_path / "a.log"
        agent.write_text("2026-01-01T00:40:00Z INFO ASSESSMENT_END\n")
        assert vrc._run_duration_seconds(agent, None, None) is None

    def test_run_duration_end_before_start(self, tmp_path):
        agent = tmp_path / "a.log"
        agent.write_text("2026-01-01T00:40:00Z INFO ASSESSMENT_START\n2026-01-01T00:10:00Z INFO AGENT_END\n")
        assert vrc._run_duration_seconds(agent, None, None) is None


# ===========================================================================
# Calibration
# ===========================================================================
class TestCalibration:
    def test_load_calibration_missing(self, tmp_path):
        assert vrc._load_calibration(tmp_path) == {}

    def test_load_calibration_bad_json(self, tmp_path):
        d = tmp_path / ".appsec-cache"
        d.mkdir()
        (d / vrc._CALIBRATION_FILE).write_text("{bad")
        assert vrc._load_calibration(tmp_path) == {}

    def test_save_actual_cost_calibration(self, tmp_path):
        vrc.save_actual_cost_calibration(tmp_path, "standard-sonnet", 10.0, 2.0)
        data = vrc._load_calibration(tmp_path)
        assert data["standard-sonnet"]["samples"] == [5.0]
        assert data["standard-sonnet"]["n"] == 1

    def test_save_actual_cost_calibration_zero_host(self, tmp_path):
        vrc.save_actual_cost_calibration(tmp_path, "k", 10.0, 0.0)
        assert vrc._load_calibration(tmp_path) == {}

    def test_save_calibration_rolling_window(self, tmp_path):
        for i in range(vrc._CALIBRATION_MAX_SAMPLES + 3):
            vrc.save_actual_cost_calibration(tmp_path, "k", float(i + 1), 1.0)
        data = vrc._load_calibration(tmp_path)
        assert data["k"]["n"] == vrc._CALIBRATION_MAX_SAMPLES

    def test_get_multiplier_default(self, tmp_path):
        mult, src = vrc._get_multiplier("standard-sonnet", tmp_path)
        assert mult == 4.7 and src == "default"

    def test_get_multiplier_unknown_key_falls_back(self, tmp_path):
        mult, src = vrc._get_multiplier("nonexistent-key", tmp_path)
        assert mult == 4.7 and src == "default"

    def test_get_multiplier_calibrated(self, tmp_path):
        d = tmp_path / ".appsec-cache"
        d.mkdir()
        (d / vrc._CALIBRATION_FILE).write_text(json.dumps({"k": {"average": 6.6, "n": 3, "samples": [6, 7, 7]}}))
        mult, src = vrc._get_multiplier("k", tmp_path)
        assert mult == 6.6 and "calibrated" in src

    def test_get_multiplier_single_sample_ignored(self, tmp_path):
        d = tmp_path / ".appsec-cache"
        d.mkdir()
        (d / vrc._CALIBRATION_FILE).write_text(json.dumps({"standard-sonnet": {"average": 9.9, "n": 1}}))
        mult, src = vrc._get_multiplier("standard-sonnet", tmp_path)
        assert mult == 4.7 and src == "default"


# ===========================================================================
# Model detection / normalization
# ===========================================================================
class TestModels:
    def test_normalize(self):
        assert vrc._normalize_model_name("claude-sonnet-4-6") == "sonnet-4-6"
        assert vrc._normalize_model_name("anthropic/opus") == "opus-4-6"
        assert vrc._normalize_model_name("haiku") == "haiku-4-5"
        assert vrc._normalize_model_name("custom-model") == "custom-model"

    def test_detect_no_yaml(self, tmp_path):
        assert vrc._detect_agent_models(tmp_path) == {}

    def test_detect_agent_models(self, tmp_path):
        (tmp_path / "threat-model.yaml").write_text(
            "meta:\n"
            '  model: "claude-sonnet-4-6"\n'
            "  agent_models:\n"
            '    stride-analyzer: "claude-opus-4-6"\n'
            '    qa-reviewer: "sonnet"\n'
            "  other: x\n"
        )
        models = vrc._detect_agent_models(tmp_path)
        assert models["stride-analyzer"] == "opus-4-6"
        assert models["qa-reviewer"] == "sonnet-4-6"
        # orchestrator added under base model
        assert models["threat-analyst"] == "sonnet-4-6"


# ===========================================================================
# Aggregation
# ===========================================================================
class TestAggregate:
    def _result(self, sid, agents, in_=100, cost=1.0):
        delta = vrc.TokenSnapshot(in_tokens=in_, out_tokens=10, cache_write=5, cache_read=5, cost=cost)
        return vrc.SessionResult(
            session_id=sid,
            agents=agents,
            before_boundary=vrc.TokenSnapshot(),
            final_in_window=vrc.TokenSnapshot(),
            delta=delta,
            computed_cost=cost,
            cross_check="OK",
        )

    def test_primary_agent(self):
        assert vrc._primary_agent({}) == "unknown"
        assert vrc._primary_agent({"a": 1, "b": 3}) == "b"
        # tie broken alphabetically
        assert vrc._primary_agent({"z": 2, "a": 2}) == "a"

    def test_aggregate_by_counts(self):
        results = [self._result("5a1", ["x"], cost=2.0)]
        counts = {"5a1": {"qa-reviewer": 3, "threat-analyst": 1}}
        rows = vrc.aggregate_by_agent(results, counts, SONNET)
        assert rows[0]["agent"] == "qa-reviewer"
        assert rows[0]["ambiguous_sessions"] == 1
        assert rows[0]["pct_of_total"] == 100.0

    def test_aggregate_fallback_to_agents_list(self):
        results = [self._result("5a1", ["threat-analyst"], cost=1.0)]
        rows = vrc.aggregate_by_agent(results, {}, SONNET)
        assert rows[0]["agent"] == "threat-analyst"

    def test_aggregate_unknown(self):
        results = [self._result("5a1", ["unknown"], cost=1.0)]
        rows = vrc.aggregate_by_agent(results, {}, SONNET)
        assert rows[0]["agent"] == "unknown"

    def test_aggregate_zero_cost_pct(self):
        results = [self._result("5a1", ["a"], cost=0.0)]
        rows = vrc.aggregate_by_agent(results, {}, SONNET)
        assert rows[0]["pct_of_total"] == 0.0


# ===========================================================================
# find_session_agents / counts
# ===========================================================================
class TestSessionAgents:
    def test_agents_prefix_stripping_and_window(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text(
            agent_spawn("2026-01-01T00:05:00Z", "5a1", "appsec-advisor:appsec-threat-analyst")
            + agent_spawn("2026-01-01T00:06:00Z", "5a1", "stride:stride-analyzer")
            + agent_spawn("2025-01-01T00:00:00Z", "5a2", "too-early")  # before window
        )
        agents = vrc.find_session_agents(hook, "2026-01-01T00:00:00Z", "2026-01-01T00:30:00Z")
        assert agents["5a1"] == sorted(["threat-analyst", "stride-analyzer"])
        assert "5a2" not in agents

    def test_counts(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text(
            agent_spawn("2026-01-01T00:05:00Z", "5a1", "qa-reviewer")
            + agent_spawn("2026-01-01T00:06:00Z", "5a1", "qa-reviewer")
            + agent_spawn("2026-01-01T00:07:00Z", "5a1", "threat-analyst")
        )
        counts = vrc.find_session_agent_counts(hook, None, None)
        assert counts["5a1"]["qa-reviewer"] == 2

    def test_agents_missing_file(self, tmp_path):
        assert vrc.find_session_agents(tmp_path / "no.log", None, None) == {}
        assert vrc.find_session_agent_counts(tmp_path / "no.log", None, None) == {}

    def test_counts_end_window_excludes(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text(agent_spawn("2026-01-01T01:00:00Z", "5a1", "late"))
        counts = vrc.find_session_agent_counts(hook, None, "2026-01-01T00:30:00Z")
        assert counts == {}


# ===========================================================================
# Sub-agent estimate
# ===========================================================================
class TestSubagentEstimate:
    def test_no_assessment_tokens_heuristic(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text("")
        est = vrc.build_subagent_estimate(hook, None, None, host_session_cost=2.0, pricing=SONNET, output_dir=tmp_path)
        assert est["confidence"] == "heuristic"
        assert est["assessment_tokens_cost"] is None
        assert est["multiplier_estimate"] == pytest.approx(2.0 * 4.7, abs=0.01)

    def test_assessment_tokens_signal(self, tmp_path):
        hook = tmp_path / "h.log"
        # at_cost high so multiplier_estimate < at_cost -> confidence "signal"
        hook.write_text(assessment_tokens("2026-01-01T00:10:00Z", "5a1", inp=100, out=10, cw=5, cr=5, cost=50.0))
        est = vrc.build_subagent_estimate(
            hook,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:30:00Z",
            host_session_cost=2.0,
            pricing=SONNET,
            output_dir=tmp_path,
        )
        assert est["assessment_tokens_cost"] == 50.0
        # effective_base = max(host, at_cost) = 50; multiplier 4.7 -> estimate 235 >= at_cost
        # so this always lands in the "heuristic" branch (multiplier estimate dominates).
        assert est["confidence"] == "heuristic"
        assert est["best_estimate"] == pytest.approx(235.0, abs=0.01)

    def test_assessment_tokens_heuristic_when_multiplier_higher(self, tmp_path):
        hook = tmp_path / "h.log"
        # at_cost just above host but multiplier estimate higher
        hook.write_text(assessment_tokens("2026-01-01T00:10:00Z", "5a1", inp=100, out=10, cw=5, cr=5, cost=2.5))
        est = vrc.build_subagent_estimate(
            hook,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:30:00Z",
            host_session_cost=2.0,
            pricing=SONNET,
            output_dir=tmp_path,
        )
        # 2.5 > 2.0 host, multiplier = max(2.5,2.0)*4.7 = 11.75 >= 2.5
        assert est["confidence"] == "heuristic"
        assert est["best_estimate"] == pytest.approx(11.75, abs=0.01)

    def test_assessment_tokens_below_host(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text(assessment_tokens("2026-01-01T00:10:00Z", "5a1", inp=100, out=10, cw=5, cr=5, cost=1.0))
        est = vrc.build_subagent_estimate(
            hook,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:30:00Z",
            host_session_cost=5.0,
            pricing=SONNET,
            output_dir=tmp_path,
        )
        # at_cost(1.0) <= host(5.0), not None -> heuristic fallback branch
        assert est["confidence"] == "heuristic"
        assert "≤ host-session" in est["note"]

    def test_duration_floor(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text("")
        agent = tmp_path / ".agent-run.log"
        agent.write_text("2026-01-01T00:00:00Z INFO ASSESSMENT_START\n2026-01-01T00:40:00Z INFO ASSESSMENT_END\n")
        est = vrc.build_subagent_estimate(
            hook,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:43:00Z",
            host_session_cost=0.05,
            pricing=SONNET,
            output_dir=tmp_path,
        )
        assert est["data_incomplete"] is True
        assert est["confidence"] == "duration-floor"
        # 40 min * 0.19 = 7.6
        assert est["duration_floor_cost"] == pytest.approx(40 * 0.19, abs=0.01)

    def test_duration_floor_calibrated_per_minute(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text("")
        agent = tmp_path / ".agent-run.log"
        agent.write_text("2026-01-01T00:00:00Z INFO ASSESSMENT_START\n2026-01-01T00:40:00Z INFO ASSESSMENT_END\n")
        cache = tmp_path / ".appsec-cache"
        cache.mkdir()
        (cache / vrc._CALIBRATION_FILE).write_text(
            json.dumps({"standard-sonnet_per_minute": {"average": 0.5, "n": 2, "samples": [0.5, 0.5]}})
        )
        est = vrc.build_subagent_estimate(
            hook,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:43:00Z",
            host_session_cost=0.05,
            pricing=SONNET,
            output_dir=tmp_path,
        )
        assert est["duration_floor_cost"] == pytest.approx(40 * 0.5, abs=0.01)
        assert "calibrated per-minute" in est["multiplier_source"]

    def test_opus_depth_detection(self, tmp_path):
        hook = tmp_path / "h.log"
        hook.write_text("")
        (tmp_path / "threat-model.yaml").write_text(
            "meta:\n  assessment_depth: 'thorough'\n  stride model is opus here\n"
        )
        est = vrc.build_subagent_estimate(hook, None, None, host_session_cost=1.0, pricing=SONNET, output_dir=tmp_path)
        assert est["multiplier_key"] == "thorough-opus"


# ===========================================================================
# verify_run_costs end-to-end
# ===========================================================================
class TestVerifyRunCosts:
    def test_no_hook_log(self, tmp_path):
        res = vrc.verify_run_costs(tmp_path)
        assert res["exit_code"] == 2 and "No .hook-events.log" in res["error"]

    def test_no_start(self, tmp_path):
        write_logs(tmp_path, hook_lines=["irrelevant\n"], agent_lines=["nothing\n"])
        res = vrc.verify_run_costs(tmp_path)
        assert res["exit_code"] == 2 and "Could not determine run start" in res["error"]

    def test_no_session_stops(self, tmp_path):
        write_logs(
            tmp_path,
            hook_lines=["2026-01-01T00:00:00Z [s1] INFO SESSION_STOP cost=n/a\n"],
            agent_lines=["2026-01-01T00:00:00Z INFO ASSESSMENT_START\n"],
        )
        res = vrc.verify_run_costs(tmp_path)
        assert res["exit_code"] == 1 and "No SESSION_STOP entries" in res["error"]

    def test_no_activity_in_window(self, tmp_path):
        # SESSION_STOP exists but only before the window start
        write_logs(
            tmp_path,
            hook_lines=[session_stop("2025-01-01T00:00:00Z", "5a1", in_=100, cost=1.0)],
            agent_lines=[
                "2026-01-01T00:00:00Z INFO ASSESSMENT_START\n",
                "2026-01-01T00:10:00Z INFO ASSESSMENT_END\n",
            ],
        )
        res = vrc.verify_run_costs(tmp_path)
        assert res["exit_code"] == 1 and "No sessions had activity" in res["error"]

    def _good_run(self, tmp_path, *, cost_final=2.0):
        # baseline before window, two in-window snapshots (cumulative)
        hook = [
            session_stop("2025-12-31T23:00:00Z", "5a1", in_=1000, out=100, cw=2000, cr=3000, cost=0.5),
            agent_spawn("2026-01-01T00:01:00Z", "5a1", "appsec-threat-analyst"),
            session_stop("2026-01-01T00:05:00Z", "5a1", in_=2000, out=200, cw=4000, cr=6000, cost=1.0),
            # final values picked so calc_cost roughly matches cost delta
            session_stop(
                "2026-01-01T00:20:00Z",
                "5a1",
                in_=2_000_000,
                out=200_000,
                cw=4_000_000,
                cr=6_000_000,
                cost=cost_final,
            ),
        ]
        agent = [
            "2026-01-01T00:00:00Z INFO ASSESSMENT_START\n",
            "2026-01-01T00:30:00Z INFO ASSESSMENT_END\n",
        ]
        write_logs(tmp_path, hook_lines=hook, agent_lines=agent)

    def test_full_run_ok(self, tmp_path):
        # cost chosen so cross-check is OK: compute calc_cost on delta
        # delta in=1.999M out=199.9k cw=3.996M cr=5.997M
        # cost = 1.999*3 + 0.1999*15 + 3.996*3.75 + 5.997*0.30 = ~25.78
        self._good_run(tmp_path, cost_final=25.78 + 1.0)  # +baseline-in-window 1.0
        res = vrc.verify_run_costs(tmp_path, verbose=False)
        assert res["exit_code"] == 0
        assert res["totals"]["cross_check"] == "OK"
        assert res["sessions"][0]["agents"] == ["threat-analyst"]
        assert res["billing"] in ("api", "subscription")
        assert res["subagent_estimate"] is not None

    def test_full_run_mismatch_warning(self, tmp_path):
        self._good_run(tmp_path, cost_final=2.0)  # logged cost tiny vs computed -> MISMATCH
        res = vrc.verify_run_costs(tmp_path)
        assert res["totals"]["cross_check"] == "MISMATCH"
        assert any("vs computed" in w for w in res["warnings"])

    def test_negative_delta_clamped(self, tmp_path):
        # in-window final lower than baseline -> negative delta clamp
        hook = [
            session_stop("2025-12-31T23:00:00Z", "5a1", in_=5000, out=500, cw=5000, cr=5000, cost=10.0),
            session_stop("2026-01-01T00:05:00Z", "5a1", in_=10, out=5, cw=10, cr=10, cost=0.01),
        ]
        agent = [
            "2026-01-01T00:00:00Z INFO ASSESSMENT_START\n",
            "2026-01-01T00:10:00Z INFO ASSESSMENT_END\n",
        ]
        write_logs(tmp_path, hook_lines=hook, agent_lines=agent)
        res = vrc.verify_run_costs(tmp_path)
        assert any("negative delta clamped" in w for w in res["warnings"])
        assert res["totals"]["in"] == 0

    def test_pricing_flag_used(self, tmp_path):
        self._good_run(tmp_path, cost_final=10.0)
        res = vrc.verify_run_costs(tmp_path, pricing_model="opus-4-6")
        assert res["pricing"] == vrc.PRICING_MODELS["opus-4-6"]

    def test_mixed_model_costs(self, tmp_path):
        self._good_run(tmp_path, cost_final=10.0)
        (tmp_path / "threat-model.yaml").write_text(
            'meta:\n  model: "claude-sonnet-4-6"\n  agent_models:\n    stride-analyzer: "claude-opus-4-6"\n'
        )
        res = vrc.verify_run_costs(tmp_path)
        assert res["mixed_model_costs"] is not None
        assert "opus-4-6" in res["mixed_model_costs"]
        assert any("Mixed models detected" in w for w in res["warnings"])

    def test_verbose_prints(self, tmp_path, capsys):
        self._good_run(tmp_path, cost_final=26.78)
        (tmp_path / "threat-model.yaml").write_text(
            'meta:\n  model: "claude-sonnet-4-6"\n  agent_models:\n    stride-analyzer: "claude-opus-4-6"\n'
        )
        res = vrc.verify_run_costs(tmp_path, verbose=True)
        err = capsys.readouterr().err
        assert "Run window:" in err
        assert "Totals:" in err
        assert "Sub-Agent Cost Estimate:" in err
        assert res["exit_code"] == 0


# ===========================================================================
# _print_verbose with per-agent + ambiguous
# ===========================================================================
class TestPrintVerbose:
    def test_print_verbose_with_ambiguous(self, capsys):
        result = {
            "run_window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:30:00Z"},
            "pricing_model": "sonnet-4-6",
            "sessions": [
                {
                    "session_id": "5a1",
                    "agents": ["a", "b"],
                    "before_boundary": {"in": 1, "out": 2, "cache_write": 3, "cache_read": 4, "cost": 0.1},
                    "final_in_window": {"in": 10, "out": 20, "cache_write": 30, "cache_read": 40, "cost": 1.0},
                    "delta": {"in": 9, "out": 18, "cache_write": 27, "cache_read": 36, "cost": 0.9},
                    "computed_cost": 0.9,
                    "cross_check": "OK",
                }
            ],
            "totals": {
                "in": 9,
                "out": 18,
                "cache_write": 27,
                "cache_read": 36,
                "total_tokens": 90,
                "cost": 0.9,
                "cross_check": "OK",
                "no_cache_cost": 1.0,
                "cache_savings_pct": 10.0,
            },
            "per_agent": [
                {
                    "agent": "a",
                    "sessions": 1,
                    "total_tokens": 90,
                    "cost": 0.9,
                    "pct_of_total": 100.0,
                    "ambiguous_sessions": 1,
                }
            ],
            "mixed_model_costs": {
                "opus-4-6": {"cached": 1.0, "no_cache": 2.0, "pricing": vrc.PRICING_MODELS["opus-4-6"]}
            },
            "agent_models": {"threat-analyst": "sonnet-4-6"},
            "subagent_estimate": {
                "assessment_tokens_cost": 5.0,
                "multiplier_estimate": 4.0,
                "multiplier_key": "standard-sonnet",
                "multiplier": 4.7,
                "best_estimate": 5.0,
                "confidence": "signal",
                "note": "ok",
            },
            "billing": "api",
            "warnings": ["something"],
        }
        vrc._print_verbose(result, sys.stderr)
        err = capsys.readouterr().err
        assert "Per-Agent Cost Breakdown" in err
        assert "* Session hosted multiple agents" in err
        assert "Mixed-model cost estimates" in err
        assert "Warnings:" in err


# ===========================================================================
# CLI via subprocess
# ===========================================================================
class TestCLI:
    def _setup_good(self, d: Path):
        hook = (
            session_stop("2025-12-31T23:00:00Z", "5a1", in_=1000, out=100, cw=2000, cr=3000, cost=0.5)
            + agent_spawn("2026-01-01T00:01:00Z", "5a1", "appsec-threat-analyst")
            + session_stop(
                "2026-01-01T00:20:00Z",
                "5a1",
                in_=2_000_000,
                out=200_000,
                cw=4_000_000,
                cr=6_000_000,
                cost=26.78,
            )
        )
        agent = "2026-01-01T00:00:00Z INFO ASSESSMENT_START\n2026-01-01T00:30:00Z INFO ASSESSMENT_END\n"
        (d / ".hook-events.log").write_text(hook)
        (d / ".agent-run.log").write_text(agent)

    def test_cli_not_a_directory(self, run_plugin_script, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("x")
        r = run_plugin_script("verify_run_costs.py", str(f), check=False)
        assert r.returncode == 2
        assert "is not a directory" in r.stderr

    def test_cli_error_json(self, run_plugin_script, tmp_path):
        # empty dir -> no hook log -> error path with --json
        r = run_plugin_script("verify_run_costs.py", str(tmp_path), "--json", check=False)
        assert r.returncode == 2
        out = json.loads(r.stdout)
        assert "error" in out

    def test_cli_default_output(self, run_plugin_script, tmp_path):
        self._setup_good(tmp_path)
        r = run_plugin_script("verify_run_costs.py", str(tmp_path), check=False)
        assert r.returncode == 0
        assert "Tokens:" in r.stdout
        assert "Sub-agent estimate" in r.stdout

    def test_cli_json_output(self, run_plugin_script, tmp_path):
        self._setup_good(tmp_path)
        r = run_plugin_script("verify_run_costs.py", str(tmp_path), "--json", check=False)
        assert r.returncode == 0
        out = json.loads(r.stdout)
        assert out["totals"]["cross_check"] == "OK"
        assert "exit_code" not in out

    def test_cli_verbose(self, run_plugin_script, tmp_path):
        self._setup_good(tmp_path)
        r = run_plugin_script("verify_run_costs.py", str(tmp_path), "--verbose", check=False)
        assert r.returncode == 0
        assert "Run window:" in r.stderr

    def test_cli_actual_cost_host_path(self, run_plugin_script, tmp_path):
        self._setup_good(tmp_path)
        r = run_plugin_script("verify_run_costs.py", str(tmp_path), "--actual-cost", "50.0", check=False)
        assert r.returncode == 0
        assert "Calibration recorded" in r.stderr
        cal = json.loads((tmp_path / ".appsec-cache" / vrc._CALIBRATION_FILE).read_text())
        assert any("samples" in v for v in cal.values())

    def test_cli_actual_cost_incomplete_path(self, run_plugin_script, tmp_path):
        # tiny host cost + long duration -> data_incomplete -> per-minute calibration
        hook = session_stop("2026-01-01T00:05:00Z", "5a1", in_=100, out=10, cw=100, cr=100, cost=0.02)
        agent = "2026-01-01T00:00:00Z INFO ASSESSMENT_START\n2026-01-01T00:40:00Z INFO ASSESSMENT_END\n"
        (tmp_path / ".hook-events.log").write_text(hook)
        (tmp_path / ".agent-run.log").write_text(agent)
        r = run_plugin_script("verify_run_costs.py", str(tmp_path), "--actual-cost", "20.0", check=False)
        assert r.returncode == 0
        assert "per-minute rate" in r.stderr
        cal = json.loads((tmp_path / ".appsec-cache" / vrc._CALIBRATION_FILE).read_text())
        assert any(k.endswith("_per_minute") for k in cal)
