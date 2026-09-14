"""A call is priced as the release it ran on, not the alias it asked for.

A family alias names no release: the host resolves ``opus`` to its current Opus,
and releases of one family differ in price by a factor. Every surface that
prices or labels a sub-agent call is held here to the release the host reported.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import agent_lifecycle as lifecycle  # noqa: E402
import cost_running_total as crt  # noqa: E402
import record_stage_stats as rec  # noqa: E402
import verify_run_costs as vrc  # noqa: E402

_AGENT_TYPE = "appsec-advisor:appsec-stride-analyzer-v2"


@pytest.mark.parametrize(
    "model_id, release",
    [
        ("claude-opus-5", "opus-5"),
        ("claude-sonnet-4-6", "sonnet-4-6"),
        ("claude-haiku-4-5-20251001", "haiku-4-5"),
        ("us.anthropic.claude-sonnet-4-6-v1:0", "sonnet-4-6"),
        ("claude-opus-4-6@20250101", "opus-4-6"),
        ("claude-opus-5[1m]", "opus-5"),
        ("anthropic/claude-opus-4-8", "opus-4-8"),
    ],
)
def test_release_key_names_the_release_in_every_host_spelling(model_id: str, release: str) -> None:
    assert vrc.release_key(model_id) == release


@pytest.mark.parametrize("model_id", ["opus", "sonnet", "haiku", "<synthetic>", "?", ""])
def test_release_key_refuses_what_names_no_release(model_id: str) -> None:
    assert vrc.release_key(model_id) == ""


def test_learned_alias_resolution_takes_the_most_frequent_release() -> None:
    rows = [
        {"model": "opus", "resolved_model": "claude-opus-5"},
        {"model": "opus", "resolved_model": "claude-opus-5"},
        {"model": "opus", "resolved_model": "claude-opus-4-8"},
        {"model": "sonnet"},
    ]
    assert vrc.learn_alias_releases(rows) == {"opus": "opus-5"}


def _usage_line(call_id: str, model: str, *, resolved: str = "", out: int = 1_000_000) -> str:
    resolved_field = f"  resolved_model={resolved}" if resolved else ""
    return (
        f"2026-05-01T10:05:00Z  [abc]  INFO   stride-analyzer-v2  AGENT_USAGE  agent_call_id={call_id}  "
        f"agent_type={_AGENT_TYPE}  model={model}{resolved_field}  background=true  "
        f"in=0  out={out}  cache_write=0  cache_read=0\n"
    )


def _output_price(release: str) -> float:
    """USD for one million output tokens of a release."""
    return vrc.PRICING_MODELS[release]["output"]


def test_a_call_is_priced_as_the_release_the_host_reported(tmp_path: Path) -> None:
    log = tmp_path / ".agent-run.log"
    log.write_text(_usage_line("toolu_a", "opus", resolved="claude-opus-5"))
    result = crt.aggregate_subagent_usage(log)
    assert result["subagent_cost"] == pytest.approx(_output_price(vrc.release_key("claude-opus-5")))


def test_an_alias_only_call_takes_the_release_the_same_run_resolved_that_alias_to(tmp_path: Path) -> None:
    log = tmp_path / ".agent-run.log"
    log.write_text(_usage_line("toolu_a", "opus", resolved="claude-opus-5") + _usage_line("toolu_b", "opus"))
    result = crt.aggregate_subagent_usage(log)
    assert result["subagent_cost"] == pytest.approx(2 * _output_price("opus-5"))


def test_without_any_reported_release_the_fallback_table_prices_the_alias(tmp_path: Path) -> None:
    log = tmp_path / ".agent-run.log"
    log.write_text(_usage_line("toolu_a", "haiku"))
    result = crt.aggregate_subagent_usage(log)
    assert result["subagent_cost"] == pytest.approx(_output_price(vrc.ALIAS_FALLBACK_RELEASES["haiku"]))


def test_a_release_the_table_does_not_know_stays_unpriced(tmp_path: Path) -> None:
    log = tmp_path / ".agent-run.log"
    log.write_text(_usage_line("toolu_a", "opus", resolved="claude-opus-99", out=500))
    assert vrc.release_key("claude-opus-99") not in vrc.PRICING_MODELS
    result = crt.aggregate_subagent_usage(log)
    assert result["subagent_cost"] == 0
    assert result["unpriced_tokens"] == 500
    assert result["unpriced_calls"] == 1
    assert result["subagent_count"] == 1
    assert result["unmetered_agents"] == 0


def test_mixed_model_reference_uses_the_run_s_alias_resolution(tmp_path: Path) -> None:
    (tmp_path / "threat-model.yaml").write_text(
        'meta:\n  model: "sonnet"\n  agent_models:\n    stride-analyzer: "opus"\n  other: x\n'
    )
    (tmp_path / ".agent-run.log").write_text(_usage_line("toolu_a", "opus", resolved="claude-opus-5"))
    models = vrc._detect_agent_models(tmp_path, vrc.learned_alias_releases(tmp_path / ".agent-run.log"))
    assert models["stride-analyzer"] == "opus-5"
    assert models["threat-analyst"] == vrc.ALIAS_FALLBACK_RELEASES["sonnet"]


def _identity(call_id: str) -> dict:
    return {
        "agent_call_id": call_id,
        "session_id": "sess0001",
        "agent": "stride-analyzer-v2",
        "agent_type": _AGENT_TYPE,
        "model": "opus",
        "description": "STRIDE",
        "background": False,
    }


def test_usage_event_carries_the_reported_release_without_persisting_it(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_a"))
    events = lifecycle.record_call_usage(tmp_path, "toolu_a", {"output_tokens": 10}, resolved_model="claude-opus-5")
    assert "resolved_model=claude-opus-5" in lifecycle.event_detail(events[0])
    stored = json.loads(lifecycle.state_path(tmp_path).read_text(encoding="utf-8"))
    assert "resolved_model" not in stored["calls"][0]


def test_a_malformed_reported_model_is_dropped(tmp_path: Path) -> None:
    lifecycle.register_call(tmp_path, _identity("toolu_b"))
    events = lifecycle.record_call_usage(tmp_path, "toolu_b", {"output_tokens": 10}, resolved_model="bad model\nx")
    assert "resolved_model=" not in lifecycle.event_detail(events[0])


def test_the_logged_usage_line_is_priced_by_its_release(tmp_path: Path) -> None:
    """Producer and consumer agree on the field, end to end."""
    lifecycle.register_call(tmp_path, _identity("toolu_c"))
    lifecycle.append_events(
        tmp_path,
        lifecycle.record_call_usage(tmp_path, "toolu_c", {"output_tokens": 1_000_000}, resolved_model="claude-opus-5"),
    )
    result = crt.aggregate_subagent_usage(tmp_path / ".agent-run.log")
    assert result["subagent_cost"] == pytest.approx(_output_price("opus-5"))


def _record_stats(output_dir: Path, *extra: str) -> dict:
    argv = [
        "record_stage_stats.py",
        str(output_dir),
        "--stage",
        "1",
        "--name",
        "stride",
        "--agent",
        _AGENT_TYPE,
        "--model",
        "opus",
        "--duration-ms",
        "1",
        "--tool-uses",
        "1",
        "--tokens",
        "5",
        "--subagent-type",
        _AGENT_TYPE,
        "--since-iso",
        "2000-01-01T00:00:00Z",
        *extra,
    ]
    assert rec.main(argv) == 0
    return json.loads((output_dir / ".stage-stats.jsonl").read_text(encoding="utf-8").splitlines()[-1])


@pytest.mark.parametrize("resolved, expected", [("claude-opus-5", "claude-opus-5"), ("", None)])
def test_stage_row_records_the_release_its_dispatches_ran_on(tmp_path: Path, resolved: str, expected) -> None:
    events = lifecycle.register_call(tmp_path, _identity("toolu_d"))
    events += lifecycle.record_call_usage(tmp_path, "toolu_d", {"output_tokens": 5}, resolved_model=resolved)
    lifecycle.append_events(tmp_path, events)
    row = _record_stats(tmp_path)
    assert row["model"] == "opus"
    assert row.get("resolved_model") == expected


def test_accumulated_stage_row_keeps_every_reported_release(tmp_path: Path) -> None:
    events = lifecycle.register_call(tmp_path, _identity("toolu_e"))
    events += lifecycle.record_call_usage(tmp_path, "toolu_e", {"output_tokens": 5}, resolved_model="claude-opus-5")
    lifecycle.append_events(tmp_path, events)
    _record_stats(tmp_path, "--accumulate", "--accumulation-id", "wave-1")
    events = lifecycle.register_call(tmp_path, {**_identity("toolu_f"), "job_id": "second"})
    events += lifecycle.record_call_usage(tmp_path, "toolu_f", {"output_tokens": 5}, resolved_model="claude-opus-4-8")
    lifecycle.append_events(tmp_path, events)
    row = _record_stats(tmp_path, "--accumulate", "--accumulation-id", "wave-2")
    assert row["resolved_model"] == "claude-opus-4-8,claude-opus-5"
