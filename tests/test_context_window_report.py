from __future__ import annotations

import json
from pathlib import Path

import context_window_report as report


def _write(path: Path, entries: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(entry) + "\n" for entry in entries),
        encoding="utf-8",
    )
    return path


def _turn(resident: tuple[int, int, int], text: str, model: str = "sonnet", msg_id: str | None = None) -> dict:
    fresh, cache_read, cache_write = resident
    message = {
        "model": model,
        "content": [{"type": "text", "text": text}],
        "usage": {
            "input_tokens": fresh,
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_write,
        },
    }
    if msg_id is not None:
        message["id"] = msg_id
    return {"type": "assistant", "version": "2.1.0", "message": message}


def _turn_with_content(
    resident: tuple[int, int, int],
    content: list[dict],
    *,
    msg_id: str,
    role: str = "appsec-advisor:test-role",
) -> dict:
    entry = _turn(resident, "placeholder", msg_id=msg_id)
    entry["message"]["content"] = content
    entry["attributionAgent"] = role
    entry["timestamp"] = "2026-08-05T10:00:00Z"
    return entry


def _startup_record(**overrides) -> dict:
    record = {
        "measurement_id": "kernel-provider-count",
        "layer": "shared_kernel",
        "label": "Internal threat-analysis kernel",
        "measurement_method": "provider_token_count",
        "measured_tokens": 2000,
        "baseline_resident_tokens": None,
        "variant_resident_tokens": None,
        "changed_variable": "shared kernel",
        "claude_code_version": "2.1.220",
        "model_id": "claude-sonnet-4-6",
        "pricing_table_version": "2026-08-05",
        "tool_allow_list": ["Read", "Write"],
        "task_sha256": "sha256:" + "a" * 64,
        "agent_definition_sha256": "sha256:" + "b" * 64,
        "input_sha256": "sha256:" + "c" * 64,
        "review_status": "reviewed",
    }
    record.update(overrides)
    return record


def test_resident_metric_and_real_compaction_boundary(tmp_path):
    path = _write(
        tmp_path / "main.jsonl",
        [
            _turn((10, 20, 30), "Stage 1 dispatch"),
            {"type": "system", "subtype": "stop", "cache_read": 9_000_000},
            _turn((5, 100, 1), "Phase 9 fan-out"),
            {
                "type": "system",
                "subtype": "compact_boundary",
                "timestamp": "2026-01-01T00:00:00Z",
            },
            _turn((20, 30, 10), "continued"),
        ],
    )
    result = report.analyze_session(path)
    assert result["peak_resident_context"] == 106
    assert result["cache_read_throughput"] == 150
    assert len(result["compact_boundaries"]) == 1
    assert result["compact_boundaries"][0]["resident_before"] == 106
    assert result["compact_boundaries"][0]["stage_before"] == "Phase 9"
    assert result["stages"] == {
        "Phase 9": {
            "assistant_turns_with_usage": 2,
            "cache_read_throughput": 130,
            "peak_resident_context": 106,
        },
        "Stage 1": {
            "assistant_turns_with_usage": 1,
            "cache_read_throughput": 20,
            "peak_resident_context": 60,
        },
    }


def test_multiple_content_blocks_per_message_are_not_double_counted(tmp_path):
    # Claude Code logs one JSONL record per content block (thinking/text/tool_use)
    # for a single API turn; all of them carry the SAME message.usage snapshot.
    # Summing cache_read/turns per JSONL record (instead of per unique message id)
    # inflates cache_read_throughput by however many blocks the turn had.
    path = _write(
        tmp_path / "main.jsonl",
        [
            _turn((0, 100, 10), "thinking chunk", msg_id="msg_1"),
            _turn((0, 100, 10), "text chunk", msg_id="msg_1"),
            _turn((0, 100, 10), "tool_use chunk", msg_id="msg_1"),
            _turn((0, 50, 5), "second turn", msg_id="msg_2"),
        ],
    )
    result = report.analyze_session(path)
    assert result["assistant_turns_with_usage"] == 2
    assert result["cache_read_throughput"] == 150
    assert result["peak_resident_context"] == 110


def test_main_and_subagent_are_grouped_separately(tmp_path):
    main = _write(tmp_path / "session.jsonl", [_turn((100, 0, 0), "Stage 1")])
    sub = _write(
        tmp_path / "subagents" / "agent-a.jsonl",
        [_turn((200, 0, 0), "Phase 3")],
    )
    result = report.build_report([main, sub])
    assert result["groups"]["main"]["sessions"] == 1
    assert result["groups"]["main"]["peak_resident_context"] == 100
    assert result["groups"]["subagent"]["sessions"] == 1
    assert result["groups"]["subagent"]["peak_resident_context"] == 200


def test_nominal_window_only_reported_when_present(tmp_path):
    path = _write(
        tmp_path / "main.jsonl",
        [
            {
                **_turn((1, 2, 3), "Stage 2"),
                "metadata": {"context_window_tokens": 300_000},
            }
        ],
    )
    result = report.analyze_session(path)
    assert result["nominal_context_windows"] == [300_000]


def test_cli_rejects_missing_path(capsys):
    assert report.main(["/definitely/missing"]) == 2
    assert "not found" in capsys.readouterr().err


def test_text_labels_cache_read_as_throughput(tmp_path, capsys):
    path = _write(tmp_path / "main.jsonl", [_turn((1, 2, 3), "Stage 1")])
    assert report.main([str(path)]) == 0
    output = capsys.readouterr().out
    assert "throughput, not current occupancy" in output
    assert "stage=Stage 1 turns=1 peak=6 cache_read=2" in output


def test_turn_diagnostics_aggregate_late_tool_block_and_batch_dispatch(tmp_path):
    thinking = _turn_with_content(
        (1, 20, 3),
        [{"type": "thinking", "thinking": "Preparing a bounded wave"}],
        msg_id="msg_batch",
    )
    dispatch = _turn_with_content(
        (1, 20, 3),
        [
            {
                "type": "tool_use",
                "name": "Agent",
                "input": {"description": f"STRIDE component {index}"},
            }
            for index in range(8)
        ],
        msg_id="msg_batch",
    )
    path = _write(tmp_path / "main.jsonl", [thinking, dispatch])

    result = report.analyze_session(path, include_turn_diagnostics=True)
    diagnostics = result["turn_diagnostics"]
    assert diagnostics["summary"]["turns"] == 1
    assert diagnostics["summary"]["primary_category_counts"]["agent_dispatch"] == 1
    turn = diagnostics["turns"][0]
    assert turn["entry_numbers"] == [1, 2]
    assert turn["content_block_count"] == 9
    assert turn["tool_use_count"] == 8
    assert turn["primary_category"] == "agent_dispatch"
    assert turn["secondary_categories"] == []
    assert turn["confidence"] == "high"


def test_turn_diagnostics_include_blocks_without_repeated_usage(tmp_path):
    first = _turn_with_content(
        (1, 20, 3),
        [{"type": "text", "text": "Inspecting the evidence."}],
        msg_id="msg_read",
    )
    later = _turn_with_content(
        (1, 20, 3),
        [{"type": "tool_use", "name": "Read", "input": {"file_path": "source.py"}}],
        msg_id="msg_read",
    )
    later["message"].pop("usage")
    path = _write(tmp_path / "main.jsonl", [first, later])

    turn = report.analyze_session(path, include_turn_diagnostics=True)["turn_diagnostics"]["turns"][0]
    assert turn["content_block_count"] == 2
    assert turn["tool_use_count"] == 1
    assert turn["primary_category"] == "evidence_request"


def test_turn_cost_uses_first_usage_snapshot_while_aggregating_late_blocks(tmp_path):
    first = _turn_with_content(
        (1_000_000, 2_000_000, 3_000_000),
        [{"type": "thinking", "thinking": "working"}],
        msg_id="msg_cost",
    )
    first["message"]["usage"]["output_tokens"] = 100_000
    later = _turn_with_content(
        (1_000_000, 2_000_000, 3_000_000),
        [{"type": "tool_use", "name": "Read", "input": {"file_path": "source.py"}}],
        msg_id="msg_cost",
    )
    later["message"]["usage"]["output_tokens"] = 900_000
    path = _write(tmp_path / "main.jsonl", [first, later])

    diagnostics = report.analyze_session(path, include_turn_diagnostics=True)["turn_diagnostics"]
    turn = diagnostics["turns"][0]
    assert turn["tool_use_count"] == 1
    assert turn["usage"]["output_tokens"] == 100_000
    assert turn["reconstructed_cost_usd"] == 16.35
    assert diagnostics["summary"]["reconstructed_cost_usd"] == 16.35


def test_turn_diagnostics_preserve_secondary_categories_for_adjudication(tmp_path):
    path = _write(
        tmp_path / "main.jsonl",
        [
            _turn_with_content(
                (1, 2, 3),
                [
                    {"type": "tool_use", "name": "Read", "input": {"file_path": "input.json"}},
                    {"type": "tool_use", "name": "Write", "input": {"file_path": "output.json"}},
                ],
                msg_id="msg_mixed",
            )
        ],
    )

    diagnostics = report.analyze_session(path, include_turn_diagnostics=True)["turn_diagnostics"]
    turn = diagnostics["turns"][0]
    assert turn["primary_category"] == "artifact_write"
    assert turn["secondary_categories"] == ["evidence_request"]
    assert turn["mixed"] is True
    assert turn["requires_manual_adjudication"] is True
    assert diagnostics["summary"]["mixed_turns"] == 1
    assert diagnostics["summary"]["zero_category_claims_blocked"] is True


def test_turn_diagnostics_low_confidence_fallback_remains_visible(tmp_path):
    path = _write(
        tmp_path / "main.jsonl",
        [_turn_with_content((1, 2, 3), [{"type": "text", "text": "Done."}], msg_id="msg_done")],
    )

    turn = report.analyze_session(path, include_turn_diagnostics=True)["turn_diagnostics"]["turns"][0]
    assert turn["primary_category"] == "semantic_decision"
    assert turn["confidence"] == "low"
    assert turn["requires_manual_adjudication"] is True


def test_turn_diagnostics_unknown_tool_gets_low_confidence_primary(tmp_path):
    path = _write(
        tmp_path / "main.jsonl",
        [
            _turn_with_content(
                (1, 2, 3),
                [{"type": "tool_use", "name": "Bash", "input": {"command": "custom-command"}}],
                msg_id="msg_unknown",
            )
        ],
    )

    turn = report.analyze_session(path, include_turn_diagnostics=True)["turn_diagnostics"]["turns"][0]
    assert turn["primary_category"] == "semantic_decision"
    assert turn["unknown_tool_names"] == ["Bash"]
    assert turn["confidence"] == "low"
    assert turn["requires_manual_adjudication"] is True


def test_turn_diagnostics_disclose_empty_unclassified_turn(tmp_path):
    path = _write(
        tmp_path / "main.jsonl",
        [_turn_with_content((1, 2, 3), [], msg_id="msg_empty")],
    )

    diagnostics = report.analyze_session(path, include_turn_diagnostics=True)["turn_diagnostics"]
    assert diagnostics["turns"][0]["primary_category"] is None
    assert diagnostics["summary"]["unclassified_turns"] == 1
    assert diagnostics["summary"]["manual_adjudication_required"] == 1


def test_report_diagnostics_include_role_totals_precedence_and_compaction_duration(tmp_path):
    boundary = {
        "type": "system",
        "subtype": "compact_boundary",
        "compactMetadata": {"durationMs": 4321},
    }
    path = _write(
        tmp_path / "main.jsonl",
        [
            _turn_with_content(
                (1, 2, 3),
                [{"type": "tool_use", "name": "Read", "input": {"file_path": "input.json"}}],
                msg_id="msg_read",
            ),
            boundary,
        ],
    )

    result = report.build_report([path], include_turn_diagnostics=True)
    assert result["turn_diagnostics"]["telemetry_only"] is True
    assert result["turn_diagnostics"]["pricing_table_version"] == "2026-08-05"
    assert result["turn_diagnostics"]["classification_precedence"][0] == "agent_dispatch"
    assert result["turn_diagnostics"]["summary"]["role_counts"] == {"appsec-advisor:test-role": 1}
    session = result["sessions"][0]["turn_diagnostics"]
    assert session["compaction_duration_ms"] == 4321
    assert session["compactions_with_duration"] == 1


def test_before_cutoff_reproduces_bounded_session(tmp_path):
    first = _turn((1, 2, 3), "Stage 1", msg_id="msg_1")
    first["timestamp"] = "2026-08-05T10:00:00Z"
    second = _turn((4, 5, 6), "Stage 2", msg_id="msg_2")
    second["timestamp"] = "2026-08-05T10:05:00Z"
    path = _write(tmp_path / "main.jsonl", [first, second])

    result = report.build_report(
        [path],
        include_turn_diagnostics=True,
        before="2026-08-05T10:01:00Z",
    )
    assert result["turn_diagnostics"]["summary"]["turns"] == 1
    assert result["turn_diagnostics"]["before"] == "2026-08-05T10:01:00Z"


def test_before_cutoff_rejects_timestamp_without_offset(tmp_path):
    path = _write(tmp_path / "main.jsonl", [_turn((1, 2, 3), "Stage 1")])
    try:
        report.build_report([path], before="2026-08-05T10:01:00")
    except ValueError as exc:
        assert "UTC offset" in str(exc)
    else:
        raise AssertionError("timestamp without offset was accepted")


def test_default_report_remains_without_turn_diagnostics(tmp_path):
    path = _write(tmp_path / "main.jsonl", [_turn((1, 2, 3), "Stage 1")])
    result = report.build_report([path])
    assert "turn_diagnostics" not in result
    assert "turn_diagnostics" not in result["sessions"][0]


def test_cli_turn_diagnostics_require_json(tmp_path, capsys):
    path = _write(tmp_path / "main.jsonl", [_turn((1, 2, 3), "Stage 1")])
    assert report.main(["--turn-diagnostics", str(path)]) == 2
    assert "requires --json" in capsys.readouterr().err


def test_cli_json_turn_diagnostics(tmp_path, capsys):
    path = _write(tmp_path / "main.jsonl", [_turn((1, 2, 3), "Analyze threat evidence")])
    assert report.main(["--json", "--turn-diagnostics", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["turn_diagnostics"]["schema_version"] == 1
    assert result["turn_diagnostics"]["summary"]["turns"] == 1


def test_startup_measurements_validate_provider_and_controlled_ab(tmp_path):
    path = tmp_path / "startup.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "measurements": [
                    _startup_record(),
                    _startup_record(
                        measurement_id="role-controlled-ab",
                        layer="role_definition",
                        measurement_method="controlled_startup_ab",
                        measured_tokens=1200,
                        baseline_resident_tokens=20_000,
                        variant_resident_tokens=21_200,
                        changed_variable="architecture analyst definition",
                        review_status="pending",
                    ),
                ],
            }
        )
    )

    result = report.load_startup_measurements(path)
    assert result["summary"] == {
        "measurements": 2,
        "reviewed": 1,
        "pending_review": 1,
        "layers": {"role_definition": 1, "shared_kernel": 1},
        "release_claim_blocked": True,
    }


def test_startup_measurements_reject_unbounded_or_inconsistent_records(tmp_path):
    cases = [
        _startup_record(extra="not allowed"),
        _startup_record(tool_allow_list=["Read", "Read"]),
        _startup_record(task_sha256="not-a-hash"),
        _startup_record(
            measurement_method="controlled_startup_ab",
            baseline_resident_tokens=100,
            variant_resident_tokens=200,
            measured_tokens=99,
        ),
    ]
    for index, record in enumerate(cases):
        path = tmp_path / f"bad-{index}.json"
        path.write_text(json.dumps({"schema_version": 1, "measurements": [record]}))
        try:
            report.load_startup_measurements(path)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid startup record {index} was accepted")


def test_startup_measurements_reject_duplicate_ids(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "measurements": [_startup_record(), _startup_record()],
            }
        )
    )
    try:
        report.load_startup_measurements(path)
    except ValueError as exc:
        assert "unique" in str(exc)
    else:
        raise AssertionError("duplicate startup measurement IDs were accepted")


def test_cli_attaches_startup_measurements(tmp_path, capsys):
    transcript = _write(tmp_path / "main.jsonl", [_turn((1, 2, 3), "Analyze")])
    measurements = tmp_path / "startup.json"
    measurements.write_text(json.dumps({"schema_version": 1, "measurements": [_startup_record()]}))
    assert (
        report.main(
            [
                "--json",
                "--startup-measurements",
                str(measurements),
                str(transcript),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["startup_layer_measurements"]["summary"]["reviewed"] == 1
