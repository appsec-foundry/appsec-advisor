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
    assert "throughput, not current occupancy" in capsys.readouterr().out
