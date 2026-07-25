"""Tests for scripts/headless_usage.py and its run-headless.sh wiring.

The readout has one job: show the run's real token spend per model, or show
nothing. Most of these tests therefore pin the *negative* path — a truncated,
empty or event-only capture must yield "no authoritative result" so the caller
falls back to an explicitly labelled estimate instead of printing a confident
lower bound.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHELL = ROOT / "scripts" / "run-headless.sh"


def _load_module():
    spec = importlib.util.spec_from_file_location("_hu", ROOT / "scripts" / "headless_usage.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hu = _load_module()


def _result_obj(**overrides):
    obj = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "num_turns": 12,
        "duration_ms": 900_000,
        "session_id": "abc",
        "total_cost_usd": 3.41,
        "modelUsage": {
            "claude-sonnet-4-6-20260101": {
                "inputTokens": 12_043,
                "outputTokens": 38_221,
                "cacheReadInputTokens": 1_204_880,
                "cacheCreationInputTokens": 420_113,
                "costUSD": 3.10,
                "canonicalModel": "claude-sonnet-4-6",
            },
            "claude-haiku-4-5-20251001": {
                "inputTokens": 812,
                "outputTokens": 2_004,
                "cacheReadInputTokens": 44_120,
                "cacheCreationInputTokens": 12_000,
                "costUSD": 0.31,
                "canonicalModel": "claude-haiku-4-5",
            },
        },
    }
    obj.update(overrides)
    return obj


# ---------------------------------------------------------------------------
# load_result — every capture shape the CLI can produce
# ---------------------------------------------------------------------------
class TestLoadResult:
    def test_single_object(self, tmp_path):
        """`--output-format json` writes exactly one result object."""
        f = tmp_path / "c.json"
        f.write_text(json.dumps(_result_obj()), encoding="utf-8")
        assert hu.load_result(f)["total_cost_usd"] == 3.41

    def test_verbose_json_array(self, tmp_path):
        """`--output-format json --verbose` writes an ARRAY of every event.

        run-headless.sh forwards its own --verbose to the CLI, so this shape is
        reached on any verbose run — not a hypothetical.
        """
        f = tmp_path / "c.json"
        f.write_text(
            json.dumps([{"type": "system", "subtype": "init"}, {"type": "assistant"}, _result_obj()]),
            encoding="utf-8",
        )
        assert hu.load_result(f)["total_cost_usd"] == 3.41

    def test_stream_json_lines(self, tmp_path):
        """JSONL: the terminal result line wins, earlier events are ignored."""
        f = tmp_path / "c.jsonl"
        f.write_text(
            "\n".join(
                [
                    json.dumps({"type": "system", "subtype": "init"}),
                    json.dumps({"type": "assistant", "message": {"usage": {"output_tokens": 3}}}),
                    json.dumps(_result_obj()),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        assert hu.load_result(f)["total_cost_usd"] == 3.41

    def test_trailing_garbage_after_result_line(self, tmp_path):
        """A half-written final line must not hide the complete result before it."""
        f = tmp_path / "c.jsonl"
        f.write_text(json.dumps(_result_obj()) + '\n{"type":"partial","x', encoding="utf-8")
        assert hu.load_result(f)["total_cost_usd"] == 3.41

    @pytest.mark.parametrize(
        "content",
        [
            "",
            "   \n",
            '{"type":"result","total_cost',  # truncated by a SIGKILL
            json.dumps({"type": "system", "subtype": "init"}),  # events only, no result
            json.dumps([{"type": "assistant"}]),  # verbose array, run never finished
            "not json at all",
        ],
        ids=["empty", "blank", "truncated", "events-only", "array-no-result", "garbage"],
    )
    def test_no_authoritative_result(self, tmp_path, content):
        """Anything short of a complete result object yields None.

        This is the reliability contract: an incomplete capture must produce
        *no* number, never a partial one.
        """
        f = tmp_path / "c.json"
        f.write_text(content, encoding="utf-8")
        assert hu.load_result(f) is None

    def test_missing_file(self, tmp_path):
        assert hu.load_result(tmp_path / "nope.json") is None


# ---------------------------------------------------------------------------
# extract_usage — per-model breakdown
# ---------------------------------------------------------------------------
class TestExtractUsage:
    def test_per_model_rows(self):
        usage = hu.extract_usage(_result_obj())
        assert [m["model"] for m in usage["models"]] == ["claude-sonnet-4-6", "claude-haiku-4-5"]
        sonnet = usage["models"][0]
        assert sonnet["input"] == 12_043
        assert sonnet["output"] == 38_221
        assert sonnet["cache_read"] == 1_204_880
        assert sonnet["cache_write"] == 420_113
        assert sonnet["cost_usd"] == 3.10
        assert sonnet["total_tokens"] == 12_043 + 38_221 + 1_204_880 + 420_113

    def test_sorted_by_cost_descending(self):
        """The expensive model is the one the operator needs to see first."""
        obj = _result_obj()
        obj["modelUsage"]["claude-haiku-4-5-20251001"]["costUSD"] = 99.0
        usage = hu.extract_usage(obj)
        assert usage["models"][0]["model"] == "claude-haiku-4-5"

    def test_dated_snapshots_stay_separate_rows(self):
        """Two dated ids of one canonical model must not be silently merged —
        the operator needs to see that two snapshots were billed."""
        obj = _result_obj(
            modelUsage={
                "claude-sonnet-4-6-20260101": {
                    "outputTokens": 10,
                    "costUSD": 1.0,
                    "canonicalModel": "claude-sonnet-4-6",
                },
                "claude-sonnet-4-6-20260201": {
                    "outputTokens": 20,
                    "costUSD": 2.0,
                    "canonicalModel": "claude-sonnet-4-6",
                },
            }
        )
        usage = hu.extract_usage(obj)
        assert len(usage["models"]) == 2
        assert {m["model_id"] for m in usage["models"]} == {
            "claude-sonnet-4-6-20260101",
            "claude-sonnet-4-6-20260201",
        }

    def test_falls_back_to_model_id_without_canonical_name(self):
        obj = _result_obj(modelUsage={"some-model": {"outputTokens": 5, "costUSD": 0.1}})
        assert hu.extract_usage(obj)["models"][0]["model"] == "some-model"

    def test_missing_and_malformed_fields_are_zero(self):
        obj = _result_obj(modelUsage={"m": {"outputTokens": "x"}}, total_cost_usd=None)
        usage = hu.extract_usage(obj)
        assert usage["models"][0]["output"] == 0
        assert usage["total_cost_usd"] == 0.0

    def test_modelusage_absent(self):
        """Older CLIs may only carry the total; the total must still survive."""
        obj = _result_obj()
        del obj["modelUsage"]
        usage = hu.extract_usage(obj)
        assert usage["models"] == []
        assert usage["total_cost_usd"] == 3.41


# ---------------------------------------------------------------------------
# format_table
# ---------------------------------------------------------------------------
class TestFormatTable:
    def test_multi_model_has_total_row(self):
        table = hu.format_table(hu.extract_usage(_result_obj()))
        assert "claude-sonnet-4-6" in table
        assert "claude-haiku-4-5" in table
        assert "total" in table
        assert "$3.41" in table
        # Per-model token columns are the point of the breakdown.
        assert "12,043" in table
        assert "1,204,880" in table

    def test_total_row_sums_the_model_columns(self):
        table = hu.format_table(hu.extract_usage(_result_obj()))
        total_line = [ln for ln in table.splitlines() if ln.strip().startswith("total")][0]
        assert f"{12_043 + 812:,}" in total_line
        assert f"{1_204_880 + 44_120:,}" in total_line

    def test_single_model_run_has_no_redundant_total(self):
        obj = _result_obj(modelUsage={"m": {"outputTokens": 5, "costUSD": 0.1}}, total_cost_usd=0.1)
        table = hu.format_table(hu.extract_usage(obj))
        assert "total" not in table

    def test_subcent_cost_keeps_digits(self):
        """$0.00 would read as free; a cheap run must still show a number."""
        obj = _result_obj(
            modelUsage={"m": {"outputTokens": 5, "costUSD": 0.0034}},
            total_cost_usd=0.0034,
        )
        table = hu.format_table(hu.extract_usage(obj))
        assert "$0.0034" in table

    def test_labels_the_source_and_the_subscription_caveat(self):
        """Both labels are the honesty contract: where the number comes from,
        and that it is list price rather than what a subscription is billed."""
        table = hu.format_table(hu.extract_usage(_result_obj()))
        assert "/cost" in table
        assert "subscription" in table


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
class TestCli:
    def test_table_exit_zero(self, tmp_path, run_plugin_script):
        f = tmp_path / "c.json"
        f.write_text(json.dumps(_result_obj()), encoding="utf-8")
        r = run_plugin_script("headless_usage.py", str(f))
        assert r.returncode == 0
        assert "claude-sonnet-4-6" in r.stdout

    def test_exit_one_without_result(self, tmp_path, run_plugin_script):
        """Exit 1 is the caller's signal to fall back to a labelled estimate."""
        f = tmp_path / "c.json"
        f.write_text("", encoding="utf-8")
        r = run_plugin_script("headless_usage.py", str(f))
        assert r.returncode == 1
        assert r.stdout.strip() == ""

    def test_json_format(self, tmp_path, run_plugin_script):
        f = tmp_path / "c.json"
        f.write_text(json.dumps(_result_obj()), encoding="utf-8")
        r = run_plugin_script("headless_usage.py", str(f), "--format", "json")
        assert r.returncode == 0
        payload = json.loads(r.stdout)
        assert payload["total_cost_usd"] == 3.41
        assert len(payload["models"]) == 2

    def test_result_text(self, tmp_path, run_plugin_script):
        f = tmp_path / "c.json"
        f.write_text(json.dumps(_result_obj(result="Assessment complete.")), encoding="utf-8")
        r = run_plugin_script("headless_usage.py", str(f), "--result-text")
        assert r.returncode == 0
        assert r.stdout.strip() == "Assessment complete."

    def test_result_text_prints_nothing_when_absent(self, tmp_path, run_plugin_script):
        f = tmp_path / "c.json"
        f.write_text(json.dumps(_result_obj()), encoding="utf-8")
        r = run_plugin_script("headless_usage.py", str(f), "--result-text")
        assert r.returncode == 0
        assert r.stdout.strip() == ""


# ---------------------------------------------------------------------------
# run-headless.sh wiring — drift guards
# ---------------------------------------------------------------------------
class TestShellWiring:
    @pytest.fixture(scope="class")
    def body(self) -> str:
        return SHELL.read_text(encoding="utf-8")

    def test_output_format_is_pinned_to_json(self, body):
        """`text` carries no usage data at all. The result object is the only
        readout with total_cost_usd + modelUsage, so the format is not optional."""
        assert 'CLAUDE_CMD="$CLAUDE_CMD --output-format json"' in body
        assert "--output-format $OUTPUT_FORMAT" not in body

    def test_stdout_is_captured_to_the_result_file(self, body):
        assert 'RESULT_CAPTURE="$RESULT_DIR/.headless-result.json"' in body
        assert 'eval "$CLAUDE_CMD" < /dev/null > "$RESULT_CAPTURE" &' in body

    def test_capture_redirect_keeps_claude_a_direct_child(self, body):
        """A pipe would make $! the reader's PID and break the
        `kill -SIG -$CLAUDE_PID` process-group escalation."""
        assert 'eval "$CLAUDE_CMD" < /dev/null |' not in body

    def test_non_result_stdout_is_passed_through(self, body):
        """Redirecting stdout must not cost diagnosability: anything the CLI
        writes there that is not a result object still has to reach the
        operator."""
        assert 'case "$(head -c 1 "$RESULT_CAPTURE")" in' in body
        assert 'cat "$RESULT_CAPTURE"' in body

    def test_final_assistant_text_is_re_emitted(self, body):
        """stdout no longer reaches the terminal, so the text that
        `--output-format text` used to print must be printed by the wrapper."""
        assert "--result-text" in body

    def test_json_flag_still_emits_the_raw_object(self, body):
        assert '[ "$EMIT_RAW_JSON" -eq 1 ] && cat "$RESULT_CAPTURE"' in body

    def test_usage_printed_on_success_failure_and_abort(self, body):
        """A failed or aborted run spent the tokens too."""
        assert body.count("print_usage_summary") >= 3  # definition + abort + summary

    def test_fallback_is_labelled_an_estimate(self, body):
        """The hook-log figure is host-session-only. Presenting it unlabelled
        next to the exact readout would make a lower bound look like the cost."""
        assert "cost_running_total.py" in body
        assert "ESTIMATE" in body
        assert "lower bound" in body

    def test_capture_is_discarded_after_readout(self, body):
        """The capture holds the assistant's final text, which can quote
        repository content — it is scratch, not an artifact."""
        assert "discard_capture_if_consumed" in body
        assert 'rm -f "$RESULT_CAPTURE"' in body
        assert '[ "${KEEP_RUNTIME_FILES:-}" != "true" ] || return 0' in body
