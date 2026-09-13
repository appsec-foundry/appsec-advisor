"""Guards for completion_relay: the run's closing message carries the printed summary.

Runs rewrote the completion summary in their closing message and dropped Next
Steps with its team questions. These tests drive the rule the way the host
does — the summary script records what it printed, the outermost Stop hook
reviews the closing message — on neutral repositories.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import acquire_lock
import completion_relay as relay
import hook_payload
import pytest
import render_completion_summary as rcs

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_LOGGER = REPO_ROOT / "scripts" / "agent_logger.py"
RUN_IDENTITY_VARS = ("APPSEC_RUN_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "OUTPUT_DIR")
RUN_ID = "run-1788592678-3277507"


def _summary(root: str, finding: str = "F-003", weakness: str = "W-001") -> str:
    report = f"{root}/docs/security/threat-model.md"
    rule = "═" * 62
    return (
        f"{rule}\n  Assessment complete: Create Threat Model\n{rule}\n\n"
        "Next Steps\n"
        f'  - Open the report — {report} → start at "Management Summary"\n'
        "  - Triage the findings — /appsec-advisor:review-threat-model\n"
        "  - Open questions for the team:\n"
        f"      - [{weakness}](<{report}#{weakness.lower()}>): [{finding}](<{report}#{finding.lower()}>)"
        " — Which services accept these tokens?\n"
        "  - Or just ask me:\n"
        '      "What should I fix first?"\n\n'
        "Logs\n"
        f"  Agent run  : {root}/docs/security/.agent-run.log\n"
    )


def _rewrite(root: str) -> str:
    """The shape runs produced: own headings and a table, Next Steps in one sentence."""
    return (
        "**Assessment complete: Create Threat Model**\n\n"
        f"**Repository:** `{root}`\n\n"
        "| Format | Path |\n|---|---|\n| Markdown | `docs/security/threat-model.md` |\n\n"
        "**Next steps:** Open the report, or run `/appsec-advisor:review-threat-model` to triage.\n"
    )


def _clear_run_identity(monkeypatch) -> None:
    for name in RUN_IDENTITY_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def run_dir(tmp_path, monkeypatch):
    """An output directory whose lock this run holds, as during completion."""
    _clear_run_identity(monkeypatch)
    monkeypatch.setenv("APPSEC_RUN_ID", RUN_ID)
    output = tmp_path / "docs" / "security"
    output.mkdir(parents=True)
    acquire_lock._write_lock(output / ".appsec-lock", 4242, 1788592678, RUN_ID)
    return output


class TestMissingLines:
    @pytest.mark.parametrize(
        "relay_of",
        [
            lambda text: text,
            lambda text: "Here is the completion summary:\n```\n" + text + "```\nDone.",
            lambda text: "\n".join(line.strip() for line in text.splitlines()),
        ],
        ids=["as-printed", "fenced-with-lead-in", "reindented"],
    )
    def test_a_relay_that_keeps_every_line_misses_nothing(self, relay_of):
        text = _summary("/srv/app")
        assert relay.missing_lines(text, relay_of(text)) == []

    def test_a_rewrite_misses_next_steps_and_the_team_questions(self):
        missing = relay.missing_lines(_summary("/srv/app"), _rewrite("/srv/app"))
        assert "Next Steps" in missing
        assert "- Open questions for the team:" in missing

    def test_a_dropped_block_is_named(self):
        text = _summary("/srv/app")
        without_logs = text.split("\nLogs\n")[0]
        assert relay.missing_lines(text, without_logs) == ["Logs", "Agent run : /srv/app/docs/security/.agent-run.log"]

    def test_a_moved_block_counts_as_missing(self):
        text = _summary("/srv/app")
        head, logs = text.split("\nLogs\n")
        assert relay.missing_lines(text, "Logs\n" + logs + head)


class TestPersist:
    def test_records_the_printed_summary_for_the_run_holding_the_lock(self, run_dir):
        relay.persist(run_dir, "line one\n")
        record = json.loads((run_dir / relay.RECORD).read_text(encoding="utf-8"))
        assert record == {"run_id": RUN_ID, "summary": "line one\n"}

    def test_records_nothing_without_a_lock(self, tmp_path, monkeypatch):
        _clear_run_identity(monkeypatch)
        monkeypatch.setenv("APPSEC_RUN_ID", RUN_ID)
        relay.persist(tmp_path, "line one\n")
        assert not (tmp_path / relay.RECORD).exists()

    def test_records_nothing_under_another_runs_lock(self, run_dir, monkeypatch):
        monkeypatch.setenv("APPSEC_RUN_ID", "run-1788000000-1")
        relay.persist(run_dir, "line one\n")
        assert not (run_dir / relay.RECORD).exists()


class TestReview:
    def test_a_rewrite_is_returned_once_then_the_session_stops(self, run_dir):
        relay.persist(run_dir, _summary("/srv/app"))
        assert relay.review_final_message(run_dir, "", _rewrite("/srv/app"), retry=False)
        assert json.loads((run_dir / relay.RECORD).read_text(encoding="utf-8"))["returned"] is True
        # A host that reports no stop_hook_active still gets no second return.
        assert relay.review_final_message(run_dir, "", _rewrite("/srv/app"), retry=False) == []
        assert not (run_dir / relay.RECORD).exists()

    def test_the_hosts_retry_is_never_returned(self, run_dir):
        relay.persist(run_dir, _summary("/srv/app"))
        assert relay.review_final_message(run_dir, "", _rewrite("/srv/app"), retry=True) == []
        assert not (run_dir / relay.RECORD).exists()

    def test_a_verbatim_relay_lets_the_session_stop(self, run_dir):
        relay.persist(run_dir, _summary("/srv/app"))
        assert relay.review_final_message(run_dir, "", _summary("/srv/app"), retry=False) == []
        assert not (run_dir / relay.RECORD).exists()

    def test_another_runs_record_is_left_for_its_session(self, run_dir, monkeypatch):
        relay.persist(run_dir, _summary("/srv/app"))
        monkeypatch.setenv("APPSEC_RUN_ID", "run-1788000000-1")
        assert relay.review_final_message(run_dir, "", _rewrite("/srv/app"), retry=False) == []
        assert (run_dir / relay.RECORD).exists()

    def test_no_closing_message_ends_the_review(self, run_dir):
        relay.persist(run_dir, _summary("/srv/app"))
        assert relay.review_final_message(run_dir, "", "", retry=False) == []
        assert not (run_dir / relay.RECORD).exists()

    def test_a_malformed_record_is_discarded(self, run_dir):
        (run_dir / relay.RECORD).write_text("{", encoding="utf-8")
        assert relay.review_final_message(run_dir, "", _rewrite("/srv/app"), retry=False) == []
        assert not (run_dir / relay.RECORD).exists()

    def test_without_a_record_there_is_nothing_to_review(self, tmp_path):
        assert relay.review_final_message(tmp_path, "", _rewrite("/srv/app"), retry=False) == []


class TestFinalMessage:
    def test_reads_the_text_after_the_last_tool_call(self, tmp_path):
        records = [
            {"message": {"role": "assistant", "content": [{"type": "text", "text": "Running the summary."}]}},
            {"message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "Bash"}]}},
            {"message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1"}]}},
            {"type": "attachment"},
            {"message": {"role": "assistant", "content": [{"type": "text", "text": "Next Steps"}]}},
            {"message": {"role": "assistant", "content": "  - Open the report"}},
        ]
        transcript = tmp_path / "session.jsonl"
        transcript.write_text("\n".join(json.dumps(r) for r in records) + "\nnot json\n", encoding="utf-8")
        assert relay.final_message(str(transcript)) == "Next Steps\n  - Open the report"

    def test_a_session_without_a_transcript_yields_nothing(self, tmp_path):
        assert relay.final_message(str(tmp_path / "absent.jsonl")) == ""
        assert relay.final_message("") == ""


def test_the_stop_payload_carries_the_retry_flag_and_the_closing_message():
    base = {"hook_event_name": "Stop", "session_id": "s", "transcript_path": "/t.jsonl", "cwd": "/"}
    event = hook_payload.parse({**base, "stop_hook_active": True, "last_assistant_message": "Done."}, "Stop")
    assert event.stop_hook_active is True
    assert event.last_assistant_message == "Done."
    bare = hook_payload.parse(base, "Stop")
    assert (bare.stop_hook_active, bare.last_assistant_message, bare.problems) == (False, "", ())


class TestTheSummaryScriptRecordsWhatItPrinted:
    @pytest.fixture
    def summary_run(self, run_dir, monkeypatch):
        (run_dir / "threat-model.md").write_text("# Threat Model\n", encoding="utf-8")
        monkeypatch.setattr(rcs, "render_summary", lambda *args, **kwargs: "line one\nline two\n")
        monkeypatch.setattr(rcs, "extract_run_statistics", lambda *args, **kwargs: {})
        monkeypatch.setattr(rcs, "_export_deliverables_if_configured", lambda output_dir: None)
        monkeypatch.setattr(rcs, "_stamp_slug_if_configured", lambda output_dir: None)
        return ["--output-dir", str(run_dir), "--repo-root", str(run_dir.parent.parent)]

    def test_the_printing_call_records_its_stdout(self, run_dir, summary_run, capsys):
        assert rcs.main(summary_run) == 0
        printed = capsys.readouterr().out
        assert json.loads((run_dir / relay.RECORD).read_text(encoding="utf-8"))["summary"] == printed

    def test_the_placeholder_call_records_nothing(self, run_dir, summary_run):
        assert rcs.main([*summary_run, "--no-print"]) == 0
        assert not (run_dir / relay.RECORD).exists()


class TestTheOutermostStop:
    """The hook as the host runs it: a Stop payload on stdin, a decision on stdout."""

    @staticmethod
    def _stop(repo: Path, message: str, *, retry: bool = False, run_id: str = RUN_ID) -> str:
        payload = {
            "hook_event_name": "Stop",
            "session_id": "0f3c9a21-5d7e-4c1b-9a60-2b8e7d4f1c55",
            "transcript_path": str(repo / "absent.jsonl"),
            "cwd": str(repo),
            "stop_hook_active": retry,
            "last_assistant_message": message,
        }
        env = {key: value for key, value in os.environ.items() if key not in RUN_IDENTITY_VARS}
        env.update({"APPSEC_RUN_ID": run_id, "CLAUDE_PLUGIN_ROOT": str(REPO_ROOT)})
        result = subprocess.run(
            [sys.executable, str(AGENT_LOGGER)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            cwd=repo,
            env=env,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    @staticmethod
    def _completed_run(tmp_path, monkeypatch, name: str, **names) -> tuple[Path, Path, str]:
        """Record a printed summary under the run's lock, then release the lock."""
        repo = tmp_path / name
        output = repo / "docs" / "security"
        output.mkdir(parents=True)
        _clear_run_identity(monkeypatch)
        monkeypatch.setenv("APPSEC_RUN_ID", RUN_ID)
        acquire_lock._write_lock(output / ".appsec-lock", 4242, 1788592678, RUN_ID)
        summary = _summary(str(repo), **names)
        relay.persist(output, summary)
        (output / ".appsec-lock").unlink()
        return repo, output, summary

    @pytest.mark.parametrize(
        ("name", "names"),
        [("service-a", {}), ("billing/api gateway", {"finding": "F-114", "weakness": "W-007"})],
        ids=["neutral", "other-names-and-paths"],
    )
    def test_a_rewritten_summary_is_returned_once(self, tmp_path, monkeypatch, name, names):
        repo, output, _ = self._completed_run(tmp_path, monkeypatch, name, **names)
        decision = json.loads(self._stop(repo, _rewrite(str(repo))))
        assert decision == {"decision": "block", "reason": relay.RETRY_INSTRUCTION}
        assert "SUMMARY_NOT_RELAYED" in (output / ".hook-events.log").read_text(encoding="utf-8")
        assert self._stop(repo, _rewrite(str(repo)), retry=True) == ""
        assert not (output / relay.RECORD).exists()

    def test_a_verbatim_summary_lets_the_session_stop(self, tmp_path, monkeypatch):
        repo, output, summary = self._completed_run(tmp_path, monkeypatch, "service-a")
        assert self._stop(repo, summary) == ""
        assert not (output / relay.RECORD).exists()

    def test_a_stop_while_the_run_holds_its_lock_is_not_reviewed(self, tmp_path, monkeypatch):
        repo, output, _ = self._completed_run(tmp_path, monkeypatch, "service-a")
        acquire_lock._write_lock(output / ".appsec-lock", 4242, 1788592678, RUN_ID)
        assert self._stop(repo, _rewrite(str(repo))) == ""
        assert (output / relay.RECORD).exists()

    def test_an_unrelated_session_is_never_sent_back(self, tmp_path, monkeypatch):
        repo, output, _ = self._completed_run(tmp_path, monkeypatch, "service-a")
        assert self._stop(repo, "Unrelated answer.", run_id="run-1788000000-1") == ""
        assert (output / relay.RECORD).exists()
