"""Guards for completion_relay: the reader sees the printed summary exactly once.

Asking the orchestrator to reproduce the summary failed twice over: runs
rewrote it, and a Stop hook that returned the turn on a dropped line showed it
twice. The plugin now shows the record as a hook ``systemMessage`` (headless:
``run-headless.sh`` prints it). These tests drive that the way the host does,
on neutral repositories.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import renderers.render_completion_summary as rcs
import runtime.acquire_lock as acquire_lock
import runtime.agent_logger as agent_logger
import runtime.completion_relay as relay

REPO_ROOT = Path(__file__).resolve().parent.parent
AGENT_LOGGER = REPO_ROOT / "scripts" / "runtime/agent_logger.py"
RELAY = REPO_ROOT / "scripts" / "runtime/completion_relay.py"
COMPLETION_SKILL = REPO_ROOT / "skills" / "create-threat-model" / "SKILL-thin-completion.md"
RUN_IDENTITY_VARS = ("APPSEC_RUN_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "OUTPUT_DIR", "APPSEC_HEADLESS")
RUN_ID = "run-1788592678-3277507"
OTHER_RUN_ID = "run-1788000000-1"


def _summary(root: str) -> str:
    report = f"{root}/docs/security/threat-model.md"
    rule = "═" * 62
    return (
        f"{rule}\n  Assessment complete: Create Threat Model\n{rule}\n\n"
        "Next Steps\n"
        f'  - Open the report — {report} → start at "Management Summary"\n'
        "  - Triage the findings — /appsec-advisor:review-threat-model\n\n"
        "Logs\n"
        f"  Agent run  : {root}/docs/security/.agent-run.log\n"
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
        monkeypatch.setenv("APPSEC_RUN_ID", OTHER_RUN_ID)
        relay.persist(run_dir, "line one\n")
        assert not (run_dir / relay.RECORD).exists()


class TestTake:
    @pytest.mark.parametrize("root", ["/srv/app", "/work/billing api"])
    def test_the_summary_is_returned_once(self, run_dir, root):
        relay.persist(run_dir, _summary(root))
        assert relay.take(run_dir) == _summary(root)
        assert relay.take(run_dir) == ""
        assert not (run_dir / relay.RECORD).exists()

    def test_another_runs_record_is_left_for_that_run(self, run_dir, monkeypatch):
        relay.persist(run_dir, _summary("/srv/app"))
        monkeypatch.setenv("APPSEC_RUN_ID", OTHER_RUN_ID)
        assert relay.take(run_dir) == ""
        assert (run_dir / relay.RECORD).exists()

    @pytest.mark.parametrize("content", ["{", "[]", '{"run_id": "' + RUN_ID + '", "summary": 3}'])
    def test_a_malformed_record_is_discarded_unshown(self, run_dir, content):
        (run_dir / relay.RECORD).write_text(content, encoding="utf-8")
        assert relay.take(run_dir) == ""
        assert not (run_dir / relay.RECORD).exists()

    def test_without_a_record_there_is_nothing_to_take(self, tmp_path):
        assert relay.take(tmp_path) == ""


class TestHookNotice:
    def test_shows_the_summary_as_a_system_message_once(self, run_dir):
        relay.persist(run_dir, _summary("/srv/app"))
        assert relay.hook_notice(run_dir, "") == {"systemMessage": _summary("/srv/app").rstrip("\n")}
        assert relay.hook_notice(run_dir, "") is None

    def test_a_sub_agent_event_never_takes_the_record(self, run_dir):
        relay.persist(run_dir, _summary("/srv/app"))
        assert relay.hook_notice(run_dir, "", agent_id="a1b2c3") is None
        assert (run_dir / relay.RECORD).exists()

    def test_a_headless_session_leaves_the_record_to_the_wrapper(self, run_dir, monkeypatch):
        relay.persist(run_dir, _summary("/srv/app"))
        monkeypatch.setenv("APPSEC_HEADLESS", "1")
        assert relay.hook_notice(run_dir, "") is None
        assert (run_dir / relay.RECORD).exists()

    def test_a_blank_summary_shows_nothing(self, run_dir):
        relay.persist(run_dir, "\n")
        assert relay.hook_notice(run_dir, "") is None
        assert not (run_dir / relay.RECORD).exists()


class TestTheHeadlessWrapper:
    def _cli(self, output: Path, run_id: str) -> str:
        env = {key: value for key, value in os.environ.items() if key not in RUN_IDENTITY_VARS}
        env.update({"APPSEC_RUN_ID": run_id, "APPSEC_HEADLESS": "1"})
        result = subprocess.run(
            [sys.executable, str(RELAY), "--output-dir", str(output)],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    def test_prints_the_summary_once(self, run_dir):
        relay.persist(run_dir, _summary("/srv/app"))
        assert self._cli(run_dir, RUN_ID) == _summary("/srv/app")
        assert self._cli(run_dir, RUN_ID) == ""

    def test_leaves_another_runs_record_alone(self, run_dir):
        relay.persist(run_dir, _summary("/srv/app"))
        assert self._cli(run_dir, OTHER_RUN_ID) == ""
        assert (run_dir / relay.RECORD).exists()

    def test_the_wrapper_prints_the_record_after_the_result_text(self):
        script = (REPO_ROOT / "scripts" / "run-headless.sh").read_text(encoding="utf-8")
        result_text = script.index("--result-text")
        relay_call = script.index('runtime/completion_relay.py" --output-dir "$OUTPUT_PATH"')
        assert result_text < relay_call


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


class TestTheHooks:
    """The hook as the host runs it: a payload on stdin, hook output on stdout."""

    SESSION = "0f3c9a21-5d7e-4c1b-9a60-2b8e7d4f1c55"

    def _hook(self, repo: Path, payload: dict, *, run_id: str = RUN_ID, headless: bool = False) -> str:
        payload = {
            "session_id": self.SESSION,
            "transcript_path": str(repo / "absent.jsonl"),
            "cwd": str(repo),
            **payload,
        }
        env = {key: value for key, value in os.environ.items() if key not in RUN_IDENTITY_VARS}
        env.update({"APPSEC_RUN_ID": run_id, "CLAUDE_PLUGIN_ROOT": str(REPO_ROOT)})
        if headless:
            env["APPSEC_HEADLESS"] = "1"
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

    def _post_tool_use(self, repo: Path, tool: str = "Bash", **extra) -> str:
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": tool,
            "tool_use_id": "toolu_01",
            "tool_input": {"command": "printf '%s\\n' \"$S\""},
            "tool_response": {"stdout": "", "stderr": ""},
        }
        return self._hook(repo, {**payload, **extra.pop("payload", {})}, **extra)

    def _stop(self, repo: Path, **extra) -> str:
        return self._hook(repo, {"hook_event_name": "Stop"}, **extra)

    @staticmethod
    def _completed_run(tmp_path, monkeypatch, name: str) -> tuple[Path, Path, str]:
        """Record a printed summary under the run's lock, then release the lock."""
        repo = tmp_path / name
        output = repo / "docs" / "security"
        output.mkdir(parents=True)
        _clear_run_identity(monkeypatch)
        monkeypatch.setenv("APPSEC_RUN_ID", RUN_ID)
        acquire_lock._write_lock(output / ".appsec-lock", 4242, 1788592678, RUN_ID)
        summary = _summary(str(repo))
        relay.persist(output, summary)
        (output / ".appsec-lock").unlink()
        return repo, output, summary

    @pytest.mark.parametrize("name", ["service-a", "billing/api gateway"], ids=["neutral", "other-names-and-paths"])
    def test_the_printing_bash_call_shows_the_summary_once(self, tmp_path, monkeypatch, name):
        repo, output, summary = self._completed_run(tmp_path, monkeypatch, name)
        assert json.loads(self._post_tool_use(repo)) == {"systemMessage": summary.rstrip("\n")}
        assert "SUMMARY_SHOWN" in (output / ".hook-events.log").read_text(encoding="utf-8")
        assert self._post_tool_use(repo) == ""
        assert self._stop(repo) == ""

    def test_the_closing_stop_shows_a_summary_left_over(self, tmp_path, monkeypatch):
        repo, output, summary = self._completed_run(tmp_path, monkeypatch, "service-a")
        assert json.loads(self._stop(repo)) == {"systemMessage": summary.rstrip("\n")}
        assert not (output / relay.RECORD).exists()

    def test_another_tool_does_not_take_the_record(self, tmp_path, monkeypatch):
        repo, output, _ = self._completed_run(tmp_path, monkeypatch, "service-a")
        read = {"tool_input": {"file_path": str(output / "threat-model.md")}, "tool_response": ""}
        assert self._post_tool_use(repo, "Read", payload=read) == ""
        assert (output / relay.RECORD).exists()

    def test_a_sub_agents_bash_call_does_not_take_the_record(self, tmp_path, monkeypatch):
        repo, output, _ = self._completed_run(tmp_path, monkeypatch, "service-a")
        sub_agent = {"agent_id": "a1b2c3d4", "agent_type": "appsec-advisor:appsec-recon-scanner"}
        assert self._post_tool_use(repo, payload=sub_agent) == ""
        assert (output / relay.RECORD).exists()

    def test_a_stop_while_the_run_holds_its_lock_shows_nothing(self, tmp_path, monkeypatch):
        repo, output, _ = self._completed_run(tmp_path, monkeypatch, "service-a")
        acquire_lock._write_lock(output / ".appsec-lock", 4242, 1788592678, RUN_ID)
        assert self._stop(repo) == ""
        assert (output / relay.RECORD).exists()

    def test_an_unrelated_session_is_never_shown_the_summary(self, tmp_path, monkeypatch):
        repo, output, _ = self._completed_run(tmp_path, monkeypatch, "service-a")
        assert self._post_tool_use(repo, run_id=OTHER_RUN_ID) == ""
        assert self._stop(repo, run_id=OTHER_RUN_ID) == ""
        assert (output / relay.RECORD).exists()

    def test_a_headless_session_leaves_the_record_to_the_wrapper(self, tmp_path, monkeypatch):
        repo, output, _ = self._completed_run(tmp_path, monkeypatch, "service-a")
        assert self._post_tool_use(repo, headless=True) == ""
        assert self._stop(repo, headless=True) == ""
        assert (output / relay.RECORD).exists()


def test_the_logger_checks_for_the_record_relay_owns():
    assert agent_logger._SUMMARY_RECORD == relay.RECORD


def test_the_completion_runtime_does_not_ask_for_a_copy_of_the_summary():
    text = COMPLETION_SKILL.read_text(encoding="utf-8")
    assert "exactly as printed" not in text
    assert "Do not reproduce, rewrite or summarize it" in text
