"""Drift guards for the headless-completion contract in run-headless.sh.

The deterministic compose logic (``_compose_if_ready`` via ``next``) is unit
tested in ``test_orchestration_controller.py``. These tests pin the *shell
wiring* that makes it fire on a bg-ceiling process-kill and that the artifact
gate is fail-closed on a missing ``threat-model.md`` — the 2026-07-03 gap where
a killed run left ``threat-model.yaml`` + fragments but no report and headless
reported ``✓ completed successfully`` (exit 0).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-headless.sh"


def _body() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_shell_invokes_compose_backstop_when_md_missing() -> None:
    """A yaml-present / md-absent run must invoke the controller `next`
    backstop from the shell, not depend on an LLM finalize turn."""
    body = _body()
    assert 'orchestration_controller.py" \\\n        next --output-dir "$RESULT_DIR"' in body
    # The backstop must be gated on yaml-present AND md-absent so it is a no-op
    # for a normally-composed run.
    assert '[ -s "$RESULT_DIR/threat-model.yaml" ] \\' in body
    assert '[ ! -s "$RESULT_DIR/threat-model.md" ]' in body


def test_artifact_gate_is_fail_closed_on_missing_md() -> None:
    """The artifact gate must fail closed when threat-model.md is absent.

    The old gate only failed when BOTH md and yaml were missing, so a
    yaml-without-md run (the process-kill gap) was reported as success.
    """
    body = _body()
    assert 'err "No threat-model.md in $RESULT_DIR — treating as failure (fail-closed)."' in body
    # Guard against a regression back to the md-OR-yaml (fail-open) condition.
    assert '[ ! -s "$RESULT_DIR/threat-model.md" ] && [ ! -s "$RESULT_DIR/threat-model.yaml" ]' not in body


def test_failure_branch_surfaces_run_issues() -> None:
    """On a non-zero exit the rich Run Issues block is normally rendered by the
    LLM Completion turn, which never runs on an abort/kill. The shell must
    regenerate .run-issues.json from the logs and render it deterministically so
    the operator sees WHAT failed, not just `exited with code N`.

    The refresh is now one step of ``terminate_run.py``, which also closes the
    lock and checkpoint the failed run left open. The invariant is unchanged:
    the file is regenerated before it is rendered.
    """
    body = _body()
    assert "--issues-only" in body, "failure branch must render the Run Issues block"
    assert "terminate_run.py" in body, "failure branch must refresh .run-issues.json from the logs before rendering"
    assert body.index("terminate_run.py") < body.index("--issues-only"), (
        "the run issues must be regenerated before they are rendered"
    )
    # Gated on the log existing so it is a no-op for pre-dispatch failures.
    assert '[ -f "$RESULT_DIR/.agent-run.log" ]' in body


def test_progress_monitor_never_replays_a_previous_runs_log() -> None:
    """`.hook-events.log` is appended across runs in one output directory, so a
    bare `tail -F` prints the previous run's last lines before the new run's
    first — which read as a fresh failure, with that run's timestamps."""
    body = _body()
    assert 'tail -n 0 -F "$1" "$2"' in body
    assert 'tail -F "$1"' not in body


def test_every_non_clean_exit_class_reaches_the_terminator() -> None:
    """An interrupt and a failed exit both have to leave one terminal state.
    Without this the lock stays held and live status reports an unknown phase
    until the heartbeat ages out."""
    body = _body()
    assert "--outcome interrupt" in body
    assert "--outcome failure" in body
    interrupt_branch = body.index('if [ "$SIGINT_COUNT" -gt 0 ]; then')
    assert interrupt_branch < body.index("--outcome interrupt") < body.index('exit "$EXIT_CODE"')


def test_failure_branch_prints_full_recovery_command() -> None:
    """The failure hint must print a paste-ready fresh-run command."""
    body = _body()
    # Raw invocation is preserved before the parser consumes it.
    assert 'ORIG_ARGS=""' in body, "must capture the original invocation for the hint"
    # The re-run command is reconstructed (mode flags stripped, one appended).
    assert "_rerun_cmd" in body
    assert "_rerun_cmd --resume" not in body
    assert "_rerun_cmd --rebuild" in body


def test_unsupported_modes_fail_before_output_path_mutation() -> None:
    body = _body()
    guard = '[ "$RESUME_REQUESTED" = "1" ] && die "--resume is not supported by the compact runtime.'
    assert guard in body
    assert body.index(guard) < body.index("# ── Resolve paths")
    for state in ("INCREMENTAL_REQUESTED", "DRY_RUN_REQUESTED", "UNSUPPORTED_RUNTIME_OPTION"):
        assert state in body


def test_effective_mode_is_admitted_before_output_creation_and_dispatch() -> None:
    body = _body()
    admission = 'ADMISSION_RESULT="$(python3 "$PLUGIN_DIR/scripts/orchestration_controller.py"'
    assert admission in body
    assert body.index(admission) < body.index('mkdir -p "$OUTPUT_PATH"')
    assert body.index(admission) < body.index('"$@" < /dev/null')


def test_headless_has_no_generation_escape_hatch() -> None:
    body = _body()
    assert "APPSEC_CONTEXT_V2" not in body
    assert "CONTEXT_V2_SELECTED" not in body
    assert "PERSISTED_RUNTIME_GENERATION" not in body


@pytest.mark.parametrize(
    ("extra_args", "live_phase", "error_text"),
    [
        (["--incremental"], False, "--incremental is not supported"),
        (["--resume"], False, "--resume is not supported"),
        (["--full", "--resume"], False, "--resume is not supported"),
        (["--dry-run"], False, "--dry-run is not supported"),
        (["--max-wall-time", "1"], False, "--max-wall-time is not supported"),
        (["--max-cost", "1"], False, "--max-cost is not supported"),
        ([], True, "APPSEC_LIVE_PHASE=1 is not supported"),
    ],
)
def test_unsupported_mode_exits_before_output_creation_or_claude(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra_args: list[str],
    live_phase: bool,
    error_text: str,
) -> None:
    repo = tmp_path / "repo"
    output = tmp_path / "not-created"
    repo.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "claude-invoked"
    claude = bin_dir / "claude"
    claude.write_text('#!/bin/sh\nprintf invoked > "$CLAUDE_MARKER"\nexit 42\n', encoding="utf-8")
    claude.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("CLAUDE_MARKER", str(marker))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    if live_phase:
        monkeypatch.setenv("APPSEC_LIVE_PHASE", "1")

    result = subprocess.run(
        [str(SCRIPT), "--repo", str(repo), "--output", str(output), *extra_args],
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    assert error_text in result.stderr
    assert not output.exists(), "unsupported mode mutated the requested output path"
    assert not marker.exists(), "unsupported mode reached Claude dispatch"


def test_headless_parser_retains_no_yaml() -> None:
    body = _body()
    assert "|--no-yaml|" in body


def test_default_progress_monitor_is_reaped_after_claude_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    claude = bin_dir / "claude"
    claude.write_text("#!/bin/sh\nsleep 1\nprintf 'CLAUDE_STUB_INVOKED\\n'\nexit 42\n", encoding="utf-8")
    claude.chmod(0o755)

    tail_started = tmp_path / "tail-started"
    tail_stopped = tmp_path / "tail-stopped"
    fake_tail = bin_dir / "tail"
    fake_tail.write_text(
        "#!/bin/sh\n"
        'for arg in "$@"; do\n'
        '  if [ "$arg" = "-F" ]; then\n'
        '    printf "%s\\n" "$$" > "$TAIL_STARTED"\n'
        "    trap 'printf stopped > \"$TAIL_STOPPED\"; exit 0' TERM INT HUP\n"
        "    while :; do sleep 1; done\n"
        "  fi\n"
        "done\n"
        'exec "$REAL_TAIL" "$@"\n',
        encoding="utf-8",
    )
    fake_tail.chmod(0o755)
    real_tail = shutil.which("tail")
    assert real_tail is not None
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("REAL_TAIL", real_tail)
    monkeypatch.setenv("TAIL_STARTED", str(tail_started))
    monkeypatch.setenv("TAIL_STOPPED", str(tail_stopped))

    result = subprocess.run(
        [str(SCRIPT), "--repo", str(repo), "--output", str(output), "--no-qa"],
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 42, result.stdout + result.stderr
    assert tail_started.exists(), "default progress monitor never started"
    assert tail_stopped.read_text(encoding="utf-8") == "stopped"


def test_headless_scans_default_to_untrusted_mode() -> None:
    """A repository checkout must opt in before bypassing untrusted preflight."""
    body = _body()
    assert 'TRUST_MODE="untrusted"' in body
    assert 'trusted|untrusted) TRUST_MODE="$2"' in body


def test_bg_wait_ceiling_is_disabled_for_headless() -> None:
    """Headless must not inherit Claude Code's 600s background-task ceiling.

    Stage 1 (Analyst-A, phases 1-8) routinely outlives 600s, so the default
    ceiling hard-kills `claude -p` mid-phase before any threat-model.yaml
    exists — which the compose backstop above cannot salvage, because its own
    yaml-present gate is false. This was a documented-but-unset knob for a
    year; the guard exists so it does not silently revert.
    """
    body = _body()
    assert "export CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0" in body


def test_resolved_output_dir_is_exported_before_claude_launch() -> None:
    """Every hook process, including Stop and Bash, must share run-local state."""
    body = _body()
    export = 'export OUTPUT_DIR="$RESULT_DIR"'
    launch = '"$@" < /dev/null'
    assert export in body
    assert body.index(export) < body.index(launch)


def test_configured_claude_executable_is_used_for_auth_and_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A launcher wrapper must own both Claude invocations, not only the scan."""
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    marker = tmp_path / "launcher-args"
    launcher = tmp_path / "claude-via-gateway"
    launcher.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "auth" ] && [ "$2" = "status" ]; then\n'
        "  printf '{\"loggedIn\": true}\\n'\n"
        "  exit 0\n"
        "fi\n"
        'printf "%s\\n" "$@" > "$CLAUDE_LAUNCH_MARKER"\n'
        "exit 42\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    monkeypatch.setenv("APPSEC_CLAUDE_EXECUTABLE", str(launcher))
    monkeypatch.setenv("CLAUDE_LAUNCH_MARKER", str(marker))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    result = subprocess.run(
        [
            str(SCRIPT),
            "--repo",
            str(repo),
            "--output",
            str(output),
            "--trust-mode",
            "trusted",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 42, result.stdout + result.stderr
    launched_args = marker.read_text(encoding="utf-8").splitlines()
    assert launched_args[0] == "-p"
    assert "--plugin-dir" in launched_args
    assert "--output-format" in launched_args


def test_configured_claude_executable_is_not_evaluated_as_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "must-not-exist"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("APPSEC_CLAUDE_EXECUTABLE", f"claude;touch {marker}")

    result = subprocess.run(
        [str(SCRIPT), "--repo", str(repo), "--trust-mode", "trusted", "--quiet"],
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 1
    assert "Configured Claude executable not found or not executable" in result.stderr
    assert not marker.exists()


# ── Untrusted-preflight abort message ───────────────────────────────────
# 2026-07-20: the abort named the problem ("preflight findings present") and
# pointed at preflight_untrusted.py for details, but never mentioned that
# --trust-mode trusted exists. An operator whose own .claude/ setup tripped the
# check was left to hunt for an override with no guidance on when it is
# appropriate — the failure mode that guidance is supposed to prevent.


def test_preflight_abort_names_the_trust_mode_escape_hatch() -> None:
    body = _body()
    assert "--trust-mode trusted" in body, "the untrusted-preflight abort must name the flag that unblocks it"


def test_preflight_abort_scopes_when_the_override_is_appropriate() -> None:
    """Naming the flag without the caveat turns a control into a speed bump."""
    body = _body()
    assert "do NOT use that flag" in body, "the abort offers --trust-mode trusted but never says when not to use it"
    assert "third-party" in body, "the abort must distinguish own vs third-party repos"


def test_preflight_abort_offers_a_non_override_remedy() -> None:
    """There must be a way forward that keeps the check armed."""
    body = _body()
    assert ".claude.off" in body, "no remedy offered that preserves the safety check"
    assert "ls-files" in body, (
        "the abort should show how to tell own files from repo-owned ones, since "
        "that is the fact the choice actually turns on"
    )


def test_interrupt_arms_timed_escalation_watchdog() -> None:
    """A single Ctrl-C must guarantee teardown even when the script runs under
    `make ... | tee`: make dies on the same SIGINT and hands the shell prompt
    back, orphaning this script so no further Ctrl-C can reach the manual
    TERM/KILL escalation. The graceful first interrupt therefore arms a timed
    watchdog that escalates SIGTERM→SIGKILL on its own, and it is cancelled once
    claude exits so it never lingers or signals a reused process group."""
    body = _body()
    assert "start_escalation_watchdog()" in body, "no timed escalation watchdog"
    # timed escalation sequence: sleep → SIGTERM → sleep → SIGKILL
    assert 'sleep "$INTERRUPT_TERM_SECS"' in body
    assert 'sleep "$INTERRUPT_KILL_SECS"' in body
    # armed from the graceful first interrupt AND on TERM/HUP (def + ≥2 call sites)
    assert body.count("start_escalation_watchdog") >= 3, (
        "watchdog must be armed from on_interrupt's graceful branch and on_terminate"
    )
    # delays are env-overridable so a stuck orphan can never hang un-escalated
    # (and tests can run fast)
    assert "APPSEC_INTERRUPT_TERM_SECS" in body
    assert "APPSEC_INTERRUPT_KILL_SECS" in body
    # cancelled after claude exits — no lingering sleeper, no reused-pgroup signal
    assert 'kill "$ESCALATION_WATCHDOG_PID"' in body


def test_headless_exit_clears_live_tool_markers() -> None:
    body = _body()
    cleanup = "--clear-active-tool-calls >/dev/null 2>&1 || true"
    assert cleanup in body
    assert body.index(cleanup) < body.index("# If the run was interrupted by Ctrl-C")
    assert "cleanup_headless_runtime()" in body
    assert "trap 'cleanup_headless_runtime' EXIT INT TERM HUP" in body
    assert "trap 'cleanup_headless_runtime' EXIT\n\nset -m" in body
    terminal_block = body[body.index("# PreToolUse markers are live-state") :]
    assert terminal_block.index("cleanup_live_tool_markers") < terminal_block.index("cleanup_tails")
