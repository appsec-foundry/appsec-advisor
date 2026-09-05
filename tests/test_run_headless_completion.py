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
import signal
import subprocess
import time
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
    assert "trap 'cleanup_headless_runtime' EXIT\n\n# Start claude in its own session" in body
    terminal_block = body[body.index("# PreToolUse markers are live-state") :]
    assert terminal_block.index("cleanup_live_tool_markers") < terminal_block.index("cleanup_tails")


# ── Abort and recovery ──────────────────────────────────────────────────
# 2026-09-05: the escalation ladder was verified only from an interactive
# terminal. Without a controlling terminal `set -m` fails ("can't access tty"),
# the child keeps the wrapper's process group, and every
# `kill -<sig> -$CLAUDE_PID` addresses a process group that does not exist —
# the wrapper printed "forwarding SIGINT to claude" while nothing was
# forwarded, and the watchdog's `kill -0 -$PID` guard exited before escalating.
# That is the shape of every unattended caller: nohup, systemd, cron, CI.


def test_claude_is_launched_into_its_own_session() -> None:
    """PID == PGID == SID, established without needing a tty."""
    body = _body()
    assert "os.setsid()" in body, "claude must lead its own session"
    assert "set -m\n" not in body, "job control needs a tty and silently no-ops without one"
    # The shell marks SIGINT/SIGQUIT ignored for asynchronous children; a child
    # that inherits that disposition swallows the forwarded interrupt.
    assert "signal.signal(getattr(signal, name), signal.SIG_DFL)" in body
    assert "os.execvp(sys.argv[1], sys.argv[1:])" in body, "the launcher must keep $! == claude"


def _stub_claude(path: Path, sleep_seconds: int, marker: Path) -> Path:
    """A claude stand-in that answers the auth preflight, then runs long.

    It takes the run lock the way the controller's `prepare` does — under the
    run id the wrapper minted — and heartbeats it once, so the lock the
    terminator meets afterwards looks exactly like a killed run's: fresh.
    """
    lock = str(ROOT / "scripts" / "acquire_lock.py")
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "auth" ] && [ "$2" = "status" ]; then\n'
        "  printf '{\"loggedIn\": true}\\n'\n"
        "  exit 0\n"
        "fi\n"
        f'python3 "{lock}" "$OUTPUT_DIR/.appsec-lock" "--run-id=$APPSEC_RUN_ID" >/dev/null\n'
        f'python3 "{lock}" "$OUTPUT_DIR/.appsec-lock" --heartbeat --phase=8 >/dev/null\n'
        f"sleep {sleep_seconds}\n"
        f'printf "survived\\n" > "{marker}"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _headless_env(stub: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["APPSEC_CLAUDE_EXECUTABLE"] = str(stub)
    env["CLAUDE_PLUGIN_DIR"] = str(ROOT)
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
    return env


def test_an_interrupt_without_a_controlling_terminal_tears_the_run_down(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    (output / ".agent-run.log").write_text(
        "2026-09-05T10:00:00Z  [--------]  INFO   threat-analyst  ASSESSMENT_START  x\n",
        encoding="utf-8",
    )
    (output / ".appsec-checkpoint").write_text("phase=8 status=dispatching\n", encoding="utf-8")
    survived = tmp_path / "survived"
    stub = _stub_claude(tmp_path / "claude", 60, survived)

    proc = subprocess.Popen(
        [
            str(SCRIPT),
            "--repo",
            str(repo),
            "--output",
            str(output),
            "--full",
            "--trust-mode",
            "trusted",
            "--quiet",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=_headless_env(stub),
        # No controlling terminal — the unattended shape this guards.
        start_new_session=True,
    )
    lock = output / ".appsec-lock"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not lock.exists():
        time.sleep(0.2)
    time.sleep(1)  # let the wrapper install its traps
    assert lock.is_file(), "the stub never took the lock — the rest of this test proves nothing"
    os.kill(proc.pid, signal.SIGINT)

    try:
        rc = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:  # pragma: no cover - failure path
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.communicate()
        pytest.fail("the interrupt never reached claude — the wrapper kept waiting")

    stdout = rc[0]
    assert not survived.exists(), "claude survived the interrupt"
    assert "Run aborted by user" in stdout
    assert "can't access tty" not in stdout
    # One terminal state: the terminator closed the checkpoint the run left
    # open and released the lock. A retained lock blocks the next attempt for
    # the whole heartbeat-stale window, and headless cannot answer the
    # take-over question.
    assert "status=aborted" in (output / ".appsec-checkpoint").read_text(encoding="utf-8")
    assert not lock.exists(), "the interrupted run left its lock behind"


def test_the_wrapper_mints_the_run_id_the_lock_release_needs() -> None:
    """A killed run's last heartbeat is always fresh, so the terminator can
    only release the lock if it can name the run that holds it. The wrapper
    mints that id itself — the Claude session that would otherwise own it is
    already gone when the lock has to go."""
    body = _body()
    assert 'export APPSEC_RUN_ID="run-$(date +%s)-$$"' in body
    launch = body.index("SESSION_LAUNCHER=")
    assert body.index("export APPSEC_RUN_ID") < launch, "the id must exist before the run takes the lock"
    # Both non-clean exit classes hand it to the terminator.
    assert body.count('--run-id "$APPSEC_RUN_ID"') == 2


def test_the_skill_force_flag_reaches_the_prompt(tmp_path: Path) -> None:
    """`--force` is the override the controller demands before a completed
    Stage 1 is discarded. The parser used to swallow it for --clean-all only,
    so the abort recommended a flag that never left this wrapper."""
    repo = tmp_path / "repo"
    repo.mkdir()
    marker = tmp_path / "launcher-args"
    launcher = tmp_path / "claude-arg-dump"
    launcher.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "auth" ] && [ "$2" = "status" ]; then\n'
        "  printf '{\"loggedIn\": true}\\n'\n"
        "  exit 0\n"
        "fi\n"
        'printf "%s\\n" "$@" > "$CLAUDE_LAUNCH_MARKER"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    env = _headless_env(launcher)
    env["CLAUDE_LAUNCH_MARKER"] = str(marker)

    subprocess.run(
        [
            str(SCRIPT),
            "--repo",
            str(repo),
            "--output",
            str(tmp_path / "out"),
            "--rebuild",
            "--force",
            "--trust-mode",
            "trusted",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )

    prompt = marker.read_text(encoding="utf-8").splitlines()[1]
    assert "--rebuild" in prompt
    assert "--force" in prompt, "the skill-only override never reached the skill"


def test_the_recovery_hint_offers_rerender_after_a_completed_stage_one() -> None:
    """Stage 1 is the expensive part. A run killed between the Stage-1 gate and
    the report leaves it validated on disk, and --rerender turns it into a
    report without re-analyzing anything — while --rebuild is refused by the
    controller on exactly that checkpoint."""
    body = _body()
    hint = body[body.index("print_recovery_hint() {") : body.index("# Every mode, including --quiet")]
    for token in ("phase=10b", "status=completed", "need_render=true"):
        assert token in hint, "the hint must read the same checkpoint tokens as the controller"
    assert "--rerender" in hint
    assert "--rebuild --force" in hint, "the discard path must carry the override the controller requires"
    assert "--resume" not in hint.replace("--resume|--full", ""), "--resume is rejected by this wrapper"


def test_a_blocked_run_touches_nothing_in_the_holders_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run refused the lock owns nothing in the output directory.

    `acquire_lock.lock_held_by_live_other_run` states the rule; the terminator
    already asked it and the post-run artifact handling did not. A LOCK_BLOCKED
    run then composed into the holder's mid-flight directory, called the
    holder's not-yet-composed report its own fail-closed failure, and told the
    operator to start fresh with a command that collides again.
    """
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    output.mkdir()
    # The holder's state: a live lock naming a different run, and a yaml with no
    # composed report — the shape that arms the compose backstop.
    now = int(time.time())
    (output / ".appsec-lock").write_text(f"999999\n{now}\nrun-holder-1\nacquired={now}\n", encoding="utf-8")
    (output / "threat-model.yaml").write_text("meta:\n  schema_version: 1\n", encoding="utf-8")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    claude = bin_dir / "claude"
    claude.write_text("#!/bin/sh\nprintf 'LOCK_BLOCKED: held\\n'\nexit 1\n", encoding="utf-8")
    claude.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    result = subprocess.run(
        [str(SCRIPT), "--repo", str(repo), "--output", str(output), "--rebuild"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    combined = result.stdout + result.stderr

    assert not (output / ".compose-blocked.json").exists(), "composed into the holder's directory"
    assert not (output / "threat-model.md").exists(), "composed into the holder's directory"
    assert "fail-closed" not in combined, "reported the holder's missing report as its own failure"
    assert "does not resume incomplete analysis" not in combined, "offered a hint for a run it never made"
    assert "held by another assessment" in combined, "the operator is not told why the run stopped"
