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
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest
from shared import assessment_location as loc

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-headless.sh"


def _body() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_progress_monitor_never_replays_a_previous_runs_log() -> None:
    """`.hook-events.log` is appended across runs in one output directory, so a
    bare `tail -F` prints the previous run's last lines before the new run's
    first — which read as a fresh failure, with that run's timestamps."""
    body = _body()
    assert 'tail -n 0 -F "$1" "$2"' in body
    assert 'tail -F "$1"' not in body


def test_headless_has_no_generation_escape_hatch() -> None:
    body = _body()
    assert "APPSEC_CONTEXT_V2" not in body
    assert "CONTEXT_V2_SELECTED" not in body
    assert "PERSISTED_RUNTIME_GENERATION" not in body


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
        [str(SCRIPT), "--audit-requirements", "--repo", str(repo), "--output", str(output), "--no-qa"],
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
            "--audit-requirements",
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
    assert f'--output "{output.resolve()}"' in launched_args[1]
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
# pointed at validators/preflight_untrusted.py for details, but never mentioned that
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
    lock = str(ROOT / "scripts" / "runtime/acquire_lock.py")
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
            "--audit-requirements",
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
        [str(SCRIPT), "--audit-requirements", "--repo", str(repo), "--output", str(output), "--rebuild"],
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


def test_the_hard_cut_is_derived_from_the_soft_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """One number is the interface. The derived backstop sits above the band the
    soft mechanism may use, so it only fires when that mechanism was wrong."""
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    argv_file = tmp_path / "claude-argv"
    claude = bin_dir / "claude"
    claude.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$CLAUDE_ARGV"\nexit 0\n', encoding="utf-8")
    claude.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("CLAUDE_ARGV", str(argv_file))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    result = subprocess.run(
        [
            str(SCRIPT),
            "--audit-requirements",
            "--repo",
            str(repo),
            "--output",
            str(output),
            "--full",
            "--soft-budget",
            "30",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    argv = argv_file.read_text(encoding="utf-8").splitlines() if argv_file.exists() else []
    assert "--max-budget-usd" in argv, result.stdout + result.stderr
    assert argv[argv.index("--max-budget-usd") + 1] == "37.50"
    assert "--soft-budget 30" in " ".join(argv), "the soft budget never reached the skill"


def test_an_explicit_hard_budget_wins_over_the_derived_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    argv_file = tmp_path / "claude-argv"
    claude = bin_dir / "claude"
    claude.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$CLAUDE_ARGV"\nexit 0\n', encoding="utf-8")
    claude.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("CLAUDE_ARGV", str(argv_file))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    result = subprocess.run(
        [
            str(SCRIPT),
            "--audit-requirements",
            "--repo",
            str(repo),
            "--output",
            str(output),
            "--full",
            "--soft-budget",
            "30",
            "--hard-budget",
            "50",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    argv = argv_file.read_text(encoding="utf-8").splitlines() if argv_file.exists() else []
    assert "--max-budget-usd" in argv, result.stdout + result.stderr
    assert argv[argv.index("--max-budget-usd") + 1] == "50"


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ((), "requires --soft-budget or --hard-budget"),
        (("--hard-budget", "5", "--trust-mode", "trusted"), "repository selection rejected"),
        (("--hard-budget", "5", "--incremental"), "--incremental is not supported"),
    ],
)
def test_repeated_repository_selection_reaches_the_combined_assessment_before_output_or_claude(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: tuple[str, ...], message: str
) -> None:
    first, second, output = tmp_path / "first", tmp_path / "second", tmp_path / "not-created"
    first.mkdir()
    second.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "claude-invoked"
    claude = bin_dir / "claude"
    claude.write_text('#!/bin/sh\nprintf invoked > "$CLAUDE_MARKER"\nexit 42\n', encoding="utf-8")
    claude.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("CLAUDE_MARKER", str(marker))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    result = subprocess.run(
        [str(SCRIPT), "--repo", str(first), "--repo", str(second), "--output", str(output), *extra],
        capture_output=True,
        text=True,
        timeout=30,
    )

    # Neither directory is a Git checkout and no budget may be missing: the
    # combined assessment refuses before it creates output or starts a model.
    assert result.returncode == 2, result.stdout + result.stderr
    assert message in result.stderr
    assert not output.exists()
    assert not marker.exists()


def _run_banner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **env: str) -> subprocess.CompletedProcess:
    """Run the wrapper up to a stub Claude that exits at once; return its output."""
    repo, output = tmp_path / "repo", tmp_path / "out"
    repo.mkdir()
    launcher = tmp_path / "claude-stub"
    launcher.write_text(
        '#!/bin/sh\nif [ "$1" = "auth" ]; then printf \'{"loggedIn": true}\\n\'; exit 0; fi\nexit 42\n',
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    monkeypatch.setenv("APPSEC_CLAUDE_EXECUTABLE", str(launcher))
    for key in ("NO_COLOR", "FORCE_COLOR", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return subprocess.run(
        [
            str(SCRIPT),
            "--audit-requirements",
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


def test_output_off_a_terminal_carries_no_escape_sequences(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Logs and CI output read the summary as plain text, exactly as before."""
    result = _run_banner(tmp_path, monkeypatch)
    assert result.returncode == 42, result.stdout + result.stderr
    assert "\x1b" not in result.stdout + result.stderr
    assert "▶ AppSec Plugin — Headless Mode" in result.stdout
    assert "\n  Skill      : audit-security-requirements\n" in result.stdout


def test_forced_colour_styles_the_banner_without_changing_its_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run_banner(tmp_path, monkeypatch, FORCE_COLOR="1")
    assert result.returncode == 42, result.stdout + result.stderr
    assert "\x1b[" in result.stdout
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    # The logo glyphs belong to tests/test_term_style.py; only the fields beside them are checked here.
    assert "  appsec-advisor\n" in plain
    assert "  code-derived STRIDE threat modeling\n" in plain
    assert "\n  Skill      : audit-security-requirements\n" in plain


@pytest.mark.parametrize("flag", ["--audit-requirements", "--check-requirements"])
def test_a_requirements_audit_runs_the_audit_skill_in_the_selected_repository(tmp_path: Path, flag: str) -> None:
    """A single --repo reaches the controller only for an assessment; the audit skill inspects its working directory."""
    repo = tmp_path / "repo"
    repo.mkdir()
    seen = tmp_path / "seen"
    stub = tmp_path / "claude"
    stub.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "auth" ]; then\n'
        "  printf '{\"loggedIn\": true}\\n'\n"
        "  exit 0\n"
        "fi\n"
        f'printf "%s\\n" "$PWD" "$2" > "{seen}"\n'
        'printf \'{"type": "result", "result": "done", "total_cost_usd": 0}\\n\'\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    env = _headless_env(stub)
    env["XDG_DATA_HOME"] = str(tmp_path / "data")

    subprocess.run(
        [str(SCRIPT), flag, "--repo", str(repo), "--trust-mode", "trusted", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )

    cwd, prompt = seen.read_text(encoding="utf-8").splitlines()[:2]
    assert Path(cwd).resolve() == repo.resolve()
    assert prompt.startswith("/appsec-advisor:audit-security-requirements")
    private = loc.application_directory(repo, tmp_path / "data" / "appsec-advisor" / "assessments")
    assert f'--output "{private}"' in prompt
    assert not (repo / "docs").exists()
