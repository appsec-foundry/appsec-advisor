"""Drift guards for the headless-completion contract in run-headless.sh.

The deterministic compose logic (``_compose_if_ready`` via ``next``) is unit
tested in ``test_orchestration_controller.py``. These tests pin the *shell
wiring* that makes it fire on a bg-ceiling process-kill and that the artifact
gate is fail-closed on a missing ``threat-model.md`` — the 2026-07-03 gap where
a killed run left ``threat-model.yaml`` + fragments but no report and headless
reported ``✓ completed successfully`` (exit 0).
"""

from __future__ import annotations

from pathlib import Path

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
    """
    body = _body()
    assert "--issues-only" in body, "failure branch must render the Run Issues block"
    # Must regenerate the file first — on a hard kill it is stale or absent.
    assert "aggregate_run_issues.py" in body, (
        "failure branch must refresh .run-issues.json from the logs before rendering"
    )
    # Gated on the log existing so it is a no-op for pre-dispatch failures.
    assert '[ -f "$RESULT_DIR/.agent-run.log" ]' in body


def test_failure_branch_prints_full_recovery_command() -> None:
    """The failure hint must print a paste-ready re-run command, and choose
    --resume vs --rebuild from what the resume-guard actually allows — never a
    bare 'run with --resume' that the guard would then refuse."""
    body = _body()
    # Raw invocation is preserved before the parser consumes it.
    assert 'ORIG_ARGS=""' in body, "must capture the original invocation for the hint"
    # The re-run command is reconstructed (mode flags stripped, one appended).
    assert "_rerun_cmd" in body
    # The resume/rebuild choice is delegated to the resume-guard, not guessed.
    assert "--resume-guard" in body, "hint must consult the resume-guard before suggesting --resume"
    assert "_rerun_cmd --resume" in body and "_rerun_cmd --rebuild" in body


def test_context_v2_resume_fails_before_dispatch() -> None:
    """WP7 has not implemented context-v2 resume, so the wrapper must not
    silently route a resume request through the legacy full runtime."""
    body = _body()
    guard = 'die "Context-v2 does not support --resume yet (WP7).'
    assert guard in body
    assert body.index(guard) < body.index("# ── Trust mode: preflight + strict defaults")
    assert 'get("runtime_generation", "")' in body
    assert "refusing to fall back to the legacy full runtime" in body
    hint = 'warn "Context-v2 resume is not available yet (WP7) — start fresh:"'
    assert hint in body
    assert body.index(hint) < body.index('warn "Resume from the last checkpoint:"')


def test_context_v2_is_the_headless_default_with_a_legacy_escape_hatch() -> None:
    body = _body()
    assert "APPSEC_CONTEXT_V2=0        Use the legacy producer" in body
    assert "CONTEXT_V2_RESUME_TARGET=0" in body
    assert '[ "$PERSISTED_RUNTIME_GENERATION" = "legacy" ]' in body
    assert "context-v2) CONTEXT_V2_SELECTED=1" in body
    assert "legacy) CONTEXT_V2_SELECTED=0" in body


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
    launch = 'eval "$CLAUDE_CMD" < /dev/null'
    assert export in body
    assert body.index(export) < body.index(launch)


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
