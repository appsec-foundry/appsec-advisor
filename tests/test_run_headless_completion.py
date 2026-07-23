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
