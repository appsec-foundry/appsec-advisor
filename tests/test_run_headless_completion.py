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
