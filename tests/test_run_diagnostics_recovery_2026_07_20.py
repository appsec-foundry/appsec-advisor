"""Diagnostics and recovery gaps from the 2026-07-20 juice-shop run.

The run died without a deliverable and the plugin's own diagnostics reported a
clean run. Three independent mechanisms had to fail for that:

  D6a evidence-verifier degenerate output was gated on file existence only
  D6b its turn budget could not cover the sample it was told to verify
  D7a AGENT_ERROR was parsed then dropped (fixed in the sibling suite)
  D7b the terminal outcome was computed but never became an issue
  D7c run scoping silently discarded the first half of a long run
  D8  a structurally-blocked component had no recovery path at all
"""

from __future__ import annotations

import json
import math
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import aggregate_run_issues as agg  # noqa: E402
import stride_dispatch_waves as waves  # noqa: E402

AGENTS = REPO_ROOT / "agents"


def _log(ts: str, level: str, source: str, event: str, detail: str) -> str:
    return f"{ts}  [--------]  {level}   {source}  {event}   {detail}"


# --------------------------------------------------------------------------
# D7c — run scoping must not discard events from a long run
# --------------------------------------------------------------------------


def test_scoping_keeps_events_from_a_long_run(tmp_path: Path) -> None:
    """A 147-minute run must not lose its own early events.

    The sliding window assumed "the longest thorough run is ~40 min". The
    2026-07-20 run spanned 147 min, so its AGENT_ERROR (93 min before the last
    entry) fell outside the 90-minute window and never reached any extractor.
    `.scan-start-epoch` is the exact per-invocation boundary.
    """
    # Run starts 15:23, AGENT_ERROR at 16:20, last entry at 17:52 (=149 min span).
    (tmp_path / ".scan-start-epoch").write_text("1784560995", encoding="utf-8")
    lines = [
        (1, _log("2026-07-20T15:25:00Z", "INFO", "threat-analyst", "PHASE_START", "[Phase 1/11]")),
        (
            2,
            _log(
                "2026-07-20T16:20:10Z",
                "WARN",
                "threat-analyst",
                "AGENT_ERROR",
                "evidence-verifier: all sampled findings unchecked",
            ),
        ),
        (3, _log("2026-07-20T17:52:46Z", "INFO", "threat-analyst", "SESSION_STOP", "stop_reason=unknown")),
    ]
    scoped = agg._scope_to_current_run(lines, tmp_path)
    kept = [raw for _ln, raw in scoped]
    assert any("AGENT_ERROR" in raw for raw in kept), (
        "an event from the first half of a long run was dropped by run scoping; "
        "no extractor can see it regardless of the matcher"
    )
    assert len(kept) == 3


def test_scoping_still_excludes_a_previous_run(tmp_path: Path) -> None:
    """The marker must not make scoping useless — old runs stay excluded."""
    (tmp_path / ".scan-start-epoch").write_text("1784560995", encoding="utf-8")
    lines = [
        (1, _log("2026-07-19T09:00:00Z", "WARN", "threat-analyst", "AGENT_ERROR", "yesterday's failure")),
        (2, _log("2026-07-20T16:20:10Z", "WARN", "threat-analyst", "AGENT_ERROR", "today's failure")),
    ]
    kept = [raw for _ln, raw in agg._scope_to_current_run(lines, tmp_path)]
    assert not any("yesterday" in raw for raw in kept)
    assert any("today" in raw for raw in kept)


def test_scoping_falls_back_when_marker_absent(tmp_path: Path) -> None:
    """Legacy runs with no .scan-start-epoch keep the heuristic behaviour."""
    lines = [(1, _log("2026-07-20T16:20:10Z", "WARN", "a", "AGENT_ERROR", "x"))]
    assert len(agg._scope_to_current_run(lines, tmp_path)) == 1


# --------------------------------------------------------------------------
# D7b — a run that produced nothing is the loudest possible issue
# --------------------------------------------------------------------------


def test_incomplete_run_becomes_an_error_issue(tmp_path: Path) -> None:
    """No threat-model.md + unrecovered aborts must not aggregate to 'clean'."""
    agent_log = [
        (
            1,
            _log("2026-07-20T16:24:12Z", "WARN", "threat-analyst", "SESSION_ABORTED_MIDRUN", "phase=11 reason=unknown"),
        ),
        (
            2,
            _log("2026-07-20T16:25:12Z", "WARN", "threat-analyst", "SESSION_ABORTED_MIDRUN", "phase=11 reason=unknown"),
        ),
    ]
    issues = agg._extract_run_outcome(agent_log, tmp_path)
    assert issues, "a run with no deliverable produced no issue"
    assert issues[0]["severity"] == "error"
    assert issues[0]["category"] == "run_incomplete"


def test_completed_run_produces_no_outcome_issue(tmp_path: Path) -> None:
    """A run that produced its deliverable must stay quiet."""
    (tmp_path / "threat-model.md").write_text("# report", encoding="utf-8")
    agent_log = [
        (
            1,
            _log("2026-07-20T16:24:12Z", "WARN", "threat-analyst", "SESSION_ABORTED_MIDRUN", "phase=11 reason=unknown"),
        ),
    ]
    assert agg._extract_run_outcome(agent_log, tmp_path) == []


# --------------------------------------------------------------------------
# D7 — the aggregator must actually run when the controller aborts
# --------------------------------------------------------------------------


def test_controller_abort_populates_run_issues(tmp_path: Path) -> None:
    """An aborted run must leave a diagnostic bundle behind.

    aggregate_run_issues.py's only call site is the Completion step, which an
    aborted run never reaches — so the runs that most need diagnostics produced
    none, and report-error/diagnose-bundle read a stale file or nothing.
    """
    out = tmp_path / "security"
    out.mkdir()
    (out / ".agent-run.log").write_text(
        _log("2026-07-20T16:20:10Z", "WARN", "threat-analyst", "AGENT_ERROR", "something failed") + "\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "orchestration_controller.py"),
            "post-stage1",
            "--output-dir",
            str(out),
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode != 0, "expected this run to abort"
    assert json.loads(completed.stdout)["action"] == "abort"
    assert (out / ".run-issues.json").is_file(), (
        "controller aborted without leaving .run-issues.json; the diagnostic "
        "bundle is empty for exactly the runs that need it"
    )


# --------------------------------------------------------------------------
# D6 — evidence verifier: gate on content, and budget for the sample
# --------------------------------------------------------------------------


def _frontmatter_max_turns(path: Path) -> int:
    m = re.search(r"^maxTurns:\s*(\d+)", path.read_text(encoding="utf-8"), re.M)
    assert m, f"maxTurns not found in {path.name}"
    return int(m.group(1))


def _turns_needed(sample: int) -> int:
    """N reads + 2 writes per 5-finding flush + pre-seed + startup."""
    return sample + 2 * math.ceil(sample / 5) + 3


def test_evidence_verifier_budget_covers_the_standard_sample() -> None:
    """The default depth must be able to finish what it is told to sample.

    standard = all Criticals (uncapped) + up to 30 non-Criticals. The 2026-07-20
    run sampled 38 and needed ~57 turns against a ceiling of 40, so it resolved
    nothing and left the untouched pre-seed behind.
    """
    ceiling = _frontmatter_max_turns(AGENTS / "appsec-evidence-verifier.md")
    observed_sample = 38  # 8 Critical + 30 capped non-Critical
    assert ceiling >= _turns_needed(observed_sample), (
        f"maxTurns {ceiling} cannot cover a {observed_sample}-finding sample "
        f"(~{_turns_needed(observed_sample)} turns) — the verifier cannot finish"
    )


def test_evidence_verifier_turn_guard_text_matches_frontmatter() -> None:
    """The in-prompt ⅔ guard must cite the real ceiling.

    It read "turn 20 of 30" while maxTurns was 40 — stale since 2026-06-13.
    """
    path = AGENTS / "appsec-evidence-verifier.md"
    ceiling = _frontmatter_max_turns(path)
    text = path.read_text(encoding="utf-8")
    m = re.search(r"turn\s+(\d+)\s+of\s+(\d+)", text)
    assert m, "turn-budget guard no longer states a concrete turn pair"
    cited_of = int(m.group(2))
    assert cited_of == ceiling, (
        f"guard cites 'of {cited_of}' but maxTurns is {ceiling}; the agent paces "
        "itself against a budget it does not have"
    )


def test_stage1_gates_evidence_content_not_just_existence() -> None:
    """Phase 10a must detect a present-but-zeroed verification file.

    The pre-seed is schema-clean with every count at zero, so an existence check
    passes while triage silently loses the entire refutation signal.
    """
    text = (AGENTS / "phases" / "phase-group-threats.md").read_text(encoding="utf-8")
    assert "all sampled findings unchecked" in text, (
        "Phase 10a still gates only on file existence; a zeroed pre-seed passes "
        "and Phase 10b rates every finding with no refutation signal"
    )
    assert "guard_evidence_verification.py" in text, (
        "the content detector exists but is not invoked where its consumer runs"
    )


# --------------------------------------------------------------------------
# D8 — a structurally-blocked component needs a way forward
# --------------------------------------------------------------------------


def test_attempt_budget_defaults_to_two() -> None:
    assert waves.max_attempts() == 2


def test_attempt_budget_is_overridable_for_recovery(monkeypatch) -> None:
    """After fixing the structural cause, the run must be recoverable.

    Attempts persist across resume, so without an override the only way forward
    was a full --rebuild that discards the merge and triage already paid for.
    """
    monkeypatch.setenv("APPSEC_STRIDE_MAX_ATTEMPTS", "3")
    assert waves.max_attempts() == 3


def test_attempt_budget_override_is_bounded(monkeypatch) -> None:
    """The override must not become a licence for unbounded retrying."""
    monkeypatch.setenv("APPSEC_STRIDE_MAX_ATTEMPTS", "99")
    assert waves.max_attempts() == waves.MAX_ATTEMPTS_CEILING

    monkeypatch.setenv("APPSEC_STRIDE_MAX_ATTEMPTS", "1")
    assert waves.max_attempts() == 2, "override must never lower the budget below the default"

    monkeypatch.setenv("APPSEC_STRIDE_MAX_ATTEMPTS", "not-a-number")
    assert waves.max_attempts() == 2


def test_raised_attempt_counts_still_validate(tmp_path: Path) -> None:
    """A plan carrying a raised attempt count must pass schema validation."""
    manifest = {
        "generated_at": "2026-07-20T09:00:00Z",
        "components": [{"component_id": "svc", "max_turns": 22, "index_paths": {}}],
    }
    plan = waves.build_plan(manifest, 8)
    plan["attempts"]["svc"] = 3
    waves.validate_plan(plan, manifest)  # must not raise
