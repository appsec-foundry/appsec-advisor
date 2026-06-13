#!/usr/bin/env python3
"""Per-issue fix recommendation engine for ``aggregate_run_issues.py`` /
``$OUTPUT_DIR/.run-issues.json``.

For every issue produced by the aggregator, a category-specific
recommender returns a structured ``fix_recommendation`` dict with:

  category         "agent_def" | "config_tune" | "yaml_edit" | "skill_spec"
                   | "user_action" | "rerun" | "investigate" | "no_fix"
  auto_applicable  bool — only True for well-bounded changes
                   (single-value edits in agent frontmatter, settings)
  confidence       "high" | "medium" | "low" — only "high" + auto_applicable
                   are surfaced as auto-fix candidates by the
                   /appsec-advisor:fix-run-issues skill
  risk_level       "low" | "medium" | "high"
  summary          one-line human-readable description
  rationale        why this fix is recommended
  actions          ordered list of {type, target, ...} dicts
  verification     list of commands to verify the fix succeeded

The recommender library is intentionally pluggable: unknown issue
categories get a default ``investigate`` recommendation rather than
being silently dropped, and adding a new category only requires
appending one entry to ``RECOMMENDERS``.

Auto-applicable categories (in scope for the fix-run-issues skill):

  * ``max_turns_subagent``        bump <agent>.md maxTurns by 50%
  * ``max_turns_orchestrator``    bump appsec-threat-analyst maxTurns
  * (more added as patterns prove safe through repeated production runs)

All other categories return ``auto_applicable: False`` with a manual
remediation guide. The skill prints those for the user but does not
attempt to apply them.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Callable

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = PLUGIN_ROOT / "agents"


# ---------------------------------------------------------------------------
# Helpers — read agent frontmatter
# ---------------------------------------------------------------------------


def _read_agent_max_turns(agent_name: str) -> int | None:
    """Return current `maxTurns:` from agents/<agent_name>.md frontmatter."""
    path = AGENTS_DIR / f"{agent_name}.md"
    if not path.is_file():
        return None
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r"^maxTurns:\s*(\d+)\s*$", content, re.MULTILINE)
    if not m:
        return None
    return int(m.group(1))


# ---------------------------------------------------------------------------
# Recommenders — one per category
# ---------------------------------------------------------------------------


def _recommend_max_turns_subagent(issue: dict, output_dir: Path) -> dict:
    """Sub-agent hit MAX_TURNS → bump its maxTurns by 50%."""
    src = (issue["evidence"].get("source_agent") or "").strip()
    # Map log "source" (short name) to canonical agent name. The logger
    # writes the short name (e.g. "stride-analyzer") in the source field;
    # the agent file is "appsec-stride-analyzer.md".
    agent_name = src if src.startswith("appsec-") else f"appsec-{src}"
    current = _read_agent_max_turns(agent_name)
    if current is None:
        return {
            "category": "investigate",
            "auto_applicable": False,
            "confidence": "low",
            "risk_level": "low",
            "summary": f"Sub-agent {src!r} hit MAX_TURNS but the agent file could not be located.",
            "rationale": "Could not read agents/<agent>.md to compute a bump.",
            "actions": [
                {
                    "type": "manual_review",
                    "target": "agents/",
                    "details": f"Locate the agent file for source {src!r} and bump its maxTurns by ~50%.",
                }
            ],
            "verification": [],
        }
    suggested = max(current + 5, int(current * 1.5))
    return {
        "category": "agent_def",
        "auto_applicable": True,
        "confidence": "high",
        "risk_level": "low",
        "summary": f"Bump {agent_name} maxTurns: {current} → {suggested}",
        "rationale": (
            f"M2.8/M2.9 pattern: same fix worked for qa-reviewer (80→120) and "
            f"orchestrator (75→120). Rule of thumb: bump by 50% on first "
            f"MAX_TURNS event for any agent. Cost impact: agent may use up to "
            f"{suggested - current} more tool-calls per dispatch, but only when "
            f"genuinely needed."
        ),
        "actions": [
            {
                "type": "edit_file",
                "target": f"agents/{agent_name}.md",
                "find": f"maxTurns: {current}",
                "replace": f"maxTurns: {suggested}",
            },
            {
                "type": "edit_file",
                "target": "tests/test_agent_definitions.py",
                "find": f'"{agent_name}":  {current}',
                "replace": f'"{agent_name}": {suggested}',
                "fallback_find": f'"{agent_name}": {current}',
                "fallback_replace": f'"{agent_name}": {suggested}',
            },
        ],
        "verification": [
            "python3 -m pytest tests/test_agent_definitions.py -v",
        ],
    }


def _recommend_max_turns_orchestrator(issue: dict, output_dir: Path) -> dict:
    """Specialized recommender for the orchestrator (different file naming)."""
    return _recommend_max_turns_subagent(issue, output_dir)


def _recommend_perf_anomaly_phase(issue: dict, output_dir: Path) -> dict:
    """Phase exceeded its depth-specific limit. Manual investigation."""
    ev = issue["evidence"]
    phase = ev.get("phase", "?")
    label = ev.get("label", "(unknown)")
    actual = ev.get("duration_seconds", 0)
    expected = ev.get("expected_max_seconds", 0)
    end_inferred = ev.get("end_inferred", False)
    inferred_note = (
        " Note: PHASE_END was missing — duration is inferred from the next "
        "PHASE_START, may be inflated by inter-phase overhead."
        if end_inferred
        else ""
    )
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "medium",
        "risk_level": "low",
        "summary": (
            f"Phase {phase} ({label}) ran {actual}s vs expected ≤{expected}s — investigate which sub-step dominated."
        ),
        "rationale": (
            f"This phase exceeded the {issue['evidence'].get('multiplier', 1.0)}× threshold "
            f"for the assessment depth. Common causes: (a) sub-agent stuck in long "
            f"reasoning loop, (b) external command (git, gh) slow, (c) repo "
            f"size larger than expected.{inferred_note}"
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".agent-run.log",
                "details": (
                    f"grep for PHASE_START at line {ev.get('log_line', 0)} and read "
                    "downstream STEP_START/AGENT_INVOKE entries to identify the "
                    "dominating sub-step."
                ),
            },
            {
                "type": "manual_review",
                "target": ".hook-events.log",
                "details": "Look for repeated FILE_WRITE / BASH_WARN entries in the time window.",
            },
        ],
        "verification": [],
    }


def _recommend_stage1_excessive_duration(issue: dict, output_dir: Path) -> dict:
    """HIGH-ALERT: Phase 1 (Context Resolution) ran beyond 30 min — likely
    a runaway sub-agent or a process that should have been killed."""
    ev = issue["evidence"]
    actual = ev.get("duration_seconds", 0)
    return {
        "category": "user_action",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "high",
        "summary": (
            f"Phase 1 ran {actual}s — far beyond any reasonable expectation. "
            "This indicates a runaway agent (likely the orchestrator was waiting "
            "for a sub-agent that never returned)."
        ),
        "rationale": (
            "Phase 1 (Context Resolution) is bounded by the recon-scanner + context-resolver "
            "sub-agents (~3-5 min total). A 30+ min runtime here means the orchestrator was "
            "stuck — either user input was expected and not provided, or a sub-agent looped. "
            "Token cost likely high; check ASSESSMENT_TOKENS in the same log."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".agent-run.log",
                "details": (
                    "Inspect SESSION_STOP entries and the cost field. The 2026-04-25 "
                    "juice-shop incident lost $51 to a runaway 8h Phase-1 — same shape."
                ),
            },
            {
                "type": "investigate",
                "target": "process",
                "details": "If the run is still active: kill the Claude Code session. "
                "Then run /appsec-advisor:clean-run-state to reap the lock files.",
            },
        ],
        "verification": [],
    }


def _recommend_session_stop_unknown(issue: dict, output_dir: Path) -> dict:
    """SESSION_STOP with stop_reason=unknown — usually budget exhaustion."""
    ev = issue["evidence"]
    src = ev.get("source_agent", "?")
    cost = ev.get("cost_usd", 0.0)
    out_tokens = ev.get("output_tokens", 0)
    if out_tokens > 50_000 or cost > 5.0:
        return {
            "category": "investigate",
            "auto_applicable": False,
            "confidence": "high",
            "risk_level": "medium",
            "summary": (
                f"Agent {src} hit SESSION_STOP with reason=unknown after "
                f"{out_tokens:,} output tokens (cost ${cost:.2f}). "
                "This is almost certainly turn-budget exhaustion."
            ),
            "rationale": (
                "stop_reason=unknown combined with high output-token count is the "
                "hallmark of MAX_TURNS without an explicit MAX_TURNS event. Bump the "
                "agent's maxTurns or move expensive work to a dedicated sub-agent. "
                "Compare with the M2.9 pattern (orchestrator 75→120)."
            ),
            "actions": [
                {
                    "type": "manual_review",
                    "target": f"agents/{src if src.startswith('appsec-') else 'appsec-' + src}.md",
                    "details": "Bump maxTurns by 50% if not already at the maximum acceptable for the workload.",
                },
            ],
            "verification": [],
        }
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "low",
        "risk_level": "low",
        "summary": f"Agent {src} ended with reason=unknown — token usage normal.",
        "rationale": "Low token count suggests this was an early bail-out, not budget exhaustion.",
        "actions": [
            {
                "type": "manual_review",
                "target": ".agent-run.log",
                "details": "Read the lines BEFORE SESSION_STOP for the actual cause.",
            },
        ],
        "verification": [],
    }


def _recommend_high_token_usage(issue: dict, output_dir: Path) -> dict:
    """High output-token count — flag for review."""
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "medium",
        "risk_level": "low",
        "summary": "High output-token count from a single agent session.",
        "rationale": (
            "Output token count above 50K can indicate either legitimate large work "
            "(big repo, thorough depth) or runaway generation. Compare against the "
            "expected baseline for the assessment depth."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".appsec-trace.log",
                "details": "If --tracing was on, inspect per-agent token breakdown.",
            },
        ],
        "verification": [],
    }


def _recommend_tool_error(issue: dict, output_dir: Path) -> dict:
    """A tool returned is_error=true."""
    ev = issue["evidence"]
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "medium",
        "risk_level": "medium",
        "summary": "Tool returned is_error=true — review the failing call.",
        "rationale": (
            "The tool call failed but the orchestrator may have continued. "
            "Common causes: missing permissions, network failures, malformed input."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".hook-events.log",
                "details": (
                    f"Read the lines around line {ev.get('log_line', 0)} for the "
                    f"failing tool call's input and the error response."
                ),
            },
            {
                "type": "manual_review",
                "target": ".claude/settings.json",
                "details": "Check whether a permission prompt was missed (run /appsec-advisor:check-permissions --update).",
            },
        ],
        "verification": [],
    }


def _recommend_bash_warn(issue: dict, output_dir: Path) -> dict:
    """Bash output contained error/warning keywords."""
    ev = issue["evidence"]
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "low",
        "risk_level": "low",
        "summary": "Bash command output contained error/warning keywords.",
        "rationale": (
            "BASH_WARN is heuristic — the orchestrator's command produced output "
            "matching ERROR_KW (Traceback, error:, exit status 1, etc.). May be a "
            "false positive (e.g. printing example error text)."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".hook-events.log",
                "details": f"Read line {ev.get('log_line', 0)} for the full command + response.",
            },
        ],
        "verification": [],
    }


def _recommend_auto_retry_fired(issue: dict, output_dir: Path) -> dict:
    """Stage 2 auto-retry fired but ultimately succeeded."""
    ev = issue["evidence"]
    n = ev.get("iterations", 0)
    return {
        "category": "no_fix",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "low",
        "summary": (f"Auto-retry fired {n}× and ultimately succeeded — informational only. No action required."),
        "rationale": (
            "If this happens repeatedly on the same repo, the root cause should be "
            "addressed (most likely an LLM-fragment authoring issue). One-off auto-"
            "retries are normal Sonnet variance."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": "history",
                "details": (
                    "Compare with previous runs against the same repo — if this is the "
                    "3rd+ occurrence, file a plugin bug."
                ),
            },
        ],
        "verification": [],
    }


def _recommend_compose_retries_section(issue: dict, output_dir: Path) -> dict:
    """compose retried a section to convergence."""
    ev = issue["evidence"]
    sec = ev.get("section", "?")
    n = ev.get("attempts", 0)
    return {
        "category": "no_fix",
        "auto_applicable": False,
        "confidence": "medium",
        "risk_level": "low",
        "summary": f"§{sec} required {n}/3 attempts. Currently informational.",
        "rationale": (
            "If the same section retries on every run, the LLM author for that "
            "fragment is producing systematic schema drift. Update the orchestrator "
            "fragment-authoring guidance for that section."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": "agents/phases/phase-group-finalization.md",
                "details": f"Look for the §{sec} authoring guidance — tighten the schema explanation.",
            },
        ],
        "verification": [],
    }


def _recommend_contract_gate_drift(issue: dict, output_dir: Path) -> dict:
    """A QA contract repair plan was left unresolved on disk."""
    ev = issue.get("evidence", {})
    items = ev.get("items") or []
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "medium",
        "summary": (
            "The Stage-3 contract gate flagged section drift that was not cleared. "
            "Re-render from fragments, or — if the flagged section is depth-conditional "
            "(§3 walkthroughs / §7 security-architecture at --quick) — this is a checker bug."
        ),
        "rationale": (
            "A lingering .qa-repair-plan.json means check_contract found an expected "
            "section missing (or out of order). Genuine drift is fixed by recomposing "
            "from the fragments. But the contract gate evaluates depth/skip conditions: "
            "§3 and §7 are intentionally suppressed at --quick, so a plan naming ONLY "
            f"those is a false positive. Flagged items: {', '.join(str(i) for i in items[:6]) or '(see plan)'}."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".qa-repair-plan.json",
                "details": "Inspect the `actions[].heading` list — are the named sections genuinely expected at this depth?",
            },
            {
                "type": "rerun",
                "target": "/appsec-advisor:create-threat-model --rerender",
                "details": "Recompose from the existing fragments when the drift is real (a fragment was edited or a renderer/contract change landed).",
            },
        ],
        "verification": [],
    }


def _recommend_inline_shortcut_unresolved(issue: dict, output_dir: Path) -> dict:
    """The Stage-2 inline-shortcut hard gate never cleanly passed."""
    return {
        "category": "rerun",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "high",
        "summary": "Stage-2 inline-shortcut auto-retry was exhausted — the rendered document may be contract-incomplete.",
        "rationale": (
            "A surviving .inline-shortcut-repair-plan.json means compose could not "
            "produce a contract-clean threat-model.md within MAX_INLINE_RETRIES. The "
            "deliverable on disk may be missing required sections."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".inline-shortcut-repair-plan.json",
                "details": "Read the repair plan for the indicators (A1/A2/B/C + missing fragments).",
            },
            {
                "type": "rerun",
                "target": "/appsec-advisor:create-threat-model --rebuild",
                "details": "A contract-compliant Phase-11 output is reachable from the on-disk artifacts; if this reproduces, file a plugin bug.",
            },
        ],
        "verification": [],
    }


def _recommend_qa_status_not_pass(issue: dict, output_dir: Path) -> dict:
    """`.qa-status.json` shows a non-pass status at completion."""
    ev = issue.get("evidence", {})
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "medium",
        "risk_level": "medium",
        "summary": f"QA status is {ev.get('status', '?')!r} (not pass) — the document shipped with an unresolved QA concern.",
        "rationale": (
            "The deterministic gate or the QA reviewer wrote a non-pass status. The "
            "report still exists but a check (contract, mermaid, placeholders, "
            "yaml↔md consistency) did not clear."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".qa-status.json",
                "details": "Read the status note + any referenced repair plan to see which check failed.",
            },
        ],
        "verification": [],
    }


def _recommend_default(issue: dict, output_dir: Path) -> dict:
    """Fallback for unknown categories."""
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "low",
        "risk_level": "low",
        "summary": f"Unknown issue category {issue.get('category')!r} — manual review required.",
        "rationale": "No automated recommender for this category yet.",
        "actions": [
            {
                "type": "manual_review",
                "target": issue["evidence"].get("log_file", "logs"),
                "details": "Inspect the raw evidence and decide on a fix.",
            },
        ],
        "verification": [],
    }


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

RECOMMENDERS: dict[str, Callable[[dict, Path], dict]] = {
    "max_turns_subagent": _recommend_max_turns_subagent,
    "max_turns_orchestrator": _recommend_max_turns_orchestrator,
    "perf_anomaly_phase": _recommend_perf_anomaly_phase,
    "stage1_excessive_duration": _recommend_stage1_excessive_duration,
    "session_stop_unknown": _recommend_session_stop_unknown,
    "high_token_usage": _recommend_high_token_usage,
    "tool_error": _recommend_tool_error,
    "bash_warn": _recommend_bash_warn,
    "auto_retry_fired": _recommend_auto_retry_fired,
    "compose_retries_section": _recommend_compose_retries_section,
    "contract_gate_drift": _recommend_contract_gate_drift,
    "inline_shortcut_unresolved": _recommend_inline_shortcut_unresolved,
    "qa_status_not_pass": _recommend_qa_status_not_pass,
}


def enrich_with_recommendations(data: dict, output_dir: Path) -> dict:
    """Add `fix_recommendation` to every issue in `data['issues']` and
    update `summary['auto_applicable_fixes']` to count high-confidence
    auto-applicable recommendations.

    Mutates `data` in place AND returns it (so callers can chain).
    """
    auto_count = 0
    for issue in data.get("issues") or []:
        cat = issue.get("category", "")
        rec = RECOMMENDERS.get(cat, _recommend_default)(issue, output_dir)
        issue["fix_recommendation"] = rec
        if rec.get("auto_applicable") and rec.get("confidence") == "high":
            auto_count += 1
    if "summary" in data:
        data["summary"]["auto_applicable_fixes"] = auto_count
    return data


def main(argv: list[str] | None = None) -> int:
    """Standalone CLI: read .run-issues.json, enrich in place, write back."""
    import argparse

    p = argparse.ArgumentParser(prog="recommend_fixes.py", description=__doc__.splitlines()[0])
    p.add_argument("output_dir", type=Path)
    args = p.parse_args(argv)

    issues_path = args.output_dir / ".run-issues.json"
    if not issues_path.is_file():
        print(f"error: {issues_path} not found — run aggregate_run_issues.py first", file=sys.stderr)
        return 1
    try:
        data = json.loads(issues_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot parse {issues_path}: {exc}", file=sys.stderr)
        return 1

    data = enrich_with_recommendations(data, args.output_dir)

    try:
        issues_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write {issues_path}: {exc}", file=sys.stderr)
        return 1

    auto = data.get("summary", {}).get("auto_applicable_fixes", 0)
    print(f"recommend-fixes: enriched {len(data.get('issues') or [])} issue(s); {auto} auto-applicable")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
