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

Symptom recommendations are investigation guidance, never automatic edits.
The CLI's --diagnosis mode consumes a schema-valid diagnosis tied to the current
issue snapshot and replaces symptom advice with manual root-cause guidance.
Diagnosis text never selects commands or write targets.
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
    if not re.fullmatch(r"appsec-[a-z0-9]+(?:-[a-z0-9]+)*", agent_name):
        return None
    path = AGENTS_DIR / f"{agent_name}.md"
    if not path.resolve().is_relative_to(AGENTS_DIR.resolve()):
        return None
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


# The denominator budget_watchdog actually measured against, from its own
# `turns=<used>/<budget>` detail (budget_watchdog.format_detail).
_EVENT_BUDGET_RE = re.compile(r"\bturns=\d+/(\d+)\b")


def _event_turn_budget(issue: dict) -> int | None:
    """Return the ceiling the run really exceeded, not the frontmatter one.

    They are the same for most agents, but a STRIDE dispatch carries a PER-CALL
    override: build_stride_dispatch_manifest computes a per-component budget
    (a complexity tier, or the flat CHEAP_STRIDE_TURNS screening budget) into
    context-plan.json, agent_logger forwards it as MAX_TURNS, and
    budget_watchdog measures against THAT. Those budgets sit far below the
    frontmatter ceiling, so a component overshooting its soft budget raised a
    MAX_TURNS event while the hard limit was never approached and the agent
    delivered complete output. Recommending a frontmatter bump there edits a
    number nobody exceeded and quietly lifts the real ceiling for every
    dispatch of that agent (juice-shop 2026-08-21: turns=21/8 against
    `maxTurns: 96`).
    """
    m = _EVENT_BUDGET_RE.search(str(issue.get("evidence", {}).get("raw_event") or ""))
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# Recommenders — one per category
# ---------------------------------------------------------------------------


def _recommend_max_turns_subagent(issue: dict, output_dir: Path) -> dict:
    """A budget crossing establishes a symptom, not a need for more turns."""
    src = (issue["evidence"].get("source_agent") or "").strip()
    agent_name = src if src.startswith("appsec-") else f"appsec-{src}"
    current = _read_agent_max_turns(agent_name)
    measured = _event_turn_budget(issue)
    rec = {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "low",
        "risk_level": "low",
        "summary": f"Investigate {src!r} turn usage (measured budget: {measured}; maxTurns: {current}).",
        "rationale": (
            "A budget event does not establish a plugin root cause or legitimate need for more turns. "
            "Inspect the producing prompt, context routing, repeated reads, retries, and publication work. "
            "Increase a limit only when measured useful work requires it; never adjust a test ceiling "
            "as a substitute for a regression test."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".agent-run.log",
                "details": (
                    "Trace measured usage to the plugin producer and its contract. Propose a neutral "
                    "reproduction, an incidental-name/path variant, and a negative case before developing a fix."
                ),
            }
        ],
        "verification": [],
    }
    if current is None:
        rec["degraded"] = "missing_recommender_input"
        rec["summary"] = f"Sub-agent {src!r} reported a budget event but its agent definition is unavailable."
    elif measured is not None and measured != current:
        rec["summary"] = (
            f"{src} exceeded a per-call budget of {measured} turns, not its "
            f"maxTurns ceiling of {current} — do not bump the agent file."
        )
    return rec


def _recommend_max_turns_orchestrator(issue: dict, output_dir: Path) -> dict:
    """The controller has no prompt-local turn ceiling to auto-edit."""
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "low",
        "summary": "The compact orchestration session exhausted its host turn budget.",
        "rationale": "The deterministic controller owns orchestration; no legacy analyst prompt remains to tune.",
        "actions": [
            {
                "type": "manual_review",
                "target": ".agent-run.log",
                "details": "Identify the bounded semantic job that failed to return before starting a fresh full run.",
            }
        ],
        "verification": [],
    }


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
                    "Inspect SESSION_STOP entries and the cost field. A runaway Phase-1 "
                    "of this shape has cost $51 over 8 hours before being noticed."
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
    """Unknown stop reasons require lifecycle evidence, regardless of usage."""
    ev = issue["evidence"]
    src = ev.get("source_agent", "?")
    cost = ev.get("cost_usd", 0.0)
    out_tokens = ev.get("output_tokens", 0)
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "low",
        "risk_level": "low",
        "summary": (
            f"Agent {src} ended with reason=unknown after {out_tokens:,} output tokens "
            f"(cost ${cost:.2f}); the cause is unconfirmed."
        ),
        "rationale": (
            "Token usage and cost do not establish why a call stopped. Inspect the call lifecycle, "
            "host return, measured turn budget, and plugin error handling before proposing a producer fix."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".agent-run.log",
                "details": "Correlate SESSION_STOP with the call's terminal evidence; do not infer a need for more turns.",
            }
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


def _recommend_abuse_case_inconclusive(issue: dict, output_dir: Path) -> dict:
    """A verifier could not settle one step of an abuse-case chain.

    Inconclusive is a real verdict, not a defect: the verifier found no code
    evidence either way within its budget. It matters because the chain is
    then reported without end-to-end confirmation, and the `✓ verified attack
    path` badge is withheld — a reader may read that absence as "not
    exploitable" rather than "not established".
    """
    ev = issue.get("evidence") or {}
    ac_id = ev.get("abuse_case_id") or "the abuse case"
    n_inc = ev.get("inconclusive_steps") or 1
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "low",
        "summary": f"{ac_id}: {n_inc} chain step(s) unresolved — the chain ships without end-to-end confirmation.",
        "rationale": (
            "An inconclusive step means the verifier found no evidence either way, not that "
            "the step fails. The usual causes are that the step's evidence lives outside the "
            "repository (deployment config, runtime state) or that the referenced finding "
            "names no concrete code path to check. Confirm the step by hand before treating "
            "the chain as broken; the missing badge understates the risk."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".abuse-case-verdicts.json",
                "details": (
                    f"Read the step_verdicts for {ac_id} and check whether the unresolved step "
                    "depends on evidence a source-tree scan cannot see."
                ),
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
                "target": "agents/appsec-threat-renderer.md",
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
            "The Stage-3 QA gate left one or more repair actions unresolved. "
            "Classify each action before choosing re-render, producer repair, or checker repair."
        ),
        "rationale": (
            "A lingering .qa-repair-plan.json can describe section structure, cross-references, "
            "walkthrough coverage, placeholders, or YAML/Markdown consistency. Only fragment-owned "
            "actions are re-render-fixable; an empty fragments_to_rewrite list requires producer or "
            f"checker review. Flagged items: {', '.join(str(i) for i in items[:6]) or '(see plan)'}."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".qa-repair-plan.json",
                "details": "Inspect action type, raw issue, severity, and fragments_to_rewrite before selecting a repair path.",
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


def _recommend_editorial_pass_incomplete(issue: dict, output_dir: Path) -> dict:
    """An optional editorial pass failed, lost packets, or restored its edits."""
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "low",
        "summary": "Editorial work was incomplete or discarded; the report was not fully polished.",
        "rationale": "Stage completion does not prove the reviewer delivered a valid plan for every packet.",
        "actions": [
            {
                "type": "manual_review",
                "target": ".agent-run.log",
                "details": "Inspect the final EDITORIAL_PASS outcome and packet counts; correlate failed dispatches before another run. Do not raise token limits or alter the released report manually.",
            }
        ],
        "verification": [],
    }


def _recommend_architect_status_not_pass(issue: dict, output_dir: Path) -> dict:
    """`.architect-status.json` shows a non-pass status at completion."""
    ev = issue.get("evidence", {})
    defects = ev.get("technical_defects")
    defect_note = f" with {defects} technical defect(s)" if isinstance(defects, int) else ""
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "medium",
        "summary": f"Architect status is {ev.get('status', '?')!r}{defect_note} — the review did not pass.",
        "rationale": (
            "The Stage-4 reviewer persisted a non-pass status after report rendering. "
            "Its repair plan distinguishes fragment repairs from plugin defects that "
            "cannot converge through re-rendering alone."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".architect-repair-plan.json",
                "details": "Inspect the action type and non_actionable_reason before rerendering.",
            },
        ],
        "verification": [],
    }


def _recommend_component_evidence_coverage(issue: dict, output_dir: Path) -> dict:
    """A component reached STRIDE with evidence for few of its in-scope files."""
    ev = issue.get("evidence", {})
    dropped = ev.get("unadmitted_focus_paths") or []
    drop_note = (
        f" {len(dropped)} focus path(s) were not admitted: {', '.join(map(str, dropped[:5]))}."
        if dropped
        else " Every focus path was admitted, so the narrow view comes from routing selection, not the budget."
    )
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "medium",
        "risk_level": "medium",
        "summary": (
            f"{ev.get('component_id', '?')} was analyzed from {ev.get('evidence_files', '?')} of "
            f"{ev.get('file_count', '?')} in-scope file(s)."
        ),
        "rationale": (
            "The bundle directs the analyzer's attention. Where it names few of a component's "
            "files, the rest were covered only if the analyzer independently looked, which makes "
            "coverage depend on exploration rather than on routing." + drop_note
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ev.get("log_file", ".dispatch-context"),
                "details": (
                    "Compare path_routing.focus_paths against the component's paths. A component "
                    "far larger than its focus list either needs narrower components or more "
                    "focus paths; unadmitted paths point at the slice budget instead."
                ),
            },
        ],
        "verification": [],
    }


def _recommend_routing_effectiveness(issue: dict, output_dir: Path) -> dict:
    """No finding for this component rested on a file routing delivered."""
    ev = issue.get("evidence", {})
    delivered = ev.get("delivered_files") or []
    cited = ev.get("cited_files") or []
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "medium",
        "risk_level": "low",
        "summary": (f"{ev.get('component_id', '?')} produced its findings from files the routing did not deliver."),
        "rationale": (
            "The analyzer read past its bundle and found the evidence itself, so this is not a "
            "gap in the findings. It does say the routing spent its budget on the wrong files "
            "for this component: nothing it delivered was cited, and everything cited came from "
            "elsewhere. Delivered: "
            + (", ".join(map(str, delivered[:5])) or "(none)")
            + ". Cited: "
            + (", ".join(map(str, cited[:5])) or "(none)")
            + "."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ev.get("log_file", ".dispatch-context"),
                "details": (
                    "Compare the cited files against the component's focus paths. Files the "
                    "analyzer had to find itself belong in the focus list; delivered files no "
                    "finding cites are candidates to drop."
                ),
            },
        ],
        "verification": [],
    }


def _recommend_dispatch_count_inconsistent(issue: dict, output_dir: Path) -> dict:
    """A stage row claims more dispatches than the run spawned."""
    ev = issue.get("evidence", {})
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "low",
        "summary": (
            f"Run statistics for {ev.get('agent', '?')} claim {ev.get('dispatch_count', '?')} "
            f"dispatch(es) against {ev.get('observed_spawns', '?')} spawn event(s)."
        ),
        "rationale": (
            "dispatch_count is derived from AGENT_SPAWN and summed across accumulate calls, so "
            "it cannot exceed the spawn events in the hook log. A count above them means a "
            "measurement window opened after its agents had started and the derivation fell "
            "back to the whole log. The cost and duration figures for that stage are affected; "
            "the analysis is not."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": ".stage-stats.jsonl",
                "details": (
                    "Check that the stage captured --since-iso before dispatching. The recorded "
                    "run cannot be corrected after the fact; read that stage's dispatch count "
                    "from .hook-events.log instead."
                ),
            },
        ],
        "verification": [],
    }


def _recommend_requirements_export_inconsistent(issue: dict, output_dir: Path) -> dict:
    """The report assessed requirements the structured export does not carry."""
    ev = issue.get("evidence", {})
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "medium",
        "summary": (
            f"The catalog declared {ev.get('declared', '?')} requirement(s); threat-model.yaml "
            f"exports {ev.get('exported', '?')} as assessed."
        ),
        "rationale": (
            "Consumers of the export — a CI gate, a dashboard, the completion summary — read "
            "their requirement counts from this key. Where it disagrees with the catalog the "
            "run was given, they report a requirements dimension the report does not have."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": "threat-model.yaml",
                "details": (
                    "Re-run build_threat_model_yaml.py against this output directory and read "
                    "its stderr: the compliance export is skipped rather than failed when its "
                    "parser cannot read the rendered assessment."
                ),
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
        # An issue category the aggregator emits but no recommender covers is a
        # coverage gap in this module, not a property of the scanned repository.
        "degraded": "no_recommender_for_category",
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


def _recommend_business_context_unmapped(issue: dict, output_dir: Path) -> dict:
    """Declared business context that the control analyst mapped to no component.

    Nothing is broken in the pipeline: the document was read and fenced, the
    analyst simply found no component the facts apply to. That is either a
    document written about the product rather than about what the code contains,
    or a component inventory whose names the document never touches. Both are
    the operator's call, so this proposes reading, never editing.
    """
    return {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "high",
        "risk_level": "low",
        "summary": (
            "Business context was declared for this run but applies to no component, "
            "so it changed neither scope nor any finding."
        ),
        "rationale": (
            "The control analyst projects declared facts onto component IDs; only a "
            "mapped component reaches STRIDE, crown-jewel selection, and the ranking "
            "tie-break. An unmapped context usually describes the product in terms the "
            "component inventory does not use — name the concrete services, data "
            "stores, and assets instead."
        ),
        "actions": [
            {
                "type": "manual_review",
                "target": "docs/business-context.md",
                "details": (
                    "Compare the wording with the component names in .components.json "
                    "and state the sensitive assets and compromise impact per service."
                ),
            },
        ],
        "verification": [],
    }


RECOMMENDERS: dict[str, Callable[[dict, Path], dict]] = {
    "editorial_pass_incomplete": _recommend_editorial_pass_incomplete,
    "business_context_unmapped": _recommend_business_context_unmapped,
    "component_evidence_coverage": _recommend_component_evidence_coverage,
    "routing_effectiveness": _recommend_routing_effectiveness,
    "dispatch_count_inconsistent": _recommend_dispatch_count_inconsistent,
    "requirements_export_inconsistent": _recommend_requirements_export_inconsistent,
    "max_turns_subagent": _recommend_max_turns_subagent,
    # A soft budget crossing is the same finding at warning severity — the
    # aggregator splits the category so the run stops reporting an error for a
    # component that delivered complete output. The recommender already tells
    # the two apart via _event_turn_budget and gives the soft case its own
    # advice, so it must stay reachable under both names.
    "turn_budget_exceeded": _recommend_max_turns_subagent,
    "max_turns_orchestrator": _recommend_max_turns_orchestrator,
    "perf_anomaly_phase": _recommend_perf_anomaly_phase,
    "stage1_excessive_duration": _recommend_stage1_excessive_duration,
    "session_stop_unknown": _recommend_session_stop_unknown,
    "high_token_usage": _recommend_high_token_usage,
    "abuse_case_inconclusive": _recommend_abuse_case_inconclusive,
    "tool_error": _recommend_tool_error,
    "bash_warn": _recommend_bash_warn,
    "auto_retry_fired": _recommend_auto_retry_fired,
    "compose_retries_section": _recommend_compose_retries_section,
    "contract_gate_drift": _recommend_contract_gate_drift,
    "inline_shortcut_unresolved": _recommend_inline_shortcut_unresolved,
    "qa_status_not_pass": _recommend_qa_status_not_pass,
    "architect_status_not_pass": _recommend_architect_status_not_pass,
}


def _current_diagnoses(data: dict, output_dir: Path) -> dict[str, dict]:
    """Validate the diagnostic snapshot before using its advisory prose.

    Old sidecars remain renderable but cannot guide fixes without source identity.
    Partial examination is valid; duplicate, foreign, or stale entries are not.
    """
    import jsonschema

    diagnosis = json.loads((output_dir / ".run-bugs.json").read_text(encoding="utf-8"))
    schema = json.loads((PLUGIN_ROOT / "schemas/run-bugs.schema.json").read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator(schema).validate(diagnosis)
    except jsonschema.ValidationError as exc:
        raise ValueError("diagnosis failed run-bugs schema validation") from exc
    if not data.get("generated") or diagnosis.get("source_generated") != data["generated"]:
        raise ValueError("diagnosis does not identify the current issue snapshot; run diagnose-run again")
    issues = data.get("issues") or []
    titles = {issue["id"]: issue["title"] for issue in issues}
    entries = diagnosis["diagnoses"]
    if len(titles) != len(issues) or diagnosis["issues_total"] != len(issues):
        raise ValueError("diagnosis issue total or source IDs do not match")
    if diagnosis["issues_examined"] != len(entries):
        raise ValueError("diagnosis examination count does not match")
    index = {}
    counts = dict.fromkeys(diagnosis["summary"], 0)
    for entry in entries:
        issue_id = entry["issue_id"]
        if issue_id in index or titles.get(issue_id) != entry["issue_title"]:
            raise ValueError("diagnosis contains a duplicate or unmatched issue")
        index[issue_id] = entry
        counts[entry["verdict"]] += 1
    if counts != diagnosis["summary"]:
        raise ValueError("diagnosis verdict counts do not match")
    return index


def _recommend_from_diagnosis(diagnosis: dict | None) -> dict:
    """Keep model-authored locations and suggestions in display-only details."""
    rec = {
        "category": "investigate",
        "auto_applicable": False,
        "confidence": "low",
        "risk_level": "low",
        "summary": "No diagnosis for this issue; investigate before developing a plugin fix.",
        "rationale": "The diagnosis may cover only a subset of recorded issues.",
        "actions": [],
        "verification": [],
    }
    if diagnosis is None:
        return rec
    verdict = diagnosis["verdict"]
    rec.update(
        summary=f"Diagnosis: {verdict} — {diagnosis['issue_title']}",
        confidence=diagnosis["confidence"],
        rationale=diagnosis["rationale"],
    )
    if verdict == "plugin_bug":
        root = diagnosis["root_cause"]
        rec["actions"] = [
            {
                "type": "manual_review",
                "target": ".",
                "details": (
                    f"Producer: {root['location']}. Defect: {root['description']}. "
                    f"Causal path: {root['causal_path']}. "
                    f"Proposed direction (unverified): {diagnosis.get('suggested_fix') or 'Not supplied'}. "
                    "Re-read the current plugin source and applicable contracts before editing. "
                    "Demonstrate a failing neutral reproduction, an incidental-name/path variant, "
                    "and a negative case. Report run recovery separately from the permanent plugin fix."
                ),
            }
        ]
    elif verdict in {"environment", "expected"}:
        rec["category"] = "no_fix"
    return rec


def enrich_with_recommendations(data: dict, output_dir: Path, *, use_diagnosis: bool = False) -> dict:
    """Add `fix_recommendation` to every issue in `data['issues']` and
    update `summary['auto_applicable_fixes']` to count high-confidence
    auto-applicable recommendations.

    Mutates `data` in place AND returns it (so callers can chain).
    """
    diagnoses = _current_diagnoses(data, output_dir) if use_diagnosis else None
    auto_count = 0
    for issue in data.get("issues") or []:
        cat = issue.get("category", "")
        if diagnoses is not None:
            rec = _recommend_from_diagnosis(diagnoses.get(issue.get("id")))
        else:
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
    p.add_argument(
        "--diagnosis", action="store_true", help="Require a valid current-run diagnosis for manual fix guidance"
    )
    p.add_argument("--dry-run", action="store_true", help="Print enriched JSON without writing the issue file")
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

    try:
        data = enrich_with_recommendations(data, args.output_dir, use_diagnosis=args.diagnosis)
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        print(f"error: cannot use diagnosis: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(json.dumps(data, indent=2))
        return 0

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
