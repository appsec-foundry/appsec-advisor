#!/usr/bin/env python3
"""Cross-check the surfaces that describe one returned semantic dispatch.

Four producers describe the same Agent call: the controller accepts the output
artifacts and advances, the hook lifecycle records a terminal state and the
child's usage, the budget watchdog retires the call, and the skill records the
stage stats. Each is locally correct on its own and they can still disagree —
postfix6 accepted the recon artifacts and advanced to architecture while the
lifecycle held the same call as failed with zero tokens.

The check runs at a semantic boundary, after the controller has accepted the
prior output. It looks only at the calls of the most recent dispatch action:
those are the calls whose producer has just returned, and a controller-owned
retry opens a new action rather than replaying one.

Reporting is diagnostic by default — lifecycle and hook state are observational,
and a mismatch must not abort a production run. ``APPSEC_TELEMETRY_STRICT=1``
turns the same finding into a hard failure for an acceptance run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import agent_lifecycle
import budget_watchdog
import context_routing

STAGE_STATS_FILENAME = ".stage-stats.jsonl"


def strict_enabled() -> bool:
    """True when a mismatch must fail the run instead of being reported."""
    return os.environ.get("APPSEC_TELEMETRY_STRICT", "").strip().lower() in {"1", "true", "yes"}


def _dispatched_jobs_by_action(output_dir: Path) -> dict[str, set[str]]:
    """Job IDs per action, from the controller's effective plan."""
    path = Path(output_dir) / context_routing.PLAN_NAME
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(plan, dict):
        return {}
    actions: dict[str, set[str]] = {}
    for row in plan.get("actions") or []:
        if isinstance(row, dict) and isinstance(row.get("action_id"), str):
            actions[row["action_id"]] = {job for job in row.get("job_ids") or [] if isinstance(job, str)}
    return actions


def _latest_action_calls(calls: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Return the action ID and the calls of the most recently spawned action."""
    if not calls:
        return "", []
    # Persisted order breaks the tie: several calls can be spawned inside one
    # second, and the whole-second timestamp alone would then pick an earlier
    # action over the wave that just returned.
    _, newest = max(enumerate(calls), key=lambda item: (int(item[1].get("spawned_at") or 0), item[0]))
    action_id = newest.get("action_id")
    if not isinstance(action_id, str) or not action_id:
        return "", [newest]
    return action_id, [call for call in calls if call.get("action_id") == action_id]


def _stage_stats_tokens(output_dir: Path) -> dict[str, int]:
    """Tokens recorded per agent type in the stage stats.

    Absence is not a finding: the skill records a wave's stats around the same
    boundary and the two orders are both legitimate. A record that exists and
    reports nothing is a finding, because a call the lifecycle charged cannot
    also have cost nothing.
    """
    try:
        raw = (Path(output_dir) / STAGE_STATS_FILENAME).read_text(encoding="utf-8")
    except OSError:
        return {}
    tokens: dict[str, int] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict) or not isinstance(record.get("agent"), str):
            continue
        try:
            count = int(record.get("tokens") or 0)
        except (TypeError, ValueError):
            count = 0
        tokens[record["agent"]] = tokens.get(record["agent"], 0) + max(0, count)
    return tokens


def _open_budget_calls(output_dir: Path) -> set[str]:
    try:
        state = json.loads((Path(output_dir) / budget_watchdog.STATE_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    calls = state.get("calls") if isinstance(state, dict) else None
    return set(calls) if isinstance(calls, dict) else set()


def _mismatch(call: dict[str, Any], code: str, detail: str) -> dict[str, str]:
    return {
        "job_id": str(call.get("job_id") or "?"),
        "agent_call_id": str(call.get("agent_call_id") or "?"),
        "agent_type": str(call.get("agent_type") or "?"),
        "code": code,
        "detail": detail,
    }


def check_returned_calls(output_dir: str | Path) -> list[dict[str, str]]:
    """Return one record per disagreement about the calls that just returned.

    Empty when every surface agrees, when nothing has been dispatched yet, or
    when the lifecycle state is unreadable — this is a consistency check, not a
    second lifecycle authority.
    """
    output_dir = Path(output_dir)
    try:
        state = json.loads(agent_lifecycle.state_path(output_dir).read_text(encoding="utf-8"))
        calls = agent_lifecycle.validate_state(state)["calls"]
    except (OSError, ValueError, agent_lifecycle.LifecycleError):
        return []

    # The effective plan is the record of what the controller dispatched. No
    # plan means nothing passed the context-v2 contract, so there is no
    # accepted output to cross-check against.
    dispatched = _dispatched_jobs_by_action(output_dir)
    if not dispatched:
        return []
    action_id, action_calls = _latest_action_calls(calls)
    accepted_jobs = dispatched.get(action_id, set())
    candidates = [call for call in action_calls if str(call.get("job_id") or "") in accepted_jobs]
    if not candidates:
        return []

    open_budget = _open_budget_calls(output_dir)
    stats_tokens = _stage_stats_tokens(output_dir)
    findings: list[dict[str, str]] = []
    for job_id in sorted(accepted_jobs - {str(call.get("job_id") or "") for call in candidates}):
        findings.append(
            _mismatch(
                {"job_id": job_id, "agent_call_id": "?", "agent_type": "?"},
                "lifecycle_call_missing",
                "the dispatched job has no lifecycle call; its admission hook never registered",
            )
        )
    for call in candidates:
        state_name = call.get("state")
        if state_name == "running":
            findings.append(
                _mismatch(call, "lifecycle_not_terminal", "output was accepted while the call is still running")
            )
        elif state_name == "failed":
            findings.append(
                _mismatch(
                    call,
                    "lifecycle_failed_after_accepted_output",
                    f"output was accepted but the call is failed: {call.get('failure_reason') or 'unknown'}",
                )
            )
        usage = call.get("usage") or {}
        charged = int(usage.get("output_tokens") or 0)
        if state_name == "done" and not charged:
            findings.append(_mismatch(call, "usage_unattributed", "terminal call carries no child output tokens"))
        if call.get("agent_call_id") in open_budget:
            findings.append(_mismatch(call, "budget_not_retired", "turn budget still holds an entry for the call"))
        agent_type = str(call.get("agent_type") or "")
        if charged and agent_type in stats_tokens and not stats_tokens[agent_type]:
            findings.append(
                _mismatch(call, "stage_stats_zero_usage", "stage stats report zero tokens for a charged call")
            )
    return findings


def format_detail(finding: dict[str, str]) -> str:
    """Canonical event detail for one mismatch."""
    return (
        f"code={finding['code']}  job_id={finding['job_id']}  "
        f"agent_call_id={finding['agent_call_id']}  agent_type={finding['agent_type']}  "
        f"detail={finding['detail']}"
    )
