#!/usr/bin/env python3
"""cost_running_total.py — running token + cost total since the assessment
started, computed from ``.hook-events.log``.

Used by:
  - The orchestrator after each PHASE_END to print a one-line banner showing
    cumulative token spend and cost delta since the previous phase.
  - The skill-level heartbeat watchdog to enforce ``--max-cost`` budget caps.

Design contract:
  - Pure read-only — never mutates the log.
  - Deterministic — same log content → same output.
  - Cheap — ~10 ms even on multi-MB hook logs.
  - Zero LLM tokens — pure regex parsing.

Usage:
    cost_running_total.py <output-dir> [--format banner|json|total-only]
                                       [--since-iso <iso-timestamp>]

Exit codes:
  0 — total computed and emitted
  1 — log file missing or unreadable (banner shows "n/a")
  2 — usage error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Reuse the canonical pricing + parsing primitives from verify_run_costs.py.
# This keeps the pricing-tier table single-sourced (haiku-4-5 was added
# there in 2026-04 — any new model lands there first, this script picks
# it up automatically).
THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(THIS_DIR))
import verify_run_costs as vrc  # type: ignore  # noqa: E402

# ---------------------------------------------------------------------------
# Pricing helpers — model-aware cost computation per snapshot
# ---------------------------------------------------------------------------


def _model_key_from_session(session_id: str, agent_log: Path) -> str | None:
    """Best-effort model attribution.

    For the orchestrator's host session we can read the model from
    .session-agent-map (written by agent_logger.py). For sub-agent
    sessions the model is logged in the AGENT_INVOKE line.
    """
    map_file = agent_log.parent / ".session-agent-map"
    if not map_file.exists():
        return None
    try:
        for line in map_file.read_text().splitlines():
            if not line or "=" not in line:
                continue
            sid, _, agent = line.partition("=")
            if sid.strip() == session_id:
                return agent.strip()
    except OSError:
        pass
    return None


def _compute_cost_from_snapshot(snap: vrc.TokenSnapshot, model_id: str = "sonnet-4-6") -> float:
    """Apply model pricing to a TokenSnapshot.

    Falls back to sonnet-4-6 pricing when the model is unknown — same
    conservative default verify_run_costs.py uses.
    """
    pricing = vrc.PRICING_MODELS.get(model_id, vrc.PRICING_MODELS["sonnet-4-6"])
    return (
        snap.in_tokens * pricing["input"] / 1_000_000
        + snap.out_tokens * pricing["output"] / 1_000_000
        + snap.cache_write * pricing["cache_write"] / 1_000_000
        + snap.cache_read * pricing["cache_read"] / 1_000_000
    )


# ---------------------------------------------------------------------------
# Window detection — "since assessment start"
# ---------------------------------------------------------------------------


_ASSESSMENT_START_RE = re.compile(r"^(\S+)\s+\[[^\]]+\]\s+INFO\s+\S+\s+ASSESSMENT_START")


def find_assessment_start(hook_log: Path, agent_log: Path) -> str | None:
    """Find the ASSESSMENT_START timestamp from agent-run.log first
    (most reliable), fall back to the earliest SESSION_STOP timestamp."""
    if agent_log.exists():
        try:
            for line in agent_log.read_text().splitlines():
                m = _ASSESSMENT_START_RE.match(line)
                if m:
                    return m.group(1)
        except OSError:
            pass
    # Fallback: earliest SESSION_STOP in hook log
    if hook_log.exists():
        entries = vrc.parse_session_stops(hook_log)
        if entries:
            return entries[0].timestamp
    return None


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def aggregate_running_total(output_dir: Path, since_iso: str | None = None) -> dict[str, Any]:
    """Sum all SESSION_STOP deltas in the run window."""
    hook_log = output_dir / ".hook-events.log"
    agent_log = output_dir / ".agent-run.log"

    if not hook_log.exists():
        return {
            "status": "no-log",
            "total_tokens": 0,
            "cost_usd": 0.0,
            "in_tokens": 0,
            "out_tokens": 0,
            "cache_write": 0,
            "cache_read": 0,
            "session_count": 0,
        }

    window_start = since_iso or find_assessment_start(hook_log, agent_log)
    entries = vrc.parse_session_stops(hook_log)

    # SESSION_STOP lines are cumulative per session_id. To get the
    # window total we take the LAST snapshot per session within the
    # window minus the snapshot at-or-before the window start.
    by_session: dict[str, list[vrc.SessionEntry]] = {}
    for e in entries:
        by_session.setdefault(e.session_id, []).append(e)

    total = vrc.TokenSnapshot()
    session_count = 0
    for sid, ses_entries in by_session.items():
        ses_entries.sort(key=lambda x: x.timestamp)
        # Last snapshot at or before window_start (= baseline to subtract)
        baseline = vrc.TokenSnapshot()
        if window_start:
            for e in ses_entries:
                if e.timestamp <= window_start:
                    baseline = e.snapshot
                else:
                    break
        # Last snapshot in window (= cumulative top)
        latest_in_window = None
        for e in ses_entries:
            if window_start is None or e.timestamp >= window_start:
                latest_in_window = e.snapshot
        if latest_in_window is None:
            continue
        delta = latest_in_window.subtract(baseline)
        # Aggregate
        total.in_tokens += max(delta.in_tokens, 0)
        total.out_tokens += max(delta.out_tokens, 0)
        total.cache_write += max(delta.cache_write, 0)
        total.cache_read += max(delta.cache_read, 0)
        session_count += 1

    # Compute cost — host session is typically Sonnet; if any sub-agent
    # used Haiku/Opus, the SESSION_STOP cost field already reflects that
    # so we sum the reported cost where available.
    reported_cost_sum = 0.0
    used_reported = False
    for sid, ses_entries in by_session.items():
        for e in ses_entries:
            if window_start and e.timestamp < window_start:
                continue
            if e.snapshot.cost > 0:
                used_reported = True
        # Use the LATEST cost in the window per session (cumulative)
        latest = None
        for e in ses_entries:
            if window_start and e.timestamp < window_start:
                continue
            if e.snapshot.cost > 0:
                latest = e.snapshot.cost
        if latest is not None:
            reported_cost_sum += latest

    if used_reported:
        cost = round(reported_cost_sum, 4)
    else:
        # No reported cost — compute from token counts at Sonnet pricing
        # (best-effort fallback)
        cost = round(_compute_cost_from_snapshot(total, "sonnet-4-6"), 4)

    return {
        "status": "ok",
        "window_start": window_start,
        "session_count": session_count,
        "in_tokens": total.in_tokens,
        "out_tokens": total.out_tokens,
        "cache_write": total.cache_write,
        "cache_read": total.cache_read,
        "total_tokens": total.total(),
        "cost_usd": cost,
    }


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------


def format_banner(result: dict[str, Any], phase_label: str | None = None) -> str:
    """One-line banner for orchestrator phase boundaries."""
    if result["status"] != "ok":
        return "  ↳ running total: n/a (no hook log yet)"
    total = result["total_tokens"]
    cost = result["cost_usd"]
    if total == 0:
        return "  ↳ running total: 0 tokens, $0.00"
    # Format token count with k-suffix for readability
    if total >= 1_000_000:
        token_str = f"{total / 1_000_000:.1f}M"
    elif total >= 1_000:
        token_str = f"{total / 1_000:.0f}k"
    else:
        token_str = str(total)
    return f"  ↳ running total: {token_str} tokens, ${cost:.2f}"


def format_total_only(result: dict[str, Any]) -> str:
    """Just the dollar amount — for budget-cap watchdog comparisons."""
    return f"{result.get('cost_usd', 0.0):.4f}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cost_running_total.py")
    p.add_argument("output_dir", help="$OUTPUT_DIR — must contain .hook-events.log")
    p.add_argument("--format", choices=("banner", "json", "total-only"), default="banner")
    p.add_argument("--since-iso", default=None, help="Override window start (ISO 8601). Default: ASSESSMENT_START.")
    p.add_argument("--phase-label", default=None, help="Optional phase label for the banner (informational).")
    ns = p.parse_args(argv)

    output_dir = Path(ns.output_dir)
    if not output_dir.exists():
        print("  ↳ running total: n/a (output dir missing)", file=sys.stderr)
        return 1

    result = aggregate_running_total(output_dir, ns.since_iso)

    if ns.format == "json":
        print(json.dumps(result, indent=2))
    elif ns.format == "total-only":
        print(format_total_only(result))
    else:
        print(format_banner(result, ns.phase_label))

    return 0


if __name__ == "__main__":
    sys.exit(main())
