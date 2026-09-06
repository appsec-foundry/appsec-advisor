#!/usr/bin/env python3
"""cost_running_total.py — token + cost total for the assessment, computed
from ``.hook-events.log`` and ``.agent-run.log``.

Used by:
  - ``skill_watchdog.py`` for the running figure on the live progress line,
    refreshed on the cadence that view shows rather than every tick.
  - ``run-headless.sh`` at the end of a run: the cost-by-phase table always, and
    the whole-run figure when no result object survived to carry the exact one.

What the run costs is not what one session reports. Two boundaries decide it,
and getting either wrong moves the figure by a factor:

  - ``SESSION_STOP`` covers the emitting session only. Sub-agents carry the
    larger half of a run and report separately through ``AGENT_USAGE``, so
    both are summed here. Agents that never report usage are counted, and the
    total is then a floor.
  - The host session outlives the assessment. Its cumulative counter keeps
    growing while the user works on afterwards, so the window is closed at
    the last pipeline event rather than at the last snapshot.

Design contract:
  - Pure read-only — never mutates the log.
  - Deterministic — same log content → same output.
  - Cheap — ~10 ms even on multi-MB hook logs.
  - Zero LLM tokens — pure regex parsing.

Usage:
    cost_running_total.py <output-dir> [--format banner|json|total-only|phases]
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
from datetime import datetime, timedelta, timezone
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
# Window detection — the assessment, not the host session
# ---------------------------------------------------------------------------


_ASSESSMENT_START_RE = re.compile(r"^(\S+)\s+\[[^\]]+\]\s+INFO\s+\S+\s+ASSESSMENT_START")
_AGENT_LOG_EVENT_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\[[^\]]*\]\s+\S+\s+(\S+)\s")

# Roles that keep writing to .agent-run.log after the pipeline is done:
# the watchdog polls until it is killed, and the host session mirrors its
# own SESSION_STOP snapshots. Neither marks pipeline work.
_NON_PIPELINE_ROLES = frozenset({"skill-watchdog", "shared-session"})

# The last pipeline event and the SESSION_STOP that reports it are not
# simultaneous — the snapshot lands on the next turn boundary.
_END_GRACE_SECONDS = 180

_AGENT_USAGE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?\sAGENT_USAGE\s+(.*)$")
_AGENT_SPAWN_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?\sAGENT_SPAWN\s+(.*)$")
_USAGE_SOURCE_ABSENT = "code=usage_source_absent"

#: Per-wave stats the orchestrator records from the host's `<usage>` block. The
#: fallback token source when no hook-visible per-call usage exists.
STAGE_STATS_FILENAME = ".stage-stats.jsonl"

# AGENT_USAGE logs a model family; the pricing table is keyed by release.
_PRICING_ALIAS = {"sonnet": "sonnet-4-6", "haiku": "haiku-4-5", "opus": "opus-4-6"}


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


def _shift_iso(timestamp: str, seconds: int) -> str:
    """Move an ISO-8601 Z timestamp by ``seconds``, preserving the format."""
    moved = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return moved.strftime("%Y-%m-%dT%H:%M:%SZ")


def find_assessment_end(agent_log: Path) -> str | None:
    """Return the timestamp after which SESSION_STOP no longer reports the run.

    The host session outlives the assessment: once the pipeline finishes, the
    same session keeps working, and its cumulative ``SESSION_STOP`` counter
    keeps growing. Taking the last snapshot therefore charges the run for
    whatever the user did next. The boundary is the last event a pipeline role
    wrote to ``.agent-run.log``, plus a grace window for the snapshot that
    follows it.

    Returns ``None`` when no pipeline event is present; the caller then leaves
    the window open, which is the pre-existing behaviour.
    """
    if not agent_log.exists():
        return None
    last: str | None = None
    try:
        with open(agent_log) as handle:
            for line in handle:
                m = _AGENT_LOG_EVENT_RE.match(line)
                if m and m.group(2) not in _NON_PIPELINE_ROLES and (last is None or m.group(1) > last):
                    last = m.group(1)
    except OSError:
        return None
    return _shift_iso(last, _END_GRACE_SECONDS) if last else None


# ---------------------------------------------------------------------------
# Sub-agent usage — the half no SESSION_STOP snapshot contains
# ---------------------------------------------------------------------------


def stage_stats_residual_tokens(
    output_dir: Path,
    host_tokens: dict[str, int],
    window_start: str | None = None,
    window_end: str | None = None,
) -> tuple[int, set[str]]:
    """Tokens of calls no ``AGENT_USAGE`` covers, from the stage stats.

    ``AGENT_USAGE`` exists only where the host answered the call itself: a child
    transcript at the path ``SubagentStop`` names, or a synchronous Agent return
    carrying ``usage``. A headless session persists no transcript, and a host
    that promotes the call to async returns a launch acknowledgement instead —
    when both hold, the hook layer sees no usage for any call and every token
    and cost figure in the run reads zero while the run in fact spent them.

    ``.stage-stats.jsonl`` survives that, because its number comes from the
    ``<usage>`` block the host renders to the orchestrator rather than from a
    hook payload. It is the same quantity: on the one 2026-09-05 run where both
    sources exist, the record's ``tokens`` equals the sum of ``in + out +
    cache_write + cache_read`` of the calls it names, exactly, on eight of eight
    waves. What it does not carry is the split into those four classes, and the
    price of a token differs fiftyfold between them — so these tokens are
    counted and deliberately left unpriced rather than priced on an invented
    mix.

    A record names its calls in ``dispatch_event_ids``. Where some of them are
    already metered, their host totals are subtracted so a wave that is half
    covered contributes only its remainder. Returns the residual token count and
    the calls it accounts for.
    """
    path = Path(output_dir) / STAGE_STATS_FILENAME
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0, set()

    residual = 0
    covered: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        # A record that does not say when it was written stays in: dropping it
        # would silently lose real spend, while keeping it can at worst charge
        # this run for a wave of its own output directory.
        recorded_at = record.get("recorded_at")
        if isinstance(recorded_at, str) and recorded_at:
            if window_start and recorded_at < window_start:
                continue
            if window_end and recorded_at > window_end:
                continue
        try:
            tokens = int(record.get("tokens") or 0)
        except (TypeError, ValueError):
            continue
        ids = [
            str(entry)[len("call:") :]
            for entry in record.get("dispatch_event_ids") or []
            if isinstance(entry, str) and entry.startswith("call:")
        ]
        # A record that names no call cannot be attributed, and one reporting
        # nothing is not evidence that its calls were free — the abuse-case
        # verifiers record zero tokens and stay unmetered on purpose.
        if not ids or tokens <= 0:
            continue
        unclaimed = [call_id for call_id in ids if call_id not in host_tokens]
        if not unclaimed:
            continue
        remainder = tokens - sum(host_tokens[call_id] for call_id in ids if call_id in host_tokens)
        if remainder <= 0:
            continue
        residual += remainder
        covered.update(unclaimed)
    return residual, covered


def aggregate_subagent_usage(
    agent_log: Path,
    window_start: str | None = None,
    window_end: str | None = None,
) -> dict[str, Any]:
    """Sum the sub-agent spend the host session does not account for.

    ``AGENT_USAGE`` is the priced source: each sub-agent reports its four token
    classes once, priced by the model it ran on. Calls it does not reach fall
    back to the stage stats, which give an exact token total and no class split
    — see ``stage_stats_residual_tokens``. ``unmetered_agents`` counts the
    spawns neither source covers; with those, or with unpriced tokens present,
    the returned cost is a floor rather than a total.
    """
    result: dict[str, Any] = {
        "subagent_count": 0,
        "unmetered_agents": 0,
        "usage_source_absent": False,
        "unpriced_tokens": 0,
        "unpriced_calls": 0,
        "subagent_snapshot": vrc.TokenSnapshot(),
        "subagent_cost": 0.0,
    }
    if not agent_log.exists():
        return result

    snapshot = vrc.TokenSnapshot()
    cost = 0.0
    metered: set[str] = set()
    spawned: set[str] = set()
    host_tokens: dict[str, int] = {}
    try:
        lines = agent_log.read_text(errors="replace").splitlines()
    except OSError:
        return result

    for line in lines:
        for pattern, seen in ((_AGENT_USAGE_RE, metered), (_AGENT_SPAWN_RE, spawned)):
            m = pattern.match(line)
            if not m:
                continue
            timestamp, rest = m.group(1), m.group(2)
            if window_start and timestamp < window_start:
                continue
            if window_end and timestamp > window_end:
                continue
            fields = dict(re.findall(r"(\w+)=([^\s]+)", rest))
            call_id = fields.get("agent_call_id")
            if not call_id or call_id in seen:
                continue
            seen.add(call_id)
            if pattern is not _AGENT_USAGE_RE:
                continue
            pricing = vrc.PRICING_MODELS.get(
                _PRICING_ALIAS.get(fields.get("model", ""), ""),
                vrc.PRICING_MODELS["sonnet-4-6"],
            )
            for log_field, attr in (
                ("in", "in_tokens"),
                ("out", "out_tokens"),
                ("cache_write", "cache_write"),
                ("cache_read", "cache_read"),
            ):
                try:
                    value = int(fields.get(log_field, "0").replace(",", ""))
                except ValueError:
                    continue
                setattr(snapshot, attr, getattr(snapshot, attr) + value)
                host_tokens[call_id] = host_tokens.get(call_id, 0) + value
                cost += value * pricing[{"in": "input", "out": "output"}.get(log_field, log_field)] / 1_000_000
        if _USAGE_SOURCE_ABSENT in line:
            result["usage_source_absent"] = True

    unpriced, covered = stage_stats_residual_tokens(agent_log.parent, host_tokens, window_start, window_end)
    result["subagent_count"] = len(metered | covered)
    result["unmetered_agents"] = len(spawned - metered - covered)
    result["unpriced_tokens"] = unpriced
    result["unpriced_calls"] = len(covered)
    result["subagent_snapshot"] = snapshot
    result["subagent_cost"] = cost
    return result


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
    window_end = find_assessment_end(agent_log)
    entries = vrc.parse_session_stops(hook_log)
    if window_end:
        in_window = [e for e in entries if e.timestamp <= window_end]
        # A pipeline log that ends before the first snapshot bounds nothing —
        # it is too sparse to say where the run stopped. Keep the window open
        # rather than report zero.
        if in_window:
            entries = in_window
        else:
            window_end = None

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
        # Strictly before: when the window start is itself the first snapshot
        # (no ASSESSMENT_START line to key on), that snapshot is run cost and
        # subtracting it would drop the pipeline's own startup.
        baseline = vrc.TokenSnapshot()
        if window_start:
            for e in ses_entries:
                if e.timestamp < window_start:
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
        host_cost = round(reported_cost_sum, 4)
    else:
        # No reported cost — compute from token counts at Sonnet pricing
        # (best-effort fallback)
        host_cost = round(_compute_cost_from_snapshot(total, "sonnet-4-6"), 4)

    # A SESSION_STOP snapshot covers the session that emitted it and nothing
    # else. Sub-agents report separately, so a run's cost is the sum of both.
    sub = aggregate_subagent_usage(agent_log, window_start, window_end)
    sub_snapshot: vrc.TokenSnapshot = sub["subagent_snapshot"]

    return {
        "status": "ok",
        "window_start": window_start,
        "window_end": window_end,
        "session_count": session_count,
        "in_tokens": total.in_tokens + sub_snapshot.in_tokens,
        "out_tokens": total.out_tokens + sub_snapshot.out_tokens,
        "cache_write": total.cache_write + sub_snapshot.cache_write,
        "cache_read": total.cache_read + sub_snapshot.cache_read,
        # Unpriced tokens are real spend and belong in the token total. They
        # carry no class, so they are added to no class column and to no cost.
        "total_tokens": total.total() + sub_snapshot.total() + sub["unpriced_tokens"],
        "cost_usd": round(host_cost + sub["subagent_cost"], 4),
        "host_cost_usd": host_cost,
        "subagent_cost_usd": round(sub["subagent_cost"], 4),
        "subagent_count": sub["subagent_count"],
        "unmetered_agents": sub["unmetered_agents"],
        "unpriced_tokens": sub["unpriced_tokens"],
        "unpriced_calls": sub["unpriced_calls"],
        # Exposed, not just folded into `cost_is_floor`: mid-run every reading is
        # a floor because sub-agents report at completion, while this flag means
        # the host reports no per-call usage at all and the figure is short by
        # orders of magnitude. Only the second is a reason to show nothing.
        "usage_source_absent": bool(sub["usage_source_absent"]),
        "cost_is_floor": bool(sub["unmetered_agents"] or sub["usage_source_absent"] or sub["unpriced_tokens"]),
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
    if result.get("unpriced_tokens") and cost <= 0:
        # Every token this run reported came from the stage stats, which carry
        # no class split. "≥$0.00" would read as "the run was nearly free" when
        # the truth is that nothing here can be priced at all.
        return f"  ↳ running total: {token_str} tokens, cost n/a (host reports no per-call token classes)"
    # "≥" rather than a number the reader would take as complete: some agents
    # run without reporting usage, and their spend is missing from `cost`.
    prefix = "≥" if result.get("cost_is_floor") else ""
    return f"  ↳ running total: {token_str} tokens, {prefix}${cost:.2f}"


def format_total_only(result: dict[str, Any]) -> str:
    """Just the dollar amount — for budget-cap watchdog comparisons."""
    return f"{result.get('cost_usd', 0.0):.4f}"


_PHASE_COST_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?\sPHASE_COST\s+(.*)$")


def _run_start_iso(output_dir: Path) -> str | None:
    """This run's start as an ISO timestamp, from ``.scan-start-epoch``."""
    try:
        epoch = int((output_dir / ".scan-start-epoch").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if epoch <= 0:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_phase_table(agent_log: Path, since_iso: str | None = None) -> str:
    """Where the run's time and money went, phase by phase.

    Built from the ``PHASE_COST`` lines ``skill_watchdog.py`` writes at every
    checkpoint phase change. The model table answers what a run cost; this
    answers which phase spent it — Phase 9 alone is 30-55 % of the weighted
    plan. Costs are the same floor the live view showed, so they are marked
    ``≥`` and a phase whose window carried no metered usage shows a duration
    only. Empty output when the log holds no such line: a run that ended before
    its first phase boundary, or a watchdog that never started, has nothing to
    report and must not print an empty frame.

    ``since_iso`` scopes the table to the current run. ``.agent-run.log`` is
    append-only and ``--rebuild`` preserves it on purpose, so without the bound
    a rebuilt run would report the phases of the run before it as its own.
    """
    try:
        lines = agent_log.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    rows: list[tuple[str, str, str]] = []
    for line in lines:
        m = _PHASE_COST_RE.match(line)
        if not m:
            continue
        if since_iso and m.group(1) < since_iso:
            continue
        fields = dict(re.findall(r"(\w+)=([^\s]+)", m.group(2)))
        phase = fields.get("phase")
        if not phase:
            continue
        rows.append((phase, fields.get("duration", "?"), fields.get("delta", "")))
    if not rows:
        return ""
    width = max(len(r[0]) for r in rows)
    out = ["  Cost by phase — floor, from the run log"]
    for phase, duration, cost in rows:
        out.append(f"    phase {phase.ljust(width)}  {duration:>7}  {cost:>9}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cost_running_total.py")
    p.add_argument("output_dir", help="$OUTPUT_DIR — must contain .hook-events.log")
    p.add_argument("--format", choices=("banner", "json", "total-only", "phases"), default="banner")
    p.add_argument("--since-iso", default=None, help="Override window start (ISO 8601). Default: ASSESSMENT_START.")
    p.add_argument("--phase-label", default=None, help="Optional phase label for the banner (informational).")
    ns = p.parse_args(argv)

    output_dir = Path(ns.output_dir)
    if not output_dir.exists():
        print("  ↳ running total: n/a (output dir missing)", file=sys.stderr)
        return 1

    if ns.format == "phases":
        table = format_phase_table(output_dir / ".agent-run.log", ns.since_iso or _run_start_iso(output_dir))
        if table:
            print(table)
        return 0

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
