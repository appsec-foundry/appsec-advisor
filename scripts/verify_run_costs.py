#!/usr/bin/env python3
"""verify_run_costs.py — Delta-based token/cost extraction from cumulative SESSION_STOP logs.

SESSION_STOP lines in .hook-events.log are **cumulative** per session ID: each
line is a running total, not an increment. A Claude Code session can span
multiple skill invocations, and sessions are reused for subagent work and
post-assessment activity (e.g. user-interactive exploration after the QA
reviewer completes).

To isolate the cost of a single assessment run, this script:
  1. Determines the run window (start boundary from ASSESSMENT_START,
     end boundary from ASSESSMENT_END + QA completion heuristic).
  2. For each session with activity inside the window, computes the delta
     between the last snapshot before/at window-start and the last snapshot
     within the window.
  3. Cross-verifies computed cost against API pricing formulas.
  4. Computes hypothetical cost without prompt caching.
  5. Parses ASSESSMENT_TOKENS lines (written by agent_logger.py at run-end)
     which include sub-agent token spend captured by the hook, and uses them
     to build a best-effort sub-agent cost estimate.

Known limitation: Claude Code's hook infrastructure only fires SESSION_STOP
events for the *host* Claude session. Sub-agents dispatched via the Agent tool
run in isolated sub-processes whose SESSION_STOP events are not visible here.
ASSESSMENT_TOKENS is a partial remedy — it sums token usage across all agents
that reported back to the orchestrator via structured log lines, but deep
sub-agents (e.g. STRIDE analyzers spawned by the orchestrator's own sub-agents)
may still be invisible. The subagent_estimate field is therefore a lower bound.

Usage:
    verify_run_costs.py <output-dir> [--pricing <model>] [--json] [--verbose]

Exit codes: 0 = success, 1 = data warnings, 2 = usage error.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Pricing models (USD per 1M tokens)
# ---------------------------------------------------------------------------
PRICING_MODELS: dict[str, dict[str, float]] = {
    "sonnet-4-6": {
        "input": 3.00,
        "output": 15.00,
        "cache_write": 3.75,
        "cache_read": 0.30,
    },
    "opus-4-6": {
        "input": 15.00,
        "output": 75.00,
        "cache_write": 18.75,
        "cache_read": 1.50,
    },
    "haiku-4-5": {
        "input": 0.80,
        "output": 4.00,
        "cache_write": 1.00,
        "cache_read": 0.08,
    },
}

# Field name in SESSION_STOP log → TokenSnapshot attribute name
_FIELD_MAP = {
    "in": "in_tokens",
    "out": "out_tokens",
    "cache_write": "cache_write",
    "cache_read": "cache_read",
}

# Sub-agent multiplier table: maps (depth, stride_model) → estimated true/hook ratio.
# These are *factory defaults* used only when no calibration data exists yet.
# After the first run where an ASSESSMENT_TOKENS signal is available, the script
# writes the observed ratio into .appsec-cache/cost-calibration.json and uses
# that on subsequent runs instead of these defaults (rolling average).
_SUBAGENT_MULTIPLIERS_DEFAULT: dict[str, float] = {
    "quick-sonnet":    3.5,
    "standard-sonnet": 4.7,
    "thorough-sonnet": 7.0,
    "quick-opus":      4.0,
    "standard-opus":   6.0,
    "thorough-opus":   9.0,
}

_CALIBRATION_FILE = "cost-calibration.json"
_CALIBRATION_MAX_SAMPLES = 10  # rolling window per key


def _load_calibration(output_dir: Path) -> dict[str, Any]:
    """Load per-key calibration data from .appsec-cache/cost-calibration.json."""
    path = output_dir / ".appsec-cache" / _CALIBRATION_FILE
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_actual_cost_calibration(output_dir: Path, key: str, actual_cost: float, host_cost: float) -> None:
    """Record a ground-truth ratio (actual_cost / host_cost) into the calibration file.

    Called externally via --actual-cost flag. This is the only correct way to
    calibrate the multiplier — ASSESSMENT_TOKENS is itself incomplete and must
    not be used as ground truth.
    """
    if host_cost <= 0:
        return
    ratio = actual_cost / host_cost
    cache_dir = output_dir / ".appsec-cache"
    path = cache_dir / _CALIBRATION_FILE
    try:
        data: dict[str, Any] = {}
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
        samples: list[float] = data.get(key, {}).get("samples", [])
        samples.append(round(ratio, 4))
        samples = samples[-_CALIBRATION_MAX_SAMPLES:]
        avg = round(sum(samples) / len(samples), 4)
        data[key] = {"samples": samples, "average": avg, "n": len(samples)}
        cache_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except (OSError, json.JSONDecodeError):
        pass


def _get_multiplier(key: str, output_dir: Path) -> tuple[float, str]:
    """Return (multiplier, source) for a given depth-model key.

    Preference order:
      1. Ground-truth calibration from .appsec-cache/cost-calibration.json
         (written via --actual-cost flag, requires ≥2 samples for stability)
      2. Factory default from _SUBAGENT_MULTIPLIERS_DEFAULT
    """
    cal = _load_calibration(output_dir)
    entry = cal.get(key, {})
    # Require at least 2 samples before trusting calibration — a single
    # data point is too noisy given run-to-run cost variation.
    if entry.get("n", 0) >= 2:
        return entry["average"], f"calibrated (n={entry['n']})"
    default = _SUBAGENT_MULTIPLIERS_DEFAULT.get(
        key, _SUBAGENT_MULTIPLIERS_DEFAULT["standard-sonnet"]
    )
    return default, "default"


def _load_plugin_pricing() -> dict[str, float] | None:
    """Load pricing from config. config.local.json overrides config.json when present."""
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if not plugin_root:
        return None
    local_path = os.path.join(plugin_root, "config.local.json")
    base_path = os.path.join(plugin_root, "config.json")
    config_path = local_path if os.path.isfile(local_path) else base_path
    if not os.path.isfile(config_path):
        return None
    try:
        with open(config_path) as f:
            cfg = json.load(f)
        p = cfg.get("pricing", {})
        if p:
            return {
                "input": p.get("input_per_1m", 3.00),
                "output": p.get("output_per_1m", 15.00),
                "cache_write": p.get("cache_write_per_1m", 3.75),
                "cache_read": p.get("cache_read_per_1m", 0.30),
            }
    except (json.JSONDecodeError, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class TokenSnapshot:
    in_tokens: int = 0
    out_tokens: int = 0
    cache_write: int = 0
    cache_read: int = 0
    cost: float = 0.0

    def total(self) -> int:
        return self.in_tokens + self.out_tokens + self.cache_write + self.cache_read

    def subtract(self, other: TokenSnapshot) -> TokenSnapshot:
        return TokenSnapshot(
            in_tokens=self.in_tokens - other.in_tokens,
            out_tokens=self.out_tokens - other.out_tokens,
            cache_write=self.cache_write - other.cache_write,
            cache_read=self.cache_read - other.cache_read,
            cost=self.cost - other.cost,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "in": self.in_tokens,
            "out": self.out_tokens,
            "cache_write": self.cache_write,
            "cache_read": self.cache_read,
            "cost": round(self.cost, 4),
        }


@dataclass
class SessionEntry:
    timestamp: str
    session_id: str
    snapshot: TokenSnapshot


@dataclass
class SessionResult:
    session_id: str
    agents: list[str]
    before_boundary: TokenSnapshot
    final_in_window: TokenSnapshot
    delta: TokenSnapshot
    computed_cost: float
    cross_check: str  # "OK" | "MISMATCH" | "NO_DATA"

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agents": self.agents,
            "before_boundary": self.before_boundary.as_dict(),
            "final_in_window": self.final_in_window.as_dict(),
            "delta": self.delta.as_dict(),
            "computed_cost": round(self.computed_cost, 4),
            "cross_check": self.cross_check,
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
SESSION_STOP_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\[([a-f0-9]+)\]\s+INFO\s+SESSION_STOP"
)
TOKEN_FIELD_RE = {
    "in": re.compile(r"\bin=([\d,]+)"),
    "out": re.compile(r"\bout=([\d,]+)"),
    "cache_write": re.compile(r"cache_write=([\d,]+)"),
    "cache_read": re.compile(r"cache_read=([\d,]+)"),
}
COST_RE = re.compile(r"cost=\$([\d.]+)")

# Agent attribution from AGENT_SPAWN lines in .hook-events.log
AGENT_SPAWN_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\[([a-f0-9]+)\]\s+INFO\s+AGENT_SPAWN\s+"
    r"(\S+)"
)

# ASSESSMENT_TOKENS lines written by agent_logger.py at assessment completion.
# Format (two variants):
#   throughput=N  input=N  output=N  (input split: fresh=N cache_write=N cache_read=N)  cost=$N
#   OR older format without fresh= split
ASSESSMENT_TOKENS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\[([a-f0-9]+)\]\s+INFO\s+ASSESSMENT_TOKENS\s+"
    r".*?input=([\d,]+).*?output=([\d,]+).*?cache_write=([\d,]+).*?cache_read=([\d,]+)"
    r".*?cost=\$([\d.]+)"
)

# ASSESSMENT_MODELS lines  (e.g. "agents: qa-reviewer=sonnet, stride-analyzer=sonnet")
ASSESSMENT_MODELS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+\[([a-f0-9]+)\]\s+INFO\s+ASSESSMENT_MODELS\s+"
    r"agents:\s*(.*)"
)


@dataclass
class AssessmentTokensEntry:
    timestamp: str
    session_id: str
    snapshot: TokenSnapshot   # input here = fresh (non-cached) input tokens
    # The hook also records the raw "input" field which includes cache_write+cache_read;
    # we store it separately for completeness.
    total_input_reported: int = 0


def parse_session_stops(hook_log: Path) -> list[SessionEntry]:
    """Parse all SESSION_STOP lines with token data from .hook-events.log."""
    entries: list[SessionEntry] = []
    with open(hook_log) as f:
        for line in f:
            m = SESSION_STOP_RE.match(line)
            if not m:
                continue
            if "cost=n/a" in line or "no usage data" in line:
                continue

            ts = m.group(1)
            sid = m.group(2)

            snap = TokenSnapshot()
            for log_field, regex in TOKEN_FIELD_RE.items():
                fm = regex.search(line)
                if fm:
                    val = int(fm.group(1).replace(",", ""))
                    setattr(snap, _FIELD_MAP[log_field], val)

            cm = COST_RE.search(line)
            if cm:
                snap.cost = float(cm.group(1))

            entries.append(SessionEntry(timestamp=ts, session_id=sid, snapshot=snap))

    return entries


def parse_assessment_tokens(hook_log: Path) -> list[AssessmentTokensEntry]:
    """Parse ASSESSMENT_TOKENS lines from .hook-events.log.

    These lines are written by agent_logger.py at the end of each assessment
    Agent invocation. They contain token counts aggregated across the
    orchestrator *and* any sub-agents that reported their usage back via
    structured log lines — giving a better picture than SESSION_STOP alone,
    which only captures the host Claude session.

    Log format (two variants):
      throughput=N  input=N  output=N  (input split: fresh=N cache_write=N cache_read=N)  cost=$N
      throughput=N  input=N  output=N  cache_write=N  cache_read=N  cost=$N
    """
    entries: list[AssessmentTokensEntry] = []
    with open(hook_log) as f:
        for line in f:
            m = ASSESSMENT_TOKENS_RE.match(line)
            if not m:
                continue
            ts = m.group(1)
            sid = m.group(2)
            total_input = int(m.group(3).replace(",", ""))
            out_tokens = int(m.group(4).replace(",", ""))
            cache_write = int(m.group(5).replace(",", ""))
            cache_read = int(m.group(6).replace(",", ""))
            cost = float(m.group(7))

            # "input" in this log line = fresh (non-cached) input tokens
            fresh_input = total_input
            # Reconstruct fresh_input from "fresh=N" sub-field when present
            fresh_m = re.search(r"fresh=([\d,]+)", line)
            if fresh_m:
                fresh_input = int(fresh_m.group(1).replace(",", ""))

            snap = TokenSnapshot(
                in_tokens=fresh_input,
                out_tokens=out_tokens,
                cache_write=cache_write,
                cache_read=cache_read,
                cost=cost,
            )
            entry = AssessmentTokensEntry(
                timestamp=ts,
                session_id=sid,
                snapshot=snap,
                total_input_reported=total_input,
            )
            entries.append(entry)
    return entries


def find_run_window(agent_log: Path, hook_log: Path) -> tuple[str | None, str | None]:
    """Find the assessment start and end boundaries.

    The start boundary is the earliest of:
      - ASSESSMENT_START / SCAN_START in .agent-run.log
      - The first AGENT_SPAWN in .hook-events.log for this assessment
        (the skill spawns the orchestrator *before* ASSESSMENT_START is logged,
        so pre-assessment setup costs — permissions, config — are captured too)

    Returns (start_boundary, end_boundary). The end boundary is the latest of
    ASSESSMENT_END, the last qa-reviewer CHECK_END, and the last
    architect-reviewer STEP_END/AGENT_END, plus a 180-second buffer to capture
    trailing SESSION_STOP entries.
    """
    start: str | None = None
    assess_end: str | None = None
    qa_end: str | None = None
    arch_end: str | None = None

    boundary_start_re = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?(ASSESSMENT_START|SCAN_START)"
    )
    boundary_end_re = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?ASSESSMENT_END"
    )
    qa_end_re = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?qa-reviewer\s+(?:CHECK_END|AGENT_COMPLETE|AGENT_END)"
    )
    arch_end_re = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?architect-reviewer\s+(?:STEP_END|AGENT_COMPLETE|AGENT_END)"
    )

    try:
        with open(agent_log) as f:
            for line in f:
                m = boundary_start_re.match(line)
                if m and start is None:
                    start = m.group(1)
                m = boundary_end_re.match(line)
                if m:
                    assess_end = m.group(1)
                m = qa_end_re.match(line)
                if m:
                    qa_end = m.group(1)  # keep updating — want the LAST one
                m = arch_end_re.match(line)
                if m:
                    arch_end = m.group(1)  # keep updating — want the LAST one
    except FileNotFoundError:
        pass

    # Fallback: try SCAN_START from hook-events.log
    if not start:
        scan_re = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+.*?SCAN_START")
        try:
            with open(hook_log) as f:
                for line in f:
                    m = scan_re.match(line)
                    if m:
                        start = m.group(1)
        except FileNotFoundError:
            pass

    # Extend start boundary backwards to capture pre-ASSESSMENT_START activity.
    # The skill runs configuration steps (permissions, settings) in the same
    # Claude session *before* the orchestrator logs ASSESSMENT_START. Those
    # SESSION_STOP snapshots are otherwise attributed to a prior window.
    # Strategy: find the earliest AGENT_SPAWN in hook-events.log that belongs
    # to the same logical run (within 30 min before the detected start), and
    # pull start back to the first SESSION_STOP *before* that spawn's timestamp.
    if start:
        try:
            with open(hook_log) as f:
                lines = f.readlines()
            earliest_spawn: str | None = None
            for line in lines:
                m = AGENT_SPAWN_RE.match(line)
                if not m:
                    continue
                ts = m.group(1)
                # Only consider spawns within 30 min before the detected start
                cutoff = _add_seconds_to_iso(start, -1800)
                if ts >= cutoff and ts <= start:
                    if earliest_spawn is None or ts < earliest_spawn:
                        earliest_spawn = ts
            if earliest_spawn:
                # Pull start back to the earliest spawn (minus 5s for the
                # session activity that preceded it)
                start = _add_seconds_to_iso(earliest_spawn, -5)
        except (FileNotFoundError, OSError):
            pass

    # End boundary: latest of assess_end, qa_end, and arch_end, plus 180s buffer
    candidates = [t for t in (assess_end, qa_end, arch_end) if t]
    end = max(candidates) if candidates else None

    if end:
        # SESSION_STOP entries have 1-3 min latency after agent work completes.
        # 180s buffer captures trailing snapshots without bleeding into
        # post-assessment activity (which typically starts 5+ min later).
        end = _add_seconds_to_iso(end, 180)

    return start, end


def build_subagent_estimate(
    hook_log: Path,
    start: str | None,
    end: str | None,
    host_session_cost: float,
    pricing: dict[str, float],
    output_dir: Path,
) -> dict[str, Any] | None:
    """Build a sub-agent cost estimate using two complementary signals.

    Signal 1 — ASSESSMENT_TOKENS lines: agent_logger.py writes these at the
    end of each Agent invocation. They aggregate token usage from the
    orchestrator plus any sub-agents that piped their usage back via structured
    log lines. This is typically more complete than SESSION_STOP alone.

    Signal 2 — Heuristic multiplier: when ASSESSMENT_TOKENS is missing or
    yields a lower figure than the host-session SESSION_STOP delta (which
    shouldn't happen but can due to log truncation), fall back to a depth- and
    model-based multiplier from _SUBAGENT_MULTIPLIERS.

    Returns a dict with:
      assessment_tokens_cost  — best figure from ASSESSMENT_TOKENS (may be None)
      multiplier_estimate     — heuristic upper bound
      best_estimate           — max(assessment_tokens_cost, multiplier_estimate)
      confidence              — "signal" | "heuristic" | "none"
      note                    — human-readable explanation
    """
    # --- Signal 1: parse ASSESSMENT_TOKENS ---
    at_entries = parse_assessment_tokens(hook_log)
    at_cost: float | None = None

    if at_entries:
        # Filter to those within run window
        in_window = [
            e for e in at_entries
            if (start is None or e.timestamp >= start)
            and (end is None or e.timestamp <= end)
        ]
        if in_window:
            # Sum all ASSESSMENT_TOKENS entries — each covers one Agent invocation.
            # Avoid double-counting repeated entries for the same session by
            # keeping only the highest-cost entry per session_id.
            by_session: dict[str, float] = {}
            for e in in_window:
                sid = e.session_id
                by_session[sid] = max(by_session.get(sid, 0.0), e.snapshot.cost)
            at_cost = sum(by_session.values())

    # --- Signal 2: heuristic multiplier from depth + model ---
    assessment_depth = "standard"
    stride_model_key = "sonnet"
    yaml_path = output_dir / "threat-model.yaml"
    if yaml_path.exists():
        try:
            with open(yaml_path) as f:
                content = f.read()
            depth_m = re.search(r"assessment_depth:\s*['\"]?(\w+)['\"]?", content)
            if depth_m:
                assessment_depth = depth_m.group(1).lower()
            # Detect Opus stride model
            if re.search(r"stride.*opus|opus.*stride", content, re.IGNORECASE):
                stride_model_key = "opus"
        except OSError:
            pass

    multiplier_key = f"{assessment_depth}-{stride_model_key}"
    multiplier, multiplier_source = _get_multiplier(multiplier_key, output_dir)
    multiplier_estimate = round(host_session_cost * multiplier, 2)

    # --- Combine ---
    # ASSESSMENT_TOKENS captures sub-agents that report back to the orchestrator via
    # structured log lines, but misses deep sub-agents that don't (e.g. STRIDE analyzers
    # running in fully isolated sessions). The multiplier (calibrated or default) covers
    # the remainder.
    #
    # Best estimate logic:
    #   - If ASSESSMENT_TOKENS > host_session (confirms sub-agents captured): use
    #     max(at_cost, multiplier_estimate) — both are lower bounds, take the higher.
    #   - If ASSESSMENT_TOKENS <= host_session (no sub-agent signal): use multiplier.
    #   - If no ASSESSMENT_TOKENS at all: use multiplier.
    multiplier_tag = f"{multiplier_key} ×{multiplier} [{multiplier_source}]"

    if at_cost is not None and at_cost > host_session_cost:
        best_estimate = round(max(at_cost, multiplier_estimate), 2)
        if multiplier_estimate >= at_cost:
            confidence = "heuristic"
            note = (
                f"ASSESSMENT_TOKENS reported ${at_cost:.2f} (sub-agent signal confirmed, "
                f"but multiplier estimate ${multiplier_estimate:.2f} is higher — "
                f"ASSESSMENT_TOKENS likely missed some sub-agents). "
                f"Best estimate uses multiplier ({multiplier_tag})."
            )
        else:
            confidence = "signal"
            note = (
                f"ASSESSMENT_TOKENS reported ${at_cost:.2f} (includes sub-agent usage "
                f"logged back to orchestrator). Multiplier upper bound: ${multiplier_estimate:.2f} "
                f"({multiplier_tag}). Best estimate uses the higher of the two."
            )
    elif at_cost is not None:
        best_estimate = round(multiplier_estimate, 2)
        confidence = "heuristic"
        note = (
            f"ASSESSMENT_TOKENS reported ${at_cost:.2f} (≤ host-session cost — "
            f"sub-agents likely not captured). Falling back to multiplier: "
            f"${multiplier_estimate:.2f} ({multiplier_tag})."
        )
    else:
        best_estimate = round(multiplier_estimate, 2)
        confidence = "heuristic"
        note = (
            f"No ASSESSMENT_TOKENS lines found in run window. "
            f"Multiplier estimate: ${multiplier_estimate:.2f} ({multiplier_tag})."
        )

    return {
        "assessment_tokens_cost": round(at_cost, 4) if at_cost is not None else None,
        "multiplier_key": multiplier_key,
        "multiplier": multiplier,
        "multiplier_source": multiplier_source,
        "multiplier_estimate": multiplier_estimate,
        "best_estimate": best_estimate,
        "confidence": confidence,
        "note": note,
    }


def _add_seconds_to_iso(ts: str, seconds: int) -> str:
    """Add seconds to an ISO 8601 timestamp string."""
    from datetime import datetime, timedelta, timezone
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    dt += timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def find_session_agents(
    hook_log: Path, start: str | None, end: str | None
) -> dict[str, list[str]]:
    """Map session IDs to agent names from AGENT_SPAWN lines within the run window."""
    sid_agents: dict[str, set[str]] = {}

    try:
        with open(hook_log) as f:
            for line in f:
                m = AGENT_SPAWN_RE.match(line)
                if not m:
                    continue
                ts, sid, agent_raw = m.group(1), m.group(2), m.group(3)

                # Only consider spawns within the run window
                if start and ts < start:
                    continue
                if end and ts > end:
                    continue

                # Simplify agent names
                agent = agent_raw.split(":")[-1] if ":" in agent_raw else agent_raw
                # Drop common prefixes for readability
                for prefix in ("appsec-advisor:appsec-", "appsec-advisor:", "appsec-"):
                    if agent.startswith(prefix):
                        agent = agent[len(prefix):]
                        break

                sid_agents.setdefault(sid, set()).add(agent)
    except FileNotFoundError:
        pass

    return {sid: sorted(agents) for sid, agents in sid_agents.items()}


def find_session_agent_counts(
    hook_log: Path, start: str | None, end: str | None
) -> dict[str, dict[str, int]]:
    """Map session IDs to a Counter-like dict of agent → spawn count.

    Used for primary-agent attribution when a single session hosted multiple
    agent lifecycles (e.g. threat-analyst followed by qa-reviewer in the same
    Claude session). The agent with the highest spawn count is treated as the
    dominant user of that session's tokens; ties are broken by sort order so
    attribution is deterministic across runs.
    """
    sid_counts: dict[str, dict[str, int]] = {}

    try:
        with open(hook_log) as f:
            for line in f:
                m = AGENT_SPAWN_RE.match(line)
                if not m:
                    continue
                ts, sid, agent_raw = m.group(1), m.group(2), m.group(3)

                if start and ts < start:
                    continue
                if end and ts > end:
                    continue

                agent = agent_raw.split(":")[-1] if ":" in agent_raw else agent_raw
                for prefix in ("appsec-advisor:appsec-", "appsec-advisor:", "appsec-"):
                    if agent.startswith(prefix):
                        agent = agent[len(prefix):]
                        break

                bucket = sid_counts.setdefault(sid, {})
                bucket[agent] = bucket.get(agent, 0) + 1
    except FileNotFoundError:
        pass

    return sid_counts


def _primary_agent(counts: dict[str, int]) -> str:
    """Return the dominant agent name for a session given spawn counts."""
    if not counts:
        return "unknown"
    # Sort by count descending, then agent name ascending for deterministic ties
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def aggregate_by_agent(
    results: list[SessionResult],
    sid_counts: dict[str, dict[str, int]],
    pricing: dict[str, float],
) -> list[dict[str, Any]]:
    """Fold per-session deltas onto a per-agent view.

    Each session's full delta is attributed to its primary agent (the agent
    with the highest spawn count in that session). For sessions with exactly
    one agent, this is exact. For sessions with multiple agents (rare — only
    happens when the outer Claude session is reused between orchestrator and
    QA reviewer), the delta slightly over-attributes to the dominant agent;
    this is documented as a known limitation and flagged via `ambiguous=true`
    in the per-agent entry.

    Returns a list of dicts, one per agent, sorted by cost descending.
    """
    agent_buckets: dict[str, dict[str, Any]] = {}

    for r in results:
        counts = sid_counts.get(r.session_id, {})
        # Fall back to the `agents` list from the SessionResult when the
        # counter map has no data (can happen if AGENT_SPAWN was outside the
        # run window but the session still had activity inside it).
        if counts:
            primary = _primary_agent(counts)
            ambiguous = len(counts) > 1
        elif r.agents and r.agents != ["unknown"]:
            primary = r.agents[0]
            ambiguous = len(r.agents) > 1
        else:
            primary = "unknown"
            ambiguous = False

        bucket = agent_buckets.setdefault(primary, {
            "agent": primary,
            "sessions": 0,
            "in": 0,
            "out": 0,
            "cache_write": 0,
            "cache_read": 0,
            "cost": 0.0,
            "ambiguous_sessions": 0,
        })
        bucket["sessions"] += 1
        bucket["in"] += r.delta.in_tokens
        bucket["out"] += r.delta.out_tokens
        bucket["cache_write"] += r.delta.cache_write
        bucket["cache_read"] += r.delta.cache_read
        bucket["cost"] += r.delta.cost
        if ambiguous:
            bucket["ambiguous_sessions"] += 1

    # Round costs and compute totals + pct_of_total
    total_cost = sum(b["cost"] for b in agent_buckets.values())
    rows: list[dict[str, Any]] = []
    for b in agent_buckets.values():
        b["cost"] = round(b["cost"], 4)
        b["total_tokens"] = b["in"] + b["out"] + b["cache_write"] + b["cache_read"]
        b["pct_of_total"] = (
            round(100 * b["cost"] / total_cost, 1) if total_cost > 0 else 0.0
        )
        rows.append(b)

    rows.sort(key=lambda x: x["cost"], reverse=True)
    return rows


def _detect_agent_models(output_dir: Path) -> dict[str, str]:
    """Read agent_models from threat-model.yaml, return normalized model map.

    Returns a dict like {"threat-analyst": "sonnet-4-6", "stride-analyzer": "opus-4-6"}.
    """
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.exists():
        return {}

    models: dict[str, str] = {}
    in_agent_models = False
    base_model: str | None = None

    try:
        with open(yaml_path) as f:
            for line in f:
                # Top-level model field (orchestrator model)
                m = re.match(r"^\s{2}model:\s+\"?([^\"]+)\"?\s*$", line)
                if m and not in_agent_models:
                    raw = m.group(1).strip()
                    base_model = _normalize_model_name(raw)

                # agent_models: block
                if re.match(r"^\s{2}agent_models:\s*$", line):
                    in_agent_models = True
                    continue
                if in_agent_models:
                    am = re.match(r"^\s{4}(\S+):\s+\"?([^\"]+)\"?\s*$", line)
                    if am:
                        agent = am.group(1).strip()
                        model = _normalize_model_name(am.group(2).strip())
                        models[agent] = model
                    elif not line.startswith("    "):
                        in_agent_models = False
    except OSError:
        return {}

    # Add orchestrator under its base model
    if base_model:
        models.setdefault("threat-analyst", base_model)

    return models


def _normalize_model_name(raw: str) -> str:
    """Normalize model identifiers to pricing model keys.

    Maps 'claude-sonnet-4-6' → 'sonnet-4-6', 'claude-opus-4-6' → 'opus-4-6', etc.
    """
    name = raw.lower().strip()
    for prefix in ("claude-", "anthropic/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    # Map common aliases
    aliases = {
        "sonnet": "sonnet-4-6",
        "opus": "opus-4-6",
        "haiku": "haiku-4-5",
    }
    return aliases.get(name, name)


def calc_cost(snap: TokenSnapshot, pricing: dict[str, float]) -> float:
    """Compute expected cost from token counts and pricing rates."""
    return (
        snap.in_tokens * pricing["input"] / 1_000_000
        + snap.out_tokens * pricing["output"] / 1_000_000
        + snap.cache_write * pricing["cache_write"] / 1_000_000
        + snap.cache_read * pricing["cache_read"] / 1_000_000
    )


def calc_no_cache_cost(snap: TokenSnapshot, pricing: dict[str, float]) -> float:
    """Hypothetical cost if all cached tokens were regular input."""
    all_input = snap.in_tokens + snap.cache_write + snap.cache_read
    return (
        all_input * pricing["input"] / 1_000_000
        + snap.out_tokens * pricing["output"] / 1_000_000
    )


# ---------------------------------------------------------------------------
# Main verification logic
# ---------------------------------------------------------------------------
def verify_run_costs(
    output_dir: Path,
    pricing_model: str = "sonnet-4-6",
    verbose: bool = False,
) -> dict[str, Any]:
    hook_log = output_dir / ".hook-events.log"
    agent_log = output_dir / ".agent-run.log"

    if not hook_log.exists():
        return {"error": "No .hook-events.log found", "exit_code": 2}

    # Resolve pricing: CLI --pricing flag takes precedence over plugin config.
    # Plugin config is a fallback default, not an override.
    if pricing_model != "sonnet-4-6":
        # Explicit --pricing flag was passed — use it
        pricing = PRICING_MODELS.get(pricing_model, PRICING_MODELS["sonnet-4-6"])
    else:
        # No explicit flag — try plugin config, then fall back to built-in sonnet
        plugin_pricing = _load_plugin_pricing()
        pricing = plugin_pricing or PRICING_MODELS["sonnet-4-6"]

    # Find run window
    start, end = find_run_window(agent_log, hook_log)
    if not start:
        return {"error": "Could not determine run start from .agent-run.log", "exit_code": 2}

    if verbose:
        print(f"Run window: {start} → {end or 'open'}", file=sys.stderr)

    # Parse all SESSION_STOP entries
    entries = parse_session_stops(hook_log)
    if not entries:
        return {"error": "No SESSION_STOP entries with token data found", "exit_code": 1}

    # Group by session ID
    by_session: dict[str, list[SessionEntry]] = {}
    for e in entries:
        by_session.setdefault(e.session_id, []).append(e)

    # Agent attribution: widen start by 60s to catch agent spawns that
    # precede ASSESSMENT_START (the orchestrator is spawned first, then
    # logs ASSESSMENT_START a few seconds later).
    attr_start = _add_seconds_to_iso(start, -60)
    sid_agents = find_session_agents(hook_log, attr_start, end)
    sid_agent_counts = find_session_agent_counts(hook_log, attr_start, end)

    # Compute deltas per session
    results: list[SessionResult] = []
    warnings: list[str] = []

    for sid, sess_entries in by_session.items():
        # Split entries relative to the run window
        before_start = [e for e in sess_entries if e.timestamp < start]
        if end:
            in_window = [e for e in sess_entries if start <= e.timestamp <= end]
        else:
            in_window = [e for e in sess_entries if e.timestamp >= start]

        if not in_window:
            continue  # Session had no activity during the assessment

        # Baseline: last cumulative snapshot before the run started
        baseline = before_start[-1].snapshot if before_start else TokenSnapshot()
        # Final: last cumulative snapshot within the run window
        final = in_window[-1].snapshot

        delta = final.subtract(baseline)

        # Sanity: negative deltas indicate data anomaly (session reset, etc.)
        has_negative = False
        for attr in ("in_tokens", "out_tokens", "cache_write", "cache_read"):
            if getattr(delta, attr) < 0:
                has_negative = True
                setattr(delta, attr, 0)
        if delta.cost < 0:
            has_negative = True
            delta.cost = 0.0
        if has_negative:
            warnings.append(f"Session {sid}: negative delta clamped to zero (data anomaly)")

        # Cross-verify: compute expected cost from delta tokens
        computed = calc_cost(delta, pricing)

        # Tolerance: 5% or $0.01, whichever is greater
        tolerance = max(abs(delta.cost) * 0.05, 0.01)
        if delta.cost == 0 and computed == 0:
            cross_check = "OK"
        elif abs(computed - delta.cost) <= tolerance:
            cross_check = "OK"
        else:
            cross_check = "MISMATCH"
            pct = abs(computed - delta.cost) / max(delta.cost, 0.001) * 100
            warnings.append(
                f"Session {sid}: logged=${delta.cost:.4f} vs computed=${computed:.4f} "
                f"(diff={abs(computed - delta.cost):.4f}, {pct:.1f}%)"
            )

        # Agent attribution
        agents = sid_agents.get(sid, ["unknown"])

        results.append(SessionResult(
            session_id=sid,
            agents=agents,
            before_boundary=baseline,
            final_in_window=final,
            delta=delta,
            computed_cost=computed,
            cross_check=cross_check,
        ))

    if not results:
        return {"error": "No sessions had activity during the assessment window", "exit_code": 1}

    # Aggregate totals
    totals = TokenSnapshot()
    for r in results:
        totals.in_tokens += r.delta.in_tokens
        totals.out_tokens += r.delta.out_tokens
        totals.cache_write += r.delta.cache_write
        totals.cache_read += r.delta.cache_read
        totals.cost += r.delta.cost

    total_computed = calc_cost(totals, pricing)
    total_tolerance = max(abs(totals.cost) * 0.05, 0.01)
    if abs(total_computed - totals.cost) <= total_tolerance:
        total_cross_check = "OK"
    else:
        total_cross_check = "MISMATCH"

    no_cache_cost = calc_no_cache_cost(totals, pricing)
    cache_savings_pct = (
        round((1 - totals.cost / no_cache_cost) * 100, 1)
        if no_cache_cost > 0 and totals.cost > 0 else 0.0
    )

    has_api_key = bool(os.environ.get("ANTHROPIC_API_KEY"))

    # Detect mixed-model runs from threat-model.yaml agent_models
    agent_models = _detect_agent_models(output_dir)
    mixed_model_costs: dict[str, Any] | None = None
    if agent_models:
        unique_models = set(agent_models.values())
        if len(unique_models) > 1 or (unique_models and pricing_model not in unique_models):
            # Compute cost estimates under each model's pricing
            mixed_model_costs = {}
            for model_key in sorted(unique_models):
                if model_key in PRICING_MODELS:
                    mp = PRICING_MODELS[model_key]
                    mixed_model_costs[model_key] = {
                        "cached": round(calc_cost(totals, mp), 4),
                        "no_cache": round(calc_no_cache_cost(totals, mp), 2),
                        "pricing": mp,
                    }
            if not mixed_model_costs:
                mixed_model_costs = None
            else:
                warnings.append(
                    f"Mixed models detected ({', '.join(f'{a}={m}' for a, m in sorted(agent_models.items()))}). "
                    f"Hook events only capture the host session — sub-agent tokens are not tracked. "
                    f"Cost estimates under each model's pricing are shown for reference."
                )

    per_agent = aggregate_by_agent(results, sid_agent_counts, pricing)

    # Sub-agent cost estimate — two complementary signals
    subagent_estimate = build_subagent_estimate(
        hook_log=hook_log,
        start=start,
        end=end,
        host_session_cost=totals.cost,
        pricing=pricing,
        output_dir=output_dir,
    )

    result: dict[str, Any] = {
        "run_window": {"start": start, "end": end},
        "sessions": [r.as_dict() for r in results],
        "per_agent": per_agent,
        "totals": {
            **totals.as_dict(),
            "total_tokens": totals.total(),
            "computed_cost": round(total_computed, 4),
            "cross_check": total_cross_check,
            "no_cache_cost": round(no_cache_cost, 2),
            "cache_savings_pct": cache_savings_pct,
        },
        "subagent_estimate": subagent_estimate,
        "agent_models": agent_models,
        "mixed_model_costs": mixed_model_costs,
        "pricing_model": pricing_model,
        "pricing": pricing,
        "billing": "api" if has_api_key else "subscription",
        "warnings": warnings,
        "exit_code": 0,
    }

    if verbose:
        _print_verbose(result, sys.stderr)

    return result


def _print_verbose(result: dict, out=sys.stderr) -> None:
    w = result["run_window"]
    print(f"\n{'=' * 70}", file=out)
    print(f"  Run window: {w['start']} → {w['end'] or 'open'}", file=out)
    print(f"  Pricing model: {result['pricing_model']}", file=out)
    print(f"  Sessions with activity: {len(result['sessions'])}", file=out)
    print(f"{'=' * 70}", file=out)

    for s in result["sessions"]:
        d = s["delta"]
        print(f"\n  Session {s['session_id']} ({', '.join(s['agents'])}):", file=out)
        bb = s["before_boundary"]
        fw = s["final_in_window"]
        print(f"    Baseline:  in={bb['in']:>8,}  out={bb['out']:>8,}  cw={bb['cache_write']:>10,}  cr={bb['cache_read']:>12,}  cost=${bb['cost']:.4f}", file=out)
        print(f"    Final:     in={fw['in']:>8,}  out={fw['out']:>8,}  cw={fw['cache_write']:>10,}  cr={fw['cache_read']:>12,}  cost=${fw['cost']:.4f}", file=out)
        print(f"    Delta:     in={d['in']:>8,}  out={d['out']:>8,}  cw={d['cache_write']:>10,}  cr={d['cache_read']:>12,}  cost=${d['cost']:.4f}", file=out)
        print(f"    Computed cost: ${s['computed_cost']:.4f}  [{s['cross_check']}]", file=out)

    t = result["totals"]
    billing = result["billing"]
    print(f"\n  {'─' * 50}", file=out)
    print(f"  Totals:", file=out)
    print(f"    Tokens: {t['total_tokens']:,} (host session only)", file=out)
    print(f"      Input:       {t['in']:>10,}", file=out)
    print(f"      Output:      {t['out']:>10,}", file=out)
    print(f"      Cache Write: {t['cache_write']:>10,}", file=out)
    print(f"      Cache Read:  {t['cache_read']:>10,}", file=out)

    cost_label = "Actual cost" if billing == "api" else "Est. cost (cached)"
    nocache_label = "Est. cost (no cache)" if billing == "subscription" else "No-cache cost"
    print(f"    {cost_label}:  ${t['cost']:.4f}  [{t['cross_check']}]", file=out)
    print(f"    {nocache_label}: ${t['no_cache_cost']:.2f}", file=out)
    print(f"    Cache savings: {t['cache_savings_pct']}%", file=out)

    # Per-agent breakdown
    per_agent = result.get("per_agent") or []
    if per_agent:
        print(f"\n  {'─' * 50}", file=out)
        print(f"  Per-Agent Cost Breakdown (primary-agent attribution):", file=out)
        header = f"    {'Agent':<20} {'Sessions':>8} {'Tokens':>14} {'Cost':>10} {'% Total':>8}"
        print(header, file=out)
        print(f"    {'-' * 20} {'-' * 8} {'-' * 14} {'-' * 10} {'-' * 8}", file=out)
        for row in per_agent:
            ambiguous_tag = " *" if row.get("ambiguous_sessions", 0) > 0 else ""
            print(
                f"    {row['agent']:<20} {row['sessions']:>8} "
                f"{row['total_tokens']:>14,} ${row['cost']:>8.4f} "
                f"{row['pct_of_total']:>7.1f}%{ambiguous_tag}",
                file=out,
            )
        if any(r.get("ambiguous_sessions", 0) > 0 for r in per_agent):
            print(
                f"    * Session hosted multiple agents — attribution rolled up to the "
                f"agent with the most spawns in that session.",
                file=out,
            )

    # Mixed-model cost breakdown
    mmc = result.get("mixed_model_costs")
    if mmc:
        print(f"\n  {'─' * 50}", file=out)
        print(f"  Mixed-model cost estimates (host session tokens under each model's pricing):", file=out)
        for model_key, costs in sorted(mmc.items()):
            p = costs["pricing"]
            print(f"    {model_key}:", file=out)
            print(f"      Cached:    ${costs['cached']:.4f}  (in=${p['input']}/M  out=${p['output']}/M  cw=${p['cache_write']}/M  cr=${p['cache_read']}/M)", file=out)
            print(f"      No cache:  ${costs['no_cache']:.2f}", file=out)

    agent_models = result.get("agent_models")
    if agent_models:
        print(f"\n  Agent models: {', '.join(f'{a}={m}' for a, m in sorted(agent_models.items()))}", file=out)

    # Sub-agent estimate block
    se = result.get("subagent_estimate")
    if se:
        print(f"\n  {'─' * 50}", file=out)
        print(f"  Sub-Agent Cost Estimate:", file=out)
        host = result["totals"]["cost"]
        print(f"    Host session (SESSION_STOP delta): ${host:.4f}", file=out)
        if se.get("assessment_tokens_cost") is not None:
            print(f"    ASSESSMENT_TOKENS (hook signal):   ${se['assessment_tokens_cost']:.4f}", file=out)
        print(f"    Heuristic multiplier estimate:     ${se['multiplier_estimate']:.2f}  "
              f"({se['multiplier_key']} ×{se['multiplier']})", file=out)
        print(f"    Best estimate (all agents):        ~${se['best_estimate']:.2f}  "
              f"[confidence: {se['confidence']}]", file=out)
        print(f"    Note: {se['note']}", file=out)

    if result["warnings"]:
        print(f"\n  Warnings:", file=out)
        for w in result["warnings"]:
            print(f"    ⚠ {w}", file=out)

    print(f"{'=' * 70}\n", file=out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Delta-based token/cost verification for threat model runs."
    )
    parser.add_argument("output_dir", help="Path to OUTPUT_DIR containing .hook-events.log")
    parser.add_argument(
        "--pricing", default="sonnet-4-6",
        choices=list(PRICING_MODELS.keys()),
        help="Pricing model to use for cross-verification (default: sonnet-4-6)",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout")
    parser.add_argument("--verbose", action="store_true", help="Print detailed breakdown to stderr")
    parser.add_argument(
        "--actual-cost", type=float, default=None, metavar="DOLLARS",
        help=(
            "Record the ground-truth total cost (e.g. from /cost) into "
            ".appsec-cache/cost-calibration.json so future multiplier estimates "
            "use real observed ratios instead of factory defaults. "
            "Example: --actual-cost 18.30"
        ),
    )

    args = parser.parse_args()
    output_dir = Path(args.output_dir)

    if not output_dir.is_dir():
        print(f"Error: {output_dir} is not a directory", file=sys.stderr)
        return 2

    result = verify_run_costs(output_dir, pricing_model=args.pricing, verbose=args.verbose)

    # Record ground-truth calibration when --actual-cost is provided.
    # Must happen after verify_run_costs so we have host_session_cost and multiplier_key.
    if args.actual_cost is not None:
        se = result.get("subagent_estimate", {})
        key = se.get("multiplier_key", "standard-sonnet")
        host_cost = result.get("totals", {}).get("cost", 0.0)
        if host_cost > 0:
            save_actual_cost_calibration(output_dir, key, args.actual_cost, host_cost)
            # Reload to get updated multiplier for display
            new_multiplier, new_source = _get_multiplier(key, output_dir)
            print(
                f"Calibration recorded: actual=${args.actual_cost:.2f}  "
                f"host=${host_cost:.4f}  ratio={args.actual_cost / host_cost:.4f}  "
                f"key={key}  new_multiplier={new_multiplier} [{new_source}]",
                file=sys.stderr,
            )
        else:
            print("Calibration skipped: host_session_cost is zero.", file=sys.stderr)

    exit_code = result.pop("exit_code", 0)

    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        if args.json:
            json.dump(result, sys.stdout, indent=2)
            print()
        return exit_code

    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    elif not args.verbose:
        t = result["totals"]
        billing = result["billing"]
        se = result.get("subagent_estimate")
        if billing == "api":
            cost_str = f"${t['cost']:.2f} (cached) / ${t['no_cache_cost']:.2f} (no cache)"
        else:
            cost_str = f"~${t['cost']:.2f} cached / ~${t['no_cache_cost']:.2f} no cache (estimated — subscription plan)"
        print(f"Tokens: {t['total_tokens']:,}  Cost: {cost_str}  Cross-check: {t['cross_check']}  Cache savings: {t['cache_savings_pct']}%")
        if se:
            conf_tag = f" [{se['confidence']}]" if se['confidence'] != 'signal' else ""
            print(f"  Sub-agent estimate (all agents): ~${se['best_estimate']:.2f}{conf_tag}  "
                  f"(host-only: ${t['cost']:.2f})")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
