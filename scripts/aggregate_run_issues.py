#!/usr/bin/env python3
"""Aggregate post-run issues from .agent-run.log + .hook-events.log
+ .appsec-trace.log into a structured ``$OUTPUT_DIR/.run-issues.json``.

Goal
----
Make every error / warning / performance anomaly / recovery event that
fired during the run discoverable WITHOUT log-grep. The output is the
single source of truth for:

  * The §Run Issues appendix in threat-model.md (rendered by
    compose_threat_model.py)
  * The "-- Run Issues --" block in the completion summary (rendered by
    render_completion_summary.py)
  * The /appsec-advisor:fix-run-issues skill (consumes recommendations
    and applies auto-eligible fixes)

Issue categories
----------------
  * ``error``           — TOOL_ERROR, MAX_TURNS, RENDER_FAILED, AGENT_ERROR
  * ``warning``         — BASH_WARN, RENDER_WARN, schema validation issues
  * ``perf_anomaly``    — phase / sub-agent wall-time exceeds depth threshold
  * ``recovery_event``  — auto-retry, REPAIR_MODE, re-render-loop iterations

Performance heuristics are hardcoded per assessment-depth (see
``PHASE_DURATION_LIMITS_SECONDS``). They are intentionally conservative —
``ANY_PHASE_HARD_CEILING_SECONDS`` (30 min) catches runaway phases
regardless of depth.

Each issue carries an ``evidence`` block (log file + line + raw snippet)
so downstream consumers (and human reviewers) can verify the
classification. ``recommend_fixes.py`` reads the issues, dispatches a
per-category recommender, and enriches each issue with a structured
``fix_recommendation`` block.

Exit codes
----------
0   ``.run-issues.json`` written (regardless of issue count).
1   Fatal error (output dir missing, log files unreadable).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Phase budgets — single source of truth in data/phase-budgets.yaml. Loaded
# via the shared phase_budgets module so this script, watch_run.py,
# acquire_lock.py, check_state.py and skill_watchdog.py all see the same
# numbers. Falls back to the historical hard-coded table when the YAML or
# loader is unavailable.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import phase_budgets  # type: ignore  # noqa: E402
except Exception:  # pragma: no cover
    phase_budgets = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Performance thresholds — phase wall-time max (seconds) before anomaly.
# ---------------------------------------------------------------------------
PHASE_DURATION_LIMITS_SECONDS: dict[str, dict[str, int]] = (
    {d: phase_budgets.budgets_for_depth(d) for d in ("quick", "standard", "thorough")}
    if phase_budgets
    else {
        "quick": {"1": 180, "2": 120, "3": 60, "9": 180, "10b": 60, "11": 300},
        "standard": {"1": 240, "2": 180, "3": 120, "9": 360, "10b": 120, "11": 600},
        "thorough": {"1": 360, "2": 240, "3": 180, "9": 720, "10b": 180, "11": 900},
    }
)

# Hard ceiling regardless of depth — anything beyond is always anomaly.
# A run-away phase (e.g. orchestrator stuck on sub-agent that never
# returned) blows past every reasonable expected duration.
ANY_PHASE_HARD_CEILING_SECONDS = phase_budgets.hard_ceiling_seconds() if phase_budgets else 1800


# Sprint 4B (M3.5): scale per-phase budgets by repository size. The bare
# table above is calibrated for "small" repos (~100-300 source files); a
# larger codebase like OWASP juice-shop (~1500 files) routinely sprints
# past the quick budgets purely because there is more to scan, not because
# anything is hung. Without this scaler every quick run on a non-trivial
# repo emitted 3-5 perf_anomaly_phase warnings that boiled down to
# "we're a bigger codebase than the test fixture".
#
# Formula: factor = 1 + log10(max(file_count / 100, 1))
#   100 files  → factor 1.0  (no change)
#   500 files  → factor 1.7
#   1500 files → factor 2.18 (juice-shop)
#   5000 files → factor 2.7
# The factor is applied to ALL phase budgets equally; the hard ceiling
# stays fixed (a true runaway is still a runaway, regardless of repo size).
def scale_phase_limits(
    base: dict[str, int],
    file_count: int,
) -> dict[str, int]:
    """Return a budget dict scaled by ``file_count`` per the formula above.

    ``file_count`` ≤ 100 → factor 1.0 (returns ``base`` unchanged).
    Negative counts and non-numerics → factor 1.0 (defensive).
    """
    import math

    try:
        n = max(int(file_count), 1)
    except (TypeError, ValueError):
        n = 1
    factor = 1.0 + math.log10(max(n / 100.0, 1.0))
    return {k: int(round(v * factor)) for k, v in base.items()}


def _count_repo_files(repo_root: Path) -> int:
    """Best-effort source-file count via ``git ls-files``. Falls back to a
    walk + extension allow-list when not in a git repo. Bounded to 50000
    so a misclassified vendor directory cannot pin the factor at infinity.
    """
    import subprocess as _sp

    try:
        r = _sp.run(
            ["git", "-C", str(repo_root), "ls-files"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if r.returncode == 0:
            n = sum(1 for _ in r.stdout.splitlines() if _.strip())
            return min(n, 50_000)
    except (OSError, _sp.TimeoutExpired, FileNotFoundError):
        pass
    # Fallback walk — restrict to common source extensions to avoid
    # counting node_modules etc. (git ls-files would have respected
    # .gitignore for free; the fallback can't, so be conservative).
    EXTS = {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".java",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".kt",
        ".swift",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".html",
        ".css",
        ".scss",
        ".vue",
        ".svelte",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
    }
    n = 0
    try:
        for p in repo_root.rglob("*"):
            if p.is_file() and p.suffix.lower() in EXTS:
                n += 1
                if n >= 50_000:
                    break
    except OSError:
        pass
    return n


# Sub-agent token-output ceiling — abnormal Sonnet sessions go up to
# ~64K output tokens. >50K signals a long-running session worth flagging
# even when the agent didn't hit MAX_TURNS.
SUBAGENT_OUTPUT_TOKEN_WARN = 50_000


# ---------------------------------------------------------------------------
# Log parsers — tolerant of incomplete/malformed lines
# ---------------------------------------------------------------------------

_LOG_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+\[(?P<sid>[^\]]*)\]\s+(?P<level>\S+)\s+(?P<source>\S+)\s+(?P<event>\S+)\s+(?P<detail>.*)$"
)

_PHASE_RE = re.compile(r"\[Phase\s+(?P<phase>[0-9b]+)/(?P<total>[0-9]+)\]\s*(?P<label>.*)")

_SESSION_STOP_RE = re.compile(
    r"stop_reason=(?P<reason>\S+).*?in=(?P<in>[\d,]+).*?out=(?P<out>[\d,]+).*?cost=\$(?P<cost>[\d.]+)"
)


def _parse_iso(ts: str) -> int | None:
    try:
        return int(datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def _read_log(path: Path) -> list[tuple[int, str]]:
    """Return list of (line_number, line) — empty list if file missing.
    Streaming-tolerant for huge logs (line by line)."""
    out = []
    if not path.is_file():
        return out
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                out.append((n, line.rstrip("\n")))
    except OSError:
        return []
    return out


_RUN_WINDOW_SECONDS = 5400  # 1.5 h — outer envelope of the longest thorough run


def _scope_to_current_run(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Limit the log slice to events from the current run only.

    Both ``.hook-events.log`` and ``.agent-run.log`` are append-only audit
    logs that survive across runs (preserved by ``--rebuild`` on purpose).
    Without scoping, the aggregator picks up ``SESSION_STOP``,
    ``BASH_WARN``, and other events from days-old runs and reports them
    as if they happened in the current invocation — observed during the
    2026-04-26 19:55 run, where 19 ``SESSION_STOP unknown`` events were
    flagged but most were from a long-completed prior session.

    Heuristic: keep only lines whose timestamp is within
    ``_RUN_WINDOW_SECONDS`` (90 min) of the **latest** parseable
    timestamp in the log. This works because:

      • ``--rebuild`` and ``--full`` runs always start with a fresh
        wipe and a new SCAN_START, so the freshest entries are the
        current run.
      • The longest thorough run is ~40 min; doubling that gives
        comfortable headroom while still excluding day-old events.
      • Boundary signals (``ASSESSMENT_END`` / ``ASSESSMENT_TOKENS``
        / ``SCAN_START``) are unreliable individually — ``ASSESSMENT_TOKENS``
        in particular fires at every Agent-dispatch session boundary,
        not only at end-of-run.

    Fallback: if no parseable timestamps exist (legacy log format),
    return all lines unchanged.
    """
    if not lines:
        return lines

    # Find the latest parseable timestamp.
    latest_ts = None
    for _, raw in lines:
        ev = _parse_event_line(raw)
        if not ev:
            continue
        ts_e = _parse_iso(ev["ts"])
        if ts_e is None:
            continue
        if latest_ts is None or ts_e > latest_ts:
            latest_ts = ts_e
    if latest_ts is None:
        return lines

    cutoff = latest_ts - _RUN_WINDOW_SECONDS
    out = []
    for ln, raw in lines:
        ev = _parse_event_line(raw)
        if not ev:
            # Keep unparseable lines that occur after the cutoff window
            # (continuation lines, etc.) — but if we cannot place them
            # in time we have to err towards including, since dropping
            # them might lose a multi-line event payload.
            out.append((ln, raw))
            continue
        ts_e = _parse_iso(ev["ts"])
        if ts_e is None or ts_e >= cutoff:
            out.append((ln, raw))
    return out


def _parse_event_line(line: str) -> dict[str, str] | None:
    """Parse a canonical agent_logger.py line into structured fields."""
    m = _LOG_LINE_RE.match(line.strip())
    if not m:
        return None
    return m.groupdict()


# ---------------------------------------------------------------------------
# Phase duration extraction
# ---------------------------------------------------------------------------


def _extract_phase_durations(agent_log: list[tuple[int, str]]) -> list[dict]:
    """Walk the agent-run.log, pair PHASE_START / PHASE_END events. When
    PHASE_END is missing (mid-run crash, batched logging quirk), fall
    back to the next PHASE_START as approximate end timestamp.

    Pairing semantics (M3.2 — fix for double-counted Phase 2 perf anomaly):

      • An END pops the **most recent** preceding unmatched START for
        the same phase number. Older orphan STARTs for the same phase
        are then discarded so they don't pair against a later, unrelated
        END. This kills the "Phase 2 ran 6m 31s" ghost duration the
        2026-04-26 19:55 run produced (two Phase-2 STARTs followed by
        one Phase-2 END — the orphan START was silently picked up as a
        valid pair, producing a false anomaly alongside the real one).

      • A still-unmatched START at end-of-log uses the **next-in-time
        START** (any phase) as approximate end timestamp, preserving the
        legacy mid-run-crash heuristic. The next-start search is done
        across the *full* event stream, not just other unmatched starts,
        because a Phase 1 START followed by a Phase 2 START (matched)
        + END should still surface Phase 1's approximate duration.

    Returns list of dicts: {phase, label, start_ts, end_ts, duration_seconds, end_inferred}
    """
    # All STARTs in original log order (used for the "next-START fallback"
    # when an unmatched START needs an approximate end).
    all_starts: list[tuple[int, int, str, str, str]] = []
    # Per-phase stack of unmatched STARTs. Append on PHASE_START; pop the
    # latest on PHASE_END.
    open_starts: dict[str, list[tuple[int, int, str, str]]] = {}
    pairs: list[tuple[tuple[int, int, str, str, str], tuple[int, int, str], bool]] = []
    # tuple shape: (start_record, end_record, end_inferred)

    for ln, raw in agent_log:
        ev = _parse_event_line(raw)
        if not ev:
            continue
        if "PHASE_START" in ev["event"]:
            pm = _PHASE_RE.search(ev["detail"])
            if pm:
                ts_e = _parse_iso(ev["ts"])
                if ts_e is not None:
                    phase = pm.group("phase")
                    label = pm.group("label").strip()
                    all_starts.append((ln, ts_e, ev["ts"], phase, label))
                    open_starts.setdefault(phase, []).append((ln, ts_e, ev["ts"], label))
        elif "PHASE_END" in ev["event"]:
            pm = _PHASE_RE.search(ev["detail"])
            if pm:
                ts_e = _parse_iso(ev["ts"])
                if ts_e is not None:
                    phase = pm.group("phase")
                    stack = open_starts.get(phase) or []
                    if stack:
                        # Latest unmatched START is the real one — discard older
                        # orphan STARTs so the next END (if any) pairs against a
                        # different phase, not a stale start.
                        start_ln, start_ts, start_raw, label = stack.pop()
                        # Drop any older orphans for this phase — they have no
                        # matching END within the run window.
                        open_starts[phase] = []
                        pairs.append(((start_ln, start_ts, start_raw, phase, label), (ln, ts_e, ev["ts"]), False))

    # Any STARTs still in open_starts were never matched by an END. Use the
    # next-in-time START (any phase) as approximate end so a mid-run crash
    # still surfaces a (best-effort) duration. We sort all_starts by line
    # number so "next" means "next chronologically" which agrees with line
    # ordering for the canonical agent-run.log shape.
    all_starts.sort(key=lambda r: r[0])
    for phase, stack in open_starts.items():
        for entry in stack:
            ln, ts_e, raw_ts, label = entry
            # Find the next START strictly after this one.
            next_record = None
            for cand in all_starts:
                if cand[0] > ln:
                    next_record = cand
                    break
            if next_record is None:
                continue  # no later START — skip
            next_ln, next_ts_e, next_raw_ts, _, _ = next_record
            pairs.append(((ln, ts_e, raw_ts, phase, label), (next_ln, next_ts_e, next_raw_ts), True))

    out = []
    for (start_ln, ts_start, raw_ts, phase, label), (end_ln, ts_end, raw_end_ts), end_inferred in pairs:
        out.append(
            {
                "phase": phase,
                "label": label,
                "start_ts": raw_ts,
                "end_ts": raw_end_ts,
                "duration_seconds": ts_end - ts_start,
                "start_line": start_ln,
                "end_line": end_ln,
                "end_inferred": end_inferred,
            }
        )
    # Sort by start line for stable ordering (matches the prior implementation).
    out.sort(key=lambda d: d["start_line"])
    return out


# ---------------------------------------------------------------------------
# Issue extractors — one per category
# ---------------------------------------------------------------------------


def _extract_errors(hook_log: list[tuple[int, str]], agent_log: list[tuple[int, str]]) -> list[dict]:
    """TOOL_ERROR, MAX_TURNS, RENDER_FAILED."""
    issues: list[dict] = []
    for source_path, lines in (("hook-events.log", hook_log), ("agent-run.log", agent_log)):
        for ln, raw in lines:
            ev = _parse_event_line(raw)
            if not ev:
                continue
            event = ev["event"]
            if event in ("TOOL_ERROR", "MAX_TURNS"):
                issues.append(
                    {
                        "category": "max_turns_subagent" if event == "MAX_TURNS" else "tool_error",
                        "severity": "error",
                        "title": f"{event}: {_clip(ev['detail'], 80)}",
                        "evidence": {
                            "log_file": f".{source_path}",
                            "log_line": ln,
                            "raw_event": raw[:300],
                            "timestamp_iso": ev["ts"],
                            "source_agent": ev["source"],
                        },
                    }
                )
    return issues


def _extract_warnings(hook_log: list[tuple[int, str]]) -> list[dict]:
    """BASH_WARN events from PostToolUse hook."""
    issues: list[dict] = []
    for ln, raw in hook_log:
        ev = _parse_event_line(raw)
        if not ev or ev["event"] != "BASH_WARN":
            continue
        issues.append(
            {
                "category": "bash_warn",
                "severity": "warning",
                "title": f"Bash command emitted error/warn keyword: {_clip(ev['detail'], 80)}",
                "evidence": {
                    "log_file": ".hook-events.log",
                    "log_line": ln,
                    "raw_event": raw[:300],
                    "timestamp_iso": ev["ts"],
                },
            }
        )
    return issues


def _extract_perf_anomalies(
    phase_durs: list[dict],
    depth: str,
    *,
    file_count: int = 0,
) -> list[dict]:
    """Phases that exceed depth-specific limits or the hard ceiling.

    Sprint 4B: when ``file_count > 100`` the per-phase budgets are scaled
    via ``scale_phase_limits`` so a non-trivial-sized repo is not flagged
    just for being a non-trivial-sized repo. The scaling factor is
    surfaced in each issue's evidence dict (``budget_scale_factor``,
    ``repo_file_count``) so the user can verify why a budget moved.
    """
    issues: list[dict] = []
    base = PHASE_DURATION_LIMITS_SECONDS.get(depth, PHASE_DURATION_LIMITS_SECONDS["standard"])
    limits = scale_phase_limits(base, file_count) if file_count > 0 else base
    for pd in phase_durs:
        ph = pd["phase"]
        dur = pd["duration_seconds"]
        expected = limits.get(ph)
        # Hard ceiling first — fires regardless of expected.
        if dur > ANY_PHASE_HARD_CEILING_SECONDS:
            issues.append(
                {
                    "category": "stage1_excessive_duration" if ph == "1" else "perf_anomaly_phase",
                    "severity": "error",
                    "title": (
                        f"Phase {ph} {pd['label']} ran {_fmt_dur(dur)} — "
                        f"exceeds hard ceiling ({_fmt_dur(ANY_PHASE_HARD_CEILING_SECONDS)})"
                    ),
                    "evidence": {
                        "log_file": ".agent-run.log",
                        "log_line": pd["start_line"],
                        "raw_event": f"PHASE_START {pd['start_ts']} → END {pd['end_ts']}",
                        "phase": ph,
                        "label": pd["label"],
                        "duration_seconds": dur,
                        "expected_max_seconds": expected or 0,
                        "ceiling_seconds": ANY_PHASE_HARD_CEILING_SECONDS,
                        "end_inferred": pd["end_inferred"],
                    },
                }
            )
        elif expected and dur > expected:
            # Hysteresis (M3.3): ignore micro-overshoots. A 1.01× over-budget
            # ping is noise — it pollutes .run-issues.json with non-actionable
            # warnings and hides genuinely slow phases. Flag only when the
            # phase exceeds the budget by ≥20% AND by at least 30 seconds.
            mult = dur / expected
            slack_seconds = dur - expected
            if mult < 1.20 or slack_seconds < 30:
                continue
            issues.append(
                {
                    "category": "perf_anomaly_phase",
                    "severity": "warning",
                    "title": (
                        f"Phase {ph} {pd['label']} ran {_fmt_dur(dur)} — "
                        f"exceeds {depth}-depth expected ({_fmt_dur(expected)}, "
                        f"{mult:.1f}× over)"
                    ),
                    "evidence": {
                        "log_file": ".agent-run.log",
                        "log_line": pd["start_line"],
                        "raw_event": f"PHASE_START {pd['start_ts']} → END {pd['end_ts']}",
                        "phase": ph,
                        "label": pd["label"],
                        "duration_seconds": dur,
                        "expected_max_seconds": expected,
                        "multiplier": round(mult, 2),
                        "end_inferred": pd["end_inferred"],
                    },
                }
            )
    return issues


def _extract_session_stop_anomalies(agent_log: list[tuple[int, str]]) -> list[dict]:
    """SESSION_STOP with stop_reason=unknown is a budget-exhaustion signal.

    Sprint 4C (M3.5): the Claude Code Agent tool returns ``stop_reason=unknown``
    for every successful sub-agent dispatch in Subscription mode (the harness
    does not surface a meaningful reason — it is a transport limitation, not
    a problem). Result: a normal run produced 3-5 false-positive warnings,
    drowning real signals. Filter rule:

      * ``stop_reason=unknown`` AND ``output_tokens == 0``
            → suspicious (session ended without producing output — could
              be budget exhaustion or crash). Warn.
      * ``stop_reason=unknown`` AND ``0 < output_tokens ≤ 50k``
            → normal Subscription-mode sub-agent completion. Skip
              silently — there is nothing to act on.
      * ``stop_reason=unknown`` AND ``output_tokens > 50k``
            → still suspicious (a 50k-token session that cannot say why
              it ended is worth a look). Warn as ``session_stop_unknown``.
      * ``output_tokens > 50k`` regardless of reason → ``high_token_usage``
            (always emit — long sessions are independently interesting).
    """
    issues: list[dict] = []
    for ln, raw in agent_log:
        ev = _parse_event_line(raw)
        if not ev or ev["event"] != "SESSION_STOP":
            continue
        m = _SESSION_STOP_RE.search(ev["detail"])
        if not m:
            continue
        reason = m.group("reason")
        try:
            out_tokens = int(m.group("out").replace(",", ""))
        except ValueError:
            out_tokens = 0
        cost = float(m.group("cost"))
        # Sprint 4C: skip the dominant noise source — `unknown` with a
        # moderate non-zero output is just a normal Subscription-mode
        # sub-agent stop. But still surface high-output stops (>50k
        # tokens) regardless of stop_reason — that signal is independently
        # actionable (long-running session worth flagging).
        if reason == "unknown" and 0 < out_tokens <= SUBAGENT_OUTPUT_TOKEN_WARN:
            continue
        if reason == "unknown" or out_tokens > SUBAGENT_OUTPUT_TOKEN_WARN:
            issues.append(
                {
                    "category": "session_stop_unknown" if reason == "unknown" else "high_token_usage",
                    "severity": "warning",
                    "title": (
                        f"SESSION_STOP from {ev['source']}: reason={reason}, "
                        f"out={out_tokens:,} tokens, cost=${cost:.2f}"
                    ),
                    "evidence": {
                        "log_file": ".agent-run.log",
                        "log_line": ln,
                        "raw_event": raw[:300],
                        "timestamp_iso": ev["ts"],
                        "source_agent": ev["source"],
                        "stop_reason": reason,
                        "output_tokens": out_tokens,
                        "cost_usd": cost,
                    },
                }
            )
    return issues


def _extract_recovery_events(output_dir: Path) -> list[dict]:
    """Read .compose-stats.json + .inline-shortcut-retry-count for recovery
    events that fired but ultimately resolved."""
    issues: list[dict] = []

    # Inline-shortcut auto-retries
    retry_path = output_dir / ".inline-shortcut-retry-count"
    if retry_path.is_file():
        try:
            n = int(retry_path.read_text(encoding="utf-8").strip() or 0)
        except (OSError, ValueError):
            n = 0
        if n > 0:
            issues.append(
                {
                    "category": "auto_retry_fired",
                    "severity": "info",
                    "title": f"Stage 2 inline-shortcut auto-retry fired {n}× (ultimately succeeded)",
                    "evidence": {
                        "log_file": ".inline-shortcut-retry-count",
                        "log_line": 1,
                        "raw_event": f"counter={n}",
                        "iterations": n,
                        "outcome": "succeeded",
                    },
                }
            )

    # Compose section retries
    stats_path = output_dir / ".compose-stats.json"
    if stats_path.is_file():
        try:
            stats = json.loads(stats_path.read_text(encoding="utf-8"))
            if isinstance(stats, dict):
                section_retries = stats.get("section_retries") or {}
                for sid, n in section_retries.items():
                    if n and n > 1:
                        issues.append(
                            {
                                "category": "compose_retries_section",
                                "severity": "info",
                                "title": (f"§{sid} required {n}/3 compose attempts to converge (ultimately succeeded)"),
                                "evidence": {
                                    "log_file": ".compose-stats.json",
                                    "log_line": 1,
                                    "raw_event": f"section_retries[{sid}] = {n}",
                                    "section": sid,
                                    "attempts": n,
                                    "outcome": "succeeded",
                                },
                            }
                        )
        except (OSError, ValueError):
            pass

    return issues


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clip(s: str, n: int) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _fmt_dur(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60:02d}s"


def _now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Main aggregator
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1


def aggregate(output_dir: Path, depth: str, repo_root: Path | None = None) -> dict:
    """Build the .run-issues.json structure (without fix_recommendation —
    that is added by recommend_fixes.py in a separate pass).

    Sprint 4B: ``repo_root`` (optional) is used to scale phase budgets by
    repository size. When omitted, the function tries to infer it from
    ``$REPO_ROOT`` or ``output_dir.parent.parent`` (typical layout:
    ``<repo>/docs/security/.run-issues.json``). A scale factor of 1.0
    (no change) is used when inference fails.
    """
    agent_log_full = _read_log(output_dir / ".agent-run.log")
    hook_log_full = _read_log(output_dir / ".hook-events.log")
    # Scope to the current run only — these audit logs are append-only and
    # accumulate across runs. See ``_scope_to_current_run`` docstring for
    # the heuristic.
    agent_log = _scope_to_current_run(agent_log_full)
    hook_log = _scope_to_current_run(hook_log_full)
    phase_durs = _extract_phase_durations(agent_log)

    # Sprint 4B: scale per-phase budgets by repo size before passing them
    # downstream. The inference order is: (a) explicit repo_root arg,
    # (b) $REPO_ROOT env, (c) output_dir.parent.parent (typical layout).
    if repo_root is None:
        env_root = os.environ.get("REPO_ROOT")
        if env_root and Path(env_root).is_dir():
            repo_root = Path(env_root)
        elif output_dir.parent.parent.is_dir():
            repo_root = output_dir.parent.parent
    file_count = _count_repo_files(repo_root) if repo_root else 0

    issues: list[dict] = []
    issues.extend(_extract_errors(hook_log, agent_log))
    issues.extend(_extract_warnings(hook_log))
    issues.extend(_extract_perf_anomalies(phase_durs, depth, file_count=file_count))
    issues.extend(_extract_session_stop_anomalies(agent_log))
    issues.extend(_extract_recovery_events(output_dir))

    # Assign deterministic IDs (ordered by category then evidence line).
    issues.sort(key=lambda i: (i["category"], i["evidence"].get("log_line", 0)))
    for idx, issue in enumerate(issues, 1):
        issue["id"] = f"ISSUE-{idx:03d}"

    summary = {
        "errors": sum(1 for i in issues if i["severity"] == "error"),
        "warnings": sum(1 for i in issues if i["severity"] == "warning"),
        "perf_anomalies": sum(
            1
            for i in issues
            if i["category"].startswith("perf_anomaly") or i["category"] == "stage1_excessive_duration"
        ),
        "recovery_events": sum(1 for i in issues if i["category"] in ("auto_retry_fired", "compose_retries_section")),
        "auto_applicable_fixes": 0,  # filled in by recommend_fixes.py
    }
    run_status = "issues" if issues else "clean"

    return {
        "schema_version": SCHEMA_VERSION,
        "run_status": run_status,
        "assessment_depth": depth,
        "generated": _now_iso_z(),
        "summary": summary,
        "issues": issues,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aggregate_run_issues.py", description=__doc__.splitlines()[0])
    p.add_argument("output_dir", type=Path)
    p.add_argument("--depth", choices=["quick", "standard", "thorough"], default="standard")
    p.add_argument(
        "--no-recommend", action="store_true", help="Skip the recommend_fixes.py enrichment pass (testing only)."
    )
    args = p.parse_args(argv)

    if not args.output_dir.is_dir():
        print(f"error: output_dir not a directory: {args.output_dir}", file=sys.stderr)
        return 1

    data = aggregate(args.output_dir, args.depth)

    # Optionally enrich with fix recommendations. The recommender lives in
    # a separate module so this aggregator stays minimal and testable.
    if not args.no_recommend:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from recommend_fixes import enrich_with_recommendations  # type: ignore

            data = enrich_with_recommendations(data, args.output_dir)
        except (ImportError, AttributeError) as exc:
            print(f"warning: recommend_fixes not available — skipping enrichment ({exc})", file=sys.stderr)

    out_path = args.output_dir / ".run-issues.json"
    try:
        out_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write {out_path}: {exc}", file=sys.stderr)
        return 1

    n = len(data["issues"])
    s = data["summary"]
    auto = s.get("auto_applicable_fixes", 0)
    print(
        f"run-issues: {n} total · {s['errors']}E / {s['warnings']}W / "
        f"{s['perf_anomalies']}P / {s['recovery_events']}R · "
        f"{auto} auto-applicable fix(es)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
