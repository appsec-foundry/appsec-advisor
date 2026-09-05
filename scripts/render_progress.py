#!/usr/bin/env python3
"""Render the raw headless event stream into a readable live progress view.

Reads canonical event-log lines on stdin (as produced by ``scripts/event_log.py``
and tailed from ``.hook-events.log`` / ``.agent-run.log``) and emits a compact,
*stateful* progress view: it tracks the current phase so every heartbeat tells
you which stage the run is in, how long it has been there, and how long the run
has been going — instead of the cryptic ``step=watchdog`` the raw log shows.

Used by ``run-headless.sh`` as the default (non-``--verbose``) progress monitor:

    tail -F .hook-events.log .agent-run.log | python3 render_progress.py >&2
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone

# Canonical lines are double-space separated (event_log.format_line). Splitting
# on 2+ spaces recovers the leading fixed columns; the trailing detail is
# rejoined so its own internal double-spaces survive.
_FIELD_SEP = re.compile(r" {2,}")
_EVENT_TOKEN = re.compile(r"^[A-Z][A-Z0-9_]+$")
_PHASE_RE = re.compile(r"\[Phase ([\d.]+)/(\d+)\]\s*[▶✓⟳✗]?\s*(.*)")
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

# Static roadmap, shown once at ASSESSMENT_START so the long quiet stretches have
# context. The live PHASE_START banners remain authoritative if the pipeline
# ever drifts from this list.
_ROADMAP = (
    "1 Context · 2 Recon · 2.5 Config/IaC · 3 Architecture · 4 Walkthroughs · "
    "5 Assets · 6 Attack-Surface · 7 Trust-Boundaries · 8 Controls · "
    "9 STRIDE · 10 Scan-Synthesis · 11 Finalization"
)


def parse_line(line: str):
    """Return (ts, component, event, detail) or None for unparseable lines."""
    parts = _FIELD_SEP.split(line.rstrip("\n"))
    if len(parts) < 4:
        return None
    ts = parts[0]
    rest = parts[3:]  # parts[1]=sid, parts[2]=level
    if _EVENT_TOKEN.match(rest[0]):  # 5-field: event sits in column 4
        comp, event, detail = "", rest[0], "  ".join(rest[1:])
    elif len(rest) >= 2:  # 6-field: column 4 is component, column 5 is event
        comp, event, detail = rest[0], rest[1], "  ".join(rest[2:])
    else:
        return None
    return ts, comp, event, detail


def _parse_ts(ts: str):
    try:
        return datetime.strptime(ts, _TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


_TIER_DISPLAY = {"screening": "light"}

_AGENT_PHASES = {
    "appsec-recon-scanner": "2/11 Reconnaissance",
    "appsec-architecture-analyst": "3/11 Architecture",
    "appsec-trust-boundary-analyst": "7/11 Trust Boundaries",
    "appsec-control-analyst": "8/11 Controls",
    "appsec-stride-analyzer-v2": "9/11 STRIDE",
    "appsec-threat-merger": "10/11 Scan Synthesis",
    "appsec-evidence-verifier": "10/11 Scan Synthesis",
    "appsec-triage-validator": "10/11 Scan Synthesis",
    "appsec-post-stride-synthesizer": "10/11 Scan Synthesis",
    "appsec-abuse-case-verifier": "10/11 Abuse Verification",
}


def _kv(detail: str, key: str) -> str:
    # `)` terminates a value too: the orchestrator's own echoes put pairs inside
    # parentheses (`… (model: sonnet, MAX_TURNS=8, depth=screening)`), and
    # without it the closing paren is captured as part of the value.
    m = re.search(rf"\b{re.escape(key)}=([^\s,\])]+)", detail)
    return m.group(1) if m else ""


def _strip_ids(detail: str, *keys: str) -> str:
    """Drop opaque correlation ids from a detail before it is displayed.

    ``agent_call_id=toolu_…`` and ``action_id=stage1c:<hash>`` identify nothing
    a reader can act on, but they cost ~35 columns each and push the part that
    does carry meaning (component, counts, stop reason) past the right edge of
    the terminal. They stay in the log for correlation; only the live view is
    trimmed. ``job_id`` is stripped only from the component-scoped step lines,
    where ``log_event.py`` prepends ``component=`` and ``attempt=`` alongside it
    and the id repeats both; on a warning line it is kept, being the only
    locator such a line has.
    """
    for key in keys:
        detail = re.sub(rf"\s*\b{re.escape(key)}=[^\s]+", "", detail)
    return detail.strip()


# Lifecycle failure reasons are contract tokens. They stay verbatim in the log,
# where aggregation and correlation read them; the live view is read by a person
# watching a run, and a token names the internal state rather than what happened
# to the agent on the line above it.
_REASON_PROSE = {
    "outer_session_terminal": "the run ended while it was still working",
    "join_deadline_expired": "did not return before the wave's join window closed",
    "superseded_without_return": "replaced by a newer dispatch of the same job",
    "agent_tool_error": "the Agent tool returned an error",
    "terminal_before_spawn": "its end arrived before its start (hook events out of order)",
    "post_before_spawn": "its result arrived before its start (hook events out of order)",
}


def _terminal_subject(detail: str) -> str:
    """Parenthesised suffix for an agent's terminal line: which call ended.

    The lifecycle detail of ``AGENT_DONE`` / ``AGENT_FAILED`` repeats the
    dispatch parameters (``agent_type``, ``model``, ``background``,
    ``action_id``, ``description``) that the spawn line two lines up already
    showed, and carries no outcome of its own. Only two things matter here:
    *which* of several parallel calls of the same agent ended — its component
    or job — and why it stopped. The reason carries an ``AGENT_FAILED``
    explanation (``agent_lifecycle.event_detail``), so it is read to the end of
    its field rather than to the next space, and never dropped.
    """
    subject = _kv(detail, "component_id") or _kv(detail, "job_id")
    m = re.search(r"\b(?:stop_)?reason=(.*?)(?=\s{2,}|$)", detail)
    reason = m.group(1).strip() if m else ""
    reason = _REASON_PROSE.get(reason, reason)
    parts = [p for p in (subject, f"reason: {reason}" if reason else "") if p]
    return f" ({', '.join(parts)})" if parts else ""


def _agent_tag(model: str, depth: str = "") -> str:
    """Parenthesised suffix for an agent line: model, plus the STRIDE tier.

    ``depth`` is empty for every agent that is not a STRIDE analyzer, so the
    tag stays exactly as it was for them. The serialized tier value is
    ``screening`` (manifest ``analysis_depth``, log ``ANALYSIS_DEPTH``); every
    view shows it as ``light``, the word the dispatch labels and the pre-flight
    use, so one tier never carries two names on screen.
    """
    parts = [p for p in (model, _TIER_DISPLAY.get(depth, depth)) if p]
    return f" ({', '.join(parts)})" if parts else ""


def _mins(start, now) -> str:
    if not start or not now:
        return "?"
    secs = int((now - start).total_seconds())
    return "<1m" if secs < 60 else f"{secs // 60}m"


def _clock(when) -> str:
    """Local wall-clock HH:MM:SS for the left column.

    Logs are UTC; ``.astimezone()`` (no arg) converts to the system-default
    timezone — CET/CEST here — so the displayed time matches the host clock and
    follows any TZ change automatically.
    """
    if not when:
        return " " * 8
    return when.astimezone().strftime("%H:%M:%S")


def main() -> int:
    cur_phase = ""  # e.g. "2/11 Reconnaissance"
    phase_start = None  # datetime the current phase began
    run_start = None  # datetime the assessment began (or first line)

    out = sys.stdout
    is_tty = out.isatty()
    cur_clock = " " * 8
    cur_when = None  # datetime of the line being processed
    status_shown = False  # a transient \r heartbeat line is on screen
    last_perm = None  # datetime of the last permanent (scrolling) line
    last_pct_shown = None  # last RUN_PROGRESS percentage given a permanent line
    spawned_calls: set[str] = set()
    terminal_calls: set[str] = set()
    stride_calls: set[str] = set()  # STRIDE analyzer calls dispatched so far
    stride_finished: set[str] = set()  # …of those, the ones that reached a terminal event
    seen_ts = ""  # timestamp of the duplicate-suppression bucket below
    seen_in_ts: set[tuple[str, str, str]] = set()
    _CLEAR = "\r\033[K"  # carriage-return + clear-to-end-of-line

    # Heartbeats are pure liveness — on a TTY they update one in-place status
    # line (no scroll); off a TTY (log/CI) they are throttled to this interval
    # so a continuous scan doesn't flood the file. The watchdog's file logging
    # (stall detection) is unaffected — this is display only.
    _HB_THROTTLE_S = 300

    def w(line: str = "") -> None:
        """Emit one permanent (scrolling) line with the local-time column."""
        nonlocal status_shown, last_perm
        if status_shown:  # retire the transient heartbeat line first
            out.write(_CLEAR)
            status_shown = False
        out.write("\n" if line == "" else f"{cur_clock}  {line}\n")
        out.flush()
        last_perm = cur_when

    def stride_tally() -> str:
        """``STRIDE 3/5 components done``, or empty before the first dispatch.

        Phase 9 runs the analyzers in parallel for ~20 minutes and interleaves
        their spawn and completion lines, so the count of finished components is
        the one number that says how far the phase has come. It is derived from
        the dispatch lifecycle this view already renders, which makes it
        independent of the watchdog's ``STRIDE_PROGRESS`` mirror — that one
        counts artifact *files* and stays silent whenever ``.appsec-checkpoint``
        does not read exactly ``phase=9``.
        """
        if not stride_calls:
            return ""
        return f"STRIDE {len(stride_finished)}/{len(stride_calls)} components done"

    def heartbeat(line: str) -> None:
        """Show liveness without flooding the console."""
        nonlocal status_shown
        if is_tty:
            out.write(f"{_CLEAR}{cur_clock}  {line}")  # in-place, no newline
            out.flush()
            status_shown = True
        elif last_perm is None or cur_when is None or (cur_when - last_perm).total_seconds() >= _HB_THROTTLE_S:
            w(line)  # off-TTY: occasional scrolling tick only

    for raw in sys.stdin:
        parsed = parse_line(raw)
        if not parsed:
            continue
        ts, comp, event, detail = parsed
        # `log_event.py` mirrors PHASE_START / PHASE_END into `.hook-events.log`
        # from the same `format_line` call that writes `.agent-run.log`, and
        # run-headless.sh tails both files — so a mirrored event arrives twice,
        # carrying the same timestamp. Render the first copy and drop the
        # second: two identical lines within one second produce two identical
        # banners and no additional information.
        #
        # The component is deliberately not part of the key. A mirror is
        # byte-identical only in its detail: the `.agent-run.log` copy carries
        # the writing component and a blank session, so keying on it let every
        # `agent_logger`-mirrored event through twice — the assessment summary
        # among them. Two distinct producers emitting one event with identical
        # detail in the same second would have to agree on the call id or
        # component the detail names, which is what makes the detail sufficient.
        dup_key = (event, detail)
        if ts != seen_ts:
            seen_ts, seen_in_ts = ts, {dup_key}
        elif dup_key in seen_in_ts:
            continue
        else:
            seen_in_ts.add(dup_key)
        when = _parse_ts(ts)
        cur_when = when
        cur_clock = _clock(when)
        if run_start is None:
            run_start = when

        if event == "ASSESSMENT_START":
            run_start = when or run_start
            mode = _kv(detail, "mode") or "?"
            reqs = _kv(detail, "CHECK_REQUIREMENTS") == "true"
            req_src = _kv(detail, "REQUIREMENTS_URL_OVERRIDE")
            w()
            w(f"══ Assessment started · mode={mode}{'  requirements=on' if reqs else ''} ══")
            if reqs and req_src:
                w(f"   requirements ← {req_src}")
            w(f"   Pipeline: {_ROADMAP}")

        elif event in ("PHASE_START", "PHASE_END"):
            m = _PHASE_RE.search(detail)
            if not m:
                continue
            num, total, label = m.group(1), m.group(2), m.group(3).strip()
            head, _, action = label.partition("—")
            head = head.strip().rstrip(".… ") or label
            total_el = _mins(run_start, when)
            if event == "PHASE_START":
                cur_phase = f"{num}/{total} {head}"
                phase_start = when
                w()
                w(f"▶ Phase {num}/{total} · {head}   [+{total_el} total]")
                if action.strip():
                    w(f"    {action.strip()}")
            else:
                tail = f" — {action.strip()}" if action.strip() else ""
                w(f"✓ Phase {num}/{total} · {head}{tail}")

        elif event == "AGENT_SPAWN":
            call_id = _kv(detail, "agent_call_id")
            if call_id and call_id in spawned_calls:
                continue
            if call_id:
                spawned_calls.add(call_id)
            # Current lifecycle lines name the agent in agent_type=. Retain the
            # positional fallback for logs produced before call-scoped lifecycle.
            agent = _kv(detail, "agent_type") or (detail.split()[0] if detail else "")
            if not agent:
                continue
            model = _kv(detail, "model")
            # The trailing [KEY=value …] block is stripped as noise below, so lift
            # the STRIDE tier out of it first: in the default (non-verbose) headless
            # view this line is the only per-component record the user gets, and a
            # screened component must not read like a full-depth one.
            depth = _kv(detail, "analysis_depth") or _kv(detail, "ANALYSIS_DEPTH")
            description = re.search(r"(?:^|\s{2})description=(.*)$", detail)
            task = description.group(1).strip() if description else detail
            if not description:
                task = re.sub(r"\s*\[REPO_ROOT=[^\]]*\]\s*$", "", task)
                task = re.sub(rf"^{re.escape(agent)}\s+model=\S+\s*", "", task).strip()
            agent_name = agent.split(":")[-1]
            inferred_phase = _AGENT_PHASES.get(agent_name)
            if inferred_phase and inferred_phase != cur_phase:
                cur_phase = inferred_phase
                phase_start = when
            if call_id and "stride-analyzer" in agent_name:
                stride_calls.add(call_id)
            w(f"    ↳ {agent_name}{_agent_tag(model, depth)}: {task}")

        elif event == "AGENT_INVOKE":
            # Legacy PostToolUse mislabeled a successful return as a new start.
            # Keep parsing compatibility but never render it as lifecycle.
            continue

        elif event in ("AGENT_DONE", "AGENT_FAILED"):
            call_id = _kv(detail, "agent_call_id")
            if call_id and call_id in terminal_calls:
                continue
            if call_id:
                terminal_calls.add(call_id)
            agent = _kv(detail, "agent_type") or comp
            agent_name = agent.split(":")[-1] if agent else "agent"
            mark = "✓" if event == "AGENT_DONE" else "⚠"
            state = "done" if event == "AGENT_DONE" else "failed"
            tail = _terminal_subject(detail)
            if call_id and call_id in stride_calls:
                stride_finished.add(call_id)
                tail += f"   [{stride_tally()}]"
            w(f"    {mark} {agent_name} {state}{tail}")

        elif event == "SCAN_END":
            # Publication milestone, not a lifecycle terminal: the producer has
            # written its artifacts, but the call is closed by the hook
            # lifecycle (AGENT_DONE / AGENT_FAILED) alone. Rendering this as
            # "done" showed two completions for one call — and, when the
            # lifecycle disagreed, a success and a failure for the same call.
            owner = comp or "scan"
            w(f"      · {owner} output ready — {detail}")

        elif event in ("STEP_START", "STEP_END"):
            mark = "·" if event == "STEP_START" else "✓"
            w(f"      {mark} {_strip_ids(detail, 'agent_call_id', 'action_id', 'job_id')}")

        elif event == "STRIDE_PROGRESS":
            files = _kv(detail, "stride_files")
            w(f"      · STRIDE {files} component(s) analysed")

        elif event == "HEARTBEAT":
            total_el = _mins(run_start, when)
            if cur_phase:
                phase_el = _mins(phase_start, when) if phase_start else "?"
                tally = stride_tally() if cur_phase.startswith("9/") else ""
                tally = f", {tally}" if tally else ""
                heartbeat(f"    · still in Phase {cur_phase} — {phase_el}{tally}   [+{total_el} total]")
            else:
                step = _kv(detail, "step") or "startup"
                heartbeat(f"    · starting up ({step}) — +{total_el}")

        elif event == "WATCHDOG_START":
            w("    ⤷ watchdog armed (idle / stall guard active)")
        elif event == "RUN_IDLE":
            w(f"    ⚠ idle stall detected — {detail}")
        elif event == "RUN_RESUMED":
            w(f"    ↻ resumed — {detail}")
        elif event == "RUN_PROGRESS":
            # The watchdog's `phase=` token is read from `.appsec-checkpoint`,
            # which is only written at phase *end* and therefore lags the live
            # PHASE_START banner by one phase. The banners are authoritative
            # here, so show the phase we tracked from them.
            if cur_phase:
                detail = re.sub(r"\bphase=\S+", f"phase={cur_phase.split('/')[0]}", detail)
            # The percentage is phase-granular: it sits flat for the whole of a
            # long phase (Phase 9 / STRIDE runs ~20m). Only a *changed* reading
            # earns a permanent line; the repeats carry no new progress and go
            # through the heartbeat channel instead. They can't be dropped —
            # the watchdog emits no HEARTBEAT of its own, so this line is the
            # run's only liveness signal during those flat stretches.
            m_pct = re.match(r"~(\d+)%", detail)
            pct = m_pct.group(1) if m_pct else None
            line = f"    ◷ progress · {detail}"
            if pct is None or pct != last_pct_shown:
                last_pct_shown = pct
                w(line)
            else:
                heartbeat(line)
        elif event in ("STRIDE_STALE", "STRIDE_CANARY_TIMEOUT", "STRIDE_COMPONENT_TIMEOUT"):
            w(f"    ⚠ {event.lower().replace('_', ' ')} — {detail}")
        elif event == "SUBSTEP2_IDLE":
            w(f"    ⛔ substep-2 idle — {detail}")
        elif event == "SESSION_BLOAT":
            w(f"    ⚠ session context bloat — {detail}")
        elif event == "SESSION_NONEMPTY":
            w(f"    ⚠ non-empty session at scan start — {detail}")
        elif event == "SESSION_ABORTED_MIDRUN":
            w(f"    ⛔ aborted mid-run — {detail}")
        elif event in ("BUDGET_WARN", "BUDGET_CRITICAL"):
            # Turn consumption is not something an operator can act on mid-run,
            # and it crosses 75% on healthy agents that go on to finish. Shown
            # as plain progress so ⚠ and ⛔ keep meaning "look at this now".
            # The event itself is unchanged in the log and in run issues, and
            # MAX_TURNS — an agent that actually died — still carries a glyph.
            w(f"   budget · {_strip_ids(detail, 'agent_call_id')}")
        elif event in (
            "MAX_TURNS",
            "AGENT_ERROR",
            "RENDER_FAILED",
            "TELEMETRY_MISMATCH",
            "HOOK_PAYLOAD_UNEXPECTED",
        ):
            w(f"    ⚠ {event.lower().replace('_', ' ')} — {_strip_ids(detail, 'agent_call_id', 'action_id')}")
        elif event == "PARALLEL_STRIDE_RESOLVED":
            w(f"   config · {detail}")
        elif event == "ROUTE_INVENTORY_PREPASS":
            w(f"   prep · {detail}")
        elif event == "ASSESSMENT_SUMMARY":
            w()
            w(f"✓ assessment complete — {detail}")
        elif event == "ASSESSMENT_MODELS":
            w(f"    models · {detail}")

    if status_shown:  # leave the cursor on a clean line at EOF
        out.write("\n")
        out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
