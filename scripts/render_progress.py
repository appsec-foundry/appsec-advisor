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


def _kv(detail: str, key: str) -> str:
    m = re.search(rf"\b{re.escape(key)}=([^\s,\]]+)", detail)
    return m.group(1) if m else ""


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
    cur_phase = ""          # e.g. "2/11 Reconnaissance"
    phase_start = None      # datetime the current phase began
    run_start = None        # datetime the assessment began (or first line)

    out = sys.stdout
    is_tty = out.isatty()
    cur_clock = " " * 8
    cur_when = None        # datetime of the line being processed
    status_shown = False   # a transient \r heartbeat line is on screen
    last_perm = None       # datetime of the last permanent (scrolling) line
    _CLEAR = "\r\033[K"    # carriage-return + clear-to-end-of-line

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

    def heartbeat(line: str) -> None:
        """Show liveness without flooding the console."""
        nonlocal status_shown
        if is_tty:
            out.write(f"{_CLEAR}{cur_clock}  {line}")  # in-place, no newline
            out.flush()
            status_shown = True
        elif last_perm is None or cur_when is None or \
                (cur_when - last_perm).total_seconds() >= _HB_THROTTLE_S:
            w(line)  # off-TTY: occasional scrolling tick only

    for raw in sys.stdin:
        parsed = parse_line(raw)
        if not parsed:
            continue
        ts, comp, event, detail = parsed
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
            w(f"══ Assessment started · mode={mode}"
              f"{'  requirements=on' if reqs else ''} ══")
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
            # SPAWN: agent name leads the detail, model in a model= field.
            agent = detail.split()[0] if detail else "?"
            model = _kv(detail, "model")
            task = re.sub(r"\s*\[REPO_ROOT=[^\]]*\]\s*$", "", detail)
            task = re.sub(rf"^{re.escape(agent)}\s+model=\S+\s*", "", task).strip()
            tag = f" ({model})" if model else ""
            w(f"    ↳ {agent.split(':')[-1]}{tag}: {task}")

        elif event == "AGENT_INVOKE":
            # INVOKE: agent name is the component, model in a "(model: x)" suffix.
            m = re.search(r"\(model:\s*(\w+)\)", detail)
            model = m.group(1) if m else ""
            task = re.sub(r"\s*\(model:\s*\w+\)\s*$", "", detail).strip()
            tag = f" ({model})" if model else ""
            w(f"    ↳ {comp.split(':')[-1]}{tag}: {task}")

        elif event == "AGENT_DONE":
            w(f"    ✓ {comp.split(':')[-1]} done — {detail}")

        elif event in ("STEP_START", "STEP_END"):
            mark = "·" if event == "STEP_START" else "✓"
            w(f"      {mark} {detail}")

        elif event == "STRIDE_PROGRESS":
            files = _kv(detail, "stride_files")
            w(f"      · STRIDE {files} component(s) analysed")

        elif event == "HEARTBEAT":
            total_el = _mins(run_start, when)
            if cur_phase:
                phase_el = _mins(phase_start, when) if phase_start else "?"
                heartbeat(f"    · still in Phase {cur_phase} — {phase_el}"
                          f"   [+{total_el} total]")
            else:
                step = _kv(detail, "step") or "startup"
                heartbeat(f"    · starting up ({step}) — +{total_el}")

        elif event == "WATCHDOG_START":
            w("    ⤷ watchdog armed (idle / stall guard active)")
        elif event == "RUN_IDLE":
            w(f"    ⚠ idle stall detected — {detail}")
        elif event == "RUN_RESUMED":
            w(f"    ↻ resumed — {detail}")
        elif event == "PARALLEL_STRIDE_RESOLVED":
            w(f"   config · {detail}")
        elif event == "ROUTE_INVENTORY_PREPASS":
            w(f"   prep · {detail}")
        elif event == "ASSESSMENT_SUMMARY":
            w()
            w(f"✓ assessment complete — {detail}")

    if status_shown:  # leave the cursor on a clean line at EOF
        out.write("\n")
        out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
