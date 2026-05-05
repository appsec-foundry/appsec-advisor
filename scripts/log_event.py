#!/usr/bin/env python3
"""
log_event.py — unified phase/step event emitter.

Writes a canonical log entry to ``$OUTPUT_DIR/.agent-run.log`` (same format
the orchestrator bash echoes used to produce), updates
``$OUTPUT_DIR/.appsec-progress.json`` with the latest structured phase/step
state, **and** mirrors a compact human-readable line to stderr so the user
sees live progress without needing ``--verbose``.

This replaces the two-line pattern:

    PE=$(cat .phase-epoch ...) && EL=$(( ... )) && ES=$(printf ...)
    echo "$(date ...) ... PHASE_START ... ..." >> "$OUTPUT_DIR/.agent-run.log"

…which starts with a variable assignment and cannot be matched by Claude
Code's Bash allow-list rules, nor surface progress to the user.

Usage
-----

  log_event.py <output_dir> phase-start "[Phase 3/11] ▶ Architecture Modeling…"
  log_event.py <output_dir> phase-end   "[Phase 3/11] ✓ 4 diagrams produced"
  log_event.py <output_dir> step-start  "[Phase 11] [4/7] Writing fragments…"
  log_event.py <output_dir> step-end    "[Phase 11] [4/7] ✓ 10 fragments written"
  log_event.py <output_dir> info        "CUSTOM_EVENT"  "arbitrary detail text"

The first three forms auto-compute an elapsed suffix from ``.phase-epoch``
and emit a one-line summary to stderr in a compact format:

  ↳ (+4m12s) Phase 11/11 · step 4/7 · Writing fragments…

Output contract
---------------

  stdout: nothing  (the caller does not need to capture anything)
  stderr: one compact human-readable line (always — this is the point of
          the helper; it is not gated on ``--verbose``)
  file  : one canonical log line appended to ``$OUTPUT_DIR/.agent-run.log``
          and one latest-state JSON object written to
          ``$OUTPUT_DIR/.appsec-progress.json``

Exit codes
----------

  0 — event written and mirrored
  2 — usage error (missing/invalid arguments)
"""
from __future__ import annotations

import os
import json
import re
import sys
import time
from pathlib import Path

_CANONICAL_EVENTS = {
    "phase-start":  "PHASE_START",
    "phase-end":    "PHASE_END",
    "step-start":   "STEP_START",
    "step-end":     "STEP_END",
    "info":         None,            # caller supplies the event name
}

_PHASE_RE = re.compile(r"\[Phase\s+(\d+)/(\d+)\]")
_PHASE_LOOSE_RE = re.compile(r"\[Phase\s+([0-9]+b?|[0-9]+(?:\.[0-9]+)?)(?:/(\d+))?\]")
_STEP_RE  = re.compile(r"(?:\[Phase\s+[0-9]+b?(?:/\d+)?\]\s*)?\[(\d+)/(\d+)\]")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _phase_epoch(output_dir: Path) -> int | None:
    try:
        return int((output_dir / ".phase-epoch").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _elapsed_str(output_dir: Path) -> str:
    pe = _phase_epoch(output_dir)
    if pe is None:
        return ""
    el = int(time.time()) - pe
    if el < 0:
        el = 0
    return f"+{el // 60}m{el % 60:02d}s"


def _mirror_line(kind: str, detail: str, elapsed: str) -> str:
    """Short human-readable terminal line."""
    # Extract phase and optional step numbers so the prefix stays terse.
    phase = _PHASE_RE.search(detail)
    step  = _STEP_RE.search(detail)
    parts: list[str] = []
    if elapsed:
        parts.append(f"({elapsed})")
    if phase:
        parts.append(f"Phase {phase.group(1)}/{phase.group(2)}")
    if step:
        parts.append(f"step {step.group(1)}/{step.group(2)}")
    # Clean up the detail: drop the duplicated [Phase .../...] / [k/N] prefixes
    # we already surfaced in `parts`, so the line reads well.
    clean = detail
    if phase:
        clean = _PHASE_RE.sub("", clean, count=1)
    if step:
        clean = _STEP_RE.sub("", clean, count=1)
    clean = clean.strip("[] ").strip()
    glyph = {
        "phase-start": "▶",
        "phase-end":   "✓",
        "step-start":  "↳",
        "step-end":    "✓",
        "info":        "·",
    }.get(kind, "·")
    head = " ".join(parts)
    if head and clean:
        return f"  {glyph} {head} · {clean}"
    if head:
        return f"  {glyph} {head}"
    return f"  {glyph} {clean}"


def _append_log(output_dir: Path, event: str, detail: str, agent: str) -> None:
    log_path = output_dir / ".agent-run.log"
    line = f"{_now_iso()}  [--------]  INFO   {agent}  {event:<12}  {detail}\n"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass                                # best-effort — never crash a log write


def _clean_detail(detail: str) -> str:
    clean = _PHASE_LOOSE_RE.sub("", detail, count=1)
    clean = _STEP_RE.sub("", clean, count=1)
    return clean.strip("[] ").strip()


def _progress_payload(kind: str, event: str, detail: str, agent: str) -> dict:
    phase = _PHASE_LOOSE_RE.search(detail)
    step = _STEP_RE.search(detail)
    payload = {
        "updated_at": _now_iso(),
        "event": event,
        "kind": kind,
        "agent": agent,
        "detail": detail,
        "label": _clean_detail(detail),
    }
    if phase:
        payload["phase"] = phase.group(1)
        if phase.group(2):
            payload["phase_total"] = phase.group(2)
    if step:
        payload["step"] = int(step.group(1))
        payload["step_total"] = int(step.group(2))
    if event == "PHASE_START":
        payload["status"] = "phase_started"
    elif event == "PHASE_END":
        payload["status"] = "phase_completed"
    elif event == "STEP_START":
        payload["status"] = "step_started"
    elif event == "STEP_END":
        payload["status"] = "step_completed"
    else:
        payload["status"] = "info"
    return payload


def _write_progress(output_dir: Path, payload: dict) -> None:
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / ".appsec-progress.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    except OSError:
        pass


def main(argv: list[str]) -> int:
    argv = list(argv)
    agent = os.environ.get("APPSEC_LOG_AGENT", "threat-analyst").strip() or "threat-analyst"
    if "--agent" in argv:
        i = argv.index("--agent")
        try:
            agent = argv[i + 1].strip() or agent
        except IndexError:
            print(f"{argv[0]}: --agent requires a value", file=sys.stderr)
            return 2
        del argv[i:i + 2]

    if len(argv) < 4:
        print(f"usage: {argv[0]} <output_dir> <kind> <detail> [<event>]",
              file=sys.stderr)
        return 2

    output_dir = Path(argv[1])
    kind = argv[2]
    if kind not in _CANONICAL_EVENTS:
        print(f"{argv[0]}: unknown kind {kind!r} "
              f"(expected one of {sorted(_CANONICAL_EVENTS)})", file=sys.stderr)
        return 2

    if kind == "info":
        # `info <event> <detail>` — positional arg order: output_dir info event detail
        if len(argv) < 5:
            print(f"{argv[0]}: `info` requires <event-name> <detail>", file=sys.stderr)
            return 2
        event  = argv[3]
        detail = argv[4]
    else:
        event  = _CANONICAL_EVENTS[kind]
        detail = argv[3]

    _append_log(output_dir, event, detail, agent)
    _write_progress(output_dir, _progress_payload(kind, event, detail, agent))
    elapsed = _elapsed_str(output_dir) if kind != "info" else ""
    try:
        sys.stderr.write(_mirror_line(kind, detail, elapsed) + "\n")
        sys.stderr.flush()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
