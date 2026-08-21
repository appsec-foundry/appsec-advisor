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

import json
import os
import re
import sys
import time
from pathlib import Path

import agent_lifecycle
from event_log import format_line
from jsonschema import ValidationError
from write_stride_progress import authoritative_call

_CANONICAL_EVENTS = {
    "phase-start": "PHASE_START",
    "phase-end": "PHASE_END",
    "step-start": "STEP_START",
    "step-end": "STEP_END",
    "info": None,  # caller supplies the event name
}

# Catalog events are underscore-separated (`AGENT_START`); kinds are
# hyphenated (`phase-start`). Requiring the underscore keeps a malformed kind
# such as `bogus-kind` a usage error instead of an invented event.
_EVENT_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+")

_PHASE_RE = re.compile(r"\[Phase\s+(\d+)/(\d+)\]")
_PHASE_LOOSE_RE = re.compile(r"\[Phase\s+([0-9]+b?|[0-9]+(?:\.[0-9]+)?)(?:/(\d+))?\]")
_STEP_RE = re.compile(r"(?:\[Phase\s+[0-9]+b?(?:/\d+)?\]\s*)?\[(\d+)/(\d+)\]")
_DEPTH_TOKEN_RE = re.compile(r"(?i)(?:analysis_)?depth\s*[:=]\s*[^\s,;)\]]+")
_COMPONENT_TOKEN_RE = re.compile(r"\bcomponent\s*[:=]\s*([a-z0-9][a-z0-9-]{0,99})\b")


def _is_dispatched_component(output_dir: Path, component_id: str) -> bool:
    """Whether a dispatched Agent call currently owns this component."""
    try:
        return any(call.get("component_id") == component_id for call in agent_lifecycle.running_calls(output_dir))
    except Exception:
        return False


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
    step = _STEP_RE.search(detail)
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
        "phase-end": "✓",
        "step-start": "↳",
        "step-end": "✓",
        "info": "·",
    }.get(kind, "·")
    head = " ".join(parts)
    if head and clean:
        return f"  {glyph} {head} · {clean}"
    if head:
        return f"  {glyph} {head}"
    return f"  {glyph} {clean}"


_PHASE_BOUNDARY_EVENTS = frozenset({"PHASE_START", "PHASE_END"})


def _append_log(output_dir: Path, event: str, detail: str, agent: str) -> None:
    log_path = output_dir / ".agent-run.log"
    line = format_line(event, detail, component=agent)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass  # best-effort — never crash a log write
    # Mirror phase boundaries to .hook-events.log so external tooling and
    # tests that read the hook log see phase progression without parsing
    # .agent-run.log.
    if event in _PHASE_BOUNDARY_EVENTS:
        hook_path = output_dir / ".hook-events.log"
        try:
            with open(hook_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass


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
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass


def main(argv: list[str]) -> int:
    argv = list(argv)
    agent = os.environ.get("APPSEC_LOG_AGENT", "threat-analyst").strip() or "threat-analyst"
    component_id = ""
    if "--agent" in argv:
        i = argv.index("--agent")
        try:
            agent = argv[i + 1].strip() or agent
        except IndexError:
            print(f"{argv[0]}: --agent requires a value", file=sys.stderr)
            return 2
        del argv[i : i + 2]
    if "--component-id" in argv:
        i = argv.index("--component-id")
        try:
            component_id = argv[i + 1].strip()
        except IndexError:
            print(f"{argv[0]}: --component-id requires a value", file=sys.stderr)
            return 2
        del argv[i : i + 2]

    if len(argv) < 4:
        print(f"usage: {argv[0]} <output_dir> <kind> <detail> [<event>]", file=sys.stderr)
        return 2

    # An unset `$OUTPUT_DIR` reaches us as an empty argument, and `Path("")` is
    # the current directory — the target repository root for an agent. Writing
    # `.appsec-progress.json` there changes the worktree fingerprint that
    # evidence bundles are bound to and aborts the run at the next dispatch
    # gate. An option name in this slot means the arguments shifted for the
    # same reason. Refuse both instead of logging to an arbitrary directory.
    if not argv[1].strip():
        print(f"{argv[0]}: <output_dir> is empty — is $OUTPUT_DIR exported?", file=sys.stderr)
        return 2
    if argv[1].startswith("-"):
        print(f"{argv[0]}: <output_dir> looks like an option: {argv[1]!r}", file=sys.stderr)
        return 2

    output_dir = Path(argv[1])
    kind = argv[2]
    if kind not in _CANONICAL_EVENTS:
        # The event catalog in agents/shared/logging-standard.md names events
        # (`AGENT_START`, `SCAN_END`, …) while this slot wants a *kind*, and the
        # only route to a catalog event is the literal `info`. Callers that know
        # the catalog put the event name here instead — 10 of 12 rejected calls
        # on the 2026-08-21 insecure-large-spring-app run. Rejecting them lost
        # the very lifecycle lines cost accounting is reconstructed from
        # (20 AGENT_START vs 15 AGENT_END for 24 dispatched agents), and the
        # non-zero exit went unnoticed behind the callers' `2>/dev/null`.
        # Accept both spellings instead; the strict form is unchanged.
        canonical = kind.strip().lower().replace("_", "-")
        normalized_event = kind.strip().upper().replace("-", "_")
        if canonical in _CANONICAL_EVENTS:
            kind = canonical
        elif _EVENT_NAME_RE.fullmatch(kind.strip()):
            argv.insert(2, "info")
            argv[3] = normalized_event
            kind = "info"
        else:
            print(f"{argv[0]}: unknown kind {kind!r} (expected one of {sorted(_CANONICAL_EVENTS)})", file=sys.stderr)
            return 2

    if kind == "info":
        # `info <event> <detail>` — positional arg order: output_dir info event detail
        if len(argv) < 5:
            print(f"{argv[0]}: `info` requires <event-name> <detail>", file=sys.stderr)
            return 2
        event = argv[3]
        detail = argv[4]
    else:
        event = _CANONICAL_EVENTS[kind]
        detail = argv[3]

    if agent == "stride-analyzer-v2" and not component_id:
        print(f"{argv[0]}: stride-analyzer-v2 logging requires --component-id", file=sys.stderr)
        return 2
    if not component_id:
        # A depth claim about a named component is validated whoever writes it.
        # Keying the check on the caller naming itself made it opt-out: a line
        # logged under the default agent kept whatever depth its author chose,
        # and a `light` component was recorded as `full`.
        named = _COMPONENT_TOKEN_RE.search(detail)
        if named and _DEPTH_TOKEN_RE.search(detail) and _is_dispatched_component(output_dir, named.group(1)):
            component_id = named.group(1)

    if component_id:
        try:
            call = authoritative_call(output_dir, component_id, Path(__file__).resolve().parent.parent)
        except (OSError, ValueError, json.JSONDecodeError, ValidationError) as exc:
            print(f"{argv[0]}: cannot validate STRIDE logging depth: {exc}", file=sys.stderr)
            return 2
        detail = _DEPTH_TOKEN_RE.sub("", detail)
        detail = re.sub(r"\s{2,}", " ", detail).strip(" ,;()")
        detail = (
            f"component={component_id} depth={call['analysis_depth']} action_id={call['action_id']} "
            f"job_id={call['job_id']} attempt={call['attempt']}" + (f"  {detail}" if detail else "")
        )

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
