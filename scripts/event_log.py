#!/usr/bin/env python3
"""event_log.py — the single source of truth for the appsec-advisor event-log
line format.

Every structured event the pipeline emits — whether from a hook
(``agent_logger.py``, ``security_steering.py``, ``acquire_lock.py``), a CLI
helper (``log_event.py``, ``log_agent_end.py``), or a guard/watchdog
(``skill_watchdog.py``, ``enforce_*.py``, ``runtime_cleanup.py``) — is
rendered through :func:`format_line` so the on-disk format never drifts.

Before this module each call site hand-rolled its own f-string, which had
produced at least four different event-column widths (``<12``, ``<18``,
``<22``, ``<24``), inconsistent component padding, and two different
"no-session" sentinels (eight spaces vs eight dashes). Parsers tolerated it
because they key on field *order* + ``key=value`` pairs, but the logs were
visually misaligned and impossible to diff cleanly.

Canonical line schema
---------------------

Two shapes share one schema. Fields are separated by **two spaces**; the
detail is free text (conventionally ``key=value`` pairs so downstream tools
can regex out ``dur=``, ``in=``, ``cost=$…`` etc.).

  6-field (component-bearing — written to ``.agent-run.log``)::

    <ts>  [<sid>]  <LEVEL>  <component>  <EVENT>  <detail>

  5-field (no component — raw hook tool-events, written to
  ``.hook-events.log``)::

    <ts>  [<sid>]  <LEVEL>  <EVENT>  <detail>

Field definitions
-----------------

  ts         ISO-8601 UTC, second resolution: ``%Y-%m-%dT%H:%M:%SZ``.
  sid        8-char session id left-justified; the literal ``--------``
             when no session applies (orchestrator / out-of-hook context).
  LEVEL      one of INFO / WARN / ERROR / DEBUG / TRACE, left-justified to 5.
  component  the emitting agent / script / subsystem, left-justified to 18.
             Present only in the 6-field shape.
  EVENT      UPPER_SNAKE_CASE event name, left-justified to 18.
  detail     free text (never truncated here; callers pre-clip).

The returned string **includes** its trailing newline so callers can write
it directly with ``fh.write(format_line(...))``.
"""

from __future__ import annotations

import time

# Field widths — the canonical column layout. Changing one of these changes
# the format for every emitter at once, which is the whole point.
SID_WIDTH = 8
LEVEL_WIDTH = 5
COMPONENT_WIDTH = 18
EVENT_WIDTH = 18

# Sentinel for the session-id field when no session id applies.
NO_SESSION = "-" * SID_WIDTH

# Recognised levels (informational — format_line does not reject others).
LEVELS = ("INFO", "WARN", "ERROR", "DEBUG", "TRACE")


def now_iso() -> str:
    """Return the canonical ISO-8601 UTC timestamp (second resolution)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sid_field(sid: str | None) -> str:
    """Render the bracketed session-id field's *inner* text.

    ``None`` or empty → the ``--------`` no-session sentinel. Any real id is
    clipped to 8 chars and left-justified so the column stays aligned.
    """
    if not sid:
        return NO_SESSION
    return str(sid)[:SID_WIDTH].ljust(SID_WIDTH)


def format_line(
    event: str,
    detail: str = "",
    *,
    level: str = "INFO",
    component: str | None = None,
    sid: str | None = None,
) -> str:
    """Render one canonical event-log line (newline-terminated).

    Pass ``component`` to get the 6-field shape (``.agent-run.log``); omit it
    for the 5-field hook tool-event shape (``.hook-events.log``).
    """
    ts = now_iso()
    sid_field = _sid_field(sid)
    lvl = f"{str(level).strip():<{LEVEL_WIDTH}}"
    ev = f"{str(event):<{EVENT_WIDTH}}"
    if component is None:
        return f"{ts}  [{sid_field}]  {lvl}  {ev}  {detail}\n"
    comp = f"{str(component):<{COMPONENT_WIDTH}}"
    return f"{ts}  [{sid_field}]  {lvl}  {comp}  {ev}  {detail}\n"
