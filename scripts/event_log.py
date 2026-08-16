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

import re
import time
from dataclasses import dataclass

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
_EVENT_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PREFIX_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)  "
    r"\[(?P<sid>.{8})\]  (?P<level>.{5})  (?P<rest>.*)$"
)


@dataclass(frozen=True)
class ParsedEventLine:
    """Fields recovered from one canonical event-log line."""

    timestamp: str
    sid: str | None
    level: str
    component: str | None
    event: str
    detail: str


def parse_line(line: str) -> ParsedEventLine | None:
    """Parse either canonical line shape; reject prose that only names an event."""
    match = _PREFIX_RE.fullmatch(line.rstrip("\r\n"))
    if match is None:
        return None
    level = match.group("level").strip()
    if level not in LEVELS:
        return None
    rest = match.group("rest")
    candidates: list[tuple[str | None, str, str]] = []
    component_boundary = COMPONENT_WIDTH
    event_start = component_boundary + 2
    event_end = event_start + EVENT_WIDTH
    if (
        len(rest) >= event_end + 2
        and rest[component_boundary:event_start] == "  "
        and rest[event_end : event_end + 2] == "  "
    ):
        candidates.append(
            (rest[:component_boundary].strip() or None, rest[event_start:event_end].strip(), rest[event_end + 2 :])
        )
    if len(rest) >= EVENT_WIDTH + 2 and rest[EVENT_WIDTH : EVENT_WIDTH + 2] == "  ":
        candidates.insert(0, (None, rest[:EVENT_WIDTH].strip(), rest[EVENT_WIDTH + 2 :]))
    legacy_parts = re.split(r" {2,}", rest, maxsplit=2)
    if len(legacy_parts) == 2:
        candidates.append((None, legacy_parts[0].strip(), legacy_parts[1]))
    elif len(legacy_parts) == 3:
        candidates.append((legacy_parts[0].strip() or None, legacy_parts[1].strip(), legacy_parts[2]))
    # An event name longer than EVENT_WIDTH overflows its column — format_line
    # pads but never truncates — so neither fixed-width offset lands on it. Read
    # the leading field as the event when it looks like one, which also covers a
    # detail that itself contains a double space.
    head = re.split(r" {2,}", rest, maxsplit=1)
    if len(head) == 2:
        candidates.append((None, head[0].strip(), head[1]))
        tail = re.split(r" {2,}", head[1], maxsplit=1)
        if len(tail) == 2:
            candidates.append((head[0].strip() or None, tail[0].strip(), tail[1]))
    for component, event, detail in candidates:
        if _EVENT_RE.fullmatch(event):
            sid = match.group("sid").strip()
            return ParsedEventLine(
                timestamp=match.group("timestamp"),
                sid=None if sid == NO_SESSION else sid,
                level=level,
                component=component,
                event=event,
                detail=detail,
            )
    return None


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
