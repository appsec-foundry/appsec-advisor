"""Pin the canonical event-log line format produced by scripts/event_log.py.

The format is the single source of truth shared by every emitter
(agent_logger, log_event, log_agent_end, security_steering, acquire_lock,
skill_watchdog, enforce_*, runtime_cleanup). These tests lock the field
order, separators, column widths, and the no-session sentinel so a future
edit to any one emitter cannot silently re-introduce format drift.
"""

import re

import event_log
from event_log import format_line

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SEP = "  "  # canonical two-space field separator


def _ts_and_rest(line):
    """Return (timestamp, everything-after-first-separator-without-newline)."""
    assert line.endswith("\n"), "line must be newline-terminated"
    ts, _, rest = line[:-1].partition(SEP)
    assert _TS_RE.match(ts), f"bad timestamp: {ts!r}"
    return ts, rest


def test_six_field_shape_with_component():
    line = format_line("PHASE_START", "[Phase 3/11] modeling", component="threat-analyst")
    _, rest = _ts_and_rest(line)
    expected = SEP.join(
        [
            "[--------]",  # no sid → canonical sentinel
            f"{'INFO':<{event_log.LEVEL_WIDTH}}",
            f"{'threat-analyst':<{event_log.COMPONENT_WIDTH}}",
            f"{'PHASE_START':<{event_log.EVENT_WIDTH}}",
            "[Phase 3/11] modeling",
        ]
    )
    assert rest == expected


def test_five_field_shape_without_component():
    line = format_line("COACH_INJECTED", "topics=a chars=10")
    _, rest = _ts_and_rest(line)
    expected = SEP.join(
        [
            "[--------]",
            f"{'INFO':<{event_log.LEVEL_WIDTH}}",
            f"{'COACH_INJECTED':<{event_log.EVENT_WIDTH}}",
            "topics=a chars=10",
        ]
    )
    assert rest == expected


def test_real_sid_is_clipped_and_justified():
    line = format_line("SESSION_STOP", "in=1", sid="abcdef0123456789")
    _, rest = _ts_and_rest(line)
    assert rest.startswith("[abcdef01]")  # clipped to 8


def test_empty_sid_uses_sentinel_not_spaces():
    # Both None and "" must collapse to the dash sentinel — the old code
    # used eight spaces in some emitters and eight dashes in others.
    assert _ts_and_rest(format_line("E", sid=""))[1].startswith("[--------]")
    assert _ts_and_rest(format_line("E", sid=None))[1].startswith("[--------]")


def test_level_is_normalised_and_padded():
    # Callers pass "INFO", "INFO " (already padded), "WARN", "ERROR", "TRACE".
    # All render to a 5-wide field; the trailing pad merges with the 2-space
    # separator, so we assert on the leading content instead.
    def level_field(lvl):
        return format_line("E", level=lvl).split("]" + SEP, 1)[1][: event_log.LEVEL_WIDTH]

    assert level_field("INFO ") == "INFO "
    assert level_field("WARN") == "WARN "
    assert level_field("ERROR") == "ERROR"
    assert level_field("TRACE") == "TRACE"


def test_long_event_name_is_not_truncated():
    # ljust only pads; a name longer than the column must survive intact so
    # parsers keying on the event name still match.
    long_event = "YAML_INVARIANT_DRIFT"  # 20 > EVENT_WIDTH (18)
    line = format_line(long_event, "msg", level="WARN", component="skill")
    assert long_event in line
