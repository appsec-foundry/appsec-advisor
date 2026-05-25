#!/usr/bin/env python3
"""
record_stage_stats.py — append one Stage's stats to ``$OUTPUT_DIR/.stage-stats.jsonl``.

Called by the skill (SKILL-impl.md) after each Stage Agent dispatch returns.
The Agent tool's return notification carries a ``<usage>`` block with the
total tokens, tool-use count, and duration in milliseconds — the LLM driving
the skill extracts those values and passes them in via this helper. The
JSONL file is then read by ``compose_threat_model.py`` to render the
``### Per-Stage Breakdown`` table inside ``## Appendix: Run Statistics``.

Why a JSONL helper instead of yaml/JSON
---------------------------------------
JSONL appends are atomic and idempotent at the line level — a crash mid-write
truncates at most one line. Stage 1's call writes line 1; Stage 2 writes
line 2 (no read-modify-write cycle); etc. Compose reads one record per
line, drops malformed ones, sorts by ``stage`` field for stable rendering.

Dispatch wall-time derivation
-----------------------------
``duration_ms`` (from the Agent tool's ``<usage>`` block) is the API-billed
time for the **single** dispatch that returned successfully. When the skill
re-dispatches an agent — via the auto-retry loop in ``SKILL-impl.md`` after
``check_inline_shortcut.py`` trips, or via the ``STAGE11_CUTOFF`` recovery
path — earlier failed/aborted spawns are NOT reflected in ``duration_ms``.
This under-reports actual wall time by ~50% in observed multi-dispatch runs
(2026-05-23 juice-shop: Stage 2 reported 8m06s, actual wall 15m58s).

When ``--subagent-type`` and ``--since-iso`` are provided, the helper parses
``.hook-events.log`` and derives two additional fields:

  * ``dispatch_count`` — number of ``AGENT_SPAWN`` events for this subagent
    in the stage window. ``> 1`` means the skill re-dispatched the agent.
  * ``wall_secs_observed`` — seconds from the first ``AGENT_SPAWN`` to the
    last ``AGENT_INVOKE`` for this subagent. Covers all dispatches.

Both are omitted when the args are not passed or ``.hook-events.log`` is
absent (back-compat with pre-existing call sites).

Usage
-----

  python3 record_stage_stats.py <output_dir>      \\
      --stage 1                                    \\
      --name "Threat Analysis & Triage"            \\
      --agent appsec-advisor:appsec-threat-analyst \\
      --model claude-sonnet-4-6                    \\
      --duration-ms 1503583                        \\
      --tool-uses 113                              \\
      --tokens 93066                               \\
      [--subagent-type appsec-advisor:appsec-threat-analyst] \\
      [--since-iso 2026-05-23T17:32:13Z]

Exit codes
----------
  0  Record appended (or duplicate stage already present — no-op)
  2  Usage error / missing required argument
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

JSONL_FILENAME = ".stage-stats.jsonl"
HOOK_LOG_FILENAME = ".hook-events.log"

# Hook log lines come in two shapes:
#   AGENT_SPAWN / AGENT_INVOKE — subagent is the first positional token:
#     2026-05-23T18:28:15Z  [f13a4710]  INFO   AGENT_SPAWN  appsec-advisor:appsec-threat-renderer  model=sonnet  ...
#   SCAN_START / SCAN_COMPLETE — subagent is after `agent=`:
#     2026-05-25T06:55:22Z  [1b5162a8]  INFO   SCAN_COMPLETE  repo=…  agent=appsec-advisor:appsec-threat-analyst  model=sonnet
# Without SCAN_COMPLETE support the recorder saw only AGENT_SPAWN and
# computed wall_secs_observed = 0, defeating the multi-dispatch tracker.
# Use two regexes (one per shape) to avoid the alternation eating the
# wrong positional token (e.g. `repo=/path` being captured as subagent).
_HOOK_EVENT_AGENT_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+"
    r"\S+\s+"            # session-id bracketed token, e.g. [f13a4710]
    r"\S+\s+"            # level (INFO/WARN/ERROR)
    r"(?P<event>AGENT_SPAWN|AGENT_INVOKE)\s+"
    r"(?P<subagent>\S+)"
)
_HOOK_EVENT_SCAN_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"(?P<event>SCAN_START|SCAN_COMPLETE)\s+"
    r".*?\bagent=(?P<subagent>\S+)"
)


def _match_hook_event(line: str):
    """Match an AGENT_* OR SCAN_* hook event. Returns the match or None.

    Tries the AGENT_* shape first (positional subagent), falls back to the
    SCAN_* shape (subagent after `agent=`). Returning the whichever-matched
    object is fine — both define the same named groups (`ts`, `event`,
    `subagent`).
    """
    m = _HOOK_EVENT_AGENT_RE.match(line)
    if m:
        return m
    return _HOOK_EVENT_SCAN_RE.match(line)


# Back-compat alias for any external caller / test that references the
# pre-split symbol. New code should use `_match_hook_event(line)` instead.
_HOOK_EVENT_RE = _HOOK_EVENT_AGENT_RE


def _derive_dispatch_stats(
    log_path: Path,
    subagent_type: str,
    since_iso: str,
) -> dict | None:
    """Parse ``.hook-events.log`` and derive multi-dispatch wall stats.

    Returns ``{"dispatch_count": int, "wall_secs_observed": int}`` or
    ``None`` when the log is missing or no matching events were found.

    Events earlier than ``since_iso`` are skipped (string compare on the
    ISO timestamps is correct because the format is fixed-width and
    lexicographically sortable).

    ``wall_secs_observed`` is the seconds from the first ``AGENT_SPAWN``
    to the last ``AGENT_INVOKE`` for this subagent. When no
    ``AGENT_INVOKE`` is present (all dispatches aborted), the field is
    set to the spread between first and last ``AGENT_SPAWN`` — the
    caller can detect "no clean return" via ``dispatch_count > 0`` plus
    a missing successful-return signal elsewhere.
    """
    if not log_path.is_file():
        return None
    spawn_count = 0
    first_ts: str | None = None
    last_ts: str | None = None
    try:
        with log_path.open(encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                m = _match_hook_event(raw)
                if not m:
                    continue
                if m.group("subagent") != subagent_type:
                    continue
                ts = m.group("ts")
                if ts < since_iso:
                    continue
                event = m.group("event")
                if event == "AGENT_SPAWN":
                    spawn_count += 1
                    if first_ts is None:
                        first_ts = ts
                # Track the latest timestamp regardless of event. Preferred
                # "end" markers are AGENT_INVOKE (legacy) and SCAN_COMPLETE
                # (current hooks); SCAN_START is also tracked so a dispatch
                # that hasn't yet completed still produces a non-zero spread.
                last_ts = ts
    except OSError:
        return None
    if spawn_count == 0 or first_ts is None or last_ts is None:
        return None
    try:
        t0 = datetime.strptime(first_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        t1 = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    wall_secs = max(0, int((t1 - t0).total_seconds()))
    return {"dispatch_count": spawn_count, "wall_secs_observed": wall_secs}


def _existing_stage_keys(path: Path) -> set[tuple[int, str]]:
    """Return the set of (stage, variant) tuples already on disk so re-running
    the helper for the same key is a no-op (idempotent).

    Pre-2026-05 records have no ``variant`` field — they map to the empty
    string, matching the default for the new flag. New callers can pass
    ``--variant repair`` (or similar) to write a second record for the
    same stage, e.g. when a Re-Render-Loop REPAIR_MODE dispatch runs after
    the QA fast-path was already recorded.
    """
    out: set[tuple[int, str]] = set()
    if not path.is_file():
        return out
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            stage = rec.get("stage")
            variant = rec.get("variant") or ""
            if isinstance(stage, int):
                out.add((stage, variant))
    except OSError:
        return out
    return out


# Back-compat alias for any external caller of the old function name.
def _existing_stage_numbers(path: Path) -> set[int]:
    return {s for s, _ in _existing_stage_keys(path)}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=os.environ.get("OUTPUT_DIR"),
        help="Path to $OUTPUT_DIR (positional, or set $OUTPUT_DIR env)",
    )
    parser.add_argument("--stage", type=int, required=True, help="Stage number (1, 2, 3, ...)")
    parser.add_argument(
        "--variant",
        default="",
        help="Optional substage tag (e.g. 'repair'). When set, the "
        "uniqueness key for idempotency becomes (stage, variant) instead "
        "of just stage — letting a single stage emit multiple records "
        "(e.g. Stage 3 — QA fast-path + Stage 3 — Re-Render-Loop Repair).",
    )
    parser.add_argument("--name", required=True, help='Human-readable description, e.g. "Threat Analysis & Triage"')
    parser.add_argument("--agent", required=True, help="Agent identifier, e.g. appsec-advisor:appsec-threat-analyst")
    parser.add_argument("--model", default="—", help="Model id, e.g. claude-sonnet-4-6")
    parser.add_argument(
        "--duration-ms",
        type=int,
        required=True,
        help="Wall-clock duration in milliseconds (Agent tool's <usage> block)",
    )
    parser.add_argument("--tool-uses", type=int, required=True, help="Total tool calls (from <usage>)")
    parser.add_argument("--tokens", type=int, required=True, help="Total tokens (from <usage> total_tokens)")
    parser.add_argument(
        "--allow-duplicates",
        action="store_true",
        help="Append even when a record for this stage already exists. "
        "Default behaviour is idempotent: same --stage twice → no-op.",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Sprint 3C (M3.5): truncate the stats file on the FIRST stage of "
        "a rebuild run before appending. The skill passes this flag for "
        "Stage 1 in `--rebuild` mode so the second --rebuild in a row "
        "starts with a clean stats slate (the wipe in SKILL-impl handles "
        "the rest, but this is a safety net for environments where the "
        "wipe was skipped or partial).",
    )
    parser.add_argument(
        "--subagent-type",
        default=None,
        help="Subagent identifier (e.g. appsec-advisor:appsec-threat-renderer) "
        "used to filter .hook-events.log when deriving dispatch_count + "
        "wall_secs_observed. Requires --since-iso. Optional — when omitted "
        "the derived fields are not added (back-compat).",
    )
    parser.add_argument(
        "--since-iso",
        default=None,
        help="ISO8601 UTC timestamp (e.g. 2026-05-23T17:32:13Z) marking the "
        "stage start. Events earlier than this are ignored when deriving "
        "dispatch_count + wall_secs_observed. Requires --subagent-type.",
    )
    args = parser.parse_args(argv[1:])

    if not args.output_dir:
        parser.error("output_dir is required (positional or $OUTPUT_DIR env)")

    output_dir = Path(args.output_dir).resolve()
    if not output_dir.is_dir():
        sys.stderr.write(f"output_dir not a directory: {output_dir}\n")
        return 2
    jsonl = output_dir / JSONL_FILENAME

    # Sprint 3C: --rebuild + --stage 1 truncates first. Other --stage values
    # in --rebuild mode are no-op on the truncate (Stage 1 already cleared it).
    if args.rebuild and args.stage == 1 and jsonl.exists():
        try:
            jsonl.unlink()
        except OSError as exc:
            sys.stderr.write(f"warn: could not unlink stale {jsonl}: {exc}\n")

    variant_key = (args.stage, args.variant or "")
    if not args.allow_duplicates and variant_key in _existing_stage_keys(jsonl):
        # Idempotent — return 0 without writing. Surface a hint to stderr
        # so re-runs are observable but never noisy on stdout.
        variant_hint = f" variant={args.variant!r}" if args.variant else ""
        sys.stderr.write(
            f"stage {args.stage}{variant_hint} already recorded in {jsonl} — "
            f"skipping (use --allow-duplicates or --rebuild to override)\n"
        )
        return 0

    # Sanity gate: a record that claims a deterministic / no-LLM agent
    # cannot simultaneously carry non-zero tokens or tool_uses. This combo
    # was observed in production (juice-shop 2026-05-25 run, Stage 3) where
    # the skill recorded deterministic LABELS — `--agent deterministic:*
    # --model none` — but plumbed the REPAIR-MODE threat-analyst's
    # `<usage>` values for duration/tool_uses/tokens, producing a
    # 119k-token "deterministic" record that's impossible by construction.
    # Surface the inconsistency as a stderr warning + add a structured
    # `_inconsistency` field to the record so /appsec-advisor:status and
    # the completion summary can flag the suspect entry. Non-fatal —
    # writing a flagged record is preferable to losing data.
    deterministic_claim = (
        (args.model or "").strip().lower() in ("none", "—", "")
        or (args.agent or "").strip().startswith("deterministic:")
    )
    llm_evidence = (args.tokens or 0) > 0 or (args.tool_uses or 0) > 0
    inconsistency: str | None = None
    if deterministic_claim and llm_evidence:
        inconsistency = (
            f"agent='{args.agent}' / model='{args.model}' claims deterministic, "
            f"but tokens={args.tokens} / tool_uses={args.tool_uses} indicate an "
            f"LLM dispatch — record likely conflates two stages (e.g. QA fast-path "
            f"label + Re-Render-Loop REPAIR_MODE values)."
        )
        sys.stderr.write(f"warn: stage {args.stage}: {inconsistency}\n")

    record = {
        "stage": args.stage,
        "name": args.name,
        "agent": args.agent,
        "model": args.model,
        "duration_ms": args.duration_ms,
        "tool_uses": args.tool_uses,
        "tokens": args.tokens,
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if args.variant:
        record["variant"] = args.variant
    if inconsistency:
        record["_inconsistency"] = inconsistency

    # Optional dispatch-wall derivation. Both args must be present; either
    # alone is a user error worth surfacing because the pairing is the only
    # form that produces meaningful output.
    if bool(args.subagent_type) ^ bool(args.since_iso):
        sys.stderr.write(
            "warn: --subagent-type and --since-iso must be passed together; "
            "ignoring partial argument and skipping dispatch derivation\n"
        )
    elif args.subagent_type and args.since_iso:
        derived = _derive_dispatch_stats(
            output_dir / HOOK_LOG_FILENAME,
            args.subagent_type,
            args.since_iso,
        )
        if derived is not None:
            record.update(derived)
    try:
        with jsonl.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        sys.stderr.write(f"failed to append to {jsonl}: {exc}\n")
        return 2

    print(f"recorded stage {args.stage}: {args.duration_ms}ms · {args.tool_uses} tools · {args.tokens} tokens")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
