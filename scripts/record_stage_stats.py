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

Usage
-----

  python3 record_stage_stats.py <output_dir>           \\
      --stage 1                                         \\
      --name "Threat Model Orchestrator (Phases 1-10b)" \\
      --agent appsec-advisor:appsec-threat-analyst      \\
      --model claude-sonnet-4-6                         \\
      --duration-ms 1503583                             \\
      --tool-uses 113                                   \\
      --tokens 93066

Exit codes
----------
  0  Record appended (or duplicate stage already present — no-op)
  2  Usage error / missing required argument
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

JSONL_FILENAME = ".stage-stats.jsonl"


def _existing_stage_numbers(path: Path) -> set[int]:
    """Return the set of stage numbers already on disk so re-running the
    helper for the same stage is a no-op (idempotent)."""
    out: set[int] = set()
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
            if isinstance(stage, int):
                out.add(stage)
    except OSError:
        return out
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=os.environ.get("OUTPUT_DIR"),
        help="Path to $OUTPUT_DIR (positional, or set $OUTPUT_DIR env)",
    )
    parser.add_argument("--stage", type=int, required=True,
                        help="Stage number (1, 2, 3, ...)")
    parser.add_argument("--name", required=True,
                        help='Human-readable description, e.g. "Threat Model Orchestrator (Phases 1-10b)"')
    parser.add_argument("--agent", required=True,
                        help="Agent identifier, e.g. appsec-advisor:appsec-threat-analyst")
    parser.add_argument("--model", default="—",
                        help="Model id, e.g. claude-sonnet-4-6")
    parser.add_argument("--duration-ms", type=int, required=True,
                        help="Wall-clock duration in milliseconds (Agent tool's <usage> block)")
    parser.add_argument("--tool-uses", type=int, required=True,
                        help="Total tool calls (from <usage>)")
    parser.add_argument("--tokens", type=int, required=True,
                        help="Total tokens (from <usage> total_tokens)")
    parser.add_argument("--allow-duplicates", action="store_true",
                        help="Append even when a record for this stage already exists. "
                             "Default behaviour is idempotent: same --stage twice → no-op.")
    args = parser.parse_args(argv[1:])

    if not args.output_dir:
        parser.error("output_dir is required (positional or $OUTPUT_DIR env)")

    output_dir = Path(args.output_dir).resolve()
    if not output_dir.is_dir():
        sys.stderr.write(f"output_dir not a directory: {output_dir}\n")
        return 2
    jsonl = output_dir / JSONL_FILENAME

    if not args.allow_duplicates and args.stage in _existing_stage_numbers(jsonl):
        # Idempotent — return 0 without writing. Surface a hint to stderr
        # so re-runs are observable but never noisy on stdout.
        sys.stderr.write(
            f"stage {args.stage} already recorded in {jsonl} — skipping (use --allow-duplicates to override)\n"
        )
        return 0

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
