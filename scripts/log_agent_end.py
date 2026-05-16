#!/usr/bin/env python3
"""
log_agent_end.py — Append AGENT_END log entry with elapsed duration.

Replaces the compound Bash completion-log chain:
  END_EPOCH=$(date +%s) && ELAPSED=$((...)) && DURATION=... && echo ...
which starts with a variable assignment and cannot be matched by Claude Code's
Bash(date:*) or Bash(echo:*) allow-list entries.

Usage:
  python3 log_agent_end.py <output_dir> <agent_name> <model_id> <start_epoch>

Arguments:
  output_dir   Directory containing .agent-run.log
  agent_name   Short agent name (e.g. threat-analyst, stride-analyzer)
  model_id     Model identifier string
  start_epoch  Unix timestamp (integer) from the AGENT_START Bash call

Exit codes:
  0  — entry appended (or output_dir not writable — silently ignored)
  2  — wrong number of arguments
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def fmt_duration(seconds: int) -> str:
    return f"{seconds // 60} min {seconds % 60:02d} s"


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(f"usage: {argv[0]} <output_dir> <agent_name> <model_id> <start_epoch>", file=sys.stderr)
        return 2

    output_dir = Path(argv[1])
    agent_name = argv[2]
    model_id = argv[3]
    try:
        start_epoch = int(argv[4])
    except ValueError:
        start_epoch = 0

    end_epoch = int(time.time())
    elapsed = max(0, end_epoch - start_epoch)
    duration = fmt_duration(elapsed)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = (
        f"{ts}  [--------]  INFO   {agent_name}  AGENT_END   {agent_name} completed in {duration} (model: {model_id})\n"
    )
    log_path = output_dir / ".agent-run.log"
    try:
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass  # non-writable output dir is silently ignored
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
