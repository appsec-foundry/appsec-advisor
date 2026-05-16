#!/usr/bin/env python3
"""
phase_elapsed.py — Compute elapsed time since a phase epoch marker.

Replaces the compound variable-assignment chain:
  PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) &&
  EL=$(( $(date +%s) - PE )) &&
  ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60)))
which starts with a variable assignment and cannot be matched by Claude
Code's Bash allow-list rules.

Usage:
  python3 phase_elapsed.py <output_dir>

Output (stdout, one line):
  <elapsed_seconds> <formatted_elapsed>
  e.g.:  127 2m07s

The caller reads the two fields via shell substitution:
  read EL ES < <(python3 "$CLAUDE_PLUGIN_ROOT/scripts/phase_elapsed.py" "$OUTPUT_DIR")

Exit codes:
  0  — always (falls back to epoch 0 if the file is missing/unreadable)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <output_dir>", file=sys.stderr)
        return 2

    epoch_file = Path(argv[1]) / ".phase-epoch"
    try:
        pe = int(epoch_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        pe = int(time.time())

    elapsed = max(0, int(time.time()) - pe)
    fmt = f"{elapsed // 60}m{elapsed % 60:02d}s"
    print(f"{elapsed} {fmt}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
