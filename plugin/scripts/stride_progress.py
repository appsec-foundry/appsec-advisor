#!/usr/bin/env python3
"""
Print a one-line progress summary for STRIDE analyzers running in the background.

Reads `$OUTPUT_DIR/.progress/<component-id>.json` files written by each
`appsec-stride-analyzer` sub-agent and collapses them into a single line
showing current step/label per component plus an overall "K/N ready" counter.

Exits 0 when all `EXPECTED` `.stride-<component-id>.json` output files are
present (so the orchestrator's poll loop can terminate), exits 1 otherwise.

Usage:
    stride_progress.py <output_dir> <expected_count>

Designed to be called from the orchestrator's Phase 9 poll loop:

    while ! python3 stride_progress.py "$OUTPUT_DIR" "$N" >&2; do sleep 20; done
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


STALE_SECONDS = 180  # progress file is considered stale after 3 minutes


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _format_entry(data: dict, done: bool, stale: bool) -> str:
    name = data.get("component_name") or data.get("component_id") or "?"
    if done:
        return f"{name} ✓"
    step = data.get("step")
    total = data.get("total")
    label = data.get("label") or ""
    label = label.strip()
    if step and total:
        core = f"{name} [{step}/{total}"
        if label:
            core += f" {label}"
        core += "]"
    else:
        core = f"{name} [starting]"
    if stale:
        core += " ⧗"
    return core


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: stride_progress.py <output_dir> <expected_count>", file=sys.stderr)
        return 2

    output_dir = Path(argv[1])
    try:
        expected = int(argv[2])
    except ValueError:
        print(f"invalid expected count: {argv[2]}", file=sys.stderr)
        return 2

    progress_dir = output_dir / ".progress"
    ready_files = sorted(output_dir.glob(".stride-*.json"))
    ready_ids = {p.stem.removeprefix(".stride-") for p in ready_files}

    progress_files = sorted(progress_dir.glob("*.json")) if progress_dir.exists() else []
    now = time.time()

    entries: list[str] = []
    seen_ids: set[str] = set()
    for pf in progress_files:
        data = _load(pf)
        comp_id = data.get("component_id") or pf.stem
        seen_ids.add(comp_id)
        done = comp_id in ready_ids
        stale = False
        if not done:
            try:
                mtime = pf.stat().st_mtime
                stale = (now - mtime) > STALE_SECONDS
            except OSError:
                stale = True
        entries.append(_format_entry(data, done=done, stale=stale))

    # Components that already produced final output but never wrote progress.
    # Flag as potentially stale if the output file is older than STALE_SECONDS
    # (may indicate a crash after partial write).
    for cid in sorted(ready_ids - seen_ids):
        stride_file = output_dir / f".stride-{cid}.json"
        stale = False
        try:
            mtime = stride_file.stat().st_mtime
            stale = (now - mtime) > STALE_SECONDS
        except OSError:
            pass
        label = f"{cid} ✓"
        if stale:
            label += " ⧗ (no progress file — may be stale)"
        entries.append(label)

    ready = len(ready_ids)
    header = f"[stride] {ready}/{expected} ready"
    if entries:
        body = " · ".join(entries)
        print(f"{header}  —  {body}")
    else:
        print(f"{header}  —  (no progress reported yet)")

    return 0 if ready >= expected else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
