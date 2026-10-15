#!/usr/bin/env python3
"""Report the live assessment that holds an output directory, if any.

Usage:
  python3 runtime/live_run_holder.py --output <OUTPUT_DIR> [--wait <seconds>]

Prints ``free`` and exits 0 when no live run holds ``<OUTPUT_DIR>/.appsec-lock``.
Otherwise prints ``live run_id=<id> started=<HH:MM> heartbeat_age=<N>s`` and
exits 3. With ``--wait``, polls once a second until the directory is free or
the seconds have passed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runtime import acquire_lock  # noqa: E402


def holder(output_dir: Path, now: float | None = None) -> str | None:
    """Describe the live run that holds ``output_dir``, or None when it is free."""
    lock = output_dir / ".appsec-lock"
    if not acquire_lock.lock_held_by_live_other_run(lock):
        return None
    now = time.time() if now is None else now
    _, heartbeat = acquire_lock._parse_lock(lock)
    try:
        started = json.loads((output_dir / ".assessment-state.json").read_text(encoding="utf-8")).get("started_at")
    except (OSError, ValueError, AttributeError):
        started = None
    started_text = time.strftime("%H:%M", time.localtime(started)) if isinstance(started, (int, float)) else "?"
    age = f"{int(now - heartbeat)}s" if heartbeat is not None else "?"
    return f"live run_id={acquire_lock.read_run_id(lock) or '?'} started={started_text} heartbeat_age={age}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--wait", type=int, default=0)
    args = parser.parse_args(argv)
    deadline = time.monotonic() + max(0, args.wait)
    while True:
        found = holder(args.output)
        if found is None or time.monotonic() >= deadline:
            break
        time.sleep(1)
    print(found or "free")
    return 0 if found is None else 3


if __name__ == "__main__":
    sys.exit(main())
