#!/usr/bin/env python3
"""
reserve_ids.py — atomic ID counter assignment for sidecar-emitting phases.

When a phase agent writes a sidecar that needs new IDs (M-NNN for
mitigations, A-NNN for assets, MF-NNN for meta-findings, HYP-NNN for
threat hypotheses), it MUST reserve them through this script rather
than picking numbers locally. Reserving via the central counter:

  * prevents collisions between phases that emit in parallel
    (config-scanner Phase 2.5 + recon-scanner Phase 2)
  * prevents collisions across runs (incremental baseline vs new run)
  * survives resume/cut-off — the counter persists in baseline.json
  * gives the Python aggregator a single invariant to check
    (sidecar-claimed IDs must be ≤ current counter)

State lives in $OUTPUT_DIR/.appsec-cache/baseline.json under
`id_counters`. Each counter is stored as an integer (the next-available
number); the script renders the prefixed form (T-001 / M-001 / A-001 /
MF-001 / HYP-001) for callers.

Atomicity uses fcntl.LOCK_EX on baseline.json itself. The lock is held
only across read-modify-write — typically under 1ms — so contention
is negligible even with the parallel phase dispatch.

CLI usage (shell-friendly, JSON output):

    python3 reserve_ids.py mitigation --count 3 --output-dir <DIR>
    → ["M-008", "M-009", "M-010"]

    python3 reserve_ids.py asset --count 1 --output-dir <DIR>
    → ["A-011"]

    python3 reserve_ids.py meta_finding --count 1 --output-dir <DIR>
    → ["MF-002"]

    python3 reserve_ids.py hyp --count 2 --output-dir <DIR>
    → ["HYP-004", "HYP-005"]

Exit codes:
  0 = reservation succeeded, JSON list on stdout
  1 = IO / lock / unexpected error
  2 = usage error
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# ID-type → (counter key, prefix, default-width). Adding a new ID class
# means adding one entry here AND adding a counter key to baseline_state.py.
_ID_TYPES = {
    "threat":       ("next_threat_id",       "T",   3),
    "mitigation":   ("next_mitigation_id",   "M",   3),
    "asset":        ("next_asset_id",        "A",   3),
    "meta_finding": ("next_meta_finding_id", "MF",  3),
    "hyp":          ("next_hyp_id",          "HYP", 3),
}

# Lock-acquisition timeout. Phases write sidecars in single-digit ms;
# 5 s is conservative. Failing fast surfaces deadlocks rather than
# silently hanging the whole skill.
_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_RETRY_INTERVAL = 0.05


def _baseline_path(output_dir: Path) -> Path:
    return output_dir / ".appsec-cache" / "baseline.json"


def _acquire_exclusive_lock(fd: int) -> None:
    """Block until exclusive lock acquired, or raise TimeoutError after deadline."""
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"could not acquire lock on baseline.json within "
                    f"{_LOCK_TIMEOUT_SECONDS}s — another process holds it"
                )
            time.sleep(_LOCK_RETRY_INTERVAL)


def _parse_counter(raw: Any, fallback: int = 1) -> int:
    """Accept int, prefixed-string ('M-007'), or None; return integer counter."""
    if raw is None:
        return fallback
    if isinstance(raw, int):
        return max(raw, fallback)
    if isinstance(raw, str):
        # Strip prefix if present (e.g., "M-008" → 8)
        cleaned = raw.split("-")[-1] if "-" in raw else raw
        try:
            return max(int(cleaned), fallback)
        except ValueError:
            return fallback
    return fallback


def reserve(
    output_dir: Path, id_type: str, count: int
) -> list[str]:
    """Atomically reserve `count` consecutive IDs of the given type.

    Returns the list of newly-reserved prefixed IDs (e.g. ["M-008","M-009"]).

    Behaviour on missing baseline.json: creates a minimal baseline file with
    just `id_counters` populated. The full baseline (recon_fingerprint,
    stride_files, etc.) is written later by baseline_state.py — these two
    writers must NOT clobber each other, which is why we always read-modify-
    write rather than overwrite.
    """
    if id_type not in _ID_TYPES:
        raise ValueError(f"unknown id_type: {id_type}")
    if count < 1:
        raise ValueError(f"count must be ≥ 1, got {count}")

    counter_key, prefix, width = _ID_TYPES[id_type]
    cache_dir = output_dir / ".appsec-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = _baseline_path(output_dir)

    # Open (or create) with O_RDWR; lock; read; mutate; write; close.
    # `open(..., "a+")` doesn't truncate and gives a writable fd; we seek
    # manually because the file pointer position after lock is undefined.
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        _acquire_exclusive_lock(fd)

        # Read current contents — empty file is valid (first-run).
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, 10 * 1024 * 1024).decode("utf-8") or "{}"
        try:
            state = json.loads(raw)
        except json.JSONDecodeError:
            # Corrupted baseline.json — refuse rather than silently wiping it.
            raise RuntimeError(
                f"baseline.json is malformed JSON; refusing to reserve IDs. "
                f"Inspect {path} or delete it to start fresh."
            )

        counters = state.setdefault("id_counters", {})
        current = _parse_counter(counters.get(counter_key), 1)
        reserved_nums = list(range(current, current + count))
        counters[counter_key] = current + count

        # Persist — write whole file, truncate any trailing bytes.
        new_payload = json.dumps(state, indent=2, sort_keys=True).encode("utf-8")
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, new_payload)
        os.ftruncate(fd, len(new_payload))
        os.fsync(fd)

        return [f"{prefix}-{n:0{width}d}" for n in reserved_nums]
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        os.close(fd)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument(
        "id_type",
        choices=sorted(_ID_TYPES.keys()),
        help="ID class to reserve (mitigation, asset, meta_finding, hyp, threat)",
    )
    ap.add_argument("--count", type=int, default=1, help="how many consecutive IDs (default 1)")
    ap.add_argument("--output-dir", type=Path, required=True, help="$OUTPUT_DIR (e.g. docs/security)")
    args = ap.parse_args()

    if not args.output_dir.is_dir():
        sys.stderr.write(f"FATAL: output_dir does not exist: {args.output_dir}\n")
        return 2

    try:
        reserved = reserve(args.output_dir, args.id_type, args.count)
    except TimeoutError as exc:
        sys.stderr.write(f"FATAL: {exc}\n")
        return 1
    except (ValueError, RuntimeError) as exc:
        sys.stderr.write(f"FATAL: {exc}\n")
        return 1

    print(json.dumps(reserved))
    return 0


if __name__ == "__main__":
    sys.exit(main())
