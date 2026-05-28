#!/usr/bin/env python3
"""
batch_checkpoint.py — combine checkpoint write + lock heartbeat into one Bash call.

Saves 1 tool-use round-trip per phase boundary by replacing the two-call pattern:

    python3 acquire_lock.py $LOCK --heartbeat --phase=11 --step=1
    echo 'CHECKPOINT phase=11 step=1 status=counts_computed' > $OUTPUT_DIR/.appsec-checkpoint

with a single call:

    python3 batch_checkpoint.py $OUTPUT_DIR --phase 11 --step 1 --status counts_computed

At standard depth (3 components, Phases 1–10b) this saves approximately 15 orchestrator
turns across all phase boundaries — enough headroom to avoid hitting the 250-turn ceiling
on large repos (>500 source files). See: docs/turn-budget-analysis.md §3.

Usage:
  python3 batch_checkpoint.py <output_dir> --phase <phase> --step <step> --status <status>
                              [--lock <lock_file>]

Arguments:
  output_dir   Path to the assessment output directory (e.g. docs/security)
  --phase      Phase label (e.g. 3, 8, 10b, 11)
  --step       Step label (e.g. 1, tier_detected, yaml_written)
  --status     Status string written into the checkpoint line
  --lock       Lock file path (default: <output_dir>/.appsec-lock)

Exit codes:
  0   Always. Both operations are best-effort and non-fatal — a missing lock
      file or unwritable checkpoint is logged to stderr but never aborts the run.
      This matches acquire_lock.py's defensive --heartbeat contract.
"""

import argparse
import datetime
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch checkpoint write + lock heartbeat")
    parser.add_argument("output_dir", help="Assessment output directory")
    parser.add_argument("--phase", required=True, help="Phase label")
    parser.add_argument("--step", required=True, help="Step label")
    parser.add_argument("--status", required=True, help="Status string")
    parser.add_argument("--lock", default=None, help="Lock file path (default: <output_dir>/.appsec-lock)")
    args = parser.parse_args()

    output_dir = args.output_dir
    lock_path = args.lock or os.path.join(output_dir, ".appsec-lock")
    checkpoint_path = os.path.join(output_dir, ".appsec-checkpoint")
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Step 1: Write checkpoint atomically via tmp-file + rename.
    checkpoint_line = f"phase={args.phase} step={args.step} status={args.status} timestamp={ts}\n"
    tmp_path = checkpoint_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(checkpoint_line)
        os.replace(tmp_path, checkpoint_path)
    except OSError as exc:
        print(f"batch_checkpoint: checkpoint write failed (non-fatal): {exc}", file=sys.stderr)

    # Step 2: Refresh lock heartbeat by delegating to acquire_lock.py.
    # Locate acquire_lock.py relative to this script.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    acquire_lock = os.path.join(script_dir, "acquire_lock.py")
    if os.path.isfile(acquire_lock):
        import subprocess
        result = subprocess.run(
            [sys.executable, acquire_lock, lock_path,
             "--heartbeat", f"--phase={args.phase}", f"--step={args.step}"],
            capture_output=True,
        )
        if result.returncode != 0:
            print(
                f"batch_checkpoint: heartbeat failed (non-fatal, rc={result.returncode}): "
                f"{result.stderr.decode(errors='replace').strip()}",
                file=sys.stderr,
            )
    else:
        print(
            f"batch_checkpoint: acquire_lock.py not found at {acquire_lock} — heartbeat skipped",
            file=sys.stderr,
        )

    # Always exit 0 (matches acquire_lock.py --heartbeat contract).
    sys.exit(0)


if __name__ == "__main__":
    main()
