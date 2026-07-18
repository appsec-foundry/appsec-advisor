#!/usr/bin/env python3
"""
stall_notice.py — single-source reassurance banner for API-stream stalls.

When a dispatched ``Agent`` call is killed by Claude Code's stream watchdog
("no progress for Ns … stream watchdog did not recover") the harness hands
control back to the orchestrator with a failure. That message reads like a
plugin defect, but it is an **infrastructure hiccup** — a standard-tier model
API stream that stopped emitting tokens — and the pipeline recovers from it
automatically (each stage re-runs the affected step through its own bounded
recovery machinery, and intermediate artefacts on disk are reused).

This helper is the ONE place the user-facing "this is automatic recovery, not
a defect" copy lives, so every stall — Stage 1 recon, the STRIDE fan-out,
Stage 2 render, Stage 3 QA, Stage 4 architect, or a recon sub-agent — surfaces
the same calm message. The orchestrator calls it from its own Bash at the
post-dispatch error seam; a hook could detect the stall but hook stderr is not
surfaced in the interactive TUI (see SKILL-impl.md §"MAX_TURNS surfacing"), so
the banner MUST come from the orchestrator's own stderr.

Usage
-----

  stall_notice.py <output_dir> --stage "Stage 1 — Threat Analysis" \
      [--phase "Phase 1 (recon)"] [--attempt 1 --max 1]

Output contract
---------------

  stdout: nothing
  stderr: one prominent multi-line reassurance banner (always)
  file  : one canonical ``STALL_RECOVERY`` line appended to
          ``$OUTPUT_DIR/.agent-run.log`` (component=skill) for forensics

Exit codes
----------

  0 — banner emitted
  2 — usage error (missing output_dir)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from event_log import format_line


def _append_log(output_dir: Path, detail: str) -> None:
    """Best-effort canonical log line; never blocks the recovery on failure."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(output_dir / ".agent-run.log", "a", encoding="utf-8") as fh:
            fh.write(format_line("STALL_RECOVERY", detail, level="WARN", component="skill"))
    except Exception:
        pass


def _banner(stage: str, phase: str, attempt: str) -> str:
    where = stage if not phase else f"{stage} · {phase}"
    lines = [
        "",
        "══════════════════════════════════════════════════════════════",
        "  ↻ AUTOMATIC RETRY — this is not a plugin error",
        "══════════════════════════════════════════════════════════════",
        "",
        f"  Where:   {where}",
        "  Cause:   a model API stream stalled (no tokens for the watchdog",
        "           window). This is Claude Code infrastructure latency —",
        "           caught by the stream watchdog, NOT triggered by the",
        "           plugin, your repository, or your configuration.",
        "",
        "  Action:  the affected step is being re-run automatically. Work",
        "           already written to disk is reused, so the retry does not",
        "           start from zero. No action is needed from you.",
    ]
    if attempt:
        lines.append("")
        lines.append(f"  Retry:   {attempt}")
        lines.append("           If stalls keep recurring the run stops cleanly")
        lines.append("           instead of burning tokens — re-running later")
        lines.append("           usually clears transient API congestion.")
    lines.append("══════════════════════════════════════════════════════════════")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Emit the shared stall-recovery banner.")
    ap.add_argument("output_dir", help="Run output directory (holds .agent-run.log)")
    ap.add_argument("--stage", default="the current stage", help="Human stage label, e.g. 'Stage 1 — Threat Analysis'")
    ap.add_argument("--phase", default="", help="Optional finer locator, e.g. 'Phase 1 (recon)'")
    ap.add_argument("--attempt", default="", help="Attempt counter, e.g. '1'")
    ap.add_argument("--max", default="", help="Attempt cap, e.g. '1'")
    args = ap.parse_args()

    if not args.output_dir:
        sys.stderr.write("stall_notice.py: output_dir is required\n")
        return 2

    attempt = ""
    if args.attempt and args.max:
        attempt = f"attempt {args.attempt}/{args.max}"
    elif args.attempt:
        attempt = f"attempt {args.attempt}"

    sys.stderr.write(_banner(args.stage, args.phase, attempt))
    sys.stderr.flush()

    detail = f"stage={args.stage}"
    if args.phase:
        detail += f" phase={args.phase}"
    if attempt:
        detail += f" {attempt}"
    detail += " — API stream stall caught by watchdog; auto-retry (not a plugin fault)"
    _append_log(Path(args.output_dir), detail)
    return 0


if __name__ == "__main__":
    sys.exit(main())
