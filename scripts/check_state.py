#!/usr/bin/env python3
"""
check_state.py — assessment run-state introspection & cleanup.

Classifies the transient run-state files under `$OUTPUT_DIR` (``.appsec-lock``,
``.appsec-checkpoint``, ``.phase-epoch``, ``.session-agent-map``) into one of
four states and — with ``--clean`` — removes stale / orphan artifacts so the
next run starts from a clean slate.

Why this exists
---------------

A Claude Code session that crashes mid-assessment leaves:

  * ``.appsec-lock`` — PID of the (now dead) orchestrator
  * ``.appsec-checkpoint`` — ``phase=<N> status=started`` (no ``completed``
    pair)
  * ``.phase-epoch`` — Unix-timestamp of the last phase boundary
  * ``.session-agent-map`` — transient hook-session tracking

The Claude Code UI and ``/appsec-advisor:status`` read these files and, when
they are present, report the skill as "scanning / in progress". Without
automatic recovery the user sees a perpetual "scanning" indicator and
every subsequent ``--incremental`` run bails out on ``LOCK_BLOCKED`` for up
to an hour (the ``acquire_lock.py`` stale-mtime window).

This script closes the gap by:

  1. Probing the lock PID (``kill -0``) to tell a truly-running process
     from a crash-orphan in O(1).
  2. Reading the checkpoint to correlate lock presence with declared
     run-phase.
  3. Optionally removing orphan files so the next run can proceed without
     manual cleanup.

States
------

  * ``clean``    — no state files present (no run in progress, no residue).
  * ``active``   — lock PID is alive; a real run is in progress. Never
                   auto-cleaned. ``--clean`` still refuses.
  * ``stale``    — lock PID is dead OR lock mtime older than
                   ``STALE_SECONDS`` (1 hour, matching ``acquire_lock.py``).
                   Auto-cleanup removes ``.appsec-lock`` +
                   ``.appsec-checkpoint`` + ``.phase-epoch`` +
                   ``.session-agent-map``.
  * ``orphaned`` — no lock but checkpoint still says ``status=started``
                   (crash after lock release, before checkpoint completion).
                   Auto-cleanup removes checkpoint + epoch + session map.

Usage
-----

  python3 check_state.py <output_dir>
      → prints the human-readable report, exits 0 on clean/active, 1 on
        stale/orphaned (for shell conditionals).

  python3 check_state.py <output_dir> --json
      → machine-readable JSON on stdout; exit code unchanged.

  python3 check_state.py <output_dir> --clean
      → removes stale / orphan files if it is safe to do so; leaves active
        runs untouched. Exits 0 on success, 2 when an active run blocks
        the cleanup.

Exit codes
----------

  0 — clean OR active OR (stale/orphaned AND --clean succeeded)
  1 — stale OR orphaned (report only; no --clean)
  2 — --clean requested but skipped because state is active
  3 — usage error / unreadable output dir
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

STALE_SECONDS = 3600              # 1h mtime fallback — same as acquire_lock.py
HEARTBEAT_STALE_SECONDS = 300     # 5m — same as acquire_lock.HEARTBEAT_STALE_SECONDS

LOCK_FILE       = ".appsec-lock"
CHECKPOINT_FILE = ".appsec-checkpoint"
PHASE_EPOCH     = ".phase-epoch"
SESSION_MAP     = ".session-agent-map"

# Files removed by a successful `--clean` run. Covers every transient state
# file a crashed prior run can leave behind. Never touches threat-model.md/
# yaml, .fragments/, .appsec-cache/, or the audit log files (.agent-run.log,
# .hook-events.log) — those are either deliverables, baseline state, or audit
# trail respectively. Drift between this list and runtime_cleanup.py is
# checked by tests/test_runtime_cleanup.py.
_CLEANUP_TARGETS: tuple[str, ...] = (
    # Core state — pre-2026-04 set, always cleaned.
    LOCK_FILE,
    CHECKPOINT_FILE,
    PHASE_EPOCH,
    SESSION_MAP,
    # Stage-1 resume bookkeeping (turn-budget cutoff counter).
    ".stage1-resume-count",
    # Pre-render gate output. Run 2 (2026-04-25) left these behind when
    # Phase 11 died mid-repair-cycle; without cleanup the next run reads
    # a stale "fail" status and gets confused.
    ".pre-render-repair-plan.json",
    ".pre-render-report.json",
    # Stage 3 (QA) status + repair plan. Successful runs clean these via
    # runtime_cleanup.py post-QA; crashes leave them stale.
    ".qa-status.json",
    ".qa-repair-plan.json",
    # Stage 4 (architect) status + repair plan.
    ".architect-status.json",
    ".architect-repair-plan.json",
    # Hook-side completion marker.
    ".assessment-summary-emitted",
    # Phase 1 prior-findings cache (regenerated on every fresh start).
    ".prior-findings-index.json",
    # Skill-config snapshot from a prior run.
    ".skill-config.json",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    """Return True when the OS considers the PID alive.

    Uses ``os.kill(pid, 0)`` which does not send any signal but raises
    ``ProcessLookupError`` when the PID no longer maps to a process and
    ``PermissionError`` when the PID belongs to another user (still alive).
    Both error subclasses are handled explicitly so the caller never has to
    care about platform quirks.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # PID exists but we cannot signal it — still a running process, so
        # treat the lock as active rather than stale.
        return True
    except OSError:
        # Any other OSError: err on the side of "not alive" so cleanup can
        # proceed; a truly-live process would have passed the two checks above.
        return False
    return True


def _read_lock(output_dir: Path) -> dict | None:
    """Return a dict describing the lock file, or None if absent.

    Keys:
      * ``pid``           — parsed integer PID (None when malformed)
      * ``alive``         — boolean from ``_pid_alive``; None when PID is None
      * ``age``           — seconds since last mtime (float; None when stat fails)
      * ``heartbeat``     — parsed heartbeat timestamp (int; None for v1 locks)
      * ``heartbeat_age`` — seconds since heartbeat (float; None when absent)
      * ``path``          — absolute path (str) for error messages

    Lock format v2 (written by `acquire_lock.py`):
        <pid>\\n
        <heartbeat_unix_ts>\\n
    v1 (legacy, PID-only) is still accepted — heartbeat fields remain None
    and callers fall back to the mtime-based staleness heuristic.
    """
    lock = output_dir / LOCK_FILE
    if not lock.exists():
        return None
    pid: int | None = None
    heartbeat: int | None = None
    try:
        raw = lock.read_text(encoding="utf-8", errors="replace")
        lines = [l for l in raw.splitlines() if l.strip()]
        if lines:
            try:
                pid = int(lines[0].split()[0])
            except (ValueError, IndexError):
                pid = None
        if len(lines) >= 2:
            try:
                heartbeat = int(lines[1].split()[0])
            except (ValueError, IndexError):
                heartbeat = None
    except OSError:
        pid = None
    alive: bool | None = _pid_alive(pid) if pid is not None else None
    age: float | None = None
    try:
        age = time.time() - lock.stat().st_mtime
    except OSError:
        age = None
    hb_age: float | None = None
    if heartbeat is not None:
        hb_age = time.time() - heartbeat
    return {
        "pid": pid,
        "alive": alive,
        "age": age,
        "heartbeat": heartbeat,
        "heartbeat_age": hb_age,
        "path": str(lock),
    }


def _read_checkpoint(output_dir: Path) -> dict | None:
    """Parse ``.appsec-checkpoint`` of the form::

        phase=<N> status=<started|completed> timestamp=<ISO>

    Returns None when the file is absent. Returns a dict with whatever keys
    were parseable when the file exists; malformed files produce an empty
    dict (not None) so callers can distinguish "absent" from "corrupt".
    """
    ckpt = output_dir / CHECKPOINT_FILE
    if not ckpt.exists():
        return None
    out: dict = {"path": str(ckpt)}
    try:
        raw = ckpt.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return out
    for token in raw.split():
        if "=" not in token:
            continue
        k, v = token.split("=", 1)
        out[k] = v
    return out


def _file_mtime_age(output_dir: Path, name: str) -> float | None:
    p = output_dir / name
    try:
        return time.time() - p.stat().st_mtime
    except (OSError, FileNotFoundError):
        return None


# ---------------------------------------------------------------------------
# State classification
# ---------------------------------------------------------------------------


def classify(output_dir: Path) -> dict:
    """Inspect ``output_dir`` and return a state description dict.

    Returned shape (always present):
      * ``state``        — one of ``clean | active | stale | orphaned | needs_stage2``
      * ``reasons``      — list[str], one per input signal
      * ``lock``         — dict or None (see ``_read_lock``)
      * ``checkpoint``   — dict or None (see ``_read_checkpoint``)
      * ``files``        — list[str] of the transient files present on disk
      * ``needs_stage2`` — bool; True when Stage 1 completed but Stage 2 never ran
    """
    lock = _read_lock(output_dir)
    checkpoint = _read_checkpoint(output_dir)
    files_present = [
        name for name in _CLEANUP_TARGETS
        if (output_dir / name).exists()
    ]

    reasons: list[str] = []

    # G-1: Detect Stage-1-complete / Stage-2-never-dispatched state.
    # checkpoint=phase=10b status=completed need_render=true + threat-model.md absent
    # → a special "needs_stage2" state so callers can surface a targeted hint
    #   instead of silently wiping Phase-1–10b work on the next --rebuild.
    needs_stage2 = False
    if checkpoint is not None:
        cp_phase  = checkpoint.get("phase", "")
        cp_status = checkpoint.get("status", "")
        cp_render = checkpoint.get("need_render", "")
        if (cp_phase == "10b" and cp_status == "completed"
                and cp_render == "true"
                and not (output_dir / "threat-model.md").exists()):
            needs_stage2 = True

    if lock is None and checkpoint is None and not files_present:
        return {
            "state":       "clean",
            "reasons":     ["no transient state files present"],
            "lock":        None,
            "checkpoint":  None,
            "files":       [],
            "needs_stage2": False,
        }

    # Heartbeat freshness is authoritative when present: the stored PID is an
    # ephemeral Python-subprocess PID that is usually dead by the time the
    # next turn reads the lock (see acquire_lock.py::_do_heartbeat docstring).
    # A fresh heartbeat means the orchestrator is actively progressing —
    # regardless of whether the stored PID is still alive.
    hb_age = lock.get("heartbeat_age") if lock else None
    has_hb = hb_age is not None
    hb_fresh = has_hb and hb_age <= HEARTBEAT_STALE_SECONDS
    is_hung = has_hb and not hb_fresh          # stale heartbeat = hung or dead
    # Active = fresh heartbeat (v2 lock) OR alive PID with legacy v1 lock.
    is_active = bool(lock) and (
        hb_fresh or (not has_hb and lock.get("alive") is True)
    )
    if is_active:
        liveness = "heartbeat fresh" if hb_fresh else "live PID (legacy v1 lock)"
        reasons.append(
            f"lock active — {liveness} (pid {lock.get('pid')}, "
            f"mtime age {int(lock.get('age') or 0)}s)"
        )
        if hb_age is not None:
            reasons.append(f"heartbeat age: {int(hb_age)}s")
        if checkpoint:
            phase = checkpoint.get("phase", "?")
            status = checkpoint.get("status", "?")
            reasons.append(f"checkpoint: phase={phase} status={status}")
        return {
            "state":       "active",
            "reasons":     reasons,
            "lock":        lock,
            "checkpoint":  checkpoint,
            "files":       files_present,
            "needs_stage2": needs_stage2,
        }

    # Stale — lock exists but PID is dead, heartbeat is stale, or mtime is old.
    if lock is not None:
        pid = lock.get("pid")
        age = lock.get("age")
        if is_hung:
            reasons.append(
                f"lock PID {pid} is alive but heartbeat is "
                f"{int(hb_age or 0)}s old (> {HEARTBEAT_STALE_SECONDS}s threshold — "
                f"orchestrator appears hung)"
            )
        if lock.get("alive") is False:
            reasons.append(f"lock PID {pid} is not running (process dead)")
        elif lock.get("alive") is None:
            reasons.append("lock file is malformed — no parseable PID")
        if age is not None and age > STALE_SECONDS:
            reasons.append(
                f"lock mtime is {int(age)}s old (> {STALE_SECONDS}s threshold)"
            )
        if checkpoint:
            phase = checkpoint.get("phase", "?")
            status = checkpoint.get("status", "?")
            reasons.append(f"checkpoint: phase={phase} status={status}")
        return {
            "state":       "stale",
            "reasons":     reasons,
            "lock":        lock,
            "checkpoint":  checkpoint,
            "files":       files_present,
            "needs_stage2": needs_stage2,
        }

    # Orphaned — no lock but checkpoint shows an incomplete or aborted run.
    if checkpoint is not None and checkpoint.get("status") in ("started", "aborted"):
        status = checkpoint.get("status", "?")
        if status == "aborted":
            reason = checkpoint.get("reason", "unknown")
            reasons.append(
                f"no lock, but checkpoint says "
                f"phase={checkpoint.get('phase', '?')} status=aborted reason={reason} "
                f"(Stop hook marked run as aborted)"
            )
        else:
            reasons.append(
                f"no lock, but checkpoint says "
                f"phase={checkpoint.get('phase', '?')} status=started "
                f"(crash between lock release and checkpoint completion)"
            )
        return {
            "state":       "orphaned",
            "reasons":     reasons,
            "lock":        None,
            "checkpoint":  checkpoint,
            "files":       files_present,
            "needs_stage2": needs_stage2,
        }

    # Residue only — leftover .phase-epoch / .session-agent-map with no
    # lock and no incomplete checkpoint. Treat as orphaned too so --clean
    # removes them.
    if files_present:
        reasons.append(
            f"leftover transient files without lock or checkpoint: "
            f"{', '.join(files_present)}"
        )
        return {
            "state":       "orphaned",
            "reasons":     reasons,
            "lock":        None,
            "checkpoint":  checkpoint,
            "files":       files_present,
            "needs_stage2": needs_stage2,
        }

    # Fallback: nothing unusual.
    return {
        "state":       "clean",
        "reasons":     ["no transient state files present"],
        "lock":        lock,
        "checkpoint":  checkpoint,
        "files":       files_present,
        "needs_stage2": needs_stage2,
    }


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


def clean(output_dir: Path, report: dict | None = None) -> dict:
    """Remove stale / orphan transient files.

    Safety gate: when ``report["state"] == "active"`` (or the classifier
    says so), refuses to clean and returns a dict with ``skipped: True``.
    Always leaves ``threat-model.*``, ``.appsec-cache/``, ``.fragments/``,
    ``.agent-run.log`` and ``.hook-events.log`` untouched.
    """
    report = report if report is not None else classify(output_dir)
    if report["state"] == "active":
        return {
            "skipped":  True,
            "reason":   "an active run holds the lock; refusing to clean",
            "removed":  [],
            "state":    report["state"],
        }

    removed: list[str] = []
    for name in _CLEANUP_TARGETS:
        target = output_dir / name
        if target.exists():
            try:
                target.unlink()
                removed.append(name)
            except OSError:
                # Best-effort: one file failing to delete should not block
                # the others. The caller can re-run the command if needed.
                pass
    return {
        "skipped":  False,
        "reason":   None,
        "removed":  removed,
        "state":    report["state"],
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _render_text(report: dict, clean_result: dict | None) -> str:
    lines: list[str] = []
    state = report["state"]
    emoji = {
        "clean":    "✓",
        "active":   "▶",
        "stale":    "⚠",
        "orphaned": "⚠",
    }.get(state, "?")
    lines.append(f"{emoji} Assessment state: {state}")
    # G-1: surface needs_stage2 prominently so operators don't --rebuild by mistake.
    if report.get("needs_stage2"):
        lines.append("")
        lines.append("⚠ Stage 1 is complete (phase=10b need_render=true) but threat-model.md is missing.")
        lines.append("  Stage 2 (composition) was never dispatched — Phase 1–10b work is still on disk.")
        lines.append("  → Run  /appsec-advisor:create-threat-model --resume  to dispatch Stage 2 only.")
        lines.append("  → Running --rebuild will discard all Phase 1–10b results. Use --rebuild --force to confirm.")
    for r in report["reasons"]:
        lines.append(f"    • {r}")
    if clean_result is not None:
        if clean_result["skipped"]:
            lines.append("")
            lines.append(f"⚠ Cleanup skipped — {clean_result['reason']}")
        elif clean_result["removed"]:
            lines.append("")
            lines.append(
                f"✓ Removed {len(clean_result['removed'])} stale file(s): "
                f"{', '.join(clean_result['removed'])}"
            )
        else:
            lines.append("")
            lines.append("✓ Nothing to clean.")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_state.py",
        description=(
            "Classify and optionally clean assessment run-state files "
            "(.appsec-lock, .appsec-checkpoint, .phase-epoch, "
            ".session-agent-map)."
        ),
    )
    p.add_argument(
        "output_dir",
        help="Directory to inspect (typically $OUTPUT_DIR / docs/security).",
    )
    p.add_argument(
        "--clean",
        action="store_true",
        help="Remove stale / orphan files when it is safe to do so. "
             "Refuses when an active run holds the lock.",
    )
    p.add_argument(
        "--auto-clean",
        action="store_true",
        help="Like --clean but exits 0 even when no cleanup was needed. "
             "Intended for SKILL-impl preflight — never fails loud.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON on stdout.",
    )
    p.add_argument(
        "--resume-guard",
        action="store_true",
        help="Refuse-to-proceed gate for --resume: exits 3 with a "
             "user-facing error when the checkpoint is stale "
             "(status in {started, aborted} and older than "
             "--max-age-seconds).",
    )
    p.add_argument(
        "--max-age-seconds",
        type=int,
        default=900,
        help="Max checkpoint age (seconds) tolerated by --resume-guard "
             "before the run is classified as stale. Default: 900 (15 min).",
    )
    return p


def _resume_guard_result(output_dir: Path, max_age: int) -> tuple[int, str]:
    """Classify whether a --resume request should be allowed.

    Returns (exit_code, message). Exit codes:
      0 — safe to resume (checkpoint absent, or status=completed, or fresh,
          or lock proves the orchestrator is dead).
      3 — refuse to resume (stale checkpoint and lock cannot prove death).
    """
    checkpoint_path = output_dir / CHECKPOINT_FILE
    if not checkpoint_path.is_file():
        return (0, "no checkpoint present — treating as fresh run")
    try:
        age = time.time() - checkpoint_path.stat().st_mtime
    except OSError:
        age = float("inf")
    cp = _read_checkpoint(output_dir) or {}
    status = cp.get("status", "")
    phase = cp.get("phase", "?")
    if status == "completed":
        return (0, "checkpoint status=completed — prior run finalized cleanly")
    if status in ("started", "aborted") and age > max_age:
        # Dead-PID override: the max-age threshold exists to avoid racing with
        # a possibly-still-running orchestrator. When the lock proves the prior
        # process is dead (PID gone AND heartbeat stale, or dead PID on a v1
        # lock without heartbeat), there is no race left — resume is safe.
        lock = _read_lock(output_dir)
        if lock is not None and lock.get("alive") is False:
            hb_age = lock.get("heartbeat_age")
            hb_stale = hb_age is None or hb_age > HEARTBEAT_STALE_SECONDS
            if hb_stale:
                return (
                    0,
                    (
                        f"checkpoint phase={phase} status={status} is "
                        f"{int(age)}s old, but lock PID {lock.get('pid')} "
                        f"is dead and heartbeat is stale — safe to resume"
                    ),
                )
        return (
            3,
            (
                f"Refusing to resume: checkpoint phase={phase} status={status} "
                f"is {int(age)}s old (> {max_age}s threshold). The prior run "
                "likely hung or crashed. Run `/appsec-advisor:clean-state` "
                "and retry with --full or --rebuild."
            ),
        )
    return (0, f"checkpoint phase={phase} status={status} (age {int(age)}s) — OK to resume")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    out = Path(args.output_dir)

    # --resume-guard is an independent sub-mode: evaluate and return without
    # touching state. Never mutates files.
    if args.resume_guard:
        if not out.is_dir():
            if args.json:
                print(json.dumps({"allow": True, "reason": "output dir missing"}))
            else:
                print("✓ No prior run state — --resume is allowed.")
            return 0
        code, msg = _resume_guard_result(out, args.max_age_seconds)
        if args.json:
            print(json.dumps({
                "allow": code == 0,
                "reason": msg,
                "exit_code": code,
            }))
        else:
            marker = "✓" if code == 0 else "✗"
            print(f"{marker} {msg}")
        return code

    if not out.is_dir():
        # Missing output dir is effectively "clean" — nothing to report.
        report = {
            "state":   "clean",
            "reasons": [f"output dir {out} does not exist"],
            "lock":    None,
            "checkpoint": None,
            "files":   [],
        }
        clean_result = None
    else:
        report = classify(out)
        clean_result = None
        if args.clean or args.auto_clean:
            clean_result = clean(out, report)

    if args.json:
        payload = {"report": report}
        if clean_result is not None:
            payload["clean"] = clean_result
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(_render_text(report, clean_result), end="")

    # Exit-code matrix (see module docstring for rationale).
    if args.auto_clean:
        return 0
    if clean_result is not None:
        if clean_result["skipped"]:
            return 2
        return 0
    if report["state"] in ("stale", "orphaned"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
