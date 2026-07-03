#!/usr/bin/env python3
"""
acquire_lock.py — assessment concurrency lock helper.

Replaces the compound Bash lock script in appsec-threat-analyst.md so the
operation runs under a single `python3:*` permission entry instead of
requiring compound-command approval from Claude Code.

Usage:
  python3 acquire_lock.py <lock_file_path> [--reset-dirs]
  python3 acquire_lock.py <lock_file_path> --heartbeat [--phase=<P>] [--step=<S>]

Positional argument:
  <lock_file_path>   Path to the lock file (e.g. $OUTPUT_DIR/.appsec-lock).

Options:
  --reset-dirs       Wipe $OUTPUT_DIR/.progress and recreate it (and ensure
                     .appsec-cache and .fragments exist). Use this in step 7 of
                     the pre-phase checklist to avoid a separate mkdir call.
                     When --reset-dirs is given the lock check is SKIPPED — the
                     lock was already acquired in step 2.
  --heartbeat        Refresh the liveness heartbeat on an existing lock. The
                     lock file must exist; otherwise the call exits 0 without
                     mutating so the orchestrator can fire heartbeats defensively
                     at every phase boundary without racing a cleanup pass.
                     Each heartbeat additionally appends a single
                     ``HEARTBEAT`` line to ``$OUTPUT_DIR/.hook-events.log`` so
                     external watchers (status command, monitor scripts, IDE
                     plugins) see liveness without parsing the lock file.
  --phase=<P>        Optional phase label written into the HEARTBEAT event
                     detail (e.g. ``--phase=10b``). Defaults to "?".
  --step=<S>         Optional step label written into the HEARTBEAT event
                     detail (e.g. ``--step=triage``). Defaults to "".

Lock file format
----------------
Version 2 (current):
    <pid>\n
    <heartbeat_unix_ts>\n

Version 1 (pre-heartbeat, still accepted for reads):
    <pid>\n

When a v2 lock's heartbeat timestamp is older than HEARTBEAT_STALE_SECONDS
(5 min), the lock is considered **hung** — the PID is alive but the
orchestrator has not emitted any observable progress in a threshold window.
The lock is reaped in that case as if the PID were dead. V1 locks continue
to use the legacy mtime-based STALE_SECONDS fallback (1 h).

Exit codes:
  0  — LOCK_ACQUIRED / DIRS_RESET / HEARTBEAT_OK; directories created
  1  — LOCK_BLOCKED; another assessment is running
  2  — usage error
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import time
from pathlib import Path

from event_log import format_line

# Phase-budgets loader is sibling-imported so this script stays standalone
# (no package init required). Falls back to the historical 300 s default
# when phase context is unavailable or the YAML is missing.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import phase_budgets  # type: ignore  # noqa: E402
except Exception:  # pragma: no cover
    phase_budgets = None  # type: ignore[assignment]

STALE_SECONDS = 3600  # 1h mtime fallback for v1 / ambiguous locks
# Default heartbeat-stale threshold — phase-agnostic fallback. Phase-aware
# callers (M3.6) can pass --phase=<P> --depth=<D> on a heartbeat call to
# pick a phase-specific threshold from data/phase-budgets.yaml; classify
# uses the same lookup against the on-disk .appsec-checkpoint.
HEARTBEAT_STALE_SECONDS = phase_budgets.default_heartbeat_stale_seconds() if phase_budgets else 300

# Hook-log line shape mirrors agent_logger._write so a HEARTBEAT line is
# indistinguishable from any other event for downstream parsers. Session-ID
# is unknown to this script (it runs from Bash, not from a Claude Code hook
# context), so the bracketed slot is left blank and padded to 8 chars to
# keep column alignment.
_LOG_FILENAME = ".hook-events.log"
_HEARTBEAT_EVENT = "HEARTBEAT"


def _emit_hook_event(output_dir: Path, level: str, event: str, detail: str) -> None:
    """Append a single line to ``$OUTPUT_DIR/.hook-events.log``.

    Best-effort: any IO error is silently swallowed because the heartbeat
    must never fail the run. The format is byte-compatible with the lines
    written by ``agent_logger._write`` so existing parsers (`render_completion_summary`,
    `aggregate_run_issues`, etc.) handle it uniformly.
    """
    try:
        log_path = output_dir / _LOG_FILENAME
        line = format_line(event, detail, level=level)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        # Never crash the heartbeat caller — the run is the priority, not
        # the audit log.
        pass


def _pid_alive(pid: int) -> bool:
    """Return True when the OS considers ``pid`` alive.

    Mirrors ``check_state._pid_alive`` — kept as a local copy so this script
    stays importable without a dependency on the sibling module.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Signal denied ⇒ process exists under another user.
        return True
    except OSError:
        return False
    return True


# Standard subdirectories created alongside the lock so the orchestrator
# never needs a separate mkdir -p call (which would cause compound-command
# permission prompts when batched with this python3 invocation).
STANDARD_SUBDIRS = (".appsec-cache", ".fragments")
# .progress is handled separately because --reset-dirs wipes+recreates it.
PROGRESS_DIR = ".progress"


def _ensure_dirs(output_dir: Path, reset_progress: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for sub in STANDARD_SUBDIRS:
        (output_dir / sub).mkdir(exist_ok=True)
    progress = output_dir / PROGRESS_DIR
    if reset_progress and progress.exists():
        shutil.rmtree(progress, ignore_errors=True)
    progress.mkdir(exist_ok=True)


def _parse_lock(lock_path: Path) -> tuple[int | None, int | None]:
    """Return (pid, heartbeat_ts) — either value may be None.

    Malformed locks return (None, None). A v1 lock (PID-only) returns
    (pid, None). A v2 lock returns (pid, heartbeat_ts). Extra lines are
    ignored so future versions can append without breaking older readers.
    """
    try:
        raw = lock_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return (None, None)
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return (None, None)
    try:
        pid = int(lines[0].split()[0])
    except (ValueError, IndexError):
        return (None, None)
    heartbeat: int | None = None
    if len(lines) >= 2:
        try:
            heartbeat = int(lines[1].split()[0])
        except (ValueError, IndexError):
            heartbeat = None
    return (pid, heartbeat)


def _write_lock(lock_path: Path, pid: int, heartbeat_ts: int, run_id: str = "") -> None:
    body = f"{pid}\n{heartbeat_ts}\n"
    if run_id:
        # Optional 3rd line — a stable per-run token so an agent dispatched by
        # the same logical run can re-acquire a skill-held lock (see main()).
        body += f"{run_id}\n"
    lock_path.write_text(body, encoding="utf-8")


def _read_run_id(lock_path: Path) -> str:
    """Return the optional run-id on the lock's 3rd line, or '' if absent.

    Backward compatible: v2 locks (pid + heartbeat only) return ''.
    """
    try:
        lines = [l for l in lock_path.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    except OSError:
        return ""
    return lines[2].strip() if len(lines) >= 3 else ""


def _read_phase_from_checkpoint(output_dir: Path) -> tuple[str | None, str | None]:
    """Best-effort: parse ``.appsec-checkpoint`` for phase + depth context.

    Returns ``(phase, depth)``; either may be ``None``. The checkpoint file
    is optional — callers without phase context get ``(None, None)`` and
    fall back to the depth-agnostic ``HEARTBEAT_STALE_SECONDS`` default.
    Depth is read from the resolved-config sidecar (``.skill-config.json``)
    when present; the checkpoint itself never carries depth so a separate
    read is required.
    """
    phase: str | None = None
    depth: str | None = None
    cp = output_dir / ".appsec-checkpoint"
    if cp.is_file():
        try:
            for tok in cp.read_text(encoding="utf-8", errors="replace").split():
                if tok.startswith("phase="):
                    phase = tok.split("=", 1)[1] or None
                    break
        except OSError:
            pass
    sk = output_dir / ".skill-config.json"
    if sk.is_file():
        try:
            import json as _json

            data = _json.loads(sk.read_text(encoding="utf-8"))
            d = data.get("assessment_depth")
            if isinstance(d, str) and d:
                depth = d
        except (OSError, ValueError):
            pass
    return (phase, depth)


# Matches the live phase banner the threat-analyst writes into .agent-run.log,
# e.g. "[Phase 2/11] Reconnaissance — dispatching recon-scanner…". Captured as
# a single space-free token "2/11" to keep the HEARTBEAT detail's key=value
# columns parseable (values never contain spaces by convention).
_RUN_LOG_PHASE_RE = re.compile(r"\[Phase ([\d.]+)/(\d+)\]")
_RUN_LOG_FILENAME = ".agent-run.log"


def _current_phase_label(output_dir: Path) -> str | None:
    """Best-effort current-phase token for a heartbeat with no explicit phase.

    The watchdog and bare heartbeat callers don't know which analysis phase the
    orchestrator is in, so they previously logged ``phase=?`` / ``phase=skill``.
    Resolve the real phase from the most recent ``[Phase X/Y]`` banner in
    ``.agent-run.log`` (authoritative, always written), falling back to the
    ``.appsec-checkpoint`` phase. Returns ``None`` when nothing is resolvable
    (e.g. before the first phase starts) so the caller keeps its placeholder.
    """
    log = output_dir / _RUN_LOG_FILENAME
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    for line in reversed(lines):
        if "PHASE_START" not in line:
            continue
        m = _RUN_LOG_PHASE_RE.search(line)
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    cp_phase, _ = _read_phase_from_checkpoint(output_dir)
    return cp_phase


def _stale_threshold_for_lock(lock_path: Path) -> int:
    """Phase-aware stall threshold for the lock at ``lock_path``.

    Reads the sibling ``.appsec-checkpoint`` to resolve the current phase,
    then asks ``phase_budgets`` for the matching threshold. Falls back to
    the depth-agnostic default when phase or yaml is unavailable.
    """
    if phase_budgets is None:  # pragma: no cover
        return HEARTBEAT_STALE_SECONDS
    phase, depth = _read_phase_from_checkpoint(lock_path.parent)
    return phase_budgets.threshold_for_phase(phase, depth or "standard")


def _classify_lock(lock_path: Path) -> tuple[str, dict]:
    """Return (state, info). state in {'fresh', 'hung', 'dead', 'stale_mtime', 'malformed', 'absent'}.

    Classification precedence (heartbeat-first, because the stored PID is an
    ephemeral Python-subprocess PID that is always dead shortly after
    acquisition — see `_do_heartbeat` docstring):

      'fresh'        — v2 heartbeat is within the phase-aware threshold
                       (data/phase-budgets.yaml; depth-agnostic default
                       300 s when no phase context is resolvable).
      'hung'         — v2 heartbeat exceeds the phase-aware threshold
                       AND the stored PID is still alive. A live PID with a
                       silent heartbeat is the signature of a thinking-loop
                       stall — the anti-stall caller reaps it.
      'dead'         — v2 lock whose heartbeat is stale AND the PID is gone
                       (process exited, crash, Ctrl-C).
      'stale_mtime'  — v1 lock (no heartbeat) with mtime older than STALE_SECONDS.
      'malformed'    — unparseable lock file.
      'absent'       — no lock file.

    The ``info`` dict carries ``threshold`` (the resolved phase-aware value
    used for the decision) so callers and tests can assert on the same
    number the classifier saw.
    """
    if not lock_path.exists():
        return ("absent", {})
    try:
        mtime = lock_path.stat().st_mtime
    except OSError:
        return ("malformed", {"reason": "stat failed"})
    age_mtime = time.time() - mtime

    pid, heartbeat = _parse_lock(lock_path)
    if pid is None:
        return ("malformed", {"mtime_age": int(age_mtime)})

    alive = _pid_alive(pid)
    threshold = _stale_threshold_for_lock(lock_path)
    info = {
        "pid": pid,
        "heartbeat": heartbeat,
        "mtime_age": int(age_mtime),
        "threshold": threshold,
    }

    # v2 lock with heartbeat — heartbeat freshness is authoritative.
    if heartbeat is not None:
        hb_age = time.time() - heartbeat
        info["heartbeat_age"] = int(hb_age)
        if hb_age <= threshold:
            return ("fresh", info)
        # Stale heartbeat — distinguish hung (PID still alive) from dead.
        if alive:
            return ("hung", info)
        return ("dead", info)

    # Legacy v1 lock (pre-heartbeat). PID liveness is the only signal.
    if not alive:
        return ("dead", info)
    if age_mtime > STALE_SECONDS:
        return ("stale_mtime", info)
    return ("fresh", info)


def _do_heartbeat(lock_path: Path, phase: str = "?", step: str = "") -> int:
    """Refresh the heartbeat timestamp on the existing lock and emit a
    ``HEARTBEAT`` event into ``$OUTPUT_DIR/.hook-events.log``.

    The stored PID stays the PID originally written at acquisition time — we
    only update the heartbeat timestamp. This matters because every orchestrator
    Bash turn spawns a fresh short-lived Python interpreter (different PID from
    the one that acquired the lock), so a PID-match gate would silently no-op
    every heartbeat and leave the anti-stall classifier blind. File-based lock
    semantics make this safe: whoever owns the lock file owns the lock; if two
    runs race, the loser's `acquire_lock.py` (without `--heartbeat`) sees the
    existing file and either blocks or reaps.

    The hook-log line keeps the heartbeat visible to any external watcher
    that tails ``.hook-events.log`` — previously the heartbeat was silent
    (lock-file-only) and there was no way for ``/appsec-advisor:status`` or
    a monitor script to see "the agent is alive" without parsing the lock
    file. Format is identical to the other ``INFO`` events so existing
    parsers handle it uniformly. Skipped heartbeats also emit a line so a
    silent run is never misclassified as alive.
    """
    output_dir = lock_path.parent
    # Placeholder phases ("?" from a bare heartbeat, "skill" from the watchdog)
    # carry no useful signal — resolve the real current phase from the run log.
    if phase in ("?", "skill", ""):
        derived = _current_phase_label(output_dir)
        if derived:
            phase = derived
    if not lock_path.exists():
        _emit_hook_event(
            output_dir, "WARN", _HEARTBEAT_EVENT, f"skip=lock_absent  phase={phase}{('  step=' + step) if step else ''}"
        )
        print("HEARTBEAT_SKIP: lock file absent", file=sys.stderr)
        return 0
    pid, _ = _parse_lock(lock_path)
    if pid is None:
        _emit_hook_event(
            output_dir,
            "WARN",
            _HEARTBEAT_EVENT,
            f"skip=lock_malformed  phase={phase}{('  step=' + step) if step else ''}",
        )
        print("HEARTBEAT_SKIP: lock file malformed", file=sys.stderr)
        return 0
    # Preserve the original acquirer PID and run-id — only bump the heartbeat.
    now = int(time.time())
    _write_lock(lock_path, pid, now, _read_run_id(lock_path))
    _emit_hook_event(
        output_dir, "INFO", _HEARTBEAT_EVENT, f"pid={pid}  phase={phase}{('  step=' + step) if step else ''}  ts={now}"
    )
    print("HEARTBEAT_OK")
    return 0


def main(argv: list[str]) -> int:
    # Parse args: positional lock path + optional flags. ``--phase=<P>`` and
    # ``--step=<S>`` are key=value flags consumed by the heartbeat path.
    bare_flags = {"--reset-dirs", "--heartbeat"}
    rest = argv[1:]
    reset_dirs = "--reset-dirs" in rest
    heartbeat = "--heartbeat" in rest
    phase = "?"
    step = ""
    # Stable per-run token. Lets an agent dispatched by the same logical run
    # re-acquire a lock the skill pre-acquired (and a watchdog keeps warm)
    # instead of hard-blocking on it. Env is the fallback so callers that
    # cannot thread a CLI flag still opt in. Empty → legacy behaviour.
    run_id = os.environ.get("APPSEC_RUN_ID", "").strip()
    args: list[str] = []
    for tok in rest:
        if tok in bare_flags:
            continue
        if tok.startswith("--phase="):
            phase = tok.split("=", 1)[1] or "?"
            continue
        if tok.startswith("--step="):
            step = tok.split("=", 1)[1]
            continue
        if tok.startswith("--run-id="):
            run_id = tok.split("=", 1)[1].strip() or run_id
            continue
        args.append(tok)

    if len(args) != 1:
        print(
            f"usage: {argv[0]} <lock_file_path> [--run-id=<id>] [--reset-dirs | --heartbeat [--phase=<P>] [--step=<S>]]",
            file=sys.stderr,
        )
        return 2

    lock_path = Path(args[0])
    output_dir = lock_path.parent

    if heartbeat:
        return _do_heartbeat(lock_path, phase=phase, step=step)

    if reset_dirs:
        # Called from step 7 — lock already held, just reset dirs.
        _ensure_dirs(output_dir, reset_progress=True)
        print("DIRS_RESET")
        return 0

    # Normal lock acquisition (step 2).
    _ensure_dirs(output_dir, reset_progress=False)

    state, info = _classify_lock(lock_path)

    if state == "fresh":
        # Re-entrant grant: a fresh lock carrying THIS run's id belongs to the
        # same logical assessment (the skill pre-acquired it and a background
        # watchdog keeps its heartbeat warm). An agent dispatched by that run
        # re-acquiring must not be mistaken for a concurrent assessment — that
        # false LOCK_BLOCKED aborted the 2026-07-02 juice-shop Stage-1 dispatch
        # and forced a costly re-dispatch. Concurrency safety is preserved: a
        # genuinely different run carries a different (or no) run-id and blocks.
        existing_run_id = _read_run_id(lock_path)
        if run_id and existing_run_id and run_id == existing_run_id:
            _write_lock(lock_path, os.getpid(), int(time.time()), run_id)
            print("LOCK_ACQUIRED")
            return 0
        hb = info.get("heartbeat_age")
        hb_str = f", hb_age={hb}s" if hb is not None else ""
        print(
            f"LOCK_BLOCKED: Another assessment is running "
            f"(pid={info['pid']}, mtime_age={info['mtime_age']}s{hb_str}). "
            f"Remove {lock_path} if stale."
        )
        return 1

    if state == "hung":
        hb = info.get("heartbeat_age", "?")
        threshold = info.get("threshold", HEARTBEAT_STALE_SECONDS)
        print(
            f"LOCK_STALE: prior lock held by pid={info['pid']} but heartbeat "
            f"is {hb}s old (> {threshold}s threshold) — reaped.",
            file=sys.stderr,
        )
    elif state == "dead":
        print(
            f"LOCK_STALE: prior lock held by dead PID {info['pid']} — reaped.",
            file=sys.stderr,
        )
    elif state == "stale_mtime":
        print(
            f"LOCK_STALE: prior lock mtime {info['mtime_age']}s > {STALE_SECONDS}s threshold — reaped.",
            file=sys.stderr,
        )
    elif state == "malformed":
        print(
            "LOCK_STALE: prior lock file was malformed — reaped.",
            file=sys.stderr,
        )
    # state == "absent" — fall through and write a fresh lock.

    _write_lock(lock_path, os.getpid(), int(time.time()), run_id)
    print("LOCK_ACQUIRED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
