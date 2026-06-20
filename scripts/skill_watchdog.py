#!/usr/bin/env python3
"""skill_watchdog.py — long-running watchdog spawned by the create-threat-model skill.

Replaces the ~60-line ``HEARTBEAT_LOOP_CMD`` Bash blob in ``SKILL-impl.md``
with a single Python process the skill spawns via the ``Bash`` tool with
``run_in_background: true``. The Python rewrite is unit-testable, has no
shell-quoting hell, and gives us a clean place to add per-component
timeout escalation (M3.6 #7) and task-id-driven selective kills (M3.6 #8)
later.

Responsibilities (1:1 with the previous Bash loop unless flagged ``[NEW]``)
--------------------------------------------------------------------------

  1. **Heartbeat refresh.** Every ``--heartbeat-interval`` seconds (default
     60) shell out to ``acquire_lock.py --heartbeat`` so the lock file's
     second-line timestamp keeps advancing. Exits cleanly the first time
     the lock file disappears (the deadline-watchdog or post-stage cleanup
     removed it).

  2. **STRIDE progress logging.** Mirrors the historical ``STRIDE_PROGRESS``
     line — ``stride_files=K  total_bytes=B  progress_files=P`` — appended
     to ``.agent-run.log`` so verbose terminals see the pulse. Suppressed
     once a STAGNATION warning has fired (avoids log spam after escalation).

  3. **Phase-9 stagnation detection.** Counts consecutive ticks where the
     STRIDE-output aggregate (file count + total bytes) is unchanged. Once
     ``--stride-stale-seconds`` of stagnation accumulate after Phase 9 has
     visibly started, emits ``STRIDE_STALE`` once.

  4. **Phase-9 progress canary.** Phase 9 is "started" when ``.progress/``
     gains entries OR any ``.stride-*.json`` lands. If the watchdog still
     sees zero ``.stride-*.json`` files ``--stride-canary-seconds`` after
     the start signal, emits ``STRIDE_CANARY_TIMEOUT`` once.

  5. **[NEW] Per-component timeout (M3.6 #7).** Tracks the mtime of each
     ``.progress/<component>.json`` independently. When a single component
     stays untouched longer than ``--component-timeout-seconds`` after
     Phase 9 starts, emits ``STRIDE_COMPONENT_TIMEOUT  component=<id>
     idle=<n>s``. The current implementation is **log-only**; selective
     ``TaskStop`` requires the orchestrator's task-id map (``#8``) which
     this script does NOT yet read — adding that is straightforward once
     the orchestrator persists ``.background-tasks.json``.

  6. **[NEW] Self-liveness tick.** Writes ``.skill-watchdog.tick`` with
     a monotonically-increasing counter every iteration so a future
     watchdog-watchdog (M3.6 #10) can detect a wedged Python loop.

Output
------

All warnings flow into ``$OUTPUT_DIR/.agent-run.log`` so the post-Stage cut-
off detection picks them up the same way it did with the Bash version. The
hook-events log and ``.appsec-trace.log`` are untouched — this script is a
liveness watchdog, not a tracing tool.

Exit codes
----------

  0 — lock file disappeared, watchdog exited cleanly.
  2 — usage error.

The watchdog never returns a non-zero status while running. Anything
fatal during a tick (filesystem error, permission denied) is logged with
``WATCHDOG_ERROR`` and the loop continues.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from event_log import format_line

# Reuse the central phase budgets so per-component-timeout defaults stay
# in sync with the rest of the toolchain.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import phase_budgets  # type: ignore
except Exception:  # pragma: no cover
    phase_budgets = None  # type: ignore[assignment]

# Reuse the calibrated per-phase relative weights for the coarse run-progress
# percentage (RUN_PROGRESS). Single source of truth — the same table drives
# the resume-time estimate in estimate_duration.py. Guarded like phase_budgets
# so a missing/partial sibling never breaks the watchdog loop; progress % is
# simply skipped when the table is unavailable.
try:
    from estimate_duration import _PHASE_DURATION as _PROGRESS_WEIGHTS  # type: ignore
except Exception:  # pragma: no cover
    _PROGRESS_WEIGHTS = None  # type: ignore[assignment]


_LOG_NAME = ".agent-run.log"
_HOOK_LOG_NAME = ".hook-events.log"
_TICK_NAME = ".skill-watchdog.tick"
_AGENT_NAME = "skill-watchdog"


def _ts_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(output_dir: Path, level: str, event: str, detail: str) -> None:
    """Append one structured line to ``$OUTPUT_DIR/.agent-run.log``.

    Format mirrors ``agent_logger._write`` so existing parsers handle it
    uniformly. Failures are swallowed — the watchdog must never break the
    run because of a log-write error.
    """
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        log_path = output_dir / _LOG_NAME
        line = format_line(event, detail, level=level, component=_AGENT_NAME)
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass


def _log_error_loud(output_dir: Path, event: str, detail: str, remedy: str) -> None:
    """Loudly escalate a watchdog defect — ERROR-level log + stderr banner +
    sentinel file + structured run-issue entry.

    Used for hard-limit conditions (SUBSTEP2_IDLE etc.) where a WARN line
    buried in ``.agent-run.log`` is not loud enough. The user must see this
    in their terminal and the orchestrator's downstream code must be able
    to detect the defect via sentinel file or ``.run-issues.json``.

    Failures are swallowed (same contract as ``_log``) — the watchdog
    never breaks the run because of an emit error.
    """
    # 1. ERROR-level line in .agent-run.log
    _log(output_dir, "ERROR", event, detail)

    # 2. Bright stderr banner so the terminal user sees it without grepping
    try:
        banner = f"\n⛔  {event} — {detail}\n    Remedy: {remedy}\n\n"
        sys.stderr.write(banner)
        sys.stderr.flush()
    except Exception:
        pass

    # 3. Sentinel file so downstream code can branch on "stall happened"
    try:
        sentinel = output_dir / f".{event.lower().replace('_', '-')}"
        sentinel.write_text(
            f"{_ts_now()}\n{detail}\nremedy: {remedy}\n",
            encoding="utf-8",
        )
    except OSError:
        pass

    # 4. Append a structured defect to .run-issues.json so the orchestrator's
    #    final assessment summary surfaces the failure to the user.
    try:
        runissues_path = output_dir / ".run-issues.json"
        if runissues_path.exists():
            try:
                payload = json.loads(runissues_path.read_text(encoding="utf-8"))
                if not isinstance(payload, list):
                    payload = []
            except (json.JSONDecodeError, OSError):
                payload = []
        else:
            payload = []
        payload.append(
            {
                "source": _AGENT_NAME,
                "severity": "defect",
                "type": event.lower(),
                "detail": detail,
                "remedy": remedy,
                "timestamp": _ts_now(),
            }
        )
        runissues_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError:
        pass


_SUBSTEP2_START_RE = re.compile(r"STEP_START\s+\[Phase\s*11\]\s+\[2/\d+\]\s+Writing\s+threat-model\.yaml")
_SUBSTEP2_DONE_RE = re.compile(r"FILE_WRITE\s+\S*threat-model\.yaml\b")
_ISO_LEAD_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")


def _find_substep2_start(output_dir: Path) -> str | None:
    """Return the timestamp (ISO 8601 string) of the most recent Substep 2
    STEP_START in ``.agent-run.log``, or None if Substep 2 hasn't started.

    Scanning is by line — the log appends only, so a forward iteration is
    cheap. We return the LAST match so re-entry after a recovered run
    starts a fresh idle window.
    """
    log_path = output_dir / _LOG_NAME
    if not log_path.exists():
        return None
    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    last_ts: str | None = None
    for line in content.splitlines():
        if _SUBSTEP2_START_RE.search(line):
            m = _ISO_LEAD_RE.match(line)
            if m:
                last_ts = m.group(1)
    return last_ts


def _substep2_completed_after(output_dir: Path, started_at_iso: str) -> bool:
    """True once Substep 2's deliverable — ``threat-model.yaml`` — has landed,
    by EITHER of two independent signals:

      1. A ``FILE_WRITE threat-model.yaml`` log line at/after ``started_at_iso``
         in ``.agent-run.log`` (ISO 8601 sorts lexicographically — no parse).
      2. **[robustness]** ``threat-model.yaml`` present on disk with an mtime
         >= ``started_at_iso``.

    Signal 2 closes a false-positive: the analyst writes the yaml via
    ``build_threat_model_yaml.py``, which does NOT reliably emit the
    ``FILE_WRITE`` marker signal 1 keys on. Without the disk check the watchdog
    never set ``substep2_complete``, kept measuring idle long after Substep 2
    finished, and mis-attributed the Stage-2 renderer's legitimate multi-minute
    compose turn (one big LLM turn, no interim log lines) as a Substep-2 stall
    — the 2026-06-04 juice-shop pstride-e2e SUBSTEP2_IDLE false-positive.
    """
    # Signal 2 — yaml on disk (robust to a missing FILE_WRITE marker).
    try:
        st = (output_dir / "threat-model.yaml").stat()
        started_epoch = datetime.strptime(started_at_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        # +1s tolerance: log STEP_START is whole-second, the write may stamp
        # within the same second.
        if st.st_mtime + 1 >= started_epoch:
            return True
    except (OSError, ValueError):
        pass

    # Signal 1 — FILE_WRITE log marker (original).
    log_path = output_dir / _LOG_NAME
    if not log_path.exists():
        return False
    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    for line in content.splitlines():
        if _SUBSTEP2_DONE_RE.search(line):
            m = _ISO_LEAD_RE.match(line)
            if m and m.group(1) >= started_at_iso:
                return True
    return False


def _log_idle_seconds(output_dir: Path, started_at_iso: str) -> float:
    """Seconds since the last NON-watchdog event was appended to
    ``.agent-run.log`` at or after ``started_at_iso``.

    Mtime-based idle would be wrong here because the watchdog itself
    writes ``WATCHDOG_START`` (once at boot) and may write other
    progress/escalation lines during a run — each of those updates the
    file mtime and would mask a genuine orchestrator stall. Instead we
    scan the log content for the latest timestamped line whose agent
    field is not ``skill-watchdog`` and compute the delta to now.

    Falls back to ``started_at_iso`` when no non-watchdog event has
    landed since the substep started (= "no progress at all"). Returns
    0.0 conservatively on any I/O error so a transient glitch never
    false-positives.
    """
    log_path = output_dir / _LOG_NAME
    if not log_path.exists():
        return 0.0
    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return 0.0
    last_non_watchdog_ts: str | None = None
    needle = f"  {_AGENT_NAME}  "
    for line in content.splitlines():
        m = _ISO_LEAD_RE.match(line)
        if not m:
            continue
        ts = m.group(1)
        if ts < started_at_iso:
            continue
        if needle in line:
            # Watchdog's own line — does not count as "agent still alive".
            continue
        last_non_watchdog_ts = ts
    baseline_iso = last_non_watchdog_ts or started_at_iso
    try:
        dt = datetime.strptime(baseline_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return 0.0
    return max(0.0, time.time() - dt.timestamp())


def _hook_log_idle_seconds(output_dir: Path) -> float | None:
    """Seconds since the last NON-heartbeat line was appended to
    ``.hook-events.log``.

    The file's mtime is unusable as an activity signal: the skill's own
    60 s heartbeat (``acquire_lock.py --heartbeat``) appends a ``HEARTBEAT``
    line here every minute, so the mtime never goes stale and would mask a
    genuine multi-minute API stall. That is exactly what let a 21-min Stage-1
    stall (2026-06-06 juice-shop, §7 security-architecture generated in one
    slow standard-tier turn) go completely unsurfaced — ``min(60s, real)``
    always collapsed to ~60s and RUN_IDLE never fired. We instead scan the
    log content for the latest timestamped line that is NOT a heartbeat and
    measure the delta to now, mirroring ``_log_idle_seconds``.

    Returns ``None`` when the log is absent or has no non-heartbeat line yet
    (caller then relies on the ``.agent-run.log`` signal alone), or on any
    I/O error. Returns 0.0-floored seconds otherwise.
    """
    log_path = output_dir / _HOOK_LOG_NAME
    if not log_path.exists():
        return None
    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    last_ts: str | None = None
    for line in content.splitlines():
        m = _ISO_LEAD_RE.match(line)
        if not m:
            continue
        if "HEARTBEAT" in line:
            # Skill's own 60 s heartbeat — not agent activity.
            continue
        last_ts = m.group(1)
    if last_ts is None:
        return None
    try:
        dt = datetime.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return max(0.0, time.time() - dt.timestamp())


def _run_idle_seconds(output_dir: Path, run_start_iso: str) -> float:
    """Seconds since the run last showed ANY observable activity — across ALL
    phases, not just Phase 9 / Substep 2.

    This is the GENERAL stall signal. The existing detectors (STRIDE_STALE,
    SUBSTEP2_IDLE) only cover two narrow windows; the recon / context phases
    (Phase 1-2) ran completely unmonitored. The 2026-05-31 juice-shop run sat
    idle for 7m and 11m on two recon-phase model requests (standard-tier API
    latency that blew the 5-min prompt-cache TTL — verified from the session
    transcript: 98 / 1128 output tokens after 441s / 667s of wall-clock), and
    nothing surfaced it — the user watched 46 min and aborted, unsure whether
    the run had wedged.

    Two independent activity signals, whichever is freshest wins (so we never
    false-positive while either log is advancing):

      1. ``.hook-events.log`` — the latest NON-heartbeat line (every
         Bash/Read/Write tool call appends here). Heartbeat lines are
         excluded because the skill writes one every 60 s and a raw mtime
         would never go stale — see ``_hook_log_idle_seconds``.
      2. The last NON-watchdog entry in ``.agent-run.log`` (reuses
         ``_log_idle_seconds`` semantics) — catches phase-boundary progress
         even if the hook log is absent (hooks are opt-in).

    Returns 0.0 on any I/O error so a transient glitch never false-positives.
    """
    idles: list[float] = []
    hook_idle = _hook_log_idle_seconds(output_dir)
    if hook_idle is not None:
        idles.append(hook_idle)
    idles.append(_log_idle_seconds(output_dir, run_start_iso))
    return min(idles) if idles else 0.0


def _bump_tick(output_dir: Path, n: int) -> None:
    try:
        (output_dir / _TICK_NAME).write_text(f"{n}\n{int(time.time())}\n", encoding="utf-8")
    except OSError:
        pass


def _refresh_heartbeat(plugin_root: Path, lock_path: Path) -> None:
    """Invoke ``acquire_lock.py --heartbeat`` as a sub-process.

    Spawning Python again costs ~50 ms but mirrors what the Bash loop did
    and keeps a clean separation from the watchdog's own state. A direct
    in-process call to ``acquire_lock._do_heartbeat`` would skip the
    sub-process overhead but couples the two scripts at the import level.
    """
    import subprocess

    try:
        subprocess.run(
            [
                "python3",
                str(plugin_root / "scripts" / "acquire_lock.py"),
                str(lock_path),
                "--heartbeat",
                "--phase=skill",
                "--step=watchdog",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except Exception:
        # Heartbeat failures must never crash the watchdog. The lock-age
        # signal degrades gracefully (the orchestrator's own per-phase
        # heartbeats are still firing).
        pass


def _scan_stride(output_dir: Path) -> dict[str, Any]:
    """Snapshot the STRIDE-output state in one stat-only pass."""
    stride_files = sorted(output_dir.glob(".stride-*.json"))
    stride_count = len(stride_files)
    stride_bytes = 0
    for f in stride_files:
        try:
            stride_bytes += f.stat().st_size
        except OSError:
            pass
    progress_dir = output_dir / ".progress"
    progress_files: list[Path] = []
    if progress_dir.is_dir():
        progress_files = sorted(progress_dir.glob("*.json"))
    return {
        "stride_count": stride_count,
        "stride_bytes": stride_bytes,
        "progress_files": progress_files,
    }


def _component_idle_seconds(progress_files: list[Path]) -> dict[str, int]:
    """Map ``component_id`` → seconds since last mtime for its progress file."""
    now = time.time()
    out: dict[str, int] = {}
    for f in progress_files:
        try:
            comp = f.stem
            out[comp] = max(0, int(now - f.stat().st_mtime))
        except OSError:
            continue
    return out


def _is_past_stride_phase(output_dir: Path) -> bool:
    """Return True when ``.appsec-checkpoint`` shows the orchestrator has
    moved past Phase 9 (STRIDE enumeration).

    Checkpoint format examples written by other parts of the skill:
      ``phase=10 status=...``
      ``phase=11 status=writing_output``
      ``phase=repair/1 status=completed``

    After Phase 9 ends, ``.stride-*.json`` files are intentionally frozen
    — a flat progress curve is the expected state. Continuing to count
    stagnant_seconds in that window produces false-positive STRIDE_STALE
    warnings (verified in the 2026-05-23 juice-shop run: 7 spurious
    STRIDE_STALE lines between 07:00 and 07:23 while Phase 11 was rendering
    normally). Read errors / missing checkpoint default to ``False`` so the
    pre-Phase-9 and Phase-9-active windows keep the existing semantics.
    """
    cp = output_dir / ".appsec-checkpoint"
    try:
        text = cp.read_text(encoding="utf-8")
    except OSError:
        return False
    # Match `phase=<token>` — token may contain digits, slashes, letters
    # (e.g. `repair/1`). Anything that is not a bare `9` is treated as
    # past-STRIDE. Pre-Phase-9 the watchdog is gated by ``phase9_detected``
    # via stride file presence, so an early-phase checkpoint value here
    # (``phase=1`` … ``phase=8``) cannot trip the false-positive.
    import re as _re

    m = _re.search(r"phase=([^\s]+)", text)
    if not m:
        return False
    token = m.group(1)
    # The exact STRIDE phase is `phase=9` — anything else (including
    # repair/N and 10/11) is past it.
    return token != "9"


def _read_epoch(path: Path) -> int | None:
    """Best-effort read of an integer epoch file (``.scan-start-epoch``).

    Returns None on any error so the caller drops the timing portion of the
    progress line rather than crashing.
    """
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _fmt_hms(secs: float) -> str:
    """Compact ``1h02m`` / ``3m05s`` / ``42s`` duration formatting."""
    s = int(max(0, secs))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{sec:02d}s"
    return f"{sec}s"


def _phase_position(token: str) -> float | None:
    """Map an ``.appsec-checkpoint`` phase token to a numeric pipeline position.

    Examples: ``1`` → 1.0, ``2.5`` → 2.5, ``10b`` → 10.5, ``11`` → 11.0.
    Non-numeric tokens (``repair/1``, ``writing_output``) mean the run is at or
    past finalization → a large sentinel so the percentage saturates near 100.
    """
    m = re.match(r"(\d+(?:\.\d+)?)", token)
    if not m:
        return 99.0
    val = float(m.group(1))
    # `10b` (and any `<n>b` sub-phase) sits just after its base integer phase.
    if token[m.end():].startswith("b"):
        val += 0.5
    return val


def _resolve_depth(output_dir: Path) -> str:
    """Resolve ASSESSMENT_DEPTH from ``.skill-config.json`` (quick/standard/
    thorough). Defaults to ``standard`` when the file is absent or malformed —
    the percentage only needs the right relative phase weights, and standard is
    the representative middle profile."""
    try:
        cfg = json.loads((output_dir / ".skill-config.json").read_text(encoding="utf-8"))
        depth = cfg.get("assessment_depth")
        if isinstance(depth, str) and _PROGRESS_WEIGHTS and depth in _PROGRESS_WEIGHTS:
            return depth
    except Exception:
        pass
    return "standard"


def _progress_snapshot(output_dir: Path, weights: dict[int, float]) -> tuple[int, str] | None:
    """Return ``(percent, phase_token)`` from ``.appsec-checkpoint``, or None.

    The percentage is the cumulative weight of all *completed* phases (those
    strictly before the current phase position) over the total — a deliberate
    lower bound that never overstates and is phase-granular (it jumps at phase
    boundaries and sits flat within a long phase such as Phase 9 / STRIDE). The
    caller clamps it monotonically so resume/incremental can't move it back.
    """
    try:
        text = (output_dir / ".appsec-checkpoint").read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r"phase=([^\s]+)", text)
    if not m:
        return None
    token = m.group(1)
    # Terminal checkpoint — the phase token (e.g. `11`) is still mid-table but
    # the run is done; saturate to 100 rather than the 96% the weights imply.
    if re.search(r"status=completed", text):
        return 100, token
    pos = _phase_position(token)
    if pos is None:
        return None
    total = sum(weights.values())
    if total <= 0:
        return None
    done = sum(w for p, w in weights.items() if p < pos)
    pct = max(0, min(100, round(100 * done / total)))
    return pct, token


def watch(
    output_dir: Path,
    plugin_root: Path,
    heartbeat_interval: int,
    stride_stale_seconds: int,
    stride_canary_seconds: int,
    component_timeout_seconds: int,
    max_iterations: int | None,
    *,
    substep2_idle_seconds: int = 0,
    run_idle_seconds: int = 0,
) -> int:
    lock_path = output_dir / ".appsec-lock"
    if not output_dir.is_dir():
        sys.stderr.write(f"output_dir not found: {output_dir}\n")
        return 2

    # Floor for the global idle window — activity before the watchdog booted
    # does not count toward "currently stalled".
    run_start_iso = _ts_now()

    _log(
        output_dir,
        "INFO",
        "WATCHDOG_START",
        f"interval={heartbeat_interval}s  "
        f"stride_stale={stride_stale_seconds}s  "
        f"canary={stride_canary_seconds}s  "
        f"component_timeout={component_timeout_seconds}s  "
        f"substep2_idle={substep2_idle_seconds}s",
    )

    last_count = 0
    last_bytes = 0
    stagnant_seconds = 0
    phase9_detected = False
    phase9_start: float | None = None
    canary_fired = False
    stale_fired = False
    component_fired: set[str] = set()
    # Substep-2 idle tracking — see _log_error_loud + _find_substep2_start.
    # `substep2_start_iso` is the ISO timestamp of the most recent Substep-2
    # STEP_START log entry; None until detected, "complete" once the
    # corresponding FILE_WRITE threat-model.yaml has landed (so we stop
    # scanning the log on every tick once Substep 2 is done).
    substep2_start_iso: str | None = None
    substep2_complete = False
    substep2_idle_fired = False
    # Global idle (RUN_IDLE) tracking — re-arms after activity resumes so each
    # distinct stall logs exactly one WARN line. ``run_idle_peak`` records the
    # largest idle seen during the current stall so RUN_RESUMED can report the
    # true stall length (the summary subtracts it from wall-clock).
    run_idle_fired = False
    run_idle_peak = 0.0
    # Periodic RUN_PROGRESS line (coarse % + net runtime). `idle_total`
    # accumulates the peak of every *completed* stall so net runtime mid-run is
    # wall-clock minus all standby so far; `last_pct` enforces a monotonic
    # percentage. Both stay inert unless the run is timeable + checkpointed.
    idle_total = 0.0
    last_pct = -1
    scan_start_epoch = _read_epoch(output_dir / ".scan-start-epoch")
    progress_weights = _PROGRESS_WEIGHTS.get(_resolve_depth(output_dir)) if _PROGRESS_WEIGHTS else None
    iteration = 0

    while lock_path.exists():
        iteration += 1
        if max_iterations is not None and iteration > max_iterations:
            _log(output_dir, "INFO", "WATCHDOG_END", f"iterations_capped  iter={iteration - 1}")
            return 0

        # 1 — heartbeat.
        _refresh_heartbeat(plugin_root, lock_path)

        # 2 — snapshot.
        snap = _scan_stride(output_dir)
        sc = snap["stride_count"]
        sb = snap["stride_bytes"]
        pg_files = snap["progress_files"]
        pg = len(pg_files)

        # 3 — phase-9 detection.
        if not phase9_detected and (pg > 0 or sc > 0):
            phase9_detected = True
            phase9_start = time.time()
            _log(output_dir, "INFO", "PHASE9_DETECTED", f"progress_files={pg}  stride_files={sc}")

        # Determine whether Phase 9 is still the active phase BEFORE the
        # STRIDE-progress mirror. Once `_is_past_stride_phase` returns True
        # (checkpoint at phase 10 / 11 / repair / completed), the .stride-*.json
        # snapshot is frozen — emitting a STRIDE_PROGRESS heartbeat every 60s
        # for the rest of Stage 2 / Stage 3 / repair-mode is observability
        # noise that drowns the actual stage events in the run log.
        past_stride = _is_past_stride_phase(output_dir)

        # 4 — STRIDE progress mirror line. Suppressed once Phase 9 has
        # advanced (otherwise emits identical lines through Stage 2 / 3 /
        # repair, ~17+ false-progress entries per run). Also silent once
        # stagnation has fired (avoids piling further noise after WARN).
        if (sc > 0 or pg > 0) and not stale_fired and not past_stride:
            _log(output_dir, "INFO", "STRIDE_PROGRESS", f"stride_files={sc}  total_bytes={sb}  progress_files={pg}")

        # 5 — stagnation tracking (only after Phase 9 has started, and only
        # while Phase 9 is still the active phase. Once the orchestrator
        # advances past STRIDE — observable via .appsec-checkpoint reading
        # `phase=10`, `phase=11`, `phase=repair/*`, or any non-9 marker —
        # the .stride-*.json files are intentionally frozen and a flat
        # progress curve is the expected state, not a hang.)
        if phase9_detected and not past_stride:
            if sc == last_count and sb == last_bytes:
                stagnant_seconds += heartbeat_interval
            else:
                stagnant_seconds = 0
            if not stale_fired and stagnant_seconds >= stride_stale_seconds:
                _log(
                    output_dir,
                    "WARN",
                    "STRIDE_STALE",
                    f"no progress for {stagnant_seconds}s  stride_files={sc}  threshold={stride_stale_seconds}s",
                )
                stale_fired = True

        # 6 — canary timeout (no .stride-*.json N seconds after Phase 9 start).
        # Same Phase-9-active gate as #5 — a post-STRIDE phase legitimately
        # has zero stride output once the orchestrator moves on.
        if (
            phase9_detected
            and not past_stride
            and not canary_fired
            and sc == 0
            and phase9_start is not None
            and (time.time() - phase9_start) >= stride_canary_seconds
        ):
            _log(
                output_dir,
                "WARN",
                "STRIDE_CANARY_TIMEOUT",
                f"no stride output {stride_canary_seconds}s after Phase 9 start — Phase 9 likely wedged",
            )
            canary_fired = True

        # 7 — per-component timeout (M3.6 #7).
        if phase9_detected and component_timeout_seconds > 0:
            for comp, idle in _component_idle_seconds(pg_files).items():
                if comp in component_fired:
                    continue
                # Skip components that already have a final .stride-<id>.json
                # (they are done — idle progress file is the post-completion
                # state, not a hang).
                final = output_dir / f".stride-{comp}.json"
                if final.is_file():
                    continue
                if idle >= component_timeout_seconds:
                    _log(
                        output_dir,
                        "WARN",
                        "STRIDE_COMPONENT_TIMEOUT",
                        f"component={comp}  idle={idle}s  threshold={component_timeout_seconds}s",
                    )
                    component_fired.add(comp)

        # 7b — Substep 2 idle detection (review-recommendations §4 Fix 3).
        #
        # Phase 11 Substep 2 is, by spec (phase-group-finalization.md:264),
        # a single Bash call to `build_threat_model_yaml.py` expected to
        # complete in under 5 seconds. The 2026-05-25 juice-shop run hung
        # for 1 h 39 min in Substep 2 because the LLM followed an
        # obsolete pre-cutover instruction in appsec-threat-analyst.md
        # (pre-validate intermediates, clip titles, then call Write) — the
        # entire stall was idle (no non-watchdog log events for 1h 38m 58s).
        #
        # Detection: once a Substep-2 STEP_START line appears in
        # `.agent-run.log`, compute idle as "time since the most recent
        # non-watchdog log entry at or after that STEP_START". If idle
        # exceeds threshold AND the corresponding FILE_WRITE
        # threat-model.yaml has not yet landed, escalate loudly via
        # `_log_error_loud` (ERROR log + stderr banner + sentinel +
        # `.run-issues.json` defect entry). Fires once per substep.
        # `substep2_idle_seconds <= 0` disables the check entirely
        # (parity with `--component-timeout-seconds 0`).
        if substep2_idle_seconds > 0 and not substep2_complete and not substep2_idle_fired:
            if substep2_start_iso is None:
                substep2_start_iso = _find_substep2_start(output_dir)
            if substep2_start_iso is not None:
                if _substep2_completed_after(output_dir, substep2_start_iso):
                    substep2_complete = True
                else:
                    idle = _log_idle_seconds(output_dir, substep2_start_iso)
                    if idle >= substep2_idle_seconds:
                        _log_error_loud(
                            output_dir,
                            "SUBSTEP2_IDLE",
                            (
                                f"Phase 11 Substep 2 idle for {int(idle)}s "
                                f"(threshold={substep2_idle_seconds}s).  "
                                f"STEP_START at {substep2_start_iso}.  "
                                f"No FILE_WRITE threat-model.yaml has occurred and "
                                f".agent-run.log has not been touched in this window — "
                                f"the orchestrator appears stuck."
                            ),
                            (
                                "Substep 2 must be a SINGLE Bash call to "
                                "`build_threat_model_yaml.py` "
                                "(phase-group-finalization.md:264). If the agent is "
                                "pre-inspecting `.stride-*.json` / `.threats-merged.json` "
                                "or clipping titles, that is a spec violation introduced "
                                "by stale pre-cutover prose in appsec-threat-analyst.md. "
                                "Either: (a) abort and re-run with `--resume` so a "
                                "fresh Stage-1 session picks up the corrected spec, or "
                                "(b) inspect `.agent-run.log` to see what Bash the "
                                "agent issued last and steer it to call the builder directly."
                            ),
                        )
                        substep2_idle_fired = True

        # 7c — global RUN_IDLE detection (all phases).
        #
        # The phase-9 / substep-2 detectors above cover only two narrow
        # windows. Phases 1-10 — including the recon/context phase where the
        # 2026-05-31 juice-shop run lost ~23 min to standard-tier API latency
        # stalls — were unmonitored. This fires a single WARN whenever the run
        # makes no observable progress (no hook-events.log tool activity and no
        # non-watchdog .agent-run.log entry) for `run_idle_seconds`, then
        # re-arms once activity resumes so every distinct stall is surfaced.
        #
        # Deliberately WARN, not the loud `_log_error_loud` escalation used by
        # SUBSTEP2_IDLE: a multi-minute model response is usually slow-but-fine
        # API latency, not a defect. The message tells the user it is almost
        # certainly an API wait, not a hang — which is exactly the question
        # ("is it stuck or still working?") that this signal answers in real
        # time instead of after a 46-min abort. `run_idle_seconds <= 0`
        # disables it (parity with the other --*-seconds knobs).
        if run_idle_seconds > 0:
            idle = _run_idle_seconds(output_dir, run_start_iso)
            if idle >= run_idle_seconds:
                run_idle_peak = max(run_idle_peak, idle)
                if not run_idle_fired:
                    _log(
                        output_dir,
                        "WARN",
                        "RUN_IDLE",
                        f"no run activity for {int(idle)}s (threshold={run_idle_seconds}s) — "
                        f"the run is waiting, almost certainly on a slow model/API response "
                        f"(standard-tier latency), not a hang. A wait past the 5-min cache "
                        f"TTL forces the recovered turn to re-prefill cold. Still watching…",
                    )
                    run_idle_fired = True
            else:
                if run_idle_fired:
                    # Report the PEAK idle (true stall length), not the small
                    # post-resume value — the summary sums these to subtract
                    # API-wait time from wall-clock.
                    _log(
                        output_dir,
                        "INFO",
                        "RUN_RESUMED",
                        f"activity resumed after {int(run_idle_peak)}s idle (this stall)",
                    )
                    run_idle_fired = False
                # Roll the just-ended stall's peak into the cumulative standby
                # total before resetting (adds 0 when no stall was active).
                idle_total += run_idle_peak
                run_idle_peak = 0.0

        # 7d — periodic RUN_PROGRESS line: coarse phase-granular % plus net
        # runtime (wall minus cumulative standby). Best-effort and additive —
        # only emitted for a real, timeable run (``.scan-start-epoch`` present)
        # so unit tests with bare fixtures and pre-checkpoint early phases stay
        # silent. The percentage is intentionally approximate (it jumps at
        # phase boundaries and sits flat through long phases); cost is
        # deliberately NOT shown here — a mid-run total is always an undercount
        # while sub-agents are still running.
        if progress_weights and scan_start_epoch:
            snap = _progress_snapshot(output_dir, progress_weights)
            if snap is not None:
                pct, token = snap
                if pct < last_pct:  # monotonic clamp (resume/incremental)
                    pct = last_pct
                last_pct = pct
                elapsed = time.time() - scan_start_epoch
                idle_now = idle_total + run_idle_peak
                net = elapsed - idle_now
                detail = f"~{pct}%  phase={token}  elapsed={_fmt_hms(elapsed)}  net={_fmt_hms(net)}"
                if idle_now >= 1:
                    detail += f" (standby {_fmt_hms(idle_now)})"
                _log(output_dir, "INFO", "RUN_PROGRESS", detail)

        # 8 — self-liveness tick.
        _bump_tick(output_dir, iteration)

        last_count = sc
        last_bytes = sb
        time.sleep(heartbeat_interval)

    _log(
        output_dir,
        "INFO",
        "WATCHDOG_END",
        f"lock_removed  iter={iteration}  fired_stale={stale_fired}  "
        f"fired_canary={canary_fired}  components_fired={len(component_fired)}",
    )
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="skill_watchdog.py", description=__doc__)
    p.add_argument("output_dir", help="Path to $OUTPUT_DIR (the per-repo docs/security dir).")
    p.add_argument(
        "--plugin-root",
        default=os.environ.get("CLAUDE_PLUGIN_ROOT", ""),
        help="Plugin root (defaults to $CLAUDE_PLUGIN_ROOT).",
    )
    p.add_argument(
        "--heartbeat-interval", type=int, default=60, help="Seconds between heartbeat refreshes (default 60)."
    )
    p.add_argument(
        "--stride-stale-seconds",
        type=int,
        default=900,
        help="Stagnation window before STRIDE_STALE fires (default 900 = 15 min).",
    )
    p.add_argument(
        "--stride-canary-seconds",
        type=int,
        default=180,
        help="Wait after Phase 9 start before STRIDE_CANARY_TIMEOUT (default 180 = 3 min).",
    )
    p.add_argument(
        "--component-timeout-seconds",
        type=int,
        default=480,
        help="Per-component idle limit before STRIDE_COMPONENT_TIMEOUT "
        "(default 480 = 8 min). 0 disables per-component checks.",
    )
    p.add_argument(
        "--substep2-idle-seconds",
        type=int,
        default=int(os.environ.get("APPSEC_SUBSTEP2_IDLE_SECONDS", "300")),
        help="Idle window (seconds since last .agent-run.log update) after a "
        "Phase 11 Substep 2 STEP_START before SUBSTEP2_IDLE fires "
        "(default 300 = 5 min, override via env APPSEC_SUBSTEP2_IDLE_SECONDS). "
        "Set 0 to disable. Catches the 1h 39m stall pattern observed in the "
        "2026-05-25 juice-shop run where the LLM ignored the Substep-2 "
        "single-Bash-call rule and pre-validated intermediates instead.",
    )
    p.add_argument(
        "--run-idle-seconds",
        type=int,
        default=int(os.environ.get("APPSEC_RUN_IDLE_SECONDS", "240")),
        help="Global idle window (seconds with no hook-events.log tool activity "
        "AND no non-watchdog .agent-run.log entry) before a one-shot RUN_IDLE "
        "WARN fires, re-arming after activity resumes. Covers ALL phases — "
        "unlike STRIDE_STALE (Phase 9) and SUBSTEP2_IDLE (Phase 11). Default "
        "240 = 4 min (just under the 5-min prompt-cache TTL, so it warns "
        "before a stall turns into a cold re-prefill). Override via env "
        "APPSEC_RUN_IDLE_SECONDS. Set 0 to disable. Catches the standard-tier "
        "API-latency stalls that cost the 2026-05-31 juice-shop run ~23 min in "
        "the unmonitored recon/context phase.",
    )
    p.add_argument(
        "--max-iterations", type=int, default=None, help="Optional cap on iterations (test hook; not for production)."
    )
    args = p.parse_args(argv[1:])

    plugin_root = Path(args.plugin_root) if args.plugin_root else (Path(__file__).resolve().parent.parent)

    return watch(
        output_dir=Path(args.output_dir).resolve(),
        plugin_root=plugin_root.resolve(),
        heartbeat_interval=args.heartbeat_interval,
        stride_stale_seconds=args.stride_stale_seconds,
        stride_canary_seconds=args.stride_canary_seconds,
        component_timeout_seconds=args.component_timeout_seconds,
        max_iterations=args.max_iterations,
        substep2_idle_seconds=args.substep2_idle_seconds,
        run_idle_seconds=args.run_idle_seconds,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
