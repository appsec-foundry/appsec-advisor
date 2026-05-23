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
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Reuse the central phase budgets so per-component-timeout defaults stay
# in sync with the rest of the toolchain.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import phase_budgets  # type: ignore
except Exception:  # pragma: no cover
    phase_budgets = None  # type: ignore[assignment]


_LOG_NAME = ".agent-run.log"
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
        sid = "-" * 8  # not a hook context
        line = f"{_ts_now()}  [{sid}]  {level:<5}  {_AGENT_NAME}  {event:<24}  {detail}\n"
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass


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


def watch(
    output_dir: Path,
    plugin_root: Path,
    heartbeat_interval: int,
    stride_stale_seconds: int,
    stride_canary_seconds: int,
    component_timeout_seconds: int,
    max_iterations: int | None,
) -> int:
    lock_path = output_dir / ".appsec-lock"
    if not output_dir.is_dir():
        sys.stderr.write(f"output_dir not found: {output_dir}\n")
        return 2

    _log(
        output_dir,
        "INFO",
        "WATCHDOG_START",
        f"interval={heartbeat_interval}s  "
        f"stride_stale={stride_stale_seconds}s  "
        f"canary={stride_canary_seconds}s  "
        f"component_timeout={component_timeout_seconds}s",
    )

    last_count = 0
    last_bytes = 0
    stagnant_seconds = 0
    phase9_detected = False
    phase9_start: float | None = None
    canary_fired = False
    stale_fired = False
    component_fired: set[str] = set()
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

        # 4 — STRIDE progress mirror line (silent once stagnation has fired).
        if (sc > 0 or pg > 0) and not stale_fired:
            _log(output_dir, "INFO", "STRIDE_PROGRESS", f"stride_files={sc}  total_bytes={sb}  progress_files={pg}")

        # 5 — stagnation tracking (only after Phase 9 has started, and only
        # while Phase 9 is still the active phase. Once the orchestrator
        # advances past STRIDE — observable via .appsec-checkpoint reading
        # `phase=10`, `phase=11`, `phase=repair/*`, or any non-9 marker —
        # the .stride-*.json files are intentionally frozen and a flat
        # progress curve is the expected state, not a hang.)
        past_stride = _is_past_stride_phase(output_dir)
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
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
