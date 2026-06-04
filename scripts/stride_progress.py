#!/usr/bin/env python3
"""
Print a one-line progress summary for STRIDE analyzers running in the background.

Reads `$OUTPUT_DIR/.progress/<component-id>.json` files written by each
`appsec-stride-analyzer` sub-agent and collapses them into a single line
showing current step/label per component plus an overall "K/N ready" counter.

Exits 0 when all `EXPECTED` `.stride-<component-id>.json` output files are
present (so the orchestrator's poll loop can terminate), exits 1 otherwise.

Noise control
-------------
Called every ~20 s from the orchestrator's poll loop. To keep the console
readable on long Phase 9 runs, the tool remembers the last printed line
in `$OUTPUT_DIR/.progress/.last-print` and **suppresses re-prints when the
state has not changed**. A heartbeat is emitted every `HEARTBEAT_TICKS`
unchanged polls so the user still sees a pulse. Pass `--force` to disable
the dedup.

Emoji fallback
--------------
Progress markers default to unicode (`✓`, `⧗`). On non-TTY stderr (CI log
files, redirected output) ASCII fallbacks (`[done]`, `[stale]`) are used
so plain-text consumers render cleanly.

Usage:
    stride_progress.py <output_dir> <expected_count> [--force]

Designed to be called from the orchestrator's Phase 9 poll loop:

    while ! python3 stride_progress.py "$OUTPUT_DIR" "$N" >&2; do sleep 20; done
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

STALE_SECONDS = 180  # progress file is considered stale after 3 minutes
HEARTBEAT_TICKS = 6  # force a reprint every N unchanged polls (~2 min at 20 s cadence)


def _use_unicode() -> bool:
    """True when stderr is a TTY and its encoding can handle unicode markers.

    Falls back to ASCII markers on redirected/CI stderr so pipelines and log
    files do not accumulate mojibake.
    """
    try:
        if not sys.stderr.isatty():
            return False
        enc = (sys.stderr.encoding or "").lower()
        return "utf" in enc
    except Exception:
        return False


def _markers() -> dict:
    if _use_unicode():
        return {"done": "✓", "stale": "⧗", "bullet": "·"}
    return {"done": "[done]", "stale": "[stale]", "bullet": "-"}


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _format_entry(data: dict, done: bool, stale: bool, marks: dict) -> str:
    name = data.get("component_name") or data.get("component_id") or "?"
    if done:
        return f"{name} {marks['done']}"
    step = data.get("step")
    total = data.get("total")
    label = (data.get("label") or "").strip()
    if step and total:
        core = f"{name} [{step}/{total}"
        if label:
            core += f" {label}"
        core += "]"
    else:
        core = f"{name} [starting]"
    if stale:
        core += f" {marks['stale']}"
    return core


def _read_last(progress_dir: Path) -> tuple[str, int]:
    """Return (last_block, unchanged_count). Defaults to ('', 0).

    The unchanged-count is stored on the first line so the remembered block
    may itself span multiple lines (the vertical per-component layout).
    """
    state = progress_dir / ".last-print"
    try:
        count_str, _, body = state.read_text(encoding="utf-8").partition("\n")
        return body.rstrip("\n"), int(count_str)
    except (OSError, ValueError):
        pass
    return "", 0


def _write_last(progress_dir: Path, line: str, unchanged: int) -> None:
    state = progress_dir / ".last-print"
    try:
        progress_dir.mkdir(parents=True, exist_ok=True)
        state.write_text(f"{unchanged}\n{line}\n", encoding="utf-8")
    except OSError:
        pass


def _write_appsec_progress(output_dir: Path, ready: int, expected: int, entries: list[str]) -> None:
    """Mirror the collapsed STRIDE line into ``.appsec-progress.json``.

    Bridges the rich ``.progress/*.json`` channel into the file that the
    streaming watcher (``watch_run.py``) tails. Without this, a user tailing
    ``watch_run.py`` during Phase 9 sees only ``phase=9`` and the one-shot
    "dispatching N analyzers" line — never the live per-component substep
    pulse (``authn [4/9 Tampering]``). Shape matches ``log_event.py``'s
    payload so ``watch_run._read_progress_state`` renders phase/step/label.
    """
    payload = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "STRIDE_PROGRESS",
        "kind": "step-start",
        "agent": "stride-analyzer",
        "phase": "9",
        "phase_total": "11",
        "step": ready,
        "step_total": expected,
        "label": " · ".join(entries) if entries else "dispatching analyzers",
        "status": "step_completed" if ready >= expected else "step_started",
    }
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / ".appsec-progress.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError:
        pass


def main(argv: list[str]) -> int:
    force = "--force" in argv
    args = [a for a in argv[1:] if a != "--force"]
    if len(args) != 2:
        print("usage: stride_progress.py <output_dir> <expected_count> [--force]", file=sys.stderr)
        return 2

    output_dir = Path(args[0])
    try:
        expected = int(args[1])
    except ValueError:
        print(f"invalid expected count: {args[1]}", file=sys.stderr)
        return 2

    marks = _markers()
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
        entries.append(_format_entry(data, done=done, stale=stale, marks=marks))

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
        label = f"{cid} {marks['done']}"
        if stale:
            label += f" {marks['stale']} (no progress file — may be stale)"
        entries.append(label)

    ready = len(ready_ids)
    header = f"[stride] {ready}/{expected} ready"
    if entries:
        # One line per component, mirroring the foreground multi-agent progress
        # widget's vertical layout instead of a single dense bullet-joined line.
        body = "\n".join(f"  {marks['bullet']} {e}" for e in entries)
        line = f"{header}\n{body}"
    else:
        line = f"{header}  {marks['bullet']}{marks['bullet']}  (no progress reported yet)"

    # Dedup: suppress if identical to last print unless heartbeat or --force.
    last_line, unchanged = _read_last(progress_dir)
    should_emit = force or line != last_line or unchanged >= HEARTBEAT_TICKS

    if should_emit:
        print(line)
        _write_last(progress_dir, line, 0)
        _write_appsec_progress(output_dir, ready, expected, entries)
    else:
        _write_last(progress_dir, last_line, unchanged + 1)

    return 0 if ready >= expected else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
