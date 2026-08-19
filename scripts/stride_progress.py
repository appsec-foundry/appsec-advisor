#!/usr/bin/env python3
"""
Print a one-line progress summary for STRIDE analyzers running in the background.

Reads `$OUTPUT_DIR/.progress/<component-id>.json` files written by each
`appsec-stride-analyzer-v2` sub-agent and collapses them into a single line
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

from jsonschema import Draft202012Validator, ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stride_outputs import component_id as _stride_component_id  # noqa: E402
from stride_outputs import stride_output_files  # noqa: E402
from write_stride_progress import authoritative_depth  # noqa: E402

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


def _validate_progress_record(output_dir: Path, data: dict, done: bool) -> None:
    """Validate v2 progress identity and reject an obsolete active attempt."""
    if data.get("schema_version") != 2:
        return
    schema = _load(Path(__file__).resolve().parent.parent / "schemas" / "stride-progress.schema.json")
    Draft202012Validator(schema).validate(data)
    waves = _load(output_dir / ".dispatch-waves.json")
    active = waves.get("active_claim") if isinstance(waves, dict) else None
    if not isinstance(active, dict):
        if not done:
            raise ValueError("v2 progress has no dispatch-wave claim")
        return
    component_id = data["component_id"]
    if component_id in (active.get("component_ids") or []):
        if (active.get("attempts") or {}).get(component_id) != data["attempt"]:
            raise ValueError(f"progress attempt contradicts current dispatch claim for {component_id}")


def _depths(output_dir: Path) -> dict[str, str] | None:
    """Validated per-component depths from context plans or the legacy manifest.

    ``build_stride_dispatch_manifest.py`` marks every cheap-stride entry with
    ``cheap_stride: true``, so the tier is known deterministically here — the
    poller never has to infer it from the turn budget. Absent or unreadable
    manifest → ``None``: the tier could not be established, so no entry claims
    one. Printing ``(full)`` there would assert a depth nobody verified.
    """
    context_root = output_dir / ".dispatch-context"
    plans = sorted(context_root.glob("*/context-plan.json")) if context_root.is_dir() else []
    if plans:
        depths: dict[str, str] = {}
        for path in plans:
            plan = _load(path)
            component_id = plan.get("component_id") if isinstance(plan, dict) else None
            if not isinstance(component_id, str) or component_id != path.parent.name:
                raise ValueError(f"invalid component context plan identity: {path}")
            depth = authoritative_depth(output_dir, component_id, Path(__file__).resolve().parent.parent)
            depths[component_id] = depth
        return depths
    manifest = _load(output_dir / ".stride-dispatch-manifest.json")
    components = manifest.get("components") if isinstance(manifest, dict) else None
    if not isinstance(components, list):
        return None
    return {
        str(c.get("component_id")): "light" if c.get("cheap_stride") else "full"
        for c in components
        if isinstance(c, dict) and c.get("component_id")
    }


def _light_ids(output_dir: Path) -> set[str] | None:
    """Compatibility view for callers that only need the legacy light set."""
    try:
        depths = _depths(output_dir)
    except (OSError, ValueError, json.JSONDecodeError, ValidationError) as exc:
        print(f"stride_progress: invalid component context plan: {exc}", file=sys.stderr)
        return None
    return None if depths is None else {component_id for component_id, depth in depths.items() if depth == "light"}


def _tier(comp_id: str, depths: dict[str, str] | set[str] | None) -> str:
    """``(light)`` / ``(full)`` prefix for a component, ``''`` when unknown.

    Both tiers are named so the list reads as a depth column; a lone marked
    entry reads as an anomaly instead of a tier.
    """
    if isinstance(depths, set):
        return "(light) " if comp_id in depths else "(full) "
    if depths is None or depths.get(comp_id) not in {"full", "light"}:
        return ""
    return f"({depths[comp_id]}) "


def _format_entry(data: dict, done: bool, stale: bool, marks: dict, tier: str = "") -> str:
    name = data.get("component_name") or data.get("component_id") or "?"
    # The tier rides with the name so it survives into .appsec-progress.json and
    # from there into watch_run.py — a light-depth component must never read as
    # a full-depth one in any live view.
    name = f"{tier}{name}"
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
    ready_files = stride_output_files(output_dir)
    ready_ids = {_stride_component_id(p) for p in ready_files}

    progress_files = sorted(progress_dir.glob("*.json")) if progress_dir.exists() else []
    now = time.time()
    try:
        depths = _depths(output_dir)
    except (OSError, ValueError, json.JSONDecodeError, ValidationError) as exc:
        print(f"stride_progress: invalid component context plan: {exc}", file=sys.stderr)
        return 2

    entries: list[str] = []
    seen_ids: set[str] = set()
    for pf in progress_files:
        data = _load(pf)
        comp_id = data.get("component_id") or pf.stem
        done = comp_id in ready_ids
        try:
            _validate_progress_record(output_dir, data, done)
        except (ValueError, ValidationError) as exc:
            print(f"stride_progress: invalid progress record: {exc}", file=sys.stderr)
            return 2
        expected_depth = depths.get(comp_id) if depths is not None else None
        if expected_depth is not None and data.get("analysis_depth") not in (None, expected_depth):
            print(f"stride_progress: progress depth contradicts current context plan for {comp_id}", file=sys.stderr)
            return 2
        seen_ids.add(comp_id)
        stale = False
        if not done:
            try:
                mtime = pf.stat().st_mtime
                stale = (now - mtime) > STALE_SECONDS
            except OSError:
                stale = True
        entries.append(_format_entry(data, done=done, stale=stale, marks=marks, tier=_tier(comp_id, depths)))

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
        name = f"{_tier(cid, depths)}{cid}"
        label = f"{name} {marks['done']}"
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
