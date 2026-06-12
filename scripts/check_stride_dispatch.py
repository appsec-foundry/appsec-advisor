#!/usr/bin/env python3
"""Hard gate that detects the Phase-9 STRIDE inline-shortcut bypass.

Exit codes
----------
0   No bypass detected. STRIDE was dispatched to sub-agents (or every
    component is a trivial stub / carry-forward). Skill may proceed.
2   Inline-shortcut detected — the orchestrator authored one or more
    real ``.stride-<id>.json`` files itself instead of dispatching the
    ``appsec-stride-analyzer`` sub-agents the design mandates.
3   Tool error (bad path).

Why this script exists
----------------------
``agents/phases/phase-group-threats.md`` instructs the orchestrator to
dispatch one parallel ``appsec-stride-analyzer`` background sub-agent per
component (``run_in_background: true``). Each dispatched analyzer writes a
per-component progress file ``$OUTPUT_DIR/.progress/<component-id>.json``
via ``agent_progress.sh`` at the start of every substep.

Under turn-budget pressure the orchestrator sometimes ignores that
instruction and performs the STRIDE analysis **inline** — writing the
``.stride-<id>.json`` files itself with ``cat >`` Bash calls and issuing
zero ``Agent`` tool calls. The 2026-06-02 juice-shop run was the canonical
case: 5 components, 0 Agent dispatches, ``.progress/`` empty, all five
analyses collapsed into one ~182k-token serial context. A single
standard-tier API stall on that fat context then froze the entire phase
for 23 minutes.

This is the same class of failure as the Phase-11 rendering
inline-shortcut already guarded by ``check_inline_shortcut.py``: a "soft"
LLM instruction that occasionally gets talked around. Promoting the
detection to a stand-alone Python script with a hard exit code makes the
gate mechanical — ``|| exit $?`` cannot be re-interpreted.

Detection signal
----------------
A ``.stride-<id>.json`` carrying **real** threats (i.e. not a trivial-skip
stub and not empty) but with **no** matching ``.progress/<id>.json`` was
produced without dispatching the analyzer — the only writer of progress
files.

Positive dispatch evidence that suppresses the signal is **count-based**:
at least as many dispatched ``appsec-stride-analyzer`` analyzers in
``.hook-events.log`` as the ``.stride-dispatch-manifest.json`` planned
components (or, with no manifest, any dispatch). A dispatch is proven by
EITHER an ``AGENT_SPAWN`` (PreToolUse) OR an ``AGENT_INVOKE`` (PostToolUse)
line — both are emitted per analyzer, and the harness occasionally logs only
one of the pair, so counting both (deduped by ``COMPONENT_ID``) avoids the
false-trip seen on 2026-06-12 (1 SPAWN + 4 INVOKE for a real 4-way fan-out).
The manifest's *mere
existence* is deliberately NOT proof — it is written by
``build_stride_dispatch_manifest.py`` from Analyst-A's output *before* the
skill fans the analyzers out, so it survives the exact inline-collapse this
gate guards (manifest built, fan-out skipped, ``.stride-*.json`` hand-written
with no ``.progress/``). Treating manifest-existence as proof (pre-2026-06-05)
silently disabled this gate across the whole default parallel path.

The check is intentionally narrow so it never false-positives on:

  * **Trivial-component stubs (M24)** — written inline by design with a
    single ``"trivial-component, no detailed STRIDE performed"``
    placeholder threat. Excluded by the stub marker.
  * **Empty / partial wrap-ups** — ``{"threats": []}``. No real work to
    attribute, excluded.
  * **Incremental carry-forward** — a reused ``.stride-<id>.json`` has no
    fresh progress file by design. The whole gate is skipped when
    ``--incremental`` is passed (carry-forward makes progress-file absence
    ambiguous).

Timing
------
Run from the skill's **Phase-10b precondition gate** (after Stage 1
returns, before Stage 2). ``.progress/`` lives in ``runtime_cleanup.py``'s
``ALWAYS_DIRS`` and is only reaped at the ``pre-qa`` stage, which runs
after this gate — so the per-component progress files are still on disk
when this script runs.

Usage
-----
    python3 scripts/check_stride_dispatch.py <output-dir> [--incremental]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Extracts the dispatched component from a hook line's trailing
# ``[… COMPONENT_ID=<id> …]`` payload. Both AGENT_SPAWN and AGENT_INVOKE
# carry it (agent_logger.py propagates COMPONENT_ID into the pair block).
_COMPONENT_ID_RE = re.compile(r"COMPONENT_ID=([^\s\]]+)")

# A threat is a trivial-skip stub placeholder when its text carries this
# marker (see phase-group-threats.md "Trivial-component skip (M24)").
_STUB_MARKERS = ("trivial-component", "no detailed stride")


def _is_stub_threat(threat: dict) -> bool:
    """True when a single threat is the M24 trivial-component placeholder."""
    blob = " ".join(
        str(threat.get(k, "")) for k in ("title", "description", "skip_reason", "resolution_reason")
    ).lower()
    return any(marker in blob for marker in _STUB_MARKERS)


def _component_id(stride_path: Path) -> str:
    """`.stride-backend-api.json` -> `backend-api`."""
    name = stride_path.name
    return name[len(".stride-") : -len(".json")]


def _stride_has_real_threats(stride_path: Path) -> bool:
    """True when the file carries at least one non-stub threat.

    A malformed / unreadable file is treated as *not* real — a malformed
    intermediate is a separate problem the downstream builder catches; this
    gate only fires on a confidently-inlined real analysis.
    """
    try:
        data = json.loads(stride_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    threats = data.get("threats")
    if not isinstance(threats, list) or not threats:
        return False
    return any(isinstance(t, dict) and not _is_stub_threat(t) for t in threats)


def _stride_dispatch_evidence_count(output_dir: Path, since: str | None = None) -> int:
    """How many distinct ``appsec-stride-analyzer`` dispatches the hook log proves.

    Each dispatched analyzer emits BOTH an ``AGENT_SPAWN`` (PreToolUse) and an
    ``AGENT_INVOKE`` (PostToolUse) line to ``.hook-events.log``
    (``scripts/agent_logger.py``). Counting *only* ``AGENT_SPAWN`` (the
    pre-2026-06-12 behaviour) under-reported whenever the harness logged the
    PostToolUse hook but dropped the PreToolUse one for some dispatches — the
    2026-06-12 juice-shop run logged 1 ``AGENT_SPAWN`` but 4 ``AGENT_INVOKE`` for
    a genuinely-parallel 4-component fan-out, so the gate under-counted (1 < 4),
    fell through to ``.progress``, and false-tripped on the two components whose
    analyzer happened not to write a progress file.

    Both event types are equally conclusive dispatch proof, so this counts the
    union. To avoid double-counting the SPAWN+INVOKE pair of the same dispatch it
    dedupes by ``COMPONENT_ID`` when the lines carry it (the parallel fan-out
    always passes ``COMPONENT_ID=<id>``); when no component id is parseable
    (serial / legacy lines) it falls back to ``max(spawn_lines, invoke_lines)``,
    which is the true dispatch count without double-counting the pair.

    ``.hook-events.log`` is **append-only across runs**, so a prior run's
    dispatches linger. ``since`` (the manifest's ``generated_at``, written in
    step 3b immediately *before* this run's fan-out) bounds the count to the
    current run: every legitimate dispatch line carries a leading timestamp
    ``>= since``. ISO-8601 Zulu is fixed-width, so lexicographic compare ==
    chronological. Without ``since`` (no manifest) all matching lines count.
    """
    try:
        text = (output_dir / ".hook-events.log").read_text(encoding="utf-8")
    except OSError:
        return 0
    component_ids: set[str] = set()
    spawn_lines = 0
    invoke_lines = 0
    for line in text.splitlines():
        if "appsec-stride-analyzer" not in line:
            continue
        is_spawn = "AGENT_SPAWN" in line
        is_invoke = "AGENT_INVOKE" in line
        if not (is_spawn or is_invoke):
            continue
        if since is not None:
            ts = line.split("  ", 1)[0].strip()
            if ts < since:
                continue  # stale dispatch from an earlier run — not this run's
        if is_spawn:
            spawn_lines += 1
        if is_invoke:
            invoke_lines += 1
        m = _COMPONENT_ID_RE.search(line)
        if m:
            component_ids.add(m.group(1))
    if component_ids:
        return len(component_ids)
    return max(spawn_lines, invoke_lines)


# Back-compat alias — older callers / tests referenced the spawn-only name.
_stride_analyzer_spawn_count = _stride_dispatch_evidence_count


def _read_manifest(output_dir: Path) -> dict:
    """Parse ``.stride-dispatch-manifest.json`` (``{}`` when absent/unreadable)."""
    try:
        data = json.loads((output_dir / ".stride-dispatch-manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _stride_was_dispatched(output_dir: Path) -> bool:
    """Conclusive, **count-based** proof the STRIDE fan-out actually fired.

    The dispatch manifest alone is NOT proof. ``build_stride_dispatch_manifest.py``
    writes it from Analyst-A's output (``.components.json`` etc.) *before* the
    skill fans out the analyzers, so it exists even when the orchestrator then
    inlines STRIDE instead of dispatching — the exact Phase-9 collapse this gate
    guards (manifest built in step 3b, fan-out 3c skipped, ``.stride-*.json``
    hand-written with no ``.progress/``). Trusting manifest existence alone (the
    pre-2026-06-05 behaviour) disabled this gate for the entire default parallel
    path.

    Real proof is the ``AGENT_SPAWN`` evidence: at least as many dispatched
    ``appsec-stride-analyzer`` calls as the manifest planned (``>=`` because a
    re-dispatch on failure only adds spawns). When the manifest is absent
    (serial / live / opt-out path) any spawn is still a positive signal.

    When there is NOT enough spawn evidence this returns ``False`` and the caller
    does NOT globally trust it — it falls through to the per-component
    ``.progress`` check, which is the per-component safety net that BOTH the
    dispatched analyzer and the sanctioned serial-inline analyst write (see
    ``appsec-threat-analyst.md`` §"Reality check" + ``phase-group-threats.md``).
    So a genuinely-parallel run whose hooks happened not to log still passes on
    its ``.progress/`` files; only a real inline-collapse (no spawns AND no
    ``.progress/``) trips.
    """
    manifest = _read_manifest(output_dir)
    comps = manifest.get("components")
    expected = len(comps) if isinstance(comps, list) else 0
    if expected > 0:
        # Bound the spawn count to this run via the manifest's own timestamp —
        # the fan-out reads the manifest, so every real spawn is at-or-after it.
        since = manifest.get("generated_at")
        return _stride_dispatch_evidence_count(output_dir, since=since) >= expected
    return _stride_dispatch_evidence_count(output_dir) > 0


def detect_inlined_components(output_dir: Path) -> list[str]:
    """Return component ids whose STRIDE analysis was inlined.

    A component is inlined when its ``.stride-<id>.json`` has real threats
    but no ``.progress/<id>.json`` exists. Empty list = clean.

    Globally suppressed only when there is *count-based* dispatch evidence
    (``_stride_was_dispatched`` — enough dispatched ``appsec-stride-analyzer``
    spawns to cover the manifest). A manifest WITHOUT matching spawns is NOT
    suppression evidence: it is written before the fan-out and survives an
    inline-collapse, so it falls through to the per-component ``.progress``
    check here.
    """
    if _stride_was_dispatched(output_dir):
        return []
    progress_dir = output_dir / ".progress"
    inlined: list[str] = []
    for stride_path in sorted(output_dir.glob(".stride-*.json")):
        cid = _component_id(stride_path)
        if not _stride_has_real_threats(stride_path):
            continue  # stub or empty — legitimately inline / no work
        if not (progress_dir / f"{cid}.json").is_file():
            inlined.append(cid)
    return inlined


def _print_banner(inlined: list[str], output_dir: Path) -> None:
    bar = "═" * 62
    print("", file=sys.stderr)
    print(bar, file=sys.stderr)
    print("  ASSESSMENT DEGRADED — STRIDE inline-shortcut detected", file=sys.stderr)
    print(bar, file=sys.stderr)
    print("", file=sys.stderr)
    print("  Phase 9 produced real .stride-<id>.json files without", file=sys.stderr)
    print("  dispatching the appsec-stride-analyzer sub-agents. The", file=sys.stderr)
    print("  following components were analyzed INLINE (no .progress/", file=sys.stderr)
    print("  file — the only writer of which is a dispatched analyzer):", file=sys.stderr)
    print("", file=sys.stderr)
    for cid in inlined:
        print(f"    • {cid}", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Why this matters: inlining collapses every component into one", file=sys.stderr)
    print("  large serial orchestrator context. That context is slow and", file=sys.stderr)
    print("  expensive per turn, serializes work that should run in", file=sys.stderr)
    print("  parallel, and — most damaging — turns a single standard-tier", file=sys.stderr)
    print("  API request stall into a phase-wide freeze (the per-component", file=sys.stderr)
    print("  watchdog is blind because no .progress/ files exist).", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Fix: re-run the assessment. The orchestrator MUST issue one", file=sys.stderr)
    print("  Agent tool call per component (run_in_background: true) — see", file=sys.stderr)
    print("  phase-group-threats.md → 'STRIDE dispatch is mandatory'. If", file=sys.stderr)
    print("  this reproduces, the Phase-9 dispatch rule needs enforcing", file=sys.stderr)
    print("  harder in the orchestrator prompt.", file=sys.stderr)
    print(bar, file=sys.stderr)
    print("", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_stride_dispatch.py",
        description="Hard gate detecting the Phase-9 STRIDE inline-shortcut bypass.",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Assessment output directory (typically <repo>/docs/security).",
    )
    parser.add_argument(
        "--incremental",
        action="store_true",
        help="Skip the gate (exit 0). In incremental mode a carry-forward "
        ".stride-<id>.json legitimately has no fresh .progress/ file, so "
        "progress-file absence is not a reliable inline signal.",
    )
    args = parser.parse_args(argv)

    output_dir: Path = args.output_dir
    if not output_dir.is_dir():
        print(f"Error: output directory does not exist: {output_dir}", file=sys.stderr)
        return 3

    if args.incremental:
        return 0  # carry-forward makes the signal ambiguous — not applicable.

    inlined = detect_inlined_components(output_dir)
    if not inlined:
        return 0

    _print_banner(inlined, output_dir)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
