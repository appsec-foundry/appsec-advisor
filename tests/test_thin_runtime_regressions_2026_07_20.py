"""Regression proofs for the defects surfaced by the 2026-07-20 juice-shop e2e run.

Each test here encodes a defect that the existing suite (72 green tests across the
budget/lazy-load/wave files) did not catch. See
docs/internal/analysis/analysis-thin-runtime-regressions-2026-07-20.md

  D3  instruction files describe script calls in prose the CLI cannot satisfy
  D6  runtime/aggregate_run_issues.py drops AGENT_ERROR / RENDER_FAILED despite promising them
  D8  agent_logger wall_secs is unresolvable across hook process boundaries
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"


# --------------------------------------------------------------------------
# D6 — runtime/aggregate_run_issues.py error matcher vs its own documented contract
# --------------------------------------------------------------------------


def test_error_extractor_matches_documented_event_list() -> None:
    """The module docstring promises four error events; the matcher must accept all.

    2026-07-20: docstring line ~20 lists TOOL_ERROR, MAX_TURNS, RENDER_FAILED,
    AGENT_ERROR, but _extract_errors matched only the first two. A real
    AGENT_ERROR ("evidence-verifier: all sampled findings unchecked") was parsed
    and silently dropped, so the run reported 0 issues.
    """
    src = (SCRIPTS / "runtime/aggregate_run_issues.py").read_text(encoding="utf-8")

    doc = re.search(r"``error``\s+—\s+(.+)", src)
    assert doc, "error-category docstring line not found"
    promised = {tok.strip() for tok in doc.group(1).split(",") if tok.strip()}

    matcher = re.search(r'if event in \((\s*"[A-Z_]+"\s*(?:,\s*"[A-Z_]+"\s*)*),?\):', src)
    assert matcher, "_extract_errors event tuple not found"
    accepted = set(re.findall(r'"([A-Z_]+)"', matcher.group(1)))

    missing = promised - accepted
    assert not missing, (
        f"runtime/aggregate_run_issues.py promises {sorted(promised)} as error events but "
        f"_extract_errors only accepts {sorted(accepted)}; dropped: {sorted(missing)}"
    )


# --------------------------------------------------------------------------
# D8 — cross-process hook state
# --------------------------------------------------------------------------


def test_dispatch_times_survive_hook_process_boundary() -> None:
    """wall_secs must not depend on in-process state.

    hooks.json runs `python3 runtime/agent_logger.py` as a FRESH PROCESS per event, so a
    module-level dict written during dispatch is always empty by the time the
    Stop hook reads it. Observed 2026-07-20: wall_secs=? on 211/211 AGENT_COMPLETE
    trace lines — the trace can never report agent wall-time.
    """
    src = (SCRIPTS / "runtime/agent_logger.py").read_text(encoding="utf-8")

    assert "_DISPATCH_TIMES" in src, "dispatch-time bookkeeping not found"

    # The store must be backed by something that outlives the process. Accept any
    # of the codebase's existing persistence idioms; reject a bare dict literal
    # that is only ever mutated in memory.
    decl = re.search(r"^_DISPATCH_TIMES.*$", src, re.M)
    assert decl, "_DISPATCH_TIMES declaration not found"

    persisted = re.search(
        r"def _dispatch_time_path\(|_DISPATCH_TIMES_FILE|_read_dispatch_times\(",
        src,
    )
    assert persisted, (
        "_DISPATCH_TIMES is an in-process dict but hooks.json spawns a new process "
        "per event (PreToolUse writes it, Stop reads it) — the value is always lost, "
        "so wall_secs resolves to '?' on every AGENT_COMPLETE. It needs a disk-backed "
        "store like the existing _active_tool_path() sidecar pattern."
    )


# --------------------------------------------------------------------------
# D3 — thin-runtime instructions must remain executable, not merely descriptive
# --------------------------------------------------------------------------


def test_thin_runtimes_have_headroom_for_operational_detail() -> None:
    """Budgets must leave room to state a command, or compaction will delete it.

    Every thin surface sat at 93-96% of its ceiling on 2026-07-20, which is what
    forced exact command lines out in favour of prose.

    Scoped to `thin_stage*` until 2026-08-29, which left the tightest surface in
    the set outside it: `thin_full_runtime` reached 13226 of 13250 bytes, so the
    hard ceiling would have failed the next edit with no warning first. The
    warning is the whole point of this test, so it now covers every thin
    runtime.
    """
    import yaml  # noqa: PLC0415

    budgets = yaml.safe_load((REPO_ROOT / "data" / "context-budgets.yaml").read_text())
    tight = []
    for name, spec in budgets.get("surfaces", {}).items():
        if not name.startswith("thin_"):
            continue
        path = REPO_ROOT / spec["path"]
        if not path.is_file() or "max_bytes" not in spec:
            continue
        pct = path.stat().st_size * 100 / spec["max_bytes"]
        if pct > 90:
            tight.append(f"{name}: {pct:.0f}% of {spec['max_bytes']}B")
    assert not tight, (
        "thin runtime surfaces are at/over 90% of budget, leaving no room to restore "
        "the exact script invocations that compaction removed: " + "; ".join(tight)
    )
