#!/usr/bin/env python3
"""Wall-clock duration estimator for ``/appsec-advisor:create-threat-model``.

The skill prints a Stage-1 banner like::

    ▶ Stage 1/2 — Threat Analysis & Triage starting  (expect ~25 min)

Earlier versions of that banner used a single hardcoded number per
``ASSESSMENT_DEPTH`` (`15` / `25` / `40`) regardless of mode, repo size,
prior measurements, reasoning model, or which stages were enabled.
Empirical runs on `juice-shop` (see `.run-observations-*.md`) showed the
actual wall-clock was 36–44 min for `standard --full`, i.e. **+50 %**
beyond the user's mental expectation, and the spread depends strongly on
factors the banner ignored.

This helper aggregates **everything we already know** at banner-print
time (no LLM call, no agent dispatch, only files the skill is already
reading) into a single per-stage breakdown plus a total. The skill
invokes it once via Bash, parses the JSON, and renders the banner.

Estimation source priority:

  1. ``last_run_cache`` — ``.appsec-cache/baseline.json::last_run_*``
     fields (written at the end of every successful run). Same repo,
     same mode → use the prior measurement directly. Most accurate.
  2. ``resume_checkpoint`` — ``.appsec-checkpoint`` exists and we are
     in ``--resume`` mode → estimate remaining phases only.
  3. ``incremental_dirty_set`` — ``--incremental`` mode → scale the
     parametric estimate by ``SEC_CHANGE_COUNT / MAX_STRIDE_COMPONENTS``
     (Phase 9 dominates and only the dirty subset re-runs).
  4. ``parametric`` — fallback: ``base[depth] × size_factor ×
     model_factor + composition + qa + architect + transition_buffer``.

Output: a single JSON object on stdout. Exit 0 on success; exit 0 with
``"source": "fallback"`` on any error so the caller can still print a
sensible banner.

Token cost: 1 Bash invocation, single-line numeric output (~80 tokens).
Wall-clock cost: ≤ 100 ms (one ``git ls-files | wc -l`` on cache miss,
~3 file reads on hit).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Calibration constants — kept module-level so they're cheap to tweak when
# new run observations land. All values in MINUTES.
# ---------------------------------------------------------------------------

# Stage 1 (Phases 1–10b) base time per assessment depth, calibrated
# against juice-shop observations (24m–27m for standard).
# quick=20 calibrated 2026-04-28: Phase 1 (5m) + Phase 2 (5m parallel) +
# Phases 3-8 (5m) + Phase 9 STRIDE×3 (4m) + Phase 10/10b (2m) ≈ 21m total.
_STAGE1_BASE: dict[str, float] = {
    "quick": 20.0,
    "standard": 25.0,
    "thorough": 40.0,
}

# Stage 2 (Phase 11 Composition) — gained its own 120-turn budget in
# M2.12. Empirical: 8m 24s on juice-shop standard.
# quick=9 calibrated 2026-04-28: Stage 2 ran 14m when Stage 1 stopped at
# 10b and Stage 2 had to produce all Phase-11 fragments from scratch
# (RENDER_ONLY=false path). Normal quick path (fragments already authored
# inline) is ~6m. 9m splits the difference conservatively.
_STAGE2_COMPOSITION: dict[str, float] = {
    "quick": 9.0,
    "standard": 8.0,
    "thorough": 11.0,
}

# Stage 3 QA — empirical 7–8 min on juice-shop. Hardcoded banner says
# 5 min; real observations are consistently +40 %.
_STAGE3_QA: dict[str, float] = {
    "quick": 4.0,
    "standard": 7.0,
    "thorough": 9.0,
}

# Stage 4 Architect Review (Opus) — auto-on at thorough.
_STAGE4_ARCHITECT: dict[str, float] = {
    "quick": 3.0,
    "standard": 4.0,
    "thorough": 6.0,
}

# Stage 1c — Abuse-case verifier fan-out. A separate skill-level dispatch
# that runs after Phase 10b and before Stage 2 (single-pass sonnet, wall-clock
# ≈ slowest verifier). Default-on at standard/thorough, off at quick. ~5 min
# observed on juice-shop standard (2026-06). Gated by --skip-abuse-cases so
# `--no-abuse-cases` zeroes it; quick is 0 because abuse is off there by
# default and the estimator is not told about the rare --abuse-cases override.
_STAGE1C_ABUSE: dict[str, float] = {
    "quick": 0.0,
    "standard": 5.0,
    "thorough": 6.0,
}

# Skill-layer transition buffer — pre-flight wipe, task-list bootstrap,
# stage hand-offs, completion summary. Empirical: ~5 min unaccounted
# wall-clock summed across the run.
_TRANSITION_BUFFER = 4.0

# Reasoning-model multiplier on Stage 1 (STRIDE + triage).
_MODEL_FACTOR: dict[str, float] = {
    "sonnet": 1.0,
    "opus-cheap": 1.05,  # Opus only on threat-merger (triage downgraded to Sonnet)
    "opus": 1.40,  # Opus also on STRIDE analyzers
}


# Repo-size factor against the juice-shop baseline (~1k files,
# ~50k LOC, 5 components → factor 1.0). Boundaries are loose because
# we have only one calibration data point; better numbers will land
# when we have measurements from a larger and a smaller repo.
def _size_factor_from_files(n_files: int) -> float:
    # Calibration data point: juice-shop = 1399 git-tracked files, observed
    # Stage 1 wall-clock ≈ 24 min vs the 25 min standard base → factor 1.0.
    # The 1.0× bucket therefore extends well beyond the previous 1k cap.
    if n_files < 200:
        return 0.6  # demo apps, single libraries, < 5k LOC
    if n_files < 2_500:
        return 1.0  # typical web app (juice-shop fits here)
    if n_files < 10_000:
        return 1.5  # large monorepo with multiple services
    return 2.0  # very large monorepo (50k+ files)


# Per-phase remaining time for `--resume`. Index = phase id from
# `.appsec-checkpoint`. Sum across phase >= checkpoint phase is the
# remaining-time estimate.
_PHASE_DURATION: dict[str, dict[int, float]] = {
    "quick": {
        # Calibrated 2026-04-28 juice-shop run (without double-dispatch bug):
        # Phase 1 ≈ 5m (context-resolver), Phase 2 ≈ 5m (recon-scanner, parallel),
        # Phase 9 ≈ 4m (3 components × ~1m each, parallel STRIDE), Phase 10b ≈ 2m.
        1: 0.5,
        2: 5.0,
        3: 0.5,
        4: 0.5,
        5: 0.3,
        6: 0.3,
        7: 0.5,
        8: 1.0,
        9: 4.0,
        10: 0.3,
        11: 0.5,
    },
    "standard": {
        1: 1.0,
        2: 4.0,
        3: 1.0,
        4: 1.0,
        5: 0.5,
        6: 0.5,
        7: 1.0,
        8: 2.0,
        9: 15.0,
        10: 0.5,
        11: 1.0,
    },
    "thorough": {
        1: 1.5,
        2: 6.0,
        3: 2.0,
        4: 2.0,
        5: 1.0,
        6: 1.0,
        7: 1.5,
        8: 3.0,
        9: 25.0,
        10: 0.5,
        11: 1.5,
    },
}


# ---------------------------------------------------------------------------
# Input helpers — every function is allowed to fail silently. The
# fallback path always produces SOME number.
# ---------------------------------------------------------------------------


def _try_read_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _count_repo_files(repo_root: Path) -> int:
    """Cheap repo-file count. Prefers ``git ls-files`` (~50 ms on a
    50k-file monorepo). Falls back to ``find`` when not a git repo.
    Returns 0 on any error so the caller falls back to size_factor=1.0.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0 and out.stdout:
            return out.stdout.count("\n")
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    # Fallback: find. Bounded to maxdepth 6 to avoid pathological dirs.
    try:
        result = subprocess.run(
            [
                "find",
                str(repo_root),
                "-maxdepth",
                "6",
                "-type",
                "f",
                "-not",
                "-path",
                "*/.git/*",
                "-not",
                "-path",
                "*/node_modules/*",
                "-not",
                "-path",
                "*/vendor/*",
                "-not",
                "-path",
                "*/dist/*",
                "-not",
                "-path",
                "*/build/*",
                "-not",
                "-path",
                "*/.venv/*",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            return result.stdout.count("\n")
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass
    return 0


# ---------------------------------------------------------------------------
# Estimation strategies — each returns (per-stage dict, source-tag) or
# None when its preconditions don't match.
# ---------------------------------------------------------------------------


def _last_run_cache(output_dir: Path, mode: str, depth: str) -> tuple[dict[str, float], str] | None:
    """Highest-priority source: the last successful run on the SAME repo
    in the SAME mode & depth wrote its wall-clock. We replay that.

    M5 enhancement: when component_durations is present in baseline.json,
    use the per-component sum as a Phase-9 estimator. The remaining
    Stage 1 (Phase 1-8 + 10b) takes ~10 min on standard, ~6 min on quick.
    This makes the estimate Phase-9-aware without needing per-phase splits.
    """
    cache = _try_read_json(output_dir / ".appsec-cache" / "baseline.json")
    if not cache:
        return None
    last_seconds = cache.get("last_run_seconds")
    last_mode = (cache.get("last_run_mode") or "").lower()
    last_depth = (cache.get("last_run_depth") or "").lower()
    if not isinstance(last_seconds, (int, float)) or last_seconds <= 0:
        return None
    if last_mode and last_mode != mode:
        return None
    if last_depth and last_depth != depth:
        return None
    total_min = last_seconds / 60.0
    # We don't know the per-stage split from the cache alone — emit it
    # as a single "total" line and zero out the synthetic stages so the
    # caller can show "expected ~N min (from last run)".
    return (
        {"stage1": 0.0, "stage2": 0.0, "stage3": 0.0, "stage4": 0.0, "transition": 0.0, "total": total_min},
        "last_run_cache",
    )


def _component_durations_estimate(
    output_dir: Path, depth: str, max_components: int
) -> tuple[dict[str, float], str] | None:
    """M5 — Phase-9 estimate based on per-component last-run durations.

    Used as a SECONDARY source: lower priority than full last_run_cache
    (which captures total wall-clock), but higher priority than parametric.
    Returns a "phase 9 only" dict; the caller layers Phase 1-8/10b/11
    parametric estimates on top.

    Strategy: take the largest N component durations (where N matches the
    current MAX_STRIDE_COMPONENTS). Phase 9 wall-clock ≈ max(durations) +
    ~30s merge overhead, NOT the sum (sub-agents run in parallel).
    """
    cache = _try_read_json(output_dir / ".appsec-cache" / "baseline.json")
    if not cache:
        return None
    durations = cache.get("component_durations")
    if not isinstance(durations, dict) or not durations:
        return None
    # Take the top-N longest from the prior run as the proxy.
    sorted_secs = sorted(durations.values(), reverse=True)
    top_secs = sorted_secs[:max_components]
    if not top_secs:
        return None
    # Phase 9 wall-clock = max(top_secs) (parallel) + 30s merge overhead.
    phase_9_seconds = max(top_secs) + 30
    # Phase 1-8 + Phase 10b parametric: ~7 min standard, ~5 min quick, ~10 min thorough.
    phase_other_seconds = {"quick": 300, "standard": 420, "thorough": 600}.get(depth, 420)
    stage1_min = (phase_9_seconds + phase_other_seconds) / 60.0
    return (
        {
            "stage1": stage1_min,
            "stage2": 6.0,
            "stage3": 5.0,
            "stage4": 0.0,
            "transition": 2.0,
            "total": stage1_min + 13.0,
        },
        "component_durations",
    )


def _resume_remaining(output_dir: Path, depth: str) -> tuple[dict[str, float], str] | None:
    """`--resume` re-enters at the last completed phase. Sum of remaining
    phase budgets is the estimate."""
    checkpoint = _try_read_json(output_dir / ".appsec-checkpoint")
    if not checkpoint:
        # The file is also written as plain "phase=N status=..." — try parsing.
        cp_path = output_dir / ".appsec-checkpoint"
        if not cp_path.is_file():
            return None
        try:
            text = cp_path.read_text(encoding="utf-8").strip()
            phase_n = None
            for tok in text.replace(",", " ").split():
                if tok.startswith("phase="):
                    phase_n = int(tok.split("=", 1)[1])
                    break
            if phase_n is None:
                return None
        except (OSError, ValueError):
            return None
    else:
        try:
            phase_n = int(checkpoint.get("phase") or 0)
        except (TypeError, ValueError):
            return None
    if phase_n <= 0 or phase_n > 11:
        return None
    table = _PHASE_DURATION.get(depth, _PHASE_DURATION["standard"])
    remaining = sum(v for k, v in table.items() if k >= phase_n)
    # Plus the downstream stages — they always re-run from scratch on resume.
    return (
        {
            "stage1": remaining,
            "stage2": _STAGE2_COMPOSITION[depth],
            "stage3": _STAGE3_QA[depth],
            "stage4": 0.0,
            "transition": _TRANSITION_BUFFER,
            "total": remaining + _STAGE2_COMPOSITION[depth] + _STAGE3_QA[depth] + _TRANSITION_BUFFER,
        },
        "resume_checkpoint",
    )


def _incremental_dirty_set(
    depth: str, sec_change_count: int, max_components: int
) -> tuple[dict[str, float], str] | None:
    """`--incremental` runs Phase 9 only on dirty components; everything
    else runs full. Scale Phase 9 by the dirty-set ratio.
    """
    if sec_change_count <= 0 or max_components <= 0:
        return None
    dirty_ratio = min(1.0, sec_change_count / max_components)
    phase9 = _PHASE_DURATION[depth][9] * dirty_ratio
    # Phases 1, 2, 10b run roughly full (recon must scan the whole repo
    # to determine the dirty-set); 3–8 run partial because architecture
    # only re-evaluates changed components.
    other_stage1 = (
        _PHASE_DURATION[depth][1]
        + _PHASE_DURATION[depth][2]
        + _PHASE_DURATION[depth][10]
        + _PHASE_DURATION[depth][3] * 0.5
        + _PHASE_DURATION[depth][4] * 0.5
        + _PHASE_DURATION[depth][5] * 0.3
        + _PHASE_DURATION[depth][6] * 0.3
        + _PHASE_DURATION[depth][7] * 0.5
        + _PHASE_DURATION[depth][8] * 0.5
        + 4.0  # 4 min Phase 10b weak scaling
    )
    stage1 = phase9 + other_stage1
    return (
        {
            "stage1": stage1,
            "stage2": _STAGE2_COMPOSITION[depth],
            "stage3": _STAGE3_QA[depth],
            "stage4": 0.0,
            "transition": _TRANSITION_BUFFER,
            "total": stage1 + _STAGE2_COMPOSITION[depth] + _STAGE3_QA[depth] + _TRANSITION_BUFFER,
        },
        "incremental_dirty_set",
    )


def _parametric(
    depth: str,
    reasoning_model: str,
    repo_root: Path,
    architect_review: bool,
    skip_qa: bool,
    skip_abuse_cases: bool,
) -> tuple[dict[str, float], str]:
    """Fallback when no measured data is available. Multiplicative
    formula based on depth × repo-size × model + per-stage additives."""
    n_files = _count_repo_files(repo_root)
    size_factor = _size_factor_from_files(n_files)
    model_factor = _MODEL_FACTOR.get(reasoning_model, 1.0)
    stage1 = _STAGE1_BASE[depth] * size_factor * model_factor
    stage1c = 0.0 if skip_abuse_cases else _STAGE1C_ABUSE.get(depth, 0.0)
    stage2 = _STAGE2_COMPOSITION[depth]
    stage3 = 0.0 if skip_qa else _STAGE3_QA[depth]
    stage4 = _STAGE4_ARCHITECT[depth] if architect_review else 0.0
    transition = _TRANSITION_BUFFER
    total = stage1 + stage1c + stage2 + stage3 + stage4 + transition
    return (
        {
            "stage1": stage1,
            "stage1c": stage1c,
            "stage2": stage2,
            "stage3": stage3,
            "stage4": stage4,
            "transition": transition,
            "total": total,
        },
        "parametric",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _format_minutes(m: float) -> str:
    """Round to whole minutes for the banner — "27.3 min" looks fake-precise."""
    return f"{int(round(m))} min"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="estimate_duration.py", add_help=True)
    p.add_argument("--depth", default="standard", choices=("quick", "standard", "thorough"))
    p.add_argument("--mode", default="full", choices=("full", "incremental", "rebuild", "resume"))
    p.add_argument("--reasoning-model", default="sonnet", choices=("sonnet", "opus-cheap", "opus", "haiku-economy"))
    p.add_argument("--architect-review", action="store_true")
    p.add_argument("--skip-qa", action="store_true")
    p.add_argument("--skip-abuse-cases", action="store_true",
                   help="abuse-case verifier fan-out is disabled (mirrors "
                        "skip_abuse_case_verification); drops the Stage-1c additive")
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--repo-root", required=True, type=Path)
    p.add_argument("--max-stride-components", type=int, default=5)
    p.add_argument("--sec-change-count", type=int, default=0)
    args = p.parse_args(argv[1:])

    # Source priority — try each strategy in order, take the first hit.
    breakdown: dict[str, float] | None = None
    source: str = "parametric"

    if args.mode == "resume":
        result = _resume_remaining(args.output_dir, args.depth)
        if result:
            breakdown, source = result

    if breakdown is None:
        # `rebuild` and `full` and `resume` (when no checkpoint) and the
        # initial parametric run all consult the last-run cache before
        # falling back to formula. Incremental uses its own ratio path.
        if args.mode != "incremental":
            result = _last_run_cache(args.output_dir, args.mode, args.depth)
            if result:
                breakdown, source = result

    # M5 — fall through to per-component-duration estimate when last_run_cache
    # didn't hit (different mode/depth, or first time after upgrade where
    # last_run_seconds has been reset). Lower priority than last_run_cache
    # (which captures total wall-clock more accurately) but higher than the
    # generic parametric formula.
    if breakdown is None and args.mode != "incremental":
        result = _component_durations_estimate(args.output_dir, args.depth, args.max_stride_components)
        if result:
            breakdown, source = result

    if breakdown is None and args.mode == "incremental":
        result = _incremental_dirty_set(args.depth, args.sec_change_count, args.max_stride_components)
        if result:
            breakdown, source = result

    if breakdown is None:
        breakdown, source = _parametric(
            args.depth,
            args.reasoning_model,
            args.repo_root,
            args.architect_review,
            args.skip_qa,
            args.skip_abuse_cases,
        )

    out = {
        "source": source,
        "stage1_min": int(round(breakdown["stage1"])),
        "stage1c_min": int(round(breakdown.get("stage1c", 0.0))),
        "stage2_min": int(round(breakdown["stage2"])),
        "stage3_min": int(round(breakdown["stage3"])),
        "stage4_min": int(round(breakdown["stage4"])),
        "transition_min": int(round(breakdown["transition"])),
        "total_min": int(round(breakdown["total"])),
        "total_pretty": _format_minutes(breakdown["total"]),
    }
    print(json.dumps(out, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
